package gate

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/waksana/passkey-gate/internal/config"
	"github.com/waksana/passkey-gate/internal/flow"
	"github.com/waksana/passkey-gate/internal/store"
)

const (
	sessionCookie   = "__Host-pg_session"
	flowCookie      = "__Host-pg_flow"
	bootstrapCookie = "__Host-pg_bootstrap"
	clientCookie    = "__Host-pg_client"
	maxRequestBody  = 1 << 20
	maxRateWindows  = 4096
)

//go:embed templates/*.html static/*
var assets embed.FS

type App struct {
	cfg           config.Config
	store         *store.Store
	flows         *flow.Store
	webauthn      map[string]*webauthn.WebAuthn
	loginWebauthn map[string]*webauthn.WebAuthn
	templates     *template.Template
	csrfKey       [32]byte
	limiter       *limiter
	credentialMu  sync.Mutex
	logger        *slog.Logger
	handler       http.Handler
	now           func() time.Time
}

func New(cfg config.Config, database *store.Store, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.Default()
	}
	tmpl, err := template.ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	app := &App{
		cfg:           cfg,
		store:         database,
		flows:         flow.New(1024),
		webauthn:      make(map[string]*webauthn.WebAuthn, len(cfg.AllowedHosts)),
		loginWebauthn: make(map[string]*webauthn.WebAuthn, len(cfg.AllowedHosts)),
		templates:     tmpl,
		limiter:       newLimiter(),
		logger:        logger,
		now:           time.Now,
	}
	if _, err := rand.Read(app.csrfKey[:]); err != nil {
		return nil, fmt.Errorf("generate CSRF key: %w", err)
	}

	for _, host := range cfg.AllowedHosts {
		options := webauthn.Config{
			RPID:                  cfg.RPID,
			RPDisplayName:         cfg.RPName,
			RPOrigins:             cfg.OriginsForHost(host),
			AttestationPreference: protocol.PreferNoAttestation,
			AuthenticatorSelection: protocol.AuthenticatorSelection{
				RequireResidentKey: protocol.ResidentKeyRequired(),
				ResidentKey:        protocol.ResidentKeyRequirementRequired,
				UserVerification:   protocol.VerificationRequired,
			},
			Timeouts: webauthn.TimeoutsConfig{
				Login: webauthn.TimeoutConfig{
					Enforce: true,
					Timeout: cfg.ChallengeDuration.Duration,
				},
				Registration: webauthn.TimeoutConfig{
					Enforce: true,
					Timeout: cfg.ChallengeDuration.Duration,
				},
			},
		}
		instance, err := webauthn.New(&options)
		if err != nil {
			return nil, fmt.Errorf("configure WebAuthn for %s: %w", host, err)
		}
		app.webauthn[host] = instance
		// Native origins are trusted only for login, never registration or fresh management verification.
		loginOptions := options
		loginOptions.RPOrigins = cfg.LoginOriginsForHost(host)
		loginInstance, err := webauthn.New(&loginOptions)
		if err != nil {
			return nil, fmt.Errorf("configure login WebAuthn for %s: %w", host, err)
		}
		app.loginWebauthn[host] = loginInstance
	}
	app.handler = app.routes()
	return app, nil
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	a.handler.ServeHTTP(w, r)
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /_gate/static/gate.js", a.staticJS)
	mux.HandleFunc("GET /_gate/static/gate.css", a.staticCSS)
	mux.HandleFunc("GET /_gate/check", a.check)
	mux.HandleFunc("GET /_gate/redirect", a.loginRedirect)
	mux.HandleFunc("GET /_gate/login", a.loginPage)
	mux.HandleFunc("POST /_gate/auth/options", a.authOptions)
	mux.HandleFunc("POST /_gate/auth/finish", a.authFinish)
	mux.HandleFunc("GET /_gate/bootstrap", a.bootstrapPage)
	mux.HandleFunc("POST /_gate/bootstrap/claim", a.bootstrapClaim)
	mux.HandleFunc("GET /_gate/manage", a.managePage)
	mux.HandleFunc("POST /_gate/fresh/options", a.freshOptions)
	mux.HandleFunc("POST /_gate/fresh/finish", a.freshFinish)
	mux.HandleFunc("POST /_gate/register/options", a.registerOptions)
	mux.HandleFunc("POST /_gate/register/finish", a.registerFinish)
	mux.HandleFunc("POST /_gate/credentials/{id}/rename", a.renameCredential)
	mux.HandleFunc("POST /_gate/credentials/{id}/delete", a.deleteCredential)
	mux.HandleFunc("POST /_gate/sessions/revoke", a.revokeSessions)
	mux.HandleFunc("POST /_gate/logout", a.logout)
	return mux
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "publickey-credentials-create=(self), publickey-credentials-get=(self)")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func (a *App) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := a.store.Health(ctx); err != nil {
		a.serverError(w, "database health check", err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (a *App) staticJS(w http.ResponseWriter, _ *http.Request) {
	a.serveAsset(w, "static/gate.js", "text/javascript; charset=utf-8")
}

func (a *App) staticCSS(w http.ResponseWriter, _ *http.Request) {
	a.serveAsset(w, "static/gate.css", "text/css; charset=utf-8")
}

func (a *App) serveAsset(w http.ResponseWriter, name, contentType string) {
	data, err := assets.ReadFile(name)
	if err != nil {
		a.serverError(w, "read embedded asset", err)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (a *App) requestHost(w http.ResponseWriter, r *http.Request) (string, bool) {
	host := strings.ToLower(r.Host)
	if host == "" || strings.Contains(host, ":") || !a.cfg.HostAllowed(host) {
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return "", false
	}
	return host, true
}

func (a *App) currentSession(r *http.Request, host string) (store.Session, error) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return store.Session{}, store.ErrUnauthorized
	}
	return a.store.Session(r.Context(), cookie.Value, host)
}

func (a *App) managementSession(w http.ResponseWriter, r *http.Request, fresh bool) (store.Session, bool) {
	host, ok := a.requestHost(w, r)
	if !ok {
		return store.Session{}, false
	}
	if host != a.cfg.ManagementHost() {
		http.Error(w, "not found", http.StatusNotFound)
		return store.Session{}, false
	}
	if !a.allow(r, "management", 120, time.Minute) {
		a.jsonError(w, http.StatusTooManyRequests, "try again later")
		return store.Session{}, false
	}
	session, err := a.currentSession(r, host)
	if err != nil {
		a.clearCookie(w, sessionCookie)
		a.jsonError(w, http.StatusUnauthorized, "authentication required")
		return store.Session{}, false
	}
	if fresh && a.now().Sub(session.AuthenticatedAt) > a.cfg.FreshAuthDuration.Duration {
		a.jsonError(w, http.StatusUnauthorized, "fresh passkey verification required")
		return store.Session{}, false
	}
	return session, true
}

func (a *App) check(w http.ResponseWriter, r *http.Request) {
	host, ok := a.requestHost(w, r)
	if !ok {
		return
	}
	if _, err := a.currentSession(r, host); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if cookies := applicationCookies(r.Header.Get("Cookie")); cookies != "" {
		w.Header().Set("X-PG-Upstream-Cookie", cookies)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requestHost(w, r); !ok {
		return
	}
	returnPath, err := ValidateReturnPath(r.URL.Query().Get("return"))
	if err != nil {
		http.Error(w, "invalid return path", http.StatusBadRequest)
		return
	}
	if _, ok := a.ensureClientCookie(w, r); !ok {
		a.serverError(w, "create client binding", errors.New("random source failed"))
		return
	}
	a.render(w, "login.html", map[string]any{"ReturnPath": returnPath})
}

func (a *App) loginRedirect(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requestHost(w, r); !ok {
		return
	}
	returnPath, err := ValidateReturnPath(r.Header.Get("X-Original-URI"))
	if err != nil {
		http.Error(w, "invalid original URI", http.StatusBadRequest)
		return
	}
	location := "/_gate/login?return=" + url.QueryEscape(returnPath)
	http.Redirect(w, r, location, http.StatusFound)
}

func (a *App) authOptions(w http.ResponseWriter, r *http.Request) {
	host, ok := a.requestHost(w, r)
	if !ok {
		return
	}
	if !a.allow(r, "auth-options", 20, time.Minute) {
		a.jsonError(w, http.StatusTooManyRequests, "try again later")
		return
	}
	returnPath, err := ValidateReturnPath(r.URL.Query().Get("return"))
	if err != nil {
		a.jsonError(w, http.StatusBadRequest, "invalid return path")
		return
	}
	count, err := a.store.CredentialCount(r.Context())
	if err != nil {
		a.serverError(w, "count credentials", err)
		return
	}
	if count == 0 {
		a.jsonError(w, http.StatusServiceUnavailable, "no passkeys are registered")
		return
	}
	options, session, err := a.loginWebauthn[host].BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		a.serverError(w, "begin authentication", err)
		return
	}
	token, err := a.flows.Create(flow.Flow{
		Kind:       flow.Login,
		Host:       host,
		ReturnPath: returnPath,
		Session:    *session,
		ExpiresAt:  a.now().Add(a.cfg.ChallengeDuration.Duration),
	})
	if err != nil {
		a.serverError(w, "create authentication flow", err)
		return
	}
	a.setFlowCookie(w, token)
	a.writeJSON(w, http.StatusOK, options)
}

func (a *App) authFinish(w http.ResponseWriter, r *http.Request) {
	host, ok := a.requestHost(w, r)
	if !ok {
		return
	}
	value, err := a.consumeFlow(r, host, flow.Login)
	a.clearCookie(w, flowCookie)
	if err != nil {
		a.jsonError(w, http.StatusBadRequest, "authentication flow expired; retry")
		return
	}
	if !a.allow(r, "auth-finish", 30, time.Minute) {
		a.jsonError(w, http.StatusTooManyRequests, "try again later")
		return
	}

	a.credentialMu.Lock()
	defer a.credentialMu.Unlock()

	owner, err := a.store.Owner(r.Context())
	if err != nil {
		a.serverError(w, "load owner", err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	_, credential, err := a.loginWebauthn[host].FinishPasskeyLogin(discoverableOwner(owner), value.Session, r)
	if err != nil {
		a.logger.Warn("passkey authentication rejected", "host", host, "error", err)
		a.jsonError(w, http.StatusUnauthorized, "passkey verification failed")
		return
	}
	token, session, err := a.store.CreateSession(r.Context(), host, *credential, a.cfg.SessionDuration.Duration)
	if err != nil {
		a.serverError(w, "create session", err)
		return
	}
	a.setSessionCookie(w, token, session.ExpiresAt)
	a.writeJSON(w, http.StatusOK, map[string]string{"redirect": value.ReturnPath})
}

func discoverableOwner(owner store.Owner) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (webauthn.User, error) {
		if !bytes.Equal(userHandle, owner.ID) {
			return nil, errors.New("unknown user handle")
		}
		for _, credential := range owner.Credentials {
			if bytes.Equal(rawID, credential.Value.ID) {
				return owner, nil
			}
		}
		return nil, errors.New("unknown credential")
	}
}

func (a *App) bootstrapPage(w http.ResponseWriter, r *http.Request) {
	host, ok := a.requestHost(w, r)
	if !ok {
		return
	}
	if host != a.cfg.ManagementHost() {
		http.NotFound(w, r)
		return
	}
	if !a.allow(r, "bootstrap", 30, 10*time.Minute) {
		http.Error(w, "try again later", http.StatusTooManyRequests)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "bootstrap tokens must be supplied in the URL fragment", http.StatusBadRequest)
		return
	}
	if _, ok := a.ensureClientCookie(w, r); !ok {
		a.serverError(w, "create client binding", errors.New("random source failed"))
		return
	}
	_, authorized := a.validBootstrapCookie(r)
	a.render(w, "bootstrap.html", map[string]any{"Authorized": authorized})
}

func (a *App) bootstrapClaim(w http.ResponseWriter, r *http.Request) {
	host, ok := a.requestHost(w, r)
	if !ok {
		return
	}
	if host != a.cfg.ManagementHost() {
		http.NotFound(w, r)
		return
	}
	if !a.allow(r, "bootstrap-claim", 20, 10*time.Minute) {
		a.jsonError(w, http.StatusTooManyRequests, "try again later")
		return
	}
	var request struct {
		Token string `json:"token"`
	}
	if err := a.decodeJSON(w, r, &request); err != nil {
		a.jsonError(w, http.StatusBadRequest, "invalid request")
		return
	}
	hash, valid := tokenHash(request.Token)
	if !valid {
		a.jsonError(w, http.StatusUnauthorized, "invalid bootstrap token")
		return
	}
	allowed, err := a.store.ValidBootstrap(r.Context(), hash)
	if err != nil {
		a.serverError(w, "validate bootstrap token", err)
		return
	}
	if !allowed {
		a.jsonError(w, http.StatusUnauthorized, "invalid bootstrap token")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     bootstrapCookie,
		Value:    request.Token,
		Path:     "/",
		MaxAge:   int(a.cfg.BootstrapDuration.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) managePage(w http.ResponseWriter, r *http.Request) {
	host, ok := a.requestHost(w, r)
	if !ok {
		return
	}
	if host != a.cfg.ManagementHost() {
		http.NotFound(w, r)
		return
	}
	if !a.allow(r, "management", 120, time.Minute) {
		http.Error(w, "try again later", http.StatusTooManyRequests)
		return
	}
	session, err := a.currentSession(r, host)
	if err != nil {
		a.clearCookie(w, sessionCookie)
		http.Redirect(w, r, "/_gate/login?return=%2F_gate%2Fmanage", http.StatusFound)
		return
	}
	credentials, err := a.store.ListCredentials(r.Context())
	if err != nil {
		a.serverError(w, "list credentials", err)
		return
	}
	a.render(w, "manage.html", map[string]any{
		"Credentials": credentials,
		"CSRF":        a.csrfToken(session.TokenHash),
		"FreshUntil":  session.AuthenticatedAt.Add(a.cfg.FreshAuthDuration.Duration).UnixMilli(),
	})
}

func (a *App) freshOptions(w http.ResponseWriter, r *http.Request) {
	session, ok := a.managementSession(w, r, false)
	if !ok || !a.requireCSRF(w, r, session) {
		return
	}
	host := a.cfg.ManagementHost()
	options, ceremony, err := a.webauthn[host].BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		a.serverError(w, "begin fresh authentication", err)
		return
	}
	token, err := a.flows.Create(flow.Flow{
		Kind:        flow.Fresh,
		Host:        host,
		Session:     *ceremony,
		SessionHash: session.TokenHash,
		ExpiresAt:   a.now().Add(a.cfg.ChallengeDuration.Duration),
	})
	if err != nil {
		a.serverError(w, "create fresh-auth flow", err)
		return
	}
	a.setFlowCookie(w, token)
	a.writeJSON(w, http.StatusOK, options)
}

func (a *App) freshFinish(w http.ResponseWriter, r *http.Request) {
	session, ok := a.managementSession(w, r, false)
	if !ok || !a.requireCSRF(w, r, session) {
		return
	}
	value, err := a.consumeFlow(r, a.cfg.ManagementHost(), flow.Fresh)
	a.clearCookie(w, flowCookie)
	if err != nil || subtle.ConstantTimeCompare(value.SessionHash[:], session.TokenHash[:]) != 1 {
		a.jsonError(w, http.StatusBadRequest, "verification flow expired; retry")
		return
	}
	a.credentialMu.Lock()
	defer a.credentialMu.Unlock()

	owner, err := a.store.Owner(r.Context())
	if err != nil {
		a.serverError(w, "load owner", err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	_, credential, err := a.webauthn[a.cfg.ManagementHost()].FinishPasskeyLogin(
		discoverableOwner(owner), value.Session, r)
	if err != nil {
		a.logger.Warn("fresh passkey verification rejected", "error", err)
		a.jsonError(w, http.StatusUnauthorized, "passkey verification failed")
		return
	}
	if err := a.store.MarkFresh(r.Context(), session.TokenHash, *credential); err != nil {
		a.serverError(w, "mark session fresh", err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]int64{
		"fresh_until": time.Unix(a.now().Unix(), 0).Add(a.cfg.FreshAuthDuration.Duration).UnixMilli(),
	})
}

func (a *App) registerOptions(w http.ResponseWriter, r *http.Request) {
	host, ok := a.requestHost(w, r)
	if !ok {
		return
	}
	if host != a.cfg.ManagementHost() {
		http.NotFound(w, r)
		return
	}
	if !a.allow(r, "registration", 30, 10*time.Minute) {
		a.jsonError(w, http.StatusTooManyRequests, "try again later")
		return
	}
	label := strings.TrimSpace(r.URL.Query().Get("label"))
	if !validLabel(label) {
		a.jsonError(w, http.StatusBadRequest, "label must be between 1 and 80 characters")
		return
	}

	var value flow.Flow
	if bootstrapHash, bootstrapOK := a.validBootstrapCookie(r); bootstrapOK {
		value.Kind = flow.Bootstrap
		value.BootstrapHash = bootstrapHash
	} else {
		session, sessionOK := a.managementSession(w, r, true)
		if !sessionOK || !a.requireCSRF(w, r, session) {
			return
		}
		value.Kind = flow.Registration
		value.SessionHash = session.TokenHash
	}
	owner, err := a.store.Owner(r.Context())
	if err != nil {
		a.serverError(w, "load owner", err)
		return
	}
	options, ceremony, err := a.webauthn[host].BeginRegistration(owner,
		webauthn.WithExclusions(webauthn.Credentials(owner.WebAuthnCredentials()).CredentialDescriptors()),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
	if err != nil {
		a.serverError(w, "begin registration", err)
		return
	}
	value.Host = host
	value.Label = label
	value.Session = *ceremony
	value.ExpiresAt = a.now().Add(a.cfg.ChallengeDuration.Duration)
	token, err := a.flows.Create(value)
	if err != nil {
		a.serverError(w, "create registration flow", err)
		return
	}
	a.setFlowCookie(w, token)
	a.writeJSON(w, http.StatusOK, options)
}

func (a *App) registerFinish(w http.ResponseWriter, r *http.Request) {
	host, ok := a.requestHost(w, r)
	if !ok {
		return
	}
	if !a.allow(r, "registration", 30, 10*time.Minute) {
		a.jsonError(w, http.StatusTooManyRequests, "try again later")
		return
	}
	value, err := a.consumeFlow(r, host, flow.Bootstrap, flow.Registration)
	a.clearCookie(w, flowCookie)
	if err != nil {
		a.jsonError(w, http.StatusBadRequest, "registration flow expired; retry")
		return
	}

	var bootstrapHash *[32]byte
	var session store.Session
	switch value.Kind {
	case flow.Bootstrap:
		hash, valid := a.validBootstrapCookie(r)
		if !valid || subtle.ConstantTimeCompare(hash[:], value.BootstrapHash[:]) != 1 {
			a.jsonError(w, http.StatusUnauthorized, "bootstrap token is invalid or expired")
			return
		}
		bootstrapHash = &value.BootstrapHash
	case flow.Registration:
		var sessionOK bool
		session, sessionOK = a.managementSession(w, r, true)
		if !sessionOK || !a.requireCSRF(w, r, session) {
			return
		}
		if subtle.ConstantTimeCompare(session.TokenHash[:], value.SessionHash[:]) != 1 {
			a.jsonError(w, http.StatusUnauthorized, "session changed during registration")
			return
		}
	default:
		a.jsonError(w, http.StatusBadRequest, "invalid registration flow")
		return
	}

	a.credentialMu.Lock()
	defer a.credentialMu.Unlock()

	owner, err := a.store.Owner(r.Context())
	if err != nil {
		a.serverError(w, "load owner", err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	credential, err := a.webauthn[host].FinishRegistration(owner, value.Session, r)
	if err != nil {
		a.logger.Warn("passkey registration rejected", "error", err)
		a.jsonError(w, http.StatusUnauthorized, "passkey registration failed")
		return
	}
	if err := a.store.AddCredential(r.Context(), *credential, value.Label, bootstrapHash); err != nil {
		if errors.Is(err, store.ErrBootstrap) {
			a.jsonError(w, http.StatusUnauthorized, "bootstrap token is invalid or expired")
			return
		}
		a.serverError(w, "save credential", err)
		return
	}
	if value.Kind == flow.Bootstrap {
		a.clearCookie(w, bootstrapCookie)
		token, newSession, err := a.store.CreateSession(r.Context(), host, *credential, a.cfg.SessionDuration.Duration)
		if err != nil {
			a.serverError(w, "create bootstrap session", err)
			return
		}
		a.setSessionCookie(w, token, newSession.ExpiresAt)
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"redirect": "/_gate/manage"})
}

func (a *App) renameCredential(w http.ResponseWriter, r *http.Request) {
	session, ok := a.managementSession(w, r, false)
	if !ok || !a.requireCSRF(w, r, session) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var request struct {
		Label string `json:"label"`
	}
	if err := a.decodeJSON(w, r, &request); err != nil || !validLabel(request.Label) {
		a.jsonError(w, http.StatusBadRequest, "invalid label")
		return
	}
	if err := a.store.RenameCredential(r.Context(), id, request.Label); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			a.jsonError(w, http.StatusNotFound, "credential not found")
			return
		}
		a.serverError(w, "rename credential", err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) deleteCredential(w http.ResponseWriter, r *http.Request) {
	session, ok := a.managementSession(w, r, true)
	if !ok || !a.requireCSRF(w, r, session) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	a.credentialMu.Lock()
	defer a.credentialMu.Unlock()

	if err := a.store.DeleteCredential(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, store.ErrLastCredential):
			a.jsonError(w, http.StatusConflict, "the last passkey cannot be deleted")
		case errors.Is(err, store.ErrNotFound):
			a.jsonError(w, http.StatusNotFound, "credential not found")
		default:
			a.serverError(w, "delete credential", err)
		}
		return
	}
	a.clearCookie(w, sessionCookie)
	a.writeJSON(w, http.StatusOK, map[string]string{"redirect": "/_gate/login?return=%2F_gate%2Fmanage"})
}

func (a *App) revokeSessions(w http.ResponseWriter, r *http.Request) {
	session, ok := a.managementSession(w, r, false)
	if !ok || !a.requireCSRF(w, r, session) {
		return
	}
	if err := a.store.RevokeAllSessions(r.Context()); err != nil {
		a.serverError(w, "revoke sessions", err)
		return
	}
	a.clearCookie(w, sessionCookie)
	a.writeJSON(w, http.StatusOK, map[string]string{"redirect": "/_gate/login?return=%2F_gate%2Fmanage"})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	session, ok := a.managementSession(w, r, false)
	if !ok || !a.requireCSRF(w, r, session) {
		return
	}
	if err := a.store.RevokeSession(r.Context(), session.TokenHash); err != nil {
		a.serverError(w, "revoke session", err)
		return
	}
	a.clearCookie(w, sessionCookie)
	a.writeJSON(w, http.StatusOK, map[string]string{"redirect": "/"})
}

func (a *App) consumeFlow(r *http.Request, host string, kinds ...flow.Kind) (flow.Flow, error) {
	cookie, err := r.Cookie(flowCookie)
	if err != nil {
		return flow.Flow{}, flow.ErrMissing
	}
	return a.flows.Consume(cookie.Value, host, kinds...)
}

func (a *App) validBootstrapCookie(r *http.Request) ([32]byte, bool) {
	cookie, err := r.Cookie(bootstrapCookie)
	if err != nil {
		return [32]byte{}, false
	}
	hash, ok := tokenHash(cookie.Value)
	if !ok {
		return [32]byte{}, false
	}
	valid, err := a.store.ValidBootstrap(r.Context(), hash)
	return hash, err == nil && valid
}

func tokenHash(token string) ([32]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return [32]byte{}, false
	}
	return sha256.Sum256(raw), true
}

func (a *App) csrfToken(sessionHash [32]byte) string {
	mac := hmac.New(sha256.New, a.csrfKey[:])
	_, _ = mac.Write(sessionHash[:])
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *App) requireCSRF(w http.ResponseWriter, r *http.Request, session store.Session) bool {
	expected := a.csrfToken(session.TokenHash)
	provided := r.Header.Get("X-CSRF-Token")
	if subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) != 1 {
		a.jsonError(w, http.StatusForbidden, "invalid CSRF token")
		return false
	}
	return true
}

func (a *App) setFlowCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     flowCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(a.cfg.ChallengeDuration.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (a *App) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *App) ensureClientCookie(w http.ResponseWriter, r *http.Request) (string, bool) {
	if cookie, err := r.Cookie(clientCookie); err == nil {
		if identity, valid := a.clientIdentity(cookie.Value); valid {
			return identity, true
		}
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", false
	}
	if !a.limiter.allow("client-cookie\x00global", 60, time.Minute, a.now()) {
		return "", false
	}
	mac := hmac.New(sha256.New, a.csrfKey[:])
	_, _ = mac.Write([]byte("client-cookie\x00"))
	_, _ = mac.Write(raw)
	signed := append(raw, mac.Sum(nil)...)
	value := base64.RawURLEncoding.EncodeToString(signed)
	http.SetCookie(w, &http.Cookie{
		Name:     clientCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   int((365 * 24 * time.Hour).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return base64.RawURLEncoding.EncodeToString(raw), true
}

func (a *App) clientIdentity(value string) (string, bool) {
	signed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(signed) != 24+sha256.Size {
		return "", false
	}
	payload, providedMAC := signed[:24], signed[24:]
	mac := hmac.New(sha256.New, a.csrfKey[:])
	_, _ = mac.Write([]byte("client-cookie\x00"))
	_, _ = mac.Write(payload)
	if !hmac.Equal(providedMAC, mac.Sum(nil)) {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(payload), true
}

func (a *App) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.templates.ExecuteTemplate(w, name, data); err != nil {
		a.logger.Error("render template", "template", name, "error", err)
	}
}

func (a *App) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		a.logger.Error("encode response", "error", err)
	}
}

func (a *App) jsonError(w http.ResponseWriter, status int, message string) {
	a.writeJSON(w, status, map[string]string{"error": message})
}

func (a *App) serverError(w http.ResponseWriter, operation string, err error) {
	a.logger.Error(operation, "error", err)
	a.jsonError(w, http.StatusInternalServerError, "internal server error")
}

func (a *App) decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid credential ID", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

func validLabel(label string) bool {
	label = strings.TrimSpace(label)
	return utf8.ValidString(label) && len([]rune(label)) >= 1 && len([]rune(label)) <= 80
}

func (a *App) allow(r *http.Request, action string, limit int, window time.Duration) bool {
	identity := "unbound"
	if cookie, err := r.Cookie(clientCookie); err == nil {
		if verified, valid := a.clientIdentity(cookie.Value); valid {
			identity = verified
		}
	}
	now := a.now()
	if !a.limiter.allow(action+"\x00global", limit*5, window, now) {
		return false
	}
	return a.limiter.allow(action+"\x00client\x00"+identity, limit, window, now)
}

type rateWindow struct {
	start     time.Time
	expiresAt time.Time
	count     int
}

type limiter struct {
	mu      sync.Mutex
	windows map[string]rateWindow
}

func newLimiter() *limiter {
	return &limiter{windows: make(map[string]rateWindow)}
}

func (l *limiter) allow(key string, maximum int, duration time.Duration, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	value := l.windows[key]
	if value.start.IsZero() || !now.Before(value.expiresAt) {
		if _, exists := l.windows[key]; !exists && len(l.windows) >= maxRateWindows {
			for existing, window := range l.windows {
				if !now.Before(window.expiresAt) {
					delete(l.windows, existing)
				}
			}
			if len(l.windows) >= maxRateWindows {
				return false
			}
		}
		value = rateWindow{start: now, expiresAt: now.Add(duration)}
	}
	value.count++
	l.windows[key] = value
	return value.count <= maximum
}

func ValidateReturnPath(value string) (string, error) {
	if value == "" {
		return "/", nil
	}
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") ||
		strings.Contains(value, "\\") || strings.ContainsAny(value, "\r\n\t\x00") {
		return "", errors.New("return path must be a single-slash relative URI")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" {
		return "", errors.New("invalid relative URI")
	}
	decodedPath, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil || !strings.HasPrefix(decodedPath, "/") || strings.HasPrefix(decodedPath, "//") ||
		strings.Contains(decodedPath, "\\") || hasControl(decodedPath) {
		return "", errors.New("unsafe encoded path")
	}
	if parsed.RawQuery != "" {
		decodedQuery, err := url.QueryUnescape(parsed.RawQuery)
		if err != nil || hasControl(decodedQuery) || strings.Contains(decodedQuery, "\\") {
			return "", errors.New("unsafe query")
		}
	}
	return value, nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func applicationCookies(header string) string {
	parts := strings.Split(header, ";")
	filtered := parts[:0]
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, _, found := strings.Cut(part, "=")
		if found && strings.HasPrefix(strings.TrimSpace(name), "__Host-pg_") {
			continue
		}
		filtered = append(filtered, part)
	}
	return strings.Join(filtered, "; ")
}
