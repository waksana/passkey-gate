package gate

import (
	"crypto/subtle"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/waksana/passkey-gate/internal/flow"
	"github.com/waksana/passkey-gate/internal/store"
)

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

func (a *App) oauthError(w http.ResponseWriter, err error) {
	var oauth store.OAuthError
	if errors.As(err, &oauth) {
		status := http.StatusBadRequest
		if oauth == store.Unavailable {
			status = http.StatusServiceUnavailable
		}
		a.jsonError(w, status, string(oauth))
		return
	}
	a.logger.Error("device operation failed", "error", err)
	a.jsonError(w, http.StatusInternalServerError, "server_error")
}

func (a *App) deviceRate(w http.ResponseWriter, r *http.Request, action string, maximum int) bool {
	allowed, err := a.store.DeviceRate(r.Context(), action, maximum)
	if err != nil {
		a.oauthError(w, err)
		return false
	}
	if !allowed {
		w.Header().Set("Retry-After", "60")
		a.jsonError(w, http.StatusTooManyRequests, "temporarily_unavailable")
	}
	return allowed
}

func (a *App) oauthForm(w http.ResponseWriter, r *http.Request, action string, maximum int) (string, url.Values, bool) {
	w.Header().Set("Pragma", "no-cache")
	host, ok := a.requestHost(w, r)
	if !ok {
		return "", nil, false
	}
	if host == a.cfg.ManagementHost() {
		a.jsonError(w, http.StatusBadRequest, "invalid_target")
		return "", nil, false
	}
	if !a.deviceRate(w, r, action, maximum) {
		return "", nil, false
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/x-www-form-urlencoded" ||
		r.URL.RawQuery != "" || len(r.Header.Values("Authorization")) != 0 {
		a.jsonError(w, http.StatusBadRequest, "invalid_request")
		return "", nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		a.jsonError(w, http.StatusBadRequest, "invalid_request")
		return "", nil, false
	}
	for _, values := range r.PostForm {
		if len(values) != 1 || len(values[0]) > 512 {
			a.jsonError(w, http.StatusBadRequest, "invalid_request")
			return "", nil, false
		}
	}
	if r.PostForm.Get("client_id") != store.DeviceClient {
		a.jsonError(w, http.StatusBadRequest, "invalid_client")
		return "", nil, false
	}
	if _, supplied := r.PostForm["client_secret"]; supplied {
		a.jsonError(w, http.StatusBadRequest, "invalid_client")
		return "", nil, false
	}
	return host, r.PostForm, true
}

func (a *App) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	host, form, ok := a.oauthForm(w, r, "create", 60)
	if !ok {
		return
	}
	if form.Get("scope") != store.DeviceScope {
		a.jsonError(w, http.StatusBadRequest, "invalid_scope")
		return
	}
	device, err := a.store.CreateDevice(r.Context(), host)
	if err != nil {
		a.oauthError(w, err)
		return
	}
	uri := a.cfg.ManagementOrigin + "/_gate/device"
	a.writeJSON(w, http.StatusOK, struct {
		store.DeviceAuthorization
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
	}{device, uri, uri + "?user_code=" + url.QueryEscape(device.UserCode)})
	a.logger.Info("device authorization created", "host", host)
}

func (a *App) deviceToken(w http.ResponseWriter, r *http.Request) {
	host, form, ok := a.oauthForm(w, r, "token", 600)
	if !ok {
		return
	}
	var tokens store.DeviceTokens
	var err error
	switch form.Get("grant_type") {
	case "":
		err = store.OAuthError("invalid_request")
	case deviceGrantType:
		if form.Get("device_code") == "" {
			err = store.OAuthError("invalid_request")
		} else {
			tokens, err = a.store.PollDevice(r.Context(), form.Get("device_code"), host)
		}
	case "refresh_token":
		if scope, present := form["scope"]; present && scope[0] != store.DeviceScope {
			err = store.OAuthError("invalid_scope")
		} else if form.Get("refresh_token") == "" {
			err = store.OAuthError("invalid_request")
		} else {
			tokens, err = a.store.RefreshDevice(r.Context(), form.Get("refresh_token"), host)
		}
	default:
		err = store.OAuthError("unsupported_grant_type")
	}
	if err != nil {
		a.oauthError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, tokens)
	a.logger.Info("device tokens issued", "host", host, "grant", form.Get("grant_type"))
}

func (a *App) deviceRevoke(w http.ResponseWriter, r *http.Request) {
	host, form, ok := a.oauthForm(w, r, "revoke", 120)
	if !ok {
		return
	}
	if form.Get("token") == "" {
		a.jsonError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	// RFC 7009: an unrecognized hint is ignored; both opaque token types revoke the family.
	if err := a.store.RevokeDeviceToken(r.Context(), form.Get("token"), host); err != nil {
		a.oauthError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	a.logger.Info("device revocation requested", "host", host)
}

func (a *App) devicePage(w http.ResponseWriter, r *http.Request) {
	host, ok := a.requestHost(w, r)
	if !ok {
		return
	}
	if host != a.cfg.ManagementHost() {
		http.NotFound(w, r)
		return
	}
	session, err := a.currentSession(r, host)
	if err != nil {
		if !errors.Is(err, store.ErrUnauthorized) {
			a.serverError(w, "load device approval session", err)
			return
		}
		http.Redirect(w, r, "/_gate/login?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values["user_code"]) > 1 {
		a.jsonError(w, http.StatusBadRequest, "invalid user code")
		return
	}
	code := values.Get("user_code")
	resourceHost := ""
	if code != "" {
		if !a.deviceRate(w, r, "lookup", 30) {
			return
		}
		var valid bool
		code, valid = store.NormalizeUserCode(code)
		if valid {
			resourceHost, err = a.store.DeviceHost(r.Context(), code)
		} else {
			err = store.InvalidGrant
		}
		if err != nil {
			a.oauthError(w, err)
			return
		}
	}
	a.render(w, "device.html", map[string]any{
		"CSRF": a.csrfToken(session.TokenHash), "Code": code, "Host": resourceHost,
	})
}

func approvalCode(r *http.Request) (string, bool) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values["user_code"]) != 1 || len(values["confirm_code"]) != 1 {
		return "", false
	}
	code, ok := store.NormalizeUserCode(values.Get("user_code"))
	confirmed, matched := store.NormalizeUserCode(values.Get("confirm_code"))
	return code, ok && matched && code == confirmed
}

func (a *App) deviceOptions(w http.ResponseWriter, r *http.Request) {
	session, ok := a.managementSession(w, r, false)
	if !ok || !a.requireCSRF(w, r, session) {
		return
	}
	if !a.deviceRate(w, r, "approval", 30) {
		return
	}
	code, ok := approvalCode(r)
	if !ok {
		a.jsonError(w, http.StatusBadRequest, "codes must match")
		return
	}
	if _, err := a.store.DeviceHost(r.Context(), code); err != nil {
		a.oauthError(w, err)
		return
	}
	options, ceremony, err := a.webauthn[a.cfg.ManagementHost()].BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		a.serverError(w, "begin device approval", err)
		return
	}
	token, err := a.flows.Create(flow.Flow{
		Kind: flow.Device, Host: a.cfg.ManagementHost(), UserCode: code,
		Session: *ceremony, SessionHash: session.TokenHash,
		ExpiresAt: a.now().Add(min(a.cfg.ChallengeDuration.Duration, time.Duration(store.DeviceLifetime)*time.Second)),
	})
	if err != nil {
		a.serverError(w, "create device approval flow", err)
		return
	}
	a.setFlowCookie(w, token)
	a.writeJSON(w, http.StatusOK, options)
}

func (a *App) deviceFinish(w http.ResponseWriter, r *http.Request) {
	session, ok := a.managementSession(w, r, false)
	if !ok || !a.requireCSRF(w, r, session) {
		return
	}
	value, err := a.consumeFlow(r, a.cfg.ManagementHost(), flow.Device)
	a.clearCookie(w, flowCookie)
	if err != nil || subtle.ConstantTimeCompare(value.SessionHash[:], session.TokenHash[:]) != 1 {
		a.jsonError(w, http.StatusBadRequest, "device approval flow expired; retry")
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
	_, credential, err := a.webauthn[a.cfg.ManagementHost()].FinishPasskeyLogin(discoverableOwner(owner), value.Session, r)
	if err != nil {
		a.jsonError(w, http.StatusUnauthorized, "passkey verification failed")
		return
	}
	if err := a.store.DecideDevice(r.Context(), value.UserCode, session, credential); err != nil {
		a.oauthError(w, err)
		return
	}
	a.logger.Info("device authorization approved")
	a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) deviceDeny(w http.ResponseWriter, r *http.Request) {
	session, ok := a.managementSession(w, r, false)
	if !ok || !a.requireCSRF(w, r, session) {
		return
	}
	if !a.deviceRate(w, r, "approval", 30) {
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values["user_code"]) != 1 {
		a.jsonError(w, http.StatusBadRequest, "invalid user code")
		return
	}
	if err := a.store.DecideDevice(r.Context(), values.Get("user_code"), session, nil); err != nil {
		a.oauthError(w, err)
		return
	}
	a.logger.Info("device authorization denied")
	a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) revokeManagedDevice(w http.ResponseWriter, r *http.Request) {
	session, ok := a.managementSession(w, r, false)
	if !ok || !a.requireCSRF(w, r, session) {
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.store.RevokeDevice(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
		} else {
			a.serverError(w, "revoke device", err)
		}
		return
	}
	a.logger.Info("device revoked", "id", id)
	a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) checkBearer(w http.ResponseWriter, r *http.Request, host string) bool {
	headers := r.Header.Values("Authorization")
	if len(headers) == 0 {
		return false
	}
	valid := len(headers) == 1 && len(headers[0]) == len("Bearer ")+43 && host != a.cfg.ManagementHost()
	if valid {
		scheme, token, found := strings.Cut(headers[0], " ")
		valid = found && strings.EqualFold(scheme, "Bearer")
		if !valid {
			token = ""
		}
		err := a.store.CheckDevice(r.Context(), token, host)
		if err != nil && !errors.Is(err, store.ErrUnauthorized) {
			a.serverError(w, "check device token", err)
			return true
		}
		valid = err == nil
	}
	if !valid {
		w.Header().Set("WWW-Authenticate", `Bearer realm="passkey-gate", error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	w.Header().Set("X-PG-Upstream-Cookie", applicationCookies(r.Header.Get("Cookie")))
	w.WriteHeader(http.StatusNoContent)
	return true
}
