package gate

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/waksana/passkey-gate/internal/config"
	"github.com/waksana/passkey-gate/internal/store"
)

func testApp(t *testing.T) (*App, *store.Store) {
	t.Helper()
	cfg := config.Config{
		Listen:            "127.0.0.1:8081",
		RPID:              "example.com",
		RPName:            "Personal Services",
		ManagementOrigin:  "https://auth.example.com",
		SessionDuration:   config.Duration{Duration: 36 * time.Hour},
		ChallengeDuration: config.Duration{Duration: 5 * time.Minute},
		FreshAuthDuration: config.Duration{Duration: 5 * time.Minute},
		BootstrapDuration: config.Duration{Duration: 10 * time.Minute},
		AllowedOrigins:    []string{"https://auth.example.com", "https://app.example.com"},
		AllowedHosts:      []string{"auth.example.com", "app.example.com"},
		Database:          filepath.Join(t.TempDir(), "gate.sqlite3"),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(context.Background(), cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app, err := New(cfg, database, logger)
	if err != nil {
		t.Fatal(err)
	}
	return app, database
}

func request(app http.Handler, method, target, host string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = host
	response := httptest.NewRecorder()
	app.ServeHTTP(response, req)
	return response
}

func TestReturnPathValidation(t *testing.T) {
	valid := []string{"", "/", "/dashboard", "/a/b?x=1&y=%2Fz", "/%E4%B8%AD"}
	for _, value := range valid {
		if _, err := ValidateReturnPath(value); err != nil {
			t.Errorf("valid path %q rejected: %v", value, err)
		}
	}
	invalid := []string{
		"https://evil.example/", "//evil.example/", "/\\evil", "/%5cevil", "/%2f%2fevil",
		"/x%00y", "/x?bad=%zz", "/x\nLocation:https://evil.example",
	}
	for _, value := range invalid {
		if _, err := ValidateReturnPath(value); err == nil {
			t.Errorf("unsafe path %q accepted", value)
		}
	}
}

func TestUnknownHostAndSecurityHeaders(t *testing.T) {
	app, _ := testApp(t)
	response := request(app, http.MethodGet, "/_gate/login?return=%2F", "evil.example.com")
	if response.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d", response.Code)
	}
	for _, header := range []string{
		"Cache-Control", "Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options",
	} {
		if response.Header().Get(header) == "" {
			t.Errorf("missing %s", header)
		}
		response = request(app, http.MethodGet, "/_gate/login?return=%2F", "app.example.com.")
		if response.Code != http.StatusMisdirectedRequest {
			t.Fatalf("trailing-dot host status = %d", response.Code)
		}
	}
}

func TestLoginPageIsOneUnframedLine(t *testing.T) {
	app, _ := testApp(t)
	response := request(app, http.MethodGet, "/_gate/login?return=%2F", "app.example.com")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "正在验证 Passkey…") || !strings.Contains(body, `class="login-line"`) {
		t.Fatalf("minimal login status is missing: %s", body)
	}
	for _, unwanted := range []string{"login-card", "passkey-mark", "<h1>", "login-note"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("login page contains %q", unwanted)
		}
	}
}

func TestLoginRedirectSafelyEncodesOriginalURI(t *testing.T) {
	app, _ := testApp(t)
	req := httptest.NewRequest(http.MethodGet, "/_gate/redirect", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Original-URI", "/report?a=1&b=two")
	response := httptest.NewRecorder()
	app.ServeHTTP(response, req)
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d", response.Code)
	}
	location := response.Header().Get("Location")
	if location != "/_gate/login?return=%2Freport%3Fa%3D1%26b%3Dtwo" {
		t.Fatalf("unsafe or incorrect location %q", location)
	}
}

func TestSessionCookieAndHostIsolation(t *testing.T) {
	app, database := testApp(t)
	credential := webauthn.Credential{ID: []byte{1}, PublicKey: []byte{1, 2, 3}}
	if err := database.AddCredential(context.Background(), credential, "Primary", nil); err != nil {
		t.Fatal(err)
	}
	token, session, err := database.CreateSession(
		context.Background(), "app.example.com", credential, 36*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/_gate/check", nil)
	req.Host = "app.example.com"
	req.Header.Set("Cookie", "application=abc; "+sessionCookie+"="+token+"; theme=\"a=b\"; "+clientCookie+"=private")
	response := httptest.NewRecorder()
	app.ServeHTTP(response, req)
	if response.Code != http.StatusNoContent {
		t.Fatalf("valid session status = %d", response.Code)
	}
	if got := response.Header().Get("X-PG-Upstream-Cookie"); got != `application=abc; theme="a=b"` {
		t.Fatalf("filtered cookies = %q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/_gate/check", nil)
	req.Host = "auth.example.com"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response = httptest.NewRecorder()
	app.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("cross-host session status = %d", response.Code)
	}

	cookieResponse := httptest.NewRecorder()
	app.setSessionCookie(cookieResponse, token, session.ExpiresAt)
	header := cookieResponse.Header().Get("Set-Cookie")
	for _, required := range []string{
		"__Host-pg_session=", "Path=/", "Expires=", "Max-Age=", "HttpOnly", "Secure", "SameSite=Lax",
	} {
		if !strings.Contains(header, required) {
			t.Errorf("cookie missing %q: %s", required, header)
		}
	}
	if strings.Contains(header, "Domain=") {
		t.Errorf("host-only cookie has Domain: %s", header)
	}
}

func TestApplicationCookieFilterPreservesNonGateCookies(t *testing.T) {
	input := `a=1; __Host-pg_session=secret; quoted="x=y"; __Host-pg_flow=flow; malformed`
	if got, want := applicationCookies(input), `a=1; quoted="x=y"; malformed`; got != want {
		t.Fatalf("filter result = %q, want %q", got, want)
	}
}

func TestClientCookieIsAuthenticatedAndLimiterIsBounded(t *testing.T) {
	app, _ := testApp(t)
	page := request(app, http.MethodGet, "/_gate/login?return=%2F", "app.example.com")
	var signed string
	for _, cookie := range page.Result().Cookies() {
		if cookie.Name == clientCookie {
			signed = cookie.Value
		}
	}
	if signed == "" {
		t.Fatal("client cookie was not issued")
	}
	if _, valid := app.clientIdentity(signed); !valid {
		t.Fatal("issued client cookie was not authenticated")
	}
	forged := base64.RawURLEncoding.EncodeToString(make([]byte, 24+sha256.Size))
	if _, valid := app.clientIdentity(forged); valid {
		t.Fatal("forged client cookie was accepted")
	}

	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < maxRateWindows+100; i++ {
		app.limiter.allow(fmt.Sprintf("key-%d", i), 1, time.Hour, now)
	}
	if got := len(app.limiter.windows); got > maxRateWindows {
		t.Fatalf("limiter grew to %d entries", got)
	}
}

func TestBootstrapClaimKeepsTokenOutOfURL(t *testing.T) {
	app, database := testApp(t)
	token, err := database.IssueBootstrap(context.Background(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	page := request(app, http.MethodGet, "/_gate/bootstrap", "auth.example.com")
	if page.Code != http.StatusOK {
		t.Fatalf("bootstrap page status: %d", page.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/_gate/bootstrap/claim",
		strings.NewReader(`{"token":"`+token+`"}`))
	req.Host = "auth.example.com"
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range page.Result().Cookies() {
		req.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	app.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("claim status: %d, body: %s", response.Code, response.Body.String())
	}
	header := response.Header().Get("Set-Cookie")
	if !strings.Contains(header, bootstrapCookie+"=") || !strings.Contains(header, "HttpOnly") ||
		!strings.Contains(header, "Secure") || !strings.Contains(header, "SameSite=Strict") {
		t.Fatalf("unsafe bootstrap cookie: %s", header)
	}

	query := request(app, http.MethodGet, "/_gate/bootstrap?token="+token, "auth.example.com")
	if query.Code != http.StatusBadRequest {
		t.Fatalf("query token status: %d", query.Code)
	}
}
