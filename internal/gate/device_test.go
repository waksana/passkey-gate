package gate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/waksana/passkey-gate/internal/store"
)

func oauthRequest(app *App, endpoint, host string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/_gate/oauth/"+endpoint, strings.NewReader(form.Encode()))
	r.Host = host
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	return w
}

func oauthCode(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatal(err, w.Body.String())
	}
	if w.Code != status || value["error"] != code {
		t.Fatalf("got %d %s; want %d %s", w.Code, w.Body.String(), status, code)
	}
}

func createHTTPDevice(t *testing.T, app *App) store.DeviceAuthorization {
	t.Helper()
	w := oauthRequest(app, "device_authorization", "app.example.com",
		url.Values{"client_id": {store.DeviceClient}, "scope": {store.DeviceScope}})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var d store.DeviceAuthorization
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["verification_uri"] != "https://auth.example.com/_gate/device" ||
		payload["verification_uri_complete"] != "https://auth.example.com/_gate/device?user_code="+d.UserCode {
		t.Fatalf("verification URI mismatch: %v", payload)
	}
	if strings.Contains(fmt.Sprint(payload["verification_uri_complete"]), d.DeviceCode) {
		t.Fatal("secret in QR")
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
		t.Fatal("missing cache controls")
	}
	return d
}

func TestOAuthProtocolValidation(t *testing.T) {
	tests := []struct{ endpoint, body, code string }{
		{"device_authorization", "client_id=other&scope=host-access", "invalid_client"},
		{"device_authorization", "scope=host-access", "invalid_client"},
		{"device_authorization", "client_id=cockpit-dashboard&scope=openid", "invalid_scope"},
		{"device_authorization", "client_id=cockpit-dashboard", "invalid_scope"},
		{"device_authorization", "client_id=cockpit-dashboard&scope=host-access&scope=host-access", "invalid_request"},
		{"device_authorization", "client_id=cockpit-dashboard&scope=host-access&unknown=x&unknown=y", "invalid_request"},
		{"token", "client_id=cockpit-dashboard&grant_type=client_credentials", "unsupported_grant_type"},
		{"token", "client_id=cockpit-dashboard", "invalid_request"},
		{"token", "client_id=cockpit-dashboard&grant_type=refresh_token", "invalid_request"},
		{"token", "client_id=cockpit-dashboard&grant_type=refresh_token&refresh_token=abc", "invalid_grant"},
		{"token", "client_id=cockpit-dashboard&grant_type=refresh_token&refresh_token=abc&scope=openid", "invalid_scope"},
		{"token", "client_id=cockpit-dashboard&client_secret=x", "invalid_client"},
		{"token", "client_id=cockpit-dashboard&grant_type=" + url.QueryEscape(deviceGrantType), "invalid_request"},
		{"revoke", "client_id=cockpit-dashboard", "invalid_request"},
		{"token", "client_id=cockpit-dashboard&bad=%zz", "invalid_request"},
		{"token", "client_id=cockpit-dashboard&large=" + strings.Repeat("x", 513), "invalid_request"},
	}
	for _, tc := range tests {
		t.Run(tc.body[:min(len(tc.body), 80)], func(t *testing.T) {
			app, _ := testApp(t)
			r := httptest.NewRequest("POST", "/_gate/oauth/"+tc.endpoint, strings.NewReader(tc.body))
			r.Host = "app.example.com"
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			app.ServeHTTP(w, r)
			oauthCode(t, w, 400, tc.code)
		})
	}
	app, _ := testApp(t)
	for _, tc := range []struct{ target, content, body string }{
		{"/_gate/oauth/token", "application/json", `{}`},
		{"/_gate/oauth/token?client_id=cockpit-dashboard", "application/x-www-form-urlencoded", "client_id=cockpit-dashboard"},
		{"/_gate/oauth/token", "application/x-www-form-urlencoded", strings.Repeat("x", 4097)},
	} {
		r := httptest.NewRequest("POST", tc.target, strings.NewReader(tc.body))
		r.Host = "app.example.com"
		r.Header.Set("Content-Type", tc.content)
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		oauthCode(t, w, 400, "invalid_request")
	}
	form := url.Values{"client_id": {store.DeviceClient}, "scope": {store.DeviceScope}}
	oauthCode(t, oauthRequest(app, "device_authorization", "auth.example.com", form), 400, "invalid_target")
	if w := oauthRequest(app, "device_authorization", "evil.example.com", form); w.Code != 421 {
		t.Fatal(w.Code)
	}
	w := oauthRequest(app, "revoke", "app.example.com", url.Values{"client_id": {store.DeviceClient}, "token": {"unknown"}, "token_type_hint": {"unrecognized"}})
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
}

// Synthetic ES256 assertions exercise the real WebAuthn signature/origin/UV verifier.
type syntheticPasskey struct {
	key        *ecdsa.PrivateKey
	credential webauthn.Credential
	userID     []byte
	counter    uint32
}

func newSyntheticPasskey(t *testing.T, database *store.Store) *syntheticPasskey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	credential := webauthn.Credential{ID: []byte("synthetic-device-test"), PublicKey: public, AttestationType: "none"}
	if err := database.AddCredential(context.Background(), credential, "Synthetic only", nil); err != nil {
		t.Fatal(err)
	}
	owner, err := database.Owner(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return &syntheticPasskey{key: key, credential: credential, userID: owner.ID}
}

func (p *syntheticPasskey) assertion(t *testing.T, options []byte, origin string, uv bool) []byte {
	t.Helper()
	var challenge struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &challenge); err != nil {
		t.Fatal(err)
	}
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge.PublicKey.Challenge, "origin": origin})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte("example.com"))
	authData := append([]byte{}, rpHash[:]...)
	flags := byte(1)
	if uv {
		flags |= 4
	}
	authData = append(authData, flags)
	p.counter++
	authData = binary.BigEndian.AppendUint32(authData, p.counter)
	clientHash := sha256.Sum256(client)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, p.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id": encode(p.credential.ID), "rawId": encode(p.credential.ID), "type": "public-key",
		"response": map[string]string{"clientDataJSON": encode(client), "authenticatorData": encode(authData),
			"signature": encode(signature), "userHandle": encode(p.userID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func humanRequest(app *App, method, path string, body []byte, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Host = "auth.example.com"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	return w
}

func TestSignedPasskeyDeviceEndToEnd(t *testing.T) {
	app, database := testApp(t)
	p := newSyntheticPasskey(t, database)
	d := createHTTPDevice(t, app)
	page := humanRequest(app, "GET", "/_gate/device?user_code="+d.UserCode, nil, nil, "")
	if page.Code != 302 {
		t.Fatal("device link authorized without login")
	}
	options := humanRequest(app, "POST", "/_gate/auth/options?return=%2F_gate%2Fdevice", nil, nil, "")
	if options.Code != 200 {
		t.Fatal(options.Code, options.Body.String())
	}
	login := humanRequest(app, "POST", "/_gate/auth/finish", p.assertion(t, options.Body.Bytes(), "https://auth.example.com", true), options.Result().Cookies(), "")
	if login.Code != 200 {
		t.Fatal(login.Code, login.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range login.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no human session")
	}
	session, err := database.Session(context.Background(), cookie.Value, "auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cookies := []*http.Cookie{cookie}
	csrf := app.csrfToken(session.TokenHash)
	page = humanRequest(app, "GET", "/_gate/device?user_code="+d.UserCode, nil, cookies, "")
	if page.Code != 200 || !strings.Contains(page.Body.String(), "app.example.com") ||
		!strings.Contains(page.Body.String(), d.UserCode) || !strings.Contains(page.Body.String(), "confirm-code") {
		t.Fatal(page.Code, page.Body.String())
	}
	target := "/_gate/device/options?user_code=" + d.UserCode + "&confirm_code=" + d.UserCode
	if w := humanRequest(app, "POST", target, nil, cookies, ""); w.Code != 403 {
		t.Fatal("CSRF missing accepted", w.Code)
	}
	if w := humanRequest(app, "POST", target+"X", nil, cookies, csrf); w.Code != 400 {
		t.Fatal("mismatched code accepted", w.Code)
	}
	if w := humanRequest(app, "POST", "/_gate/device/finish", []byte(`{}`), cookies, csrf); w.Code != 400 {
		t.Fatal("cookie alone approved")
	}
	// Signed assertions still fail without UV or on a different origin.
	for _, bad := range []struct {
		origin string
		uv     bool
	}{{"https://auth.example.com", false}, {"https://app.example.com", true}} {
		options = humanRequest(app, "POST", target, nil, cookies, csrf)
		flowCookies := append([]*http.Cookie{cookie}, options.Result().Cookies()...)
		w := humanRequest(app, "POST", "/_gate/device/finish", p.assertion(t, options.Body.Bytes(), bad.origin, bad.uv), flowCookies, csrf)
		if w.Code != 401 {
			t.Fatal("invalid assertion approved", w.Code, w.Body.String())
		}
	}
	options = humanRequest(app, "POST", target, nil, cookies, csrf)
	if options.Code != 200 {
		t.Fatal(options.Code, options.Body.String())
	}
	flowCookies := append([]*http.Cookie{cookie}, options.Result().Cookies()...)
	body := p.assertion(t, options.Body.Bytes(), "https://auth.example.com", true)
	w := humanRequest(app, "POST", "/_gate/device/finish", body, flowCookies, csrf)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if replay := humanRequest(app, "POST", "/_gate/device/finish", body, flowCookies, csrf); replay.Code != 400 {
		t.Fatal("ceremony replay accepted")
	}
	// The actual HTTP clock enforces the advertised initial interval.
	time.Sleep(time.Duration(store.DeviceInterval) * time.Second)
	form := url.Values{"client_id": {store.DeviceClient}, "grant_type": {deviceGrantType}, "device_code": {d.DeviceCode}}
	w = oauthRequest(app, "token", "app.example.com", form)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var tokens store.DeviceTokens
	if err := json.Unmarshal(w.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	oauthCode(t, oauthRequest(app, "token", "app.example.com", form), 400, "invalid_grant")
	check := func(host, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/_gate/check", nil)
		r.Host = host
		r.Header.Set("Authorization", "Bearer "+token)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w
	}
	if w := check("app.example.com", tokens.AccessToken); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w := check("auth.example.com", tokens.AccessToken); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("management token accepted")
	}
	refresh := url.Values{"client_id": {store.DeviceClient}, "grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}}
	w = oauthRequest(app, "token", "app.example.com", refresh)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var rotated store.DeviceTokens
	if err := json.Unmarshal(w.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.RefreshToken == tokens.RefreshToken {
		t.Fatal("refresh not rotated")
	}
	revoke := url.Values{"client_id": {store.DeviceClient}, "token": {rotated.RefreshToken}, "token_type_hint": {"refresh_token"}}
	if w := oauthRequest(app, "revoke", "app.example.com", revoke); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := check("app.example.com", rotated.AccessToken); w.Code != 401 {
		t.Fatal("revoked device accepted")
	}
	// Ordinary browser authentication is unchanged.
	if w := humanRequest(app, "GET", "/_gate/check", nil, cookies, ""); w.Code != 204 {
		t.Fatal("human cookie regressed")
	}
	for _, path := range []string{"/_gate/manage", "/_gate/device", "/_gate/fresh/options", "/_gate/auth/options"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "auth.example.com"
		r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("device bearer reached %s: %d", path, w.Code)
		}
	}
}

func TestDeviceWireFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/device-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version       int  `json:"wire_version"`
		Synthetic     bool `json:"synthetic_only"`
		Authorization struct {
			Path     string `json:"path"`
			Response struct {
				store.DeviceAuthorization
				URI      string `json:"verification_uri"`
				Complete string `json:"verification_uri_complete"`
			} `json:"response"`
		} `json:"device_authorization"`
		Token struct {
			Response store.DeviceTokens `json:"response"`
		} `json:"token"`
		Refresh struct {
			Response store.DeviceTokens `json:"response"`
		} `json:"refresh"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || !fixture.Synthetic {
		t.Fatal("fixture must be synthetic wire v1")
	}
	d := fixture.Authorization.Response
	if d.Interval != store.DeviceInterval || d.ExpiresIn != store.DeviceLifetime ||
		fixture.Authorization.Path != "/_gate/oauth/device_authorization" ||
		d.URI != "https://auth.example.com/_gate/device" ||
		d.Complete != d.URI+"?user_code="+d.UserCode {
		t.Fatal("fixture authorization drift")
	}
	for _, token := range []string{d.DeviceCode, fixture.Token.Response.AccessToken, fixture.Token.Response.RefreshToken,
		fixture.Refresh.Response.AccessToken, fixture.Refresh.Response.RefreshToken} {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
		if err != nil || len(decoded) != 32 || len(token) != 43 {
			t.Fatal("bad synthetic token encoding", err)
		}
	}
	for _, tokens := range []store.DeviceTokens{fixture.Token.Response, fixture.Refresh.Response} {
		if tokens.TokenType != "Bearer" || tokens.ExpiresIn != store.AccessLifetime || tokens.Scope != store.DeviceScope {
			t.Fatal("fixture token drift")
		}
	}
}

func TestManagedDeviceRevocationAndCookieFallback(t *testing.T) {
	app, database := testApp(t)
	p := newSyntheticPasskey(t, database)
	token, session, err := database.CreateSession(context.Background(), "auth.example.com", p.credential, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	d := createHTTPDevice(t, app)
	if err := database.DecideDevice(context.Background(), d.UserCode, session, &p.credential); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Duration(store.DeviceInterval) * time.Second)
	tokens, err := database.PollDevice(context.Background(), d.DeviceCode, "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	families, err := database.ListDevices(context.Background())
	if err != nil || len(families) != 1 {
		t.Fatal(err)
	}
	cookies := []*http.Cookie{{Name: sessionCookie, Value: token}}
	path := fmt.Sprintf("/_gate/devices/%d/revoke", families[0].ID)
	if w := humanRequest(app, "POST", path, nil, cookies, ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := humanRequest(app, "POST", path, nil, cookies, app.csrfToken(session.TokenHash)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := database.CheckDevice(context.Background(), tokens.AccessToken, "app.example.com"); err != store.ErrUnauthorized {
		t.Fatal(err)
	}
	appCookie, _, err := database.CreateSession(context.Background(), "app.example.com", p.credential, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"Bearer " + tokens.AccessToken, "Bearer invalid", "Basic x", "", strings.Repeat("x", 10000)} {
		r := httptest.NewRequest("GET", "/_gate/check", nil)
		r.Host = "app.example.com"
		r.Header["Authorization"] = []string{header}
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: appCookie})
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
			t.Fatal("invalid auth fell back to cookie", header, w.Code)
		}
	}
}
func TestDeviceDenialCSRFHostAndRate(t *testing.T) {
	app, database := testApp(t)
	p := newSyntheticPasskey(t, database)
	token, session, err := database.CreateSession(context.Background(), "auth.example.com", p.credential, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cookies := []*http.Cookie{{Name: sessionCookie, Value: token}}
	d := createHTTPDevice(t, app)
	target := "/_gate/device/deny?user_code=" + d.UserCode
	if w := humanRequest(app, "POST", target, nil, cookies, ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := humanRequest(app, "POST", target, nil, cookies, app.csrfToken(session.TokenHash)); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	form := url.Values{"client_id": {store.DeviceClient}, "grant_type": {deviceGrantType}, "device_code": {d.DeviceCode}}
	oauthCode(t, oauthRequest(app, "token", "app.example.com", form), 400, "access_denied")
	r := httptest.NewRequest("POST", "/_gate/oauth/device_authorization", strings.NewReader("client_id=cockpit-dashboard&scope=host-access"))
	r.Host = "evil.example.com"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != 421 {
		t.Fatal("forwarded host trusted")
	}
	for i := 0; i < 60; i++ {
		oauthRequest(app, "device_authorization", "app.example.com", url.Values{"client_id": {store.DeviceClient}, "scope": {store.DeviceScope}})
	}
	w = oauthRequest(app, "device_authorization", "app.example.com", url.Values{"client_id": {store.DeviceClient}, "scope": {store.DeviceScope}})
	oauthCode(t, w, 429, "temporarily_unavailable")
}
