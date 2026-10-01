package gate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestNativeLoginUsesSignedHostBoundOriginAndPreservesWeb(t *testing.T) {
	native := "android:apk-key-hash:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	other := "android:apk-key-hash:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	for _, tc := range []struct {
		name, host, origin                    string
		enabled, uv, tampered, wrongChallenge bool
		status                                int
	}{
		{"native enabled", "app.example.com", native, true, true, false, false, 200},
		{"native disabled", "app.example.com", native, false, true, false, false, 401},
		{"different host", "auth.example.com", native, true, true, false, false, 401},
		{"wrong signer", "app.example.com", other, true, true, false, false, 401},
		{"missing UV", "app.example.com", native, true, false, false, false, 401},
		{"bad signature", "app.example.com", native, true, true, true, false, 401},
		{"wrong challenge", "app.example.com", native, true, true, false, true, 401},
		{"web preserved", "app.example.com", "https://app.example.com", true, true, false, false, 200},
		{"web default", "app.example.com", "https://app.example.com", false, true, false, false, 200},
		{"other web host", "app.example.com", "https://auth.example.com", true, true, false, false, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := testApp(t)
			if tc.enabled {
				cfg := app.cfg
				cfg.AndroidOrigins = map[string][]string{"app.example.com": {native}}
				if err := cfg.Validate(); err != nil {
					t.Fatal(err)
				}
				var err error
				app, err = New(cfg, db, app.logger)
				if err != nil {
					t.Fatal(err)
				}
			}
			if len(app.webauthn["app.example.com"].Config.RPOrigins) != 1 {
				t.Fatal("management/registration verifier was broadened")
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			public, err := cbor.Marshal(map[int]any{
				1: 2, 3: -7, -1: 1,
				-2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32)),
			})
			if err != nil {
				t.Fatal(err)
			}
			id := []byte("synthetic-test-credential")
			if err := db.AddCredential(context.Background(), webauthn.Credential{
				ID: id, PublicKey: public, Flags: webauthn.NewCredentialFlags(protocol.FlagUserPresent | protocol.FlagUserVerified),
			}, "Synthetic", nil); err != nil {
				t.Fatal(err)
			}
			owner, err := db.Owner(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			options := request(app, http.MethodPost, "/_gate/auth/options", tc.host)
			if options.Code != 200 {
				t.Fatal(options.Code, options.Body.String())
			}
			var challenge struct {
				PublicKey struct{ Challenge, RpID, UserVerification string }
			}
			if err := json.Unmarshal(options.Body.Bytes(), &challenge); err != nil {
				t.Fatal(err)
			}
			if challenge.PublicKey.UserVerification != "required" || challenge.PublicKey.RpID != "example.com" {
				t.Fatal("login no longer requires RP and UV")
			}
			if tc.wrongChallenge {
				challenge.PublicKey.Challenge = "wrong"
			}
			client, err := json.Marshal(map[string]any{
				"type": "webauthn.get", "challenge": challenge.PublicKey.Challenge, "origin": tc.origin, "crossOrigin": false,
			})
			if err != nil {
				t.Fatal(err)
			}
			rp := sha256.Sum256([]byte("example.com"))
			auth := append([]byte{}, rp[:]...)
			flags := byte(1)
			if tc.uv {
				flags |= 4
			}
			auth = append(auth, flags, 0, 0, 0, 0)
			hash := sha256.Sum256(client)
			signed := sha256.Sum256(append(append([]byte{}, auth...), hash[:]...))
			signature, err := ecdsa.SignASN1(rand.Reader, key, signed[:])
			if err != nil {
				t.Fatal(err)
			}
			if tc.tampered {
				signature[len(signature)-1] ^= 1
			}
			encode := base64.RawURLEncoding.EncodeToString
			body, err := json.Marshal(map[string]any{
				"id": encode(id), "rawId": encode(id), "type": "public-key",
				"response": map[string]string{
					"clientDataJSON": encode(client), "authenticatorData": encode(auth),
					"signature": encode(signature), "userHandle": encode(owner.ID),
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			finish := func() *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, "/_gate/auth/finish", bytes.NewReader(body))
				req.Host = tc.host
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "https://"+tc.host)
				for _, cookie := range options.Result().Cookies() {
					req.AddCookie(cookie)
				}
				result := httptest.NewRecorder()
				app.ServeHTTP(result, req)
				return result
			}
			result := finish()
			if result.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", result.Code, tc.status, result.Body.String())
			}
			if replay := finish(); replay.Code != 400 {
				t.Fatalf("replayed flow accepted: %d", replay.Code)
			}
			var session *http.Cookie
			for _, cookie := range result.Result().Cookies() {
				if cookie.Name == sessionCookie {
					session = cookie
				}
			}
			if tc.status != 200 {
				if session != nil {
					t.Fatal("failed assertion issued session")
				}
				return
			}
			if session == nil || !session.Secure || !session.HttpOnly || session.Domain != "" ||
				session.MaxAge <= 0 || session.Expires.IsZero() {
				t.Fatal("invalid persistent session")
			}
			for _, host := range []string{tc.host, "auth.example.com"} {
				req := httptest.NewRequest(http.MethodGet, "/_gate/check", nil)
				req.Host = host
				req.AddCookie(session)
				check := httptest.NewRecorder()
				app.ServeHTTP(check, req)
				want := http.StatusNoContent
				if host != tc.host {
					want = http.StatusUnauthorized
				}
				if check.Code != want {
					t.Fatalf("session scope %s: %d", host, check.Code)
				}
			}
		})
	}
}
