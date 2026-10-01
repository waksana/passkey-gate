# Passkey Gate

Passkey Gate is a small, single-owner WebAuthn authentication service for
protecting multiple web applications behind a reverse proxy.

One set of discoverable passkeys is shared across explicitly allowed
subdomains. Sessions are not shared: every protected host receives a separate,
host-only cookie with a fixed lifetime.

Passkey Gate is intentionally not an identity provider. It has no usernames,
passwords, email, roles, groups, OAuth, OIDC, or application identity headers.

## Features

- Automatic WebAuthn authentication with no username or sign-in form
- Exact Host and HTTPS Origin allowlists
- Discoverable credentials with user verification required
- Opaque, host-bound session tokens stored as SHA-256 hashes
- Fixed session expiration with no sliding refresh
- One-time, SSH-generated bootstrap links
- Passkey naming, registration, deletion, and session revocation
- Fresh passkey verification for sensitive credential changes
- CSRF protection and strict security headers
- SQLite storage and a single self-contained binary

## Build

Go 1.25 or newer is required.

```bash
go test ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -o passkey-gate ./cmd/passkey-gate
```

Tagged GitHub releases contain one uploaded asset: a statically built Linux
amd64 binary named `passkey-gate`.

## Configuration

Create `passkey-gate.yaml`:

```yaml
listen: 127.0.0.1:8081
rp_id: example.com
rp_name: Personal Services
management_origin: https://auth.example.com
session_duration: 36h
challenge_duration: 5m
fresh_auth_duration: 5m
bootstrap_duration: 10m

allowed_origins:
  - https://auth.example.com
  - https://app.example.com

allowed_hosts:
  - auth.example.com
  - app.example.com

database: /srv/passkey-gate/gate.sqlite3
```

Configuration requirements:

- `listen` must be a loopback address outside test mode.
- `rp_id` must be the registrable parent domain used by every passkey.
- Origins must be canonical HTTPS origins without paths, wildcards, or
  non-default ports.
- Hosts must be exact DNS names within the RP ID.
- Every allowed host must have a matching allowed origin.
- Optional `android_origins` maps exact allowed hosts to native Android signing
  origins. It is disabled when omitted. See [Android login](#android-login).
- `management_origin` must exactly match one allowed origin.
- The database path must be absolute. Its parent directory must be writable by
  the service account.

## Run

```bash
./passkey-gate serve -config ./passkey-gate.yaml
```

Print the embedded build version with:

```bash
./passkey-gate version
```

The process exposes:

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Process and database health |
| `GET /_gate/check` | Reverse-proxy authorization subrequest |
| `GET /_gate/login` | Automatic passkey authentication |
| `GET /_gate/manage` | Passkey management |
| `POST /_gate/auth/*` | Authentication ceremony |
| `POST /_gate/register/*` | Registration ceremony |
| `POST /_gate/sessions/revoke` | Revoke all sessions |

Keep the listener private. TLS must terminate at a trusted reverse proxy, and
only configured hosts should be routed to Passkey Gate.

## Android login

Native Android login is opt-in, separately from the HTTPS origin allowlist:

```yaml
android_origins:
  app.example.com:
    - android:apk-key-hash:REPLACE_WITH_UNPADDED_BASE64URL_SHA256_CERT_DIGEST
```

Replace the placeholder with the **32-byte SHA-256 signing certificate digest**,
encoded as unpadded base64url (43 characters), not the APK file hash, certificate
bytes or colon-separated hex fingerprint. Empty lists, unknown/noncanonical
hosts, duplicates and malformed digests are rejected. Never allow arbitrary
Android origins or add them to `allowed_origins`.

This expands only the login verifier for the selected host. Browser origins,
registration, fresh management verification, required user verification, flow
expiry/one-time consumption, CSRF checks and fixed-lifetime host-bound sessions
retain their existing rules. Other hosts do not inherit the native origin.

The native client can use the existing ceremony without a new pairing service:

1. GET `https://app.example.com/_gate/login` to obtain the client-binding cookie.
2. POST `{}` to `/_gate/auth/options`, retaining the flow cookie.
3. Pass the returned `publicKey` object to Android Credential Manager.
4. POST the returned assertion JSON to `/_gate/auth/finish` with the same cookies.
5. Retain the secure, host-only `__Host-pg_session` cookie and its absolute expiry.

An HTTP `Origin: https://app.example.com` header is not proof of native identity:
the verifier checks the Android origin inside the **signed** `clientDataJSON`.
The client must not replace that origin with a web origin. Authentication
failures must not trigger automatic assertion retries.

Before enabling a signing identity, explicitly authorize its package and signing
certificate using Digital Asset Links on the **RP ID domain**. For RP ID
`example.com`, serve `https://example.com/.well-known/assetlinks.json` publicly
over trusted HTTPS, with HTTP 200 and `Content-Type: application/json`, without
authentication or redirects:

```json
[
  {
    "relation": ["delegate_permission/common.get_login_creds"],
    "target": {
      "namespace": "android_app",
      "package_name": "io.github.waksana.cockpitdashboard",
      "sha256_cert_fingerprints": ["REPLACE_WITH_COLON_SEPARATED_SHA256_CERT_FINGERPRINT"]
    }
  }
]
```

Here the fingerprint is uppercase colon-separated hex of the same certificate
digest. Preserve unrelated existing association entries. For example, add this
exact location to the RP ID's TLS virtual host, outside the gate's protected
catch-all (adapt the static file path):

```nginx
location = /.well-known/assetlinks.json {
    auth_request off;
    default_type application/json;
    alias /srv/passkey-gate-public/assetlinks.json;
}
```

Do not expose the config, database or service listener. Changing the APK signing
key requires deliberately updating both associations and the selected host's
origin allowlist. A debug signing key is for a controlled trial, not a production
distribution identity. No deployment or configuration changes are performed by
this repository's build.

Android 9/API 28+ and a compatible credential provider are required. A TV's
firmware label does not establish compatibility. Cross-device QR availability
depends on the device/provider; the server cannot force it. Existing browser
login remains available if the device cannot support native credentials.

## Reverse proxy contract

For each protected virtual host:

1. Route `/_gate/*` directly to Passkey Gate without applying the authorization
   subrequest again.
2. Make `/_gate/check` and `/_gate/redirect` internal-only.
3. Send the exact public Host header to Passkey Gate.
4. Use `auth_request` (or an equivalent subrequest mechanism) before proxying
   the application.
5. On `401`, internally request `/_gate/redirect` with the original relative
   URI in `X-Original-URI`.
6. Forward the `X-PG-Upstream-Cookie` value returned by the authorization
   subrequest as the application's Cookie header. It preserves application
   cookies while removing all reserved `__Host-pg_*` cookies.
7. Reject every unknown Host before it reaches Passkey Gate or an application.

Illustrative Nginx locations:

```nginx
location = /_gate/check {
    internal;
    proxy_pass http://127.0.0.1:8081/_gate/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Host $host;
}

location = /_gate/redirect {
    internal;
    proxy_pass http://127.0.0.1:8081;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Host $host;
    proxy_set_header X-Original-URI $request_uri;
}

location ^~ /_gate/ {
    proxy_pass http://127.0.0.1:8081;
    proxy_set_header Host $host;
}

location / {
    auth_request /_gate/check;
    error_page 401 = /_gate/redirect;
    auth_request_set $gate_cookie $upstream_http_x_pg_upstream_cookie;

    proxy_set_header Cookie $gate_cookie;
    proxy_pass http://127.0.0.1:9000;
}
```

This is a contract example, not a complete hardened Nginx configuration.
Configure TLS, exact `server_name` values, body and header limits, logging, and
default-host rejection for your environment.

On the management host, route `/_gate/*` to Passkey Gate and redirect `/` to
`/_gate/manage`; do not configure an application upstream there.

## Register the first passkey

Generate a short-lived bootstrap link from a trusted local shell:

```bash
./passkey-gate bootstrap -config ./passkey-gate.yaml
```

Open the printed HTTPS URL within ten minutes. The token is carried in the URL
fragment, removed from browser history before use, stored only as a SHA-256
hash, and consumed in the same transaction that stores the credential.

Register at least two independent passkeys. If every passkey is lost, local
shell access and a new bootstrap link are the only recovery mechanism.

## Session behavior

- Cookie name: `__Host-pg_session`
- Attributes: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`
- At least 32 random token bytes
- Only the token hash is stored
- Each session is bound to one exact host
- Expiration is absolute and never extended by activity
- Deleting a passkey revokes every active session

Applications receive no user identity and should never receive Gate cookies.

## Release

Push a semantic version tag to run tests and publish the binary:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow runs the test suite and `go vet`, then uploads exactly one
Linux amd64 binary to the GitHub Release.
