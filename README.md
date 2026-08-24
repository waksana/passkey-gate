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
