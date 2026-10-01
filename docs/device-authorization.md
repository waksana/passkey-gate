# Device authorization: wire contract v1

This is a narrow, single-owner implementation of the
[RFC 8628 device authorization grant](https://www.rfc-editor.org/rfc/rfc8628)
with opaque bearer credentials and
[RFC 7009 revocation](https://www.rfc-editor.org/rfc/rfc7009).
It is not an OIDC provider or a general OAuth authorization server: no discovery,
ID tokens, dynamic registration, authorization-code/password grants, user
accounts, consent delegation, or application identity headers are provided.
The public client identifier is not a secret or proof of an installed genuine app.

Gate authorizes access to **one entire protected site/instance**, not an
individual Cockpit conversation/session. Cockpit and its SSE protocol do not
change. An established HTTP/SSE/WebSocket connection is not terminated by
revocation; subsequent authorization subrequests are rejected.

## Deployment boundary

The endpoints below are reached through the user's configured **protected HTTPS
site root**, for example `https://app.example.com`. Never send these tokens to
the management domain, another saved site, an arbitrary redirect target, or
an application upstream. A client must disable cross-origin redirects for
credential-bearing requests. Use the returned absolute verification URL only
for the human browser/QR flow.

Gate still listens on loopback behind a trusted TLS-terminating proxy.
`Host` must be overwritten by that proxy to the exact configured public site.
Gate uses `r.Host`, not `Forwarded`, `X-Forwarded-Host`, or body parameters, as
the resource binding. The management host is explicitly excluded from device
resources. Do not expose the private listener or share it with untrusted local
tenants. Gate cannot independently prove TLS on a loopback proxy connection.
Keep default-vhost rejection, HTTPS, exact host routing and body/header limits.

See [the illustrative Nginx configuration](../deploy/nginx-device.conf).
It adds only the three exact public OAuth endpoints. The human approval,
Passkey ceremonies and management routes retain Gate's existing human-cookie,
CSRF, host/origin and required-UV checks. A device `Authorization` header on
human routes is rejected even if a valid human cookie is also present.
Do not clear that header on requests sent to Gate. Clear it only before
proxying an already-authorized application request to the application.

## Requests and common responses

All three protocol endpoints accept **POST** with
`Content-Type: application/x-www-form-urlencoded`, parameters in the body only:

| Value | Contract |
| --- | --- |
| `client_id` | Required, exactly `cockpit-dashboard`, public/non-secret |
| `scope` | Exactly `host-access`; required at device authorization |
| Body limit | 4096 bytes; each decoded parameter at most 512 bytes |
| Duplicate parameters | `400 {"error":"invalid_request"}` |
| Unknown parameters | Ignored; never used as host/redirect/client authority |
| Wrong/missing client | `400 {"error":"invalid_client"}` |
| Unsupported scope | `400 {"error":"invalid_scope"}` |
| Unsupported grant | `400 {"error":"unsupported_grant_type"}` |
| Missing grant/required grant credential | `400 {"error":"invalid_request"}` |
| Client secrets/HTTP Authorization | Not accepted on protocol endpoints |
| Caching | `Cache-Control: no-store`, `Pragma: no-cache` |

Malformed encoding, wrong content type, query parameters, duplicate parameters
and oversized input produce `invalid_request`. JSON error bodies use the
OAuth `error` field, not a human-readable message in that field. Unknown
hosts fail closed with HTTP 421; the management resource is rejected with
HTTP 400 `invalid_target` (a documented product error).
No CORS support is provided for browser JavaScript clients.

### 1. Request a device authorization

```http
POST /_gate/oauth/device_authorization
Content-Type: application/x-www-form-urlencoded

client_id=cockpit-dashboard&scope=host-access
```

Successful HTTP 200 JSON:

```json
{
  "device_code": "<opaque secret>",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://auth.example.com/_gate/device",
  "verification_uri_complete": "https://auth.example.com/_gate/device?user_code=ABCD-EFGH",
  "expires_in": 300,
  "interval": 5
}
```

`device_code` is an independently generated 256-bit secret, encoded as a
43-character unpadded base64url string. `user_code` has eight uniformly sampled
characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (40 bits), displayed `XXXX-XXXX`.
Only their SHA-256 hashes are persisted. Do not encode `device_code`, access
tokens or refresh tokens in QR codes, URLs, logs, analytics, or clipboard prompts.
The QR contains only `verification_uri_complete`; also show the short code and
resource host on the initiating device.

The human opens the Auth-domain page and signs in using the existing Passkey
login. Merely opening the QR or having a cookie does **not** approve anything.
The review page identifies the resource site, client, scope and short code.
The human must compare and retype the code shown by their own device, explicitly
select **Approve with Passkey**, and complete a new UV-required assertion bound
to that particular code and human session. Approval is single-use and
transactional. Denial requires a human session and CSRF but no new assertion.
Fresh assertions and explicit confirmation do not eliminate social engineering:
users must never approve an unexpected request initiated by somebody else.

### 2. Poll the token endpoint

```http
POST /_gate/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=<secret>&client_id=cockpit-dashboard
```

Wait at least `interval` seconds before the first poll and between subsequent
polls. RFC 8628 errors use HTTP **400**:

| Error | Client action |
| --- | --- |
| `authorization_pending` | Continue after the current interval |
| `slow_down` | Permanently add 5 seconds to the interval for this authorization |
| `access_denied` | Stop; the human denied/revoked the request |
| `expired_token` | Stop; start a new authorization only on a new user action |
| `invalid_grant` | Stop; unknown, malformed, wrong-host or already-consumed code |

Early polling also slows down an already-approved request. There is no second
issuance or response-recovery mechanism for consumed device codes. If a token
response is lost, do not claim the same grant can be retrieved again.
Expired-code tombstones last up to 24 hours after expiry and may be evicted
earlier under capacity pressure; subsequently an expired code is unknown
(`invalid_grant`).

Success, HTTP 200:

```json
{
  "access_token": "<opaque secret>",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "<opaque secret>",
  "scope": "host-access"
}
```

Both token types have independent 256-bit entropy and only hashes are stored.
Access-token lifetime is 900 seconds. The family lifetime is exactly 30 days
from initial issuance. Neither usage nor refresh extends that deadline.

### 3. Access the protected site

Send `Authorization: Bearer <access_token>` to the same configured site root.
The existing `/_gate/check` authorization subrequest checks scope, client,
resource host, access expiry, absolute family expiry and family revocation.
A supplied malformed/expired/revoked/wrong-host bearer returns HTTP 401 with
`WWW-Authenticate: Bearer realm="passkey-gate", error="invalid_token"`.
It never falls back to a human cookie. The proxy must preserve this response
rather than turn it into a successful HTML sign-in page.

Bearer credentials have no access to `auth.example.com`, registration,
Passkey management, device approval or session management. Human-cookie
requests without Authorization continue to work as before.

### 4. Refresh

```http
POST /_gate/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<secret>&client_id=cockpit-dashboard
```

The optional `scope` must be exactly `host-access`; omission retains it.
Success has the same fields as initial issuance. `expires_in` is normally
900 and is shortened if fewer than 900 seconds remain in the family.
Every success consumes the old refresh token and returns a new one atomically.
Reusing a consumed refresh token on its bound host revokes the **entire
family**, including access tokens and the newest refresh token, and returns
`invalid_grant`. Concurrent refreshes are therefore a client bug, not a safe
retry strategy. Serialize refresh per stored device identity and atomically
replace local credentials. Start renewal shortly before access expiry; do not
blindly retry an uncertain refresh response. Reauthenticate on an unrecoverable
credential state. Old access tokens remain valid until expiry or family
revocation; they are not individually refreshed.

### 5. Revoke

```http
POST /_gate/oauth/revoke
Content-Type: application/x-www-form-urlencoded

client_id=cockpit-dashboard&token=<refresh-token>&token_type_hint=refresh_token
```

Success is HTTP 200 with an empty body, including unknown or already-revoked
tokens (RFC 7009). Both access and refresh tokens can revoke their bound family;
unrecognized hints are ignored. Wrong-host credentials reveal nothing and do
not revoke the other host's family. The human management page lists active
families by site, ID and creation/absolute-expiry times and can revoke each.
**Revoke all sessions and devices**, or deleting a Passkey, also revokes all
device families and denies outstanding unconsumed grants. Logging out one
human browser session does not revoke devices.

## Persistence, capacity and abuse controls

All grant state, poll timestamps and intervals, token hashes, consumed refresh
tombstones, revocations, absolute expirations and protocol rate windows are in
the existing SQLite database. Mutating multi-step operations acquire the
SQLite write lock before state reads and commit as one transaction, including
across separate database handles. Existing schema-version-1 databases receive
additive `device_*` tables on startup; no existing browser tables are replaced.
Passkey challenges remain short-lived, one-use in-memory flows as before;
restart requires a new browser assertion, not a new approval inferred from a cookie.

Product defaults (not RFC-mandated values):

| Limit | Default |
| --- | --- |
| Codes / initial polling interval | 300 seconds / 5 seconds |
| Access / absolute family lifetime | 900 seconds / 30 days |
| Device-authorize requests | 60 per minute, instance-wide |
| Token requests (all clients/hosts) | 600 per minute, instance-wide |
| Revoke requests | 120 per minute, instance-wide |
| Authenticated short-code lookups | 30 per minute, instance-wide |
| Approval attempts / denials | 30 per minute, instance-wide |
| Retained device grants | 1024 |
| Retained families (including revoked) | 1024 |
| Token records per family | 4096, including consumed-refresh tombstones |

Global rate exhaustion is HTTP 429 `temporarily_unavailable` with
`Retry-After: 60`. Capacity exhaustion is HTTP 503 `temporarily_unavailable`.
Neither condition means a refresh succeeded. These aggregate limits deliberately
avoid trusting spoofable forwarded IPs or distributing limits by attacker-
supplied client IDs. A shared instance can experience denial of service under
abuse; deploy additional trusted-edge connection/request limits. They do not
replace per-code RFC polling enforcement. Short-code failures do not reveal
whether a code was approved, denied or expired, and only an authenticated owner
can look them up.

Expired grant records are pruned after the tombstone window, or earlier when
the retained-grant capacity is reached so they cannot block new authorizations;
expired families
and their tokens and expired access tokens are cleaned during issuance/refresh.
Consumed refresh hashes are retained until family expiry for replay detection.
No unbounded background queue or extra database is introduced. SQLite file
pages can retain their high-water allocation; cleanup bounds live rows, not
on-disk compaction. Audit events include only operation, resource host or
family ID, never codes, token hashes, raw tokens, assertions or request bodies.
Ensure proxy/application logging does not reintroduce these values.

## Dependencies and standard scope

No additional Go dependency is added. Existing `net/http` and modernc SQLite
keep the state machine and transactional boundary together. The presence of an
indirect JWT dependency for WebAuthn is not a reason to issue JWT device tokens.

Primary upstream-source evaluation:

- `go-oauth2/oauth2` v4.6.0
  [grant whitelist](https://github.com/go-oauth2/oauth2/blob/e444dfa1af98b5e2d4d9ff5dbb0747ad9e82c218/const.go#L22-L44)
  does not implement RFC 8628. Its
  [store interface](https://github.com/go-oauth2/oauth2/blob/e444dfa1af98b5e2d4d9ff5dbb0747ad9e82c218/store.go#L12-L34)
  is not a device/approval/polling store.
- Fosite's inspected source commit `a5f0b09bf31c17297b25637bb3fec2ff7a55b159`
  has [real server-side device factories](https://github.com/ory/fosite/blob/a5f0b09bf31c17297b25637bb3fec2ff7a55b159/compose/compose_rfc8628.go#L14-L36),
  but they are not in the inspected latest published v0.49.0 release.
  Durable [device storage](https://github.com/ory/fosite/blob/a5f0b09bf31c17297b25637bb3fec2ff7a55b159/handler/rfc8628/storage.go#L13-L35)
  and [transactions](https://github.com/ory/fosite/blob/a5f0b09bf31c17297b25637bb3fec2ff7a55b159/storage/transactional.go#L8-L35)
  still need integration, and its default
  [polling limiter returns false](https://github.com/ory/fosite/blob/a5f0b09bf31c17297b25637bb3fec2ff7a55b159/handler/rfc8628/strategy_hmacsha.go#L94-L97).
- `golang.org/x/oauth2`
  [DeviceAuth/DeviceAccessToken](https://github.com/golang/oauth2/blob/c624b89dadc3221560b7345c090bbe69e90808ee/deviceauth.go)
  are **client** operations, not an authorization server.

This implementation deliberately supports only the agreed device/refresh
profile. It is not a claim of OAuth/OIDC certification or implementation of
every optional feature. Review applicable
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) bearer-token and refresh-replay
considerations before production adoption.

## Synthetic interoperability material

[`testdata/device-wire-v1.json`](../testdata/device-wire-v1.json) contains fixed,
non-live protocol examples for App parsers/state-machine tests. Its example
secrets are public synthetic placeholders and must never be seeded into a
running database. `internal/gate/device_test.go` generates ephemeral ES256
keys in memory and signs real assertions against the actual WebAuthn verifier.
It exercises human login, missing CSRF, wrong confirmation, wrong origin,
missing UV, explicit approval, ceremony replay, token issuance, rotation,
revocation, management rejection and cookie compatibility. Store tests cover
restart, polling, expiry, capacity, cross-handle concurrent consumption and
refresh-replay family revocation without real hosts or credentials.

Before deployment: obtain separate deployment authorization, back up the
database, review the proxy boundary and limits, configure the actual HTTPS
allowlists out of band, and exercise the App against a disposable Gate instance.
This PR does not install binaries, merge, release, edit production configuration,
restart services, migrate a live database, or operate a real Passkey.
