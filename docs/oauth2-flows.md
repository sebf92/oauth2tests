# OAuth2 / OIDC Flows — Detailed Guide

## What is OAuth2?

OAuth2 (RFC 6749) is an **authorisation framework** — not an authentication protocol.
It defines how an application can obtain limited access to a resource on behalf of a user
(or on its own behalf) without sharing the user's credentials.

Key actors:
| Role | In this demo |
|---|---|
| **Resource Owner** | The human user (alice, bob, charlie) |
| **Client** | The Flask Client App (`:5000`) |
| **Authorisation Server** | Keycloak (`:8080`) |
| **Resource Server** | The FastAPI API (`:8001`) |

This demo implements **eleven flows** across four categories:

| # | Flow | RFC |
|---|------|-----|
| 1 | Authorization Code | RFC 6749 §4.1 |
| 2 | Resource Owner Password Credentials (ROPC) | RFC 6749 §4.3 |
| 3 | Client Credentials | RFC 6749 §4.4 |
| 4 | On-Behalf-Of (Token Exchange) | RFC 8693 |
| 5 | Token Rescoping (Token Exchange) | RFC 8693 |
| 6 | SPIFFE Workload Identity (RFC 7523 private_key_jwt) | SPIFFE / RFC 7523 |
| 7 | OIDC Identity Layer | OpenID Connect Core |
| 8 | DPoP — Proof of Possession | RFC 9449 |
| 9 | Device Authorization Grant | RFC 8628 |
| 10 | PKCE — Proof Key for Code Exchange | RFC 7636 |
| 11 | Token Introspection | RFC 7662 |

---

## Flow 1 — Authorization Code

**When to use:** Any web application where a human user must log in.

### Flow diagram

```
Client App                 Keycloak                  Browser
    │                          │                          │
    │◀─── User clicks Login ───────────────────────────── │
    │                          │                          │
    │ Build auth URL           │                          │
    │ ?response_type=code      │                          │
    │ &client_id=demo-client   │                          │
    │ &redirect_uri=...        │                          │
    │ &scope=openid profile    │                          │
    │ &state=<random>          │                          │
    │ &nonce=<random>          │                          │
    │ ──────────────────────────────────────────────────▶ │
    │              302 Redirect to Keycloak login page    │
    │                          │◀────────────────────── GET│
    │                          │ ──────────────────────▶  │
    │                          │    Login form             │
    │                          │◀── POST credentials ──── │
    │                          │                          │
    │                          │ Validate credentials      │
    │                          │ Generate auth code        │
    │                          │ ──── 302 /callback ─────▶ │
    │◀─────────────────── GET /callback?code=X&state=Y ── │
    │                          │                          │
    │ Verify state == session  │                          │
    │ POST /token              │                          │
    │   grant_type=authorization_code                     │
    │   code=X                 │                          │
    │   client_secret=***      │                          │
    │ ────────────────────────▶│                          │
    │◀─── {access_token, id_token, refresh_token} ────── │
    │                          │                          │
    │ Store tokens in session  │                          │
    │ ──────────────────────────────────────────────────▶ │
    │              200 Home page (user is logged in)      │
```

### What gets exchanged

**Step 1 — Authorisation URL** (browser redirect):
```
GET http://localhost:8080/realms/demo/protocol/openid-connect/auth
  ?client_id=demo-client
  &redirect_uri=http://localhost:5000/auth/callback
  &response_type=code
  &scope=openid profile email roles
  &state=<random-csrf-token>
  &nonce=<random-replay-protection>
```

**Step 2 — Code exchange** (server-side, never in browser):
```
POST http://keycloak:8080/realms/demo/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&client_id=demo-client
&client_secret=demo-client-secret
&redirect_uri=http://localhost:5000/auth/callback
&code=<authorisation-code>
```

**Response:**
```json
{
  "access_token":  "<JWT>",
  "id_token":      "<JWT>",
  "refresh_token": "<opaque or JWT>",
  "token_type":    "Bearer",
  "expires_in":    1800,
  "scope":         "openid profile email roles"
}
```

### Security features

| Feature | Mechanism |
|---|---|
| CSRF protection | `state` parameter — random value set in session, verified in callback |
| Replay protection | `nonce` claim inside the JWT |
| Secret not exposed | Token exchange is server-side; the browser only sees the short-lived code |
| Code is one-time-use | Keycloak rejects the code after first use |

---

## Flow 2 — Resource Owner Password Credentials (ROPC)

**When to use:** Scripting, testing, CLI tools. **Avoid in production web apps.**

### Flow

```
Client App               Keycloak
    │                        │
    │ POST /token            │
    │   grant_type=password  │
    │   username=alice       │
    │   password=alice123    │
    │   client_id=...        │
    │   client_secret=...    │
    │ ──────────────────────▶│
    │◀── {access_token, ...} │
```

### Request

```
POST http://localhost:8080/realms/demo/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=password
&client_id=demo-client
&client_secret=demo-client-secret
&username=alice
&password=alice123
&scope=openid profile email roles
```

### Why it is legacy

- The client application **sees the user's password** — breaks separation of concerns.
- No support for MFA or external identity providers.
- OAuth2 Security Best Current Practice (RFC 9700) recommends avoiding ROPC.
- Keycloak disables it by default; `directAccessGrantsEnabled: true` must be set explicitly.

---

## Flow 3 — Client Credentials

**When to use:** Microservice-to-microservice communication. No user is involved.

### Flow

```
Service A                Keycloak               Service B (resource server)
    │                        │                          │
    │ POST /token            │                          │
    │   grant_type=          │                          │
    │     client_credentials │                          │
    │   client_id=           │                          │
    │     service-client     │                          │
    │   client_secret=***    │                          │
    │ ──────────────────────▶│                          │
    │◀── {access_token}      │                          │
    │                        │                          │
    │ GET /api/products      │                          │
    │ Authorization: Bearer <token>                     │
    │ ──────────────────────────────────────────────────▶
    │◀───────────────────────────────────────────────── │
    │                      200 {products}               │
```

### Request

```
POST http://localhost:8080/realms/demo/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=service-client
&client_secret=service-client-secret
&scope=openid profile roles
```

### Token differences vs. user tokens

| Claim | User token | Service account token |
|---|---|---|
| `sub` | User UUID | Service account UUID |
| `preferred_username` | `alice` | `service-account-service-client` |
| `email` | User's email | Not present |
| `realm_access.roles` | User's roles | Service account roles |
| `session_state` | SSO session ID | Not present (no session) |
| `id_token` | Present | **Not present** |
| `refresh_token` | Present | **Not present** |

---

## Flow 4 — On-Behalf-Of / Token Exchange (RFC 8693)

**When to use:** A middle-tier service needs to call a downstream API *on behalf of* a user,
preserving the user's identity in the delegated token while the acting client changes.

### Prerequisites

- `standard.token.exchange.enabled = true` set on `middle-tier-client` (done by `keycloak-init`
  at startup via the Admin REST API — KC 26.2+ GA, no feature flags required)
- `middle-tier-client` in the `aud` claim of the subject token (configured via audience mapper
  in `realm-export.json`)

### Flow

```
User (Alice)           Client App          middle-tier-client        Keycloak
     │                     │                       │                     │
     │  Login (Auth Code)  │                       │                     │
     │────────────────────▶│                       │                     │
     │◀─── access_token ───│                       │                     │
     │   (sub=alice,       │                       │                     │
     │    aud=[demo-client, │                       │                     │
     │    middle-tier-client])                      │                     │
     │                     │                       │                     │
     │  Request OBO        │                       │                     │
     │────────────────────▶│                       │                     │
     │                     │  POST /token          │                     │
     │                     │  grant_type=token-exchange                  │
     │                     │  subject_token=<alice's token>              │
     │                     │  actor=middle-tier-client                   │
     │                     │  client_secret=***    │                     │
     │                     │──────────────────────────────────────────▶  │
     │                     │◀────────── delegated access_token ──────────│
     │                     │  (sub=alice, azp=middle-tier-client)        │
     │◀────────────────────│                       │                     │
```

### Request

```
POST http://keycloak:8080/realms/demo/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&client_id=middle-tier-client
&client_secret=middle-tier-client-secret
&subject_token=<alice's access token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
```

### Delegated token claims

| Claim | Subject token | Delegated token |
|---|---|---|
| `sub` | Alice's UUID | Alice's UUID (preserved) |
| `azp` | `demo-client` | `middle-tier-client` |
| `aud` | `[account]` | `[account]` |
| `act` | Not present | `{"sub": "middle-tier-client"}` |

The `sub` (Alice's identity) is preserved, but `azp` and `act` show that `middle-tier-client`
performed the exchange. This creates an auditable delegation chain.

---

## Flow 5 — Token Rescoping (RFC 8693)

**When to use:** A middle-tier service wants to forward a *weaker* token downstream, removing
roles that the downstream service does not need (least-privilege principle).

Same grant type as OBO, but adds `scope` to restrict the resulting token:

```
POST http://keycloak:8080/realms/demo/protocol/openid-connect/token

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&client_id=middle-tier-client
&client_secret=middle-tier-client-secret
&subject_token=<alice's token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
&scope=openid profile email
```

The downscoped token inherits `sub` from Alice but contains only the requested scopes, not
her `admin-role`. The downstream service cannot use it for admin operations even if compromised.

---

## Token Refresh

Access tokens are short-lived (30 minutes in this demo). When they expire, the client can
obtain a new access token using the refresh token — without asking the user to log in again.

```
POST http://keycloak:8080/realms/demo/protocol/openid-connect/token

grant_type=refresh_token
&client_id=demo-client
&client_secret=demo-client-secret
&refresh_token=<refresh-token>
```

The response contains a fresh `access_token` (and usually a new `refresh_token`).

Refresh tokens are **not available** in the Client Credentials flow.

---

## Flow 7 — OIDC Identity Layer

**What it adds:** OpenID Connect sits on top of OAuth2 and adds a standardised identity layer.

### Three OIDC-specific artefacts

| Artefact | Endpoint | Purpose |
|----------|----------|---------|
| `id_token` | Included in token response | JWT for the **client** — proves who the user is |
| UserInfo | `GET /userinfo` + `Authorization: Bearer` | Live user profile claims from the IdP |
| Discovery | `GET /.well-known/openid-configuration` | Endpoint autodiscovery for clients |

### id_token vs access_token

| | `id_token` | `access_token` |
|---|---|---|
| Audience | The client application | Resource servers |
| Purpose | Authentication (who is the user?) | Authorisation (what can the bearer do?) |
| Send to APIs? | **No** — send only to the client | **Yes** — included in every API call |
| Contains | `sub`, `email`, `name`, `nonce` | `realm_access.roles`, `azp`, `scope` |

The `id_token` is verified by the client using Keycloak's JWKS public key, then discarded —
it is never forwarded to the resource server.

---

## Flow 8 — DPoP — Demonstrating Proof of Possession (RFC 9449)

**When to use:** High-value APIs where stolen Bearer tokens must be worthless to an attacker.

### The problem with Bearer tokens

A stolen `Authorization: Bearer <token>` header can be replayed by anyone, anywhere.
DPoP binds the token to an ephemeral key pair — the token is useless without the private key.

### How DPoP works

```
Client                               Keycloak
  │                                      │
  │  1. Generate ephemeral EC P-256 key  │
  │     compute JWK thumbprint (jkt)     │
  │                                      │
  │  2. Build DPoP proof JWT:            │
  │     { htu, htm, iat, jti }           │
  │     signed with private key          │
  │                                      │
  │  POST /token                         │
  │  DPoP: <proof JWT>                   │
  │  grant_type=password                 │
  │  client_id=dpop-client               │
  │──────────────────────────────────────▶
  │◀── access_token                      │
  │    token_type: DPoP                  │
  │    cnf.jkt: <thumbprint>             │
  │                                      │
  │  3. Build second proof for API call  │
  │     includes ath (access token hash) │
  │                                      │
  │  GET /api/dpop-protected             │
  │  Authorization: DPoP <access_token>  │
  │  DPoP: <proof JWT #2>                │
  │──────────────────────────────────────────────────────▶ Resource Server
  │                                                         verifies cnf.jkt
  │                                                         verifies proof sig
  │◀────────────────────────────────────────────────────── 200 OK
```

### Key fields in the DPoP proof JWT

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { /* public key inline */ }
}
{
  "htm": "POST",
  "htu": "http://keycloak:8080/.../token",
  "iat": 1718000000,
  "jti": "<unique per request>"
}
```

For resource server calls, the proof additionally includes:
```json
{
  "ath": "<base64url(SHA-256(access_token))>"
}
```

### Keycloak requirement

DPoP binding on Password Grant (and all grant types) requires **Keycloak 26.4+** (GA; no
feature flags needed). Earlier versions silently ignored the `DPoP` header and issued a
plain Bearer token.

---

## Flow 9 — Device Authorization Grant (RFC 8628)

**When to use:** Smart TVs, CLIs, IoT devices — any client that cannot display a browser
or handle redirects.

### Flow

```
Device                    Keycloak              User's Browser
  │                           │                       │
  │ POST /auth/device         │                       │
  │   client_id=device-client │                       │
  │   client_secret=...       │                       │
  │──────────────────────────▶│                       │
  │◀── {device_code,          │                       │
  │     user_code: XXXX-YYYY, │                       │
  │     verification_uri,     │                       │
  │     expires_in, interval} │                       │
  │                           │                       │
  │ display user_code         │                       │
  │ to user                   │                       │
  │                           │  User opens           │
  │                           │  verification_uri ────▶
  │                           │  enters XXXX-YYYY     │
  │                           │  logs in              │
  │                           │◀──────────────────────│
  │                           │  grants consent       │
  │                           │◀──────────────────────│
  │                           │                       │
  │ POST /token (polling)     │                       │
  │   grant_type=device_code  │                       │
  │   device_code=...         │                       │
  │──────────────────────────▶│                       │
  │◀── {access_token, ...}    │ (after user approves) │
```

### Error codes during polling

| Error | Meaning | Action |
|---|---|---|
| `authorization_pending` | User has not approved yet | Wait `interval` seconds, retry |
| `slow_down` | Polling too fast | Add 5 s to interval, retry |
| `expired_token` | Device code expired | Request a new code |
| `access_denied` | User rejected | Stop polling, notify user |

The demo's `/auth/device/poll` AJAX endpoint handles these states and updates the UI in real time.

---

## Flow 10 — PKCE — Proof Key for Code Exchange (RFC 7636)

**When to use:** Public clients (SPAs, mobile apps, native apps) that cannot safely hold a
`client_secret`.

### The problem PKCE solves

In the standard Authorization Code flow, a `client_secret` proves that the token request
came from the legitimate client. Public clients cannot keep secrets (the secret would be
visible in source code or decompiled binaries). PKCE replaces the secret with a
cryptographic binding generated fresh for each flow.

### The math

```
code_verifier  = 32 cryptographically-random bytes, base64url-encoded (no padding)
code_challenge = BASE64URL(SHA-256(ASCII(code_verifier)))
```

### Flow

```
Client (public)                    Keycloak
    │                                  │
    │ 1. Generate code_verifier        │
    │    compute code_challenge        │
    │                                  │
    │ GET /auth                        │
    │   response_type=code             │
    │   client_id=pkce-client          │
    │   code_challenge=<hash>          │
    │   code_challenge_method=S256     │
    │──────────────────────────────────▶
    │    (Keycloak stores the challenge)
    │◀── 302 /callback?code=X ─────────│
    │                                  │
    │ POST /token                      │
    │   grant_type=authorization_code  │
    │   code=X                         │
    │   client_id=pkce-client          │
    │   code_verifier=<original>       │
    │   (no client_secret)             │
    │──────────────────────────────────▶
    │   Keycloak: SHA-256(verifier)    │
    │             must match stored    │
    │             challenge            │
    │◀── {access_token, ...} ──────────│
```

The intercepting attacker who stole the authorization code does not know the `code_verifier`
and cannot complete the exchange.

### Keycloak enforcement

`pkce-client` has `pkce.code.challenge.method: S256` set as a client attribute. Keycloak
**rejects** authorization code requests that omit `code_challenge` — PKCE is mandatory for
this client.

---

## Flow 11 — Token Introspection (RFC 7662)

**When to use:** Resource servers that need real-time revocation awareness, or auditing tools
that want authoritative token state from the authorization server.

### Local decode vs. introspection

| | Local JWT decode | RFC 7662 Introspection |
|---|---|---|
| Network call | No | Yes (POST to `/introspect`) |
| Verifies signature | Yes | Yes (done by KC) |
| Detects revocation | **No** — JWT is still valid locally | **Yes** — `active: false` |
| Speed | Very fast | Adds one network round trip |
| Best for | Every API call (performance) | Logout, revocation, audit paths |

### Request

```
POST http://keycloak:8080/realms/demo/protocol/openid-connect/token/introspect
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

token=<access_token>
```

### Response

```json
{
  "active": true,
  "sub": "564fc7e2-...",
  "exp": 1718000000,
  "iat": 1717999700,
  "username": "alice",
  "realm_access": { "roles": ["admin-role", "user-role"] },
  "scope": "openid profile email roles"
}
```

After revocation (e.g., revoking the refresh token):

```json
{ "active": false }
```

### What the demo shows

1. Get a fresh access token via Client Credentials.
2. Introspect → `active: true` with full claims.
3. Revoke the refresh token (simulates logout).
4. Introspect again → `active: false`.
5. Decode the same JWT locally → still shows a valid-looking payload.

This proves that local JWT decode cannot detect revocation — only introspection can.

---

## JWT Validation in detail

The Resource Server performs the following checks on every request:

```python
# 1. Fetch public keys from Keycloak JWKS endpoint (cached)
jwks_client = PyJWKClient("http://keycloak:8080/realms/demo/protocol/openid-connect/certs")

# 2. Match the token's kid to a public key
signing_key = jwks_client.get_signing_key_from_jwt(token)

# 3. Verify signature, issuer, and expiry
payload = jwt.decode(
    token,
    signing_key.key,
    algorithms=["RS256"],
    issuer="http://localhost:8080/realms/demo",
    options={"verify_exp": True, "verify_iss": True},
)

# 4. Role check (for protected endpoints)
roles = payload["realm_access"]["roles"]
if "admin-role" not in roles:
    raise HTTPException(status_code=403)
```

### Why RS256 (asymmetric) and not HS256 (symmetric)?

| | RS256 | HS256 |
|---|---|---|
| Keys | Private key (sign) + Public key (verify) | Single shared secret |
| Who can sign | Only Keycloak (has private key) | Anyone with the secret |
| Key distribution | Public key via JWKS endpoint (open) | Secret must be shared securely |
| Key rotation | Add new key to JWKS, keep old one briefly | Must update all services simultaneously |
| **Verdict** | **Preferred for distributed systems** | Simple but requires secret sharing |

With RS256, the Resource Server never needs a secret — it just fetches the public JWKS.
New resource servers can be added without any Keycloak configuration change.

---

## OpenID Connect (OIDC)

This demo uses OAuth2 + **OpenID Connect**, which adds identity on top of OAuth2:

- The `openid` scope requests an `id_token` alongside the `access_token`
- The `id_token` is a JWT containing user identity claims (`sub`, `email`, `name`, etc.)
- The `id_token` is for the **client** — it should not be sent to resource servers
- The `access_token` is for **resource servers** — it carries authorisation information

In practice, the distinction matters: an OIDC `id_token` proves *who* the user is,
while an OAuth2 `access_token` grants *what* the bearer can do.

The `/auth/oidc` demo in this project shows all three OIDC artefacts side by side:
the decoded `id_token`, the live `/userinfo` response, and the Discovery document.
