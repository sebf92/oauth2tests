# OAuth2 Grant Types — Detailed Guide

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

---

## Grant Type 1 — Authorization Code Flow

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

### Production additions

- **PKCE** (Proof Key for Code Exchange, RFC 7636): add `code_challenge` and `code_verifier`.
  Mandatory for public clients (SPAs, mobile apps) where there is no client secret.

---

## Grant Type 2 — Resource Owner Password Credentials (ROPC)

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

- The client application **sees the user's password** — breaks the separation of concerns.
- No support for MFA or external identity providers.
- OAuth2 Security Best Current Practice (RFC 9700) recommends avoiding ROPC.
- Keycloak disables it by default on new clients; it must be explicitly enabled
  (`directAccessGrantsEnabled: true`).

**Use case in this demo:** simplifies testing without browser redirects.

---

## Grant Type 3 — Client Credentials

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

## Grant Type 4 — On-Behalf-Of / Token Exchange (RFC 8693)

**When to use:** A middle-tier service needs to call a downstream API *on behalf of* a user,
preserving the user's identity in the delegated token while the acting client changes.

### Prerequisites

- `KC_FEATURES=preview` enabled on the Keycloak service (already in `docker-compose.yml`)
- Fine-grained permissions enabled on `demo-client` (done by `keycloak-init` at startup)
- `middle-tier-client` in the `aud` claim of the subject token (configured via audience mapper)

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

### Why the audience mapper matters

Keycloak refuses to exchange a token on behalf of a client that is not listed in the token's
`aud` claim. The audience mapper on `demo-client` injects `middle-tier-client` into Alice's
`aud` so the exchange can proceed. This prevents arbitrary middle-tier services from
impersonating users to downstream APIs they were never intended to reach.

---

## Token Refresh

Access tokens are short-lived. When they expire, the client can obtain a new access token
using the refresh token — without asking the user to log in again.

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
