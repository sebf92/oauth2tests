# OAuth2 + JWT with Keycloak — Learning Demo

A fully containerised environment to understand how **OAuth2**, **OIDC**, **JWT**, **SPIFFE/SPIRE**,
and **Keycloak** work together. Eleven flows are demonstrated end-to-end, from browser login and
device authorization through workload identity to proof-of-possession and token introspection.

---

## Architecture overview

```
Browser / curl
     │
     ▼
┌──────────────────────────────────────┐        ┌──────────────────────────────┐
│   Client App  (Flask :5000)          │──JWT──▶│   Resource Server            │
│                                      │        │   FastAPI :8001              │
│ 1.  Authorization Code               │        │                              │
│ 2.  Password Grant (ROPC)            │        │ GET /api/public   (open)     │
│ 3.  Client Credentials               │        │ GET /api/products (any token)│
│ 4.  On-Behalf-Of (RFC 8693)          │        │ GET /api/users/me (user-role)│
│ 5.  Token Rescoping (RFC 8693)       │        │ GET /api/users    (admin)    │
│ 6.  SPIFFE / Workload Identity       │        │ GET /api/admin/*  (admin)    │
│ 7.  OIDC Identity Layer              │        │ GET /api/dpop-protected      │
│ 8.  DPoP (RFC 9449)                  │        └──────────────┬───────────────┘
│ 9.  Device Authorization (RFC 8628)  │                       │ JWKS fetch
│ 10. PKCE (RFC 7636)                  │                       ▼
│ 11. Token Introspection (RFC 7662)   │        ┌─────────────────────────────────────────┐
└──────┬───────────────────────────────┘        │   Keycloak :8080   (realm: demo)         │
       │ token exchange / API calls             │                                          │
       ▼                                        │ • Issues JWT access tokens (RS256)       │
┌──────────────────────────────────────┐        │ • Manages users, roles, clients          │
│   Keycloak :8080   (realm: demo)     │        │ • RFC 8693 token exchange (GA, KC 26.2+) │
│   PostgreSQL :5432 (persistence)     │        │ • DPoP enforcement (RFC 9449)            │
└──────────────────────────────────────┘        │ • Device Authorization Grant (RFC 8628)  │
                                                │ • PKCE enforcement (RFC 7636)            │
                                                └──────────────────────────────────────────┘

SPIFFE / SPIRE stack (workload identity):

┌──────────────┐  gRPC :8081  ┌─────────────────┐   Workload API  ┌────────────────┐
│ spire-server │◄─────────────│  spire-agent     │────unix socket──│ spiffe-service │
│  CA/registry │              │  (attestation)   │                 │  FastAPI :8002 │
└──────────────┘              └─────────────────┘                 └────────────────┘
```

**Key networking rule:** the browser always talks to Keycloak via `http://localhost:8080`.
Server-side containers talk to each other via the Docker network (`http://keycloak:8080`).
`KC_HOSTNAME=localhost` ensures all JWT `iss` claims equal `http://localhost:8080/realms/demo`.

---

## Quick start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose v2)
- Ports **8080**, **8001**, **8002**, and **5000** free on your machine

### 1 — Start the stack

```bash
cd oauth2sample
docker compose up --build
```

First boot takes **3–5 minutes**: PostgreSQL initialises, Keycloak imports the realm and
generates RSA key pairs, SPIRE bootstraps its CA, and `keycloak-init` configures token
exchange permissions and provisions all clients via the Admin API.

Watch for all services to show `healthy` or `Exited (0)`:

```bash
docker compose ps
```

### 2 — Open the demo app

| Service | URL |
|---|---|
| **Client App** (Flask) | http://localhost:5000 |
| **Resource Server** (FastAPI docs) | http://localhost:8001/docs |
| **SPIFFE Service** — HTML UI | http://localhost:8002/ui |
| **SPIFFE Service** — API / Swagger | http://localhost:8002/docs |
| **Keycloak Admin Console** | http://localhost:8080/admin (`admin` / `admin`) |

### 3 — Try the flows

1. Open http://localhost:5000
2. Click **"Login with Authorization Code"** → log in as `alice` / `alice123`
3. Click **"Inspect Token"** to see the decoded JWT
4. Click any API button to see role-based access in action
5. Try **"On-Behalf-Of"** under Advanced Token Exchange
6. Click **"Run SPIFFE Demo"** to see workload identity without secrets
7. Try **"DPoP"** to see sender-constrained tokens with a proof-of-possession key
8. Try **"Device Authorization Grant"** to simulate a TV/CLI device flow
9. Try **"PKCE"** to see the public-client code exchange
10. Try **"Token Introspection"** to watch a token go from `active: true` to `active: false`
11. Log out, log in as `bob` / `bob123` (user-role only), try the admin endpoint → 403

---

## Test accounts

| Username | Password | Roles | Can access |
|---|---|---|---|
| `alice` | `alice123` | `admin-role`, `user-role` | Everything |
| `bob` | `bob123` | `user-role` | Products, /me, public |
| `charlie` | `charlie123` | _(none)_ | Public only |

**Service accounts** (no password — machine identity only):

| Client ID | Secret | Roles | Used for |
|---|---|---|---|
| `service-client` | `service-client-secret` | `user-role` | Client Credentials flow |
| `middle-tier-client` | `middle-tier-client-secret` | — | On-Behalf-Of exchange |
| `spiffe-service` | _(none — private_key_jwt)_ | `user-role` | RFC 7523 private_key_jwt workload identity |
| `dpop-client` | `dpop-client-secret` | — | DPoP bound tokens (Password Grant) |
| `device-client` | `device-client-secret` | — | Device Authorization Grant |
| `pkce-client` | _(none — public client)_ | — | PKCE Authorization Code |

---

## Flows Demonstrated

### 1. Authorization Code (recommended for web apps)

```
User → Client App → Keycloak login page → code → Client App → tokens
```

The browser never sees tokens directly. The short-lived code is exchanged server-side.
Includes `state` (CSRF) and `nonce` (replay) protection.

### 2. Resource Owner Password Credentials / ROPC (legacy)

```
username + password → POST /token → access_token
```

Credentials are sent directly to the token endpoint. Avoid in production; useful for
testing and scripting. Requires `directAccessGrantsEnabled: true` on the client.

### 3. Client Credentials (machine-to-machine)

```
client_id + client_secret → POST /token → access_token (no user)
```

The application authenticates as itself. Produces a service account token, not a user token.
No `id_token` or `refresh_token` in the response.

### 4. On-Behalf-Of / Token Exchange (RFC 8693)

```
User token + middle-tier-client credentials → POST /token → delegated token
```

`middle-tier-client` exchanges Alice's token for a new token scoped to itself, preserving
the user's identity (`sub`) while switching the acting client (`azp`). Standard Token Exchange
is GA in Keycloak 26.2+ — the `standard.token.exchange.enabled` attribute on `middle-tier-client`
is all that is needed; no feature flags or fine-grained permission policies required.

### 5. Token Rescoping (RFC 8693)

```
User token + middle-tier-client → POST /token (downscoped) → restricted token
```

A variant of token exchange that uses `scope` to request a token with fewer permissions than
the original, allowing middle-tier services to enforce least privilege on delegated tokens.

### 6. SPIFFE Workload Identity

```
SPIRE attests container → JWT-SVID → RFC 7523 private_key_jwt → access_token
```

`spiffe-service` proves its identity to the SPIRE agent using OS-level attributes (unix UID),
receives a short-lived JWT-SVID (~5 min), then authenticates to Keycloak via
**RFC 7523 `private_key_jwt`**: it signs a client assertion with an ephemeral EC key and
presents it to the token endpoint — no `client_secret` stored or transmitted anywhere.
Keycloak validates the assertion by fetching the service's own `GET /jwks` endpoint.
See [docs/spiffe-oauth2.md](docs/spiffe-oauth2.md) for details.

### 7. OIDC Identity Layer

```
id_token + UserInfo endpoint + Discovery document
```

Shows the three OIDC-specific artefacts that sit on top of OAuth2: the `id_token` JWT (for
the client, proves who the user is), the `/userinfo` endpoint (live profile claims), and the
`/.well-known/openid-configuration` Discovery document (endpoint autodiscovery).

### 8. DPoP — Proof of Possession (RFC 9449)

```
Ephemeral EC key → DPoP proof header → token with cnf.jkt → proof-bound API call
```

Generates an ephemeral P-256 key pair, binds it to the access token (`cnf.jkt` = JWK
Thumbprint), then calls the resource server with a second per-request DPoP proof. Even if
the token is stolen, it cannot be replayed without the private key. Requires Keycloak 26.4+
(DPoP is GA; no feature flags needed).

### 9. Device Authorization Grant (RFC 8628)

```
Device → /auth/device → user_code → user approves in browser → device polls → token
```

Browserless device flow for smart TVs, CLIs, or IoT devices. The device requests a code,
displays a `user_code` for the user to enter on a separate device, then polls until the user
approves. The demo shows real-time polling feedback.

### 10. PKCE — Proof Key for Code Exchange (RFC 7636)

```
code_verifier → SHA-256 → code_challenge → auth request → verifier proves ownership
```

Hardens the Authorization Code flow for public clients (SPAs, mobile apps) that cannot
safely hold a client secret. `pkce-client` is a public client (no secret); the
`code_verifier` takes the place of the client secret during the token exchange.

### 11. Token Introspection (RFC 7662)

```
POST /introspect → {active: true} → revoke refresh_token → POST /introspect → {active: false}
```

Demonstrates the difference between local JWT decode (signature-only) and remote introspection
(real-time revocation status from the authorization server). After the refresh token is revoked,
the access token still decodes locally but introspection returns `active: false`.

---

## JWT Validation (Resource Server)

Every protected endpoint performs these checks:

```
Authorization: Bearer <token>
                    │
          1. Split into header.payload.signature
          2. Decode header → get kid (Key ID)
          3. Fetch JWKS from Keycloak (cached)
          4. Find the public key matching kid
          5. Verify RS256 signature
          6. Check exp (not expired)
          7. Check iss == "http://localhost:8080/realms/demo"
          8. For role-protected routes: check realm_access.roles
```

If any check fails → **401 Unauthorized** or **403 Forbidden**.

---

## Keycloak Realm Configuration

The realm is auto-imported from [`keycloak/realm-export.json`](keycloak/realm-export.json)
on first boot. Post-import configuration (token-exchange permissions, client provisioning) is
handled by the `keycloak-init` container on every startup.

Keycloak version: **26.6.1** (`quay.io/keycloak/keycloak:26.6.1`)

| Setting | Value |
|---|---|
| Realm | `demo` |
| Token lifetime | 30 minutes |
| Signature algorithm | RS256 |
| Token Exchange | GA (KC 26.2+) — `standard.token.exchange.enabled = true` on `middle-tier-client` |
| DPoP | GA (KC 26.4+) — `dpop.bound.access.tokens = true` on `dpop-client` |

### Clients

| Client | Flow | Notes |
|---|---|---|
| `demo-client` | Auth Code + Password | Browser login and ROPC testing; confidential |
| `service-client` | Client Credentials | Machine-to-machine demo; confidential |
| `middle-tier-client` | Client Credentials | OBO / rescoping actor; confidential |
| `spiffe-service` | Client Credentials | RFC 7523 private_key_jwt workload identity; **no secret** |
| `dpop-client` | Password Grant (DPoP) | `dpop.bound.access.tokens: true`; confidential |
| `device-client` | Device Authorization Grant | `oauth2.device.authorization.grant.enabled: true`; confidential |
| `pkce-client` | Authorization Code + PKCE | `pkce.code.challenge.method: S256`; **public** (no secret) |

### Roles

| Role | Description |
|---|---|
| `admin-role` | Full access — all API endpoints |
| `user-role` | User-level access — `/api/products`, `/api/users/me` |

---

## Useful curl commands

```bash
# Get a token via Password Grant
TOKEN=$(curl -s -X POST http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d "grant_type=password&client_id=demo-client&client_secret=demo-client-secret" \
  -d "username=alice&password=alice123&scope=openid" \
  | jq -r .access_token)

# Call a protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/users/me

# Client Credentials
TOKEN=$(curl -s -X POST http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d "grant_type=client_credentials&client_id=service-client&client_secret=service-client-secret" \
  | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" http://localhost:8001/api/products

# Device Authorization Grant — step 1: request device code
curl -s -X POST http://localhost:8080/realms/demo/protocol/openid-connect/auth/device \
  -d "client_id=device-client&client_secret=device-client-secret" | jq .

# Device Authorization Grant — step 2: poll for token (replace DEVICE_CODE)
curl -s -X POST http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=device-client&client_secret=device-client-secret" \
  -d "device_code=DEVICE_CODE" | jq .

# Token Introspection
curl -s -X POST http://localhost:8080/realms/demo/protocol/openid-connect/token/introspect \
  -d "client_id=demo-client&client_secret=demo-client-secret" \
  -d "token=$TOKEN" | jq .active

# Decode token locally (without verification)
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# SPIFFE service — HTML UI (open in browser)
# http://localhost:8002/ui

# SPIFFE service demo endpoint (JSON)
curl http://localhost:8002/demo | jq .overall_success
```

---

## Stopping and resetting

```bash
# Stop containers (data preserved)
docker compose down

# Stop AND delete all data (full reset — re-imports realm on next boot)
docker compose down -v
```

After `docker compose down -v`, a clean `docker compose up --build` will:
1. Re-import the realm from `realm-export.json`
2. Run `keycloak-init` to configure token exchange, provision all clients, and assign roles
3. Bootstrap SPIRE (new CA keys, new join token)

---

## Troubleshooting

### "invalid_token" or 401 after starting

Keycloak may still be importing the realm. Wait 30 s and retry. Check with:

```bash
docker compose ps keycloak
```

### 401 with "Invalid token issuer"

The `iss` claim in your token does not match `KEYCLOAK_ISSUER` in the resource server.
Ensure `KC_HOSTNAME=localhost` is set in `docker-compose.yml` and restart Keycloak.

```bash
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .iss
# Should print: "http://localhost:8080/realms/demo"
```

### Service account has no roles (Client Credentials → 403)

The `keycloak-init` container configures service accounts on every boot. If it failed:

```bash
docker compose logs keycloak-init
```

To re-run it: `docker compose up keycloak-init`.

### DPoP demo shows "DPoP proof is missing" or no `cnf.jkt`

This requires **Keycloak 26.4+** (DPoP is GA; no feature flags needed). Check the image
in `docker-compose.yml`:

```bash
docker compose images keycloak
```

Keycloak 24.x silently ignores the DPoP header on Password Grant — upgrade to 26.4+.

### Device Authorization Grant — poll returns "expired"

Device codes expire after a few minutes. Reload `/auth/device` to get a fresh code.

### PKCE demo shows "invalid_grant"

The PKCE flow is session-bound. If you open `/auth/pkce/result` directly without going
through `/auth/pkce` first, the `code_verifier` is missing. Start from the home page card.

### SPIFFE demo shows error

Check all SPIRE containers are healthy and `spiffe-service` is running:

```bash
docker compose ps spire-server spire-agent spiffe-service
docker compose logs spiffe-service --tail 30
```

If `spire-agent` is unhealthy, check `docker compose logs spire-agent`. The agent needs
`spire-init` to complete first (writes the join token).

### Port conflict

Edit the `ports` section in `docker-compose.yml`. If you change the Keycloak port, also
update `KEYCLOAK_EXTERNAL_URL` and `KEYCLOAK_ISSUER` in the relevant services.

---

## Project structure

```
oauth2sample/
├── docker-compose.yml              # Full 10-service stack
├── keycloak/
│   └── realm-export.json           # Auto-imported realm (users, clients, roles)
├── keycloak-init/
│   ├── Dockerfile
│   └── setup.py                    # Provisions token-exchange + all demo clients
├── resource-server/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── main.py                     # FastAPI + JWT validation + DPoP endpoint
├── client-app/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py                      # Flask — all 11 OAuth2/OIDC flows
│   └── templates/
│       ├── base.html
│       ├── index.html
│       ├── password_grant.html
│       ├── api_result.html
│       ├── token_inspect.html
│       ├── token_exchange_obo.html
│       ├── token_exchange_rescope.html
│       ├── spiffe_demo.html
│       ├── dpop_demo.html
│       ├── oidc_demo.html
│       ├── device_demo.html
│       ├── pkce_demo.html
│       └── introspect_demo.html
├── spiffe-service/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── main.py                     # FastAPI — SPIFFE workload identity demo
├── spire/
│   ├── server/
│   │   └── server.conf             # SPIRE server configuration
│   ├── agent/
│   │   └── agent.conf              # SPIRE agent configuration
│   ├── init/
│   │   └── Dockerfile              # Alpine + spire-server binary (one-shot setup)
│   ├── agent-wrapper/
│   │   └── Dockerfile              # Alpine + spire-agent binary
│   ├── setup.sh                    # Creates join token + workload entry
│   └── agent-start.sh              # Waits for token, starts agent
└── docs/
    ├── architecture.md
    ├── oauth2-flows.md
    ├── obo-manual-setup.md
    └── spiffe-oauth2.md
```

---

## Further reading

- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 8693 — Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 9449 — DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 8628 — Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 7662 — Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [JSON Web Token RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [SPIFFE Specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md)
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [jwt.io](https://jwt.io) — online JWT decoder and verifier
