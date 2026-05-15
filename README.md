# OAuth2 + JWT + Agentic AI with Keycloak — Learning Demo

A fully containerised environment to understand how **OAuth2**, **OIDC**, **JWT**,
**SPIFFE/SPIRE**, **MCP**, and **Keycloak** work together.

- **Eleven OAuth2 / OIDC flows** demonstrated end-to-end, from browser login and
  device authorization through workload identity to proof-of-possession and token
  introspection.
- **Five Agentic AI patterns** — four service-principal mechanisms (client
  secret, SPIFFE attestation, **SPIFFE + mTLS / RFC 8705**, X.509 certificate)
  and one user-delegated flow (RFC 8693 OBO + scope narrowing) — each backed by
  a real Model Context Protocol (MCP) server protected by Bearer JWT and the
  **Anthropic SDK** tool-use loop.

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

Agentic AI stack (MCP-authenticated AI agents):

                                                ┌────────────────────────────┐
                                                │  mcp-service :8003         │
                                                │  Real MCP Streamable HTTP  │
                                                │  Bearer JWT required       │
                                                │  Tools: list_products,     │
                                                │         get_product_details│
                                                └────────────▲───────────────┘
                                                             │ Authorization: Bearer
   ┌──────────────────┬────────────────┬───────────────┬─────┴──────────┬────────────────┐
   │                  │                │               │                │                │
┌──┴──────────────┐ ┌─┴────────────┐ ┌─┴──────────┐ ┌──┴─────────────┐ ┌┴────────────────┐
│ agent-secret    │ │ agent-spiffe │ │ agent-     │ │ agent-cert     │ │ agent-delegated │
│ :9001           │ │ :9002        │ │ spiffe-    │ │ :9003          │ │ :9004           │
│ UC1 ClientCreds │ │ UC2 SPIFFE   │ │ mtls :9005 │ │ UC3a X.509     │ │ UC4 OBO+Rescope │
│ (client_secret) │ │ (priv_key_   │ │ UC2-       │ │ (priv_key_jwt) │ │ (user-delegated)│
│                 │ │  jwt)        │ │ Hardened   │ │                │ │                 │
│                 │ │              │ │ (mTLS/8705)│ │                │ │                 │
└─────────────────┘ └──────────────┘ └─────┬──────┘ └────────────────┘ └─────────────────┘
                                           │ mTLS  ┌──────────────────────────────┐
                                           └─────▶│ keycloak-mtls-proxy :8443    │
                                                  │ nginx — terminates mTLS,     │
                                                  │ validates vs SPIRE CA bundle │
                                                  └──────────────────────────────┘
   Each agent: Anthropic SDK tool-use loop  (mock fallback when ANTHROPIC_API_KEY unset)
```

**Key networking rule:** the browser always talks to Keycloak via `http://localhost:8080`.
Server-side containers talk to each other via the Docker network (`http://keycloak:8080`).
`KC_HOSTNAME=localhost` ensures all JWT `iss` claims equal `http://localhost:8080/realms/demo`.

---

## Quick start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose v2)
- Ports **5000**, **8001**, **8002**, **8003**, **8080**, **8443**, **9000**,
  **9001**–**9005** free on your machine

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
| **Agentic AI section** | http://localhost:5000/agentic |
| **Documentation** | http://localhost:5000/docs |
| **Resource Server** (FastAPI docs) | http://localhost:8001/docs |
| **SPIFFE Service** — HTML UI | http://localhost:8002/ui |
| **MCP Service** — landing page | http://localhost:8003/ |
| **MCP Service** — RFC 9728 discovery | http://localhost:8003/.well-known/oauth-protected-resource |
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

### 4 — Try the Agentic AI section

1. Open http://localhost:5000/agentic
2. Click **"Run Agent"** under **UC1 — Client Secret** to see a service-principal
   agent obtain a token and call MCP tools (no login needed)
3. Click **UC2 SPIFFE** and **UC3a Certificate** to see two zero-secret patterns.
   Each renders the auth path, MCP discovery, and tool-use loop
4. Click **UC2-Hardened — SPIFFE + mTLS** to see the same SPIFFE identity used
   as a TLS client certificate (RFC 8705). The issued token carries `cnf.x5t#S256`
   — a cert-bound binding that makes a stolen token unreplayable
5. Log in as `alice`, then click **UC4 User-Delegated** → see the RFC 8693
   exchange diff: `sub=alice` preserved, scope narrowed, full custody chain
   surfaced both in the UI and in `docker logs oauth2-mcp-service`
6. Set `ANTHROPIC_API_KEY` in `.env` and restart agent containers to swap the
   mock loop for a real Claude tool-use loop

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

## Agentic AI — Authenticated MCP Access

Five patterns for AI agents accessing a protected **Model Context Protocol (MCP)** server.
The MCP server is real (official `mcp` Python SDK, Streamable HTTP transport) and the
Anthropic SDK drives a Claude tool-use loop; falls back to a deterministic mock when
`ANTHROPIC_API_KEY` is unset. See [docs/agentic-ai.md](docs/agentic-ai.md) for the deep dive.

### UC1 — Client Secret

```
client_id + client_secret → POST /token (scope=mcp) → access_token → MCP
```

The simplest pattern. A service principal uses static credentials to obtain a token
with `scope=mcp` and `aud=mcp-service`. Open `/agentic/client-secret` in the UI.

### UC2 — SPIFFE Workload Identity

```
SPIRE attests → in-memory EC key → RFC 7523 client_assertion → token → MCP
```

The agent runs as UID 1000 and is attested by SPIRE (selector `unix:uid:1000`).
An ephemeral EC key signs the `client_assertion`; Keycloak fetches the public
key from `agent-spiffe:9002/jwks` to verify. Zero static secrets anywhere.

### UC2-Hardened — SPIFFE + mTLS (RFC 8705)

```
SPIRE attests → X.509-SVID → mTLS handshake to nginx → Keycloak client-x509 → cert-bound token → MCP
```

Closes the cryptographic gap of UC2: the SVID issued by SPIRE is presented
**as the TLS client certificate** to a `keycloak-mtls-proxy` sidecar (nginx on
:8443). The proxy validates the chain against the SPIRE trust-domain bundle
and forwards the verified cert to Keycloak via the `ssl-client-cert` header.
Keycloak's `client-x509` authenticator matches the Subject DN and issues an
access token bound to that exact cert via the `cnf.x5t#S256` claim — a stolen
token cannot be replayed without the matching private key. The agent runs as
UID 1001 and the proxy as UID 1002, both attested by SPIRE.

### UC3a — X.509 Certificate

```
agent.key + agent.crt (from cert-init) → RFC 7523 client_assertion → token → MCP
```

The `cert-init` container generates a demo CA + agent certificate on first run.
The agent loads the cert + key at startup and signs RFC 7523 `client_assertion`
JWTs; its `/jwks` endpoint includes the cert chain (`x5c` + `x5t#S256`) so
Keycloak can verify the signature.

### UC4 — User-Delegated (OBO + Rescope)

```
alice logs in → user_access_token → RFC 8693 token exchange → narrowed delegated token → MCP
```

An authenticated user delegates a task to the agent. The agent performs a single
RFC 8693 token exchange that **preserves the user's identity (`sub`)** while
narrowing the scope to `mcp` only. The MCP server logs the full custody chain
(`subject=alice actors=ai-agent-delegated`) so every tool call is attributable
back to both the user and the acting agent. Requires a logged-in user — see
[docs/agentic-ai.md § UC4](docs/agentic-ai.md#uc4--user-delegated-obo--rescoping).

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
├── CLAUDE.md                       # Canonical Claude Code instructions
├── docker-compose.yml              # Full multi-service stack (≈15 containers)
├── keycloak/
│   └── realm-export.json           # Auto-imported realm (users, clients, roles)
├── keycloak-init/
│   ├── Dockerfile
│   └── setup.py                    # Idempotent client/role/scope provisioning
├── resource-server/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── main.py                     # FastAPI + JWT validation + DPoP endpoint
├── client-app/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py                      # Flask — all 11 OAuth2/OIDC flows + Agentic AI
│   └── templates/                  # base + per-flow templates + agentic_*.html
├── spiffe-service/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                     # FastAPI — SPIFFE workload identity demo
│   └── templates/                  # Service's own HTML UI
├── spire/
│   ├── server/                     # SPIRE server config
│   ├── agent/                      # SPIRE agent config
│   ├── init/                       # One-shot workload registration container
│   ├── agent-wrapper/              # Alpine + spire-agent binary
│   ├── setup.sh                    # Creates join token + workload entries
│   └── agent-start.sh
├── mcp-service/                    # NEW — Real MCP HTTP server on :8003
│   ├── Dockerfile
│   ├── requirements.txt
│   └── main.py                     # FastAPI + FastMCP + Bearer JWT auth
├── ai-agents/                      # Five agentic AI demo containers
│   ├── agent-secret/               # UC1 :9001  (Client Credentials)
│   ├── agent-spiffe/               # UC2 :9002  (SPIRE → RFC 7523)
│   ├── agent-spiffe-mtls/          # UC2-Hardened :9005 (SPIRE → RFC 8705 mTLS)
│   ├── agent-cert/                 # UC3a :9003 (X.509 cert → RFC 7523)
│   └── agent-delegated/            # UC4 :9004  (RFC 8693 OBO + Rescope)
├── cert-init/                      # One-shot CA + cert generator for UC3a
│   ├── Dockerfile
│   └── setup.sh
├── keycloak-mtls-proxy/            # nginx sidecar for UC2-Hardened (:8443)
│   ├── Dockerfile
│   ├── nginx.conf
│   └── entrypoint.sh
└── docs/
    ├── architecture.md             # Learner — system architecture
    ├── oauth2-flows.md             # Learner — all eleven OAuth2 flows
    ├── spiffe-oauth2.md            # Learner — SPIFFE deep dive
    ├── obo-manual-setup.md         # Learner — manual OBO config guide
    ├── keycloakbrokeringtoping.md  # Learner — Keycloak ↔ Ping brokering
    ├── agentic-ai.md               # Learner — four Agentic AI patterns
    ├── PROJECT-ARCHITECTURE.md     # AI-agent reference — system architecture
    ├── PROJECT-SPECIFICATION.md    # AI-agent reference — feature inventory
    └── ROADMAP-uc3b-mtls.md        # Deferred — true mTLS plan (RFC 8705)
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
