# OAuth2 + JWT with Keycloak — Learning Demo

A fully containerised environment to understand how **OAuth2**, **JWT**, **SPIFFE/SPIRE**, and
**Keycloak** work together. Five flows are demonstrated end-to-end, from browser login through
workload identity to protected API access.

---

## Architecture overview

```
Browser / curl
     │
     ▼
┌─────────────────────┐        ┌──────────────────────────────┐
│   Client App        │──JWT──▶│   Resource Server            │
│   Flask :5000       │        │   FastAPI :8001              │
│                     │        │                              │
│ • Auth Code flow    │        │ GET /api/public   (open)     │
│ • Password grant    │        │ GET /api/products (any token)│
│ • Client creds      │        │ GET /api/users/me (user-role)│
│ • On-Behalf-Of      │        │ GET /api/users    (admin)    │
│ • SPIFFE demo       │        │ GET /api/admin/*  (admin)    │
└──────┬──────────────┘        └──────────────┬───────────────┘
       │ token exchange                        │ JWKS fetch
       │ (server-to-server)                    ▼
       ▼                       ┌─────────────────────────────────────────┐
┌─────────────────────────────────────────────────────────────────────┐  │
│   Keycloak :8080   (realm: demo)                                    │  │
│                                                                     │  │
│ • Issues JWT access tokens (RS256)                                  │  │
│ • Manages users, roles, clients                                     │  │
│ • RFC 8693 token exchange (preview feature)                         │  │
└──────────────────────────┬──────────────────────────────────────────┘  │
                           │ Postgres                                     │
                    ┌──────▼──────┐                                       │
                    │  PostgreSQL  │                                       │
                    │  :5432       │                                       │
                    └─────────────┘                                       │

SPIFFE / SPIRE stack (workload identity):
                                                                          │
┌──────────────┐  gRPC :8081  ┌─────────────────┐   Workload API  ┌──────▼─────────┐
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
exchange permissions via the Admin API.

Watch for all services to show `healthy` or `Exited (0)`:

```bash
docker compose ps
```

### 2 — Open the demo app

| Service | URL |
|---|---|
| **Client App** (Flask) | http://localhost:5000 |
| **Resource Server** (FastAPI docs) | http://localhost:8001/docs |
| **SPIFFE Service** (FastAPI) | http://localhost:8002 |
| **Keycloak Admin Console** | http://localhost:8080/admin (`admin` / `admin`) |

### 3 — Try the flows

1. Open http://localhost:5000
2. Click **"Login with Authorization Code"** → log in as `alice` / `alice123`
3. Click **"Inspect Token"** to see the decoded JWT
4. Click any API button to see role-based access in action
5. Try **"On-Behalf-Of"** under Advanced Token Exchange
6. Click **"Run SPIFFE Demo"** to see workload identity without secrets
7. Log out, log in as `bob` / `bob123` (user-role only), try the admin endpoint → 403

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
| `spiffe-service` | `spiffe-service-secret` | `user-role` | SPIFFE→OAuth2 bridge |

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
testing and scripting.

### 3. Client Credentials (machine-to-machine)

```
client_id + client_secret → POST /token → access_token (no user)
```

The application authenticates as itself. Produces a service account token, not a user token.

### 4. On-Behalf-Of / Token Exchange (RFC 8693)

```
User token + middle-tier-client credentials → POST /token → delegated token
```

`middle-tier-client` exchanges Alice's token for a new token scoped to itself, preserving
the user's identity (`sub`) while switching the acting client (`azp`). Requires the
`KC_FEATURES=preview` flag and fine-grained authorization policies on `demo-client`.

### 5. SPIFFE Workload Identity

```
SPIRE attests container → JWT-SVID → OAuth2 bridge → access_token
```

`spiffe-service` proves its identity to the SPIRE agent using OS-level attributes (unix UID),
receives a short-lived JWT-SVID (~5 min), maps it to a Keycloak service account, and uses
the resulting OAuth2 token to call the resource server — no static secret ever stored.
See [docs/spiffe-oauth2.md](docs/spiffe-oauth2.md) for details.

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
on first boot. Post-import configuration (token-exchange permissions, `spiffe-service` client
provisioning) is handled by the `keycloak-init` container on every startup.

| Setting | Value |
|---|---|
| Realm | `demo` |
| Token lifetime | 30 minutes |
| Signature algorithm | RS256 |
| Client `demo-client` | Auth Code + Password flows, confidential |
| Client `service-client` | Client Credentials only, confidential |
| Client `middle-tier-client` | Client Credentials only — OBO actor |
| Client `spiffe-service` | Client Credentials only — SPIFFE bridge |

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

# Decode token locally (without verification)
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# SPIFFE service demo endpoint
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
2. Run `keycloak-init` to configure token exchange and provision the `spiffe-service` client
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

### SPIFFE demo shows error

Check all SPIRE containers are healthy and `spiffe-service` is running:

```bash
docker compose ps spire-server spire-agent spiffe-service
docker compose logs spiffe-service --tail 30
```

If `spire-agent` is unhealthy, check `docker compose logs spire-agent`. The agent needs
`spire-init` to complete first (writes the join token).

If `spiffe-service` is stuck in `Created`, run:

```bash
docker compose up -d keycloak-init spiffe-service
```

### Port conflict

Edit the `ports` section in `docker-compose.yml`. If you change the Keycloak port, also
update `KEYCLOAK_EXTERNAL_URL` and `KEYCLOAK_ISSUER` in the relevant services.

---

## Project structure

```
oauth2sample/
├── docker-compose.yml              # Full 9-service stack
├── keycloak/
│   └── realm-export.json           # Auto-imported realm (users, clients, roles)
├── keycloak-init/
│   ├── Dockerfile
│   └── setup.py                    # Configures token-exchange + spiffe-service client
├── resource-server/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── main.py                     # FastAPI + JWT validation
├── client-app/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py                      # Flask + all OAuth2 flows
│   └── templates/
│       ├── base.html
│       ├── index.html
│       ├── password_grant.html
│       ├── api_result.html
│       ├── token_inspect.html
│       ├── token_exchange_obo.html
│       ├── token_exchange_rescope.html
│       └── spiffe_demo.html
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
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [JSON Web Token RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [SPIFFE Specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md)
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [jwt.io](https://jwt.io) — online JWT decoder and verifier
