# OAuth2 + JWT with Keycloak — Learning Demo

A fully containerised environment to understand how **OAuth2**, **JWT**, and **Keycloak** work together.
Three grant types are demonstrated end-to-end, from token issuance to protected API access.

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
└──────┬──────────────┘        │ GET /api/users    (admin)    │
       │                       │ GET /api/admin/*  (admin)    │
       │ token exchange        └──────────────┬───────────────┘
       │ (server-to-server)                   │ JWKS fetch
       ▼                                      ▼
┌─────────────────────────────────────────────────────────┐
│   Keycloak :8080   (realm: demo)                        │
│                                                         │
│ • Issues JWT access tokens (RS256)                      │
│ • Manages users, roles, clients                         │
│ • Exposes JWKS public-key endpoint                      │
└──────────────────────────┬──────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │  PostgreSQL  │
                    │  :5432       │
                    └─────────────┘
```

**Key networking rule:** the browser always talks to Keycloak via `http://localhost:8080`.
Server-side containers talk to each other via the Docker network (`http://keycloak:8080`).
Keycloak is configured with `KC_HOSTNAME=localhost` so all JWT `iss` claims equal
`http://localhost:8080/realms/demo`, regardless of which container made the token request.

---

## Quick start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose v2)
- Ports **8080**, **8001**, and **5000** free on your machine

### 1 — Start the stack

```bash
cd oauth2sample
docker compose up --build
```

First boot takes **2–4 minutes**: PostgreSQL initialises, then Keycloak imports the realm
and generates RSA key pairs before accepting requests.

Watch for this line in the logs to know Keycloak is ready:

```
oauth2-keycloak  | ... Keycloak 24.0 ... started in ...
```

### 2 — Open the demo app

| Service | URL |
|---|---|
| **Client App** (Flask) | http://localhost:5000 |
| **Resource Server** (FastAPI docs) | http://localhost:8001/docs |
| **Keycloak Admin Console** | http://localhost:8080/admin (`admin` / `admin`) |

### 3 — Try the flows

1. Open http://localhost:5000
2. Click **"Login with Authorization Code"** → log in as `alice` / `alice123`
3. Click **"Inspect Token"** to see the decoded JWT
4. Click any API button to see role-based access in action
5. Log out, log in as `bob` / `bob123` (user-role only), try the admin endpoint → 403

---

## Test accounts

| Username | Password | Roles | Can access |
|---|---|---|---|
| `alice` | `alice123` | `admin-role`, `user-role` | Everything |
| `bob` | `bob123` | `user-role` | Products, /me, public |
| `charlie` | `charlie123` | _(none)_ | Public only |
| `service-client` | — | `user-role` (service account) | Client Credentials flow |

---

## OAuth2 Grant Types Demonstrated

### 1. Authorization Code Flow (recommended for web apps)

```
User → Client App → Keycloak login page → code → Client App → tokens
```

1. User clicks "Login" → app builds an authorization URL with `response_type=code`
2. Browser redirects to Keycloak; user enters credentials
3. Keycloak redirects back to `/auth/callback?code=xxx&state=yyy`
4. App verifies the `state` parameter (CSRF protection)
5. App exchanges the code for tokens via a **server-side** POST to Keycloak
6. Tokens are stored in the Flask session (never exposed to the browser)

### 2. Resource Owner Password Credentials / ROPC (legacy)

```
username + password → POST /token → access_token
```

Credentials are sent directly to the token endpoint. Simpler but the client app
sees the password. Useful for testing/scripting; avoid in production.

### 3. Client Credentials (machine-to-machine)

```
client_id + client_secret → POST /token → access_token (no user)
```

The application authenticates as itself. No human user involved.
The resulting token contains the service account identity, not a user's.

---

## JWT Validation (Resource Server)

Every protected endpoint in the Resource Server performs these checks:

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

The realm is auto-imported from [`keycloak/realm-export.json`](keycloak/realm-export.json) on first boot.

| Setting | Value |
|---|---|
| Realm | `demo` |
| Token lifetime | 5 minutes (300 s) |
| Signature algorithm | RS256 |
| Client `demo-client` | Auth Code + Password flows, confidential |
| Client `service-client` | Client Credentials only, confidential |

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
```

---

## Stopping and resetting

```bash
# Stop containers (data preserved)
docker compose down

# Stop AND delete all data (full reset — re-imports realm on next boot)
docker compose down -v
```

---

## Troubleshooting

### "invalid_token" or 401 after starting

Keycloak may still be importing the realm. Wait 30 s and retry.

### 401 with "Invalid token issuer"

The `iss` claim in your token does not match `KEYCLOAK_ISSUER` in the resource server.
Check what issuer your token actually contains:

```bash
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .iss
```

If it says `http://keycloak:8080/realms/demo` instead of `http://localhost:8080/realms/demo`,
ensure `KC_HOSTNAME=localhost` is set in `docker-compose.yml` and restart Keycloak.

### Service account has no roles (Client Credentials → 403)

The service account user import may have been skipped if the realm already existed.
Fix manually:

1. Open http://localhost:8080/admin → realm `demo`
2. **Clients** → `service-client` → **Service account roles** tab
3. Assign `user-role` from the **Available roles** list

### Port conflict

Edit the `ports` section in `docker-compose.yml` to use different host ports.
If you change the Keycloak port, also update `KEYCLOAK_EXTERNAL_URL` and `KEYCLOAK_ISSUER`.

---

## Project structure

```
oauth2sample/
├── docker-compose.yml          # All four services
├── keycloak/
│   └── realm-export.json       # Auto-imported realm (users, clients, roles)
├── resource-server/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── main.py                 # FastAPI + JWT validation
├── client-app/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py                  # Flask + OAuth2 flows
│   └── templates/
│       ├── base.html
│       ├── index.html
│       ├── password_grant.html
│       ├── api_result.html
│       └── token_inspect.html
└── docs/
    ├── architecture.md
    └── oauth2-flows.md
```

---

## Further reading

- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [JSON Web Token RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [jwt.io](https://jwt.io) — online JWT decoder and verifier
