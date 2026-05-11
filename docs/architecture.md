# Architecture

## Components

### Keycloak (port 8080)

Keycloak is the **Identity Provider (IdP)** and **Authorisation Server**.

Responsibilities:
- Authenticates users (login form, MFA, social login, etc.)
- Issues signed JWT tokens after successful authentication
- Manages users, roles, clients, and realms
- Exposes a JWKS endpoint so resource servers can verify token signatures
- Handles token refresh and SSO session management

Key Keycloak concepts used in this demo:

| Concept | Description |
|---|---|
| **Realm** | An isolated namespace (`demo`) containing its own users, clients, and roles |
| **Client** | An application registered with Keycloak (`demo-client`, `service-client`) |
| **Confidential client** | Has a `client_secret`; token exchange happens server-side |
| **Service account** | A non-human identity attached to a client (for Client Credentials) |
| **Realm role** | A role scoped to the realm (`admin-role`, `user-role`) |
| **JWKS** | JSON Web Key Set — the Keycloak public keys used to verify JWT signatures |

### Resource Server (port 8001)

A **FastAPI** application that represents a protected backend API.

It has no user database of its own — it trusts tokens issued by Keycloak entirely.
Every protected endpoint:

1. Extracts the `Bearer` token from the `Authorization` header
2. Fetches Keycloak's JWKS (cached in memory after first fetch)
3. Verifies the JWT signature using the matching public key (`kid` header claim)
4. Validates `iss`, `exp` claims
5. Checks `realm_access.roles` for role-protected routes

The resource server **never** calls Keycloak to validate a token — it validates the
cryptographic signature locally using Keycloak's public key. This makes validation
stateless and extremely fast.

### Client Application (port 5000)

A **Flask** web application that demonstrates all three OAuth2 grant types.

It acts as the OAuth2 **client** (not the resource server, not the IdP).
Its responsibilities:
- Redirect the user's browser to Keycloak for authentication (Auth Code flow)
- Exchange the authorization code for tokens (server-side, not in the browser)
- Store tokens in the server-side Flask session
- Use the access token to call the Resource Server on behalf of the user
- Display the raw and decoded JWT for educational purposes

### PostgreSQL (port 5432)

Stores Keycloak's internal state (users, sessions, keys, realm configuration).
Not accessed directly by the Python applications.

---

## Network topology

```
Host machine
├── localhost:5000  → oauth2-client-app
├── localhost:8001  → oauth2-resource-server
└── localhost:8080  → oauth2-keycloak
                         └── keycloak:5432 → oauth2-postgres

Internal Docker network (oauth2-net):
  oauth2-client-app ──────────────────────▶ oauth2-keycloak:8080  (token exchange)
  oauth2-client-app ──────────────────────▶ oauth2-resource-server:8001  (API calls)
  oauth2-resource-server ─────────────────▶ oauth2-keycloak:8080  (JWKS fetch)
  oauth2-keycloak ─────────────────────────▶ oauth2-postgres:5432
```

**Important:** the browser uses `localhost:8080` to reach Keycloak (via port mapping).
Server-to-server calls inside Docker use the container name `keycloak:8080`.
`KC_HOSTNAME=localhost` ensures all JWT `iss` claims always say `http://localhost:8080/...`.

---

## Token flow — Authorization Code

```
User                  Client App              Keycloak              Resource Server
 │                        │                      │                        │
 │  GET /                 │                      │                        │
 │───────────────────────▶│                      │                        │
 │                        │                      │                        │
 │  Click "Login"         │                      │                        │
 │───────────────────────▶│                      │                        │
 │                        │  Build auth URL      │                        │
 │                        │  + state, nonce      │                        │
 │◀───────────────────────│  302 Redirect        │                        │
 │                        │                      │                        │
 │  GET /auth?...         │                      │                        │
 │──────────────────────────────────────────────▶│                        │
 │◀──────────────────────────────────────────────│  Login page            │
 │  POST credentials      │                      │                        │
 │──────────────────────────────────────────────▶│                        │
 │◀──────────────────────────────────────────────│  302 /callback?code=X  │
 │                        │                      │                        │
 │  GET /callback?code=X  │                      │                        │
 │───────────────────────▶│                      │                        │
 │                        │  POST /token         │                        │
 │                        │  grant_type=auth_code│                        │
 │                        │  code=X              │                        │
 │                        │──────────────────────▶                        │
 │                        │◀──────────────────────  {access_token,        │
 │                        │                      │   id_token,            │
 │                        │                      │   refresh_token}       │
 │                        │  Store in session    │                        │
 │◀───────────────────────│  302 /               │                        │
 │                        │                      │                        │
 │  Click "Call API"      │                      │                        │
 │───────────────────────▶│                      │                        │
 │                        │  GET /api/products   │                        │
 │                        │  Authorization: Bearer <token>                │
 │                        │───────────────────────────────────────────────▶
 │                        │                      │  GET /certs (JWKS)     │
 │                        │                      │◀───────────────────────│
 │                        │                      │──────────────────────▶ │
 │                        │                      │  {keys}                │
 │                        │                      │◀──────────────────────-│
 │                        │                      │  Verify signature      │
 │                        │                      │  Check exp, iss, roles │
 │                        │◀───────────────────────────────────────────────
 │                        │                      │  200 {products}        │
 │◀───────────────────────│                      │                        │
```

---

## JWT Structure

A JWT has three Base64URL-encoded parts separated by dots:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLiJ9   ← Header
.
eyJzdWIiOiI1NjRmYy4uLiIsInJlYWxtX2FjY2Vzcy4uLiJ9        ← Payload
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c              ← Signature
```

### Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "abc123"
}
```

### Payload (selected claims)

```json
{
  "sub":                "564fc7e2-...",
  "iss":                "http://localhost:8080/realms/demo",
  "aud":                ["account"],
  "azp":                "demo-client",
  "exp":                1718000000,
  "iat":                1717999700,
  "preferred_username": "alice",
  "email":              "alice@example.com",
  "realm_access": {
    "roles": ["admin-role", "user-role", "offline_access"]
  },
  "scope": "openid profile email roles"
}
```

### Signature

```
RS256(
  Base64URL(header) + "." + Base64URL(payload),
  keycloakPrivateKey
)
```

Only Keycloak's private key can produce this signature.
Any server that has the matching public key (from JWKS) can verify it.

---

## Security considerations

This demo intentionally simplifies some things for clarity:

| Topic | Demo choice | Production recommendation |
|---|---|---|
| Audience validation | Disabled (`verify_aud: False`) | Configure audience mapper in Keycloak; validate `aud` |
| HTTPS | HTTP only | Always use HTTPS; set `KC_HOSTNAME_STRICT_HTTPS=true` |
| Token storage | Flask server-side session | Use secure, HttpOnly cookies or server-side session store |
| Client secret | Hardcoded in compose | Use Docker secrets or a vault |
| JWKS caching | In-memory, no TTL | Add TTL-based cache with rotation support |
| PKCE | Not implemented | Add `code_challenge` / `code_verifier` to Auth Code flow |
