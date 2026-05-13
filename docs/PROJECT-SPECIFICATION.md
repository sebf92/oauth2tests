# PROJECT-SPECIFICATION.md — Feature inventory and component contracts

This document specifies *what* every component and every flow does. For
*how* the system is wired together see `docs/PROJECT-ARCHITECTURE.md`. For
high-level orientation see `CLAUDE.md`.

---

## 1. Project scope

The platform demonstrates **fifteen authentication / authorization patterns**
in a single Docker Compose stack:

- **Eleven OAuth2 / OpenID Connect flows** (§2 below) accessible from
  `http://localhost:5000`
- **Four Agentic AI patterns** (§3 below) accessible from
  `http://localhost:5000/agentic`

A **rendered markdown documentation system** (§4) presents long-form
explanations at `http://localhost:5000/docs`.

Every flow is **end-to-end runnable** from a button click — no manual setup
beyond `docker compose up -d --build`. Every flow renders the resulting
JWT (header + decoded payload + signature preview) and the result of
calling the protected `resource-server` API.

---

## 2. OAuth2 / OpenID Connect flows

Each flow exists in two places that must stay in sync:
- A route + view in `client-app/app.py`
- A card on the home page `client-app/templates/index.html`

Most flows also have a Keycloak client requirement (`realm-export.json` +
`keycloak-init/setup.py`).

### 2.1 Authorization Code (RFC 6749 §4.1)

- **Route:** `GET /auth/authorization-code` → redirect to Keycloak
- **Callback:** `GET /auth/callback`
- **Client:** `demo-client` (confidential)
- **Security:** `state` (CSRF), `nonce` (replay protection on id_token)
- **Scopes requested:** `openid profile email roles`
- **Returns:** access_token + id_token + refresh_token, stored in Flask session.

### 2.2 Resource Owner Password Credentials (RFC 6749 §4.3)

- **Route:** `GET/POST /auth/password`
- **Client:** `demo-client` (`directAccessGrantsEnabled=true`)
- **Status:** documented as **legacy** in the UI — avoid in production
- **Returns:** full token set.

### 2.3 Client Credentials (RFC 6749 §4.4)

- **Route:** `GET /auth/client-credentials`
- **Client:** `service-client`
- **Returns:** access_token only (no id_token, no refresh_token — service
  accounts have no SSO session).

### 2.4 On-Behalf-Of token exchange (RFC 8693)

- **Route:** `GET /auth/token-exchange/obo`
- **Requirements:** user must be logged in (any flow that issues a user token)
- **Client performing exchange:** `middle-tier-client`
- **Prerequisites:**
  - `standard.token.exchange.enabled=true` on `middle-tier-client` (set
    by `keycloak-init`)
  - `middle-tier-client` listed in `aud` claim of the user's token
    (configured via audience mapper in `realm-export.json`)
- **Result token:** preserves `sub` (user identity), changes `azp` to
  `middle-tier-client`, adds `act` claim recording the delegation.

### 2.5 Token Rescoping (RFC 8693)

- **Route:** `GET /auth/token-exchange/rescope`
- **Same grant type as OBO**, but adds `scope=openid email profile`
  (omitting `roles`) so the resulting token strips `realm_access.roles`.
- **Client:** `demo-client` (`standard.token.exchange.enabled=true` set by
  `keycloak-init`).

### 2.6 SPIFFE workload identity → OAuth2

- **Route:** `GET /auth/spiffe` (proxies to `spiffe-service:8002/demo`)
- **Implementation:** `spiffe-service/main.py`
- **Auth method:** RFC 7523 private_key_jwt
- **Client:** `spiffe-service` (`clientAuthenticatorType=client-jwt`,
  `jwks_url=http://spiffe-service:8002/jwks`)
- **Flow:** SPIRE Workload API → JWT-SVID (display) → ephemeral EC key
  signs `client_assertion` → Keycloak → access_token → call
  resource-server.
- **Note:** This is the **"flow 6" home page demo**, separate from the
  Agentic AI section (which has its own SPIFFE agent at UC2).

### 2.7 OIDC Identity Layer

- **Route:** `GET /auth/oidc`
- **Requirements:** user must be logged in
- **Renders:**
  - decoded `id_token`
  - `GET /userinfo` response (live call to Keycloak)
  - `/.well-known/openid-configuration` discovery document

### 2.8 DPoP — Proof of Possession (RFC 9449)

- **Route:** `GET /auth/dpop`
- **Client:** `dpop-client` (`dpop.bound.access.tokens=true`)
- **Implementation:** generates ephemeral EC P-256 key in the Flask
  process, builds two DPoP proofs (one for token endpoint, one with `ath`
  claim for the resource server), calls
  `resource-server:/api/dpop-protected`.
- **Critical detail:** Resource-server validates `cnf.jkt` claim binding
  in `_validate_dpop_proof` (resource-server/main.py).

### 2.9 Device Authorization Grant (RFC 8628)

- **Route:** `GET /auth/device` (kicks off), `GET /auth/device/poll`
  (AJAX polling)
- **Client:** `device-client` (`oauth2.device.authorization.grant.enabled=true`)
- **Flow:** device endpoint returns `device_code` + `user_code` +
  `verification_uri`; UI displays them; JavaScript polls `/auth/device/poll`
  until Keycloak returns a token.
- **URL substitution:** `verification_uri` returned by Keycloak uses
  `KC_INT`; the Flask handler substitutes `KC_EXT` so the link is
  clickable from the browser.

### 2.10 PKCE — Proof Key for Code Exchange (RFC 7636)

- **Route:** `GET /auth/pkce` (start), `GET /auth/pkce/result` (result page)
- **Callback:** `GET /auth/callback` (shared with Auth Code, switched via
  `session["pkce_flow"]=True`)
- **Client:** `pkce-client` (`publicClient=true`,
  `pkce.code.challenge.method=S256`)
- **Critical:** `code_verifier` is base64url-encoded random bytes;
  `code_challenge = BASE64URL(SHA-256(verifier))`.

### 2.11 Token Introspection (RFC 7662)

- **Route:** `GET /auth/introspect`
- **Demo:** obtains a fresh token → introspects (active: true) → revokes
  the refresh token → introspects again (active: false). Demonstrates
  that local JWT decode cannot detect revocation.

---

## 3. Agentic AI patterns

Each agent is a self-contained Python container with a uniform HTTP contract:

```
GET  /info       → { client_id, auth_method, mcp_url, model, mode, task, ... }
GET  /health     → { status, mode }
POST /run        → AgentRun JSON (see §3.4)
```

The Flask client-app proxies `/agentic/<slug>` to the corresponding agent's
`/run` endpoint and renders the result.

### 3.1 UC1 — Client Secret → MCP

- **Container:** `agent-secret` :9001
- **Keycloak client:** `ai-agent-secret` (confidential, has secret)
- **Auth:** OAuth 2.0 Client Credentials with `scope=mcp`
- **Trace fields:** `auth` (no `cert`, no `svid`)

### 3.2 UC2 — SPIFFE → MCP

- **Container:** `agent-spiffe` :9002
- **Keycloak client:** `ai-agent-spiffe`
  (`clientAuthenticatorType=client-jwt`,
  `jwks_url=http://agent-spiffe:9002/jwks`)
- **SPIRE workload entry:** `spiffe://demo.local/ai-agent-spiffe` selector
  `unix:uid:1000`
- **Container constraints:**
  - Runs as UID 1000 (Dockerfile `useradd -u 1000`)
  - Shares PID namespace with `spire-agent`
  - Mounts the `spire-agent-socket` volume read-only
- **Auth:** SPIRE attestation produces a JWT-SVID (shown in trace);
  separate in-memory EC key signs the RFC 7523 `client_assertion`.
- **Trace fields:** `svid` + `auth` (with `assertion_claims`)

### 3.3 UC3a — X.509 Certificate → MCP

- **Container:** `agent-cert` :9003
- **Keycloak client:** `ai-agent-cert`
  (`clientAuthenticatorType=client-jwt`,
  `jwks_url=http://agent-cert:9003/jwks`)
- **PKI source:** `cert-init` one-shot writes to volume `agent-cert-pki`:
  - `ca.crt`, `ca.key` — demo CA (10-year validity)
  - `agent.crt`, `agent.key` — agent leaf cert (1-year validity, signed
    by CA, EKU=clientAuth)
- **Container constraints:**
  - Runs as UID 1100
  - Reads `agent-cert-pki` read-only
- **Auth:** loads cert + key at startup → signs RFC 7523 `client_assertion`
  → Keycloak validates by fetching `/jwks` (which embeds `x5c` cert chain
  + `x5t#S256` thumbprint per RFC 7517 §4.7).
- **Trace fields:** `cert` + `auth` (with `assertion_header` showing
  `x5t#S256`, `assertion_claims`)

### 3.4 UC4 — User-Delegated (OBO + Rescope) → MCP

- **Container:** `agent-delegated` :9004
- **Slug (URL path):** `user-delegated-rescope`
- **Keycloak client:** `ai-agent-delegated` (confidential, `client-secret` auth,
  `standard.token.exchange.enabled=true`)
- **Auth:** RFC 8693 token exchange. Single-step OBO + scope narrowing — the
  exchange request includes `subject_token=<user T0>` + `scope=mcp`.
- **Prerequisites:**
  - Audience mapper on `demo-client` named `delegated-agent-audience` adding
    `ai-agent-delegated` to the `aud` claim of alice's tokens
  - `mcp` scope assigned to `ai-agent-delegated` as optional
  - **No `mcp-user` role on the service account** — the resulting token's
    identity is the user, not the service account
- **Contract differs from UC1/UC2/UC3a:**
  - `POST /run` body MUST contain `{"user_access_token": "<T0>"}` (validated
    via pydantic — empty body returns 422)
  - `GET /info` returns `requires_user_token: true`
- **Trace fields (additional to base AgentRun):**
  - `user_identity`: decoded subject token (T0) — display only
  - `custody`: `{subject, actors[], summary}` — actor chain extracted from
    nested `act` claims
  - `scope_diff`: `{user_scopes[], delegated_scopes[], kept[], dropped[], added[]}`
- **MCP audit logging:** mcp-service logs the actor chain for every accepted
  request:
  ```
  MCP token accepted — subject=alice actors=ai-agent-delegated scope=… azp=ai-agent-delegated
  ```
- **AGENT_REGISTRY entry:** sets `requires_user_token: True` flag. The Flask
  `/agentic/<slug>` route gates on a valid Flask session and forwards
  `td["access_token"]` as the `user_access_token` body field. Unauthenticated
  visitors are redirected to `/auth/authorization-code`.

### 3.5 Agent trace contract (AgentRun JSON)

Every agent's `/run` returns a dataclass-serialised JSON object with this
shape (fields are use-case-dependent; unused ones are `null`):

```python
{
  "started_at":   "2026-05-13T14:21:41.298071+00:00",
  "mode":         "mock" | "live",
  "model":        "claude-haiku-4-5-20251001" | "deterministic-mock",
  "task":         "<the task given to the agent>",

  # Optional — UC2 only
  "svid":         { "success": bool, "spiffe_id": str, "socket": str,
                    "header": dict, "payload": dict, "error": str|null },

  # Optional — UC3a only
  "cert":         { "success": bool,
                    "agent": { "subject", "issuer", "serial", "not_before",
                               "not_after", "sha256_fp", "signature_algorithm" },
                    "ca":    {  ... same shape ... } | null },

  # Always present
  "auth": {
    "grant_type":        str,
    "auth_method":       str,
    "client_id":         str,
    "scope":             str,
    "status_code":       int,
    "success":           bool,
    "error":             str | null,
    "access_token":      str | null,         # raw JWT
    "token_header":      dict | null,        # decoded
    "token_claims":      dict | null,        # decoded
    "expires_in":        int | null,
    "assertion_header":  dict | null,        # UC2/UC3a only
    "assertion_claims":  dict | null         # UC2/UC3a only
  },

  "mcp": {
    "server_url": str,
    "tools":      [{ "name", "description", "input_schema": dict }, ...],
    "error":      str | null
  },

  "turns": [
    { "iteration": int,
      "stop_reason": str | null,
      "text": str | null,
      "tool_calls": [
        { "name": str, "input": dict, "result": Any, "ok": bool }, ...
      ]
    }, ...
  ],

  "final_answer": str | null,
  "duration_ms":  int,
  "error":        str | null
}
```

The Flask renderer (`client-app/templates/agentic_result.html`) is generic
across this shape — adding fields requires extending only the agent's
dataclass + the template.

### 3.6 Agent task (shared across all four)

```
I have a $40 budget for a gift. Look at the product catalogue, pick the
best candidate, fetch its full details, and write a one-paragraph
recommendation. Use the MCP tools available to you — do not invent
product data.
```

Each agent uses the same task so traces are comparable across UCs.
Configurable via the `AGENT_TASK` env var on each agent container.

### 3.7 Mock vs live mode

Each agent checks `ANTHROPIC_API_KEY`:
- **Live:** invokes `anthropic.Anthropic().messages.create(...)` in a
  thread (via `asyncio.to_thread`). Loop continues until
  `stop_reason != "tool_use"` or `MAX_TOOL_ITERATIONS` (6) reached.
- **Mock:** runs a deterministic 3-turn loop calling `list_products`,
  then `get_product_details(<chosen.id>)`, then synthesising a final
  answer string. Same MCP calls a real run would make — so the auth +
  MCP path is exercised identically.

---

## 4. MCP service

### 4.1 Wire endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/mcp` | **Bearer required** | MCP Streamable HTTP JSON-RPC |
| `GET`  | `/mcp` | Bearer required | SSE upgrade (same endpoint) |
| `GET`  | `/.well-known/oauth-protected-resource` | anonymous | RFC 9728 discovery |
| `GET`  | `/health` | anonymous | Liveness |
| `GET`  | `/` | anonymous | HTML landing page |

### 4.2 Bearer token validation contract

Performed on every `/mcp` request, in order. Failure produces 401 with
`WWW-Authenticate: Bearer error="invalid_token",
resource_metadata="<discovery URL>"`.

1. Authorization header starts with `Bearer ` (case-insensitive).
2. JWKS-resolved signing key by `kid`.
3. RS256 signature verifies.
4. `iss == http://localhost:8080/realms/demo` (configurable via
   `KEYCLOAK_ISSUER` env var).
5. `exp` not in past (30s leeway).
6. `aud` contains `mcp-service` (configurable via `MCP_AUDIENCE`).
7. `scope` claim (space-separated string) contains `mcp`.

### 4.3 Discovery document

```json
{
  "resource":                 "http://localhost:8003",
  "authorization_servers":    ["http://localhost:8080/realms/demo"],
  "bearer_methods_supported": ["header"],
  "scopes_supported":         ["mcp"],
  "resource_documentation":   "http://localhost:8003/"
}
```

### 4.4 Tools exposed via MCP

| Tool | Input | Returns |
|---|---|---|
| `list_products` | none | List of `{id, name, price, category, stock}` |
| `get_product_details` | `product_id: int` | One product dict, or `{"error": "..."}` |

Product data is hardcoded in `mcp-service/main.py` (mirroring
`resource-server/main.py` so the educational link is obvious).

### 4.5 Adding a new MCP tool

```python
@mcp.tool()
def my_tool(arg: int, name: str = "default") -> dict:
    """One-line docstring becomes the tool description shown to Claude."""
    return {"...": "..."}
```

`@mcp.tool()` derives the JSON Schema from type hints. Tool results
become one or more `TextContent` items in `CallToolResult.content` —
lists produce **one TextContent per element**, so any client must use the
`_mcp_result_to_python` helper pattern (or equivalent).

---

## 5. Documentation system

### 5.1 Markdown rendering pipeline

`client-app/app.py` → `_render_doc(filename)` flow:

1. Read file from `DOCS_DIR` (`/app/docs/` in container,
   `./docs/` on host).
2. `_MERMAID_FENCE_RE = re.compile(r'```mermaid\s*\n(.*?)```', re.DOTALL)`
   extracts every `` ```mermaid `` block.
3. Each block's content is `html.escape()`-encoded, then wrapped in
   `<div class="mermaid">…</div>`.
4. Resulting raw is passed to `python-markdown` with extensions:
   `tables, fenced_code, codehilite, toc, attr_list`.
5. Codehilite uses Pygments with the `monokai` style; CSS is generated
   once at startup and injected via `pygments_css` context var.
6. Toc extension generates a separate TOC HTML rendered in the right
   sidebar of `templates/docs_page.html`.
7. Mermaid.js (CDN, dynamic import) renders the diagrams client-side.
   `securityLevel: 'loose'` permits `<br/>` in node labels (which we use).

### 5.2 Adding a documentation page

1. Create `docs/<slug>.md`. Use ` ```mermaid ` fences for diagrams.
2. Add a registration entry to `DOCS_MANIFEST` in `client-app/app.py`:

```python
{
    "slug":        "<slug>",
    "file":        "<slug>.md",
    "title":       "Display title",
    "icon":        "bi-<bootstrap-icon>",
    "color":       "primary" | "success" | "info" | "warning" | "danger",
    "badge":       "Category Badge",
    "description": "One-sentence summary for the index card.",
},
```

3. The Flask route `/docs/<slug>` is generic — picks up the new entry
   automatically.

### 5.3 Existing rendered pages

| Slug | Source file | Audience |
|---|---|---|
| `architecture` | `docs/architecture.md` | Learners — system architecture |
| `oauth2-flows` | `docs/oauth2-flows.md` | Learners — all eleven flows |
| `spiffe-oauth2` | `docs/spiffe-oauth2.md` | Learners — SPIFFE deep dive |
| `obo-manual-setup` | `docs/obo-manual-setup.md` | Operators — OBO config guide |
| `keycloak-brokering` | `docs/keycloakbrokeringtoping.md` | Learners — KC↔Ping brokering |
| `agentic-ai` | `docs/agentic-ai.md` | Learners — four Agentic AI patterns |

Files NOT in `DOCS_MANIFEST` (engineering artefacts, not rendered):
- `docs/PROJECT-ARCHITECTURE.md` (this project's architecture spec)
- `docs/PROJECT-SPECIFICATION.md` (this document)
- `docs/ROADMAP-uc3b-mtls.md` (deferred mTLS plan)
- `CLAUDE.md` (root — Claude Code instructions)

---

## 6. Keycloak realm contract

The `demo` realm is configured by `realm-export.json` on first import and
augmented at runtime by `keycloak-init/setup.py` (see §7 for the upgrade
pattern).

### 6.1 Realm-level configuration

- **accessTokenLifespan:** 1800 (30 minutes)
- **defaultSignatureAlgorithm:** RS256
- **sslRequired:** none (HTTP only — KC_HOSTNAME=localhost)
- **bruteForceProtected:** false (demo)

### 6.2 Roles

| Role | Description | Assigned to |
|---|---|---|
| `admin-role` | Full API access | `alice` |
| `user-role` | User-level API access | `alice`, `bob`, service-account-{service-client,middle-tier-client,spiffe-service} |
| `mcp-user` | MCP service access | service-account-ai-agent-{secret,spiffe,cert} |

### 6.3 Users

| Username | Password | Roles | Purpose |
|---|---|---|---|
| `alice` | `alice123` | admin-role, user-role | Admin test |
| `bob` | `bob123` | user-role | Regular user test |
| `charlie` | `charlie123` | — | No-role test (admin endpoints → 403) |

### 6.4 Clients summary

| clientId | Authenticator | Public | Grants | Notes |
|---|---|---|---|---|
| `demo-client` | client-secret | No | Auth Code, ROPC | `standard.token.exchange.enabled=true` |
| `middle-tier-client` | client-secret | No | Token Exchange | `standard.token.exchange.enabled=true` |
| `service-client` | client-secret | No | Client Credentials | |
| `spiffe-service` | **client-jwt** | No | Client Credentials | `jwks_url=http://spiffe-service:8002/jwks` |
| `dpop-client` | client-secret | No | ROPC | `dpop.bound.access.tokens=true` |
| `device-client` | client-secret | No | Device Grant | `oauth2.device.authorization.grant.enabled=true` |
| `pkce-client` | — | **Yes** | Auth Code | `pkce.code.challenge.method=S256` |
| `ai-agent-secret` | client-secret | No | Client Credentials | UC1 |
| `ai-agent-spiffe` | **client-jwt** | No | Client Credentials | UC2, `jwks_url=http://agent-spiffe:9002/jwks` |
| `ai-agent-cert` | **client-jwt** | No | Client Credentials | UC3a, `jwks_url=http://agent-cert:9003/jwks` |
| `ai-agent-delegated` | client-secret | No | **Token Exchange** | UC4, `standard.token.exchange.enabled=true`, OBO + rescope |

### 6.5 Custom client scope

The `mcp` client scope (created by `ensure_mcp_client_scope`):
- `include.in.token.scope=true` → name appears in the `scope` claim
- `display.on.consent.screen=false`
- One protocol mapper: `mcp-audience` (oidc-audience-mapper) with
  `included.custom.audience=mcp-service`, `access.token.claim=true`,
  `id.token.claim=false`

Assigned as **optional** scope on `ai-agent-{secret,spiffe,cert}`. Agents
must explicitly request `scope=mcp` in the token request.

---

## 7. `keycloak-init` upgrade pattern

Mandatory pattern for any Keycloak realm change. `keycloak-init` is
designed to be runnable any number of times on any realm state.

### 7.1 Helper functions

Defined in `setup.py`:
- `_get(url, headers, **kw)`, `_post(...)`, `_put(...)` — wrap `httpx` with
  `raise_for_status()`
- `wait_for_keycloak()` — polls `/health/ready` on :9000 for 5 minutes
- `wait_for_realm_import()` — polls Admin API until `demo-client` exists
  (proves the realm import finished)
- `get_admin_token()` — Password Grant against the master realm

### 7.2 The `ensure_*` family

Every realm modification has its own function. Pattern:

```python
def ensure_<thing>(token: str) -> None:
    """Docstring explaining what this does and why it's idempotent."""
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    # 1. Probe for existing artifact
    existing = _get(f"{base}/<endpoint>", h, params={...}).json()

    # 2. If exists, optionally migrate, else create
    if existing:
        # Idempotent migration of mutable attrs
        ...
        print(f"  <thing> already exists")
        return

    # 3. Create
    r = httpx.post(..., json={...})
    r.raise_for_status()
    print(f"  ✓ <thing> created")
```

### 7.3 Order of operations in `main()`

```
wait_for_keycloak()
wait_for_realm_import()
setup_token_exchange()             # demo-client + middle-tier-client
ensure_spiffe_service_client()
ensure_dpop_client()
ensure_device_client()
ensure_pkce_client()

# Agentic AI block
ensure_mcp_user_role()
ensure_ai_agent_secret_client()
ensure_ai_agent_spiffe_client()
ensure_ai_agent_cert_client()
ensure_ai_agent_delegated_client()                       # UC4
ensure_delegated_audience_mapper_on_demo_client()        # UC4
setup_token_exchange()  # re-runs to pick up ai-agent-delegated's attribute
mcp_scope_id = ensure_mcp_client_scope()
# UC1/UC2/UC3a — service-principal agents need scope AND role on service account
for cid in ("ai-agent-secret", "ai-agent-spiffe", "ai-agent-cert"):
    ensure_mcp_scope_on_client(token, cid, mcp_scope_id)
    ensure_mcp_role_on_service_account(token, cid)
# UC4 — user-delegated agent needs scope only; sub is the user, not the service account
ensure_mcp_scope_on_client(token, "ai-agent-delegated", mcp_scope_id)
```

### 7.4 When the existing realm and code disagree

If `realm-export.json` declares a role/client/scope but the realm already
exists in Postgres (warm start), Keycloak does NOT re-import. Two options:

- **Recommended for development:** `docker compose down -v` then
  `up --build`. Fresh import, no `ensure_*` needed.
- **Recommended for upgrades:** Add an `ensure_*` function to
  `setup.py`. Re-running `keycloak-init` then converges any realm state
  to the desired state.

Both paths must work — every `ensure_*` is idempotent for that reason.

---

## 8. Resource server API contract

`resource-server/main.py` exposes the following endpoints. All Bearer-protected
unless noted.

| Path | Auth | Required role | Returns |
|---|---|---|---|
| `GET /` | anonymous | — | Service info JSON |
| `GET /health` | anonymous | — | Liveness JSON |
| `GET /api/public` | anonymous | — | Static demo data |
| `GET /api/products` | Bearer | any | Product catalogue |
| `GET /api/users/me` | Bearer | `user-role` | Caller's profile |
| `GET /api/users` | Bearer | `admin-role` | Full user list |
| `GET /api/admin/dashboard` | Bearer | `admin-role` | Mock admin stats |
| `GET /api/token/info` | Bearer | any | Decoded claims of the supplied token |
| `GET /api/dpop-protected` | DPoP | any (DPoP-bound) | Per RFC 9449 |

JWT validation uses `_decode_token(raw)`:
- JWKS resolved via `PyJWKClient(JWKS_URL, cache_keys=True,
  cache_jwk_set=False)`
- RS256 only
- `verify_iss=True` (`KEYCLOAK_ISSUER`)
- `verify_aud=False` (deliberate — simplifies the demo; real deployments
  should validate the audience)
- 30s leeway on `exp`

Role enforcement via `require_role(<role>)` dependency factory that wraps
`get_current_user` and checks `payload["realm_access"]["roles"]`.

DPoP validation is performed by `_validate_dpop_proof` and is full
RFC 9449 §4.3: signature, `htm`, `htu`, `iat` (60s window),
`cnf.jkt` match, `ath` match.

---

## 9. Client-app surface

### 9.1 Configuration via environment variables

| Variable | Default | Notes |
|---|---|---|
| `KEYCLOAK_EXTERNAL_URL` | `http://localhost:8080` | `KC_EXT` |
| `KEYCLOAK_INTERNAL_URL` | `http://keycloak:8080` | `KC_INT` |
| `KEYCLOAK_REALM` | `demo` | |
| `KEYCLOAK_CLIENT_ID` | `demo-client` | |
| `KEYCLOAK_CLIENT_SECRET` | `demo-client-secret` | |
| `SERVICE_CLIENT_ID` | `service-client` | |
| `SERVICE_CLIENT_SECRET` | `service-client-secret` | |
| `MIDDLE_TIER_CLIENT_ID` | `middle-tier-client` | |
| `MIDDLE_TIER_CLIENT_SECRET` | `middle-tier-client-secret` | |
| `DPOP_CLIENT_ID` | `dpop-client` | |
| `DPOP_CLIENT_SECRET` | `dpop-client-secret` | |
| `DEVICE_CLIENT_ID` | `device-client` | |
| `DEVICE_CLIENT_SECRET` | `device-client-secret` | |
| `PKCE_CLIENT_ID` | `pkce-client` | |
| `RESOURCE_SERVER_URL` | `http://resource-server:8001` | |
| `SPIFFE_SERVICE_URL` | `http://spiffe-service:8002` | |
| `MCP_SERVICE_URL` | `http://mcp-service:8003` | Display only |
| `AGENT_SECRET_URL` | `http://agent-secret:9001` | UC1 backend |
| `AGENT_SPIFFE_URL` | `http://agent-spiffe:9002` | UC2 backend |
| `AGENT_CERT_URL` | `http://agent-cert:9003` | UC3a backend |
| `REDIRECT_URI` | `http://localhost:5000/auth/callback` | |
| `SECRET_KEY` | dev-secret-key-… | Flask session cookie key |
| `DOCS_DIR` | `/app/docs` | Bound from host `./docs` |

### 9.2 Session model

Flask session (encrypted cookie, key = `SECRET_KEY`) carries:

```python
session["token_data"] = {
    "access_token":  str,
    "id_token":      str,                # optional, OIDC flows only
    "refresh_token": str,                # optional, interactive flows only
    "expires_at":    float,              # absolute time.time() at expiry
    "expires_in":    int,                # from Keycloak
    "flow":          str,                # human-readable flow name
    "token_type":    "Bearer",
    "scope":         str,
}
session["oauth_state"]    = str          # CSRF guard during Auth Code
session["oauth_nonce"]    = str          # replay guard for id_token
session["pkce_flow"]      = bool         # switches /auth/callback to PKCE path
session["pkce_verifier"]  = str          # during PKCE
session["pkce_challenge"] = str          # during PKCE
session["device_code"]    = str          # during Device Grant polling
session["device_expires"] = float        # ...
session["device_interval"] = int         # ...
```

### 9.3 Routes summary (see CLAUDE.md for full list)

All under `/auth/*` for OAuth flows, `/api/call/*` for resource-server
proxy, `/agentic/*` for AI agents, `/docs/*` for markdown rendering,
`/token/inspect` for the JWT decoder UI.

---

## 10. Extension contracts

### 10.1 Adding a new OAuth2 flow

1. Identify the Keycloak client (existing or new).
2. If new client: add to `realm-export.json` AND
   `keycloak-init/setup.py`'s `ensure_*` family.
3. Add `client-app/app.py` route — copy pattern from the closest existing
   flow.
4. Add a card in `client-app/templates/index.html` "Advanced Flows" row.
5. Update `docs/oauth2-flows.md` with a new section including a Mermaid
   sequence diagram.

### 10.2 Adding a new Agentic AI use case

See `CLAUDE.md` §3 "AGENT_REGISTRY for new agents". Six files to touch.

### 10.3 Adding a new MCP tool

Single file: `mcp-service/main.py` — append a `@mcp.tool()` function.
The MCP SDK derives the input schema from type hints. All agents pick up
the new tool automatically via `tools/list`.

### 10.4 Adding a new resource-server endpoint

Single file: `resource-server/main.py` — add a route with the appropriate
dependency (`Depends(get_current_user)` for any token,
`Depends(require_role("<role>"))` for role-gated).

### 10.5 Adding a new Keycloak role

1. Add to `realm-export.json` `roles.realm` array.
2. Add an `ensure_<role>_role` function to `keycloak-init/setup.py` and
   call it from `main()`.
3. Bind to relevant service accounts via existing
   `ensure_*_role_on_service_account` pattern.

---

## 11. Non-goals (explicit)

These are intentionally out of scope:

- **HTTPS / TLS in the demo stack.** All inter-service traffic is plain
  HTTP. UC3b (mTLS) is the one exception and is deferred — see
  `docs/ROADMAP-uc3b-mtls.md`.
- **Audience enforcement at resource-server.** `verify_aud=False` is
  deliberate; production deployments should set this to True with an
  explicit `audience=` and an audience mapper per resource.
- **Token caching at agents.** Each `/run` invocation fetches a fresh
  token. Production agents should cache and refresh.
- **Real-time UI updates.** Agent runs are synchronous on the Flask side
  (`requests.post` with 120s timeout). SSE / WebSocket streaming was
  considered and deferred.
- **Multi-tenant Keycloak.** One realm (`demo`); adding realms is left
  to the reader.
- **Cert-bound resource server access (`cnf.x5t#S256`).** The MCP service
  does NOT validate this claim even when present. See
  `docs/ROADMAP-uc3b-mtls.md` §"Cert-bound tokens at the resource server".

---

## 12. Versioning and changelog

The project is currently at the equivalent of **v1.0** — feature-complete
for the original scope plus the Agentic AI section. No formal versioning
or changelog exists; significant changes should be reflected here and in
`CLAUDE.md`.

Deferred work:
- UC3b — true mTLS (`docs/ROADMAP-uc3b-mtls.md`)
- Documentation refinements / additional learner docs as needed
