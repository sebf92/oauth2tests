# CLAUDE.md — Claude Code instructions for the OAuth2 + JWT + Agentic AI demo

This file is the **canonical orientation document** for any AI agent (Claude
Code or otherwise) extending this project. Read it first before touching any
source file.

For deeper detail:
- System layout & containers → `docs/PROJECT-ARCHITECTURE.md`
- Per-flow + per-component specs → `docs/PROJECT-SPECIFICATION.md`
- Agentic AI section (live) → `docs/agentic-ai.md`
- Deferred UC3b mTLS plan → `docs/ROADMAP-uc3b-mtls.md`
- Learner-facing docs (rendered in the Flask UI at `/docs`) →
  `docs/architecture.md`, `docs/oauth2-flows.md`, `docs/spiffe-oauth2.md`,
  `docs/obo-manual-setup.md`, `docs/keycloakbrokeringtoping.md`

---

## What this project is

An end-to-end **educational demonstration** of OAuth2 / OpenID Connect /
SPIFFE / MCP-authenticated AI agents, backed by Keycloak 26.6.1 and a
multi-container Docker stack. Eleven OAuth2 / OIDC flows and five agentic
AI patterns are demonstrated **live and clickable** from a Flask web UI on
`http://localhost:5000`.

The intent is pedagogical, not production-grade. Code paths and configuration
favour clarity over enterprise hardening. New work must preserve that bias.

## Tech stack (do not change without strong reason)

| Layer | Technology | Version |
|---|---|---|
| Identity Provider | Keycloak | 26.6.1 |
| Persistence (KC) | PostgreSQL | 16-alpine |
| Web client | Flask + Jinja2 + Bootstrap 5 | latest stable |
| Resource server | FastAPI + PyJWT | 0.111 / 2.8 |
| SPIFFE | SPIRE | 1.10.0 |
| MCP server/client | Official `mcp` Python SDK | 1.12+ |
| AI agent loop | Anthropic Python SDK | 0.40+ |
| Default agent model | `claude-haiku-4-5-20251001` | |
| Container orchestration | Docker Compose | v2 |

## Repository layout

```
client-app/          Flask UI on :5000 — all eleven OAuth2 demos + Agentic AI section
resource-server/     Protected FastAPI API on :8001 — JWT validation, role enforcement
keycloak/            realm-export.json — initial KC realm definition
keycloak-init/       One-shot container that idempotently applies KC config changes
                     not expressible in realm-export.json
spire/               SPIRE server + agent + workload registration scripts
spiffe-service/      Demo SPIFFE-attested service on :8002 (separate from agentic AI)
mcp-service/         Real MCP HTTP server on :8003 — protected by Bearer JWT
ai-agents/
  agent-secret/      UC1 :9001 — Client Credentials → MCP
  agent-spiffe/      UC2 :9002 — SPIFFE attestation → RFC 7523 → MCP
  agent-spiffe-mtls/ UC2-Hardened :9005 — SPIFFE → mTLS (RFC 8705) → MCP
  agent-cert/        UC3a :9003 — X.509 cert → RFC 7523 → MCP
  agent-delegated/   UC4 :9004 — RFC 8693 OBO + rescope → MCP (requires logged-in user)
cert-init/           One-shot container that generates CA + agent.crt for UC3a
keycloak-mtls-proxy/ nginx sidecar on :8443 for UC2-Hardened — terminates mTLS using a
                     SPIRE-issued server cert, validates client certs against the SPIRE
                     trust-domain bundle, forwards to Keycloak with the cert in a header
docs/                Markdown docs (rendered in the Flask UI via DOCS_MANIFEST in
                     client-app/app.py) + AI-agent reference docs (ALL-CAPS prefix)
docker-compose.yml   Single source of truth for all services + volumes + network
```

## How to run, build, and verify

```bash
# Full first run (builds images, generates SPIRE + cert PKI, runs keycloak-init):
docker compose up -d --build

# Rebuild and restart a single service after editing:
docker compose up -d --build <service>          # e.g. agent-secret, mcp-service

# Apply Keycloak config changes (idempotent — safe to re-run):
docker compose build keycloak-init
docker compose run --rm keycloak-init

# Watch logs:
docker logs -f oauth2-<service>                  # mcp-service, agent-secret, …

# Smoke-test the four Agentic AI agents (returns structured JSON traces):
curl -s -X POST http://localhost:9001/run        # UC1
curl -s -X POST http://localhost:9002/run        # UC2
curl -s -X POST http://localhost:9005/run        # UC2-Hardened
curl -s -X POST http://localhost:9003/run        # UC3a
# UC4 requires a logged-in user — fetch T0 first via /token/inspect:
curl -s -X POST http://localhost:9004/run \
     -H "Content-Type: application/json" \
     -d "{\"user_access_token\": \"$T0\"}"        # UC4

# Smoke-test the MCP server discovery (no auth needed):
curl -s http://localhost:8003/.well-known/oauth-protected-resource

# UI entry points:
#   http://localhost:5000/                       Home — all flow buttons
#   http://localhost:5000/agentic                Agentic AI section
#   http://localhost:5000/docs                   Rendered markdown documentation

# Full reset (wipes Postgres + SPIRE state + UC3a PKI):
docker compose down -v
docker compose up -d --build
```

The Anthropic-driven tool-use loop activates only when `ANTHROPIC_API_KEY` is
set in the environment (or `.env`); otherwise every agent runs a deterministic
mock that exercises the same MCP calls. Adding `ANTHROPIC_API_KEY` requires
restarting the agent containers (`docker compose up -d agent-secret
agent-spiffe agent-cert`).

## Critical conventions

These are pervasive across the codebase. New code must match them.

### 1. Dual-URL pattern (`KC_EXT` vs `KC_INT`)

Keycloak runs at two different URLs depending on who's calling it:
- **`KC_EXT = http://localhost:8080`** — browser-facing (host port mapping).
  Used for redirects (Auth Code, RP-initiated logout, OIDC discovery in templates).
- **`KC_INT = http://keycloak:8080`** — server-to-server (Docker DNS).
  Used for token endpoint, introspection, JWKS fetch.

`KC_HOSTNAME=localhost` (on the Keycloak container) ensures Keycloak publishes
its token endpoint as `http://localhost:8080/...`, so the `iss` claim in JWTs
matches `KC_EXT` and OIDC discovery returns `KC_EXT` URLs.

**Where this matters:** any agent building an RFC 7523 `client_assertion`
must use the **published** URL (from OIDC discovery `token_endpoint`) as the
`aud` claim, not the internal URL it actually POSTs to. Pattern lives in
`spiffe-service/main.py` and `ai-agents/agent-{spiffe,cert}/agent.py` — copy
when adding new clients of this kind.

### 2. Idempotent `keycloak-init` for upgrades

Keycloak only processes `realm-export.json` when the realm doesn't yet exist.
For an existing demo install, new clients/roles/scopes in the export are
**ignored**. Therefore every realm modification has two parts:

1. Add the change to `keycloak/realm-export.json` (for fresh installs)
2. Add an idempotent `ensure_*` function to `keycloak-init/setup.py` (for
   upgrades) and call it from `main()`

All existing functions in `keycloak-init/setup.py` follow this shape —
copy the closest one. Examples:
- New role → `ensure_mcp_user_role` (creates if missing)
- New client → `ensure_ai_agent_secret_client` (creates if missing)
- New scope → `ensure_mcp_client_scope` (creates scope + protocol mappers)
- Scope binding → `ensure_mcp_scope_on_client`
- Role assignment → `ensure_mcp_role_on_service_account`

### 3. `AGENT_REGISTRY` for new agents

To add a new agentic AI demo:
1. Create `ai-agents/<name>/` with `Dockerfile`, `requirements.txt`, `agent.py`
   following the closest existing pattern:
   - **Service-principal agents** (agent authenticates as itself): clone
     `agent-secret` (client_credentials) / `agent-spiffe` (SPIFFE +
     private_key_jwt) / `agent-cert` (X.509 + private_key_jwt).
   - **User-delegated agents** (agent acts on behalf of a logged-in user):
     clone `agent-delegated` (RFC 8693 token exchange) — `POST /run`
     accepts a `{"user_access_token": "..."}` body via pydantic.
2. Agent must expose `GET /info`, `GET /health`, `POST /run` returning the
   structured trace dataclass shape used by `agentic_result.html`
3. Add a service in `docker-compose.yml`
4. Add an `AGENT_REGISTRY` entry to `client-app/app.py`. For user-delegated
   agents, set `requires_user_token: True` so the route layer gates on a
   session and forwards `td["access_token"]` automatically.
5. Update `client-app/templates/index.html` and
   `client-app/templates/agentic_index.html` with a card pointing at
   `/agentic/<slug>`
6. Add a section to `docs/agentic-ai.md`

The Flask route `/agentic/<slug>` is generic — no Flask code change needed
beyond the registry entry.

### 4. `DOCS_MANIFEST` for new markdown docs

To add a markdown documentation page rendered in the Flask UI:
1. Create `docs/<slug>.md`
2. Add an entry to `DOCS_MANIFEST` in `client-app/app.py` with `slug`,
   `file`, `title`, `icon` (Bootstrap Icons class), `color`
   (`primary`/`success`/`info`/`warning`/`danger`), `badge`, `description`
3. The Flask route `/docs/<slug>` is generic — no route changes needed

Mermaid diagrams in markdown files are auto-rendered via the
`_MERMAID_FENCE_RE` pipeline in `client-app/app.py`. Use ` ```mermaid ` fences.

### 5. Mermaid in user docs

Diagram blocks must use the ` ```mermaid ` fence. The pipeline:
1. `_MERMAID_FENCE_RE` extracts the source
2. `_html.escape()` encodes it (critical — without this, browser parses `<…>`
   in labels as HTML elements and Mermaid breaks)
3. Wrapped in `<div class="mermaid">` and passed through python-markdown
   unchanged
4. Mermaid.js reads `textContent`, which decodes HTML entities back
5. Renders client-side

**Implication:** safe to use `<br/>`, `<token>`, etc. in mermaid labels —
they survive the round-trip.

## Critical gotchas

Time-eaters that every developer rediscovers if they're not warned.

### FastMCP path collision under Starlette mount

`FastMCP.streamable_http_app()` defaults its path to `/mcp`. Mounting under
`/mcp` in the parent FastAPI app yields `/mcp/mcp/` effective URL → 307 + 404.
Fix in `mcp-service/main.py`:
```python
mcp = FastMCP("mcp-service", stateless_http=True, streamable_http_path="/")
app.mount("/mcp", mcp.streamable_http_app())
```

### FastMCP session manager lifespan not propagated

`streamable_http_app()`'s lifespan is **not** automatically run when the app
is mounted. Without driving it from the parent, `/mcp` returns HTTP 500. Fix
in `mcp-service/main.py`:
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ... own setup ...
    async with mcp.session_manager.run():
        yield
```

### FastMCP list returns are one TextContent per element

A tool returning `list[dict]` produces multiple `TextContent` objects in
`CallToolResult.content`, not a single JSON array. A naive `content[0].text`
only sees the first element. Use the `_mcp_result_to_python` helper in any
of the agent files — copy when implementing a new MCP client.

### SPIRE selectors must be distinct between workloads

Four SPIRE workloads share the same agent — UID 0 (`spiffe-service`),
UID 1000 (`ai-agent-spiffe`), UID 1001 (`ai-agent-spiffe-mtls`), and
UID 1002 (`keycloak-mtls-proxy`). Same selector → SPIRE issues all SPIFFE
IDs to all matching containers and audit trails become meaningless. When
adding a new SPIRE workload, choose a distinct UID + run the container as
that UID + register with `unix:uid:<N>`. PID-namespace sharing
(`pid: "service:spire-agent"`) is also required.

### `x5c` uses base64 (not base64url)

RFC 7517 §4.7. The agent-cert JWK has `x5c` encoded with
`base64.b64encode(cert_der)` while `x` and `y` use
`base64.urlsafe_b64encode(...).rstrip(b"=")`. Mixing them up breaks the JWKS
endpoint silently.

### SPIRE entries don't auto-update on existing installs

`spire-init` is `restart: "no"` and only runs the registration script the
first time. After adding a new entry to `spire/setup.sh`, **existing demo
installs do not get the new entry automatically**. Either:
- `docker compose down -v` to wipe everything (clean install path), or
- Run the entry creation manually:
  ```bash
  MSYS_NO_PATHCONV=1 docker exec oauth2-spire-server \
    /opt/spire/bin/spire-server entry create \
    -socketPath /tmp/spire-server/private/api.sock \
    -parentID spiffe://demo.local/agents/demo-agent \
    -spiffeID spiffe://demo.local/<new-id> \
    -selector unix:uid:<N> -ttl 3600
  ```

### UC3a PKI is on a persistent volume

`cert-init` is idempotent — it does **not** regenerate the cert if files
already exist on `agent-cert-pki`. This is intentional (keeps Keycloak's
registered JWK in sync with the agent's key across restarts). To force
regeneration:
```bash
docker compose down
docker volume rm oauth2sample_agent-cert-pki
docker compose up -d
```

### Git Bash path mangling

When running `docker exec` from Git Bash on Windows with Unix-style paths in
arguments, Git Bash converts them to Windows paths and breaks the command.
Workaround: `MSYS_NO_PATHCONV=1 docker exec ...`. Affects SPIRE CLI commands
and any other `docker exec` with absolute Unix paths.

## Where each piece of business logic lives

| What | Where |
|---|---|
| The eleven OAuth2 flows | `client-app/app.py` (one route per flow, well-commented) |
| OAuth2 flow templates | `client-app/templates/` |
| Markdown doc rendering pipeline | `client-app/app.py` → `_render_doc` |
| Keycloak realm seed | `keycloak/realm-export.json` |
| Keycloak idempotent upgrades | `keycloak-init/setup.py` (always call after editing) |
| JWT validation (resource server) | `resource-server/main.py` → `_decode_token` |
| Role-based authorization | `resource-server/main.py` → `require_role` |
| DPoP proof validation | `resource-server/main.py` → `_validate_dpop_proof` |
| SPIFFE → OAuth2 (production-style) | `spiffe-service/main.py` |
| MCP server with Bearer protection | `mcp-service/main.py` |
| Agentic AI agent loop | `ai-agents/agent-*/agent.py` (three near-identical files, deliberately) |
| Cert generation (UC3a) | `cert-init/setup.sh` |
| Agent registration in UI | `client-app/app.py` → `AGENT_REGISTRY` |

## Working on the codebase — defaults

- **Edit, don't rewrite.** Use `Edit` on existing files. Match surrounding
  patterns. The five agent files (`agent-secret`, `agent-spiffe`,
  `agent-spiffe-mtls`, `agent-cert`, `agent-delegated`) have intentional
  duplication so each is self-contained for learning — don't refactor them
  into a shared module without explicit user request.
- **Idempotent Keycloak changes.** Any realm modification needs both a
  `realm-export.json` update AND a `keycloak-init` `ensure_*` function. See
  convention §2 above.
- **Comment the WHY, not the WHAT.** Existing code follows
  `octo:principles:maintainability-principles` style — comments explain
  non-obvious constraints, design decisions, gotchas. Never narrate what
  well-named code already says.
- **Preserve dual-URL pattern.** Any new code that talks to Keycloak must
  pick `KC_EXT` vs `KC_INT` correctly. See convention §1 above.
- **Defer to existing patterns.** Adding a new client follows the
  `ensure_*_client` pattern. Adding a new docs page follows
  `DOCS_MANIFEST`. Adding a new agent follows `AGENT_REGISTRY`. Don't invent
  new patterns when an existing one fits.
- **Never commit unless asked.** The user controls commits. If asked to
  commit, follow the project's commit message style (check `git log`).

## Common edits and where to make them

| Task | Files to touch |
|---|---|
| Add an OAuth2 flow | `client-app/app.py` (new route), `client-app/templates/index.html` (card), maybe `keycloak/realm-export.json` + `keycloak-init/setup.py` (new client) |
| Add a documentation page | `docs/<slug>.md`, `client-app/app.py` → `DOCS_MANIFEST` |
| Add a Keycloak client | `keycloak/realm-export.json` (fresh install) + `keycloak-init/setup.py` (existing install) |
| Add an MCP tool | `mcp-service/main.py` → new `@mcp.tool()` function |
| Add an Agentic AI agent | new directory under `ai-agents/`, `docker-compose.yml`, `AGENT_REGISTRY` in `client-app/app.py`, `index.html` + `agentic_index.html` cards, section in `docs/agentic-ai.md` |
| Modify token validation | `resource-server/main.py` → `_decode_token` (and `mcp-service/main.py` → `_validate_bearer` if same change applies to MCP) |

## Anti-patterns — do not do

- **Do not** add HTTPS to Keycloak directly. The dual-URL pattern relies on
  HTTP-only port 8080. The mTLS path is via the `keycloak-mtls-proxy` sidecar
  on `:8443` (used by UC2-Hardened — see `docs/agentic-ai.md` § UC2-Hardened).
- **Do not** make the mTLS proxy send `X-Forwarded-Proto: https` to Keycloak.
  With `KC_PROXY_HEADERS=xforwarded` set, Keycloak would derive `iss` from
  that header and emit `https://localhost:8080/realms/demo`, which
  resource-server and mcp-service (configured with `KEYCLOAK_ISSUER=http://...`)
  would reject. The proxy sets only `Host` and `X-Forwarded-For`.
- **Do not** persist secrets in the repo. The demo's "secrets"
  (`demo-client-secret`, `ai-agent-secret-secret`, etc.) are *intentional*
  test fixtures, but never add real keys/tokens/passwords.
- **Do not** disable JWT signature verification in resource-server or
  mcp-service. The educational value of the demo depends on the validation
  being real.
- **Do not** change the `iss` claim format without updating the
  `KEYCLOAK_ISSUER` env var on every service that validates tokens
  (resource-server, mcp-service). They currently expect
  `http://localhost:8080/realms/demo`.
- **Do not** introduce new ports without considering the host's existing
  port allocations. Active ports: 5000 (client-app), 8001 (resource-server),
  8002 (spiffe-service), 8003 (mcp-service), 8080 (Keycloak), 9000
  (Keycloak management), 8443 (keycloak-mtls-proxy, used by UC2-Hardened),
  9001/9002/9003/9004 (agents UC1–UC4), 9005 (agent-spiffe-mtls,
  UC2-Hardened), 5432 (Postgres).  UC3b (deferred roadmap) would need to
  pick new ports — the 8443/9005 originally reserved for it are now in use.

## When in doubt

- Read `docs/PROJECT-ARCHITECTURE.md` for component-level questions.
- Read `docs/PROJECT-SPECIFICATION.md` for flow-level / contract questions.
- Read the docstring of the closest existing file/function — most are
  exhaustive.
- Ask the user; do not invent.
