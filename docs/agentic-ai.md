# Agentic AI — Authenticated MCP Access

This section adds four demos to the project, each showing a different way an
AI agent can authenticate (or be delegated to) when calling a protected
**Model Context Protocol (MCP)** server. The agents are containerised Python services that drive the official
**Anthropic SDK** tool-use loop; the MCP server speaks the real
**MCP Streamable HTTP** transport (official `mcp` Python SDK) over OAuth 2.1
Bearer tokens.

The four patterns differ in *how the agent obtains its access token* and
*whose identity is in the token*:

| # | Use case | Auth mechanism | Identity in token | Demo container |
|---|----------|----------------|---------------|----------------|
| UC1 | **Client Secret** | OAuth 2.0 Client Credentials (RFC 6749 §4.4) | `sub` = service account | `agent-secret` (:9001) |
| UC2 | **SPIFFE Workload Identity** | SPIRE attestation → RFC 7523 `private_key_jwt` | `sub` = service account | `agent-spiffe` (:9002) |
| UC3a | **X.509 Certificate** | CA-issued cert → RFC 7523 `private_key_jwt` | `sub` = service account | `agent-cert` (:9003) |
| UC4 | **User-Delegated (OBO + Rescope)** | RFC 8693 Token Exchange | `sub` = **the human user**; `act` = agent | `agent-delegated` (:9004) |

The MCP server (`mcp-service` on port 8003) is the same for all four. The
agents all run the same task against the same tools — only the
credential machinery and (for UC4) the identity model change.

---

## Architecture

```mermaid
graph TB
    subgraph Browser["User's Browser"]
        UI["Flask UI<br/>/agentic"]
    end

    subgraph Flask["client-app :5000"]
        Routes["/agentic/&lt;slug&gt;"]
    end

    subgraph Agents["AI Agent containers"]
        A1["agent-secret<br/>:9001<br/>UC1"]
        A2["agent-spiffe<br/>:9002<br/>UC2"]
        A3["agent-cert<br/>:9003<br/>UC3a"]
    end

    subgraph Keycloak["Keycloak :8080"]
        KC["realm: demo<br/>clients: ai-agent-{secret,spiffe,cert}<br/>scope: mcp · role: mcp-user"]
    end

    subgraph SPIRE["SPIRE"]
        SS["spire-server"]
        SA["spire-agent"]
    end

    subgraph PKI["X.509 PKI"]
        CI["cert-init<br/>(one-shot)"]
        Vol["agent-cert-pki<br/>volume"]
    end

    subgraph MCP["MCP Service :8003"]
        Disco["/.well-known/<br/>oauth-protected-resource"]
        Trans["POST /mcp<br/>Streamable HTTP<br/>Bearer required"]
        Tools["list_products<br/>get_product_details"]
    end

    Claude["Anthropic API<br/>claude-haiku-4-5"]

    UI --> Routes
    Routes -- "POST /run" --> A1
    Routes -- "POST /run" --> A2
    Routes -- "POST /run" --> A3

    A1 -- "client_credentials" --> KC
    A2 -- "private_key_jwt" --> KC
    A3 -- "private_key_jwt" --> KC

    SS <--> SA
    SA -- "Workload API" --> A2

    CI --> Vol
    Vol --> A3

    KC -- "GET /jwks" --> A2
    KC -- "GET /jwks" --> A3

    A1 -- "Bearer + MCP" --> Trans
    A2 -- "Bearer + MCP" --> Trans
    A3 -- "Bearer + MCP" --> Trans

    A1 -- "tool calls" --> Claude
    A2 -- "tool calls" --> Claude
    A3 -- "tool calls" --> Claude

    Trans --> Tools
```

The Flask client-app is a passthrough — it triggers each agent's `/run`
endpoint and renders the structured trace the agent returns. All the OAuth2,
SPIFFE, and MCP work happens inside the agent containers, which is what
would run in production.

---

## MCP server protection

The MCP server is a FastAPI app with the official `mcp` SDK mounted at
`/mcp`. Bearer enforcement is implemented as middleware that gates the MCP
endpoint only — discovery and health stay anonymous.

### Discovery (RFC 9728)

```
GET http://localhost:8003/.well-known/oauth-protected-resource
```

```json
{
  "resource":                 "http://localhost:8003",
  "authorization_servers":    ["http://localhost:8080/realms/demo"],
  "bearer_methods_supported": ["header"],
  "scopes_supported":         ["mcp"]
}
```

Any MCP client without a token sees this metadata advertised in the
`WWW-Authenticate` header of a 401 response and can use it to bootstrap an
OAuth flow per the MCP authorization spec.

### Token validation

Performed on every request to `/mcp`, in order:

1. JWKS signing-key resolution via `kid`
2. RS256 signature
3. `iss` matches Keycloak
4. `exp` not in the past (30 s leeway)
5. `aud` contains `mcp-service`
6. `scope` claim contains `mcp`

Failure produces 401 with `WWW-Authenticate: Bearer error="invalid_token",
resource_metadata="..."`.

### Tools

| Tool | Input | Returns |
|------|-------|---------|
| `list_products` | none | Array of products (id, name, price, category, stock) |
| `get_product_details` | `product_id: int` | One product or `{"error": "..."}` |

These tools share the catalogue data with `resource-server` so the demo
remains tightly coupled to the existing OAuth2 demos.

---

## The agent tool-use loop

All four agents run the same loop after the authentication step.  Only the
"Auth — varies by use case" lane in the diagram differs: UC1 does Client
Credentials, UC2 attests via SPIRE then exchanges a `client_assertion`, UC3a
loads a cert from a volume and exchanges a `client_assertion`, UC4 performs
an RFC 8693 token exchange using the user's token as the subject.

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant F as Flask /agentic
    participant A as Agent (any UC)
    participant KC as Keycloak
    participant M as MCP Service
    participant CL as Claude API

    U->>F: Click "Run Agent"
    F->>A: POST /run

    Note over A,KC: Auth — varies by use case
    A->>KC: Token request (varies)
    KC-->>A: access_token (aud=mcp-service, scope=mcp)

    A->>M: Streamable HTTP session<br/>Authorization: Bearer <access_token>
    M-->>A: session initialised
    A->>M: tools/list
    M-->>A: [list_products, get_product_details]

    Note over A,CL: Tool-use loop until stop_reason ≠ tool_use
    loop until Claude returns a final answer
        A->>CL: messages.create(task, tools, messages)
        CL-->>A: content[] (text + tool_use blocks)
        opt for each tool_use block
            A->>M: tools/call
            M-->>A: tool result
        end
        A->>A: append assistant + tool_result turns
    end

    A-->>F: structured trace<br/>{auth, mcp, turns, final_answer}
    F-->>U: rendered page
```

If `ANTHROPIC_API_KEY` is unset each agent runs a deterministic mock loop
that issues the same MCP calls a real run would, so the demo works
end-to-end without an external dependency.

---

## UC1 — Client Secret

### Flow

```mermaid
sequenceDiagram
    autonumber
    participant A as agent-secret
    participant KC as Keycloak
    participant M as MCP Service

    A->>KC: POST /token<br/>grant_type=client_credentials<br/>client_id=ai-agent-secret<br/>client_secret=...<br/>scope=mcp
    KC->>KC: Validate secret<br/>Include mcp scope mapper<br/>aud += mcp-service
    KC-->>A: access_token (JWT, RS256)
    A->>M: POST /mcp (Bearer access_token)
    M-->>A: MCP session
```

### Prerequisites

- Client `ai-agent-secret`: `serviceAccountsEnabled=true`, secret configured
- `mcp` client scope (with audience mapper `aud += mcp-service`) assigned as **optional** scope on the client
- Realm role `mcp-user` assigned to the client's service account

### What makes this UC1

- A static `client_secret` is the credential.
- Simplest pattern, suitable when a secret store is available (Vault,
  Kubernetes secrets, AWS Secrets Manager).
- **Risk:** secret theft = full impersonation until rotation.

### Run

```bash
# In Flask UI
open http://localhost:5000/agentic/client-secret

# Or directly
curl -s -X POST http://localhost:9001/run | jq
```

---

## UC2 — SPIFFE Workload Identity

### Flow

```mermaid
sequenceDiagram
    autonumber
    participant A as agent-spiffe
    participant SA as SPIRE agent
    participant KC as Keycloak
    participant M as MCP Service

    Note over A: Startup: generate ephemeral EC P-256 key,<br/>expose GET /jwks
    A->>SA: Workload API: fetch_jwt_svids()
    Note over SA: Match unix:uid:1000 selector,<br/>validate workload entry
    SA-->>A: JWT-SVID (ES256, ~5 min TTL)<br/>sub=spiffe://demo.local/ai-agent-spiffe

    Note over A: Build RFC 7523 client_assertion<br/>iss/sub=ai-agent-spiffe<br/>aud=token_endpoint (public URL)<br/>signed with EC private key

    A->>KC: POST /token<br/>grant_type=client_credentials<br/>client_assertion_type=jwt-bearer<br/>client_assertion=<JWT><br/>scope=mcp
    KC->>A: GET /jwks
    A-->>KC: JWKS (public EC key)
    KC->>KC: Verify ES256 signature
    KC-->>A: access_token
    A->>M: POST /mcp (Bearer access_token)
    M-->>A: MCP session
```

### Prerequisites

- SPIRE workload entry: `spiffe://demo.local/ai-agent-spiffe`, selector `unix:uid:1000`, parent `spiffe://demo.local/agents/demo-agent`
- Agent container runs as UID 1000 (in `Dockerfile`: `useradd -u 1000`) and shares PID namespace with `spire-agent` (`pid: "service:spire-agent"` in `docker-compose.yml`)
- Keycloak client `ai-agent-spiffe`: `clientAuthenticatorType=client-jwt`, `jwks_url=http://agent-spiffe:9002/jwks`
- `mcp` scope as optional, `mcp-user` role on the service account

### Why two JWTs (SVID and client_assertion)

RFC 7523 requires `iss == sub == OAuth2 client_id`, but the JWT-SVID's `sub`
is the SPIFFE ID (`spiffe://demo.local/ai-agent-spiffe`) — Keycloak would
refuse it. So the agent uses:

| JWT | Purpose | iss/sub | Key | Signed by |
|-----|---------|---------|-----|-----------|
| JWT-SVID | Runtime proof of attestation (shown in trace) | SPIFFE ID | SPIRE | SPIRE CA |
| client_assertion | OAuth2 client auth | `ai-agent-spiffe` | Agent's ephemeral EC key | Agent itself |

Both come from the same process; the SPIFFE link is implicit (only an
attested workload could have got far enough to call Keycloak).

### What makes this UC2

- No static credential anywhere. The agent has no secret at any moment.
- Key rotates on every container restart.
- Compromising one running container does not compromise others.

### Run

```bash
open http://localhost:5000/agentic/spiffe
curl -s -X POST http://localhost:9002/run | jq
```

---

## UC3a — X.509 Certificate

### Flow

```mermaid
sequenceDiagram
    autonumber
    participant CI as cert-init (once)
    participant V as agent-cert-pki<br/>volume
    participant A as agent-cert
    participant KC as Keycloak
    participant M as MCP Service

    Note over CI,V: Run once at first compose up
    CI->>V: Generate CA key + CA cert
    CI->>V: Generate agent key (EC P-256)
    CI->>V: Sign agent.crt with CA

    Note over A: Startup: load cert + key from /pki<br/>Publish /jwks with x5c chain + x5t#S256

    Note over A: Build RFC 7523 client_assertion<br/>Header: kid + x5t#S256<br/>Signed with cert's private key

    A->>KC: POST /token<br/>grant_type=client_credentials<br/>client_assertion_type=jwt-bearer<br/>client_assertion=<JWT><br/>scope=mcp
    KC->>A: GET /jwks
    A-->>KC: JWKS (with x5c cert chain)
    KC->>KC: Verify ES256 signature
    KC-->>A: access_token
    A->>M: POST /mcp (Bearer access_token)
    M-->>A: MCP session
```

### Prerequisites

- `cert-init` ran once and populated the `agent-cert-pki` volume with `ca.crt`, `agent.key`, `agent.crt`
- Keycloak client `ai-agent-cert`: `clientAuthenticatorType=client-jwt`, `jwks_url=http://agent-cert:9003/jwks`
- `mcp` scope as optional, `mcp-user` role on the service account

### What makes this UC3a

- The certificate IS the credential. Closer to corporate PKI workflows
  (CA → cert → service).
- Key is long-lived and persisted in a Docker volume — restarting the agent
  reuses the same key, so the Keycloak-side JWK keeps matching.
- The JWKS exposes `x5c` (DER cert, base64) and `x5t#S256` (cert thumbprint)
  so the cert chain behind the key is verifiable. Per RFC 7517 §4.7:
  - `x5c` uses **base64** with padding (not base64url)
  - `x` / `y` use **base64url** without padding

### UC3a versus UC2 — the differentiator

Both clients are configured identically on Keycloak (`client-jwt` +
`jwks_url`). The educational difference is in the agent:

| Aspect | UC2 (SPIFFE) | UC3a (Certificate) |
|--------|--------------|--------------------|
| Where does the key come from? | Generated in memory at startup | Loaded from `agent.key` on a shared volume |
| Lifetime | Rotates on every container restart | Long-lived (validity in `agent.crt`) |
| Runtime attestation | Yes (SPIRE selector check) | No — possession of `agent.key` is sufficient |
| Identity proof | JWT-SVID issued by SPIRE | X.509 cert chain (CA → leaf) |
| Recovery from key theft | Restart, key gone | Revoke cert, rotate CA |
| JWKS contents | `kty`, `crv`, `x`, `y` | + `x5c`, `x5t#S256` |

### Regenerating the cert

```bash
docker compose down
docker volume rm oauth2sample_agent-cert-pki
docker compose up -d        # cert-init regenerates everything
```

### Run

```bash
open http://localhost:5000/agentic/cert
curl -s -X POST http://localhost:9003/run | jq
```

---

---

## UC4 — User-Delegated (OBO + Rescoping)

The first three use cases authenticate the agent as **itself** — a service
principal with its own service account.  UC4 inverts this: a logged-in
human delegates a task to the agent, and the agent obtains a token that
**preserves the user's identity** while restricting the scope.

### Flow

```mermaid
sequenceDiagram
    autonumber
    actor U as alice (browser)
    participant CA as client-app :5000
    participant A as agent-delegated :9004
    participant KC as Keycloak
    participant M as MCP Service

    U->>CA: GET /auth/authorization-code
    CA->>KC: Authorization Code flow
    KC-->>CA: T0 (sub=alice, azp=demo-client,<br/>aud includes ai-agent-delegated,<br/>scope=openid profile email roles)
    CA->>U: Logged in
    U->>CA: Click "Run Agent on My Behalf"
    CA->>A: POST /run<br/>{ "user_access_token": T0 }
    Note over A: Single RFC 8693 exchange<br/>combines OBO + scope narrowing
    A->>KC: POST /token<br/>grant_type=token-exchange<br/>subject_token=T0<br/>client_id=ai-agent-delegated<br/>client_secret=…<br/>scope=mcp
    KC->>KC: Validate T0 (audience contains<br/>ai-agent-delegated)<br/>Apply mcp scope mappers<br/>Add act claim
    KC-->>A: T1 (sub=alice, azp=ai-agent-delegated,<br/>act={sub: ai-agent-delegated},<br/>scope=mcp, aud=mcp-service)
    A->>M: MCP session with Bearer T1
    Note over M: Logs custody chain:<br/>"subject=alice actors=ai-agent-delegated"
    M-->>A: tools/list, then tool calls
    A->>A: Anthropic tool-use loop<br/>(system: "you act on behalf of alice")
    A-->>CA: AgentRun trace + custody summary + scope diff
    CA-->>U: Render result page
```

### What's preserved, what's added, what's dropped

A side-by-side diff of T0 (the user's login token) and T1 (the delegated
token the agent uses for MCP):

| Claim | T0 (user) | T1 (delegated) | Change |
|-------|-----------|----------------|--------|
| `sub` | `<alice's UUID>` | `<alice's UUID>` | **Preserved** |
| `azp` | `demo-client` | `ai-agent-delegated` | Changed — the actor |
| `act` | (absent) | (absent — see note below) | — |
| `azp` (effective actor) | `demo-client` | **`ai-agent-delegated`** | **The acting party** |
| `scope` | `openid profile email roles` | `mcp` | **Narrowed** |
| `aud` | `[demo-client, middle-tier-client, ai-agent-delegated]` | `[mcp-service]` | Narrowed |
| `realm_access.roles` | `[admin-role, user-role]` | (absent) | **Dropped** with the roles scope |

The dropped roles claim is the **point** of rescoping: even though alice is
an admin, the token the agent holds cannot perform admin actions because the
roles scope was not requested in the exchange.  This is the principle of
least privilege.

> **Note on the `act` claim.**  RFC 8693 §4.1 specifies that the resulting
> token's `act` claim names the actor.  In practice, **Keycloak 26's V2
> (standard) token exchange does not emit `act` by default** for single-hop
> exchanges — instead it sets `azp` to the exchanging client and leaves the
> custody trail there.  Adding a literal `act` claim would require a custom
> protocol mapper (Keycloak SPI work).
>
> The MCP audit log and the agent's custody display both fall back to `azp`
> when `act` is absent **AND** the subject is a human user
> (`preferred_username` doesn't start with `service-account-`).  This
> preserves the audit information; only the claim name differs.  Nested
> multi-hop exchanges (alice → middle-tier → agent) would emit `act`
> properly and the code walks that chain correctly.

### Prerequisites

- Keycloak client `ai-agent-delegated`:
  - `clientAuthenticatorType=client-secret` (confidential)
  - `serviceAccountsEnabled=true` (Keycloak requires this for token-exchange
    initiator clients)
  - `standard.token.exchange.enabled=true` attribute
- Audience mapper on `demo-client`: adds `ai-agent-delegated` to `aud` of
  alice's tokens so the exchange is permitted (Keycloak rejects exchanges
  where the exchanging client isn't in the subject_token's audience)
- `mcp` client scope assigned as **optional** to `ai-agent-delegated`
- **No `mcp-user` role** on the service account — the resulting token's
  identity is the user, not the service account.  The MCP server validates
  scope + audience but does not enforce roles, so this is enough.

### What makes this UC4

- The agent acts as an **intermediary**, not an actor in its own right.
- The MCP server's audit logs attribute every tool call back to BOTH the
  user (subject) and the agent (actor in the act chain).
- The token's scope is strictly narrower than the user's original — the
  agent literally cannot do things outside the delegated scope, even
  though the user could.
- Compromising the agent only exposes the narrow scope. The user's broader
  permissions remain untouched.

### MCP server audit logging

Every accepted Bearer token is logged with its custody chain. Watch the
mcp-service container while running UC4:

```bash
docker logs -f oauth2-mcp-service | grep "MCP token accepted"
```

Sample output for a UC4 run:

```
MCP token accepted — subject=alice actors=ai-agent-delegated scope=profile email mcp azp=ai-agent-delegated
```

Compare to UC1's direct service-principal access (no delegation):

```
MCP token accepted — subject=service-account-ai-agent-secret (direct, no delegation) scope=profile email mcp azp=ai-agent-secret
```

The single line tells you exactly who acted, on whose behalf, and with
what authorization — the full custody chain in one place.

### Run

```bash
# Log in first (any of the three test accounts works — alice has the most roles)
open http://localhost:5000/auth/authorization-code

# Then trigger the delegated agent
open http://localhost:5000/agentic/user-delegated-rescope

# Or via curl (after logging in — copy the access token from /token/inspect)
curl -s -X POST http://localhost:9004/run \
     -H "Content-Type: application/json" \
     -d "{\"user_access_token\": \"$T0\"}" | jq
```

### UC4 versus UC1/UC2/UC3a

| Question | UC1/UC2/UC3a (service principal) | UC4 (user-delegated) |
|----------|----------------------------------|---------------------|
| Who needs to be logged in? | Nobody | The human user |
| What is `sub` in the MCP-bound token? | The agent's service account | The user |
| What is in the `act` claim? | (absent) | The agent |
| What grant type to Keycloak? | `client_credentials` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| Can the agent be more privileged than the user? | Yes (its own scope/roles) | No (strictly bounded by user's permissions + the requested scope) |
| Suitable for | Background jobs, scheduled tasks, infrastructure-to-infrastructure | AI assistants, copilots, "agent acts as me" features |

---

## Implementation notes

A handful of details we had to get right while building this section, kept
here so anyone extending the demos doesn't trip over the same problems.

### FastMCP path collision with Starlette mount

`FastMCP.streamable_http_app()` defaults its internal path to `/mcp`. When
that app is mounted under `/mcp` in the parent FastAPI app, the effective
URL becomes `/mcp/mcp/` and the parent issues a 307 redirect that the
client follows to a 404. Fix:

```python
mcp = FastMCP("mcp-service", stateless_http=True, streamable_http_path="/")
app.mount("/mcp", mcp.streamable_http_app())
```

### FastMCP session manager lifespan

The Starlette app returned by `streamable_http_app()` ships its own
lifespan that starts the session manager. **Mounted apps do not get their
lifespan run** by the parent — so `/mcp` returns 500 until the parent
drives the session manager itself:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ... your own setup ...
    async with mcp.session_manager.run():
        yield
```

### FastMCP list returns are one TextContent per element

A tool returning `list[dict]` produces multiple `TextContent` objects in
the `CallToolResult.content` array, not a single JSON array. A naive
`content[0].text` only sees the first element. Collect all parts:

```python
texts = [c.text for c in result.content if getattr(c, "text", None)]
parsed = [json.loads(t) for t in texts]
```

### Keycloak assertion audience

Keycloak validates a `client_assertion`'s `aud` claim against its
**published** token endpoint URL (`KC_HOSTNAME`-derived, e.g.
`http://localhost:8080/...`), not the internal Docker URL the request
arrives on. Use OIDC discovery to find the right value at startup:

```python
disc = httpx.get(f"{KC_INT}/realms/{REALM}/.well-known/openid-configuration").json()
aud  = disc["token_endpoint"]
```

### SPIRE selectors must be distinct

`spiffe-service` and `ai-agent-spiffe` both connect to the same SPIRE
agent. If both register with `unix:uid:0`, SPIRE issues BOTH SPIFFE IDs to
BOTH containers — and the audit trail is meaningless. The fix: register
the new agent with a different UID (`unix:uid:1000`) and run the container
as that UID.

### `x5c` encoding

`x5c` entries are **base64** (RFC 4648 §4, padded), not base64url. The JWK's
`x` and `y` are base64url without padding. Using the wrong one breaks the
JWKS endpoint silently.

---

## Troubleshooting

### Agent returns `"token audience doesn't match"`

The `mcp` scope wasn't included in the token request, or the audience mapper
isn't on the scope, or the scope isn't assigned to the client. Re-run
`docker compose run --rm keycloak-init` — it's idempotent.

### MCP returns 401 even with a valid-looking token

Check the token contains `scope=...mcp...`. The MCP server enforces both
audience and scope; either failure produces the same 401.

### Agent run returns `"unhandled errors in a TaskGroup (1 sub-exception)"`

This is anyio's wrapper. Look in the agent's container logs
(`docker logs oauth2-agent-secret`) — the actual exception is nested
inside. Common causes: MCP server unreachable, `/jwks` not responding (for
UC2/UC3), bad audience.

### `agent-spiffe` returns `"SPIRE returned no JWT-SVIDs"`

Either the workload entry isn't registered (check
`spire-server entry show`), or the selector doesn't match (the container
must run as UID 1000 and share the agent's PID namespace).

### `agent-cert` fails to start with "no such file or directory: /pki/agent.crt"

`cert-init` didn't run. From the host:
```bash
docker compose run --rm cert-init
docker compose up -d agent-cert
```

### Resetting the entire Agentic AI stack

```bash
docker compose down -v          # nukes all volumes including the cert PKI
docker compose up -d --build    # rebuilds, regenerates the cert, re-runs keycloak-init
```
