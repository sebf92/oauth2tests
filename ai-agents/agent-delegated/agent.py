"""
AI Agent — Use Case 4: User-Delegated (OBO + Rescoping) → MCP.

A human user logs in to the platform and delegates a task to this agent. The
agent performs an RFC 8693 Token Exchange to act *on the user's behalf*,
combined with scope narrowing in a single call:

  • subject_token  = the user's access token (T0), forwarded by the client-app
  • client_id      = ai-agent-delegated (this agent's own credentials)
  • scope          = mcp  (narrower than T0's scope — least privilege)

Keycloak returns a new token (T1) with:
  • sub             = the user's UUID            ← preserved
  • azp             = ai-agent-delegated         ← the actor
  • act.sub         = ai-agent-delegated         ← custody chain entry
  • scope           = mcp                        ← narrowed
  • aud             = mcp-service                ← narrowed
  • realm_access    = (absent — roles scope dropped)

T1 is used to call the MCP service.  The MCP server logs the actor chain so
that every tool invocation can be attributed back to BOTH the user and the
agent that acted in their name (see mcp-service/main.py).

How this differs from UC1/UC2/UC3a
──────────────────────────────────
The three service-principal agents authenticate as themselves — the MCP
server sees the agent's service account as the caller.  UC4 inverts this:
the user is preserved as the principal, and the agent appears as the
intermediary actor in the act claim.  This is the pattern for
"AI assistants acting on a logged-in user's authority", with auditability
of who did what.

Endpoints
─────────
  GET  /info       Agent metadata (no user token required)
  GET  /health     Liveness probe
  POST /run        Body: {"user_access_token": "<T0>"} — runs the OBO+rescope
                   exchange, then the MCP tool-use loop, returns trace JSON.
"""

import asyncio
import base64
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s — %(message)s")
logger = logging.getLogger("agent-delegated")

# ── Configuration ──────────────────────────────────────────────────────────────
KC_INTERNAL_URL = os.getenv("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
KC_REALM        = os.getenv("KEYCLOAK_REALM",        "demo")
KC_TOKEN_URL    = f"{KC_INTERNAL_URL}/realms/{KC_REALM}/protocol/openid-connect/token"

CLIENT_ID       = os.getenv("AGENT_CLIENT_ID",       "ai-agent-delegated")
CLIENT_SECRET   = os.getenv("AGENT_CLIENT_SECRET",   "ai-agent-delegated-secret")

MCP_SERVER_URL  = os.getenv("MCP_SERVER_URL",        "http://mcp-service:8003/mcp")

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL   = os.getenv("ANTHROPIC_MODEL",   "claude-haiku-4-5-20251001")

AGENT_TASK = os.getenv(
    "AGENT_TASK",
    "I have a $40 budget for a gift. Look at the product catalogue, pick the best "
    "candidate, fetch its full details, and write a one-paragraph recommendation. "
    "Use the MCP tools available to you — do not invent product data.",
)

MAX_TOOL_ITERATIONS = 6


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class UserIdentity:
    """The decoded user token T0 — captures who delegated to the agent."""
    username:        str | None     = None
    sub:             str | None     = None
    email:           str | None     = None
    azp:             str | None     = None
    aud:             Any            = None
    scope:           str | None     = None
    realm_roles:     list[str]      = field(default_factory=list)
    exp:             int | None     = None


@dataclass
class ExchangeStep:
    """Step 1 result — RFC 8693 OBO + rescope exchange outcome."""
    grant_type:      str            = "urn:ietf:params:oauth:grant-type:token-exchange"
    auth_method:     str            = "User-delegated token exchange (RFC 8693)"
    client_id:       str            = CLIENT_ID
    requested_scope: str            = "mcp"
    status_code:     int            = 0
    success:         bool           = False
    error:           str | None     = None
    access_token:    str | None     = None
    token_header:    dict | None    = None
    token_claims:    dict | None    = None
    expires_in:      int | None     = None


@dataclass
class CustodyChain:
    """Audit-trail summary derived from the resulting token's claims.

    Walks the act claim chain so deeper delegations (alice → middle-tier → agent)
    are fully captured.  For the v1 single-hop UC4 the chain has exactly two
    entries: the user (subject) and the agent (act.sub).
    """
    subject:     str | None         = None      # who the action is FOR
    actors:      list[str]          = field(default_factory=list)  # actor chain (inner-most first)
    summary:     str | None         = None      # human-readable one-liner


@dataclass
class ScopeDiff:
    """Side-by-side comparison of scopes before vs after the exchange.

    `kept` is the intersection (scopes present in both); `dropped` is what the
    user had but the new token doesn't; `added` is anything in the new token
    that was not in the original (rare in pure downscoping).
    """
    user_scopes:     list[str]      = field(default_factory=list)
    delegated_scopes: list[str]     = field(default_factory=list)
    kept:            list[str]      = field(default_factory=list)
    dropped:         list[str]      = field(default_factory=list)
    added:           list[str]      = field(default_factory=list)


@dataclass
class McpDiscovery:
    server_url:  str
    tools:       list[dict]         = field(default_factory=list)
    error:       str | None         = None


@dataclass
class AgentTurn:
    iteration:   int
    stop_reason: str | None         = None
    text:        str | None         = None
    tool_calls:  list[dict]         = field(default_factory=list)


@dataclass
class AgentRun:
    started_at:    str
    mode:          str
    model:         str
    task:          str
    user_identity: UserIdentity | None  = None
    auth:          ExchangeStep | None  = None
    custody:       CustodyChain | None  = None
    scope_diff:    ScopeDiff | None     = None
    mcp:           McpDiscovery | None  = None
    turns:         list[AgentTurn]      = field(default_factory=list)
    final_answer:  str | None           = None
    duration_ms:   int                  = 0
    error:         str | None           = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _b64decode(s: str) -> dict:
    s += "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))


def _decode_jwt_unverified(token: str) -> tuple[dict, dict]:
    """Decode header + payload of a JWT WITHOUT signature verification.

    The agent receives T0 from the client-app (which obtained it from Keycloak)
    and forwards it as the subject_token to Keycloak — Keycloak does the real
    validation.  We decode only for trace display.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return {}, {}
    return _b64decode(parts[0]), _b64decode(parts[1])


def _user_identity_from(claims: dict) -> UserIdentity:
    return UserIdentity(
        username=claims.get("preferred_username"),
        sub=claims.get("sub"),
        email=claims.get("email"),
        azp=claims.get("azp"),
        aud=claims.get("aud"),
        scope=claims.get("scope"),
        realm_roles=claims.get("realm_access", {}).get("roles", []),
        exp=claims.get("exp"),
    )


def _build_custody_chain(t1_claims: dict) -> CustodyChain:
    """Walk the act claim chain to build the audit summary.

    RFC 8693 §4.1 says the resulting token's `act` claim names the actor.
    However, **Keycloak 26's V2 (standard) token exchange does not emit `act`
    by default** for single-hop exchanges — it sets `azp` to the new client
    and considers that sufficient.  Adding an `act` claim would require a
    custom protocol mapper.

    Our pragmatic approach: walk the `act` chain if present (handles nested
    exchanges correctly when KC is configured to emit it, or future versions
    that emit by default), and fall back to `azp` when the subject is a
    human user (preferred_username doesn't have the `service-account-` prefix).

    The resulting audit information is equivalent — only the claim location
    differs.  The MCP server uses the same fallback in its access logs.
    """
    subject = t1_claims.get("preferred_username") or t1_claims.get("sub")
    actors: list[str] = []
    act = t1_claims.get("act") or {}
    while act:
        actor = act.get("sub") or act.get("client_id") or act.get("preferred_username") or "?"
        actors.append(actor)
        act = act.get("act") or {}

    # Fallback when act is absent: azp identifies the actor in single-hop
    # delegations.  We only apply this when the subject is a human (not a
    # service account) to avoid misclassifying service-principal flows as
    # "delegated" — in UC1/UC2/UC3a the subject IS the agent.
    azp = t1_claims.get("azp")
    pref = t1_claims.get("preferred_username") or ""
    is_human_subject = pref and not pref.startswith("service-account-")
    if not actors and is_human_subject and azp and azp != pref:
        actors.append(azp)

    chain_parts = [subject or "?"]
    chain_parts.extend(actors)
    summary = " → ".join(chain_parts)
    return CustodyChain(subject=subject, actors=actors, summary=summary)


def _scope_diff(t0_claims: dict, t1_claims: dict) -> ScopeDiff:
    """Compute the scope diff between the user's original token and the delegated one."""
    u = (t0_claims.get("scope") or "").split()
    d = (t1_claims.get("scope") or "").split()
    us, ds = set(u), set(d)
    return ScopeDiff(
        user_scopes=u,
        delegated_scopes=d,
        kept=sorted(us & ds),
        dropped=sorted(us - ds),
        added=sorted(ds - us),
    )


async def _exchange_user_token(user_access_token: str) -> tuple[str, ExchangeStep]:
    """Perform RFC 8693 token exchange with scope narrowing.

    Single-step: the same call accomplishes both OBO (preserves sub) and
    rescoping (requests scope=mcp, narrower than the user's original).
    """
    step = ExchangeStep()
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(KC_TOKEN_URL, data={
                "grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id":            CLIENT_ID,
                "client_secret":        CLIENT_SECRET,
                # subject_token + subject_token_type — RFC 8693 §2.1 parameters.
                "subject_token":        user_access_token,
                "subject_token_type":   "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                # Narrower scope than the user's original — least privilege.
                # The mcp scope's audience mapper adds 'mcp-service' to aud.
                "scope":                "mcp",
            })
            step.status_code = resp.status_code
            if resp.status_code != 200:
                step.error = f"Keycloak returned {resp.status_code}: {resp.text[:300]}"
                return "", step
            data = resp.json()
            token = data["access_token"]
            header, payload = _decode_jwt_unverified(token)
            step.success      = True
            step.access_token = token
            step.token_header = header
            step.token_claims = payload
            step.expires_in   = data.get("expires_in")
            return token, step
    except Exception as exc:
        step.error = f"token exchange failed: {exc}"
        return "", step


# ── MCP loop (helpers shared in shape with the other agents) ──────────────────

def _mcp_result_to_python(mcp_result) -> tuple[Any, str]:
    """FastMCP returns one TextContent per element for list returns — collect them."""
    texts = [c.text for c in (mcp_result.content or []) if getattr(c, "text", None)]
    if not texts:
        return None, ""
    parsed: list[Any] = []
    for t in texts:
        try:
            parsed.append(json.loads(t))
        except Exception:
            parsed.append(t)
    if len(parsed) == 1:
        return parsed[0], texts[0]
    return parsed, json.dumps(parsed)


def _mcp_tools_to_anthropic(tools) -> list[dict]:
    return [
        {"name": t.name, "description": t.description or t.name,
         "input_schema": t.inputSchema or {"type": "object", "properties": {}}}
        for t in tools
    ]


async def _run_mock_loop(run: AgentRun, mcp_session: ClientSession) -> None:
    """Deterministic stand-in for when ANTHROPIC_API_KEY is not set."""
    t1 = AgentTurn(iteration=1, stop_reason="tool_use")
    res = await mcp_session.call_tool("list_products", arguments={})
    products, _ = _mcp_result_to_python(res)
    if not isinstance(products, list):
        products = [products] if products else []
    t1.tool_calls.append({"name": "list_products", "input": {},
                          "result": products, "ok": not res.isError})
    run.turns.append(t1)

    eligible = [p for p in products if isinstance(p, dict) and p.get("price", 999) <= 40]
    chosen = max(eligible, key=lambda p: p["price"]) if eligible else (products[0] if products else None)

    if chosen:
        t2 = AgentTurn(iteration=2, stop_reason="tool_use")
        res = await mcp_session.call_tool("get_product_details",
                                          arguments={"product_id": chosen["id"]})
        details, _ = _mcp_result_to_python(res)
        t2.tool_calls.append({"name": "get_product_details",
                              "input": {"product_id": chosen["id"]},
                              "result": details, "ok": not res.isError})
        run.turns.append(t2)

        user_label = (run.user_identity.username if run.user_identity else None) or "the user"
        run.turns.append(AgentTurn(
            iteration=3, stop_reason="end_turn",
            text=(f"[mock] Acting on behalf of {user_label}, I recommend the "
                  f"{chosen['name']} at ${chosen['price']:.2f} ({chosen['category']}). "
                  f"This token was scope-restricted to 'mcp' only — I cannot perform "
                  f"any administrative action even though my principal could."),
        ))
        run.final_answer = run.turns[-1].text
    else:
        run.final_answer = "[mock] No products available."


async def _run_anthropic_loop(run: AgentRun, mcp_session: ClientSession,
                              tools_for_claude: list[dict]) -> None:
    import anthropic
    user_label = (run.user_identity.username if run.user_identity else None) or "the user"
    # Tweak the system framing slightly to remind Claude that it is acting on
    # someone's behalf.  Helps the final answer reference the principal.
    system_prompt = (
        f"You are an AI agent acting on behalf of {user_label}. You hold a "
        f"delegated, scope-restricted token (scope=mcp) — you cannot perform "
        f"actions outside that scope. Reference the user when relevant."
    )
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    messages: list[dict] = [{"role": "user", "content": AGENT_TASK}]

    for iteration in range(1, MAX_TOOL_ITERATIONS + 1):
        turn = AgentTurn(iteration=iteration)
        response = await asyncio.to_thread(
            client.messages.create,
            model=ANTHROPIC_MODEL,
            max_tokens=1024,
            system=system_prompt,
            tools=tools_for_claude,
            messages=messages,
        )
        turn.stop_reason = response.stop_reason
        text_chunks = [b.text for b in response.content if b.type == "text"]
        if text_chunks:
            turn.text = "\n".join(text_chunks)

        if response.stop_reason != "tool_use":
            run.final_answer = turn.text or ""
            run.turns.append(turn)
            return

        tool_results: list[dict] = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            mcp_result = await mcp_session.call_tool(
                block.name, arguments=dict(block.input) if block.input else {},
            )
            result_data, result_text = _mcp_result_to_python(mcp_result)
            turn.tool_calls.append({
                "name": block.name, "input": dict(block.input) if block.input else {},
                "result": result_data, "ok": not mcp_result.isError,
            })
            tool_results.append({
                "type": "tool_result", "tool_use_id": block.id,
                "content": result_text, "is_error": mcp_result.isError,
            })

        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user",      "content": tool_results})
        run.turns.append(turn)

    run.error = f"agent did not converge within {MAX_TOOL_ITERATIONS} iterations"


# ── End-to-end runner ─────────────────────────────────────────────────────────

async def run_agent(user_access_token: str) -> AgentRun:
    """User identity → OBO+rescope → MCP session → tool-use loop → final answer."""
    started = time.time()
    run = AgentRun(
        started_at=datetime.now(timezone.utc).isoformat(),
        mode="live" if ANTHROPIC_API_KEY else "mock",
        model=ANTHROPIC_MODEL if ANTHROPIC_API_KEY else "deterministic-mock",
        task=AGENT_TASK,
    )

    # Step 0 — decode user identity from T0 (display + audit context only)
    _, user_claims = _decode_jwt_unverified(user_access_token)
    if not user_claims:
        run.error = "user_access_token is not a valid JWT"
        run.duration_ms = int((time.time() - started) * 1000)
        return run
    run.user_identity = _user_identity_from(user_claims)

    # Step 1 — OBO + rescope in one exchange
    delegated_token, exchange = await _exchange_user_token(user_access_token)
    run.auth = exchange
    if not exchange.success:
        run.duration_ms = int((time.time() - started) * 1000)
        return run

    # Build the custody chain + scope diff from T0 vs T1 — both useful for the UI.
    run.custody    = _build_custody_chain(exchange.token_claims or {})
    run.scope_diff = _scope_diff(user_claims, exchange.token_claims or {})

    # Steps 2+ — MCP session and tool-use loop (identical shape to other agents)
    try:
        async with streamablehttp_client(
            MCP_SERVER_URL,
            headers={"Authorization": f"Bearer {delegated_token}"},
        ) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools_result = await session.list_tools()
                run.mcp = McpDiscovery(
                    server_url=MCP_SERVER_URL,
                    tools=[
                        {"name": t.name, "description": t.description,
                         "input_schema": t.inputSchema}
                        for t in tools_result.tools
                    ],
                )
                if ANTHROPIC_API_KEY:
                    await _run_anthropic_loop(
                        run, session, _mcp_tools_to_anthropic(tools_result.tools)
                    )
                else:
                    await _run_mock_loop(run, session)
    except Exception as exc:
        logger.exception("Agent run failed during MCP/loop")
        if run.mcp is None:
            run.mcp = McpDiscovery(server_url=MCP_SERVER_URL, error=str(exc))
        else:
            run.error = str(exc)

    run.duration_ms = int((time.time() - started) * 1000)
    return run


# ── FastAPI app ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("agent-delegated starting — client_id=%s mcp=%s mode=%s",
                CLIENT_ID, MCP_SERVER_URL, "live" if ANTHROPIC_API_KEY else "mock")
    yield


app = FastAPI(title="AI Agent (User-Delegated)", version="1.0.0", lifespan=lifespan)


class RunRequest(BaseModel):
    """POST /run body.  user_access_token MUST be supplied — UC4 is delegated."""
    user_access_token: str


@app.get("/health", tags=["Info"])
def health():
    return {"status": "healthy", "mode": "live" if ANTHROPIC_API_KEY else "mock"}


@app.get("/info", tags=["Info"])
def info():
    return {
        "client_id":    CLIENT_ID,
        "auth_method":  "User-delegated token exchange (RFC 8693)",
        "mcp_url":      MCP_SERVER_URL,
        "model":        ANTHROPIC_MODEL,
        "mode":         "live" if ANTHROPIC_API_KEY else "mock",
        "task":         AGENT_TASK,
        "requires_user_token": True,
    }


@app.post("/run", tags=["Agent"])
async def run(body: RunRequest):
    """Synchronously execute the agent loop and return a structured trace.

    A user_access_token is REQUIRED — the agent acts on the user's behalf, so
    without a token there is nobody to delegate from.  The client-app's
    /agentic/<slug> handler is responsible for fetching it from the Flask
    session and forwarding it here.
    """
    try:
        result = await run_agent(body.user_access_token)
        return asdict(result)
    except Exception as exc:
        logger.exception("Unhandled error in /run")
        raise HTTPException(status_code=500, detail=str(exc))
