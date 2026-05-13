"""
AI Agent — Use Case 1: Service Principal with client_id + client_secret.

Demonstrates the simplest agentic auth pattern:
  1. Authenticate to Keycloak using OAuth 2.0 Client Credentials grant
     (RFC 6749 §4.4) → service-account access token, scope=mcp.
  2. Connect to the protected MCP server via the real MCP Streamable HTTP
     transport, passing the access token in the Authorization: Bearer header.
  3. Discover available tools via the MCP `tools/list` JSON-RPC method.
  4. Run a Claude tool-use loop using the Anthropic SDK: Claude decides which
     MCP tools to call, the agent executes them via the MCP session, and the
     results are fed back to Claude until it returns a final answer.

If ANTHROPIC_API_KEY is unset the agent runs a deterministic mock loop so the
demo works end-to-end without an external dependency.

Endpoint
────────
  POST /run                       Trigger a single agent run, return structured JSON.
  GET  /health                    Liveness probe.
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

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s — %(message)s")
logger = logging.getLogger("agent-secret")

# ── Configuration ──────────────────────────────────────────────────────────────
KC_INTERNAL_URL   = os.getenv("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
KC_REALM          = os.getenv("KEYCLOAK_REALM",        "demo")
KC_TOKEN_URL      = f"{KC_INTERNAL_URL}/realms/{KC_REALM}/protocol/openid-connect/token"

CLIENT_ID         = os.getenv("AGENT_CLIENT_ID",       "ai-agent-secret")
CLIENT_SECRET     = os.getenv("AGENT_CLIENT_SECRET",   "ai-agent-secret-secret")

# Internal URL for the MCP service.  Streamable HTTP uses POST/GET to a single URL.
MCP_SERVER_URL    = os.getenv("MCP_SERVER_URL",        "http://mcp-service:8003/mcp")

# Anthropic configuration.  When ANTHROPIC_API_KEY is missing we fall back to a mock.
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL   = os.getenv("ANTHROPIC_MODEL",       "claude-haiku-4-5-20251001")

# The task we hand to Claude.  Crafted so the agent actually exercises the MCP tools.
AGENT_TASK = os.getenv(
    "AGENT_TASK",
    "I have a $40 budget for a gift. Look at the product catalogue, pick the best "
    "candidate, fetch its full details, and write a one-paragraph recommendation. "
    "Use the MCP tools available to you — do not invent product data.",
)

MAX_TOOL_ITERATIONS = 6  # safety cap — runaway loops should not pile up Anthropic costs


# ── Result types — what the agent returns to the client-app ────────────────────

@dataclass
class AuthStep:
    """Captures the OAuth2 token request → Bearer token outcome."""
    grant_type:   str
    client_id:    str
    scope:        str
    status_code:  int
    success:      bool
    error:        str | None         = None
    access_token: str | None         = None   # raw JWT — useful for jwt.io inspection
    token_header: dict | None        = None
    token_claims: dict | None        = None
    expires_in:   int | None         = None


@dataclass
class McpDiscovery:
    server_url:   str
    tools:        list[dict]         = field(default_factory=list)
    error:        str | None         = None


@dataclass
class AgentTurn:
    """One iteration of the Claude tool-use loop."""
    iteration:    int
    stop_reason:  str | None         = None
    text:         str | None         = None
    tool_calls:   list[dict]         = field(default_factory=list)  # list of {name, input, result, ok}


@dataclass
class AgentRun:
    started_at:   str
    mode:         str                # "live" (Anthropic) or "mock"
    model:        str
    task:         str
    auth:         AuthStep | None    = None
    mcp:          McpDiscovery | None = None
    turns:        list[AgentTurn]    = field(default_factory=list)
    final_answer: str | None         = None
    duration_ms:  int                = 0
    error:        str | None         = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _decode_jwt_unverified(token: str) -> tuple[dict, dict]:
    """Decode a JWT's header + payload WITHOUT verifying the signature.

    The agent does not need to validate its own access token — Keycloak just issued
    it and the MCP server will validate it on the next hop.  We only decode it so
    the demo can display the claims to the user.
    """
    def b64decode(s: str) -> dict:
        s += "=" * (-len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s))
    parts = token.split(".")
    if len(parts) != 3:
        return {}, {}
    return b64decode(parts[0]), b64decode(parts[1])


async def _get_service_token() -> tuple[str, AuthStep]:
    """Obtain a service-account access token via Client Credentials grant."""
    step = AuthStep(grant_type="client_credentials", client_id=CLIENT_ID, scope="mcp",
                    status_code=0, success=False)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(KC_TOKEN_URL, data={
                "grant_type":    "client_credentials",
                "client_id":     CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                # Request the mcp scope so Keycloak adds the mcp-service audience
                # and the scope claim that the MCP server checks.
                "scope":         "mcp",
            })
            step.status_code = resp.status_code
            if resp.status_code != 200:
                step.error = f"Keycloak returned {resp.status_code}: {resp.text[:200]}"
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
        step.error = f"token request failed: {exc}"
        return "", step


def _mcp_tools_to_anthropic(tools: list) -> list[dict]:
    """Convert MCP tool definitions into Anthropic's tool schema.

    MCP tools come with a JSON Schema input.  Anthropic's `tools` parameter expects
    {"name", "description", "input_schema"} — the input_schema must be a JSON Schema
    object.  The two formats are aligned, so the conversion is mostly a rename.
    """
    out = []
    for t in tools:
        out.append({
            "name":        t.name,
            "description": t.description or t.name,
            # FastMCP exposes the JSON Schema as `inputSchema` (MCP wire format).
            "input_schema": t.inputSchema or {"type": "object", "properties": {}},
        })
    return out


def _mcp_result_to_python(mcp_result) -> tuple[Any, str]:
    """Convert an MCP CallToolResult into a Python value + a human-readable text form.

    FastMCP returns one TextContent per element when the tool returns a list, so a
    naive content[0].text only sees the first element.  We collect every TextContent
    and try to parse each as JSON; if all parse, we return a list (or the single
    value when there's exactly one content).  The text form is the joined JSON,
    useful for feeding back to Claude as a tool_result string.
    """
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


async def _run_mock_loop(run: AgentRun, mcp_session: ClientSession) -> None:
    """Deterministic stand-in for the Anthropic loop when no API key is configured.

    The mock issues the same MCP tool calls a real agent would, so the demo still
    shows the auth → MCP discovery → tool calls → answer pipeline end-to-end.
    """
    # Turn 1 — list products
    t1 = AgentTurn(iteration=1, stop_reason="tool_use")
    mcp_result = await mcp_session.call_tool("list_products", arguments={})
    products, _ = _mcp_result_to_python(mcp_result)
    if not isinstance(products, list):
        products = [products] if products else []
    t1.tool_calls.append({"name": "list_products", "input": {},
                          "result": products, "ok": not mcp_result.isError})
    run.turns.append(t1)

    # Pick a product under $40 (matches the task's budget)
    eligible = [p for p in products if isinstance(p, dict) and p.get("price", 999) <= 40]
    chosen = max(eligible, key=lambda p: p["price"]) if eligible else (products[0] if products else None)

    if chosen:
        # Turn 2 — fetch details for the chosen product
        t2 = AgentTurn(iteration=2, stop_reason="tool_use")
        mcp_result = await mcp_session.call_tool("get_product_details",
                                                 arguments={"product_id": chosen["id"]})
        details, _ = _mcp_result_to_python(mcp_result)
        t2.tool_calls.append({"name": "get_product_details",
                              "input": {"product_id": chosen["id"]},
                              "result": details, "ok": not mcp_result.isError})
        run.turns.append(t2)

        # Turn 3 — final answer
        run.turns.append(AgentTurn(
            iteration=3, stop_reason="end_turn",
            text=(f"[mock] For your $40 budget I recommend the {chosen['name']} "
                  f"at ${chosen['price']:.2f}. It is in the {chosen['category']} "
                  f"category with {chosen['stock']} units in stock — a safe choice "
                  f"that uses most of the budget without exceeding it."),
        ))
        run.final_answer = run.turns[-1].text
    else:
        run.final_answer = "[mock] No products available."


async def _run_anthropic_loop(run: AgentRun, mcp_session: ClientSession,
                              tools_for_claude: list[dict]) -> None:
    """Real Claude tool-use loop.  Imports anthropic only when needed."""
    import anthropic

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    messages: list[dict] = [{"role": "user", "content": AGENT_TASK}]

    for iteration in range(1, MAX_TOOL_ITERATIONS + 1):
        turn = AgentTurn(iteration=iteration)
        # asyncio.to_thread keeps the FastAPI event loop responsive while the SDK
        # blocks on HTTP I/O (the Anthropic SDK is synchronous in this version).
        response = await asyncio.to_thread(
            client.messages.create,
            model=ANTHROPIC_MODEL,
            max_tokens=1024,
            tools=tools_for_claude,
            messages=messages,
        )
        turn.stop_reason = response.stop_reason
        # Extract any plain text the assistant produced this turn (Claude often
        # explains its reasoning alongside tool calls).
        text_chunks = [b.text for b in response.content if b.type == "text"]
        if text_chunks:
            turn.text = "\n".join(text_chunks)

        if response.stop_reason != "tool_use":
            # Terminal turn — capture the final answer and exit.
            run.final_answer = turn.text or ""
            run.turns.append(turn)
            return

        # Execute every tool_use block from this turn, in order.
        tool_results: list[dict] = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            tool_name  = block.name
            tool_input = dict(block.input) if block.input else {}
            mcp_result = await mcp_session.call_tool(tool_name, arguments=tool_input)
            # FastMCP returns one TextContent per element for list returns, so use
            # the helper that collects all parts into a single Python value + text.
            result_data, result_text = _mcp_result_to_python(mcp_result)
            turn.tool_calls.append({
                "name": tool_name, "input": tool_input,
                "result": result_data, "ok": not mcp_result.isError,
            })
            tool_results.append({
                "type":         "tool_result",
                "tool_use_id":  block.id,
                "content":      result_text,
                "is_error":     mcp_result.isError,
            })

        # Append assistant + tool_result turns to the conversation and continue.
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user",      "content": tool_results})
        run.turns.append(turn)

    # Exhausted the iteration cap without a terminal stop_reason.
    run.error = f"agent did not converge within {MAX_TOOL_ITERATIONS} iterations"


async def run_agent() -> AgentRun:
    """End-to-end agent run: auth → MCP discovery → Claude loop → final answer."""
    started = time.time()
    run = AgentRun(
        started_at=datetime.now(timezone.utc).isoformat(),
        mode="live" if ANTHROPIC_API_KEY else "mock",
        model=ANTHROPIC_MODEL if ANTHROPIC_API_KEY else "deterministic-mock",
        task=AGENT_TASK,
    )

    # 1. OAuth2 token request
    token, auth_step = await _get_service_token()
    run.auth = auth_step
    if not auth_step.success:
        run.duration_ms = int((time.time() - started) * 1000)
        return run

    # 2/3/4. Open an MCP session, list tools, run the loop.
    try:
        async with streamablehttp_client(
            MCP_SERVER_URL,
            headers={"Authorization": f"Bearer {token}"},
        ) as (read_stream, write_stream, _get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools_result = await session.list_tools()
                tools_payload = [
                    {"name": t.name,
                     "description": t.description,
                     "input_schema": t.inputSchema}
                    for t in tools_result.tools
                ]
                run.mcp = McpDiscovery(server_url=MCP_SERVER_URL, tools=tools_payload)

                if ANTHROPIC_API_KEY:
                    await _run_anthropic_loop(
                        run, session, _mcp_tools_to_anthropic(tools_result.tools)
                    )
                else:
                    await _run_mock_loop(run, session)
    except Exception as exc:
        logger.exception("Agent run failed")
        if run.mcp is None:
            run.mcp = McpDiscovery(server_url=MCP_SERVER_URL, error=str(exc))
        else:
            run.error = str(exc)

    run.duration_ms = int((time.time() - started) * 1000)
    return run


# ── FastAPI app ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("agent-secret starting — client_id=%s mcp=%s mode=%s",
                CLIENT_ID, MCP_SERVER_URL, "live" if ANTHROPIC_API_KEY else "mock")
    yield


app = FastAPI(title="AI Agent (Client Secret)", version="1.0.0", lifespan=lifespan)


@app.get("/health", tags=["Info"])
def health():
    return {"status": "healthy", "mode": "live" if ANTHROPIC_API_KEY else "mock"}


@app.get("/info", tags=["Info"])
def info():
    return {
        "client_id":    CLIENT_ID,
        "auth_method":  "OAuth 2.0 Client Credentials",
        "mcp_url":      MCP_SERVER_URL,
        "model":        ANTHROPIC_MODEL,
        "mode":         "live" if ANTHROPIC_API_KEY else "mock",
        "task":         AGENT_TASK,
    }


@app.post("/run", tags=["Agent"])
async def run():
    """Synchronously execute the agent loop and return a structured trace."""
    try:
        result = await run_agent()
        return asdict(result)
    except Exception as exc:
        logger.exception("Unhandled error in /run")
        raise HTTPException(status_code=500, detail=str(exc))
