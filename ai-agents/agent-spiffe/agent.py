"""
AI Agent — Use Case 2: SPIFFE workload identity → MCP.

Demonstrates the zero-secret agentic auth pattern:
  1. SPIRE attests this container at runtime via the unix workload attestor
     (selector unix:uid:1000) and issues a short-lived JWT-SVID.
  2. The agent builds an RFC 7523 private_key_jwt client_assertion JWT, signed
     by an EC key generated in memory at startup (not the SVID — see below).
     Keycloak validates the assertion by fetching GET /jwks on this service.
  3. With the resulting Bearer token (scope=mcp), the agent opens an MCP
     Streamable HTTP session and runs the Claude tool-use loop.

Why is the JWT-SVID not used directly as the client_assertion?
  RFC 7523 requires iss/sub to equal the OAuth2 client_id ("ai-agent-spiffe"),
  but SPIRE sets them to the SPIFFE ID ("spiffe://demo.local/ai-agent-spiffe").
  Keycloak would not recognise that issuer.  Instead the SVID is captured for
  display/audit ("workload was attested"), and a separate JWT signed with the
  in-memory key authenticates to Keycloak.  Both identities are linked through
  the same process.

Endpoint contract (identical to agent-secret for symmetry):
  GET /info       Agent configuration
  GET /jwks       Public JWKS Keycloak uses to verify client_assertion
  POST /run       Trigger a single agent run, return the structured trace
  GET /health     Liveness probe
"""

import asyncio
import base64
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
import jwt as pyjwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from fastapi import FastAPI, HTTPException
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s — %(message)s")
logger = logging.getLogger("agent-spiffe")

# ── Configuration ──────────────────────────────────────────────────────────────
SPIFFE_SOCKET   = os.getenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire-agent/public/api.sock")
TRUST_DOMAIN    = os.getenv("SPIFFE_TRUST_DOMAIN",    "demo.local")

KC_INTERNAL_URL = os.getenv("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
KC_REALM        = os.getenv("KEYCLOAK_REALM",        "demo")
KC_TOKEN_URL    = f"{KC_INTERNAL_URL}/realms/{KC_REALM}/protocol/openid-connect/token"

# Keycloak client_id this agent authenticates as.  Keycloak's client config has
# clientAuthenticatorType=client-jwt and jwks_url=http://agent-spiffe:9002/jwks.
SVC_CLIENT_ID   = os.getenv("AGENT_CLIENT_ID", "ai-agent-spiffe")

MCP_SERVER_URL  = os.getenv("MCP_SERVER_URL",  "http://mcp-service:8003/mcp")

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL   = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

AGENT_TASK = os.getenv(
    "AGENT_TASK",
    "I have a $40 budget for a gift. Look at the product catalogue, pick the best "
    "candidate, fetch its full details, and write a one-paragraph recommendation. "
    "Use the MCP tools available to you — do not invent product data.",
)

MAX_TOOL_ITERATIONS = 6


# ── Ephemeral EC key pair — generated at startup, never persisted ──────────────
# Keycloak fetches the public key from GET /jwks to verify our client_assertion
# signatures.  Restarting the container rotates the key automatically.
_private_key = generate_private_key(SECP256R1(), default_backend())
_public_key  = _private_key.public_key()
_KEY_ID      = uuid.uuid4().hex[:16]
logger.info("EC P-256 key pair generated (kid=%s)", _KEY_ID)


# ── Discover Keycloak's published token endpoint for the assertion aud claim ──
# Keycloak validates the aud claim of a client_assertion against the URL it
# publishes for its token endpoint (governed by KC_HOSTNAME) — which is NOT the
# internal Docker hostname we use to send the request.  Using the internal URL
# produces "Token audience doesn't match".  Discover the public URL at startup
# so the assertion is built with the right value.
def _discover_assertion_audience() -> str:
    try:
        r = httpx.get(
            f"{KC_INTERNAL_URL}/realms/{KC_REALM}/.well-known/openid-configuration",
            timeout=10,
        )
        return r.json().get("token_endpoint", KC_TOKEN_URL)
    except Exception as exc:
        logger.warning("OIDC discovery failed (%s) — using internal URL as fallback", exc)
        return KC_TOKEN_URL


_ASSERTION_AUD = _discover_assertion_audience()
logger.info("Keycloak assertion audience = %s", _ASSERTION_AUD)


# ── Result types — same shape as agent-secret so the Flask renderer is shared ─

@dataclass
class SvidStep:
    """Step 1 result — SPIRE attestation outcome."""
    success:   bool                = False
    spiffe_id: str | None          = None
    socket:    str                 = SPIFFE_SOCKET
    header:    dict | None         = None
    payload:   dict | None         = None
    error:     str | None          = None


@dataclass
class AuthStep:
    """Step 2 result — private_key_jwt → Keycloak access token."""
    grant_type:        str         = "client_credentials"
    auth_method:       str         = "private_key_jwt (RFC 7523, ES256)"
    client_id:         str         = SVC_CLIENT_ID
    scope:             str         = "mcp"
    status_code:       int         = 0
    success:           bool        = False
    error:             str | None  = None
    access_token:      str | None  = None   # raw JWT — useful for jwt.io inspection
    token_header:      dict | None = None
    token_claims:      dict | None = None
    expires_in:        int | None  = None
    assertion_claims:  dict | None = None   # decoded client_assertion (debug aid)


@dataclass
class McpDiscovery:
    server_url: str
    tools:      list[dict]         = field(default_factory=list)
    error:      str | None         = None


@dataclass
class AgentTurn:
    iteration:   int
    stop_reason: str | None        = None
    text:        str | None        = None
    tool_calls:  list[dict]        = field(default_factory=list)


@dataclass
class AgentRun:
    started_at:   str
    mode:         str
    model:        str
    task:         str
    svid:         SvidStep | None  = None
    auth:         AuthStep | None  = None
    mcp:          McpDiscovery | None = None
    turns:        list[AgentTurn] = field(default_factory=list)
    final_answer: str | None      = None
    duration_ms:  int             = 0
    error:        str | None      = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _b64decode(s: str) -> dict:
    s += "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))


def _decode_jwt_unverified(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) != 3:
        return {}, {}
    return _b64decode(parts[0]), _b64decode(parts[1])


def _public_key_to_jwk() -> dict:
    """Serialize the startup EC public key as a JWK."""
    pub      = _public_key.public_numbers()
    key_size = (_public_key.key_size + 7) // 8
    return {
        "kty": "EC",
        "crv": "P-256",
        "kid": _KEY_ID,
        "use": "sig",
        "alg": "ES256",
        "x":   base64.urlsafe_b64encode(pub.x.to_bytes(key_size, "big")).rstrip(b"=").decode(),
        "y":   base64.urlsafe_b64encode(pub.y.to_bytes(key_size, "big")).rstrip(b"=").decode(),
    }


# ── Step 1: SPIRE attestation → JWT-SVID ───────────────────────────────────────

def _fetch_svid_blocking(audience: str) -> SvidStep:
    """Call the SPIRE Workload API.  Synchronous — the spiffe-py SDK uses gRPC."""
    try:
        from spiffe import WorkloadApiClient
    except ImportError as exc:
        return SvidStep(error=f"spiffe library not importable: {exc}")

    last_err = "unknown error"
    for attempt in range(3):
        try:
            with WorkloadApiClient(socket_path=SPIFFE_SOCKET) as client:
                svids = client.fetch_jwt_svids(audience={audience})
                if not svids:
                    last_err = "SPIRE returned no JWT-SVIDs — check workload entry selector"
                    continue
                svid = svids[0]
                header, payload = _decode_jwt_unverified(svid.token)
                return SvidStep(
                    success=True,
                    spiffe_id=str(svid.spiffe_id),
                    header=header,
                    payload=payload,
                )
        except Exception as exc:
            last_err = f"Workload API error: {exc}"
            if attempt < 2:
                time.sleep(2)

    return SvidStep(error=last_err)


# ── Step 2: build client_assertion + obtain Keycloak access token ─────────────

def _build_client_assertion() -> tuple[str, dict]:
    """RFC 7523 client_assertion JWT, signed with the in-memory EC key.

    iss == sub == OAuth2 client_id (NOT the SPIFFE ID — see module docstring).
    """
    now = int(time.time())
    claims = {
        "iss": SVC_CLIENT_ID,
        "sub": SVC_CLIENT_ID,
        "aud": _ASSERTION_AUD,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 60,
    }
    token = pyjwt.encode(claims, _private_key, algorithm="ES256",
                         headers={"kid": _KEY_ID})
    return token, claims


async def _get_access_token() -> tuple[str, AuthStep]:
    """Authenticate to Keycloak using RFC 7523 private_key_jwt, scope=mcp."""
    step = AuthStep()
    assertion, claims = _build_client_assertion()
    step.assertion_claims = claims

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(KC_TOKEN_URL, data={
                "grant_type":            "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion":      assertion,
                "scope":                 "mcp",
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


# ── Step 3: MCP tool-use loop (same shape as agent-secret) ────────────────────

def _mcp_result_to_python(mcp_result) -> tuple[Any, str]:
    """Collect every TextContent into a single value + text form (FastMCP returns
    one TextContent per element for list-typed tool results)."""
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
    """Deterministic stand-in when no ANTHROPIC_API_KEY is set."""
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

        run.turns.append(AgentTurn(
            iteration=3, stop_reason="end_turn",
            text=(f"[mock] For your $40 budget I recommend the {chosen['name']} "
                  f"at ${chosen['price']:.2f}. It is in the {chosen['category']} "
                  f"category with {chosen['stock']} units in stock. Attested by "
                  f"SPIRE — no static secret was used at any step."),
        ))
        run.final_answer = run.turns[-1].text
    else:
        run.final_answer = "[mock] No products available."


async def _run_anthropic_loop(run: AgentRun, mcp_session: ClientSession,
                              tools_for_claude: list[dict]) -> None:
    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    messages: list[dict] = [{"role": "user", "content": AGENT_TASK}]

    for iteration in range(1, MAX_TOOL_ITERATIONS + 1):
        turn = AgentTurn(iteration=iteration)
        response = await asyncio.to_thread(
            client.messages.create,
            model=ANTHROPIC_MODEL,
            max_tokens=1024,
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

async def run_agent() -> AgentRun:
    """SPIRE attest → private_key_jwt → MCP session → Claude loop → answer."""
    started = time.time()
    run = AgentRun(
        started_at=datetime.now(timezone.utc).isoformat(),
        mode="live" if ANTHROPIC_API_KEY else "mock",
        model=ANTHROPIC_MODEL if ANTHROPIC_API_KEY else "deterministic-mock",
        task=AGENT_TASK,
    )

    # Step 1 — fetch a JWT-SVID (proof we are who SPIRE thinks we are).
    # Audience is the trust domain — used by SPIRE for the SVID's own aud claim.
    # The SVID is NOT sent to Keycloak; it's evidence in the trace.
    run.svid = await asyncio.to_thread(_fetch_svid_blocking, f"spiffe://{TRUST_DOMAIN}")
    if not run.svid.success:
        run.error = run.svid.error or "SPIRE attestation failed"
        run.duration_ms = int((time.time() - started) * 1000)
        return run

    # Step 2 — obtain an OAuth2 access token via RFC 7523 private_key_jwt.
    token, auth_step = await _get_access_token()
    run.auth = auth_step
    if not auth_step.success:
        run.duration_ms = int((time.time() - started) * 1000)
        return run

    # Steps 3+ — MCP session and tool-use loop (identical to agent-secret).
    try:
        async with streamablehttp_client(
            MCP_SERVER_URL,
            headers={"Authorization": f"Bearer {token}"},
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
    logger.info("agent-spiffe starting — client_id=%s spiffe_socket=%s mcp=%s mode=%s",
                SVC_CLIENT_ID, SPIFFE_SOCKET, MCP_SERVER_URL,
                "live" if ANTHROPIC_API_KEY else "mock")
    yield


app = FastAPI(title="AI Agent (SPIFFE)", version="1.0.0", lifespan=lifespan)


@app.get("/health", tags=["Info"])
def health():
    return {"status": "healthy", "mode": "live" if ANTHROPIC_API_KEY else "mock"}


@app.get("/info", tags=["Info"])
def info():
    return {
        "client_id":   SVC_CLIENT_ID,
        "auth_method": "SPIFFE attestation → RFC 7523 private_key_jwt",
        "spiffe_id":   f"spiffe://{TRUST_DOMAIN}/ai-agent-spiffe",
        "mcp_url":     MCP_SERVER_URL,
        "model":       ANTHROPIC_MODEL,
        "mode":        "live" if ANTHROPIC_API_KEY else "mock",
        "task":        AGENT_TASK,
        "key_id":      _KEY_ID,
    }


@app.get("/jwks", tags=["Auth"])
def jwks():
    """Public JWKS Keycloak fetches to validate this agent's client_assertion.

    Configured in Keycloak as the ai-agent-spiffe client's jwks_url.  The key is
    ephemeral — restarting this container automatically rotates it.
    """
    return {"keys": [_public_key_to_jwk()]}


@app.post("/run", tags=["Agent"])
async def run():
    try:
        result = await run_agent()
        return asdict(result)
    except Exception as exc:
        logger.exception("Unhandled error in /run")
        raise HTTPException(status_code=500, detail=str(exc))
