"""
AI Agent — Use Case 2-Hardened: SPIFFE + mTLS (RFC 8705) → MCP.

Closes the SPIFFE/Keycloak cryptographic gap left open by UC2:
  • UC2 (live):    SPIRE attestation is conceptual; the JWT signed for Keycloak
                   uses an unrelated EC key generated in memory.  Keycloak only
                   verifies the JWKS endpoint of the agent, not the SPIRE CA.
                   An attacker that controls any container on the network can
                   impersonate the agent by hosting their own /jwks.
  • UC2-Hardened:  The X.509-SVID issued by SPIRE is presented during the TLS
                   handshake to the keycloak-mtls-proxy sidecar.  nginx validates
                   the cert chain against the SPIRE trust-domain bundle, then
                   forwards the verified cert to Keycloak via the
                   x509cert-lookup=nginx provider (header-based PEM).
                   Keycloak's client-x509 authenticator matches the cert's
                   subject DN to this client and issues a Bearer token
                   optionally bound to the cert via cnf.x5t#S256 (RFC 8705).

What this gives that UC2 did not:
  ✓ Cryptographic proof that this caller comes from the SPIRE trust domain.
  ✓ Auto-rotating short-lived credential (X.509-SVID renews ~hourly).
  ✓ Cert-bound access token: a stolen token cannot be replayed without the
    private key that backed the original TLS handshake.

Endpoints (uniform contract with the other agent containers):
  GET  /info     Agent + SVID metadata
  GET  /health   Liveness probe
  POST /run      One end-to-end run, returns the structured trace
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import ssl
import tempfile
import time
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s — %(message)s")
logger = logging.getLogger("agent-spiffe-mtls")

# ── Configuration ──────────────────────────────────────────────────────────────
SPIFFE_SOCKET   = os.getenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire-agent/public/api.sock")
TRUST_DOMAIN    = os.getenv("SPIFFE_TRUST_DOMAIN",    "demo.local")

# We talk to Keycloak through the mTLS proxy.  The internal proxy URL is HTTPS
# on a self-resolving Docker hostname.  Note we deliberately use a fixed token
# endpoint URL (no OIDC discovery) — discovery would return localhost:8080
# (Keycloak's published hostname), which is not the proxy.
KC_MTLS_TOKEN_URL = os.getenv(
    "KEYCLOAK_MTLS_TOKEN_URL",
    "https://keycloak-mtls-proxy:8443/realms/demo/protocol/openid-connect/token",
)
SVC_CLIENT_ID     = os.getenv("AGENT_CLIENT_ID", "ai-agent-spiffe-mtls")

MCP_SERVER_URL    = os.getenv("MCP_SERVER_URL",  "http://mcp-service:8003/mcp")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL   = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

AGENT_TASK = os.getenv(
    "AGENT_TASK",
    "I have a $40 budget for a gift. Look at the product catalogue, pick the best "
    "candidate, fetch its full details, and write a one-paragraph recommendation. "
    "Use the MCP tools available to you — do not invent product data.",
)

MAX_TOOL_ITERATIONS = 6


# ── Result types — shape matches the other agent containers so the Flask
# renderer (agentic_result.html) needs no changes for this agent.

@dataclass
class SvidStep:
    """Step 1 — outcome of fetching the X.509-SVID from SPIRE."""
    success:     bool                = False
    spiffe_id:   str | None          = None
    socket:      str                 = SPIFFE_SOCKET
    cert_subject:  str | None        = None
    cert_issuer:   str | None        = None
    cert_serial:   str | None        = None
    cert_not_before: str | None      = None
    cert_not_after:  str | None      = None
    cert_san_uris:   list[str]       = field(default_factory=list)
    cert_sha256_fp:  str | None      = None
    error:       str | None          = None


@dataclass
class AuthStep:
    """Step 2 — outcome of the mTLS token request."""
    grant_type:    str         = "client_credentials"
    auth_method:   str         = "mTLS (RFC 8705) — X.509-SVID presented in TLS handshake"
    client_id:     str         = SVC_CLIENT_ID
    scope:         str         = "mcp"
    proxy_url:     str         = KC_MTLS_TOKEN_URL
    status_code:   int         = 0
    success:       bool        = False
    error:         str | None  = None
    access_token:  str | None  = None
    token_header:  dict | None = None
    token_claims:  dict | None = None
    expires_in:    int | None  = None
    cert_bound:    bool        = False
    cnf_x5t_s256:  str | None  = None  # the RFC 8705 cnf.x5t#S256 claim if present


@dataclass
class McpDiscovery:
    server_url: str
    tools:      list[dict] = field(default_factory=list)
    error:      str | None = None


@dataclass
class AgentTurn:
    iteration:   int
    stop_reason: str | None  = None
    text:        str | None  = None
    tool_calls:  list[dict]  = field(default_factory=list)


@dataclass
class AgentRun:
    started_at:   str
    mode:         str
    model:        str
    task:         str
    svid:         SvidStep | None     = None
    auth:         AuthStep | None     = None
    mcp:          McpDiscovery | None = None
    turns:        list[AgentTurn]     = field(default_factory=list)
    final_answer: str | None          = None
    duration_ms:  int                 = 0
    error:        str | None          = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _b64decode(s: str) -> dict:
    s += "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))


def _decode_jwt_unverified(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) != 3:
        return {}, {}
    return _b64decode(parts[0]), _b64decode(parts[1])


def _cert_sha256_thumbprint(cert: x509.Certificate) -> tuple[str, str]:
    """Return (hex-colon FP for display, base64url FP for cnf.x5t#S256 comparison)."""
    der = cert.public_bytes(serialization.Encoding.DER)
    fp  = hashlib.sha256(der).digest()
    hex_fp = ":".join(f"{b:02x}" for b in fp)
    b64_fp = base64.urlsafe_b64encode(fp).rstrip(b"=").decode()
    return hex_fp, b64_fp


def _extract_san_uris(cert: x509.Certificate) -> list[str]:
    """Pull URI SAN entries — the SPIFFE ID lives here."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return [str(u) for u in ext.value.get_values_for_type(x509.UniformResourceIdentifier)]
    except x509.ExtensionNotFound:
        return []


# ── Step 1: SPIRE attestation → X.509-SVID ─────────────────────────────────────

def _fetch_x509_svid_blocking() -> tuple[SvidStep, str | None, str | None]:
    """Call the SPIRE Workload API for an X.509-SVID.

    Returns the structured trace step plus paths to a temp cert + key file
    (caller is responsible for cleanup once the TLS request completes).
    """
    try:
        from spiffe import WorkloadApiClient
    except ImportError as exc:
        return SvidStep(error=f"spiffe library not importable: {exc}"), None, None

    last_err = "unknown error"
    for attempt in range(3):
        try:
            with WorkloadApiClient(socket_path=SPIFFE_SOCKET) as client:
                svids = client.fetch_x509_svids()
                if not svids:
                    last_err = "SPIRE returned no X.509-SVIDs — workload entry missing?"
                    continue

                svid = svids[0]
                # svid.cert_chain is list[x509.Certificate]; svid.private_key is the parsed key.
                leaf      = svid.cert_chain[0]
                hex_fp, _ = _cert_sha256_thumbprint(leaf)
                san_uris  = _extract_san_uris(leaf)

                # Serialise to PEM for httpx's cert= parameter (it wants files).
                cert_pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in svid.cert_chain)
                key_pem  = svid.private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
                cert_fd, cert_path = tempfile.mkstemp(prefix="svid-", suffix=".crt")
                key_fd,  key_path  = tempfile.mkstemp(prefix="svid-", suffix=".key")
                os.write(cert_fd, cert_pem); os.close(cert_fd)
                os.write(key_fd,  key_pem);  os.close(key_fd)

                return SvidStep(
                    success=True,
                    spiffe_id=str(svid.spiffe_id),
                    cert_subject=leaf.subject.rfc4514_string(),
                    cert_issuer=leaf.issuer.rfc4514_string(),
                    cert_serial=hex(leaf.serial_number),
                    cert_not_before=leaf.not_valid_before_utc.isoformat() if hasattr(leaf, "not_valid_before_utc") else leaf.not_valid_before.isoformat(),
                    cert_not_after=leaf.not_valid_after_utc.isoformat() if hasattr(leaf, "not_valid_after_utc") else leaf.not_valid_after.isoformat(),
                    cert_san_uris=san_uris,
                    cert_sha256_fp=hex_fp,
                ), cert_path, key_path
        except Exception as exc:
            last_err = f"Workload API error: {exc}"
            if attempt < 2:
                time.sleep(2)

    return SvidStep(error=last_err), None, None


# ── Step 2: mTLS → Keycloak token via the nginx proxy ─────────────────────────

async def _get_access_token(cert_path: str, key_path: str) -> tuple[str, AuthStep]:
    """RFC 8705 mTLS client authentication.

    The TLS handshake is the credential — no client_assertion, no client_secret.
    nginx terminates mTLS, validates the chain against the SPIRE bundle, and
    forwards the cert to Keycloak; Keycloak's client-x509 authenticator matches
    the cert subject DN to ai-agent-spiffe-mtls and issues a token.

    verify=False disables verification of the proxy's own server cert.  Real
    deployments would mount the proxy's CA into the agent and verify it; for
    this demo the proxy is a same-network sidecar so MITM is not in scope.
    """
    step = AuthStep()
    try:
        async with httpx.AsyncClient(
            cert=(cert_path, key_path),
            verify=False,   # demo only — see docstring
            timeout=15.0,
        ) as client:
            resp = await client.post(KC_MTLS_TOKEN_URL, data={
                "grant_type": "client_credentials",
                "client_id":  SVC_CLIENT_ID,
                "scope":      "mcp",
            })
            step.status_code = resp.status_code
            if resp.status_code != 200:
                step.error = f"Keycloak returned {resp.status_code}: {resp.text[:300]}"
                return "", step
            data  = resp.json()
            token = data["access_token"]
            header, payload = _decode_jwt_unverified(token)
            cnf = payload.get("cnf") or {}
            step.success      = True
            step.access_token = token
            step.token_header = header
            step.token_claims = payload
            step.expires_in   = data.get("expires_in")
            step.cnf_x5t_s256 = cnf.get("x5t#S256")
            step.cert_bound   = step.cnf_x5t_s256 is not None
            return token, step
    except Exception as exc:
        step.error = f"token request failed: {exc}"
        return "", step


# ── Step 3+: MCP tool-use loop (same helpers as the other agents) ─────────────

def _mcp_result_to_python(mcp_result) -> tuple[Any, str]:
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
    """Deterministic stand-in when ANTHROPIC_API_KEY is not configured."""
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

        bound_note = "Token cert-bound (cnf.x5t#S256) — replay-proof." if run.auth and run.auth.cert_bound else ""
        run.turns.append(AgentTurn(
            iteration=3, stop_reason="end_turn",
            text=(f"[mock] mTLS authenticated as {chosen and 'SPIRE workload'}. "
                  f"For your $40 budget I recommend the {chosen['name']} at "
                  f"${chosen['price']:.2f} in the {chosen['category']} category. "
                  f"{bound_note}"),
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
    started = time.time()
    run = AgentRun(
        started_at=datetime.now(timezone.utc).isoformat(),
        mode="live" if ANTHROPIC_API_KEY else "mock",
        model=ANTHROPIC_MODEL if ANTHROPIC_API_KEY else "deterministic-mock",
        task=AGENT_TASK,
    )

    # Step 1 — fetch the X.509-SVID.  cert_path/key_path are temp files used
    # by the next step and cleaned up before the function returns.
    svid_step, cert_path, key_path = await asyncio.to_thread(_fetch_x509_svid_blocking)
    run.svid = svid_step
    if not svid_step.success or not cert_path or not key_path:
        run.error = svid_step.error or "SPIRE attestation failed"
        run.duration_ms = int((time.time() - started) * 1000)
        return run

    try:
        # Step 2 — mTLS auth to Keycloak via the proxy.
        token, auth_step = await _get_access_token(cert_path, key_path)
        run.auth = auth_step
        if not auth_step.success:
            run.duration_ms = int((time.time() - started) * 1000)
            return run

        # Steps 3+ — MCP session and tool-use loop.
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
    finally:
        # Clean up the temp SVID files — they hold a private key.
        for p in (cert_path, key_path):
            try:
                os.unlink(p)
            except OSError:
                pass

    run.duration_ms = int((time.time() - started) * 1000)
    return run


# ── FastAPI app ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("agent-spiffe-mtls starting — client_id=%s proxy=%s mcp=%s mode=%s",
                SVC_CLIENT_ID, KC_MTLS_TOKEN_URL, MCP_SERVER_URL,
                "live" if ANTHROPIC_API_KEY else "mock")
    yield


app = FastAPI(title="AI Agent (SPIFFE + mTLS, UC2-Hardened)", version="1.0.0", lifespan=lifespan)


@app.get("/health", tags=["Info"])
def health():
    return {"status": "healthy", "mode": "live" if ANTHROPIC_API_KEY else "mock"}


@app.get("/info", tags=["Info"])
def info():
    return {
        "client_id":    SVC_CLIENT_ID,
        "auth_method":  "SPIFFE attestation → X.509-SVID → mTLS (RFC 8705)",
        "spiffe_id":    f"spiffe://{TRUST_DOMAIN}/{SVC_CLIENT_ID}",
        "proxy_url":    KC_MTLS_TOKEN_URL,
        "mcp_url":      MCP_SERVER_URL,
        "model":        ANTHROPIC_MODEL,
        "mode":         "live" if ANTHROPIC_API_KEY else "mock",
        "task":         AGENT_TASK,
        "cert_bound_tokens": True,
    }


@app.post("/run", tags=["Agent"])
async def run():
    try:
        result = await run_agent()
        return asdict(result)
    except Exception as exc:
        logger.exception("Unhandled error in /run")
        raise HTTPException(status_code=500, detail=str(exc))
