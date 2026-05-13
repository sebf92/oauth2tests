"""
AI Agent — Use Case 3a: X.509 certificate → RFC 7523 client_assertion → MCP.

Demonstrates the "service principal with a certificate" pattern:
  • A CA (generated once by cert-init) issued this agent a long-lived
    certificate + private key on a shared docker volume.
  • The agent's private key signs an RFC 7523 client_assertion JWT.
  • Keycloak validates the assertion against the public key it fetches from
    GET /jwks on this service.  The JWK embeds the certificate chain (`x5c`)
    and its SHA-256 thumbprint (`x5t#S256`) so the JWKS faithfully advertises
    the cert behind the key.
  • The resulting Bearer token (scope=mcp) drives the MCP tool-use loop.

How this differs from UC2 (SPIFFE)
──────────────────────────────────
  UC2  Ephemeral EC key regenerated on every container restart, SPIRE attests
       at runtime, no static credential anywhere.
  UC3a Long-lived cert + key persisted on a shared volume, no runtime
       attestation — possession of the key file IS the credential.  Closer
       to traditional PKI workflows (corporate CA → leaf cert → service).

Endpoints (uniform contract with the other agent containers)
  GET /info       Agent + certificate metadata
  GET /jwks       Public JWK derived from the cert (used by Keycloak)
  POST /run       Execute one agent run, return the structured trace
  GET /health     Liveness probe
"""

import asyncio
import base64
import hashlib
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
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import FastAPI, HTTPException
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s — %(message)s")
logger = logging.getLogger("agent-cert")

# ── Configuration ──────────────────────────────────────────────────────────────
PKI_DIR         = os.getenv("PKI_DIR",         "/pki")
CERT_PATH       = os.getenv("AGENT_CERT_PATH", f"{PKI_DIR}/agent.crt")
KEY_PATH        = os.getenv("AGENT_KEY_PATH",  f"{PKI_DIR}/agent.key")
CA_CERT_PATH    = os.getenv("CA_CERT_PATH",    f"{PKI_DIR}/ca.crt")

KC_INTERNAL_URL = os.getenv("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
KC_REALM        = os.getenv("KEYCLOAK_REALM",        "demo")
KC_TOKEN_URL    = f"{KC_INTERNAL_URL}/realms/{KC_REALM}/protocol/openid-connect/token"
SVC_CLIENT_ID   = os.getenv("AGENT_CLIENT_ID",       "ai-agent-cert")

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


# ── Load the certificate + private key at startup ─────────────────────────────
# Failing fast here gives a clear startup error if cert-init didn't run; the
# alternative would be a confusing 500 the first time /run is called.

def _load_pki() -> tuple[EllipticCurvePrivateKey, x509.Certificate, x509.Certificate | None]:
    with open(KEY_PATH, "rb") as fh:
        key = load_pem_private_key(fh.read(), password=None, backend=default_backend())
    if not isinstance(key, EllipticCurvePrivateKey):
        raise RuntimeError(f"{KEY_PATH} is not an EC private key (got {type(key).__name__})")

    with open(CERT_PATH, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read(), default_backend())

    ca: x509.Certificate | None = None
    try:
        with open(CA_CERT_PATH, "rb") as fh:
            ca = x509.load_pem_x509_certificate(fh.read(), default_backend())
    except FileNotFoundError:
        pass  # CA is shown in the trace if present, but not required at runtime.

    return key, cert, ca


_private_key, _cert, _ca_cert = _load_pki()
_KEY_ID = uuid.uuid4().hex[:16]   # JWK kid — stable for this process
logger.info(
    "Loaded agent certificate: subject=%s issuer=%s serial=%s",
    _cert.subject.rfc4514_string(),
    _cert.issuer.rfc4514_string(),
    hex(_cert.serial_number),
)


def _cert_der() -> bytes:
    from cryptography.hazmat.primitives import serialization
    return _cert.public_bytes(serialization.Encoding.DER)


def _cert_summary(cert: x509.Certificate) -> dict:
    fp = hashlib.sha256(cert.public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.DER
    )).hexdigest()
    return {
        "subject":      cert.subject.rfc4514_string(),
        "issuer":       cert.issuer.rfc4514_string(),
        "serial":       hex(cert.serial_number),
        "not_before":   cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.isoformat(),
        "not_after":    cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.isoformat(),
        "sha256_fp":    ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)),
        "signature_algorithm": cert.signature_algorithm_oid._name,
    }


def _public_jwk() -> dict:
    """Build a JWK from the cert's public key + cert chain metadata.

    Includes x5c (the cert chain DER, base64-encoded) and x5t#S256 (the
    SHA-256 cert thumbprint) so that any client (Keycloak, jwt.io, …) can
    see the certificate sitting behind this key, not just the raw EC numbers.
    """
    pub = _private_key.public_key().public_numbers()
    key_size = (_private_key.public_key().key_size + 7) // 8
    cert_der = _cert_der()
    cert_b64 = base64.b64encode(cert_der).decode()
    fp       = hashlib.sha256(cert_der).digest()
    x5tS256  = base64.urlsafe_b64encode(fp).rstrip(b"=").decode()

    jwk = {
        "kty":      "EC",
        "crv":      "P-256",
        "kid":      _KEY_ID,
        "use":      "sig",
        "alg":      "ES256",
        "x":        base64.urlsafe_b64encode(pub.x.to_bytes(key_size, "big")).rstrip(b"=").decode(),
        "y":        base64.urlsafe_b64encode(pub.y.to_bytes(key_size, "big")).rstrip(b"=").decode(),
        # x5c carries the full DER-encoded cert (base64, NOT base64url, per RFC 7517).
        "x5c":      [cert_b64],
        "x5t#S256": x5tS256,
    }
    return jwk


# ── Discover Keycloak's published token endpoint (for the assertion aud claim) ─
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


# ── Result types — same shape as the other agents so the Flask renderer is shared ─

@dataclass
class CertStep:
    """Step 0 — certificate metadata shown in the trace.

    There's no runtime attestation in UC3a — the cert IS the proof.  This step
    just displays what the agent loaded, so the reader can see which credential
    was used and verify CA chain details.
    """
    success:  bool        = True
    agent:    dict | None = None
    ca:       dict | None = None


@dataclass
class AuthStep:
    grant_type:        str         = "client_credentials"
    auth_method:       str         = "X.509 cert → RFC 7523 private_key_jwt (ES256)"
    client_id:         str         = SVC_CLIENT_ID
    scope:             str         = "mcp"
    status_code:       int         = 0
    success:           bool        = False
    error:             str | None  = None
    access_token:      str | None  = None   # raw JWT — useful for jwt.io inspection
    token_header:      dict | None = None
    token_claims:      dict | None = None
    expires_in:        int | None  = None
    assertion_header:  dict | None = None
    assertion_claims:  dict | None = None


@dataclass
class McpDiscovery:
    server_url: str
    tools:      list[dict]    = field(default_factory=list)
    error:      str | None    = None


@dataclass
class AgentTurn:
    iteration:   int
    stop_reason: str | None   = None
    text:        str | None   = None
    tool_calls:  list[dict]   = field(default_factory=list)


@dataclass
class AgentRun:
    started_at:   str
    mode:         str
    model:        str
    task:         str
    cert:         CertStep | None = None
    auth:         AuthStep | None = None
    mcp:          McpDiscovery | None = None
    turns:        list[AgentTurn] = field(default_factory=list)
    final_answer: str | None     = None
    duration_ms:  int            = 0
    error:        str | None     = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _b64decode(s: str) -> dict:
    s += "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s))


def _decode_jwt_unverified(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) != 3:
        return {}, {}
    return _b64decode(parts[0]), _b64decode(parts[1])


# ── Build the RFC 7523 client_assertion JWT ───────────────────────────────────

def _build_client_assertion() -> tuple[str, dict, dict]:
    """Sign a client_assertion JWT with the certificate's private key.

    The header includes:
      kid      — matches the kid in /jwks so Keycloak knows which key to use.
      x5t#S256 — SHA-256 cert thumbprint, lets a verifier double-check that
                 the key behind the signature is the one in the certificate
                 it has on file.

    Note: we intentionally do NOT inline x5c here.  The cert is already in the
    JWKS that Keycloak fetches from /jwks; duplicating it in every assertion
    would just inflate the JWT.
    """
    fp_b64 = base64.urlsafe_b64encode(
        hashlib.sha256(_cert_der()).digest()
    ).rstrip(b"=").decode()
    headers = {"alg": "ES256", "typ": "JWT", "kid": _KEY_ID, "x5t#S256": fp_b64}

    now = int(time.time())
    claims = {
        "iss": SVC_CLIENT_ID,
        "sub": SVC_CLIENT_ID,
        "aud": _ASSERTION_AUD,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 60,
    }
    token = pyjwt.encode(claims, _private_key, algorithm="ES256", headers=headers)
    return token, headers, claims


async def _get_access_token() -> tuple[str, AuthStep]:
    step = AuthStep()
    assertion, header, claims = _build_client_assertion()
    step.assertion_header = header
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
            h, p = _decode_jwt_unverified(token)
            step.success      = True
            step.access_token = token
            step.token_header = h
            step.token_claims = p
            step.expires_in   = data.get("expires_in")
            return token, step
    except Exception as exc:
        step.error = f"token request failed: {exc}"
        return "", step


# ── MCP loop (same helpers as the other agents) ───────────────────────────────

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
            text=(f"[mock] Authenticated with my X.509 cert. For your $40 budget I "
                  f"recommend the {chosen['name']} at ${chosen['price']:.2f} in the "
                  f"{chosen['category']} category."),
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

    # Step 0 — record the certificate metadata (no remote call; pure display).
    run.cert = CertStep(
        success=True,
        agent=_cert_summary(_cert),
        ca=_cert_summary(_ca_cert) if _ca_cert else None,
    )

    # Step 1 — RFC 7523 private_key_jwt → Keycloak token
    token, auth_step = await _get_access_token()
    run.auth = auth_step
    if not auth_step.success:
        run.duration_ms = int((time.time() - started) * 1000)
        return run

    # Steps 2+ — MCP session + Claude tool-use loop
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
    logger.info("agent-cert starting — client_id=%s cert=%s kid=%s mode=%s",
                SVC_CLIENT_ID, CERT_PATH, _KEY_ID,
                "live" if ANTHROPIC_API_KEY else "mock")
    yield


app = FastAPI(title="AI Agent (Certificate)", version="1.0.0", lifespan=lifespan)


@app.get("/health", tags=["Info"])
def health():
    return {"status": "healthy", "mode": "live" if ANTHROPIC_API_KEY else "mock"}


@app.get("/info", tags=["Info"])
def info():
    return {
        "client_id":     SVC_CLIENT_ID,
        "auth_method":   "X.509 cert → RFC 7523 private_key_jwt (ES256)",
        "cert_path":     CERT_PATH,
        "cert_subject":  _cert.subject.rfc4514_string(),
        "cert_issuer":   _cert.issuer.rfc4514_string(),
        "mcp_url":       MCP_SERVER_URL,
        "model":         ANTHROPIC_MODEL,
        "mode":          "live" if ANTHROPIC_API_KEY else "mock",
        "task":          AGENT_TASK,
        "key_id":        _KEY_ID,
    }


@app.get("/jwks", tags=["Auth"])
def jwks():
    """JWKS Keycloak fetches to verify this agent's client_assertion signatures.

    Each key carries x5c + x5t#S256 so the JWKS faithfully advertises the X.509
    certificate backing the key (RFC 7517 §4.7).  Keycloak only needs the JWK to
    verify, but exposing the cert here lets human operators audit the credential.
    """
    return {"keys": [_public_jwk()]}


@app.post("/run", tags=["Agent"])
async def run():
    try:
        result = await run_agent()
        return asdict(result)
    except Exception as exc:
        logger.exception("Unhandled error in /run")
        raise HTTPException(status_code=500, detail=str(exc))
