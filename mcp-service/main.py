"""
MCP Service — protected Model Context Protocol server using real MCP HTTP transport.

Demonstrates the Agentic AI use cases for this project:
  • Speaks the MCP wire protocol (JSON-RPC 2.0 over Streamable HTTP) so any MCP-aware
    client can connect — including the official Python `mcp` SDK used by the agents.
  • Protected by OAuth 2.1 Bearer authentication per the MCP authorization spec
    (https://modelcontextprotocol.io/specification/draft/basic/authorization).
  • Publishes /.well-known/oauth-protected-resource (RFC 9728) so MCP clients can
    discover that this resource is OAuth-protected and which authorization server
    (Keycloak) to obtain tokens from.

Exposed tools (MCP)
───────────────────
  list_products()             → full product catalogue
  get_product_details(id)     → one product

The catalogue mirrors the resource-server's PRODUCTS list so a future iteration can
chain calls: MCP server → resource-server with its own service-account token.

Wire layout
───────────
  GET  /                                          Service info (HTML)
  GET  /health                                    Liveness probe
  GET  /.well-known/oauth-protected-resource      RFC 9728 discovery
  POST /mcp                                       MCP Streamable HTTP endpoint
  GET  /mcp                                       (SSE upgrade for the same endpoint)
"""

import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import jwt
from fastapi import FastAPI, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from jwt import PyJWKClient
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s — %(message)s")
logger = logging.getLogger("mcp-service")

# ── Configuration ──────────────────────────────────────────────────────────────
# See client-app/app.py for the KC_EXT / KC_INT dual-URL convention used everywhere.
KC_INTERNAL_URL = os.getenv("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
KC_REALM        = os.getenv("KEYCLOAK_REALM",        "demo")
KC_ISSUER       = os.getenv("KEYCLOAK_ISSUER",       "http://localhost:8080/realms/demo")

# The aud claim that tokens must carry to be accepted at this resource.
# An audience mapper in Keycloak adds this value to tokens issued under the `mcp` scope.
EXPECTED_AUDIENCE = os.getenv("MCP_AUDIENCE",        "mcp-service")

# Public URL where this service can be reached.  Published in the discovery document
# so MCP clients know which `resource` they are talking to.  Must be reachable from
# the client (browser or agent container).
SERVICE_PUBLIC_URL = os.getenv("MCP_SERVICE_URL",    "http://localhost:8003")

JWKS_URL = f"{KC_INTERNAL_URL}/realms/{KC_REALM}/protocol/openid-connect/certs"
_jwks_client: PyJWKClient | None = None


# ── Sample data (same shape as resource-server/main.py) ────────────────────────
PRODUCTS = [
    {"id": 1, "name": "Widget Pro",       "price": 29.99, "category": "Electronics", "stock": 150},
    {"id": 2, "name": "Gadget Plus",      "price": 49.99, "category": "Electronics", "stock":  75},
    {"id": 3, "name": "Doohickey Basic",  "price":  9.99, "category": "Accessories", "stock": 300},
    {"id": 4, "name": "Thingamajig",      "price": 19.99, "category": "Accessories", "stock": 220},
    {"id": 5, "name": "Whatchamacallit",  "price": 99.99, "category": "Premium",     "stock":  30},
]


# ── MCP server — FastMCP with two demo tools ───────────────────────────────────
# stateless_http=True makes every JSON-RPC request independent (no Mcp-Session-Id
# tracking on the server).  For short-lived agent runs this is simpler and avoids
# server-side state — each tool call carries its own Bearer token via the request.
#
# streamable_http_path="/" matters: FastMCP defaults this to "/mcp", but we mount
# the returned ASGI app under /mcp in FastAPI.  Without this override the effective
# URL would be /mcp/mcp/ — Starlette redirects with 307 and the inner route 404s.
mcp = FastMCP("mcp-service", stateless_http=True, streamable_http_path="/")


@mcp.tool()
def list_products() -> list[dict]:
    """Return the full product catalogue with id, name, price (USD), category, and stock."""
    logger.info("MCP tool call: list_products() → %d products", len(PRODUCTS))
    return PRODUCTS


@mcp.tool()
def get_product_details(product_id: int) -> dict:
    """Return details for a single product looked up by its integer id.

    Returns {"error": "..."} when the product does not exist so the agent can
    react gracefully instead of seeing a JSON-RPC error envelope.
    """
    logger.info("MCP tool call: get_product_details(product_id=%s)", product_id)
    for p in PRODUCTS:
        if p["id"] == product_id:
            return p
    return {"error": f"product id {product_id} not found"}


# ── Bearer token validation ────────────────────────────────────────────────────

class TokenError(Exception):
    """Raised when Bearer token validation fails.  Mapped to HTTP 401 by the middleware."""
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def _validate_bearer(raw_token: str) -> dict:
    """
    Validate a Bearer JWT issued by Keycloak.

    Performed in order: JWKS key resolution, RS256 signature, iss, exp, aud,
    and finally the required scope.  Returns the decoded payload on success.
    """
    if _jwks_client is None:
        raise TokenError("JWKS client not initialised — Keycloak may still be starting")

    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(raw_token)
    except Exception as exc:
        logger.warning("JWKS key lookup failed: %s", exc)
        raise TokenError(f"cannot obtain signing key: {exc}")

    try:
        payload = jwt.decode(
            raw_token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=KC_ISSUER,
            audience=EXPECTED_AUDIENCE,
            leeway=30,
            options={"verify_exp": True, "verify_iss": True, "verify_aud": True},
        )
    except jwt.ExpiredSignatureError:
        raise TokenError("token has expired")
    except jwt.InvalidAudienceError:
        raise TokenError(
            f"token audience does not include '{EXPECTED_AUDIENCE}' — "
            f"the agent must request the 'mcp' scope when authenticating to Keycloak"
        )
    except jwt.InvalidIssuerError:
        raise TokenError(f"invalid token issuer; expected '{KC_ISSUER}'")
    except jwt.InvalidTokenError as exc:
        raise TokenError(f"invalid token: {exc}")

    # Required-scope check (Keycloak puts scopes in a single space-separated string).
    scopes = (payload.get("scope") or "").split()
    if "mcp" not in scopes:
        raise TokenError("token missing required 'mcp' scope")

    return payload


def _unauthorized(detail: str) -> JSONResponse:
    """Build a 401 response per the MCP authorization spec (resource_metadata hint)."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"error": "unauthorized", "error_description": detail},
        headers={
            # The MCP spec recommends advertising the discovery document so clients
            # can recover from missing/expired tokens by re-running the OAuth flow.
            "WWW-Authenticate": (
                f'Bearer error="invalid_token", '
                f'error_description="{detail}", '
                f'resource_metadata="{SERVICE_PUBLIC_URL}/.well-known/oauth-protected-resource"'
            ),
        },
    )


# ── Lifespan: prepare the JWKS client at startup ───────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _jwks_client
    logger.info("Initialising JWKS client (url=%s)", JWKS_URL)
    # cache_jwk_set=False so a failed initial fetch (Keycloak still starting) does not
    # poison the cache — same defensive pattern as resource-server.
    _jwks_client = PyJWKClient(JWKS_URL, cache_keys=True, cache_jwk_set=False)
    try:
        keys = _jwks_client.get_signing_keys()
        logger.info("✓ JWKS prefetched — %d signing key(s) available", len(keys))
    except Exception as exc:
        logger.warning("JWKS prefetch failed (will retry on demand): %s", exc)

    # IMPORTANT: FastMCP's streamable_http_app() expects its session manager to
    # be running for the duration of the request lifecycle.  When the MCP app is
    # mounted inside a FastAPI app via app.mount(), Starlette does NOT propagate
    # the inner app's lifespan — so we drive mcp.session_manager.run() ourselves
    # from this outer lifespan.  Skipping this causes /mcp/ to return HTTP 500.
    async with mcp.session_manager.run():
        logger.info("✓ MCP session manager running")
        yield


# ── FastAPI app + mounted MCP endpoint ─────────────────────────────────────────
# We compose two ASGI apps:
#   • FastAPI handles the discovery endpoint, health, and home page.
#   • FastMCP.streamable_http_app() handles the MCP wire protocol at /mcp.
# Bearer-token enforcement is implemented as middleware that gates /mcp only,
# so /.well-known/* stays anonymous (required for discovery to work pre-auth).

app = FastAPI(
    title="MCP Service",
    description="OAuth2-protected Model Context Protocol server for the Agentic AI demos.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def bearer_auth_for_mcp(request: Request, call_next):
    """Enforce Bearer authentication on the MCP transport endpoint only.

    The discovery endpoint and health checks must remain anonymous; otherwise an
    MCP client could never bootstrap its OAuth flow.
    """
    if request.url.path == "/mcp" or request.url.path.startswith("/mcp/"):
        auth = request.headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "):
            return _unauthorized("missing Bearer token")
        try:
            _validate_bearer(auth[7:])
        except TokenError as exc:
            return _unauthorized(exc.detail)
    return await call_next(request)


# Mount the MCP streamable HTTP transport.
# The MCP SDK's streamable_http_app() returns a Starlette app that handles both
# POST (request/response) and GET (SSE) on its root path.  Mounting at /mcp means
# clients connect to http://host:8003/mcp.
app.mount("/mcp", mcp.streamable_http_app())


# ── Discovery endpoint (RFC 9728 + MCP authorization spec) ─────────────────────

@app.get("/.well-known/oauth-protected-resource", tags=["Discovery"])
def oauth_protected_resource():
    """
    OAuth 2.0 Protected Resource metadata — RFC 9728.

    Tells an MCP client (before it has any token) which authorization server to
    use to obtain a token, what scopes are supported, and where to send Bearer
    tokens.  This is the entry point of the MCP authorization handshake.
    """
    return {
        "resource":                   SERVICE_PUBLIC_URL,
        "authorization_servers":      [KC_ISSUER],
        "bearer_methods_supported":   ["header"],
        "scopes_supported":           ["mcp"],
        "resource_documentation":     f"{SERVICE_PUBLIC_URL}/",
    }


# ── Info / health endpoints ────────────────────────────────────────────────────

@app.get("/health", tags=["Info"])
def health():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/", response_class=HTMLResponse, tags=["Info"])
def home():
    """A minimal HTML landing page so a human visitor sees something meaningful."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>MCP Service — Agentic AI Demo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
</head>
<body class="bg-light">
  <div class="container py-5">
    <h1 class="h3 mb-3"><i class="bi bi-robot text-primary me-2"></i>MCP Service</h1>
    <p class="text-muted">
      Model Context Protocol server (real MCP HTTP transport) protected by OAuth 2.1 Bearer tokens.
      Used by the agent containers in the Agentic AI section of the main demo.
    </p>

    <h2 class="h6 mt-4">Endpoints</h2>
    <table class="table table-sm bg-white shadow-sm rounded">
      <tr><td><code>POST /mcp</code></td><td>MCP Streamable HTTP — Bearer required</td></tr>
      <tr><td><code>GET /.well-known/oauth-protected-resource</code></td><td>RFC 9728 discovery</td></tr>
      <tr><td><code>GET /health</code></td><td>Liveness</td></tr>
    </table>

    <h2 class="h6 mt-4">Tools exposed via MCP</h2>
    <ul>
      <li><code>list_products()</code> — full product catalogue</li>
      <li><code>get_product_details(product_id)</code> — single product lookup</li>
    </ul>

    <h2 class="h6 mt-4">Authentication</h2>
    <p class="small text-muted mb-0">
      Tokens must be issued by <code>{KC_ISSUER}</code>, carry audience <code>{EXPECTED_AUDIENCE}</code>,
      and include the <code>mcp</code> scope.
      Try <a href="/.well-known/oauth-protected-resource">/.well-known/oauth-protected-resource</a>
      to see the discovery document.
    </p>

    <p class="mt-4"><a href="http://localhost:5000/agentic">← Back to the Agentic AI demos</a></p>
  </div>
</body>
</html>"""
