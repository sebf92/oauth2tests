"""
SPIFFE Service — workload identity demo.

Demonstrates machine-to-machine authentication using SPIFFE/SPIRE identity
with Keycloak 26.4+ RFC 7523 private_key_jwt client authentication.

Authentication flow (KC 26.4+ native — no client_secret):
  1. Container is attested by the SPIRE agent at runtime (unix UID selector).
  2. SPIRE issues a short-lived JWT-SVID — a cryptographic proof of workload identity.
  3. The service authenticates to Keycloak via RFC 7523 private_key_jwt:
       grant_type             = client_credentials
       client_assertion_type  = urn:ietf:params:oauth:client-assertion-type:jwt-bearer
       client_assertion       = <JWT signed with in-memory EC key>
     Keycloak fetches the public key from GET /jwks (this service).
     No client_secret is stored or transmitted anywhere.
  4. The resulting OAuth2 access token is used to call the resource server.

Endpoints:
  GET /          JSON service info (API)
  GET /health    Health check
  GET /jwks      Public JWKS for Keycloak to validate client_assertion JWTs
  GET /svid      Raw JWT-SVID claims from SPIRE (for inspection)
  GET /demo      Full demo (JSON): SPIRE attestation → private_key_jwt → OAuth2 → API call
  GET /ui        HTML home — service info, config, endpoint reference
  GET /ui/demo   HTML interactive demo runner
"""

import base64
import json
import logging
import os
import secrets
import time
import uuid
from datetime import datetime, timezone

import httpx
import jwt as pyjwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s — %(message)s")
logger = logging.getLogger("spiffe-service")

# ── Configuration ──────────────────────────────────────────────────────────────
SPIFFE_SOCKET = os.getenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire-agent/public/api.sock")
TRUST_DOMAIN  = os.getenv("SPIFFE_TRUST_DOMAIN",    "demo.local")

KC_INT        = os.getenv("KEYCLOAK_INTERNAL_URL",  "http://keycloak:8080")
REALM         = os.getenv("KEYCLOAK_REALM",          "demo")
SVC_ID        = os.getenv("SVC_CLIENT_ID",           "spiffe-service")
RESOURCE_URL  = os.getenv("RESOURCE_SERVER_URL",     "http://resource-server:8001")

KC_TOKEN_URL  = f"{KC_INT}/realms/{REALM}/protocol/openid-connect/token"

# ── Discover the public token endpoint URL (used as aud in client_assertion) ──
# Keycloak validates aud against its own published URLs (KC_HOSTNAME=localhost),
# which differ from the internal Docker hostname used for actual HTTP requests.
_KC_ASSERTION_AUD = KC_TOKEN_URL  # fallback — overwritten below at startup
try:
    _disc = httpx.get(
        f"{KC_INT}/realms/{REALM}/.well-known/openid-configuration", timeout=10
    ).json()
    _KC_ASSERTION_AUD = _disc.get("token_endpoint", KC_TOKEN_URL)
except Exception:
    pass  # leave fallback; will likely fail auth but provides a clear error

# ── Ephemeral EC key pair ──────────────────────────────────────────────────────
# Generated once at process startup. Never written to disk — eliminated the
# client_secret entirely. Keycloak fetches our public key via GET /jwks.
_private_key = generate_private_key(SECP256R1(), default_backend())
_public_key  = _private_key.public_key()
_KEY_ID      = secrets.token_hex(8)   # stable within this process lifetime

logger.info(f"EC P-256 key pair generated at startup (kid={_KEY_ID})")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _b64pad(s: str) -> str:
    return s + "=" * (4 - len(s) % 4)


def decode_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        header  = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(_b64pad(parts[1])))
        for field in ("iat", "exp"):
            if field in payload:
                try:
                    payload[f"{field}_human"] = datetime.fromtimestamp(
                        payload[field], tz=timezone.utc
                    ).strftime("%Y-%m-%d %H:%M:%S UTC")
                except Exception:
                    pass
        return {"header": header, "payload": payload}
    except Exception:
        return {}


def _public_key_to_jwk() -> dict:
    """Serialize the startup EC public key as a JWK dict (P-256)."""
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


# ── SPIRE workload API ─────────────────────────────────────────────────────────

def _fetch_svid(audience: str) -> dict:
    """Call the SPIRE Workload API to obtain a JWT-SVID."""
    try:
        from spiffe import WorkloadApiClient  # type: ignore[import]
    except ImportError:
        return {"error": "spiffe library not installed — check spiffe-service/requirements.txt"}

    try:
        with WorkloadApiClient(socket_path=SPIFFE_SOCKET) as client:
            svids = client.fetch_jwt_svids(audience={audience})
            if not svids:
                return {"error": "SPIRE returned no JWT SVIDs — check workload registration entry"}
            svid    = svids[0]
            token   = svid.token
            decoded = decode_jwt(token)
            return {
                "success":   True,
                "token":     token,
                "spiffe_id": str(svid.spiffe_id),
                "header":    decoded.get("header",  {}),
                "payload":   decoded.get("payload", {}),
            }
    except Exception as exc:
        return {"error": f"Workload API call failed: {exc}"}


def fetch_svid_with_retry(audience: str, retries: int = 3) -> dict:
    """Retry SVID fetch to tolerate a briefly-starting SPIRE agent."""
    for attempt in range(retries):
        result = _fetch_svid(audience)
        if result.get("success"):
            return result
        if attempt < retries - 1:
            logger.info(f"SVID fetch attempt {attempt + 1}/{retries} failed, retrying…")
            time.sleep(2)
    return result


# ── RFC 7523 private_key_jwt client authentication ────────────────────────────

def build_client_assertion() -> str:
    """
    Build an RFC 7523 client_assertion JWT, signed with the in-memory EC key.

    iss/sub = SVC_ID (Keycloak client ID)  — required by RFC 7523
    aud     = KC_TOKEN_URL                 — Keycloak validates this
    jti     = random UUID                  — prevents replay
    exp     = now + 60 s                   — short window is sufficient

    Keycloak verifies the signature by fetching our public key from GET /jwks.
    """
    now = int(time.time())
    return pyjwt.encode(
        {
            "iss": SVC_ID,
            "sub": SVC_ID,
            "aud": _KC_ASSERTION_AUD,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + 60,
        },
        _private_key,
        algorithm="ES256",
        headers={"kid": _KEY_ID},
    )


def authenticate_to_keycloak() -> dict:
    """
    Obtain an OAuth2 access token using RFC 7523 private_key_jwt.

    No client_secret — Keycloak validates the signed client_assertion against
    the JWKS endpoint exposed by this service at GET /jwks.
    """
    assertion = build_client_assertion()
    try:
        resp = httpx.post(
            KC_TOKEN_URL,
            data={
                "grant_type":            "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion":       assertion,
                "scope":                  "openid profile roles",
            },
            timeout=10,
        )
        resp.raise_for_status()
        token_data = resp.json()
        decoded    = decode_jwt(token_data.get("access_token", ""))
        return {
            "success":             True,
            "auth_method":         "private_key_jwt (RFC 7523, ES256)",
            "client_id":           SVC_ID,
            "jwks_url":            f"<this service>/jwks  kid={_KEY_ID}",
            "token_type":          token_data.get("token_type"),
            "expires_in":          token_data.get("expires_in"),
            "access_token":        token_data.get("access_token"),
            "access_token_claims": decoded.get("payload", {}),
        }
    except httpx.HTTPStatusError as exc:
        return {"error": f"Keycloak returned {exc.response.status_code}: {exc.response.text}"}
    except Exception as exc:
        return {"error": f"Keycloak token request failed: {exc}"}


# ── Resource server call ───────────────────────────────────────────────────────

def call_resource_server(access_token: str, path: str = "/api/products") -> dict:
    url = f"{RESOURCE_URL}{path}"
    try:
        resp = httpx.get(
            url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        return {
            "url":         url,
            "status_code": resp.status_code,
            "success":     resp.status_code < 400,
            "data":        resp.json() if resp.content else None,
        }
    except Exception as exc:
        return {"url": url, "status_code": 503, "success": False,
                "data": {"error": str(exc)}}


# ── FastAPI app ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SPIFFE Service Demo",
    description="SPIFFE/SPIRE workload identity with KC 26.4+ RFC 7523 private_key_jwt",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))


@app.get("/", tags=["Info"])
def root():
    return {
        "service":      "SPIFFE Service Demo",
        "trust_domain": TRUST_DOMAIN,
        "spiffe_id":    f"spiffe://{TRUST_DOMAIN}/spiffe-service",
        "socket":       SPIFFE_SOCKET,
        "auth_method":  "private_key_jwt (RFC 7523, ES256) — no client_secret",
        "key_id":       _KEY_ID,
        "endpoints": {
            "GET /jwks":  "JWKS for Keycloak to validate client_assertion",
            "GET /svid":  "Fetch raw JWT-SVID claims from SPIRE (inspection)",
            "GET /demo":  "Full demo: SPIRE attestation → private_key_jwt → resource server",
        },
    }


@app.get("/health", tags=["Info"])
def health():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/jwks", tags=["Auth"])
def jwks():
    """
    Public JWKS served to Keycloak for validating private_key_jwt client assertions.

    Keycloak is configured with jwks.url pointing here. It fetches this on first
    use (or when it sees an unknown kid), caches it, and uses it to verify our
    client_assertion signatures. The key is ephemeral — regenerated on each restart.
    """
    return {"keys": [_public_key_to_jwk()]}


@app.get("/svid", tags=["SPIFFE"])
def get_svid():
    """Fetch and return JWT-SVID claims from SPIRE Workload API (for inspection)."""
    result = fetch_svid_with_retry(audience=f"spiffe://{TRUST_DOMAIN}")
    if not result.get("success"):
        return {"success": False, **result}
    result.pop("token", None)
    return result


@app.get("/demo", tags=["SPIFFE"])
def demo():
    """
    Full SPIFFE → OAuth2 → Resource Server demonstration (KC 26.4+ native mode).

    Step 1  SPIRE Workload API attests container → JWT-SVID
    Step 2  SPIFFE identity extracted from JWT-SVID
    Step 3  RFC 7523 private_key_jwt authentication to Keycloak (no client_secret)
    Step 4  Protected resource server called with the OAuth2 access token
    """
    steps: dict = {}

    # ── Step 1: workload attestation → JWT-SVID ────────────────────────────────
    svid = fetch_svid_with_retry(audience=f"spiffe://{TRUST_DOMAIN}")
    steps["step_1_workload_api"] = {
        "title":       "SPIRE Workload API — container attestation",
        "description": (
            "The SPIRE agent identifies this container via OS-level selectors (unix UID) "
            "and checks it against a registered entry on the SPIRE server. "
            "It then issues a short-lived JWT-SVID signed by SPIRE's JWT authority."
        ),
        "success":     svid.get("success", False),
        "spiffe_id":   svid.get("spiffe_id"),
        "jwt_header":  svid.get("header"),
        "jwt_payload": svid.get("payload"),
        "error":       svid.get("error"),
    }

    if not svid.get("success"):
        return {"overall_success": False, "steps": steps}

    spiffe_id = svid["spiffe_id"]

    # ── Step 2: SPIFFE identity summary ───────────────────────────────────────
    payload = svid.get("payload", {})
    steps["step_2_identity_summary"] = {
        "title":       "SPIFFE Identity",
        "description": "Claims extracted from the SPIRE-issued JWT-SVID.",
        "success":     True,
        "spiffe_id":   spiffe_id,
        "issuer":      payload.get("iss"),
        "audience":    payload.get("aud"),
        "issued_at":   payload.get("iat_human"),
        "expires_at":  payload.get("exp_human"),
        "note": (
            "No secret was stored or transmitted. SPIRE verified this container's OS "
            "identity before issuing this token. The JWT-SVID is the runtime proof."
        ),
    }

    # ── Step 3: RFC 7523 private_key_jwt → Keycloak access token ──────────────
    oauth = authenticate_to_keycloak()
    steps["step_3_keycloak_auth"] = {
        "title": "RFC 7523 Private Key JWT Client Authentication",
        "description": (
            "Keycloak 26.4+ native mode: the service authenticates using a signed "
            "client_assertion JWT — no client_secret. "
            "Keycloak validates the ES256 signature via GET /jwks on this service. "
            "The EC key is generated in-memory at startup and never persisted."
        ),
        "success":             oauth.get("success", False),
        "auth_method":         oauth.get("auth_method"),
        "client_id":           oauth.get("client_id"),
        "jwks_url":            oauth.get("jwks_url"),
        "token_type":          oauth.get("token_type"),
        "expires_in":          oauth.get("expires_in"),
        "access_token_claims": oauth.get("access_token_claims"),
        "keycloak_token_url":  KC_TOKEN_URL,
        "error":               oauth.get("error"),
    }

    if not oauth.get("success"):
        return {"overall_success": False, "steps": steps}

    access_token = oauth["access_token"]

    # ── Step 4: call resource server ──────────────────────────────────────────
    api = call_resource_server(access_token)
    steps["step_4_resource_server"] = {
        "title":       "Resource Server API Call",
        "description": "Protected endpoint called with the OAuth2 token issued via SPIFFE identity.",
        **api,
    }

    return {
        "overall_success": api.get("success", False),
        "spiffe_id":       spiffe_id,
        "steps":           steps,
    }


# ── HTML UI routes ─────────────────────────────────────────────────────────────

@app.get("/ui", response_class=HTMLResponse, tags=["UI"], include_in_schema=False)
def ui_home(request: Request):
    """HTML home page — service info, config, and endpoint reference."""
    return templates.TemplateResponse("index.html", {
        "request":      request,
        "trust_domain": TRUST_DOMAIN,
        "spiffe_id":    f"spiffe://{TRUST_DOMAIN}/spiffe-service",
        "socket":       SPIFFE_SOCKET,
        "key_id":       _KEY_ID,
        "svc_id":       SVC_ID,
        "kc_token_url": KC_TOKEN_URL,
        "kc_aud":       _KC_ASSERTION_AUD,
        "resource_url": RESOURCE_URL,
    })


@app.get("/ui/demo", response_class=HTMLResponse, tags=["UI"], include_in_schema=False)
def ui_demo(request: Request):
    """HTML interactive demo runner — calls /demo via AJAX and renders results."""
    return templates.TemplateResponse("ui_demo.html", {
        "request":      request,
        "trust_domain": TRUST_DOMAIN,
        "spiffe_id":    f"spiffe://{TRUST_DOMAIN}/spiffe-service",
    })
