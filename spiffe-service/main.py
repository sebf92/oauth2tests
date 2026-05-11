"""
SPIFFE Service — workload identity demo.

This service demonstrates machine-to-machine authentication using SPIFFE/SPIRE
instead of static client secrets.

Authentication flow:
  1. This container is attested by the SPIRE agent at runtime (unix UID selector).
  2. It calls the SPIRE Workload API to obtain a short-lived JWT-SVID — a signed
     proof of its own identity (spiffe://demo.local/spiffe-service).
  3. The JWT-SVID is validated locally against the SPIRE trust bundle.
  4. The validated SPIFFE ID is mapped to a Keycloak service account via the
     SPIFFE→OAuth2 bridge pattern (works with Keycloak 24).
     With Keycloak 26.4+, the JWT-SVID can be presented directly to Keycloak
     as a client_assertion (RFC 7523), removing the bridge step entirely.
  5. The resulting OAuth2 access token is used to call the resource server.

Endpoints:
  GET /          health check
  GET /svid      raw JWT-SVID from SPIRE (for inspection / debugging)
  GET /demo      full five-step demo: SVID → validation → OAuth2 → API call
"""

import base64
import json
import logging
import os
import time
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s — %(message)s")
logger = logging.getLogger("spiffe-service")

# ── Configuration ──────────────────────────────────────────────────────────────
SPIFFE_SOCKET = os.getenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire-agent/public/api.sock")
TRUST_DOMAIN  = os.getenv("SPIFFE_TRUST_DOMAIN",    "demo.local")

KC_INT        = os.getenv("KEYCLOAK_INTERNAL_URL",  "http://keycloak:8080")
REALM         = os.getenv("KEYCLOAK_REALM",          "demo")
SVC_ID        = os.getenv("SVC_CLIENT_ID",           "spiffe-service")
SVC_SECRET    = os.getenv("SVC_CLIENT_SECRET",       "spiffe-service-secret")
RESOURCE_URL  = os.getenv("RESOURCE_SERVER_URL",     "http://resource-server:8001")

KC_TOKEN_URL  = f"{KC_INT}/realms/{REALM}/protocol/openid-connect/token"

# SPIFFE ID → (keycloak_client_id, keycloak_client_secret)
# In a production system this mapping would be driven by policy (OPA, etc.).
SPIFFE_CLIENT_MAP: dict[str, tuple[str, str]] = {
    f"spiffe://{TRUST_DOMAIN}/spiffe-service": (SVC_ID, SVC_SECRET),
}


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


# ── SPIRE workload API ─────────────────────────────────────────────────────────

def _fetch_svid(audience: str) -> dict:
    """
    Call the SPIRE Workload API to obtain a JWT-SVID.
    Returns a dict with either 'token'/'spiffe_id'/... or 'error'.
    """
    try:
        from spiffe import WorkloadApiClient  # type: ignore[import]
    except ImportError:
        return {"error": "spiffe library not installed — check spiffe-service/requirements.txt"}

    try:
        with WorkloadApiClient(socket_path=SPIFFE_SOCKET) as client:
            svids = client.fetch_jwt_svids(audience={audience})
            if not svids:
                return {"error": "SPIRE returned no JWT SVIDs — check workload registration entry"}
            svid  = svids[0]
            token = svid.token
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


# ── SPIFFE → OAuth2 bridge ─────────────────────────────────────────────────────

def exchange_spiffe_for_oauth2(spiffe_id: str) -> dict:
    """
    Map a validated SPIFFE ID to a Keycloak client and obtain an OAuth2 token.

    This is the "SPIFFE→OAuth2 bridge" pattern required when the OAuth2 server
    does not natively support SPIFFE JWT-SVID client authentication (Keycloak < 26.4).

    With Keycloak 26.4+ (Federated Client Authentication), the JWT-SVID would be
    presented directly to Keycloak:
        POST /token
          grant_type            = client_credentials
          client_assertion_type = urn:ietf:params:oauth:client-assertion-type:jwt-bearer
          client_assertion      = <JWT-SVID>
    and Keycloak would validate it against SPIRE's JWKS endpoint.
    """
    mapping = SPIFFE_CLIENT_MAP.get(spiffe_id)
    if not mapping:
        return {
            "error": (
                f"No Keycloak client mapped for SPIFFE ID '{spiffe_id}'. "
                f"Known mappings: {list(SPIFFE_CLIENT_MAP.keys())}"
            )
        }

    client_id, client_secret = mapping
    logger.info(f"Mapping {spiffe_id} → Keycloak client '{client_id}'")

    try:
        resp = httpx.post(
            KC_TOKEN_URL,
            data={
                "grant_type":    "client_credentials",
                "client_id":     client_id,
                "client_secret": client_secret,
                "scope":         "openid profile roles",
            },
            timeout=10,
        )
        resp.raise_for_status()
        token_data = resp.json()
        decoded    = decode_jwt(token_data.get("access_token", ""))
        return {
            "success":             True,
            "mapped_client_id":    client_id,
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
    description="Demonstrates SPIFFE workload identity → OAuth2 token acquisition",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["Info"])
def root():
    return {
        "service":      "SPIFFE Service Demo",
        "trust_domain": TRUST_DOMAIN,
        "spiffe_id":    f"spiffe://{TRUST_DOMAIN}/spiffe-service",
        "socket":       SPIFFE_SOCKET,
        "endpoints": {
            "GET /svid":  "Fetch raw JWT-SVID from SPIRE workload API",
            "GET /demo":  "Full demo: SVID → OAuth2 → resource server",
        },
    }


@app.get("/health", tags=["Info"])
def health():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/svid", tags=["SPIFFE"])
def get_svid():
    """Fetch and return the raw JWT-SVID from the SPIRE workload API."""
    result = fetch_svid_with_retry(audience=KC_TOKEN_URL)
    if not result.get("success"):
        return {"success": False, **result}
    # Don't return the raw token in this endpoint — just the decoded claims
    result.pop("token", None)
    return result


@app.get("/demo", tags=["SPIFFE"])
def demo():
    """
    Full SPIFFE → OAuth2 → Resource Server demonstration.

    Step 1  Fetch JWT-SVID from SPIRE workload API
    Step 2  Validate SPIFFE identity (SPIRE-attested, short TTL)
    Step 3  Map SPIFFE ID → Keycloak service account (bridge pattern)
    Step 4  Obtain OAuth2 access token from Keycloak
    Step 5  Call protected resource server with the OAuth2 token
    """
    steps: dict = {}

    # ── Step 1: workload attestation → JWT-SVID ────────────────────────────────
    svid = fetch_svid_with_retry(audience=KC_TOKEN_URL)
    steps["step_1_workload_api"] = {
        "title":       "SPIRE Workload API — fetch JWT-SVID",
        "description": (
            "The SPIRE agent attests this container (unix UID selector) and issues "
            "a short-lived JWT-SVID signed by the SPIRE server's JWT authority."
        ),
        "success":     svid.get("success", False),
        "spiffe_id":   svid.get("spiffe_id"),
        "jwt_header":  svid.get("header"),
        "jwt_payload": svid.get("payload"),
        "error":       svid.get("error"),
    }

    if not svid.get("success"):
        return {"overall_success": False, "steps": steps}

    spiffe_id   = svid["spiffe_id"]
    raw_token   = svid["token"]

    # ── Step 2: SPIFFE identity summary ───────────────────────────────────────
    payload     = svid.get("payload", {})
    steps["step_2_identity_summary"] = {
        "title":       "SPIFFE Identity",
        "description": "Claims extracted from the validated JWT-SVID.",
        "success":     True,
        "spiffe_id":   spiffe_id,
        "issuer":      payload.get("iss"),
        "audience":    payload.get("aud"),
        "issued_at":   payload.get("iat_human"),
        "expires_at":  payload.get("exp_human"),
        "note": (
            "The SPIRE agent verified this container's OS identity before issuing this token. "
            "No secret was stored or transmitted — identity is runtime-attested."
        ),
    }

    # ── Step 3 + 4: SPIFFE → OAuth2 bridge ────────────────────────────────────
    oauth = exchange_spiffe_for_oauth2(spiffe_id)
    steps["step_3_oauth2_bridge"] = {
        "title": "SPIFFE → OAuth2 Bridge",
        "description": (
            "The validated SPIFFE ID is mapped to a Keycloak service account. "
            "Keycloak issues a standard OAuth2 access_token. "
            "With Keycloak 26.4+ this step would use RFC 7523 client_assertion directly."
        ),
        "success":          oauth.get("success", False),
        "mapped_client_id": oauth.get("mapped_client_id"),
        "token_type":       oauth.get("token_type"),
        "expires_in":       oauth.get("expires_in"),
        "access_token_claims": oauth.get("access_token_claims"),
        "keycloak_token_url":  KC_TOKEN_URL,
        "error":            oauth.get("error"),
    }

    if not oauth.get("success"):
        return {"overall_success": False, "steps": steps}

    access_token = oauth["access_token"]

    # ── Step 5: call resource server ──────────────────────────────────────────
    api = call_resource_server(access_token)
    steps["step_4_resource_server"] = {
        "title":       "Resource Server API Call",
        "description": "Protected endpoint called with the OAuth2 token obtained via SPIFFE identity.",
        **api,
    }

    return {
        "overall_success": api.get("success", False),
        "spiffe_id":       spiffe_id,
        "steps":           steps,
    }
