"""
Resource Server — Protected FastAPI application.

Validates JWT tokens issued by Keycloak and enforces role-based access control.
The JWKS (public keys) are fetched from Keycloak to verify token signatures.

Token validation steps performed on every protected request:
  1. Extract Bearer token from Authorization header
  2. Fetch Keycloak's public keys (JWKS) — cached after first fetch
  3. Verify the JWT signature using RS256
  4. Verify the `iss` (issuer) claim matches our Keycloak realm
  5. Verify the token has not expired (`exp` claim)
  6. For role-protected routes: check `realm_access.roles` inside the payload
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated

import httpx
import jwt
from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s — %(message)s")
logger = logging.getLogger("resource-server")

# ── Configuration ──────────────────────────────────────────────────────────────
KEYCLOAK_INTERNAL_URL = os.getenv("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
KEYCLOAK_REALM        = os.getenv("KEYCLOAK_REALM",        "demo")
KEYCLOAK_ISSUER       = os.getenv("KEYCLOAK_ISSUER",       "http://localhost:8080/realms/demo")

JWKS_URL = f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"

# ── JWKS client (module-level singleton, populated at startup) ─────────────────
_jwks_client: PyJWKClient | None = None


async def _wait_for_keycloak() -> None:
    """Poll the JWKS endpoint until Keycloak is ready (max 5 minutes)."""
    logger.info(f"Waiting for Keycloak JWKS at {JWKS_URL}")
    for attempt in range(30):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(JWKS_URL, timeout=5.0)
                if resp.status_code == 200:
                    logger.info("✓ Keycloak is reachable — JWKS loaded")
                    return
        except Exception as exc:
            pass
        logger.info(f"  Keycloak not ready (attempt {attempt + 1}/30) — retrying in 10 s…")
        await asyncio.sleep(10)
    logger.warning("Keycloak did not respond in time; token validation may fail on first request")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _jwks_client
    await _wait_for_keycloak()
    # cache_keys=True   → individual PyJWK objects are cached by kid (efficient)
    # cache_jwk_set=False → the raw JWKS is NOT cached; it is always re-fetched when
    #   a kid cache-miss occurs.  This prevents a bad first fetch (e.g. Keycloak still
    #   starting, cryptography not yet usable) from poisoning the cache for the entire
    #   lifespan and blocking all subsequent requests.
    _jwks_client = PyJWKClient(JWKS_URL, cache_keys=True, cache_jwk_set=False)
    # Eagerly verify connectivity and key usability so problems appear in startup
    # logs, not buried in the first user request.
    try:
        signing_keys = _jwks_client.get_signing_keys()
        logger.info(f"✓ JWKS OK — {len(signing_keys)} usable signing key(s) loaded")
    except Exception as exc:
        logger.warning(
            f"JWKS prefetch failed — token validation will fail until Keycloak "
            f"is reachable and 'cryptography' is importable: {exc}"
        )
    yield


# ── FastAPI app ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="OAuth2 Demo — Resource Server",
    description=(
        "Protected API that validates Keycloak JWTs and enforces role-based access.\n\n"
        "Most endpoints require an `Authorization: Bearer <token>` header."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_security = HTTPBearer()


# ── Token validation helpers ───────────────────────────────────────────────────

def _decode_token(raw_token: str) -> dict:
    """
    Validate and decode a JWT issued by Keycloak.

    Raises HTTPException 401 if the token is invalid, expired, or has the wrong issuer.
    """
    if _jwks_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWKS client not initialised — Keycloak may still be starting",
        )

    # ── Step 1: resolve the signing key from the token's kid header claim ──────
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(raw_token)
    except Exception as exc:
        # PyJWKClientConnectionError, PyJWKClientError, or any network failure.
        logger.error(f"JWKS key lookup failed (url={JWKS_URL}): {exc}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Cannot obtain signing key from Keycloak: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ── Step 2: verify signature, issuer, and expiry ───────────────────────────
    try:
        payload = jwt.decode(
            raw_token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=KEYCLOAK_ISSUER,
            # 30 s of tolerance compensates for:
            #   • clock skew between Docker containers
            #   • the network round-trip between Flask and this service
            #     (token checked as valid in Flask, then slightly expired here)
            leeway=30,
            options={
                "verify_exp": True,
                "verify_iss": True,
                # Audience validation is disabled for simplicity in this demo.
                # In production, configure an audience mapper in Keycloak and
                # set options={"verify_aud": True} with audience="your-resource-server".
                "verify_aud": False,
            },
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired — please obtain a new one",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidIssuerError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"Invalid token issuer. "
                f"Expected: '{KEYCLOAK_ISSUER}'. "
                f"Check KC_HOSTNAME in docker-compose.yml."
            ),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as exc:
        logger.error(f"Unexpected token validation error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Security(_security)],
) -> dict:
    """FastAPI dependency — validates token and returns the decoded payload."""
    return _decode_token(credentials.credentials)


def require_role(role: str):
    """
    FastAPI dependency factory — validates token AND checks for a specific realm role.

    Usage:
        @app.get("/protected")
        def endpoint(payload = Depends(require_role("admin-role"))):
            ...
    """
    def _checker(payload: dict = Depends(get_current_user)) -> dict:
        roles: list[str] = payload.get("realm_access", {}).get("roles", [])
        if role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied — required role: '{role}'. Your roles: {roles}",
            )
        return payload
    return _checker


# ── Sample data ────────────────────────────────────────────────────────────────

PRODUCTS = [
    {"id": 1, "name": "Widget Pro",       "price": 29.99, "category": "Electronics",  "stock": 150},
    {"id": 2, "name": "Gadget Plus",      "price": 49.99, "category": "Electronics",  "stock": 75},
    {"id": 3, "name": "Doohickey Basic",  "price":  9.99, "category": "Accessories",  "stock": 300},
    {"id": 4, "name": "Thingamajig",      "price": 19.99, "category": "Accessories",  "stock": 220},
    {"id": 5, "name": "Whatchamacallit",  "price": 99.99, "category": "Premium",      "stock": 30},
]

ALL_USERS = [
    {"id": 1, "username": "alice",   "email": "alice@example.com",   "roles": ["admin-role", "user-role"], "active": True},
    {"id": 2, "username": "bob",     "email": "bob@example.com",     "roles": ["user-role"],               "active": True},
    {"id": 3, "username": "charlie", "email": "charlie@example.com", "roles": [],                          "active": True},
]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Routes: open ───────────────────────────────────────────────────────────────

@app.get("/", tags=["Info"])
def root():
    """Service information — no auth required."""
    return {
        "service": "OAuth2 Demo — Resource Server",
        "version": "1.0.0",
        "keycloak_issuer": KEYCLOAK_ISSUER,
        "endpoints": {
            "GET /api/public":           "No auth required",
            "GET /api/products":         "Any valid JWT",
            "GET /api/users/me":         "Requires user-role",
            "GET /api/users":            "Requires admin-role",
            "GET /api/admin/dashboard":  "Requires admin-role",
            "GET /api/token/info":       "Any valid JWT — returns decoded claims",
        },
    }


@app.get("/health", tags=["Info"])
def health():
    return {"status": "healthy", "timestamp": _utcnow()}


@app.get("/api/public", tags=["Public"])
def public_endpoint():
    """Public endpoint — no authentication required."""
    return {
        "message": "This is public data — no token required!",
        "description": "Anyone can call this endpoint, even without a Keycloak account.",
        "timestamp": _utcnow(),
    }


# ── Routes: any valid token ────────────────────────────────────────────────────

@app.get("/api/products", tags=["Products"])
def get_products(payload: dict = Depends(get_current_user)):
    """Returns the product catalog — requires any valid JWT (no specific role)."""
    username = payload.get("preferred_username", "service-account")
    return {
        "message": f"Hello {username}! Here is the product catalog.",
        "products": PRODUCTS,
        "total": len(PRODUCTS),
        "requested_by": username,
        "token_subject": payload.get("sub"),
        "timestamp": _utcnow(),
    }


@app.get("/api/token/info", tags=["Debug"])
def token_info(payload: dict = Depends(get_current_user)):
    """Returns the decoded JWT claims — useful for understanding token structure."""
    iat = payload.get("iat", 0)
    exp = payload.get("exp", 0)
    return {
        "message": "Token decoded and validated successfully",
        "identity": {
            "subject":   payload.get("sub"),
            "username":  payload.get("preferred_username"),
            "email":     payload.get("email"),
            "full_name": f"{payload.get('given_name', '')} {payload.get('family_name', '')}".strip() or None,
        },
        "authorization": {
            "issuer":    payload.get("iss"),
            "audience":  payload.get("aud"),
            "client_id": payload.get("azp"),
            "scope":     payload.get("scope"),
            "roles":     payload.get("realm_access", {}).get("roles", []),
        },
        "timing": {
            "issued_at":  datetime.fromtimestamp(iat, tz=timezone.utc).isoformat() if iat else None,
            "expires_at": datetime.fromtimestamp(exp, tz=timezone.utc).isoformat() if exp else None,
            "session_id": payload.get("session_state"),
        },
        "raw_payload": payload,
    }


# ── Routes: user-role required ─────────────────────────────────────────────────

@app.get("/api/users/me", tags=["Users"])
def get_me(payload: dict = Depends(require_role("user-role"))):
    """Returns the current user's profile — requires user-role."""
    iat = payload.get("iat", 0)
    exp = payload.get("exp", 0)
    return {
        "username":    payload.get("preferred_username"),
        "email":       payload.get("email"),
        "full_name":   f"{payload.get('given_name', '')} {payload.get('family_name', '')}".strip() or None,
        "subject":     payload.get("sub"),
        "roles":       payload.get("realm_access", {}).get("roles", []),
        "issued_at":   datetime.fromtimestamp(iat, tz=timezone.utc).isoformat() if iat else None,
        "expires_at":  datetime.fromtimestamp(exp, tz=timezone.utc).isoformat() if exp else None,
        "client_id":   payload.get("azp"),
    }


# ── Routes: admin-role required ────────────────────────────────────────────────

@app.get("/api/users", tags=["Admin"])
def get_all_users(payload: dict = Depends(require_role("admin-role"))):
    """Returns the full user list — requires admin-role."""
    return {
        "users": ALL_USERS,
        "total": len(ALL_USERS),
        "requested_by": payload.get("preferred_username"),
        "timestamp": _utcnow(),
    }


@app.get("/api/admin/dashboard", tags=["Admin"])
def admin_dashboard(payload: dict = Depends(require_role("admin-role"))):
    """Returns admin statistics — requires admin-role."""
    return {
        "message": "Welcome to the admin dashboard!",
        "stats": {
            "total_users":      3,
            "active_sessions":  42,
            "api_calls_today":  1337,
            "revenue_mtd":      98_765.43,
            "system_health":    "OK",
            "last_updated":     _utcnow(),
        },
        "accessed_by": payload.get("preferred_username"),
    }
