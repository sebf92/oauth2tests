"""
Client Application — Flask OAuth2 demo.

Demonstrates three OAuth2 grant types and eight advanced flows:
  1. Authorization Code Flow  — the standard, browser-redirect-based flow
  2. Resource Owner Password Credentials (ROPC) — direct username/password exchange
  3. Client Credentials — machine-to-machine, no user involved
  4. On-Behalf-Of (OBO) — RFC 8693 token exchange, middle tier acts on behalf of user
  5. Token Rescoping — RFC 8693 downscoping, strip roles from a token
  6. SPIFFE/SPIRE — workload identity: RFC 7523 private_key_jwt → resource server
  7. OIDC Identity Layer — id_token, UserInfo endpoint, Discovery document
  8. DPoP — RFC 9449 proof of possession, sender-constrained tokens
  9. Device Authorization Grant — RFC 8628 device code flow for browserless clients
 10. PKCE — RFC 7636 proof key for code exchange, public client hardening
 11. Token Introspection — RFC 7662 remote active/revoked token state lookup

After obtaining a token, the app uses it to call the protected Resource Server
and shows the raw + decoded JWT to help understand what is inside the token.

URL layout:
  /                               Home page (shows session, flow buttons, API demo)
  /auth/authorization-code        Start Authorization Code flow (redirect to Keycloak)
  /auth/callback                  OAuth2 redirect_uri handler
  /auth/password                  Password Grant form (GET shows form, POST submits it)
  /auth/client-credentials        Client Credentials grant (one-click)
  /auth/token-exchange/obo        On-Behalf-Of token exchange demo (RFC 8693)
  /auth/token-exchange/rescope    Token downscoping / rescoping demo (RFC 8693)
  /auth/spiffe                    SPIFFE workload identity → OAuth2 demo
  /auth/dpop                      DPoP proof of possession demo (RFC 9449)
  /auth/oidc                      OIDC identity layer demo (id_token, UserInfo, Discovery)
  /auth/device                    Device Authorization Grant demo (RFC 8628)
  /auth/device/poll               AJAX polling endpoint for device flow status
  /auth/pkce                      Start PKCE Authorization Code flow (RFC 7636)
  /auth/pkce/result               PKCE result page (after Keycloak callback)
  /auth/introspect                Token Introspection demo (RFC 7662)
  /auth/refresh                   Refresh the current access token
  /auth/logout                    Clear session + SSO logout from Keycloak
  /token/inspect                  Detailed JWT inspection page
  /api/call/<name>                Proxied calls to the Resource Server
  /docs                           Documentation index
  /docs/<slug>                    Rendered documentation page
"""

import base64
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

import html as _html
import markdown as _markdown
import re as _re
import requests
from markupsafe import Markup
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1, generate_private_key
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")

# ── Configuration ──────────────────────────────────────────────────────────────
KC_EXT  = os.getenv("KEYCLOAK_EXTERNAL_URL", "http://localhost:8080")   # browser-facing
KC_INT  = os.getenv("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")   # server-to-server
REALM   = os.getenv("KEYCLOAK_REALM",         "demo")

CLIENT_ID     = os.getenv("KEYCLOAK_CLIENT_ID",     "demo-client")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "demo-client-secret")

SVC_CLIENT_ID     = os.getenv("SERVICE_CLIENT_ID",     "service-client")
SVC_CLIENT_SECRET = os.getenv("SERVICE_CLIENT_SECRET", "service-client-secret")

MIDDLE_CLIENT_ID     = os.getenv("MIDDLE_TIER_CLIENT_ID",     "middle-tier-client")
MIDDLE_CLIENT_SECRET = os.getenv("MIDDLE_TIER_CLIENT_SECRET", "middle-tier-client-secret")

DPOP_CLIENT_ID     = os.getenv("DPOP_CLIENT_ID",     "dpop-client")
DPOP_CLIENT_SECRET = os.getenv("DPOP_CLIENT_SECRET", "dpop-client-secret")

DEVICE_CLIENT_ID     = os.getenv("DEVICE_CLIENT_ID",     "device-client")
DEVICE_CLIENT_SECRET = os.getenv("DEVICE_CLIENT_SECRET", "device-client-secret")
PKCE_CLIENT_ID       = os.getenv("PKCE_CLIENT_ID",       "pkce-client")

RESOURCE_URL  = os.getenv("RESOURCE_SERVER_URL", "http://resource-server:8001")
SPIFFE_URL    = os.getenv("SPIFFE_SERVICE_URL",  "http://spiffe-service:8002")
REDIRECT_URI  = os.getenv("REDIRECT_URI", "http://localhost:5000/auth/callback")

# Keycloak endpoints
KC_AUTH_URL       = f"{KC_EXT}/realms/{REALM}/protocol/openid-connect/auth"
KC_TOKEN_URL      = f"{KC_INT}/realms/{REALM}/protocol/openid-connect/token"
KC_LOGOUT_URL     = f"{KC_EXT}/realms/{REALM}/protocol/openid-connect/logout"
KC_DEVICE_URL     = f"{KC_INT}/realms/{REALM}/protocol/openid-connect/auth/device"
KC_INTROSPECT_URL = f"{KC_INT}/realms/{REALM}/protocol/openid-connect/token/introspect"
KC_REVOKE_URL     = f"{KC_INT}/realms/{REALM}/protocol/openid-connect/revoke"


# ── DPoP helpers ───────────────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def generate_dpop_keypair():
    """Generate an ephemeral EC P-256 key pair. Returns (private_key, public_jwk_dict)."""
    priv = generate_private_key(SECP256R1(), default_backend())
    nums = priv.public_key().public_numbers()
    pub_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x":   _b64url(nums.x.to_bytes(32, "big")),
        "y":   _b64url(nums.y.to_bytes(32, "big")),
    }
    return priv, pub_jwk


def jwk_thumbprint(pub_jwk: dict) -> str:
    """Compute the RFC 7638 JWK thumbprint (SHA-256 of canonical key members)."""
    canonical = json.dumps(
        {"crv": pub_jwk["crv"], "kty": pub_jwk["kty"], "x": pub_jwk["x"], "y": pub_jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return _b64url(hashlib.sha256(canonical.encode()).digest())


def make_dpop_proof(
    priv_key,
    pub_jwk: dict,
    htm: str,
    htu: str,
    access_token: str | None = None,
) -> str:
    """
    Build a signed DPoP proof JWT (RFC 9449).

    htm: HTTP method in uppercase ("POST", "GET", …)
    htu: Full URI without query/fragment
    access_token: if provided, adds the ath claim (required at resource servers)
    """
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": pub_jwk}
    claims = {"jti": secrets.token_urlsafe(16), "htm": htm, "htu": htu, "iat": int(time.time())}
    if access_token is not None:
        claims["ath"] = _b64url(hashlib.sha256(access_token.encode()).digest())

    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()

    der_sig = priv_key.sign(signing_input, ECDSA(crypto_hashes.SHA256()))
    r, s    = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{h_b64}.{p_b64}.{_b64url(raw_sig)}"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _b64_decode(s: str) -> dict:
    padding = 4 - len(s) % 4
    try:
        return json.loads(base64.urlsafe_b64decode(s + "=" * padding))
    except Exception:
        return {}


def decode_jwt(token: str) -> dict:
    """Split a JWT into its three parts and decode header + payload."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    header  = _b64_decode(parts[0])
    payload = _b64_decode(parts[1])
    # Humanise timestamps for display
    for field in ("iat", "exp", "auth_time", "nbf"):
        if field in payload:
            try:
                payload[f"{field}_human"] = datetime.fromtimestamp(
                    payload[field], tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                pass
    return {
        "header":    header,
        "payload":   payload,
        "signature": parts[2][:24] + "…" if len(parts[2]) > 24 else parts[2],
        "raw_parts": parts,
    }


def token_expired(token_data: dict) -> bool:
    return time.time() >= token_data.get("expires_at", 0)


def call_resource(path: str, token: str | None) -> dict:
    """HTTP GET to the resource server, with or without a Bearer token."""
    url = f"{RESOURCE_URL}{path}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        return {
            "url":         url,
            "status_code": resp.status_code,
            "success":     resp.status_code < 400,
            "data":        resp.json() if resp.content else None,
        }
    except requests.ConnectionError:
        return {"url": url, "status_code": 503, "success": False,
                "data": {"error": "Cannot connect to resource server"}}
    except Exception as exc:
        return {"url": url, "status_code": 500, "success": False,
                "data": {"error": str(exc)}}


# ── Context processor — inject user info into every template ───────────────────

@app.context_processor
def inject_user():
    td = session.get("token_data")
    username = None
    roles: list[str] = []
    if td and not token_expired(td):
        info = decode_jwt(td.get("access_token", ""))
        pl   = info.get("payload", {})
        username = pl.get("preferred_username")
        roles    = pl.get("realm_access", {}).get("roles", [])
    return {
        "current_user":    username,
        "user_roles":      roles,
        "is_authenticated": username is not None,
        "keycloak_url":    KC_EXT,
        "realm":           REALM,
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    td           = session.get("token_data")
    token_info   = None
    is_expired   = False
    flow_used    = None

    if td:
        is_expired = token_expired(td)
        flow_used  = td.get("flow", "unknown")
        if not is_expired:
            token_info = decode_jwt(td.get("access_token", ""))

    return render_template(
        "index.html",
        token_data=td,
        token_info=token_info,
        is_expired=is_expired,
        flow_used=flow_used,
    )


# ── 1. Authorization Code Flow ─────────────────────────────────────────────────

@app.route("/auth/authorization-code")
def start_auth_code():
    """Redirect the browser to Keycloak's authorization endpoint."""
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    session["oauth_nonce"]  = nonce

    params = {
        "client_id":     CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "response_type": "code",
        "scope":         "openid profile email roles",
        "state":         state,
        "nonce":         nonce,
    }
    return redirect(f"{KC_AUTH_URL}?{urlencode(params)}")


@app.route("/auth/callback")
def auth_callback():
    """
    Keycloak redirects here after the user authenticates.
    Shared by Authorization Code (flow 1) and PKCE (flow 10).
    Set session["pkce_flow"] = True before redirecting to trigger PKCE token exchange.
    """
    if err := request.args.get("error"):
        flash(f"Keycloak error: {request.args.get('error_description', err)}", "danger")
        return redirect(url_for("index"))

    code  = request.args.get("code")
    state = request.args.get("state")

    if not code or state != session.pop("oauth_state", None):
        flash("Invalid state parameter — possible CSRF attack.", "danger")
        return redirect(url_for("index"))

    pkce_mode      = session.pop("pkce_flow",      False)
    pkce_verifier  = session.pop("pkce_verifier",  None)
    pkce_challenge = session.pop("pkce_challenge", None)
    pkce_auth_url  = session.pop("pkce_auth_url",  "")

    token_payload = {
        "grant_type":   "authorization_code",
        "redirect_uri": REDIRECT_URI,
        "code":         code,
    }
    if pkce_mode and pkce_verifier:
        token_payload["client_id"]     = PKCE_CLIENT_ID
        token_payload["code_verifier"] = pkce_verifier
        # public client — no client_secret
    else:
        token_payload["client_id"]     = CLIENT_ID
        token_payload["client_secret"] = CLIENT_SECRET

    resp = requests.post(KC_TOKEN_URL, data=token_payload, timeout=10)

    if not resp.ok:
        flash(f"Token exchange failed: {resp.text}", "danger")
        return redirect(url_for("index"))

    tokens = resp.json()
    tokens["expires_at"] = time.time() + tokens.get("expires_in", 300)

    if pkce_mode:
        tokens["flow"] = "pkce"
        session["token_data"] = tokens
        session["pkce_result"] = {
            "verifier":   pkce_verifier,
            "challenge":  pkce_challenge,
            "auth_url":   pkce_auth_url,
            "client_id":  PKCE_CLIENT_ID,
        }
        return redirect(url_for("pkce_result"))

    tokens["flow"] = "authorization_code"
    session["token_data"] = tokens
    flash("Logged in via Authorization Code flow!", "success")
    return redirect(url_for("index"))


# ── 2. Resource Owner Password Credentials (ROPC) ─────────────────────────────

@app.route("/auth/password", methods=["GET", "POST"])
def password_grant():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        resp = requests.post(
            KC_TOKEN_URL,
            data={
                "grant_type":    "password",
                "client_id":     CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "username":      username,
                "password":      password,
                "scope":         "openid profile email roles",
            },
            timeout=10,
        )

        if not resp.ok:
            err = resp.json().get("error_description", "Invalid credentials")
            flash(f"Authentication failed: {err}", "danger")
            return render_template("password_grant.html")

        tokens = resp.json()
        tokens["expires_at"] = time.time() + tokens.get("expires_in", 300)
        tokens["flow"]       = "password"
        session["token_data"] = tokens

        flash(f"Logged in as '{username}' via Password Grant!", "success")
        return redirect(url_for("index"))

    return render_template("password_grant.html")


# ── 3. Client Credentials ──────────────────────────────────────────────────────

@app.route("/auth/client-credentials")
def client_credentials():
    """Obtain a token on behalf of the service account — no user involved."""
    resp = requests.post(
        KC_TOKEN_URL,
        data={
            "grant_type":    "client_credentials",
            "client_id":     SVC_CLIENT_ID,
            "client_secret": SVC_CLIENT_SECRET,
            "scope":         "openid profile roles",
        },
        timeout=10,
    )

    if not resp.ok:
        flash(f"Client Credentials flow failed: {resp.text}", "danger")
        return redirect(url_for("index"))

    tokens = resp.json()
    tokens["expires_at"] = time.time() + tokens.get("expires_in", 300)
    tokens["flow"]       = "client_credentials"
    session["token_data"] = tokens

    flash("Service-account token obtained via Client Credentials!", "success")
    return redirect(url_for("index"))


# ── 4. On-Behalf-Of (RFC 8693) ────────────────────────────────────────────────

@app.route("/auth/token-exchange/obo")
def token_exchange_obo():
    """
    On-Behalf-Of (OBO) demo.

    The middle-tier-client exchanges the current user's token for a new token
    that represents the same user but is issued to the middle-tier service.
    This lets middle-tier services propagate user identity downstream without
    storing or forwarding the original credentials.

    RFC 8693 grant_type: urn:ietf:params:oauth:grant-type:token-exchange
    """
    td = session.get("token_data")
    if not td:
        flash("Please log in first to try the On-Behalf-Of demo.", "warning")
        return redirect(url_for("index"))
    if token_expired(td):
        flash("Your token has expired. Please log in again.", "warning")
        return redirect(url_for("index"))

    original_token = td.get("access_token", "")
    original_info  = decode_jwt(original_token)

    resp = requests.post(
        KC_TOKEN_URL,
        data={
            "grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id":            MIDDLE_CLIENT_ID,
            "client_secret":        MIDDLE_CLIENT_SECRET,
            "subject_token":        original_token,
            "subject_token_type":   "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        },
        timeout=10,
    )

    exchange_result = {
        "status_code": resp.status_code,
        "success":     resp.ok,
        "data":        resp.json() if resp.content else None,
    }
    exchanged_token_info = None
    if resp.ok:
        new_token = exchange_result["data"].get("access_token", "")
        exchanged_token_info = decode_jwt(new_token)

    return render_template(
        "token_exchange_obo.html",
        original_token_info=original_info,
        exchange_result=exchange_result,
        exchanged_token_info=exchanged_token_info,
    )


# ── 5. Token Rescoping / Downscoping (RFC 8693) ────────────────────────────────

@app.route("/auth/token-exchange/rescope")
def token_exchange_rescope():
    """
    Token rescoping (downscoping) demo.

    demo-client exchanges its own token for a new one with a narrower scope —
    the 'roles' scope is intentionally omitted so realm_access.roles disappears
    from the new token.  This lets a service hand a third party a token that can
    only do a limited subset of what the original token could do.

    RFC 8693 grant_type: urn:ietf:params:oauth:grant-type:token-exchange
    """
    td = session.get("token_data")
    if not td:
        flash("Please log in first to try the Token Rescoping demo.", "warning")
        return redirect(url_for("index"))
    if token_expired(td):
        flash("Your token has expired. Please log in again.", "warning")
        return redirect(url_for("index"))

    original_token = td.get("access_token", "")
    original_info  = decode_jwt(original_token)

    resp = requests.post(
        KC_TOKEN_URL,
        data={
            "grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id":            CLIENT_ID,
            "client_secret":        CLIENT_SECRET,
            "subject_token":        original_token,
            "subject_token_type":   "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            # Deliberately omit 'roles' → the new token will have no realm_access.roles
            "scope":                "openid email profile",
        },
        timeout=10,
    )

    exchange_result = {
        "status_code": resp.status_code,
        "success":     resp.ok,
        "data":        resp.json() if resp.content else None,
    }
    rescoped_token_info = None
    if resp.ok:
        new_token = exchange_result["data"].get("access_token", "")
        rescoped_token_info = decode_jwt(new_token)

    return render_template(
        "token_exchange_rescope.html",
        original_token_info=original_info,
        exchange_result=exchange_result,
        rescoped_token_info=rescoped_token_info,
    )


# ── 6. SPIFFE workload identity demo ──────────────────────────────────────────

@app.route("/auth/spiffe")
def spiffe_demo():
    """
    Proxy the full SPIFFE → OAuth2 → Resource Server demo from the spiffe-service.

    The spiffe-service container holds the SPIRE agent socket and performs:
      1. Fetch JWT-SVID from SPIRE workload API (proves container identity)
      2. Validate SPIFFE identity locally
      3. Map SPIFFE ID → Keycloak service account (bridge pattern)
      4. Call the protected resource server with the resulting OAuth2 token

    We just proxy the /demo endpoint result here and render it nicely.
    """
    try:
        resp = requests.get(f"{SPIFFE_URL}/demo", timeout=15)
        demo_data = resp.json() if resp.content else {}
        error = None if resp.ok else f"spiffe-service returned HTTP {resp.status_code}"
    except requests.ConnectionError:
        demo_data = {}
        error = "Cannot connect to spiffe-service — is the container running?"
    except Exception as exc:
        demo_data = {}
        error = str(exc)

    return render_template("spiffe_demo.html", demo=demo_data, error=error)


# ── 8. DPoP — Proof of Possession (RFC 9449) ──────────────────────────────────

@app.route("/auth/dpop")
def dpop_demo():
    """
    DPoP (Demonstrating Proof of Possession) demo — RFC 9449.

    Generates an ephemeral EC P-256 key pair, performs a Password Grant for alice
    using a DPoP-bound request (so the token contains cnf.jkt), then calls the
    DPoP-protected resource server endpoint with a second proof.

    The private key is used in-place and never stored — the demo is fully self-contained
    and does not depend on an existing session.
    """
    priv, pub_jwk = generate_dpop_keypair()
    jkt = jwk_thumbprint(pub_jwk)

    # DPoP proof for the token endpoint. htu must match the URL we actually POST to —
    # Keycloak builds the expected htu from the received request URI, not from KC_HOSTNAME.
    token_htu   = KC_TOKEN_URL
    token_proof = make_dpop_proof(priv, pub_jwk, "POST", token_htu)
    token_proof_info = decode_jwt(token_proof)

    token_resp = requests.post(
        KC_TOKEN_URL,
        data={
            "grant_type":    "password",
            "client_id":     DPOP_CLIENT_ID,
            "client_secret": DPOP_CLIENT_SECRET,
            "username":      "alice",
            "password":      "alice123",
            "scope":         "openid profile email roles",
        },
        headers={"DPoP": token_proof},
        timeout=10,
    )
    token_result = {
        "status_code": token_resp.status_code,
        "success":     token_resp.ok,
        "data":        token_resp.json() if token_resp.content else {},
    }

    dpop_token_info   = None
    api_proof_info    = None
    api_result        = None

    if token_resp.ok:
        dpop_access_token = token_result["data"].get("access_token", "")
        dpop_token_info   = decode_jwt(dpop_access_token)

        api_url    = f"{RESOURCE_URL}/api/dpop-protected"
        api_proof  = make_dpop_proof(priv, pub_jwk, "GET", api_url, access_token=dpop_access_token)
        api_proof_info = decode_jwt(api_proof)

        try:
            api_resp = requests.get(
                api_url,
                headers={"Authorization": f"DPoP {dpop_access_token}", "DPoP": api_proof},
                timeout=10,
            )
            api_result = {
                "status_code": api_resp.status_code,
                "success":     api_resp.ok,
                "data":        api_resp.json() if api_resp.content else {},
                "url":         api_url,
            }
        except requests.ConnectionError:
            api_result = {
                "status_code": 503, "success": False,
                "data": {"error": "Cannot connect to resource server"}, "url": api_url,
            }

    return render_template(
        "dpop_demo.html",
        pub_jwk=pub_jwk,
        jkt=jkt,
        token_proof_info=token_proof_info,
        token_htu=token_htu,
        token_result=token_result,
        dpop_token_info=dpop_token_info,
        api_proof_info=api_proof_info,
        api_url_display="http://localhost:8001/api/dpop-protected",
        api_result=api_result,
    )


# ── 7. OIDC Identity Layer ────────────────────────────────────────────────────

@app.route("/auth/oidc")
def oidc_demo():
    """
    OpenID Connect identity layer demo.

    Shows the three OIDC-specific artefacts that sit on top of OAuth2:
      - id_token: JWT for the client, proves who the user is
      - UserInfo endpoint: live call returning user profile claims
      - Discovery document: /.well-known/openid-configuration

    Client Credentials tokens have no id_token — that case is handled gracefully.
    """
    td = session.get("token_data")
    if not td:
        flash("Please log in first to explore the OIDC identity layer.", "warning")
        return redirect(url_for("index"))
    if token_expired(td):
        flash("Your token has expired. Please log in again.", "warning")
        return redirect(url_for("index"))

    flow = td.get("flow", "unknown")
    id_token_raw  = td.get("id_token")
    id_token_info = decode_jwt(id_token_raw) if id_token_raw else None

    access_token      = td.get("access_token", "")
    access_token_info = decode_jwt(access_token)

    # Call UserInfo endpoint (server-to-server)
    userinfo_internal = f"{KC_INT}/realms/{REALM}/protocol/openid-connect/userinfo"
    userinfo_display  = f"{KC_EXT}/realms/{REALM}/protocol/openid-connect/userinfo"
    try:
        ui_resp      = requests.get(userinfo_internal, headers={"Authorization": f"Bearer {access_token}"}, timeout=10)
        userinfo     = ui_resp.json() if ui_resp.content else {}
        userinfo_status = ui_resp.status_code
        userinfo_ok  = ui_resp.ok
    except Exception as exc:
        userinfo        = {"error": str(exc)}
        userinfo_status = 503
        userinfo_ok     = False

    # Fetch OIDC discovery document
    discovery_internal = f"{KC_INT}/realms/{REALM}/.well-known/openid-configuration"
    discovery_display  = f"{KC_EXT}/realms/{REALM}/.well-known/openid-configuration"
    try:
        disc_resp    = requests.get(discovery_internal, timeout=10)
        discovery    = disc_resp.json() if disc_resp.content else {}
        discovery_ok = disc_resp.ok
    except Exception as exc:
        discovery    = {"error": str(exc)}
        discovery_ok = False

    return render_template(
        "oidc_demo.html",
        flow=flow,
        id_token_raw=id_token_raw,
        id_token_info=id_token_info,
        access_token_info=access_token_info,
        userinfo=userinfo,
        userinfo_status=userinfo_status,
        userinfo_ok=userinfo_ok,
        userinfo_url=userinfo_display,
        discovery=discovery,
        discovery_ok=discovery_ok,
        discovery_url=discovery_display,
        has_id_token=id_token_raw is not None,
    )


# ── 9. Device Authorization Grant (RFC 8628) ──────────────────────────────────

@app.route("/auth/device")
def device_flow():
    """
    Device Authorization Grant demo — RFC 8628.

    Calls Keycloak's device authorization endpoint to obtain a device_code and
    user_code. The template polls /auth/device/poll via JavaScript every N seconds
    until the user approves the request at the verification_uri.
    """
    resp = requests.post(
        KC_DEVICE_URL,
        data={"client_id": DEVICE_CLIENT_ID, "scope": "openid profile email roles"},
        auth=(DEVICE_CLIENT_ID, DEVICE_CLIENT_SECRET),
        timeout=10,
    )
    device_data = resp.json() if resp.content else {}

    if not resp.ok:
        return render_template("device_demo.html",
                               error_info={"status_code": resp.status_code, "data": device_data},
                               device_data=None)

    # Replace the internal KC hostname with the browser-accessible one so the
    # verification_uri link works when the user clicks it.
    for key in ("verification_uri", "verification_uri_complete"):
        if key in device_data:
            device_data[key] = device_data[key].replace(KC_INT, KC_EXT)

    session["device_code"]    = device_data.get("device_code")
    session["device_expires"] = time.time() + device_data.get("expires_in", 600)
    session["device_interval"] = device_data.get("interval", 5)

    return render_template("device_demo.html", device_data=device_data, error_info=None)


@app.route("/auth/device/poll")
def device_poll():
    """AJAX endpoint polled by the device demo page. Returns JSON status."""
    device_code = session.get("device_code")
    if not device_code:
        return jsonify({"status": "error", "error": "no_device_session",
                        "error_description": "No active device flow. Start a new one."})

    if time.time() > session.get("device_expires", 0):
        session.pop("device_code", None)
        return jsonify({"status": "expired", "error": "expired_token",
                        "error_description": "The device code has expired."})

    resp = requests.post(
        KC_TOKEN_URL,
        data={
            "grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
            "client_id":   DEVICE_CLIENT_ID,
            "device_code": device_code,
        },
        auth=(DEVICE_CLIENT_ID, DEVICE_CLIENT_SECRET),
        timeout=10,
    )
    result = resp.json() if resp.content else {}

    if resp.ok:
        session.pop("device_code", None)
        access_token = result.get("access_token", "")
        return jsonify({
            "status":     "success",
            "token_type": result.get("token_type"),
            "expires_in": result.get("expires_in"),
            "scope":      result.get("scope"),
            "token_info": decode_jwt(access_token),
        })

    error = result.get("error", "")
    if error == "authorization_pending":
        return jsonify({"status": "authorization_pending"})
    if error == "slow_down":
        return jsonify({"status": "slow_down"})
    session.pop("device_code", None)
    return jsonify({"status": "error", "error": error,
                    "error_description": result.get("error_description", "")})


# ── 10. PKCE — Proof Key for Code Exchange (RFC 7636) ─────────────────────────

@app.route("/auth/pkce")
def pkce_flow():
    """
    Start a PKCE-protected Authorization Code flow — RFC 7636.

    Generates an ephemeral code_verifier, derives its S256 challenge, stores both
    in the session, then redirects to Keycloak.  The callback detects pkce_flow=True
    and includes the verifier in the token exchange.  The result is shown on
    /auth/pkce/result.
    """
    code_verifier  = _b64url(secrets.token_bytes(32))
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    session["oauth_state"]    = state
    session["oauth_nonce"]    = nonce
    session["pkce_flow"]      = True
    session["pkce_verifier"]  = code_verifier
    session["pkce_challenge"] = code_challenge

    params = {
        "client_id":             PKCE_CLIENT_ID,
        "redirect_uri":          REDIRECT_URI,
        "response_type":         "code",
        "scope":                 "openid profile email roles",
        "state":                 state,
        "nonce":                 nonce,
        "code_challenge":        code_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{KC_AUTH_URL}?{urlencode(params)}"
    session["pkce_auth_url"] = auth_url
    return redirect(auth_url)


@app.route("/auth/pkce/result")
def pkce_result():
    """Shows the PKCE details and resulting token after the Keycloak callback."""
    pkce_info  = session.pop("pkce_result", None)
    token_data = session.get("token_data")

    if not pkce_info or not token_data or token_data.get("flow") != "pkce":
        flash("No PKCE result found — start the flow from the home page.", "warning")
        return redirect(url_for("index"))

    token_info    = decode_jwt(token_data.get("access_token", ""))
    id_token_info = decode_jwt(token_data.get("id_token", "")) if token_data.get("id_token") else None

    return render_template("pkce_demo.html",
        pkce_info=pkce_info,
        token_data=token_data,
        token_info=token_info,
        id_token_info=id_token_info,
    )


# ── 11. Token Introspection (RFC 7662) ────────────────────────────────────────

@app.route("/auth/introspect")
def introspect_demo():
    """
    Token Introspection demo — RFC 7662.

    Gets a fresh token pair for alice, calls the Keycloak introspection endpoint
    (active: true), revokes the refresh token to invalidate the session, then
    introspects again to show active: false — demonstrating that introspection
    detects revocation in real time while local JWT decode cannot.
    """
    # 1. Get a fresh access + refresh token
    token_resp = requests.post(KC_TOKEN_URL, data={
        "grant_type":    "password",
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "username":      "alice",
        "password":      "alice123",
        "scope":         "openid profile email roles",
    }, timeout=10)

    token_result = {
        "status_code": token_resp.status_code,
        "success":     token_resp.ok,
        "data":        token_resp.json() if token_resp.content else {},
    }

    if not token_resp.ok:
        return render_template("introspect_demo.html", token_result=token_result,
                               access_token=None, local_decode=None,
                               introspect_active=None, revoke_result=None,
                               introspect_revoked=None)

    access_token  = token_result["data"].get("access_token", "")
    refresh_token = token_result["data"].get("refresh_token", "")
    local_decode  = decode_jwt(access_token)

    # 2. Introspect the active token
    intr_resp = requests.post(
        KC_INTROSPECT_URL,
        data={"token": access_token, "token_type_hint": "access_token"},
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=10,
    )
    introspect_active = {
        "status_code": intr_resp.status_code,
        "success":     intr_resp.ok,
        "data":        intr_resp.json() if intr_resp.content else {},
    }

    # 3. Revoke the refresh token (invalidates the Keycloak session)
    revoke_resp = requests.post(
        KC_REVOKE_URL,
        data={
            "token":           refresh_token,
            "token_type_hint": "refresh_token",
            "client_id":       CLIENT_ID,
            "client_secret":   CLIENT_SECRET,
        },
        timeout=10,
    )
    revoke_result = {"status_code": revoke_resp.status_code, "success": revoke_resp.ok}

    # 4. Introspect again after revocation
    intr_rev_resp = requests.post(
        KC_INTROSPECT_URL,
        data={"token": access_token, "token_type_hint": "access_token"},
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=10,
    )
    introspect_revoked = {
        "status_code": intr_rev_resp.status_code,
        "success":     intr_rev_resp.ok,
        "data":        intr_rev_resp.json() if intr_rev_resp.content else {},
    }

    return render_template("introspect_demo.html",
        token_result=token_result,
        access_token=access_token,
        local_decode=local_decode,
        introspect_active=introspect_active,
        revoke_result=revoke_result,
        introspect_revoked=introspect_revoked,
    )


# ── Token refresh ──────────────────────────────────────────────────────────────

@app.route("/auth/refresh")
def refresh_token():
    td = session.get("token_data")
    if not td or "refresh_token" not in td:
        flash("No refresh token available.", "warning")
        return redirect(url_for("index"))

    resp = requests.post(
        KC_TOKEN_URL,
        data={
            "grant_type":    "refresh_token",
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": td["refresh_token"],
        },
        timeout=10,
    )

    if not resp.ok:
        flash("Token refresh failed — please log in again.", "warning")
        session.pop("token_data", None)
        return redirect(url_for("index"))

    tokens = resp.json()
    tokens["expires_at"] = time.time() + tokens.get("expires_in", 300)
    tokens["flow"]       = td.get("flow", "unknown") + " (refreshed)"
    session["token_data"] = tokens

    flash("Access token refreshed successfully!", "success")
    return redirect(url_for("index"))


# ── Logout ─────────────────────────────────────────────────────────────────────

@app.route("/auth/logout")
def logout():
    td = session.pop("token_data", None)
    flow = (td or {}).get("flow", "")
    # Client Credentials tokens belong to a service account — there is no
    # interactive SSO session to end in Keycloak, so skip the RP-initiated
    # logout redirect and just clear the Flask session.
    if td and "id_token" in td and flow != "client_credentials":
        params = {
            "post_logout_redirect_uri": "http://localhost:5000/",
            "id_token_hint": td["id_token"],
        }
        return redirect(f"{KC_LOGOUT_URL}?{urlencode(params)}")
    flash("Logged out.", "info")
    return redirect(url_for("index"))


# ── API calls to Resource Server ──────────────────────────────────────────────

ENDPOINT_MAP = {
    "public":      ("/api/public",          False),   # (path, requires_token)
    "products":    ("/api/products",         True),
    "me":          ("/api/users/me",         True),
    "users":       ("/api/users",            True),
    "admin":       ("/api/admin/dashboard",  True),
    "token-info":  ("/api/token/info",       True),
}

@app.route("/api/call/<name>")
def api_call(name: str):
    path, needs_token = ENDPOINT_MAP.get(name, (f"/api/{name}", True))
    td = session.get("token_data")

    if needs_token:
        if not td:
            flash("Please log in first.", "warning")
            return redirect(url_for("index"))
        if token_expired(td):
            flash("Your token has expired. Please log in again.", "warning")
            return redirect(url_for("index"))

    access_token = td["access_token"] if (td and not token_expired(td)) else None
    result       = call_resource(path, access_token if needs_token else None)
    token_info   = decode_jwt(access_token) if access_token else None

    return render_template(
        "api_result.html",
        result=result,
        endpoint=path,
        token_info=token_info,
        endpoint_name=name,
    )


# ── Token inspector ────────────────────────────────────────────────────────────

@app.route("/token/inspect")
def token_inspect():
    td = session.get("token_data")
    if not td:
        flash("No token in session. Please log in first.", "warning")
        return redirect(url_for("index"))

    return render_template(
        "token_inspect.html",
        token_data=td,
        access_token_info  = decode_jwt(td.get("access_token",  "")),
        refresh_token_info = decode_jwt(td["refresh_token"])  if "refresh_token" in td else None,
        id_token_info      = decode_jwt(td["id_token"])        if "id_token"      in td else None,
        flow=td.get("flow", "unknown"),
    )


# ── Docs section — rendered markdown documentation ────────────────────────────

DOCS_DIR = os.getenv(
    "DOCS_DIR",
    # Development fallback: docs/ sits next to client-app/ in the project root
    os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "docs")),
)

DOCS_MANIFEST = [
    {
        "slug":        "architecture",
        "file":        "architecture.md",
        "title":       "Architecture",
        "icon":        "bi-diagram-3-fill",
        "color":       "primary",
        "badge":       "System Design",
        "description": "Components, network topology, JWT structure, and security model",
    },
    {
        "slug":        "oauth2-flows",
        "file":        "oauth2-flows.md",
        "title":       "OAuth2 / OIDC Flows",
        "icon":        "bi-arrow-repeat",
        "color":       "success",
        "badge":       "Core Reference",
        "description": "All eleven flows in detail — diagrams, request/response examples, and key differences",
    },
    {
        "slug":        "spiffe-oauth2",
        "file":        "spiffe-oauth2.md",
        "title":       "SPIFFE / SPIRE + OAuth2",
        "icon":        "bi-fingerprint",
        "color":       "info",
        "badge":       "Workload Identity",
        "description": "JWT-SVIDs, RFC 7523 private_key_jwt client auth, and the legacy bridge pattern",
    },
    {
        "slug":        "obo-manual-setup",
        "file":        "obo-manual-setup.md",
        "title":       "OBO Manual Setup",
        "icon":        "bi-wrench-adjustable-circle-fill",
        "color":       "warning",
        "badge":       "How-To Guide",
        "description": "Step-by-step guide for manually configuring On-Behalf-Of token exchange in KC 26.2+",
    },
    {
        "slug":        "keycloak-brokering",
        "file":        "keycloakbrokeringtoping.md",
        "title":       "Keycloak → Ping Brokering",
        "icon":        "bi-arrow-left-right",
        "color":       "danger",
        "badge":       "Identity Brokering",
        "description": "How Keycloak brokers authentication to PingFederate / PingOne — sequence diagrams and 23-step flow walkthrough",
    },
]

# Generate Pygments CSS once at startup; injected into docs_page.html
try:
    from pygments.formatters import HtmlFormatter as _HtmlFormatter
    _PYGMENTS_CSS = _HtmlFormatter(style="monokai").get_style_defs(".highlight")
except Exception:
    _PYGMENTS_CSS = ""


_MERMAID_FENCE_RE = _re.compile(r'```mermaid\s*\n(.*?)```', _re.DOTALL)


def _render_doc(filename: str):
    """Read and render a markdown file. Returns (content_html, toc_html)."""
    path = os.path.join(DOCS_DIR, filename)
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return (
            Markup("<p class='text-danger'><strong>Documentation file not found.</strong><br>"
                   f"Expected path: <code>{path}</code></p>"),
            Markup(""),
        )
    # Convert mermaid fenced blocks to raw HTML divs before markdown processes them.
    # Python-markdown passes block-level HTML through unchanged, so Mermaid.js
    # on the client picks them up and renders the diagrams.
    raw = _MERMAID_FENCE_RE.sub(
        lambda m: f'<div class="mermaid">\n{_html.escape(m.group(1))}\n</div>', raw
    )
    md = _markdown.Markdown(
        extensions=["tables", "fenced_code", "codehilite", "toc", "attr_list"],
        extension_configs={
            "codehilite": {"css_class": "highlight", "use_pygments": True},
            "toc": {"title": "", "toc_depth": "2-3", "permalink": True,
                    "permalink_class": "toc-anchor", "permalink_title": "¶"},
        },
    )
    return Markup(md.convert(raw)), Markup(md.toc)


@app.route("/docs")
def docs_index():
    return render_template("docs_index.html", docs=DOCS_MANIFEST)


@app.route("/docs/<slug>")
def docs_page(slug: str):
    doc = next((d for d in DOCS_MANIFEST if d["slug"] == slug), None)
    if not doc:
        flash(f"Documentation page '{slug}' not found.", "warning")
        return redirect(url_for("docs_index"))
    content, toc = _render_doc(doc["file"])
    return render_template(
        "docs_page.html",
        doc=doc,
        content=content,
        toc=toc,
        all_docs=DOCS_MANIFEST,
        pygments_css=_PYGMENTS_CSS,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
