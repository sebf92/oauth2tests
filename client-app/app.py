"""
Client Application — Flask OAuth2 demo.

Demonstrates three OAuth2 grant types and two advanced token exchange patterns:
  1. Authorization Code Flow  — the standard, browser-redirect-based flow
  2. Resource Owner Password Credentials (ROPC) — direct username/password exchange
  3. Client Credentials — machine-to-machine, no user involved
  4. On-Behalf-Of (OBO) — RFC 8693 token exchange, middle tier acts on behalf of user
  5. Token Rescoping — RFC 8693 downscoping, strip roles from a token

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
  /auth/refresh                   Refresh the current access token
  /auth/logout                    Clear session + SSO logout from Keycloak
  /token/inspect                  Detailed JWT inspection page
  /api/call/<name>                Proxied calls to the Resource Server
"""

import base64
import json
import os
import secrets
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

import requests
from flask import Flask, flash, redirect, render_template, request, session, url_for

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

RESOURCE_URL  = os.getenv("RESOURCE_SERVER_URL", "http://resource-server:8001")
REDIRECT_URI  = os.getenv("REDIRECT_URI", "http://localhost:5000/auth/callback")

# Keycloak endpoints
KC_AUTH_URL    = f"{KC_EXT}/realms/{REALM}/protocol/openid-connect/auth"
KC_TOKEN_URL   = f"{KC_INT}/realms/{REALM}/protocol/openid-connect/token"
KC_LOGOUT_URL  = f"{KC_EXT}/realms/{REALM}/protocol/openid-connect/logout"


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
    Keycloak redirects here with ?code=… after the user authenticates.
    We exchange the code for tokens (server-side, never exposed to browser).
    """
    if err := request.args.get("error"):
        flash(f"Keycloak error: {request.args.get('error_description', err)}", "danger")
        return redirect(url_for("index"))

    code  = request.args.get("code")
    state = request.args.get("state")

    if not code or state != session.pop("oauth_state", None):
        flash("Invalid state parameter — possible CSRF attack.", "danger")
        return redirect(url_for("index"))

    # Exchange authorisation code for tokens (server-to-server call)
    resp = requests.post(
        KC_TOKEN_URL,
        data={
            "grant_type":   "authorization_code",
            "client_id":    CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "code":         code,
        },
        timeout=10,
    )

    if not resp.ok:
        flash(f"Token exchange failed: {resp.text}", "danger")
        return redirect(url_for("index"))

    tokens = resp.json()
    tokens["expires_at"] = time.time() + tokens.get("expires_in", 300)
    tokens["flow"]       = "authorization_code"
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
