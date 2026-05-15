"""
Client Application — Flask OAuth2 / OIDC learning demo.

Demonstrates eleven flows across the OAuth2 / OpenID Connect family:

  # Grant type         RFC               When to use
  ─────────────────────────────────────────────────────────────────────────────
  1  Authorization Code  RFC 6749 §4.1   Any web app where a human logs in
  2  ROPC                RFC 6749 §4.3   Scripts / CLIs only — avoid in prod
  3  Client Credentials  RFC 6749 §4.4   Service-to-service, no user session
  4  On-Behalf-Of        RFC 8693        Middle tier propagates user identity
  5  Token Rescoping     RFC 8693        Strip roles for least-privilege forwarding
  6  SPIFFE private_key_jwt  RFC 7523    Workload identity, no static secret
  7  OIDC identity layer OIDC Core       id_token, UserInfo, Discovery
  8  DPoP                RFC 9449        Sender-constrained tokens (replay-proof)
  9  Device Auth Grant   RFC 8628        Browserless / IoT devices
 10  PKCE                RFC 7636        Public clients without a client_secret
 11  Token Introspection RFC 7662        Real-time active/revoked state from AS

After obtaining a token each flow calls the protected Resource Server at :8001
and shows the raw JWT alongside the decoded header/payload so readers can see
exactly what Keycloak put inside each token type.

Dual-URL convention used throughout this file
─────────────────────────────────────────────
KC_EXT  Browser-facing URL (localhost:8080, port-mapped from Docker to the host).
        Used for all URLs the browser must follow: auth redirect, logout redirect.
KC_INT  Server-facing URL (keycloak:8080, Docker-internal DNS).
        Used for all server-to-server calls: token endpoint, introspection, JWKS.
        KC_INT is not reachable from outside Docker; KC_EXT is not guaranteed
        to be reachable from inside Docker (depends on host networking).
        KC_HOSTNAME=localhost ensures Keycloak publishes its token endpoint as
        http://localhost:8080/... so id_token iss/aud and OIDC discovery always
        reference the external URL, matching what browsers and JWT validators expect.

URL layout
──────────
  /                               Home page (session state, flow buttons, API demo)
  /auth/authorization-code        Start Authorization Code flow
  /auth/callback                  Shared OAuth2 redirect_uri (Auth Code + PKCE)
  /auth/password                  ROPC form (GET shows form, POST submits it)
  /auth/client-credentials        Client Credentials grant
  /auth/token-exchange/obo        On-Behalf-Of token exchange demo
  /auth/token-exchange/rescope    Token downscoping demo
  /auth/spiffe                    SPIFFE workload identity demo (proxy to :8002)
  /auth/dpop                      DPoP proof-of-possession demo
  /auth/oidc                      OIDC identity layer (id_token, UserInfo, Discovery)
  /auth/device                    Device Authorization Grant demo
  /auth/device/poll               AJAX polling endpoint for device flow
  /auth/pkce                      Start PKCE Authorization Code flow
  /auth/pkce/result               PKCE result page
  /auth/introspect                Token Introspection + revocation demo
  /auth/refresh                   Refresh the current access token
  /auth/logout                    RP-initiated logout (clears session + Keycloak SSO)
  /token/inspect                  Full JWT inspection page
  /api/call/<name>                Proxied calls to the Resource Server
  /docs                           Documentation index
  /docs/<slug>                    Rendered markdown documentation page
"""

import base64
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone
from urllib.parse import urlencode

import requests
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for

# DPoP cryptography helpers — extracted module (RFC 9449).  _b64url lives there
# too because PKCE re-uses it for encoding the code_verifier.
from dpop import _b64url, generate_dpop_keypair, jwk_thumbprint, make_dpop_proof

# Markdown rendering pipeline for /docs/* — extracted module.  The Flask routes
# stay here; everything they need (manifest, renderer, Pygments CSS) lives there.
from docs_renderer import DOCS_DIR, DOCS_MANIFEST, _PYGMENTS_CSS, _render_doc

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")

# ── Configuration ──────────────────────────────────────────────────────────────
# See module docstring for the KC_EXT / KC_INT dual-URL explanation.
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

# ── Agentic AI configuration ──────────────────────────────────────────────────
# Server-side URLs for the MCP service and each agent container.  Used by the
# /agentic/* routes which trigger an agent run and render its structured trace.
MCP_SERVICE_URL     = os.getenv("MCP_SERVICE_URL",     "http://mcp-service:8003")
AGENT_SECRET_URL      = os.getenv("AGENT_SECRET_URL",      "http://agent-secret:9001")
AGENT_SPIFFE_URL      = os.getenv("AGENT_SPIFFE_URL",      "http://agent-spiffe:9002")
AGENT_CERT_URL        = os.getenv("AGENT_CERT_URL",        "http://agent-cert:9003")
AGENT_DELEGATED_URL   = os.getenv("AGENT_DELEGATED_URL",   "http://agent-delegated:9004")
AGENT_SPIFFE_MTLS_URL = os.getenv("AGENT_SPIFFE_MTLS_URL", "http://agent-spiffe-mtls:9005")

# Agent registry — slug → (display name, agent base URL, description, icon, color, badge).
# Adding a new agent (e.g. UC3 cert) is a single entry here plus a container in
# docker-compose.yml that exposes the same /run + /info contract.
AGENT_REGISTRY = {
    "client-secret": {
        "title":       "Client Secret",
        "url":         AGENT_SECRET_URL,
        "description": "Service principal authenticating with a static client_id + client_secret. "
                       "Obtains a Keycloak token via the Client Credentials grant, then calls the "
                       "protected MCP server.",
        "icon":        "bi-key-fill",
        "color":       "primary",
        "badge":       "UC1 · Client Credentials",
        "rfc":         "RFC 6749 §4.4",
    },
    "spiffe": {
        "title":       "SPIFFE Workload Identity",
        "url":         AGENT_SPIFFE_URL,
        "description": "Agent attests its identity to SPIRE (unix:uid:1000 selector) and signs an "
                       "RFC 7523 client_assertion with an ephemeral EC key. Keycloak validates "
                       "the assertion against the agent's JWKS endpoint — zero static secrets.",
        "icon":        "bi-fingerprint",
        "color":       "success",
        "badge":       "UC2 · Workload Identity",
        "rfc":         "RFC 7523 + SPIFFE",
    },
    "spiffe-mtls": {
        "title":       "SPIFFE + mTLS (Hardened)",
        "url":         AGENT_SPIFFE_MTLS_URL,
        "description": "Production-grade SPIFFE: the agent presents its SPIRE-issued X.509-SVID "
                       "during the TLS handshake to a sidecar proxy.  The proxy validates the cert "
                       "chain against the SPIRE trust-domain bundle before forwarding to Keycloak. "
                       "Issued access tokens are cert-bound (cnf.x5t#S256, RFC 8705) — replay-proof.",
        "icon":        "bi-shield-lock-fill",
        "color":       "danger",
        "badge":       "UC2-Hardened · SPIFFE + mTLS",
        "rfc":         "RFC 8705 + SPIFFE",
    },
    "cert": {
        "title":       "X.509 Certificate",
        "url":         AGENT_CERT_URL,
        "description": "Service principal with a CA-issued certificate and long-lived private key. "
                       "The key signs an RFC 7523 client_assertion; the JWKS published by the agent "
                       "embeds the certificate (x5c + x5t#S256) so the cert chain is verifiable.",
        "icon":        "bi-patch-check-fill",
        "color":       "warning",
        "badge":       "UC3a · Certificate",
        "rfc":         "RFC 7523 + X.509",
    },
    "user-delegated-rescope": {
        "title":       "User-Delegated (OBO + Rescope)",
        "url":         AGENT_DELEGATED_URL,
        "description": "An authenticated user delegates a task to the agent.  RFC 8693 token "
                       "exchange preserves the user's identity (sub) while narrowing the scope, "
                       "and the act claim records the agent as the actor — full custody chain "
                       "for audit.  Requires a logged-in user.",
        "icon":        "bi-person-arms-up",
        "color":       "info",
        "badge":       "UC4 · OBO + Rescoping",
        "rfc":         "RFC 8693",
        "requires_user_token": True,
    },
}

# Keycloak endpoints
KC_AUTH_URL       = f"{KC_EXT}/realms/{REALM}/protocol/openid-connect/auth"
KC_TOKEN_URL      = f"{KC_INT}/realms/{REALM}/protocol/openid-connect/token"
KC_LOGOUT_URL     = f"{KC_EXT}/realms/{REALM}/protocol/openid-connect/logout"
KC_DEVICE_URL     = f"{KC_INT}/realms/{REALM}/protocol/openid-connect/auth/device"
KC_INTROSPECT_URL = f"{KC_INT}/realms/{REALM}/protocol/openid-connect/token/introspect"
KC_REVOKE_URL     = f"{KC_INT}/realms/{REALM}/protocol/openid-connect/revoke"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _b64_decode(s: str) -> dict:
    """Base64url-decode a JWT segment (no padding required in the token itself)."""
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
    """Return True if the stored access token has passed its computed expiry time.

    expires_at is set by the caller as time.time() + expires_in at the moment the
    token is received.  We track it separately rather than decoding exp from the JWT
    so that the check works even when the JWT is opaque or the clock is slightly skewed.
    """
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
    """Inject auth state into every template render.

    Decodes the session's access token on each request so templates can display
    the current user, roles, and login state without explicit view logic.
    keycloak_url and realm are injected so templates can build admin/account links
    without hard-coding Keycloak's address.
    """
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
    """Render the home page with the current session state and API call buttons."""
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
    """
    Start the Authorization Code flow — RFC 6749 §4.1.

    Generates CSRF and replay-protection values, stores them in the server-side
    session, then redirects the browser to Keycloak's /auth endpoint.

    state  — random value stored in session and echoed back by Keycloak in the
             redirect to /auth/callback.  The callback rejects any response where
             state does not match, preventing CSRF attacks on the redirect_uri.

    nonce  — random value included in the auth request and embedded by Keycloak
             inside the id_token.  The client verifies it matches after decoding
             the id_token, preventing token replay attacks across sessions.
    """
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
    Handle the Keycloak redirect after user authentication — RFC 6749 §4.1.3.

    This single route serves as redirect_uri for both the plain Authorization Code
    flow (flow 1) and the PKCE flow (flow 10).  The flows share the same callback
    URL because Keycloak requires redirect_uri to match exactly what was registered
    for the client.  The session flag pkce_flow=True switches the token exchange
    logic to use pkce-client (public, no secret) and include code_verifier.

    Security checks performed here:
      • Error param  — propagated back to the user if Keycloak rejected the request.
      • state match  — verifies the returned state equals the value we stored before
                       redirecting, preventing CSRF on the redirect_uri endpoint.
      • code         — the short-lived one-time authorization code issued by Keycloak,
                       exchanged server-side for tokens (never exposed in the browser).
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
        # redirect_uri must exactly match the value sent in the authorization request;
        # Keycloak validates it as a security measure before issuing tokens.
        "redirect_uri": REDIRECT_URI,
        "code":         code,
    }
    if pkce_mode and pkce_verifier:
        token_payload["client_id"]     = PKCE_CLIENT_ID
        token_payload["code_verifier"] = pkce_verifier
        # pkce-client is a public client (no secret).  The code_verifier replaces
        # the client_secret as proof that this token request originates from the
        # same party that initiated the authorization request.
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
    """
    Resource Owner Password Credentials (ROPC) grant — RFC 6749 §4.3.

    The client submits the user's plaintext credentials directly to the token
    endpoint; there is no browser redirect.  Useful for scripts and CLIs where
    a redirect flow is impractical, but avoided in production web apps because:
      • The client application sees and handles the user's password directly.
      • It cannot support MFA, external identity providers, or consent screens.
      • RFC 9700 (OAuth 2.0 Security BCP) recommends against ROPC entirely.

    Requires directAccessGrantsEnabled: true on the Keycloak client (set in
    realm-export.json).  Keycloak will still validate credentials against the
    same user store, apply brute-force protection, and issue a full token set.
    """
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
    """
    Client Credentials grant — RFC 6749 §4.4.

    Authenticates the application itself (service-client) rather than a user.
    Keycloak issues a token for the service account attached to service-client.

    Key differences from user tokens:
      • No id_token in the response — service accounts have no user identity.
      • No refresh_token — service accounts have no SSO session to maintain;
        a new token is obtained by repeating the client_credentials request.
      • sub is the service account's UUID, not a user UUID.
      • preferred_username is "service-account-<client_id>".

    Typical use: microservice calling another microservice without user context.
    """
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
    On-Behalf-Of (OBO) token exchange — RFC 8693.

    middle-tier-client exchanges the authenticated user's token for a new token
    that carries the same user identity (sub unchanged) but is issued to the
    middle-tier service (azp = middle-tier-client).  An act claim is added to the
    delegated token recording that middle-tier-client performed the exchange,
    creating an auditable delegation chain.

    This pattern lets a middle-tier service call downstream APIs on behalf of the
    user without ever seeing or forwarding the original credentials or token.

    Prerequisites (both must be in place — configured by keycloak-init at startup):
      1. standard.token.exchange.enabled = true on middle-tier-client
         (KC 26.2+ GA, no feature flags; set via Admin REST API).
      2. middle-tier-client listed in the aud claim of the subject token
         (configured via an audience mapper in realm-export.json).
         Without this, Keycloak rejects the exchange: "token is not in the audience".
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
            # RFC 8693 standard token exchange grant type (KC 26.2+ GA)
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
    Token downscoping (rescoping) — RFC 8693.

    demo-client exchanges its own access token for a new token with a narrower
    scope list.  By omitting the 'roles' scope from the requested scope, the
    resulting token contains no realm_access.roles claim — the downstream service
    receiving this token cannot use it to perform role-protected operations even
    if it is compromised.

    This implements the least-privilege forwarding pattern: a middle tier holds
    a powerful token (e.g. admin-role) but passes only a weak, scope-limited token
    to the components that do not need elevated access.

    Requires standard.token.exchange.enabled = true on demo-client (set by
    keycloak-init alongside middle-tier-client at startup).
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
            # Omitting 'roles' causes Keycloak to exclude the realm_access.roles claim
            # entirely from the new token.  The scope list controls which protocol
            # mappers run; the roles mapper only fires when the 'roles' scope is present.
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
    Proxy the SPIFFE workload identity demo from the spiffe-service container.

    The spiffe-service holds the SPIRE agent unix socket and must run in the
    agent's PID namespace (pid: "service:spire-agent" in docker-compose.yml) so
    the SPIRE unix WorkloadAttestor can identify it by OS UID.  The four-step
    flow it executes:
      1. Fetch a JWT-SVID from the SPIRE Workload API (proves container identity
         via runtime attestation — no static credentials involved).
      2. Build an RFC 7523 client_assertion JWT signed with the service's own
         ephemeral EC key (generated in memory at startup, never persisted).
      3. POST to Keycloak's token endpoint using grant_type=client_credentials
         and client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer.
         Keycloak validates the assertion by fetching GET /jwks from spiffe-service.
      4. Call the Resource Server API with the resulting OAuth2 access token.

    This app merely proxies GET /demo and renders the structured JSON result.
    The actual SPIFFE logic lives in spiffe-service/main.py.
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
    with a DPoP-bound token request, then calls the DPoP-protected resource server
    endpoint with a second proof.  The demo is self-contained and does not depend
    on an existing browser session.

    How DPoP prevents Bearer token theft:
      A plain Bearer token can be replayed by anyone who intercepts it.  DPoP binds
      the token to a specific key pair: the access token contains a cnf.jkt claim
      (JWK thumbprint of the ephemeral public key).  Every request must be accompanied
      by a signed DPoP proof that includes the HTTP method and URL, so a stolen token
      is useless without the matching private key.

    Requires Keycloak 26.4+ (DPoP GA) and dpop.bound.access.tokens: true on
    dpop-client (provisioned by keycloak-init).
    """
    priv, pub_jwk = generate_dpop_keypair()
    jkt = jwk_thumbprint(pub_jwk)

    # Proof 1 of 2: for the token endpoint.
    # htu must match the URL Keycloak actually receives — use KC_TOKEN_URL (internal).
    # Keycloak compares htu against its own request URI, not its published KC_HOSTNAME URL.
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

        api_url = f"{RESOURCE_URL}/api/dpop-protected"
        # Proof 2 of 2: for the resource server call.  access_token is passed so
        # make_dpop_proof adds the ath (access token hash) claim — required by RFC 9449
        # §4.2 for resource server requests to bind the proof to this specific token.
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
    Device Authorization Grant — RFC 8628.

    Designed for devices that cannot display a browser (TVs, CLIs, IoT).  The
    device obtains a device_code and user_code from Keycloak, then displays the
    user_code and verification_uri to the user.  The user opens the URI on a
    separate device (phone, laptop), enters the code, and authenticates.  Meanwhile
    the device polls /auth/device/poll until Keycloak grants the token.

    Polling states returned by Keycloak:
      authorization_pending — user has not acted yet; wait interval seconds and retry
      slow_down             — polling too fast; add 5 s to interval and retry
      expired_token         — device_code expired; restart the flow
      access_denied         — user rejected; stop polling
      200 OK                — user approved; token issued
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

    # Keycloak returns verification_uri using KC_INT (the server's own hostname).
    # Replace with KC_EXT so the link is clickable from the user's browser outside
    # Docker.  The path and query string are not affected by this substitution.
    for key in ("verification_uri", "verification_uri_complete"):
        if key in device_data:
            device_data[key] = device_data[key].replace(KC_INT, KC_EXT)

    session["device_code"]    = device_data.get("device_code")
    session["device_expires"] = time.time() + device_data.get("expires_in", 600)
    session["device_interval"] = device_data.get("interval", 5)

    return render_template("device_demo.html", device_data=device_data, error_info=None)


@app.route("/auth/device/poll")
def device_poll():
    """
    AJAX polling endpoint for the Device Authorization Grant flow.

    The template calls this every interval seconds (as told by Keycloak in the
    initial device authorization response).  Returns a JSON object with a status
    field that the client-side JavaScript maps to a UI state:
      authorization_pending — still waiting; keep polling
      slow_down             — polling too fast; JS must increase the interval
      expired / error       — terminal states; stop polling and show an error
      success               — token received; render the decoded JWT claims
    """
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

    PKCE (Proof Key for Code Exchange) allows public clients — apps that cannot
    safely hold a client_secret (SPAs, mobile apps, CLIs) — to use the
    Authorization Code flow securely.  It works by binding the authorization
    request to the token exchange through a one-time cryptographic challenge:

      code_verifier   32 random bytes, base64url-encoded.  Kept secret in session.
      code_challenge  BASE64URL(SHA-256(code_verifier)).  Sent to Keycloak upfront.

    At the token exchange step, the verifier is sent instead of a client_secret.
    Keycloak recomputes SHA-256(verifier) and matches it against the stored challenge
    — only the party that initiated the authorization request can complete it.

    pkce-client is configured with pkce.code.challenge.method=S256 in Keycloak,
    which makes PKCE mandatory for that client (plain-text challenges are rejected).
    """
    code_verifier  = _b64url(secrets.token_bytes(32))
    # The verifier is base64url-encoded so it contains only URI-safe characters;
    # passing raw random bytes as a form field would corrupt them at transport.
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
    """
    Exchange the stored refresh_token for a fresh access_token — RFC 6749 §6.

    Refresh tokens are only issued for interactive flows (Authorization Code,
    ROPC, PKCE, DPoP).  Client Credentials tokens have no session and therefore
    no refresh token; calling this route when only a service-account token is in
    the session will show a warning.

    After a successful refresh Keycloak also rotates the refresh token: the old
    refresh token is invalidated and a new one is issued.  The response is stored
    back into the session, preserving the original flow name with " (refreshed)".
    """
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
    """
    Clear the Flask session and terminate the Keycloak SSO session (when possible).

    RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0) redirects the
    browser to Keycloak's end_session endpoint with id_token_hint so Keycloak can
    identify and terminate the correct SSO session without prompting the user.
    After Keycloak ends the session it redirects back to post_logout_redirect_uri.

    Client Credentials tokens have no id_token (service accounts have no SSO
    session) so we skip the Keycloak redirect and just clear the local session.
    Similarly, PKCE tokens issued to a public client include an id_token and do
    trigger the SSO logout redirect.
    """
    td = session.pop("token_data", None)
    flow = (td or {}).get("flow", "")
    if td and "id_token" in td and flow != "client_credentials":
        params = {
            "post_logout_redirect_uri": "http://localhost:5000/",
            "id_token_hint": td["id_token"],
        }
        return redirect(f"{KC_LOGOUT_URL}?{urlencode(params)}")
    flash("Logged out.", "info")
    return redirect(url_for("index"))


# ── API calls to Resource Server ──────────────────────────────────────────────

# Maps friendly URL name → (resource server path, requires_bearer_token).
# The "public" endpoint is intentionally unprotected on the resource server to
# demonstrate that the Flask session is not involved — any visitor can call it.
ENDPOINT_MAP = {
    "public":      ("/api/public",          False),
    "products":    ("/api/products",         True),
    "me":          ("/api/users/me",         True),
    "users":       ("/api/users",            True),
    "admin":       ("/api/admin/dashboard",  True),
    "token-info":  ("/api/token/info",       True),
}

@app.route("/api/call/<name>")
def api_call(name: str):
    """
    Proxy a call to a resource server endpoint by friendly name.

    Looks up the path and token requirement in ENDPOINT_MAP; unknown names fall
    back to /api/<name> with token required.  The resource server validates the
    JWT independently — it never calls this app back.  The result (status code +
    JSON body) is rendered in api_result.html alongside the decoded token so the
    reader can correlate claims with what the API accepted or rejected.
    """
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
    """
    Show fully decoded details for every token in the current session.

    Decodes the access_token, refresh_token (if present), and id_token (if present)
    side by side so the reader can compare header/payload claims across token types.
    Useful for understanding what Keycloak puts into each token type and how they
    differ (e.g. id_token is for the client, access_token is for resource servers).
    """
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


# ── Agentic AI section — MCP-protected agent demos ────────────────────────────
#
# Each agent container exposes a uniform HTTP contract:
#   GET  /info        Agent metadata (auth method, MCP URL, model, …)
#   POST /run         Synchronously execute one agent task; returns a structured
#                     trace (auth step, MCP discovery, Claude tool-use loop,
#                     final answer).  See ai-agents/agent-secret/agent.py.
#
# The Flask app does not perform any OAuth2 or MCP work itself for these demos —
# it just proxies the agent's response and renders it.  This keeps the
# educational story focused on the agent container, which is what would run in
# production.


@app.route("/agentic")
def agentic_index():
    """Landing page for the Agentic AI demos — lists every registered agent."""
    return render_template(
        "agentic_index.html",
        agents=AGENT_REGISTRY,
        mcp_service_url=MCP_SERVICE_URL,
    )


@app.route("/agentic/<slug>")
def agentic_agent(slug: str):
    """
    Trigger a single run of the named agent and render the result.

    Flow:
      1. GET  <agent>/info   to display configuration without running anything
         heavy if the agent is unhealthy.
      2. POST <agent>/run    to execute the full pipeline (token → MCP → Claude
         → final answer).  Long-ish — the Anthropic loop can take a few seconds.

    User-delegated agents (those with meta["requires_user_token"] = True) need
    the authenticated user's access token forwarded as the subject_token for the
    RFC 8693 exchange.  If the user is not logged in we redirect to login.
    """
    meta = AGENT_REGISTRY.get(slug)
    if not meta:
        flash(f"Unknown agent: '{slug}'.", "warning")
        return redirect(url_for("agentic_index"))

    # Gate on a valid session for user-delegated agents.
    payload: dict = {}
    if meta.get("requires_user_token"):
        td = session.get("token_data")
        if not td:
            flash("This agent acts on your behalf — please log in first.", "warning")
            return redirect(url_for("start_auth_code"))
        if token_expired(td):
            flash("Your token has expired. Please log in again to delegate to this agent.", "warning")
            return redirect(url_for("start_auth_code"))
        payload = {"user_access_token": td["access_token"]}

    info_data: dict = {}
    run_data:  dict | None = None
    error:     str  | None = None

    try:
        info_resp = requests.get(f"{meta['url']}/info", timeout=10)
        info_data = info_resp.json() if info_resp.ok else {}
    except Exception as exc:
        error = f"Cannot reach agent at {meta['url']}: {exc}"

    if error is None:
        try:
            # Agent runs can take several seconds when the Anthropic SDK is in use,
            # so we use a generous timeout. The agent itself caps the tool-use loop.
            # `json=payload` sends an empty body for service-principal agents, and a
            # {"user_access_token": "…"} body for user-delegated ones.  The agents
            # that don't need the body simply ignore it (FastAPI accepts unknown
            # JSON when no body is declared on the route).
            run_resp = requests.post(f"{meta['url']}/run",
                                     json=payload if payload else None,
                                     timeout=120)
            if run_resp.ok:
                run_data = run_resp.json()
            else:
                error = f"Agent returned HTTP {run_resp.status_code}: {run_resp.text[:300]}"
        except requests.ConnectionError as exc:
            error = f"Cannot connect to the agent container: {exc}"
        except Exception as exc:
            error = f"Agent run failed: {exc}"

    return render_template(
        "agentic_result.html",
        slug=slug,
        meta=meta,
        info=info_data,
        run=run_data,
        error=error,
        mcp_service_url=MCP_SERVICE_URL,
    )


# ── Docs section — Flask routes (rendering pipeline lives in docs_renderer.py) ─

@app.route("/docs")
def docs_index():
    """Render the documentation landing page listing all entries in DOCS_MANIFEST."""
    return render_template("docs_index.html", docs=DOCS_MANIFEST)


@app.route("/docs/<slug>")
def docs_page(slug: str):
    """
    Render a single documentation page identified by slug.

    Looks up the slug in DOCS_MANIFEST, reads the corresponding markdown file
    from DOCS_DIR, converts it to HTML via _render_doc (including Mermaid and
    Pygments syntax highlighting), and renders docs_page.html with the result.
    all_docs is passed so the left sidebar can list all available guides.
    """
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
