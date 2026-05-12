#!/usr/bin/env python3
"""
Configures Keycloak clients via the Admin REST API.

Realm import cannot express all per-client settings, so we apply them here
after the realm has been imported.

What this script does:
  1. Waits for Keycloak to be fully ready.
  2. Enables Standard Token Exchange (KC 26.2+ GA) on middle-tier-client.
     → Sets the 'standard.token.exchange.enabled' attribute to 'true'.
       The old fine-grained authz approach (management/permissions + KC_FEATURES=preview)
       is replaced by this per-client attribute in KC 26.2+.
  3. Ensures spiffe-service, dpop-client, device-client, and pkce-client exist.
"""

import sys
import time

import httpx

KC_URL     = "http://keycloak:8080"
KC_MGMT    = "http://keycloak:9000"   # management interface (health, metrics) — KC 26+
REALM      = "demo"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"


# ── helpers ────────────────────────────────────────────────────────────────────

def _get(url: str, headers: dict, **kw) -> httpx.Response:
    r = httpx.get(url, headers=headers, timeout=10, **kw)
    r.raise_for_status()
    return r


def _post(url: str, headers: dict, **kw) -> httpx.Response:
    r = httpx.post(url, headers=headers, timeout=10, **kw)
    r.raise_for_status()
    return r


def _put(url: str, headers: dict, **kw) -> httpx.Response:
    r = httpx.put(url, headers=headers, timeout=10, **kw)
    r.raise_for_status()
    return r


# ── wait ───────────────────────────────────────────────────────────────────────

def wait_for_keycloak() -> None:
    """Wait until /health/ready returns 200 on the management interface (port 9000 in KC 26+)."""
    print(f"Waiting for Keycloak at {KC_MGMT} …")
    for attempt in range(60):
        try:
            r = httpx.get(f"{KC_MGMT}/health/ready", timeout=5)
            if r.status_code == 200:
                print("✓ Keycloak HTTP server is up")
                return
        except Exception:
            pass
        print(f"  attempt {attempt + 1}/60 — retrying in 10 s")
        time.sleep(10)
    raise SystemExit("Keycloak did not become ready in time")


def wait_for_realm_import() -> None:
    """
    Poll the Admin API until demo-client exists.

    Keycloak processes --import-realm AFTER /health/ready goes green, so a
    fixed sleep is unreliable. We wait for the actual artefact we need instead.
    """
    print("Waiting for realm import to complete (polling Admin API) …")
    for attempt in range(60):
        try:
            token = get_admin_token()
            h = {"Authorization": f"Bearer {token}"}
            r = httpx.get(
                f"{KC_URL}/admin/realms/{REALM}/clients",
                params={"clientId": "demo-client"},
                headers=h,
                timeout=10,
            )
            if r.status_code == 200 and r.json():
                print("✓ Realm import complete — demo-client found")
                return
        except Exception:
            pass
        print(f"  attempt {attempt + 1}/60 — realm not ready yet, retrying in 10 s")
        time.sleep(10)
    raise SystemExit("Realm import did not complete in time")


# ── admin token ────────────────────────────────────────────────────────────────

def get_admin_token() -> str:
    r = httpx.post(
        f"{KC_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id":  "admin-cli",
            "username":   ADMIN_USER,
            "password":   ADMIN_PASS,
        },
        timeout=10,
    )
    r.raise_for_status()
    print("✓ Admin token obtained")
    return r.json()["access_token"]


# ── core setup ─────────────────────────────────────────────────────────────────

def setup_token_exchange(token: str) -> None:
    """
    Enable Standard Token Exchange on middle-tier-client (KC 26.2+ approach).

    KC 26.2 promoted Standard Token Exchange from preview to GA and changed the
    permission model. The old approach used the realm-management authz server
    (management/permissions endpoint) and required KC_FEATURES=preview.

    The new approach simply sets 'standard.token.exchange.enabled' = 'true' on
    the requesting client. No fine-grained authz policies are needed.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    for client_id_str in ("middle-tier-client", "demo-client"):
        client_list = _get(f"{base}/clients", h, params={"clientId": client_id_str}).json()
        cid = client_list[0]["id"]
        print(f"  {client_id_str:<25} id = {cid}")

        client_rep = _get(f"{base}/clients/{cid}", h).json()
        attrs = client_rep.get("attributes") or {}

        if attrs.get("standard.token.exchange.enabled") == "true":
            print(f"  standard.token.exchange.enabled already set on {client_id_str}")
            continue

        attrs["standard.token.exchange.enabled"] = "true"
        client_rep["attributes"] = attrs
        _put(f"{base}/clients/{cid}", h, json=client_rep)
        print(f"✓ standard.token.exchange.enabled = true set on {client_id_str}")


# ── spiffe-service client ──────────────────────────────────────────────────────

SPIFFE_JWKS_URL = "http://spiffe-service:8002/jwks"

def ensure_spiffe_service_client(token: str) -> None:
    """
    Ensure spiffe-service uses RFC 7523 private_key_jwt auth (KC 26.4+ approach).

    No client_secret is configured. Keycloak validates client_assertion JWTs
    by fetching the JWKS from spiffe-service's /jwks endpoint. The key is
    generated in-memory at startup in spiffe-service/main.py.

    Idempotent: creates the client if missing, migrates it if it exists with
    the old client_secret authenticator type.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    existing = httpx.get(
        f"{base}/clients", headers=h, params={"clientId": "spiffe-service"}, timeout=10
    ).json()

    if existing:
        client      = existing[0]
        client_id   = client["id"]
        attrs       = client.get("attributes") or {}
        auth_type   = client.get("clientAuthenticatorType", "")
        jwks_ok     = attrs.get("use.jwks.url") == "true" and attrs.get("jwks.url") == SPIFFE_JWKS_URL

        if auth_type == "client-jwt" and jwks_ok:
            print(f"  spiffe-service client  id = {client_id} (already using private_key_jwt)")
        else:
            client["clientAuthenticatorType"] = "client-jwt"
            attrs["use.jwks.url"]             = "true"
            attrs["jwks.url"]                 = SPIFFE_JWKS_URL
            client["attributes"]              = attrs
            r = httpx.put(f"{base}/clients/{client_id}", headers=h, json=client, timeout=10)
            r.raise_for_status()
            print(f"  spiffe-service client  id = {client_id} (migrated to private_key_jwt)")
    else:
        r = httpx.post(
            f"{base}/clients",
            headers=h,
            json={
                "clientId":                  "spiffe-service",
                "enabled":                   True,
                "serviceAccountsEnabled":    True,
                "standardFlowEnabled":       False,
                "directAccessGrantsEnabled": False,
                "publicClient":              False,
                "clientAuthenticatorType":   "client-jwt",
                "protocol":                  "openid-connect",
                "defaultClientScopes":       ["web-origins", "acr", "profile", "roles", "email"],
                "attributes": {
                    "use.jwks.url": "true",
                    "jwks.url":     SPIFFE_JWKS_URL,
                },
            },
            timeout=10,
        )
        r.raise_for_status()
        location  = r.headers.get("Location", "")
        client_id = location.rstrip("/").split("/")[-1]
        print(f"  spiffe-service client  id = {client_id} (created with private_key_jwt)")

    # Ensure service account has user-role
    sa_user    = httpx.get(f"{base}/clients/{client_id}/service-account-user", headers=h, timeout=10).json()
    sa_user_id = sa_user["id"]

    realm_roles = httpx.get(f"{base}/roles", headers=h, timeout=10).json()
    user_role   = next((r for r in realm_roles if r["name"] == "user-role"), None)
    if not user_role:
        print("  user-role not found in realm — skipping assignment")
        return

    assigned = httpx.get(f"{base}/users/{sa_user_id}/role-mappings/realm", headers=h, timeout=10).json()
    if any(r["name"] == "user-role" for r in assigned):
        print("  user-role already assigned to spiffe-service service account")
    else:
        r = httpx.post(
            f"{base}/users/{sa_user_id}/role-mappings/realm",
            headers=h, json=[user_role], timeout=10,
        )
        r.raise_for_status()
        print("  user-role assigned to spiffe-service service account")


# ── dpop-client ────────────────────────────────────────────────────────────────

def ensure_dpop_client(token: str) -> None:
    """
    Ensure the dpop-client Keycloak client exists with DPoP enforcement enabled.

    dpop.bound.access.tokens: true means every token request to this client MUST
    include a valid DPoP proof header — plain Bearer requests are rejected.
    directAccessGrantsEnabled: true is required for the Password Grant demo flow.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    existing = httpx.get(
        f"{base}/clients", headers=h, params={"clientId": "dpop-client"}, timeout=10
    ).json()

    if existing:
        client_id = existing[0]["id"]
        print(f"  dpop-client            id = {client_id} (already exists)")
    else:
        r = httpx.post(
            f"{base}/clients",
            headers=h,
            json={
                "clientId":                  "dpop-client",
                "secret":                    "dpop-client-secret",
                "enabled":                   True,
                "serviceAccountsEnabled":    False,
                "standardFlowEnabled":       False,
                "directAccessGrantsEnabled": True,
                "publicClient":              False,
                "protocol":                  "openid-connect",
                "defaultClientScopes":       ["web-origins", "acr", "profile", "roles", "email"],
                "attributes": {
                    "dpop.bound.access.tokens": "true",
                },
            },
            timeout=10,
        )
        r.raise_for_status()
        location  = r.headers.get("Location", "")
        client_id = location.rstrip("/").split("/")[-1]
        print(f"  dpop-client            id = {client_id} (created)")


# ── device-client ─────────────────────────────────────────────────────────────

def ensure_device_client(token: str) -> None:
    """
    Ensure the device-client Keycloak client exists with Device Authorization Grant enabled.

    oauth2.device.authorization.grant.enabled: true activates the RFC 8628 device flow.
    standardFlowEnabled and directAccessGrantsEnabled are both false — this client is
    exclusively for the device code grant.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    existing = httpx.get(
        f"{base}/clients", headers=h, params={"clientId": "device-client"}, timeout=10
    ).json()

    if existing:
        client_id = existing[0]["id"]
        print(f"  device-client          id = {client_id} (already exists)")
    else:
        r = httpx.post(
            f"{base}/clients",
            headers=h,
            json={
                "clientId":                  "device-client",
                "secret":                    "device-client-secret",
                "enabled":                   True,
                "serviceAccountsEnabled":    False,
                "standardFlowEnabled":       False,
                "directAccessGrantsEnabled": False,
                "publicClient":              False,
                "protocol":                  "openid-connect",
                "defaultClientScopes":       ["web-origins", "acr", "profile", "roles", "email"],
                "attributes": {
                    "oauth2.device.authorization.grant.enabled": "true",
                },
            },
            timeout=10,
        )
        r.raise_for_status()
        location  = r.headers.get("Location", "")
        client_id = location.rstrip("/").split("/")[-1]
        print(f"  device-client          id = {client_id} (created)")


# ── pkce-client ────────────────────────────────────────────────────────────────

def ensure_pkce_client(token: str) -> None:
    """
    Ensure the pkce-client Keycloak client exists with PKCE enforcement enabled.

    publicClient: true — no client secret; the code_verifier provides the binding.
    pkce.code.challenge.method: S256 — Keycloak rejects auth code requests that
    omit a code_challenge, enforcing PKCE for every Authorization Code exchange.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    existing = httpx.get(
        f"{base}/clients", headers=h, params={"clientId": "pkce-client"}, timeout=10
    ).json()

    if existing:
        client_id = existing[0]["id"]
        print(f"  pkce-client            id = {client_id} (already exists)")
    else:
        r = httpx.post(
            f"{base}/clients",
            headers=h,
            json={
                "clientId":                  "pkce-client",
                "enabled":                   True,
                "serviceAccountsEnabled":    False,
                "standardFlowEnabled":       True,
                "directAccessGrantsEnabled": False,
                "publicClient":              True,
                "protocol":                  "openid-connect",
                "redirectUris":              ["http://localhost:5000/auth/callback"],
                "webOrigins":                ["http://localhost:5000"],
                "defaultClientScopes":       ["web-origins", "acr", "profile", "roles", "email"],
                "attributes": {
                    "pkce.code.challenge.method": "S256",
                },
            },
            timeout=10,
        )
        r.raise_for_status()
        location  = r.headers.get("Location", "")
        client_id = location.rstrip("/").split("/")[-1]
        print(f"  pkce-client            id = {client_id} (created)")


# ── entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    wait_for_keycloak()
    wait_for_realm_import()
    token = get_admin_token()
    setup_token_exchange(token)
    print("\n✓ Token exchange setup complete — OBO is ready!")
    token = get_admin_token()
    ensure_spiffe_service_client(token)
    print("\n✓ SPIFFE service client setup complete!")
    token = get_admin_token()
    ensure_dpop_client(token)
    print("\n✓ DPoP client setup complete!")
    token = get_admin_token()
    ensure_device_client(token)
    print("\n✓ Device Authorization Grant client setup complete!")
    token = get_admin_token()
    ensure_pkce_client(token)
    print("\n✓ PKCE client setup complete!")


if __name__ == "__main__":
    main()
