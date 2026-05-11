#!/usr/bin/env python3
"""
Configures Keycloak token-exchange permissions via the Admin REST API.

Realm import cannot express fine-grained authorization policies, so we apply
them here after the realm has been imported.

What this script does:
  1. Waits for Keycloak to be fully ready.
  2. Enables fine-grained permissions on demo-client.
     → Keycloak creates a token-exchange resource + a scope permission inside
       the realm-management authorization server.
  3. Creates a client policy that identifies middle-tier-client as the actor.
  4. Attaches that policy to the token-exchange scope permission.
     → middle-tier-client can now call the token endpoint with
       grant_type=urn:ietf:params:oauth:grant-type:token-exchange and a
       demo-client subject_token (On-Behalf-Of flow).
"""

import sys
import time

import httpx

KC_URL     = "http://keycloak:8080"
KC_MGMT    = "http://keycloak:9000"   # management interface (health, metrics) — KC 26+
REALM      = "demo"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"

POLICY_NAME = "allow-middle-tier-token-exchange"


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
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    # ── Step 1: resolve client UUIDs ──────────────────────────────────────────
    demo_id = _get(f"{base}/clients", h, params={"clientId": "demo-client"}).json()[0]["id"]
    print(f"  demo-client            id = {demo_id}")

    rm_id = _get(f"{base}/clients", h, params={"clientId": "realm-management"}).json()[0]["id"]
    print(f"  realm-management       id = {rm_id}")

    mid_id = _get(f"{base}/clients", h, params={"clientId": "middle-tier-client"}).json()[0]["id"]
    print(f"  middle-tier-client     id = {mid_id}")

    # ── Step 2: enable fine-grained permissions on demo-client ────────────────
    # This call creates a client.resource.{uuid} in realm-management's authz server
    # and returns the UUIDs of the scope permissions for view/manage/token-exchange/…
    mgmt = _put(
        f"{base}/clients/{demo_id}/management/permissions",
        h,
        json={"enabled": True},
    ).json()
    tx_perm_id = mgmt.get("scopePermissions", {}).get("token-exchange")
    if not tx_perm_id:
        raise SystemExit(
            f"token-exchange permission not found in management response: {mgmt}"
        )
    print(f"  token-exchange perm    id = {tx_perm_id}")

    # ── Step 3: create (or reuse) a client policy for middle-tier-client ──────
    create_resp = httpx.post(
        f"{base}/clients/{rm_id}/authz/resource-server/policy/client",
        headers=h,
        json={
            "name":             POLICY_NAME,
            "description":      "Allows middle-tier-client to perform OBO token exchange",
            "type":             "client",
            "logic":            "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "clients":          [mid_id],
        },
        timeout=10,
    )
    if create_resp.status_code == 409:
        # Policy already exists — fetch its ID
        existing = _get(
            f"{base}/clients/{rm_id}/authz/resource-server/policy",
            h,
            params={"name": POLICY_NAME},
        ).json()
        policy_id = existing[0]["id"]
        print(f"  client policy (exists) id = {policy_id}")
    else:
        create_resp.raise_for_status()
        policy_id = create_resp.json()["id"]
        print(f"  client policy (new)    id = {policy_id}")

    # ── Step 4: attach the policy to the token-exchange scope permission ──────
    # GET the current permission body so we can patch only the policies list
    perm = _get(
        f"{base}/clients/{rm_id}/authz/resource-server/permission/scope/{tx_perm_id}",
        h,
    ).json()

    existing_policies: list[str] = perm.get("policies") or []
    if policy_id not in existing_policies:
        perm["policies"] = existing_policies + [policy_id]
        _put(
            f"{base}/clients/{rm_id}/authz/resource-server/permission/scope/{tx_perm_id}",
            h,
            json=perm,
        )
        print("✓ Policy attached to token-exchange permission")
    else:
        print("  policy already attached — nothing to do")


# ── spiffe-service client ──────────────────────────────────────────────────────

def ensure_spiffe_service_client(token: str) -> None:
    """
    Ensure the spiffe-service Keycloak client exists with the correct config.

    Keycloak's --import-realm only fires when the realm is first created, so
    clients added to realm-export.json after the initial import are not picked
    up on subsequent runs. This function is idempotent: it creates the client
    when missing and assigns user-role to its service account.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    existing = httpx.get(
        f"{base}/clients", headers=h, params={"clientId": "spiffe-service"}, timeout=10
    ).json()

    if existing:
        client_id = existing[0]["id"]
        print(f"  spiffe-service client  id = {client_id} (already exists)")
    else:
        r = httpx.post(
            f"{base}/clients",
            headers=h,
            json={
                "clientId":               "spiffe-service",
                "secret":                 "spiffe-service-secret",
                "enabled":                True,
                "serviceAccountsEnabled": True,
                "standardFlowEnabled":    False,
                "directAccessGrantsEnabled": False,
                "publicClient":           False,
                "protocol":               "openid-connect",
                "defaultClientScopes":    ["web-origins", "acr", "profile", "roles", "email"],
            },
            timeout=10,
        )
        r.raise_for_status()
        location = r.headers.get("Location", "")
        client_id = location.rstrip("/").split("/")[-1]
        print(f"  spiffe-service client  id = {client_id} (created)")

    # Ensure service account has user-role
    sa_user = httpx.get(
        f"{base}/clients/{client_id}/service-account-user", headers=h, timeout=10
    ).json()
    sa_user_id = sa_user["id"]

    realm_roles = httpx.get(f"{base}/roles", headers=h, timeout=10).json()
    user_role   = next((r for r in realm_roles if r["name"] == "user-role"), None)
    if not user_role:
        print("  user-role not found in realm — skipping assignment")
        return

    assigned = httpx.get(
        f"{base}/users/{sa_user_id}/role-mappings/realm", headers=h, timeout=10
    ).json()
    if any(r["name"] == "user-role" for r in assigned):
        print("  user-role already assigned to spiffe-service service account")
    else:
        r = httpx.post(
            f"{base}/users/{sa_user_id}/role-mappings/realm",
            headers=h,
            json=[user_role],
            timeout=10,
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
