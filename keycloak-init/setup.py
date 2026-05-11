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
    """Wait until /health/ready returns 200."""
    print(f"Waiting for Keycloak at {KC_URL} …")
    for attempt in range(60):
        try:
            r = httpx.get(f"{KC_URL}/health/ready", timeout=5)
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


# ── entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    wait_for_keycloak()
    wait_for_realm_import()
    token = get_admin_token()
    setup_token_exchange(token)
    print("\n✓ Token exchange setup complete — OBO is ready!")


if __name__ == "__main__":
    main()
