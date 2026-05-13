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

    for client_id_str in ("middle-tier-client", "demo-client", "ai-agent-delegated"):
        client_list = _get(f"{base}/clients", h, params={"clientId": client_id_str}).json()
        if not client_list:
            # ai-agent-delegated may not exist yet on first run — handled below.
            print(f"  {client_id_str:<25} not found yet, will be created later")
            continue
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


# ── MCP scope + Agentic AI clients ─────────────────────────────────────────────

MCP_AUDIENCE = "mcp-service"   # the resource identifier the MCP server validates

def ensure_mcp_user_role(token: str) -> None:
    """Ensure the mcp-user realm role exists.

    realm-export.json declares this role, but Keycloak only processes the import
    when the realm is first created.  Existing demo installations have a realm
    without the role, so we create it here idempotently.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    roles = _get(f"{base}/roles", h).json()
    if any(r["name"] == "mcp-user" for r in roles):
        print("  mcp-user role already exists")
        return
    r = httpx.post(
        f"{base}/roles",
        headers=h,
        json={
            "name":        "mcp-user",
            "description": "Allowed to call the MCP service tools (Agentic AI demos)",
        },
        timeout=10,
    )
    r.raise_for_status()
    print("  ✓ mcp-user role created")


def ensure_mcp_client_scope(token: str) -> str:
    """
    Create the 'mcp' client scope (if missing) with an audience mapper that adds
    'mcp-service' to the access token's aud claim.

    Returns the scope's internal Keycloak id.

    Why a client scope and not a built-in role?
      The MCP server checks BOTH the audience and a scope claim ("mcp"). A client
      scope is the standard way to model both in Keycloak — including the scope name
      in the access token's `scope` claim AND running protocol mappers attached to
      that scope (here: the audience mapper).
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    existing = _get(f"{base}/client-scopes", h).json()
    scope = next((s for s in existing if s["name"] == "mcp"), None)

    if scope:
        scope_id = scope["id"]
        print(f"  mcp client scope        id = {scope_id} (already exists)")
    else:
        r = httpx.post(
            f"{base}/client-scopes",
            headers=h,
            json={
                "name":        "mcp",
                "description": "Grant access to the MCP service (Agentic AI demos)",
                "protocol":    "openid-connect",
                "attributes": {
                    # Make the scope appear in the `scope` claim so MCP can verify it.
                    "include.in.token.scope":   "true",
                    "display.on.consent.screen": "false",
                },
            },
            timeout=10,
        )
        r.raise_for_status()
        scope_id = r.headers["Location"].rstrip("/").split("/")[-1]
        print(f"  mcp client scope        id = {scope_id} (created)")

    # Ensure the audience mapper exists on the mcp scope.
    mappers = _get(f"{base}/client-scopes/{scope_id}/protocol-mappers/models", h).json()
    if not any(m["name"] == "mcp-audience" for m in mappers):
        r = httpx.post(
            f"{base}/client-scopes/{scope_id}/protocol-mappers/models",
            headers=h,
            json={
                "name":           "mcp-audience",
                "protocol":       "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    # included.custom.audience adds a literal string to aud (vs.
                    # included.client.audience which references another KC client).
                    "included.custom.audience": MCP_AUDIENCE,
                    "id.token.claim":           "false",
                    "access.token.claim":       "true",
                },
            },
            timeout=10,
        )
        r.raise_for_status()
        print(f"  ✓ mcp-audience mapper attached (aud += '{MCP_AUDIENCE}')")
    else:
        print("  mcp-audience mapper already attached")

    return scope_id


def ensure_mcp_scope_on_client(token: str, client_id_str: str, mcp_scope_id: str) -> None:
    """Attach the mcp scope to the given client as an OPTIONAL client scope.

    Optional (not default) means the agent must request `scope=mcp` explicitly when
    obtaining a token — matching the principle of least privilege and making the
    audience binding visible in code.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    client_list = _get(f"{base}/clients", h, params={"clientId": client_id_str}).json()
    if not client_list:
        print(f"  ⚠ {client_id_str} not found — skipping mcp scope assignment")
        return
    cid = client_list[0]["id"]

    optional = _get(f"{base}/clients/{cid}/optional-client-scopes", h).json()
    if any(s["id"] == mcp_scope_id for s in optional):
        print(f"  mcp scope already assigned to {client_id_str}")
        return

    r = httpx.put(
        f"{base}/clients/{cid}/optional-client-scopes/{mcp_scope_id}",
        headers=h, timeout=10,
    )
    r.raise_for_status()
    print(f"  ✓ mcp scope assigned (optional) to {client_id_str}")


def ensure_mcp_role_on_service_account(token: str, client_id_str: str) -> None:
    """Ensure the mcp-user realm role is assigned to a client's service account.

    This is the AUTHORIZATION half of the MCP demo (the audience mapper is the
    AUDIENCE half).  Without the role the token validates fine but the MCP server
    will refuse the call.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    client_list = _get(f"{base}/clients", h, params={"clientId": client_id_str}).json()
    if not client_list:
        return
    cid = client_list[0]["id"]

    sa_user_id = _get(f"{base}/clients/{cid}/service-account-user", h).json()["id"]

    roles = _get(f"{base}/roles", h).json()
    role  = next((r for r in roles if r["name"] == "mcp-user"), None)
    if not role:
        print("  ⚠ mcp-user role not found — realm-export.json may be stale")
        return

    assigned = _get(f"{base}/users/{sa_user_id}/role-mappings/realm", h).json()
    if any(r["name"] == "mcp-user" for r in assigned):
        print(f"  mcp-user role already on {client_id_str} service account")
        return
    r = httpx.post(
        f"{base}/users/{sa_user_id}/role-mappings/realm",
        headers=h, json=[role], timeout=10,
    )
    r.raise_for_status()
    print(f"  ✓ mcp-user role assigned to {client_id_str} service account")


AGENT_SPIFFE_JWKS_URL = "http://agent-spiffe:9002/jwks"

def ensure_ai_agent_spiffe_client(token: str) -> None:
    """Ensure the ai-agent-spiffe Keycloak client exists with private_key_jwt auth.

    Same pattern as spiffe-service: clientAuthenticatorType=client-jwt, jwks_url
    pointing at the agent container.  No client_secret.  The agent's in-memory
    EC key signs the client_assertion and Keycloak fetches the public half from
    the agent's /jwks endpoint to verify.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    existing = _get(f"{base}/clients", h, params={"clientId": "ai-agent-spiffe"}).json()
    if existing:
        client    = existing[0]
        client_id = client["id"]
        attrs     = client.get("attributes") or {}
        # Idempotent migration: ensure auth type and JWKS URL are correct in case
        # the client was created by an older version of this script.
        if (client.get("clientAuthenticatorType") != "client-jwt"
                or attrs.get("jwks.url") != AGENT_SPIFFE_JWKS_URL):
            client["clientAuthenticatorType"] = "client-jwt"
            attrs["use.jwks.url"] = "true"
            attrs["jwks.url"]     = AGENT_SPIFFE_JWKS_URL
            client["attributes"]  = attrs
            _put(f"{base}/clients/{client_id}", h, json=client)
            print(f"  ai-agent-spiffe client   id = {client_id} (migrated to private_key_jwt)")
        else:
            print(f"  ai-agent-spiffe client   id = {client_id} (already exists)")
        return

    r = httpx.post(
        f"{base}/clients",
        headers=h,
        json={
            "clientId":                  "ai-agent-spiffe",
            "enabled":                   True,
            "publicClient":              False,
            "clientAuthenticatorType":   "client-jwt",
            "serviceAccountsEnabled":    True,
            "standardFlowEnabled":       False,
            "directAccessGrantsEnabled": False,
            "protocol":                  "openid-connect",
            "defaultClientScopes":       ["web-origins", "acr", "profile", "email"],
            "optionalClientScopes":      ["roles"],
            "attributes": {
                "use.jwks.url": "true",
                "jwks.url":     AGENT_SPIFFE_JWKS_URL,
            },
        },
        timeout=10,
    )
    r.raise_for_status()
    cid = r.headers["Location"].rstrip("/").split("/")[-1]
    print(f"  ai-agent-spiffe client   id = {cid} (created with private_key_jwt)")


AGENT_CERT_JWKS_URL = "http://agent-cert:9003/jwks"

def ensure_ai_agent_cert_client(token: str) -> None:
    """Ensure the ai-agent-cert client exists with private_key_jwt + cert-backed JWK.

    The key behind the JWK is itself backed by an X.509 cert (cert-init generated
    the cert + private key onto a shared volume; the agent loads them at startup).
    From Keycloak's point of view this is identical to the SPIFFE agent — both
    use clientAuthenticatorType=client-jwt with jwks_url.  The interesting
    difference (cert chain in /jwks via x5c, long-lived key, distinct identity)
    lives entirely in the agent.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    existing = _get(f"{base}/clients", h, params={"clientId": "ai-agent-cert"}).json()
    if existing:
        client    = existing[0]
        client_id = client["id"]
        attrs     = client.get("attributes") or {}
        if (client.get("clientAuthenticatorType") != "client-jwt"
                or attrs.get("jwks.url") != AGENT_CERT_JWKS_URL):
            client["clientAuthenticatorType"] = "client-jwt"
            attrs["use.jwks.url"] = "true"
            attrs["jwks.url"]     = AGENT_CERT_JWKS_URL
            client["attributes"]  = attrs
            _put(f"{base}/clients/{client_id}", h, json=client)
            print(f"  ai-agent-cert client     id = {client_id} (migrated to private_key_jwt)")
        else:
            print(f"  ai-agent-cert client     id = {client_id} (already exists)")
        return

    r = httpx.post(
        f"{base}/clients",
        headers=h,
        json={
            "clientId":                  "ai-agent-cert",
            "enabled":                   True,
            "publicClient":              False,
            "clientAuthenticatorType":   "client-jwt",
            "serviceAccountsEnabled":    True,
            "standardFlowEnabled":       False,
            "directAccessGrantsEnabled": False,
            "protocol":                  "openid-connect",
            "defaultClientScopes":       ["web-origins", "acr", "profile", "email"],
            "optionalClientScopes":      ["roles"],
            "attributes": {
                "use.jwks.url": "true",
                "jwks.url":     AGENT_CERT_JWKS_URL,
            },
        },
        timeout=10,
    )
    r.raise_for_status()
    cid = r.headers["Location"].rstrip("/").split("/")[-1]
    print(f"  ai-agent-cert client     id = {cid} (created with private_key_jwt)")


def ensure_ai_agent_delegated_client(token: str) -> None:
    """Ensure the ai-agent-delegated client exists (UC4 — user-delegated agent).

    Confidential client used by the agent to perform RFC 8693 token exchange on
    behalf of an authenticated user.  Standard token exchange must be enabled on
    this client; the resulting tokens carry the user's `sub` and an `act` claim
    naming this client as the actor.

    Idempotent: creates the client if missing, otherwise leaves it alone.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    existing = _get(f"{base}/clients", h, params={"clientId": "ai-agent-delegated"}).json()
    if existing:
        print(f"  ai-agent-delegated client id = {existing[0]['id']} (already exists)")
        return

    r = httpx.post(
        f"{base}/clients",
        headers=h,
        json={
            "clientId":                  "ai-agent-delegated",
            "secret":                    "ai-agent-delegated-secret",
            "enabled":                   True,
            "serviceAccountsEnabled":    True,
            "standardFlowEnabled":       False,
            "directAccessGrantsEnabled": False,
            "publicClient":              False,
            "protocol":                  "openid-connect",
            "defaultClientScopes":       ["web-origins", "acr", "profile", "email"],
            "optionalClientScopes":      ["roles"],
            "attributes": {
                # Required for RFC 8693 token exchange on KC 26.2+.
                "standard.token.exchange.enabled": "true",
            },
        },
        timeout=10,
    )
    r.raise_for_status()
    cid = r.headers["Location"].rstrip("/").split("/")[-1]
    print(f"  ai-agent-delegated client id = {cid} (created)")


def ensure_delegated_audience_mapper_on_demo_client(token: str) -> None:
    """Ensure demo-client's user tokens include ai-agent-delegated in their aud claim.

    OBO exchange requires the exchanging client (ai-agent-delegated) to appear in
    the subject_token's audience.  We add a second audience mapper on demo-client
    alongside the existing middle-tier-audience mapper.

    Idempotent: skips if the mapper already exists.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    demo_clients = _get(f"{base}/clients", h, params={"clientId": "demo-client"}).json()
    if not demo_clients:
        print("  ⚠ demo-client not found — cannot attach audience mapper")
        return
    demo_id = demo_clients[0]["id"]

    mappers = _get(f"{base}/clients/{demo_id}/protocol-mappers/models", h).json()
    if any(m["name"] == "delegated-agent-audience" for m in mappers):
        print("  delegated-agent-audience mapper already attached to demo-client")
        return

    r = httpx.post(
        f"{base}/clients/{demo_id}/protocol-mappers/models",
        headers=h,
        json={
            "name":           "delegated-agent-audience",
            "protocol":       "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.client.audience": "ai-agent-delegated",
                "id.token.claim":           "false",
                "access.token.claim":       "true",
            },
        },
        timeout=10,
    )
    r.raise_for_status()
    print("  ✓ delegated-agent-audience mapper attached to demo-client")


def ensure_ai_agent_secret_client(token: str) -> None:
    """Ensure the ai-agent-secret client exists.

    realm-export.json already declares this client when the realm is freshly
    imported.  This function is a safety net for the case where the realm was
    created before the Agentic AI section existed.
    """
    h    = {"Authorization": f"Bearer {token}"}
    base = f"{KC_URL}/admin/realms/{REALM}"

    existing = _get(f"{base}/clients", h, params={"clientId": "ai-agent-secret"}).json()
    if existing:
        print(f"  ai-agent-secret client  id = {existing[0]['id']} (already exists)")
        return

    r = httpx.post(
        f"{base}/clients",
        headers=h,
        json={
            "clientId":                  "ai-agent-secret",
            "secret":                    "ai-agent-secret-secret",
            "enabled":                   True,
            "serviceAccountsEnabled":    True,
            "standardFlowEnabled":       False,
            "directAccessGrantsEnabled": False,
            "publicClient":              False,
            "protocol":                  "openid-connect",
            "defaultClientScopes":       ["web-origins", "acr", "profile", "email"],
            "optionalClientScopes":      ["roles"],
        },
        timeout=10,
    )
    r.raise_for_status()
    cid = r.headers["Location"].rstrip("/").split("/")[-1]
    print(f"  ai-agent-secret client  id = {cid} (created)")


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

    # ── Agentic AI setup ──────────────────────────────────────────────────────
    # The mcp scope + audience mapper + role assignments are required by the MCP
    # service.  These steps are idempotent so they are safe to re-run.
    token = get_admin_token()
    ensure_mcp_user_role(token)
    ensure_ai_agent_secret_client(token)
    ensure_ai_agent_spiffe_client(token)
    ensure_ai_agent_cert_client(token)
    ensure_ai_agent_delegated_client(token)
    ensure_delegated_audience_mapper_on_demo_client(token)
    # standard.token.exchange.enabled was set above for the existing clients;
    # the newly-created ai-agent-delegated client needs it too.  Re-run the
    # idempotent loop to pick it up.
    setup_token_exchange(token)
    mcp_scope_id = ensure_mcp_client_scope(token)
    # UC1/UC2/UC3a — service-principal agents.  Need both the scope (so the agent
    # can request scope=mcp) and the mcp-user role on the service account.
    for client_id_str in ("ai-agent-secret", "ai-agent-spiffe", "ai-agent-cert"):
        ensure_mcp_scope_on_client(token, client_id_str, mcp_scope_id)
        ensure_mcp_role_on_service_account(token, client_id_str)
    # UC4 — user-delegated agent.  Need the scope so the exchange can request
    # scope=mcp, but NO role on the service account: the resulting token's
    # identity is the user (sub=alice), not the agent's service account.
    ensure_mcp_scope_on_client(token, "ai-agent-delegated", mcp_scope_id)
    print("\n✓ Agentic AI (UC1 + UC2 + UC3a + UC4) setup complete — all four agents can access MCP!")


if __name__ == "__main__":
    main()
