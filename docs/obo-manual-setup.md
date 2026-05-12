# Activating On-Behalf-Of (OBO) Token Exchange — Manual Setup Guide

This document covers every manual step required to make the RFC 8693 On-Behalf-Of demo work
in this environment. These steps are normally handled automatically by the `keycloak-init`
container at startup, but are documented here for learning purposes or in case the init
container fails.

---

## Prerequisites

- The Docker stack is running (`docker compose up --build`)
- Keycloak is accessible at http://localhost:8080
- Keycloak version **26.2 or later** (Standard Token Exchange is GA — no feature flags needed)

---

## How Standard Token Exchange works in KC 26.2+

In Keycloak 26.2+, Standard Token Exchange is a GA feature enabled by a single client
attribute. No fine-grained authorization policies or realm-management permissions are needed:

- Set `standard.token.exchange.enabled = true` on the **requesting** client (`middle-tier-client`)
- That's it — `middle-tier-client` can now perform exchanges against any token issued to any
  client in the realm, as long as `middle-tier-client` is listed in the subject token's `aud`
  claim.

---

## Step 1 — Log in to the Admin Console

Open http://localhost:8080/admin and sign in with:

| Field    | Value   |
|----------|---------|
| Username | `admin` |
| Password | `admin` |

Select the **demo** realm from the realm selector in the top-left corner if it is not
already selected.

---

## Step 2 — Enable Standard Token Exchange on middle-tier-client

1. Go to **Clients** in the left sidebar.
2. Click on **middle-tier-client**.
3. Open the **Advanced** tab.
4. Scroll down to **Additional settings**.
5. Find **Standard Token Exchange Enabled** and set it to **On**.
6. Click **Save**.

That is the only change needed. `middle-tier-client` can now exchange tokens on behalf of
users, subject to the audience constraint below.

---

## Step 3 — Verify the Audience mapper on demo-client

For the exchange to succeed, the subject token (Alice's token) must include
`middle-tier-client` in its `aud` (audience) claim. This is controlled by an audience
mapper on `demo-client` that is already declared in `realm-export.json`.

To verify it is in place:

1. Go to **Clients** → **demo-client**.
2. Open the **Client scopes** tab.
3. In the **Dedicated client scopes** section, click **demo-client-dedicated**.
4. Open the **Mappers** tab.
5. Confirm there is a mapper named `middle-tier-audience` of type **Audience** with
   **Included Client Audience** = `middle-tier-client`.

If it is missing (e.g., the realm was imported from an older export), add it:

1. Click **Add mapper** → **By configuration** → choose **Audience**.
2. Fill in:

   | Field                    | Value                  |
   |--------------------------|------------------------|
   | Name                     | `middle-tier-audience` |
   | Included Client Audience | `middle-tier-client`   |
   | Add to ID token          | OFF                    |
   | Add to access token      | ON                     |

3. Click **Save**.

---

## Step 4 — Obtain a fresh token

The audience mapper only affects **newly issued** tokens. Alice's current session token
was minted before the mapper existed, so it may still lack `middle-tier-client` in its `aud`.

1. In the demo app (http://localhost:5000), click **Logout**.
2. Log back in as **alice / alice123** (any grant type works).
3. Navigate to **On-Behalf-Of** under "Advanced Token Exchange".

The exchange should now succeed and return a new token where:
- `sub` still identifies Alice
- `azp` is now `middle-tier-client` (the exchanging client)
- `act` records the delegation chain

---

## Summary

| Step | What it configures | Why it is needed |
|------|-------------------|------------------|
| 2    | `standard.token.exchange.enabled = true` on `middle-tier-client` | Authorises this client to perform RFC 8693 exchanges (KC 26.2+ mechanism) |
| 3    | Audience mapper on `demo-client` | Puts `middle-tier-client` in Alice's token `aud` so Keycloak accepts it as a valid subject |
| 4    | Fresh login | Forces a new token that includes the updated audience |

---

## Automation

All of the above is automated by the `keycloak-init` container on every `docker compose up`:

- **Step 2** is handled by `setup_token_exchange()` in `keycloak-init/setup.py`, which sets
  the `standard.token.exchange.enabled` attribute on `middle-tier-client` via the Admin API.
- **Step 3** (the audience mapper) is declared in `keycloak/realm-export.json` via
  `protocolMappers` — it is applied during the initial realm import.
- Additional clients are provisioned by `keycloak-init` via dedicated `ensure_*()` functions,
  each idempotent (safe to re-run):
  - `ensure_spiffe_service_client()` — creates/migrates `spiffe-service` to `client-jwt` auth
    (RFC 7523 private_key_jwt), assigns `user-role` to its service account
  - `ensure_dpop_client()` — creates `dpop-client` with `dpop.bound.access.tokens: true`
  - `ensure_device_client()` — creates `device-client` with Device Authorization Grant enabled
  - `ensure_pkce_client()` — creates `pkce-client` as a public client with PKCE S256 enforced

The manual steps are only required when:

- The `keycloak-init` container failed — check with `docker compose logs keycloak-init`
- You wiped the Postgres volume and are re-configuring a running stack without rebuilding

To force `keycloak-init` to re-run:

```bash
docker compose run --rm keycloak-init
```
