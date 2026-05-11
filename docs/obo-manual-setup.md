# Activating On-Behalf-Of (OBO) Token Exchange — Manual Setup Guide

This document covers every manual step required to make the RFC 8693 On-Behalf-Of demo work
in this environment. These steps are normally handled automatically by the `keycloak-init`
container at startup, but are documented here for learning purposes or in case the init
container fails.

---

## Prerequisites

- The Docker stack is running (`docker compose up --build`)
- Keycloak is accessible at http://localhost:8080
- `KC_FEATURES=preview` is present in `docker-compose.yml` under the `keycloak` service
  (it already is — this enables RFC 8693 token exchange)

---

## Why manual steps are needed

The `realm-export.json` file controls what Keycloak imports at first startup: clients, users,
roles, and basic client configuration. However, two things **cannot** be expressed there:

1. **Fine-grained authorization policies** — Keycloak's token exchange permission system
   lives inside the `realm-management` client's authorization server and is not part of the
   realm export schema.
2. **Audience mappers defined after import** — these can be included in the export but
   require a full restart cycle to take effect if added manually.

Both must be configured via the Admin Console or Admin REST API after the realm is imported.

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

## Step 2 — Enable fine-grained permissions on demo-client

This tells Keycloak to create the authorization resources and scope permissions required
to control who can exchange tokens originally issued to `demo-client`.

1. Go to **Clients** in the left sidebar.
2. Click on **demo-client**.
3. Open the **Permissions** tab (last tab in the row).
4. Toggle **"Permissions enabled"** to **ON**.
5. Keycloak now shows a list of scope permissions:
   `view`, `manage`, `configure`, `map-roles`, `token-exchange`, …

> Do **not** change any other toggle on this page.

---

## Step 3 — Open the token-exchange permission

Still on the Permissions tab of `demo-client`:

1. Click the **token-exchange** link in the permissions list.
   This opens the permission editor inside the `realm-management` authorization server.
2. You will see:
   - **Type**: `scope`
   - **Resources**: `client.resource.{uuid}` (pre-filled — do not change)
   - **Scopes**: `token-exchange` (pre-filled — do not change)
   - **Apply to resource type**: leave **OFF**
   - **Policies**: empty for now

---

## Step 4 — Create a Client policy for middle-tier-client

A **Client policy** grants access based on which OAuth2 client is authenticating to the
token endpoint. Here the actor is `middle-tier-client`, which presents its
`client_id` + `client_secret` when calling the exchange endpoint.

1. In the permission editor, click **"Create policy"** → choose **Client**.
2. Fill in:

   | Field              | Value                                    |
   |--------------------|------------------------------------------|
   | Name               | `allow-middle-tier-token-exchange`       |
   | Description        | *(optional, for documentation)*          |
   | Clients            | `middle-tier-client`                     |
   | Logic              | Positive                                 |
   | Decision strategy  | Unanimous                                |

3. Click **Save**.

> **Why Client, not Role?**
> Keycloak evaluates the token exchange permission against the identity of the *requesting
> client* (`middle-tier-client`), not against the roles of the *user* in the subject token.
> A Role policy would check claims on the user's token, which is the wrong identity for
> this check.

---

## Step 5 — Attach the policy to the token-exchange permission

After saving the policy, Keycloak redirects you back to the permission editor.

1. In the **Policies** field, select `allow-middle-tier-token-exchange`.
2. Leave **"Apply to resource type"** toggled **OFF**.
   (Turning it ON would allow `middle-tier-client` to exchange tokens from *any* client
   in the realm — far broader than needed.)
3. Click **Save**.

At this point `middle-tier-client` is *authorized* to request an exchange. However, there
is one more prerequisite: the subject token must contain `middle-tier-client` in its
audience.

---

## Step 6 — Add an Audience mapper to demo-client

When Alice logs in, her access token's `aud` (audience) claim contains only `demo-client`.
Keycloak refuses to exchange a token on behalf of a client that is not in the audience —
this prevents a compromised middle-tier from impersonating users to arbitrary downstream
services.

You need to add a mapper that injects `middle-tier-client` into the `aud` claim of every
access token issued by `demo-client`.

1. Go back to **Clients** → **demo-client**.
2. Open the **Client scopes** tab.
3. In the **Dedicated client scopes** section, click **demo-client-dedicated**.
4. Open the **Mappers** tab.
5. Click **Add mapper** → **By configuration** → choose **Audience**.
6. Fill in:

   | Field                    | Value                  |
   |--------------------------|------------------------|
   | Name                     | `middle-tier-audience` |
   | Included Client Audience | `middle-tier-client`   |
   | Add to ID token          | OFF                    |
   | Add to access token      | ON                     |

7. Click **Save**.

---

## Step 7 — Obtain a fresh token

The audience mapper only affects **newly issued** tokens. Alice's current session token
was minted before the mapper existed, so it still lacks `middle-tier-client` in its `aud`.

1. In the demo app (http://localhost:5000), click **Logout**.
2. Log back in as **alice / alice123** (any grant type works).
3. Navigate to **On-Behalf-Of** under "Advanced Token Exchange".

The exchange should now succeed and return a new token where:
- `sub` still identifies Alice
- `azp` is now `middle-tier-client` (the exchanging client)
- `aud` includes `middle-tier-client`
- `act` records the delegation chain

---

## Summary of what each step does

| Step | What it configures | Why it is needed |
|------|--------------------|------------------|
| 2    | Fine-grained permissions on `demo-client` | Creates the token-exchange authorization resource in Keycloak |
| 3    | Opens the token-exchange permission | Targets the permission to `demo-client` tokens specifically |
| 4    | Client policy for `middle-tier-client` | Defines *who* is allowed to perform the exchange |
| 5    | Attaches policy to permission | Links the "who" rule to the "what" resource |
| 6    | Audience mapper on `demo-client` | Puts `middle-tier-client` in Alice's token `aud` so Keycloak accepts it as a valid subject |
| 7    | Fresh login | Forces a new token that includes the updated audience |

---

## Automation

All of the above is automated by the `keycloak-init` container on every `docker compose up`:

- **Steps 2–5** are handled by `setup_token_exchange()` in `keycloak-init/setup.py`.
- **Step 6** (the audience mapper) is declared in `keycloak/realm-export.json` via
  `protocolMappers` — it is applied during the initial realm import.
- Additional clients are provisioned by `keycloak-init` via dedicated `ensure_*()` functions,
  each idempotent (safe to re-run):
  - `ensure_spiffe_service_client()` — creates `spiffe-service` client, assigns `user-role`
  - `ensure_dpop_client()` — creates `dpop-client` with `dpop.bound.access.tokens: true`
  - `ensure_device_client()` — creates `device-client` with Device Authorization Grant enabled
  - `ensure_pkce_client()` — creates `pkce-client` as a public client with PKCE S256 enforced

The manual steps are only required when:

- The `keycloak-init` container failed — check with `docker compose logs keycloak-init`
- You wiped the Postgres volume and are re-configuring a running stack without rebuilding

To force `keycloak-init` to re-run:

```bash
docker compose up keycloak-init
```
