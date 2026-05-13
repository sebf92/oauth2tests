# Keycloak as Idp and OAuthz server

The diagram below shows how Keycloak can act as both an Idp and an Authorization server to issue tokens to the application.

At a glance:

1. The user navigates to the application and requests a protected resource while not yet authenticated.
2. The application detects that there is no valid session or access token and redirects the user’s browser to Keycloak’s authorization endpoint, passing its client ID, redirect URI, requested scopes, state, and nonce.
3. Keycloak presents its login page to the user and, if configured, any MFA challenges, then validates the submitted credentials and completes its authentication flow.
4. Once authentication succeeds, Keycloak creates an SSO session for the user and redirects the browser back to the application’s redirect URI with an authorization code and the original state value.
5. The application receives the authorization code and sends a back‑channel request to Keycloak’s token endpoint, including the code, redirect URI, client credentials, and grant type set to authorization_code.
6. Keycloak validates the client, the authorization code, and the redirect URI, then issues an access token, an ID token, and optionally a refresh token, all signed by Keycloak.
7. The application stores the tokens and calls the protected API, sending the access token in the Authorization header as a Bearer token.
8. The API validates the access token using Keycloak’s public keys and checks claims such as issuer, audience, expiry, scopes, and roles before returning the protected resource to the application.
9. Finally, the application returns the requested content to the user, who is now authenticated by Keycloak and authorized via the Keycloak-issued access token.


```mermaid
sequenceDiagram
    autonumber
    actor User
    participant App as Application (OIDC Client)
    participant KC as Keycloak (IdP & OAuth2 AS)
    participant API as API / Resource Server

    %% 1. User hits the app
    User ->> App: Access protected resource (no session)

    %% 2. App redirects to Keycloak
    App ->> KC: Redirect to KC /auth<br/>client_id, redirect_uri, scope, state, nonce

    %% 3. Keycloak authenticates user
    KC ->> User: Show login page (username/password, MFA)
    User ->> KC: Submit credentials / MFA
    KC ->> KC: Validate credentials, execute auth flow
    KC ->> KC: Create SSO session for user

    %% 4. KC returns authorization code to app
    KC ->> User: Redirect to app redirect_uri<br/>code, state
    User ->> App: Return with KC code, state

    %% 5. App exchanges code for tokens
    App ->> KC: Token request<br/>grant_type=authorization_code,<br/>code, redirect_uri, client_id, client_secret
    KC ->> KC: Validate client, code, redirect_uri
    KC -->> App: Access token, ID token,<br/>optional refresh token (all from KC)

    %% 6. App calls API with KC token
    App ->> API: Request with Authorization: Bearer <KC access_token>

    %% 7. API validates Keycloak token
    API ->> KC: Fetch/refresh JWKS (public keys) if needed
    API ->> API: Validate token (sig, iss, aud, exp, scopes/roles)
    API -->> App: Protected resource
    App -->> User: Response with protected content
```

# Keycloak brokering to Ping

This diagram shows how Keycloak delegates login to Ping and then issues its own tokens to the application.

At a glance:

1. The user accesses a protected resource in the application without an existing session or token, triggering an OpenID Connect authorization request to Keycloak.
2. The application redirects the browser to Keycloak’s authorization endpoint, asking Keycloak to authenticate the user and later issue tokens back to the application.
3. Keycloak detects that the user is not yet authenticated locally and, based on its identity brokering configuration, redirects the browser to Ping as the upstream OIDC identity provider.
4. The user authenticates with Ping (including MFA and any risk policies), and Ping sends the browser back to Keycloak with an authorization code representing the successful authentication.
5. Keycloak exchanges this code with Ping over a back‑channel, validates the returned tokens, maps Ping attributes to a local user (creating or linking as needed), and establishes a Keycloak SSO session.
6. Keycloak then completes the outer OIDC flow by redirecting the browser back to the application with a Keycloak authorization code, which the application exchanges for Keycloak‑issued tokens (access, ID, and optional refresh tokens).
7. The application calls APIs using the Keycloak access token, and APIs validate and authorize requests based solely on Keycloak tokens, remaining unaware of Ping’s involvement.

### Actors

- User (Browser)
- Application (OIDC client of Keycloak)
- Keycloak (Identity Broker, OIDC Provider for the app, OIDC client of Ping)
- Ping (PingFederate or PingOne, OIDC Identity Provider)
- API / Resource Server (validates Keycloak tokens)


```mermaid
sequenceDiagram
    autonumber
    actor User
    participant App as Application
    participant KC as Keycloak (Broker & AS)
    participant Ping as Ping (OIDC IdP)
    participant API as API / Resource

    User ->> App: Access protected resource (no session)
    App ->> KC: Redirect to KC /authorize

    KC ->> KC: Check existing SSO session

    alt No KC session
        KC ->> User: Show login / IdP selection page
        User ->> KC: Select Login with Ping
    else KC session exists
        KC ->> KC: Skip login
    end

    KC ->> Ping: Redirect OIDC /authorize
    User ->> Ping: Follow redirect
    Ping ->> User: Login + MFA
    User ->> Ping: Submit credentials / MFA

    Ping ->> User: Redirect to KC broker URL with code
    User ->> KC: Hit broker endpoint

    KC ->> KC: Validate state
    KC ->> Ping: Token request
    Ping -->> KC: ID token (+ optional AT/RT)

    KC ->> KC: Verify token, map claims, create/link user
    KC ->> KC: Create KC SSO session

    KC ->> User: Redirect to app with KC code
    User ->> App: Return with code

    App ->> KC: Exchange code for tokens
    KC -->> App: KC access token, ID token, refresh token

    App ->> API: Call API with KC access token
    API ->> KC: Fetch/check JWKS
    API ->> API: Validate token
    API -->> App: Protected resource
    App -->> User: Response
```

***

### Detailed Sequence

1. **User → Application**
    - Request: Accesses a protected URL at the application (no session or token yet).
2. **Application → Keycloak**
    - Redirect: OIDC Authorization Request (Authorization Code flow)
    - Includes: `client_id` (app), `redirect_uri` (back to app), `response_type=code`, `scope=openid ...`, `state`, `nonce`.
    - Goal: Ask Keycloak to authenticate the user and issue tokens.[^3][^1]
3. **Keycloak (internal)**
    - Check: Is there an active SSO session for this user in the realm?
    - If no session, start login flow.
4. **Keycloak → User (Browser)**
    - Option A: Show Keycloak login page with list of identity providers (including Ping).
    - Option B: If realm/client is configured with a default IdP or `kc_idp_hint=ping-oidc`, skip the list and auto‑select Ping.[^4][^1]
5. **User → Keycloak**
    - Action: User clicks “Login with Ping” (or equivalent) or Keycloak auto‑selects Ping.
6. **Keycloak → Ping**
    - Redirect: OIDC Authorization Request to Ping’s authorize endpoint.
    - Keycloak acts as an OIDC client of Ping.
    - Includes:
        - `client_id` (for Keycloak in Ping)
        - `redirect_uri` (Keycloak broker endpoint)
        - `response_type=code`
        - `scope=openid profile email ...`
        - `state`, `nonce`.[^2][^5]
7. **User (Browser) → Ping**
    - Request: Browser follows redirect, reaches Ping login experience.
8. **Ping ↔ User**
    - Flow: Ping displays its login and MFA screens and executes its policies (password, OTP, push, risk, etc.).
    - Result: User successfully authenticates with Ping.[^5]
9. **Ping → User (Browser)**
    - Redirect: Back to Keycloak’s broker redirect URI with:
        - `code` (Ping authorization code)
        - `state` (for CSRF correlation).
10. **User (Browser) → Keycloak**
    - Request: Hits Keycloak’s broker endpoint with `code` and `state`.
11. **Keycloak (internal) → Keycloak (internal)**
    - Validate:
        - `state` matches what was originally sent to Ping.
        - The response is tied to the expected IdP session.[^1]
12. **Keycloak → Ping (back‑channel)**
    - HTTP POST: Token request to Ping’s token endpoint.
    - Parameters:
        - `grant_type=authorization_code`
        - `code` (from Ping)
        - `redirect_uri` (Keycloak broker endpoint)
        - Client authentication: client secret or other method configured in Ping.[^2][^5]
13. **Ping → Keycloak**
    - Response: OIDC token set
        - `id_token` (with `sub`, `email`, `name`, groups, etc.)
        - Optionally `access_token`, `refresh_token` for Ping usage.
14. **Keycloak (internal)**
    - Verify Ping ID token signature and claims (issuer, audience, nonce, etc.).
    - Optionally call Ping’s UserInfo endpoint for extra claims, depending on IdP config.[^1][^2]
15. **Keycloak (internal) – user provisioning / linking**
    - Apply identity provider mappers:
        - Import or map attributes: `sub` → Keycloak `username`, `email` → `email`, groups → Keycloak roles/groups, etc.[^6][^2]
    - Check if a Keycloak user is already linked to this Ping identity.
        - If yes: load that user.
        - If no: create a new user and link to the Ping IdP entry (first‑login flow, optional consent/profile update).[^7][^1]
    - Create/refresh a **Keycloak SSO session** for this user.
16. **Keycloak (internal) → User (Browser)**
    - Now that Keycloak trusts Ping’s auth, Keycloak completes the **outer** login.
    - It issues its own authentication for the realm (auth cookie/session).
17. **Keycloak → User (Browser) → Application**
    - Redirect: Back to the application’s redirect URI with a **Keycloak authorization code** (for the app client).
    - Parameters: `code` (Keycloak), `state`.
18. **Application → Keycloak (back‑channel)**
    - HTTP POST: Token request to Keycloak’s token endpoint.
    - Parameters:
        - `grant_type=authorization_code`
        - `code` (Keycloak code)
        - `redirect_uri` (app redirect URI)
        - Client authentication: app client ID/secret or other method.[^3][^1]
19. **Keycloak → Application**
    - Response: OIDC token set for the app
        - **Access token** (JWT, issuer = Keycloak)
        - **ID token** (JWT, issuer = Keycloak)
        - Optional **refresh token**.[^3][^1]
20. **Application → API / Resource Server**
    - HTTP request with `Authorization: Bearer <Keycloak_access_token>`.
21. **API / Resource Server → Keycloak (JWKS)**
    - Retrieve or cache Keycloak’s public keys (JWKS).
    - Validate the access token signature, audience, issuer, expiry, etc.[^3]
22. **API / Resource Server (internal)**
    - Authorization: Enforce access based on roles/groups/scopes contained in the Keycloak token (which ultimately derive from Ping attributes, via Keycloak mapping).[^8][^2]
23. **API → Application → User**
    - Return the protected resource, user is now logged in end‑to‑end via Ping → Keycloak → App → API.

***

### Logout (high‑level sequence)

A matching logout flow often looks like:

1. User → Application: clicks “Logout”.
2. Application → Keycloak: redirect or back‑channel to Keycloak end‑session endpoint.
3. Keycloak:
    - Terminates its SSO session.
    - Optionally calls Ping’s logout (front‑channel/back‑channel) if configured for Single Logout.[^9][^2]
4. Keycloak → User → Application: redirect back to post‑logout URL.
5. User is logged out of app, Keycloak, and optionally Ping (depending on SLO config).

***