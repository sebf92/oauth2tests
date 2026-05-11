# SPIFFE / SPIRE + OAuth2 Integration

## Table of Contents

1. [What is SPIFFE?](#what-is-spiffe)
2. [Core Concepts](#core-concepts)
3. [SPIRE Architecture](#spire-architecture)
4. [JWT-SVID in Detail](#jwt-svid-in-detail)
5. [The SPIFFE→OAuth2 Bridge Pattern](#the-spiffeoauth2-bridge-pattern)
6. [How This Demo Is Wired](#how-this-demo-is-wired)
7. [Step-by-Step Flow](#step-by-step-flow)
8. [Future Path: RFC 7523 Direct (Keycloak 26.4+)](#future-path-rfc-7523-direct-keycloak-264)
9. [Security Properties](#security-properties)
10. [Comparison: SPIFFE vs Client Credentials](#comparison-spiffe-vs-client-credentials)
11. [Troubleshooting](#troubleshooting)

---

## What is SPIFFE?

**SPIFFE** (Secure Production Identity Framework for Everyone) is an open standard for
assigning and verifying identities to software workloads in dynamic, cloud-native environments.
It solves a fundamental problem: *how does a service prove who it is without a long-lived secret?*

The key insight is to bind identity to the **runtime environment** (the container, the OS process,
the Kubernetes pod) rather than to a credential that can be leaked and reused. Identity becomes
a property of *what the workload is*, not *what it knows*.

**SPIRE** (SPIFFE Runtime Environment) is the reference implementation. It consists of:

- **SPIRE Server** — the certificate authority and registry of workload identities
- **SPIRE Agent** — a node-local daemon that attests workloads and serves the Workload API

---

## Core Concepts

### SPIFFE ID

A SPIFFE ID is a URI with the scheme `spiffe://`:

```
spiffe://<trust-domain>/<workload-path>
```

Example from this demo:

```
spiffe://demo.local/spiffe-service
```

It identifies *what* the workload is, not *where* it runs. The trust domain (`demo.local`) scopes
the identity to a single administrative boundary.

### SVID (SPIFFE Verifiable Identity Document)

An SVID is a cryptographically signed document that carries a SPIFFE ID. There are two formats:

| Format | Use case |
|--------|----------|
| **X.509-SVID** | mTLS between services (long-lived, auto-rotated) |
| **JWT-SVID** | Bearer-token style API calls, OAuth2 integration |

This demo uses **JWT-SVIDs** because they integrate naturally with HTTP Authorization headers
and OAuth2 flows.

### Trust Domain

The trust domain is the root of the SPIFFE identity namespace. All SPIRE servers in a deployment
share a trust domain. Federation between trust domains is possible but out of scope for this demo.

### Workload Attestation

Attestation is the process by which SPIRE verifies that a workload is what it claims to be.
The SPIRE agent uses **workload attestors** to inspect the OS-level properties of a process:

| Attestor | Selector example | Notes |
|----------|-----------------|-------|
| `unix` | `unix:uid:0` | Matches processes by OS UID/GID |
| `docker` | `docker:label:com.docker.compose.service:myapp` | Requires Docker socket access |
| `k8s` | `k8s:ns:default` | Kubernetes pod selector |

This demo uses the **unix attestor** with `unix:uid:0` (root inside the container).

> **PID namespace note:** The unix attestor identifies callers via `SO_PEERCRED` on the
> Workload API socket. When the caller and agent run in separate Docker containers, they have
> separate PID namespaces — the agent cannot find the caller's PID in its own `/proc`. The fix
> is `pid: "service:spire-agent"` on `spiffe-service` in `docker-compose.yml`, which shares
> the agent's PID namespace so both sides see the same process table.

---

## SPIRE Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Docker Compose network (oauth2-net)                              │
│                                                                  │
│  ┌──────────────┐   gRPC :8081   ┌──────────────┐               │
│  │ spire-server │◄───────────────│ spire-agent  │               │
│  │              │                │              │               │
│  │ • CA / signer│   node attest  │ • unix socket│               │
│  │ • registry   │                │   /tmp/spire-│               │
│  │ • join tokens│                │   agent/...  │               │
│  └──────────────┘                └──────┬───────┘               │
│                                         │ Workload API           │
│                                         │ (unix socket)          │
│                                   ┌─────▼──────────┐            │
│                                   │ spiffe-service │            │
│                                   │ (shared PID ns)│            │
│                                   │ 1. fetch SVID  │            │
│                                   │ 2. bridge→KC   │            │
│                                   │ 3. call API    │            │
│                                   └────────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

### Bootstrap Sequence

1. **`spire-server`** starts and listens on gRPC port 8081.
2. **`spire-init`** (one-shot container, Alpine + spire-server binary):
   - Generates a **join token** with agent SPIFFE ID:
     `spiffe://demo.local/agents/demo-agent`
   - Registers the workload entry:
     - SPIFFE ID: `spiffe://demo.local/spiffe-service`
     - Selector: `unix:uid:0`
   - Writes the join token to a shared volume (`/tmp/spire-tokens/join-token`)
3. **`spire-agent`** (Alpine + spire-agent binary) reads the join token and connects to the
   server (node attestation via `join_token` plugin).
4. **`spiffe-service`** starts after the agent is healthy, sharing the agent's PID namespace,
   and connects to the Workload API over the shared unix socket.

---

## JWT-SVID in Detail

When `spiffe-service` calls the SPIRE Workload API, it receives a JWT-SVID like this:

### Header

```json
{
  "alg": "ES256",
  "kid": "<key-id from SPIRE server>",
  "typ": "JWT"
}
```

Note: SPIRE uses **ES256** (ECDSA P-256) for JWT-SVIDs, not RS256. Keycloak uses RS256 for
its own tokens — these are separate key pairs.

### Payload

```json
{
  "sub": "spiffe://demo.local/spiffe-service",
  "aud": ["http://keycloak:8080/realms/demo/protocol/openid-connect/token"],
  "iat": 1700000000,
  "exp": 1700000300
}
```

Key fields:

| Claim | Value | Meaning |
|-------|-------|---------|
| `sub` | `spiffe://demo.local/spiffe-service` | The workload's identity |
| `aud` | Keycloak token URL | The intended recipient (prevents token reuse at other endpoints) |
| `iat` | Unix timestamp | Issued at (by SPIRE) |
| `exp` | `iat + 300` | Expires in ~5 minutes (enforced by SPIRE) |

The **audience** (`aud`) is set to the Keycloak token endpoint URL. This is important: the
JWT-SVID can only be used to talk to Keycloak, not forwarded to any other service.

---

## The SPIFFE→OAuth2 Bridge Pattern

This demo runs on **Keycloak 26.0**, which cannot yet natively validate a JWT-SVID as a
client assertion (that requires Keycloak 26.4+ with the Federated Client Authentication
feature). The bridge pattern works around this:

```
spiffe-service                     Keycloak
      │                                │
      │  1. fetch_jwt_svids()          │
      │◄──── SPIRE (JWT-SVID) ─────────┤
      │                                │
      │  2. validate SPIFFE ID locally │
      │     (check sub, exp, aud)      │
      │                                │
      │  3. POST /token                │
      │     grant_type=client_cred.    │
      │     client_id=spiffe-service   │
      │     client_secret=...          │──► validate secret
      │                                │
      │◄────── access_token ───────────│
      │                                │
      │  4. GET /api/products          │
      │     Authorization: Bearer ...  │
      │────────────────────────────────►
```

The bridge is the mapping table inside `spiffe-service/main.py`:

```python
SPIFFE_CLIENT_MAP: dict[str, tuple[str, str]] = {
    "spiffe://demo.local/spiffe-service": ("spiffe-service", "spiffe-service-secret"),
}
```

**Security model**: The bridge trusts the SPIRE-issued JWT-SVID as proof of identity. Since
SPIRE only issues SVIDs to workloads that pass attestation, and the SVID is short-lived and
audience-restricted, the bridge can safely map the SPIFFE ID to a Keycloak client and obtain
a `client_credentials` token on its behalf.

The Keycloak service account (`service-account-spiffe-service`) has `user-role` and can call
`GET /api/products` and `GET /api/users/me`.

---

## How This Demo Is Wired

### Docker Compose services

| Service | Image / Build | Role |
|---------|--------------|------|
| `spire-server` | `ghcr.io/spiffe/spire-server:1.10.0` (official) | CA, registry, join tokens |
| `spire-init` | `./spire/init` (Alpine + spire-server binary) | One-shot: creates token + workload entry |
| `spire-agent` | `./spire/agent-wrapper` (Alpine + spire-agent binary) | Attestation + Workload API |
| `spiffe-service` | `./spiffe-service` (Python/FastAPI) | Demo workload |

> **Why custom wrapper images?** The official SPIRE images are **scratch-based** (no shell,
> no shared libraries). `spire-init` and `spire-agent` need shell scripts to orchestrate
> startup. The wrapper Dockerfiles copy the statically-compiled SPIRE binary into Alpine,
> which provides `/bin/sh`.

### Shared volumes

| Volume | Mounted in | Purpose |
|--------|-----------|---------|
| `spire-server-socket` | server + init | Server admin socket (gRPC) |
| `spire-agent-socket` | agent + spiffe-service | Workload API socket (unix) |
| `spire-tokens` | init (rw) + agent (ro) | Join token hand-off |

### SPIRE server config (`spire/server/server.conf`)

```hcl
server {
  bind_address = "0.0.0.0"
  bind_port    = "8081"
  socket_path  = "/tmp/spire-server/private/api.sock"
  trust_domain = "demo.local"
  data_dir     = "/tmp/spire-server-data"
  log_level    = "INFO"
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type     = "sqlite3"
      connection_string = "/tmp/spire-server-data/datastore.sqlite3"
    }
  }
  NodeAttestor "join_token" { plugin_data {} }
  KeyManager "memory" { plugin_data {} }
}
```

> `data_dir` uses `/tmp/spire-server-data` (not `/opt/spire/data/server`) to avoid conflicts
> with Docker named volumes that would shadow that path and prevent SQLite from creating its
> database file. `KeyManager "memory"` means keys are regenerated on each restart — fine for
> a demo, use `disk` or a cloud KMS in production.

### SPIRE agent config (`spire/agent/agent.conf`)

```hcl
agent {
  data_dir           = "/tmp/spire-agent-data"
  server_address     = "spire-server"
  server_port        = "8081"
  socket_path        = "/tmp/spire-agent/public/api.sock"
  trust_domain       = "demo.local"
  insecure_bootstrap = true   # skip initial bundle validation (dev only)
}

plugins {
  NodeAttestor "join_token" { plugin_data {} }
  KeyManager "memory"       { plugin_data {} }
  WorkloadAttestor "unix"   { plugin_data {} }
}
```

### Keycloak client (`spiffe-service`)

Declared in `realm-export.json` and ensured on every startup by `keycloak-init`:

```json
{
  "clientId": "spiffe-service",
  "serviceAccountsEnabled": true,
  "secret": "spiffe-service-secret",
  "standardFlowEnabled": false
}
```

The service account user `service-account-spiffe-service` has `user-role`, allowing it to
call `GET /api/products` on the resource server.

> **Why `keycloak-init` provisions this client:** Keycloak only processes `realm-export.json`
> when the realm does not yet exist in PostgreSQL. If the realm was created before
> `spiffe-service` was added to the export, the client would be absent. `keycloak-init`
> calls `ensure_spiffe_service_client()` on every startup to create the client when missing
> and assign the role to its service account — making the setup idempotent.

---

## Step-by-Step Flow

```
spiffe-service             SPIRE agent           Keycloak          Resource Server
      │                        │                     │                    │
      │  WorkloadApiClient     │                     │                    │
      │  fetch_jwt_svids(aud)  │                     │                    │
      ├───────────────────────►│                     │                    │
      │                        │  (check unix:uid:0) │                    │
      │                        │  (validate entry)   │                    │
      │◄── JWT-SVID ───────────│                     │                    │
      │    (ES256, ~5 min TTL) │                     │                    │
      │                        │                     │                    │
      │  validate locally:     │                     │                    │
      │  - sub = spiffe://...  │                     │                    │
      │  - exp not passed      │                     │                    │
      │  - look up in map      │                     │                    │
      │                        │                     │                    │
      │  POST /token           │                     │                    │
      │  grant_type=client_cred│                     │                    │
      │  client_id=spiffe-svc  │                     │                    │
      │  client_secret=...     │                     │                    │
      ├────────────────────────┼────────────────────►│                    │
      │◄────────────────────── access_token ─────────│                    │
      │                        │                     │                    │
      │  GET /api/products     │                     │                    │
      │  Authorization: Bearer │                     │                    │
      ├────────────────────────┼─────────────────────┼───────────────────►│
      │                        │                     │                    │  validate JWT
      │◄──────────────────────────────────────── 200 OK ─────────────────│
```

---

## Future Path: RFC 7523 Direct (Keycloak 26.4+)

With **Keycloak 26.4+** and its **Federated Client Authentication** (preview) feature, the
bridge step is eliminated. The JWT-SVID is presented directly to Keycloak as a
`client_assertion` per [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523):

```http
POST /realms/demo/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=spiffe-service
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<JWT-SVID>
```

Keycloak would:

1. Decode the `client_assertion` JWT.
2. Fetch SPIRE's JWKS endpoint to verify the ES256 signature.
3. Check `sub` matches `spiffe://demo.local/spiffe-service`.
4. Issue an OAuth2 access token.

This eliminates the `client_secret` entirely. The only remaining secret in the system is the
SPIRE server's private key — which never leaves the SPIRE server.

This demo currently uses **Keycloak 26.0**, which does not yet support Federated Client
Authentication. To upgrade when 26.4+ is released:

1. Change `keycloak` image to `quay.io/keycloak/keycloak:26.4` (or later) in `docker-compose.yml`.
2. Configure a JWKS URL pointing to SPIRE's JWT authority endpoint in the Keycloak client's
   authentication settings (Federated Identity Providers → JWKS URL).
3. Replace `exchange_spiffe_for_oauth2()` in `spiffe-service/main.py` to send the raw
   JWT-SVID as `client_assertion` instead of using the hardcoded secret.
4. Remove the `SPIFFE_CLIENT_MAP` bridge table — it is no longer needed.

---

## Security Properties

### What SPIFFE provides that Client Credentials does not

| Property | Client Credentials | SPIFFE |
|----------|-------------------|--------|
| Identity proof | Secret known to the service | Runtime-attested OS identity |
| Credential lifetime | Until manually rotated | ~5 minutes (auto-renewed) |
| Leak risk | Secret can be copied and reused anywhere | SVID is audience-restricted and short-lived |
| Rotation | Manual or CI/CD pipeline | Automatic (SPIRE handles it) |
| Auditability | "The secret was used" | "This container, attested at time T, ran this workload" |
| Works without a secret store | No | Yes |

### Threat model

**Mitigated**: An attacker who exfiltrates the container's environment variables gets no
usable long-lived credential. The JWT-SVID expires in 5 minutes and can only be used at the
configured audience (Keycloak token endpoint). A new SVID requires a live, attested container.

**Not mitigated by SPIFFE alone**: An attacker who can exec into the running container can
still call the Workload API and receive a fresh SVID. This is why SPIRE workload registration
entries use precise selectors, and why network policies / pod security contexts matter in
production.

### Development simplifications in this demo

| Setting | Value | Production recommendation |
|---------|-------|--------------------------|
| `insecure_bootstrap` | `true` | `false` — pin the server's bundle |
| NodeAttestor | `join_token` | Use platform attestor (`k8s_psat`, `aws_iid`, etc.) |
| WorkloadAttestor selector | `unix:uid:0` (root) | Use a non-root UID, or `k8s` selectors |
| DataStore | SQLite | PostgreSQL or MySQL for HA |
| KeyManager | `memory` (keys lost on restart) | Cloud KMS (AWS KMS, GCP Cloud HSM) |
| PID namespace | `pid: "service:spire-agent"` | Dedicated host agent (DaemonSet in k8s) |

---

## Troubleshooting

### `spiffe-service` returns `"error": "SPIRE returned no JWT SVIDs"`

The workload entry was not registered or the selector does not match. Check:

```bash
docker compose exec spire-server \
  /opt/spire/bin/spire-server entry show -socketPath /tmp/spire-server/private/api.sock
```

You should see an entry with `unix:uid:0`. If it is missing, `spire-init` did not complete
successfully — check its logs: `docker compose logs spire-init`.

### `spiffe-service` returns `"Workload API call failed: …"`

The SPIRE agent socket is not reachable or the PID namespace is wrong. Check:

```bash
docker compose ps spire-agent
docker compose logs spire-agent | tail -30
```

The socket is at `/tmp/spire-agent/public/api.sock` (shared volume `spire-agent-socket`).
If the agent logs show `"could not resolve caller information"`, verify that
`pid: "service:spire-agent"` is set on `spiffe-service` in `docker-compose.yml`.

### `Keycloak returned 401: invalid_client` in the OAuth2 bridge step

The `spiffe-service` Keycloak client is missing or its secret is wrong. Run:

```bash
docker compose up keycloak-init
```

This will create the client and assign the `user-role` to its service account.

### SPIRE agent stuck waiting for join token

The `spire-init` container did not write the join token. Check:

```bash
docker compose logs spire-init
```

A common cause is that `spire-server` was not yet healthy when `spire-init` ran, but the
`depends_on: service_healthy` in `docker-compose.yml` should prevent this. If `spire-init`
shows `"SPIRE server did not become ready in time"`, the server may need more time — restart
with `docker compose up spire-server spire-init`.

### Everything starts slowly on first run

On first `docker compose up --build`, Docker must pull the SPIRE images (~200 MB each) and
build the Python services. SPIRE also needs time to generate its CA key. The full stack can
take 3–5 minutes to become fully healthy. Use `docker compose ps` to watch health states.
