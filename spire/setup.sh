#!/bin/sh
# SPIRE init script — runs once as the spire-init container.
#
# 1. Waits for the SPIRE server to be ready.
# 2. Generates a join token with a fixed agent SPIFFE ID so the workload
#    registration entry can reference a stable parentID.
# 3. Writes the token to a shared volume for the agent container to read.
# 4. Creates a workload registration entry for spiffe-service.
set -e

SPIRE_SERVER="/opt/spire/bin/spire-server"
SOCKET="/tmp/spire-server/private/api.sock"
TRUST_DOMAIN="demo.local"
TOKEN_FILE="/tmp/spire-tokens/join-token"
AGENT_SPIFFE_ID="spiffe://${TRUST_DOMAIN}/agents/demo-agent"

echo "=== SPIRE init: waiting for server ==="
for i in $(seq 1 30); do
  if "$SPIRE_SERVER" healthcheck -socketPath "$SOCKET" > /dev/null 2>&1; then
    echo "  ✓ SPIRE server ready (attempt ${i})"
    break
  fi
  echo "  attempt ${i}/30 — retrying in 5 s..."
  sleep 5
  if [ "$i" -eq 30 ]; then
    echo "  ✗ SPIRE server did not become ready in time"
    exit 1
  fi
done

echo "=== Generating join token ==="
mkdir -p /tmp/spire-tokens
TOKEN_OUTPUT=$("$SPIRE_SERVER" token generate \
  -socketPath "$SOCKET" \
  -spiffeID "$AGENT_SPIFFE_ID" 2>&1)

TOKEN=$(echo "$TOKEN_OUTPUT" | grep "Token:" | awk '{print $2}')
if [ -z "$TOKEN" ]; then
  echo "  ✗ Failed to parse join token from output:"
  echo "    $TOKEN_OUTPUT"
  exit 1
fi

echo "$TOKEN" > "$TOKEN_FILE"
echo "  ✓ Token written → $TOKEN_FILE"

echo "=== Creating workload entry for spiffe-service ==="
# selector unix:uid:0  — matches any process running as root (UID 0) inside
# the agent's host. The spiffe-service container runs as root by default.
"$SPIRE_SERVER" entry create \
  -socketPath "$SOCKET" \
  -parentID   "$AGENT_SPIFFE_ID" \
  -spiffeID   "spiffe://${TRUST_DOMAIN}/spiffe-service" \
  -selector   unix:uid:0 \
  -ttl        3600 2>&1 | grep -v "^$" || true
echo "  ✓ spiffe-service entry created"

# selector unix:uid:1000 → ai-agent-spiffe.  We deliberately use a DIFFERENT UID
# so this entry does not collide with spiffe-service (uid:0). The agent-spiffe
# Dockerfile creates and runs as user 1000.  Without distinct selectors, SPIRE
# would issue BOTH SPIFFE IDs to BOTH containers — masking which workload
# actually authenticated.
echo "=== Creating workload entry for ai-agent-spiffe ==="
"$SPIRE_SERVER" entry create \
  -socketPath "$SOCKET" \
  -parentID   "$AGENT_SPIFFE_ID" \
  -spiffeID   "spiffe://${TRUST_DOMAIN}/ai-agent-spiffe" \
  -selector   unix:uid:1000 \
  -ttl        3600 2>&1 | grep -v "^$" || true
echo "  ✓ ai-agent-spiffe entry created"

# selector unix:uid:1001 → ai-agent-spiffe-mtls (UC2-Hardened).  Distinct UID
# from agent-spiffe (1000), spiffe-service (0), and keycloak-mtls-proxy (1002)
# so the SPIRE unix workload attestor can tell them apart at the socket peer's
# UID alone — see CLAUDE.md "SPIRE selectors must be distinct" gotcha.
echo "=== Creating workload entry for ai-agent-spiffe-mtls ==="
# -dns injects a DNS SAN and (SPIRE behaviour) makes the first DNS SAN the
# cert's Subject CN.  Without it the SVID has Subject=O=SPIRE,C=US with no
# CN — making it indistinguishable from any other workload's cert via
# Subject-DN matching alone (which is what Keycloak client-x509 supports).
"$SPIRE_SERVER" entry create \
  -socketPath "$SOCKET" \
  -parentID   "$AGENT_SPIFFE_ID" \
  -spiffeID   "spiffe://${TRUST_DOMAIN}/ai-agent-spiffe-mtls" \
  -selector   unix:uid:1001 \
  -dns        ai-agent-spiffe-mtls \
  -ttl        3600 2>&1 | grep -v "^$" || true
echo "  ✓ ai-agent-spiffe-mtls entry created"

# selector unix:uid:1002 → keycloak-mtls-proxy (UC2-Hardened sidecar).  The
# proxy uses its own X.509-SVID as the HTTPS server cert and the trust-domain
# bundle (delivered alongside the SVID) as the ssl_client_certificate trust
# anchor for validating incoming mTLS clients.
echo "=== Creating workload entry for keycloak-mtls-proxy ==="
"$SPIRE_SERVER" entry create \
  -socketPath "$SOCKET" \
  -parentID   "$AGENT_SPIFFE_ID" \
  -spiffeID   "spiffe://${TRUST_DOMAIN}/keycloak-mtls-proxy" \
  -selector   unix:uid:1002 \
  -dns        keycloak-mtls-proxy \
  -dns        localhost \
  -ttl        3600 2>&1 | grep -v "^$" || true
echo "  ✓ keycloak-mtls-proxy entry created"

echo "=== SPIRE init complete ==="
