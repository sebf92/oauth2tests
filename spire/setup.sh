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

echo "  ✓ Workload entry created"
echo "=== SPIRE init complete ==="
