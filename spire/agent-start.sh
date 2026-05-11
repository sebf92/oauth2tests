#!/bin/sh
# SPIRE agent entrypoint — waits for the join token written by spire-init,
# then starts the agent with that token.
set -e

TOKEN_FILE="/tmp/spire-tokens/join-token"

echo "=== SPIRE agent: waiting for join token ==="
for i in $(seq 1 30); do
  if [ -f "$TOKEN_FILE" ] && [ -s "$TOKEN_FILE" ]; then
    echo "  ✓ Join token found (attempt ${i})"
    break
  fi
  echo "  attempt ${i}/30 — token not yet written, retrying in 3 s..."
  sleep 3
  if [ "$i" -eq 30 ]; then
    echo "  ✗ Join token never appeared"
    exit 1
  fi
done

TOKEN=$(cat "$TOKEN_FILE")
echo "=== Starting SPIRE agent ==="
exec /opt/spire/bin/spire-agent run \
  -config    /opt/spire/conf/agent/agent.conf \
  -joinToken "$TOKEN"
