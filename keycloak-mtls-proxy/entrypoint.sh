#!/bin/bash
# UC2-Hardened mTLS proxy — startup script.
#
#   1. Wait for the SPIRE agent socket to appear.
#   2. Call the SPIRE Workload API as UID 1002 to fetch this proxy's
#      X.509-SVID (server cert + key) and the trust-domain bundle.
#   3. Move the files to predictable names referenced by nginx.conf.
#   4. exec into the original CMD (nginx).
set -euo pipefail

SPIRE_SOCKET="/tmp/spire-agent/public/api.sock"
TLS_DIR="/etc/nginx/tls"

echo "=== keycloak-mtls-proxy startup ==="

mkdir -p "$TLS_DIR"
chown spireworker:spireworker "$TLS_DIR"

# 1. Wait for SPIRE agent socket.  The spire-agent container has its own
# healthcheck so this should normally be immediate, but on a cold start the
# socket can lag a couple of seconds behind container readiness.
echo "→ Waiting for SPIRE agent socket at $SPIRE_SOCKET..."
for i in $(seq 1 60); do
    if [ -S "$SPIRE_SOCKET" ]; then
        echo "  ✓ socket ready (attempt $i)"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "  ✗ timed out — is the spire-agent container healthy?"
        exit 1
    fi
    sleep 2
done

# 2. Fetch the SVID + trust bundle as UID 1002 so SPIRE attests us as
# spiffe://demo.local/keycloak-mtls-proxy.  Running as root here would match
# spiffe-service's selector (unix:uid:0) and SPIRE would issue the wrong SVID.
echo "→ Fetching X.509-SVID + trust bundle from SPIRE (as UID 1002)..."
for attempt in 1 2 3 4 5; do
    if su-exec spireworker /usr/local/bin/spire-agent api fetch x509 \
            -socketPath "$SPIRE_SOCKET" \
            -write "$TLS_DIR" 2>&1; then
        break
    fi
    if [ "$attempt" -eq 5 ]; then
        echo "  ✗ SPIRE fetch failed after 5 attempts — workload entry registered?"
        exit 1
    fi
    echo "  retrying in 3s (SPIRE may still be registering this workload)..."
    sleep 3
done

# 3. Normalise filenames.  spire-agent writes svid.N.pem / svid.N.key /
# bundle.N.pem (N=0 for the primary identity); nginx.conf references stable
# filenames so the config doesn't have to know about SPIRE's numbering scheme.
mv "$TLS_DIR/svid.0.pem"   "$TLS_DIR/server.crt"
mv "$TLS_DIR/svid.0.key"   "$TLS_DIR/server.key"
mv "$TLS_DIR/bundle.0.pem" "$TLS_DIR/spire-bundle.crt"

# nginx worker runs as `nginx` user — must read all three.
chmod 644 "$TLS_DIR/server.crt" "$TLS_DIR/spire-bundle.crt"
chmod 644 "$TLS_DIR/server.key"   # demo trade-off — production: use a TLS-aware user

echo "  ✓ server cert: $(openssl x509 -in "$TLS_DIR/server.crt" -noout -subject -ext subjectAltName 2>/dev/null | tr '\n' ' ')"
echo "  ✓ trust bundle: $(openssl x509 -in "$TLS_DIR/spire-bundle.crt" -noout -subject -dates 2>/dev/null | tr '\n' ' ')"

# 4. Hand off to nginx.
echo "→ Starting nginx on :8443 (mTLS required)..."
exec "$@"
