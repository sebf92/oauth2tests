#!/bin/sh
# cert-init — generates the demo CA + agent leaf certificate for UC3a.
#
# The output is written to /pki, which is a Docker named volume shared with
# the agent-cert container (read-only on that side).  The script is
# IDEMPOTENT: if the files already exist on the volume, it does nothing.
# This means a `docker compose up` second-run reuses the same cert, so the
# Keycloak client's registered public key keeps matching the agent's private key.
#
# Files produced
# ──────────────
#   ca.key       EC P-256 private key for the demo CA (kept on the volume so
#                a redeploy doesn't break a re-issuance path; not actually used
#                by anything after cert.crt is signed)
#   ca.crt       Self-signed CA certificate (10-year validity)
#   agent.key    EC P-256 private key for the agent (used at runtime to sign
#                RFC 7523 client_assertion JWTs)
#   agent.csr    Intermediate file — kept only for transparency, not used later
#   agent.crt    Agent leaf certificate signed by the demo CA (1-year validity)
#
# Why a CA (and not just a self-signed agent cert)?
#   Mirrors the production pattern: in real life the agent's cert is issued by
#   a corporate or platform CA, not signed by itself.  The demo shows the chain
#   even though Keycloak only needs the leaf's public key.

set -e

OUT_DIR=/pki
CA_KEY="$OUT_DIR/ca.key"
CA_CRT="$OUT_DIR/ca.crt"
AGENT_KEY="$OUT_DIR/agent.key"
AGENT_CSR="$OUT_DIR/agent.csr"
AGENT_CRT="$OUT_DIR/agent.crt"

# Subject DNs.  Kept simple — production deployments would use OUs, country, etc.
CA_SUBJ="/CN=OAuth2 Demo CA/O=OAuth2 Sample"
AGENT_SUBJ="/CN=ai-agent-cert/O=OAuth2 Sample/OU=Agentic AI"

echo "=== cert-init: target volume $OUT_DIR ==="

# Idempotency guard: if everything is already there, stop.  We check the agent
# certificate specifically (the final artifact) so partial state is regenerated.
if [ -s "$AGENT_KEY" ] && [ -s "$AGENT_CRT" ] && [ -s "$CA_CRT" ]; then
  echo "  ✓ PKI already present — leaving existing files in place."
  echo "    To regenerate, run:  docker volume rm oauth2sample_agent-cert-pki"
  exit 0
fi

mkdir -p "$OUT_DIR"

echo "=== Generating demo CA (EC P-256, 10-year validity) ==="
openssl ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
openssl req -new -x509 \
    -key "$CA_KEY" \
    -out "$CA_CRT" \
    -days 3650 \
    -subj "$CA_SUBJ" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
echo "  ✓ CA written to $CA_CRT"

echo "=== Generating agent key + CSR ==="
openssl ecparam -name prime256v1 -genkey -noout -out "$AGENT_KEY"
openssl req -new \
    -key "$AGENT_KEY" \
    -out "$AGENT_CSR" \
    -subj "$AGENT_SUBJ"

echo "=== Signing agent certificate (1-year validity) ==="
# The leaf is constrained to client-auth + signing usage.  Keycloak only looks
# at the public key, but a real CA would issue with these EKU/KU values.
openssl x509 -req \
    -in "$AGENT_CSR" \
    -CA "$CA_CRT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$AGENT_CRT" \
    -days 365 \
    -extensions v3_req \
    -extfile /dev/stdin <<'EOF'
[v3_req]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
echo "  ✓ Agent cert written to $AGENT_CRT"

# Make the agent key world-readable so the non-root agent process can read it.
# The volume is private to this docker-compose stack so this is acceptable for a demo.
chmod 644 "$AGENT_KEY" "$AGENT_CRT" "$CA_CRT"

echo
echo "=== Certificate summary ==="
openssl x509 -in "$AGENT_CRT" -noout -subject -issuer -dates -serial -fingerprint -sha256

echo
echo "=== cert-init done ==="
