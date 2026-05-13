FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN python -c "from cryptography.hazmat.primitives.serialization import load_pem_private_key; from mcp.client.streamable_http import streamablehttp_client; import anthropic; print('SDKs OK')"

COPY . .

# The agent reads its long-lived cert + key from /pki, populated by cert-init.
# Running as non-root for symmetry with agent-spiffe.  Note that there's no
# SPIRE selector here — Keycloak authenticates this client purely through the
# RFC 7523 client_assertion signed by the agent's private key.
RUN useradd -u 1100 -m -s /bin/bash agent
USER 1100

EXPOSE 9003
CMD ["uvicorn", "agent:app", "--host", "0.0.0.0", "--port", "9003"]
