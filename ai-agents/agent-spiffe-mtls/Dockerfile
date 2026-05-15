FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN python -c "from spiffe import WorkloadApiClient; from mcp.client.streamable_http import streamablehttp_client; import anthropic; print('SDKs OK')"

COPY . .

# UID 1001 — must match the SPIRE workload entry's unix:uid:1001 selector
# (see spire/setup.sh).  Distinct from agent-spiffe (uid:1000), spiffe-service
# (uid:0), and keycloak-mtls-proxy (uid:1002) so SPIRE can tell them apart.
RUN useradd -u 1001 -m -s /bin/bash agent
USER 1001

EXPOSE 9005
CMD ["uvicorn", "agent:app", "--host", "0.0.0.0", "--port", "9005"]
