FROM python:3.12-slim

WORKDIR /app

# cryptography may need a toolchain on platforms without a manylinux wheel.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN python -c "from spiffe import WorkloadApiClient; from mcp.client.streamable_http import streamablehttp_client; import anthropic; print('SDKs OK')"

COPY . .

# IMPORTANT: this container is registered with SPIRE under the selector
# unix:uid:1000.  Running as a different UID would make SPIRE refuse to issue
# the JWT-SVID (no matching workload entry).  Both the user and the spiffe
# library must be readable by uid:1000 — we use site-packages from /usr/local
# which is world-readable by default, so no extra chmod is required.
RUN useradd -u 1000 -m -s /bin/bash agent
USER 1000

EXPOSE 9002
CMD ["uvicorn", "agent:app", "--host", "0.0.0.0", "--port", "9002"]
