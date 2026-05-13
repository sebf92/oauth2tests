FROM python:3.12-slim

WORKDIR /app

# Same toolchain as resource-server — needed if cryptography falls back to source build.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       gcc \
       libssl-dev \
       libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Sanity-check that the MCP SDK is importable before copying the app code, so any
# version-incompatibility shows up at build time rather than buried in container logs.
RUN python -c "from mcp.server.fastmcp import FastMCP; print('mcp SDK OK')"

COPY . .

EXPOSE 8003
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8003"]
