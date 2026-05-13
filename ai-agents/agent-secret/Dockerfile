FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Fail at build time if the MCP SDK or Anthropic SDK is unusable.
RUN python -c "from mcp.client.streamable_http import streamablehttp_client; import anthropic; print('SDKs OK')"

COPY . .

EXPOSE 9001
CMD ["uvicorn", "agent:app", "--host", "0.0.0.0", "--port", "9001"]
