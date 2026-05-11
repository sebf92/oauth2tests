FROM python:3.12-slim

WORKDIR /app

# grpcio (required by spiffe) needs gcc + linux headers to build from source
# on platforms without a pre-built wheel.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8002
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
