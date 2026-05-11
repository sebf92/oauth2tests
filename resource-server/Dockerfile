FROM python:3.12-slim

WORKDIR /app

# libssl-dev + libffi-dev + gcc are required to build the 'cryptography' package
# from source on platforms where a pre-built wheel is unavailable (e.g. linux/arm64
# on some Docker versions).  On amd64 the manylinux wheel is used and these are
# not strictly needed, but they add < 5 MB and prevent hard-to-debug failures.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       gcc \
       libssl-dev \
       libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Verify cryptography is importable before we even copy the app code.
# A failed import here produces a clear error at build time, not at runtime.
RUN python -c "from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey; print('cryptography OK')"

COPY . .

EXPOSE 8001
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
