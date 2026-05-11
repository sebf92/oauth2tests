FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir httpx==0.27.0

COPY setup.py .

CMD ["python", "setup.py"]
