# INTENTIONALLY INSECURE — for pipeline demo
# Checkov will catch:
#   CKV_DOCKER_7  — latest tag (unpinned base image)
#   CKV_DOCKER_8  — secrets in ENV vars

FROM python:3.11-slim

# VULNERABILITY: secrets in ENV — Checkov catches this
ENV DB_PASSWORD=super_secret_password_123
ENV API_KEY=sk-1234567890abcdef

# FIX: Create and use non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chown -R appuser:appuser /app

# FIX: HEALTHCHECK present
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/')" || exit 1

# FIX: Non-root user
USER appuser

CMD ["python", "app.py"]
