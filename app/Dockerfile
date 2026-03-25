# INTENTIONALLY INSECURE — for pipeline demo
# Checkov will catch:
#   CKV_DOCKER_3  — no USER directive (running as root)
#   CKV_DOCKER_2  — no HEALTHCHECK
#   CKV_DOCKER_7  — latest tag (unpinned base image)
#   CKV_DOCKER_8  — secrets in ENV vars

FROM python:3.11-slim

# VULNERABILITY: secrets in ENV — Checkov catches this
ENV DB_PASSWORD=super_secret_password_123
ENV API_KEY=sk-1234567890abcdef

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# VULNERABILITY: no HEALTHCHECK
# VULNERABILITY: no USER — runs as root

CMD ["python", "app.py"]
