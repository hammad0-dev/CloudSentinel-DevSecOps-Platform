# Clean Python fixture. Base image pinned by digest: python:3.13-alpine (Alpine 3.24.4), checked 2026-11-27.
# Why not the generated python:3.11-slim: every Debian 13 slim tag (3.11/3.12/3.13) still ships libzstd1
# 1.5.7+dfsg-1 (CVE-2026-124851, HIGH, fixed in 1.5.7+dfsg-1+deb13u1), which the image gate blocks
# (HIGH with a fix available). This base scans 0 CRITICAL / 0 HIGH OS-package vulnerabilities.
# Non-root numeric UID (the CloudSentinel-generated manifest sets its own runAsUser, which takes precedence).
FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e
RUN addgroup -g 1000 app && adduser -D -H -u 1000 -G app app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=1000:1000 . .
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080
USER 1000:1000
CMD ["python", "app.py"]
