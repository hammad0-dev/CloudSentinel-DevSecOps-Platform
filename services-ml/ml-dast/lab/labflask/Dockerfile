# LAB ONLY: deliberately vulnerable app for ml-dast ground truth. Never deploy.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir flask==3.0.3 waitress==3.0.0 \
 && mkdir -p /srv/files && chown nobody /srv/files
WORKDIR /app
COPY app.py .
USER nobody
EXPOSE 8080
CMD ["python", "app.py"]
