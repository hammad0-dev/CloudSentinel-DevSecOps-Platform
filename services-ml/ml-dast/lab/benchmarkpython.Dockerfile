# OWASP BenchmarkPython @ f129148 (GPL-3.0): v4 TRAINING data (one LOAO group). LAB ONLY, 127.0.0.1 only.
# Upstream runs `flask --app app.py run --debug --port 8443 --cert=adhoc`; here plain HTTP on 8080 without the
# debugger (the lab never uses TLS, and the Werkzeug debugger would expose a console). Same pinned requirements.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends gcc libxml2-dev libxslt1-dev && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10002 --create-home bench
WORKDIR /bench
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Code stays root-owned (read-only for the app user): some path-traversal cases OPEN FILES FOR WRITING at the
# traversed path (e.g. BenchmarkTest00667), so the app user may write only to ./testfiles (also its SQLite db).
RUN chown -R bench /bench/testfiles
USER 10002
EXPOSE 8080
CMD ["flask", "--app", "app.py", "run", "--host", "0.0.0.0", "--port", "8080", "--no-debugger", "--no-reload"]
