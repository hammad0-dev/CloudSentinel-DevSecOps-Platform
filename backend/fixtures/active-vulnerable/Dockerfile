# Supply an independently verified Linux/amd64 Python base by digest; no default.
ARG PYTHON_BASE
FROM ${PYTHON_BASE}
ARG PYTHON_BASE
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TMPDIR=/tmp HOME=/tmp
WORKDIR /app
COPY --chown=10001:10001 app.py /app/app.py
RUN python3 -c 'import re,sys,sqlite3,wsgiref.simple_server; assert re.fullmatch(r"[a-z0-9./_-]+@sha256:[a-f0-9]{64}",sys.argv[1]); assert sqlite3.connect(":memory:").execute("SELECT 1").fetchone()==(1,)' "${PYTHON_BASE}" \
    && chmod 0444 /app/app.py
USER 10001:10001
HEALTHCHECK --interval=5s --timeout=2s --retries=3 CMD ["python3", "-c", "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:18080/health',timeout=1).read()==b'fixture-ready'"]
ENTRYPOINT ["python3", "/app/app.py"]
