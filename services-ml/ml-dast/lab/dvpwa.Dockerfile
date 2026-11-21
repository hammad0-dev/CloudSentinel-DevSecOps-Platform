# DVPWA (anxolerd/dvpwa @ 4a8f4a4, MIT): the v4 FINAL HELD-OUT app. LAB ONLY, 127.0.0.1 only.
# Never used for training or tuning; collected and scored once by scripts/eval_final_v4.py.
# Differs from the upstream Dockerfile.app only in the base image (python:3.14-slim: the requirements were
# compiled with Python 3.14, and psycopg2-binary has wheels for it) and in not downloading the wait-for script
# (compose waits for the database health check instead). Same requirements, code and config.
FROM python:3.14-slim
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt && useradd --uid 10003 --no-create-home dvpwa
WORKDIR /app
COPY run.py /app/
COPY sqli /app/sqli
COPY config /app/config
USER 10003
EXPOSE 8080
CMD ["python", "run.py"]
