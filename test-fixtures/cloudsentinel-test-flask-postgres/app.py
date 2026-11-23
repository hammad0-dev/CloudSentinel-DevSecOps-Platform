"""Two-tier test fixture: Flask API + PostgreSQL.

Configuration comes only from the environment, never from source:
  DB_HOST, DB_PORT, DB_NAME      non-secret (ConfigMap generated from the RDS outputs)
  DB_USER, DB_PASSWORD           from the RDS-managed Secrets Manager secret via External Secrets Operator
  APP_GREETING                   optional, from the project's own Secrets Manager secret
"""
import hashlib
import os

import psycopg2
from flask import Flask, jsonify
from waitress import serve

app = Flask(__name__)
SECRET_DIR = "/var/run/secrets/cloudsentinel"


def connect():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST"),
        port=int(os.environ.get("DB_PORT", "5432")),
        dbname=os.environ.get("DB_NAME"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        sslmode="require",
        connect_timeout=5,
    )


@app.get("/")
def home():
    return jsonify(status="ok", greeting=bool(os.environ.get("APP_GREETING"))), 200


@app.get("/health")
def health():
    return jsonify(status="healthy"), 200


@app.get("/db")
def db():
    with connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT current_user, version()")
        user, version = cur.fetchone()
    # Shows where the credentials came from without revealing them.
    mounted = sorted(os.listdir(SECRET_DIR)) if os.path.isdir(SECRET_DIR) else []
    return jsonify(connected=True, db_user=user, server=version.split(",")[0], mounted_secret_dirs=mounted), 200


@app.get("/secret-fingerprint")
def secret_fingerprint():
    # Short hash of the mounted secret file, to show rotation without printing the value.
    path = None
    for root, _dirs, files in os.walk(SECRET_DIR):
        if "APP_GREETING" in files:
            path = os.path.join(root, "APP_GREETING")
    if path is None:
        return jsonify(present=False), 200
    with open(path, "rb") as f:
        return jsonify(present=True, sha256_12=hashlib.sha256(f.read()).hexdigest()[:12]), 200


if __name__ == "__main__":
    serve(app, listen="*:8080")
