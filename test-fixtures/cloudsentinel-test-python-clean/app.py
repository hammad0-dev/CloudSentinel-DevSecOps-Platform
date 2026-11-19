from flask import Flask, jsonify
from flask_wtf.csrf import CSRFProtect
from waitress import serve

app = Flask(__name__)
# Secrets come only from the environment (FLASK_SECRET_KEY), never from source.
app.config.from_prefixed_env()
CSRFProtect(app)


@app.get("/")
def home():
    return jsonify(status="ok"), 200


@app.get("/health")
def health():
    return jsonify(status="healthy"), 200


if __name__ == "__main__":
    # Containers must accept traffic from the pod network; waitress listens on all interfaces.
    serve(app, listen="*:8080")
