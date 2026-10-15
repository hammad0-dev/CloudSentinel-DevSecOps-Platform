# CloudSentinel Python Flask Test Fixture

Minimal public-test fixture for CloudSentinel's generated Python deployment path.

## Run locally

```bash
python -m pip install -r requirements.txt
python app.py
```

The service listens on `0.0.0.0:8080`.

```bash
curl http://127.0.0.1:8080/health
```

Expected response:

```json
{"status":"healthy"}
```

The application has no persistent storage or runtime filesystem writes, making it compatible with a non-root user and a read-only root filesystem when `/tmp` is provided by the platform.
