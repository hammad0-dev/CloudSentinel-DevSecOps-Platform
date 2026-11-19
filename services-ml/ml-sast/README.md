# ml-sast

FastAPI service that the CloudSentinel backend calls when `SAST_ENGINE=ml`. Targets: Python and Node.js
sources (`.py .js .mjs .cjs .jsx .ts .tsx`). See `docs/ml-architecture.md` for the full flow.

## Endpoints

| Method | Path | Response |
|---|---|---|
| GET | `/health` | `{status, service, model}` |
| GET | `/model-info` | `{name, version, sha256, trained_on, metrics, status}` (`status` is `untrained` or `trained`) |
| POST | `/scan` | body `{files:[{path, content}]}` → `{findings:[{rule, cwe_id, severity, message, file_path, line_number, confidence}]}` |

`severity` is one of `CRITICAL HIGH MEDIUM LOW INFO`; `confidence` is 0..1.

## Untrained mode

With no model file at `MODEL_PATH`, `/scan` returns `{"findings": []}` and `/model-info` reports
`"status": "untrained"`, `"sha256": null`. No findings are invented. The backend refuses to complete a
scan with an untrained model unless `ML_ALLOW_UNTRAINED=true`, so a gate never passes on an empty
untrained result by accident.

## Model contract

`MODEL_PATH` (default `/models/ml-sast/model.joblib`) is a joblib artifact exposing
`scan(files) -> list[dict]` with the finding fields above. Metadata comes from `MODEL_META_PATH`
(default: same path with `.json`): `{"name", "version", "trained_on", "metrics"}`. The SHA-256 of the
model file is computed at startup and recorded by the backend as scan provenance. Model files are
mounted at runtime and are never committed.

## Run

```bash
pip install -r requirements.txt
uvicorn app:app --port 8001          # backend: ML_SAST_URL=http://localhost:8001

docker build -t cloudsentinel/ml-sast services-ml/ml-sast
docker run --rm -p 8001:8001 -v "$PWD/models:/models:ro" cloudsentinel/ml-sast
```

Tests: `pip install pytest httpx && pytest services-ml/ml-sast`.
