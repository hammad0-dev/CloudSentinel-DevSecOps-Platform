# ml-dast

FastAPI service that the CloudSentinel backend calls on the baseline DAST path when `DAST_ENGINE=ml`.
Targets: Python and Node.js web apps deployed to staging. See `docs/ml-architecture.md` for the full flow.

## Endpoints

| Method | Path | Response |
|---|---|---|
| GET | `/health` | `{status, service, model}` |
| GET | `/model-info` | `{name, version, sha256, trained_on, metrics, status}` (`status` is `untrained` or `trained`) |
| POST | `/scan` | body `{baseUrl, maxPages, maxRequests}` → `{findings:[{alert, attack_type, severity, endpoint, method, param, request_payload, response_details, cwe_id, solution, confidence}]}` |

`severity` is one of `HIGH MEDIUM LOW INFORMATIONAL` (the existing `dast_findings` scale);
`maxPages` ≤ 500, `maxRequests` ≤ 5000.

## Untrained mode

With no model file at `MODEL_PATH`, `/scan` returns `{"findings": []}`, sends no traffic to the target,
and `/model-info` reports `"status": "untrained"`. No findings are invented. The backend refuses to
complete a scan with an untrained model unless `ML_ALLOW_UNTRAINED=true`.

## Target authorization

The service scans whatever `baseUrl` it is given. Only the backend should be able to reach it: the
backend authorizes the target first (verified staging deployment for pipeline runs, owner-configured
target for manual runs). Do not expose this port publicly.

## Model contract

`MODEL_PATH` (default `/models/ml-dast/model.joblib`) is a joblib artifact exposing
`scan(base_url, max_pages, max_requests) -> list[dict]` with the finding fields above. Metadata comes
from `MODEL_META_PATH` (default: same path with `.json`). The SHA-256 of the model file is recorded by
the backend as scan provenance. Model files are mounted at runtime and are never committed.

## Run

```bash
pip install -r requirements.txt
uvicorn app:app --port 8002          # backend: ML_DAST_URL=http://localhost:8002

docker build -t cloudsentinel/ml-dast services-ml/ml-dast
docker run --rm -p 8002:8002 -v "$PWD/models:/models:ro" cloudsentinel/ml-dast
```

Tests: `pip install pytest httpx && pytest services-ml/ml-dast`.
