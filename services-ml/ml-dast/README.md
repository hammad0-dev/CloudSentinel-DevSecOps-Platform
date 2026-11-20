# ml-dast

The CloudSentinel backend calls this FastAPI service on the baseline DAST path when
`DAST_ENGINE=ml`. Targets are Python and Node.js web apps. The full backend flow is in
`docs/ml-architecture.md`; the model, data and metrics are in
[`docs/ml-dast-model-card.md`](../../docs/ml-dast-model-card.md).

## Endpoints

| Method | Path | Response |
|---|---|---|
| GET | `/health` | `{status, service, model}` |
| GET | `/model-info` | `{name, version, sha256, trained_on, metrics, status, threshold, classes, limitations, components}` |
| POST | `/scan` | body `{baseUrl, maxPages, maxRequests, seedPaths?, openapiUrl?}` → `{findings:[{alert, attack_type, severity, endpoint, method, param, request_payload, response_details, cwe_id, solution, confidence}], coverage:{pages, points_found, points_probed, requests, stopped}}` |

How `/scan` works with a trained model (`dastml.detector.DastDetector`):

1. **Crawl.** Same-origin HTML crawl collects injection points from links, forms, query parameters,
   form fields and numeric path segments. For endpoints not linked from HTML (JSON roots, APIs):
   - `seedPaths` (max 50) are extra start pages, e.g. `["/users?name=alice", "/search?q=test"]`;
   - `openapiUrl` is an OpenAPI 3 / Swagger 2 **JSON** document (`dastml/openapi.py`). Its GET and
     POST operations become points: query and path parameters, plus JSON or form body properties.
     PUT, PATCH and DELETE are never probed, and a `servers` host is never used as a destination.

   Each seed is resolved against `baseUrl` and must stay on its origin under the allowlist; otherwise
   the scan is refused with 400 before any traffic. A model build without seed support answers 501.
   `coverage` reports what was tested: `points_found: 0` means nothing was tested, not "clean".
2. **Probe.** Each point gets two baseline requests, one benign probe and the fixed payload list in
   `data/dast/payloads/` (28 SQLi, 16 XSS).
3. **Featurize.** Each request/response pair becomes a feature row (`dastml/features.py`).
4. **Classify.** The model scores every row. Each (endpoint, parameter, class) whose highest
   probability is at least the threshold becomes one finding. `ML_DAST_CONFIDENCE_THRESHOLD`
   overrides the model's threshold.

Classes are CWE-89 (SQL injection) and CWE-79 (reflected XSS). `severity` uses the existing
`dast_findings` scale (`HIGH MEDIUM LOW INFORMATIONAL`). Limits: `maxPages` ≤ 500 and `maxRequests` ≤
5000.

## Safety guards (`dastml/guards.py`)

Every request goes through `GuardedClient`:

| Guard | Default | Configure |
|---|---|---|
| Host allowlist (exact names; no other spelling of loopback, no userinfo) | `127.0.0.1`, `localhost` | `ML_DAST_ALLOWED_HOSTS` |
| Port allowlist | `5101-5108` (lab) | `ML_DAST_ALLOWED_PORTS` (e.g. `30000-32767` for NodePorts) |
| Same origin only; off-origin redirects are reported, never followed | always | – |
| Page and request budgets | `maxPages` / `maxRequests` per scan | request body |
| Rate limit | 20 requests/s | `ML_DAST_RATE_PER_SEC` |
| Proxy settings from the environment | ignored | – |
| Never-attack paths | lab skip list (`ground_truth.json`) | detector policy |
| Never-attack parameters (v2): a (path, parameter) pair, e.g. DSVW `/?object=` | lab skip list (`ground_truth_v2.json`) | detector policy (`skip_params`) |
| No URL-carrying parameters (v2): a query or body value with `scheme://` (raw or %-encoded) is refused, so a crawled link can never make the target fetch another host | always | – |

A target outside the allowlist gets **HTTP 400 before any traffic is sent**. To scan the pipeline's
staging deployment, set the allowlist to the staging host and NodePort range. The backend also
authorizes the target first (the verified staging deployment). Don't expose this service's port.

## v2: rule-based classes and passive checks

A v2 model (`models/release_v2/`, built by `scripts/train_final_v2.py`; `data_version: "v2"` in the
artifact) adds deterministic **rules (not machine learning)** to the same scan (`dastml/rules.py`):

| Class | Evidence | Severity |
|---|---|---|
| CWE-78 OS command injection | the shell computes `{M}1337` from `{M}$((7*191))`, or `;sleep 2` is ≥ 1.6 s slower than `;sleep 0` (sent twice) | HIGH |
| CWE-22 path traversal | `/etc/passwd` content (`root:x:0:0:`) not in the baseline | HIGH |
| CWE-601 open redirect | 3xx `Location` to `{M}.invalid` (scheme-less payload; header read, redirect never followed) | MEDIUM |
| Passive: CSP, `nosniff`, framing, session cookie HttpOnly/SameSite, CORS echo | headers of up to 10 crawled pages (cookie-less re-request, every redirect hop) and one foreign-`Origin` request | LOW / INFO, never gate-blocking |

Rule findings carry `response_details` starting `[rule-based`, `confidence` 1.0, and passive ones have
`attack_type` `passive_*` (the backend classifies them as `MISCONFIGURATION`). When the CWE-78 rule
confirms command injection on a parameter, the ML SQLi score on that parameter yields to it (quote
parity also fires for shell quoting). v1 artifacts keep the exact v1 behaviour. Point the service at a
v2 model with `ML_DAST_MODEL_DIR=services-ml/ml-dast/models/release_v2 scripts/run-ml-dast.sh`.

## Untrained mode

With no model file at `MODEL_PATH`, `/scan` returns `{"findings": []}`, sends no traffic, and
`/model-info` reports `"status": "untrained"`. The service never invents findings. The backend
refuses to finish a scan with an untrained model unless `ML_ALLOW_UNTRAINED=true`.

## Model artifact

`MODEL_PATH` (default `/models/ml-dast/model.joblib`) is a joblib file holding a `DastDetector`, built
by `scripts/train_final.py` into `models/release/`. Its metadata comes from `MODEL_META_PATH`, which
defaults to the same path with `.json`. The SHA-256 of the model file is reported in `/model-info`,
and the backend records it as scan provenance. Model files are gitignored and mounted at runtime.

## Lab, data and reproduction

v2 data lives beside the frozen v1 files (never edited): `data/dast/ground_truth_v2.json`,
`payloads/payloads_v2.json`, `raw_v2/`, `features_v2/`; the v2 held-out app DSVW is frozen in
`data/dast/FREEZE_v2.json`. Scripts take `--data v2`; see the model card for the v2 reproduction steps.


Everything runs from `services-ml/ml-dast/`. The `.venv/`, `data/dast/{raw,features}/`, `models/`,
`logs/` and `lab/vendor/` directories are gitignored.

```bash
python3 -m venv .venv && .venv/bin/pip install requests numpy scikit-learn lightgbm joblib matplotlib fastapi uvicorn pydantic pytest httpx
cd lab && ./fetch-vendor.sh && docker compose up -d --build && cd ..   # lab apps on 127.0.0.1:5101-5108 (see data/dast/GROUND_TRUTH.md)
.venv/bin/python scripts/collect_lab.py            # crawl + payloads -> data/dast/{raw,features}/<app>.jsonl.gz
.venv/bin/python scripts/featurize.py              # rebuild features from raw records (no traffic)
.venv/bin/python scripts/dataset_stats.py          # dataset statistics and leakage checks -> data/dast/manifest.json
.venv/bin/python scripts/loao.py                   # main evaluation: leave-one-app-out -> reports/loao.{json,md}, confusion PNGs
lab/zap-scan.sh labflask:8080 ...                  # offline ZAP baseline (unmodified image) -> logs/zap/
.venv/bin/python scripts/zap_compare.py            # ZAP on the same endpoint-param clusters
.venv/bin/python scripts/train_final.py            # final model on all training apps -> models/release/
.venv/bin/python scripts/eval_final.py             # DVNA, exactly once -> reports/final_dvna.json
```

## Run

```bash
pip install -r requirements.txt
MODEL_PATH=models/release/model.joblib uvicorn app:app --port 8002     # backend: ML_DAST_URL=http://localhost:8002

docker build -t cloudsentinel/ml-dast services-ml/ml-dast
docker run --rm -p 127.0.0.1:8002:8002 -v "$PWD/services-ml/ml-dast/models/release:/models/ml-dast:ro" \
  -e ML_DAST_ALLOWED_HOSTS=<staging host> -e ML_DAST_ALLOWED_PORTS=30000-32767 cloudsentinel/ml-dast
```

Tests: `.venv/bin/python -m pytest tests test_app.py`. They cover the guards, the features, the
service, and a local fixture app end to end.
