# ml-sast

FastAPI service that the CloudSentinel backend calls when `SAST_ENGINE=ml`. Targets: Python and
JavaScript (`.py .js .mjs .cjs .jsx`; TypeScript is skipped). The model card, with its data, metrics
and limitations, is in [`docs/ml-sast-model-card.md`](../../docs/ml-sast-model-card.md). The backend
flow is in [`docs/ml-architecture.md`](../../docs/ml-architecture.md).

## Endpoints

| Method | Path | Response |
|---|---|---|
| GET | `/health` | `{status, service, model}` |
| GET | `/model-info` | `{name, version, sha256, trained_on, metrics, status, classes, threshold, limitations, components?}` |
| POST | `/scan` | body `{files:[{path, content}]}` → `{findings:[{rule, cwe_id, severity, message, file_path, line_number, confidence}]}` |

How `/scan` works:

1. It splits every file into function-level units (`sastml/extract.py`).
2. It classifies each unit as `safe` or one of CWE-89, CWE-79, CWE-78, CWE-22, CWE-798, CWE-502 or
   CWE-327.
3. It returns findings that pass the confidence threshold. The default threshold is stored with the
   model; `ML_SAST_CONFIDENCE_THRESHOLD` overrides it.
   - **v1 (single model):** one finding per unit, for its most likely vulnerable class.
   - **v2 hybrid (`sastml/hybrid.py`):** one finding per (unit, class) that passes that class's
     threshold.

In v2, CWE-798 also comes from a **rule-based secrets detector** (`sastml/secrets.py`), not machine
learning. Its findings are labelled as rule-based:
- the rule is `<lang>.hardcoded-credentials.rule`;
- the message starts with `[rule-based secrets detector]`;
- `/model-info` → `components.secrets.type` is `"rule-based"`, next to `components.ml.type`
  `"machine-learning"`.

The `line_number` of a finding is the function's start line (the `def`/`function` line), or the first
line of top-level code for `<module>` units. Rule names are `<lang>.<kind>`, for example
`python.sql-injection` and `javascript.command-injection`.

The severity of each finding depends on its class:

| Severity | Classes |
|---|---|
| CRITICAL | CWE-89, CWE-78, CWE-502 |
| HIGH | CWE-79, CWE-22, CWE-798 |
| MEDIUM | CWE-327 |

## Model artifact

`MODEL_PATH` is either of these:

- A joblib file holding `sastml.hybrid.HybridModel` (v2: `models/release_v2/`), `sastml.model.SastModel`
  (LR / RF / LightGBM; v1: `models/release/`) or `sastml.codebert.CodeBertXGB`.
- A fine-tuned CodeBERT folder (`config.json` + weights). A CodeBERT model needs the image built with
  `--build-arg WITH_CODEBERT=1`.

`model.json` sits next to the joblib file, or `cloudsentinel.json` inside the folder. It holds the name,
version, threshold, training-data summary, metrics and limitations. The SHA-256 of the model file (for
a folder, its weights file) is computed at startup. The backend records it as scan provenance.

Without a model the service is **untrained**: `/scan` returns no findings and `/model-info` says
`status: "untrained"`. Model files are mounted at runtime and are never committed.

## Reproduce the model

Everything runs from `services-ml/ml-sast/`. The `.venv/`, `data/` (except the manifest, samples and
held-out labels), `models/`, `logs/`, `checkpoints/` and `.hf/` directories are gitignored.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-train.txt
# CrossVul (Zenodo 4734050, 367 MB) -> data/raw/crossvul/extracted/ ; held-out apps -> data/heldout/<app>/ (see data/heldout/LABELS.md)
.venv/bin/python scripts/build_dataset.py            # CrossVul + synthetic -> data/processed/{train,val,test}.jsonl, data/manifest.json
.venv/bin/python scripts/build_heldout.py            # held-out apps + labels.json -> data/processed/heldout.jsonl
.venv/bin/python scripts/train_classic.py            # LR, RF, LightGBM -> models/{lr,rf,lgbm}.joblib
.venv/bin/python scripts/train_codebert.py > logs/codebert.stdout 2>&1 &   # CPU fine-tune with checkpoints; rerun to resume
.venv/bin/python scripts/train_codebert_xgb.py       # frozen CodeBERT embeddings + XGBoost
.venv/bin/python scripts/eval_sast.py                # reports/{comparison.md,csv,json}, per-model JSON + confusion PNGs
.venv/bin/python scripts/package_model.py            # best by held-out macro-F1 -> models/release/
```

v2 adds a development/fresh evaluation protocol, OSV data and the hybrid. Since v2, `data/heldout/` is
the **development** set and `data/fresh/` is the frozen fresh held-out set.

```bash
.venv/bin/python scripts/build_heldout.py --set heldout                  # development set (4 apps)
.venv/bin/python scripts/build_heldout.py --set fresh                    # fails unless it matches data/fresh/FREEZE.json
.venv/bin/python scripts/secrets_dev_report.py                           # rule-based secrets detector on dev
# OSV dumps (npm/all.zip, PyPI/all.zip from osv-vulnerabilities) -> data/raw/osv/
GH_TOKEN=... .venv/bin/python scripts/collect_osv.py --deadline-minutes 150 --max-gb 5
.venv/bin/python scripts/build_dataset.py --with-osv                     # CrossVul + OSV + synthetic
.venv/bin/python scripts/osv_noise_sample.py                             # 50-row manual label-noise check
MODELS_DIR=models/v2 .venv/bin/python scripts/train_classic.py lr rf lgbm
.venv/bin/python scripts/tune_v2.py --tag step4 --models-dir models/v2 --out hybrid_step4 --baseline models/release/model.joblib
.venv/bin/python scripts/package_v2.py --hybrid models/hybrid_step4.joblib --tag step4
.venv/bin/python scripts/eval_fresh_final.py --v1 models/release/model.joblib --v2 models/release_v2/model.joblib   # once only
.venv/bin/python scripts/package_v2.py --hybrid models/hybrid_step4.joblib --tag step4 --with-fresh
```

## Run

```bash
pip install -r requirements.txt
MODEL_PATH=models/release_v2/model.joblib uvicorn app:app --port 8001     # backend: ML_SAST_URL=http://localhost:8001

docker build -t cloudsentinel/ml-sast services-ml/ml-sast
docker run --rm -p 8001:8001 -v "$PWD/services-ml/ml-sast/models/release_v2:/models/ml-sast:ro" cloudsentinel/ml-sast
```

Tests: `.venv/bin/python -m pytest tests` (extractor, features, `/scan`, `/model-info`).
