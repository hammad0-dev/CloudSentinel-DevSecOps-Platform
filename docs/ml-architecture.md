# ML scan engines: architecture

CloudSentinel can run SAST and the baseline DAST stage on trained ML services instead of SonarQube
and ZAP. Targets are Python and Node.js apps only. SonarQube and ZAP remain the default until the ML
engines pass evaluation.

- **ml-sast** has a trained model: `ml-sast-hybrid` 2.0.0 (`models/release_v2/`). It combines a
  function-level Random Forest with a **rule-based** secrets detector for CWE-798. On a fresh set of
  three apps, scored once, it reaches 0.59 macro-F1 against 0.50 for v1 (`ml-sast-rf` 1.0.0), but
  that difference is not statistically significant. Vulnerable precision is about 0.32, so it is not
  yet good enough to replace SonarQube as the gate. Rule-based findings are marked: rule suffix
  `.rule`, and `/model-info` → `components.secrets.type: "rule-based"`. See
  [ml-sast-model-card.md](ml-sast-model-card.md).
- **ml-dast** has no trained model yet.

## Selection

| Flag | Values | Default | Effect |
|---|---|---|---|
| `SAST_ENGINE` | `sonar`, `ml` | `sonar` | `POST /api/sast/scan/:projectId` uses SonarQube or `ml-sast` |
| `DAST_ENGINE` | `zap`, `ml` | `zap` | `POST /api/dast/scan/:projectId` (baseline path) uses ZAP or `ml-dast` |

Any other value fails the stage with a clear error. Active DAST is unaffected.

## Flow

```mermaid
flowchart LR
  O[Orchestrator] -->|POST /api/sast/scan| S[SAST route]
  O -->|POST /api/dast/scan| D[DAST route]
  S -->|SAST_ENGINE=sonar| SQ[SonarQube]
  S -->|SAST_ENGINE=ml| MS[ml-sast /scan]
  D -->|DAST_ENGINE=zap| Z[ZAP baseline]
  D -->|DAST_ENGINE=ml| MD[ml-dast /scan]
  SQ & MS --> P1[persistSastEvidence: scan_history + scan_results]
  Z & MD --> P2[persistCompletedScan: dast_scans + dast_findings]
  P1 & P2 --> G[Gate + governance + UI, unchanged]
```

**SAST (`ml`)**

1. The route creates the `scan_history` row, clones the repository, and calls `runMlSast`.
2. The backend reads `/model-info`. An untrained model is refused (see below).
3. It collects `.py .js .mjs .cjs .jsx .ts .tsx` files. It skips `node_modules`, virtualenvs, build
   output, symlinks, binaries, and files over `ML_SAST_MAX_FILE_BYTES`. Repos over the size limits fail
   instead of being partly scanned.
4. It records `scan_engine='ml'` and `tool_provenance` on the scan row, then posts `{files}` to `/scan`.
5. It validates every finding: the severity scale, that the file is one of the submitted files, the
   line number, the CWE, and the confidence.
6. Each finding becomes a `VULNERABILITY` issue with rule `ml:<rule>:CWE-<n>`. The CWE goes into the
   rule because governance derives SAST references from the rule. The issue is persisted through the
   same transactional `persistSastEvidence` the SonarQube engine uses. The orchestrator gate counts
   `scan_results` exactly as before: CRITICAL and HIGH vulnerabilities block.

**DAST (`ml`)**

1. The backend authorizes the target with the same `authorizeTarget` the ZAP scanner uses: the
   verified staging deployment for pipeline runs, or an owner-configured target for manual runs.
2. It creates a `dast_scans` row with `scan_mode='BASELINE'`.
3. It reads `/model-info`, then posts `{baseUrl, maxPages, maxRequests}` to `/scan`.
4. Findings get the same `fingerprint()` as ZAP findings, are de-duplicated, and are persisted with
   `persistCompletedScan`, which re-verifies the counts and fingerprints.
5. Any failure marks the row `FAILED` with the message in `failure_reason`.

## Provenance

Each ML scan row stores:

- `scan_engine = 'ml'`.
- `tool_provenance`:
  - `tool`: `"<model name> <version> sha256:<SHA-256 of the model file>"`.
  - `model`: name, version, sha256, trainedOn, metrics.
  - Input facts. For SAST: file count, skipped count, and an input digest. For DAST: page and
    request bounds.
- For DAST, `policy_name` and `policy_version` hold the model name and version.

Migration: `backend/migrations/023_scan_engine_provenance.sql`. Without it, ML scans fail with a
message that names the migration. The default engines do not need it.

Provenance-bound STATIC_HTML executions (`PIPELINE_PROVENANCE_ENABLED`) attest Sonar- and ZAP-specific
evidence: a quality gate and a pinned ZAP image. ML engines refuse those executions with
`ML_ENGINE_PROVENANCE_UNSUPPORTED` rather than attesting something weaker.

## Safety rules

- **Untrained models.**
  - Both services answer with an empty findings list and `status: "untrained"`. They never
    invent detections.
  - The backend refuses to complete a scan with an untrained model (`ML_MODEL_UNTRAINED`), because
    an empty result would pass every gate.
  - `ML_ALLOW_UNTRAINED=true` allows it, for plumbing tests only.
- **Unreachable or slow service.**
  - Every call has a timeout: `ML_SAST_TIMEOUT_MS` (default 300 s) and `ML_DAST_TIMEOUT_MS`
    (default 1800 s).
  - On failure the stage fails with the service URL and the cause, for example
    `ML SAST service at http://localhost:8001 is unreachable (ECONNREFUSED)`. The orchestrator
    retries once, as it does for every stage.
- **The ML DAST service scans whatever it is given.** Keep it reachable only from the backend.

## Services

`services-ml/ml-sast` and `services-ml/ml-dast` are FastAPI apps. Each has `GET /health`,
`GET /model-info` and `POST /scan`.

- A model is a joblib artifact mounted at `MODEL_PATH`, with metadata JSON next to it. Its interface
  is described in each service README.
- Model files are never committed; `.gitignore` blocks common model formats.
- Training code belongs in `/ml`.

## Running locally

```bash
cd services-ml/ml-sast && pip install -r requirements.txt && uvicorn app:app --port 8001
cd services-ml/ml-dast && pip install -r requirements.txt && uvicorn app:app --port 8002
psql -d cloudsentinel -f backend/migrations/023_scan_engine_provenance.sql
# backend/.env: SAST_ENGINE=ml DAST_ENGINE=ml ML_SAST_URL=http://localhost:8001 ML_DAST_URL=http://localhost:8002
```

Tests: `cd backend && npm run test:ml`, and `pytest` in each service directory.
