# Model card: ml-sast 3.0.0 (`ml-sast-v3-ensemble`): deployed

**Status (2026-11-22): v3 is the deployed model.** Port 8001 serves `ml-sast-v3-ensemble` 3.0.0
(sha256 `f28cc42baae8fcd8473c9603a0ac4a112bfede4c24969c8d03ed0f2ad30c954f`), from
`services-ml/ml-sast/models/release_v3`. v3 passed the pre-registered held-out rule and the switch was approved by
the project owner. v2 (`ml-sast-hybrid` 2.0.0, sha256 `00fe69cf…`) is kept for rollback.

**Checks before the switch.**
- v3 was first started on spare port 8011: `/model-info` returned the right name, version and hash, and the
  service tests passed (21).
- e2e through a backend pointed at 8011:
  - `python-clean`: pipeline completed, SAST 0 findings, gate passed.
  - `demo-forms`: SAST 2 CRITICAL + 4 HIGH (SQL injection, XSS), gate blocked. This is expected for the
    deliberately vulnerable app; v2 also blocked it, with 8 findings.
- After the switch, the same e2e through the backend on port 3000 gave identical results.

**Timing (CPU, measured on port 8011).**

| | Scan time |
|---|---|
| Fixed cost per scan (CodeBERT is loaded on each scan) | about 3–5 s |
| Short functions (about 100 tokens) | about 0.14 s each |
| Functions at the 256-token cap | about 0.26 s each |
| v2 | about 1 s per 1,000 functions |

| Limit | Short functions | Full-length functions |
|---|---|---|
| 300 s (old default `ML_SAST_TIMEOUT_MS`) | about 2,100 | about 1,100 |
| 1,800 s (now set in `backend/.env`; same as the orchestrator's stage timeout) | about 12,600 | about 6,800 |

The e2e apps (one source file each) took 4–6 s per SAST stage. Larger repositories past these counts time out
(`ML_SERVICE_TIMEOUT`).

**Running it offline.**
- CodeBERT (`microsoft/codebert-base`, about 480 MB) is read from the local Hugging Face cache
  `HF_HOME=/mnt/d/cs-data/hf-cache` on D:; nothing is cached under `~/.cache` on C:.
- The service runs with `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1` and the HTTP(S) proxy set to a dead local port,
  so any download attempt fails instead of reaching the network. Scans succeed under these settings, and the process
  opened no outgoing connections.

**Start command (v3 on 8001).** `scripts/start-stack.sh` starts the whole stack with these settings; v3 alone:
```bash
cd ~/cs-sast && ML_SAST_MODEL_DIR=$HOME/cs-sast/services-ml/ml-sast/models/release_v3 ML_SAST_PORT=8001 \
  HF_HOME=/mnt/d/cs-data/hf-cache HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
  HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 TMPDIR=/mnt/d/cs-data/tmp \
  setsid nohup scripts/run-ml-sast.sh < /dev/null > services-ml/ml-sast/logs/v3-8001.log 2>&1 &
```

**Rollback to v2.** Same command line and model files as before the switch; no backend restart is needed.
```bash
pkill -f 'uvicorn app:app --host 127.0.0.1 --port 8001'; cd ~/cs-e2e/services-ml/ml-sast && MODEL_PATH=$HOME/cs-e2e/services-ml/ml-sast/models/release_v2/model.joblib MODEL_META_PATH=$HOME/cs-e2e/services-ml/ml-sast/models/release_v2/model.json setsid nohup $HOME/cs-sast/services-ml/ml-sast/.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8001 < /dev/null > ~/ml-sast-v2-8001.log 2>&1 &
curl -s localhost:8001/model-info   # expect ml-sast-hybrid 2.0.0
```

**Node.js evidence is inconclusive.** On the Node.js held-out (4 apps, 137 units, only 19 vulnerable), v3 − v2
macro-F1 is +0.173 with a 95% CI of [−0.005, +0.290], which includes zero. The deployment decision rests on the
combined held-out sets, where Python (660 units) dominates. For Node.js projects, treat v3 as not proven better than
v2.

**What it is.** Every scan runs three models on each function: (A) a Random Forest over v2's features (TF-IDF code
tokens, 31 security features, a language flag), (B) LightGBM on the same features, and (C) frozen CodeBERT embeddings
with XGBoost. A function is reported for a class only if **2 of the 3** agree (rule R2). Hard-coded secrets (CWE-798)
come from the rule-based detector, as in v2. Every finding names the agreeing models (`models_agree`).

**Held-out result** (RealVuln, scored once; 797 units, 151 vulnerable):

| | v2 (previous) | v3 (deployed) |
|---|---|---|
| Macro-F1 [95% CI] | 0.544 [0.471, 0.605] | **0.653 [0.587, 0.705]** |
| Precision / recall (vulnerable vs safe) | 0.511 / 0.589 | **0.605 / 0.629** |
| v3 − v2 | | **+0.109 [+0.053, +0.167]** |

- **Per language:** Python (660 units) +0.110 [+0.043, +0.175]; Node.js (137 units, 19 vulnerable)
  +0.173 [−0.005, +0.290].
- **Per class:** v3 is better on CWE-22, 78, 89, 798 and 79, about level on CWE-502 (worse on Python alone), and
  slightly worse on CWE-327.

**The development set disagrees.** On development (NodeGoat, DVNA, vulpy, PyGoat; 439 units) v2 scores 0.642 and v3
0.571 (−0.082 [−0.180, +0.022]). v2's thresholds were tuned on that same set, which favours v2 there; v3 never saw it.
The held-out sets were never used by either model.

**Data:** 9,313 training+validation rows (v2: 5,347), from CrossVul, OSV, CVEfixes, JsVul, PyVul, GitLab rule tests
and synthetic data (48.3% of training). See `docs/ml-sast-data-inventory.md`.

**Limitations:**
- **Speed:** frozen CodeBERT on CPU makes scans about 140–260 s per 1,000 functions (v2: about 1 s); see Timing
  above for where the backend timeout is reached. The service needs the CodeBERT weights (about 480 MB) in its
  Hugging Face cache.
- **Thin real data:** CWE-89, 78 and 502 still have about 120–180 real training rows (the 300 target was missed).
- **Small Node.js held-out:** 4 apps, 19 vulnerable units.
- **Label noise:** the new sources' samples show 2–16% wrong labels (one reviewer).
- **Unmapped findings:** 46 Python and 9 Node.js held-out findings in templates or config files are not unit-mappable
  and are not scored.

Full report: `docs/ml-sast-v3-final-report.md`.

---

# Model card: ml-sast 2.0.0 (`ml-sast-hybrid`)

Function-level vulnerability detector for the CloudSentinel `ml-sast` service (`SAST_ENGINE=ml`).
v2 is a **hybrid**:

- **Machine learning:** a Random Forest over code features. It covers SQL injection, XSS, command
  injection, path traversal, insecure deserialization, weak crypto and, as a second signal, secrets.
- **Rule-based secrets detector** for CWE-798 hardcoded credentials (`sastml/secrets.py`). It is
  deterministic regex rules, **not machine learning**.

**SonarQube stays the default SAST engine.** On a fresh set of three apps, scored once, v2 finds about
two thirds of the vulnerable functions with about one finding in three correct. Without the
rule-based secrets part it is still not good enough to be a pipeline gate.

| | |
|---|---|
| Artifact | `services-ml/ml-sast/models/release_v2/model.joblib` (gitignored), metadata in `model.json` |
| SHA-256 | `00fe69cfc62abd9d…` (full value in `/model-info` and `reports/v2/fresh_preregistration.json`) |
| ML component | Random Forest (400 trees, `max_depth=40`, `min_samples_leaf=2`, balanced class weights) over TF-IDF code tokens, 31 hand-made security features and a language flag, retrained on the v2 data. The RF+LightGBM ensemble weight was tuned and came out at RF only (`weight_rf=1.0`) |
| Rule-based component | `sastml/secrets.py`: known key formats (0.95), secret-named assignments, `env \|\| "literal"` fallbacks, literal secrets passed to `jwt.sign`/`createCipheriv`-style calls (0.85) and credentials in URLs (0.8). Mode `union`: a unit is CWE-798 if the rules fire **or** the ML's CWE-798 score passes its threshold |
| Decision rule | Per-class thresholds tuned on the development set: CWE-89 0.20, CWE-79 0.35, CWE-78 0.35, CWE-22 0.40, CWE-798 0.25, CWE-502 0.35, CWE-327 0.25. `ML_SAST_CONFIDENCE_THRESHOLD` overrides all of them |
| Output | One finding per (function, class) that passes. Rule-based findings have rule `<lang>.hardcoded-credentials.rule` and a message starting `[rule-based secrets detector]`; in CloudSentinel they are stored as `ml:<lang>.hardcoded-credentials.rule:CWE-798`. `/model-info` lists both components under `components` (`ml`: `machine-learning`, `secrets`: `rule-based`) |
| Targets | Python and JavaScript (`.py .js .mjs .cjs .jsx`), one prediction per function, plus one for top-level code (`<module>`) |
| Classes | `safe`, CWE-89, CWE-79, CWE-78, CWE-22, CWE-798, CWE-502, CWE-327 |
| Previous | v1 (`ml-sast-rf` 1.0.0, SHA-256 `f8a6c545…`), see [v1 results](#v1-results-for-reference) |

## What changed from v1

1. **Fresh held-out set.** Three new apps were labelled, then hashed and frozen before any v2 work:
   django.nV, dvws-node and vulnerable-node (`data/fresh/`). They were scored **exactly once**, at the
   end. The four v1 held-out apps (NodeGoat, DVNA, vulpy, PyGoat) became the **development set**, used
   for tuning.
2. **Development label corrections.** The secrets detector exposed 8 real, unlabelled hardcoded
   secrets in the development apps: five PyGoat `app.secret_key` literals, two PyGoat sec_misconfig
   token functions, and a NodeGoat test-config key. These were added as labels, and one false label was excluded. v1 is
   rescored on the corrected labels, so its development numbers here (0.494) differ slightly from the
   v1 card (0.498). The labels were corrected with the detector's help, so **its development CWE-798
   score is optimistic**. The fresh set is the honest measure.
3. **Rule-based secrets detector** for CWE-798, plus per-class thresholds and an RF+LightGBM ensemble
   weight, all tuned on the development set only.
4. **OSV advisory data.** GitHub-reviewed npm and PyPI advisories that map to exactly one target class
   were traced to their GitHub fix commits, giving 1,774 function-level before/after rows. See Data.
5. **CodeBERT was NOT retrained on the v2 data.** The CodeBERT and CodeBERT+XGBoost numbers below
   are from v1 and are not comparable with the v2 rows.

## Data

The full counts are in `services-ml/ml-sast/data/manifest.json`.

| Source | What | Rows (train / val / test) |
|---|---|---|
| CrossVul (Zenodo 4734050) | Real fix commits: each changed Python/JS function gives a vulnerable "before" row and a safe "after" row | 665 / 139 / 138 |
| **OSV advisories (new)** | `osv-vulnerabilities` npm and PyPI dumps. Fix commits from GitHub-reviewed advisories mapping to exactly one target class, with filters (below) | 1,241 / 267 / 266 |
| Synthetic (`sastml/synthetic.py`) | 66 template families, rendered as vulnerable/safe pairs | 1,956 / 1,079 / 1,160 |

**OSV collection filters** (`scripts/collect_osv.py`):
- Malicious-package (`MAL-`) and withdrawn advisories are skipped.
- Only advisories that map to exactly one target CWE are kept.
- Only GitHub commit references are used.
- Merge and root commits are dropped, and so are commits touching more than 5 non-test source files.
- A changed function is kept only if the class's sink pattern appears in its removed or added lines.
  For CWE-798, the secrets rules must match the removed lines.
- At most 20 pairs per repository.
- Commits already in CrossVul are dropped, and so is every repository of a development or fresh app.

**Funnel and drops:**
- The 2,483 mapped commits, from 1,005 repositories, produced 1,940 rows.
- `build_dataset.py` then dropped 171 duplicates and 219 rows whose normalized code appeared with
  conflicting labels.
- Near-duplicates of development or fresh units (5-shingle Jaccard ≥ 0.8) were also checked for and
  dropped; none were found.
- The v1 repository-to-split assignment is frozen (`data/processed/v1_group_assignment.json`), so v1
  test groups stay in test. No group appears in two splits.

**OSV label noise.** I reviewed 50 randomly sampled vulnerable OSV rows (seed 2026) by hand; there was
no second reviewer. The criterion: does the pre-fix function visibly contain the labelled CWE pattern?

| Verdict | Rows |
|---|---|
| Correct | 41 |
| Weak (CWE right, but the sink is outside the function, e.g. input sanitized where it is stored) | 5 |
| Wrong | 4 |

**Estimated noise: 8% strict (95% Wilson interval 3–19%), or 18% counting weak rows (10–31%).**
Details are in `data/osv_noise_check.json`.

**Real training rows per class (CrossVul + OSV):**

| Class | v1 | v2 | Status |
|---|---|---|---|
| CWE-89 | 40 | 78 | |
| CWE-79 | 213 | 436 | |
| CWE-78 | 33 | 117 | |
| CWE-22 | 33 | 220 | |
| CWE-798 | 0 | **1** | ML part synthetic only; the **rule-based** detector carries this class |
| CWE-502 | 9 | 85 | |
| CWE-327 | 4 | **15** | still mostly synthetic |

## Results

Macro-F1 is taken over the classes present in each set. "Vuln P/R" means vulnerable-vs-safe precision
and recall, ignoring which CWE. Intervals are 95% bootstrap intervals (1,000 resamples).

Some units have more than one acceptable CWE (for example a hardcoded key used for weak crypto). A
prediction of any acceptable class counts as correct, and that unit's support goes to the class the
system predicted. Per-class support can therefore differ by one or two between systems.

### Development set (NodeGoat, DVNA, vulpy, PyGoat; 439 units, 56 vulnerable): tuned here, optimistic

| System | macro-F1 | Vuln P / R | Code-visible macro-F1 |
|---|---|---|---|
| v1 RF (shipped 1.0.0) | 0.494 (0.366–0.604) | 0.31 / 0.30 | 0.545 |
| v2 ML part only | 0.523 (0.409–0.615) | 0.35 / 0.43 | 0.573 |
| **v2 hybrid (ML + rule-based secrets)** | **0.642 (0.549–0.737)** | **0.52 / 0.88** | 0.707 |

Per class, F1 before (v1) and after (v2 hybrid), with support:

| Class | v1 | v2 | Support |
|---|---|---|---|
| safe | 0.90 | 0.93 | 383 |
| CWE-89 | 0.27 | 0.36 | 6 |
| CWE-79 | 0.14 | 0.19 | 5 (all template-sink) |
| CWE-78 | 1.00 | 1.00 | 2 |
| CWE-22 | 0.33 | 0.50 | 1 |
| CWE-798 (**rule-based** in v2) | 0.06 | 0.98 | 30 |
| CWE-502 | 0.67 | 0.55 | 4 |
| CWE-327 | 0.57 | 0.62 | 8 |

**Bootstrap differences:**
- v2 hybrid − v1: **+0.156 (+0.065 to +0.255)**.
- v2 ML part only − v1: **+0.027 (−0.069 to +0.125), not significant**. On the development set, the
  OSV data and retraining did not measurably improve the ML part. Most of the gain comes from the
  rule-based secrets detector.
- The secrets rules alone, on development: 29 true positives, 0 false positives, 1 false negative
  (`reports/v2/secrets_dev.json`).
- On safe code they fire on 1 of 402 real safe rows and on 0 of 1,716 synthetic ones (v1 splits).

**Final system choice.** An intermediate hybrid built on the v1 models scored 0.637 on development
and 0.406 on the real-code test split. The v2 hybrid scored 0.642 and 0.487. The choice was written
down before the fresh set was scored (`reports/v2/selection.json`).

### Test split (v2 split; groups never seen in training)

| Set | n | v1 RF | v2 hybrid |
|---|---|---|---|
| Test, all (mostly synthetic) | 1,564 | 0.717 | 0.721 |
| Test, real (CrossVul + OSV) | 404 | 0.367 | **0.487** |

On real test code the biggest per-class gains are CWE-502 (0.44 → 0.78), CWE-89 (0.20 → 0.53) and
CWE-22 (0.24 → 0.44).

### Fresh held-out set: single final run

django.nV, dvws-node and vulnerable-node, frozen in `data/fresh/FREEZE.json`. Both systems were fixed
by SHA-256 in `reports/v2/fresh_preregistration.json` before any prediction was made. The script
refuses a second run. There are 312 scored units, 35 of them vulnerable. vulnerable-node's
`sast/seeds/` files are small deliberately vulnerable snippets, so views with and without them are
reported, all from the same run.

| View | n (vuln) | v1 macro-F1 | v2 macro-F1 | v2 − v1 | v1 Vuln P / R | v2 Vuln P / R |
|---|---|---|---|---|---|---|
| All | 312 (35) | 0.503 (0.328–0.621) | **0.592 (0.431–0.680)** | +0.097 (−0.024 to +0.213) | 0.31 / 0.49 | 0.32 / 0.66 |
| Code-visible | 309 (32) | 0.505 (0.333–0.627) | 0.595 (0.443–0.689) | +0.098 (−0.011 to +0.216) | 0.31 / 0.53 | 0.32 / 0.72 |
| Without seeds | 280 (20) | 0.275 (0.203–0.441) | 0.423 (0.292–0.539) | +0.112 (−0.086 to +0.221) | 0.17 / 0.35 | 0.19 / 0.50 |
| App code only | 277 (17) | 0.315 (0.239–0.533) | 0.494 (0.359–0.630) | +0.136 (−0.090 to +0.263) | 0.17 / 0.41 | 0.19 / 0.59 |

v2 is ahead in every view, **but no difference is statistically significant**: every interval
includes zero. The fresh set is small.

Per class, all fresh units, P / R / F1 (support):

| Class | v1 | v2 |
|---|---|---|
| safe | 0.93 / 0.87 / 0.90 (277) | 0.95 / 0.82 / 0.88 (277) |
| CWE-89 | 0.67 / 0.75 / 0.71 (8) | 0.35 / 1.00 / 0.52 (8) |
| CWE-79 | 0.07 / 0.33 / 0.12 (6) | 0.08 / 0.33 / 0.12 (6) |
| CWE-78 | 0.43 / 1.00 / 0.60 (3) | 0.50 / 1.00 / 0.67 (3) |
| CWE-22 | 0.38 / 0.43 / 0.40 (7) | 0.22 / 0.29 / 0.25 (7) |
| CWE-798 (**rule-based** in v2) | 1.00 / 0.25 / 0.40 (4) | 1.00 / 1.00 / 1.00 (5) |
| CWE-502 | 1.00 / 0.33 / 0.50 (3) | 1.00 / 0.33 / 0.50 (3) |
| CWE-327 | 1.00 / 0.25 / 0.40 (4) | 1.00 / 0.67 / 0.80 (3) |

**Reading these results:**
- The rule-based secrets detector is the clearest gain.
- The lower CWE-89 threshold (0.20) raises recall but costs precision.
- CWE-22 is worse than v1.
- Vulnerable precision stays low, at about 0.32: roughly two of three findings are false alarms.

### Model comparison

| Model | Trained on | dev (all) | test (real) | Notes |
|---|---|---|---|---|
| **v2 hybrid (RF + rule-based secrets)** | v2 | **0.642** | **0.487** | selected |
| v2 ML part only (RF, per-class thresholds) | v2 | 0.523 | n/a | |
| v1 RF (1.0.0) | v1 | 0.494 | 0.367 | |
| LR (v2 retrain) | v2 | n/a | n/a | val 0.660; tuning grid covered RF/LightGBM only |
| LightGBM (v2 retrain) | v2 | n/a | n/a | val 0.680; given weight 0 by the ensemble tuning |
| CodeBERT fine-tuned | **v1, not retrained** | 0.458 (v1 labels) | 0.391 (v1 split) | v1 numbers |
| CodeBERT embeddings + XGBoost | **v1, not retrained** | 0.200 (v1 labels) | 0.177 (v1 split) | v1 numbers |

### Comparison with SonarQube

**TODO, not measured.** No SonarQube results exist for these apps at the pinned commits, so no Sonar
numbers are reported.

## Intended use

- **Intended:** an experimental, opt-in second opinion for Python and JS repositories in CloudSentinel
  (`SAST_ENGINE=ml`), and a baseline for further ML SAST work.
- **Not intended:** replacing SonarQube as the blocking SAST gate, any language other than Python or
  JavaScript, or certifying code as secure.

## Limitations

1. **CWE-798 is rule-based.** Findings marked `.rule` / `[rule-based secrets detector]` come from
   deterministic rules, not ML. The rules catch literals in assignments, fallbacks, calls and URLs,
   but miss secrets with neutral names. Its development score is optimistic because the development
   labels were corrected with its help.
2. **Granularity.** It works per function and reports the function's start line, not the sink line.
   There is no inter-procedural or cross-file taint tracking.
3. **Template sinks.** XSS whose sink is in a template (`|safe`, `<%- %>`, autoescape off) is
   essentially invisible. CWE-79 F1 is about 0.1 on every held-out set.
4. **Sparse real data.** CWE-327 has 15 real training rows, and the ML part of CWE-798 has 1.
5. **Low precision on real code.** About two thirds of vulnerable findings on the fresh apps are
   false alarms.
6. **Tuned on the development set.** Thresholds, the ensemble weight and the secrets rules were all
   tuned there, so development scores are optimistic.
7. **CodeBERT was not retrained on the v2 data.**
8. **Coverage.** Minified files, files over 512 KB, TypeScript and Python files that don't parse
   yield no units.

## Threats to validity

- **Small evaluation sets.** The fresh set has 35 vulnerable units, with 3–8 per class, so per-class
  numbers can swing a lot on one function. All v2 − v1 fresh intervals include zero.
- **One labeller.** The development and fresh labels, and the OSV noise check, all come from one
  reviewer.
- **Development labels changed after seeing detector output.** The changes are documented in
  `data/heldout/LABELS.md` and v1 was rescored on the same labels, but development CWE-798 is
  optimistic.
- **OSV label noise:** about 8–18% (see Data). Fix commits often touch the function that sanitizes
  input rather than the one containing the sink.
- **Teaching apps.** All held-out apps are deliberately vulnerable teaching code, and the seeds in
  vulnerable-node are minimal snippets. Production code may behave differently.

## v1 results (for reference)

v1 (`ml-sast-rf` 1.0.0) was trained on CrossVul + synthetic data, with the four development apps as
its held-out set:
- held-out macro-F1 0.498 (0.371–0.610), vuln P/R 0.31 / 0.35;
- test 0.750; test-real (CrossVul) 0.366.

LR, LightGBM and CodeBERT were statistically tied with it on held-out data. The full v1 reports are in
`services-ml/ml-sast/reports/` (`comparison.md`, `heldout_bootstrap.json`).

## Reproduce

See [`services-ml/ml-sast/README.md`](../services-ml/ml-sast/README.md#reproduce-the-model).

- v2 reports: `services-ml/ml-sast/reports/v2/`.
- OSV collection took about 16 minutes with a GitHub token.
- The classic models retrain in about 10 minutes on 8 CPU threads.
