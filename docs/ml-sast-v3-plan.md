# ml-sast v3: plan (Python + Node.js)

Branch `feat/ml-sast-v3` (from origin/master). The deployed v2 (`ml-sast-hybrid` 2.0.0, port 8001,
`models/release_v2`, sha256 `00fe69cf…`) is not touched. v3 is packaged as `models/release_v3`. It is deployed only
if the pre-registered rule passes **and** you approve.

**Resuming.** Every stage ends with a commit; `git log` on this branch shows the last finished stage. Downloads
resume (`scripts/v3/download.sh` uses `curl -C -`). Processed outputs refuse to overwrite.

## Disk rules (from the brief)

- **Locations:** everything external goes under `/mnt/d/cs-data/sast-v3/` (work files in `work/`). `HF_HOME`,
  `TMPDIR` and `PIP_CACHE_DIR` point to `/mnt/d/cs-data/*`. Nothing is cached or extracted to `~/` or `/tmp` on C:.
- **Free-space check:** before each download and extraction (`df -h /mnt/c /mnt/d`). Stop if C: drops below 15 GB
  or D: below 60 GB.
- **Data is untrusted:** never executed; Python that reads it runs with `python -I`; scripts live in the repo, never
  in the data directories.
- **Backup** before any change: `/mnt/d/ml-backup/pre-sast-v3/`, data 2.1 GB and models 1.5 GB, 29,037 files,
  verified with `du -sh` and a file count.

## Sources: verified sizes and licences

| # | Source | What | Size | Licence (as published) | Status |
|---|---|---|---|---|---|
| 1 | PyVul (`billquan/PyVul` @ `1172bfd`) | function-level fix pairs from Python package advisories (`dataset/function_level_dataset.out`, sha256 `73eb0e3c…`) | 21.7 MB | **none stated**: research use with attribution (limitation) | downloaded |
| 2 | JsVul (Zenodo 18195839 v1.0.0; code `jsvul/jsvul` @ `036c7f7`) | `js_vul.zip`, `js_vul_pairs_only.zip`, `merged_data.zip` | 9.3 MB + 1.9 MB + 726 MB, MD5s verified | **CC BY 4.0** on the Zenodo record (the brief expected none) | downloaded |
| 3 | SALVE JS/TS (`salve-research/salve-js-vuln-dataset`, `salve-core-le9-v2.jsonl`) | Hugging Face dataset | — | — | **skipped**: gated, needs a Hugging Face account and accepted terms. **Manual download needed** |
| 4a | Semgrep rule tests (`semgrep/semgrep-rules`) | ruleid/ok test files | — | Semgrep Rules License v1.0: "only for your own internal business purposes … not … make them available to others as a service" | **skipped**: the licence does not allow training a SAST service |
| 4b | GitLab SAST rules (`gitlab-org/security-products/sast-rules` @ `83144bd`) | ruleid/ok annotated test files | 6.5 MB | **MIT** | downloaded |
| 5 | CVEfixes v1.0.8 (Zenodo 13118970) | `CVEfixes_v1.0.8.zip`, SQLite inside | 12.7 GB, publisher MD5 `4586a358…` | **CC BY 4.0** (data) | downloading (resumable) |
| 6 | MoreFixes v3 (Zenodo 20702039) | Postgres dump | — | — | **skipped**: the record was deleted (HTTP 410, removed 2026-06-25) |
| 7 | OSV (existing `scripts/collect_osv.py`) | per-repo cap raised from 20 to 50 pairs, other filters reviewed | — | as v2 | to do |

Each source directory on D: holds `SOURCE.download.txt` (URL, date, size, SHA-256, verified MD5), and `SOURCE.txt`
adds the licence text. Everything is recorded in `data/manifest.json`.

## Language scope and mapping

- **Languages:** Python and JavaScript only (`.py`, `.js`, `.mjs`, `.cjs`). TypeScript and every other language are
  dropped.
- **Server-side JS:** JS rows are kept as server-side or npm code where the metadata allows. Otherwise they are kept
  and recorded as "JavaScript, not strictly Node.js".
- **CWE mapping:** the v2 CWE map (CWE-564 → 89, CWE-80/83/87 → 79, CWE-77/88 → 78, CWE-23/35/36/73 → 22,
  CWE-259/321 → 798, CWE-328/326/916/759/760 → 327). A row is kept only if it maps to exactly one target class.
- **Rows:** a fix pair gives the function before the fix (labelled with its CWE) and after the fix (labelled safe),
  as in v2.

## Data quality

- **Deduplication:** exact (normalized code) and near-duplicate (5-token shingle Jaccard ≥ 0.8). It runs against all
  v2 train, val and test rows, the development and fresh sets, the new held-out sets, and across the new sources.
- **Kept out of training:**
  - every RealVuln repository;
  - every development, fresh and held-out repository;
  - DVPWA and every app used in DAST.

  A leakage check of the existing training data comes first (`collect_osv.py` mentions DVPWA).
- **Splits:** train, val and test are split by repository, so no repository is in two splits. The v1/v2 group
  assignment is kept.
- **Label noise:** 50 random rows per new source are checked by hand against the code and the fix. A source above
  25% errors is dropped or down-weighted.

## Synthetic data (v3)

- **New generator:** source tag `synthetic_v3`. It makes vulnerable and safe-twin pairs in Python and Node.js
  (Express, child_process, fs, mysql/pg, mongoose) for CWE-79, 22, 502, 78 and 89, varying style, framework, names and
  structure.
- **Checks:** distinct patterns per CWE are reported, the rows are deduplicated against everything, and 50 rows per
  CWE are checked by hand.
- **Never evaluated on:** synthetic rows are never in any held-out or evaluation set.
- **Share:** the total synthetic share of training stays below 50% (v2: 61% of all rows), and the exact figure is
  reported.
- **Ablation:** v3 with and without `synthetic_v3`, on the development set.

## Held-out sets (new, frozen by SHA-256 before any training, scored once)

**Source.** RealVuln Benchmark (`kolega-ai/Real-Vuln-Benchmark` @ `0152445`, Apache-2.0, ground truth v3.0.0):
- **Ground truth:** file and line findings with a primary CWE, plus false-positive traps.
- **Corpus used:** only the community, human-authored corpus. The LLM-generated apps are not real code.

**Excluded, because already used in this project:**

| Apps | Earlier use |
|---|---|
| PyGoat, vulpy, NodeGoat, DVNA | SAST development set |
| django.nV, dvws-node, vulnerable-node | SAST fresh set |
| DVPWA, DSVW, VAmPI, Juice Shop, node-api-goat, nodejs-goof | DAST data or held-outs |
| DSVPWA | read for a DAST qualification |
| XVNA | no licence |
| the React and Angular apps | browser code, not Node.js |

**Python held-out: 20 apps.** damn-vulnerable-flask-application, damn-vulnerable-graphql-application, djangoat,
dvblab, extremely-vulnerable-flask-app, flask-xss, insecure-web, intentionally-vulnerable-python-application,
lets-be-bad-guys, owasp-web-playground, python-app, python-insecure-app, pythonssti, threatbyte, vfapi,
vulnerable-api, vulnerable-flask-app (we45), vulnerable-python-apps, vulnerable-tornado-app, vulnpy.

**Node.js held-out: 4 apps**, never used anywhere in this project: ninjasworkout, vuln-node-express,
vulnerable-nodejs, VulnNodeApp. SecBench.js was considered: its ground truth is per package and exploit, not per
code location, so it cannot be scored at unit level without new labelling; not used. The Node.js set is small; that
is recorded as a limitation.

**Units and labels.** The same method as v2's fresh set:
- **Units:** functions or `<module>` blocks of the apps' source files (tests, static files, vendored code and
  `node_modules` excluded).
- **Vulnerable:** a unit is labelled with the target class of every RealVuln finding whose line range overlaps it.
- **Excluded:** a vulnerable finding outside the 7 classes excludes its unit (as v2's `exclude`).
- **Safe:** false-positive traps and every other unit.

**Licences.** Several apps have no licence. They are used only for local evaluation, never trained on, and their code
is never committed (a limitation).

**Freeze.** `data/heldout_v3/FREEZE.json`: commits, SHA-256 of the sources, labels and rows, written before any v3
training.

## Models and runtime system (pre-registered before training)

- **Base models:** exactly three, on the same v3 data:
  - **(A)** Random Forest as in v2 (TF-IDF tokens, 31 hand-made features, language flag);
  - **(B)** LightGBM on the same features;
  - **(C)** frozen CodeBERT embeddings + XGBoost (no fine-tuning).
- **Rules:** every scan runs all three; the candidate combination rules are:
  - **R1:** per-class routing (each class uses the base model with the best development F1 for it);
  - **R2:** 2-of-3 majority vote;
  - **R3:** union, with the number of agreeing models as the confidence.
- **Selection:** grouped cross-validation by repository on train+val, plus the development set. The pick is the
  highest development macro-F1 with precision not below v2's.
- **Written before training:** the candidates, the criterion and the configs go to
  `reports/v3/selection_preregistration.json`.
- **Final system:** the rule-based secrets detector (CWE-798) plus the selected rule. Each finding carries
  `models_agree` and names the agreeing models in its message. No backend or UI change.
- **Reported on the development set:** each base model, each rule, and v2 (macro-F1 with CI, per-class P/R/F1,
  training time, size, scan time per file and per 1,000 functions).
- **Held-out scoring:** only v2 and the selected v3 system are scored on the held-out sets, once.

## Decision rule (pre-registered)

**v3 replaces v2 only if, on the new frozen held-out sets:**
- v3's macro-F1 is higher than v2's;
- and its precision is not worse (binary vulnerable-vs-safe precision, as v2 reports);
- and the paired bootstrap shows the improvement is not within noise: the 95% CI of the v3 − v2 macro-F1 difference
  lies above 0.

**Otherwise:** a tie or anything unclear means v2 stays deployed and v3 is packaged only. Even a win needs your
approval before deployment. Wins and losses per class are reported.

## Stages (each ends with a commit)

| Stage | Work |
|---|---|
| 0 | Setup, backup, downloads, this plan |
| 1 | Leakage check of the v2 data (DVPWA and the held-out apps), held-out labels and freeze |
| 2 | Process the new sources (PyVul, JsVul, GitLab rules, CVEfixes, OSV extension), with language/CWE counts before and after filtering |
| 3 | Dedup, splits, 50-row noise checks per new source, manifest |
| 4 | `synthetic_v3` generator, checks, share |
| 5 | Pre-registration, then training A/B/C, the rules on the development set, the ablation |
| 6 | Single held-out scoring (v2 and the selected v3), decision |
| 7 | Package `release_v3`, docs (model card, data inventory, final report, traceability), backup, PR |
