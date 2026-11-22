# ml-sast v3: final report

Branch `feat/ml-sast-v3`. Plan: [`ml-sast-v3-plan.md`](ml-sast-v3-plan.md); data:
[`ml-sast-data-inventory.md`](ml-sast-data-inventory.md); model card: [`ml-sast-model-card.md`](ml-sast-model-card.md).

**Decision: v3 passed the pre-registered held-out rule.** On the frozen RealVuln sets, macro-F1 rose from 0.544 to
0.653 (+0.109 [+0.053, +0.167]) and precision from 0.511 to 0.605. **It is not deployed**: the brief requires your
approval first. Port 8001 still serves `ml-sast-hybrid` 2.0.0. v3 is packaged as `models/release_v3`.

## 1. Data sources, downloads and skipped sources

| Source | Download (verified) | Licence | Status |
|---|---|---|---|
| PyVul (`billquan/PyVul` @ `1172bfd`) | 54 MB repo; function file 21.7 MB, sha256 `73eb0e3c…` | none stated (research use with attribution) | used, weight 0.5 |
| JsVul (Zenodo 18195839) | 9.3 MB + 1.9 MB + 726 MB, publisher MD5s verified | CC BY 4.0 (Zenodo record) | used (fix pairs only) |
| GitLab sast-rules (@ `83144bd`) | 6.5 MB | MIT (repo), LGPL (`rules/lgpl*`) | used |
| CVEfixes v1.0.8 (Zenodo 13118970) | 12.71 GB zip, publisher MD5 `4586a358…` verified, sha256 `6acd55aa…` | CC BY 4.0 | used, after quality filters |
| OSV (v2 collector, relaxed) | GitHub API | as v2 | used, weight 0.5 |
| SALVE JS/TS (Hugging Face) | — | — | **skipped: gated** (needs an account and accepted terms). Please download `salve-core-le9-v2.jsonl` manually if you want it |
| Semgrep rule tests | — | Semgrep Rules License v1.0: internal business use only | **skipped: the licence does not allow it** |
| MoreFixes v3 (Zenodo 20702039) | — | — | **skipped: the record was deleted** (HTTP 410, 2026-06-25) |

**How CVEfixes was processed.** It was streamed from its SQL dump twice (zip → pigz → SQLite's own parser) into a
filtered SQLite file on D:, with no database server. That gave 6,409 Python/JS file changes and 182,496 method
changes. Of the 25,187 raw pairs, **81% came from minified drawio bundles**. The quality filters then dropped:
- minified or vendored files: 19,531;
- minified code: 581;
- test files;
- pairs with no sink of the class in the changed lines: 1,205;
- pairs over the 50-per-repository cap: 24.

**554 pairs** remained, from 196 repositories.

## 2. Filtering, counts and real vs synthetic share

The full table is in the data inventory. In summary:
- **Total:** 11,714 rows: 4,681 real fix-commit rows, 472 hand-written rule tests, 6,561 synthetic.
- **Splits:** train / val / test = 7,015 / 2,298 / 2,401, split by repository. No repository is in two splits, and
  the v1/v2 group assignment is kept.
- **Synthetic share of training:** **48.3%** (v2: 51% of training, 61% of all rows); without `synthetic_v3`, 35.1%.
- **Real training rows per class:**

| Class | v2 | v3 | 300 target |
|---|---|---|---|
| CWE-89 | 78 | 119 | short by 181 |
| CWE-79 | 436 | 845 | met |
| CWE-78 | 117 | 179 | short by 121 |
| CWE-22 | 220 | 305 | met |
| CWE-502 | 85 | 121 | short by 179 |
| CWE-327 | 15 | 27 | (as many as exist) |

**Leakage:** none of the 230 excluded repositories (every RealVuln repository, the development, fresh and held-out
apps, and the DAST apps, DVPWA included) occurs in v2's data. The same exclusions were applied to the new sources.
Near-duplicates of any evaluation unit were dropped.

## 3. Label noise of the new sources (50 rows each, one reviewer)

| Source | Strict error [95% CI] | Counting weak | Decision |
|---|---|---|---|
| PyVul | 12% [6, 24] | 60% | weight 0.5 |
| JsVul | 2% [0, 11] | 42% | weight 1.0 |
| GitLab rule tests | 2% [0, 11] | 16% | weight 1.0 |
| OSV extension | 16% [8, 29] | 52% | weight 0.5 |
| CVEfixes (filtered) | 16% [8, 29] | 36% | weight 1.0 |
| synthetic_v3 (50 per CWE) | 0% | 6 weak CWE-22 twins | weight 1.0 |

**The OSV relaxation lowered label quality** (v2 OSV: 8% / 18%):
- raising the cap from 20 to 50 pairs per repo added 73 pairs, with 1 wrong row in 16 sampled;
- allowing up to 8 changed files added 110 pairs, with 7 wrong rows in 34 sampled.

## 4. Ablation (development set only)

| System (rule R2) | Dev macro-F1 | Precision |
|---|---|---|
| With synthetic_v3 | 0.571 | 0.58 |
| Without synthetic_v3 | 0.528 | 0.48 |

`synthetic_v3` helps on the development set.

## 5. Three-model comparison and rule selection (development set, pre-registered)

| System | Dev macro-F1 [95% CI] | P / R | Per-class F1 (89 / 79 / 78 / 22 / 502 / 327 / 798) | Train time | Size | Scan time per file / per 1,000 functions |
|---|---|---|---|---|---|---|
| A: Random Forest | 0.581 [0.471, 0.670] | 0.54 / 0.77 | 0.33 / 0.00 / 1.00 / 0.29 / 0.67 / 0.44 / 0.98 | 16 s | 29 MB | 0.003 s / 0.8 s |
| B: LightGBM | 0.570 [0.470, 0.682] | 0.55 / 0.77 | 0.57 / 0.00 / 0.80 / 0.20 / 0.67 / 0.40 / 0.98 | 31 s | 2 MB | 0.002 s / 0.5 s |
| C: CodeBERT + XGBoost | 0.372 [0.291, 0.451] | 0.19 / 0.79 | 0.42 / 0.02 / 0.80 / 0.09 / 0.00 / 0.00 / 0.98 | 221 s (+28 min embedding) | 2 MB + 499 MB CodeBERT | 0.94 s / 231 s |
| R1 per-class routing | 0.585 [0.472, 0.677] | 0.22 / 0.84 | 0.57 / 0.02 / 1.00 / 0.29 / 0.67 / 0.44 / 0.98 | all three | all three | 0.95 s / 233 s |
| **R2 2-of-3 (selected)** | **0.571 [0.463, 0.664]** | **0.58 / 0.75** | 0.48 / 0.00 / 1.00 / 0.25 / 0.67 / 0.25 / 0.98 | all three | 33 MB + CodeBERT | 0.95 s / 233 s |
| R3 union | 0.473 [0.382, 0.572] | 0.19 / 0.89 | 0.32 / 0.02 / 0.67 / 0.08 / 0.62 / 0.50 / 0.98 | all three | all three | 0.95 s / 233 s |
| v2 (deployed) | 0.642 [0.549, 0.737] | 0.52 / 0.88 | 0.36 / 0.19 / 1.00 / 0.50 / 0.55 / 0.62 / 0.98 | — | — | 0.004 s / 1.0 s |

**Selection:** by the criterion written before training, **R2** was chosen as the only rule with development
precision ≥ v2's (0.521).
- **Against v2 on development:** v3 scores below it, −0.082 [−0.180, +0.022].
- **Why development favours v2:** v2's thresholds were tuned on this same set, while v3's were tuned on grouped
  cross-validation of its own training data.
- **In-distribution test split:** R2 0.747, v2 0.700.

## 6. Held-out results: v2 vs v3 (frozen RealVuln, scored once)

**Freeze:** 20 Python and 4 Node.js community apps never used before, labelled from RealVuln's ground truth with v2's
unit method. The sets were frozen by SHA-256 before any v3 training. Both model hashes (v2 `00fe69cf…`, v3
`f28cc42b…`) and the decision rule were committed before any prediction.

| Set | Units (vulnerable) | v2 macro-F1 [CI] | v3 macro-F1 [CI] | v3 − v2 [CI] | v2 P / R | v3 P / R |
|---|---|---|---|---|---|---|
| **Both (decision)** | 797 (151) | 0.544 [0.471, 0.605] | **0.653 [0.587, 0.705]** | **+0.109 [+0.053, +0.167]** | 0.511 / 0.589 | **0.605 / 0.629** |
| Python | 660 (132) | 0.559 [0.479, 0.623] | 0.670 [0.588, 0.727] | +0.110 [+0.043, +0.175] | 0.549 / 0.598 | 0.651 / 0.636 |
| Node.js | 137 (19) | 0.401 [0.294, 0.597] | 0.581 [0.462, 0.761] | +0.173 [−0.005, +0.290] | 0.333 / 0.526 | 0.393 / 0.579 |

**Per class, both sets** (F1, v2 → v3; support in brackets):
- **Clearly better:**
  - CWE-22 [19]: 0.27 → **0.68**
  - CWE-78 [13]: 0.47 → **0.73**
  - CWE-89 [28]: 0.52 → **0.62**
  - CWE-798 [34]: 0.58 → 0.63 (precision 0.76 → 0.94)
- **About level:**
  - CWE-79 [27]: 0.45 → 0.48
  - CWE-502 [15]: 0.74 → 0.76 (on Python alone, 0.80 → **0.72**)
- **Slightly worse:**
  - CWE-327 [15]: 0.44 → **0.41**
- **Safe units:** 0.88 → 0.91

**The decision, per the pre-registered rule:**
1. macro-F1 higher: ✓
2. precision not worse: ✓
3. the paired 95% CI lies above 0: ✓

**v3 qualifies to replace v2, pending your approval.**

## 7. Limitations

- **Speed:** CodeBERT on CPU makes v3 about 230 times slower than v2 (about 233 s per 1,000 functions), and the
  service needs the CodeBERT weights (about 500 MB) offline in its Hugging Face cache.
- **Development vs held-out:** the development set favours v2 and the held-out sets favour v3. The held-out result is
  the pre-registered one, but the disagreement is a reason for caution.
- **Small Node.js held-out:** 19 vulnerable units; its improvement CI includes 0.
- **Real data:** still short for CWE-89, 78 and 502. PyVul has no licence. JS rows from JsVul, PyVul and CVEfixes are
  "JavaScript, not strictly Node.js".
- **Label noise:**
  - **Reviewing:** one reviewer.
  - **Rates:** 2–16% strict errors in the new sources; the OSV relaxation lowered quality.
  - **Held-out labels:** they come from RealVuln's ground truth, spot-checked on 10 units.
  - **Unscored findings:** 55 held-out findings outside code units are not scored.
- **Held-out licences:** several apps have no licence; they are used for local evaluation only.

## 8. Corrections and disclosures

**Bugs found in my own code by the checks, and fixed before use:**
- **GitLab rule tests:** a unit with both `ruleid` and `ok` annotations took the first one, so 3 vulnerable functions
  in the first sample were labelled safe. Fixed before the recorded sample.
- **Synthetic generator:** Python CWE-78 twins ended with different, unrelated return lines; django twins used
  different model names; JS path checks lacked a separator. Fixed after the hand check; the recorded verdicts are from
  before the fix.
- **CVEfixes test filter:** test files slipped through, because CVEfixes stores only base names. A name check was
  added after the noise sample.
- **CVEfixes processing:** a first run timed out on an unindexed join and was replaced by a single scan.
- **Training weights:** a double-weighting bug (class weights applied twice to RF and LightGBM) was caught before
  training.

**Smaller disclosures:**
- **CVEfixes pairs:** 1,081 broken pairs (overloaded method names) were dropped. 982 of them were in minified or
  vendored files anyway.
- **Ablation embeddings:** the ablation reused the main run's embeddings (the same frozen model).

## 8b. `/scan` response format (v3)

No backend or UI code was changed. With a v3 model loaded, each ML finding carries one extra field and names the
agreeing models in its message:

```json
{"rule": "python.sql-injection", "cwe_id": 89, "severity": "HIGH",
 "message": "SQL injection suspected in function 'view' (model confidence 0.81; flagged by 2 of 3 models: rf, lgbm; signals: ...).",
 "file_path": "app/views.py", "line_number": 12, "confidence": 0.81,
 "models_agree": ["rf", "lgbm"]}
```

- **Values:** `models_agree` lists the base models that flagged the finding: `rf`, `lgbm` and/or `codebert_xgb`. Under
  R2 it always has 2 or 3 entries.
- **When it is absent:**
  - findings of the rule-based secrets detector;
  - findings from v1/v2 models. The response omits unset fields, so a v2 response is unchanged; this is pinned by
    `tests/test_models_agree_v3.py`.
- **Confidence:** the mean probability of the agreeing models.

## 9. Disk use

| Drive | Start | End | Change | What used it |
|---|---|---|---|---|
| C: | 34 GB free | 33 GB free | about −1 GB | small processed data and models in the repo |
| D: | 179 GB free | 119 GB free | | `/mnt/d/cs-data` 55 GB (CVEfixes zip 12.7 GB plus the filtered SQLite file 43.7 GB, kept for reproducibility; it can be deleted) and backups |

C: never went below 15 GB, and D: never below 60 GB.

## 10. Plain-language summary

- **How accurate it is:** on 24 vulnerable practice apps the models had never seen, the new model gets about two out of
  three of its judgements right, measured as macro-F1 0.65; v2 scored 0.54. When it says "vulnerable" it is right
  about 6 times in 10 (v2: 5 in 10), and it finds about 63% of the vulnerable functions (v2: 59%).
- **What it detects best:** command injection, path traversal, SQL injection, insecure deserialization and hard-coded
  secrets.
- **What it misses:** XSS that happens in HTML templates, weak cryptography, and many Node.js issues; Node.js was
  tested on only 19 vulnerable functions.
- **Cost:** it is much slower than v2, because it runs a large language model of code on every function.
- **What happens next:** it passed the agreed test, but it is waiting for your approval before it replaces v2.
