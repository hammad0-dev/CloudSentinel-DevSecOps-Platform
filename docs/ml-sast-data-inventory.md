# ml-sast data inventory (v2 → v3)

**How much data does the SAST model use?**
- **Size:** v3 learns from **9,313 labelled code functions**: 7,015 training plus 2,298 validation rows, out of a
  v3 dataset of 11,714 rows. v2's dataset had 6,911 rows.
- **Where they come from:** 4,681 rows are real code from security-fix commits, 472 are hand-written rule test
  cases, and 6,561 are generated (synthetic).
- **Real code by class:** CWE-79 has 845 real training rows; CWE-89, CWE-78 and CWE-502 still have only about
  120–180.

Rows are functions (or module-level code). A fix pair gives two rows: the function before the fix, labelled with the
vulnerability class, and after the fix, labelled safe.

## Sources

| Source | Real or synthetic | Language | Licence | Rows before filtering | Rows after filtering | Train / val / test |
|---|---|---|---|---|---|---|
| CrossVul (v2) | real (fix commits) | Python, JS | CC BY 4.0 | 942 (v2) | 940 | 664 / 138 / 138 |
| OSV advisories (v2) | real (fix commits) | Python, JS | CC BY 4.0 metadata; code under each repo's licence | 1,774 (v2) | 1,765 | 1,237 / 262 / 266 |
| **CVEfixes v1.0.8** (new) | real (fix commits) | Python, JS | CC BY 4.0 | 50,374 (25,187 method pairs from 6,409 Python/JS file changes) | 714 | 550 / 82 / 82 |
| **JsVul** (new) | real (fix commits) | JS (.js/.mjs/.cjs; not strictly Node.js) | CC BY 4.0 (Zenodo record) | 21,901 functions (17,029 JS, 4,859 TS/TSX/JSX) | 632 | 326 / 154 / 152 |
| **PyVul** (new) | real (fix commits) | Python (+ a little JS) | none stated (research use with attribution) | 2,173 functions (1,569 Python, 50 JS) | 374 (weight 0.5) | 272 / 44 / 58 |
| **OSV extension** (new) | real (fix commits) | Python, JS | as OSV | 288 re-processed commits → 366 rows | 256 (weight 0.5) | 144 / 60 / 52 |
| **GitLab SAST rule tests** (new) | hand-written rule test cases | Python, JS | MIT (repo), LGPL (rules/lgpl*) | 1,443 annotations | 472 | 432 / 16 / 24 |
| Synthetic (v2) | synthetic | Python, JS | own | 4,195 | 4,195 | 1,956 / 1,079 / 1,160 |
| **synthetic_v3** (new) | synthetic | Python, JS | own | 2,400 (1,200 pairs, 64–99 distinct patterns per class and language) | 2,366 | 1,434 / 463 / 469 |
| **Total** | | | | | **11,714** | **7,015 / 2,298 / 2,401** |

**Filtering, in order:**
- **Language:** Python and JS only; TypeScript dropped.
- **Class mapping:** a row is kept only if its CWE maps to exactly one target class.
- **Fix pairs only:** for CVEfixes, also no minified or vendored files, no test files, a sink of the labelled class in
  the changed lines, and at most 50 pairs per repository.
- **Exclusions:** excluded repositories (RealVuln, development, fresh, held-out and DAST apps) are dropped.
- **Duplicates:** exact duplicates and conflicting labels are dropped, as are near-duplicates (5-shingle Jaccard
  ≥ 0.8) of any development, fresh or held-out unit or of an already-kept row.

Every count is in `services-ml/ml-sast/data/manifest.json` (`v3`) and in `reports/v3/sources/*.json`.

**Skipped sources:**
- **SALVE:** gated on Hugging Face, so it needs a manual download.
- **Semgrep rule tests:** their licence allows internal business use only.
- **MoreFixes:** the Zenodo record was deleted.

## Label noise of the new sources (50 random rows each, one reviewer)

| Source | Wrong | Weak | Strict error (95% CI) | Error counting weak | Decision |
|---|---|---|---|---|---|
| PyVul | 6 | 24 | 12% [6, 24] | 60% | weight 0.5 |
| JsVul | 1 | 20 | 2% [0, 11] | 42% | weight 1.0 |
| GitLab rule tests | 1 | 7 | 2% [0, 11] | 16% | weight 1.0 |
| OSV extension | 8 | 18 | 16% [8, 29] | 52% | weight 0.5 |
| CVEfixes (after its quality filters) | 8 | 10 | 16% [8, 29] | 36% | weight 1.0 |
| synthetic_v3 (50 per CWE) | 0 | 6 (CWE-22) | 0% | 2.4% | weight 1.0 |

The policy was fixed before any source after PyVul was checked: drop a source above 25% strict errors; weight 0.5
above 50% counting weak rows. For comparison, v2's OSV rows were 8% strict and 18% counting weak.

## Per-class training rows: v2 vs v3 (train split)

| Class | v2 real | v2 synthetic | v3 real | v3 rule tests | v3 synthetic | v3 real vs the 300 target |
|---|---|---|---|---|---|---|
| CWE-89 SQL injection | 78 | 160 | **119** | 53 | 328 | short by 181 |
| CWE-79 XSS | 436 | 160 | **845** | 19 | 310 | met |
| CWE-78 command injection | 117 | 80 | **179** | 57 | 224 | short by 121 |
| CWE-22 path traversal | 220 | 120 | **305** | 27 | 247 | met |
| CWE-502 deserialization | 85 | 120 | **121** | 26 | 250 | short by 179 |
| CWE-327 weak crypto | 15 | 80 | **27** | 78 | 80 | (as many as exist) |
| CWE-798 secrets (rules carry it) | 1 | 120 | 1 | 11 | 120 | — |
| safe | 954 | 1,116 | 1,596 | 161 | 1,831 | — |
| **Train total** | 1,906 | 1,956 | 3,193 | 432 | 3,390 | |

**Synthetic share:**
- **v3 training:** **48.3%** synthetic (v2: 51% of training, 61% of all rows).
- **v3 rows overall:** 56% synthetic.
- **Without synthetic_v3** (the ablation): training is 35.1% synthetic.

**Languages in v3 training:** Python 3,791, JavaScript 3,224.

## Evaluation sets (never used for training; near-duplicates removed from training)

| Set | Role | Apps | Scored units (vulnerable) |
|---|---|---|---|
| Development | rule selection and tuning (since v2) | NodeGoat, DVNA, vulpy, PyGoat | 439 |
| v2 fresh held-out | scored once in v2; not reused | django.nV, dvws-node, vulnerable-node | 312 (35) |
| **v3 held-out, Python** (new, frozen) | scored once in v3 | 20 RealVuln community apps | 660 (132) |
| **v3 held-out, Node.js** (new, frozen) | scored once in v3 | 4 RealVuln community apps | 137 (19) |
