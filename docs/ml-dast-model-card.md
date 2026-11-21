# Model card: ml-dast 4.0.0 (`ml-dast-lr`): DEPLOYED on port 8002 since the v5 held-out test

## v5 update: authenticated scanning, dvws-node held-out test, v4 deployed

**v5 changes the scanner, not the model.**
- **New:** authenticated scanning (login, shared session, re-login, a destructive-action skip list), plus one new
  held-out test on an unseen app that needs a login.
- **Unchanged:** features, models and thresholds. Plan: [`ml-dast-auth-plan.md`](ml-dast-auth-plan.md); how-to:
  [`ml-dast-auth-howto.md`](ml-dast-auth-howto.md).

**Deployed now: v4.** It replaced v2 on port 8002 under the rule pre-registered in
`reports/final_preregistration_v5.json` (before the scan).
- **v2 on dvws-node:** endpoint-param macro-F1 **0.853**, 95% CI [0.632, 1.000]; 3 of 3 SQLi found, 2 false alarms.
- **v4 on dvws-node:** macro-F1 **0.918**, 95% CI [0.730, 1.000]; 3 of 3 SQLi found, 1 false alarm.
- **Rule conditions:** all four hold. Coverage was 27/27 (100%); v4's macro-F1 was strictly higher; it found as many
  vulnerable parameters; and it had no extra false alarm.

| Held-out: dvws-node @ 4221c04f, 27 endpoint-params (3 CWE-89), one scan | v2 (was deployed) | v3 | **v4 (deployed)** |
|---|---|---|---|
| Endpoint-param macro-F1 [95% cluster-bootstrap CI] | 0.853 [0.632, 1.000] | 0.870 [0.672, 0.979] | **0.918 [0.730, 1.000]** |
| Vulnerable parameters found (of 3) | 3 | 3 | 3 |
| False alarms (of 24 safe) | 2 | 5 (4 as XSS) | 1 |
| Paired difference vs v4 | v2 − v4 = −0.065 [−0.239, 0.000] | v3 − v4 = −0.051 [−0.115, −0.011] | |

**How strong the evidence is.** One small app is weak evidence.
- The v2 − v4 interval reaches 0, so v4 is not significantly better than v2 there.
- The CI was not part of the rule.
- **The whole v4-v2 difference is one cluster:** v2 also flags `GET /api/v2/notes/{noteId}` as SQLi; v4 does not.
- **Shared false alarm:** all three models flag `GET /api/v2/users/{id}/profile-details` as SQLi (a Mongoose cast
  error that echoes the id, in JSON).
- **v3's extra false alarms:** it also flags four JSON write fields as XSS (`POST /api/v2/notes` name and body, the
  `bio`, and the notification `email`).
- Every cluster is listed in `reports/final_dvws.json`.
- Together with the leave-one-app-out result (v4 0.970 against v2 0.827 on the same 111 endpoint-params, significant),
  this is the first held-out test where v4 was not tied with v2.

**Rule checks on dvws-node (counts):**
- **Passive:** 4 of 4 positives found, 0 false alarms.
- **CWE-22:** 0 of 1 (`/api/v2/reports/monthly` only reads `*.json` files).
- **Stored XSS / CSRF:** no labelled units (single-page app, bearer-token API).

**In-distribution (not held-out).** These are training apps (DVPWA, NodeGoat, vulnerable-node): 9 ML clusters reached
only by the authenticated collection, scored separately in `reports/indist_v5.json`.
- **Scores:** v2 0.667 [0.308, 0.962], v3 0.639, v4 0.903 [0.471, 1.000].
- **Why it is not held-out:** the models were trained on these apps.

**What authenticated scanning adds.** Pages and parameters behind a login are now reached. Labelled endpoint-params
reached, before → with login:

| App | Before | With login |
|---|---|---|
| DVPWA | 8 | 14 of 17 |
| NodeGoat | 7 | 15 of 15 |
| vulnerable-node | 10 | 13 of 18 |

These counts are the union of the logged-out and logged-in crawls (`data/dast/coverage_v5.json`). The dvws-node
held-out was scanned logged in, with 100% coverage.

**Limits of authenticated scanning:**
- **Logins it cannot do:** MFA/OTP, CAPTCHA and SSO on another origin.
- **CSRF tokens:** tokens that rotate per request are not refreshed per probe.
- **API apps:** a single-page app's API still needs seeds or an OpenAPI document.
- **Login-form probing:** the login form itself is probed logged out.
- **Passive checks:** the passive header checks stay cookie-less.
- **App bugs:** an app whose login is broken cannot be scanned logged in (vulpy in the lab: its own session code
  raises a 500).
- **The model is the same:** authentication adds reach, not accuracy.

**v5 data is not used by any model yet** (`data/dast/*_v5`).

**Rollback** to v2 (the exact commands are in `docs/ml-architecture.md`, "ML DAST v5"): stop the 8002 process and
start `scripts/run-ml-dast.sh` with `ML_DAST_MODEL_DIR=…/models/release_v2` and the same allowlist.
`models/release_v4/model.json` still says `"default": false`, because files under `models/` are never rewritten.
The deployment is the run command, not that flag.

---

# Model card: ml-dast 4.0.0 (`ml-dast-lr`) as packaged in v4 (v2 was then kept deployed)

v4 adds OWASP BenchmarkPython (a subset) as training data, freezes DVPWA as a new held-out app, and widens the
tuning range. It adds no new features.

**v4 does not replace v2.** The rule, fixed before the held-out scan, had two conditions:
1. **v4 must beat v2 on the frozen held-out app.** Not met: on DVPWA they tied, v2 = v3 = v4 = 1.000.
2. **v4 must not be significantly worse in leave-one-app-out.** Met: it is significantly *better*.

**The held-out result is uninformative.** The unauthenticated crawl reached only 8 of DVPWA's 17 labelled parameters,
1 of them vulnerable. DVPWA renders its vulnerable forms only for logged-in users. I wrote in the plan that no login
was needed and pre-registered an unauthenticated scan: a **planning mistake** (see Threats). It was not re-scanned,
because the held-out app is scored once.

So the engine on port 8002 keeps serving v2 (`models/release_v2`); v4 is opt-in at `models/release_v4`. ZAP stays
the default DAST engine.

| | |
|---|---|
| Artifact | `services-ml/ml-dast/models/release_v4/model.joblib` (gitignored), metadata in `model.json` (`"default": false`) |
| SHA-256 | `7a306aca5b07…` (full value in `reports/final_preregistration_v4.json`) |
| ML component | Logistic regression (`C=0.1`, balanced class weights, standardized inputs) over **63 features**: the v3 set without the location one-hot, chosen by inner leave-one-app-out against the v2 set |
| Decision rule (ML) | P(C) ≥ **0.995**, chosen by inner leave-one-app-out over 0.20 to 0.95 plus 0.97/0.98/0.99/0.995. 8 of 11 outer folds and the final model chose 0.995, **the top of the widened grid again** (see Threats) |
| Rule-based component | As v3: CWE-78, CWE-22, CWE-601, passive checks, stored XSS (HIGH), CSRF heuristic (LOW). A v4 detector scans exactly like v3 |
| Selection | LR over LightGBM by pooled leave-one-app-out on the real apps (0.933 against 0.826), fixed in `reports/selection_v4.json` before DVPWA was started |
| Previous | v3 3.0.0 (packaged separately), v2 2.0.0 (deployed): [below](#v3-ml-dast-lr-300-kept-for-reference) |

## What changed from v3, and why

All decisions were fixed in `docs/ml-dast-v4-plan.md` before any held-out scan.

**No new features.** The inner leave-one-app-out chooses between the two existing feature sets:
- `FEATURE_NAMES_V2`: 70 features, the deployed model's;
- `FEATURE_NAMES_V3`: 63 features.

Each is tried with and without the location one-hot. v3's features had won leave-one-app-out but lost the held-out
app, while v2's had won the held-out app.

v2's feature extraction is unchanged byte for byte. `tests/test_v2_compat_v4.py` re-featurizes a fixed sample of 1,950
v2 rows and requires identical feature values and identical scores from the deployed v2 model.

**Wider threshold grid:** 0.20 to 0.95 plus 0.97, 0.98, 0.99 and 0.995, because v3 hit 0.95 in every fold.

**Families:** logistic regression and LightGBM. RF was dropped: it lost in v2 and v3.

**Selection:** inner leave-one-app-out only, scored on the non-Benchmark clusters. The family is the one with the best
pooled leave-one-app-out score on the real apps, fixed before DVPWA was started.

**New training data: OWASP BenchmarkPython** (@ f129148, GPL-3.0), as one synthetic leave-one-app-out group with its
own origin.
- **Which cases:** the SQLi, XSS, command-injection and path-traversal cases whose input the probe can drive (a form
  field, a query parameter or the raw query string): **155 cases**. Header, cookie, form-key and constant-path cases
  are unreachable and excluded.
- **Labels:** the shipped `expectedresults-0.1.csv`, after a seeded random source spot-check of 16 cases (16 of 16
  agree).
- **ML rows:** all 60 SQLi/XSS cases, plus a seeded 20 command-injection/path-traversal cases as hard negatives.
  The other 75 are rule-only.
- **Balance:** `class_weight="balanced"` handles class imbalance as before. Limiting the rule-category cases keeps the
  synthetic group from flooding the safe class.
- **Reporting:** its numbers are reported separately as in-benchmark results, and never as third-party
  generalization.

**New frozen held-out app: DVPWA** (anxolerd/dvpwa @ 4a8f4a4, MIT): aiohttp, Postgres and Redis, with Jinja2
autoescape off.
- **Unseen:** never used in this project. ml-sast's OSV collector explicitly excludes it, and the v3 plan mentioned it
  only as a never-collected option.
- **Labelled from source and frozen** by SHA-256 (`FREEZE_v4.json`) before any container was created.
- **Scored once,** for v2, v3 and v4 on the same records.

**Unchanged:**
- The guards, allowlist, refusal of untrained models and rules.
- DVNA, and the v1, v2 and v3 files (every freeze hash is tested).
- SirAppSec is burned and not used as training data.
- All v4 outputs have new names.

## Data (v4)

| Group | Origin | ML rows | SQLi / XSS endpoint-params | Safe |
|---|---|---|---|---|
| labflask, labexpress, labfastapi | own | 5,250 | 20 / 16 | 69 |
| Juice Shop, NodeGoat, vulpy, vulnerable-node, DSVW, VAmPI, node-api-goat | third-party | 4,152 | 14 / 16 | 34 |
| BenchmarkPython (one group) | benchmark | 4,000 | 3 / 21 | 56 |
| **Training total** (11 leave-one-app-out groups) | | **13,402** (11,120 safe, 1,258 SQLi, **1,024 XSS**) | 37 / 53 | 159 |
| DVPWA (final held-out), reached by the crawl | third-party | 600 | 0 / 1 | 7 |

The v3 training records were re-featurized into `features_v4` with no new traffic; their row counts are identical
to v3. Ground truth: `data/dast/ground_truth_v4.json` (`changes_v4`). The BenchmarkPython subset and the spot-check
are described in `docs/ml-dast-v4-plan.md`.

## Results

The metric is unchanged: endpoint-param macro-F1 with 95% cluster bootstrap intervals (1,000 resamples). The headline
**"real"** set is own plus third-party apps. **BenchmarkPython's numbers are in-benchmark only**, reported separately,
and are not evidence of generalization.

### Main: leave-one-app-out (11 groups; real apps 169 endpoint-params)

| Set | LR (selected) | LightGBM | LR − LightGBM |
|---|---|---|---|
| **Real (169)** | **0.933 [0.887, 0.969]**; SQLi 0.94/0.85/0.89 (34) [0.81, 0.97]; XSS 0.91/1.00/0.96 (32) [0.89, 1.00] | 0.826 [0.756, 0.883] | +0.110 [+0.044, +0.173] |
| Own (105) | 0.919 [0.854, 0.970] | 0.859 | +0.063 [−0.008, +0.142] |
| Third-party (64) | 0.948 [0.881, 1.000] | 0.762 | +0.192 [+0.081, +0.317] |
| *BenchmarkPython, in-benchmark (80)* | *1.000* | *0.930* | |

All real-app folds were above 0.87 (labflask 0.873 was the lowest), and every LR fold chose the v3 features.
Full tables: `reports/loao_v4.md`.

### v2 (deployed) against v4 on the same endpoint-params

| Set | v2 | v4 | v2 − v4 [95% CI] |
|---|---|---|---|
| **Same 111 endpoint-params** as v2's leave-one-app-out | 0.827 | **0.970** | **−0.146 [−0.225, −0.076]** |
| … own (73) / third-party (38) | 0.871 / 0.757 | 0.964 / 0.973 | −0.097 [−0.191, −0.010] / −0.218 [−0.350, −0.090] |
| **Enlarged set (169 real)**, the v2 system re-run on the v4 data | 0.836 [0.773, 0.891] | **0.933** | **−0.099 [−0.155, −0.045]** |

**Errors on the same 111 endpoint-params:** v2 17, v3 7, v4 3:
- labflask `/item?id`: SQLi missed;
- vulnerable-node `/orders?sort`: SQLi missed;
- labflask `/widget-safe`: XSS false alarm.

v3's XSS false alarms on our own escaped twins are almost gone. This is **somewhat optimistic**: the candidate feature
sets came from v2 and v3 error analysis on these folds, and the threshold sits at the top of the grid.
Reports: `before_after_v4.json`, `before_after_v4_enlarged.json`.

### Final held-out app: DVPWA, single run, v2, v3 and v4 on the same records

| | v2 (deployed) | v3 | v4 |
|---|---|---|---|
| Endpoint-param macro-F1 (8 reached) | 1.000 | 1.000 | 1.000 |
| SQLi (1 labelled; **not reached**) | – | – | – |
| XSS (4 labelled; **1 reached**: `review_text`) | 1/1, 0 false alarms | 1/1, 0 false alarms | 1/1, 0 false alarms |
| Paired differences | | | all 0.000 [0.000, 0.000] |

**Coverage:** the crawl found 8 of 17 labelled parameters. DVPWA renders the student form only for logged-in users
(`{% if auth_user %}`) and the course and evaluate forms only for admins. Their POST handlers check nothing, but a
crawler that is never shown a form cannot submit it. The held-out comparison therefore rests on 1 vulnerable and
7 safe endpoint-params and **cannot separate the models**.

| Rule-based on DVPWA | Result |
|---|---|
| Passive | found 5 of 5 (CSP, nosniff, framing, cookie without HttpOnly, cookie without SameSite); 0 false alarms |
| Stored XSS | found 1 of 4 (`review_text`), 0 false alarms; the other 3 forms were never reached |
| CSRF heuristic | found 0 of 5. Four forms carry an unvalidated `_csrf_token` field (the known blind spot); the evaluate form was never reached |
| CWE-78 / 22 / 601 | no instances in DVPWA; 0 false alarms on 12 safe endpoints |

### Rule-based checks on the training apps (counts)

- **Real apps:** unchanged from v3 (`reports/rules_v4.md`):
  - CWE-78 3/4, CWE-22 4/5, CWE-601 4/5, each with 0 false alarms on about 185 safe endpoints;
  - passive 33/33;
  - stored XSS 2/8;
  - CSRF 13/20.
- **BenchmarkPython (in-benchmark):**
  - CWE-78: found 8 of 8, with 0 false alarms on 147 safe endpoints.
  - CWE-22: **found 0 of 39.** The benchmark HTML-escapes its output (`:` becomes an entity), so the `/etc/passwd`
    signature never matches, and some cases only open files for writing. This is a rule limit, not a label problem.

### ZAP comparison

**Setup:**
- ZAP is run as in v3: unmodified, unauthenticated and without seeds.
- **Scans used:** a scan is used only if it completed validly (`logs/zap_v*/<app>.status`); a timed-out scan is not
  a miss. The training apps are unchanged since v3, so their v3 scans are reused. DSVW's scan is unusable and
  excluded.
- **BenchmarkPython is not ZAP-scanned.** Its code-injection and deserialization cases could not be kept out of ZAP's
  reach, since ZAP's exclusions did not hold in v2 or v3.
- **DVPWA was scanned once** after scoring. The scan completed in 178 s and was valid.

| Set (endpoint-params) | ml-dast v4 | ZAP | ml-dast − ZAP [95% CI] |
|---|---|---|---|
| Real training apps (157 usable) | **0.935** [0.886, 0.972] | 0.915 [0.858, 0.961] | +0.020 [−0.037, +0.081], not significant |
| … own (105) | 0.919 | 0.954 | −0.035 [−0.101, +0.026] |
| … third-party (52) | 0.957 | 0.848 | ml-dast ahead (not significant) |
| DVPWA, the 8 reached | 1.000 | 0.795 | +0.125 [0.000, +0.436]: XSS 1/1 for both; ZAP 1 false alarm. Too small to mean much |

| Check (counts) | Training apps: known / ml-dast / ZAP | DVPWA: known / ml-dast / ZAP |
|---|---|---|
| Stored XSS | 8 / 2 / 1 | 4 / 1 / 1 |
| CSRF (forms) | 20 / 13 / 9 | 5 / 0 / 0 |

**The comparison has moved:**
- **v2:** ZAP was significantly better (−0.112).
- **v3:** not significant, but ZAP was significantly better on our own apps (−0.131).
- **v4:** ml-dast's point estimate is ahead overall. The difference is not significant, and the leave-one-app-out
  caveat applies.

Reports: `reports/zap_comparison_v4.md`, `zap_comparison_v4_final.md`.

## Intended use

- **Intended:** v2 remains the deployed ml-dast model. v4 is an opt-in comparison candidate for authorized staging
  targets.
- **Not intended:** replacing ZAP, certifying an app as free of injection, or gating a pipeline on DAST findings. The
  gate never reads DAST findings.

## Limitations

1. **ML covers SQLi and reflected XSS only.** Rule classes are counted on few instances.
2. **No authenticated scanning.** DVPWA shows the cost: its vulnerable forms are visible only after login, so the
   scan never reaches them.
3. **BenchmarkPython is synthetic,** and its cases are short, single-sink handlers. Its in-benchmark 1.000 says
   nothing about real apps. Only cases with form or query input are used.
4. **XSS is still the class with the fewest real-app endpoint-params** (32).
5. **The rule limits from v3 remain:**
   - CWE-22 recognizes unescaped `/etc/passwd` content only;
   - stored XSS needs crawlable sink pages and unauthenticated POST forms;
   - the CSRF heuristic is fooled by unvalidated token fields.

## Threats to validity

- **Planning mistake, my own:** the DVPWA plan said "no login is needed for the vulnerable routes". True for the
  handlers, but I did not check whether the forms are rendered for an anonymous visitor. They are not, so the
  pre-registered unauthenticated scan made the held-out comparison uninformative. It was not repaired after the fact.
- **The threshold is at the grid edge again:** 0.995 in 8 of 11 folds and in the final model. The grid was not
  widened further.
- **Optimistic leave-one-app-out:** the candidate feature sets came from earlier error analyses on these folds, after
  three earlier rounds. With the held-out app uninformative, there is **no honest out-of-sample estimate for v4**.
- **Synthetic training group:** BenchmarkPython is 30% of the rows. Its weight was limited (20 hard-negative
  endpoints from the rule categories), but its style differs from real apps.
- **Author bias:** 3 of 11 groups and all lab twins are mine.

## Reproduce (v4)

```bash
cd services-ml/ml-dast
python scripts/snapshot_v2_scores.py          # once, before any change (tests/data/v2_scores_sample_v4.json)
python scripts/freeze_v4.py                   # once, before any DVPWA request
# copy raw_v3/<training app>.* to raw_v4/, then:
python scripts/featurize.py --data v4 labflask labexpress labfastapi juice-shop nodegoat vulpy-bad vulpy-good vulnerable-node vampi node-api-goat dsvw
(cd lab && docker compose --profile v4 up -d --build benchmarkpython) && python scripts/collect_lab.py --data v4 benchmarkpython
python scripts/eval_rules_v4.py
LOAO_FOLD_JOBS=4 OMP_NUM_THREADS=1 python scripts/loao_v4.py --system v4 --kinds lr,lgbm
LOAO_FOLD_JOBS=3 OMP_NUM_THREADS=1 python scripts/loao_v4.py --system v2 --kinds lr
python scripts/select_v4.py && python scripts/compare_v4.py && python scripts/train_final_v4.py
python scripts/eval_final_v4.py               # once only: DVPWA, v2 v3 v4 on the same records
```

---

## v3 (`ml-dast-lr` 3.0.0), kept for reference

v3 is a targeted accuracy round for SQL injection and reflected XSS. It also adds two rule-based checks,
stored XSS and a CSRF heuristic.

**v3 is not the default.** The rule was fixed before the held-out app was scored: v3 had to beat v2 on the
new frozen held-out app and not be significantly worse in leave-one-app-out. The second condition held. The
first did not:
- **Held-out (SirAppSec):** v3 0.652 against v2 0.718 on the same records. The difference, −0.047
  [−0.277, +0.169], is not significant.
- **Leave-one-app-out:** v3 is significantly better than v2 on the same endpoint-params.

So `models/release_v2` stays the ml-dast model in use, and v3 is opt-in at `models/release_v3`. The
service's built-in default directory is still v1's `models/release`, as it has been since v1. Deployments
set `ML_DAST_MODEL_DIR`. ZAP stays the default DAST engine.

| | |
|---|---|
| Artifact | `services-ml/ml-dast/models/release_v3/model.joblib` (gitignored), metadata in `model.json` (`"default": false`) |
| SHA-256 | `bbcd03d12b21…` (full value in `reports/final_preregistration_v3.json`) |
| ML component | Logistic regression (`C=0.1`, balanced class weights, standardized inputs) over 63 response features. The location one-hot was dropped by the inner selection |
| Decision rule (ML) | A row with a class-C payload is C if P(C) ≥ **0.95**; an endpoint parameter is C if any of its C rows is. The threshold was chosen by inner leave-one-app-out over a grid of 0.20 to 0.95, and every outer fold chose 0.95, the top of the grid (see Threats) |
| Rule-based component | As v2 (CWE-78, CWE-22, CWE-601, passive), plus **stored XSS (HIGH)** and a **CSRF heuristic (LOW, confidence 0.5)**. Passive and CSRF findings are LOW/INFO and never gate-blocking |
| Payloads | `payloads_v2.json`, unchanged. The stored-XSS marker is built by `dastml/stored.py` |
| Selection | Highest pooled leave-one-app-out macro-F1 among LR, RF and LightGBM (`reports/selection_v3.json`), fixed and committed before SirAppSec was started |
| Previous | v2 `ml-dast-lr` 2.0.0, [below](#v2-ml-dast-lr-200-kept-for-reference) |

### What changed from v2, and why

**Error analysis first** (`docs/ml-dast-v3-plan.md`, section A). Every v2 leave-one-app-out error (LR: 6 missed
vulnerable endpoint-params, 11 false alarms) and the 3 DSVW SQLi misses was traced to its deciding row:

| v2 error | Cause | v3 change |
|---|---|---|
| DSVW `/?id` SQLi missed (p=0.017): a real SQL error in a text/plain 500 | `ct_text` −5.87: every text/plain response in training was safe | F1: content-type one-hots dropped; text/plain and JSON SQL-error twins; DSVW as training data |
| DSVW `/login`, `/?comment` SQLi missed (0.882, 0.894 < 0.9) | Every LR fold chose t=0.9, the top of the grid | F6: threshold grid extended to 0.95 (still chosen by inner leave-one-app-out); parity-only SQLi twins |
| NodeGoat `/profile` XSS × 6 missed (p≈0.73) | `len_log` −3.48: long pages looked safe (an app-size prior); the first occurrence sat in a script block | F1: `len_log` dropped; F5: the context of the most dangerous occurrence, taken where the reflection starts |
| `javascript:` false alarms × 4 | The attribute-context one-hot fired for a harmless reflection | F3: context one-hots only for a reflection that breaks out of its context |
| labflask `/next` false alarm | The body of a 302 echoes `href="javascript:…"`; browsers never render it | F2: XSS evidence only for rendered HTML (HTML content type, not 3xx) |
| labflask `/widget-safe` false alarm | A `'` inside a JSON-encoded `"…"` JS string cannot break out | F4: `x_script_breakout` (the quote must match the enclosing JS string) |
| SQLi false alarms on JSON 200 / non-SQL 500 / union payload | Content-type priors and the threshold edge | F1, F6, and safe twins that answer bad input with text/JSON/500 errors |
| vulnerable-node `/orders sort` SQLi missed | ORDER BY injection with a reflected parameter was rare in training | ORDER BY twins |

No label errors were found among the v2 errors (each endpoint re-read in source).

**Disclosed iterations.** The v2 features had already been iterated twice on the same leave-one-app-out folds;
the v3 changes above were chosen from the v2 leave-one-app-out errors (and the DSVW misses), so the v3
leave-one-app-out numbers are **somewhat optimistic**. The feature set was fixed before any v3 training and not
changed after; the new frozen held-out app is the honest estimate.

**Rule-based checks added (not ML):**
- **Stored XSS (CWE-79, HIGH):** each POST/PUT form or JSON field gets a random marker `cs<hex>'"<i>cs<hex></i>`;
  after each submission the crawled pages are re-fetched and the field is reported only if `<i>marker</i>`
  comes back unescaped in a rendered HTML page. Markers are random per submission, so leftovers from earlier
  scans never match; lab apps are reset before every collection; writes go only through the guarded client
  (allowlisted targets). `ML_DAST_STORED_XSS=0` disables the pass.
- **CSRF (CWE-352) heuristic, LOW, confidence 0.5, never gate-blocking:** a POST form without an anti-CSRF token
  field while the session cookie has no `SameSite=Lax/Strict`. Known blind spots: a token field that is never
  validated counts as protected, and state-changing GETs are out of scope.

**Data:**
- Own-app `/v3/*` twins (labflask, labexpress, labfastapi). VULN and SAFE versions differ only in the sink.
- Third-party training apps **VAmPI** (JSON API, SQLi) and **node-api-goat** (XSS), plus vulnerable-node's review form.
- **DSVW moves from held-out to training.** It was scored once as the v2 held-out and is burned as a test set.
- **New frozen held-out app: SirAppSec** `vuln-node.js-express.js-app` @ b977c74. It is unused anywhere else in
  the project. It was labelled from source and frozen by SHA-256 (115 source files plus its ground-truth subset,
  `data/dast/FREEZE_v3.json`) before any request, and scored once.
- **DVNA stays frozen and untouched** (all freeze hashes are tested). v2 files are byte-identical.

**Backend:**
- `stored_xss` → HIGH DAST `VULNERABILITY` (OWASP A03).
- `csrf_heuristic` → LOW `HOTSPOT_REVIEW`.
- Passive and heuristic findings are clamped to LOW/INFO.
- The gate never reads DAST findings (tested).
- The UI tags rule, stored, passive and heuristic findings.

### Data (v3)

| App group | Origin | Rows (ML) | SQLi / XSS endpoint-params | Safe |
|---|---|---|---|---|
| labflask, labexpress, labfastapi (with the `/v3` twins) | own | 5,250 | 20 / 16 | 69 |
| Juice Shop, NodeGoat, vulpy (bad+good), vulnerable-node, DSVW, VAmPI, node-api-goat | third-party | 4,152 | 14 / 16 | 34 |
| **Training total** (10 LOAO groups) | | **9,402** (7,558 safe, 1,156 SQLi, **688 XSS**, up from 336) | **34 / 32** | 103 |
| SirAppSec (v3 final held-out) | third-party | 1,868 | 2 / 2 | 34 |

Ground truth: `data/dast/ground_truth_v3.json`, summarized in `data/dast/GROUND_TRUTH.md` (v3 section). The v2
raw records are never reused: every training app was collected again under v3, with fresh databases.

### Results

The metric is the same as in v1 and v2: endpoint-param macro-F1 with 95% cluster bootstrap intervals (1,000
resamples), also per class. Rule-based checks are reported as counts.

#### Main: leave-one-app-out (10 groups, 169 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | Own (105) | Third-party (64) |
|---|---|---|---|---|---|
| **LR** (selected) | **0.863 [0.805, 0.914]** | 0.84/0.91/0.87 (34) [0.78, 0.95] | 0.71/1.00/0.83 (32) [0.72, 0.91] | 0.825 [0.746, 0.896] | 0.921 [0.843, 0.982] |
| RF | 0.813 [0.746, 0.870] | 0.74/0.76/0.75 (34) | 0.75/0.94/0.83 (32) | 0.814 | 0.795 |
| LightGBM | 0.831 [0.761, 0.890] | 0.76/0.76/0.76 (34) | 0.77/0.94/0.85 (32) | 0.868 | 0.762 |

The family differences over all apps are not significant (LR − RF +0.050 [−0.009, +0.115]). On the
third-party apps, LR is significantly better than both RF and LightGBM. Full tables: `reports/loao_v3.md`.

**Remaining errors (LR):**
- **XSS:** 13 false alarms, all on our own escaped `-safe` twins. A harmless reflection, such as
  `javascript:x()` echoed as text or a quote that cannot leave its JS string, still scores ≥ 0.95. Once the
  context one-hots are gated, the model leans on the marker-reflection and payload-family priors. The new
  features themselves are correct (`x_dangerous` = 0 on these rows).
- **SQLi:** 6 false alarms and 3 misses.

#### v2 against v3 on the same endpoint-params

| Set | v2 | v3 | v2 − v3 [95% CI] |
|---|---|---|---|
| **Same 111 endpoint-params** as v2's leave-one-app-out | 0.827 [0.744, 0.894] | **0.933 [0.874, 0.976]** | **−0.109 [−0.193, −0.031]** |
| … own (73) | 0.871 | 0.902 | −0.032 [−0.131, +0.057] |
| … third-party (38) | 0.757 | **0.974** | **−0.220 [−0.378, −0.073]** |
| **Enlarged set (169)**, the v2 system re-run on v3 data | 0.808 [0.745, 0.864] | **0.863 [0.805, 0.914]** | **−0.055 [−0.105, −0.008]** |

In leave-one-app-out, v3 is significantly better, mainly on third-party apps (`reports/before_after_v3.json`,
`before_after_v3_enlarged.json`). This leave-one-app-out gain is **somewhat optimistic**, because the changes
were chosen from the v2 errors on these folds (see Threats).

#### Final held-out app: SirAppSec, single run, v2 scored on the same records

The scan configuration was pre-registered (`reports/final_preregistration_v3.json`): crawl plus
`/v1/api-docs`, the `populate.sh` seed data, a 5 s timeout, and both model hashes. It found 38 of 39 labelled
parameters; `/beer?relationship` is never reachable because that handler throws before responding.

| | v2 | v3 |
|---|---|---|
| Endpoint-param macro-F1 [95% CI] | **0.718 [0.525, 0.938]** | 0.652 [0.502, 0.879] |
| SQLi (2 known, `/v1/search/{filter}/{query}`) | found 2/2, **9 false alarms** (F1 0.31) | found 2/2, 4 false alarms (F1 0.50) |
| Reflected XSS (2 known, `/?message`, `/register?message`) | found 2/2, **0 false alarms** (F1 1.00) | found 2/2, 3 false alarms (F1 0.57) |
| v3 − v2 | | −0.047 [−0.277, +0.169], not significant |

**What this shows:**
- **The SQLi gap is closed for both models.** Both find SirAppSec's SQL injection, whose error is a
  501 text response; v2 found none of DSVW's 3.
- **v3 halves the SQLi false alarms** (9 → 4).
- **v3's 3 XSS false alarms** are the JSON fields of `POST /v1/admin/new-beer/`, whose JSON response echoes
  the marker. Dropping the content-type features (F1) removed v2's only signal that a JSON response is not
  rendered. This is the price of F1, and the same marker-reflection prior seen in the leave-one-app-out errors.
- **Nothing was changed after this result.**

| Rule-based (same rules in v2 and v3) | SirAppSec |
|---|---|
| CWE-22 / CWE-601 | found 1 of 1 / 1 of 1, 0 false alarms on 37 safe endpoints. CWE-78 is not evaluable: its only instance, `/v1/status`, is never requested |
| Passive | found 4 of 4 (CSP, nosniff, framing, cookie without HttpOnly); 0 false alarms on 2 negatives (SameSite present, no CORS) |
| Stored XSS (v3) | found 0 of 1. The sink is the new user's own `/profile?id=<new>`, which is never a crawled page, as expected in the ground truth. Outside the rule's scope: `GET /registerform` |
| CSRF heuristic (v3) | 0 known instances in scope (only GET forms, SameSite=Lax). Its real CSRF is a state-changing GET, outside the heuristic by design |

#### Rule-based checks on the training apps (counts, not rates)

| Check | Found / known | False alarms | Missed |
|---|---|---|---|
| CWE-78 | 3 of 4 | 0 on 186 safe endpoints | vulnerable-node `/tools/ping` (no ping binary) |
| CWE-22 | 4 of 5 | 0 on 185 | Juice Shop `/ftp/{file}` |
| CWE-601 | 4 of 5 | 0 on 185 | vulnerable-node `returnurl` (only after a successful login) |
| Passive (6 checks × apps) | 33 of 33 | 0 | – |
| **Stored XSS** | **2 of 8** | 0 on 8 safe fields | NodeGoat `/profile` × 6. Its update is refused unless `bankRouting` matches `/([0-9]+)+\#/`, so a crawl that sends the form's empty value as "test" never stores anything |
| **CSRF heuristic** | **13 of 20** | 0 on 6 safe forms | NodeGoat login/signup/profile (unvalidated `_csrf` field: the known blind spot); NodeGoat `/memos` (page not crawled); vulnerable-node `/register`, `/account`, `/account/token` (skip-listed pages, so the forms are never seen) |

Known stored-XSS instances outside the rule's scope: DSVW `/?comment` (a GET write), vulpy posts (behind a login
that fails in the lab), and NodeGoat memos (a markdown-only bypass). Full report: `reports/rules_v3.md`.

#### ZAP comparison

**Setup:**
- Offline ZAP, unmodified `zap-full-scan.py`, unauthenticated, no seeds, as in v1 and v2.
- **Exclusions:** this time every skip-listed and remote-fetch parameter was put on ZAP's global exclude list.
- **Usability rule:** a scan is used only if the wrapper exits 0, the target was not killed or restarted, and
  its request log shows no excluded parameter or path (`scripts/zap_run_v3.py`, `logs/zap_v3/*.status`).
- **The DSVW scan is unusable again.** ZAP itself sent 398 requests carrying excluded parameters (204 with
  `include=`), so the global exclude list did not hold either. DSVW has no resolver, so nothing left the lab.
  DSVW is excluded from the comparison, not scored as a ZAP miss.

| Set (endpoint-params) | ml-dast v3 | ZAP | ml-dast − ZAP [95% CI] |
|---|---|---|---|
| All usable (157) | 0.874 [0.814, 0.923] | 0.915 [0.858, 0.961] | −0.042 [−0.113, +0.027], not significant |
| Own (105) | 0.825 | **0.954** | **−0.131 [−0.206, −0.053]** |
| Third-party (52) | 0.959 | 0.848 | +0.115 [−0.018, +0.253] |

| Check (counts) | Known | ml-dast | ZAP |
|---|---|---|---|
| CWE-78 / CWE-22 / CWE-601 | 4 / 5 / 5 | 3 / 4 / 4 | 2 / 2 / 3 |
| Stored XSS | 8 | 2 | 1 |
| CSRF (forms) | 20 | 13 | 9 |

In v2, ZAP was significantly better overall (−0.112). In v3 the gap is no longer significant. ZAP is still
better on our own apps, where all of ml-dast's XSS false alarms are; ml-dast is ahead on the third-party apps.
Full tables: `reports/zap_comparison_v3.md`.

**ZAP on SirAppSec:** **not available.** The scan did not finish within its 45-minute limit (: wrapper timeout). Several SirAppSec handlers never answer, so ZAP waits out its timeout on each such request. Under the rule fixed before the run, a scan that did not complete is not used, so there is no ZAP comparison on the held-out app. It was not re-run with a longer limit.

### Intended use

- **Intended:** an experimental, opt-in second opinion (`DAST_ENGINE=ml`) on authorized staging targets,
  with v2 as the model in use. v3 is for comparison and further work.
- **Not intended:** replacing ZAP, certifying an app as free of injection, or gating a pipeline on DAST
  findings. The security gate never reads DAST findings (tested).

### Limitations

1. **ML covers SQLi and reflected XSS only.** Every other class is rule-based and was evaluated on very few
   instances.
2. **SQLi with plain-text or JSON errors is no longer missed on the held-out app**, but the training evidence
   is still thin: own twins, DSVW and VAmPI.
3. **XSS is the thinnest class** (688 rows; 32 endpoint-params). v3 over-flags harmless reflections,
   including JSON echoes, because the content type is no longer a feature.
4. **No authenticated scanning in `/scan`.** Lab collection logs in for some apps, but the service cannot.
5. **No stored XSS behind a login.** The stored-XSS rule also misses:
   - sinks that are not crawled pages (a new record's own page);
   - writes the server refuses because of format checks it cannot satisfy (NodeGoat);
   - GET writes;
   - markdown-only bypasses.
6. **CSRF is a heuristic** (LOW, confidence 0.5):
   - a token field that is never validated counts as protected;
   - state-changing GETs are out of scope;
   - forms on skip-listed or uncrawled pages are not seen.
7. **The rule limitations carry over from v2:** CWE-78 needs observable output or a delay, and CWE-22
   recognizes `/etc/passwd` only.

### Threats to validity

- **Optimistic leave-one-app-out:** the v3 feature changes (F1 to F6) were chosen from the v2 errors on these
  folds, after two earlier feature rounds. The held-out app is the honest estimate.
- **Threshold at the grid edge, again:** every outer fold chose t=0.95, the top of the grid that was extended
  for v3. It was not extended again (that would be another round of tuning).
- **Tiny held-out:** 38 endpoint-params, with 2 SQLi and 2 XSS. The 95% CIs are wide, and the decision rests
  on a non-significant difference.
- **Author bias:** 3 of 10 training groups and all `/v3` twins were written by me, as were the payloads and rules.
- **Ground-truth additions prompted by results:** the rule-based CSRF labels for labflask `/find-safe` and
  vulnerable-node `/tools/regex`. Both forms were missing from the first labelling, were flagged by the rule,
  then verified in source. The vulnerable-node review form was un-skipped before its collection. All of these
  are logged in `changes_v3`. No ML label changed after v3 results.
- **DSVW reuse:** it was the v2 held-out (scored once) and is a v3 training app.

### Reproduce (v3)

```bash
cd services-ml/ml-dast
lab/fetch-vendor.sh && (cd lab && docker compose --profile final-v2 up -d --build labflask labexpress labexpress-db labfastapi labfastapi-db juice-shop nodegoat nodegoat-db vulpy-bad vulpy-good vulnerable-node vn-db vn-mongo vampi node-api-goat dsvw)
for a in labflask labexpress labfastapi juice-shop nodegoat vulpy-bad vulpy-good vulnerable-node vampi node-api-goat dsvw; do python scripts/collect_lab.py --data v3 $a; done
python scripts/eval_rules_v3.py                                   # rule counts -> reports/rules_v3.md
python scripts/loao.py --data v3                                  # main evaluation -> reports/loao_v3.md
python scripts/loao.py --data v3 --features v2 --kinds lr         # the v2 system on the enlarged data
python scripts/compare_before_after.py --before reports/loao_clusters_v2.json --after reports/loao_clusters_v3.json --out reports/before_after_v3.json
python scripts/compare_before_after.py --before reports/loao_clusters_v3data_v2feat.json --after reports/loao_clusters_v3.json --out reports/before_after_v3_enlarged.json
python scripts/select_v3.py && python scripts/train_final_v3.py
python scripts/eval_final_v3.py                                   # once only: SirAppSec, v3 and v2 on the same records
python scripts/zap_run_v3.py labflask labexpress labfastapi vulnerable-node vampi node-api-goat dsvw && python scripts/zap_compare_v3.py
```

---

### v2 (`ml-dast-lr` 2.0.0), kept for reference

v2 of the CloudSentinel `ml-dast` service (`DAST_ENGINE=ml`). It has two parts:

- **Machine learning** for SQL injection (CWE-89) and reflected XSS (CWE-79): logistic regression over
  response features, as in v1, with new features chosen from an error analysis of v1.
- **Deterministic rules, not machine learning,** for OS command injection (CWE-78), path traversal
  (CWE-22), open redirect (CWE-601), and passive checks of security headers, session cookies and CORS
  (`dastml/rules.py`). Every rule finding says `[rule-based]`.

**ZAP stays the default DAST engine.** In leave-one-app-out the v2 model is not significantly better than
v1 on the same endpoints. On the third-party apps it got significantly worse once more training data was
added. On the new frozen held-out app (DSVW, scored once) it found both reflected XSS and **none of the
3 SQL injections**. The rules found every known instance on DSVW with no false alarms.

| | |
|---|---|
| Artifact | `services-ml/ml-dast/models/release_v2/model.joblib` (gitignored), metadata in `model.json` |
| SHA-256 | `5dc397d0b6c4…` (full value in `/model-info` and `reports/final_preregistration_v2.json`) |
| ML component | Logistic regression (`C=0.1`, balanced class weights, standardized inputs) over 70 response features; the location one-hot was dropped by the inner selection |
| Decision rule (ML) | As v1: a row with a class-C payload is C if P(C) ≥ 0.9; an endpoint parameter is C if any of its C rows is |
| Rule-based component | CWE-78: the shell must compute `{M}1337` from `{M}$((7*191))`, or `;sleep 2` must be ≥ 1.6 s slower than `;sleep 0` (sent twice). CWE-22: `/etc/passwd` content absent from the baseline. CWE-601: a 3xx `Location` to `{M}.invalid` (scheme-less payload, header only, never followed). Passive: CSP, `nosniff`, framing protection, session cookie HttpOnly/SameSite, CORS echo; **LOW/INFO only, never gate-blocking** |
| Precedence | Quote-parity and timing signals also fire for shell quoting. When the CWE-78 rule confirms command injection on a parameter, the SQLi score on that parameter yields to it |
| Payloads | `data/dast/payloads/payloads_v2.json`: every v1 payload unchanged, plus sleep-0 controls and repeats, quote-parity partners, and the rule payloads |
| Selection | Highest pooled leave-one-app-out macro-F1 among LR, RF and LightGBM (`reports/selection_v2.json`), fixed before DSVW was collected |
| Previous | v1 `ml-dast-lr` 1.0.0, see [v1](#v1-ml-dast-lr-100-kept-for-reference) |

#### What changed from v1, and why

**Error analysis first.** The v1 leave-one-app-out errors were 3 false positives and 2 false negatives
per class. I traced each one to its deciding row and the endpoint's source:

| v1 error | Cause | v2 change |
|---|---|---|
| SQLi FP on labexpress `/dns` | The real CWE-78 endpoint, labelled safe for SQLi; the shell hangs about 5 s | CWE-78 rule plus precedence |
| SQLi FP on `/dns-safe` | A DNS lookup of junk input is slow; one-shot timing | `dose_*`: sleep-N vs sleep-0, sent twice, the faster counts |
| SQLi FP on `/slow` | A *faster* response raised the SQLi score (signed time ratio) | `time_slow_*`: slowdowns only |
| SQLi FN on `/book/{id}` | `loc_path` acted as an app-specific prior (0.895 < 0.9) | Inner selection may drop the location one-hot (it did) |
| SQLi FN on JSON `/api/status` | A generic 500 cannot be told apart from non-SQL errors | `parity_*`: `'` breaks the response and `''` restores it |
| XSS FP × 3 on `-safe` twins | `javascript:x()` has no HTML specials, so escaping leaves it unchanged | `html_specials_*`, `ctx_url_attr`, `raw_reflected_dangerous` |
| XSS FN × 2 on NodeGoat `/signup` | **Label error:** `firstName`/`lastName` are never re-rendered (session.js lines 200-204) | Relabelled from source, disclosed |

**Disclosed iterations.** Two feature rounds were run on the same leave-one-app-out folds:
- **Round 1** left the `javascript:` false alarms in place, because a linear model cannot combine the new
  parts. That led to `raw_reflected_dangerous`.
- **The feature set was then frozen.** The final data was evaluated once with it, and DSVW is the clean check.

**More data:**
- **vulnerable-node** joined as a third-party training app (cr0hn @ d68f2a3, labelled from source).
- **20 own-app endpoints:** realistic safe ones (validated JSON APIs, slow upstreams, escaped 404s,
  same-site redirects and links) and vulnerable twins.
- **New frozen held-out app: DSVW** (stamparm @ 9ca3c9a). It was labelled from `dsvw.py` and frozen by SHA-256
  before any request (`data/dast/FREEZE_v2.json`).
- **DVNA stays frozen and untouched.** v2 changes the probe, so the v2 model is never scored on DVNA; DVNA's
  0.389 remains the v1 result.

**Guards (stricter only):**
- `skip` may name a parameter.
- Any request whose parameters carry a URL is refused, so a crawled link can never make the target fetch
  another host.
- Session cookies are now read from every hop of a same-origin redirect chain.

#### Data (v2)

| App group | Origin | Rows (ML) | SQLi / XSS endpoint-params | Safe |
|---|---|---|---|---|
| labflask, labexpress, labfastapi | own | 3,650 | 13 / 10 | 50 |
| Juice Shop, NodeGoat, vulpy (bad+good), vulnerable-node | third-party | 1,818 | 10 / 11 | 17 |
| **Training total** (7 LOAO groups) | | **5,468** (4,350 safe, 782 SQLi, 336 XSS) | **23 / 21** | 67 |
| DSVW (v2 final held-out) | third-party | 534 | 3 / 2 | 7 |

Ground truth: `data/dast/ground_truth_v2.json`, summarized in `data/dast/GROUND_TRUTH.md` (v2 section).

#### Results

The metric is the same as v1:
- **ML:** endpoint-param macro-F1, with 95% cluster bootstrap intervals (1,000 resamples), per class too.
- **Rules:** counts, because n is too small for rates.

##### Main: leave-one-app-out (final data, 7 groups, 111 endpoint-params)

| Set | LR (selected) | RF | LightGBM |
|---|---|---|---|
| All (111) | **0.827 [0.744, 0.894]** | 0.696 [0.592, 0.778] | 0.731 [0.633, 0.810] |
| Own apps (73) | 0.871 [0.767, 0.945] | 0.787 | 0.845 |
| **Third-party (38)** | **0.757 [0.609, 0.884]** | 0.521 | 0.520 |

LR per class over all apps:

| Class | P / R / F1 (n) | F1 95% CI |
|---|---|---|
| SQLi | 0.85 / 0.96 / 0.90 (23) | [0.80, 0.98] |
| XSS | 0.71 / 0.71 / 0.71 (21) | [0.54, 0.85] |

On the third-party apps, XSS recall is 0.45 (11), F1 CI [0.20, 0.80]. NodeGoat's XSS fold fell to 0.571.

##### Before / after on the same 78 endpoint-params

Paired cluster bootstrap. "Before" is the v1 model re-scored on the corrected labels.

| Set | Before (v1, corrected labels) | After (v2, final) | After − before [95% CI] |
|---|---|---|---|
| All (78) | 0.858 [0.778, 0.934] | 0.831 [0.732, 0.904] | −0.031 [−0.128, +0.066], not significant |
| Own (53) | 0.775 | 0.872 | +0.100 [0.000, +0.203] |
| Third-party (25) | 1.000 | 0.774 | **−0.234 [−0.390, −0.089]** |

What this shows:
- **The error-driven fixes worked on the data they were designed on.** With the original 7 apps, round 2
  reached LR 0.877, RF 0.933 [0.868, 0.984] and LightGBM 0.900. RF and LightGBM were significantly better
  than before (`reports/loao_v2_iter2_7apps.md`).
- **Adding data did not improve the honest estimate. It hurt third-party XSS.** The extra own-app XSS
  patterns moved the decision away from NodeGoat's attribute-context reflections.
- **I did not tune anything in response.**

##### Rule-based checks on the training apps (counts, not rates)

| Check | Result | Missed (cause) |
|---|---|---|
| CWE-78 | found 2 of 3, 0 false alarms on 107 safe endpoints | vulnerable-node `/tools/ping`: the image has no `ping` binary, so the injected output never appears |
| CWE-22 | found 3 of 4, 0 false alarms on 106 safe endpoints | Juice Shop `/ftp/{file}`: the null-byte bypass stays inside `ftp/`, so no `/etc/passwd` appears |
| CWE-601 | found 3 of 4, 0 false alarms on 106 safe endpoints | vulnerable-node `returnurl`: only redirects after a successful login |
| Missing CSP | found 7 of 7, 0 false alarms on 1 app without the issue | |
| Missing nosniff | found 7 of 7, 0 false alarms on 1 app without the issue | |
| Framing unprotected | found 7 of 7, 0 false alarms on 1 app without the issue | |
| Cookie without SameSite | found 2 of 2, 0 false alarms on 4 apps without the issue | |
| Cookie without HttpOnly | 0 known instances, 0 false alarms on 6 apps | vulpy is not evaluable: login crashes on a bytes cookie value |
| CORS echoes any origin | 0 known instances, 0 false alarms on 8 apps | |

##### Final held-out app: DSVW, single run

DSVW was frozen before any request. The model was fixed by SHA-256 before collection
(`reports/final_preregistration_v2.json`), and the script refuses a second run.

**Disclosed:** attempt 1 was aborted during collection. DSVW was OOM-killed after the crawler followed its
own `RANDOMBLOB(300000000)` exploit link under a 128 MB limit. No data and no model output existed. The fix
was a 2 GB memory limit; nothing else changed (`reports/final_dsvw_aborted_attempt1.json`).

| DSVW (12 endpoint-params) | Result |
|---|---|
| ML macro-F1 | **0.608 [0.368, 1.000]** |
| XSS (`/?v`, `/?tmpl`) | found 2 of 2, 0 false alarms |
| SQLi (`/?id`, `/login` `password`, `/?comment`) | **found 0 of 3**, 0 false alarms |
| CWE-78 / CWE-22 / CWE-601 rules | found 1 of 1 each, 0 false alarms on 11 safe endpoints |
| Passive | found 5 of 5; CORS correctly not flagged |

**Why SQLi was missed** (`reports/final_dsvw_explain.json`; explanation only, no re-scoring):
- `/login` `password` and `/?comment` scored 0.882 and 0.894, just under the 0.9 threshold. Quote parity
  fired on both.
- `/?id` shows its real SQLite error as a **text/plain** 500. In training, text/plain responses were only
  ever XSS hard negatives, so the model learned "text/plain means safe" for SQLi too (−5.9 log-odds), and
  that outweighed the SQL error signature.

The DSVW interval is wide (12 endpoint-params) and should not be compared with v1's DVNA 0.389 (a
different app).

##### ZAP comparison

**Setup.** Offline ZAP, unmodified `zap-full-scan.py`, unauthenticated and without seeds, on the same units
(`reports/zap_comparison_v2.md`). The own apps and vulnerable-node were re-scanned for v2
(`logs/zap_v2/`); Juice Shop, NodeGoat and vulpy reuse their unchanged v1 scans.

| Set (endpoint-params) | ml-dast ML | ZAP | ml-dast − ZAP [95% CI] |
|---|---|---|---|
| All (111) | 0.827 [0.744, 0.894] | **0.937 [0.882, 0.979]** | **−0.112 [−0.202, −0.028]** |
| Own (73) | 0.871 | 0.966 | −0.098 [−0.208, +0.004] |
| Third-party (38) | 0.757 | 0.890 | −0.130 [−0.287, +0.034] |

TP/FP/FN, all apps:

| System | SQLi | XSS |
|---|---|---|
| ml-dast | 22/4/1 | 15/6/6 |
| ZAP | 18/0/5 | 21/1/0 |

**Rule-based classes and passive checks** (counts):

| Check | Known | ml-dast found | ZAP found | ml-dast false alarms | ZAP false alarms |
|---|---|---|---|---|---|
| CWE-78 | 3 | 2 | 2 | 0 | 0 |
| CWE-22 | 4 | 3 | 2 | 0 | 0 |
| CWE-601 | 4 | 3 | 3 | 0 | 0 |
| Missing CSP / nosniff / framing (apps) | 7 / 7 / 7 | 7 / 7 / 7 | 7 / 7 / 7 | 0 | 0 |
| Cookie without SameSite (apps) | 2 | 2 | 2 | 0 | 2 (non-session cookies) |
| CORS echoes any origin (apps) | 0 | 0 | 0 | 0 | 1 (Juice Shop wildcard without credentials) |

ZAP is significantly better than the ML part on SQLi/XSS. The rules match or beat ZAP on these few
instances, and the passive checks raise fewer false alarms because they only consider session-like
cookies and only flag CORS that is actually exploitable.

**ZAP on DSVW: incomplete, not a valid comparison.** DSVW was killed (exit 137) during the ZAP scan.
ZAP's spider also requested the parameters excluded in `lab/zap-dsvw.context` (`?include=https://…`,
`?xml=…`, `?path=http://…`): the context did not stop its spider. Those requests failed because the DSVW
container has no DNS resolver, so nothing left the lab. The incomplete scan scores 0.246 against
ml-dast's 0.608; it is not used as evidence. This is a lesson for future ZAP runs on DSVW: use a
URL-exclusion rule for the spider (`-config spider.excludes…`) in addition to the context, or a smaller
spider scope.

#### Intended use

- **Intended:** an experimental, opt-in second opinion (`DAST_ENGINE=ml`) on authorized staging targets.
  The rule-based checks are a cheap complement.
- **Not intended:** replacing ZAP, certifying an app as free of injection, or gating a pipeline on DAST
  findings. The security gate never blocks on DAST.

#### Limitations

1. **The ML classes are SQLi and reflected XSS only.** Everything else is rule-based and was evaluated on
   very few known instances.
2. **SQLi shown in non-HTML error responses** (text/plain tracebacks) is systematically under-scored; see
   DSVW.
3. **Third-party XSS recall is low** (0.45 in leave-one-app-out), mostly NodeGoat's attribute contexts.
4. **No authentication in `/scan`.** Cookies or redirects that appear only after login are not seen.
5. **The command-injection rule needs observable output or a controllable delay.** Blind injection inside
   quotes, or when the binary is missing, is not seen.
6. **The CWE-22 rule only recognizes `/etc/passwd`.**
7. **v1 timing features made v1 results load-dependent:** a shipped-model test failed under heavy
   machine load. v2 drops the signed timing features.

#### Threats to validity

- **Small evaluation sets:** DSVW has 12 endpoint-params, and rule classes have 1 to 4 known instances.
- **Author bias:** 3 of 8 training app groups and all B3 endpoints were written by me, as were the payloads.
- **Repeated feature iteration** on the same leave-one-app-out folds (two rounds) makes the round-2 numbers
  optimistic. The final data and DSVW were each evaluated once with the frozen feature set.
- **Labels changed after seeing errors:** the NodeGoat `/signup` correction, vulpy-good's CSP, and vulpy's
  cookie checks set to not evaluable. Each was verified in source and is logged in `ground_truth_v2.json`
  under `changes`.
- **Supplementary collection:** the CWE-601 payloads were added after the final collection to the same
  recorded points (`scripts/collect_supplement_v2.py`). ML rows were not affected.

#### Reproduce (v2)

```bash
cd services-ml/ml-dast
lab/fetch-vendor.sh && (cd lab && docker compose up -d --build labflask labexpress labfastapi juice-shop nodegoat vulpy-bad vulpy-good vulnerable-node)
python scripts/collect_lab.py --data v2 && python scripts/collect_supplement_v2.py
python scripts/loao.py --data v1 --labels v2      # "before" on corrected labels
python scripts/loao.py --data v2                  # main evaluation -> reports/loao_v2.md
python scripts/compare_before_after.py            # paired before/after
python scripts/eval_rules.py                      # rule counts -> reports/rules_v2.md
python scripts/select_v2.py && python scripts/train_final_v2.py
(cd lab && docker compose --profile final-v2 up -d dsvw) && python scripts/eval_final_v2.py   # once only
```

---

#### v1 (`ml-dast-lr` 1.0.0), kept for reference

This is a request/response classifier for the CloudSentinel `ml-dast` service (`DAST_ENGINE=ml`). It
covers SQL injection (CWE-89) and reflected XSS (CWE-79) in Python and Node.js web apps. **ZAP stays
the default DAST engine.** On the same lab endpoints the offline ZAP baseline matches or beats this
model, and ZAP raised no false positives. On the frozen held-out app (DVNA, scored once) the model
found 1 of 2 vulnerable parameters and raised 1 false class.

| | |
|---|---|
| Artifact | `services-ml/ml-dast/models/release/model.joblib` (gitignored; a `dastml.detector.DastDetector`), metadata in `model.json` |
| SHA-256 | `ce04524f2f3b…` (full value in `/model-info` and `reports/final_preregistration.json`) |
| Model | Logistic regression (`C=0.1`, balanced class weights, standardized inputs) over 65 response features |
| Decision rule | A row sent with a class-C payload is C if P(C) ≥ 0.9. An endpoint parameter is reported as C if any of its C rows is (the highest probability wins). The threshold was chosen by inner leave-one-app-out; `ML_DAST_CONFIDENCE_THRESHOLD` overrides it |
| Rule-based component | **None** in the shipped decision. The payload list is fixed, not learned. Two rule-based reference detectors appear only as baselines in the reports |
| Classes | `safe`, CWE-89, CWE-79. CWE-78 and CWE-22 are not covered: phase 2 was not started |
| Selection | Highest pooled leave-one-app-out macro-F1 among LR, RF and LightGBM, written down in `reports/selection.json` before DVNA was scored |

##### How it scans

`/scan` runs these steps:

1. **Crawl.** Same-origin crawl over HTML links and forms. Injection points are query, form, JSON and
   numeric path parameters.
2. **Probe.** Each point gets two baseline requests (the original value, to measure noise), one benign
   probe (a random token: is the parameter reflected at all?), then 28 SQLi and 16 XSS payloads from
   `data/dast/payloads/payloads.json`. This is my own list, which follows PayloadsAllTheThings (MIT)
   categories; nothing was copied. Every payload carries a unique marker.
3. **Classify.** One feature row per payload response, scored by the model.

**Features** (`dastml/features.py`), all measured relative to the baselines:

- status and status change;
- length change against baseline noise; token similarity;
- time delta;
- new SQL error signatures (SQLite, MySQL, PostgreSQL, generic); new stack traces and generic errors;
- content type and `nosniff`;
- reflection: marker reflected; payload reflected raw, HTML-escaped or URL-encoded; special characters
  kept in place; HTML context (text, attribute, script, comment);
- contrast between the true and false response of a boolean SQL pair;
- payload class, family and location.

**No URL, path, parameter-name or body-token features.** Those would let the model memorize endpoints.

**Safety** (`dastml/guards.py`, 24 tests):

- exact host and port allowlist (default 127.0.0.1 / localhost on the lab ports);
- same-origin requests only; off-origin redirects are never followed;
- page and request budgets, and a rate limit;
- proxy settings from the environment are ignored;
- a skip list of never-attack paths.

A target outside the allowlist is refused with HTTP 400 before any traffic is sent.

##### Data

The lab is `services-ml/ml-dast/lab/docker-compose.yml`, published on 127.0.0.1 only. Labels come
from the ground truth (`data/dast/GROUND_TRUTH.md`, `ground_truth.json`). Each endpoint was read in
the app's source at a pinned commit or image; Juice Shop was also checked against the running app.
**Labels never come from scanner output.** A row is C only if its (endpoint, parameter) is vulnerable
to C and a C payload was sent; anything unlisted is dropped.

There is no synthetic data. The "own" apps are written by me, the same author as the payloads and
features, and are reported separately as the less honest half.

| App group | Origin | Rows | Vulnerable endpoint-params (SQLi / XSS) | Safe |
|---|---|---|---|---|
| labflask (Flask + SQLite) | own | 968 | 4 / 3 | 15 |
| labexpress (Express + PostgreSQL) | own | 792 | 4 / 2 | 12 |
| labfastapi (FastAPI + MySQL + Jinja2) | own | 572 | 4 / 2 | 7 |
| Juice Shop v20.4.0-SNAPSHOT | third-party | 176 | 2 / 0 | 2 |
| NodeGoat @ c5cb68a | third-party | 572 | 0 / 12 | 1 |
| vulpy bad + good @ 5249cc8 (one group) | third-party | 352 | 4 / 0 | 4 |
| **Training total** | | **3,432** | **18 / 19** | 41 |
| DVNA (final held-out, frozen by SHA-256) | third-party | 160 | 1 / 1 | 2 |

Rows: 2,624 safe, 504 SQLi and 304 XSS (3.3 safe rows per positive). The safe endpoint-params include
safe twins of every vulnerable endpoint in my apps, plus hard negatives: raw reflection in JSON and
`text/plain`, non-SQL stack traces, and input-dependent timing.

##### Results

The metric is macro-F1 over the classes present (`safe`, CWE-89, CWE-79). The headline is
**endpoint-param level**; row-level results are also given.

- **Endpoint-param level:** each (endpoint, parameter) is one unit, flagged C if any of its C rows is.
- **Intervals:** 95% bootstrap with 1,000 resamples **over endpoint-params**, not rows.

###### Main: leave-one-app-out over the 6 training groups

Each group is the unseen test app once. Hyperparameters and the threshold are chosen by an inner
leave-one-app-out over the other 5 groups only. Predictions are pooled.

| Set (endpoint-params) | LR (selected) | RF | LightGBM |
|---|---|---|---|
| All (78) | **0.871 (0.790–0.945)** | 0.643 (0.524–0.747) | 0.774 (0.672–0.862) |
| Own apps (53) | 0.833 (0.695–0.926) | 0.788 | 0.724 |
| **Third-party apps (25)** | **0.928 (0.811–1.000)** | 0.383 | 0.877 |
| Row-level, all | 0.801 | 0.582 | 0.739 |

Pairwise differences on all apps:
- LR − LightGBM: +0.098 (+0.016 to +0.179).
- LR − RF: +0.230 (+0.111 to +0.354).

**LR per class, endpoint-param level:**

| Set | SQLi P / R / F1 (n) | XSS P / R / F1 (n) | safe F1 (n) |
|---|---|---|---|
| All | 0.84 / 0.89 / 0.86 (18) | 0.85 / 0.89 / 0.87 (19) | 0.88 (41) |
| Own | 0.77 / 0.83 / 0.80 (12) | 0.70 / 1.00 / 0.82 (7) | 0.87 (34) |
| Third-party | 1.00 / 1.00 / 1.00 (6) | 1.00 / 0.83 / 0.91 (12) | 0.88 (7) |

**LR per held-out app, endpoint macro-F1:**

| App | Macro-F1 |
|---|---|
| Juice Shop | 1.000 |
| labexpress | 0.845 |
| labfastapi | 0.838 |
| labflask | 0.843 |
| NodeGoat | 0.705 |
| vulpy | 1.000 |

The confusion-matrix PNGs are in `services-ml/ml-dast/reports/confusion_<model>_<set>.png`. The LR
confusion over all apps, endpoint level:

| True ↓ / predicted → | safe | CWE-89 | CWE-79 |
|---|---|---|---|
| safe | 35 | 3 | 3 |
| CWE-89 | 2 | 16 | 0 |
| CWE-79 | 2 | 0 | 17 |

**What the comparison shows:**

- RF overfits signals from my apps and finds **none** of NodeGoat's XSS.
- LR is best, and it is the only model that does not get worse on third-party apps. The third-party
  set is small, though: 6 SQLi endpoint-params (about 3 independent sinks) and 12 XSS endpoint-params,
  all from NodeGoat and mostly one template.

###### ZAP comparison (same 78 endpoint-params)

ZAP 2.17.0 ran from the offline image `cloudsentinel/zap-offline:verified-closure`:

- unmodified `zap-full-scan.py`, on the lab network;
- unauthenticated and without seeds;
- the frozen ZAP code in the backend was not touched.

ZAP alerts 40018–40027 and 90018 count as SQLi; 40012 and 40014 count as XSS.

| Set | ML (pooled leave-one-app-out) | ZAP | ML − ZAP |
|---|---|---|---|
| All | 0.871 (0.790–0.945), SQLi 16/3/2, XSS 17/3/2 | **0.917 (0.846–0.971)**, SQLi 14/0/4, XSS 17/0/2 | −0.045 (−0.130 to +0.040) |
| Own apps | 0.833 | **0.960** | −0.133 (−0.269 to −0.018) |
| Third-party | **0.928** | 0.829 | +0.107 (0.000 to +0.258) |

TP/FP/FN are counts of endpoint-params.

**Reading the comparison:**

- **ZAP raised no false positives**; ML raised 6.
- ML's lead on third-party apps comes entirely from Juice Shop, a coverage difference rather than
  better detection. ML was given Juice Shop's API endpoints as seeds, which ZAP's spider never
  reaches. On NodeGoat (10/0/2) and vulpy (4/0/0), ML and ZAP got identical counts.
- **Lab incidents during the ZAP scans:**
  - labexpress crashed: an unhandled database error in an async handler.
  - Juice Shop ran out of JS heap.
  - Both were fixed (`06a2065`) and re-scanned. The ML data had been collected before, and the
    crash path was never hit.

###### Final held-out app: DVNA, single run

DVNA was frozen (`data/dast/FREEZE.json`) and excluded from all loading. It was scored once by
`scripts/eval_final.py`, which records the model SHA-256 first and refuses a second run. Its features
were rebuilt once, before scoring, from the unchanged raw records after the `specials_kept` fix; this
is recorded in `FREEZE.json`.

| DVNA endpoint-param | Truth | ML |
|---|---|---|
| `POST /app/products` `name` | CWE-79 | **CWE-79** ✓ |
| `POST /app/usersearch` `login` | CWE-89 (blind) | safe ✗ (top score 0.886 < 0.9) |
| `POST /app/ping` `address` | safe for SQLi/XSS (it is CWE-78, phase 2) | CWE-79 ✗ |
| `POST /forgotpw` `login` | safe | safe ✓ |

**Single-run scores:**
- Endpoint macro-F1: **0.389**. With 4 endpoint-params, the 95% interval is (0.0–1.0), so it says
  almost nothing.
- Row macro-F1: 0.489.

**Why the two errors happened.** The `/app/ping` XSS score came from a large anomalous response change
(the input runs in a shell), not from a reflection. That is a real vulnerability reported with the
wrong class.

**Crawler coverage on DVNA:**
- **Reached:** 4 of 7 listed parameters.
- **Missed:** `/login`, because logged-in users are redirected away from it, and `modifyproduct?id`,
  because nothing links to it.

**ZAP on DVNA: timed out, no report.** The unauthenticated full scan produced no report, and it was
not retried. Note that without login, ZAP sees almost nothing of DVNA anyway.

##### Intended use

- **Intended:** an experimental, opt-in second opinion on the baseline DAST path (`DAST_ENGINE=ml`),
  on staging deployments the backend has authorized. Configure the allowlist to the staging host and
  ports.
- **Not intended:** replacing ZAP as the DAST gate, scanning anything not explicitly allowlisted, or
  claiming an app is free of SQLi or XSS.

##### Limitations

1. **Only two classes.** It covers CWE-89 and reflected CWE-79. Command injection and path traversal
   are not covered; DVNA shows the model calling a command-injection endpoint XSS.
2. **No authentication in `/scan`.** Pages behind a login are not reached; the lab collection used
   per-app login recipes.
3. **Crawler limits.** It follows HTML links and forms only. Single-page-app APIs need seeds, and
   unlinked pages are never found.
4. **Blind SQLi is hard.** It is detected only through boolean-pair contrast or 1-second time payloads,
   and SQLite has no time payload. DVNA's blind SQLi was missed at 0.886.
5. **XSS scope.** Only reflected XSS is detected; stored and DOM XSS are not.
6. **Fragile threshold.** At the 0.9 threshold several decisions sit close to the line:
   - DVNA's blind SQLi: 0.886, missed.
   - The fixture's error-based SQLi: 0.79, missed (a documented `xfail` test).
   - An escaped XSS twin: 0.898, almost a false positive. A `javascript:` payload has no HTML special
     characters, so it is reflected even when the output is escaped.
7. **Threshold grid capped.** LR and LightGBM often chose the top of the grid (0.9); the grid was
   not widened after seeing the test folds.
8. **Coverage depends on budget.** Each injection point costs about 47 requests, and with the default
   500-request budget only about 10 points are scanned.

##### Threats to validity

- **Few independent positives.** Third-party evidence rests on about 3 SQLi sinks and one NodeGoat
  XSS template. DVNA has 4 endpoint-params. All intervals are wide.
- **Author bias.** I wrote 12 of the 18 SQLi and 7 of the 19 XSS positive endpoint-params, as well
  as the payloads and the features. The own-vs-third-party split is reported for this reason.
- **Payload knowledge.** Two parenthesis-depth SQLi pairs were added, before any collection, after I
  tested Juice Shop's search by hand. The Juice Shop SQLi result may be optimistic (`PAYLOADS.md`).
- **App fingerprinting.** A random forest predicts the app from the features with 55% accuracy
  (majority baseline 28%). This cannot leak labels across leave-one-app-out folds, but it allows
  app-specific shortcuts.
- **Row-level label noise.** Labels are exact per endpoint, but many positive rows cannot fire, such as
  a numeric payload in a string context. Share of positive rows with no anomaly: 23% (own SQLi), 54%
  (third-party SQLi), 17% (third-party XSS). This is why endpoint level is the headline.
- **A bug found late.** A feature bug (`specials_kept` counted the page's markup as payload
  characters) was found by a test after the first leave-one-app-out run. Everything was re-featurized
  and re-run before selection and before DVNA. It is disclosed in `52b2c63`.
- **Time features.** The ZAP test scan overlapped the labexpress and labfastapi collection, and
  stored payloads (NodeGoat, vulpy create) change app state. Per-request markers keep stored copies
  from counting as reflection.
- **Teaching apps.** All the third-party apps are deliberately vulnerable teaching apps; production
  apps behave differently.

##### Reproduce

See [`services-ml/ml-dast/README.md`](../services-ml/ml-dast/README.md#lab-data-and-reproduction).

| Step | Time |
|---|---|
| Collection | ~5 min |
| Leave-one-app-out | ~4 min on 8 CPU threads |
| ZAP scans | 2–12 min per app |
