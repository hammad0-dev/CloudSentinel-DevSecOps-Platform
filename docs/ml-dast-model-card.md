# Model card: ml-dast 1.0.0 (`ml-dast-lr`)

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

## How it scans

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

## Data

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

## Results

The metric is macro-F1 over the classes present (`safe`, CWE-89, CWE-79). The headline is
**endpoint-param level**; row-level results are also given.

- **Endpoint-param level:** each (endpoint, parameter) is one unit, flagged C if any of its C rows is.
- **Intervals:** 95% bootstrap with 1,000 resamples **over endpoint-params**, not rows.

### Main: leave-one-app-out over the 6 training groups

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

### ZAP comparison (same 78 endpoint-params)

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

### Final held-out app: DVNA, single run

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

## Intended use

- **Intended:** an experimental, opt-in second opinion on the baseline DAST path (`DAST_ENGINE=ml`),
  on staging deployments the backend has authorized. Configure the allowlist to the staging host and
  ports.
- **Not intended:** replacing ZAP as the DAST gate, scanning anything not explicitly allowlisted, or
  claiming an app is free of SQLi or XSS.

## Limitations

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

## Threats to validity

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

## Reproduce

See [`services-ml/ml-dast/README.md`](../services-ml/ml-dast/README.md#lab-data-and-reproduction).

| Step | Time |
|---|---|
| Collection | ~5 min |
| Leave-one-app-out | ~4 min on 8 CPU threads |
| ZAP scans | 2–12 min per app |
