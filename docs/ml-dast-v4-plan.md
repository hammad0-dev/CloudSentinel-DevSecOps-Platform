# ml-dast v4 plan: OWASP BenchmarkPython (subset) as training data, DVPWA held-out, wider tuning range

Branch `feat/dast-v4-benchmark` (from `origin/master` at `065f3f6`, PR #16 merged). Started 2026-11-21T10:30Z; time cap
1 day. Every decision below is fixed **before** any held-out scan.

## 1. OWASP BenchmarkPython

**Source:** OWASP-Benchmark/BenchmarkPython @ `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` (GPL-3.0, v0.1).

**Runs in Docker here:** yes, verified 35 minutes in, well under the 2-hour viability limit.
- The image uses `lab/benchmarkpython.Dockerfile` with the repo's pinned requirements and Flask on plain HTTP 8080,
  without the debugger.
- **Constraints:** no resolver, 1 GB memory limit (about 50 MB used), and the app user may write only to `./testfiles`.
  Some path-traversal cases open files for writing.

**How a test case is built:**
- One module `testcode/BenchmarkTestNNNNN.py` registers `GET` and `POST /benchmark/<category>-NN/BenchmarkTestNNNNN`.
  The GET handler usually calls the POST handler.
- The input is a parameter named after the test: a form field, a query parameter, the raw query string, a header,
  a cookie, a form-key name, or a request-path segment.
- The response is a plain string (text/html).
- `expectedresults-0.1.csv` gives the category, "real vulnerability" and the CWE.

**How the scanner reaches them:** seeds built from the ground truth (`POST form` or `GET query` points with the test
name as the parameter). The crawl of the 1,230-page index is not needed, and the scanner never reaches the unlisted cases.

**Subset (decided):** the SQLi, XSS, command-injection and path-traversal categories, limited to cases whose input the
probe can drive (form field, query parameter, raw query string). Header, cookie, form-key and constant-path cases
(`request.path.split("/")[1]` is always `benchmark`) are excluded as unreachable.

| Category | In the file (vuln / safe) | Reachable (vuln / safe) | Used for ML rows | Used for rules |
|---|---|---|---|---|
| SQLi (CWE-89) | 5 / 11 | 3 / 7 | all 10 | – |
| XSS (CWE-79) | 31 / 58 | 21 / 29 | all 50 | – |
| Command injection (CWE-78) | 13 / 7 | 8 / 3 | 5 hard negatives* | all 11 |
| Path traversal (CWE-22) | 65 / 103 | 39 / 45 | 15 hard negatives* | all 84 |

\* As safe rows for the ML classes. A seeded random choice (seed 4) of 5 command-injection and 15 path-traversal
cases, 20 endpoints in total, so file and shell endpoints appear as SQLi/XSS negatives without flooding the data.

**Volume:** 155 probed points, about 11k requests; the memory limit is respected.

**Class balance:**
- Every reachable SQLi/XSS case is kept. The in-benchmark ratios are SQLi 3:7 and XSS 21:29; `class_weight="balanced"`
  already handles class imbalance.
- The Benchmark adds 50 XSS endpoint-params (21 vulnerable), the class v3 lacked most.
- To stop one synthetic group from dominating, the rule-category cases contribute only 20 endpoints to the ML rows.

**Ground truth:** the expected-results file, after a source spot-check of a seeded random sample of 16 reachable cases
(3 SQLi, 6 XSS, 3 command injection, 4 path traversal). Reading each handler's sink by hand: **16 of 16 agree**.
- Decoys are correct: constant branches, `keyA` versus `keyB` map lookups, a value moved into a response header.
- Rule-scope note: some path-traversal cases only open a file for writing. The CWE-22 rule detects reads of
  `/etc/passwd` only, so it cannot confirm those, and they count as rule misses.

**Leave-one-app-out role:** **one group** (`benchmark`, origin `benchmark`, neither own nor third-party).
- Its in-benchmark numbers are reported separately and labelled as such.
- The headline "all" set excludes it.
- It never counts as third-party generalization.

## 2. DVPWA, the new frozen held-out app

**Source:** anxolerd/dvpwa @ `4a8f4a43fafcc1b304f1b97d0f0a8dea755a7756` (MIT). aiohttp, Postgres, Redis (valkey) and
Jinja2 with **autoescape off**.

**Unseen:** not used anywhere in this project. Its only mentions are the v3 plan (listed as an optional training app
and a fallback held-out, never collected) and an **exclusion** list in ml-sast's OSV collector (`EVAL_APPS`). It was
never scanned or trained on.

**Runnable:** Postgres and Redis as compose services; the migrations create and fill the schema. No login is needed
for the vulnerable routes.

**Verified from source** (before any request):

| Endpoint | Parameter | Label | Evidence |
|---|---|---|---|
| `POST /students/` | `name` | **CWE-89, CWE-79** | `dao/student.py`: `"INSERT ... VALUES ('%(name)s')" % {...}`. The POST response renders the student list with `{{ name }}` raw (autoescape off). A DB error is rendered raw on the 50x page (`{{ error.__dict__ }}`) |
| `POST /courses/` | `title`, `description` | **CWE-79**; SQLi safe | parameterized INSERT; the list renders both raw in the same response |
| `POST /courses/{id}/review` | `review_text` | **CWE-79** (shown after the 302); SQLi safe | parameterized; `course.jinja2` renders `{{ review.review_text }}` raw |
| `POST /students/{sid}/evaluate/{cid}` | `points` | SQLi safe; CWE-79 unknown | trafaret `Int(0..5)`; whether its error text echoes the input is not determinable from source |
| `POST /` (login) | `username`, `password` | safe | parameterized; constant error text |
| `GET /students/{id}`, `/courses/{id}` | `id` | safe | `\d+` routes and an `int()` cast |

**Rule ground truth:**
- **Stored XSS:** `name` (sink `/students/`, `/courses/{id}`), `title` and `description` (sink `/courses/`), and
  `review_text` (sink `/courses/{id}`). All are unauthenticated POST forms, so they are in the rule's scope.
- **CSRF:** every POST form is truly vulnerable, because `csrf_middleware` is commented out in `app.py`. But every
  form renders a `_csrf_token` field, so the heuristic is **expected to call them protected**, its known blind spot.
- **Passive:** CSP, nosniff and framing are missing. The session cookie (`AIOHTTP_SESSION`, `httponly=False`) has no
  HttpOnly and no SameSite. No CORS.

**Procedure:**
1. Label the app.
2. Write `FREEZE_v4.json`: the SHA-256 of the tracked source and of the ground-truth subset, committed before any request.
3. Collect and score it **once**, for v2 (deployed), v3 and v4 on the **same records**.
4. Seed data: the shipped migrations (`001-fixtures.sql`) only.

**Fallback if it cannot be run:** the next unseen Python or Node.js app, with the same verify-then-freeze step.

## 3. Training and selection (decided now)

**Data:**
- v4 = v3 training data (re-featurized, no new collection), plus the BenchmarkPython subset.
- SirAppSec is burned and is **not** used as training data. DVNA is untouched.
- All v4 outputs get new names (`ground_truth_v4.json`, `raw_v4/`, `features_v4/`, `*_v4` reports, `models/release_v4`).
  Nothing existing is overwritten.

**Feature sets:** **no new feature work.** The inner leave-one-app-out may choose among the existing sets
`FEATURE_NAMES_V2` (70 features, the deployed model's) and `FEATURE_NAMES_V3` (63), each with or without the location
one-hot (4 candidate sets).
- **Why:** v3's features won leave-one-app-out but lost the held-out app on JSON-echo XSS false alarms, while v2's won
  the held-out app. Choosing between them is selection, not feature work.
- v2 feature extraction stays byte-for-byte identical, guarded by `tests/test_v2_compat_v4.py` (a fixed sample of v2
  rows re-featurized and re-scored).

**Threshold grid (widened):** 0.20 to 0.95 in steps of 0.05, **plus 0.97, 0.98, 0.99, 0.995**. v3 hit 0.95 in every fold.

**Model families:** logistic regression and LightGBM, with the same hyperparameter grids as v2 and v3. RF is dropped:
it lost to LR in both v2 and v3, and dropping it saves compute.

**Selection rule:**
- **Inner leave-one-app-out only:** feature set, hyperparameters and threshold by pooled inner endpoint-param
  macro-F1, computed on the non-Benchmark groups' clusters. Benchmark rows are trained on but never decide a selection.
- **Family:** the highest pooled outer leave-one-app-out macro-F1 over the non-Benchmark groups, fixed and committed
  before DVPWA is started.

**Deployment rule:** v4 replaces v2 as the deployed model (the engine on port 8002) **only if** both hold:
- its DVPWA endpoint-param macro-F1 is higher than v2's on the same records, **and**
- in leave-one-app-out on the same endpoint-params, v4 is not significantly worse than v2 (the 95% CI of v2 − v4 does
  not lie entirely above 0).

Otherwise v2 stays deployed and v4 is packaged as `models/release_v4`. **No retuning after any held-out result.**

## 4. Order of work and cut-off
1. Freeze DVPWA.
2. BenchmarkPython ground truth and collection.
3. Re-featurize v3 data as v4.
4. Leave-one-app-out (LR and LightGBM).
5. Select and train.
6. DVPWA once (v2, v3, v4).
7. ZAP: only scans that complete count; a timed-out scan is not a miss.
8. Docs and e2e; deploy switch only if v4 wins.

If time runs short, ZAP on BenchmarkPython is dropped first. Evaluation, docs and e2e are never cut.

## Outcome (added after the run; the sections above are unchanged)

- **v2 stays deployed, and v4 is packaged as `models/release_v4`.** The rule needed v4 to beat v2 on DVPWA and they
  tied (1.000 each). In leave-one-app-out, v4 is significantly better.
- **Planning mistake:** section 2 says "no login is needed for the vulnerable routes". That is true for the POST
  handlers, but the forms are rendered only for logged-in users or admins. The pre-registered unauthenticated scan
  therefore reached 8 of 17 labelled parameters, with 1 vulnerable, which made the held-out comparison uninformative.
  It was not re-scanned.
- Details are in `docs/ml-dast-model-card.md`.
