# Model card: ml-dast 2.0.0 (`ml-dast-lr`)

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

## What changed from v1, and why

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

## Data (v2)

| App group | Origin | Rows (ML) | SQLi / XSS endpoint-params | Safe |
|---|---|---|---|---|
| labflask, labexpress, labfastapi | own | 3,650 | 13 / 10 | 50 |
| Juice Shop, NodeGoat, vulpy (bad+good), vulnerable-node | third-party | 1,818 | 10 / 11 | 17 |
| **Training total** (7 LOAO groups) | | **5,468** (4,350 safe, 782 SQLi, 336 XSS) | **23 / 21** | 67 |
| DSVW (v2 final held-out) | third-party | 534 | 3 / 2 | 7 |

Ground truth: `data/dast/ground_truth_v2.json`, summarized in `data/dast/GROUND_TRUTH.md` (v2 section).

## Results

The metric is the same as v1:
- **ML:** endpoint-param macro-F1, with 95% cluster bootstrap intervals (1,000 resamples), per class too.
- **Rules:** counts, because n is too small for rates.

### Main: leave-one-app-out (final data, 7 groups, 111 endpoint-params)

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

### Before / after on the same 78 endpoint-params

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

### Rule-based checks on the training apps (counts, not rates)

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

### Final held-out app: DSVW, single run

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

### ZAP comparison

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

## Intended use

- **Intended:** an experimental, opt-in second opinion (`DAST_ENGINE=ml`) on authorized staging targets.
  The rule-based checks are a cheap complement.
- **Not intended:** replacing ZAP, certifying an app as free of injection, or gating a pipeline on DAST
  findings. The security gate never blocks on DAST.

## Limitations

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

## Threats to validity

- **Small evaluation sets:** DSVW has 12 endpoint-params, and rule classes have 1 to 4 known instances.
- **Author bias:** 3 of 8 training app groups and all B3 endpoints were written by me, as were the payloads.
- **Repeated feature iteration** on the same leave-one-app-out folds (two rounds) makes the round-2 numbers
  optimistic. The final data and DSVW were each evaluated once with the frozen feature set.
- **Labels changed after seeing errors:** the NodeGoat `/signup` correction, vulpy-good's CSP, and vulpy's
  cookie checks set to not evaluable. Each was verified in source and is logged in `ground_truth_v2.json`
  under `changes`.
- **Supplementary collection:** the CWE-601 payloads were added after the final collection to the same
  recorded points (`scripts/collect_supplement_v2.py`). ML rows were not affected.

## Reproduce (v2)

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

## v1 (`ml-dast-lr` 1.0.0), kept for reference

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

### How it scans

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

### Data

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

### Results

The metric is macro-F1 over the classes present (`safe`, CWE-89, CWE-79). The headline is
**endpoint-param level**; row-level results are also given.

- **Endpoint-param level:** each (endpoint, parameter) is one unit, flagged C if any of its C rows is.
- **Intervals:** 95% bootstrap with 1,000 resamples **over endpoint-params**, not rows.

#### Main: leave-one-app-out over the 6 training groups

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

#### ZAP comparison (same 78 endpoint-params)

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

#### Final held-out app: DVNA, single run

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

### Intended use

- **Intended:** an experimental, opt-in second opinion on the baseline DAST path (`DAST_ENGINE=ml`),
  on staging deployments the backend has authorized. Configure the allowlist to the staging host and
  ports.
- **Not intended:** replacing ZAP as the DAST gate, scanning anything not explicitly allowlisted, or
  claiming an app is free of SQLi or XSS.

### Limitations

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

### Threats to validity

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

### Reproduce

See [`services-ml/ml-dast/README.md`](../services-ml/ml-dast/README.md#lab-data-and-reproduction).

| Step | Time |
|---|---|
| Collection | ~5 min |
| Leave-one-app-out | ~4 min on 8 CPU threads |
| ZAP scans | 2–12 min per app |
