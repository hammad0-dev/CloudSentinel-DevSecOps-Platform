# ml-dast v5: authenticated scanning, final report

Branch `feat/dast-auth-crawl`, PR #18. Plan: [`ml-dast-auth-plan.md`](ml-dast-auth-plan.md); how-to:
[`ml-dast-auth-howto.md`](ml-dast-auth-howto.md); model card: [`ml-dast-model-card.md`](ml-dast-model-card.md).

## 1. Plain-language summary

- **What was added.** The DAST scanner can now log in to an app before testing it, so it also tests the pages that
  only signed-in users see. It keeps the session, logs in again if the session ends, and never clicks logout,
  delete, password-change or reset actions.
- **Credentials.** Passwords never travel in a scan request and are never written to logs or to the repository.
  They live in a local file or in environment variables, and are only ever sent to the one app they belong to.
- **The test.** I picked a new practice app the models had never seen (dvws-node). I wrote down what is vulnerable
  in it from its source code, locked those answers, and wrote down the pass/fail rule before scanning. Then I
  scanned it once.
- **The result.** The newer model (v4) found the same 3 real SQL injection flaws as the old one (v2) and raised one
  false alarm instead of two. That met the pre-written rule, so v4 is now the model in use. It is one small app, so
  this is encouraging but not proof.
- **Extra data.** Logging in gave the scanner up to twice as many labelled inputs on the training apps, and one new
  app (nodejs-goof) was added. No model has been retrained on any of this yet.

## 2. What authenticated scanning supports, and what it does not

**Supports:**
- **Logins:** a form or JSON login at any same-origin path, with configurable field names and fixed extra fields.
- **CSRF on the login form:** an optional token is read from the login page first.
- **Success indicators:** a cookie, a text on the page after login, or a bearer token taken from the JSON response
  and then sent as `Authorization: Bearer`.
- **One shared session:** crawler, prober, stored-XSS pass and collector use the same cookie jar and headers.
- **Re-login:** when a response shows the session expired (status, redirect to the login page, or a text), the scan
  logs in again and resends once. Re-logins are capped; none was needed in any v5 run.
- **Two crawls:** the crawl also starts from the page the login lands on. The collector also crawls logged out, so
  the login form itself is still tested (logged out).
- **Destructive-action skip list** (with login only):
  - logout, delete/remove, password change or reset, account recovery and database reset/setup;
  - matched in the route path, query or body parameter names, and link or button text;
  - the `DELETE` method is never sent.
- **Credentials:** only from `ML_DAST_AUTH_FILE` or `ML_DAST_AUTH_<REF>_*`, bound to origins. The scan is refused
  before any traffic if the target is not one of them. They are hidden in reprs, never in logs, raw records or error
  messages (errors report the exception type only).
- **`/scan` endpoint:** takes an optional `auth` object with `credentialRef` and no credential fields. Without it,
  every scan is byte-for-byte the old scan (request-sequence replay test).

**Does not support:**
- MFA/OTP, CAPTCHA, or SSO on another origin;
- CSRF tokens that rotate on every request (session tokens are fine);
- crawling a single-page app's API without seeds or an OpenAPI document;
- authenticated passive header checks (they stay cookie-less, as before);
- apps whose own login is broken (vulpy in the lab);
- backend pipeline integration: it needs a per-project credential-storage design, which is out of scope.

## 3. Coverage per app, before and after login

These are crawl-only measurements (`data/dast/coverage_v5.json`, `coverage_v5x.json`; GET pages, nothing submitted).
"Labelled reached" counts labelled endpoint-params; the collector probes the union of the logged-out and logged-in
crawls.

| App | Pages (out → in) | Injection points (out → in) | Labelled params reached (out → in, union) | Probed in the v5 collection |
|---|---|---|---|---|
| DVPWA | 17 → 17 | 12 → 38 | 8 → 11, union **14 of 17** | 14 of 17 |
| NodeGoat | 19 → 5 * | 17 → 17 | 7 → **15 of 15** | 15 of 15 |
| vulnerable-node | 28 → 41 | 10 → 34 | 10 → 12, union **13 of 18** | 13 of 18 |
| nodejs-goof (new, v5x) | 3 → 4 | 5 → 10 | 5 → 10 of 11 | **11 of 11** (the setup todo creates the update form) |
| vulpy-bad, vulpy-good | 2 → – | 6 → – | 4 of 4 logged out; **login impossible** | not re-collected |
| dvws-node (held-out) | logged in only | 27 seeded | — | **27 of 27** |

\* NodeGoat's ground-truth skip list blocks its eval, SSRF and `$where` pages, and the logged-in dashboard does not
link the tutorial pages. Every labelled parameter is still reached.

The only newly reachable parameter without a label was NodeGoat's `POST /profile` `website`. It was labelled safe
from source: the handler never reads it.

## 4. Held-out app: dvws-node

- **App:** `snoopysecurity/dvws-node` @ `4221c04f132960a0ccca4bf5aa5f3a9f53172778` (GPL-3.0). Express, MongoDB and
  MySQL, with a JSON API and JWT bearer tokens.
- **Prior use:** never used for DAST; used only in ml-sast's fresh test set, which the brief allows.

**Qualification from source, with login** (plan, section 6):
- **(a) Vulnerable:** 3 SQLi parameters, at least 3 required.
  - `POST /api/v2/passphrase`: `passphrase` and `reminder` (string-built INSERT, `src/controllers/passphrase.js:44`);
  - `GET /api/v2/passphrase/:username` (string-built SELECT, `passphrase.js:59`; XSS through the truncated MySQL
    error is labelled unknown).
- **(b) Safe:** 24 params safe for both ML classes, at least 8 required.
- **Credentials:** the documented account test/test (`CHALLENGES.md:15`, seeded by `scripts/seed-database.js:86-96`).
- **Other candidates:**
  - DSVPWA also qualified with login, but is "mainly inspired by DSVW", a training app; the pre-stated tie-break
    prefers the more independent code base.
  - Broken Crystals still had at most 2 probe-able SQLi/XSS params.
  - XVNA has no license.

**Freeze** (`data/dast/FREEZE_v5.json`, committed before any container existed; `--check` passes):
- source sha256 `366348f9f514f1dc5b8a28cae12632a1b541e40913585111282199d8f5a36f15` over 133 tracked files;
- ground-truth subset sha256 `f8ef7a1070b27838dcd73b4d508316a5266d1c85e30442cfb6f31f5a6d078bf0`;
- 20 endpoints / 27 endpoint-params labelled with file:line citations, 19 skip-listed routes (code execution, XXE,
  uploads, destructive routes, GraphQL, SOAP, XML-RPC).

**Pre-registration** (`reports/final_preregistration_v5.json`, committed before any container existed):
- the v2/v3/v4 model sha256 values;
- the coverage requirement (at least 80% of the 27, otherwise INCONCLUSIVE);
- the four-part decision rule.

**Coverage achieved:** **27 of 27 (100%)**: one scan, 1 login, 0 re-logins, 2,035 requests, 108 s.

## 5. Results on the held-out app and the decision

| dvws-node (27 endpoint-params, 3 CWE-89 vulnerable) | v2 (was deployed) | v3 | v4 |
|---|---|---|---|
| Endpoint-param macro-F1 [95% cluster bootstrap, 1,000 resamples] | 0.853 [0.632, 1.000] | 0.870 [0.672, 0.979] | **0.918 [0.730, 1.000]** |
| CWE-89 TP / FP / FN | 3 / 2 / 0 | 3 / 1 / 0 | 3 / 1 / 0 |
| CWE-79 FP (no vulnerable XSS parameter) | 0 | 4 | 0 |
| Vulnerable parameters found / false alarms | 3 / 2 | 3 / 5 | **3 / 1** |
| Paired difference with v4 | v2 − v4 = −0.065 [−0.239, 0.000] | v3 − v4 = −0.051 [−0.115, −0.011] | |

- **False alarms:**
  - all three models flag `GET /api/v2/users/{id}/profile-details` as SQLi;
  - v2 also flags `GET /api/v2/notes/{noteId}`;
  - v3 also flags four JSON write fields as XSS.
- **Rule checks (counts):** passive 4 of 4 found with 0 false alarms; CWE-22 0 of 1 (the traversal reads only
  `*.json` files); no stored-XSS or CSRF units (single-page app, bearer API).

**Decision, per the pre-registered rule:**
1. Coverage of at least 80%: ✓ (100%).
2. v4 macro-F1 strictly higher than v2: ✓ (0.918 > 0.853).
3. v4 finds at least as many vulnerable parameters: ✓ (3 = 3).
4. At most one extra false alarm: ✓ (1 ≤ 2 + 1).

**So v4 is deployed.**

**How strong the evidence is.** One small app is weak evidence.
- The whole difference is one cluster.
- The v2 − v4 interval reaches 0.
- The CIs were not part of the rule.

**In-distribution check** (training apps, newly reachable after login; NOT held-out; `reports/indist_v5.json`):
9 clusters, v2 0.667 [0.308, 0.962], v3 0.639, v4 0.903 [0.471, 1.000].

## 6. What is deployed now on port 8002, and the rollback

`/model-info` on `127.0.0.1:8002`:
- name `ml-dast-lr`, version `4.0.0`;
- sha256 `7a306aca5b07cf0360fe41e4bfbe517d56de24b669f89545d91a3461ee867322`;
- threshold 0.995, status trained;
- allowlist `ML_DAST_ALLOWED_HOSTS=192.168.49.2`, `ML_DAST_ALLOWED_PORTS=30000-32767` (unchanged).

**Order followed:**
1. A v4 candidate on spare port 8003 showed the same `/model-info`.
2. e2e on 8003 (executions 96-98) passed.
3. All tests passed.
4. 8002 was switched.
5. e2e on 8002 (executions 99-101) passed.
6. The candidate was stopped.

**Exact rollback to v2** (from the repository root `~/cs-dast` in WSL):

```bash
pkill -f 'uvicorn app:app --host 127.0.0.1 --port 8002'
ML_DAST_MODEL_DIR=$PWD/services-ml/ml-dast/models/release_v2 ML_DAST_PORT=8002 \
ML_DAST_ALLOWED_HOSTS=192.168.49.2 ML_DAST_ALLOWED_PORTS=30000-32767 \
  setsid nohup scripts/run-ml-dast.sh > services-ml/ml-dast/logs/ml-dast-8002.log 2>&1 < /dev/null &
curl -s http://127.0.0.1:8002/model-info    # expect version 2.0.0, sha256 5dc397d0b6c4…
```

The restart command for v4 is the same, with `release_v4` (`docs/ml-architecture.md`, "ML DAST v5").

## 7. v5 data added (NOT used by any model yet)

ML rows (SQLi/XSS payload rows) per app and label, plus the endpoint-param clusters that carry each label. A cluster
appears under "safe" for the payloads of the class it is not vulnerable to.

| App | Role | Rows: safe / CWE-89 / CWE-79 | Clusters with label: safe / CWE-89 / CWE-79 | Label-noise estimate |
|---|---|---|---|---|
| DVPWA | v5 data (burned v4 held-out) | 1,536 / 34 / 96 | 13 / 1 / 4 | labels are the v4 ones, frozen in FREEZE_v4 |
| NodeGoat | training app, re-collected | 590 / 0 / 160 | 15 / 0 / 10 | v2-v4 labels; 1 new label (`website`), checked at its cited lines |
| vulnerable-node | training app, re-collected | 1,374 / 136 / 208 | 12 / 4 / 2 | v2-v4 labels unchanged |
| **nodejs-goof** (new, stage 6) | v5x data | 502 / 0 / 16 | 11 / 0 / 1 | **22 cited lines spot-checked, 0 mismatches**: 0% observed (95% Wilson upper bound about 15%) |
| dvws-node | held-out (scored once; never training) | 1,164 / 102 / 0 | 26 / 3 / 0 | every citation re-read before the freeze |

**Stage-6 candidates, checked from source:**
- **PyGoat:** skipped; it needs the Docker socket (GROUND_TRUTH.md).
- **DjanGoat:** dropped; no README-documented login, Python 2.7 / Django 1.11 with MySQL.
- **Tiredful-API:** dropped; its credentials appear only on the app's own intro page, not in a README, and its API
  sits behind OAuth tokens.
- **nodejs-goof** (Apache-2.0, documented admin account `README.md:88`): kept.

**These rows are collected only. No model has been trained or tuned on v5 or v5x data.**

## 8. Corrections, mistakes, deviations and disclosures

1. **Destructive-check bug (fixed before the held-out scan).**
   - **What happened:** in the first authenticated lab collection, the destructive-word check also ran on injected
     path segments. A path-traversal payload (`../../etc/passwd` contains `passwd`) made the guard refuse whole
     points; DVPWA lost 3 path points and vulnerable-node 1.
   - **Fix:** the check now runs on the probed route (commit `945d963`, regression test).
   - **First-run data:** moved to `logs/v5_first_run_bug/`, not deleted. The lab apps were reset and collected again.
   - **Unaffected:** no model, label or pre-registration.
2. **A reset command hit every service.** One `docker compose rm/up` reset ran with an empty service-list variable,
   because Git Bash expanded it. It removed a stopped SirAppSec container and started every default-profile lab app,
   **DVNA (the frozen v1 held-out) included**. No request was sent to DVNA or to the other extra apps. They were
   stopped when noticed.
3. **Coverage file updated by mistake.** The coverage script added nodejs-goof to the already-committed
   `coverage_v5.json`. I restored that file, moved the entry to a new `coverage_v5x.json`, and changed the script to
   write one file per ground-truth version.
4. **Ground-truth draft rebuilt once.** `ground_truth_v5.json` was rebuilt once before its first commit (an image
   note: mysql:5.7 instead of 8.0). It was never changed after the commit or the freeze.
5. **Freeze note wording.** The freeze's `spot_check` note says "two citations outside dvws-node were corrected". In
   fact one was NodeGoat's and one was a dvws-node skip-list reason. Freezes are never rewritten.
6. **Plan corrections** (plan, section 8):
   - XSS on `GET /api/v2/passphrase/:username` is labelled unknown, not vulnerable.
   - mysql:5.7 and mongo:4.4 are used instead of upstream's mysql:8 and mongo:4.0.4.
   - nodejs-goof uses mongo:4.4 instead of mongo:3, and no MySQL.
   - dvws-node is built without its frontend.
7. **Login endpoints not probed.** dvws-node's login endpoints (rate-limited, 100 per 30 s) were not probed.
8. **vulpy's login is broken in the lab image.** `libsession.py:7` sets a bytes cookie, which the pinned werkzeug
   rejects with a 500. vulpy keeps its unauthenticated collection; the app was not patched.
9. **Credentials in documents.** The documented public demo credentials appear in the plan doc and in a dvws-node
   ground-truth note, because the brief asked for "the credentials documented". Scans read them only from the
   gitignored `lab/auth.local.json`. The v1-v4 collector keeps its older hard-coded lab logins (unchanged code paths).
10. **The model's flag is not the deployment.** `models/release_v4/model.json` still says `"default": false`, because
    files under `models/` are never rewritten. The deployment is the run command.
11. **Weak evidence.** One small held-out app; see section 5.

## 9. What was NOT done

- **Backend pipeline integration of authenticated scans:** needs a credential-storage design (how-to, section 5).
- **Authenticated re-collection** of Juice Shop, DSVW and VAmPI (no README-documented credentials) and of vulpy
  (broken login).
- **ZAP comparison on dvws-node.** Not run: its code-execution routes (sysinfo, greeter, node-serialize, YAML import)
  could not be kept out of ZAP's reach, since ZAP's exclusions did not hold in v2 or v3.
- **The vulnerable `python` e2e fixture:** not run (`E2E_PYTHON_REPO` unset).
- **Training on v5 or v5x data:** none, as the brief requires.
- **DjanGoat, Tiredful-API and PyGoat:** dropped (section 7).

## 10. Machine state and what to do next

**State at the end:**
- **Port 8002:** ml-dast v4 (`ml-dast-lr` 4.0.0).
- **Port 8001:** ml-sast, untouched.
- **Port 3000:** your backend, untouched.
- **Port 8003:** the candidate engine, stopped.
- **Port 3100:** the temporary e2e backend, stopped.
- **Lab containers:** none running. The dvws-node and nodejs-goof containers exist stopped, with their images built
  (`mldast-lab/dvws-node:4221c04` 1.1 GB, `mldast-lab/nodejs-goof:add14ba`). Remove them with
  `docker compose -p mldast-lab --profile final-v5 --profile v5x rm -f` if disk space matters.
- **Minikube:** never stopped; still running.
- **Backup:** `/mnt/d/ml-backup/dast5/` with SHA256SUMS.

**Next steps:**
1. Review and merge PR #18. Until it is merged, port 8002 runs code from this branch's working tree.
2. If you want more held-out evidence before trusting v4 widely, label and freeze a second login-protected app the
   same way.
3. Design per-project credential storage before wiring authenticated scans into the pipeline.
4. A v6 could train on the v5/v5x data under a new pre-registered plan, holding out a new app.
