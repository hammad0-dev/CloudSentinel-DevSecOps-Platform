# ml-dast v3 plan: targeted SQLi/XSS accuracy round, stored XSS and CSRF rules

Branch `feat/dast-v3-targeted` (from `origin/master` at `0a57003`, PR #15 merged). Started
2026-11-20T21:49Z; time cap 1.5 days, so the hard stop is 2026-11-22T09:49Z.

Baseline (v2, `ml-dast-lr` 2.0.0):
- **Leave-one-app-out:** endpoint-param macro-F1 0.827 [0.744, 0.894] on 111 endpoint-params
  (7 groups, 5,468 rows).
- **DSVW, scored once:** XSS 2/2, SQLi 0/3.

All numbers below come from `reports/loao_v2.json`, `reports/loao_clusters_v2.json` and
`reports/final_dsvw_explain.json`. The fold-by-fold trace (each outer fold refit with the
parameters it chose) is reproducible with the error-trace script described in section A.

## A. Error analysis of v2

LR made 17 endpoint-param errors in leave-one-app-out (6 missed vulnerabilities, 11 false alarms),
plus the 3 DSVW SQLi misses. For each, the deciding row is the highest-probability row of the
predicted (or, for a miss, the true) class, with its largest standardized LR contributions.

| # | Error(s) | Deciding evidence | Cause | Minimal fix |
|---|---|---|---|---|
| 1 | DSVW `/?id` SQLi missed (p=0.017) | `sql_err_new`=1 and `stack_trace_new`=1, but `ct_text` contributes −5.87 | **Missing training pattern.** Every text/plain response in training is safe, so the model learned "plain text = safe". | F1: drop the content-type one-hots (an app prior, not evidence). D1/D2: SQLi endpoints whose errors are text/plain or JSON, and safe endpoints that return text/plain or JSON errors. DSVW becomes training data. |
| 2 | DSVW `/login` password, `/?comment` SQLi missed (p=0.882, 0.894; t=0.9) | Only `parity_flip`=1; no SQL error, no boolean-pair difference | **Threshold at the grid edge.** Every LR fold chose t=0.9, the largest value in the grid, so the grid was a boundary. The evidence was real but alone. | F6: extend the threshold grid to 0.95 (chosen by inner leave-one-app-out only). D1: own-app SQLi twins whose only signal is a quote-parity flip (INSERT/UPDATE with no error shown). |
| 3 | NodeGoat `/profile` XSS ×6 missed (p≈0.73) | Raw reflection with HTML specials kept (`raw_reflected_dangerous`=1), but `len_log` −3.48 (9 KB page) | **Feature gap: app-size prior.** Lab pages are tiny, so "long page = safe". Also, the first raw occurrence of the marker sits in a script block, so the context is the wrong one. | F1: drop `len_log` (keep the relative length features). F5: take the reflection context from the most dangerous raw occurrence, not the first. |
| 4 | `xs-uri` false alarms ×4: labfastapi `/docs-link-safe`, labflask `/profile-safe`, vulnerable-node `returnurl` and `/tools/ping host` | `ctx_attr_dq` +2.6 to +4.4 on its own; the javascript: payload has no HTML specials and is not in a URL attribute | **Feature gap.** The context one-hot fires for a harmless reflection; a linear model cannot form "context AND dangerous". | F3: the `ctx_*` one-hots are set only when the reflection is dangerous (`raw_reflected_dangerous`); otherwise `ctx_none`. |
| 5 | labflask `/next` XSS false alarm (p=1.0) | 3xx; the redirect body echoes `href="javascript:…"` | **Feature gap.** Browsers do not render the body of a redirect. | F2: XSS reflection features are zero unless the response is rendered HTML (HTML content type, not 3xx). |
| 6 | labflask `/widget-safe` XSS false alarm (p=1.0) | `ctx_script`, single quote kept; the value is JSON-encoded inside a double-quoted JS string | **Feature gap.** A quote that does not match the enclosing string delimiter cannot break out. | F4: `script_breakout`, a script-context reflection counts only if it closes the enclosing JS string (same unescaped quote) or the script block (`</script`), or sits in code context. `ctx_script` requires it. |
| 7 | labexpress `/api/items-safe` SQLi false alarm (p=0.951) | `family_error` +1.14, `ct_json` +1.05; no error, status unchanged | **App prior** (JSON 200 responses look like Juice Shop's SQLi) plus the threshold edge. | F1 (drop `ct_*`), F6, D1: JSON-safe twins. |
| 8 | labflask `/calc` SQLi false alarm (p=0.941) | `is_5xx` +2.35, non-SQL stack trace; parity not flipped | **Missing training pattern.** Safe endpoints that 500 on any bad input are rare. | D1: more safe endpoints that return 500/400 with non-SQL errors (HTML, text, JSON). No new feature: `sql_err_new` and `parity_flip` already separate them, given data. |
| 9 | labflask `/slow` SQLi false alarm (p=0.901) | Nothing beyond priors (`family_union`, `time_slow_ratio_log`=0) | **Threshold edge.** | F6. |
| 10 | labflask `/ping`, vulnerable-node `/tools/ping` (SQLi or XSS false alarms on command-injection endpoints) | `parity_flip`=1 (shell quoting behaves like SQL quoting) | **Out of class.** At runtime the CWE-78 rule's precedence already suppresses the ML SQLi finding on the same point, but leave-one-app-out counts it. | No ML change. Reported as is. |
| 11 | vulnerable-node `/orders sort` SQLi missed (p=0.562) | Boolean pair differs (`pair_diff_over_noise`=1.45), `probe_reflected` −1.43 | **Missing training pattern.** ORDER BY injection with no error and a reflected parameter is rare in training. | D1: ORDER BY twins (vulnerable and whitelisted) in two own apps. |

Label noise: none found among these errors. Every endpoint was re-read in source:
- NodeGoat `/profile` re-renders all six fields unescaped.
- vulnerable-node `returnurl` is only a redirect target, so it is safe for XSS.
- `/widget-safe` uses `json.dumps` with `<`, `>` and `&` escaped.

### Feature changes for v3 (`FEATURE_NAMES_V3`)

**Fixed before any v3 training, and disclosed.** The v2 features were already iterated twice
on the same leave-one-app-out folds. This round of changes, chosen from the v2 error analysis, makes
v3's leave-one-app-out numbers somewhat optimistic, so the new frozen held-out app is the honest
estimate.

- **F1.** Drop the app-prior features `len_log`, `ct_html`, `ct_json`, `ct_text`, `ct_other` and
  `nosniff`.
- **F2.** XSS reflection features count only for rendered HTML (an HTML content type and not 3xx).
- **F3.** Context one-hots apply only to a dangerous reflection.
- **F4.** Add `script_breakout`.
- **F5.** Use the context of the most dangerous raw occurrence.
- **F6.** Threshold grid 0.20 to 0.95.

The hyperparameter grids are unchanged. The location ablation (`all` or `no_loc`) is still
chosen by inner leave-one-app-out.

## B. Targeted data

Already used:
- **ml-dast:** juice-shop, labflask, labexpress, labfastapi, NodeGoat, vulpy (bad and good),
  vulnerable-node, DVNA (frozen v1 held-out), DSVW (v2 held-out).
- **ml-sast:** pygoat, dvws-node and django.nV (fresh and held-out sets), plus OSV-derived
  real-world repositories.

| Item | Gives | Verified from source | Hours |
|---|---|---|---|
| D1 own-app twins (labflask, labexpress, labfastapi `/v3/*`) | (1) SQLi with text/plain and JSON errors, and parity-only SQLi; (2) safe endpoints with text/plain and JSON errors and non-SQL 500s; ORDER BY twins; (3) XSS in unquoted-attribute, JS-string, `<title>`, `<textarea>` and `href` contexts, each with an escaped safe twin, plus raw JSON and text echoes (safe); stored-XSS and CSRF twins | We write them; each route is commented VULN or SAFE | 3 |
| D2a DSVW as **training** (disclosed: it was the v2 held-out and is burned) | text/plain SQLi errors, parity-only SQLi | Already labelled (`FREEZE_v2.json`) | 0.3 |
| D2b VAmPI (erev0s/VAmPI @ f16052d, Flask + SQLite, OpenAPI) | SQLi in `GET /users/v1/{username}` (an f-string query, `models/user_model.py:72`) behind JSON responses; many safe JSON endpoints with JSON errors | Yes | 1.5 |
| D2c node-api-goat (layro01/node-api-goat @ 868ee6c, Express) | Third-party XSS: `/cwe79/echo` (HTML), `/cwe201/exposure` (raw `res.send`); safe `hexToRgb` | Yes (`app/server.js`) | 1 |
| D2d DVPWA (anxolerd/dvpwa @ 4a8f4a4, aiohttp + Postgres + Redis) | SQLi (`dao/student.py`), stored XSS (`autoescape=False`), CSRF-protected forms (safe twin for the CSRF rule) | Partly; finish when picked up | 2 |
| Rejected | Broken Crystals (NestJS + front-end build, too heavy for the cap); arall/vulnerabilities (code snippets, not a runnable app); we45 Vulnerable-Flask-App (SQLi behind a JWT login) | | |

## C. New frozen held-out app

**SirAppSec/vuln-node.js-express.js-app @ `b977c7407f328da929577745ad509639e26c428a`**
(Express + Nunjucks + Sequelize/SQLite, express-jsdoc-swagger OpenAPI at `/v1/api-docs`).

- **Unseen.** It appears nowhere in this repository: no ml-sast manifest, fresh or held-out set,
  ml-dast ground truth, lab, report or doc mentions it. It was never cloned before 2026-11-20
  (the clone in `~/v3-cand` was made for this check).
- **Source confirms the classes:**
  - **SQLi:** `GET /v1/search/{filter}/{query}`. `src/router/routes/order.js` builds `"SELECT * FROM
    beers WHERE "+filter+" = '"+query+"'"` and returns the error as a 501 string.
  - **Reflected XSS:** `GET /?message` and `GET /register?message`
    (`src/router/routes/frontend.js`, rendered with `{{message | safe}}` in `user.html` and
    `user-register.html`).
  - Also: CWE-22 `/v1/beer-pic/?picture`, CWE-601 `/v1/redirect/?url`, and stored XSS
    (`user.address | safe` in `profile.html`).
  - Safe twins: `/beer?relationship` is autoescaped.
- **Why not a Python app:** v2 used a Python held-out app (DSVW). A Node.js app tests the other
  target language, and it exposes JSON SQLi errors through OpenAPI, the exact gap v3 targets.
- **Fallback:** if a deeper source read fails to confirm one SQLi and one reflected XSS reachable
  by the scanner's documented inputs (crawl plus `/v1/api-docs`), use DVPWA with the same
  verify-then-freeze step.
- **Procedure:**
  1. Label from source at the pinned commit.
  2. Write `FREEZE_v3.json` with the SHA-256 of the tracked source files and of the
     ground-truth subset, committed before any request.
  3. Skip-list the dangerous parameters: `/v1/status/{brand}` (`execSync` curl), `/v1/test/?url`
     (SSRF), `/v1/init` (deserialization), multipart uploads.
  4. Run the container with no DNS or egress.
  5. Score it once, after the v3 model is fixed by SHA-256. The scan configuration
     (crawl + `openapiUrl=/v1/api-docs`) is pre-registered.

## D. New rule-based checks

| Rule | Design | Real instances (source) | Safe twins | Hours |
|---|---|---|---|---|
| Stored XSS (CWE-79, stored) | For each crawled POST form or JSON-body field (PUT only from OpenAPI; never DELETE), submit a unique marker `cs<hex>"'<>`. After all submissions, re-fetch every already-crawled page (GET only) and report the field when the marker comes back raw, with `<` and `"` unescaped, in a later page's rendered HTML. The scan never searches for a marker from an earlier run (markers are random per scan). **Reset:** lab apps are restarted between collections; the demo app's store is in memory. Writes only through the guarded client, so only on allowlisted lab apps and our own deployed demo. | NodeGoat `/profile` (shown on `/profile`) and `/memos` (marked output); DSVW `?comment` (GET, not a form: GT records it, the rule does not cover it); D1 `/v3/guestbook`; SirAppSec `address` (held-out; the profile page of a new user is not a crawled page, so the expected count is honest) | D1 `/v3/guestbook-safe` (escaped); vulpy-good posts (escaped) | 3 |
| CSRF (CWE-352, heuristic) | Passive: a POST form (state-changing) with no anti-CSRF field (name matching `csrf`, `xsrf`, `_token`, `authenticity_token`, `nonce`), **and** a session cookie without `SameSite=Lax/Strict`. Medium confidence, LOW, never gate-blocking; labelled heuristic in the finding. | NodeGoat (no token; the cookie has no SameSite); vulpy-bad; vulnerable-node; D1 labflask `/v3/settings` | D1 `/v3/settings-safe` (token field); labexpress with a SameSite=Lax cookie; DVPWA (if collected) | 1.5 |

## E. Ranking and cut-off

| Rank | Item | Value | Hours | Cumulative |
|---|---|---|---|---|
| 1 | Freeze SirAppSec (verify, label, hash) | Required before anything else | 0.5 | 0.5 |
| 2 | F1 to F6 feature fixes and tests | Addresses 14 of the 20 errors | 2 | 2.5 |
| 3 | D2a DSVW to training | Free, targets error 1 | 0.3 | 2.8 |
| 4 | D1 own-app twins and ground truth | Targets errors 1, 2, 7, 8 and 11, and XSS contexts | 3 | 5.8 |
| 5 | D2b VAmPI | Third-party JSON SQLi | 1.5 | 7.3 |
| 6 | D2c node-api-goat | Third-party XSS | 1 | 8.3 |
| 7 | Collection (background) and retrain: leave-one-app-out with 3 families | Required | 3 | 11.3 |
| 8 | Stored XSS rule | New class | 3 | 14.3 |
| 9 | CSRF rule | New heuristic | 1.5 | 15.8 |
| 10 | Held-out once, ZAP comparison (spider excludes remote-fetch parameters; no killed scans used) | Never cut | 3 | 18.8 |
| 11 | Backend, UI, tests, e2e, docs, backup, PR | Never cut | 5 | 23.8 |
| 12 | D2d DVPWA | Third-party stored XSS, CSRF safe twin | 2 | 25.8 |

About 26 hours against a 36-hour cap. **Cut order if time runs short:** DVPWA, then CSRF (9), then
stored XSS (8), then node-api-goat and VAmPI. Ranks 1-7, 10 and 11 are never cut.

**Default-model rule (decided now):** v3 becomes the packaged default only if it beats v2 on
SirAppSec (endpoint-param macro-F1, both models scored on the same frozen collection) **and** is
not significantly worse than v2 in leave-one-app-out on the same endpoint-params (the 95% CI of
the difference does not lie entirely below 0). Otherwise v2 stays the default and v3 is packaged
separately.
