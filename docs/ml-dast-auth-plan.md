# ml-dast authenticated scanning: plan and design (v5 data)

Branch: `feat/dast-auth-crawl`.

**What this changes:**
- **Changed:** which pages and parameters the scanner reaches.
- **Not changed:** features, model code behaviour, thresholds, and the models themselves (v2 deployed on port 8002;
  v3 and v4 packaged).
- **Data:** new data and reports carry the tag `v5`. Nothing under `models/`, `reports/` or `data/dast/` is
  overwritten.

## 1. Auth config format

One login profile per target. The non-secret part is JSON (or a Python dict in the lab collector):

```json
{
  "loginPath": "/login",            // same-origin path; required
  "method": "POST",                 // POST (default) or GET
  "body": "form",                   // form (default) or json
  "usernameField": "username",
  "passwordField": "password",
  "extraFields": {"remember": "1"}, // optional fixed, non-secret fields
  "loginPagePath": "/login",        // optional page fetched first (CSRF token, session cookie)
  "csrfField": "_csrf",             // optional token input read from loginPagePath's login form ("auto" = common names)
  "success": {"cookie": "SESSIONID"} | {"text": "Welcome"} | {"tokenJson": "token"},
  "loggedOut": {"status": [401], "redirectTo": "/login", "text": "Please log in"},  // expiry signs, any of
  "credentialRef": "NODEGOAT"       // which credential profile to use (see below)
}
```

**Credentials** (username and password) are never part of this config and never come from the target. They are read
only from:
- a local credential file, `ML_DAST_AUTH_FILE` (lab default `services-ml/ml-dast/lab/auth.local.json`, gitignored),
  shaped `{"<ref>": {"username": …, "password": …, "origins": ["http://127.0.0.1:5106"]}}`; or
- environment variables `ML_DAST_AUTH_<REF>_USERNAME`, `ML_DAST_AUTH_<REF>_PASSWORD` and `ML_DAST_AUTH_<REF>_ORIGINS`.

A credential profile is bound to one or more origins. A scan whose target is not one of them is refused before any
traffic is sent, so a credential can never go to another host. The login request goes through the same guarded
client (allowlist, same origin).

**Never logged:**
- Login requests are not stored in raw records.
- Login errors are reported by exception type only, never by message, because a message can contain a URL that
  carries the credentials.
- The password field is hidden in the config's `repr`.

**Default:** without an auth config, behaviour is exactly as today, with no deny list and no login. The existing
v1-v4 collection paths are untouched, including their hard-coded lab logins.

## 2. Sessions, CSRF tokens and expiry

- **One session for everything.** The crawler, the prober, the stored-XSS pass and the passive pass already share one
  `GuardedClient` and its `requests.Session`, so one cookie jar is shared. A bearer token from a JSON login
  (`success.tokenJson`) is set as an `Authorization: Bearer …` header on that same session.
- **Login:**
  1. Optionally GET `loginPagePath` and read the CSRF field from the login form.
  2. Send the login request.
  3. Check the success indicator. If it fails, the scan stops with `AuthError`; it never continues silently as
     unauthenticated.
- **Expiry.** Every response is checked against `loggedOut`:
  - its status (for example 401);
  - a same-origin redirect whose `Location` path is `loginPath` (checked over the whole redirect chain);
  - or the logged-out text in the body.

  If it matches, the client logs in again and resends the request once. Re-logins are capped (default 20 per scan).
  A request made during a login is never re-checked, so there are no loops.
- **CSRF tokens in probed forms.** The baseline value of a token field is the value captured when the form was
  crawled, as today. A session-bound token stays valid while the session lives.
  - **Limit (documented):** tokens that rotate on every request, or that a re-login invalidates, are not refreshed
    per probe request.

## 3. Destructive-action skip list (auth mode only)

With an auth config, these are never requested:
- **Links:** a link whose path or text matches.
- **Forms:** a form whose action or button text matches.
- **Everything else:** any request (crawl, probe, stored-XSS or passive pass) whose path, or the name of one of its
  query parameters, matches. Requests with the `DELETE` method are refused as well.

| Kind | Matched words (case-insensitive, whole path segment or word) |
|---|---|
| Logout | logout, log-out, log_out, logoff, signout, sign-out, sign_out |
| Delete data or accounts | delete, remove, destroy, drop, purge, wipe, erase, truncate, deactivate, unregister, close-account |
| Passwords | change-password, changepassword, password (as a path segment), passwd, new-password, forgot, forgotpw, account-recovery |
| Reset the database | reset, resetdb, reset-db, createdb, initdb, init-db, setup, install, seed |
| Button or link text | log out, logout, sign out, delete, remove, reset, change password, deactivate, drop, wipe, destroy |

- The lab apps may be reset (containers recreated) between runs.
- The list is in `dastml/auth.py` (`DESTRUCTIVE`) and is covered by tests.
- Per-app ground-truth skip lists still apply.

## 4. Service `/scan`

- **The `auth` object.** `/scan` accepts an optional `auth` object with the fields above, in camelCase. It validates
  the following and answers 400 if anything fails:
  - paths start with `/` and resolve to the target's origin;
  - `credentialRef` matches `^[A-Za-z0-9_]{1,40}$` and resolves to a credential profile bound to the target's origin;
  - there are at most 10 `extraFields`.
- **Credentials:** there are no username or password fields in the request.
- **Without `auth`:** behaviour is unchanged.
- **Older models:** a model whose `scan` has no `auth` argument answers 501, as for `seedPaths`.

**Backend pipeline integration is out of scope.** It needs per-project credential storage: encryption at rest, who
may see or rotate credentials, audit, and binding a credential to the verified staging origin. That needs its own
security design, so for now authenticated scans are run against the service directly (see the how-to).

## 5. Lab apps with a login, and their documented credentials

| App | Login | Documented credentials | Source of the credentials | Re-collected with login |
|---|---|---|---|---|
| DVPWA | POST `/login` (form), success shown by a text on the page after login (its session cookie is set before login too) | superadmin / superadmin | dvpwa `README.rst:142` | yes |
| NodeGoat | POST `/login` (form `userName`, `password`) | user1 / User1_123 | NodeGoat `README.md:23` | yes |
| vulpy-bad, vulpy-good | POST `/user/login` (form) | admin / SuperSecret | vulpy `README.rst:93-95` | yes |
| vulnerable-node | POST `/login/auth` (form) | alice / alice123 | vulnerable-node `README.md:63-67` | yes |
| Juice Shop | JSON login with a bearer token | none in the README (the admin password is a challenge solution) | — | **no** |
| DSVW | GET `/login` | only in source (`dsvw.py` USERS_XML), not documented | — | **no** |
| VAmPI | JSON login with a bearer token | none in the README (users come from `/createdb`) | — | **no** |
| DVNA | register, then login | no default account | — | **no**: frozen v1 held-out, never re-collected |
| SirAppSec | — | — | — | **no**: burned v3 held-out |
| Own lab apps, BenchmarkPython, node-api-goat | no protected area | — | — | no (nothing to gain) |

## 6. Held-out candidates: qualification from source, with login

**Rules:**
- **Thresholds:** at least 3 SQLi or reflected-XSS vulnerable parameters reachable with login, and at least 8 safe
  parameters (safe for both ML classes), with documented credentials. The thresholds are not loosened.
- **Choice among qualifying candidates:** fixed before reading the results. The app whose code base is most
  independent of the DAST training apps wins; on a tie, the one with more vulnerable parameters.
- **Excluded:** DVPWA (already scored once).

| Candidate | (a) vulnerable with login | (b) safe with login | Credentials | Result |
|---|---|---|---|---|
| **dvws-node** (`snoopysecurity/dvws-node` @ `4221c04f`, GPL-3.0, Express + MongoDB + MySQL; used only in ml-sast's fresh set, never in DAST) | **3**: `POST /api/v2/passphrase` `passphrase` and `reminder` (string-built INSERT, `controllers/passphrase.js:44`); `GET /api/v2/passphrase/:username` (string-built SELECT, `passphrase.js:59`; the MySQL error text is sent as text/html at `passphrase.js:65`, so CWE-89 and CWE-79) | well over 8 (notes, support tickets, bio, resource store, reports, preferences, …) | test / test (`CHALLENGES.md:15`) | **qualifies** |
| DSVPWA (`276231dd`, MIT) | 5 (`/users` id, `/login` password, `/post` msg, `/jump` path, `/home` path) | 9 (6 without login, plus `/settings` firstname, lastname and email) | guest / guest (`db/users.xml`, shipped seed data, not the README) | qualifies, **not chosen**: its README says it is "mainly inspired by DSVW", a DAST training app |
| Broken Crystals (`1765acfd`, MIT) | 2 probe-able (`/api/testimonials/count` query, `/api/products/search` name behind `AuthGuard`); `x-product-name` is header-only; no server-side reflected XSS | — | — | **fails (a)** |
| XVNA | — | — | — | no license (unchanged) |

**Chosen held-out app: dvws-node.**

**The full labelling and freeze come in stage 3, before any container exists:**
- **Labels:** every probe-able endpoint-param in scope, from source, with file and line citations.
- **Spot-check:** the cited lines are checked before freezing.
- **Freeze:** `FREEZE_v5.json`.

**Scope:**
- **In scope:** the REST API under `/api`, which is all JSON or path parameters with a bearer-token login.
- **Out of scope:** GraphQL, SOAP and XML-RPC; the crawler supports none of them.
- **Skip-listed for safety:** these never reach the probe, are recorded as skip-listed in the ground truth, and are
  not in the coverage denominator.
  - destructive endpoints;
  - endpoints that run code or fetch URLs: `/v2/sysinfo/:command` (OS command), `/v2/greeter` (code evaluation),
    `/v2/export` (node-serialize), the XML imports (XXE), `/download`, `/upload`, the supplier-orders import, LDAP
    search, profile-sharing `partnerOrigin`, and `/v2/users/logout/:redirect`.

**Scan configuration (pre-registered in stage 3):**
- the container runs on an internal Docker network with no outside route;
- a seed per labelled endpoint (the app is a single-page app);
- the documented test / test login.

## 7. Effort and order of work, by value

| # | Item | Effort | Can be dropped if you ask me to stop? |
|---|---|---|---|
| 1 | Auth core (`dastml/auth.py`, guards, crawler, prober, collector, `/scan`) and the fake-app tests | ~half a day | no |
| 2 | dvws-node held-out: labelling, freeze, pre-registration, one scan, v2/v3/v4 scoring, decision | ~half a day | no (the point of the task) |
| 3 | Docs, how-to, backup, tests, e2e, PR | ~2 h | no |
| 4 | Coverage measurement per lab app, unauthenticated vs authenticated (crawl only) | ~1 h | only after 1-3 |
| 5 | Labelling the newly reachable params of the lab apps from source, plus v5 collection | ~half a day | yes, first to go after 6 |
| 6 | Extra v5 apps (PyGoat, DjanGoat, Tiredful-API, nodejs-goof, …) | ~1 day | yes, dropped first |

The same-records rule, the decision rule and the coverage requirement are fixed in stage 3's pre-registration file,
before the scan.

## 8. Corrections made before the freeze (stage 3)

- **XSS on `GET /api/v2/passphrase/:username`.** Section 6 says this parameter is CWE-89 and CWE-79. The frozen ground
  truth labels it CWE-89, with CWE-79 *unknown*. MySQL echoes only a fragment of the statement near the error, so
  whether a whole XSS payload comes back raw cannot be decided from source; this follows the SirAppSec convention. The
  qualification count is unchanged (3 SQLi parameters).
- **Lab images.** dvws-node runs on `mysql:5.7` and `mongo:4.4`, the images already in the lab, instead of
  upstream's `mysql:8` and `mongo:4.0.4`. It is built from the pinned source with `npm ci` and no frontend build
  (`lab/dvws.Dockerfile`).
- **vulpy login.** Logging in to vulpy is not possible in the lab build: `libsession.py:7` sets a bytes cookie, and
  the pinned werkzeug answers 500. vulpy keeps its unauthenticated collection. The app is not patched.
- **NodeGoat skip list.** Logged in, NodeGoat crawls fewer pages than logged out. Its ground-truth skip list blocks
  `/contributions`, `/research`, `/allocations` and `/memos` (eval, SSRF and `$where`), and the logged-in dashboard
  does not link the tutorial pages. All 14 labelled parameters are reached.
- **DVPWA reset.** DVPWA's database still held the v4 scan's stored reviews, which break the HTML parse of its course
  pages. The lab apps were recreated with fresh data before measuring coverage (allowed by rule 3).
