# ml-dast ground truth

`ground_truth.json` (next to this file) is the machine-readable source; this page summarizes it. The
lab apps run from `services-ml/ml-dast/lab/docker-compose.yml` on 127.0.0.1 only.

## Labelling rule

A request/response row is labelled with class C (a CWE) only when all three hold:

- its (app, method, path, parameter) is listed in `ground_truth.json`;
- C is in that entry's `vuln`;
- the payload sent was a C payload.

Everything else is handled like this:

| Case | Label |
|---|---|
| A C payload sent to a listed parameter that is not vulnerable to C, or to a safe endpoint | `safe` |
| Classes listed under `unknown`, and endpoints under `skip` | Row dropped |
| Requests to endpoints not listed at all | Row dropped, never guessed |

Labels come from the source code of each app, read at its pinned commit or image, never from scanner
output. Juice Shop entries were verified against the running app (v20.4.0-SNAPSHOT) on 2026-11-20.

Every request carries a unique marker. "Reflected" means *this* request's marker came back in *this*
response, so payloads stored by earlier requests (NodeGoat profile, vulpy posts) don't count as
reflections.

## Apps

| App | Port | Stack | Origin | Role | Vulnerable params (89 / 79 / 78 / 22) | Safe endpoints |
|---|---|---|---|---|---|---|
| labflask | 5101 | Flask + SQLite | own | LOAO fold | 4 / 3 / 1 / 1 | 12 |
| labexpress | 5102 | Express + PostgreSQL | own | LOAO fold | 4 / 2 / 1 / 1 | 10 |
| labfastapi | 5103 | FastAPI + MySQL + Jinja2 | own | LOAO fold | 4 / 2 / – / – | 7 |
| juice-shop | 5104 | Express + Angular SPA + SQLite | OWASP (MIT) | LOAO fold | 2 / 0 / – / 1 | 7 |
| nodegoat | 5106 | Express + Swig (autoescape off) + MongoDB | OWASP @ c5cb68a (Apache-2.0) | LOAO fold | 0 / 12 / – / – | 3 |
| vulpy-bad | 5107 | Flask + SQLite | vulpy @ 5249cc8 (MIT) | LOAO fold, group `vulpy` | 4 / 0 / – / – | 1 |
| vulpy-good | 5108 | Flask + SQLite | vulpy @ 5249cc8 (MIT) | LOAO fold, group `vulpy` | 0 / 0 / – / – | 3 |
| **dvna** | 5105 | Express + EJS + MySQL | appsecco (MIT) | **final held-out, scored once** | 1 / 1 / 1 / – | 5 |

`vulpy-bad` and `vulpy-good` share code, so they form one leave-one-app-out group. CWE-78 and CWE-22
are phase 2, used only after CWE-89 and CWE-79 work.

## Vulnerable endpoints

**labflask**
- CWE-89:
  - `GET /search?q`: error-based.
  - `GET /item?id`: blind (numeric).
  - `POST /login` with `username` and `password`: generic error.
- CWE-79:
  - `GET /greet?name`: HTML body.
  - `GET /profile?color`: double-quoted attribute.
  - `GET /widget?cb`: script string.
- CWE-78: `GET /ping?host`.
- CWE-22: `GET /download?file`.

**labexpress**
- CWE-89:
  - `GET /books?category`: PostgreSQL error shown.
  - `GET /book/{id}`: path parameter, blind.
  - `POST /lookup` with `email`: generic 500.
  - `GET /sort?by`: ORDER BY.
- CWE-79:
  - `GET /hello?name`: body.
  - `GET /banner?msg`: single-quoted attribute.
- CWE-78: `GET /dns?host`.
- CWE-22: `GET /file?name`.

**labfastapi**
- CWE-89:
  - `GET /orders?status`: MySQL error shown.
  - `GET /order?id`: blind.
  - `GET /api/status?item`: JSON API.
  - `POST /report` with `region`.
- CWE-79:
  - `GET /note?text`: Jinja2 `|safe`, body.
  - `GET /docs-link?topic`: `|safe` in `href`.

**juice-shop** (verified against the running app, v20.4.0-SNAPSHOT)
- CWE-89:
  - `GET /rest/products/search?q`.
  - `POST /rest/user/login` with JSON `email`.
- CWE-22: `GET /ftp/{file}` (null-byte bypass).
- `GET /rest/track-order/{id}` is DOM XSS rendered client-side. It is not visible in the server
  response, so it is dropped (`unknown`).

**nodegoat**
- CWE-79 (all through attributes with autoescape off):
  - `POST /login` with `userName`;
  - `POST /signup` with `userName`, `firstName`, `lastName`, `email`;
  - `POST /profile` with 7 fields (reflected and stored).

**vulpy-bad**
- CWE-89: `POST /user/login` and `POST /user/create`, both with `username` and `password`.

**dvna** (final held-out)
- CWE-89: `POST /app/usersearch` with `login` (blind).
- CWE-79: `POST /app/products` with `name` (EJS `<%- %>`).
- CWE-78: `POST /app/ping` with `address`.

## Safe endpoints and hard negatives

Every vulnerable endpoint in the three apps I own has a `-safe` twin that differs only in the sink:
parameters or casts instead of string-built SQL, escaping instead of raw output, an argument list
instead of a shell string, basename plus containment instead of a raw path join.

**Hard negatives**, where the response looks suspicious but the endpoint is safe:
- raw reflection in `application/json`: labflask `/api/echo`, labexpress `/api/echo`, labfastapi
  `/api/status-safe`;
- raw reflection in `text/plain`: labflask `/plain`, labfastapi `/text`;
- non-SQL stack traces: labflask `/calc`, labexpress `/convert`;
- input-dependent timing: labflask `/slow`.

**Third-party safe endpoints:**

| App | Safe endpoints |
|---|---|
| vulpy-good | Parameterized login; create goes through login |
| dvna | `/login` and `/forgotpw` (Sequelize). `/app/products` is not SQLi: `Op.like` is parameterized |
| nodegoat | `password` (never re-rendered); `/dashboard`, `/benefits` |
| juice-shop | `/api/Products/{id}`, `/rest/languages`, `/rest/captcha`, `/rest/admin/application-version`, `/api/Quantitys` |

## Never attacked (`skip`)

These endpoints are listed in `ground_truth.json` → `skip`, and the payload sender refuses them:
- server-side eval: NodeGoat `/contributions`, DVNA `/app/calc`;
- SSRF and open redirects: NodeGoat `/research` and `/learn`, DVNA `/app/redirect`, Juice Shop
  `/redirect` and `/profile`;
- deserialization and XXE: DVNA `/app/bulkproducts*`;
- NoSQL `$where`: NodeGoat `/allocations`, Juice Shop reviews;
- account-changing endpoints: password change, MFA, user edit, logout.

## Not included

PyGoat is left out. At the pinned commit it starts each lab as its own Docker container
(`challenge/start-lab`), which needs the Docker socket inside the lab. Its image is also the largest
(451 MB compressed).

## v2 ground truth (`ground_truth_v2.json`)

v1 (`ground_truth.json`) is frozen together with DVNA and is never edited. v2 is a separate file with the
changes below, every one read from source (file and line in each entry's `note`); `changes` in the file
lists them with their evidence.

**Corrections and moves**

- NodeGoat `POST /signup` `firstName`, `lastName`: CWE-79 → safe. `handleSignup` re-renders the page with
  `errors = {userName, email}` only (`app/routes/session.js` @ c5cb68a, lines 200-204 and 249-252), so the two
  fields are never echoed. **Prompted by the error analysis of the v1 leave-one-app-out false negatives**, then
  verified from source; the v1 model was re-scored on the corrected labels (`reports/loao_v1relabel.md`).
- NodeGoat `GET /learn` `url`: moved from `skip` to an open-redirect (CWE-601) instance: plain
  `res.redirect(req.query.url)` (`app/routes/index.js` lines 70-73), no server-side fetch. Its crawled link carries
  a URL, which the guards refuse, so it is seeded with `url=/dashboard`.

**Classes in v2.** ML: CWE-89, CWE-79. Rule-based (deterministic, not ML): CWE-78, CWE-22, CWE-601 and the
passive checks. A parameter vulnerable to both ML classes (vulnerable-node `/search?q`) is evaluated as one
cluster per payload class.

| App | Origin | Role | CWE-89 | CWE-79 | CWE-78 | CWE-22 | CWE-601 | Safe params |
|---|---|---|---|---|---|---|---|---|
| labflask | own | train_loao | 5 | 4 | 1 | 1 | 1 | 19 |
| labexpress | own | train_loao | 4 | 3 | 1 | 1 | 1 | 14 |
| labfastapi | own | train_loao | 4 | 3 | 0 | 0 | 0 | 11 |
| juice-shop | third-party | train_loao | 2 | 0 | 0 | 1 | 0 | 3 |
| nodegoat | third-party | train_loao | 0 | 10 | 0 | 0 | 1 | 3 |
| vulpy-bad | third-party | train_loao | 4 | 0 | 0 | 0 | 0 | 0 |
| vulpy-good | third-party | train_loao | 0 | 0 | 0 | 0 | 0 | 4 |
| dsvw | third-party | final_heldout_v2 | 3 | 2 | 1 | 1 | 1 | 4 |
| vulnerable-node | third-party | train_loao | 4 | 1 | 1 | 1 | 1 | 8 |

Counts are parameters (a POST form with two injectable fields counts twice). DVNA (v1 final held-out) is
not part of v2 at all.

**New endpoints (B3) in the own apps**, labelled when written, before collection: validated JSON APIs that
answer 400 to any quote, slow-upstream lookups (1.2 s for unknown values, whatever their content), escaped
404 pages, same-site redirects and links, and vulnerable twins: `javascript:` URLs in `href` (escaped but
scheme not checked: CWE-79), unvalidated redirects (CWE-601), and a blind POST search form (CWE-89).

**vulnerable-node** (cr0hn @ d68f2a3, MIT; third-party training app):
- CWE-89: `GET /search` `q` (also CWE-79: `<%- q %>` in views/products.ejs line 14), `POST /login/auth`
  `username`/`password`, `GET /orders` `sort` (ORDER BY).
- CWE-78: `POST /tools/ping` `host` (inside double quotes: only `$()` and backticks execute).
- CWE-22: `GET /download` `file`; `GET /labs/docs/{file}` is allowlisted (safe).
- CWE-601: `POST /login/auth` `returnurl`, only after a successful login (the probe's form values do not log in).
- Hard negative: `GET /products/{id}` is parameterized but shows a pg type error for non-integers.
- Not started: the SSRF mocks (imds, vault); `/tools/fetch`, `/tools/regex`, NoSQL endpoints and
  account-changing routes are on `skip`.

**DSVW** (stamparm/DSVW @ 9ca3c9a, Unlicense): **v2 final held-out app**, labelled from `dsvw.py` line by line
and frozen by SHA-256 in `FREEZE_v2.json` before any request was sent to it. CWE-89 `/?id`, `/login` `password`,
`/?comment` (INSERT); CWE-79 `/?v`, `/?tmpl`; CWE-78 `/?domain`; CWE-22 `/?path`; CWE-601 `/?redir`. `/login`
`username` is reduced to word characters (safe). Unknown (dropped): XPath `/?name` for CWE-89, stored-only
`/?comment` and JSONP `/users.json?callback` for CWE-79. Never requested (parameter skip list): `object`
(pickle RCE), `include` (exec + remote fetch), `xml` (XXE with network), `size` (memory DoS).

## Passive-check ground truth (v2)

`True` = the weakness is present, read from source (evidence string per app in `passive`).

| App | CSP missing | nosniff missing | framing unprotected | session cookie no HttpOnly | no SameSite | CORS echoes any origin |
|---|---|---|---|---|---|---|
| dsvw | yes | yes | yes | yes | yes | no |
| labflask | yes | yes | yes | no | no | no |
| labexpress | yes | yes | yes | no | no | no |
| labfastapi | yes | yes | yes | no | no | no |
| juice-shop | yes | no | no | no | no | no |
| nodegoat | yes | yes | yes | no | yes | no |
| vulpy-bad | yes | yes | yes | yes | yes | no |
| vulpy-good | yes | yes | yes | yes | yes | no |
| vulnerable-node | yes | yes | yes | no | yes | no |

## Guard additions (v2)

- `skip` entries may name a parameter (`{"path": "/", "param": "object"}`): requests carrying it are refused.
- Any request whose query or body parameters carry a URL (`scheme://`, raw or %-encoded) is refused, so a
  crawled link can never make a target fetch another host.
