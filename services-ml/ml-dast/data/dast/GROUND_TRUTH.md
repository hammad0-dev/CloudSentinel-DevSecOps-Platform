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
output. Juice Shop entries are **provisional** until checked against the running app.

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

**juice-shop** (provisional)
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
