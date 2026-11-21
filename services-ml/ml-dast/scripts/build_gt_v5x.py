"""Stage 6 (extra v5 data): data/dast/ground_truth_v5x.json = ground_truth_v5.json (copied unchanged) plus
nodejs-goof (snyk-labs/nodejs-goof @ add14ba, Apache-2.0), labelled from SOURCE before the app was ever started.
v5x data is collected only; NO model uses it. Refuses to overwrite.

Candidates checked from source (docs/ml-dast-auth-final-report.md): PyGoat (skipped: needs the Docker socket),
DjanGoat and Tiredful-API (dropped: no README-documented login, Python 2.7 / Django 1.11), nodejs-goof (kept).
"""
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/dast"
APP = "nodejs-goof"
SRC = "nodejs-goof @ add14ba"


def e(method, path, params, where, vuln, note, **extra):
    return {"app": APP, "method": method, "path": path, "params": params, "in": where, "vuln": vuln, "note": f"{SRC} {note}", **extra}


ENDPOINTS = [
    e("GET", "/login", ["redirectPage"], "query", ["CWE-79"],
      "routes/index.js:80-85 renders views/admin.ejs with redirectPage from the query; views/admin.ejs:17 outputs it raw "
      "(<%- redirectPage %>) inside value=\"...\" (reflected XSS, attribute context). No database use", context="attr_double_quoted"),
    e("POST", "/login", ["username", "password"], "form", [],
      "routes/index.js:50-64: validator.isEmail(username) first (else 401, empty body), then Mongoose User.find with the string "
      "values (operator injection needs a JSON object, which the probe never sends); responses are an empty 401 or a redirect"),
    e("POST", "/login", ["redirectPage"], "form", ["CWE-601"],
      "routes/index.js:54 and 73-74: res.redirect(redirectPage) after a SUCCESSFUL login only (open redirect, a rule class); "
      "a failed login returns an empty 401, so it is never reflected (ML safe)"),
    e("POST", "/create", ["content"], "form", [], unknown=["CWE-79"],
      note="routes/index.js:165-200: Mongoose save, 302 to / (followed), whose views/index.ejs:20 renders marked(content) with "
           "app.js:75 marked.setOptions({sanitize: true}): raw HTML is escaped. The known bypass is a markdown javascript: link "
           "(marked 0.3.5, CVE-2016-10531), which no ML payload uses, so CWE-79 is dropped rather than labelled either way. "
           "SQLi safe (MongoDB). The exec() at lines 169-179 runs only for content with an http URL, which the guard never sends"),
    e("POST", "/update/{id}", ["content"], "form", [], unknown=["CWE-79"],
      note="routes/index.js:231-241: Mongoose save, 302 to / rendering marked(content) sanitized (as /create); SQLi safe"),
    e("POST", "/account_details", ["firstname", "lastname", "country", "phone", "email"], "form", [],
      "app.js:58 (isLoggedIn), routes/index.js:102-125: validator checks, then views/account.hbs:6 and 18-34 render the values "
      "with Handlebars {{ }} (HTML-escaped); no database. Reachable only after login"),
]

SKIP = [
    ("/destroy", "deletes a todo (app.js:61)"),
    ("/import", "file upload, zip extraction (zip slip)"),
    ("/about_new", "dustjs-helpers @if evaluates the device parameter as code (views/about_new.dust:4): code injection"),
    ("/chat", "prototype pollution via lodash merge; DELETE deletes messages"),
    ("/users", "TypeORM/MySQL routes, not linked; MySQL is not started in the lab"),
    ("/logout", "ends the session"),
    ("/public", "static files (st)"),
]

APP_META = {
    "port": 5117, "lang": "node", "origin": "third-party", "role": "train_loao", "group": APP,
    "framework": "Express 4.12 + EJS/Handlebars/Dust + Mongoose 4.2 (MongoDB); express-session",
    "source": "snyk-labs/nodejs-goof @ add14ba59e98240d9e00a235dd7d42cd61ae9912 (Apache-2.0)",
    "credentials": "documented admin account (README.md:88, seeded by mongoose-db.js:48-52); kept in the gitignored lab/auth.local.json",
    "note_v5x": "stage-6 extra v5 data: collected with login, NOT used by any model yet",
    "scan_config": {"start": "/", "setup": "one POST /create (a todo) so the edit pages and update forms exist",
                    "images": "lab/goof.Dockerfile (node:18-bookworm-slim, npm ci); mongo:4.4 (upstream mongo:3); no MySQL (upstream mysql:5)"},
}

PASSIVE = {"missing-csp": True, "missing-nosniff": True, "missing-frame-protection": True, "cookie-no-httponly": False,
           "cookie-no-samesite": True, "cors-any-origin": False,
           "evidence": f"{SRC} app.js:40-72: no security-header middleware and no CORS; express-session (app.js:42-46) with cookie "
                       "{path: '/'}: HttpOnly by default, no SameSite; the session cookie is set on the first visit (saveUninitialized default)"}

CSRF = {"form_csrf": True, "cookie": "connect.sid: HttpOnly, no SameSite",
        "forms": [{"path": "/create", "vuln": True, "note": "no token (views/index.ejs:12)"},
                  {"path": "/update/{id}", "vuln": True, "note": "no token (views/edit.ejs:19)"},
                  {"path": "/login", "vuln": True, "note": "no token (views/admin.ejs:8)"},
                  {"path": "/account_details", "vuln": True, "note": "no token (views/account.hbs:15)"}],
        "evidence": f"{SRC}: no CSRF middleware in app.js"}


def main():
    out = DATA / "ground_truth_v5x.json"
    if out.exists():
        sys.exit("ground_truth_v5x.json exists; never rewritten")
    gt = copy.deepcopy(json.loads((DATA / "ground_truth_v5.json").read_text()))
    gt["version"] = "v5x"
    gt["apps"][APP] = APP_META
    gt["endpoints"] += ENDPOINTS
    gt["skip"] += [{"app": APP, "path": p, "reason": r} for p, r in SKIP]
    gt["passive"][APP] = PASSIVE
    gt["csrf"][APP] = CSRF
    gt["changes_v5x"] = [{"what": "ground_truth_v5.json copied unchanged; nodejs-goof added (6 endpoints, 11 endpoint-params), labelled from source "
                                  "before the app was started", "prompted_by": "v5 brief stage 6 (extra v5 data, no model uses it)"}]
    out.write_text(json.dumps(gt, indent=1) + "\n")
    print(f"wrote {out.name}: +{len(ENDPOINTS)} endpoints, {sum(len(x['params']) for x in ENDPOINTS)} endpoint-params")


if __name__ == "__main__":
    main()
