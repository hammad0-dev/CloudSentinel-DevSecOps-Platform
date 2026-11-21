"""Build data/dast/ground_truth_v5.json from ground_truth_v4.json (v4 labels copied unchanged) plus the v5
additions, all labelled from SOURCE before any authenticated collection or held-out scan:

* NodeGoat POST /profile website: newly reachable after login (the only unlabelled parameter the
  logged-in crawls of the lab apps found; data/dast/coverage_v5.json).
* DVPWA: role train_loao (v4 held-out, scored once and burned; v5 data only). Its labels are the v4 ones.
* dvws-node (snoopysecurity/dvws-node @ 4221c04f, GPL-3.0): role final_heldout_v5, every probe-able
  REST parameter in scope, with file:line citations at that commit, a skip list and the pre-registered
  scan configuration (documented test/test login with a JSON bearer token, one seed per endpoint).

Refuses to overwrite an existing ground_truth_v5.json.
"""
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/dast"
DV = "dvws-node"
SRC = "dvws-node @ 4221c04f"
J = lambda **kw: [[k, v] for k, v in kw.items()]


def e(method, path, params, where, vuln, note, seed, **extra):
    return {"app": DV, "method": method, "path": path, "params": params, "in": where, "vuln": vuln, "note": f"{SRC} {note}", "seed": seed, **extra}


DVWS_ENDPOINTS = [
    # --- the vulnerable parameters (CWE-89) ---
    e("POST", "/api/v2/passphrase", ["passphrase", "reminder"], "json", ["CWE-89"],
      "src/routes/passphrase.js:10-11 (validateToken), src/controllers/passphrase.js:44-45: INSERT ... values ('${result.user}', "
      "'${req.body.passphrase}', '${req.body.reminder}') run with sequelize.query (string-built). Errors: res.send(err) at line 49 "
      "(the Sequelize error object, sent as JSON), so not reflected HTML XSS; success text is constant (line 46)",
      {"path": "/api/v2/passphrase", "params": J(passphrase="test", reminder="test")}),
    e("GET", "/api/v2/passphrase/{username}", ["username"], "path", ["CWE-89"],
      "src/routes/passphrase.js:16-17 (no auth), src/controllers/passphrase.js:58-59: SELECT ... WHERE username = '${req.params.username}' "
      "(string-built). On error line 65 sends err.original.sqlMessage as a string (text/html). MySQL echoes only a fragment of the "
      "statement near the error, so whether a whole XSS payload comes back raw is not determinable from source: CWE-79 unknown",
      {"path": "/api/v2/passphrase/test"}, seg=4, unknown=["CWE-79"]),
    # --- safe for both ML classes (or with one class unknown) ---
    e("POST", "/api/v2/users", ["username", "password"], "json", [],
      "src/routes/users.js:16-17 (no auth), src/controllers/users.js:80 User.findOne({username}) (Mongoose, string value), line 90 "
      "new User(req.body); 409 'User x already exists' is text/plain (line 83), otherwise JSON (line 102)",
      {"path": "/api/v2/users", "params": J(username="csdast-user", password="CsDast-2026")}),
    e("PUT", "/api/v2/users/profile/bio", ["bio"], "json", [],
      "src/routes/users.js:26 (validateToken), src/controllers/users.js:288-299: Mongoose findOneAndUpdate $set bio; JSON response",
      {"path": "/api/v2/users/profile/bio", "params": J(bio="hello")}),
    e("GET", "/api/v2/users/{id}/profile-details", ["id"], "path", [],
      "src/routes/users.js:28-29, src/controllers/users.js:444-463: User.findById(req.params.id); JSON (cast errors as JSON, line 463)",
      {"path": "/api/v2/users/1/profile-details"}, seg=4),
    e("GET", "/api/v2/notifications/{id}/read", ["id"], "path", [],
      "src/routes/users.js:43-46, src/controllers/users.js:530-535 -> src/services/notifications.js:20-29 findOneAndUpdate({_id: id, username}); "
      "errors return null -> 404 JSON",
      {"path": "/api/v2/notifications/1/read"}, seg=4),
    e("GET", "/api/v2/profile-sharing/jsonp", ["callback"], "query", [],
      "src/routes/users.js:52-53, src/controllers/users.js:574: callback must match ^[A-Za-z_$][A-Za-z0-9_$]{0,63}$ or a 400 JSON error",
      {"path": "/api/v2/profile-sharing/jsonp", "params": J(callback="cb")}),
    e("POST", "/api/v2/notes", ["name", "body", "type"], "json", [],
      "src/routes/notes.js:35-37, src/controllers/notes.js:109-116: new Note({name, body, type}).save() (Mongoose); JSON (errors res.send(err) as JSON)",
      {"path": "/api/v2/notes", "params": J(name="csdast-note", body="hello", type="public")}),
    e("GET", "/api/v2/notes/{noteId}", ["noteId"], "path", [],
      "src/routes/notes.js:39-40, src/controllers/notes.js:123: Note.findById(parseInt(noteId)); JSON",
      {"path": "/api/v2/notes/1"}, seg=4),
    e("PUT", "/api/v2/notes/{noteId}", ["noteId"], "path", [],
      "src/routes/notes.js:41, src/controllers/notes.js:133: Note.findOneAndUpdate({name: noteId}, req.body) (Mongoose, string value); JSON",
      {"path": "/api/v2/notes/csdast-note"}, seg=4),
    e("POST", "/api/v2/notesearch", ["search"], "json", [],
      "src/routes/notes.js:44-45, src/controllers/notes.js:161-167: MongoDB $where JavaScript built from search (NoSQL/JS injection, "
      "CWE-943, not SQL): CWE-89 unknown; results and errors are JSON (CWE-79 safe)",
      {"path": "/api/v2/notesearch", "params": J(search="csdast-note")}, unknown=["CWE-89"]),
    e("GET", "/api/v2/release/{release}", ["release"], "path", [],
      "src/routes/notes.js:16-17 (no auth), src/controllers/notes.js:79-97: XPath expression built from release (XPath injection, CWE-643, "
      "not SQL): CWE-89 unknown; output is the matching config nodes, never the input; errors are a constant string (CWE-79 safe)",
      {"path": "/api/v2/release/1"}, seg=4, unknown=["CWE-89"]),
    e("POST", "/api/v2/support/tickets", ["subject", "message"], "json", [],
      "src/routes/support-tickets.js:5-6, src/controllers/support-tickets.js:8-20: type checks, SupportTicket.create (Mongoose); JSON",
      {"path": "/api/v2/support/tickets", "params": J(subject="hello", message="hello")}),
    e("GET", "/api/v2/support/tickets/{id}", ["id"], "path", [],
      "src/routes/support-tickets.js:8-9, src/controllers/support-tickets.js:24: UUID v1 pattern check, else 400 JSON",
      {"path": "/api/v2/support/tickets/00000000-0000-1000-8000-000000000000"}, seg=5),
    e("GET", "/api/v2/reports/monthly", ["period"], "query", ["CWE-22"],
      "src/routes/integrations.js:11-15, src/controllers/integrations.js:130-147: period joined into a path and read without a "
      "containment check (path traversal, restricted to *.json files: a rule class, not ML); responses are JSON",
      {"path": "/api/v2/reports/monthly", "params": J(period="2026-01")}),
    e("GET", "/api/v2/reports/activity", ["limit"], "query", [],
      "src/routes/integrations.js:17-21, src/controllers/integrations.js:152-157: ^[0-9]+$ and 1..5000 or a 400 JSON error",
      {"path": "/api/v2/reports/activity", "params": J(limit="20")}),
    e("PUT", "/api/v2/users/notification-preferences", ["email", "weeklyDigest"], "json", [],
      "src/routes/integrations.js:25, src/controllers/integrations.js:181-195: Object.assign(user, req.body) then Mongoose save "
      "(mass assignment, not SQL); JSON (errors as JSON, line 195)",
      {"path": "/api/v2/users/notification-preferences", "params": J(email="test@dvws.local", weeklyDigest="true")}),
    e("POST", "/api/v2/resource-store/promotions/redeem", ["code"], "json", [],
      "src/routes/resource-store.js:56-109: length check, escapeRegex before a Mongoose $regex (line 76); JSON",
      {"path": "/api/v2/resource-store/promotions/redeem", "params": J(code="WELCOME")}),
    e("POST", "/api/v2/resource-store/promotions/timing/validate", ["flag"], "json", [],
      "src/routes/resource-store.js:112-130: length check, constant-time compare (line 127); JSON",
      {"path": "/api/v2/resource-store/promotions/timing/validate", "params": J(flag="DVWS{x}")}),
    e("POST", "/api/v2/resource-store/orders", ["itemId", "quantity"], "json", [],
      "src/routes/resource-store.js:133-160: itemId looked up in a constant catalogue (line 139), quantity must be an integer (line 141); JSON",
      {"path": "/api/v2/resource-store/orders", "params": J(itemId="api-monitor", quantity="1")}),
]

DVWS_SKIP = [
    ("/api/v2/sysinfo", "OS command execution: exec(req.params.command) (src/controllers/notes.js:69)"),
    ("/api/v2/greeter", "code evaluation: new Function over the query (src/routes/notes.js:20-30)"),
    ("/api/v2/export", "node-serialize unserialize of the body (src/controllers/passphrase.js:95-96): code execution"),
    ("/api/v2/notes/import/xml", "XML parser with entity expansion (XXE / XML bomb)"),
    ("/api/v2/users/profile/import/xml", "XML import (XXE)"),
    ("/api/v2/users/profile/restore/xml", "XML restore (signature challenge, XXE)"),
    ("/api/v2/users/profile/export/xml", "XML export (no parameters; part of the restore challenge)"),
    ("/api/upload", "file upload"),
    ("/api/download", "reads files by name (path traversal)"),
    ("/api/v2/integrations", "YAML import with an executable tag (code execution)"),
    ("/api/v2/users/ldap-search", "LDAP query (needs an LDAP backend; out of scope)"),
    ("/api/v2/users/profile-sharing", "PUT takes a partner origin URL (CORS configuration)"),
    ("/api/v2/users/logout", "logout with an off-host redirect"),
    ("/api/v2/account-recovery", "password reset flow (destructive)"),
    ("/api/v2/users/change-password", "password change (destructive)"),
    ("/api/v2/admin", "admin user creation and login logs"),
    ("/graphql", "GraphQL (the crawler does not support it)"),
    ("/dvwsuserservice", "SOAP (not supported)"),
    ("/xmlrpc", "XML-RPC (not supported)"),
]

DVWS_APP = {
    "port": 5116, "lang": "node", "origin": "third-party", "role": "final_heldout_v5",
    "framework": "Express 4 + Mongoose (MongoDB) + Sequelize (MySQL); JSON REST API under /api with JWT bearer tokens; static SPA",
    "source": "snoopysecurity/dvws-node @ 4221c04f132960a0ccca4bf5aa5f3a9f53172778 (GPL-3.0)",
    "credentials": "documented default account test / test (CHALLENGES.md line 15; created by scripts/seed-database.js lines 86-96); "
                   "kept in the gitignored lab/auth.local.json, never committed",
    "scan_config": {
        "start": "/",
        "seed_endpoints": True,
        "seeds": "one seed per labelled endpoint (the 'seed' of each ground-truth entry, with its baseline values); the app is a single-page app",
        "auth": {"loginPath": "/api/v2/login", "body": "json", "success": {"tokenJson": "token"}, "loggedOut": {"status": [401]},
                 "credentialRef": "DVWS"},
        "excluded_not_probed": "the login endpoints /api/v2/login and /api/v1/login (rate-limited to 100 attempts per 30 s; probing them "
                               "is a brute-force pattern) and every parameter-less route",
        "timeout_sec": 15.0, "rate_per_sec": 25.0,
        "network": "own compose network; the app container has no resolver (dns 127.0.0.1), as for BenchmarkPython",
        "images": "app built from the pinned source (lab/dvws.Dockerfile: node:22-bookworm-slim, npm ci, no frontend build, port 8080 "
                  "as user node); mysql:5.7 and mongo:4.4, the images already in the lab (upstream compose: mysql:8, mongo:4.0.4)",
        "seed_data": "scripts/seed-database.js at container start (upstream compose command)",
    },
}

DVWS_PASSIVE = {
    "missing-csp": True, "missing-nosniff": True, "missing-frame-protection": True,
    "cookie-no-httponly": False, "cookie-no-samesite": False, "cors-any-origin": True,
    "evidence": f"{SRC} src/server.js: no security-header middleware (lines 30-57); cors({{origin: true, credentials: true}}) at "
                "lines 45-51 reflects any Origin with credentials (registered after express.static, so the static start page "
                "does not carry it); auth_token cookie httpOnly true, sameSite lax over http (src/controllers/users.js:55-62)",
}


def main():
    out = DATA / "ground_truth_v5.json"
    if out.exists():
        sys.exit("ground_truth_v5.json exists; it is never rewritten by this script")
    v4 = json.loads((DATA / "ground_truth_v4.json").read_text())
    gt = copy.deepcopy(v4)
    gt["version"] = "v5"
    gt["derived_from_v5"] = "ground_truth_v4.json (every v4 entry copied unchanged) plus the additions in changes_v5"
    gt["apps"]["dvpwa"] = {**gt["apps"]["dvpwa"], "role": "train_loao",
                           "note_v5": "v4 final held-out (scored once, burned); v5 data only (authenticated re-collection). No model uses v5 data yet."}
    gt["endpoints"].append({"app": "nodegoat", "method": "POST", "path": "/profile", "params": ["website"], "in": "form", "vuln": [],
                            "note": "NodeGoat @ c5cb68a app/routes/profile.js:40-50: handleProfileUpdate destructures only firstName, lastName, "
                                    "ssn, dob, address, bankAcc and bankRouting, so website is never read; the page renders the stored "
                                    "document returned by updateUser (line 100), not the request. Newly reachable after login (v5)"})
    gt["apps"][DV] = DVWS_APP
    gt["endpoints"] += DVWS_ENDPOINTS
    gt["skip"] += [{"app": DV, "path": p, "reason": r} for p, r in DVWS_SKIP]
    gt["passive"][DV] = DVWS_PASSIVE
    gt.setdefault("csrf", {})[DV] = {"form_csrf": False, "forms": [],
                                      "evidence": "no server-rendered forms (static SPA plus a JSON API authenticated by a bearer header)"}
    gt["changes_v5"] = [
        {"what": "every v4 entry copied unchanged", "prompted_by": "v5 brief rule 6 (existing labels stay untouched)"},
        {"what": "dvpwa role train_loao (v4 held-out, burned); its labels are the v4 ones", "prompted_by": "v5 brief rule 9"},
        {"what": "nodegoat POST /profile website: safe (never read by the handler)", "prompted_by": "the only newly reachable unlabelled parameter in the logged-in crawls"},
        {"what": "new app dvws-node, role final_heldout_v5: 20 endpoints / 27 endpoint-params labelled from source at 4221c04f before any "
                 "container existed (3 CWE-89 parameters), 19 skip-listed routes, passive and CSRF truth; frozen in FREEZE_v5.json",
         "prompted_by": "v5 brief rule 7 (held-out app that needs a login)"},
    ]
    out.write_text(json.dumps(gt, indent=1) + "\n")
    n = sum(len(x["params"]) for x in DVWS_ENDPOINTS)
    print(f"wrote {out.name}: {len(gt['endpoints'])} entries; dvws-node {len(DVWS_ENDPOINTS)} endpoints, {n} endpoint-params")


if __name__ == "__main__":
    main()
