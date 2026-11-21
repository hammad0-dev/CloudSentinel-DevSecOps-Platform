"""Collect the ml-dast feature dataset from the local lab (services-ml/ml-dast/lab).

For each lab app:
1. log in where needed;
2. crawl (same origin, guarded), plus explicit seeds for single-page-app APIs (Juice Shop);
3. probe ONLY injection points listed in data/dast/ground_truth.json and not on its skip list: two
   baselines, one benign probe, then every CWE-89/CWE-79 payload;
4. write raw records to data/dast/raw/<app>.jsonl.gz and labelled feature rows to
   data/dast/features/<app>.jsonl.gz.

DVNA (the final held-out app) is collected into the same layout. Training and tuning code never
loads it (dastml.dataset.load excludes it unless final=True).

Usage: python scripts/collect_lab.py [app ...]
"""
import gzip
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dastml.crawl import InjectionPoint, crawl  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402
from dastml.guards import GuardedClient, TargetPolicy, parse_ports  # noqa: E402
from dastml.paths import paths, refuse_frozen  # noqa: E402
from dastml.probe import CORS_ORIGIN, load_payloads, new_marker, point_rows, probe_point, snapshot  # noqa: E402
from dastml.stored import stored_pass  # noqa: E402

OUT = ROOT / "data/dast"
# Collection-only allowlist (127.0.0.1/localhost): the lab ports. The service default is unchanged.
LAB_PORTS = parse_ports("5101-5114")
ALL_CLASSES = ("CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601")

# NodeGoat /learn's crawled link carries a URL (refused by the guards), so it is seeded with a same-site value.
SEEDS = {"nodegoat": [InjectionPoint("GET", "/learn", "url", "query", (("url", "/dashboard"),))],
         # Juice Shop's /ftp files are only listed by the SPA, never linked in HTML
         "vulnerable-node": [InjectionPoint("GET", "/download", "file", "query", (("file", "duck.svg"),)),
                             InjectionPoint("GET", "/orders", "sort", "query", (("sort", "created_at"),))],
         "juice-shop": [InjectionPoint("GET", "/ftp/legal.md", "{seg2}", "path", (("{seg2}", "legal.md"),), "/ftp/{seg2}")],
         # v3 third-party training apps: JSON API / no index page, so their documented endpoints are seeded
         "vampi": [InjectionPoint("GET", "/users/v1/name1", "{seg3}", "path", (("{seg3}", "name1"),), "/users/v1/{seg3}")]
                  + [InjectionPoint("POST", "/users/v1/register", f, "json", (("username", "csdast"), ("password", "CsDast-2026"), ("email", "csdast@lab.test"))) for f in ("username", "password", "email")]
                  + [InjectionPoint("POST", "/users/v1/login", f, "json", (("username", "name1"), ("password", "pass1"))) for f in ("username", "password")],
         "node-api-goat": [InjectionPoint("GET", path, name, "query", pairs) for path, name, pairs in (
             ("/cwe79/echo", "text", (("text", "hello"),)), ("/cwe201/exposure", "text", (("text", "hello"),)),
             ("/hexToRgb", "hex", (("hex", "ff8800"),)), ("/cwe113/split", "key", (("key", "x-lab"), ("value", "1"))),
             ("/cwe113/split", "value", (("key", "x-lab"), ("value", "1"))), ("/cwe601/redirect", "text", (("text", "hello"),)))]}
# v3: one-off setup requests before collection (never probed). They pass the guards with an empty skip list.
# sirappsec: the seed data pre-registered in FREEZE_v3.json (populate.sh lines 1-24, plus one beer).
SETUP = {"vampi": [("GET", "/createdb", None)],
         "sirappsec": [("POST", "/v1/user/", {"name": "amit", "email": "amit@gmail.com", "password": "123", "role": "user", "address": "aadssd", "profile_pic": "20aab704e5532523652ac9d908d3b8de"}),
                       ("POST", "/v1/user/", {"name": "shir", "email": "shir@gmail.com", "password": "123", "role": "user", "address": "aadssd", "profile_pic": "20aab704e5532523652ac9d908d3b8de"}),
                       ("POST", "/v1/admin/new-beer/", {"name": "Beer!!!", "price": 12, "picture": "20aab704e5532523652ac9d908d3b8de"})]}
# v3: same-origin OpenAPI documents whose operations become injection points (the scan configuration
# pre-registered for the held-out app; dastml.openapi, through the guards)
OPENAPI = {"sirappsec": "/v1/api-docs"}
# v3: per-app request timeout (pre-registered for sirappsec, whose broken handlers never answer)
TIMEOUT = {"sirappsec": 5.0}
# Passive pass (v2): a fresh, cookie-less client loads the start pages and logs in, keeping response
# headers, so cookies set on first visit or at login are seen. Vulpy is probed unauthenticated (as in
# v1); its login here only serves the cookie checks.
PASSIVE_AUTH = {"vulpy-bad": [("POST", "/user/login", {"username": "admin", "password": "SuperSecret"}, False)],
                "vulpy-good": [("POST", "/user/login", {"username": "admin", "password": "SuperSecret"}, False)],
                "dsvw": [("GET", "/login?username=admin&password=7en8aiDoh!", None, False)]}
JUICE_SEEDS = [
    InjectionPoint("GET", "/rest/products/search", "q", "query", (("q", "apple"),)),
    InjectionPoint("POST", "/rest/user/login", "email", "json", (("email", "jim@juice-sh.op"), ("password", "wrongpass"))),
    InjectionPoint("POST", "/rest/user/login", "password", "json", (("email", "jim@juice-sh.op"), ("password", "wrongpass"))),
    InjectionPoint("GET", "/api/Products/1", "{seg3}", "path", (("{seg3}", "1"),), "/api/Products/{seg3}"),
]

AUTH = {
    "vulnerable-node": [("POST", "/login/auth", {"username": "alice", "password": "alice123"}, False)],
    "dvna": [("POST", "/register", {"username": "csdast", "password": "CsDast!2026", "cpassword": "CsDast!2026", "name": "cs dast", "email": "csdast@lab.test"}, True),
             ("POST", "/login", {"username": "csdast", "password": "CsDast!2026"}, False)],
    "nodegoat": [("POST", "/login", {"userName": "user1", "password": "User1_123"}, False)],
}
START = {"dvna": "/app", "nodegoat": "/dashboard", "vulpy-bad": "/user/login", "vulpy-good": "/user/login"}
EXTRA_PAGES = {"vulnerable-node": ["/tools/ping", "/contact", "/login", "/orders"],
               "vulpy-bad": ["/user/create"], "vulpy-good": ["/user/create"], "nodegoat": ["/login", "/signup", "/profile"],
               "dvna": ["/app/usersearch", "/app/products", "/app/ping", "/login", "/forgotpw"],
               # v3: pages that set the session cookies of the v3 twins / the only HTML of the API apps
               "labflask": ["/v3/settings"], "labexpress": ["/v3/account"], "node-api-goat": ["/cwe79/echo?text=hi"], "vampi": ["/users/v1"]}


def login(client, app, first=False):
    for method, path, data, once in AUTH.get(app, []):
        if once and not first:
            continue
        client.request(method, path, data=data)


def passive_pass(base, policy, app):
    client = GuardedClient(base, policy)
    snaps = []
    for path in [START.get(app, "/")] + EXTRA_PAGES.get(app, []):
        try:
            resp, el = client.request("GET", path)
            snaps.append({"kind": "page", "path": path, **snapshot(resp, el, headers=True)})
        except Exception as exc:  # noqa: BLE001 - an unreachable page is recorded, not fatal
            snaps.append({"kind": "error", "path": path, "error": type(exc).__name__})
    for method, path, data, _ in AUTH.get(app, []) + PASSIVE_AUTH.get(app, []):
        try:
            resp, el = client.request(method, path, **({"data": data} if data else {}))
            snaps.append({"kind": "login", "path": path, **snapshot(resp, el, headers=True)})
        except Exception as exc:  # noqa: BLE001
            snaps.append({"kind": "error", "path": path, "error": type(exc).__name__})
    origin = CORS_ORIGIN.replace("{M}", new_marker())
    resp, el = client.request("GET", START.get(app, "/"), headers={"Origin": origin})
    snaps.append({"kind": "cors", "path": START.get(app, "/"), "origin": origin, **snapshot(resp, el, headers=True)})
    for r in snaps:
        r.pop("body", None)  # headers only
    return snaps


def main(apps, version="v1", final=False):
    P = paths(version)
    v2 = version != "v1"
    gt = GroundTruth(P["ground_truth"])
    payloads = load_payloads(ALL_CLASSES if v2 else ("CWE-89", "CWE-79"), P["payloads"])
    P["raw"].mkdir(parents=True, exist_ok=True)
    P["features"].mkdir(parents=True, exist_ok=True)
    summary = {}
    for app in apps:
        if v2:
            refuse_frozen(app)  # v1 DVNA files are frozen; v2 never collects DVNA
        meta = gt.apps()[app]
        if v2 and meta["role"] != "train_loao" and not final:
            raise SystemExit(f"refused: {app} is {meta['role']}; it is collected once, only by scripts/eval_final_v2.py")
        base = f"http://127.0.0.1:{meta['port']}"
        policy = TargetPolicy(allowed_ports=LAB_PORTS, max_pages=200, max_requests=20000, rate_per_sec=25.0,
                              skip_paths=gt.skip_paths(app), skip_params=gt.skip_params(app), timeout_sec=TIMEOUT.get(app, 15.0))
        client = GuardedClient(base, policy)
        t0 = time.time()
        if version == "v3":
            for method, path, body in SETUP.get(app, []):
                setup_policy = TargetPolicy(allowed_ports=LAB_PORTS, max_requests=10, timeout_sec=30.0)
                GuardedClient(base, setup_policy).request(method, path, **({"json": body} if body else {}))
        login(client, app, first=True)
        seeds = (JUICE_SEEDS if app == "juice-shop" else []) + (SEEDS.get(app, []) if v2 else [])
        forms, pages = ([], []) if version == "v3" else (None, None)
        if version == "v3" and app in OPENAPI:
            from dastml.openapi import load_points
            seeds = list(seeds) + load_points(client, OPENAPI[app])
        found, visited = crawl(client, START.get(app, "/"), seeds=seeds, forms_out=forms, pages_out=pages)
        for extra in EXTRA_PAGES.get(app, []):
            # (v3 fix: this loop used to rebind the name v2, the version flag, to the visited list)
            more, vis = crawl(client, extra, max_depth=0, forms_out=forms, pages_out=pages)
            found += more
            visited += vis
        uniq = {p.key: p for p in found}
        listed = [p for p in uniq.values() if gt.entry(app, p) is not None]
        unlisted = sorted(f"{p.method} {p.path} [{p.param}]" for p in uniq.values() if gt.entry(app, p) is None)
        listed_keys = {(e["method"], e["path"], prm) for e in gt.data["endpoints"] if e["app"] == app for prm in e["params"]}
        hit = {(gt.entry(app, p)["method"], gt.entry(app, p)["path"], p.param if p.location != "path" else gt.entry(app, p)["params"][0]) for p in listed}
        rows, errors = 0, []
        with gzip.open(P["raw"] / f"{app}.jsonl.gz", "wt") as raw, gzip.open(P["features"] / f"{app}.jsonl.gz", "wt") as feat:
            for point in sorted(listed, key=lambda p: p.key):
                login(client, app)
                try:
                    rec = probe_point(client, point, payloads, v2=v2)
                except Exception as exc:  # noqa: BLE001 - v3: one broken endpoint must not end the collection
                    errors.append(f"{point.method} {point.path} [{point.param}]: {type(exc).__name__}")
                    continue
                rec["app"] = app
                raw.write(json.dumps(rec) + "\n")
                for p, r, f in point_rows(rec, payloads):
                    label = gt.label(app, point, p["class"])
                    if label is None:
                        continue
                    feat.write(json.dumps({"app": app, "group": meta.get("group", app), "origin": meta["origin"], "role": meta["role"],
                                           "cluster": gt.cluster(app, point, p["class"]), "method": point.method, "path": point.path, "param": point.param,
                                           "location": point.location, "payload_id": p["id"], "payload_class": p["class"],
                                           "family": p["family"], "label": label, "features": f}) + "\n")
                    rows += 1
        if v2:
            passive = passive_pass(base, policy, app)
            (P["raw"] / f"{app}.passive.json").write_text(json.dumps(passive, indent=0) + "\n")
        if version == "v3":
            # forms (CSRF heuristic) and the stored-XSS pass: only listed, non-skipped write points, after the ML probing
            (P["raw"] / f"{app}.forms.json").write_text(json.dumps(forms, indent=0) + "\n")
            stored = stored_pass(client, listed, pages, relogin=lambda: login(client, app))
            (P["raw"] / f"{app}.stored.json").write_text(json.dumps({"pages": list(dict.fromkeys(pages)), "records": stored}, indent=0) + "\n")
            summary_extra = {"forms": len(forms), "stored_points": len(stored), "stored_raw_hits": sum(any(h["raw"] for h in r["hits"]) for r in stored)}
        else:
            summary_extra = {}
        summary[app] = {"pages_crawled": len(visited), "points_found": len(uniq), "points_probed": len(listed),
                        "gt_params_listed": len(listed_keys), "gt_params_found": len(hit), "gt_params_missed": sorted(map(list, listed_keys - hit)),
                        "unlisted_points_not_probed": unlisted[:50], "requests": client.requests_sent, "rows": rows, "seconds": round(time.time() - t0), "point_errors": errors, **summary_extra}
        print(app, json.dumps({k: v for k, v in summary[app].items() if k not in ("unlisted_points_not_probed",)}), flush=True)
    path = OUT / f"collection_summary{P['suffix']}.json"
    old = json.loads(path.read_text()) if path.exists() else {}
    old.update(summary)
    path.write_text(json.dumps(old, indent=1) + "\n")


if __name__ == "__main__":
    args = sys.argv[1:]
    version = "v1"
    if args[:1] == ["--data"]:
        version, args = args[1], args[2:]
    gt_apps = [a for a, m in GroundTruth(paths(version)["ground_truth"]).apps().items() if version == "v1" or m["role"] == "train_loao"]
    main(args or gt_apps, version)
