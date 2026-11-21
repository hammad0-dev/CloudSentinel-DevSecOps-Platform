"""v5 coverage: crawl each lab app twice, logged out and logged in (crawl only: GET pages, no form is
submitted, no payload is sent), and count pages, injection points and labelled parameters reached.

The two crawls use the same start page, extra pages and seeds as the collector; the logged-in crawl
also starts from the page the login lands on and applies the destructive-action skip list.
Writes data/dast/coverage_v5.json (per app, merged; refuses to change an app's recorded entry unless
--force is given for that app, so a rerun is visible) and prints a table.

Usage: python scripts/coverage_v5.py [--gt v5|v4] app ...
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from collect_lab import EXTRA_PAGES, LAB_PORTS, SEEDS, START, v5_auth  # noqa: E402
from dastml.auth import AuthError, AuthSession  # noqa: E402
from dastml.crawl import crawl  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402
from dastml.guards import GuardedClient, TargetPolicy  # noqa: E402
from dastml.paths import paths  # noqa: E402

OUT = ROOT / "data/dast/coverage_v5.json"


def run(app, gt, logged_in):
    meta = gt.apps()[app]
    base = f"http://127.0.0.1:{meta['port']}"
    policy = TargetPolicy(allowed_ports=LAB_PORTS, max_pages=200, max_requests=3000, rate_per_sec=25.0,
                          skip_paths=gt.skip_paths(app), skip_params=gt.skip_params(app), timeout_sec=15.0)
    session = AuthSession(v5_auth(app, base, gt)) if logged_in else None
    client = GuardedClient(base, policy, auth=session)
    if session is not None:
        client.login()
    starts = [session.landing] if session is not None and session.landing else []
    found, visited = crawl(client, START.get(app, "/"), seeds=SEEDS.get(app, []), start_paths=starts)
    for extra in EXTRA_PAGES.get(app, []):
        more, vis = crawl(client, extra, max_depth=0)
        found += more
        visited += vis
    uniq = {p.key: p for p in found}
    listed = {}
    for p in uniq.values():
        e = gt.entry(app, p)
        if e is not None:
            listed[(e["method"], e["path"], p.param if p.location != "path" else e["params"][0])] = p
    labelled = {(e["method"], e["path"], prm) for e in gt.data["endpoints"] if e["app"] == app for prm in e["params"]}
    unlisted = sorted(f"{p.method} {p.path} [{p.param}] ({p.location})" for p in uniq.values() if gt.entry(app, p) is None)
    return {"pages": len(set(visited)), "visited": sorted(set(visited)), "points": len(uniq), "labelled_total": len(labelled),
            "labelled_reached": len(set(listed) & labelled), "labelled_reached_list": sorted(map(list, set(listed) & labelled)),
            "unlisted_points": unlisted, "requests": client.requests_sent,
            **({"auth": {"logins": session.logins, "relogins": session.relogins}} if session is not None else {})}


def main(argv):
    version = "v5"
    if argv[:1] == ["--gt"]:
        version, argv = argv[1], argv[2:]
    force = "--force" in argv
    apps = [a for a in argv if a != "--force"]
    gt = GroundTruth(paths(version)["ground_truth"])
    data = json.loads(OUT.read_text()) if OUT.exists() else {}
    for app in apps:
        if app in data and data[app].get("gt") == version and not force:
            raise SystemExit(f"refused: coverage for {app} with the {version} ground truth is already recorded (use --force)")
        rec = {"gt": version, "logged_out": run(app, gt, False)}
        try:
            rec["logged_in"] = run(app, gt, True)
        except AuthError as exc:  # recorded, not hidden: the app cannot be logged in to in the lab
            rec["logged_in"] = None
            rec["login_error"] = str(exc)
            data[app] = rec
            OUT.write_text(json.dumps(data, indent=1) + "\n")
            print(f"{app}: logged out pages {rec['logged_out']['pages']}, points {rec['logged_out']['points']}; LOGIN FAILED: {exc}", flush=True)
            continue
        lo, li = rec["logged_out"], rec["logged_in"]
        # what the v5 collector probes: the logged-in crawl plus the logged-out one (the login form itself)
        rec["union_labelled_reached"] = len({tuple(x) for x in lo["labelled_reached_list"]} | {tuple(x) for x in li["labelled_reached_list"]})
        data[app] = rec
        print(f"{app}: pages {lo['pages']} -> {li['pages']}, points {lo['points']} -> {li['points']}, "
              f"labelled reached {lo['labelled_reached']} -> {li['labelled_reached']} (union {rec['union_labelled_reached']}) of {li['labelled_total']}, "
              f"unlisted after login {len(li['unlisted_points'])}, auth {li.get('auth')}", flush=True)
        OUT.write_text(json.dumps(data, indent=1) + "\n")


if __name__ == "__main__":
    main(sys.argv[1:])
