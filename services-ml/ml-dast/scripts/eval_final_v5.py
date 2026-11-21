"""Collect and score the v5 frozen held-out app (dvws-node) EXACTLY ONCE; v2 (deployed), v3 and v4 on the same records.

1. Refuses if reports/final_dvws.json or dvws-node's raw records already exist (it never runs twice).
2. Re-checks FREEZE_v5.json and requires reports/final_preregistration_v5.json to be COMMITTED and to match the
   three model files' SHA-256 (no model may change after the pre-registration).
3. Builds and starts dvws-node (--profile final-v5: app, MongoDB, MySQL), collects it once with the same guarded
   collector as the lab apps (documented test/test login, bearer token, one seed per labelled endpoint), stops it.
4. Coverage (pre-registered): share of the labelled endpoint-params that have probe records. Below 80% the result
   is INCONCLUSIVE and v2 stays.
5. Scores ML (CWE-89, CWE-79) for v2, v3 and v4 at endpoint-param level (cluster bootstrap, paired differences)
   and every rule as counts, and applies the pre-registered decision rule.
Usage: python scripts/eval_final_v5.py
"""
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import joblib
import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from dastml.dataset import load, matrix  # noqa: E402
from dastml.evaluation import bootstrap_endpoints, clusters, endpoint_metrics, row_metrics  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402
from dastml.paths import DATA, paths  # noqa: E402
from dastml.probe import load_payloads  # noqa: E402

APP = "dvws-node"
OUT = ROOT / "reports/final_dvws.json"
PREREG = ROOT / "reports/final_preregistration_v5.json"
P = paths("v5")
LAB = ROOT / "lab"
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
MODELS = {"v2": ROOT / "models/release_v2/model.joblib", "v3": ROOT / "models/release_v3/model.joblib", "v4": ROOT / "models/release_v4/model.joblib"}
SERVICES = ("dvws", "dvws-mongo", "dvws-mysql")


def compose(*args, timeout=900):
    return subprocess.run(["docker", "compose", "-p", "mldast-lab", "--profile", "final-v5", *args], cwd=LAB,
                          capture_output=True, text=True, timeout=timeout)


def committed(path):
    rel = str(path.relative_to(ROOT.parents[1]))
    tracked = subprocess.run(["git", "ls-files", "--error-unmatch", rel], cwd=ROOT.parents[1], capture_output=True).returncode == 0
    clean = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", rel], cwd=ROOT.parents[1]).returncode == 0
    return tracked and clean


def found_vulnerable(cl):
    return sum(1 for t, p, _, _ in cl.values() if t != 0 and p == t)


def false_alarms(cl):
    return sum(1 for t, p, _, _ in cl.values() if t == 0 and p != 0)


def main():
    if OUT.exists() or (P["raw"] / f"{APP}.jsonl.gz").exists():
        sys.exit("dvws-node has already been collected/scored once. Refusing to do it again.")
    import freeze_v5
    freeze = json.loads((DATA / "FREEZE_v5.json").read_text())
    gtj = json.loads(P["ground_truth"].read_text())
    checks = {"source_sha256": freeze_v5.source_sha()[0] == freeze["source_sha256"],
              "ground_truth_dvws_sha256": freeze_v5.gt_sha(gtj) == freeze["ground_truth_dvws_sha256"],
              "freeze_committed": committed(DATA / "FREEZE_v5.json"), "preregistration_committed": committed(PREREG)}
    prereg = json.loads(PREREG.read_text())
    for k, p in MODELS.items():
        checks[f"model_{k}_unchanged"] = sha(p) == prereg[f"model_{k}_sha256"]
    if not all(checks.values()):
        sys.exit(f"pre-scan checks failed: {checks}")

    r = compose("up", "-d", "--build", *SERVICES, timeout=2400)
    if r.returncode != 0:
        sys.exit(f"could not start {APP}: {r.stderr[-1500:]}")
    port = gtj["apps"][APP]["port"]
    up = False
    for _ in range(150):  # bounded wait: seeding + swagger generation + Apollo start
        try:
            if requests.get(f"http://127.0.0.1:{port}/api/v2/info", timeout=3).status_code in (200, 403):
                up = True
                break
        except requests.RequestException:
            pass
        time.sleep(2)
    t0 = time.time()
    try:
        if not up:
            sys.exit("dvws-node did not come up within the bounded wait; nothing was collected")
        import collect_lab
        collect_lab.main([APP], "v5", final=True)
    finally:
        logs = compose("logs", "--no-color", "--tail", "200", "dvws", timeout=120).stdout
        (ROOT / "logs").mkdir(exist_ok=True)
        (ROOT / "logs/dvws_container_v5.log").write_text(logs)
        compose("stop", *SERVICES, timeout=180)
    raw_sha = sha(P["raw"] / f"{APP}.jsonl.gz")
    collection = json.loads((DATA / "collection_summary_v5.json").read_text()).get(APP, {})

    # coverage (pre-registered): labelled endpoint-params with probe records
    gt = GroundTruth(P["ground_truth"])
    import gzip
    from dastml.crawl import InjectionPoint
    labelled = {(e["method"], e["path"], prm) for e in gtj["endpoints"] if e["app"] == APP for prm in e["params"]}
    probed = set()
    with gzip.open(P["raw"] / f"{APP}.jsonl.gz", "rt") as fh:
        for line in fh:
            pt = json.loads(line)["point"]
            point = InjectionPoint(pt["method"], pt["path"], pt["param"], pt["location"], (), pt.get("template", ""))
            e = gt.entry(APP, point)
            if e is not None:
                probed.add((e["method"], e["path"], pt["param"] if pt["location"] != "path" else e["params"][0]))
    coverage = {"labelled": len(labelled), "reached": len(probed & labelled), "share": len(probed & labelled) / len(labelled),
                "missed": sorted(map(list, labelled - probed)), "met": len(probed & labelled) / len(labelled) >= 0.80}

    rows = [r for r in load(final=True, directory=P["features"]) if r["app"] == APP]
    systems, scored = {}, {}
    for name, path in MODELS.items():
        det = joblib.load(path)
        X, _ = matrix(rows, det.feature_names)
        proba = det.model.predict_proba(X)
        systems[name] = clusters(rows, proba, det.threshold)
        scored[name] = {"threshold": det.threshold, "n_features": len(det.feature_names), "endpoint": endpoint_metrics(systems[name]),
                        "row": row_metrics(rows, proba, det.threshold), "found_vulnerable": found_vulnerable(systems[name]),
                        "false_alarms": false_alarms(systems[name]),
                        "clusters": {k: {"true": v[0], "pred": v[1]} for k, v in systems[name].items()}}
    boot = bootstrap_endpoints(systems)
    import eval_rules
    import eval_rules_v3
    eval_rules.P = eval_rules_v3.P = P
    active, passive = eval_rules.evaluate([APP], gt, load_payloads(("CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601"), P["payloads"]))
    stored, csrf = eval_rules_v3.evaluate_stored([APP], gtj), eval_rules_v3.evaluate_csrf([APP], gtj)
    counts = lambda d, neg: {"found": len(d["found"]), "known": len(d["known"]), "missed": d["missed"], "false_alarms": d["false_alarms"], "negatives": d[neg]}
    summ = lambda d, neg: f"found {len(d['found'])} of {len(d['known'])}, {len(d['false_alarms'])} false alarms on {d[neg]} safe"

    s2, s4 = scored["v2"], scored["v4"]
    cond = {"1_coverage_met": coverage["met"],
            "2_v4_macro_f1_strictly_higher": s4["endpoint"]["macro_f1"] > s2["endpoint"]["macro_f1"],
            "3_v4_finds_at_least_as_many": s4["found_vulnerable"] >= s2["found_vulnerable"],
            "4_v4_at_most_one_extra_false_alarm": s4["false_alarms"] <= s2["false_alarms"] + 1}
    if not coverage["met"]:
        verdict = "INCONCLUSIVE (coverage below 80%): v2 stays deployed"
    elif all(cond.values()):
        verdict = "v4 is deployed (all four conditions hold)"
    else:
        verdict = "v2 stays deployed (" + ", ".join(k for k, v in cond.items() if not v) + " not met)"
    decision = {"conditions": cond, "v4_deployed": bool(all(cond.values())), "verdict": verdict, "rule": prereg["deployment_rule"]}
    summary = {"collection_seconds": round(time.time() - t0), "n_rows": len(rows), "n_clusters": len(systems["v4"]), "coverage": coverage,
               "ml": {k: {"macro_f1": s["endpoint"]["macro_f1"], "ci95": boot["macro_f1"][k]["ci95"], "found_vulnerable": s["found_vulnerable"],
                          "false_alarms": s["false_alarms"],
                          "per_class": {c: {x: s["endpoint"]["per_class"][c][x] for x in ("precision", "recall", "f1", "support", "tp", "fp", "fn")} for c in ("CWE-89", "CWE-79")},
                          "per_class_f1_ci95": boot["per_class_f1_ci95"][k]} for k, s in scored.items()},
               "differences": boot["differences"],
               "rules": {c: summ(d, "safe_units") for c, d in active.items()}, "passive": {c: summ(d, "negatives") for c, d in passive.items()},
               "stored_xss": summ(stored, "safe_units"), "csrf_heuristic": summ(csrf, "safe_units"),
               "auth": collection.get("auth"), "decision": decision}
    result = {"preregistration": prereg, "pre_scan_checks": checks, "raw_sha256": raw_sha, "collection": collection, "ml": scored,
              "bootstrap": boot, "rules": {c: counts(d, "safe_units") for c, d in active.items()},
              "passive": {c: counts(d, "negatives") for c, d in passive.items()}, "stored_xss": stored, "csrf_heuristic": csrf, "summary": summary}
    OUT.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps(summary, indent=1))
    for k in MODELS:
        print(k, json.dumps(scored[k]["clusters"]))


if __name__ == "__main__":
    main()
