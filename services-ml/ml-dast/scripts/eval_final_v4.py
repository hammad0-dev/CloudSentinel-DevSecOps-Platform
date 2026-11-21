"""Collect and score the v4 frozen held-out app (DVPWA) EXACTLY ONCE; v2 (deployed), v3 and v4 on the same records.

1. Refuses if reports/final_dvpwa.json or DVPWA's raw records already exist.
2. Re-checks FREEZE_v4.json (source and ground-truth hashes).
3. Requires reports/selection_v4.json, models/release_v4 and reports/before_after_v4.json (the LOAO half of the
   deployment rule), then writes reports/final_preregistration_v4.json (all three model SHA-256, the scan
   configuration, the metric and the deployment rule) BEFORE the containers are started.
4. Starts DVPWA (--profile final-v4: app, Postgres with the shipped migrations, valkey), collects it with the
   same guarded collector as the training apps (crawl from /, stored-XSS pass, forms, passive pass), stops it.
5. Scores ML (CWE-89, CWE-79) for v4, v2 and v3 at endpoint-param level (cluster bootstrap, paired differences)
   and every rule as counts.
Usage: python scripts/eval_final_v4.py
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

APP = "dvpwa"
OUT = ROOT / "reports/final_dvpwa.json"
P = paths("v4")
LAB = ROOT / "lab"
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
MODELS = {"v4": ROOT / "models/release_v4/model.joblib", "v2": ROOT / "models/release_v2/model.joblib", "v3": ROOT / "models/release_v3/model.joblib"}
RULE = ("v4 replaces v2 as the deployed model only if (a) its DVPWA endpoint-param macro-F1 is higher than v2's on the same records "
        "AND (b) in leave-one-app-out on the same endpoint-params v4 is not significantly worse than v2 (the 95% CI of v2 - v4 does "
        "not lie entirely above 0, reports/before_after_v4.json). Otherwise v2 stays deployed and v4 is packaged as models/release_v4.")


def compose(*args, timeout=900):
    return subprocess.run(["docker", "compose", "--profile", "final-v4", *args], cwd=LAB, capture_output=True, text=True, timeout=timeout)


def main():
    if OUT.exists() or (P["raw"] / f"{APP}.jsonl.gz").exists():
        sys.exit("DVPWA has already been collected/scored once. Refusing to do it again.")
    import freeze_v4
    freeze = json.loads((DATA / "FREEZE_v4.json").read_text())
    gtj = json.loads(P["ground_truth"].read_text())
    checks = {"source_sha256": freeze_v4.source_sha()[0] == freeze["source_sha256"],
              "ground_truth_dvpwa_sha256": freeze_v4.gt_sha(gtj) == freeze["ground_truth_dvpwa_sha256"]}
    if not all(checks.values()):
        sys.exit(f"DVPWA freeze check failed: {checks}")
    ba = json.loads((ROOT / "reports/before_after_v4.json").read_text())
    loao_diff = ba["all"]["bootstrap"]["differences"]["before - after"]  # before = v2, after = v4
    prereg = {**{f"model_{k}_sha256": sha(p) for k, p in MODELS.items()},
              "selection": json.loads((ROOT / "reports/selection_v4.json").read_text()),
              "freeze": freeze, "freeze_checks": checks, "scan_config": freeze["scan_config"], "timeout_sec": 15.0,
              "metric": "ML: endpoint-param macro-F1 over the classes present, per-class P/R/F1, cluster bootstrap 1000 (paired v4/v2/v3); rules/passive/stored/CSRF: counts",
              "deployment_rule": RULE, "loao_v2_minus_v4": loao_diff}
    (ROOT / "reports/final_preregistration_v4.json").write_text(json.dumps(prereg, indent=1) + "\n")

    r = compose("up", "-d", "--build", APP)
    if r.returncode != 0:
        sys.exit(f"could not start {APP}: {r.stderr[-800:]}")
    port = gtj["apps"][APP]["port"]
    for _ in range(90):  # bounded wait for aiohttp + Postgres init
        try:
            if requests.get(f"http://127.0.0.1:{port}/", timeout=3).status_code < 500:
                break
        except requests.RequestException:
            pass
        time.sleep(2)
    t0 = time.time()
    try:
        import collect_lab
        collect_lab.main([APP], "v4", final=True)
    finally:
        compose("stop", APP, "dvpwa-db", "dvpwa-redis", timeout=120)
    raw_sha = sha(P["raw"] / f"{APP}.jsonl.gz")

    rows = [r for r in load(final=True, directory=P["features"]) if r["app"] == APP]
    systems, scored = {}, {}
    for name, path in MODELS.items():
        det = joblib.load(path)
        X, _ = matrix(rows, det.feature_names)
        proba = det.model.predict_proba(X)
        systems[name] = clusters(rows, proba, det.threshold)
        scored[name] = {"threshold": det.threshold, "n_features": len(det.feature_names), "endpoint": endpoint_metrics(systems[name]),
                        "row": row_metrics(rows, proba, det.threshold), "clusters": {k: {"true": v[0], "pred": v[1]} for k, v in systems[name].items()}}
    boot = bootstrap_endpoints(systems)
    import eval_rules
    import eval_rules_v3
    eval_rules.P = eval_rules_v3.P = P
    gt = GroundTruth(P["ground_truth"])
    active, passive = eval_rules.evaluate([APP], gt, load_payloads(("CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601"), P["payloads"]))
    stored, csrf = eval_rules_v3.evaluate_stored([APP], gtj), eval_rules_v3.evaluate_csrf([APP], gtj)
    counts = lambda d, neg: {"found": len(d["found"]), "known": len(d["known"]), "missed": d["missed"], "false_alarms": d["false_alarms"], "negatives": d[neg]}
    summ = lambda d, neg: f"found {len(d['found'])} of {len(d['known'])}, {len(d['false_alarms'])} false alarms on {d[neg]} safe"
    m4, m2 = scored["v4"]["endpoint"]["macro_f1"], scored["v2"]["endpoint"]["macro_f1"]
    loao_ok = not (loao_diff["ci95"][0] > 0)
    decision = {"v4_heldout_macro_f1": m4, "v2_heldout_macro_f1": m2, "v3_heldout_macro_f1": scored["v3"]["endpoint"]["macro_f1"],
                "a_v4_beats_v2_on_heldout": m4 > m2, "b_v4_not_significantly_worse_in_loao": loao_ok, "v4_replaces_v2": bool(m4 > m2 and loao_ok), "rule": RULE}
    summary = {"collection_seconds": round(time.time() - t0), "n_rows": len(rows), "n_clusters": len(systems["v4"]),
               "ml": {k: {"macro_f1": s["endpoint"]["macro_f1"], "ci95": boot["macro_f1"][k]["ci95"],
                          "per_class": {c: {x: s["endpoint"]["per_class"][c][x] for x in ("precision", "recall", "f1", "support", "tp", "fp", "fn")} for c in ("CWE-89", "CWE-79")},
                          "per_class_f1_ci95": boot["per_class_f1_ci95"][k]} for k, s in scored.items()},
               "differences": boot["differences"],
               "rules": {c: summ(d, "safe_units") for c, d in active.items()}, "passive": {c: summ(d, "negatives") for c, d in passive.items()},
               "stored_xss": summ(stored, "safe_units"), "stored_xss_missed": stored["missed"], "csrf_heuristic": summ(csrf, "safe_units"),
               "csrf_missed": csrf["missed"], "decision": decision}
    collection = json.loads((DATA / "collection_summary_v4.json").read_text()).get(APP, {})
    result = {"preregistration": prereg, "raw_sha256": raw_sha, "collection": collection, "ml": scored, "bootstrap": boot,
              "rules": {c: counts(d, "safe_units") for c, d in active.items()}, "passive": {c: counts(d, "negatives") for c, d in passive.items()},
              "stored_xss": stored, "csrf_heuristic": csrf, "summary": summary}
    OUT.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps(summary, indent=1))
    for k in MODELS:
        print(k, json.dumps(scored[k]["clusters"]))


if __name__ == "__main__":
    main()
