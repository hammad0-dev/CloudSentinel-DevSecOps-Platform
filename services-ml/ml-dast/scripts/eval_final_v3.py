"""Collect and score the v3 frozen held-out app (SirAppSec) EXACTLY ONCE. The v2 model is scored on the
same records, so the comparison is paired.

1. Refuses if reports/final_sirappsec.json or SirAppSec's raw records already exist.
2. Re-checks FREEZE_v3.json (source and ground-truth hashes).
3. Requires reports/selection_v3.json, models/release_v3 and reports/before_after_v3.json (the LOAO half of
   the default-model rule), then writes reports/final_preregistration_v3.json (both model SHA-256, the
   scan configuration, the metric and the default-model rule) BEFORE the container is started.
4. Starts the container (--profile final-v3), runs the pre-registered seed requests and collects it with
   the same guarded collector as the training apps (crawl + /v1/api-docs, stored-XSS pass, forms,
   passive pass), then stops it.
5. Scores ML (CWE-89, CWE-79) for v3 and v2 at endpoint-param level (cluster bootstrap, paired
   difference) and every rule as counts.
Usage: python scripts/eval_final_v3.py
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

APP = "sirappsec"
OUT = ROOT / "reports/final_sirappsec.json"
P = paths("v3")
LAB = ROOT / "lab"
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
RULE = ("v3 becomes the packaged default only if (a) its SirAppSec endpoint-param macro-F1 is higher than v2's on the same records "
        "AND (b) in leave-one-app-out on the same endpoint-params v3 is not significantly worse than v2 (the 95% CI of v2 - v3 "
        "does not lie entirely above 0, reports/before_after_v3.json). Otherwise v2 stays the default and v3 is packaged separately.")


def compose(*args, timeout=900):
    return subprocess.run(["docker", "compose", "--profile", "final-v3", *args], cwd=LAB, capture_output=True, text=True, timeout=timeout)


def main():
    if OUT.exists() or (P["raw"] / f"{APP}.jsonl.gz").exists():
        sys.exit("SirAppSec has already been collected/scored once. Refusing to do it again.")
    import freeze_v3
    freeze = json.loads((DATA / "FREEZE_v3.json").read_text())
    gtj = json.loads(P["ground_truth"].read_text())
    checks = {"source_sha256": freeze_v3.source_sha()[0] == freeze["source_sha256"],
              "ground_truth_sirappsec_sha256": freeze_v3.gt_sha(gtj) == freeze["ground_truth_sirappsec_sha256"]}
    if not all(checks.values()):
        sys.exit(f"SirAppSec freeze check failed: {checks}")
    v3_path, v2_path = ROOT / "models/release_v3/model.joblib", ROOT / "models/release_v2/model.joblib"
    ba = json.loads((ROOT / "reports/before_after_v3.json").read_text())
    loao_diff = ba["all"]["bootstrap"]["differences"]["before - after"]  # before = v2, after = v3
    prereg = {"model_v3_sha256": sha(v3_path), "model_v2_sha256": sha(v2_path),
              "selection": json.loads((ROOT / "reports/selection_v3.json").read_text()),
              "freeze": freeze, "freeze_checks": checks, "scan_config": freeze["scan_config"], "timeout_sec": 5.0,
              "metric": "ML: endpoint-param macro-F1 over the classes present, per-class P/R/F1, cluster bootstrap 1000 (paired v3 vs v2); rules/passive/stored/CSRF: counts",
              "default_model_rule": RULE, "loao_v2_minus_v3": loao_diff}
    (ROOT / "reports/final_preregistration_v3.json").write_text(json.dumps(prereg, indent=1) + "\n")

    r = compose("up", "-d", "--build", APP)
    if r.returncode != 0:
        sys.exit(f"could not start {APP}: {r.stderr[-500:]}")
    port = gtj["apps"][APP]["port"]
    for _ in range(60):  # bounded wait for the app (Sequelize sync) to listen
        try:
            requests.get(f"http://127.0.0.1:{port}/v1/order", timeout=3)
            break
        except requests.RequestException:
            time.sleep(2)
    t0 = time.time()
    try:
        import collect_lab
        collect_lab.main([APP], "v3", final=True)
    finally:
        compose("stop", APP, timeout=120)
    raw_sha = sha(P["raw"] / f"{APP}.jsonl.gz")

    rows = [r for r in load(final=True, directory=P["features"]) if r["app"] == APP]
    systems, scored = {}, {}
    for name, path in (("v3", v3_path), ("v2", v2_path)):
        det = joblib.load(path)
        X, _ = matrix(rows, det.feature_names)
        proba = det.model.predict_proba(X)
        systems[name] = clusters(rows, proba, det.threshold)
        scored[name] = {"threshold": det.threshold, "endpoint": endpoint_metrics(systems[name]), "row": row_metrics(rows, proba, det.threshold),
                        "clusters": {k: {"true": v[0], "pred": v[1]} for k, v in systems[name].items()}}
    boot = bootstrap_endpoints(systems)
    import eval_rules
    import eval_rules_v3
    gt = GroundTruth(P["ground_truth"])
    active, passive = eval_rules.evaluate([APP], gt, load_payloads(("CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601"), P["payloads"]))
    stored, csrf = eval_rules_v3.evaluate_stored([APP], gtj), eval_rules_v3.evaluate_csrf([APP], gtj)
    counts = lambda d, neg: {"found": len(d["found"]), "known": len(d["known"]), "missed": d["missed"], "false_alarms": d["false_alarms"], "negatives": d[neg]}
    summary_c = lambda d, neg: f"found {len(d['found'])} of {len(d['known'])}, {len(d['false_alarms'])} false alarms on {d[neg]} safe"
    m3, m2 = scored["v3"]["endpoint"]["macro_f1"], scored["v2"]["endpoint"]["macro_f1"]
    loao_ok = not (loao_diff["ci95"][0] > 0)
    decision = {"v3_heldout_macro_f1": m3, "v2_heldout_macro_f1": m2, "a_v3_beats_v2_on_heldout": m3 > m2,
                "b_v3_not_significantly_worse_in_loao": loao_ok, "v3_is_default": bool(m3 > m2 and loao_ok), "rule": RULE}
    summary = {"collection_seconds": round(time.time() - t0), "n_rows": len(rows), "n_clusters": len(systems["v3"]),
               "ml": {k: {"macro_f1": s["endpoint"]["macro_f1"], "ci95": boot["macro_f1"][k]["ci95"],
                          "per_class": {c: {x: s["endpoint"]["per_class"][c][x] for x in ("precision", "recall", "f1", "support")} for c in ("CWE-89", "CWE-79")},
                          "per_class_f1_ci95": boot["per_class_f1_ci95"][k]} for k, s in scored.items()},
               "v3_minus_v2": boot["differences"].get("v3 - v2"),
               "rules": {c: summary_c(d, "safe_units") for c, d in active.items()},
               "passive": {c: summary_c(d, "negatives") for c, d in passive.items()},
               "stored_xss": summary_c(stored, "safe_units"), "stored_xss_outside_rule": stored["outside_rule"],
               "csrf_heuristic": summary_c(csrf, "safe_units"), "decision": decision}
    collection = json.loads((DATA / "collection_summary_v3.json").read_text()).get(APP, {})
    result = {"preregistration": prereg, "raw_sha256": raw_sha, "collection": collection, "ml": scored, "bootstrap": boot,
              "rules": {c: counts(d, "safe_units") for c, d in active.items()}, "passive": {c: counts(d, "negatives") for c, d in passive.items()},
              "stored_xss": stored, "csrf_heuristic": csrf, "summary": summary}
    OUT.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps(summary, indent=1))
    for k in ("v3", "v2"):
        print(k, json.dumps(scored[k]["clusters"]))


if __name__ == "__main__":
    main()
