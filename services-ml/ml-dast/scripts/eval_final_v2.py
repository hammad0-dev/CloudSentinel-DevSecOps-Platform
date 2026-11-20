"""Collect and score the v2 frozen held-out app (DSVW) EXACTLY ONCE.

1. Refuses if reports/final_dsvw.json or DSVW's raw records already exist.
2. Checks FREEZE_v2.json: dsvw.py SHA-256 and the SHA-256 of DSVW's ground-truth subset.
3. Writes reports/final_preregistration_v2.json (model SHA-256, selection) BEFORE any request to DSVW.
4. Collects DSVW (guarded: 127.0.0.1:5109, parameter skip list, no URL-carrying parameters) and
   records the SHA-256 of the raw records.
5. Scores the shipped v2 model: ML (CWE-89, CWE-79) at endpoint-param level with cluster bootstrap
   and per-class CIs; rules (CWE-78, CWE-22, CWE-601) and passive checks as counts.
Usage (DSVW must be running: cd lab && docker compose --profile final-v2 up -d dsvw):
    python scripts/eval_final_v2.py
"""
import hashlib
import json
import sys
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from dastml.dataset import load, matrix  # noqa: E402
from dastml.evaluation import bootstrap_endpoints, clusters, endpoint_metrics, row_metrics  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402
from dastml.paths import DATA, paths  # noqa: E402
from dastml.probe import load_payloads  # noqa: E402

OUT = ROOT / "reports/final_dsvw.json"
P = paths("v2")
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def gt_subset_sha(gt):
    entries = [e for e in gt["endpoints"] if e["app"] == "dsvw"]
    skips = [s for s in gt["skip"] if s["app"] == "dsvw"]
    canon = json.dumps({"app": gt["apps"]["dsvw"], "endpoints": entries, "skip": skips, "passive": gt["passive"]["dsvw"]}, sort_keys=True).encode()
    return hashlib.sha256(canon).hexdigest()


def main():
    if OUT.exists() or (P["raw"] / "dsvw.jsonl.gz").exists():
        sys.exit("DSVW has already been collected/scored once. Refusing to do it again.")
    freeze = json.loads((DATA / "FREEZE_v2.json").read_text())
    gt_json = json.loads(P["ground_truth"].read_text())
    src = ROOT / "lab/vendor/DSVW/dsvw.py"
    checks = {"source_sha256": sha(src) == freeze["source_sha256"], "ground_truth_dsvw_sha256": gt_subset_sha(gt_json) == freeze["ground_truth_dsvw_sha256"]}
    if not all(checks.values()):
        sys.exit(f"DSVW freeze check failed: {checks}")
    model_path = ROOT / "models/release_v2/model.joblib"
    prereg = {"model_sha256": sha(model_path), "selection": json.loads((ROOT / "reports/selection_v2.json").read_text()),
              "freeze": freeze, "freeze_checks": checks,
              "metric": "ML: endpoint-param macro-F1 over classes present, per-class P/R/F1, cluster bootstrap 1000; rules/passive: counts"}
    (ROOT / "reports/final_preregistration_v2.json").write_text(json.dumps(prereg, indent=1) + "\n")

    import collect_lab  # collects with the same guarded collector as the training apps
    collect_lab.main(["dsvw"], "v2", final=True)
    raw_sha = sha(P["raw"] / "dsvw.jsonl.gz")

    det = joblib.load(model_path)
    rows = [r for r in load(final=True, directory=P["features"]) if r["app"] == "dsvw"]
    X, _ = matrix(rows, det.feature_names)
    proba = det.model.predict_proba(X)
    ml_cl = clusters(rows, proba, det.threshold)
    boot = bootstrap_endpoints({"ml": ml_cl})
    import eval_rules
    active, passive = eval_rules.evaluate(["dsvw"], GroundTruth(P["ground_truth"]),
                                          load_payloads(("CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601"), P["payloads"]))
    counts = lambda d, neg: {"found": len(d["found"]), "known": len(d["known"]), "missed": d["missed"], "false_alarms": d["false_alarms"], "negatives": d[neg]}
    result = {"preregistration": prereg, "raw_sha256": raw_sha, "n_rows": len(rows), "n_clusters": len(ml_cl),
              "ml": {"endpoint": endpoint_metrics(ml_cl), "row": row_metrics(rows, proba, det.threshold), "bootstrap": boot,
                     "clusters": {k: {"true": v[0], "pred": v[1]} for k, v in ml_cl.items()}},
              "rules": {c: counts(d, "safe_units") for c, d in active.items()},
              "passive": {c: counts(d, "negatives") for c, d in passive.items()}}
    aborted = sorted((ROOT / "reports").glob("final_dsvw_aborted_attempt*.json"))
    result["aborted_attempts"] = [json.loads(x.read_text()) for x in aborted]  # disclosed: infrastructure failures before any scoring
    result["summary"] = {"ml_endpoint_macro_f1": result["ml"]["endpoint"]["macro_f1"], "ml_ci95": boot["macro_f1"]["ml"]["ci95"],
                         "ml_per_class": {c: {k: result["ml"]["endpoint"]["per_class"][c][k] for k in ("precision", "recall", "f1", "support")} for c in ("CWE-89", "CWE-79")},
                         "ml_per_class_f1_ci95": boot["per_class_f1_ci95"]["ml"], "n_clusters": len(ml_cl),
                         "rules": {c: f"found {v['found']} of {v['known']}, {len(v['false_alarms'])} false alarms on {v['negatives']} safe" for c, v in result["rules"].items()},
                         "aborted_attempts_before_scoring": len(aborted),
                         "passive": {c: f"found {v['found']} of {v['known']}, {len(v['false_alarms'])} false alarms on {v['negatives']}" for c, v in result["passive"].items()}}
    OUT.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps(result["summary"], indent=1))
    print(json.dumps(result["ml"]["clusters"], indent=1))


if __name__ == "__main__":
    main()
