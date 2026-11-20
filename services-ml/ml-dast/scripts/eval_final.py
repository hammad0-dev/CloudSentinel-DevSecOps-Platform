"""Score the frozen final held-out app (DVNA) EXACTLY ONCE.

Refuses if reports/final_dvna.json exists or data/dast/FREEZE.json no longer matches the DVNA
rows, ground truth or payloads. Writes reports/final_preregistration.json (model SHA-256, selection)
before predicting. Scores the shipped model (trained on all 6 groups, never on DVNA) on the frozen
DVNA rows at endpoint-param and row level with cluster bootstrap, and scores the ZAP scan of DVNA
(logs/zap/dvna.json, run unmodified and unauthenticated) on the same clusters when it exists.
Usage: python scripts/eval_final.py
"""
import hashlib
import json
import sys
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from dastml.dataset import load, matrix  # noqa: E402
from dastml.evaluation import bootstrap_endpoints, clusters, endpoint_metrics, row_metrics  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402

OUT = ROOT / "reports/final_dvna.json"
D = ROOT / "data/dast"


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    if OUT.exists():
        sys.exit("reports/final_dvna.json exists: DVNA has already been scored once. Refusing to score it again.")
    freeze = json.loads((D / "FREEZE.json").read_text())
    checks = {"features_sha256": D / "features/dvna.jsonl.gz", "raw_sha256": D / "raw/dvna.jsonl.gz", "payloads_sha256": D / "payloads/payloads.json"}
    bad = [k for k, p in checks.items() if sha(p) != freeze[k]]
    if bad:
        sys.exit(f"DVNA freeze check failed: {bad}")
    gt_changed = sha(D / "ground_truth.json") != freeze["ground_truth_sha256"]
    model_path = ROOT / "models/release/model.joblib"
    prereg = {"model_sha256": sha(model_path), "selection": json.loads((ROOT / "reports/selection.json").read_text()),
              "freeze": freeze, "ground_truth_changed_since_freeze": gt_changed,
              "metric": "endpoint-param macro-F1 over classes present, per-class P/R/F1, row-level macro-F1, cluster bootstrap 1000"}
    (ROOT / "reports/final_preregistration.json").write_text(json.dumps(prereg, indent=1) + "\n")

    det = joblib.load(model_path)
    rows = load(final=True)
    X, _ = matrix(rows)
    proba = det.model.predict_proba(X)
    ml_cl = clusters(rows, proba, det.threshold)
    systems = {"ml": ml_cl}
    zap_stats = None
    if (ROOT / "logs/zap/dvna.json").exists():
        from zap_compare import zap_clusters
        zap_cl, zap_stats = zap_clusters(rows, GroundTruth(), ["dvna"])
        systems["zap"] = zap_cl
    result = {"preregistration": prereg, "n_rows": len(rows), "n_clusters": len(ml_cl),
              "ml": {"endpoint": endpoint_metrics(ml_cl), "row": row_metrics(rows, proba, det.threshold)},
              "zap": {"endpoint": endpoint_metrics(systems["zap"]), "coverage": zap_stats} if "zap" in systems else "TODO: no ZAP report for DVNA",
              "bootstrap": bootstrap_endpoints(systems),
              "clusters": {k: {"true": v[0], "ml": v[1], **({"zap": systems["zap"][k][1]} if "zap" in systems else {})} for k, v in ml_cl.items()}}
    result["summary"] = {"n_clusters": len(ml_cl), "ml_endpoint_macro_f1": result["ml"]["endpoint"]["macro_f1"],
                         "ml_ci95": result["bootstrap"]["macro_f1"]["ml"]["ci95"], "ml_row_macro_f1": result["ml"]["row"]["macro_f1"],
                         "zap_endpoint_macro_f1": result["zap"]["endpoint"]["macro_f1"] if "zap" in systems else None}
    OUT.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps(result["summary"], indent=1))
    print(json.dumps(result["clusters"], indent=1))


if __name__ == "__main__":
    main()
