"""Write reports/final_preregistration_v5.json for the dvws-node held-out test, BEFORE any container of it
exists. Refuses to overwrite. scripts/eval_final_v5.py refuses to run unless this file exists, is
committed, and still matches the model files and the freeze.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
OUT = ROOT / "reports/final_preregistration_v5.json"
MODELS = {"v2": ROOT / "models/release_v2/model.joblib", "v3": ROOT / "models/release_v3/model.joblib", "v4": ROOT / "models/release_v4/model.joblib"}
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()

COVERAGE = {
    "requirement": "at least 80% of the labelled reachable endpoint-params are reached, i.e. have probe records in the single scan",
    "denominator": "every dvws-node endpoint-param in ground_truth_v5.json (27; none of them is on the skip list)",
    "numerator": "labelled endpoint-params with at least one probed point in raw_v5/dvws-node.jsonl.gz",
    "threshold": 0.80,
    "if_not_met": "INCONCLUSIVE: v2 stays deployed whatever the scores",
}
UNITS = ("Endpoint-param clusters exactly as dastml.evaluation.clusters builds them from the feature rows (one cluster per "
         "(app, method, path, parameter); class-split only for a parameter vulnerable to both ML classes). A cluster is predicted "
         "C if any C-payload row has P(C) >= the model's own threshold (the detector's threshold, recorded in model_thresholds); "
         "'vulnerable parameters found' = clusters with a true class C != safe predicted as C; 'false alarms' = clusters whose true "
         "class is safe predicted as any class. Rows of classes listed as unknown are dropped (ground truth).")
RULE = ("v4 is deployed (replacing v2 on port 8002) ONLY IF (1) the coverage requirement is met AND, on the same collected records, "
        "(2) v4's endpoint-param macro-F1 is strictly higher than v2's AND (3) v4 finds at least as many vulnerable parameters as v2 "
        "AND (4) v4 has at most one more false alarm than v2. Anything else, a tie included, leaves v2 deployed and v4 packaged.")


def main():
    if OUT.exists():
        sys.exit("final_preregistration_v5.json exists; it is never rewritten")
    import freeze_v5
    freeze = json.loads((ROOT / "data/dast/FREEZE_v5.json").read_text())
    gt = json.loads((ROOT / "data/dast/ground_truth_v5.json").read_text())
    checks = {"source_sha256": freeze_v5.source_sha()[0] == freeze["source_sha256"],
              "ground_truth_dvws_sha256": freeze_v5.gt_sha(gt) == freeze["ground_truth_dvws_sha256"]}
    if not all(checks.values()):
        sys.exit(f"freeze check failed: {checks}")
    docker = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True, text=True).stdout
    if "dvws" in docker:
        sys.exit("a dvws container already exists; the pre-registration must come first")
    import joblib
    thresholds = {k: float(joblib.load(p).threshold) for k, p in MODELS.items()}
    prereg = {
        "app": "dvws-node", "written_before_any_container": True,
        **{f"model_{k}_sha256": sha(p) for k, p in MODELS.items()},
        "model_thresholds": thresholds,
        "deployed_now": "v2 (ml-dast-lr 2.0.0) on port 8002",
        "freeze": {k: freeze[k] for k in ("commit", "source_sha256", "source_files", "ground_truth_dvws_sha256", "counts")},
        "freeze_checks": checks,
        "scan_config": freeze["scan_config"],
        "collector": "scripts/collect_lab.py main(['dvws-node'], 'v5', final=True): the same guarded collector as the lab apps "
                     "(login, seeds, probes, stored-XSS pass, forms, passive pass); scanned once",
        "coverage": COVERAGE,
        "metric": "ML: endpoint-param macro-F1 (dastml.evaluation.endpoint_metrics: mean F1 over the classes present in the truth), "
                  "per-class P/R/F1 and counts; 95% cluster bootstrap (1000 resamples, seed 0) for each model and the paired "
                  "differences. The CIs are reported but are NOT part of the rule. Rules (passive, stored XSS, CSRF, CWE-78/22/601): counts only.",
        "units": UNITS,
        "deployment_rule": RULE,
        "caveat": "One small app (27 endpoint-params, 3 vulnerable) is weak evidence: a single cluster changes the macro-F1 by a lot, "
                  "and the bootstrap intervals will be wide. A win here is a necessary condition for deployment, not proof of generalization.",
        "no_changes_after": "no tuning, rescanning or relabelling after the scan; eval_final_v5.py refuses to run twice",
    }
    OUT.write_text(json.dumps(prereg, indent=1) + "\n")
    print(json.dumps({k: v for k, v in prereg.items() if k.startswith("model_") or k in ("coverage", "deployment_rule")}, indent=1))


if __name__ == "__main__":
    main()
