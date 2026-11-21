"""v5 IN-DISTRIBUTION check: v2, v3 and v4 on the endpoint-params that only the authenticated (v5) collection
reached, in apps those models were TRAINED on. Never a held-out result: the apps (and for most of them the
code paths behind the login) informed training and tuning. Reported separately (reports/indist_v5.*).

Newly reached = labelled endpoint-params reached by the v5 collection (collection_summary_v5.json) that the v4
collection of the same app did not reach (collection_summary_v4.json gt_params_missed).
Usage: python scripts/eval_indist_v5.py app ...
"""
import json
import sys
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dastml.dataset import load, matrix  # noqa: E402
from dastml.evaluation import bootstrap_endpoints, clusters, endpoint_metrics  # noqa: E402
from dastml.paths import DATA, paths  # noqa: E402

MODELS = {"v2": ROOT / "models/release_v2/model.joblib", "v3": ROOT / "models/release_v3/model.joblib", "v4": ROOT / "models/release_v4/model.joblib"}
OUT = ROOT / "reports/indist_v5.json"


def main(apps):
    if OUT.exists():
        sys.exit("reports/indist_v5.json exists; never rewritten")
    s4 = json.loads((DATA / "collection_summary_v4.json").read_text())
    s5 = json.loads((DATA / "collection_summary_v5.json").read_text())
    rows_all = [r for r in load(directory=paths("v5")["features"]) if r["app"] in apps]
    per_app, new_clusters = {}, set()
    keys_of = lambda version, app: {(e["method"], e["path"], prm) for e in json.loads(paths(version)["ground_truth"].read_text())["endpoints"]
                                     if e["app"] == app for prm in e["params"]}
    for app in apps:
        missed4 = {tuple(x) for x in s4[app]["gt_params_missed"]}
        missed5 = {tuple(x) for x in s5[app]["gt_params_missed"]}
        reached4 = keys_of("v4", app) - missed4
        reached5 = keys_of("v5", app) - missed5
        newly = sorted(reached5 - reached4)  # includes v5-only labels (e.g. NodeGoat /profile website)
        keys = {f"{app}|{m}|{p}|{prm}" for m, p, prm in newly}
        rows = [r for r in rows_all if r["app"] == app and r["cluster"].split("#")[0] in keys]
        new_clusters |= {r["cluster"] for r in rows}
        per_app[app] = {"labelled": s5[app]["gt_params_listed"], "reached_v4": len(reached4), "reached_v5": len(reached5),
                        "lost_in_v5": sorted(map(list, reached4 - reached5)), "newly_reached": [list(x) for x in newly],
                        "newly_reached_ml_clusters": len({r["cluster"] for r in rows})}
    rows = [r for r in rows_all if r["cluster"] in new_clusters]
    systems, scored = {}, {}
    for name, path in MODELS.items():
        det = joblib.load(path)
        X, _ = matrix(rows, det.feature_names)
        cl = clusters(rows, det.model.predict_proba(X), det.threshold)
        systems[name] = cl
        scored[name] = {"endpoint": endpoint_metrics(cl), "clusters": {k: {"true": v[0], "pred": v[1]} for k, v in cl.items()}}
    boot = bootstrap_endpoints(systems) if rows else {}
    result = {"what": "IN-DISTRIBUTION (training apps), not held-out", "apps": per_app, "n_rows": len(rows), "n_clusters": len(new_clusters),
              "ml": {k: {"macro_f1": s["endpoint"]["macro_f1"], "ci95": boot.get("macro_f1", {}).get(k, {}).get("ci95"),
                         "per_class": {c: {x: s["endpoint"]["per_class"][c][x] for x in ("tp", "fp", "fn", "support")} for c in ("CWE-89", "CWE-79")},
                         "clusters": s["clusters"]} for k, s in scored.items()},
              "differences": boot.get("differences", {})}
    OUT.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "ml"}, indent=1))
    for k, s in result["ml"].items():
        print(k, round(s["macro_f1"], 3), s["ci95"], s["per_class"])


if __name__ == "__main__":
    main(sys.argv[1:])
