"""Paired before/after comparison of pooled leave-one-app-out predictions on the SAME endpoint-params.

before = reports/loao_clusters_v1relabel.json (v1 features, corrected v2 labels)
after  = reports/loao_clusters_v2.json        (v2 features)
Only clusters present in both are compared (the v2 data may contain more apps or endpoints).
Writes reports/before_after.json and prints the remaining errors of the "after" system.

Usage: python scripts/compare_before_after.py [--kind lr] [--after reports/loao_clusters_v2.json] [--out reports/before_after.json]
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dastml import CLASSES  # noqa: E402
from dastml.evaluation import bootstrap_endpoints, endpoint_metrics  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", default="lr")
    ap.add_argument("--before", default=str(ROOT / "reports/loao_clusters_v1relabel.json"))
    ap.add_argument("--after", default=str(ROOT / "reports/loao_clusters_v2.json"))
    ap.add_argument("--out", default=str(ROOT / "reports/before_after.json"))
    a = ap.parse_args()
    before = {k: tuple(v) for k, v in json.loads(Path(a.before).read_text())[a.kind].items()}
    after = {k: tuple(v) for k, v in json.loads(Path(a.after).read_text())[a.kind].items()}
    common = sorted(set(before) & set(after))
    mismatch = [k for k in common if before[k][0] != after[k][0]]
    assert not mismatch, f"true labels differ between before/after for {mismatch[:5]}"
    systems = {"before": {k: before[k] for k in common}, "after": {k: after[k] for k in common}}
    out = {"kind": a.kind, "n_common": len(common), "only_before": sorted(set(before) - set(after)), "only_after": sorted(set(after) - set(before))}
    for origin in (None, "own", "third-party"):
        key = origin or "all"
        out[key] = {"metrics": {s: endpoint_metrics(cl, origin) for s, cl in systems.items()},
                    "bootstrap": bootstrap_endpoints(systems, origin=origin)}
    errors = lambda cl: sorted((k, CLASSES[v[0]], CLASSES[v[1]]) for k, v in cl.items() if v[0] != v[1])
    out["errors"] = {s: errors(cl) for s, cl in systems.items()}
    Path(a.out).write_text(json.dumps(out, indent=1) + "\n")
    for key in ("all", "own", "third-party"):
        b = out[key]["bootstrap"]
        print(f"{key:12} n={b['n_clusters']:3}  before {out[key]['metrics']['before']['macro_f1']:.3f} {b['macro_f1']['before']['ci95']}  "
              f"after {out[key]['metrics']['after']['macro_f1']:.3f} {b['macro_f1']['after']['ci95']}  "
              f"diff(before-after) {b['differences']['before - after']['mean']:+.3f} {[round(x, 3) for x in b['differences']['before - after']['ci95']]}")
    for s in ("before", "after"):
        print(f"{s} errors ({len(out['errors'][s])}):")
        for k, t, p in out["errors"][s]:
            print(f"   {k}: truth {t}, predicted {p}")


if __name__ == "__main__":
    main()
