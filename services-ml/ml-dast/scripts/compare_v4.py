"""Paired before/after on the SAME endpoint-params for v4 (family from reports/selection_v4.json).

* same set:     before = deployed v2 system (reports/loao_clusters_v2.json, LR) vs after = v4 (loao_clusters_v4.json)
* enlarged set: before = the v2 system re-run on the v4 data (loao_clusters_v4data_v2system.json, LR) vs after = v4
Benchmark clusters are excluded from the headline ("real" = own + third-party) and reported separately.
Writes reports/before_after_v4.json and before_after_v4_enlarged.json (never overwrites).
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dastml import CLASSES  # noqa: E402
from dastml.evaluation import bootstrap_endpoints, endpoint_metrics  # noqa: E402

R = ROOT / "reports"


def compare(before_file, before_kind, after_file, after_kind, out):
    if (R / out).exists():
        sys.exit(f"{out} exists; reports are never overwritten")
    before = {k: tuple(v) for k, v in json.loads((R / before_file).read_text())[before_kind].items()}
    after = {k: tuple(v) for k, v in json.loads((R / after_file).read_text())[after_kind].items()}
    common = sorted(set(before) & set(after))
    bad = [k for k in common if before[k][0] != after[k][0]]
    assert not bad, f"true labels differ for {bad[:5]}"
    systems = {"before": {k: before[k] for k in common}, "after": {k: after[k] for k in common}}
    res = {"before": f"{before_file}[{before_kind}]", "after": f"{after_file}[{after_kind}]", "n_common": len(common)}
    for o, key in (("real", "all"), ("own", "own"), ("third-party", "third-party"), ("benchmark", "benchmark")):
        if not any(v[2] == o or (o == "real" and v[2] in ("own", "third-party")) for v in systems["after"].values()):
            continue
        res[key] = {"metrics": {s: endpoint_metrics(cl, o) for s, cl in systems.items()}, "bootstrap": bootstrap_endpoints(systems, origin=o)}
    res["errors"] = {s: sorted((k, CLASSES[v[0]], CLASSES[v[1]]) for k, v in cl.items() if v[0] != v[1]) for s, cl in systems.items()}
    (R / out).write_text(json.dumps(res, indent=1) + "\n")
    for key in ("all", "own", "third-party", "benchmark"):
        if key in res:
            b = res[key]["bootstrap"]
            d = b["differences"]["before - after"]
            print(f"{out:30} {key:12} n={b['n_clusters']:3} before {res[key]['metrics']['before']['macro_f1']:.3f} after {res[key]['metrics']['after']['macro_f1']:.3f} "
                  f"before-after {d['mean']:+.3f} [{d['ci95'][0]:+.3f}, {d['ci95'][1]:+.3f}]")


if __name__ == "__main__":
    fam = json.loads((R / "selection_v4.json").read_text())["family"]
    compare("loao_clusters_v2.json", "lr", "loao_clusters_v4.json", fam, "before_after_v4.json")
    compare("loao_clusters_v4data_v2system.json", "lr", "loao_clusters_v4.json", fam, "before_after_v4_enlarged.json")
