"""ML (pooled leave-one-app-out predictions) vs offline ZAP on the same endpoint-param clusters.

Both systems are scored on every cluster of the 6 training app groups; the cluster bootstrap resamples
the same clusters for both, so the difference interval is paired. Writes reports/zap_comparison.json
and reports/zap_comparison.md. ZAP ran unauthenticated and without seeds (its own spider), the ML
scanner used the lab login and Juice Shop API seeds: coverage differs and is reported per app.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from dastml import CLASSES  # noqa: E402
from dastml.dataset import load  # noqa: E402
from dastml.evaluation import bootstrap_endpoints, endpoint_metrics  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402
from zap_compare import zap_clusters  # noqa: E402


def main():
    loao = json.loads((ROOT / "reports/loao_clusters.json").read_text())
    family = json.loads((ROOT / "reports/selection.json").read_text())["family"]
    rows = load()
    zap, stats = zap_clusters(rows, GroundTruth(), sorted({r["app"] for r in rows}))
    ml = {k: tuple(v) for k, v in loao[family].items()}
    assert set(ml) == set(zap), "cluster sets differ"
    systems = {f"ml_{family}": ml, "zap": zap}
    out = {"zap_coverage": stats, "metrics": {}, "bootstrap": {}, "per_app": {}}
    for o in (None, "own", "third-party"):
        key = o or "all"
        out["metrics"][key] = {s: endpoint_metrics(cl, o) for s, cl in systems.items()}
        out["bootstrap"][key] = bootstrap_endpoints(systems, origin=o)
    for app in sorted({v[3] for v in ml.values()}):
        sub = {s: {k: v for k, v in cl.items() if v[3] == app} for s, cl in systems.items()}
        out["per_app"][app] = {s: {c: [m["per_class"][c]["tp"], m["per_class"][c]["fp"], m["per_class"][c]["fn"]] for c in CLASSES[1:]}
                               for s, m in ((s, endpoint_metrics(cl)) for s, cl in sub.items())}
    (ROOT / "reports/zap_comparison.json").write_text(json.dumps(out, indent=1) + "\n")
    L = ["# ml-dast vs offline ZAP (same endpoint-param clusters)", "",
         "ZAP: unmodified `zap-full-scan.py` (ZAP 2.17.0, offline image), unauthenticated, no seeds. ML: pooled leave-one-app-out predictions.", "",
         "| Set | System | macro-F1 [95% CI] | SQLi TP/FP/FN | XSS TP/FP/FN |", "|---|---|---|---|---|"]
    for key in ("all", "own", "third-party"):
        for s in systems:
            m = out["metrics"][key][s]
            ci = out["bootstrap"][key]["macro_f1"][s]["ci95"]
            t = lambda c: "/".join(str(m["per_class"][c][x]) for x in ("tp", "fp", "fn"))
            L.append(f"| {key} | {s} | {m['macro_f1']:.3f} [{ci[0]:.3f}, {ci[1]:.3f}] | {t('CWE-89')} | {t('CWE-79')} |")
        d = next(iter(out["bootstrap"][key]["differences"].values()))
        L.append(f"| {key} | difference ML - ZAP | {d['mean']:+.3f} [{d['ci95'][0]:+.3f}, {d['ci95'][1]:+.3f}] | | |")
    L += ["", "Per app (TP/FP/FN, SQLi then XSS):", "", "| App | ML | ZAP |", "|---|---|---|"]
    for app, d in out["per_app"].items():
        f = lambda s: " ; ".join("/".join(map(str, d[s][c])) for c in CLASSES[1:])
        L.append(f"| {app} | {f(f'ml_{family}')} | {f('zap')} |")
    (ROOT / "reports/zap_comparison.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
