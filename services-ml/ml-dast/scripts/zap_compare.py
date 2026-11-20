"""Score the offline ZAP full scans (logs/zap/<app>.json) on the same endpoint-param clusters as ml-dast.

ZAP ran unmodified (zap-full-scan.py from cloudsentinel/zap-offline:verified-closure) on the lab
network, unauthenticated and without seeds. Alerts are mapped to (app, method, path, param):
  CWE-89: plugin ids 40018-40027, 90018;  CWE-79: 40012 (reflected), 40014 (persistent).
DOM XSS (40026) is not counted (client-side XSS is dropped from the ground truth). Listed clusters
that ZAP never reached count as "not flagged". Alerts on unlisted endpoints are counted, not scored.
Usage: python scripts/zap_compare.py [--final]   (--final adds DVNA; only used by eval_final.py)
"""
import collections
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dastml import CLASSES  # noqa: E402
from dastml.crawl import InjectionPoint  # noqa: E402
from dastml.dataset import load  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402

SQLI = {"40018", "40019", "40020", "40021", "40022", "40024", "40027", "90018"}
XSS = {"40012", "40014"}
ZAP_DIR = ROOT / "logs/zap"
LOC = {"GET": "query", "POST": "form"}


def zap_alerts(app):
    path = ZAP_DIR / f"{app}.json"
    if not path.exists():
        return None
    d = json.loads(path.read_text())
    out = []
    for site in d.get("site", []):
        for a in site.get("alerts", []):
            pid = str(a.get("pluginid"))
            cls = "CWE-89" if pid in SQLI else "CWE-79" if pid in XSS else None
            if not cls:
                continue
            for inst in a.get("instances", []):
                out.append((cls, inst.get("method", "GET").upper(), urlsplit(inst.get("uri", "")).path, inst.get("param", "") or ""))
    return out


def zap_clusters(rows, gt, apps):
    """{cluster: (true_idx, pred_idx, origin, app)} over the clusters present in `rows`, plus stats."""
    truth = {}
    for r in rows:
        prev = truth.get(r["cluster"], (0, r["origin"], r["app"]))
        truth[r["cluster"]] = (max(prev[0], CLASSES.index(r["label"])), r["origin"], r["app"])
    pred = collections.defaultdict(int)
    stats = {}
    for app in apps:
        alerts = zap_alerts(app)
        if alerts is None:
            stats[app] = "no ZAP report"
            continue
        unlisted = 0
        for cls, method, path, param in alerts:
            hit = None
            for loc in ({"query", "path"} if method == "GET" else {"form", "json", "query"}):
                point = InjectionPoint(method, path, param or "{seg}", loc)
                e = gt.entry(app, point)
                if e is None and loc == "path":
                    e = gt.entry(app, InjectionPoint(method, path, "{seg9}", "path"))
                if e is not None:
                    hit = gt.cluster(app, InjectionPoint(method, path, param, loc))
                    if loc == "path":
                        hit = f"{app}|{method}|{e['path']}|{e['params'][0]}"
                    break
            if hit is None or hit not in truth:
                unlisted += 1
                continue
            c = CLASSES.index(cls)
            pred[hit] = pred[hit] or c
        stats[app] = {"alerts_in_scope": len(alerts), "alerts_on_unscored_endpoints": unlisted}
    return {k: (v[0], pred.get(k, 0), v[1], v[2]) for k, v in truth.items()}, stats


def main(final=False):
    gt = GroundTruth()
    rows = load(final=final)
    apps = sorted({r["app"] for r in rows})
    cl, stats = zap_clusters(rows, gt, apps)
    from dastml.evaluation import endpoint_metrics
    res = {o or "all": endpoint_metrics(cl, o) for o in (None, "own", "third-party")}
    print(json.dumps(stats, indent=1))
    for o, m in res.items():
        print(o, round(m["macro_f1"], 3), {c: (m["per_class"][c]["tp"], m["per_class"][c]["fp"], m["per_class"][c]["fn"]) for c in CLASSES})
    return cl, stats


if __name__ == "__main__":
    main(final="--final" in sys.argv)
