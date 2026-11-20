"""Rebuild data/dast/features/<app>.jsonl.gz from the stored raw records (no traffic is sent).

Usage: python scripts/featurize.py [app ...]
"""
import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dastml.crawl import InjectionPoint  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402
from dastml.probe import load_payloads, point_rows  # noqa: E402

OUT = ROOT / "data/dast"


def point_of(rec):
    p = rec["point"]
    return InjectionPoint(p["method"], p["path"], p["param"], p["location"], tuple(map(tuple, p["params"])), p.get("template", ""))


def featurize(app, gt, payloads):
    meta = gt.apps()[app]
    n = 0
    with gzip.open(OUT / f"raw/{app}.jsonl.gz", "rt") as raw, gzip.open(OUT / f"features/{app}.jsonl.gz", "wt") as feat:
        for line in raw:
            rec = json.loads(line)
            point = point_of(rec)
            for p, r, f in point_rows(rec, payloads):
                label = gt.label(app, point, p["class"])
                if label is None:
                    continue
                feat.write(json.dumps({"app": app, "group": meta.get("group", app), "origin": meta["origin"], "role": meta["role"],
                                       "cluster": gt.cluster(app, point), "method": point.method, "path": point.path, "param": point.param,
                                       "location": point.location, "payload_id": p["id"], "payload_class": p["class"],
                                       "family": p["family"], "label": label, "features": f}) + "\n")
                n += 1
    return n


if __name__ == "__main__":
    gt, payloads = GroundTruth(), load_payloads()
    apps = sys.argv[1:] or [p.name.split(".")[0] for p in sorted((OUT / "raw").glob("*.jsonl.gz"))]
    for app in apps:
        print(app, featurize(app, gt, payloads))
