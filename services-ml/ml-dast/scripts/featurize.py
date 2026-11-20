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
from dastml.paths import paths, refuse_frozen  # noqa: E402
from dastml.probe import load_payloads, point_rows  # noqa: E402

OUT = ROOT / "data/dast"
ALL_CLASSES = ("CWE-89", "CWE-79", "CWE-78", "CWE-22")


def point_of(rec):
    p = rec["point"]
    return InjectionPoint(p["method"], p["path"], p["param"], p["location"], tuple(map(tuple, p["params"])), p.get("template", ""))


def featurize(app, gt, payloads, version="v1"):
    refuse_frozen(app)
    meta = gt.apps()[app]
    P = paths(version)
    P["features"].mkdir(parents=True, exist_ok=True)
    n = 0
    with gzip.open(P["raw"] / f"{app}.jsonl.gz", "rt") as raw, gzip.open(P["features"] / f"{app}.jsonl.gz", "wt") as feat:
        for line in raw:
            rec = json.loads(line)
            point = point_of(rec)
            for p, r, f in point_rows(rec, payloads):
                label = gt.label(app, point, p["class"])
                if label is None:
                    continue
                feat.write(json.dumps({"app": app, "group": meta.get("group", app), "origin": meta["origin"], "role": meta["role"],
                                       "cluster": gt.cluster(app, point, p["class"]), "method": point.method, "path": point.path, "param": point.param,
                                       "location": point.location, "payload_id": p["id"], "payload_class": p["class"],
                                       "family": p["family"], "label": label, "features": f}) + "\n")
                n += 1
    return n


if __name__ == "__main__":
    args = sys.argv[1:]
    version = "v1"
    if args[:1] == ["--data"]:
        version, args = args[1], args[2:]
    P = paths(version)
    gt, payloads = GroundTruth(P["ground_truth"]), load_payloads(ALL_CLASSES if version != "v1" else ("CWE-89", "CWE-79"), P["payloads"])
    apps = args or [p.name.split(".")[0] for p in sorted(P["raw"].glob("*.jsonl.gz"))]
    for app in apps:
        if app in __import__("dastml.paths", fromlist=["FROZEN_APPS"]).FROZEN_APPS:
            print(app, "skipped (frozen)")
            continue
        print(app, featurize(app, gt, payloads, version))
