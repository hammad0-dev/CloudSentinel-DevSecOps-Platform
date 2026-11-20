"""Load the labelled feature rows. The final held-out app (role final_heldout, DVNA) is excluded unless
final=True, so training, tuning and leave-one-app-out code cannot see it by accident."""
import gzip
import json
from pathlib import Path

import numpy as np

from . import CLASSES
from .features import FEATURE_NAMES

FEATURES_DIR = Path(__file__).resolve().parents[1] / "data/dast/features"


def load(final=False, classes=CLASSES, directory=FEATURES_DIR, relabel=None):
    """relabel: optional GroundTruth whose labels replace the stored ones (e.g. v1 features scored
    with the corrected v2 labels). Rows of rule-only payload classes (CWE-78, CWE-22) are never
    ML rows."""
    rows = []
    for path in sorted(Path(directory).glob("*.jsonl.gz")):
        with gzip.open(path, "rt") as fh:
            for line in fh:
                r = json.loads(line)
                if r["role"].startswith("final_heldout") != final:  # DVNA (v1) and DSVW (v2) never train
                    continue
                if r["payload_class"] not in classes:
                    continue
                if relabel is not None:
                    from .crawl import InjectionPoint
                    point = InjectionPoint(r["method"], r["path"], r["param"], r["location"])
                    entry = relabel.entry(r["app"], point)
                    new = relabel.label(r["app"], point, r["payload_class"]) if entry else None
                    if new is None:
                        continue
                    r["label"] = new
                if r["label"] not in classes:
                    continue
                rows.append(r)
    return rows


def matrix(rows, names=FEATURE_NAMES):
    X = np.array([[r["features"][k] for k in names] for r in rows], dtype=np.float32)
    y = np.array([CLASSES.index(r["label"]) for r in rows], dtype=np.int64)
    return X, y
