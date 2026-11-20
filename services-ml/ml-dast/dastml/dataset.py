"""Load the labelled feature rows. The final held-out app (role final_heldout, DVNA) is excluded unless
final=True, so training, tuning and leave-one-app-out code cannot see it by accident."""
import gzip
import json
from pathlib import Path

import numpy as np

from . import CLASSES
from .features import FEATURE_NAMES

FEATURES_DIR = Path(__file__).resolve().parents[1] / "data/dast/features"


def load(final=False, classes=CLASSES, directory=FEATURES_DIR):
    rows = []
    for path in sorted(Path(directory).glob("*.jsonl.gz")):
        with gzip.open(path, "rt") as fh:
            for line in fh:
                r = json.loads(line)
                if (r["role"] == "final_heldout") != final:
                    continue
                if r["label"] not in classes:
                    continue
                rows.append(r)
    return rows


def matrix(rows):
    X = np.array([[r["features"][k] for k in FEATURE_NAMES] for r in rows], dtype=np.float32)
    y = np.array([CLASSES.index(r["label"]) for r in rows], dtype=np.int64)
    return X, y
