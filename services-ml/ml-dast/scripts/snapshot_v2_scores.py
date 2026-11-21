"""Snapshot the deployed v2 model's scores on a fixed sample (v4 compatibility guard).

Re-featurizes a fixed, seeded sample of stored v2 raw records with the CURRENT feature code, scores the rows
with the shipped v2 model (models/release_v2, 70 features) and writes tests/data/v2_scores_sample_v4.json.
tests/test_v2_compat_v4.py repeats the computation and requires identical feature values and scores, so any
change to the v2 feature extraction is caught. Run once, before any v4 code change; refuses to overwrite.
"""
import gzip
import hashlib
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "tests/data/v2_scores_sample_v4.json"
APPS = ("labflask", "labexpress", "labfastapi", "juice-shop", "nodegoat", "vulnerable-node", "vulpy-bad")


def sample_rows(n_points=6, seed=4):
    """[(app, record index, payload id, feature dict)] for a seeded sample of v2 raw records."""
    import joblib  # noqa: F401  (import check only)
    from dastml.paths import paths
    from dastml.probe import load_payloads, point_rows
    P = paths("v2")
    payloads = load_payloads(("CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601"), P["payloads"])
    rng = random.Random(seed)
    out = []
    for app in APPS:
        recs = [json.loads(line) for line in gzip.open(P["raw"] / f"{app}.jsonl.gz", "rt")]
        for i in sorted(rng.sample(range(len(recs)), min(n_points, len(recs)))):
            for p, _, f in point_rows(recs[i], payloads):
                if p["class"] in ("CWE-89", "CWE-79"):
                    out.append((app, i, p["id"], f))
    return out


def score(rows):
    import joblib
    import numpy as np
    det = joblib.load(ROOT / "models/release_v2/model.joblib")
    X = np.array([[f[k] for k in det.feature_names] for *_, f in rows], dtype=np.float32)
    return det, det.model.predict_proba(X)


if __name__ == "__main__":
    if OUT.exists():
        sys.exit(f"{OUT} exists; the snapshot is never rewritten")
    rows = sample_rows()
    det, proba = score(rows)
    model_sha = hashlib.sha256((ROOT / "models/release_v2/model.joblib").read_bytes()).hexdigest()
    data = {"model_sha256": model_sha, "feature_names": det.feature_names, "n_features": len(det.feature_names),
            "rows": [{"app": a, "record": i, "payload_id": pid, "features": {k: f[k] for k in det.feature_names},
                      "proba": [float(x) for x in pr]} for (a, i, pid, f), pr in zip(rows, proba)]}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=0) + "\n")
    print(f"{len(rows)} rows, {len(det.feature_names)} features, model {model_sha[:12]}")
