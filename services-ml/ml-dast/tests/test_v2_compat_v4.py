"""The deployed v2 model must score identically after the v4 branch: same v2 feature values from the
stored raw records, same probabilities (snapshot taken before any v4 change, scripts/snapshot_v2_scores.py)."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SNAP = ROOT / "tests/data/v2_scores_sample_v4.json"
NEEDS = [ROOT / "models/release_v2/model.joblib", ROOT / "data/dast/raw_v2/labflask.jsonl.gz"]


@pytest.mark.skipif(not all(p.exists() for p in NEEDS), reason="model and lab data are gitignored")
def test_v2_features_and_scores_are_unchanged():
    sys.path.insert(0, str(ROOT / "scripts"))
    import hashlib
    from snapshot_v2_scores import sample_rows, score
    snap = json.loads(SNAP.read_text())
    assert hashlib.sha256((ROOT / "models/release_v2/model.joblib").read_bytes()).hexdigest() == snap["model_sha256"]
    rows = sample_rows()
    assert len(rows) == len(snap["rows"])
    det, proba = score(rows)
    assert det.feature_names == snap["feature_names"] and len(det.feature_names) == 70
    for (app, i, pid, f), pr, s in zip(rows, proba, snap["rows"]):
        assert (app, i, pid) == (s["app"], s["record"], s["payload_id"])
        assert {k: f[k] for k in det.feature_names} == s["features"], f"v2 features changed for {app} #{i} {pid}"
        assert [float(x) for x in pr] == s["proba"], f"v2 score changed for {app} #{i} {pid}"


def test_snapshot_is_committed_and_covers_both_ml_classes():
    snap = json.loads(SNAP.read_text())
    assert snap["n_features"] == 70 and len(snap["rows"]) >= 200
    assert {r["payload_id"][:2] for r in snap["rows"]} == {"sq", "xs"}
