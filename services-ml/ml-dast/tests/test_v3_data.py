"""v3 data: the new held-out app is frozen, v2 and v1 files are untouched, and v3 ground truth
differs from v2 only in documented ways."""
import hashlib
import json
from pathlib import Path

import pytest

from dastml.crawl import InjectionPoint
from dastml.groundtruth import GroundTruth
from dastml.paths import DATA, paths

sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
V2 = json.loads((DATA / "ground_truth_v2.json").read_text())
V3 = json.loads((DATA / "ground_truth_v3.json").read_text())
FREEZE3 = json.loads((DATA / "FREEZE_v3.json").read_text())


def test_v3_freeze_hash_of_the_heldout_ground_truth_matches():
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from freeze_v3 import gt_sha
    assert gt_sha(V3) == FREEZE3["ground_truth_sirappsec_sha256"]
    assert FREEZE3["frozen_before_any_scan"] is True and V3["apps"]["sirappsec"]["role"] == "final_heldout_v3"


@pytest.mark.skipif(not (Path(__file__).resolve().parents[1] / "lab/vendor/sirappsec/.git").exists(), reason="vendored source is gitignored")
def test_v3_freeze_hash_of_the_heldout_source_matches():
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from freeze_v3 import source_sha
    assert source_sha()[0] == FREEZE3["source_sha256"]


def test_v2_freeze_still_holds():
    """Same formula as scripts/eval_final_v2.py: ground_truth_v2.json is never edited."""
    f2 = json.loads((DATA / "FREEZE_v2.json").read_text())
    canon = json.dumps({"app": V2["apps"]["dsvw"], "endpoints": [e for e in V2["endpoints"] if e["app"] == "dsvw"],
                        "skip": [s for s in V2["skip"] if s["app"] == "dsvw"], "passive": V2["passive"]["dsvw"]}, sort_keys=True)
    assert hashlib.sha256(canon.encode()).hexdigest() == f2["ground_truth_dsvw_sha256"]
    assert V2["apps"]["dsvw"]["role"] == "final_heldout_v2"


def test_v3_ground_truth_differs_from_v2_only_by_documented_changes():
    key = lambda e: (e["app"], e["method"], e["path"], tuple(e["params"]), e.get("seg"))
    old, new = {key(e): e for e in V2["endpoints"]}, {key(e): e for e in V3["endpoints"]}
    assert all(new[k] == e for k, e in old.items()), "no v2 endpoint label changes in v3"
    assert {k[0] for k in set(new) - set(old)} <= {"sirappsec", "labflask", "labexpress", "labfastapi", "vampi", "node-api-goat", "dvpwa"}
    assert V3["apps"]["dsvw"]["role"] == "train_loao" and V3["changes_v3"][0]["what"].startswith("dsvw role")
    for app, meta in V2["apps"].items():
        if app != "dsvw":
            assert V3["apps"][app] == meta


def test_path_segment_entries_keep_two_path_parameters_apart():
    gt = GroundTruth(DATA / "ground_truth_v3.json")
    pt = lambda seg: InjectionPoint("GET", "/v1/search/test/test", "{seg%d}" % seg, "path", (), "")
    assert gt.entry("sirappsec", pt(3))["params"] == ["filter"]
    assert gt.entry("sirappsec", pt(4))["params"] == ["query"]
    assert gt.cluster("sirappsec", pt(3)) != gt.cluster("sirappsec", pt(4))
    # an entry without "seg" still matches any path parameter (v2 behaviour)
    assert gt.entry("juice-shop", InjectionPoint("GET", "/api/Products/1", "{seg3}", "path"))["params"] == ["id"]


def test_heldout_is_never_a_training_app_and_has_no_data_yet_unless_scored():
    assert V3["apps"]["sirappsec"]["role"].startswith("final_heldout")
    raw = paths("v3")["raw"] / "sirappsec.jsonl.gz"
    scored = (Path(__file__).resolve().parents[1] / "reports/final_sirappsec.json").exists()
    assert scored or not raw.exists(), "SirAppSec is collected only by eval_final_v3.py, once"
