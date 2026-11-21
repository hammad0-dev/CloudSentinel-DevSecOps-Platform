"""v5 data guards: the dvws-node freeze holds, the pre-registration exists and names the current model files,
every v4 label is carried over unchanged, and no held-out data exists unless the single scoring ran."""
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/dast"
sys.path.insert(0, str(ROOT / "scripts"))


def load(name):
    return json.loads((DATA / name).read_text())


def test_v4_entries_carried_over_unchanged():
    v4, v5 = load("ground_truth_v4.json"), load("ground_truth_v5.json")
    assert v5["endpoints"][:len(v4["endpoints"])] == v4["endpoints"]
    assert v5["skip"][:len(v4["skip"])] == v4["skip"]
    for app, meta in v4["apps"].items():
        if app != "dvpwa":
            assert v5["apps"][app] == meta, app
    assert v5["apps"]["dvpwa"]["role"] == "train_loao"  # burned v4 held-out: v5 data only


def test_dvws_is_the_v5_heldout_and_has_no_password_in_the_ground_truth():
    gt = load("ground_truth_v5.json")
    meta = gt["apps"]["dvws-node"]
    assert meta["role"] == "final_heldout_v5"
    auth = meta["scan_config"]["auth"]
    assert set(auth) <= {"loginPath", "body", "success", "loggedOut", "credentialRef"}
    assert "password" not in json.dumps(auth).lower()
    vuln = [p for e in gt["endpoints"] if e["app"] == "dvws-node" and set(e["vuln"]) & {"CWE-89", "CWE-79"} for p in e["params"]]
    safe = [p for e in gt["endpoints"] if e["app"] == "dvws-node" and not set(e["vuln"]) & {"CWE-89", "CWE-79"} for p in e["params"]]
    assert len(vuln) >= 3 and len(safe) >= 8  # the qualification thresholds (rule 7)


def test_freeze_v5_holds():
    freeze_v5 = pytest.importorskip("freeze_v5")
    if not freeze_v5.VENDOR.is_dir():
        pytest.skip("lab/vendor/dvws-node not fetched (lab/fetch-vendor.sh)")
    f = load("FREEZE_v5.json")
    assert freeze_v5.source_sha()[0] == f["source_sha256"]
    assert freeze_v5.gt_sha(load("ground_truth_v5.json")) == f["ground_truth_dvws_sha256"]


def test_earlier_freezes_still_hold():
    for name, key, mod in (("FREEZE_v4.json", "ground_truth_dvpwa_sha256", "freeze_v4"),):
        m = pytest.importorskip(mod)
        f = load(name)
        assert m.gt_sha(load("ground_truth_v4.json")) == f[key]


def test_preregistration_names_the_current_models():
    pre = json.loads((ROOT / "reports/final_preregistration_v5.json").read_text())
    for v in ("v2", "v3", "v4"):
        path = ROOT / f"models/release_{v}/model.joblib"
        if path.is_file():
            assert hashlib.sha256(path.read_bytes()).hexdigest() == pre[f"model_{v}_sha256"], v
    assert pre["coverage"]["threshold"] == 0.80
    assert "strictly higher" in pre["deployment_rule"]


def test_no_heldout_data_unless_scored_once():
    raw = DATA / "raw_v5/dvws-node.jsonl.gz"
    report = ROOT / "reports/final_dvws.json"
    assert report.exists() or not raw.exists()


def test_credential_file_is_never_tracked():
    import subprocess
    out = subprocess.run(["git", "ls-files", "services-ml/ml-dast/lab/auth.local.json"], cwd=ROOT.parents[1], capture_output=True, text=True).stdout
    assert out.strip() == ""
