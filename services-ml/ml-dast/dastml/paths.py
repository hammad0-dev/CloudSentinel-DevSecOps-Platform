"""Data versions. v1 is frozen together with DVNA (data/dast/FREEZE.json hashes ground_truth.json,
payloads.json and DVNA's raw/feature files), so v1 files are never edited or rewritten. v2 work
lives in separate files and directories.
"""
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data/dast"

VERSIONS = {
    "v1": {"ground_truth": DATA / "ground_truth.json", "payloads": DATA / "payloads/payloads.json",
           "raw": DATA / "raw", "features": DATA / "features", "suffix": ""},
    "v2": {"ground_truth": DATA / "ground_truth_v2.json", "payloads": DATA / "payloads/payloads_v2.json",
           "raw": DATA / "raw_v2", "features": DATA / "features_v2", "suffix": "_v2"},
    # v3 sends the same payloads as v2 (payloads_v2.json): the v3 changes are features, data and rules.
    "v3": {"ground_truth": DATA / "ground_truth_v3.json", "payloads": DATA / "payloads/payloads_v2.json",
           "raw": DATA / "raw_v3", "features": DATA / "features_v3", "suffix": "_v3"},
    # v4: same payloads again; v3 raw records are re-featurized into features_v4, BenchmarkPython and DVPWA are new.
    "v4": {"ground_truth": DATA / "ground_truth_v4.json", "payloads": DATA / "payloads/payloads_v2.json",
           "raw": DATA / "raw_v4", "features": DATA / "features_v4", "suffix": "_v4"},
    # v5: same payloads; authenticated collection (dastml.auth) of the lab apps with a login, new labels
    # for the newly reachable parameters and the dvws-node held-out. Collection only: no model uses v5.
    "v5": {"ground_truth": DATA / "ground_truth_v5.json", "payloads": DATA / "payloads/payloads_v2.json",
           "raw": DATA / "raw_v5", "features": DATA / "features_v5", "suffix": "_v5"},
}
# Apps whose files must never be written by any script (frozen held-out sets).
FROZEN_APPS = {"dvna"}


def paths(version="v1"):
    if version not in VERSIONS:
        raise ValueError(f"unknown data version {version!r}")
    return VERSIONS[version]


def refuse_frozen(app):
    if app in FROZEN_APPS:
        raise SystemExit(f"refused: {app} is a frozen held-out app; its data files are never rewritten")
