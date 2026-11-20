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
