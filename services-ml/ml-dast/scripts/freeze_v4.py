"""Freeze the v4 held-out app (DVPWA) BEFORE any request is sent to it.

Hashes (a) every git-tracked source file of lab/vendor/dvpwa at the pinned commit and (b) the
DVPWA subset of data/dast/ground_truth_v4.json, and writes data/dast/FREEZE_v4.json. Refuses to
overwrite an existing freeze. scripts/eval_final_v4.py re-checks both hashes before scoring.

    python scripts/freeze_v4.py          # write FREEZE_v4.json (once)
    python scripts/freeze_v4.py --check  # verify the hashes (exit 1 on mismatch)
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/dast"
VENDOR = ROOT / "lab/vendor/dvpwa"
APP = "dvpwa"
COMMIT = "4a8f4a43fafcc1b304f1b97d0f0a8dea755a7756"


def source_sha(vendor=VENDOR):
    head = subprocess.run(["git", "-C", str(vendor), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if head != COMMIT:
        raise SystemExit(f"vendor/dvpwa is at {head}, expected {COMMIT}")
    files = subprocess.run(["git", "-C", str(vendor), "ls-files", "-z"], capture_output=True, check=True).stdout.decode().split("\0")
    lines = [f"{hashlib.sha256((vendor / f).read_bytes()).hexdigest()}  {f}" for f in sorted(x for x in files if x)]
    return hashlib.sha256("\n".join(lines).encode()).hexdigest(), len(lines)


def gt_subset(gt):
    return {"app": gt["apps"][APP],
            "endpoints": [e for e in gt["endpoints"] if e["app"] == APP],
            "skip": [s for s in gt["skip"] if s["app"] == APP],
            "passive": gt["passive"].get(APP),
            "stored": [s for s in gt.get("stored", []) if s["app"] == APP],
            "csrf": gt.get("csrf", {}).get(APP)}


def gt_sha(gt):
    return hashlib.sha256(json.dumps(gt_subset(gt), sort_keys=True).encode()).hexdigest()


def counts(gt):
    s = gt_subset(gt)
    c = {}
    for e in s["endpoints"]:
        for v in e["vuln"]:
            c[v] = c.get(v, 0) + len(e["params"])
    c["safe_endpoint_params"] = sum(len(e["params"]) for e in s["endpoints"] if not e["vuln"])
    c["passive_positive"] = sum(1 for k, v in s["passive"].items() if v is True)
    c["passive_negative"] = sum(1 for k, v in s["passive"].items() if v is False)
    c["stored_xss"] = len(s["stored"])
    return c


def main(check=False):
    gt = json.loads((DATA / "ground_truth_v4.json").read_text())
    src, n_files = source_sha()
    path = DATA / "FREEZE_v4.json"
    if check:
        f = json.loads(path.read_text())
        ok = {"source_sha256": src == f["source_sha256"], "ground_truth_dvpwa_sha256": gt_sha(gt) == f["ground_truth_dvpwa_sha256"]}
        print(json.dumps(ok))
        sys.exit(0 if all(ok.values()) else 1)
    if path.exists():
        raise SystemExit("FREEZE_v4.json exists; a freeze is never rewritten")
    freeze = {
        "app": APP, "role": "final_heldout_v4", "frozen_before_any_scan": True,
        "source": gt["apps"][APP]["source"], "commit": COMMIT,
        "source_sha256": src, "source_files": n_files,
        "source_hash_covers": "sha256 of the sorted lines '<sha256(file)>  <path>' over `git ls-files` at the commit",
        "ground_truth_dvpwa_sha256": gt_sha(gt),
        "ground_truth_hash_covers": "json.dumps({app, endpoints, skip, passive, stored, csrf} for dvpwa, sort_keys=True)",
        "scan_config": gt["apps"][APP]["scan_config"],
        "rule": "DVPWA is labelled from source only and never collected for training or tuning; it is collected and scored exactly once by scripts/eval_final_v4.py after the v4 model is fixed by SHA-256. v2 (deployed) and v3 are scored on the same collection.",
        "counts": counts(gt),
    }
    path.write_text(json.dumps(freeze, indent=1) + "\n")
    print(json.dumps(freeze, indent=1))


if __name__ == "__main__":
    main("--check" in sys.argv)
