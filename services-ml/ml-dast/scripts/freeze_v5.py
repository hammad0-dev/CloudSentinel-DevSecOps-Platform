"""Freeze the v5 held-out app (dvws-node) BEFORE any container of it exists or any request is sent to it.

Hashes (a) every git-tracked source file of lab/vendor/dvws-node at the pinned commit and (b) the
dvws-node subset of data/dast/ground_truth_v5.json, and writes data/dast/FREEZE_v5.json. Refuses to
overwrite an existing freeze. scripts/eval_final_v5.py re-checks both hashes before scanning and scoring.

    python scripts/freeze_v5.py          # write FREEZE_v5.json (once)
    python scripts/freeze_v5.py --check  # verify the hashes (exit 1 on mismatch)
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/dast"
VENDOR = ROOT / "lab/vendor/dvws-node"
APP = "dvws-node"
COMMIT = "4221c04f132960a0ccca4bf5aa5f3a9f53172778"
ML = ("CWE-89", "CWE-79")


def source_sha(vendor=VENDOR):
    head = subprocess.run(["git", "-C", str(vendor), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if head != COMMIT:
        raise SystemExit(f"vendor/dvws-node is at {head}, expected {COMMIT}")
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
    params = [(e, p) for e in s["endpoints"] for p in e["params"]]
    c = {"endpoints": len(s["endpoints"]), "endpoint_params": len(params), "skip_listed_routes": len(s["skip"])}
    for cls in ML:
        c[f"{cls}_vulnerable"] = sum(1 for e, _ in params if cls in e["vuln"])
        c[f"{cls}_unknown"] = sum(1 for e, _ in params if cls in e.get("unknown", []))
        c[f"{cls}_safe"] = sum(1 for e, _ in params if cls not in e["vuln"] and cls not in e.get("unknown", []))
    c["sqli_or_xss_vulnerable_params"] = sum(1 for e, _ in params if set(e["vuln"]) & set(ML))
    c["safe_for_both_ml_classes"] = sum(1 for e, _ in params if not set(e["vuln"]) & set(ML))
    c["rule_class_vulnerable"] = {cls: sum(len(e["params"]) for e in s["endpoints"] if cls in e["vuln"]) for cls in ("CWE-78", "CWE-22", "CWE-601")}
    c["passive_positive"] = sum(1 for v in s["passive"].values() if v is True)
    c["passive_negative"] = sum(1 for v in s["passive"].values() if v is False)
    return c


def main(check=False):
    gt = json.loads((DATA / "ground_truth_v5.json").read_text())
    src, n_files = source_sha()
    path = DATA / "FREEZE_v5.json"
    if check:
        f = json.loads(path.read_text())
        ok = {"source_sha256": src == f["source_sha256"], "ground_truth_dvws_sha256": gt_sha(gt) == f["ground_truth_dvws_sha256"]}
        print(json.dumps(ok))
        sys.exit(0 if all(ok.values()) else 1)
    if path.exists():
        raise SystemExit("FREEZE_v5.json exists; a freeze is never rewritten")
    freeze = {
        "app": APP, "role": "final_heldout_v5", "frozen_before_any_container": True,
        "source": gt["apps"][APP]["source"], "commit": COMMIT,
        "source_sha256": src, "source_files": n_files,
        "source_hash_covers": "sha256 of the sorted lines '<sha256(file)>  <path>' over `git ls-files` at the commit",
        "ground_truth_dvws_sha256": gt_sha(gt),
        "ground_truth_hash_covers": "json.dumps({app, endpoints, skip, passive, stored, csrf} for dvws-node, sort_keys=True)",
        "scan_config": gt["apps"][APP]["scan_config"],
        "spot_check": "every file:line cited in the dvws-node entries was re-read at the pinned commit before this freeze "
                      "(routes and controllers, per file; two citations outside dvws-node were corrected first)",
        "rule": "dvws-node is labelled from source only and never collected for training or tuning; it is collected and scored "
                "exactly once by scripts/eval_final_v5.py after reports/final_preregistration_v5.json is committed. v2 (deployed), "
                "v3 and v4 are scored on the same records.",
        "counts": counts(gt),
    }
    path.write_text(json.dumps(freeze, indent=1) + "\n")
    print(json.dumps(freeze, indent=1))


if __name__ == "__main__":
    main("--check" in sys.argv)
