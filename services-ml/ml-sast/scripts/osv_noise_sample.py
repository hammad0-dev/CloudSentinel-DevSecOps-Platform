"""Draw the 50-row label-noise sample from the OSV rows that survived build_dataset (vulnerable side).

Prints each sampled pair compactly (advisory, CWE, file/function, removed and added lines) for manual
review, and writes data/raw/osv/noise_sample.json. The manual verdicts are recorded in
data/osv_noise_check.json (committed) and summarized in data/manifest.json.
"""
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sastml.evaluation import load  # noqa: E402


def main(n=50, seed=2026):
    kept = {r["pair_id"] for s in ("train", "val", "test") for r in load(s) if r["origin"] == "osv" and r["label"] != "safe"}
    raw = {}
    for line in (ROOT / "data/raw/osv/rows.jsonl").open():
        r = json.loads(line)
        if r["label"] != "safe" and r["pair_id"] in kept:
            raw[r["pair_id"]] = r
    pick = random.Random(seed).sample(sorted(raw), min(n, len(raw)))
    sample = []
    for i, pid in enumerate(pick, 1):
        r = raw[pid]
        sample.append({"n": i, "pair_id": pid, "advisory": r["advisory"], "label": r["label"], "commit": r["commit"], "file": r["file"], "function": r["function"]})
        print(f"#{i} {r['label']} {r['advisory']} {r['file']}::{r['function']}")
        for x in r["removed_lines"][:8]:
            print("   -", x[:150])
        for x in r["added_lines"][:8]:
            print("   +", x[:150])
    (ROOT / "data/raw/osv/noise_sample.json").write_text(json.dumps(sample, indent=1) + "\n")


if __name__ == "__main__":
    main()
