"""Print a seeded random sample of 50 vulnerable rows of one new source for the hand check (v2 criterion: does
the pre-fix function visibly contain the labelled CWE pattern?). Shows the changed lines of each fix pair.
Usage: python -I scripts/v3/noise_sample.py <source> [n] [seed]   (source = work/<source>/rows.jsonl)
The verdicts are recorded in reports/v3/noise/<source>.json by hand.
"""
import json
import random
import sys
from pathlib import Path

WORK = Path("/mnt/d/cs-data/sast-v3/work")


def changed(before, after):
    b, a = [x.strip() for x in before.split("\n")], [x.strip() for x in after.split("\n")]
    sb, sa = set(b), set(a)
    return [x for x in b if x and x not in sa], [x for x in a if x and x not in sb]


def main(src, n=50, seed=2026):
    rows = [json.loads(l) for l in (WORK / src / "rows.jsonl").open()]
    by_pair = {}
    for r in rows:
        by_pair.setdefault(r["pair_id"], {})[r["label"] == "safe"] = r
    vul = [p for p in by_pair.values() if False in p]
    picks = random.Random(seed).sample(vul, min(n, len(vul)))
    for i, p in enumerate(picks, 1):
        v, s = p[False], p.get(True)
        rem, add = changed(v["code"], s["code"]) if s else (v["code"].split("\n"), [])
        print(f"#{i} [{v['label']}] {v['lang']} {v['source'][5:]} {v.get('file','')}::{v.get('function','')} cwe_raw={v.get('cwe_raw')}")
        for x in rem[:7]:
            print("   -", x[:150])
        for x in add[:5]:
            print("   +", x[:150])
    print(json.dumps([p[False]["pair_id"] for p in picks]))


if __name__ == "__main__":
    main(sys.argv[1], *(int(x) for x in sys.argv[2:]))
