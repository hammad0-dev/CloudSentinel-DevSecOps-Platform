"""Build the ml-sast v3 training data: v2 rows + new real sources + synthetic_v3 -> data/processed_v3/{train,val,test}.jsonl.

Order of operations (every count is recorded in data/manifest.json under "v3"):
1. v2 rows (data/processed/{train,val,test}.jsonl: CrossVul, OSV, synthetic v2) keep their v2 split.
2. New real sources from /mnt/d/cs-data/sast-v3/work/<source>/rows.jsonl (cvefixes, jsvul, pyvul, osv_v3) and the
   GitLab rule tests; synthetic_v3 from sastml/synthetic_v3.py (optional: --no-synthetic-v3 for the ablation).
3. Rows of every excluded repository are dropped (RealVuln repos, development/fresh/held-out apps, DAST apps:
   /mnt/d/cs-data/sast-v3/work/excluded_repos.json plus the v2 EVAL_APPS pattern).
4. Exact duplicates (language + normalized code) dropped, keeping the highest-priority source; code seen with
   conflicting labels is dropped everywhere (as v2).
5. Near-duplicates (5-token shingle Jaccard >= 0.8, MinHash LSH candidates then the exact Jaccard): a row that
   near-duplicates any development, fresh or v3 held-out unit is dropped; a new row that near-duplicates a row
   of another pair already kept (any split, any source) is dropped. The two sides of one fix pair are never
   compared with each other (they differ only by the fix by design).
6. Splits by repository (no repository in two splits): v2 groups keep their split; new repositories are
   assigned greedily 70/15/15 per label (scripts/build_dataset.group_split); synthetic_v3 by sink family.
7. Weights: per-source sample weights from the noise policy (reports/v3/noise/*.json): PyVul 0.5.
Usage: python -I scripts/v3/build_dataset_v3.py [--no-synthetic-v3] [--out data/processed_v3]
"""
import argparse
import collections
import hashlib
import json
import random
import re
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from build_dataset import group_split, norm, shingles  # noqa: E402
from sastml import CLASSES  # noqa: E402

WORK = Path("/mnt/d/cs-data/sast-v3/work")
PRIORITY = ["crossvul", "osv", "cvefixes", "jsvul", "osv_v3", "pyvul", "gitlab_rules", "synthetic", "synthetic_v3"]
REAL = {"crossvul", "osv", "cvefixes", "jsvul", "osv_v3", "pyvul"}
RULE_TESTS = {"gitlab_rules"}
SYNTH = {"synthetic", "synthetic_v3"}
NEW_SOURCES = {"cvefixes": "cvefixes", "jsvul": "jsvul", "pyvul": "pyvul", "osv_v3": "osv_v3", "gitlab": "gitlab_rules"}
EVAL_APPS = re.compile(r"(?i)(nodegoat|dvna|vulpy|pygoat|django\.?nv|dvws|vulnerable-node|dvpwa|juice-?shop|realvuln)")


def load_jsonl(p):
    return [json.loads(l) for l in open(p)] if Path(p).exists() else []


class MinHash:
    def __init__(self, n=64, bands=16, seed=7):
        rng = np.random.default_rng(seed)
        self.a = rng.integers(1, 2**31 - 1, n, dtype=np.int64)
        self.b = rng.integers(0, 2**31 - 1, n, dtype=np.int64)
        self.bands, self.rows = bands, n // bands

    def sig(self, sh):
        if not sh:
            return None
        h = np.array([int(hashlib.md5(s.encode()).hexdigest()[:8], 16) for s in sh], dtype=np.int64)
        return ((np.outer(h, self.a) + self.b) % (2**31 - 1)).min(axis=0)

    def keys(self, sig):
        return [(i, tuple(sig[i * self.rows:(i + 1) * self.rows])) for i in range(self.bands)]


def jaccard(a, b):
    return len(a & b) / len(a | b) if a and b else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-synthetic-v3", action="store_true")
    ap.add_argument("--out", default="data/processed_v3")
    args = ap.parse_args()
    out_dir = ROOT / args.out
    stats = collections.Counter()
    excluded = set(json.loads((WORK / "excluded_repos.json").read_text()))

    # 1-2. collect
    rows = []
    for split in ("train", "val", "test"):
        for r in load_jsonl(ROOT / f"data/processed/{split}.jsonl"):
            r["v2_split"] = split
            rows.append(r)
    stats["v2_rows"] = len(rows)
    per_source_raw = collections.Counter()
    for name, origin in NEW_SOURCES.items():
        for r in load_jsonl(WORK / name / "rows.jsonl"):
            r["origin"] = origin
            rows.append(r)
            per_source_raw[origin] += 1
    if not args.no_synthetic_v3:
        from sastml.extract import js_parses
        from sastml.synthetic_v3 import generate
        syn = generate(120, js_validator=js_parses)
        rows += syn
        per_source_raw["synthetic_v3"] = len(syn)

    # 3. excluded repositories
    kept = []
    for r in rows:
        repo = r["source"][5:].lower() if r["source"].startswith("repo:") else None
        if repo and (repo in excluded or repo.split("/")[-1] in {e.split("/")[-1] for e in excluded} or EVAL_APPS.search(repo)) and "v2_split" not in r:
            stats[f"dropped_excluded_repo:{r['origin']}"] += 1
            continue
        kept.append(r)
    rows = kept

    # 4. exact duplicates / conflicts
    rows.sort(key=lambda r: (PRIORITY.index(r["origin"]), "v2_split" not in r))
    labels = collections.defaultdict(set)
    for r in rows:
        labels[(r["lang"], norm(r["code"]))].add(r["label"])
    seen, kept = set(), []
    for r in rows:
        k = (r["lang"], norm(r["code"]))
        if len(labels[k]) > 1:
            stats[f"dropped_conflicting_label:{r['origin']}"] += 1
            continue
        if k in seen:
            stats[f"dropped_exact_duplicate:{r['origin']}"] += 1
            continue
        seen.add(k)
        kept.append(r)
    rows = kept

    # 5. near duplicates (eval units first, then across pairs)
    mh = MinHash()
    eval_sh = []
    for p in [ROOT / "data/processed/heldout.jsonl", ROOT / "data/processed/fresh.jsonl", ROOT / "data/heldout_v3/python.jsonl", ROOT / "data/heldout_v3/node.jsonl"]:
        eval_sh += [shingles(r["code"]) for r in load_jsonl(p)]
    buckets = collections.defaultdict(list)  # band key -> [("eval", i) | ("row", i)]
    for i, s in enumerate(eval_sh):
        sg = mh.sig(s)
        if sg is not None:
            for k in mh.keys(sg):
                buckets[k].append(("eval", i))
    row_sh = [shingles(r["code"]) for r in rows]
    kept_idx = []
    for i, r in enumerate(rows):
        s = row_sh[i]
        sg = mh.sig(s)
        drop = None
        if sg is not None:
            cands = {c for k in mh.keys(sg) for c in buckets.get(k, ())}
            for kind, j in cands:
                if kind == "eval" and jaccard(s, eval_sh[j]) >= 0.8:
                    drop = "near_duplicate_of_eval_unit"
                    break
            if drop is None and "v2_split" not in r:
                for kind, j in cands:
                    if kind == "row" and rows[j]["pair_id"] != r["pair_id"] and jaccard(s, row_sh[j]) >= 0.8:
                        drop = "near_duplicate_of_kept_row"
                        break
        if drop:
            stats[f"dropped_{drop}:{r['origin']}"] += 1
            continue
        kept_idx.append(i)
        if sg is not None:
            for k in mh.keys(sg):
                buckets[k].append(("row", i))
    rows = [rows[i] for i in kept_idx]
    # a fix pair that lost one side is not a pair any more: keep it only if both sides survive (real fix-pair sources)
    sides = collections.Counter(r["pair_id"] for r in rows if r["origin"] in REAL - {"crossvul", "osv"})
    rows = [r for r in rows if not (r["origin"] in REAL - {"crossvul", "osv"} and sides[r["pair_id"]] < 2 and "v2_split" not in r)]

    # 6. splits
    names = ["train", "val", "test"]
    fixed = {}
    for r in rows:
        if "v2_split" in r and r["origin"] not in SYNTH:
            fixed[r["source"]] = names.index(r["v2_split"])
    real_new = [r for r in rows if r["origin"] not in SYNTH and "v2_split" not in r]
    assign = group_split([r for r in rows if r["origin"] not in SYNTH], fixed=fixed)
    fams = collections.defaultdict(set)
    for r in rows:
        if r["origin"] == "synthetic_v3":
            fams[(r["label"] if r["label"] != "safe" else r["source"].split(":")[1], r["lang"])].add(r["source"])
    rnd = random.Random(11)
    syn_assign = {}
    for key, fs in sorted(fams.items()):
        fs = sorted(fs)
        rnd.shuffle(fs)
        for i, f in enumerate(fs):
            syn_assign[f] = 2 if i == 0 and len(fs) >= 3 else 1 if i == 1 and len(fs) >= 3 else 0
    weights = {}
    for p in (ROOT / "reports/v3/noise").glob("*.json"):
        d = json.loads(p.read_text())
        weights[NEW_SOURCES.get(d["source"], d["source"])] = 0.5 if d["decision"] == "weight 0.5" else (0.0 if d["decision"] == "drop" else 1.0)
    splits = {n: [] for n in names}
    for r in rows:
        if r["origin"] == "synthetic":
            s = r["v2_split"]
        elif r["origin"] == "synthetic_v3":
            s = names[syn_assign[r["source"]]]
        else:
            s = names[assign[r["source"]]] if "v2_split" not in r else r["v2_split"]
        w = weights.get(r["origin"], 1.0)
        if w == 0.0:
            stats[f"dropped_source_policy:{r['origin']}"] += 1
            continue
        r["split"], r["weight"] = s, w
        r.setdefault("id", hashlib.sha256((r["lang"] + "\0" + r["code"]).encode()).hexdigest()[:16])
        splits[s].append(r)
    groups = {n: {r["source"] for r in splits[n] if r["origin"] not in SYNTH} for n in names}
    leaks = sorted((groups["train"] & groups["val"]) | (groups["train"] & groups["test"]) | (groups["val"] & groups["test"]))
    out_dir.mkdir(parents=True, exist_ok=True)
    for n, rs in splits.items():
        with open(out_dir / f"{n}.jsonl", "w") as fh:
            for r in rs:
                r.pop("v2_split", None)
                fh.write(json.dumps(r) + "\n")

    def cat(o):
        return "real" if o in REAL else "rule_tests" if o in RULE_TESTS else "synthetic"

    def table(rs, key=lambda r: r["label"]):
        t = collections.defaultdict(collections.Counter)
        for r in rs:
            t[key(r)][cat(r["origin"])] += 1
        return {k: dict(v) for k, v in sorted(t.items())}

    train = splits["train"]
    syn_share = sum(1 for r in train if cat(r["origin"]) == "synthetic") / max(1, len(train))
    summary = {
        "built_with_synthetic_v3": not args.no_synthetic_v3, "out": args.out,
        "raw_rows_new_sources": dict(per_source_raw), "filter_stats": dict(stats), "group_overlap_between_splits": leaks,
        "splits": {n: {"total": len(rs), "by_origin": dict(collections.Counter(r["origin"] for r in rs)),
                       "by_class_category": table(rs), "by_lang": dict(collections.Counter(r["lang"] for r in rs)),
                       "groups": len({r["source"] for r in rs})} for n, rs in splits.items()},
        "train_real_rows_per_class": {c: sum(1 for r in train if r["label"] == c and cat(r["origin"]) == "real") for c in CLASSES},
        "train_synthetic_share": round(syn_share, 4),
        "source_weights": weights,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps({k: summary[k] for k in ("filter_stats", "train_real_rows_per_class", "train_synthetic_share", "group_overlap_between_splits")}, indent=1))
    for n in names:
        print(n, summary["splits"][n]["total"], summary["splits"][n]["by_origin"])


if __name__ == "__main__":
    main()
