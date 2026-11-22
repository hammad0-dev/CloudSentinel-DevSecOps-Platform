"""ml-sast v3 OSV extension (the v2 collector, scripts/collect_osv.py, with two relaxed limits).

Relaxations (label quality unchanged: same advisories, same CWE mapping, same sink filter on the changed lines,
same test/vendor exclusions, single-parent commits only):
* per-repository cap 20 -> 50 pairs: only the repositories that hit the v2 cap are re-processed, and only
  pairs not already in v2's rows are kept;
* MAX_SOURCE_FILES 5 -> 8: the v2 commits rejected as "too_many_files" are re-processed and kept when they
  change at most 8 non-test source files.
Output (new files, v2 data untouched): /mnt/d/cs-data/sast-v3/work/osv_v3/rows.jsonl and done.jsonl;
counts in reports/v3/sources/osv_v3.json. Needs GH_TOKEN (never printed).
Usage: python -I scripts/v3/collect_osv_v3.py
"""
import collections
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import collect_osv as co  # noqa: E402

OUT = Path("/mnt/d/cs-data/sast-v3/work/osv_v3")
REPORT = ROOT / "reports/v3/sources/osv_v3.json"


def main():
    token = os.environ.get("GH_TOKEN")
    if not token:
        sys.exit("GH_TOKEN is not set")
    OUT.mkdir(parents=True, exist_ok=True)
    v2_rows = [json.loads(l) for l in (ROOT / "data/raw/osv/rows.jsonl").open()]
    v2_pairs = {r["pair_id"] for r in v2_rows}
    v2_per_repo = collections.Counter(r["source"][5:] for r in v2_rows if r["label"] != "safe")
    capped = {repo for repo, n in v2_per_repo.items() if n >= co.PER_REPO}
    done_v2 = {}
    for l in (ROOT / "data/raw/osv/commits_done.jsonl").open():
        d = json.loads(l)
        done_v2[d["key"]] = d["status"]
    commits = {f"{c['repo']}@{c['sha']}": c for c in co.advisories()}
    todo = [(k, c, "cap_20_to_50") for k, c in commits.items() if c["repo"] in capped and done_v2.get(k) == "ok"]
    todo += [(k, c, "files_5_to_8") for k, c in commits.items() if done_v2.get(k) == "too_many_files"]
    done_path, rows_path = OUT / "done.jsonl", OUT / "rows.jsonl"
    done = {json.loads(l)["key"] for l in done_path.open()} if done_path.exists() else set()
    co.PER_REPO, co.MAX_SOURCE_FILES = 50, 8
    per_repo = collections.Counter(v2_per_repo)  # the 50-pair cap counts the v2 pairs too
    if rows_path.exists():
        for l in rows_path.open():
            r = json.loads(l)
            if r["label"] != "safe":
                per_repo[r["source"][5:]] += 1
    stats, added = collections.Counter(), collections.Counter()
    print(f"capped repos {len(capped)}; to re-process {len(todo)} (resume: {len(done)} done)", flush=True)
    with done_path.open("a") as dfh, rows_path.open("a") as rfh:
        for k, c, why in todo:
            if k in done:
                continue
            if why == "cap_20_to_50":
                per_repo[c["repo"]] = min(per_repo[c["repo"]], 50)
            st, rows = co.process_commit(c, token, collections.Counter({c["repo"]: 0}) if why == "cap_20_to_50" else per_repo)
            new = [r for r in rows if r["pair_id"] not in v2_pairs]
            # keep the cap: never more than 50 pairs per repository in v2 + v3 together
            keep = []
            for i in range(0, len(new), 2):
                repo = new[i]["source"][5:]
                if per_repo[repo] >= 50:
                    break
                per_repo[repo] += 1
                keep += new[i:i + 2]
            for r in keep:
                r["origin"] = "osv_v3"
                r["v3_relaxation"] = why
                rfh.write(json.dumps(r) + "\n")
            stats[f"{why}:{st['status']}"] += 1
            added[why] += len(keep) // 2
            dfh.write(json.dumps({"key": k, "why": why, **st, "new_pairs": len(keep) // 2}) + "\n")
            dfh.flush()
            rfh.flush()
    rows = [json.loads(l) for l in rows_path.open()]
    by = collections.Counter((r["lang"], r["label"], r["v3_relaxation"]) for r in rows if r["label"] != "safe")
    out = {"source": "osv_v3", "relaxations": {"per_repo_cap": "20 -> 50", "max_source_files": "5 -> 8"},
           "capped_repos_in_v2": len(capped), "commits_reprocessed": len(todo), "status": dict(stats),
           "new_pairs_by_relaxation": dict(collections.Counter(r["v3_relaxation"] for r in rows if r["label"] != "safe")),
           "kept_pairs_by_lang_class_relaxation": {f"{a}|{b}|{c}": n for (a, b, c), n in sorted(by.items())},
           "kept_pairs": sum(by.values()), "kept_rows": len(rows), "licence": "as v2 (OSV CC BY 4.0 metadata; code under each repository's licence)"}
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
