"""Build the ml-sast training data: CrossVul real fixes + synthetic pairs -> train/val/test + manifest.

Real data (CrossVul, Zenodo 4734050): for each fix commit whose CWE maps to a target class, the Python/JS
file before (bad_*) and after (good_*) the fix is split into units; units present in both versions whose
normalized code changed give (before -> CWE class) and (after -> safe). Unchanged units are not used
(their label is unknown).

Splits are by group, never by function: real data by repository, synthetic data by template family.
A function whose normalized code appears with conflicting labels is dropped everywhere.

Usage: python scripts/build_dataset.py [--per-family 40]
"""
import argparse
import collections
import hashlib
import json
import random
import re
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=SyntaxWarning)  # old CrossVul Python files

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sastml import CLASSES  # noqa: E402
from sastml.extract import extract, js_parses  # noqa: E402
from sastml.synthetic import generate  # noqa: E402

CROSSVUL = ROOT / "data/raw/crossvul/extracted/dataset_final_sorted"
OUT = ROOT / "data/processed"
CWE_MAP = {
    "CWE-89": "CWE-89", "CWE-564": "CWE-89",
    "CWE-79": "CWE-79", "CWE-80": "CWE-79", "CWE-83": "CWE-79", "CWE-87": "CWE-79",
    "CWE-78": "CWE-78", "CWE-77": "CWE-78", "CWE-88": "CWE-78",
    "CWE-22": "CWE-22", "CWE-23": "CWE-22", "CWE-35": "CWE-22", "CWE-36": "CWE-22", "CWE-73": "CWE-22",
    "CWE-798": "CWE-798", "CWE-259": "CWE-798", "CWE-321": "CWE-798",
    "CWE-502": "CWE-502",
    "CWE-327": "CWE-327", "CWE-328": "CWE-327", "CWE-326": "CWE-327", "CWE-916": "CWE-327", "CWE-759": "CWE-327", "CWE-760": "CWE-327",
}
EXT_DIR = {".py": "py", ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js"}
TEST_NAME = re.compile(r"(^test_|_test\.py$|\.test\.js$|\.spec\.js$|^tests?\.py$)")
MAX_UNIT_LINES = 400


def norm(code):
    code = re.sub(r"(?m)#.*$|//.*$", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return re.sub(r"\s+", " ", code).strip()


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def keyed(units):
    seen = collections.Counter()
    out = {}
    for u in units:
        k = (u.name, seen[u.name])
        seen[u.name] += 1
        out[k] = u
    return out


def real_rows():
    meta = json.loads((CROSSVUL / "metadata.json").read_text())
    rows, stats = [], collections.Counter()
    for commit_idx, c in enumerate(meta):
        target = CWE_MAP.get(c.get("cwe"))
        if not target:
            continue
        m = re.match(r"https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]+)", c.get("url", ""))
        repo = m.group(1).lower() if m else c.get("url", "unknown")
        files = {f["database_name"]: f["original_name"] for f in c["files"]}
        for bad, name in files.items():
            if not bad.startswith("bad_"):
                continue
            ext = Path(name).suffix.lower()
            if ext not in EXT_DIR or TEST_NAME.search(Path(name).name):
                continue
            good = "good_" + bad[4:]
            pb, pg = CROSSVUL / c["cwe"] / EXT_DIR[ext] / bad, CROSSVUL / c["cwe"] / EXT_DIR[ext] / good
            if not (pb.exists() and pg.exists()):
                stats["missing_file"] += 1
                continue
            before = keyed(extract(name, pb.read_text("utf-8", "ignore")))
            after = keyed(extract(name, pg.read_text("utf-8", "ignore")))
            stats["file_pairs"] += 1
            for k, ub in before.items():
                ua = after.get(k)
                if ua is None or norm(ub.code) == norm(ua.code) or k[0] == "<module>" and target != "CWE-798":
                    continue
                if ub.end_line - ub.start_line > MAX_UNIT_LINES:
                    stats["too_long"] += 1
                    continue
                pair = f"crossvul:{commit_idx}:{bad}:{k[0]}:{k[1]}"
                base = {"lang": ub.lang, "source": f"repo:{repo}", "pair_id": pair, "origin": "crossvul",
                        "cve": c.get("cve"), "cwe_raw": c.get("cwe"), "file": name, "function": k[0]}
                rows.append({**base, "code": ub.code, "label": target})
                rows.append({**base, "code": ua.code, "label": "safe"})
                stats["changed_pairs"] += 1
    return rows, stats


def group_split(rows, fracs=(0.7, 0.15, 0.15), seed=7, fixed=None):
    """Greedy group assignment that keeps per-label proportions close to fracs.
    ``fixed`` (group -> split index) is honoured first; only the remaining groups are assigned."""
    groups = collections.defaultdict(collections.Counter)
    for r in rows:
        groups[r["source"]][r["label"]] += 1
    total = collections.Counter(r["label"] for r in rows)
    have = [collections.Counter() for _ in fracs]
    assign = {}
    for g, i in (fixed or {}).items():
        if g in groups:
            assign[g] = i
            have[i].update(groups[g])
    order = sorted((g for g in groups if g not in assign), key=lambda g: (-sum(groups[g].values()), g))
    random.Random(seed).shuffle(order[len(order) // 4:])  # keep the big groups first, randomize the tail
    for g in order:
        best, score = 0, None
        for i, f in enumerate(fracs):
            s = sum(max(0.0, f * total[lbl] - have[i][lbl]) * n for lbl, n in groups[g].items()) / (sum(groups[g].values()) or 1)
            if score is None or s > score:
                best, score = i, s
        assign[g] = best
        have[best].update(groups[g])
    return assign


def synthetic_split(rows, seed=11):
    """Per (class, language): hold one family out for test and one for val when there are >= 3."""
    fams = collections.defaultdict(set)
    for r in rows:
        cwe = r["source"].split(":")[1]
        fams[(cwe, r["lang"])].add(r["source"])
    rnd = random.Random(seed)
    assign = {}
    for key, fs in sorted(fams.items()):
        fs = sorted(fs)
        rnd.shuffle(fs)
        for i, f in enumerate(fs):
            assign[f] = 2 if i == 0 and len(fs) >= 2 else 1 if i == 1 and len(fs) >= 3 else 0
    return assign


def drop_conflicts(rows):
    labels = collections.defaultdict(set)
    for r in rows:
        labels[(r["lang"], norm(r["code"]))].add(r["label"])
    seen, out, dropped = set(), [], collections.Counter()
    for r in rows:
        k = (r["lang"], norm(r["code"]))
        if len(labels[k]) > 1:
            dropped["conflicting_label"] += 1
            continue
        if k in seen:
            dropped["duplicate"] += 1
            continue
        seen.add(k)
        out.append(r)
    return out, dropped


def shingles(code, k=5):
    toks = re.findall(r"[A-Za-z_$][\w$]*|\d+|\S", norm(code))
    return {" ".join(toks[i:i + k]) for i in range(max(1, len(toks) - k + 1))}


def drop_near_duplicates_of_eval(rows, threshold=0.8):
    """Leakage guard: drop training rows whose code is a near-duplicate (5-token shingle Jaccard >=
    threshold) of any development-set or fresh-set unit."""
    eval_sets = []
    for name in ("heldout", "fresh"):
        p = OUT / f"{name}.jsonl"
        if p.exists():
            eval_sets += [shingles(json.loads(line)["code"]) for line in p.open()]
    index = collections.defaultdict(set)
    for i, s in enumerate(eval_sets):
        for sh in s:
            index[sh].add(i)
    keep, dropped = [], 0
    for r in rows:
        s = shingles(r["code"])
        overlap = collections.Counter(j for sh in s for j in index.get(sh, ()))
        if any(n / len(s | eval_sets[j]) >= threshold for j, n in overlap.items()):
            dropped += 1
            continue
        keep.append(r)
    return keep, dropped


def osv_rows():
    p = ROOT / "data/raw/osv/rows.jsonl"
    if not p.exists():
        return []
    rows = []
    for line in p.open():
        r = json.loads(line)
        for k in ("removed_lines", "added_lines"):
            r.pop(k, None)
        rows.append(r)
    return rows


def fixed_assignment():
    """v1 repository -> split, so existing CrossVul groups keep their split when new data is added."""
    path = OUT / "v1_group_assignment.json"
    if path.exists():
        return json.loads(path.read_text())
    assign = {}
    for i, n in enumerate(("train", "val", "test")):
        p = OUT / f"{n}.jsonl"
        if p.exists():
            for line in p.open():
                r = json.loads(line)
                if r["origin"] == "crossvul":
                    assign[r["source"]] = i
    if assign:
        path.write_text(json.dumps(assign, indent=0, sort_keys=True))
    return assign


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-family", type=int, default=40)
    ap.add_argument("--with-osv", action="store_true", help="add data/raw/osv/rows.jsonl (v2)")
    args = ap.parse_args()
    fixed = fixed_assignment()
    real, real_stats = real_rows()
    osv = osv_rows() if args.with_osv else []
    synth = generate(per_family=args.per_family, js_validator=js_parses)
    real, real_drop = drop_conflicts(real + osv)
    synth, synth_drop = drop_conflicts(synth)
    real, near_dup = drop_near_duplicates_of_eval(real)
    real_drop["near_duplicate_of_eval_unit"] = near_dup
    # a function cannot be in two splits through real/synthetic overlap either
    rassign, sassign = group_split(real, fixed=fixed), synthetic_split(synth)
    names = ["train", "val", "test"]
    OUT.mkdir(parents=True, exist_ok=True)
    splits = {n: [] for n in names}
    for r in real:
        splits[names[rassign[r["source"]]]].append(r)
    for r in synth:
        splits[names[sassign[r["source"]]]].append(r)
    for n, rs in splits.items():
        for r in rs:
            r["split"] = n
            r["id"] = digest(r["lang"] + "\0" + r["code"])[:16]
        with open(OUT / f"{n}.jsonl", "w") as fh:
            for r in rs:
                fh.write(json.dumps(r) + "\n")

    def table(rs):
        t = {}
        for r in rs:
            t.setdefault(r["label"], collections.Counter())[r["lang"]] += 1
        return {c: dict(t.get(c, {})) for c in CLASSES}

    groups = {n: {r["source"] for r in splits[n]} for n in names}
    leaks = sorted((groups["train"] & groups["val"]) | (groups["train"] & groups["test"]) | (groups["val"] & groups["test"]))
    mpath = ROOT / "data/manifest.json"
    previous = json.loads(mpath.read_text()) if mpath.exists() else {}
    manifest = {
        "classes": CLASSES,
        "sources": {
            "crossvul": {"zenodo_record": 4734050, "file": "dataset.zip", "sha256": "fc4ede963de65239b07b64fe0b8fe559d283c6fc742120642022b8eaa30a1bef",
                          "cwe_map": CWE_MAP, "stats": dict(real_stats)},
            "real_dropped": dict(real_drop),
            "synthetic": {"generator": "sastml/synthetic.py", "per_family": args.per_family, "families": len({r["source"] for r in synth}), "dropped": dict(synth_drop)},
        },
        "split_policy": "real: by repository (greedy, per-label 70/15/15; v1 CrossVul groups keep their v1 split); synthetic: by template family "
                        "(one held out for test and one for val per class/language); real rows that near-duplicate a development/fresh unit are dropped",
        "group_overlap_between_splits": leaks,
        "splits": {n: {"total": len(rs), "by_origin": dict(collections.Counter(r["origin"] for r in rs)),
                       "groups": len({r["source"] for r in rs}), "by_class_lang": table(rs),
                       "by_class_lang_real": table([r for r in rs if r["origin"] in ("crossvul", "osv")]),
                       "by_class_lang_osv": table([r for r in rs if r["origin"] == "osv"])} for n, rs in splits.items()},
    }
    if args.with_osv:
        manifest["sources"]["osv"] = {"dumps": ["https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip", "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip"],
                                      "collector": "scripts/collect_osv.py", "rows_kept": sum(1 for r in real if r["origin"] == "osv")}
        quality = previous.get("sources", {}).get("osv", {}).get("quality")
        if quality:
            manifest["sources"]["osv"]["quality"] = quality
    for k in ("heldout", "fresh"):
        if k in previous:
            manifest[k] = previous[k]
    mpath.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({n: manifest["splits"][n]["total"] for n in names}), "group overlap:", len(leaks), "dropped:", dict(real_drop))


if __name__ == "__main__":
    main()
