"""Turn cloned evaluation apps + labels.json into function-level evaluation rows.

Sets:
* ``heldout`` (data/heldout/: NodeGoat, DVNA, vulpy, PyGoat): since v2 this is the **development set**.
  Thresholds, ensemble weights and the secrets rules may be tuned on it.
* ``fresh`` (data/fresh/: django.nV, dvws-node, vulnerable-node): the v2 **fresh held-out set**. Labelled
  and frozen before any v2 modelling and scored exactly once (scripts/eval_fresh_final.py).

Each label points at a source line by an exact code substring (``match``). The unit (function or
``<module>``) containing that line gets the label. ``exclude`` marks real issues outside the 8 target
classes (or ambiguous cases): those units are left out of the metrics instead of being counted as safe.
Every other unit in the included paths is labelled ``safe``. Neither set is ever used for training.

Usage: python scripts/build_heldout.py [--set heldout|fresh] [--freeze]
  --freeze (fresh only) writes data/fresh/FREEZE.json; later builds verify against it.
"""
import argparse
import collections
import hashlib
import json
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=SyntaxWarning)
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sastml.extract import extract, language_of  # noqa: E402

SETS = {"heldout": ROOT / "data/heldout", "fresh": ROOT / "data/fresh"}
SKIP_DIRS = {"node_modules", ".git", "static", "migrations", "test", "tests", "vendor", "assets", "public", "__pycache__"}


def unit_lines(u):
    return set(u.meta["lines"]) if "lines" in u.meta else set(range(u.start_line, u.end_line + 1))


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode("utf-8")).hexdigest()


def build(name):
    base_dir = SETS[name]
    spec = json.loads((base_dir / "labels.json").read_text())
    rows, problems, file_digests = [], [], {}
    by_file = collections.defaultdict(list)
    for lab in spec["labels"]:
        by_file[(lab["app"], lab["file"])].append(lab)
    for app, info in spec["apps"].items():
        base = base_dir / app
        files = []
        for inc in info["include"]:
            p = base / inc
            cands = [p] if p.is_file() else sorted(p.rglob("*"))
            files += [f for f in cands if f.is_file() and language_of(str(f)) and not (SKIP_DIRS & set(f.relative_to(base).parts[:-1]))]
        for f in files:
            rel = str(f.relative_to(base))
            raw = f.read_bytes()
            file_digests[f"{app}/{rel}"] = sha(raw)
            text = raw.decode("utf-8", "ignore")
            units = extract(rel, text)
            labs = by_file.pop((app, rel), [])
            tags = collections.defaultdict(lambda: {"cwes": set(), "exclude": set(), "template_sink": False, "refs": []})
            for lab in labs:
                idx = text.find(lab["match"])
                if idx < 0:
                    problems.append(f"match not found: {app}/{rel}: {lab['match'][:60]}")
                    continue
                line = text.count("\n", 0, idx) + 1
                owners = [i for i, u in enumerate(units) if line in unit_lines(u)]
                if not owners:
                    problems.append(f"no unit covers {app}/{rel}:{line}")
                    continue
                t = tags[owners[-1]]
                t["cwes"].update(lab.get("cwes") or ([lab["cwe"]] if "cwe" in lab else []))
                if "exclude" in lab:
                    t["exclude"].add(lab["exclude"])
                t["template_sink"] |= bool(lab.get("template_sink"))
                t["refs"].append(lab["ref"])
            for i, u in enumerate(units):
                t = tags.get(i)
                cwes = sorted(t["cwes"]) if t else []
                excluded = bool(t and t["exclude"] and not cwes)
                rows.append({"app": app, "file": rel, "function": u.name, "start_line": u.start_line, "lang": u.lang,
                             "code": u.code, "label": cwes[0] if cwes else "safe", "labels": cwes or ["safe"],
                             "excluded": excluded, "exclude_reason": sorted(t["exclude"]) if t else [],
                             "template_sink": bool(t and t["template_sink"]), "refs": t["refs"] if t else [],
                             "origin": name, "source": f"app:{app}"})
    problems += [f"file not found: {a}/{f}" for (a, f) in by_file]
    return spec, rows, problems, file_digests


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", choices=list(SETS), default="heldout")
    ap.add_argument("--freeze", action="store_true")
    args = ap.parse_args()
    spec, rows, problems, file_digests = build(args.set)
    body = "".join(json.dumps(r) + "\n" for r in rows)
    freeze = {"labels_sha256": sha((SETS[args.set] / "labels.json").read_bytes()), "rows_sha256": sha(body),
              "sources_sha256": sha(json.dumps(file_digests, sort_keys=True)), "n_files": len(file_digests),
              "commits": {a: i["commit"] for a, i in spec["apps"].items()}}
    fpath = SETS[args.set] / "FREEZE.json"
    if args.set == "fresh":
        if args.freeze:
            fpath.write_text(json.dumps({**freeze, "policy": "Labelled and frozen before any v2 modelling. Score exactly once with scripts/eval_fresh_final.py."}, indent=2) + "\n")
        elif fpath.exists():
            frozen = json.loads(fpath.read_text())
            changed = [k for k in ("labels_sha256", "rows_sha256", "sources_sha256") if frozen.get(k) != freeze[k]]
            if changed:
                problems.append(f"fresh set differs from FREEZE.json: {changed}")
    out = ROOT / f"data/processed/{args.set}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body)
    summary = {}
    for r in rows:
        summary.setdefault(r["app"], collections.Counter())["excluded" if r["excluded"] else r["label"]] += 1
    print(json.dumps({a: dict(c) for a, c in summary.items()}))
    mpath = ROOT / "data/manifest.json"
    manifest = json.loads(mpath.read_text()) if mpath.exists() else {}
    manifest[args.set] = {
        "role": "development set (tuning allowed since v2)" if args.set == "heldout" else "fresh held-out set, scored exactly once",
        "apps": {a: {"repo": i["repo"], "commit": i["commit"], "lang": i["lang"], "include": i["include"],
                     "units": dict(summary.get(a, {}))} for a, i in spec["apps"].items()},
        "template_sink_units": sum(1 for r in rows if r["template_sink"]),
        "total_units": len(rows), "excluded_units": sum(1 for r in rows if r["excluded"]), "freeze": freeze,
    }
    mpath.write_text(json.dumps(manifest, indent=2) + "\n")
    for p in problems:
        print("PROBLEM:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
