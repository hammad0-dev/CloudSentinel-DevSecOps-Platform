"""Turn the cloned held-out apps + data/heldout/labels.json into function-level evaluation rows.

Each label points at a source line by an exact code substring (``match``). The unit (function or
``<module>``) containing that line gets the label. ``exclude`` marks real issues outside the 8 target
classes (or ambiguous cases): those units are left out of the metrics instead of being counted as safe.
Every other unit in the included paths is labelled ``safe``. Held-out rows are NEVER used for training.
"""
import collections
import json
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=SyntaxWarning)
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sastml.extract import extract, language_of  # noqa: E402

HELD = ROOT / "data/heldout"
SKIP_DIRS = {"node_modules", ".git", "static", "migrations", "test", "tests", "vendor", "assets", "public", "__pycache__"}


def unit_lines(u):
    return set(u.meta["lines"]) if "lines" in u.meta else set(range(u.start_line, u.end_line + 1))


def main():
    spec = json.loads((HELD / "labels.json").read_text())
    rows, problems = [], []
    by_file = collections.defaultdict(list)
    for lab in spec["labels"]:
        by_file[(lab["app"], lab["file"])].append(lab)
    for app, info in spec["apps"].items():
        base = HELD / app
        files = []
        for inc in info["include"]:
            p = base / inc
            cands = [p] if p.is_file() else sorted(p.rglob("*"))
            files += [f for f in cands if f.is_file() and language_of(str(f)) and not (SKIP_DIRS & set(f.relative_to(base).parts[:-1]))]
        for f in files:
            rel = str(f.relative_to(base))
            text = f.read_text("utf-8", "ignore")
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
                             "origin": "heldout", "source": f"app:{app}"})
    problems += [f"file not found: {a}/{f}" for (a, f) in by_file]
    out = ROOT / "data/processed/heldout.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    summary = {}
    for r in rows:
        if r["excluded"]:
            key = "excluded"
        else:
            key = r["label"]
        summary.setdefault(r["app"], collections.Counter())[key] += 1
    print(json.dumps({a: dict(c) for a, c in summary.items()}, indent=1))
    mpath = ROOT / "data/manifest.json"
    manifest = json.loads(mpath.read_text()) if mpath.exists() else {}
    manifest["heldout"] = {
        "policy": "never used for training or tuning; labels by sink line in data/heldout/labels.json (see LABELS.md)",
        "apps": {a: {"repo": i["repo"], "commit": i["commit"], "lang": i["lang"], "include": i["include"],
                     "units": dict(summary.get(a, {}))} for a, i in spec["apps"].items()},
        "template_sink_units": sum(1 for r in rows if r["template_sink"]),
        "total_units": len(rows), "excluded_units": sum(1 for r in rows if r["excluded"]),
    }
    mpath.write_text(json.dumps(manifest, indent=2) + "\n")
    for p in problems:
        print("PROBLEM:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
