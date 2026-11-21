"""ml-sast v3 held-out sets from the RealVuln benchmark (community, human-authored apps never used here).

Same unit method as v2's fresh set (scripts/build_heldout.py): every function or <module> unit of the app's
source files (tests, static, migrations, vendored code and node_modules excluded) is a unit.
* a unit overlapping a RealVuln finding (is_vulnerable true) whose primary CWE maps to a target class gets
  that class (several -> multi-label, any listed class counts as correct, as in v2);
* a unit overlapping only vulnerable findings outside the target classes, findings whose target CWE is only
  an "acceptable" alternative, or non-scoring entries is EXCLUDED (v2 'exclude');
* every other unit (false-positive traps included) is safe.
Findings that fall outside every unit (templates, config files, skipped directories) are counted, not used.

Sets: python (20 apps), node (4 apps). Apps live on D: (/mnt/d/cs-data/sast-v3/heldout/apps, untrusted, never
executed). Rows go to data/heldout_v3/<set>.jsonl (gitignored); data/heldout_v3/FREEZE.json is committed.
Usage: python -I scripts/v3/build_heldout_v3.py [--freeze]   (without --freeze: verify against FREEZE.json)
"""
import argparse
import collections
import hashlib
import json
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=SyntaxWarning)
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from sastml.extract import extract, language_of  # noqa: E402

BASE = Path("/mnt/d/cs-data/sast-v3/heldout")
GT = BASE / "realvuln/ground-truth"
OUT = ROOT / "data/heldout_v3"
SETS = {
    "python": ["damn-vulnerable-flask-application", "damn-vulnerable-graphql-application", "djangoat", "dvblab", "extremely-vulnerable-flask-app",
               "flask-xss", "insecure-web", "intentionally-vulnerable-python-application", "lets-be-bad-guys", "owasp-web-playground", "python-app",
               "python-insecure-app", "pythonssti", "threatbyte", "vfapi", "vulnerable-api", "vulnerable-flask-app", "vulnerable-python-apps",
               "vulnerable-tornado-app", "vulnpy"],
    "node": ["ninjasworkout", "vuln-node-express", "vulnerable-nodejs", "vulnnodeapp"],
}
TARGET = {"CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-798", "CWE-502", "CWE-327"}
# the v2 CWE map (scripts/build_dataset.py): narrower CWEs fold into the target classes
CWE_MAP = {"CWE-564": "CWE-89", "CWE-80": "CWE-79", "CWE-83": "CWE-79", "CWE-87": "CWE-79", "CWE-77": "CWE-78", "CWE-88": "CWE-78",
           "CWE-23": "CWE-22", "CWE-35": "CWE-22", "CWE-36": "CWE-22", "CWE-73": "CWE-22", "CWE-259": "CWE-798", "CWE-321": "CWE-798",
           "CWE-328": "CWE-327", "CWE-326": "CWE-327", "CWE-916": "CWE-327", "CWE-759": "CWE-327", "CWE-760": "CWE-327"}
SKIP_DIRS = {"node_modules", ".git", "static", "migrations", "test", "tests", "vendor", "assets", "public", "__pycache__", "dist", "build",
             "bower_components", "site-packages", "venv", ".venv", "env"}
LANGS = {"python": {"python"}, "node": {"javascript"}}


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode("utf-8")).hexdigest()


def target_of(cwe):
    c = CWE_MAP.get(cwe, cwe)
    return c if c in TARGET else None


def unit_lines(u):
    return set(u.meta["lines"]) if "lines" in u.meta else set(range(u.start_line, u.end_line + 1))


def build(name):
    rows, digests, stats, commits = [], {}, collections.Counter(), {}
    for app in SETS[name]:
        g = json.loads((GT / f"realvuln-{app}/ground-truth.json").read_text())
        commits[app] = g["commit_sha"]
        base = BASE / "apps" / app
        by_file = collections.defaultdict(list)
        for f in g["findings"]:
            by_file[f["file"].lstrip("./")].append(f)
            stats[f"findings_{'vulnerable' if f.get('is_vulnerable') else 'fp_trap' if f.get('is_vulnerable') is False else 'non_scoring'}"] += 1
        used = set()
        files = [p for p in sorted(base.rglob("*")) if p.is_file() and language_of(str(p)) in LANGS[name]
                 and not (SKIP_DIRS & {x.lower() for x in p.relative_to(base).parts[:-1]})]
        for p in files:
            rel = str(p.relative_to(base))
            raw = p.read_bytes()
            digests[f"{app}/{rel}"] = sha(raw)
            units = extract(rel, raw.decode("utf-8", "ignore"))
            finds = by_file.get(rel, [])
            for u in units:
                lines = unit_lines(u)
                cwes, excl, ids = set(), set(), []
                for f in finds:
                    loc = f.get("location") or {}
                    s, e = loc.get("start_line"), loc.get("end_line") or loc.get("start_line")
                    if s is None or not lines & set(range(s, e + 1)):
                        continue
                    used.add(f["id"])
                    ids.append(f["id"])
                    if f.get("is_vulnerable") is True:
                        t = target_of(f.get("primary_cwe"))
                        if t:
                            cwes.add(t)
                        elif any(target_of(c) for c in f.get("acceptable_cwes", [])):
                            excl.add("target CWE only as an acceptable alternative")
                        else:
                            excl.add(f"out of class ({f.get('primary_cwe')})")
                    elif f.get("is_vulnerable") is None:
                        excl.add("non-scoring entry")
                cw = sorted(cwes)
                rows.append({"set": name, "app": app, "file": rel, "function": u.name, "start_line": u.start_line, "end_line": u.end_line,
                             "lang": u.lang, "code": u.code, "label": cw[0] if cw else "safe", "labels": cw or ["safe"],
                             "excluded": bool(excl and not cw), "exclude_reason": sorted(excl), "finding_ids": ids,
                             "origin": f"realvuln_{name}", "source": f"app:{app}"})
        for f in g["findings"]:
            if f["id"] not in used:
                key = "unmapped_vulnerable_target" if f.get("is_vulnerable") and target_of(f.get("primary_cwe")) else "unmapped_other"
                stats[key] += 1
    return rows, digests, stats, commits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--freeze", action="store_true")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    fpath = OUT / "FREEZE.json"
    frozen = json.loads(fpath.read_text()) if fpath.exists() else None
    if args.freeze and frozen:
        sys.exit("FREEZE.json exists; a freeze is never rewritten")
    freeze, problems, summary = {"policy": "Labelled from RealVuln ground truth and frozen BEFORE any v3 training. Scored exactly once (scripts/v3/eval_heldout_v3.py).",
                                 "realvuln_commit": "015244597a86d107f86f9574f9eda6d20928f156", "ground_truth_version": "3.0.0", "sets": {}}, [], {}
    for name in SETS:
        rows, digests, stats, commits = build(name)
        body = "".join(json.dumps(r) + "\n" for r in rows)
        gt_digest = sha(json.dumps({a: json.loads((GT / f"realvuln-{a}/ground-truth.json").read_text()) for a in SETS[name]}, sort_keys=True))
        scored = [r for r in rows if not r["excluded"]]
        cls = collections.Counter(l for r in scored for l in r["labels"])
        freeze["sets"][name] = {"apps": commits, "n_files": len(digests), "units": len(rows), "scored_units": len(scored),
                                "excluded_units": len(rows) - len(scored), "vulnerable_units": sum(1 for r in scored if r["label"] != "safe"),
                                "by_class": dict(sorted(cls.items())), "finding_stats": dict(stats),
                                "rows_sha256": sha(body), "sources_sha256": sha(json.dumps(digests, sort_keys=True)), "ground_truth_sha256": gt_digest}
        if frozen and not args.freeze:
            old = frozen["sets"][name]
            changed = [k for k in ("rows_sha256", "sources_sha256", "ground_truth_sha256") if old.get(k) != freeze["sets"][name][k]]
            if changed:
                problems.append(f"{name} differs from FREEZE.json: {changed}")
        (OUT / f"{name}.jsonl").write_text(body)
        summary[name] = {k: v for k, v in freeze["sets"][name].items() if k not in ("apps",)}
    print(json.dumps(summary, indent=1))
    if args.freeze:
        fpath.write_text(json.dumps(freeze, indent=1) + "\n")
        print("frozen:", fpath)
    for p in problems:
        print("PROBLEM:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
