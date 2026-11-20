"""Evaluate the rule-based (NOT ML) checks on stored v2 probe records; no traffic is sent.

Active rules (CWE-78, CWE-22, CWE-601): every probed point that received that class's payloads is one
unit. A known instance is a point whose ground-truth entry lists the class; every other such point is
a safe endpoint for that class. Passive checks: one unit per (app, check), compared with the
ground truth read from each app's source ("passive" in ground_truth_v2.json).

Reported as "found N of N known instances, K false alarms on M safe endpoints", not precision/recall:
the counts are too small for rates. Writes reports/rules<suffix>.json and .md.

Usage: python scripts/eval_rules.py [--apps a,b] [--suffix _v2]
"""
import argparse
import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dastml.crawl import InjectionPoint  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402
from dastml.paths import paths  # noqa: E402
from dastml.probe import load_payloads  # noqa: E402
from dastml.rules import ACTIVE_RULES, PASSIVE, passive_checks  # noqa: E402

P = paths("v2")


def evaluate(apps, gt, payloads):
    active = {c: {"known": [], "found": [], "missed": [], "false_alarms": [], "safe_units": 0} for c in ACTIVE_RULES}
    passive = {c: {"known": [], "found": [], "missed": [], "false_alarms": [], "negatives": 0} for c in PASSIVE}
    for app in apps:
        raw = P["raw"] / f"{app}.jsonl.gz"
        if not raw.exists():
            continue
        records = [json.loads(line) for line in gzip.open(raw, "rt")]
        for rec in records:
            pt = rec["point"]
            point = InjectionPoint(pt["method"], pt["path"], pt["param"], pt["location"])
            entry = gt.entry(app, point)
            if entry is None:
                continue
            unit = f"{app}|{pt['method']}|{entry['path']}|{entry['params'][0] if pt['location'] == 'path' else pt['param']}"
            sent = {r.get("payload_id") for r in rec["responses"] if r["kind"] == "payload"}
            for cls, rule in ACTIVE_RULES.items():
                if not any(p["class"] == cls and p["id"] in sent for p in payloads) or cls in entry.get("unknown", []):
                    continue
                fired, evidence, _ = rule(rec, payloads)
                a = active[cls]
                if cls in entry["vuln"]:
                    a["known"].append(unit)
                    (a["found"] if fired else a["missed"]).append(unit if fired else unit)
                else:
                    a["safe_units"] += 1
                    if fired:
                        a["false_alarms"].append(f"{unit}: {evidence}")
        truth = gt.passive(app)
        pfile = P["raw"] / f"{app}.passive.json"
        if not truth or not pfile.exists():
            continue
        snaps = json.loads(pfile.read_text())
        snaps += [r for rec in records for r in rec["responses"] if r.get("headers") is not None]
        fired = passive_checks(snaps)
        for check, present in truth.items():
            q = passive[check]
            if present:
                q["known"].append(app)
                (q["found"] if check in fired else q["missed"]).append(app)
            else:
                q["negatives"] += 1
                if check in fired:
                    q["false_alarms"].append(f"{app}: {fired[check]}")
    return active, passive


def line(cls, d, neg_key):
    return (f"| {cls} | found {len(d['found'])} of {len(d['known'])} known instances | {len(d['false_alarms'])} false alarms on {d[neg_key]} "
            f"{'safe endpoints' if neg_key == 'safe_units' else 'apps without the issue'} | {', '.join(d['missed']) or '-'} |")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apps", default="")
    ap.add_argument("--suffix", default="_v2")
    a = ap.parse_args()
    gt = GroundTruth(P["ground_truth"])
    apps = a.apps.split(",") if a.apps else [x for x, m in gt.apps().items() if m["role"] == "train_loao"]
    payloads = load_payloads(("CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601"), P["payloads"])
    active, passive = evaluate(apps, gt, payloads)
    out = {"apps": apps, "engine": "rule (deterministic, not ML)", "active": active, "passive": passive}
    (ROOT / f"reports/rules{a.suffix}.json").write_text(json.dumps(out, indent=1) + "\n")
    L = [f"# ml-dast rule-based checks (deterministic, NOT machine learning){' - ' + a.suffix.strip('_') if a.suffix else ''}", "",
         f"Apps: {', '.join(apps)}. Counts, not rates: n is too small for precision/recall.", "",
         "| Check | Known instances | False alarms | Missed |", "|---|---|---|---|"]
    L += [line(c, d, "safe_units") for c, d in active.items()] + [line(c, d, "negatives") for c, d in passive.items()]
    fa = [x for d in list(active.values()) + list(passive.values()) for x in d["false_alarms"]]
    L += ["", "False alarms:"] + ([f"- {x}" for x in fa] or ["- none"])
    (ROOT / f"reports/rules{a.suffix}.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
