"""Evaluate every rule-based (NOT ML) check on the stored v3 records; no traffic is sent.

* CWE-78 / CWE-22 / CWE-601 and the passive checks: exactly as scripts/eval_rules.py, on v3 data.
* Stored XSS: one unit per labelled write field ("stored" in ground_truth_v3.json). Known instances
  inside the rule's scope (POST/PUT form or JSON field, reachable by the unauthenticated or lab-login
  crawl) count as found/missed; instances outside it (GET writes, behind a login the lab cannot do,
  markdown-only bypasses) are listed separately; safe fields count false alarms. A finding on an
  unlabelled field is listed for a source check and never counted silently.
* CSRF heuristic: one unit per labelled form ("csrf" in ground_truth_v3.json); apps whose session
  cookie is not evaluable in the lab are skipped.
Reported as "found N of N known instances, K false alarms on M safe units", never as P/R/F1.

Usage: python scripts/eval_rules_v3.py [--apps a,b] [--suffix _v3]
"""
import argparse
import gzip
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import eval_rules  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402
from dastml.paths import paths  # noqa: E402
from dastml.probe import load_payloads  # noqa: E402
from dastml.rules import csrf_findings, stored_xss_findings  # noqa: E402

P = paths("v3")
eval_rules.P = P  # same evaluation code, v3 records


def _rx(template):
    return re.compile("^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(template)) + "$")


def evaluate_stored(apps, gtj):
    out = {"known": [], "found": [], "missed": [], "outside_rule": [], "false_alarms": [], "safe_units": 0, "unlabelled_findings": []}
    for app in apps:
        f = P["raw"] / f"{app}.stored.json"
        entries = [s for s in gtj.get("stored", []) if s["app"] == app]
        for s in entries:
            if s["vuln"] and s.get("covered_by_rule") is False:
                out["outside_rule"].append(f"{app}|{s['write']['method']} {s['write']['path']} [{s['write']['param']}]: {s['note'][:120]}")
        if not f.exists():
            continue
        records = json.loads(f.read_text())["records"]
        seen, units = set(), {}  # one unit per labelled field, however many concrete paths wrote to it
        for rec in records:
            pt = rec["point"]
            fired = bool(stored_xss_findings([rec], "http://lab/"))
            match = next((s for s in entries if s.get("covered_by_rule") is not False and s["write"]["method"] == pt["method"]
                          and s["write"]["param"] == pt["param"] and _rx(s["write"]["path"]).match(pt["path"])), None)
            unit = f"{app}|{pt['method']} {match['write']['path'] if match else pt['path']} [{pt['param']}]"
            if match is None:
                if fired and unit not in out["unlabelled_findings"]:
                    out["unlabelled_findings"].append(unit)
                continue
            seen.add(id(match))
            units[unit] = (match, units.get(unit, (match, False))[1] or fired)
        for unit, (match, fired) in units.items():
            if match["vuln"]:
                out["known"].append(unit)
                (out["found"] if fired else out["missed"]).append(unit)
            else:
                out["safe_units"] += 1
                if fired:
                    out["false_alarms"].append(unit)
        for s in entries:  # labelled in-scope fields the collection never reached
            if id(s) not in seen and s.get("covered_by_rule") is not False and s["vuln"]:
                unit = f"{app}|{s['write']['method']} {s['write']['path']} [{s['write']['param']}]"
                out["known"].append(unit)
                out["missed"].append(unit + " (not reached by the crawl)")
    return out


def evaluate_csrf(apps, gtj):
    out = {"known": [], "found": [], "missed": [], "false_alarms": [], "safe_units": 0, "unlabelled_findings": [], "not_evaluable": []}
    for app in apps:
        truth = gtj.get("csrf", {}).get(app)
        f = P["raw"] / f"{app}.forms.json"
        if truth is None or not f.exists():
            continue
        if truth.get("form_csrf") is None:
            out["not_evaluable"].append(f"{app}: {truth.get('cookie', '')}")
            continue
        forms = json.loads(f.read_text())
        snaps = json.loads((P["raw"] / f"{app}.passive.json").read_text()) if (P["raw"] / f"{app}.passive.json").exists() else []
        raw = P["raw"] / f"{app}.jsonl.gz"
        if raw.exists():
            snaps += [r for line in gzip.open(raw, "rt") for r in json.loads(line)["responses"] if r.get("headers") is not None]
        fired = {re.sub(r"^https?://[^/]+", "", x["endpoint"]) for x in csrf_findings(forms, snaps, "http://lab/")}
        fired = {x if x.startswith("/") else "/" + x for x in fired}
        labelled = truth.get("forms", [])
        for form in labelled:
            unit = f"{app}|POST {form['path']}"
            hit = any(_rx(form["path"]).match(x) for x in fired)
            if form["vuln"]:
                out["known"].append(unit)
                (out["found"] if hit else out["missed"]).append(unit + ("" if hit else f" ({form.get('note') or 'not reported'})"))
            else:
                out["safe_units"] += 1
                if hit:
                    out["false_alarms"].append(unit)
        if not labelled:  # an app with no vulnerable form: every reported form is a false alarm
            out["safe_units"] += len({x["action"] for x in forms if x["method"] == "POST"})
            out["false_alarms"] += [f"{app}|POST {x}" for x in sorted(fired)]
        else:
            out["unlabelled_findings"] += [f"{app}|POST {x}" for x in sorted(fired) if not any(_rx(fm["path"]).match(x) for fm in labelled)]
    return out


def counts(d, neg="safe_units"):
    return f"found {len(d['found'])} of {len(d['known'])} known instances, {len(d['false_alarms'])} false alarms on {d[neg]} safe units"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apps", default="")
    ap.add_argument("--suffix", default="_v3")
    a = ap.parse_args()
    gt = GroundTruth(P["ground_truth"])
    gtj = json.loads(P["ground_truth"].read_text())
    apps = a.apps.split(",") if a.apps else [x for x, m in gt.apps().items() if m["role"] == "train_loao"]
    payloads = load_payloads(("CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601"), P["payloads"])
    active, passive = eval_rules.evaluate(apps, gt, payloads)
    stored, csrf = evaluate_stored(apps, gtj), evaluate_csrf(apps, gtj)
    out = {"apps": apps, "engine": "rule (deterministic, not ML)", "active": active, "passive": passive, "stored_xss": stored, "csrf_heuristic": csrf}
    (ROOT / f"reports/rules{a.suffix}.json").write_text(json.dumps(out, indent=1) + "\n")
    L = [f"# ml-dast rule-based checks (deterministic, NOT machine learning) - {a.suffix.strip('_')}", "",
         f"Apps: {', '.join(apps)}. Counts, not rates: n is too small for precision/recall.", "",
         "| Check | Known instances | False alarms | Missed |", "|---|---|---|---|"]
    L += [eval_rules.line(c, d, "safe_units") for c, d in active.items()] + [eval_rules.line(c, d, "negatives") for c, d in passive.items()]
    L.append(eval_rules.line("stored XSS (CWE-79)", stored, "safe_units"))
    L.append(eval_rules.line("CSRF heuristic (CWE-352)", csrf, "safe_units"))
    L += ["", "Stored XSS instances outside the rule's scope (not counted above):"] + ([f"- {x}" for x in stored["outside_rule"]] or ["- none"])
    L += ["", "CSRF: apps not evaluable in the lab:"] + ([f"- {x}" for x in csrf["not_evaluable"]] or ["- none"])
    L += ["", "Findings on unlabelled units (checked against the source, see GROUND_TRUTH.md):"]
    L += [f"- {x}" for x in stored["unlabelled_findings"] + csrf["unlabelled_findings"]] or ["- none"]
    fa = [x for d in list(active.values()) + list(passive.values()) + [stored, csrf] for x in d["false_alarms"]]
    L += ["", "False alarms:"] + ([f"- {x}" for x in fa] or ["- none"])
    (ROOT / f"reports/rules{a.suffix}.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
