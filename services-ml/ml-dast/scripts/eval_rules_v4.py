"""Rule-based (NOT ML) counts on the v4 records, real apps and BenchmarkPython reported separately.

Same evaluation as scripts/eval_rules_v3.py (active rules, passive, stored XSS, CSRF), on paths("v4").
Writes reports/rules_v4.json and .md (never overwrites them).
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import eval_rules  # noqa: E402
import eval_rules_v3  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402
from dastml.paths import paths  # noqa: E402
from dastml.probe import load_payloads  # noqa: E402

P = paths("v4")
eval_rules.P = eval_rules_v3.P = P


def evaluate_all(apps, gt, gtj, payloads):
    active, passive = eval_rules.evaluate(apps, gt, payloads)
    return {"apps": apps, "active": active, "passive": passive,
            "stored_xss": eval_rules_v3.evaluate_stored(apps, gtj), "csrf_heuristic": eval_rules_v3.evaluate_csrf(apps, gtj)}


def section(title, d):
    L = [f"## {title}", "", f"Apps: {', '.join(d['apps'])}.", "", "| Check | Known instances | False alarms | Missed |", "|---|---|---|---|"]
    L += [eval_rules.line(c, x, "safe_units") for c, x in d["active"].items()]
    L += [eval_rules.line(c, x, "negatives") for c, x in d["passive"].items() if x["known"] or x["negatives"]]
    L.append(eval_rules.line("stored XSS (CWE-79)", d["stored_xss"], "safe_units"))
    L.append(eval_rules.line("CSRF heuristic (CWE-352)", d["csrf_heuristic"], "safe_units"))
    fa = [x for v in list(d["active"].values()) + list(d["passive"].values()) + [d["stored_xss"], d["csrf_heuristic"]] for x in v["false_alarms"]]
    unl = d["stored_xss"]["unlabelled_findings"] + d["csrf_heuristic"]["unlabelled_findings"]
    return L + ["", "False alarms:"] + ([f"- {x}" for x in fa] or ["- none"]) + ["", "Findings on unlabelled units:"] + ([f"- {x}" for x in unl] or ["- none"]) + [""]


def main():
    out_json, out_md = ROOT / "reports/rules_v4.json", ROOT / "reports/rules_v4.md"
    if out_json.exists():
        sys.exit("reports/rules_v4.json exists; reports are never overwritten")
    gt, gtj = GroundTruth(P["ground_truth"]), json.loads(P["ground_truth"].read_text())
    payloads = load_payloads(("CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601"), P["payloads"])
    train = [a for a, m in gt.apps().items() if m["role"] == "train_loao"]
    real = evaluate_all([a for a in train if gt.apps()[a]["origin"] != "benchmark"], gt, gtj, payloads)
    bench = evaluate_all([a for a in train if gt.apps()[a]["origin"] == "benchmark"], gt, gtj, payloads)
    out_json.write_text(json.dumps({"engine": "rule (deterministic, not ML)", "real": real, "benchmark": bench}, indent=1) + "\n")
    L = ["# ml-dast rule-based checks (deterministic, NOT machine learning) - v4", "",
         "Counts, not rates: n is too small for precision/recall. BenchmarkPython is reported separately (synthetic, in-benchmark).", ""]
    out_md.write_text("\n".join(L + section("Real training apps", real) + section("BenchmarkPython (in-benchmark)", bench)) + "\n")
    print(out_md.read_text())


if __name__ == "__main__":
    main()
