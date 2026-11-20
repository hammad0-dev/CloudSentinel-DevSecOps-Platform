"""Development-set report for the rule-based secrets detector (never run on the fresh set).

Prints per-rule TP/FP on CWE-798, then the false positives and misses for inspection.
Writes reports/v2/secrets_dev.json.
"""
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sastml.evaluation import load  # noqa: E402
from sastml.secrets import scan  # noqa: E402


def main():
    rows = [r for r in load("heldout") if not r["excluded"]]
    per_rule = collections.defaultdict(lambda: {"tp": 0, "fp": 0})
    tp = fp = fn = 0
    fps, fns = [], []
    for r in rows:
        hits = scan(r["code"])
        is_secret = "CWE-798" in r["labels"]
        for rule in {h.rule for h in hits}:
            per_rule[rule]["tp" if is_secret else "fp"] += 1
        if hits and is_secret:
            tp += 1
        elif hits:
            fp += 1
            lines = r["code"].split("\n")
            fps.append({"app": r["app"], "file": r["file"], "function": r["function"], "label": r["label"],
                        "hits": [(h.rule, lines[h.line - 1].strip()[:110]) for h in hits]})
        elif is_secret:
            fn += 1
            fns.append({"app": r["app"], "file": r["file"], "function": r["function"]})
    out = {"set": "development (data/heldout)", "detector": "rule-based", "tp": tp, "fp": fp, "fn": fn,
           "precision": tp / max(tp + fp, 1), "recall": tp / max(tp + fn, 1), "per_rule": dict(per_rule), "false_positives": fps, "misses": fns}
    (ROOT / "reports/v2").mkdir(parents=True, exist_ok=True)
    (ROOT / "reports/v2/secrets_dev.json").write_text(json.dumps(out, indent=2) + "\n")
    print(f"TP={tp} FP={fp} FN={fn} precision={out['precision']:.2f} recall={out['recall']:.2f}")
    print("per rule:", dict(per_rule))
    for f in fps:
        print("FP", f["app"], f["file"], f["function"], f["label"], f["hits"])
    for f in fns:
        print("MISS", f["app"], f["file"], f["function"])


if __name__ == "__main__":
    main()
