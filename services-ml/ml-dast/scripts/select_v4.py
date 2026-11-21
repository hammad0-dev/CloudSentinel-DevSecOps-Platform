"""Fix the v4 model family BEFORE the held-out app (DVPWA) is collected or scored.

Rule (docs/ml-dast-v4-plan.md): the family with the highest pooled leave-one-app-out endpoint-param macro-F1 over the
NON-benchmark groups ("real" = own + third-party) in reports/loao_v4.json. Writes reports/selection_v4.json once.
"""
import datetime
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports/selection_v4.json"

if __name__ == "__main__":
    if OUT.exists():
        sys.exit("reports/selection_v4.json exists: the v4 family is already fixed")
    if (ROOT / "reports/final_dvpwa.json").exists():
        sys.exit("DVPWA was already scored; selection must precede it")
    lo = json.loads((ROOT / "reports/loao_v4.json").read_text())
    scores = {k: s["endpoint"]["real"]["macro_f1"] for k, s in lo["systems"].items()}
    family = max(scores, key=scores.get)
    sel = {"family": family, "rule": "highest pooled LOAO endpoint-param macro-F1 over the non-benchmark groups, fixed before DVPWA is collected or scored",
           "loao_real_macro_f1": scores, "loao_real_ci95": {k: lo["bootstrap"]["real"]["macro_f1"][k]["ci95"] for k in scores},
           "apps": lo["apps"], "n_rows": lo["n_rows"], "date": datetime.date.today().isoformat(),
           "feature_sets": lo["feature_sets"], "thresholds": lo["thresholds"]}
    OUT.write_text(json.dumps(sel, indent=1) + "\n")
    print(json.dumps(sel, indent=1))
