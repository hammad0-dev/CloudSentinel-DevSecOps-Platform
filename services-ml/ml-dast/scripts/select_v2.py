"""Fix the v2 model family BEFORE the held-out app (DSVW) is collected or scored.

Rule (same as v1): the family with the highest pooled leave-one-app-out endpoint-param macro-F1 over
all training apps in reports/loao_v2.json. Writes reports/selection_v2.json; refuses to overwrite it.
"""
import datetime
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports/selection_v2.json"

if __name__ == "__main__":
    if OUT.exists():
        sys.exit("reports/selection_v2.json exists: the v2 family is already fixed")
    if (ROOT / "reports/final_dsvw.json").exists():
        sys.exit("DSVW was already scored; selection must precede it")
    loao = json.loads((ROOT / "reports/loao_v2.json").read_text())
    scores = {k: s["endpoint"]["all"]["macro_f1"] for k, s in loao["systems"].items()}
    family = max(scores, key=scores.get)
    sel = {"family": family, "rule": "highest pooled LOAO endpoint-param macro-F1 (all training apps), fixed before DSVW is collected or scored",
           "loao_macro_f1": scores, "loao_ci95": {k: loao["bootstrap"]["all"]["macro_f1"][k]["ci95"] for k in scores},
           "apps": loao["apps"], "n_rows": loao["n_rows"], "date": datetime.date.today().isoformat(),
           "feature_set_frozen_at": "iteration 2 (raw_reflected_dangerous); no feature changes after the final collection"}
    OUT.write_text(json.dumps(sel, indent=1) + "\n")
    print(json.dumps(sel, indent=1))
