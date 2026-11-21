"""Fix the v3 model family BEFORE the held-out app (SirAppSec) is collected or scored.

Rule (same as v1/v2): the family with the highest pooled leave-one-app-out endpoint-param macro-F1 over
all training apps in reports/loao_v3.json. Writes reports/selection_v3.json; refuses to overwrite it.
"""
import datetime
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports/selection_v3.json"

if __name__ == "__main__":
    if OUT.exists():
        sys.exit("reports/selection_v3.json exists: the v3 family is already fixed")
    if (ROOT / "reports/final_sirappsec.json").exists():
        sys.exit("SirAppSec was already scored; selection must precede it")
    loao = json.loads((ROOT / "reports/loao_v3.json").read_text())
    scores = {k: s["endpoint"]["all"]["macro_f1"] for k, s in loao["systems"].items()}
    family = max(scores, key=scores.get)
    sel = {"family": family, "rule": "highest pooled LOAO endpoint-param macro-F1 (all training apps), fixed before SirAppSec is collected or scored",
           "loao_macro_f1": scores, "loao_ci95": {k: loao["bootstrap"]["all"]["macro_f1"][k]["ci95"] for k in scores},
           "apps": loao["apps"], "n_rows": loao["n_rows"], "date": datetime.date.today().isoformat(),
           "feature_set_frozen_at": "v3 F1-F6 (docs/ml-dast-v3-plan.md, section A), fixed before any v3 training; no feature changes after the v3 collection"}
    OUT.write_text(json.dumps(sel, indent=1) + "\n")
    print(json.dumps(sel, indent=1))
