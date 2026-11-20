"""Score the frozen fresh held-out set EXACTLY ONCE.

Refuses to run if data/fresh/FREEZE.json does not match the current labels/sources/rows, or if
reports/v2/fresh_final.json already exists. Systems are pre-declared in
reports/v2/fresh_preregistration.json (written by this script before any prediction is made):
the shipped v1 model and the final v2 hybrid, identified by SHA-256.

Views (all from the same single run): all units; code-visible (template-sink XSS removed); without
vulnerable-node's sast/seeds/ files; app code only (code-visible and no seeds). Bootstrap 95% intervals.
Usage: python scripts/eval_fresh_final.py --v1 models/release/model.joblib --v2 models/release_v2/model.joblib
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sastml import CLASSES  # noqa: E402
from sastml.evaluation import bootstrap, decide, load, metrics  # noqa: E402

OUT = ROOT / "reports/v2/fresh_final.json"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def predict(model, rows):
    codes, langs = [r["code"] for r in rows], [r["lang"] for r in rows]
    if hasattr(model, "decide"):
        return model.decide(codes, langs)
    return decide(model.predict_proba(codes, langs), model.info.get("threshold", 0.3))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--v1", required=True)
    ap.add_argument("--v2", required=True)
    args = ap.parse_args()
    if OUT.exists():
        sys.exit(f"{OUT.relative_to(ROOT)} exists: the fresh set has already been scored once. Refusing to score it again.")
    check = subprocess.run([sys.executable, str(ROOT / "scripts/build_heldout.py"), "--set", "fresh"], capture_output=True, text=True)
    if check.returncode != 0:
        sys.exit("fresh set does not match FREEZE.json:\n" + check.stdout + check.stderr)
    systems = {"v1_shipped": args.v1, "v2_final": args.v2}
    prereg = {"systems": {k: {"path": v, "sha256": sha(v)} for k, v in systems.items()},
              "freeze": json.loads((ROOT / "data/fresh/FREEZE.json").read_text()),
              "views": ["all", "code_visible", "no_seeds", "app_code_only"], "metric": "macro-F1 over classes present, per-class P/R/F1, vulnerable-vs-safe P/R, bootstrap 95% CI (1000)"}
    (ROOT / "reports/v2").mkdir(parents=True, exist_ok=True)
    (ROOT / "reports/v2/fresh_preregistration.json").write_text(json.dumps(prereg, indent=2) + "\n")

    rows = [r for r in load("fresh") if not r["excluded"]]
    preds = {k: predict(joblib.load(v), rows) for k, v in systems.items()}
    views = {
        "all": [True] * len(rows),
        "code_visible": [not r["template_sink"] for r in rows],
        "no_seeds": [not r["file"].startswith("sast/seeds/") for r in rows],
        "app_code_only": [not r["template_sink"] and not r["file"].startswith("sast/seeds/") for r in rows],
    }
    result = {"preregistration": prereg, "views": {}}
    for name, mask in views.items():
        idx = [i for i, k in enumerate(mask) if k]
        sub = [rows[i] for i in idx]
        sp = {k: np.asarray(p)[idx] for k, p in preds.items()}
        result["views"][name] = {"n": len(sub), "n_vulnerable": sum(1 for r in sub if r["label"] != "safe"),
                                 "systems": {k: metrics(sub, None, pred=p) for k, p in sp.items()}, "bootstrap": bootstrap(sub, sp)}
    OUT.write_text(json.dumps(result, indent=2) + "\n")
    for name, v in result["views"].items():
        print(f"== {name} (n={v['n']}, vulnerable={v['n_vulnerable']})")
        for k, m in v["systems"].items():
            ci = v["bootstrap"]["macro_f1"][k]["ci95"]
            print(f"  {k:11} macro-F1={m['macro_f1']:.3f} [{ci[0]:.3f},{ci[1]:.3f}] vulnP={m['binary']['precision']:.2f} vulnR={m['binary']['recall']:.2f} | "
                  + " ".join(f"{c.replace('CWE-', '')}:{m['per_class'][c]['f1']:.2f}/{m['per_class'][c]['support']}" for c in CLASSES))
        for k, d in v["bootstrap"]["differences"].items():
            print(f"  diff {k}: {d['mean']:+.3f} [{d['ci95'][0]:+.3f},{d['ci95'][1]:+.3f}]")


if __name__ == "__main__":
    main()
