"""Tune the v2 hybrid on the DEVELOPMENT set only (data/heldout; the fresh set is never loaded here).

Searches: ensemble weight w (RF share), secrets mode (none / union / rules), and thresholds:
first one global threshold for all classes; per-class thresholds (coordinate ascent, 2 passes) are
kept only if they raise development macro-F1 by >= 0.02 (pre-declared, to limit overfitting on tiny
per-class supports). Compares against the shipped v1 RF (threshold 0.3) on the same (corrected) labels,
with bootstrap intervals. Writes models/<out>.joblib and reports/v2/<tag>_dev.json.

Usage: python scripts/tune_v2.py --tag step2 [--models-dir models] [--out hybrid_step2]
"""
import argparse
import itertools
import json
import sys
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sastml import CLASSES  # noqa: E402
from sastml.evaluation import bootstrap, decide, load, metrics  # noqa: E402
from sastml.hybrid import HybridModel  # noqa: E402

GRID = (0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.5, 0.6, 0.7)


def score(model, rows, proba, cand_cache=None):
    return metrics(rows, None, pred=model.decide([r["code"] for r in rows], [r["lang"] for r in rows], proba))["macro_f1"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--models-dir", default="models")
    ap.add_argument("--out", default=None)
    ap.add_argument("--baseline", default="models/release/model.joblib", help="v1 shipped model for before/after")
    args = ap.parse_args()
    mdir = ROOT / args.models_dir
    rf, lgbm = joblib.load(mdir / "rf.joblib"), joblib.load(mdir / "lgbm.joblib")
    rows = [r for r in load("heldout") if not r["excluded"]]
    codes, langs = [r["code"] for r in rows], [r["lang"] for r in rows]
    p_rf, p_lgbm = rf.predict_proba(codes, langs), lgbm.predict_proba(codes, langs)

    trials = []
    best = None
    for w, mode in itertools.product((0.0, 0.25, 0.5, 0.75, 1.0), ("none", "union", "rules")):
        proba = w * p_rf + (1 - w) * p_lgbm
        for t in GRID:
            m = HybridModel(rf, lgbm, w, {c: t for c in CLASSES[1:]}, mode)
            s = score(m, rows, proba)
            trials.append({"weight": w, "secrets_mode": mode, "global_threshold": t, "dev_macro_f1": s})
            if best is None or s > best[0]:
                best = (s, w, mode, t)
    s_global, w, mode, t = best
    proba = w * p_rf + (1 - w) * p_lgbm
    model = HybridModel(rf, lgbm, w, {c: t for c in CLASSES[1:]}, mode)
    per = dict(model.thresholds)
    s_per = s_global
    for _ in range(2):
        for c in CLASSES[1:]:
            if c == "CWE-798" and mode == "rules":
                continue
            for tc in GRID:
                trial = HybridModel(rf, lgbm, w, {**per, c: tc}, mode)
                s = score(trial, rows, proba)
                if s > s_per + 1e-9:
                    s_per, per = s, {**per, c: tc}
    use_per = s_per >= s_global + 0.02
    model.thresholds = per if use_per else model.thresholds
    final_pred = model.decide(codes, langs, proba)

    v1 = joblib.load(ROOT / args.baseline)
    v1_pred = decide(v1.predict_proba(codes, langs), v1.info.get("threshold", 0.3))
    ml_only = HybridModel(rf, lgbm, w, model.thresholds, "none").decide(codes, langs, proba)
    systems = {"v1_rf": v1_pred, f"{args.tag}_ml_only": ml_only, f"{args.tag}_hybrid": final_pred}
    code_mask = [not r["template_sink"] for r in rows]
    rows_code = [r for r, k in zip(rows, code_mask) if k]
    report = {
        "set": "development (data/heldout, corrected labels)", "tag": args.tag,
        "chosen": {"weight_rf": w, "secrets_mode": mode, "secrets_detector": "rule-based (sastml/secrets.py)", "global_threshold": t,
                   "per_class_thresholds_used": use_per, "thresholds": model.thresholds,
                   "dev_macro_f1_global": s_global, "dev_macro_f1_per_class": s_per},
        "systems": {k: {"all": metrics(rows, None, pred=v), "code_visible": metrics(rows_code, None, pred=np.asarray(v)[code_mask])} for k, v in systems.items()},
        "bootstrap_all": bootstrap(rows, systems),
        "bootstrap_code_visible": bootstrap(rows_code, {k: np.asarray(v)[code_mask] for k, v in systems.items()}),
        "trials": trials,
    }
    model.info = {"name": "ml-sast-hybrid", "kind": "hybrid", "components": {"ml": "RF+LightGBM probability ensemble", "CWE-798": "rule-based secrets detector" if mode != "none" else "ml"},
                  "weight_rf": w, "secrets_mode": mode, "thresholds": model.thresholds, "threshold": min(model.thresholds.values()),
                  "tuned_on": "development set (NodeGoat, DVNA, vulpy, PyGoat)", "models_dir": args.models_dir}
    out = args.out or f"hybrid_{args.tag}"
    joblib.dump(model, ROOT / f"models/{out}.joblib", compress=3)
    (ROOT / "reports/v2").mkdir(parents=True, exist_ok=True)
    (ROOT / f"reports/v2/{args.tag}_dev.json").write_text(json.dumps(report, indent=2, default=float) + "\n")
    print(json.dumps(report["chosen"], indent=1))
    for k, v in report["systems"].items():
        b = report["bootstrap_all"]["macro_f1"][k]
        print(f"{k:22} dev-all mF1={v['all']['macro_f1']:.3f} [{b['ci95'][0]:.3f},{b['ci95'][1]:.3f}]  code-visible={v['code_visible']['macro_f1']:.3f}  vulnP={v['all']['binary']['precision']:.2f} vulnR={v['all']['binary']['recall']:.2f}")
        print("    " + " ".join(f"{c.replace('CWE-', '')}:{v['all']['per_class'][c]['f1']:.2f}/{v['all']['per_class'][c]['support']}" for c in CLASSES))
    for k, d in report["bootstrap_all"]["differences"].items():
        print(f"  diff {k}: {d['mean']:+.3f} [{d['ci95'][0]:+.3f},{d['ci95'][1]:+.3f}]")


if __name__ == "__main__":
    main()
