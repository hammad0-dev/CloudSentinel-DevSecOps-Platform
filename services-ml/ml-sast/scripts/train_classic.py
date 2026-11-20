"""Train and tune the classical baselines (LR, RF, LightGBM) on train; tune on val only.

Writes models/<kind>.joblib and models/<kind>.json (params, val scores, chosen threshold).
Usage: python scripts/train_classic.py [lr rf lgbm]
"""
import itertools
import json
import sys
import time
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sastml.evaluation import best_threshold, load, metrics  # noqa: E402
from sastml.model import SastModel  # noqa: E402

GRIDS = {
    "lr": [{"C": c} for c in (0.3, 1.0, 3.0, 10.0)],
    "rf": [{"n_estimators": 400, "max_depth": d, "min_samples_leaf": l} for d, l in itertools.product((None, 40), (1, 2))],
    "lgbm": [{"n_estimators": 300, "learning_rate": 0.05, "num_leaves": 15}, {"n_estimators": 500, "learning_rate": 0.05, "num_leaves": 31},
             {"n_estimators": 300, "learning_rate": 0.1, "num_leaves": 15}],
}
FEAT = {"lr": {"max_features": 40000, "ngram_range": (1, 3)}, "rf": {"max_features": 8000, "ngram_range": (1, 2)}, "lgbm": {"max_features": 8000, "ngram_range": (1, 2)}}


def cols(rows):
    return [r["code"] for r in rows], [r["lang"] for r in rows], [r["label"] for r in rows]


def main(kinds):
    train, val = load("train"), load("val")
    (tc, tl, ty), (vc, vl, _) = cols(train), cols(val)
    out = ROOT / "models"
    out.mkdir(exist_ok=True)
    for kind in kinds:
        results = []
        for params in GRIDS[kind]:
            t0 = time.time()
            m = SastModel(kind, params, FEAT[kind]).fit(tc, tl, ty)
            score = metrics(val, m.predict_proba(vc, vl))["macro_f1"]
            results.append((score, params, m))
            print(f"[{kind}] {params} val macro-F1={score:.3f} ({time.time() - t0:.0f}s)", flush=True)
        score, params, model = max(results, key=lambda x: x[0])
        thr, thr_scores = best_threshold(val, model.predict_proba(vc, vl))
        model.info = {"name": f"ml-sast-{kind}", "kind": kind, "params": params, "featurizer": FEAT[kind], "val_macro_f1_argmax": score,
                      "threshold": thr, "val_macro_f1_by_threshold": thr_scores, "trained_on": "data/processed/train.jsonl", "n_train": len(train),
                      "grid": [{"params": p, "val_macro_f1": s} for s, p, _ in results]}
        joblib.dump(model, out / f"{kind}.joblib", compress=3)
        (out / f"{kind}.json").write_text(json.dumps(model.info, indent=2, default=str) + "\n")
        print(f"[{kind}] best {params} val={score:.3f} threshold={thr}", flush=True)


if __name__ == "__main__":
    main(sys.argv[1:] or ["lr", "rf", "lgbm"])
