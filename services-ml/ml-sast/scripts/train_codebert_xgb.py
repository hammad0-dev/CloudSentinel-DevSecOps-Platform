"""Cheaper alternative: frozen CodeBERT mean-pooled embeddings + XGBoost (tuned on val only).

Embeddings for every split are cached in data/processed/emb_<split>.npy. Writes models/codebert_xgb.joblib.
"""
import itertools
import json
import os
import sys
import time
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("HF_HOME", str(ROOT / ".hf"))
from sastml import CLASSES  # noqa: E402
from sastml.codebert import CodeBertXGB, embed  # noqa: E402
from sastml.evaluation import best_threshold, load, metrics  # noqa: E402


def log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [emb+xgb] {msg}"
    print(line, flush=True)
    with open(ROOT / "logs/codebert.log", "a") as fh:
        fh.write(line + "\n")


def cached(split):
    path = ROOT / f"data/processed/emb_{split}.npy"
    rows = load(split)
    if path.exists():
        return rows, np.load(path)
    t0 = time.time()
    X = embed([r["code"] for r in rows], [r["lang"] for r in rows])
    np.save(path, X)
    log(f"embedded {split}: {X.shape} in {(time.time() - t0) / 60:.1f}m")
    return rows, X


def main():
    from xgboost import XGBClassifier
    train, Xtr = cached("train")
    val, Xva = cached("val")
    for s in ("test", "heldout"):
        cached(s)
    y = np.array([CLASSES.index(r["label"]) for r in train])
    counts = np.bincount(y, minlength=len(CLASSES)).astype(float)
    sw = (len(y) / (len(CLASSES) * counts))[y]
    results = []
    for depth, n, lr in itertools.product((4, 6), (300, 600), (0.05,)):
        est = XGBClassifier(n_estimators=n, max_depth=depth, learning_rate=lr, subsample=0.8, colsample_bytree=0.5,
                            objective="multi:softprob", tree_method="hist", n_jobs=8, random_state=0)
        est.fit(Xtr, y, sample_weight=sw)
        m = CodeBertXGB(est, {})
        score = metrics(val, m.predict_proba(None, None, embeddings=Xva))["macro_f1"]
        results.append((score, {"max_depth": depth, "n_estimators": n, "learning_rate": lr}, m))
        log(f"{results[-1][1]} val macro-F1={score:.3f}")
    score, params, model = max(results, key=lambda x: x[0])
    thr, thr_scores = best_threshold(val, model.predict_proba(None, None, embeddings=Xva))
    model.info = {"name": "ml-sast-codebert-xgb", "kind": "codebert_xgb", "base_model": "microsoft/codebert-base", "params": params,
                  "val_macro_f1_argmax": score, "threshold": thr, "val_macro_f1_by_threshold": thr_scores, "n_train": len(train),
                  "trained_on": "data/processed/train.jsonl", "grid": [{"params": p, "val_macro_f1": s} for s, p, _ in results]}
    joblib.dump(model, ROOT / "models/codebert_xgb.joblib", compress=3)
    (ROOT / "models/codebert_xgb.json").write_text(json.dumps(model.info, indent=2) + "\n")
    log(f"best {params} val={score:.3f} threshold={thr}")


if __name__ == "__main__":
    main()
