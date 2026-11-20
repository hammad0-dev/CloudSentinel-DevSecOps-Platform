"""Shared evaluation: data loading, decision rule, metrics, and the evaluation sets.

Decision rule (also used by the service): take the most likely vulnerable class; report it only if its
probability is >= threshold, otherwise predict ``safe``. threshold=None means plain argmax.

Evaluation sets:
* ``test``            the test split (real + synthetic; groups never seen in training)
* ``test_real``       the CrossVul part of the test split only
* ``heldout_all``     held-out apps, all labelled units (incl. the 5 template-sink XSS units)
* ``heldout_code``    held-out apps without template-sink units ("code-visible only")
Excluded held-out units (out-of-class or ambiguous) are never scored. For multi-label held-out units a
prediction of any listed class counts as correct.
"""
import json
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support

from . import CLASSES

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/processed"


def load(split):
    with open(DATA / f"{split}.jsonl") as fh:
        return [json.loads(line) for line in fh]


def eval_sets():
    test = load("test")
    held = [r for r in load("heldout") if not r["excluded"]]
    return {
        "test": test,
        "test_real": [r for r in test if r["origin"] == "crossvul"],
        "heldout_all": held,
        "heldout_code": [r for r in held if not r["template_sink"]],
    }


def decide(proba, threshold=None):
    proba = np.asarray(proba)
    if threshold is None:
        return proba.argmax(1)
    vuln = proba[:, 1:]
    best = vuln.argmax(1) + 1
    return np.where(proba[np.arange(len(proba)), best] >= threshold, best, 0)


def true_labels(rows, pred_idx):
    y = []
    for r, p in zip(rows, pred_idx):
        allowed = r.get("labels") or [r["label"]]
        y.append(CLASSES[p] if CLASSES[p] in allowed else allowed[0])
    return np.array([CLASSES.index(l) for l in y])


def metrics(rows, proba, threshold=None, pred=None):
    """Metrics from probabilities (+ decision rule) or from explicit predicted class indices."""
    pred = decide(proba, threshold) if pred is None else np.asarray(pred)
    y = true_labels(rows, pred)
    labels = list(range(len(CLASSES)))
    p, r, f, s = precision_recall_fscore_support(y, pred, labels=labels, zero_division=0)
    present = [i for i in labels if s[i] > 0]
    vuln_true, vuln_pred = y != 0, pred != 0
    return {
        "n": len(rows),
        "macro_f1": float(f1_score(y, pred, labels=present, average="macro", zero_division=0)) if present else 0.0,
        "macro_f1_classes": [CLASSES[i] for i in present],
        "accuracy": float((y == pred).mean()) if len(rows) else 0.0,
        "binary": {  # vulnerable-vs-safe, any CWE
            "precision": float((vuln_true & vuln_pred).sum() / max(vuln_pred.sum(), 1)),
            "recall": float((vuln_true & vuln_pred).sum() / max(vuln_true.sum(), 1)),
        },
        "per_class": {CLASSES[i]: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]), "support": int(s[i])} for i in labels},
        "confusion": confusion_matrix(y, pred, labels=labels).tolist(),
    }


def bootstrap(rows, preds, n=1000, seed=0):
    """95% intervals of macro-F1 and per-class F1 for each system (dict name -> pred indices), plus
    pairwise macro-F1 differences, resampling units with replacement."""
    rng = np.random.default_rng(seed)
    names = list(preds)
    macro = {k: [] for k in names}
    per_class = {k: {c: [] for c in CLASSES} for k in names}
    for _ in range(n):
        idx = rng.integers(0, len(rows), len(rows))
        sub = [rows[i] for i in idx]
        for k in names:
            m = metrics(sub, None, pred=np.asarray(preds[k])[idx])
            macro[k].append(m["macro_f1"])
            for c in CLASSES:
                if m["per_class"][c]["support"]:
                    per_class[k][c].append(m["per_class"][c]["f1"])
    ci = lambda a: [float(np.percentile(a, 2.5)), float(np.percentile(a, 97.5))] if len(a) else None
    return {
        "resamples": n,
        "macro_f1": {k: {"point": metrics(rows, None, pred=preds[k])["macro_f1"], "ci95": ci(macro[k])} for k in names},
        "per_class_f1_ci95": {k: {c: ci(v) for c, v in per_class[k].items()} for k in names},
        "differences": {f"{a} - {b}": {"mean": float(np.mean(np.subtract(macro[a], macro[b]))), "ci95": ci(np.subtract(macro[a], macro[b]))}
                        for i, a in enumerate(names) for b in names[i + 1:]},
    }


def best_threshold(rows, proba, grid=(0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8)):
    """Pick the service threshold on validation data only."""
    scores = {t: metrics(rows, proba, t)["macro_f1"] for t in grid}
    t = max(scores, key=lambda k: (scores[k], k))
    return t, scores
