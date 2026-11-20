"""Endpoint-param and row-level metrics, decision rule and cluster bootstrap for ml-dast.

Decision rule (row): a row sent with a class-C payload is predicted C when the model's P(C) >= t,
otherwise safe. Endpoint-param (cluster) level, the headline: the cluster is predicted C when any of
its C-payload rows is; if several classes fire, the one with the highest max P wins. A cluster's
true class is the CWE of its positive rows, or safe.
"""
import collections

import numpy as np

from . import CLASSES


def row_pred(rows, proba, t):
    out = np.zeros(len(rows), dtype=np.int64)
    for i, r in enumerate(rows):
        c = CLASSES.index(r["payload_class"])
        if proba[i, c] >= t:
            out[i] = c
    return out


def clusters(rows, proba, t):
    """{cluster: (true_idx, pred_idx, origin, app)}"""
    best = collections.defaultdict(lambda: np.zeros(len(CLASSES)))
    info = {}
    for i, r in enumerate(rows):
        k = r["cluster"]
        c = CLASSES.index(r["payload_class"])
        best[k][c] = max(best[k][c], proba[i, c])
        true = CLASSES.index(r["label"])
        prev = info.get(k, (0, r["origin"], r["app"]))
        info[k] = (max(prev[0], true), r["origin"], r["app"])
    out = {}
    for k, scores in best.items():
        fired = [c for c in range(1, len(CLASSES)) if scores[c] >= t]
        pred = max(fired, key=lambda c: scores[c]) if fired else 0
        out[k] = (info[k][0], pred, info[k][1], info[k][2])
    return out


def prf(y, p, n=len(CLASSES)):
    y, p = np.asarray(y), np.asarray(p)
    per = {}
    f1s = []
    for c in range(n):
        tp = int(((p == c) & (y == c)).sum())
        fp = int(((p == c) & (y != c)).sum())
        fn = int(((p != c) & (y == c)).sum())
        sup = int((y == c).sum())
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        per[CLASSES[c]] = {"precision": prec, "recall": rec, "f1": f1, "support": sup, "tp": tp, "fp": fp, "fn": fn}
        if sup:
            f1s.append(f1)
    conf = [[int(((y == a) & (p == b)).sum()) for b in range(n)] for a in range(n)]
    vt, vp = y != 0, p != 0
    btp = int((vt & vp).sum())
    binary = {"precision": btp / max(int(vp.sum()), 1), "recall": btp / max(int(vt.sum()), 1)}
    return {"n": int(len(y)), "macro_f1": float(np.mean(f1s)) if f1s else 0.0, "per_class": per, "confusion": conf, "binary": binary}


def endpoint_metrics(cl, origin=None):
    items = [v for v in cl.values() if origin is None or v[2] == origin]
    return prf([v[0] for v in items], [v[1] for v in items])


def row_metrics(rows, proba, t, origin=None):
    idx = [i for i, r in enumerate(rows) if origin is None or r["origin"] == origin]
    y = [CLASSES.index(rows[i]["label"]) for i in idx]
    p = row_pred([rows[i] for i in idx], proba[idx], t)
    return prf(y, p)


def bootstrap_endpoints(systems, n=1000, seed=0, origin=None):
    """systems: {name: cluster dict}. Resample clusters (shared across systems) with replacement."""
    keys = sorted(next(iter(systems.values())))
    keys = [k for k in keys if origin is None or next(iter(systems.values()))[k][2] == origin]
    rng = np.random.default_rng(seed)
    scores = {s: [] for s in systems}
    per_class = {s: {c: [] for c in CLASSES[1:]} for s in systems}
    for _ in range(n):
        pick = rng.integers(0, len(keys), len(keys))
        for s, cl in systems.items():
            ks = [keys[i] for i in pick]
            m = prf([cl[k][0] for k in ks], [cl[k][1] for k in ks])
            scores[s].append(m["macro_f1"])
            for c in CLASSES[1:]:
                per_class[s][c].append(m["per_class"][c]["f1"])
    ci = lambda a: [float(np.percentile(a, 2.5)), float(np.percentile(a, 97.5))]
    out = {"n_clusters": len(keys), "macro_f1": {s: {"mean": float(np.mean(v)), "ci95": ci(v)} for s, v in scores.items()},
           "per_class_f1_ci95": {s: {c: ci(v) for c, v in d.items()} for s, d in per_class.items()}, "differences": {}}
    names = list(systems)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            d = np.array(scores[names[i]]) - np.array(scores[names[j]])
            out["differences"][f"{names[i]} - {names[j]}"] = {"mean": float(d.mean()), "ci95": ci(d)}
    return out
