"""Main evaluation: leave-one-app-out over the 6 training app groups (DVNA is never loaded).

For every outer fold (one app group held out as the unseen test app):
  * inner leave-one-app-out over the remaining 5 groups chooses hyperparameters and the threshold
    (endpoint-param macro-F1 on pooled inner predictions);
  * the chosen configuration is refit on all 5 groups and predicts the held-out group.
The held-out group's predictions are pooled across folds, so every cluster is predicted by a model
that never saw its app. Reported: endpoint-param metrics (headline) and row metrics, all apps / own
apps / third-party apps, per-app folds, cluster bootstrap (1000) with pairwise differences, and
confusion-matrix PNGs. Writes reports/loao.json, reports/loao.md, reports/confusion_*.png.
"""
import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dastml import CLASSES  # noqa: E402
from dastml.dataset import load, matrix  # noqa: E402
from dastml.evaluation import bootstrap_endpoints, clusters, endpoint_metrics, row_metrics  # noqa: E402
from dastml.model import GRIDS, THRESHOLDS, DastModel  # noqa: E402

REPORTS = ROOT / "reports"


def inner_select(kind, rows, X, y, groups):
    """Choose (params, threshold) by inner LOAO over `groups`."""
    best = (-1.0, None, None)
    gs = sorted(set(groups))
    for params in GRIDS[kind]:
        proba = np.zeros((len(rows), len(CLASSES)))
        for g in gs:
            te = groups == g
            if len(set(y[~te])) < 2:
                continue
            proba[te] = DastModel(kind, params).fit(X[~te], y[~te]).predict_proba(X[te])
        for t in THRESHOLDS:
            score = endpoint_metrics(clusters(rows, proba, t))["macro_f1"]
            if score > best[0] + 1e-9:
                best = (score, params, t)
    return best


def run_kind(kind, rows, X, y, groups):
    proba = np.zeros((len(rows), len(CLASSES)))
    thresholds = np.zeros(len(rows))
    folds = {}
    for g in sorted(set(groups)):
        te = groups == g
        tr_rows = [r for r, m in zip(rows, ~te) if m]
        score, params, t = inner_select(kind, tr_rows, X[~te], y[~te], groups[~te])
        model = DastModel(kind, params).fit(X[~te], y[~te])
        proba[te] = model.predict_proba(X[te])
        thresholds[te] = t
        te_rows = [r for r, m in zip(rows, te) if m]
        folds[g] = {"params": params, "threshold": t, "inner_macro_f1": score,
                    "endpoint": endpoint_metrics(clusters(te_rows, proba[te], t)), "row": row_metrics(te_rows, proba[te], t)}
        print(f"  [{kind}] test={g:10} params={params} t={t} inner={score:.3f} endpoint mF1={folds[g]['endpoint']['macro_f1']:.3f}", flush=True)
    # pooled: each fold's own threshold (rows carry it)
    pooled_cl = {}
    for g in sorted(set(groups)):
        te = groups == g
        te_rows = [r for r, m in zip(rows, te) if m]
        pooled_cl.update(clusters(te_rows, proba[te], float(thresholds[te][0])))
    return proba, thresholds, folds, pooled_cl


def pooled_rows(rows, proba, thresholds, origin=None):
    from dastml.evaluation import prf, row_pred
    idx = [i for i, r in enumerate(rows) if origin is None or r["origin"] == origin]
    y, p = [], []
    for t in sorted(set(thresholds[idx])):
        sub = [i for i in idx if thresholds[i] == t]
        y += [CLASSES.index(rows[i]["label"]) for i in sub]
        p += list(row_pred([rows[i] for i in sub], proba[sub], t))
    return prf(y, p)


def confusion_png(conf, title, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(4.2, 3.6))
    ax.imshow(conf, cmap="Blues")
    ax.set_xticks(range(len(CLASSES)), CLASSES)
    ax.set_yticks(range(len(CLASSES)), CLASSES)
    ax.set_xlabel("predicted")
    ax.set_ylabel("true")
    ax.set_title(title, fontsize=9)
    for i in range(len(CLASSES)):
        for j in range(len(CLASSES)):
            ax.text(j, i, conf[i][j], ha="center", va="center", color="black")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def main():
    t0 = time.time()
    rows = load()
    X, y = matrix(rows)
    groups = np.array([r["group"] for r in rows])
    REPORTS.mkdir(exist_ok=True)
    result = {"apps": sorted(set(groups)), "n_rows": len(rows), "systems": {}}
    pooled = {}
    for kind in ("lr", "rf", "lgbm"):
        proba, thr, folds, cl = run_kind(kind, rows, X, y, groups)
        pooled[kind] = cl
        result["systems"][kind] = {
            "folds": folds,
            "endpoint": {o or "all": endpoint_metrics(cl, o) for o in (None, "own", "third-party")},
            "row": {o or "all": pooled_rows(rows, proba, thr, o) for o in (None, "own", "third-party")},
        }
        for o in ("all", "own", "third-party"):
            confusion_png(result["systems"][kind]["endpoint"][o]["confusion"], f"{kind} LOAO endpoint-param ({o})", REPORTS / f"confusion_{kind}_{o}.png")
    result["bootstrap"] = {o or "all": bootstrap_endpoints(pooled, origin=o) for o in (None, "own", "third-party")}
    result["seconds"] = round(time.time() - t0)
    (REPORTS / "loao.json").write_text(json.dumps(result, indent=1) + "\n")
    write_md(result)
    print(f"done in {result['seconds']}s")


def write_md(res):
    L = ["# ml-dast leave-one-app-out (main evaluation)", "",
         f"Rows: {res['n_rows']}. Test folds (each app group unseen once): {', '.join(res['apps'])}. DVNA is not part of this table.",
         "Endpoint-param level (headline): a parameter is flagged for a class if any of its rows of that payload class passes the threshold.", ""]
    for o in ("all", "own", "third-party"):
        b = res["bootstrap"][o]
        L += [f"## {o} ({b['n_clusters']} endpoint-params)", "", "| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) | XSS P/R/F1 (n) | safe F1 (n) | vuln P/R | row macro-F1 |", "|---|---|---|---|---|---|---|"]
        for k, s in res["systems"].items():
            e = s["endpoint"][o]
            ci = b["macro_f1"][k]["ci95"]
            pc = lambda c: e["per_class"][c]
            fmt = lambda c: f"{pc(c)['precision']:.2f}/{pc(c)['recall']:.2f}/{pc(c)['f1']:.2f} ({pc(c)['support']})"
            L.append(f"| {k} | {e['macro_f1']:.3f} [{ci[0]:.3f}, {ci[1]:.3f}] | {fmt('CWE-89')} | {fmt('CWE-79')} | {pc('safe')['f1']:.2f} ({pc('safe')['support']}) | "
                     f"{e['binary']['precision']:.2f}/{e['binary']['recall']:.2f} | {s['row'][o]['macro_f1']:.3f} |")
        L += [""] + [f"- {k}: {d['mean']:+.3f} [{d['ci95'][0]:+.3f}, {d['ci95'][1]:+.3f}]" for k, d in b["differences"].items()] + [""]
    L += ["## Per fold (endpoint-param macro-F1)", "", "| Test app | " + " | ".join(res["systems"]) + " |", "|---|" + "---|" * len(res["systems"])]
    for g in res["apps"]:
        L.append(f"| {g} | " + " | ".join(f"{s['folds'][g]['endpoint']['macro_f1']:.3f} (t={s['folds'][g]['threshold']})" for s in res["systems"].values()) + " |")
    (REPORTS / "loao.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
