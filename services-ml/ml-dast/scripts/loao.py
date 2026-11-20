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
from dastml.features import FEATURE_NAMES, FEATURE_NAMES_V2, FEATURE_NAMES_V3, LOCATION_FEATURES  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402
from dastml.paths import paths  # noqa: E402
from dastml.evaluation import bootstrap_endpoints, clusters, endpoint_metrics, row_metrics  # noqa: E402
from dastml.model import GRIDS, THRESHOLDS, THRESHOLDS_V3, DastModel  # noqa: E402

REPORTS = ROOT / "reports"
# Feature subsets the inner LOAO may choose from (F5: is the location one-hot an app-specific prior?).
# Set by main(); {"all": every column} reproduces v1 exactly.
FSETS = {}
# Threshold grid for this run (v3: 0.20-0.95, see dastml.model.THRESHOLDS_V3). Set by main().
THRESH = list(THRESHOLDS)


def inner_select(kind, rows, X, y, groups):
    """Choose (params, feature set, threshold) by inner LOAO over `groups`; params carry "fset"."""
    best = (-1.0, None, None)
    gs = sorted(set(groups))
    for fset, cols in FSETS.items():
        for params in GRIDS[kind]:
            proba = np.zeros((len(rows), len(CLASSES)))
            for g in gs:
                te = groups == g
                if len(set(y[~te])) < 2:
                    continue
                proba[te] = DastModel(kind, params).fit(X[~te][:, cols], y[~te]).predict_proba(X[te][:, cols])
            for t in THRESH:
                score = endpoint_metrics(clusters(rows, proba, t))["macro_f1"]
                if score > best[0] + 1e-9:
                    best = (score, {**params, "fset": fset} if len(FSETS) > 1 else params, t)
    return best


def fit_cols(params):
    p = dict(params)
    return p, FSETS[p.pop("fset", "all")]


def run_kind(kind, rows, X, y, groups):
    proba = np.zeros((len(rows), len(CLASSES)))
    thresholds = np.zeros(len(rows))
    folds = {}
    for g in sorted(set(groups)):
        te = groups == g
        tr_rows = [r for r, m in zip(rows, ~te) if m]
        score, params, t = inner_select(kind, tr_rows, X[~te], y[~te], groups[~te])
        mp, cols = fit_cols(params)
        model = DastModel(kind, mp).fit(X[~te][:, cols], y[~te])
        proba[te] = model.predict_proba(X[te][:, cols])
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


def main(data="v1", labels=None, kinds=("lr", "rf", "lgbm")):
    """data: feature version (v1: FEATURE_NAMES; v2: FEATURE_NAMES_V2 plus the location ablation).
    labels: optionally re-label with another ground truth; the "before" model re-scored on the
    corrected labels is --data v1 --labels v2."""
    global FSETS, THRESH
    t0 = time.time()
    labels = labels or data
    relabel = GroundTruth(paths(labels)["ground_truth"]) if labels != data else None
    rows = load(directory=paths(data)["features"], relabel=relabel)
    names = {"v1": FEATURE_NAMES, "v2": FEATURE_NAMES_V2, "v3": FEATURE_NAMES_V3}[data]
    THRESH = list(THRESHOLDS_V3 if data == "v3" else THRESHOLDS)
    X, y = matrix(rows, names)
    FSETS = {"all": list(range(len(names)))}
    if data != "v1":
        FSETS["no_loc"] = [i for i, n in enumerate(names) if n not in LOCATION_FEATURES]
    tag = "" if (data, labels) == ("v1", "v1") else ("_v1relabel" if data == "v1" else f"_{data}")
    groups = np.array([r["group"] for r in rows])
    REPORTS.mkdir(exist_ok=True)
    result = {"data": data, "labels": labels, "feature_names": names, "apps": sorted(set(groups)), "n_rows": len(rows), "systems": {}}
    pooled = {}
    for kind in kinds:
        proba, thr, folds, cl = run_kind(kind, rows, X, y, groups)
        pooled[kind] = cl
        result["systems"][kind] = {
            "folds": folds,
            "endpoint": {o or "all": endpoint_metrics(cl, o) for o in (None, "own", "third-party")},
            "row": {o or "all": pooled_rows(rows, proba, thr, o) for o in (None, "own", "third-party")},
        }
        for o in ("all", "own", "third-party"):
            confusion_png(result["systems"][kind]["endpoint"][o]["confusion"], f"{kind} LOAO endpoint-param ({o})", REPORTS / f"confusion_{kind}_{o}{tag}.png")
    result["bootstrap"] = {o or "all": bootstrap_endpoints(pooled, origin=o) for o in (None, "own", "third-party")}
    (REPORTS / f"loao_clusters{tag}.json").write_text(json.dumps({k: {c: list(v) for c, v in cl.items()} for k, cl in pooled.items()}, indent=0) + "\n")
    result["seconds"] = round(time.time() - t0)
    (REPORTS / f"loao{tag}.json").write_text(json.dumps(result, indent=1) + "\n")
    write_md(result, tag)
    print(f"done in {result['seconds']}s")


def write_md(res, tag=""):
    title = {"": "", "_v1relabel": ": v1 model re-scored on the corrected (v2) labels", "_v2": ": v2 features and data", "_v3": ": v3 features and data"}.get(tag, tag)
    L = [f"# ml-dast leave-one-app-out (main evaluation){title}", "",
         f"Data {res.get('data', 'v1')}, labels {res.get('labels', 'v1')}. Rows: {res['n_rows']}. Test folds (each app group unseen once): {', '.join(res['apps'])}. DVNA is not part of this table.",
         "Endpoint-param level (headline): a parameter is flagged for a class if any of its rows of that payload class passes the threshold.", ""]
    for o in ("all", "own", "third-party"):
        b = res["bootstrap"][o]
        L += [f"## {o} ({b['n_clusters']} endpoint-params)", "", "| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |", "|---|---|---|---|---|---|---|"]
        for k, s in res["systems"].items():
            e = s["endpoint"][o]
            ci = b["macro_f1"][k]["ci95"]
            pc = lambda c: e["per_class"][c]
            cci = lambda c: b.get("per_class_f1_ci95", {}).get(k, {}).get(c)
            fmt = lambda c: f"{pc(c)['precision']:.2f}/{pc(c)['recall']:.2f}/{pc(c)['f1']:.2f} ({pc(c)['support']})" + (f" [{cci(c)[0]:.2f}, {cci(c)[1]:.2f}]" if cci(c) else "")
            L.append(f"| {k} | {e['macro_f1']:.3f} [{ci[0]:.3f}, {ci[1]:.3f}] | {fmt('CWE-89')} | {fmt('CWE-79')} | {pc('safe')['f1']:.2f} ({pc('safe')['support']}) | "
                     f"{e['binary']['precision']:.2f}/{e['binary']['recall']:.2f} | {s['row'][o]['macro_f1']:.3f} |")
        L += [""] + [f"- {k}: {d['mean']:+.3f} [{d['ci95'][0]:+.3f}, {d['ci95'][1]:+.3f}]" for k, d in b["differences"].items()] + [""]
    L += ["## Per fold (endpoint-param macro-F1)", "", "| Test app | " + " | ".join(res["systems"]) + " |", "|---|" + "---|" * len(res["systems"])]
    for g in res["apps"]:
        L.append(f"| {g} | " + " | ".join(f"{s['folds'][g]['endpoint']['macro_f1']:.3f} (t={s['folds'][g]['threshold']}{', ' + s['folds'][g]['params']['fset'] if 'fset' in s['folds'][g]['params'] else ''})" for s in res["systems"].values()) + " |")
    (REPORTS / f"loao{tag}.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="v1", choices=["v1", "v2", "v3"])
    ap.add_argument("--labels", choices=["v1", "v2", "v3"])
    ap.add_argument("--kinds", default="lr,rf,lgbm")
    a = ap.parse_args()
    main(a.data, a.labels, tuple(a.kinds.split(",")))
