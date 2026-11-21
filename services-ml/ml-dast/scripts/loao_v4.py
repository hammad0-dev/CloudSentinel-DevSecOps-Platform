"""v4 leave-one-app-out (decided in docs/ml-dast-v4-plan.md before any held-out scan).

* Data: features_v4 (v3 training apps re-featurized, plus the BenchmarkPython subset as ONE group, origin "benchmark").
* Candidates per family: feature set in {v2, v3} x {all, no_loc} (FEATURE_NAMES_V2 / FEATURE_NAMES_V3; no new
  features), the family's unchanged hyperparameter grid, threshold grid 0.20-0.95 (step 0.05) + 0.97, 0.98, 0.99, 0.995.
* Selection: inner leave-one-app-out only; the inner score is pooled endpoint-param macro-F1 over the NON-benchmark
  clusters (benchmark rows are trained on, never decide a selection).
* Reported: "real" (own + third-party; the headline), own, third-party, and benchmark (in-benchmark, labelled as such).
* --system v2: the v2 system (v2 features with/without location, v2 threshold grid) on the same data, for before/after.
Writes reports/loao_v4<tag>.json/.md, loao_clusters_v4<tag>.json; never overwrites an existing report.
"""
import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import loao  # noqa: E402
from dastml import CLASSES  # noqa: E402
from dastml.dataset import load, matrix  # noqa: E402
from dastml.evaluation import bootstrap_endpoints, clusters, endpoint_metrics, row_metrics  # noqa: E402
from dastml.features import FEATURE_NAMES_V2, FEATURE_NAMES_V3, LOCATION_FEATURES  # noqa: E402
from dastml.model import GRIDS, THRESHOLDS, DastModel  # noqa: E402
from dastml.paths import paths  # noqa: E402

REPORTS = ROOT / "reports"
THRESHOLDS_V4 = [round(x, 2) for x in np.arange(0.2, 0.96, 0.05)] + [0.97, 0.98, 0.99, 0.995]
NAMES = FEATURE_NAMES_V2 + [f for f in FEATURE_NAMES_V3 if f not in FEATURE_NAMES_V2]
ORIGINS = ("real", "own", "third-party", "benchmark")


def fsets(system):
    sets = {"v2": FEATURE_NAMES_V2, "v3": FEATURE_NAMES_V3} if system == "v4" else {"v2": FEATURE_NAMES_V2}
    out = {}
    for tag, names in sets.items():
        out[f"{tag}_all"] = [NAMES.index(n) for n in names]
        out[f"{tag}_no_loc"] = [NAMES.index(n) for n in names if n not in LOCATION_FEATURES]
    return out


def inner_select(kind, rows, X, y, groups, FS, thresholds):
    best = (-1.0, None, None)
    for fset, cols in FS.items():
        for params in GRIDS[kind]:
            proba = np.zeros((len(rows), len(CLASSES)))
            for g in sorted(set(groups)):
                te = groups == g
                if len(set(y[~te])) < 2:
                    continue
                proba[te] = DastModel(kind, params).fit(X[~te][:, cols], y[~te]).predict_proba(X[te][:, cols])
            for t in thresholds:
                score = endpoint_metrics(clusters(rows, proba, t), "real")["macro_f1"]
                if score > best[0] + 1e-9:
                    best = (score, {**params, "fset": fset}, t)
    return best


def _fold(kind, g, rows, X, y, groups, FS, thresholds):
    """One outer fold (independent of the others; run in parallel processes, same computation as serially)."""
    te = groups == g
    tr_rows = [r for r, m in zip(rows, ~te) if m]
    score, params, t = inner_select(kind, tr_rows, X[~te], y[~te], groups[~te], FS, thresholds)
    p = dict(params)
    cols = FS[p.pop("fset")]
    return g, score, params, t, DastModel(kind, p).fit(X[~te][:, cols], y[~te]).predict_proba(X[te][:, cols])


def run_kind(kind, rows, X, y, groups, FS, thresholds):
    import os
    from joblib import Parallel, delayed
    proba = np.zeros((len(rows), len(CLASSES)))
    pooled, folds = {}, {}
    jobs = int(os.environ.get("LOAO_FOLD_JOBS", "1"))
    out = Parallel(n_jobs=jobs, backend="loky")(delayed(_fold)(kind, g, rows, X, y, groups, FS, thresholds) for g in sorted(set(groups)))
    for g, score, params, t, pr in out:
        te = groups == g
        proba[te] = pr
        te_rows = [r for r, m in zip(rows, te) if m]
        cl = clusters(te_rows, proba[te], t)
        pooled.update(cl)
        folds[g] = {"params": params, "threshold": t, "inner_macro_f1": score, "endpoint": endpoint_metrics(cl), "row": row_metrics(te_rows, proba[te], t)}
        print(f"  [{kind}] test={g:16} params={params} t={t} inner={score:.3f} endpoint mF1={folds[g]['endpoint']['macro_f1']:.3f}", flush=True)
    return folds, pooled


def main(system="v4", kinds=("lr", "lgbm")):
    t0 = time.time()
    tag = "_v4" if system == "v4" else "_v4data_v2system"
    for f in (REPORTS / f"loao{tag}.json", REPORTS / f"loao_clusters{tag}.json"):
        if f.exists():
            sys.exit(f"{f} exists; reports are never overwritten")
    rows = load(directory=paths("v4")["features"])
    X, y = matrix(rows, NAMES)
    groups = np.array([r["group"] for r in rows])
    FS, thresholds = fsets(system), (THRESHOLDS_V4 if system == "v4" else list(THRESHOLDS))
    res = {"system": system, "feature_sets": {k: len(v) for k, v in FS.items()}, "thresholds": thresholds, "apps": sorted(set(groups)),
           "n_rows": len(rows), "rows_by_origin": {o: sum(r["origin"] == o for r in rows) for o in ("own", "third-party", "benchmark")}, "systems": {}}
    pooled = {}
    for kind in kinds:
        folds, cl = run_kind(kind, rows, X, y, groups, FS, thresholds)
        pooled[kind] = cl
        res["systems"][kind] = {"folds": folds, "endpoint": {o: endpoint_metrics(cl, o) for o in ORIGINS}}
    res["bootstrap"] = {o: bootstrap_endpoints(pooled, origin=o) for o in ORIGINS}
    (REPORTS / f"loao_clusters{tag}.json").write_text(json.dumps({k: {c: list(v) for c, v in cl.items()} for k, cl in pooled.items()}, indent=0) + "\n")
    res["seconds"] = round(time.time() - t0)
    (REPORTS / f"loao{tag}.json").write_text(json.dumps(res, indent=1) + "\n")
    write_md(res, tag)
    print(f"done in {res['seconds']}s")


def write_md(res, tag):
    L = [f"# ml-dast leave-one-app-out: {'v4 candidates' if res['system'] == 'v4' else 'the v2 system'} on the v4 data", "",
         f"Rows {res['n_rows']} ({res['rows_by_origin']}). Groups: {', '.join(res['apps'])}. Feature sets: {res['feature_sets']}. "
         f"Thresholds: {res['thresholds']}.",
         "**real** = own + third-party apps (the headline). **benchmark** = BenchmarkPython, one group, in-benchmark numbers only: "
         "they say nothing about generalization to real apps.", ""]
    for o in ORIGINS:
        b = res["bootstrap"][o]
        L += [f"## {o} ({b['n_clusters']} endpoint-params)", "", "| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) |", "|---|---|---|---|---|"]
        for k, s in res["systems"].items():
            e = s["endpoint"][o]
            pc = e["per_class"]
            cc = b["per_class_f1_ci95"][k]
            f = lambda c: f"{pc[c]['precision']:.2f}/{pc[c]['recall']:.2f}/{pc[c]['f1']:.2f} ({pc[c]['support']}) [{cc[c][0]:.2f}, {cc[c][1]:.2f}]"
            L.append(f"| {k} | {e['macro_f1']:.3f} [{b['macro_f1'][k]['ci95'][0]:.3f}, {b['macro_f1'][k]['ci95'][1]:.3f}] | {f('CWE-89')} | {f('CWE-79')} | {pc['safe']['f1']:.2f} ({pc['safe']['support']}) |")
        L += [""] + [f"- {k}: {d['mean']:+.3f} [{d['ci95'][0]:+.3f}, {d['ci95'][1]:+.3f}]" for k, d in b["differences"].items()] + [""]
    L += ["## Per fold", "", "| Test group | " + " | ".join(res["systems"]) + " |", "|---|" + "---|" * len(res["systems"])]
    for g in res["apps"]:
        L.append(f"| {g} | " + " | ".join(f"{s['folds'][g]['endpoint']['macro_f1']:.3f} (t={s['folds'][g]['threshold']}, {s['folds'][g]['params']['fset']})" for s in res["systems"].values()) + " |")
    (REPORTS / f"loao{tag}.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", default="v4", choices=["v4", "v2"])
    ap.add_argument("--kinds", default="lr,lgbm")
    a = ap.parse_args()
    main(a.system, tuple(a.kinds.split(",")))
