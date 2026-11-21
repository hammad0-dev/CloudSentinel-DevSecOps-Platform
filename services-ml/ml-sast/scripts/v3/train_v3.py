"""ml-sast v3 training, exactly as pre-registered in reports/v3/selection_preregistration.json.

Steps (each cached under /mnt/d/cs-data/sast-v3/work/train_v3[_<tag>]/, so an interrupted run resumes):
  emb    CodeBERT embeddings (frozen, mean-pooled, 256 tokens) of every train/val/test/development row
  oof    5-fold GroupKFold over train+val: out-of-fold probabilities for A (RF), every B (LightGBM) config and
         every C (CodeBERT+XGBoost) config; B and C configs picked by out-of-fold macro-F1
  thr    per-model thresholds from the out-of-fold probabilities (global grid; per-class only if +0.02)
  fit    final A, B, C refit on train+val (sample weights = source policy x balanced class weights)
  dev    development set: A, B, C alone (+ secrets rule), R1/R2/R3, v2; selection by the pre-registered criterion
Outputs: models/v3[_<tag>]/{rf,lgbm,codebert_xgb}.joblib, models/v3[_<tag>]/ensemble_selected.joblib,
reports/v3/dev_comparison[_<tag>].json. The frozen held-out sets are never loaded here.
Usage: python -I scripts/v3/train_v3.py [--data data/processed_v3] [--tag nosyn] [--only-selected]
"""
import argparse
import collections
import json
import os
import sys
import time
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("HF_HOME", "/mnt/d/cs-data/hf-cache")
os.environ.setdefault("HF_HUB_OFFLINE", "1")  # the base model is already cached; never download
from sastml import CLASSES  # noqa: E402
from sastml.codebert import CodeBertXGB, embed  # noqa: E402
from sastml.ensemble_v3 import NAMES, EnsembleV3  # noqa: E402
from sastml.evaluation import bootstrap, decide, metrics  # noqa: E402
from sastml.hybrid import HybridModel  # noqa: E402
from sastml.model import SastModel  # noqa: E402

PRE = json.loads((ROOT / "reports/v3/selection_preregistration.json").read_text())
GRID_T = (0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.5, 0.6, 0.7)
FEAT = {"max_features": 8000, "ngram_range": (1, 2)}
SECRET = CLASSES.index("CWE-798")


def log(msg):
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


def load(p):
    return [json.loads(l) for l in open(p)]


def class_weights(y):
    counts = np.bincount(y, minlength=len(CLASSES)).astype(float)
    w = np.zeros(len(CLASSES))
    nz = counts > 0
    w[nz] = len(y) / (nz.sum() * counts[nz])
    return w[y]


def flags_from(p, thr):
    t = np.array([1.1] + [thr[c] for c in CLASSES[1:]])
    return p >= t


def single_label(p, thr, codes, secrets=True):
    """One model's single-label decision under its per-class thresholds; CWE-798 from the secrets rule (as v2 'rules')."""
    out = []
    from sastml.secrets import unit_confidence
    fl = flags_from(p, thr)
    for i in range(len(p)):
        cands = {ci: p[i, ci] for ci in range(1, len(CLASSES)) if ci != SECRET and fl[i, ci]}
        if secrets:
            sc, hits = unit_confidence(codes[i])
            if hits:
                cands[SECRET] = max(cands.get(SECRET, 0), sc)
        out.append(max(cands, key=cands.get) if cands else 0)
    return np.array(out)


def tune_thresholds(rows, p, codes):
    best = (-1, None)
    for t in GRID_T:
        thr = {c: t for c in CLASSES[1:]}
        s = metrics(rows, None, pred=single_label(p, thr, codes, secrets=False))["macro_f1"]
        if s > best[0]:
            best = (s, thr)
    s_glob, glob = best
    per, s_per = dict(glob), s_glob
    for _ in range(2):
        for c in CLASSES[1:]:
            if c == "CWE-798":
                continue
            for t in GRID_T:
                trial = {**per, c: t}
                s = metrics(rows, None, pred=single_label(p, trial, codes, secrets=False))["macro_f1"]
                if s > s_per + 1e-9:
                    s_per, per = s, trial
    use_per = s_per >= s_glob + 0.02
    return (per if use_per else glob), {"oof_macro_f1_global": s_glob, "oof_macro_f1_per_class": s_per, "per_class_used": use_per}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/processed_v3")
    ap.add_argument("--tag", default="")
    ap.add_argument("--only-selected", action="store_true", help="ablation: reuse the main run's selected rule/configs")
    args = ap.parse_args()
    sfx = f"_{args.tag}" if args.tag else ""
    W = Path(f"/mnt/d/cs-data/sast-v3/work/train_v3{sfx}")
    W.mkdir(parents=True, exist_ok=True)
    mdir = ROOT / f"models/v3{sfx}"
    mdir.mkdir(parents=True, exist_ok=True)
    D = ROOT / args.data
    tv = load(D / "train.jsonl") + load(D / "val.jsonl")
    test = load(D / "test.jsonl")
    dev = [r for r in load(ROOT / "data/processed/heldout.jsonl") if not r["excluded"]]
    codes, langs = [r["code"] for r in tv], [r["lang"] for r in tv]
    y = np.array([CLASSES.index(r["label"]) for r in tv])
    sw_src = np.array([r.get("weight", 1.0) for r in tv])  # RF/LightGBM: SastModel applies balanced class weights itself
    sw = sw_src * class_weights(y)                          # XGBoost: source weight x balanced class weight
    groups = np.array([r["source"] for r in tv])
    timing = {}

    # emb
    def emb(name, rows):
        p = W / f"emb_{name}.npy"
        if p.exists():
            return np.load(p)
        t0 = time.time()
        X = embed([r["code"] for r in rows], [r["lang"] for r in rows], max_len=256, batch=32)
        np.save(p, X)
        timing[f"embed_{name}_s"] = round(time.time() - t0)
        log(f"embedded {name} {X.shape} in {time.time() - t0:.0f}s")
        return X
    E_tv, E_test, E_dev = emb("trainval", tv), emb("test", test), emb("dev", dev)

    # oof
    from sklearn.model_selection import GroupKFold
    folds = list(GroupKFold(n_splits=5).split(codes, y, groups))
    ref = json.loads(json.dumps(PRE["base_models"]))
    cfgs = {"rf": [ref["A_rf"]["params"]], "lgbm": ref["B_lgbm"]["grid"], "codebert_xgb": ref["C_codebert_xgb"]["grid"]}
    if args.only_selected:
        main_sel = json.loads((ROOT / "reports/v3/dev_comparison.json").read_text())["chosen_configs"]
        cfgs = {k: [main_sel[k]] for k in cfgs}

    def make(kind, cfg):
        if kind == "codebert_xgb":
            from xgboost import XGBClassifier
            return XGBClassifier(objective="multi:softprob", tree_method="hist", n_jobs=8, random_state=0,
                                 learning_rate=0.05, subsample=0.8, colsample_bytree=0.5, num_class=len(CLASSES), **cfg)
        return SastModel(kind, cfg, FEAT)

    def fit_predict(kind, cfg, tr, te, Xte_rows=None, E_te=None):
        if kind == "codebert_xgb":
            est = make(kind, cfg)
            est.fit(E_tv[tr], y[tr], sample_weight=sw[tr])
            p = np.zeros((len(te) if E_te is None else len(E_te), len(CLASSES)), dtype=np.float32)
            pr = est.predict_proba(E_tv[te] if E_te is None else E_te)
            p[:, list(est.classes_)] = pr
            return est, p
        m = make(kind, cfg).fit([codes[i] for i in tr], [langs[i] for i in tr], [CLASSES[y[i]] for i in tr], sample_weight=sw_src[tr])
        rows = Xte_rows if Xte_rows is not None else [tv[i] for i in te]
        return m, m.predict_proba([r["code"] for r in rows], [r["lang"] for r in rows])

    oof, chosen, oof_scores = {}, {}, {}
    for kind in NAMES:
        best = None
        for k, cfg in enumerate(cfgs[kind]):
            cache = W / f"oof_{kind}_{k}.npy"
            if cache.exists():
                p = np.load(cache)
            else:
                t0 = time.time()
                p = np.zeros((len(tv), len(CLASSES)), dtype=np.float32)
                for fi, (tr, te) in enumerate(folds):
                    _, p[te] = fit_predict(kind, cfg, tr, te)
                np.save(cache, p)
                timing[f"oof_{kind}_{k}_s"] = round(time.time() - t0)
                log(f"oof {kind} cfg{k} {cfg} done in {time.time() - t0:.0f}s")
            s = metrics(tv, p)["macro_f1"]
            oof_scores[f"{kind}:{json.dumps(cfg, sort_keys=True)}"] = s
            if best is None or s > best[0]:
                best = (s, k, cfg, p)
        oof[kind], chosen[kind] = best[3], best[2]
        log(f"{kind}: chosen {best[2]} oof macro-F1 (argmax) {best[0]:.3f}")

    # thr
    thresholds, thr_info = {}, {}
    for kind in NAMES:
        thresholds[kind], thr_info[kind] = tune_thresholds(tv, oof[kind], codes)
        log(f"{kind} thresholds {thresholds[kind]} {thr_info[kind]}")

    # fit
    final, fit_time = {}, {}
    alli = np.arange(len(tv))
    for kind in NAMES:
        path = mdir / f"{kind}.joblib"
        if path.exists():
            final[kind] = joblib.load(path)
            continue
        t0 = time.time()
        if kind == "codebert_xgb":
            est = make(kind, chosen[kind])
            est.fit(E_tv, y, sample_weight=sw)
            m = CodeBertXGB(est, {"name": "ml-sast-v3-codebert-xgb", "params": chosen[kind], "base_model": "microsoft/codebert-base", "max_len": 256})
        else:
            m = make(kind, chosen[kind]).fit(codes, langs, [CLASSES[i] for i in y], sample_weight=sw_src)
            m.info = {"name": f"ml-sast-v3-{kind}", "params": chosen[kind], "featurizer": FEAT}
        fit_time[kind] = round(time.time() - t0)
        joblib.dump(m, path, compress=3)
        final[kind] = m
        log(f"fit {kind} in {fit_time[kind]}s -> {path.stat().st_size / 1e6:.1f} MB")

    # dev
    dcodes, dlangs = [r["code"] for r in dev], [r["lang"] for r in dev]
    probas, ptime = {}, {}
    for kind in NAMES:
        t0 = time.time()
        if kind == "codebert_xgb":
            probas[kind] = final[kind].predict_proba(dcodes, dlangs)  # embeds inside (timed end to end)
        else:
            probas[kind] = final[kind].predict_proba(dcodes, dlangs)
        ptime[kind] = time.time() - t0
    n_files = len({(r["app"], r["file"]) for r in dev})
    systems, sys_time = {}, {}
    for kind in NAMES:
        systems[f"base_{kind}"] = single_label(probas[kind], thresholds[kind], dcodes)
    per_class_f1 = {kind: metrics(dev, None, pred=systems[f"base_{kind}"])["per_class"] for kind in NAMES}
    routes = {}
    for c in CLASSES[1:]:
        if c == "CWE-798":
            continue
        routes[c] = max(NAMES, key=lambda k: (per_class_f1[k][c]["f1"], -NAMES.index(k)))
    ens = {}
    for rule in ("R1", "R2", "R3"):
        e = EnsembleV3(final, thresholds, rule, routes if rule == "R1" else None)
        t0 = time.time()
        systems[rule] = e.decide(dcodes, dlangs, probas)
        sys_time[rule] = time.time() - t0 + sum(ptime.values())
        ens[rule] = e
    v2 = joblib.load(ROOT / "models/release_v2/model.joblib")
    t0 = time.time()
    systems["v2"] = v2.decide(dcodes, dlangs)
    sys_time["v2"] = time.time() - t0
    for kind in NAMES:
        sys_time[f"base_{kind}"] = ptime[kind]
    res = {k: metrics(dev, None, pred=v) for k, v in systems.items()}
    boot = bootstrap(dev, systems)
    v2_prec = res["v2"]["binary"]["precision"]
    ok = [r for r in ("R1", "R2", "R3") if res[r]["binary"]["precision"] >= v2_prec]
    if ok:
        sel = max(ok, key=lambda r: (res[r]["macro_f1"], -("R1", "R2", "R3").index(r)))
        why = f"highest development macro-F1 among the rules with precision >= v2's ({v2_prec:.3f})"
    else:
        sel = max(("R1", "R2", "R3"), key=lambda r: res[r]["binary"]["precision"])
        why = f"no rule reached v2's development precision ({v2_prec:.3f}); the rule with the highest precision was selected (pre-registered fallback)"
    selected = ens[sel]
    selected.info = {"name": "ml-sast-v3-ensemble", "kind": "ensemble_v3", "rule": sel, "routes": routes if sel == "R1" else None,
                     "thresholds": thresholds, "base_models": {k: chosen[k] for k in NAMES}, "secrets": "rule-based (sastml/secrets.py)",
                     "threshold": min(min(v.values()) for v in thresholds.values()), "data": args.data,
                     "components": {"ml": f"RF + LightGBM + CodeBERT/XGBoost, rule {sel}", "CWE-798": "rule-based secrets detector"}}
    joblib.dump(selected, mdir / "ensemble_selected.joblib", compress=3)
    for rule, e in ens.items():
        joblib.dump(e, mdir / f"ensemble_{rule}.joblib", compress=3)
    sizes = {k: round((mdir / f"{k}.joblib").stat().st_size / 1e6, 2) for k in NAMES}
    sizes["codebert_base_weights"] = 499.0
    test_res = {}
    tcodes, tlangs = [r["code"] for r in test], [r["lang"] for r in test]
    tprob = {k: (final[k].predict_proba(None, None, embeddings=E_test) if k == "codebert_xgb" else final[k].predict_proba(tcodes, tlangs)) for k in NAMES}
    test_res[sel] = metrics(test, None, pred=selected.decide(tcodes, tlangs, tprob))
    test_res["v2"] = metrics(test, None, pred=v2.decide(tcodes, tlangs))
    report = {
        "preregistration": "reports/v3/selection_preregistration.json", "data": args.data, "tag": args.tag,
        "n_trainval": len(tv), "n_dev_units": len(dev), "n_dev_files": n_files, "chosen_configs": chosen, "oof_scores": oof_scores,
        "thresholds": thresholds, "threshold_tuning": thr_info, "routes_R1": routes,
        "dev": {k: {"macro_f1": v["macro_f1"], "ci95": boot["macro_f1"][k]["ci95"], "precision": v["binary"]["precision"], "recall": v["binary"]["recall"],
                    "per_class": v["per_class"], "scan_seconds": round(sys_time[k], 2),
                    "seconds_per_file": round(sys_time[k] / n_files, 4), "seconds_per_1000_functions": round(1000 * sys_time[k] / len(dev), 2)}
                for k, v in res.items()},
        "dev_bootstrap_differences": boot["differences"],
        "selected_rule": sel, "selection_reason": why, "v2_dev_precision": v2_prec,
        "training_seconds": {**fit_time, **timing}, "model_size_mb": sizes,
        "test_split_in_distribution": {k: {"macro_f1": v["macro_f1"], "precision": v["binary"]["precision"], "recall": v["binary"]["recall"]} for k, v in test_res.items()},
    }
    out = ROOT / f"reports/v3/dev_comparison{sfx}.json"
    out.write_text(json.dumps(report, indent=1, default=float) + "\n")
    for k, v in report["dev"].items():
        log(f"{k:20} dev mF1 {v['macro_f1']:.3f} [{v['ci95'][0]:.3f},{v['ci95'][1]:.3f}] P {v['precision']:.2f} R {v['recall']:.2f} {v['seconds_per_1000_functions']}s/1k")
    log(f"selected {sel}: {why}")


if __name__ == "__main__":
    main()
