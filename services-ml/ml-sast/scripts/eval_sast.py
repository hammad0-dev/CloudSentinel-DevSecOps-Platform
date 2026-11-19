"""Evaluate every trained ml-sast model on the test split and the held-out apps.

Sets: test, test_real (CrossVul part of test), heldout_all (incl. 5 template-sink XSS units),
heldout_code (without them). For each model and set: precision/recall/F1 per class, macro-F1, binary
vulnerable-vs-safe precision/recall, confusion matrix (PNG), at argmax and at the model's validation-
chosen threshold. Writes reports/<model>/*.json|png and reports/comparison.{json,csv,md}.

SonarQube: compared only if existing Sonar results for the held-out apps are available. None are, so the
comparison is recorded as a TODO. No numbers are produced for it.
Usage: python scripts/eval_sast.py [model ...]   (default: every model found in models/)
"""
import csv
import json
import os
import sys
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("HF_HOME", str(ROOT / ".hf"))
from sastml import CLASSES  # noqa: E402
from sastml.evaluation import load, metrics  # noqa: E402

REPORTS = ROOT / "reports"
SETS = ["test", "test_real", "heldout_all", "heldout_code"]
SYNTH_FLAG_MAX_REAL = 20  # a class with fewer real training rows than this is flagged as (mostly) synthetic
SONAR = {"status": "TODO", "reason": "No existing SonarQube results are available for NodeGoat, DVNA, vulpy or PyGoat at the pinned commits. "
         "No Sonar numbers are reported; run the existing SAST_ENGINE=sonar pipeline on these apps and map issues to units to fill this in."}


def available_models():
    found = []
    for k in ("lr", "rf", "lgbm", "codebert_xgb"):
        if (ROOT / f"models/{k}.joblib").exists():
            found.append(k)
    if (ROOT / "models/codebert/config.json").exists():
        found.append("codebert")
    return found


def load_model(name):
    if name == "codebert":
        from sastml.codebert import CodeBertClassifier
        return CodeBertClassifier(ROOT / "models/codebert")
    return joblib.load(ROOT / f"models/{name}.joblib")


def proba_for(name, model, split, rows):
    if name == "codebert_xgb":
        emb = ROOT / f"data/processed/emb_{split}.npy"
        if emb.exists():
            return model.predict_proba(None, None, embeddings=np.load(emb))
    return model.predict_proba([r["code"] for r in rows], [r["lang"] for r in rows])


def subsets(split, rows):
    if split == "test":
        return {"test": [True] * len(rows), "test_real": [r["origin"] == "crossvul" for r in rows]}
    keep = [not r["excluded"] for r in rows]
    return {"heldout_all": keep, "heldout_code": [k and not r["template_sink"] for k, r in zip(keep, rows)]}


def plot_confusion(cm, title, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    cm = np.array(cm)
    fig, ax = plt.subplots(figsize=(6.4, 5.4))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(CLASSES)), CLASSES, rotation=45, ha="right")
    ax.set_yticks(range(len(CLASSES)), CLASSES)
    ax.set_xlabel("predicted")
    ax.set_ylabel("true")
    ax.set_title(title, fontsize=10)
    for i in range(len(CLASSES)):
        for j in range(len(CLASSES)):
            if cm[i, j]:
                ax.text(j, i, int(cm[i, j]), ha="center", va="center", fontsize=8, color="white" if cm[i, j] > cm.max() / 2 else "black")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def data_flags():
    m = json.loads((ROOT / "data/manifest.json").read_text())
    real = m["splits"]["train"]["by_class_lang_real"]
    flags = {}
    for c in CLASSES:
        n = sum(real.get(c, {}).values())
        flags[c] = {"real_train_rows": n, "synthetic_only": n == 0, "mostly_synthetic": 0 < n < SYNTH_FLAG_MAX_REAL}
    return flags


def main(names):
    REPORTS.mkdir(exist_ok=True)
    data = {"test": load("test"), "heldout": load("heldout")}
    comparison = {"sets": SETS, "classes": CLASSES, "data_flags": data_flags(), "sonarqube": SONAR, "models": {}}
    old = REPORTS / "comparison.json"
    if old.exists():
        comparison["models"] = json.loads(old.read_text()).get("models", {})
    for name in names:
        model = load_model(name)
        thr = model.info.get("threshold")
        out = {"model": model.info.get("name", name), "threshold": thr, "sets": {}}
        (REPORTS / name).mkdir(exist_ok=True)
        for split, rows in data.items():
            P = proba_for(name, model, split, rows)
            for sname, mask in subsets(split, rows).items():
                idx = [i for i, k in enumerate(mask) if k]
                sub, sp = [rows[i] for i in idx], P[idx]
                res = {"argmax": metrics(sub, sp), "threshold": metrics(sub, sp, thr) if thr is not None else None}
                out["sets"][sname] = res
                (REPORTS / name / f"{sname}.json").write_text(json.dumps(res, indent=2) + "\n")
                plot_confusion(res["argmax"]["confusion"], f"{name} - {sname} (argmax)", REPORTS / name / f"confusion_{sname}.png")
            print(f"{name}: " + " ".join(f"{s}={out['sets'][s]['argmax']['macro_f1']:.3f}" for s in subsets(split, rows)), flush=True)
        out["val_macro_f1"] = model.info.get("val_macro_f1_argmax")
        comparison["models"][name] = out
    old.write_text(json.dumps(comparison, indent=2) + "\n")
    write_tables(comparison)


def write_tables(comp):
    rows = []
    for name, m in comp["models"].items():
        for s in SETS:
            for mode in ("argmax", "threshold"):
                r = m["sets"].get(s, {}).get(mode)
                if not r:
                    continue
                rows.append({"model": name, "set": s, "mode": mode, "threshold": m["threshold"] if mode == "threshold" else "", "n": r["n"],
                             "macro_f1": round(r["macro_f1"], 4), "accuracy": round(r["accuracy"], 4),
                             "vuln_precision": round(r["binary"]["precision"], 4), "vuln_recall": round(r["binary"]["recall"], 4),
                             **{f"f1_{c}": round(r["per_class"][c]["f1"], 4) for c in CLASSES}})
    with open(REPORTS / "comparison.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    flags = comp["data_flags"]
    tag = lambda c: c + (" (synthetic-only)" if flags[c]["synthetic_only"] else " (mostly synthetic)" if flags[c]["mostly_synthetic"] else "")
    lines = ["# ml-sast model comparison", "", "Macro-F1 over classes present in each set; argmax / validation-chosen threshold.", "",
             "| Model | val | test | test (real only) | held-out (all) | held-out (code-visible) |", "|---|---|---|---|---|---|"]
    for name, m in comp["models"].items():
        cell = lambda s: "/".join(f"{m['sets'][s][k]['macro_f1']:.3f}" for k in ("argmax", "threshold") if m["sets"].get(s, {}).get(k))
        lines.append(f"| {name} | {m.get('val_macro_f1') or 0:.3f} | {cell('test')} | {cell('test_real')} | {cell('heldout_all')} | {cell('heldout_code')} |")
    lines += ["", "Data flags (real CrossVul rows in train): " + ", ".join(f"{tag(c)}: {flags[c]['real_train_rows']}" for c in CLASSES if c != "safe"),
              "", f"SonarQube comparison: {comp['sonarqube']['status']} - {comp['sonarqube']['reason']}"]
    (REPORTS / "comparison.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main(sys.argv[1:] or available_models())
