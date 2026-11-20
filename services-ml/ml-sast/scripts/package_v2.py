"""Package the v2 hybrid for the ml-sast service: models/release_v2/model.joblib + model.json.

The metadata states the components explicitly: the ML part (RF+LightGBM ensemble) and the
RULE-BASED secrets detector for CWE-798. Metrics come from reports/v2/*.json; the fresh-set result is
merged in after scripts/eval_fresh_final.py has run (--with-fresh).
Usage: python scripts/package_v2.py --hybrid models/hybrid_step4.joblib --tag step4 [--with-fresh]
"""
import argparse
import datetime
import hashlib
import json
import shutil
import sys
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sastml import CLASSES  # noqa: E402

LIMITATIONS = [
    "Hybrid: CWE-798 findings come from a RULE-BASED secrets detector (sastml/secrets.py), not from machine learning.",
    "Function-level ML classifier for the other classes: reports the function start line, not the sink line; no inter-procedural or cross-file taint tracking.",
    "Vulnerabilities whose sink is in a template (|safe, <%- %>, autoescape off) are essentially invisible.",
    "CWE-327 and CWE-502 still have little real training data; CWE-798 ML training data is synthetic only (the rules carry that class).",
    "Thresholds, ensemble weight and secrets rules were tuned on the development set (NodeGoat, DVNA, vulpy, PyGoat); development scores are optimistic.",
    "CodeBERT was NOT retrained on the v2 data; its reported numbers are v1.",
    "Python and JavaScript only; TypeScript and minified/bundled files are skipped.",
]


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hybrid", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--version", default="2.0.0")
    ap.add_argument("--with-fresh", action="store_true")
    args = ap.parse_args()
    rel = ROOT / "models/release_v2"
    rel.mkdir(parents=True, exist_ok=True)
    model_path = rel / "model.joblib"
    if not args.with_fresh or not model_path.exists():
        shutil.copy2(ROOT / args.hybrid, model_path)
    model = joblib.load(model_path)
    dev = json.loads((ROOT / f"reports/v2/{args.tag}_dev.json").read_text())
    manifest = json.loads((ROOT / "data/manifest.json").read_text())
    hybrid_key = next(k for k in dev["systems"] if k.endswith("_hybrid"))
    pick = lambda m: {"n": m["n"], "macro_f1": m["macro_f1"], "binary": m["binary"], "per_class": m["per_class"]}
    meta = {
        "name": "ml-sast-hybrid", "version": args.version, "kind": "hybrid", "packaged_at": datetime.date.today().isoformat(),
        "sha256": sha(model_path), "classes": CLASSES, "threshold": min(model.thresholds.values()), "thresholds": model.thresholds,
        "components": {
            "ml": {"type": "machine-learning", "model": "RF + LightGBM probability ensemble", "weight_rf": model.weight,
                   "classes": [c for c in CLASSES[1:] if not (c == "CWE-798" and model.secrets_mode == "rules")]},
            "secrets": {"type": "rule-based", "module": "sastml/secrets.py", "class": "CWE-798", "mode": model.secrets_mode,
                        "note": "CWE-798 findings marked '.rule' / '[rule-based secrets detector]' come from deterministic rules, not ML."},
        },
        "trained_on": {"train": manifest["splits"]["train"]["total"], "train_by_origin": manifest["splits"]["train"]["by_origin"],
                       "real_train_by_class_lang": manifest["splits"]["train"]["by_class_lang_real"],
                       "sources": ["CrossVul (Zenodo 4734050)", "OSV GitHub-reviewed npm/PyPI advisories -> fix commits", "synthetic (sastml/synthetic.py)"],
                       "osv_label_noise_estimate": manifest["sources"].get("osv", {}).get("quality")},
        "metrics": {
            "development_set": {"note": "tuned on this set; optimistic", "hybrid_all": pick(dev["systems"][hybrid_key]["all"]),
                                "hybrid_code_visible": pick(dev["systems"][hybrid_key]["code_visible"]),
                                "ml_only_all": pick(dev["systems"][next(k for k in dev["systems"] if k.endswith('_ml_only'))]["all"]),
                                "secrets_rule_based_dev": json.loads((ROOT / "reports/v2/secrets_dev.json").read_text())["precision"] if (ROOT / "reports/v2/secrets_dev.json").exists() else None,
                                "bootstrap_macro_f1": dev["bootstrap_all"]["macro_f1"]},
        },
        "limitations": LIMITATIONS,
    }
    if args.with_fresh:
        fresh = json.loads((ROOT / "reports/v2/fresh_final.json").read_text())
        meta["metrics"]["fresh_heldout_single_run"] = {view: {"n": v["n"], **{k: pick(m) for k, m in v["systems"].items()},
                                                              "bootstrap_macro_f1": v["bootstrap"]["macro_f1"]} for view, v in fresh["views"].items()}
    (rel / "model.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"packaged {args.hybrid} -> models/release_v2/model.joblib sha256={meta['sha256'][:12]}")


if __name__ == "__main__":
    main()
