"""Pick the service model by held-out macro-F1 and package it for ml-sast.

Selection: highest ``heldout_all`` macro-F1 at the model's own validation-chosen threshold (the decision
rule the service uses); ties broken by ``heldout_code``. Output: models/release/model.joblib (or
models/release/model/ for CodeBERT) + model.json with name, version, training-data summary, metrics,
threshold, data flags and limitations. Point the service at it with MODEL_PATH.
Usage: python scripts/package_model.py [--model NAME] [--version X.Y.Z]
"""
import argparse
import datetime
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sastml import CLASSES  # noqa: E402

LIMITATIONS = [
    "Function-level classifier: reports the function start line, not the exact sink line; one finding per function.",
    "No inter-procedural or cross-file taint tracking; vulnerabilities whose sink is in a template (e.g. |safe, <%- %>) are mostly invisible.",
    "CWE-798 and CWE-327 have no or almost no real training data (synthetic only); CWE-502 is mostly synthetic.",
    "Held-out evaluation set is small (48 vulnerable units); per-class scores have wide uncertainty.",
    "Python and JavaScript only; TypeScript and minified/bundled files are skipped.",
]


def score(m, s):
    r = m["sets"].get(s, {})
    r = r.get("threshold") or r.get("argmax")
    return r["macro_f1"] if r else -1


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model")
    ap.add_argument("--version", default="1.0.0")
    args = ap.parse_args()
    comp = json.loads((ROOT / "reports/comparison.json").read_text())
    ranking = sorted(comp["models"], key=lambda n: (score(comp["models"][n], "heldout_all"), score(comp["models"][n], "heldout_code")), reverse=True)
    name = args.model or ranking[0]
    chosen = comp["models"][name]
    manifest = json.loads((ROOT / "data/manifest.json").read_text())
    rel = ROOT / "models/release"
    if rel.exists():
        shutil.rmtree(rel)
    rel.mkdir(parents=True)
    if name == "codebert":
        shutil.copytree(ROOT / "models/codebert", rel / "model")
        weights = next(p for p in (rel / "model/model.safetensors", rel / "model/pytorch_model.bin") if p.exists())
        meta_path, model_path = rel / "model/cloudsentinel.json", rel / "model"
    else:
        shutil.copy2(ROOT / f"models/{name}.joblib", rel / "model.joblib")
        weights, meta_path, model_path = rel / "model.joblib", rel / "model.json", rel / "model.joblib"
    pick = lambda s: {k: chosen["sets"][s][("threshold" if chosen["sets"][s].get("threshold") else "argmax")][k] for k in ("n", "macro_f1", "binary", "per_class")}
    meta = {
        "name": chosen["model"], "version": args.version, "kind": name, "threshold": chosen["threshold"], "classes": CLASSES,
        "packaged_at": datetime.date.today().isoformat(), "sha256": sha256(weights),
        "selection": {"rule": "max held-out (all) macro-F1 at the validation-chosen threshold", "ranking": [{"model": n, "heldout_all": score(comp["models"][n], "heldout_all"),
                      "heldout_code": score(comp["models"][n], "heldout_code")} for n in ranking]},
        "trained_on": {"train": manifest["splits"]["train"]["total"], "train_by_origin": manifest["splits"]["train"]["by_origin"],
                       "train_by_class_lang": manifest["splits"]["train"]["by_class_lang"], "real_source": "CrossVul (Zenodo 4734050)",
                       "synthetic_source": "sastml/synthetic.py", "split_policy": manifest["split_policy"]},
        "metrics": {"val_macro_f1": chosen.get("val_macro_f1"), **{s: pick(s) for s in ("test", "test_real", "heldout_all", "heldout_code")}},
        "data_flags": comp["data_flags"], "sonarqube_comparison": comp["sonarqube"], "limitations": LIMITATIONS,
    }
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")
    (ROOT / "reports/selected_model.json").write_text(json.dumps({k: meta[k] for k in ("name", "version", "kind", "threshold", "sha256", "selection", "metrics")}, indent=2) + "\n")
    print(f"selected {name} -> MODEL_PATH={model_path.relative_to(ROOT)} sha256={meta['sha256'][:12]}")


if __name__ == "__main__":
    main()
