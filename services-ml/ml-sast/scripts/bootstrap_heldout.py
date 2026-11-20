"""Bootstrap 95% intervals of held-out macro-F1 (at each model's threshold) and of pairwise differences.

Resamples held-out units with replacement (1000x). Writes reports/heldout_bootstrap.json.
Usage: python scripts/bootstrap_heldout.py [model ...]
"""
import json
import os
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("HF_HOME", str(ROOT / ".hf"))
from eval_sast import available_models, load_model, proba_for  # noqa: E402
from sastml.evaluation import load, metrics  # noqa: E402


def main(names):
    rows_all = load("heldout")
    keep = [i for i, r in enumerate(rows_all) if not r["excluded"]]
    rows = [rows_all[i] for i in keep]
    probas = {}
    for n in names:
        m = load_model(n)
        probas[n] = (proba_for(n, m, "heldout", rows_all)[keep], m.info.get("threshold"))
    rng = np.random.default_rng(0)
    samples = {n: [] for n in names}
    for _ in range(1000):
        idx = rng.integers(0, len(rows), len(rows))
        sub = [rows[i] for i in idx]
        for n, (p, t) in probas.items():
            samples[n].append(metrics(sub, p[idx], t)["macro_f1"])
    ci = lambda a: [float(np.percentile(a, 2.5)), float(np.percentile(a, 97.5))]
    out = {"n_units": len(rows), "resamples": 1000,
           "macro_f1": {n: {"point": metrics(rows, p, t)["macro_f1"], "ci95": ci(samples[n])} for n, (p, t) in probas.items()},
           "differences": {f"{a}-{b}": {"mean": float(np.mean(np.subtract(samples[a], samples[b]))), "ci95": ci(np.subtract(samples[a], samples[b]))}
                           for i, a in enumerate(names) for b in names[i + 1:]}}
    (ROOT / "reports/heldout_bootstrap.json").write_text(json.dumps(out, indent=2) + "\n")
    for n, v in out["macro_f1"].items():
        print(f"{n:13} {v['point']:.3f}  95% CI [{v['ci95'][0]:.3f}, {v['ci95'][1]:.3f}]")
    for k, v in out["differences"].items():
        print(f"{k:22} diff {v['mean']:+.3f}  95% CI [{v['ci95'][0]:+.3f}, {v['ci95'][1]:+.3f}]")


if __name__ == "__main__":
    main(sys.argv[1:] or available_models())
