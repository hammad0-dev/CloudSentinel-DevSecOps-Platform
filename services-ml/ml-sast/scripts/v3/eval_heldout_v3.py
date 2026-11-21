"""Score the frozen RealVuln held-out sets EXACTLY ONCE: v2 (deployed) and the pre-selected v3 system only.

Refuses if reports/v3/heldout_final.json exists, if the held-out rows no longer match data/heldout_v3/FREEZE.json,
or if reports/v3/heldout_preregistration.json is missing, uncommitted, or names model files whose SHA-256 changed.
Metrics as v2 (sastml.evaluation): per-class P/R/F1, macro-F1, binary precision/recall, 95% bootstrap over units
(1000 resamples, paired v3 - v2). Sets: python, node, and both together (the decision uses both together).
Usage: python -I scripts/v3/eval_heldout_v3.py
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import os  # noqa: E402
os.environ.setdefault("HF_HOME", "/mnt/d/cs-data/hf-cache")
os.environ.setdefault("HF_HUB_OFFLINE", "1")
from sastml.evaluation import bootstrap, metrics  # noqa: E402

OUT = ROOT / "reports/v3/heldout_final.json"
PRE = ROOT / "reports/v3/heldout_preregistration.json"
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def committed(path):
    rel = str(path.relative_to(ROOT.parents[1]))
    t = subprocess.run(["git", "ls-files", "--error-unmatch", rel], cwd=ROOT.parents[1], capture_output=True).returncode == 0
    c = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", rel], cwd=ROOT.parents[1]).returncode == 0
    return t and c


def main():
    if OUT.exists():
        sys.exit("the held-out sets have already been scored once; refusing to score them again")
    chk = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/v3/build_heldout_v3.py")], capture_output=True, text=True)
    if chk.returncode != 0:
        sys.exit("held-out rows differ from FREEZE.json:\n" + chk.stdout[-2000:] + chk.stderr[-2000:])
    pre = json.loads(PRE.read_text())
    if not committed(PRE):
        sys.exit("heldout_preregistration.json must be committed before scoring")
    for k in ("v2", "v3"):
        if sha(ROOT / pre[f"{k}_model"]) != pre[f"{k}_sha256"]:
            sys.exit(f"{k} model changed after the pre-registration")
    models = {k: joblib.load(ROOT / pre[f"{k}_model"]) for k in ("v2", "v3")}
    sets = {n: [r for r in (json.loads(l) for l in open(ROOT / f"data/heldout_v3/{n}.jsonl")) if not r["excluded"]] for n in ("python", "node")}
    sets["all"] = sets["python"] + sets["node"]
    preds = {}
    for n in ("python", "node"):
        rows = sets[n]
        codes, langs = [r["code"] for r in rows], [r["lang"] for r in rows]
        preds[n] = {k: np.asarray(m.decide(codes, langs)) for k, m in models.items()}
    preds["all"] = {k: np.concatenate([preds["python"][k], preds["node"][k]]) for k in ("v2", "v3")}
    out = {"preregistration": pre, "sets": {}}
    for n, rows in sets.items():
        res = {k: metrics(rows, None, pred=p) for k, p in preds[n].items()}
        boot = bootstrap(rows, {"v3": preds[n]["v3"], "v2": preds[n]["v2"]})
        out["sets"][n] = {"units": len(rows), "vulnerable": sum(1 for r in rows if r["label"] != "safe"), "metrics": res, "bootstrap": boot}
    a = out["sets"]["all"]
    m3, m2 = a["metrics"]["v3"], a["metrics"]["v2"]
    diff = a["bootstrap"]["differences"]["v3 - v2"]
    cond = {"macro_f1_higher": m3["macro_f1"] > m2["macro_f1"],
            "precision_not_worse": m3["binary"]["precision"] >= m2["binary"]["precision"],
            "improvement_beyond_noise": diff["ci95"][0] > 0}
    out["decision"] = {"conditions": cond, "v3_replaces_v2": all(cond.values()), "rule": pre["decision_rule"],
                       "note": "even if all conditions hold, deployment needs the user's approval"}
    OUT.write_text(json.dumps(out, indent=1, default=float) + "\n")
    for n, s in out["sets"].items():
        for k in ("v2", "v3"):
            m = s["metrics"][k]
            ci = s["bootstrap"]["macro_f1"][k]["ci95"]
            print(f"{n:6} {k}: macro-F1 {m['macro_f1']:.3f} [{ci[0]:.3f}, {ci[1]:.3f}]  P {m['binary']['precision']:.3f}  R {m['binary']['recall']:.3f}")
        d = s["bootstrap"]["differences"]["v3 - v2"]
        print(f"{n:6} v3 - v2: {d['mean']:+.3f} [{d['ci95'][0]:+.3f}, {d['ci95'][1]:+.3f}]")
    print(json.dumps(out["decision"], indent=1))


if __name__ == "__main__":
    main()
