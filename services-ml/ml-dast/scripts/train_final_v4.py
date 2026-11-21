"""Train the v4 ml-dast model on all training groups (DVNA, SirAppSec and DVPWA are never loaded).

Family from reports/selection_v4.json; feature set (v2/v3 x location), hyperparameters and threshold by the same
inner leave-one-app-out as scripts/loao_v4.py, now over all groups (non-benchmark clusters score the selection).
Writes models/release_v4/model.joblib (a DastDetector with data_version "v4": scans like v3, i.e. ML for
CWE-89/CWE-79 plus the rule-based checks) and model.json. Never overwrites an existing release.
"""
import datetime
import hashlib
import json
import sys
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import loao_v4  # noqa: E402
from dastml import CLASSES  # noqa: E402
from dastml.dataset import load, matrix  # noqa: E402
from dastml.detector import RULE_CLASSES, DastDetector  # noqa: E402
from dastml.model import DastModel  # noqa: E402
from dastml.paths import paths  # noqa: E402
from dastml.rules import PASSIVE, PASSIVE_SEVERITY  # noqa: E402

VERSION = "4.0.0"
LIMITATIONS = [
    "ML classes: SQL injection (CWE-89) and reflected XSS (CWE-79). CWE-78, CWE-22, CWE-601, stored XSS, the CSRF heuristic and the passive checks are deterministic rules, not ML.",
    "Training includes OWASP BenchmarkPython (a synthetic benchmark, one leave-one-app-out group); its in-benchmark numbers do not measure generalization to real apps.",
    "Feature set chosen by inner leave-one-app-out between the existing v2 and v3 sets; no new features in v4.",
    "Rule-based classes were evaluated on few known instances (reports/rules_v4.md); counts, not rates.",
    "No authenticated scanning in /scan; stored XSS behind a login, on uncrawled sink pages, or written by GET is not found; CSRF is a heuristic (LOW).",
    "Every request is subject to the target allowlist, same-origin rule, budgets, rate limit, skip lists and the URL-in-parameter refusal (dastml/guards.py).",
]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    rel = ROOT / "models/release_v4"
    if (rel / "model.joblib").exists():
        sys.exit("models/release_v4/model.joblib exists; a release is never overwritten")
    sel = json.loads((ROOT / "reports/selection_v4.json").read_text())
    kind = sel["family"]
    rows = load(directory=paths("v4")["features"])
    X, y = matrix(rows, loao_v4.NAMES)
    groups = np.array([r["group"] for r in rows])
    FS = loao_v4.fsets("v4")
    score, params, t = loao_v4.inner_select(kind, rows, X, y, groups, FS, loao_v4.THRESHOLDS_V4)
    p = dict(params)
    fset = p.pop("fset")
    cols = FS[fset]
    names = [loao_v4.NAMES[i] for i in cols]
    model = DastModel(kind, p).fit(X[:, cols], y)
    info = {"name": f"ml-dast-{kind}", "version": VERSION, "threshold": t}
    det = DastDetector(model, t, names, info)
    det.data_version, det.payloads_file = "v4", "payloads_v2.json"
    rel.mkdir(parents=True, exist_ok=True)
    joblib.dump(det, rel / "model.joblib")
    res = json.loads((ROOT / "reports/loao_v4.json").read_text())
    pick = lambda m: {"macro_f1": m["macro_f1"], "binary": m["binary"], "per_class": m["per_class"]}
    meta = {
        "name": info["name"], "version": VERSION, "packaged_at": datetime.date.today().isoformat(), "sha256": sha(rel / "model.joblib"),
        "classes": CLASSES + list(RULE_CLASSES), "threshold": t, "params": params, "feature_set": fset, "n_features": len(names),
        "selection": sel, "data_version": "v4", "default": False,
        "components": {"ml": {"type": "machine-learning", "model": f"{kind} over {len(names)} response features ({fset})", "classes": CLASSES[1:]},
                       "rules": {"type": "rule-based", "classes": list(RULE_CLASSES) + ["CWE-79 (stored)", "CWE-352 (heuristic)"]},
                       "passive": {"type": "rule-based", "checks": {k: PASSIVE_SEVERITY[k] for k in PASSIVE}, "gate": "never blocking (LOW/INFO)"}},
        "trained_on": {"apps": sorted(set(groups)), "rows": len(rows), "inner_loao_macro_f1_real": score,
                       "rows_by_label": {c: sum(r["label"] == c for r in rows) for c in CLASSES},
                       "rows_by_origin": {o: sum(r["origin"] == o for r in rows) for o in ("own", "third-party", "benchmark")}},
        "metrics": {"leave_one_app_out": {o: pick(res["systems"][kind]["endpoint"][o]) for o in loao_v4.ORIGINS},
                    "leave_one_app_out_bootstrap": {o: res["bootstrap"][o]["macro_f1"][kind] for o in loao_v4.ORIGINS}},
        "limitations": LIMITATIONS,
    }
    (rel / "model.json").write_text(json.dumps(meta, indent=1) + "\n")
    print(f"{kind} params={params} t={t} inner={score:.3f} features={len(names)} sha256={meta['sha256'][:12]}")


if __name__ == "__main__":
    main()
