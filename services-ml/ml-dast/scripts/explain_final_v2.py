"""Explain (never re-score) the single DSVW run: for each true SQLi/XSS endpoint-param, the highest model
probability for its class, the payload, and the largest feature contributions (LR). Reads the stored
DSVW feature rows and the shipped v2 model; writes reports/final_dsvw_explain.json.
"""
import json
import sys
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dastml import CLASSES  # noqa: E402
from dastml.dataset import load, matrix  # noqa: E402
from dastml.paths import paths  # noqa: E402

if not (ROOT / "reports/final_dsvw.json").exists():
    sys.exit("explain only after the single scored run")
det = joblib.load(ROOT / "models/release_v2/model.joblib")
rows = [r for r in load(final=True, directory=paths("v2")["features"]) if r["app"] == "dsvw"]
X, _ = matrix(rows, det.feature_names)
P = det.model.predict_proba(X)
lr = det.model.est.named_steps.get("logisticregression")
sc = det.model.est.named_steps.get("standardscaler")
out = {}
for cl in sorted({r["cluster"] for r in rows}):
    for cls in (1, 2):
        idx = [i for i, r in enumerate(rows) if r["cluster"] == cl and r["payload_class"] == CLASSES[cls]]
        if not idx or not any(rows[i]["label"] == CLASSES[cls] for i in idx):
            continue
        b = max(idx, key=lambda i: P[i, cls])
        z = sc.transform(X[b:b + 1])[0]
        k, c0 = list(lr.classes_).index(cls), list(lr.classes_).index(0)
        contrib = (lr.coef_[k] - lr.coef_[c0]) * z
        top = np.argsort(-np.abs(contrib))[:6]
        out[f"{cl} {CLASSES[cls]}"] = {"max_p": round(float(P[b, cls]), 3), "threshold": det.threshold, "payload": rows[b]["payload_id"],
                                       "top": {det.feature_names[j]: [round(float(X[b, j]), 2), round(float(contrib[j]), 2)] for j in top},
                                       "signals": {k: rows[b]["features"][k] for k in ("status", "sql_err_new", "stack_trace_new", "ct_html", "ct_text", "parity_flip", "dose_confirmed", "pair_diff_over_noise")}}
(ROOT / "reports/final_dsvw_explain.json").write_text(json.dumps(out, indent=1) + "\n")
print(json.dumps(out, indent=1))
