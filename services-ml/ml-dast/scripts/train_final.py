"""Train the final ml-dast model on all 6 training app groups (DVNA never loaded).

The model family is fixed by reports/selection.json (written before DVNA is scored). Hyperparameters
and the decision threshold are chosen by the same inner leave-one-app-out procedure as in
scripts/loao.py, now over all 6 groups. Writes models/release/model.joblib (a DastDetector: crawl,
probe, featurize, classify) and model.json (metadata for /model-info).
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
from dastml import CLASSES  # noqa: E402
from dastml.dataset import load, matrix  # noqa: E402
from dastml.detector import DastDetector  # noqa: E402
from dastml.features import FEATURE_NAMES  # noqa: E402
from dastml.model import DastModel  # noqa: E402
from loao import inner_select  # noqa: E402

LIMITATIONS = [
    "Classes: SQL injection (CWE-89) and reflected XSS (CWE-79) only; command injection and path traversal are not covered yet.",
    "Trained on 6 lab app groups (3 written by the same author as the payloads and features); third-party evidence rests on Juice Shop, NodeGoat and vulpy.",
    "Reflected XSS only: stored and DOM-based XSS are not detected; JSON/text reflections are treated as safe.",
    "Blind SQL injection is detected only through boolean-pair contrast or 1 s time payloads (MySQL/PostgreSQL); SQLite has no time payload.",
    "No authentication support in /scan: pages behind a login are not reached.",
    "The crawler follows HTML links and forms only; single-page-app APIs need seeds.",
    "Every request is subject to the target allowlist, same-origin rule, budgets and rate limit (dastml/guards.py).",
]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    sel = json.loads((ROOT / "reports/selection.json").read_text())
    kind = sel["family"]
    rows = load()
    X, y = matrix(rows)
    groups = np.array([r["group"] for r in rows])
    score, params, t = inner_select(kind, rows, X, y, groups)
    model = DastModel(kind, params).fit(X, y)
    loao = json.loads((ROOT / "reports/loao.json").read_text())
    pick = lambda m: {"macro_f1": m["macro_f1"], "binary": m["binary"], "per_class": {c: {k: v for k, v in d.items()} for c, d in m["per_class"].items()}}
    info = {"name": f"ml-dast-{kind}", "version": "1.0.0", "threshold": t}
    detector = DastDetector(model, t, FEATURE_NAMES, info)
    rel = ROOT / "models/release"
    rel.mkdir(parents=True, exist_ok=True)
    joblib.dump(detector, rel / "model.joblib")
    manifest = json.loads((ROOT / "data/dast/manifest.json").read_text())
    meta = {
        "name": info["name"], "version": "1.0.0", "packaged_at": datetime.date.today().isoformat(), "sha256": sha(rel / "model.joblib"),
        "classes": CLASSES, "threshold": t, "params": params, "selection": sel,
        "components": {"ml": {"type": "machine-learning", "model": f"{kind} over {len(FEATURE_NAMES)} response features"},
                       "payloads": {"type": "fixed list", "source": "data/dast/payloads/payloads.json (own list, see PAYLOADS.md)"},
                       "rules": {"type": "none", "note": "no rule-based detector in the shipped decision; rule baselines appear in reports only"}},
        "trained_on": {"apps": sorted(set(groups)), "rows": len(rows), "rows_by_label": manifest["dataset"]["total"]["rows_by_label"],
                       "endpoint_params": manifest["dataset"]["total"]["clusters"], "inner_loao_macro_f1": score,
                       "own_vs_third_party_rows": {o: sum(1 for r in rows if r["origin"] == o) for o in ("own", "third-party")}},
        "metrics": {"leave_one_app_out": {o: pick(loao["systems"][kind]["endpoint"][o]) for o in ("all", "own", "third-party")},
                    "leave_one_app_out_bootstrap": {o: loao["bootstrap"][o]["macro_f1"][kind] for o in ("all", "own", "third-party")}},
        "limitations": LIMITATIONS,
    }
    final = ROOT / "reports/final_dvna.json"
    if final.exists():
        f = json.loads(final.read_text())
        meta["metrics"]["final_heldout_dvna_single_run"] = f["summary"]
    (rel / "model.json").write_text(json.dumps(meta, indent=1) + "\n")
    print(f"{kind} params={params} t={t} inner={score:.3f} sha256={meta['sha256'][:12]}")


if __name__ == "__main__":
    main()
