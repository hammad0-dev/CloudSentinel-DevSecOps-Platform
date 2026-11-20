"""Train the v2 ml-dast model on all training app groups (DVNA and DSVW are never loaded).

Family from reports/selection_v2.json; hyperparameters, feature set (with/without location) and
threshold by the same inner leave-one-app-out as scripts/loao.py, now over all groups. Writes
models/release_v2/model.joblib (a DastDetector with data_version "v2": ML for CWE-89/CWE-79 plus the
rule-based CWE-78/CWE-22/CWE-601 and passive checks of dastml/rules.py) and model.json.
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
import loao  # noqa: E402
from dastml import CLASSES  # noqa: E402
from dastml.dataset import load, matrix  # noqa: E402
from dastml.detector import RULE_CLASSES, DastDetector  # noqa: E402
from dastml.features import FEATURE_NAMES_V2, LOCATION_FEATURES  # noqa: E402
from dastml.model import DastModel  # noqa: E402
from dastml.paths import paths  # noqa: E402
from dastml.rules import PASSIVE, PASSIVE_SEVERITY  # noqa: E402

VERSION = "2.0.0"
LIMITATIONS = [
    "ML classes: SQL injection (CWE-89) and reflected XSS (CWE-79). CWE-78, CWE-22, CWE-601 and the passive header/cookie/CORS checks are deterministic rules, not ML.",
    "Rule-based classes were evaluated on very few known instances (see reports/rules_v2.md); their counts are not rates.",
    "Trained on 8 lab app groups; 3 are written by the same author as the payloads and features.",
    "Reflected XSS only: stored and DOM XSS are not detected; JSON/text reflections are treated as safe.",
    "Quote-parity and timing signals also fire for shell quoting; when the CWE-78 rule confirms command injection on a parameter, the SQLi score yields to it.",
    "Passive checks are LOW/INFO, never gate-blocking; cookies set only after a login are not seen by /scan (no authentication support).",
    "No authentication support in /scan; the crawler follows HTML links and forms only (single-page-app APIs need seeds or an OpenAPI document).",
    "Every request is subject to the target allowlist, same-origin rule, budgets, rate limit, skip lists and the URL-in-parameter refusal (dastml/guards.py).",
]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    sel = json.loads((ROOT / "reports/selection_v2.json").read_text())
    kind = sel["family"]
    rows = load(directory=paths("v2")["features"])
    X, y = matrix(rows, FEATURE_NAMES_V2)
    groups = np.array([r["group"] for r in rows])
    loao.FSETS = {"all": list(range(len(FEATURE_NAMES_V2))),
                  "no_loc": [i for i, n in enumerate(FEATURE_NAMES_V2) if n not in LOCATION_FEATURES]}
    score, params, t = loao.inner_select(kind, rows, X, y, groups)
    mp, cols = loao.fit_cols(params)
    names = [FEATURE_NAMES_V2[i] for i in cols]
    model = DastModel(kind, mp).fit(X[:, cols], y)
    info = {"name": f"ml-dast-{kind}", "version": VERSION, "threshold": t}
    det = DastDetector(model, t, names, info)
    det.data_version, det.payloads_file = "v2", "payloads_v2.json"
    rel = ROOT / "models/release_v2"
    rel.mkdir(parents=True, exist_ok=True)
    joblib.dump(det, rel / "model.joblib")
    res = json.loads((ROOT / "reports/loao_v2.json").read_text())
    rules = json.loads((ROOT / "reports/rules_v2.json").read_text()) if (ROOT / "reports/rules_v2.json").exists() else None
    pick = lambda m: {"macro_f1": m["macro_f1"], "binary": m["binary"], "per_class": m["per_class"]}
    meta = {
        "name": info["name"], "version": VERSION, "packaged_at": datetime.date.today().isoformat(), "sha256": sha(rel / "model.joblib"),
        "classes": CLASSES + list(RULE_CLASSES), "threshold": t, "params": params, "selection": sel, "data_version": "v2",
        "components": {"ml": {"type": "machine-learning", "model": f"{kind} over {len(names)} response features", "classes": CLASSES[1:]},
                       "rules": {"type": "rule-based", "classes": list(RULE_CLASSES), "source": "dastml/rules.py"},
                       "passive": {"type": "rule-based", "checks": {k: PASSIVE_SEVERITY[k] for k in PASSIVE}, "gate": "never blocking (LOW/INFO)"},
                       "payloads": {"type": "fixed list", "source": "data/dast/payloads/payloads_v2.json"}},
        "trained_on": {"apps": sorted(set(groups)), "rows": len(rows), "inner_loao_macro_f1": score,
                       "rows_by_label": {c: sum(r["label"] == c for r in rows) for c in CLASSES},
                       "own_vs_third_party_rows": {o: sum(r["origin"] == o for r in rows) for o in ("own", "third-party")}},
        "metrics": {"leave_one_app_out": {o: pick(res["systems"][kind]["endpoint"][o]) for o in ("all", "own", "third-party")},
                    "leave_one_app_out_bootstrap": {o: res["bootstrap"][o]["macro_f1"][kind] for o in ("all", "own", "third-party")},
                    "leave_one_app_out_per_class_f1_ci95": res["bootstrap"]["all"]["per_class_f1_ci95"][kind],
                    **({"rules_counts": {c: {k: len(v) if isinstance(v, list) else v for k, v in d.items() if k != "false_alarms"} | {"false_alarms": len(d["false_alarms"])}
                                         for c, d in rules["active"].items()}} if rules else {})},
        "limitations": LIMITATIONS,
    }
    final = ROOT / "reports/final_dsvw.json"
    if final.exists():
        meta["metrics"]["final_heldout_dsvw_single_run"] = json.loads(final.read_text())["summary"]
    (rel / "model.json").write_text(json.dumps(meta, indent=1) + "\n")
    print(f"{kind} params={params} t={t} inner={score:.3f} features={len(names)} sha256={meta['sha256'][:12]}")


if __name__ == "__main__":
    main()
