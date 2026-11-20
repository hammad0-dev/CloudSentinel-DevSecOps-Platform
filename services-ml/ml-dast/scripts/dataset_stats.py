"""Stage-2 statistics and leakage checks for the ml-dast feature dataset (DVNA excluded).

Writes data/dast/manifest.json -> "dataset" and prints a summary:
* rows / endpoint-param clusters per app and label, imbalance;
* identical feature vectors with conflicting labels (label noise / unlearnable rows);
* app predictability from features (5-fold RF): how strongly rows fingerprint their app;
* per-app rates of key signals among positives and negatives (do signals transfer across apps?);
* two RULE-BASED reference detectors (not ML), evaluated per app, as sanity anchors.
"""
import collections
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dastml import CLASSES  # noqa: E402
from dastml.dataset import load, matrix  # noqa: E402
from dastml.features import FEATURE_NAMES  # noqa: E402

KEY = ["sql_err_new", "pair_diff_over_noise", "time_over_1s", "status_changed", "payload_raw_reflected", "angle_kept", "ctx_text", "ct_html"]


def rule_sqli(f):
    return f["payload_sqli"] and (f["sql_err_new"] or f["time_over_1s"] or (f["pair_present"] and f["pair_diff_over_noise"] > 0.5))


def rule_xss(f):
    return f["payload_xss"] and f["ct_html"] and f["payload_raw_reflected"] and not f["ctx_none"]


def main():
    rows = load()
    apps = sorted({r["app"] for r in rows})
    out = {"apps": {}, "note": "DVNA (final held-out) excluded; counts only are recorded for it in collection_summary.json"}
    for a in apps:
        rs = [r for r in rows if r["app"] == a]
        lab = collections.Counter(r["label"] for r in rs)
        clusters = collections.defaultdict(set)
        for r in rs:
            clusters[r["label"]].add(r["cluster"])
        out["apps"][a] = {"origin": rs[0]["origin"], "group": rs[0]["group"], "rows": len(rs), "rows_by_label": dict(lab),
                          "clusters_by_label": {k: len(v) for k, v in clusters.items()}, "clusters_total": len({r["cluster"] for r in rs})}
    lab = collections.Counter(r["label"] for r in rows)
    out["total"] = {"rows": len(rows), "rows_by_label": dict(lab), "clusters": len({r["cluster"] for r in rows}),
                    "positive_clusters": {c: len({r["cluster"] for r in rows if r["label"] == c}) for c in CLASSES[1:]},
                    "imbalance_safe_per_positive": round(lab["safe"] / max(1, sum(v for k, v in lab.items() if k != "safe")), 2)}

    X, y = matrix(rows)
    seen = collections.defaultdict(set)
    for xi, yi in zip(map(bytes, np.round(X, 4)), y):
        seen[xi].add(int(yi))
    conflict_vecs = {k for k, v in seen.items() if len(v) > 1}
    conflict_rows = sum(1 for xi in map(bytes, np.round(X, 4)) if xi in conflict_vecs)
    out["label_conflicts"] = {"identical_vectors_with_different_labels": len(conflict_vecs), "rows_affected": conflict_rows,
                              "share": round(conflict_rows / len(rows), 4)}

    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score
    groups = np.array([r["group"] for r in rows])
    acc = cross_val_score(RandomForestClassifier(200, n_jobs=-1, random_state=0), X, groups, cv=5).mean()
    majority = collections.Counter(groups).most_common(1)[0][1] / len(groups)
    out["app_predictability"] = {"rf_5fold_accuracy": round(float(acc), 3), "majority_baseline": round(majority, 3)}

    sig = {}
    for a in apps:
        rs = [r for r in rows if r["app"] == a]
        sig[a] = {}
        for cls, pcls in (("CWE-89", "CWE-89"), ("CWE-79", "CWE-79")):
            pos = [r for r in rs if r["label"] == cls]
            neg = [r for r in rs if r["label"] == "safe" and r["payload_class"] == pcls]
            sig[a][cls] = {k: [round(np.mean([r["features"][k] for r in pos]), 3) if pos else None,
                               round(np.mean([r["features"][k] for r in neg]), 3) if neg else None] for k in KEY}
    out["signal_rates_pos_vs_neg"] = sig

    ref = {}
    for a in apps + ["ALL"]:
        rs = rows if a == "ALL" else [r for r in rows if r["app"] == a]
        res = {}
        for cls, rule in (("CWE-89", rule_sqli), ("CWE-79", rule_xss)):
            # endpoint-param level: a cluster is flagged if any of its rows fires
            cl = collections.defaultdict(lambda: [False, False])
            for r in rs:
                if r["payload_class"] != cls:
                    continue
                c = cl[r["cluster"]]
                c[0] |= r["label"] == cls
                c[1] |= bool(rule(r["features"]))
            tp = sum(1 for t, p in cl.values() if t and p)
            fp = sum(1 for t, p in cl.values() if not t and p)
            fn = sum(1 for t, p in cl.values() if t and not p)
            res[cls] = {"tp": tp, "fp": fp, "fn": fn}
        ref[a] = res
    out["rule_based_reference_endpoint_level"] = ref

    manifest_path = ROOT / "data/dast/manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    manifest["dataset"] = out
    manifest["feature_names"] = FEATURE_NAMES
    manifest_path.write_text(json.dumps(manifest, indent=1) + "\n")
    print(json.dumps({k: v for k, v in out.items() if k != "signal_rates_pos_vs_neg"}, indent=1))
    print("signal rates [pos, neg]:")
    for a, d in sig.items():
        for cls, s in d.items():
            print(f"  {a:11} {cls}: " + " ".join(f"{k}={v[0]}/{v[1]}" for k, v in s.items()))


if __name__ == "__main__":
    main()
