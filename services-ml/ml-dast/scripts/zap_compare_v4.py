"""Compare ml-dast v4 with the offline ZAP full scan on the same units, per class ZAP can find.

ZAP ran unmodified (lab/zap-scan.sh), unauthenticated, without seeds, with the dangerous parameters and
paths on ZAP's GLOBAL exclude list (spider, scanner and proxy; lab/zap-scan-v3.sh). Reports:
logs/zap_v3/<app>.json for apps that changed in v3 (own apps, vulnerable-node, VAmPI, node-api-goat,
DSVW, SirAppSec); unchanged apps reuse logs/zap_v2 or logs/zap (stated in the output). A scan whose
target was killed or whose wrapper did not exit 0 is never used (logs/zap_v3/<app>.status).
The v2 DSVW scan (killed) is never read.

* ML classes (CWE-89 plugins 40018-40027/90018, CWE-79 40012/40014): same endpoint-param clusters as
  the pooled v2 leave-one-app-out (reports/loao_clusters_v2.json), paired cluster bootstrap.
* Rule classes (CWE-78 plugin 90020, CWE-22 plugin 6, CWE-601 plugin 20019): same probed units as
  scripts/eval_rules.py; counts.
* Passive (CSP 10038, nosniff 10021, anti-clickjacking 10020, cookie HttpOnly 10010, SameSite 10054,
  CORS 10098/40040): one unit per (app, check); counts.
* Stored XSS (rule) vs ZAP persistent-XSS plugins 40014/40016/40017; CSRF heuristic vs ZAP 10202
  (Absence of Anti-CSRF Tokens, reported on the page that holds the form): counts.
v4: training apps are unchanged since v3, so their v3 ZAP scans are reused (BenchmarkPython is not scanned: its
code-injection and deserialization cases could not be kept out of ZAP's reach). Benchmark clusters are excluded.
Usage: python scripts/zap_compare_v4.py [--kind lr] [--final]   (--final: DVPWA only, logs/zap_v4/dvpwa.json)
"""
import argparse
import collections
import gzip
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dastml import CLASSES  # noqa: E402
from dastml.crawl import InjectionPoint  # noqa: E402
from dastml.evaluation import bootstrap_endpoints, endpoint_metrics  # noqa: E402
from dastml.groundtruth import GroundTruth  # noqa: E402
from dastml.paths import paths  # noqa: E402

PLUGINS = {"CWE-89": {"40018", "40019", "40020", "40021", "40022", "40024", "40027", "90018"}, "CWE-79": {"40012", "40014"},
           "CWE-78": {"90020"}, "CWE-22": {"6"}, "CWE-601": {"20019"}}
PASSIVE_PLUGINS = {"missing-csp": {"10038"}, "missing-nosniff": {"10021"}, "missing-frame-protection": {"10020"},
                   "cookie-no-httponly": {"10010"}, "cookie-no-samesite": {"10054"}, "cors-any-origin": {"10098", "40040"}}
P = paths("v4")
STORED_PLUGINS, CSRF_PLUGINS = {"40014", "40016", "40017"}, {"10202"}
NEVER_USE = {("zap_v2", "dsvw")}  # the v2 DSVW scan was killed mid-scan


def report(app):
    v3 = ROOT / ("logs/zap_v4" if app == "dvpwa" else "logs/zap_v3")
    if (v3 / f"{app}.json").exists():
        status = (v3 / f"{app}.status").read_text().strip() if (v3 / f"{app}.status").exists() else "missing status"
        if not status.startswith("ok"):
            return None, f"v3 scan NOT USED ({status})"
        return json.loads((v3 / f"{app}.json").read_text()), ("v4 scan" if app == "dvpwa" else "v3 scan")
    for d, label in ((ROOT / "logs/zap_v2", "v2 scan (app unchanged in v3)"), (ROOT / "logs/zap", "v1 scan (app unchanged since v1)")):
        if (d.name, app) in NEVER_USE:
            continue
        if (d / f"{app}.json").exists():
            return json.loads((d / f"{app}.json").read_text()), label
    return None, "no ZAP report"


def alerts(rep):
    out = []
    for site in rep.get("site", []):
        for a in site.get("alerts", []):
            for inst in a.get("instances", []):
                out.append((str(a.get("pluginid")), inst.get("method", "GET").upper(), urlsplit(inst.get("uri", "")).path, inst.get("param", "") or ""))
    return out


def unit_of(gt, app, method, path, param, cls=None):
    for loc in ({"query", "path"} if method == "GET" else {"form", "json", "query"}):
        point = InjectionPoint(method, path, param or "{seg}", loc)
        e = gt.entry(app, point) or (gt.entry(app, InjectionPoint(method, path, "{seg9}", "path")) if loc == "path" else None)
        if e is not None:
            p = e["params"][0] if loc == "path" else param
            return f"{app}|{method}|{e['path']}|{p}" + (f"#{cls}" if cls and len(set(e["vuln"]) & {"CWE-89", "CWE-79"}) > 1 else ""), e
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", default=None)
    ap.add_argument("--apps", default="")
    ap.add_argument("--final", action="store_true")
    a = ap.parse_args()
    gt = GroundTruth(P["ground_truth"])
    if a.final:
        apps = ["dvpwa"]
        fin = json.loads((ROOT / "reports/final_dvpwa.json").read_text())
        ml = {k: (v["true"], v["pred"], "third-party", "dvpwa") for k, v in fin["ml"]["v4"]["clusters"].items()}
    else:
        apps = a.apps.split(",") if a.apps else [x for x, m in gt.apps().items() if m["role"] == "train_loao"]
        kind = a.kind or json.loads((ROOT / "reports/selection_v4.json").read_text())["family"]
        ml = {k: tuple(v) for k, v in json.loads((ROOT / "reports/loao_clusters_v4.json").read_text())[kind].items() if v[2] != "benchmark"}
        apps = [x for x in apps if gt.apps()[x]["origin"] != "benchmark"]
    sources, zap_ml = {}, collections.defaultdict(int)
    rule_hits, passive_hits = collections.defaultdict(set), collections.defaultdict(set)
    stored_hits, csrf_pages = collections.defaultdict(set), collections.defaultdict(set)
    for app in apps:
        rep, label = report(app)
        sources[app] = label
        if rep is None:
            continue
        for pid, method, path, param in alerts(rep):
            for cls, ids in PLUGINS.items():
                if pid not in ids:
                    continue
                unit, _ = unit_of(gt, app, method, path, param, cls if cls in ("CWE-89", "CWE-79") else None)
                if unit is None:
                    continue
                if cls in ("CWE-89", "CWE-79") and unit in ml:
                    zap_ml[unit] = zap_ml[unit] or CLASSES.index(cls)
                elif cls not in ("CWE-89", "CWE-79"):
                    rule_hits[cls].add(unit)
            for check, ids in PASSIVE_PLUGINS.items():
                if pid in ids:
                    passive_hits[check].add(app)
            if pid in STORED_PLUGINS:
                stored_hits[app].add(param)
            if pid in CSRF_PLUGINS:
                csrf_pages[app].add(path)
    scanned = [x for x in apps if sources[x] in ("v3 scan", "v4 scan") or sources[x].startswith(("v2 scan", "v1 scan"))]  # unusable scans (NOT USED) are excluded, never scored as zero
    common = {k: v for k, v in ml.items() if v[3] in scanned}
    zap = {k: (v[0], zap_ml.get(k, 0), v[2], v[3]) for k, v in common.items()}
    out = {"apps": apps, "zap_sources": sources, "n_common_clusters": len(common),
           "ml_classes": {o or "all": {"ml": endpoint_metrics(common, o), "zap": endpoint_metrics(zap, o)} for o in (None, "own", "third-party")},
           "bootstrap": {o or "all": bootstrap_endpoints({"ml": common, "zap": zap}, origin=o) for o in (None, "own", "third-party")} if common else {}}
    # rule classes: units from the stored probe records, as in eval_rules.py
    import eval_rules
    import eval_rules_v3
    eval_rules.P = eval_rules_v3.P = P  # v4: both modules read the v4 records
    from dastml.probe import load_payloads
    payloads = load_payloads(("CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-601"), P["payloads"])
    active, passive = eval_rules.evaluate(scanned, gt, payloads)
    rules = {}
    for cls, d in active.items():
        units = set(d["known"]) | {x.split(": ")[0] for x in d["false_alarms"]}
        safe_units = d["safe_units"]
        z = rule_hits[cls]
        rules[cls] = {"known": len(d["known"]), "ml_dast_found": len(d["found"]), "zap_found": len(set(d["known"]) & z),
                      "ml_dast_false_alarms": len(d["false_alarms"]), "zap_false_alarms_on_listed_safe": len(z - set(d["known"])),
                      "safe_units": safe_units, "zap_missed": sorted(set(d["known"]) - z)}
    pas = {}
    for check, d in passive.items():
        z = passive_hits[check]
        pas[check] = {"known": len(d["known"]), "ml_dast_found": len(d["found"]), "zap_found": len(set(d["known"]) & z),
                      "ml_dast_false_alarms": len(d["false_alarms"]), "zap_false_alarms": len(z - set(d["known"])), "negatives": d["negatives"]}
    out["rules"], out["passive"] = rules, pas
    # stored XSS: a ZAP persistent-XSS alert on the same app naming the written parameter
    gtj = json.loads(P["ground_truth"].read_text())
    st = eval_rules_v3.evaluate_stored(scanned, gtj)
    param_of = lambda u: u.split("[", 1)[1].split("]", 1)[0]
    z_st = {u for u in st["known"] if param_of(u) in stored_hits[u.split("|")[0]]}
    out["stored_xss"] = {"known": len(st["known"]), "ml_dast_found": len(st["found"]), "zap_found": len(z_st),
                         "ml_dast_false_alarms": len(st["false_alarms"]), "safe_units": st["safe_units"], "zap_missed": sorted(set(st["known"]) - z_st),
                         "zap_persistent_alerts": {k: sorted(v) for k, v in stored_hits.items()}}
    # CSRF: ZAP reports on the page holding the form; map pages to form actions with the crawl's forms
    cs = eval_rules_v3.evaluate_csrf(scanned, gtj)
    z_cs = set()
    for u in cs["known"]:
        app, action = u.split("|")[0], u.split("POST ")[1]
        f = P["raw"] / f"{app}.forms.json"
        forms = json.loads(f.read_text()) if f.exists() else []
        rx = eval_rules_v3._rx(action)
        if any(rx.match(fm["action"]) and fm["page"] in csrf_pages[app] for fm in forms):
            z_cs.add(u)
    out["csrf_heuristic"] = {"known": len(cs["known"]), "ml_dast_found": len(cs["found"]), "zap_found": len(z_cs),
                             "ml_dast_false_alarms": len(cs["false_alarms"]), "safe_units": cs["safe_units"], "zap_missed": sorted(set(cs["known"]) - z_cs),
                             "zap_10202_pages": {k: sorted(v) for k, v in csrf_pages.items()}}
    name = "zap_comparison_v4_final" if a.final else "zap_comparison_v4"
    (ROOT / f"reports/{name}.json").write_text(json.dumps(out, indent=1) + "\n")
    L = [f"# ml-dast v4 vs offline ZAP ({'DVPWA, final held-out' if a.final else 'real training apps, pooled leave-one-app-out predictions'})", "",
         "ZAP: unmodified zap-full-scan.py (offline image), unauthenticated, no seeds. Sources: " + "; ".join(f"{k}: {v}" for k, v in sources.items()), ""]
    if common:
        L += ["## SQLi / XSS (ML) on the same endpoint-params", "", "| Set | System | macro-F1 [95% CI] | SQLi TP/FP/FN | XSS TP/FP/FN |", "|---|---|---|---|---|"]
        for o in ("all", "own", "third-party"):
            b = out["bootstrap"][o]
            for s in ("ml", "zap"):
                m = out["ml_classes"][o][s]
                t = lambda c: f"{m['per_class'][c]['tp']}/{m['per_class'][c]['fp']}/{m['per_class'][c]['fn']}"
                L.append(f"| {o} ({b['n_clusters']}) | {'ml-dast' if s == 'ml' else 'ZAP'} | {m['macro_f1']:.3f} [{b['macro_f1'][s]['ci95'][0]:.3f}, {b['macro_f1'][s]['ci95'][1]:.3f}] | {t('CWE-89')} | {t('CWE-79')} |")
            d = b["differences"]["ml - zap"]
            L.append(f"| {o} | difference ml-dast - ZAP | {d['mean']:+.3f} [{d['ci95'][0]:+.3f}, {d['ci95'][1]:+.3f}] | | |")
        L.append("")
    L += ["## Rule classes (counts)", "", "| Class | Known | ml-dast rule found | ZAP found | ml-dast false alarms | ZAP alerts on listed safe endpoints | Safe units |", "|---|---|---|---|---|---|---|"]
    L += [f"| {c} | {r['known']} | {r['ml_dast_found']} | {r['zap_found']} | {r['ml_dast_false_alarms']} | {r['zap_false_alarms_on_listed_safe']} | {r['safe_units']} |" for c, r in rules.items()]
    L += ["", "## Passive checks (per app, counts)", "", "| Check | Apps with the issue | ml-dast found | ZAP found | ml-dast false alarms | ZAP false alarms | Apps without |", "|---|---|---|---|---|---|---|"]
    L += [f"| {c} | {r['known']} | {r['ml_dast_found']} | {r['zap_found']} | {r['ml_dast_false_alarms']} | {r['zap_false_alarms']} | {r['negatives']} |" for c, r in pas.items()]
    L += ["", "## Stored XSS and CSRF (counts)", "", "| Check | Known | ml-dast found | ZAP found | ml-dast false alarms | Safe units |", "|---|---|---|---|---|---|"]
    for c in ("stored_xss", "csrf_heuristic"):
        r = out[c]
        L.append(f"| {c} | {r['known']} | {r['ml_dast_found']} | {r['zap_found']} | {r['ml_dast_false_alarms']} | {r['safe_units']} |")
    (ROOT / f"reports/{name}.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
