"""DastDetector: the object stored in models/release/model.joblib and called by the ml-dast service.

scan(base_url, max_pages, max_requests) crawls the target, probes each discovered injection point with
the fixed payload list, featurizes every response and reports one finding per (endpoint, parameter,
class) whose highest model probability reaches the threshold. All traffic goes through
GuardedClient (allowlist, same origin, budgets, rate limit). When the request budget runs out the
scan stops and returns what it has; ``last_scan`` records coverage so callers can see it.
Optional ``seed_paths`` (extra start pages) and ``openapi_url`` (an OpenAPI document) widen the crawl
for apps whose endpoints are not linked from HTML; they pass the same guards as everything else.

v3 detectors (data_version "v3") add two rule-based checks: stored XSS (dastml.stored: a marker is
written to POST/PUT form and JSON fields and the crawled pages are re-fetched; disable with
ML_DAST_STORED_XSS=0) and the CSRF heuristic (LOW, confidence 0.5). Writes go through the same
guarded client, so they only ever reach allowlisted targets.
"""
import os
from urllib.parse import urljoin

import numpy as np

from . import CLASSES
from .crawl import crawl
from .guards import BudgetExceeded, GuardedClient, GuardError, TargetPolicy
from .probe import CORS_ORIGIN, PAYLOADS_PATH, load_payloads, new_marker, point_rows, probe_point, snapshot
from .rules import active_findings, csrf_findings, passive_findings, stored_xss_findings
from .stored import stored_pass

PAYLOADS_DIR = PAYLOADS_PATH.parent
RULE_CLASSES = ("CWE-78", "CWE-22", "CWE-601")  # deterministic rules in v2 detectors (dastml.rules), never ML

ALERTS = {
    "CWE-89": ("SQL Injection", "sql_injection", "HIGH", 89,
               "Use parameterized queries or an ORM query builder for every value from the request; never build SQL by string concatenation or formatting."),
    "CWE-79": ("Cross Site Scripting (Reflected)", "reflected_xss", "HIGH", 79,
               "Encode output for its context (HTML body, attribute, script) with the template engine's auto-escaping; validate input and set a Content-Security-Policy."),
}


def evidence(f, resp, base):
    parts = [f"status {resp['status']} (baseline {base['status']})"]
    if f["sql_err_new"]:
        parts.append("new SQL error signature in the response")
    if f["pair_present"] and f["pair_diff_over_noise"] > 0.5:
        parts.append(f"boolean true/false responses differ (similarity {f['pair_sim_true_false']:.2f})")
    if f["time_over_1s"]:
        parts.append(f"response delayed by {f['time_delta']:.2f}s")
    if f["payload_raw_reflected"]:
        ctx = next((c[4:] for c in ("ctx_text", "ctx_attr_dq", "ctx_attr_sq", "ctx_attr_unquoted", "ctx_script", "ctx_comment") if f[c]), "unknown")
        parts.append(f"payload reflected unencoded ({ctx} context, {resp['ctype'] or 'no content type'})")
    elif f["marker_reflected"]:
        parts.append("marker reflected, payload partly encoded")
    return "; ".join(parts)


class DastDetector:
    def __init__(self, model, threshold, feature_names, info, classes=("CWE-89", "CWE-79")):
        self.model, self.threshold, self.feature_names, self.info = model, float(threshold), list(feature_names), dict(info)
        self.classes = tuple(classes)
        self.last_scan = {}

    def scan(self, base_url, max_pages=50, max_requests=500, policy=None, seeds=(), threshold=None,
             seed_paths=(), openapi_url=None):
        """seed_paths: extra pages to crawl; openapi_url: same-origin OpenAPI/Swagger JSON whose
        GET/POST operations become injection points (dastml.openapi). Both go through the guards."""
        t = float(self.threshold if threshold is None else threshold)
        policy = policy or TargetPolicy.from_env()
        policy.max_pages, policy.max_requests = max_pages, max_requests
        client = GuardedClient(base_url, policy)  # raises GuardError for a refused target
        for path in seed_paths:
            client.check_url(path)  # an off-origin seed refuses the whole scan before any traffic
        if openapi_url:
            client.check_url(openapi_url)
        # v1 artifacts (pickled before v2) have neither attribute and keep the exact v1 behaviour.
        version = getattr(self, "data_version", "v1")
        v2, v3 = version in ("v2", "v3"), version == "v3"  # v3 = v2 behaviour + stored XSS + CSRF heuristic
        payload_path = PAYLOADS_DIR / getattr(self, "payloads_file", "payloads.json")
        payloads = load_payloads(tuple(self.classes) + (RULE_CLASSES if v2 else ()), payload_path)
        self.last_scan = {}  # errors from a previous scan must not leak into this one
        seeds = list(seeds)
        if openapi_url:
            from .openapi import load_points
            seeds += load_points(client, openapi_url)
        forms, pages = ([], []) if v3 else (None, None)
        points, visited = crawl(client, "/", seeds=seeds, start_paths=seed_paths, forms_out=forms, pages_out=pages)
        headers = []  # header snapshots of the baselines (v2+), for the CSRF heuristic
        findings, probed, stopped = [], 0, None
        for point in points:
            try:
                rec = probe_point(client, point, payloads, v2=v2) if v2 else probe_point(client, point, payloads)
            except BudgetExceeded as exc:
                stopped = str(exc)
                break
            except Exception as exc:  # one broken endpoint must not abort the scan
                stopped = None
                self.last_scan.setdefault("errors", []).append(f"{point.method} {point.path}: {type(exc).__name__}")
                continue
            probed += 1
            headers += [r for r in rec["responses"] if r.get("headers") is not None]
            endpoint = urljoin(base_url, point.path)[:500]
            rule_findings = active_findings(rec, payloads, base_url, endpoint) if v2 else []
            findings += rule_findings
            rows = [r for r in point_rows(rec, payloads) if r[0]["class"] in self.classes]
            if not rows:
                continue
            X = np.array([[f[k] for k in self.feature_names] for _, _, f in rows], dtype=np.float32)
            proba = self.model.predict_proba(X)
            base = next(r for r in rec["responses"] if r["kind"] == "base1")
            for cls in self.classes:
                ci = CLASSES.index(cls)
                idx = [i for i, (p, _, _) in enumerate(rows) if p["class"] == cls]
                if not idx:
                    continue
                best = max(idx, key=lambda i: proba[i, ci])
                if proba[best, ci] < t:
                    continue
                # Precedence (v2, documented): quote parity and timing also fire for shell quoting, so when
                # the command-injection rule confirms CWE-78 on this parameter the SQLi score yields to it.
                if cls == "CWE-89" and any(r["cwe_id"] == 78 for r in rule_findings):
                    continue
                p, resp, f = rows[best]
                alert, attack, severity, cwe, solution = ALERTS[cls]
                findings.append({"alert": alert, "attack_type": attack, "severity": severity, "endpoint": endpoint,
                                 "method": point.method, "param": point.param[:200], "request_payload": resp["value"][:1000],
                                 "response_details": evidence(f, resp, base)[:1000], "cwe_id": cwe, "solution": solution,
                                 "confidence": round(float(proba[best, ci]), 4), **({"engine": "ml"} if v2 else {})})
        stored_records = []
        if v3 and stopped is None and os.environ.get("ML_DAST_STORED_XSS", "1") != "0":
            # before the passive pass, which clears the session's cookies
            stored_records = stored_pass(client, points, pages, max_pages=20)
            findings += stored_xss_findings(stored_records, base_url)
            if any(r.get("stopped") for r in stored_records):
                stopped = "request budget reached during the stored-XSS pass"
        if v2 and stopped is None:
            passive, snaps = self._passive(client, visited, base_url, with_snaps=True)
            findings += passive
            if v3:
                findings += csrf_findings(forms, headers + snaps, base_url)
        self.last_scan = {"pages": len(visited), "points_found": len(points), "points_probed": probed,
                          **({"forms": len(forms), "stored_xss_fields_written": len(stored_records)} if v3 else {}),
                          "requests": client.requests_sent, "stopped": stopped, **({"errors": self.last_scan["errors"]} if "errors" in self.last_scan else {})}
        return findings

    @staticmethod
    def _passive(client, visited, base_url, max_pages=10, with_snaps=False):
        """Rule-based passive checks (LOW/INFO) on up to 10 crawled pages, re-requested without the
        session's cookies so a cookie set on first visit is seen, plus one foreign-Origin request.
        Uses the same guarded client, so it counts against the scan's request budget."""
        client.session.cookies.clear()
        snaps = []
        try:
            for path in list(dict.fromkeys(visited))[:max_pages]:
                resp, el = client.request("GET", path)
                snaps.append({"kind": "page", **snapshot(resp, el, headers=True)})
            origin = CORS_ORIGIN.replace("{M}", new_marker())
            resp, el = client.request("GET", "/", headers={"Origin": origin})
            snaps.append({"kind": "cors", "origin": origin, **snapshot(resp, el, headers=True)})
        except (BudgetExceeded, GuardError):
            pass
        except Exception:  # an unreachable page only shortens the passive pass
            pass
        found = passive_findings(snaps, base_url)
        return (found, snaps) if with_snaps else found
