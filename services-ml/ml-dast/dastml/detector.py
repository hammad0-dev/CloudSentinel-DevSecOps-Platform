"""DastDetector: the object stored in models/release/model.joblib and called by the ml-dast service.

scan(base_url, max_pages, max_requests) crawls the target, probes each discovered injection point with
the fixed payload list, featurizes every response and reports one finding per (endpoint, parameter,
class) whose highest model probability reaches the threshold. All traffic goes through
GuardedClient (allowlist, same origin, budgets, rate limit). When the request budget runs out the
scan stops and returns what it has; ``last_scan`` records coverage so callers can see it.
Optional ``seed_paths`` (extra start pages) and ``openapi_url`` (an OpenAPI document) widen the crawl
for apps whose endpoints are not linked from HTML; they pass the same guards as everything else.
"""
from urllib.parse import urljoin

import numpy as np

from . import CLASSES
from .crawl import crawl
from .guards import BudgetExceeded, GuardedClient, TargetPolicy
from .probe import load_payloads, point_rows, probe_point

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
        payloads = load_payloads(self.classes)
        self.last_scan = {}  # errors from a previous scan must not leak into this one
        seeds = list(seeds)
        if openapi_url:
            from .openapi import load_points
            seeds += load_points(client, openapi_url)
        points, visited = crawl(client, "/", seeds=seeds, start_paths=seed_paths)
        findings, probed, stopped = [], 0, None
        for point in points:
            try:
                rec = probe_point(client, point, payloads)
            except BudgetExceeded as exc:
                stopped = str(exc)
                break
            except Exception as exc:  # one broken endpoint must not abort the scan
                stopped = None
                self.last_scan.setdefault("errors", []).append(f"{point.method} {point.path}: {type(exc).__name__}")
                continue
            probed += 1
            rows = point_rows(rec, payloads)
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
                p, resp, f = rows[best]
                alert, attack, severity, cwe, solution = ALERTS[cls]
                findings.append({"alert": alert, "attack_type": attack, "severity": severity, "endpoint": urljoin(base_url, point.path)[:500],
                                 "method": point.method, "param": point.param[:200], "request_payload": resp["value"][:1000],
                                 "response_details": evidence(f, resp, base)[:1000], "cwe_id": cwe, "solution": solution,
                                 "confidence": round(float(proba[best, ci]), 4)})
        self.last_scan = {"pages": len(visited), "points_found": len(points), "points_probed": probed,
                          "requests": client.requests_sent, "stopped": stopped, **({"errors": self.last_scan["errors"]} if "errors" in self.last_scan else {})}
        return findings
