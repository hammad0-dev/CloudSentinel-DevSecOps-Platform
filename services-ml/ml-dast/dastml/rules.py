"""Deterministic (rule-based, NOT machine learning) checks of ml-dast v2.

Rules run on the same guarded probe records as the classifier; they send nothing themselves.

* CWE-78 OS command injection: a payload asks the shell to compute ``{M}$((7*191))``. Only an
  evaluating shell turns that into ``{M}1337``; the literal payload never contains ``1337``, so
  reflection or escaping cannot produce it. Second signal: ``;sleep 2`` (sent twice, the faster
  response counts) is at least 1.6 s slower than ``;sleep 0`` while ``;sleep 0`` itself is fast.
* CWE-22 path traversal: a traversal payload returns ``/etc/passwd`` content (``root:x:0:0:``) that
  neither baseline contains.
* CWE-601 open redirect: a scheme-less ``//{M}.invalid/`` (or ``/\\{M}.invalid/``) payload comes back
  as a 3xx ``Location`` whose host is ``{M}.invalid``. Only the header is read; the guards never follow
  an off-origin redirect, and ``.invalid`` never resolves.
* Passive (severity LOW / INFORMATIONAL, never gate-blocking): missing Content-Security-Policy, missing
  ``X-Content-Type-Options: nosniff``, no framing protection (no X-Frame-Options and no CSP
  ``frame-ancestors``) on HTML pages; a session cookie without HttpOnly or without SameSite; CORS that
  echoes an arbitrary Origin (or ``*`` together with credentials).

Every result says ``"engine": "rule"`` so it is never reported as an ML finding.
"""
import re
from urllib.parse import urljoin, urlsplit

PASSWD = re.compile(r"root:[^:\n]*:0:0:")
CMD_PRODUCT = "1337"  # 7*191
SESSION_COOKIE = re.compile(r"sess|sid|token|auth|connect\.|jsession|phpsessid", re.I)

RULES = {
    "CWE-78": {"alert": "Remote OS Command Injection", "attack_type": "os_command_injection", "severity": "HIGH", "cwe": 78,
               "solution": "Never pass request data to a shell; call the program with an argument list (no shell) and validate the value against an allowlist."},
    "CWE-601": {"alert": "External Redirect", "attack_type": "open_redirect", "severity": "MEDIUM", "cwe": 601,
                "solution": "Redirect only to relative paths or to an allowlist of destinations; never to a URL taken from the request."},
    "CWE-22": {"alert": "Path Traversal", "attack_type": "path_traversal", "severity": "HIGH", "cwe": 22,
               "solution": "Resolve the requested name against a fixed base directory, reject anything that leaves it (basename + realpath containment), or map ids to files server-side."},
}
PASSIVE = {
    "missing-csp": ("Content Security Policy (CSP) Header Not Set", "LOW", 693,
                    "Send a Content-Security-Policy header that restricts script sources on every HTML response."),
    "missing-nosniff": ("X-Content-Type-Options Header Missing", "LOW", 693, "Send X-Content-Type-Options: nosniff on every response."),
    "missing-frame-protection": ("Missing Anti-clickjacking Header", "LOW", 1021,
                                 "Send X-Frame-Options: DENY (or SAMEORIGIN) or a CSP frame-ancestors directive on HTML responses."),
    "cookie-no-httponly": ("Cookie No HttpOnly Flag", "LOW", 1004, "Set the HttpOnly attribute on session cookies."),
    "cookie-no-samesite": ("Cookie without SameSite Attribute", "LOW", 1275, "Set SameSite=Lax (or Strict) on session cookies."),
    "cors-any-origin": ("Cross-Origin Resource Sharing Misconfiguration", "LOW", 942,
                        "Only echo origins from an explicit allowlist; never combine a wildcard or reflected origin with credentials."),
}
PASSIVE_SEVERITY = {k: ("INFORMATIONAL" if k in ("missing-nosniff",) else v[1]) for k, v in PASSIVE.items()}
assert set(PASSIVE_SEVERITY.values()) <= {"LOW", "INFORMATIONAL"}, "passive checks are LOW/INFO only (never gate-blocking)"


def _elapsed(r):
    return min(r["elapsed"], r.get("elapsed2", r["elapsed"]))


def _payload_responses(record, payloads, cls):
    by_id = {p["id"]: p for p in payloads if p["class"] == cls}
    return [(by_id[r["payload_id"]], r) for r in record["responses"] if r["kind"] == "payload" and r.get("payload_id") in by_id]


def _baselines(record):
    return [r for r in record["responses"] if r["kind"] in ("base1", "base2")]


def command_injection(record, payloads):
    """(fired, evidence, payload value) for one probed injection point."""
    base_text = " ".join(r["body"] for r in _baselines(record))
    for p, r in _payload_responses(record, payloads, "CWE-78"):
        m = r.get("marker")
        if m and p["family"] == "cmd" and (m + CMD_PRODUCT) in r["body"] and (m + CMD_PRODUCT) not in base_text:
            return True, f"shell computed {m}$((7*191)) -> {m}{CMD_PRODUCT} in the response", r["value"]
    timing = {p.get("sleep"): r for p, r in _payload_responses(record, payloads, "CWE-78") if p["family"] == "cmd_time"}
    if 2 in timing and 0 in timing:
        base_t = sum(r["elapsed"] for r in _baselines(record)) / max(len(_baselines(record)), 1)
        gap = _elapsed(timing[2]) - _elapsed(timing[0])
        if gap >= 1.6 and _elapsed(timing[0]) - base_t < 1.0:
            return True, f";sleep 2 was {gap:.2f}s slower than ;sleep 0 (both sent; repeat confirmed)", timing[2]["value"]
    return False, "", ""


def path_traversal(record, payloads):
    if any(PASSWD.search(r["body"]) for r in _baselines(record)):
        return False, "", ""
    for p, r in _payload_responses(record, payloads, "CWE-22"):
        if PASSWD.search(r["body"]):
            return True, "response contains /etc/passwd content (root:x:0:0:) absent from the baseline", r["value"]
    return False, "", ""


def open_redirect(record, payloads, base="http://target.invalid/"):
    for p, r in _payload_responses(record, payloads, "CWE-601"):
        m, loc = r.get("marker"), (r.get("location") or "").replace("\\", "/")
        if m and 300 <= r["status"] < 400 and loc:
            host = urlsplit(urljoin(base, loc)).hostname or ""
            if host == f"{m}.invalid".lower():
                return True, f"{r['status']} redirect to Location {loc[:120]!r} (host taken from the request)", r["value"]
    return False, "", ""


ACTIVE_RULES = {"CWE-78": command_injection, "CWE-22": path_traversal, "CWE-601": open_redirect}


def active_findings(record, payloads, base_url, endpoint):
    """Rule findings for one probed point, in the dast_findings contract."""
    out = []
    for cls, rule in ACTIVE_RULES.items():
        fired, evidence, value = rule(record, payloads)
        if fired:
            meta = RULES[cls]
            out.append({"alert": meta["alert"], "attack_type": meta["attack_type"], "severity": meta["severity"], "endpoint": endpoint[:500],
                        "method": record["point"]["method"], "param": record["point"]["param"][:200], "request_payload": value[:1000],
                        "response_details": f"[rule-based] {evidence}"[:1000], "cwe_id": meta["cwe"], "solution": meta["solution"],
                        "confidence": 1.0, "engine": "rule"})
    return out


def _cookie_flags(cookie):
    parts = [x.strip().lower() for x in cookie.split(";")]
    name = parts[0].split("=", 1)[0] if parts else ""
    return name, any(x == "httponly" for x in parts[1:]), any(x.startswith("samesite") for x in parts[1:])


def passive_checks(responses):
    """responses: snapshots with "headers" (and kind "cors" with "origin" for the CORS probe).
    Returns {check: evidence} for every check that fires."""
    fired = {}
    html = [r for r in responses if "html" in (r.get("ctype") or "").lower() and r.get("kind") != "cors" and r.get("headers") is not None]
    with_headers = [r for r in responses if r.get("headers") is not None and r.get("kind") != "cors"]
    lower = lambda r: {k.lower(): v for k, v in r["headers"].items()}
    if html and any("content-security-policy" not in lower(r) for r in html):
        fired["missing-csp"] = f"{sum('content-security-policy' not in lower(r) for r in html)} of {len(html)} HTML responses have no Content-Security-Policy"
    if with_headers and any(str(lower(r).get("x-content-type-options", "")).lower() != "nosniff" for r in with_headers):
        fired["missing-nosniff"] = "responses without X-Content-Type-Options: nosniff"
    framed = lambda r: "x-frame-options" in lower(r) or "frame-ancestors" in str(lower(r).get("content-security-policy", "")).lower()
    if html and any(not framed(r) for r in html):
        fired["missing-frame-protection"] = "HTML responses without X-Frame-Options or CSP frame-ancestors"
    cookies = [c for r in with_headers for c in (lower(r).get("set-cookie") or [])]
    for c in cookies:
        name, httponly, samesite = _cookie_flags(c)
        if not SESSION_COOKIE.search(name):
            continue
        if not httponly:
            fired.setdefault("cookie-no-httponly", f"cookie {name!r} without HttpOnly")
        if not samesite:
            fired.setdefault("cookie-no-samesite", f"cookie {name!r} without SameSite")
    for r in responses:
        if r.get("kind") != "cors" or r.get("headers") is None:
            continue
        h = lower(r)
        acao, acac = h.get("access-control-allow-origin", ""), str(h.get("access-control-allow-credentials", "")).lower() == "true"
        if acao and (acao == r.get("origin") or (acao == "*" and acac)):
            fired["cors-any-origin"] = f"Access-Control-Allow-Origin: {acao} for a foreign Origin" + (" with credentials" if acac else "")
            break
    return fired


def passive_findings(responses, base_url):
    out = []
    for check, evidence in passive_checks(responses).items():
        alert, _, cwe, solution = PASSIVE[check]
        out.append({"alert": alert, "attack_type": f"passive_{check.replace('-', '_')}", "severity": PASSIVE_SEVERITY[check],
                    "endpoint": base_url[:500], "method": "GET", "param": "", "request_payload": "",
                    "response_details": f"[rule-based passive check] {evidence}"[:1000], "cwe_id": cwe, "solution": solution,
                    "confidence": 1.0, "engine": "rule"})
    return out
