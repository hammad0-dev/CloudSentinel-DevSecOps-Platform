"""Stored-XSS pass (v3, rule-based, NOT machine learning).

For each POST/PUT form or JSON-body field, submit a unique harmless marker that carries HTML special
characters, then re-fetch every already-crawled page (GET only) and record where the marker comes
back. ``dastml.rules.stored_xss_findings`` reports a field only if the marker came back UNESCAPED
(``<i>{M}</i>`` literally) in a rendered HTML page fetched AFTER the submission.

State and reset:
* every marker is random per submission (``cs`` + 10 hex), so a scan only ever looks for its own
  markers and leftovers from an earlier scan can never produce a finding;
* the pass runs after the ML probing, one submission at a time, re-fetching the pages after each
  one (a form that rewrites a whole record, like a profile, would otherwise overwrite an earlier
  marker before it is seen);
* the lab apps are restarted (fresh databases) before every collection; the demo app keeps its
  data in memory. The scanner never deletes data on a target.

All traffic goes through the scan's GuardedClient, so writes only ever reach allowlisted targets
(the lab on 127.0.0.1 and our own demo deployment); skip-listed paths are never written to.
"""
from .guards import BudgetExceeded, GuardError
from .probe import new_marker, send

WRITE_METHODS = ("POST", "PUT")
WRITE_LOCATIONS = ("form", "json")


def stored_value(marker):
    return f"{marker}'\"<i>{marker}</i>"


def raw_sign(marker):
    return f"<i>{marker}</i>"


def escaped_sign(marker):
    return f"&lt;i&gt;{marker}"


def write_points(points):
    return [p for p in points if p.method in WRITE_METHODS and p.location in WRITE_LOCATIONS]


def stored_pass(client, points, pages, relogin=None, max_pages=60):
    """Returns one record per submitted field: {point, marker, value, status, hits: [{page, raw, escaped}]}."""
    pages = list(dict.fromkeys(pages))[:max_pages]
    out = []
    for point in write_points(points):
        marker = new_marker()
        rec = {"point": {"method": point.method, "path": point.path, "param": point.param, "location": point.location},
               "marker": marker, "value": stored_value(marker), "hits": []}
        try:
            if relogin:
                relogin()
            rec["status"] = send(client, point, rec["value"])["status"]
            if relogin:
                relogin()  # a login form submitted with a marker logs the session out
            for page in pages:
                resp, _ = client.request("GET", page)
                body = resp.text[:500_000]
                if marker not in body:
                    continue
                rendered = "html" in resp.headers.get("content-type", "").lower() and not 300 <= resp.status_code < 400
                rec["hits"].append({"page": page, "status": resp.status_code, "rendered": rendered,
                                    "raw": raw_sign(marker) in body, "escaped": escaped_sign(marker) in body})
        except (BudgetExceeded, GuardError) as exc:
            rec["stopped"] = type(exc).__name__
            out.append(rec)
            break
        except Exception as exc:  # noqa: BLE001 - one broken form must not end the pass
            rec["error"] = type(exc).__name__
        out.append(rec)
    return out
