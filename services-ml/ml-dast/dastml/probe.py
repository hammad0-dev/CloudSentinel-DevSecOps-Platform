"""Send baseline, benign-probe and payload requests to one injection point; return raw records.

Every request goes through GuardedClient. A record holds the request (method, path, location,
param, payload id, value sent) and a response snapshot (status, content type, body truncated to
200 kB, elapsed seconds, Location header, nosniff). Features are computed from records later
(:func:`point_rows`), so the raw data can be re-featurized without re-sending traffic.
"""
import json
import secrets
from pathlib import Path

from .features import row_features

BODY_LIMIT = 200_000
PAYLOADS_PATH = Path(__file__).resolve().parents[1] / "data/dast/payloads/payloads.json"


def load_payloads(classes=("CWE-89", "CWE-79"), path=PAYLOADS_PATH):
    return [p for p in json.loads(Path(path).read_text())["payloads"] if p["class"] in classes]


# Response headers kept for the passive checks (v2). Only baseline-type requests store them.
HEADERS = ("content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy",
           "strict-transport-security", "access-control-allow-origin", "access-control-allow-credentials")
CORS_ORIGIN = "http://{M}.invalid"


def _set_cookies(resp):
    try:
        return list(resp.raw.headers.getlist("Set-Cookie"))
    except AttributeError:
        return [resp.headers["set-cookie"]] if "set-cookie" in resp.headers else []


def header_snapshot(resp):
    """Security headers of the final response, plus Set-Cookie from every hop of a same-origin
    redirect chain (a session cookie is often set on the 302, not on the page it leads to)."""
    h = {k: resp.headers[k] for k in HEADERS if k in resp.headers}
    cookies = [c for hop in getattr(resp, "cs_hops", []) for c in _set_cookies(hop)] + _set_cookies(resp)
    if cookies:
        h["set-cookie"] = [c[:300] for c in cookies]
    return h


def new_marker():
    return "cs" + secrets.token_hex(5)


def snapshot(resp, elapsed, headers=False):
    snap = {"status": resp.status_code, "ctype": resp.headers.get("content-type", ""), "body": resp.text[:BODY_LIMIT],
            "elapsed": round(elapsed, 4), "location": resp.headers.get("location", ""),
            "nosniff": resp.headers.get("x-content-type-options", "").lower() == "nosniff"}
    if headers:
        snap["headers"] = header_snapshot(resp)
    return snap


def send(client, point, value, headers=False, extra_headers=None):
    params = dict(point.params)
    path = point.path
    if point.location == "path":
        idx = int(point.param[4:-1])
        segs = path.split("/")
        segs[idx] = value
        path = "/".join(segs)
        params = {}
    else:
        params[point.param] = value
    kw = {}
    if point.location == "query":
        kw["params"] = params
    elif point.location == "form":
        kw["data"] = params
    elif point.location == "json":
        kw["json"] = params
    from urllib.parse import quote
    if point.location == "path":
        path = "/".join(quote(s, safe="") if i else s for i, s in enumerate(path.split("/")))
    if extra_headers:
        kw["headers"] = extra_headers
    resp, elapsed = client.request(point.method, path, **kw)
    return snapshot(resp, elapsed, headers)


def probe_point(client, point, payloads, v2=False):
    """Return the raw records for one point: base1, base2, probe, then one per payload.

    v2: baselines store response headers, one extra "cors" request carries a foreign Origin, and
    payloads marked "repeat" are sent twice (elapsed2) so a one-off slow response is not a delay."""
    original = dict(point.params).get(point.param, "1") or "1"
    records = {"point": {"method": point.method, "path": point.path, "param": point.param, "location": point.location,
                         "template": point.template, "params": list(point.params)}, "responses": []}
    for kind in ("base1", "base2"):
        records["responses"].append({"kind": kind, "value": original, **send(client, point, original, headers=v2)})
    marker = new_marker()
    records["responses"].append({"kind": "probe", "marker": marker, "value": marker, **send(client, point, marker)})
    if v2:
        marker = new_marker()
        origin = CORS_ORIGIN.replace("{M}", marker)
        records["responses"].append({"kind": "cors", "marker": marker, "value": original, "origin": origin,
                                     **send(client, point, original, headers=True, extra_headers={"Origin": origin})})
    for p in payloads:
        marker = new_marker()
        raw = p["value"].replace("{M}", marker)
        value = original + raw if p["mode"] == "append" else raw
        rec = {"kind": "payload", "payload_id": p["id"], "marker": marker, "value": value, **send(client, point, value)}
        if v2 and p.get("repeat"):
            rec["elapsed2"] = send(client, point, value)["elapsed"]
        records["responses"].append(rec)
    return records


def point_rows(records, payloads):
    """Feature dicts for every payload response of one point (same order as payload records)."""
    by_kind = {r["kind"]: r for r in records["responses"] if r["kind"] != "payload"}
    peers = {r["payload_id"]: (by_id_all[r["payload_id"]], r) for r in records["responses"]
             if r["kind"] == "payload" and r["payload_id"] in (by_id_all := {p["id"]: p for p in payloads})}
    by_id = {p["id"]: p for p in payloads}
    resp_by_pid = {r["payload_id"]: r for r in records["responses"] if r["kind"] == "payload"}
    rows = []
    for r in records["responses"]:
        if r["kind"] != "payload" or r["payload_id"] not in by_id:
            continue
        p = by_id[r["payload_id"]]
        pair = None
        if p.get("pair"):
            other = next((q for q in payloads if q.get("pair") == p["pair"] and q["id"] != p["id"]), None)
            pair = resp_by_pid.get(other["id"]) if other else None
        feats = row_features(p, records["point"]["location"], r, r["marker"], by_kind["base1"], by_kind["base2"], by_kind["probe"], pair, peers=peers)
        rows.append((p, r, feats))
    return rows
