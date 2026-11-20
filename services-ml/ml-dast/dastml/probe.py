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


def new_marker():
    return "cs" + secrets.token_hex(5)


def snapshot(resp, elapsed):
    return {"status": resp.status_code, "ctype": resp.headers.get("content-type", ""), "body": resp.text[:BODY_LIMIT],
            "elapsed": round(elapsed, 4), "location": resp.headers.get("location", ""),
            "nosniff": resp.headers.get("x-content-type-options", "").lower() == "nosniff"}


def send(client, point, value):
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
    resp, elapsed = client.request(point.method, path, **kw)
    return snapshot(resp, elapsed)


def probe_point(client, point, payloads):
    """Return the raw records for one point: base1, base2, probe, then one per payload."""
    original = dict(point.params).get(point.param, "1") or "1"
    records = {"point": {"method": point.method, "path": point.path, "param": point.param, "location": point.location,
                         "template": point.template, "params": list(point.params)}, "responses": []}
    for kind in ("base1", "base2"):
        records["responses"].append({"kind": kind, "value": original, **send(client, point, original)})
    marker = new_marker()
    records["responses"].append({"kind": "probe", "marker": marker, "value": marker, **send(client, point, marker)})
    for p in payloads:
        marker = new_marker()
        raw = p["value"].replace("{M}", marker)
        value = original + raw if p["mode"] == "append" else raw
        records["responses"].append({"kind": "payload", "payload_id": p["id"], "marker": marker, "value": value, **send(client, point, value)})
    return records


def point_rows(records, payloads):
    """Feature dicts for every payload response of one point (same order as payload records)."""
    by_kind = {r["kind"]: r for r in records["responses"] if r["kind"] != "payload"}
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
        feats = row_features(p, records["point"]["location"], r, r["marker"], by_kind["base1"], by_kind["base2"], by_kind["probe"], pair)
        rows.append((p, r, feats))
    return rows
