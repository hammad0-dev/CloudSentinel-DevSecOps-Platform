"""v2 data must leave the frozen v1 / DVNA set untouched, and the new features must behave."""
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from dastml.crawl import InjectionPoint
from dastml.features import FEATURE_NAMES, FEATURE_NAMES_V2, row_features, url_attr_context
from dastml.groundtruth import GroundTruth
from dastml.paths import DATA, paths, refuse_frozen
from dastml.probe import load_payloads, point_rows

sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
FREEZE = json.loads((DATA / "FREEZE.json").read_text())


def test_v1_ground_truth_and_payloads_are_byte_identical_to_the_freeze():
    assert sha(DATA / "ground_truth.json") == FREEZE["ground_truth_sha256"]
    assert sha(DATA / "payloads/payloads.json") == FREEZE["payloads_sha256"]


@pytest.mark.skipif(not (DATA / "raw/dvna.jsonl.gz").exists(), reason="lab data is gitignored")
def test_dvna_raw_and_features_are_untouched():
    assert sha(DATA / "raw/dvna.jsonl.gz") == FREEZE["raw_sha256"]
    assert sha(DATA / "features/dvna.jsonl.gz") == FREEZE["features_sha256"]
    assert not (DATA / "raw_v2/dvna.jsonl.gz").exists() and not (DATA / "features_v2/dvna.jsonl.gz").exists()


def test_frozen_app_files_are_never_rewritten():
    with pytest.raises(SystemExit):
        refuse_frozen("dvna")


@pytest.mark.skipif(not (DATA / "raw/vulpy-good.jsonl.gz").exists(), reason="lab data is gitignored")
def test_v1_features_are_unchanged_by_the_v2_code():
    """Recompute v1 features from stored raw records: every v1 feature value must be identical."""
    gt, payloads = GroundTruth(paths("v1")["ground_truth"]), load_payloads()
    stored = [json.loads(line) for line in gzip.open(DATA / "features/labflask.jsonl.gz", "rt")]
    redone = []
    for line in gzip.open(DATA / "raw/labflask.jsonl.gz", "rt"):
        rec = json.loads(line)
        p = rec["point"]
        point = InjectionPoint(p["method"], p["path"], p["param"], p["location"], tuple(map(tuple, p["params"])), p.get("template", ""))
        for pl, _, f in point_rows(rec, payloads):
            if gt.label("labflask", point, pl["class"]) is not None:
                redone.append(f)
    assert len(redone) == len(stored)
    for a, b in zip(stored, redone):
        assert {k: a["features"][k] for k in FEATURE_NAMES} == pytest.approx({k: b[k] for k in FEATURE_NAMES})


def test_ground_truth_v2_differs_from_v1_only_by_documented_changes():
    v1 = json.loads((DATA / "ground_truth.json").read_text())
    v2 = json.loads((DATA / "ground_truth_v2.json").read_text())
    assert v2["changes"][0]["prompted_by"].startswith("error analysis")
    key = lambda e: (e["app"], e["method"], e["path"], tuple(e["params"]))
    old, new = {key(e): e for e in v1["endpoints"]}, {key(e): e for e in v2["endpoints"]}
    changed_v1 = {k for k in old if k not in new or old[k] != new[k]}
    assert changed_v1 == {("nodegoat", "POST", "/signup", ("userName", "firstName", "lastName", "email"))}
    gt = GroundTruth(DATA / "ground_truth_v2.json")
    point = lambda param: InjectionPoint("POST", "/signup", param, "form")
    assert [gt.label("nodegoat", point(p), "CWE-79") for p in ("userName", "email", "firstName", "lastName")] == ["CWE-79", "CWE-79", "safe", "safe"]
    # same cluster ids for unchanged parameters, so before/after comparisons line up
    assert gt.cluster("nodegoat", point("email")) == "nodegoat|POST|/signup|email"


def test_v2_payloads_keep_every_v1_payload_unchanged():
    v1 = {p["id"]: p for p in json.loads((DATA / "payloads/payloads.json").read_text())["payloads"]}
    v2 = {p["id"]: p for p in json.loads((DATA / "payloads/payloads_v2.json").read_text())["payloads"]}
    for pid, p in v1.items():
        assert {k: v2[pid][k] for k in p} == p
    assert all(p.get("rule") for p in v2.values() if p["class"] in ("CWE-78", "CWE-22"))


BASE = {"status": 200, "ctype": "text/html", "body": "<html><body><p>hello</p></body></html>", "elapsed": 0.02, "location": "", "nosniff": False}


def _resp(body, elapsed=0.02, status=200, **kw):
    return {**BASE, "body": body, "elapsed": elapsed, "status": status, **kw}


def test_url_attribute_context_and_html_specials():
    m = "csabc123"
    assert url_attr_context(f'<a href="javascript:{m}()">x</a>', f"javascript:{m}()", m) == 1.0
    assert url_attr_context(f'<p>javascript:{m}()</p>', f"javascript:{m}()", m) == 0.0
    assert url_attr_context(f'<div style="color: javascript:{m}()">', f"javascript:{m}()", m) == 0.0
    probe = {**BASE, "marker": "csprobe"}
    p = {"id": "xs-uri", "class": "CWE-79", "family": "attr", "value": "javascript:{M}()"}
    f = row_features(p, "query", _resp(f"<p>javascript:{m}()</p>"), m, BASE, BASE, probe)
    assert f["html_specials_payload"] == 0.0 and f["html_specials_kept_frac"] == 0.0 and f["ctx_url_attr"] == 0.0
    assert f["specials_kept_frac"] == 1.0, "v1 feature unchanged: parentheses count there"
    tag = {"id": "xs-tag-1", "class": "CWE-79", "family": "tag", "value": "<b>{M}</b>"}
    f = row_features(tag, "query", _resp(f"<p><b>{m}</b></p>"), m, BASE, BASE, probe)
    assert f["html_specials_payload"] == 1.0 and f["html_specials_kept_frac"] == 1.0


def _group_row(payloads, responses, pid):
    peers = {p["id"]: (p, r) for p, r in zip(payloads, responses)}
    p, r = peers[pid]
    return row_features(p, "query", r, "csm", BASE, BASE, {**BASE, "marker": "csprobe"}, peers=peers)


def test_dose_confirms_only_a_delay_that_follows_the_requested_sleep():
    hi = {"id": "t1", "class": "CWE-89", "family": "time", "value": "' AND SLEEP(1)-- -", "sleep": 1, "repeat": True, "dose": "t1"}
    lo = {"id": "t0", "class": "CWE-89", "family": "time", "value": "' AND SLEEP(0)-- -", "sleep": 0, "dose": "t1"}
    real = _group_row([hi, lo], [_resp("x", 1.05, elapsed2=1.04), _resp("x", 0.03)], "t1")
    assert real["dose_confirmed"] == 1.0 and real["dose_gap"] == pytest.approx(1.01, abs=0.01)
    # slow upstream (DNS lookup of junk): both requests are slow, so no dose response
    slow = _group_row([hi, lo], [_resp("x", 2.0, elapsed2=2.0), _resp("x", 2.0)], "t1")
    assert slow["dose_confirmed"] == 0.0 and slow["dose_gap"] == pytest.approx(0.0)
    # one-off spike: the repeat is fast, so the faster measurement shows no delay
    spike = _group_row([hi, lo], [_resp("x", 2.0, elapsed2=0.03), _resp("x", 0.03)], "t1")
    assert spike["dose_confirmed"] == 0.0
    fast = row_features(hi, "query", _resp("x", 0.001), "csm", {**BASE, "elapsed": 1.5}, {**BASE, "elapsed": 1.5}, {**BASE, "marker": "csprobe"})
    assert fast["time_slow_delta"] == 0.0 and fast["time_slow_ratio_log"] == 0.0 and fast["time_delta"] < 0
    assert "time_delta" not in FEATURE_NAMES_V2 and "time_slow_delta" in FEATURE_NAMES_V2


def test_quote_parity_flip():
    odd = {"id": "o", "class": "CWE-89", "family": "error", "value": "'", "parity": "s", "odd": True}
    even = {"id": "e", "class": "CWE-89", "family": "error", "value": "''", "parity": "s", "odd": False}
    sql = _group_row([odd, even], [_resp("Internal Server Error", status=500), _resp(BASE["body"])], "o")
    assert sql["parity_flip"] == 1.0
    any_error = _group_row([odd, even], [_resp("Internal Server Error", status=500), _resp("Internal Server Error", status=500)], "e")
    assert any_error["parity_odd_breaks"] == 1.0 and any_error["parity_even_restores"] == 0.0 and any_error["parity_flip"] == 0.0
    inert = _group_row([odd, even], [_resp(BASE["body"]), _resp(BASE["body"])], "o")
    assert inert["parity_flip"] == 0.0 and inert["parity_present"] == 1.0
