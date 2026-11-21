"""v4 data: DVPWA is frozen, earlier ground truth is untouched, and v4 differs from v3 only in documented ways."""
import json
import sys
from pathlib import Path

import pytest

from dastml.paths import DATA, paths

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
V3 = json.loads((DATA / "ground_truth_v3.json").read_text())
V4 = json.loads((DATA / "ground_truth_v4.json").read_text())
F4 = json.loads((DATA / "FREEZE_v4.json").read_text())


def test_dvpwa_ground_truth_hash_matches_the_freeze():
    from freeze_v4 import gt_sha
    assert gt_sha(V4) == F4["ground_truth_dvpwa_sha256"] and F4["frozen_before_any_scan"] is True
    assert V4["apps"]["dvpwa"]["role"] == "final_heldout_v4"


@pytest.mark.skipif(not (ROOT / "lab/vendor/dvpwa/.git").exists(), reason="vendored source is gitignored")
def test_dvpwa_source_hash_matches_the_freeze():
    from freeze_v4 import source_sha
    assert source_sha()[0] == F4["source_sha256"]


def test_earlier_freezes_still_hold():
    from freeze_v3 import gt_sha as gt3
    assert gt3(V3) == json.loads((DATA / "FREEZE_v3.json").read_text())["ground_truth_sirappsec_sha256"]
    assert gt3(V4) == json.loads((DATA / "FREEZE_v3.json").read_text())["ground_truth_sirappsec_sha256"], "SirAppSec subset unchanged in v4"


def test_v4_keeps_every_v3_label_and_holdouts_never_train():
    key = lambda e: (e["app"], e["method"], e["path"], tuple(e["params"]), e.get("seg"))
    old, new = {key(e): e for e in V3["endpoints"]}, {key(e): e for e in V4["endpoints"]}
    assert all(new[k] == e for k, e in old.items()), "no v3 label changes in v4"
    assert {k[0] for k in set(new) - set(old)} <= {"dvpwa", "benchmarkpython"}
    for app in ("dvna", "sirappsec", "dvpwa"):
        assert V4["apps"][app]["role"].startswith("final_heldout"), app


def test_dvpwa_has_no_data_unless_scored():
    scored = (ROOT / "reports/final_dvpwa.json").exists()
    assert scored or not (paths("v4")["raw"] / "dvpwa.jsonl.gz").exists()


def test_benchmark_is_its_own_group_and_rule_only_cases_give_no_ml_rows():
    from dastml.crawl import InjectionPoint
    from dastml.groundtruth import GroundTruth
    assert V4['apps']['benchmarkpython']['origin'] == 'benchmark' and V4['apps']['benchmarkpython']['group'] == 'benchmark'
    gt = GroundTruth(DATA / 'ground_truth_v4.json')
    bench = [e for e in V4['endpoints'] if e['app'] == 'benchmarkpython']
    assert len(bench) == 155 and sum(e['ml'] for e in bench) == 80
    rule_only = next(e for e in bench if not e['ml'] and 'CWE-22' in e['vuln'])
    pt = InjectionPoint(rule_only['method'], rule_only['path'], rule_only['params'][0], rule_only['in'])
    assert gt.label('benchmarkpython', pt, 'CWE-89') is None and gt.label('benchmarkpython', pt, 'CWE-22') == 'CWE-22'
    xss = next(e for e in bench if 'CWE-79' in e['vuln'])
    pt = InjectionPoint(xss['method'], xss['path'], xss['params'][0], xss['in'])
    assert gt.label('benchmarkpython', pt, 'CWE-79') == 'CWE-79' and gt.label('benchmarkpython', pt, 'CWE-89') == 'safe'
