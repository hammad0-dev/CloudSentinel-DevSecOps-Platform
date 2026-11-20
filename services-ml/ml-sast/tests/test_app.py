import json

import joblib
import numpy as np
import pytest
from fastapi.testclient import TestClient

import app as service
from sastml import CLASSES
from sastml.model import SastModel
from sastml.synthetic import generate

client = TestClient(service.app)

VULN_PY = '''import sqlite3

@app.route("/user")
def show_user():
    uid = request.args.get("id")
    cur.execute("SELECT * FROM users WHERE id = '" + uid + "'")
    return "ok"


def add(a, b):
    return a + b
'''


def test_untrained_mode_returns_no_findings():
    assert client.get("/health").json() == {"status": "ok", "service": "ml-sast", "model": "untrained"}
    info = client.get("/model-info").json()
    assert info["status"] == "untrained" and info["sha256"] is None
    assert client.post("/scan", json={"files": [{"path": "app.py", "content": VULN_PY}]}).json() == {"findings": []}


def test_scan_rejects_malformed_request():
    assert client.post("/scan", json={"files": [{"path": ""}]}).status_code == 422


class StubModel:
    """Flags units containing 'execute(' as CWE-89 with 0.9, everything else safe."""
    info = {"name": "stub"}

    def predict_proba(self, codes, langs):
        out = np.zeros((len(codes), len(CLASSES)), dtype=np.float32)
        for i, c in enumerate(codes):
            out[i, CLASSES.index("CWE-89") if "execute(" in c else 0] = 0.9
            out[i, 0] += 0.1
        return out


@pytest.fixture
def stub(monkeypatch):
    monkeypatch.setattr(service, "MODEL", StubModel())
    monkeypatch.setattr(service, "MODEL_INFO", {**service.MODEL_INFO, "status": "trained", "threshold": 0.5})


def test_scan_splits_functions_and_reports_start_line(stub):
    body = {"files": [{"path": "app.py", "content": VULN_PY}, {"path": "README.md", "content": "x"}, {"path": "ui.ts", "content": "let a = 1"}]}
    findings = client.post("/scan", json=body).json()["findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["rule"] == "python.sql-injection" and f["cwe_id"] == 89 and f["severity"] == "CRITICAL"
    assert f["file_path"] == "app.py" and f["line_number"] == 4, "the def line of show_user"
    assert f["confidence"] == pytest.approx(0.9) and "show_user" in f["message"]


def test_threshold_suppresses_low_confidence(stub, monkeypatch):
    monkeypatch.setitem(service.MODEL_INFO, "threshold", 0.95)
    assert client.post("/scan", json={"files": [{"path": "app.py", "content": VULN_PY}]}).json() == {"findings": []}


def test_model_failure_is_an_error_not_a_clean_scan(monkeypatch):
    class Broken:
        def predict_proba(self, codes, langs):
            raise RuntimeError("boom")
    monkeypatch.setattr(service, "MODEL", Broken())
    monkeypatch.setitem(service.MODEL_INFO, "threshold", 0.5)
    assert client.post("/scan", json={"files": [{"path": "app.py", "content": VULN_PY}]}).status_code == 500


def test_real_joblib_model_info_and_scan(tmp_path, monkeypatch):
    rows = generate(per_family=6, seed=3)
    model = SastModel("lr", {"C": 3.0}, {"max_features": 3000, "ngram_range": (1, 2)}).fit(
        [r["code"] for r in rows], [r["lang"] for r in rows], [r["label"] for r in rows])
    path = tmp_path / "model.joblib"
    joblib.dump(model, path)
    (tmp_path / "model.json").write_text(json.dumps({"name": "ml-sast-lr", "version": "1.0.0", "threshold": 0.4,
                                                       "trained_on": {"rows": len(rows)}, "metrics": {"heldout_code": {"macro_f1": 0.5}}}))
    monkeypatch.delenv("ML_SAST_CONFIDENCE_THRESHOLD", raising=False)
    loaded, info = service.load_model(path)
    assert info["status"] == "trained" and info["name"] == "ml-sast-lr" and info["version"] == "1.0.0"
    assert info["sha256"] == service.sha256_file(path) and len(info["sha256"]) == 64
    assert info["threshold"] == 0.4 and info["trained_on"] == {"rows": len(rows)} and "heldout_code" in info["metrics"]
    monkeypatch.setenv("ML_SAST_CONFIDENCE_THRESHOLD", "0.9")
    assert service.load_model(path)[1]["threshold"] == 0.9, "env overrides the model default"
    monkeypatch.setattr(service, "MODEL", loaded)
    monkeypatch.setattr(service, "MODEL_INFO", {**info, "threshold": 0.0})
    findings = client.post("/scan", json={"files": [{"path": "app.py", "content": VULN_PY}]}).json()["findings"]
    assert {f["line_number"] for f in findings} <= {4, 10, 1}
    assert all(f["file_path"] == "app.py" and 0 <= f["confidence"] <= 1 for f in findings)
