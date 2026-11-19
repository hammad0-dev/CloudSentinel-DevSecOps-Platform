import importlib
import os

os.environ["MODEL_PATH"] = "/nonexistent/ml-sast/model.joblib"
from fastapi.testclient import TestClient  # noqa: E402

import app as service  # noqa: E402

client = TestClient(service.app)


def test_untrained_health_and_model_info():
    assert client.get("/health").json() == {"status": "ok", "service": "ml-sast", "model": "untrained"}
    info = client.get("/model-info").json()
    assert info["status"] == "untrained" and info["sha256"] is None and info["version"] == "untrained"


def test_untrained_scan_returns_no_findings():
    body = {"files": [{"path": "app.py", "content": "cursor.execute('SELECT * FROM t WHERE id=' + uid)"}]}
    assert client.post("/scan", json=body).json() == {"findings": []}


def test_scan_rejects_malformed_request():
    assert client.post("/scan", json={"files": [{"path": ""}]}).status_code == 422


class FakeDetector:
    def __init__(self, findings):
        self.findings = findings
        self.seen = None

    def scan(self, files):
        self.seen = files
        return self.findings


def test_trained_detector_findings_are_validated(monkeypatch):
    finding = {"rule": "python.sqli", "cwe_id": 89, "severity": "HIGH", "message": "SQL built from input",
               "file_path": "app.py", "line_number": 3, "confidence": 0.9}
    detector = FakeDetector([finding])
    monkeypatch.setattr(service, "DETECTOR", detector)
    body = {"files": [{"path": "app.py", "content": "x"}, {"path": "README.md", "content": "y"}]}
    assert client.post("/scan", json=body).json() == {"findings": [finding]}
    assert [f["path"] for f in detector.seen] == ["app.py"], "only Python/Node sources reach the model"

    monkeypatch.setattr(service, "DETECTOR", FakeDetector([{**finding, "file_path": "other.py"}]))
    assert client.post("/scan", json=body).status_code == 500
    monkeypatch.setattr(service, "DETECTOR", FakeDetector([{**finding, "severity": "SEVERE"}]))
    assert client.post("/scan", json=body).status_code == 500


def test_model_file_sets_sha256(tmp_path, monkeypatch):
    import joblib

    model = tmp_path / "model.joblib"
    joblib.dump(FakeDetector([]), model)
    (tmp_path / "model.json").write_text('{"name":"ml-sast-rf","version":"1.2.0","trained_on":"ds-v1","metrics":{"f1":0.8}}')
    monkeypatch.setenv("MODEL_PATH", str(model))
    monkeypatch.delenv("MODEL_META_PATH", raising=False)
    reloaded = importlib.reload(service)
    try:
        info = reloaded.MODEL_INFO
        assert info["status"] == "trained" and info["name"] == "ml-sast-rf" and info["version"] == "1.2.0"
        assert info["sha256"] == reloaded.sha256_file(model) and len(info["sha256"]) == 64
    finally:
        monkeypatch.setenv("MODEL_PATH", "/nonexistent/ml-sast/model.joblib")
        importlib.reload(service)
