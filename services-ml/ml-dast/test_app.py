import os
import sys
from pathlib import Path

os.environ["MODEL_PATH"] = "/nonexistent/ml-dast/model.joblib"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fastapi.testclient import TestClient  # noqa: E402

import app as service  # noqa: E402

client = TestClient(service.app)
LAB = "http://127.0.0.1:5101"


def test_untrained_health_and_model_info():
    assert client.get("/health").json() == {"status": "ok", "service": "ml-dast", "model": "untrained"}
    info = client.get("/model-info").json()
    assert info["status"] == "untrained" and info["sha256"] is None


def test_untrained_scan_returns_no_findings():
    body = {"baseUrl": "http://staging.example:30080", "maxPages": 5, "maxRequests": 20}
    assert client.post("/scan", json=body).json() == {"findings": []}


def test_scan_validates_target_and_bounds():
    assert client.post("/scan", json={"baseUrl": "file:///etc/passwd"}).status_code == 422
    assert client.post("/scan", json={"baseUrl": "http://x", "maxRequests": 100000}).status_code == 422


class FakeDetector:
    def __init__(self, findings):
        self.findings = findings
        self.args = None

    def scan(self, base_url, max_pages, max_requests):
        self.args = (base_url, max_pages, max_requests)
        return self.findings


FINDING = {"alert": "Reflected XSS", "attack_type": "xss", "severity": "HIGH", "endpoint": "http://127.0.0.1:5101/search",
           "method": "GET", "param": "q", "request_payload": "<script>", "response_details": "reflected",
           "cwe_id": 79, "solution": "Encode output", "confidence": 0.8}


def test_trained_detector_findings_are_validated(monkeypatch):
    detector = FakeDetector([FINDING])
    monkeypatch.setattr(service, "DETECTOR", detector)
    body = {"baseUrl": LAB, "maxPages": 3, "maxRequests": 9}
    assert client.post("/scan", json=body).json() == {"findings": [FINDING]}
    assert detector.args == (LAB, 3, 9)
    monkeypatch.setattr(service, "DETECTOR", FakeDetector([{**FINDING, "severity": "CRITICAL"}]))
    assert client.post("/scan", json=body).status_code == 500


def test_target_outside_allowlist_is_refused_before_any_scan(monkeypatch):
    detector = FakeDetector([FINDING])
    monkeypatch.setattr(service, "DETECTOR", detector)
    for url in ("http://x", "http://example.com/", "http://127.0.0.1:22/", "http://10.0.0.1:5101/"):
        r = client.post("/scan", json={"baseUrl": url})
        assert r.status_code == 400 and "target refused" in r.json()["detail"], url
    assert detector.args is None, "the detector must not be called for a refused target"


def test_allowlist_is_configurable(monkeypatch):
    detector = FakeDetector([])
    monkeypatch.setattr(service, "DETECTOR", detector)
    monkeypatch.setenv("ML_DAST_ALLOWED_HOSTS", "staging.lab")
    monkeypatch.setenv("ML_DAST_ALLOWED_PORTS", "30080")
    assert client.post("/scan", json={"baseUrl": "http://staging.lab:30080"}).status_code == 200
    assert client.post("/scan", json={"baseUrl": LAB}).status_code == 400
