import os

os.environ["MODEL_PATH"] = "/nonexistent/ml-dast/model.joblib"
from fastapi.testclient import TestClient  # noqa: E402

import app as service  # noqa: E402

client = TestClient(service.app)


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

    def scan(self, base_url, max_pages, max_requests):
        self.args = (base_url, max_pages, max_requests)
        return self.findings


def test_trained_detector_findings_are_validated(monkeypatch):
    finding = {"alert": "Reflected XSS", "attack_type": "xss", "severity": "HIGH", "endpoint": "http://x/search",
               "method": "GET", "param": "q", "request_payload": "<script>", "response_details": "reflected",
               "cwe_id": 79, "solution": "Encode output", "confidence": 0.8}
    detector = FakeDetector([finding])
    monkeypatch.setattr(service, "DETECTOR", detector)
    body = {"baseUrl": "http://x", "maxPages": 3, "maxRequests": 9}
    assert client.post("/scan", json=body).json() == {"findings": [finding]}
    assert detector.args == ("http://x", 3, 9)
    monkeypatch.setattr(service, "DETECTOR", FakeDetector([{**finding, "severity": "CRITICAL"}]))
    assert client.post("/scan", json=body).status_code == 500
