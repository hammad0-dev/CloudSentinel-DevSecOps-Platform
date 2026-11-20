"""/scan end to end against a tiny local fixture app (127.0.0.1, random port)."""
import html
import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import numpy as np
import pytest
from fastapi.testclient import TestClient

from dastml import CLASSES
from dastml.detector import DastDetector
from dastml.features import FEATURE_NAMES

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript("CREATE TABLE items (id INTEGER, name TEXT); INSERT INTO items VALUES (1,'lamp'),(2,'desk');")
LOCK = threading.Lock()
INDEX = "".join(f"<a href='{u}'>{u}</a> " for u in ("/hello?name=guest", "/hello-safe?name=guest", "/item?id=1", "/item-safe?id=1", "/api?q=x"))


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, body, status=200, ctype="text/html"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        page = lambda b: f"<html><body>{b}</body></html>"
        if u.path == "/":
            return self.send(page(INDEX))
        if u.path == "/hello":  # VULN reflected XSS
            return self.send(page("<p>Hello " + q.get("name", "") + "</p>"))
        if u.path == "/hello-safe":
            return self.send(page("<p>Hello " + html.escape(q.get("name", "")) + "</p>"))
        if u.path == "/item":  # VULN SQLi, error shown
            try:
                with LOCK:
                    rows = DB.execute("SELECT name FROM items WHERE id = " + q.get("id", "0")).fetchall()
            except sqlite3.Error as exc:
                return self.send(page(f"<pre>sqlite3.OperationalError: {html.escape(str(exc))}</pre>"), 500)
            return self.send(page("".join(f"<li>{html.escape(r[0])}</li>" for r in rows) or "<p>none</p>"))
        if u.path == "/item-safe":
            try:
                pid = int(q.get("id", "0"))
            except ValueError:
                return self.send(page("<p>bad id</p>"), 400)
            with LOCK:
                rows = DB.execute("SELECT name FROM items WHERE id = ?", (pid,)).fetchall()
            return self.send(page("".join(f"<li>{html.escape(r[0])}</li>" for r in rows) or "<p>none</p>"))
        if u.path == "/api":  # SAFE: JSON reflection
            return self.send(json.dumps({"q": q.get("q", "")}), ctype="application/json")
        return self.send("not found", 404, "text/plain")


@pytest.fixture(scope="module")
def fixture_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", srv.server_address[1]
    srv.shutdown()


class RuleStandIn:
    """Transparent stand-in model for testing the scan pipeline (NOT the shipped model)."""
    ix = {k: i for i, k in enumerate(FEATURE_NAMES)}

    def predict_proba(self, X):
        out = np.zeros((len(X), len(CLASSES)))
        out[:, 0] = 1.0
        for i, x in enumerate(X):
            g = lambda k: x[self.ix[k]]
            if g("payload_xss") and g("ct_html") and g("payload_raw_reflected") and g("angle_kept"):
                out[i] = [0.05, 0.0, 0.95]
            if g("payload_sqli") and g("sql_err_new"):
                out[i] = [0.05, 0.95, 0.0]
        return out


def scan_service(monkeypatch, detector, url, port, max_requests=2000):
    import app as service
    monkeypatch.setenv("ML_DAST_ALLOWED_PORTS", str(port))
    monkeypatch.setenv("ML_DAST_RATE_PER_SEC", "500")
    monkeypatch.setattr(service, "DETECTOR", detector)
    monkeypatch.setattr(service, "MODEL_INFO", {**service.MODEL_INFO, "status": "trained", "threshold": detector.threshold})
    r = TestClient(service.app).post("/scan", json={"baseUrl": url + "/", "maxPages": 20, "maxRequests": max_requests})
    assert r.status_code == 200, r.text
    return {(urlsplit(f["endpoint"]).path, f["param"], f["cwe_id"]) for f in r.json()["findings"]}, r.json()["findings"]


def test_scan_pipeline_finds_vulnerable_and_skips_safe_endpoints(fixture_url, monkeypatch):
    url, port = fixture_url
    det = DastDetector(RuleStandIn(), 0.5, FEATURE_NAMES, {"name": "stand-in"})
    found, findings = scan_service(monkeypatch, det, url, port)
    assert found == {("/hello", "name", 79), ("/item", "id", 89)}
    f = next(x for x in findings if x["cwe_id"] == 79)
    assert f["method"] == "GET" and f["severity"] == "HIGH" and "reflected unencoded" in f["response_details"]
    assert det.last_scan["points_probed"] == 5 and det.last_scan["stopped"] is None


def test_scan_respects_request_budget(fixture_url, monkeypatch):
    url, port = fixture_url
    det = DastDetector(RuleStandIn(), 0.5, FEATURE_NAMES, {"name": "stand-in"})
    scan_service(monkeypatch, det, url, port, max_requests=60)
    assert det.last_scan["requests"] <= 60 and det.last_scan["stopped"] and "max_requests" in det.last_scan["stopped"]


MODEL = Path(__file__).resolve().parents[1] / "models/release/model.joblib"


@pytest.mark.skipif(not MODEL.exists(), reason="trained model is gitignored; run scripts/train_final.py")
def test_shipped_model_on_fixture_xss_and_no_false_positives(fixture_url, monkeypatch):
    import joblib
    url, port = fixture_url
    found, _ = scan_service(monkeypatch, joblib.load(MODEL), url, port)
    assert ("/hello", "name", 79) in found
    assert not {f for f in found if f[0] in ("/hello-safe", "/item-safe", "/api")}, found


@pytest.mark.skipif(not MODEL.exists(), reason="trained model is gitignored; run scripts/train_final.py")
@pytest.mark.xfail(strict=False, reason="known miss (2026-11-20): ml-dast-lr 1.0.0 scores the fixture's error-based SQLi at "
                   "0.79, below its 0.9 threshold; documented in docs/ml-dast-model-card.md, model not tuned for this fixture")
def test_shipped_model_on_fixture_sqli(fixture_url, monkeypatch):
    import joblib
    url, port = fixture_url
    found, _ = scan_service(monkeypatch, joblib.load(MODEL), url, port)
    assert ("/item", "id", 89) in found
