"""v3 detector end to end on a tiny local fixture: stored XSS (raw vs escaped guestbook) and the CSRF
heuristic (form with / without a token, session cookie without SameSite). The model is a stand-in that
never reports anything, so every finding here comes from the rules."""
import html
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import numpy as np
import pytest
from fastapi.testclient import TestClient

from dastml import CLASSES
from dastml.detector import DastDetector
from dastml.features import FEATURE_NAMES_V3

BOOK = {"raw": [], "safe": []}
FORM = "<form method='post' action='{a}'>{tok}<input name='msg' value='hi'><button>go</button></form>"


class App(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, body, status=200, headers=()):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            return self.send("<a href='/book'>book</a> <a href='/book-safe'>safe</a> <a href='/prefs'>prefs</a>",
                             headers=[("Set-Cookie", "sessionid=abc; Path=/; HttpOnly")])
        if path == "/book":  # VULN stored XSS: entries shown raw
            return self.send("<ul>" + "".join(f"<li>{m}</li>" for m in BOOK["raw"][-20:]) + "</ul>" + FORM.format(a="/book", tok=""))
        if path == "/book-safe":  # SAFE: escaped; has a token field
            return self.send("<ul>" + "".join(f"<li>{html.escape(m)}</li>" for m in BOOK["safe"][-20:]) + "</ul>"
                             + FORM.format(a="/book-safe", tok="<input type='hidden' name='csrf_token' value='t'>"))
        if path == "/prefs":
            return self.send(FORM.format(a="/prefs", tok="<input type='hidden' name='_csrf' value='t'>"))
        return self.send("nope", 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
        path = urlsplit(self.path).path
        if path in ("/book", "/book-safe"):
            BOOK["raw" if path == "/book" else "safe"].append(form.get("msg", ""))
            return self.send("", 303, headers=[("Location", path)])
        return self.send("ok")


@pytest.fixture(scope="module")
def app_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", srv.server_address[1]
    srv.shutdown()


class Never:
    def predict_proba(self, X):
        out = np.zeros((len(X), len(CLASSES)))
        out[:, 0] = 1.0
        return out


def run(monkeypatch, url, port, version="v3", stored="1"):
    import app as service
    monkeypatch.setenv("ML_DAST_ALLOWED_PORTS", str(port))
    monkeypatch.setenv("ML_DAST_RATE_PER_SEC", "1000")
    monkeypatch.setenv("ML_DAST_STORED_XSS", stored)
    det = DastDetector(Never(), 0.5, FEATURE_NAMES_V3, {"name": "stand-in"})
    det.data_version, det.payloads_file = version, "payloads_v2.json"
    monkeypatch.setattr(service, "DETECTOR", det)
    monkeypatch.setattr(service, "MODEL_INFO", {**service.MODEL_INFO, "status": "trained", "threshold": 0.5})
    r = TestClient(service.app).post("/scan", json={"baseUrl": url, "maxPages": 20, "maxRequests": 3000})
    assert r.status_code == 200, r.text
    return r.json(), det


def test_stored_xss_found_only_where_the_marker_comes_back_unescaped(app_url, monkeypatch):
    url, port = app_url
    body, det = run(monkeypatch, url, port)
    stored = [f for f in body["findings"] if f["attack_type"] == "stored_xss"]
    assert {(urlsplit(f["endpoint"]).path, f["param"]) for f in stored} == {("/book", "msg")}
    assert stored[0]["severity"] == "HIGH" and stored[0]["response_details"].startswith("[rule-based]")
    assert det.last_scan["stored_xss_fields_written"] >= 3


def test_csrf_heuristic_only_on_the_tokenless_form(app_url, monkeypatch):
    url, port = app_url
    body, _ = run(monkeypatch, url, port)
    csrf = [f for f in body["findings"] if f["attack_type"] == "csrf_heuristic"]
    assert {urlsplit(f["endpoint"]).path for f in csrf} == {"/book"}
    assert all(f["severity"] == "LOW" and f["confidence"] == 0.5 and "heuristic" in f["response_details"] for f in csrf)


def test_stored_pass_can_be_disabled_and_v2_detectors_never_write(app_url, monkeypatch):
    url, port = app_url
    before = len(BOOK["raw"])
    body, det = run(monkeypatch, url, port, stored="0")
    assert not [f for f in body["findings"] if f["attack_type"] == "stored_xss"]
    body2, _ = run(monkeypatch, url, port, version="v2")
    assert not [f for f in body2["findings"] if f["attack_type"] in ("stored_xss", "csrf_heuristic")]
    assert len([m for m in BOOK["raw"][before:] if "<i>cs" in m]) == 0, "no stored-XSS marker was written"
