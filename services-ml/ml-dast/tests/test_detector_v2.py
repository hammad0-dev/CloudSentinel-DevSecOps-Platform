"""v2 detector end to end on a tiny local fixture: ML classes plus rule-based CWE-78 / CWE-22 / CWE-601
and passive checks, with the CWE-78-over-SQLi precedence. The model is a transparent stand-in."""
import html
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import numpy as np
import pytest
from fastapi.testclient import TestClient

from dastml import CLASSES
from dastml.detector import DastDetector
from dastml.features import FEATURE_NAMES_V2

LINKS = ["/run?host=localhost", "/run-safe?host=localhost", "/file?name=a.txt", "/go?next=/", "/go-safe?next=/", "/hi?name=x"]


class App(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, body, status=200, ctype="text/html", headers=()):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        if u.path == "/":
            return self.send("".join(f"<a href='{x}'>{x}</a> " for x in LINKS), headers=[("Set-Cookie", "sessionid=abc; Path=/")])
        if u.path == "/run":  # VULN CWE-78: shell string (fixture-local, echo only)
            out = subprocess.run("echo " + q.get("host", ""), shell=True, capture_output=True, text=True, timeout=5).stdout
            return self.send(f"<pre>{html.escape(out)}</pre>")
        if u.path == "/run-safe":
            return self.send(f"<pre>{html.escape(q.get('host', ''))}</pre>")
        if u.path == "/file":  # VULN CWE-22 (simulated: no real file is read)
            name = q.get("name", "")
            if "etc/passwd" in name and ".." in name:
                return self.send("root:x:0:0:root:/root:/bin/sh\n", ctype="text/plain")
            return self.send("contents of a.txt", ctype="text/plain")
        if u.path == "/go":  # VULN CWE-601
            return self.send("", 302, headers=[("Location", q.get("next", "/"))])
        if u.path == "/go-safe":
            nxt = q.get("next", "/")
            return self.send("", 302, headers=[("Location", nxt if nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt else "/")])
        if u.path == "/hi":
            return self.send(f"<p>hi {html.escape(q.get('name', ''))}</p>")
        return self.send("nope", 404, "text/plain")


@pytest.fixture(scope="module")
def app_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", srv.server_address[1]
    srv.shutdown()


class SqliOnParity:
    """Stand-in: calls SQLi on any quote-parity flip (which a shell also produces); never XSS."""
    ix = {k: i for i, k in enumerate(FEATURE_NAMES_V2)}

    def predict_proba(self, X):
        out = np.zeros((len(X), len(CLASSES)))
        out[:, 0] = 1.0
        for i, x in enumerate(X):
            if x[self.ix["payload_sqli"]] and x[self.ix["parity_flip"]]:
                out[i] = [0.05, 0.95, 0.0]
        return out


def v2_detector():
    det = DastDetector(SqliOnParity(), 0.5, FEATURE_NAMES_V2, {"name": "stand-in"})
    det.data_version, det.payloads_file = "v2", "payloads_v2.json"
    return det


def run(monkeypatch, url, port, max_requests=3000):
    import app as service
    monkeypatch.setenv("ML_DAST_ALLOWED_PORTS", str(port))
    monkeypatch.setenv("ML_DAST_RATE_PER_SEC", "1000")
    det = v2_detector()
    monkeypatch.setattr(service, "DETECTOR", det)
    monkeypatch.setattr(service, "MODEL_INFO", {**service.MODEL_INFO, "status": "trained", "threshold": 0.5})
    r = TestClient(service.app).post("/scan", json={"baseUrl": url, "maxPages": 20, "maxRequests": max_requests})
    assert r.status_code == 200, r.text
    return r.json(), det


def test_v2_rules_passive_and_precedence(app_url, monkeypatch):
    url, port = app_url
    body, det = run(monkeypatch, url, port)
    by = {(urlsplit(f["endpoint"]).path, f["cwe_id"]) for f in body["findings"] if f["param"]}
    assert (("/run", 78) in by) and (("/file", 22) in by) and (("/go", 601) in by)
    assert not {k for k in by if k[0] in ("/run-safe", "/go-safe", "/hi")}, by
    assert ("/run", 89) not in by, "SQLi from shell quote parity yields to the confirmed CWE-78"
    rule = [f for f in body["findings"] if f["cwe_id"] in (78, 22, 601)]
    assert all(f["response_details"].startswith("[rule-based") and f["confidence"] == 1.0 for f in rule)
    passive = {f["attack_type"]: f["severity"] for f in body["findings"] if f["attack_type"].startswith("passive_")}
    assert {"passive_missing_csp", "passive_missing_nosniff", "passive_missing_frame_protection",
            "passive_cookie_no_httponly", "passive_cookie_no_samesite"} <= set(passive)
    assert "passive_cors_any_origin" not in passive and set(passive.values()) <= {"LOW", "INFORMATIONAL"}
    assert body["coverage"]["requests"] <= 3000


def test_v2_respects_the_request_budget(app_url, monkeypatch):
    url, port = app_url
    body, det = run(monkeypatch, url, port, max_requests=40)
    assert det.last_scan["requests"] <= 40 and det.last_scan["stopped"]
