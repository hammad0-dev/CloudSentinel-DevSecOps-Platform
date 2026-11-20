import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from dastml.guards import BudgetExceeded, GuardedClient, GuardError, TargetPolicy, parse_ports


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/off"):
            self.send_response(302)
            self.send_header("Location", "http://example.com/steal")
            self.end_headers()
        elif self.path.startswith("/same"):
            self.send_response(302)
            self.send_header("Location", "/landing")
            self.end_headers()
        else:
            body = b"ok " + self.path.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def policy(port, **kw):
    return TargetPolicy(allowed_ports=frozenset({port}), **kw)


@pytest.mark.parametrize("url", [
    "http://example.com/", "http://10.0.0.5:5101/", "http://169.254.169.254/latest/meta-data/",
    "http://127.1:5101/", "http://0x7f000001:5101/", "http://[::1]:5101/", "http://2130706433:5101/",
    "http://user:pw@127.0.0.1:5101/", "ftp://127.0.0.1:5101/", "file:///etc/passwd", "gopher://127.0.0.1:5101/",
    "http://127.0.0.1.nip.io:5101/", "http://localhost.evil.com:5101/",
])
def test_refuses_targets_outside_allowlist(url):
    with pytest.raises(GuardError):
        TargetPolicy().origin_of(url)


def test_refuses_port_outside_allowlist():
    with pytest.raises(GuardError, match="port"):
        TargetPolicy().origin_of("http://127.0.0.1:22/")
    with pytest.raises(GuardError, match="port"):
        TargetPolicy().origin_of("http://localhost/")  # port 80 is not in the lab range


def test_accepts_lab_targets():
    assert TargetPolicy().origin_of("http://127.0.0.1:5101/") == ("http", "127.0.0.1", 5101)
    assert TargetPolicy().origin_of("http://LOCALHOST:5108/x") == ("http", "localhost", 5108)


def test_env_configuration(monkeypatch):
    monkeypatch.setenv("ML_DAST_ALLOWED_HOSTS", "staging.lab")
    monkeypatch.setenv("ML_DAST_ALLOWED_PORTS", "8080,9000-9001")
    p = TargetPolicy.from_env()
    assert p.origin_of("http://staging.lab:9001/") == ("http", "staging.lab", 9001)
    with pytest.raises(GuardError):
        p.origin_of("http://127.0.0.1:5101/")
    with pytest.raises(ValueError):
        parse_ports("1-5000")  # absurdly wide ranges are refused


def test_same_origin_only(server):
    c = GuardedClient(f"http://127.0.0.1:{server}/", policy(server))
    with pytest.raises(GuardError, match="same-origin"):
        c.request("GET", "http://localhost:%d/" % server)  # different host string = different origin
    with pytest.raises(GuardError):
        c.request("GET", "http://example.com/")
    assert c.requests_sent == 0, "refused requests must not be sent"


def test_off_origin_redirect_is_not_followed(server):
    c = GuardedClient(f"http://127.0.0.1:{server}/", policy(server))
    resp, _ = c.request("GET", "/off")
    assert resp.status_code == 302 and c.requests_sent == 1


def test_same_origin_redirect_is_followed_and_counted(server):
    c = GuardedClient(f"http://127.0.0.1:{server}/", policy(server))
    resp, _ = c.request("GET", "/same")
    assert resp.status_code == 200 and resp.text == "ok /landing" and c.requests_sent == 2


def test_request_budget(server):
    c = GuardedClient(f"http://127.0.0.1:{server}/", policy(server, max_requests=3, rate_per_sec=1000))
    for _ in range(3):
        c.request("GET", "/a")
    with pytest.raises(BudgetExceeded):
        c.request("GET", "/a")


def test_page_budget(server):
    c = GuardedClient(f"http://127.0.0.1:{server}/", policy(server, max_pages=2))
    c.count_page()
    c.count_page()
    with pytest.raises(BudgetExceeded):
        c.count_page()


def test_rate_limit(server):
    c = GuardedClient(f"http://127.0.0.1:{server}/", policy(server, rate_per_sec=10))
    t0 = time.monotonic()
    for _ in range(4):
        c.request("GET", "/r")
    assert time.monotonic() - t0 >= 0.3  # 4 requests at 10/s need at least 3 gaps of 0.1 s


def test_skip_list(server):
    c = GuardedClient(f"http://127.0.0.1:{server}/", policy(server, skip_paths=("/contributions", "/allocations/{userId}")))
    for path in ("/contributions", "/contributions?x=1", "/allocations/2"):
        with pytest.raises(GuardError, match="skip"):
            c.request("GET", path)
    resp, _ = c.request("GET", "/allocationsx")
    assert resp.status_code == 200


def test_env_proxies_are_ignored(server, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://10.255.255.1:3128")
    monkeypatch.setenv("http_proxy", "http://10.255.255.1:3128")
    c = GuardedClient(f"http://127.0.0.1:{server}/", policy(server, timeout_sec=2))
    resp, _ = c.request("GET", "/p")
    assert resp.text == "ok /p"
