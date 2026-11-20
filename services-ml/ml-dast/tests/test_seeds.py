"""Crawl seeds (seedPaths) and OpenAPI import (openapiUrl): coverage for endpoints that are not linked
from HTML, under the same allowlist / same-origin guards as the crawler."""
import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from dastml.crawl import crawl
from dastml.detector import DastDetector
from dastml.features import FEATURE_NAMES
from dastml.guards import GuardedClient, GuardError, TargetPolicy
from dastml.openapi import OpenAPIError, points_from_spec
from test_scan_fixture import RuleStandIn

SPEC = {
    "openapi": "3.0.3",
    "servers": [{"url": "/"}],
    "paths": {
        "/hello": {"get": {"parameters": [{"name": "name", "in": "query", "schema": {"type": "string", "example": "guest"}}]}},
        "/hello-safe": {"get": {"parameters": [{"$ref": "#/components/parameters/Name"}]}},
    },
    "components": {"parameters": {"Name": {"name": "name", "in": "query", "schema": {"type": "string"}}}},
}
HITS = []


class JsonRootApp(BaseHTTPRequestHandler):
    """An API whose root returns JSON and links nothing: the crawler alone finds no injection point."""

    def log_message(self, *a):
        pass

    def send(self, body, ctype="text/html", status=200):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        HITS.append(self.path)
        u = urlsplit(self.path)
        name = parse_qs(u.query).get("name", [""])[0]
        if u.path == "/":
            return self.send(json.dumps({"service": "demo", "status": "ok"}), "application/json")
        if u.path == "/openapi.json":
            return self.send(json.dumps(SPEC), "application/json")
        if u.path == "/hello":  # VULN reflected XSS
            return self.send(f"<html><body><p>Hello {name}</p></body></html>")
        if u.path == "/hello-safe":
            return self.send(f"<html><body><p>Hello {html.escape(name)}</p></body></html>")
        return self.send("not found", "text/plain", 404)


@pytest.fixture(scope="module")
def app_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), JsonRootApp)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", srv.server_address[1]
    srv.shutdown()


def post_scan(monkeypatch, port, body, detector=None):
    import app as service
    detector = detector or DastDetector(RuleStandIn(), 0.5, FEATURE_NAMES, {"name": "stand-in"})
    monkeypatch.setenv("ML_DAST_ALLOWED_PORTS", str(port))
    monkeypatch.setenv("ML_DAST_RATE_PER_SEC", "500")
    monkeypatch.setattr(service, "DETECTOR", detector)
    monkeypatch.setattr(service, "MODEL_INFO", {**service.MODEL_INFO, "status": "trained", "threshold": 0.5})
    return TestClient(service.app).post("/scan", json={"maxPages": 20, "maxRequests": 2000, **body}), detector


def found(resp):
    assert resp.status_code == 200, resp.text
    return {(urlsplit(f["endpoint"]).path, f["param"], f["cwe_id"]) for f in resp.json()["findings"]}


def test_without_seeds_a_json_root_app_has_no_injection_points(app_url, monkeypatch):
    url, port = app_url
    r, det = post_scan(monkeypatch, port, {"baseUrl": url})
    assert found(r) == set()
    assert r.json()["coverage"]["points_found"] == 0, "coverage shows the scan tested nothing"


def test_seed_paths_reach_unlinked_endpoints(app_url, monkeypatch):
    url, port = app_url
    r, det = post_scan(monkeypatch, port, {"baseUrl": url, "seedPaths": ["/hello?name=guest", "/hello-safe?name=guest"]})
    assert found(r) == {("/hello", "name", 79)}, "vulnerable endpoint found, safe twin not flagged"
    assert r.json()["coverage"]["points_found"] == 2


def test_openapi_url_reaches_unlinked_endpoints(app_url, monkeypatch):
    url, port = app_url
    for spec_url in ("/openapi.json", url + "/openapi.json"):
        r, _ = post_scan(monkeypatch, port, {"baseUrl": url, "openapiUrl": spec_url})
        assert found(r) == {("/hello", "name", 79)}


@pytest.mark.parametrize("seed", ["http://example.com/x", "//example.com/x", "http://localhost:{port}/x",
                                  "http://127.0.0.1:22/x", "https://127.0.0.1:{port}/x"])
def test_off_origin_seeds_refuse_the_scan_before_any_traffic(app_url, monkeypatch, seed):
    url, port = app_url
    seed = seed.format(port=port)
    for body in ({"seedPaths": ["/hello?name=a", seed]}, {"openapiUrl": seed}):
        HITS.clear()
        r, det = post_scan(monkeypatch, port, {"baseUrl": url, **body})
        assert r.status_code == 400 and "target refused" in r.json()["detail"], (seed, r.text)
        assert HITS == [], "no request may reach the target when a seed is refused"


def test_detector_refuses_off_origin_seed_itself(app_url, monkeypatch):
    """Defence in depth: the detector checks seeds too, not only the HTTP layer."""
    url, port = app_url
    monkeypatch.setenv("ML_DAST_ALLOWED_PORTS", str(port))
    det = DastDetector(RuleStandIn(), 0.5, FEATURE_NAMES, {"name": "stand-in"})
    HITS.clear()
    with pytest.raises(GuardError):
        det.scan(url, 5, 50, seed_paths=["http://example.com/"])
    assert HITS == []


def test_crawl_seed_on_skip_list_is_not_requested(app_url):
    url, port = app_url
    policy = TargetPolicy(allowed_ports=frozenset({port}), rate_per_sec=500, skip_paths=("/hello",))
    HITS.clear()
    points, visited = crawl(GuardedClient(url, policy), "/", start_paths=["/hello?name=x", "/hello-safe?name=x"])
    assert visited == ["/", "/hello-safe"] and not any(h.startswith("/hello?") for h in HITS)


def test_model_without_seed_support_fails_loudly(app_url, monkeypatch):
    class OldDetector:
        threshold = 0.5

        def scan(self, base_url, max_pages, max_requests):
            return []

    url, port = app_url
    r, _ = post_scan(monkeypatch, port, {"baseUrl": url, "seedPaths": ["/hello?name=x"]}, detector=OldDetector())
    assert r.status_code == 501 and "seedPaths" in r.json()["detail"]


def test_seed_request_validation(monkeypatch):
    import app as service
    c = TestClient(service.app)
    assert c.post("/scan", json={"baseUrl": "http://x", "seedPaths": ["/a"] * 51}).status_code == 422
    assert c.post("/scan", json={"baseUrl": "http://x", "seedPaths": [""]}).status_code == 422
    assert c.post("/scan", json={"baseUrl": "http://x", "seedPaths": ["/" + "a" * 600]}).status_code == 422


def test_openapi_points_from_spec():
    spec = {
        "openapi": "3.1.0",
        "servers": [{"url": "https://elsewhere.example/api/v1"}],
        "paths": {
            "/items/{id}/reviews": {
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                "get": {"parameters": [{"name": "sort", "in": "query", "schema": {"enum": ["new", "old"]}}]},
                "post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Review"}}}}},
                "delete": {"parameters": [{"name": "force", "in": "query"}]},
            },
            "/login": {"post": {"requestBody": {"content": {"application/x-www-form-urlencoded": {
                "schema": {"properties": {"user": {"type": "string"}, "remember": {"type": "boolean"}}}}}}}},
        },
        "components": {"schemas": {"Review": {"type": "object", "properties": {"text": {"type": "string"}, "stars": {"type": "integer", "example": 5}}}}},
    }
    pts = {(p.method, p.path, p.param, p.location): p for p in points_from_spec(spec)}
    # the server's host is never used, only its path prefix; DELETE is never probed
    assert set(pts) == {
        ("GET", "/api/v1/items/1/reviews", "sort", "query"),
        ("GET", "/api/v1/items/1/reviews", "{seg4}", "path"),
        ("POST", "/api/v1/items/1/reviews", "{seg4}", "path"),
        ("POST", "/api/v1/items/1/reviews", "text", "json"),
        ("POST", "/api/v1/items/1/reviews", "stars", "json"),
        ("POST", "/api/v1/login", "user", "form"),
        ("POST", "/api/v1/login", "remember", "form"),
    }
    assert pts[("GET", "/api/v1/items/1/reviews", "sort", "query")].params == (("sort", "new"),)
    assert pts[("POST", "/api/v1/items/1/reviews", "stars", "json")].params == (("text", "test"), ("stars", "5"))
    assert pts[("GET", "/api/v1/items/1/reviews", "{seg4}", "path")].template == "/api/v1/items/{seg4}/reviews"
    assert pts[("POST", "/api/v1/login", "remember", "form")].params == (("user", "test"), ("remember", "true"))


def test_swagger2_and_bad_documents():
    spec = {"swagger": "2.0", "basePath": "/v2", "paths": {"/pet/findByStatus": {"get": {"parameters": [
        {"name": "status", "in": "query", "type": "string", "default": "available"}]}},
        "/pet": {"post": {"parameters": [{"name": "body", "in": "body", "schema": {"properties": {"name": {"type": "string"}}}}]}}}}
    keys = {(p.method, p.path, p.param, p.location) for p in points_from_spec(spec)}
    assert keys == {("GET", "/v2/pet/findByStatus", "status", "query"), ("POST", "/v2/pet", "name", "json")}
    for bad in ({}, {"paths": []}, [], "x"):
        with pytest.raises(OpenAPIError):
            points_from_spec(bad)
