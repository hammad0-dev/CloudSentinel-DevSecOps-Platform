"""v5 authenticated scanning against tests/fake_auth_app.py (127.0.0.1, random port).

Proves: login works (CSRF token from the login form), the session is reused, re-login after expiry,
logout and delete are never requested, credentials never appear in logs, results or errors, the
service refuses credentials bound to another origin, and the unauthenticated scan is unchanged
(byte-identical request sequence and findings vs. the pre-auth code, recorded in
tests/data/unauth_baseline_v5.json)."""
import json
import logging
from pathlib import Path
from urllib.parse import parse_qsl

import joblib
import pytest
from fastapi.testclient import TestClient

import fake_auth_app as fa
from dastml.auth import AuthConfig, AuthError, AuthSession, Credentials, destructive_path, destructive_text, load_credentials
from dastml.detector import DastDetector
from dastml.features import FEATURE_NAMES
from dastml.guards import GuardedClient, GuardError, TargetPolicy, parse_ports
from test_scan_fixture import RuleStandIn

ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads((ROOT / "tests/data/unauth_baseline_v5.json").read_text())


@pytest.fixture(scope="module")
def app_url():
    srv = fa.start()
    port = srv.server_address[1]
    yield f"http://127.0.0.1:{port}", port
    srv.shutdown()


@pytest.fixture(autouse=True)
def fresh_state():
    fa.APP.log.clear()
    fa.APP.expire_all()
    fa.APP.logins = 0
    yield


def policy(port, **kw):
    return TargetPolicy(allowed_ports=parse_ports(str(port)), rate_per_sec=500.0, **kw)


def config(url, password=fa.PASSWORD, **kw):
    creds = Credentials(fa.USER, password, (url,))
    return AuthConfig(login_path="/login", credentials=creds, login_page="/login", csrf_field="csrf_token",
                      success_cookie="sid", **kw)


def stand_in():
    det = DastDetector(RuleStandIn(), 0.5, FEATURE_NAMES, {"name": "stand-in"})
    det.data_version, det.payloads_file = "v4", "payloads_v2.json"  # exercise the stored-XSS and passive passes too
    return det


def normalized(log):
    return [[r["method"], r["path"], sorted(k for k, _ in parse_qsl(r["query"], keep_blank_values=True)),
             sorted(k for k, _ in parse_qsl(r["body"], keep_blank_values=True))] for r in log]


# --- unauthenticated behaviour unchanged ------------------------------------------------------

@pytest.mark.parametrize("name", ["release_v2", "release_v4"])
def test_unauthenticated_scan_is_unchanged(app_url, name):
    path = ROOT / f"models/{name}/model.joblib"
    if not path.is_file():
        pytest.skip(f"{name} is not present (models are not committed)")
    url, port = app_url
    det = joblib.load(path)
    findings = det.scan(url, 50, 2000, policy=policy(port))
    want = BASELINE["scans"][name]
    assert normalized(fa.APP.log) == want["requests"]
    got = sorted([f["endpoint"].split(str(port))[-1], f["param"], f.get("cwe_id")] for f in findings)
    assert got == want["findings"]
    assert {k: v for k, v in det.last_scan.items() if k != "errors"} == want["coverage"]
    assert "auth" not in det.last_scan


def test_unauthenticated_scan_has_no_skip_list(app_url):
    """Without auth the destructive-action list is not applied (pre-v5 behaviour): the guard allows /logout."""
    url, port = app_url
    client = GuardedClient(url, policy(port))
    assert client.check_url("/logout").endswith("/logout")
    resp, _ = client.request("DELETE", "/account")  # not refused without auth
    assert resp.status_code in (302, 404, 501)


# --- login, session reuse, re-login -----------------------------------------------------------

def test_login_works_and_session_is_reused(app_url):
    url, port = app_url
    det = stand_in()
    findings = det.scan(url, 50, 3000, policy=policy(port), auth=config(url))
    assert fa.APP.logins == 1, "one login, the session is reused for every pass"
    assert det.last_scan["auth"] == {"logins": 1, "relogins": 0}
    found = {(f["endpoint"].split(str(port))[-1], f["param"], f.get("cwe_id")) for f in findings}
    assert ("/account/search", "q", 79) in found  # reachable only when logged in
    paths = {r["path"] for r in fa.APP.log}
    assert {"/account", "/account/search", "/account/orders"} <= paths
    login_posts = [r for r in fa.APP.log if r["method"] == "POST" and r["path"] == "/login"]
    assert len(login_posts) >= 1 and "csrf_token=" in login_posts[0]["body"]


def test_unauthenticated_scan_does_not_reach_the_protected_page(app_url):
    url, port = app_url
    findings = stand_in().scan(url, 50, 3000, policy=policy(port))
    assert not any("/account/search" in f["endpoint"] for f in findings)
    assert "/account/search" not in {r["path"] for r in fa.APP.log}


def test_relogin_after_expiry(app_url):
    url, port = app_url
    session = AuthSession(config(url))
    client = GuardedClient(url, policy(port), auth=session)
    client.login()
    resp, _ = client.request("GET", "/account")
    assert resp.status_code == 200 and "Welcome" in resp.text
    fa.APP.expire_all()  # the server forgets every session
    resp, _ = client.request("GET", "/account")
    assert resp.status_code == 200 and "Welcome" in resp.text, "expired session detected, logged in again, request resent"
    assert session.relogins == 1 and session.logins == 2 and fa.APP.logins == 2


def test_json_login_with_bearer_token_and_relogin(app_url):
    url, port = app_url
    cfg = AuthConfig(login_path="/api/login", credentials=Credentials(fa.USER, fa.PASSWORD, (url,)), body="json",
                     token_json="token", logged_out_status=(401,))
    session = AuthSession(cfg)
    client = GuardedClient(url, policy(port), auth=session)
    client.login()
    resp, _ = client.request("GET", "/api/me")
    assert resp.status_code == 200
    assert [r["auth"].startswith("Bearer ") for r in fa.APP.log if r["path"] == "/api/me"] == [True]
    fa.APP.expire_all()
    resp, _ = client.request("GET", "/api/me")
    assert resp.status_code == 200 and session.relogins == 1 and fa.APP.logins == 2


def test_relogin_is_capped(app_url):
    url, port = app_url
    session = AuthSession(config(url, max_relogins=2))
    client = GuardedClient(url, policy(port), auth=session)
    client.login()
    for _ in range(5):
        fa.APP.expire_all()
        client.request("GET", "/account")
    assert session.relogins == 2


def test_failed_login_refuses_the_scan(app_url):
    url, port = app_url
    with pytest.raises(AuthError) as exc:
        stand_in().scan(url, 50, 500, policy=policy(port), auth=config(url, password="wrong-Pass-1"))
    assert "wrong-Pass-1" not in str(exc.value)
    assert not any(r["path"].startswith("/account") for r in fa.APP.log), "no scanning after a failed login"


# --- destructive actions ----------------------------------------------------------------------

def test_logout_and_delete_are_never_requested(app_url):
    url, port = app_url
    stand_in().scan(url, 50, 3000, policy=policy(port), auth=config(url))
    for r in fa.APP.log:
        assert r["path"] not in ("/logout", "/account/delete", "/account/close"), r
        assert r["method"] != "DELETE"


def test_destructive_requests_are_refused_by_the_guard(app_url):
    url, port = app_url
    client = GuardedClient(url, policy(port), auth=AuthSession(config(url)))
    for path in ("/logout", "/account/delete", "/user/change-password", "/admin/reset-db", "/api/v2/account-recovery/reset"):
        with pytest.raises(GuardError):
            client.request("GET", path)
    with pytest.raises(GuardError):
        client.request("DELETE", "/account")
    with pytest.raises(GuardError):
        client.request("GET", "/danger", params={"delete": "1"})
    assert fa.APP.log == []


def test_destructive_list_matching():
    for path in ("/logout", "/logout/", "/user/logout", "/v2/users/logout/x", "/sign-out", "/items/3/delete",
                 "/account/remove", "/reset", "/createdb", "/users/v1/name1/password", "/forgotpw", "/setup"):
        assert destructive_path(path), path
    for path in ("/", "/login", "/user/login", "/login/auth", "/students/", "/courses/1/review", "/api/v2/passphrase",
                 "/search", "/profile", "/dashboard", "/posts", "/v2/notes", "/release/1"):
        assert not destructive_path(path), path
    assert destructive_path("/danger", ["delete"]) and destructive_path("/x", ["remove_item"])
    assert not destructive_path("/login", ["username", "password", "csrf_token"])
    for text in ("Log out", "Logout", "Sign out", "Delete account", "Reset database", "Change password"):
        assert destructive_text(text), text
    for text in ("Log in", "Search", "Submit", "Save", "orders", ""):
        assert not destructive_text(text), text


# --- credentials ------------------------------------------------------------------------------

def test_credentials_never_appear_in_logs_results_or_reprs(app_url, caplog, capsys):
    url, port = app_url
    caplog.set_level(logging.DEBUG)
    cfg = config(url)
    det = stand_in()
    findings = det.scan(url, 50, 3000, policy=policy(port), auth=cfg)
    with pytest.raises(AuthError) as bad:
        det.scan(url, 50, 100, policy=policy(port), auth=config(url, password="Other-Secret-99"))
    out = capsys.readouterr()
    blob = "\n".join([caplog.text, out.out, out.err, json.dumps(findings), json.dumps(det.last_scan), repr(cfg),
                      repr(cfg.credentials), str(bad.value), repr(AuthSession(cfg).events)])
    for secret in (fa.PASSWORD, "Other-Secret-99"):
        assert secret not in blob
    assert fa.USER not in repr(cfg) and fa.USER not in repr(cfg.credentials)


def test_credentials_are_bound_to_their_origin(tmp_path):
    f = tmp_path / "auth.json"
    f.write_text(json.dumps({"LAB": {"username": "u", "password": "p", "origins": ["http://127.0.0.1:5106"]}}))
    assert load_credentials("LAB", "http://127.0.0.1:5106/", path=f, environ={}).username == "u"
    with pytest.raises(AuthError):
        load_credentials("LAB", "http://127.0.0.1:5107/", path=f, environ={})
    with pytest.raises(AuthError):
        load_credentials("LAB", "http://localhost:5106/", path=f, environ={})
    env = {"ML_DAST_AUTH_X_USERNAME": "u", "ML_DAST_AUTH_X_PASSWORD": "p"}
    with pytest.raises(AuthError):  # an env profile without bound origins is refused
        load_credentials("X", "http://127.0.0.1:5106/", path=f, environ=env)
    with pytest.raises(AuthError):
        load_credentials("../etc", "http://127.0.0.1:5106/", path=f, environ={})


# --- service /scan ----------------------------------------------------------------------------

def spec(**kw):
    return {"loginPath": "/login", "loginPagePath": "/login", "csrfField": "csrf_token", "success": {"cookie": "sid"},
            "credentialRef": "FAKEAPP", **kw}


def service_client(monkeypatch, port, url, origins=None):
    import app as service
    monkeypatch.setenv("ML_DAST_ALLOWED_PORTS", str(port))
    monkeypatch.setenv("ML_DAST_RATE_PER_SEC", "500")
    monkeypatch.setenv("ML_DAST_AUTH_FAKEAPP_USERNAME", fa.USER)
    monkeypatch.setenv("ML_DAST_AUTH_FAKEAPP_PASSWORD", fa.PASSWORD)
    monkeypatch.setenv("ML_DAST_AUTH_FAKEAPP_ORIGINS", origins or url)
    det = stand_in()
    monkeypatch.setattr(service, "DETECTOR", det)
    monkeypatch.setattr(service, "MODEL_INFO", {**service.MODEL_INFO, "status": "trained", "threshold": 0.5})
    return TestClient(service.app), det


def test_service_authenticated_scan(app_url, monkeypatch):
    url, port = app_url
    client, det = service_client(monkeypatch, port, url)
    r = client.post("/scan", json={"baseUrl": url + "/", "maxRequests": 3000, "auth": spec()})
    assert r.status_code == 200, r.text
    assert any(f["param"] == "q" and "/account/search" in f["endpoint"] for f in r.json()["findings"])
    assert r.json()["coverage"]["auth"]["logins"] == 1
    assert fa.PASSWORD not in r.text


def test_service_refuses_credentials_for_another_origin_before_any_traffic(app_url, monkeypatch):
    url, port = app_url
    client, _ = service_client(monkeypatch, port, url, origins="http://127.0.0.1:1")
    r = client.post("/scan", json={"baseUrl": url + "/", "auth": spec()})
    assert r.status_code == 400 and "auth refused" in r.text
    assert fa.APP.log == []


def test_service_rejects_inline_credentials_and_bad_paths(app_url, monkeypatch):
    url, port = app_url
    client, _ = service_client(monkeypatch, port, url)
    for bad in (spec(password="x"), spec(username="x"), spec(loginPath="http://evil.test/login"), spec(loginPath="//evil.test/x"),
                spec(credentialRef="../x"), {k: v for k, v in spec().items() if k != "success"}):
        r = client.post("/scan", json={"baseUrl": url + "/", "auth": bad})
        assert r.status_code == 422, (bad, r.text)
    assert fa.APP.log == []


def test_service_without_auth_is_unchanged(app_url, monkeypatch):
    url, port = app_url
    client, det = service_client(monkeypatch, port, url)
    r = client.post("/scan", json={"baseUrl": url + "/", "maxRequests": 3000})
    assert r.status_code == 200
    assert "auth" not in (r.json()["coverage"] or {})
    assert fa.APP.logins == 0
