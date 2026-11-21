"""v3 rules: stored XSS (unescaped marker in a later rendered page) and the CSRF heuristic."""
from dastml.rules import csrf_findings, stored_xss_findings
from dastml.stored import escaped_sign, raw_sign, stored_value, write_points
from dastml.crawl import InjectionPoint

BASE = "http://127.0.0.1:5101/"


def rec(hits, path="/v3/guestbook", param="message"):
    return {"point": {"method": "POST", "path": path, "param": param, "location": "form"}, "marker": "csab12cd34ef",
            "value": stored_value("csab12cd34ef"), "hits": hits}


def test_marker_carries_html_specials_and_signs_differ():
    m = "csab12cd34ef"
    v = stored_value(m)
    assert all(c in v for c in "<>\"'") and raw_sign(m) in v
    assert raw_sign(m) != escaped_sign(m)


def test_stored_xss_needs_an_unescaped_marker_in_a_rendered_page():
    raw = rec([{"page": "/v3/guestbook", "status": 200, "rendered": True, "raw": True, "escaped": False}])
    f = stored_xss_findings([raw], BASE)
    assert len(f) == 1 and f[0]["severity"] == "HIGH" and f[0]["cwe_id"] == 79 and f[0]["engine"] == "rule"
    assert f[0]["attack_type"] == "stored_xss" and "/v3/guestbook" in f[0]["response_details"]
    escaped = rec([{"page": "/v3/guestbook-safe", "status": 200, "rendered": True, "raw": False, "escaped": True}])
    redirect_body = rec([{"page": "/next", "status": 302, "rendered": False, "raw": True, "escaped": False}])
    json_echo = rec([{"page": "/api/x", "status": 200, "rendered": False, "raw": True, "escaped": False}])
    assert stored_xss_findings([escaped, redirect_body, json_echo, rec([])], BASE) == []


def test_only_post_put_form_or_json_fields_are_written():
    pts = [InjectionPoint("POST", "/a", "x", "form"), InjectionPoint("PUT", "/b", "y", "json"),
           InjectionPoint("GET", "/c", "z", "query"), InjectionPoint("POST", "/d/1", "{seg2}", "path")]
    assert [p.path for p in write_points(pts)] == ["/a", "/b"]


def snap(*cookies):
    return {"kind": "page", "headers": {"set-cookie": list(cookies)}}


FORMS = [{"page": "/v3/settings", "action": "/v3/settings", "method": "POST", "fields": ["display_name"]},
         {"page": "/v3/settings-safe", "action": "/v3/settings-safe", "method": "POST", "fields": ["csrf_token", "display_name"]},
         {"page": "/search", "action": "/search", "method": "GET", "fields": ["q"]},
         {"page": "/account", "action": "/account/token", "method": "POST", "fields": []}]


def test_csrf_heuristic_fires_for_tokenless_post_forms_with_an_unprotected_session_cookie():
    f = csrf_findings(FORMS, [snap("lf_session=x; HttpOnly; Path=/")], BASE)
    assert sorted(x["endpoint"] for x in f) == [BASE + "account/token", BASE + "v3/settings"]
    assert all(x["severity"] == "LOW" and x["confidence"] == 0.5 and "heuristic" in x["response_details"] for x in f)
    assert all(x["cwe_id"] == 352 for x in f)


def test_csrf_heuristic_is_silent_with_samesite_or_without_a_session_cookie():
    assert csrf_findings(FORMS, [snap("lx_session=x; HttpOnly; SameSite=Lax")], BASE) == []
    assert csrf_findings(FORMS, [snap("lx_session=x; SameSite=Strict")], BASE) == []
    assert csrf_findings(FORMS, [snap("theme=dark")], BASE) == [], "not a session cookie"
    assert csrf_findings(FORMS, [], BASE) == []
    assert len(csrf_findings(FORMS, [snap("sid=x; SameSite=None; Secure")], BASE)) == 2, "SameSite=None protects nothing"
