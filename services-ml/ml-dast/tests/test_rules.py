"""Rule-based (not ML) checks of ml-dast v2, and the guard additions they rely on."""
import pytest

from dastml.guards import GuardedClient, GuardError, TargetPolicy, carries_url
from dastml.rules import PASSIVE_SEVERITY, RULES, active_findings, command_injection, open_redirect, passive_checks, passive_findings, path_traversal

PAYLOADS = [
    {"id": "cm-out-1", "class": "CWE-78", "family": "cmd", "value": ";echo {M}$((7*191))"},
    {"id": "cm-time-1", "class": "CWE-78", "family": "cmd_time", "value": ";sleep 2", "sleep": 2, "repeat": True},
    {"id": "cm-time-0", "class": "CWE-78", "family": "cmd_time", "value": ";sleep 0", "sleep": 0},
    {"id": "pt-rel-1", "class": "CWE-22", "family": "traversal", "value": "../../../../etc/passwd"},
    {"id": "or-pr-1", "class": "CWE-601", "family": "redirect", "value": "//{M}.invalid/"},
]
PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"


def resp(kind, body="ok", elapsed=0.02, status=200, **kw):
    return {"kind": kind, "body": body, "elapsed": elapsed, "status": status, "ctype": "text/html", "location": "", **kw}


def record(*payload_responses, base_body="ok"):
    return {"point": {"method": "GET", "path": "/x", "param": "p", "location": "query"},
            "responses": [resp("base1", base_body), resp("base2", base_body)] + list(payload_responses)}


def pr(pid, marker="csabc", **kw):
    return resp("payload", payload_id=pid, marker=marker, value="v", **kw)


def test_command_injection_needs_the_computed_value_not_a_reflection():
    assert command_injection(record(pr("cm-out-1", body="PING csabc1337")), PAYLOADS)[0]
    # an escaped or plain reflection of the payload never contains the product
    assert not command_injection(record(pr("cm-out-1", body="host=;echo csabc$((7*191)) not found")), PAYLOADS)[0]
    # a 1337 that is already on the page (baseline) does not count
    assert not command_injection(record(pr("cm-out-1", body="csabc1337"), base_body="csabc1337"), PAYLOADS)[0]


def test_command_injection_timing_needs_dose_and_repeat():
    fired, ev, _ = command_injection(record(pr("cm-time-1", elapsed=2.1, elapsed2=2.05), pr("cm-time-0", elapsed=0.03)), PAYLOADS)
    assert fired and "sleep 2" in ev
    assert not command_injection(record(pr("cm-time-1", elapsed=5.0, elapsed2=5.0), pr("cm-time-0", elapsed=5.0)), PAYLOADS)[0], "slow for every input"
    assert not command_injection(record(pr("cm-time-1", elapsed=2.1, elapsed2=0.02), pr("cm-time-0", elapsed=0.03)), PAYLOADS)[0], "one-off spike"


def test_path_traversal_signature():
    assert path_traversal(record(pr("pt-rel-1", body=PASSWD)), PAYLOADS)[0]
    assert not path_traversal(record(pr("pt-rel-1", body="file not found")), PAYLOADS)[0]
    assert not path_traversal(record(pr("pt-rel-1", body=PASSWD), base_body=PASSWD), PAYLOADS)[0], "already in the baseline"


def test_open_redirect_reads_only_the_location_header():
    assert open_redirect(record(pr("or-pr-1", status=302, location="//csabc.invalid/")), PAYLOADS)[0]
    assert open_redirect(record(pr("or-pr-1", status=302, location="/\\csabc.invalid/")), PAYLOADS)[0]
    assert not open_redirect(record(pr("or-pr-1", status=302, location="/dashboard")), PAYLOADS)[0]
    assert not open_redirect(record(pr("or-pr-1", status=200, body="//csabc.invalid/")), PAYLOADS)[0], "reflection is not a redirect"


def test_active_findings_are_labelled_rule_based():
    out = active_findings(record(pr("cm-out-1", body="csabc1337")), PAYLOADS, "http://t", "http://t/x")
    assert len(out) == 1 and out[0]["engine"] == "rule" and out[0]["cwe_id"] == 78 and out[0]["response_details"].startswith("[rule-based]")
    assert {RULES[c]["cwe"] for c in RULES} == {78, 22, 601}


def H(**headers):
    return {"kind": "base1", "status": 200, "ctype": "text/html", "headers": headers}


def test_passive_checks():
    bare = passive_checks([H(), H(**{"set-cookie": ["SESSIONID=abc; path=/"]})])
    assert set(bare) == {"missing-csp", "missing-nosniff", "missing-frame-protection", "cookie-no-httponly", "cookie-no-samesite"}
    hardened = H(**{"content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff",
                    "set-cookie": ["sid=1; HttpOnly; SameSite=Lax; Path=/"]})
    assert passive_checks([hardened]) == {}
    assert "missing-frame-protection" not in passive_checks([H(**{"x-frame-options": "DENY"})])
    assert passive_checks([H(**{"set-cookie": ["theme=dark"]})]).keys() >= {"missing-csp"}
    assert "cookie-no-httponly" not in passive_checks([H(**{"set-cookie": ["theme=dark"]})]), "only session-like cookies"


def test_cors_check():
    cors = lambda acao, cred="": {"kind": "cors", "origin": "http://csx.invalid", "status": 200, "ctype": "text/html",
                                  "headers": {"access-control-allow-origin": acao, **({"access-control-allow-credentials": cred} if cred else {})}}
    assert "cors-any-origin" in passive_checks([cors("http://csx.invalid")])
    assert "cors-any-origin" in passive_checks([cors("*", "true")])
    assert "cors-any-origin" not in passive_checks([cors("*")]), "public wildcard without credentials is not flagged"


def test_passive_findings_are_low_or_info_and_never_gate_blocking():
    assert set(PASSIVE_SEVERITY.values()) <= {"LOW", "INFORMATIONAL"}
    for f in passive_findings([H()], "http://t"):
        assert f["severity"] in ("LOW", "INFORMATIONAL") and f["engine"] == "rule"


def test_guard_refuses_url_carrying_parameters_and_skip_params():
    assert carries_url("include=https%3A%2F%2Fpastebin.com%2Fraw") and carries_url("path=http://127.0.0.1:631")
    assert not carries_url("redir=//csabc.invalid/") and not carries_url("q=javascript:csabc()")
    policy = TargetPolicy(allowed_ports=frozenset({5109}), skip_params=(("/", "object"), ("/", "size")))
    c = GuardedClient("http://127.0.0.1:5109/", policy)
    for url in ("/?object=cos%0Asystem", "/?size=9999999", "/?include=https%3A%2F%2Fpastebin.com%2Fraw%2Fx", "/?path=http://127.0.0.1:631"):
        with pytest.raises(GuardError):
            c.check_url(url)
    assert c.check_url("/?id=2") and c.check_url("/?redir=//csabc.invalid/")
    with pytest.raises(GuardError):
        c.check_body({"url": "https://example.com/"})
    assert c.requests_sent == 0
