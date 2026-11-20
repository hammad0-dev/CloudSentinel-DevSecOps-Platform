from dastml.features import ALL_FEATURES, FEATURE_NAMES, NEW_FEATURES, SQL_ERRORS, reflection_context, row_features, specials_kept


def resp(body, status=200, ctype="text/html", elapsed=0.01):
    return {"status": status, "ctype": ctype, "body": body, "elapsed": elapsed, "location": "", "nosniff": False}


def test_reflection_context():
    m = "csabc123"
    assert reflection_context(f"<p>Hello {m}</p>", m) == "text"
    assert reflection_context(f'<div style="color: {m}">', m) == "attr_dq"
    assert reflection_context(f"<input value='{m}'>", m) == "attr_sq"
    assert reflection_context(f"<script>var a = '{m}';</script>", m) == "script"
    assert reflection_context(f"<!-- {m} -->", m) == "comment"
    assert reflection_context("<p>nothing</p>", m) == "none"


def test_specials_kept_raw_vs_escaped():
    m = "csabc123"
    payload = f"<script>{m}</script>"
    assert specials_kept(f"<p>{payload}</p>", payload, m)[0] == 1.0
    escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
    frac, angle, _ = specials_kept(f"<p>{escaped}</p>", payload, m)
    assert angle == 0 and frac < 1.0


def test_sql_error_signatures_and_shell_negative():
    assert SQL_ERRORS["sqlite"].search('sqlite3.OperationalError: near "x": syntax error')
    assert SQL_ERRORS["mysql"].search("You have an error in your SQL syntax; check the manual")
    assert SQL_ERRORS["postgres"].search('error: syntax error at or near "\'"')
    shell = "sh: 1: Syntax error: Unterminated quoted string"
    assert not any(r.search(shell) for r in SQL_ERRORS.values()), "a shell error must not look like SQL"


def test_xss_row_features_raw_reflection_in_html():
    m = "csabc123"
    p = {"id": "xs-tag-2", "class": "CWE-79", "family": "tag", "mode": "replace", "value": "<script>{M}</script>"}
    base = resp("<p>Hello guest</p>")
    probe = {**resp("<p>Hello cszz</p>"), "marker": "cszz"}
    f = row_features(p, "query", resp(f"<p>Hello <script>{m}</script></p>"), m, base, base, probe)
    assert set(f) == set(ALL_FEATURES) and set(FEATURE_NAMES) | set(NEW_FEATURES) == set(ALL_FEATURES)
    assert f["payload_raw_reflected"] == 1.0 and f["angle_kept"] == 1.0 and f["ctx_script"] == 1.0 and f["probe_reflected"] == 1.0
    g = row_features(p, "query", resp(f'{{"q": "<script>{m}</script>"}}', ctype="application/json"), m, base, base, probe)
    assert g["ct_json"] == 1.0 and g["ctx_none"] == 1.0, "JSON reflection has no HTML context"


def test_sqli_boolean_pair_features():
    base = resp("<ul><li>lamp</li></ul>")
    probe = {**resp("<ul></ul>"), "marker": "cszz"}
    t = {"id": "t", "class": "CWE-89", "family": "boolean", "pair": "p", "truth": True, "mode": "append", "value": "' AND '1'='1"}
    r_true, r_false = resp("<ul><li>lamp</li></ul>"), resp("<ul></ul><p>no results at all here</p>")
    f = row_features(t, "query", r_true, "cs1", base, base, probe, pair={**r_false, "marker": "cs2"})
    assert f["pair_present"] == 1.0 and f["pair_gap"] > 0.3 and f["pair_diff_over_noise"] > 0.5
    same = row_features(t, "query", r_true, "cs1", base, base, probe, pair={**r_true, "marker": "cs2"})
    assert same["pair_diff_over_noise"] == 0.0, "identical true/false responses carry no signal"


def test_sql_error_is_new_only_if_absent_from_baseline():
    p = {"id": "e", "class": "CWE-89", "family": "error", "mode": "append", "value": "'"}
    err = resp("sqlite3.OperationalError: unrecognized token", status=500)
    probe = {**resp("ok"), "marker": "cszz"}
    assert row_features(p, "query", err, "cs1", resp("ok"), resp("ok"), probe)["sql_err_new"] == 1.0
    assert row_features(p, "query", err, "cs1", err, err, probe)["sql_err_new"] == 0.0
