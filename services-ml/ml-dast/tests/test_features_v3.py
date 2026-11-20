"""v3 XSS features: each case is one of the v2 error-analysis patterns (docs/ml-dast-v3-plan.md, A)."""
import pytest

from dastml.features import FEATURE_NAMES_V2, FEATURE_NAMES_V3, context_at, row_features, xss_occurrences

M = "csab12cd34"
BASE = {"status": 200, "ctype": "text/html", "body": "<html><body><p>hello</p></body></html>", "elapsed": 0.02, "location": "", "nosniff": False}
PROBE = {**BASE, "marker": "csprobe"}
P = {
    "tag": {"id": "xs-tag-3", "class": "CWE-79", "family": "tag", "value": "<svg/onload={M}>"},
    "attr_dq": {"id": "xs-attr-dq", "class": "CWE-79", "family": "attr", "value": '"><svg onload={M}>'},
    "evsq": {"id": "xs-attr-evsq", "class": "CWE-79", "family": "attr", "value": "' onmouseover={M} x='"},
    "evdq": {"id": "xs-attr-evdq", "class": "CWE-79", "family": "attr", "value": '" autofocus onfocus={M} x="'},
    "uri": {"id": "xs-uri", "class": "CWE-79", "family": "attr", "value": "javascript:{M}()"},
    "js_sq": {"id": "xs-js-sq", "class": "CWE-79", "family": "script", "value": "';{M};//"},
    "js_dq": {"id": "xs-js-dq", "class": "CWE-79", "family": "script", "value": '";{M};//'},
}


def feats(kind, body, status=200, ctype="text/html"):
    p = P[kind]
    return row_features(p, "query", {**BASE, "body": body, "status": status, "ctype": ctype}, M, BASE, BASE, PROBE)


def sent(kind):
    return P[kind]["value"].replace("{M}", M)


def test_app_prior_features_are_dropped_and_v2_names_are_unchanged():
    for name in ("len_log", "ct_html", "ct_json", "ct_text", "ct_other", "nosniff", "ctx_attr_dq", "raw_reflected_dangerous"):
        assert name not in FEATURE_NAMES_V3
    assert "len_log" in FEATURE_NAMES_V2 and "ct_text" in FEATURE_NAMES_V2  # v2 model inputs unchanged
    assert {"x_dangerous", "x_script_breakout", "x_ctx_url_attr"} <= set(FEATURE_NAMES_V3)


def test_javascript_uri_in_a_plain_attribute_is_not_dangerous():
    """v2 false alarms: labfastapi /docs-link-safe, labflask /profile-safe, vulnerable-node returnurl."""
    f = feats("uri", f'<input name="q" value="{sent("uri")}">')
    assert f["ctx_attr_dq"] == 1.0, "v2 feature still fires (unchanged)"
    assert f["x_dangerous"] == 0.0 and f["x_ctx_attr_dq"] == 0.0


def test_javascript_uri_starting_a_url_attribute_is_dangerous():
    f = feats("uri", f'<a href="{sent("uri")}">x</a>')
    assert f["x_dangerous"] == 1.0 and f["x_ctx_url_attr"] == 1.0


def test_quote_breakout_from_a_url_attribute():
    assert feats("attr_dq", f'<a href="/next?u={sent("attr_dq")}">x</a>')["x_dangerous"] == 1.0


def test_redirect_body_is_not_rendered():
    """v2 false alarm: labflask /next (Werkzeug's 302 page echoes href="javascript:...")."""
    f = feats("uri", f'<a href="{sent("uri")}">redirect</a>', status=302)
    assert f["ctx_url_attr"] == 1.0 and f["x_dangerous"] == 0.0 and f["x_specials_kept_frac"] == 0.0


def test_json_or_text_reflection_is_not_rendered():
    assert feats("tag", '{"q": "%s"}' % sent("tag"), ctype="application/json")["x_dangerous"] == 0.0
    assert feats("tag", sent("tag"), ctype="text/plain")["x_dangerous"] == 0.0


def test_single_quote_inside_a_json_encoded_double_quoted_string_cannot_break_out():
    """v2 false alarm: labflask /widget-safe (json.dumps inside <script>)."""
    body = '<script>var cb = "%s"; console.log(cb);</script>' % sent("evsq")
    f = feats("evsq", body)
    assert f["x_dangerous"] == 0.0 and f["x_script_breakout"] == 0.0
    escaped = '<script>var cb = "%s"; console.log(cb);</script>' % sent("js_dq").replace('"', '\\"')
    assert feats("js_dq", escaped)["x_dangerous"] == 0.0


def test_matching_quote_breaks_out_of_a_js_string():
    """labflask /widget (vulnerable): raw into a single-quoted JS string."""
    f = feats("js_sq", "<script>var cb = '%s'; console.log(cb);</script>" % sent("js_sq"))
    assert f["x_dangerous"] == 1.0 and f["x_script_breakout"] == 1.0 and f["x_ctx_script"] == 1.0


def test_context_is_taken_where_the_reflection_starts():
    """'"><svg onload={M}>' in value="..." is an attribute breakout (v2 called it attr_unquoted)."""
    f = feats("attr_dq", f'<input value="{sent("attr_dq")}">')
    assert f["ctx_attr_unquoted"] == 1.0  # v2: context at the marker, inside the injected tag
    assert f["x_ctx_attr_dq"] == 1.0 and f["x_dangerous"] == 1.0


def test_most_dangerous_occurrence_wins_over_the_first():
    """v2 miss: NodeGoat /profile, whose first reflection is an escaped one in a script block."""
    s = sent("attr_dq")
    body = '<script>var u = "%s";</script><input value="%s">' % (s.replace('"', '\\"'), s)
    occ = xss_occurrences(body, s, M)
    assert [c for c, _ in occ] == ["script", "attr_dq"] and [d for _, d in occ] == [False, True]
    assert feats("attr_dq", body)["x_ctx_attr_dq"] == 1.0


def test_escaped_reflection_and_rcdata_are_not_dangerous():
    esc = sent("tag").replace("<", "&lt;").replace(">", "&gt;")
    assert feats("tag", f"<p>{esc}</p>")["x_dangerous"] == 0.0
    assert feats("tag", f"<textarea>{sent('tag')}</textarea>")["x_dangerous"] == 0.0
    assert feats("tag", f"<p>{sent('tag')}</p>")["x_dangerous"] == 1.0


def test_unquoted_attribute_breakout_needs_a_raw_space_or_angle():
    assert feats("evdq", f"<input value={sent('evdq')}>")["x_dangerous"] == 1.0
    assert context_at("<input value=", len("<input value=")) == "attr_unquoted"
