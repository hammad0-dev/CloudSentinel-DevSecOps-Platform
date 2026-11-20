"""Request/response features for one payload sent to one injection point.

Each row compares the payload response with the injection point's baseline responses (the
original value, sent twice, to measure noise) and a benign probe (random token: is the parameter
reflected at all?). Boolean SQL payloads come in true/false pairs; the pair's responses are compared
with each other and with the baseline.

Deliberately NOT used: URL, path or parameter names and response body tokens. Those would let a
model memorize endpoints or apps (e.g. the "-safe" suffix in the lab apps) instead of behaviour.
"""
import difflib
import html
import math
import re
from urllib.parse import quote, quote_plus

SQL_ERRORS = {
    "sqlite": re.compile(r"SQLITE_ERROR|sqlite3?\.(Operational|Programming)Error|SQLite.*(syntax|error)|unrecognized token|near \".{0,40}\": syntax error", re.I),
    "mysql": re.compile(r"You have an error in your SQL syntax|MySQL server version|mysql_fetch|pymysql\.err|ER_PARSE_ERROR|Warning: mysql", re.I),
    "postgres": re.compile(r"syntax error at or near|unterminated quoted string at or near|PG::SyntaxError|psycopg2?\.|invalid input syntax for|column \".{1,40}\" does not exist", re.I),
    "generic": re.compile(r"SQL syntax|SQLSTATE|ORA-\d{5}|ODBC|unclosed quotation mark|quoted string not properly terminated|SequelizeDatabaseError", re.I),
}
STACK_TRACE = re.compile(r"Traceback \(most recent call last\)|\n\s+at [\w$.<>]+ \(.+:\d+:\d+\)|File \".+\", line \d+|Exception in thread|\w+Error: .+\n\s+at ", re.I)
GENERIC_ERROR = re.compile(r"internal (server )?error|something went wrong|an error occurred|exception|query failed", re.I)
TOKEN = re.compile(r"[A-Za-z_]+|\d+|[^\sA-Za-z_\d]")
SPECIAL = "<>\"'`;()/="
FAMILIES = ["error", "boolean", "union", "time", "tag", "attr", "script", "evasion", "template"]
LOCATIONS = ["query", "form", "json", "path"]
CONTEXTS = ["none", "text", "attr_dq", "attr_sq", "attr_unquoted", "script", "comment"]

FEATURE_NAMES = (
    ["payload_sqli", "payload_xss"] + [f"family_{f}" for f in FAMILIES] + [f"loc_{l}" for l in LOCATIONS]
    + ["status", "is_2xx", "is_3xx", "is_4xx", "is_5xx", "status_changed", "baseline_5xx",
       "len_log", "len_delta_rel", "len_delta_over_noise", "sim_baseline", "baseline_self_sim",
       "time_delta", "time_ratio_log", "time_over_1s",
       "sql_err_new", "sql_err_any", "sql_err_families", "stack_trace_new", "generic_error_new",
       "ct_html", "ct_json", "ct_text", "ct_other", "nosniff",
       "probe_reflected", "marker_reflected", "payload_raw_reflected", "payload_html_escaped", "payload_url_encoded",
       "specials_kept_frac", "angle_kept", "quote_kept", "redirect_marker"]
    + [f"ctx_{c}" for c in CONTEXTS]
    + ["pair_present", "pair_sim_true_base", "pair_sim_false_base", "pair_gap", "pair_abs_gap", "pair_sim_true_false",
       "pair_diff_over_noise", "pair_status_differs", "pair_len_rel_diff"]
)


def norm_tokens(text, marker=None, limit=3000):
    if marker:
        text = text.replace(marker, " ")
    toks = TOKEN.findall(text[:200_000])
    return [("NUM" if t.isdigit() else t) for t in toks[:limit]]


def similarity(a, b):
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def content_kind(ctype):
    c = (ctype or "").lower()
    if "html" in c:
        return "html"
    if "json" in c:
        return "json"
    if c.startswith("text/"):
        return "text"
    return "other"


def reflection_context(body, marker):
    """Where does the first raw occurrence of the marker sit in the HTML?"""
    i = body.find(marker)
    if i < 0:
        return "none"
    before = body[:i]
    if before.rfind("<!--") > before.rfind("-->"):
        return "comment"
    if before.lower().rfind("<script") > before.lower().rfind("</script"):
        return "script"
    lt, gt = before.rfind("<"), before.rfind(">")
    if lt > gt:  # inside a tag
        tag = before[lt:]
        dq, sq = tag.count('"') % 2 == 1, tag.count("'") % 2 == 1
        if dq:
            return "attr_dq"
        if sq:
            return "attr_sq"
        return "attr_unquoted"
    return "text"


def specials_kept(body, payload, marker, window=40):
    """Fraction of the payload's special characters that appear raw next to a marker occurrence."""
    specials = {c for c in payload if c in SPECIAL}
    if not specials:
        return 0.0, 0, 0
    best = 0.0
    angle = quote_k = 0
    start = 0
    while True:
        i = body.find(marker, start)
        if i < 0:
            break
        seg = body[max(0, i - window): i + len(marker) + window]
        kept = {c for c in specials if c in seg}
        best = max(best, len(kept) / len(specials))
        angle |= int("<" in specials and "<" in seg and ">" in seg)
        quote_k |= int(bool({'"', "'"} & specials & kept))
        start = i + 1
    return best, angle, quote_k


def row_features(payload, location, resp, marker, base1, base2, probe, pair=None, pair_payload=None):
    """resp/base*/probe/pair are dicts: status, ctype, body, elapsed, location, nosniff."""
    f = dict.fromkeys(FEATURE_NAMES, 0.0)
    f["payload_sqli"] = float(payload["class"] == "CWE-89")
    f["payload_xss"] = float(payload["class"] == "CWE-79")
    if payload["family"] in FAMILIES:
        f["family_" + payload["family"]] = 1.0
    if location in LOCATIONS:
        f["loc_" + location] = 1.0
    st, b_st = resp["status"], base1["status"]
    f.update(status=st / 100.0, is_2xx=float(200 <= st < 300), is_3xx=float(300 <= st < 400), is_4xx=float(400 <= st < 500),
             is_5xx=float(st >= 500), status_changed=float(st != b_st), baseline_5xx=float(b_st >= 500))
    body, b1, b2 = resp["body"], base1["body"], base2["body"]
    n, n1 = len(body), len(b1)
    noise = abs(len(b1) - len(b2))
    f["len_log"] = math.log10(n + 1)
    f["len_delta_rel"] = abs(n - n1) / max(n1, 1)
    f["len_delta_over_noise"] = min(abs(n - n1) / (noise + 1.0), 1000.0) / 100.0
    tb1, tb2 = norm_tokens(b1), norm_tokens(b2)
    tr = norm_tokens(body, marker)
    f["sim_baseline"] = similarity(tr, tb1)
    f["baseline_self_sim"] = similarity(tb1, tb2)
    t_base = (base1["elapsed"] + base2["elapsed"]) / 2
    f["time_delta"] = resp["elapsed"] - t_base
    f["time_ratio_log"] = math.log((resp["elapsed"] + 0.01) / (t_base + 0.01))
    f["time_over_1s"] = float(resp["elapsed"] - t_base > 0.9)
    fams_now = {k for k, r in SQL_ERRORS.items() if r.search(body)}
    fams_base = {k for k, r in SQL_ERRORS.items() if r.search(b1)}
    f["sql_err_any"] = float(bool(fams_now))
    f["sql_err_new"] = float(bool(fams_now - fams_base))
    f["sql_err_families"] = float(len(fams_now))
    f["stack_trace_new"] = float(bool(STACK_TRACE.search(body)) and not STACK_TRACE.search(b1))
    f["generic_error_new"] = float(bool(GENERIC_ERROR.search(body)) and not GENERIC_ERROR.search(b1))
    kind = content_kind(resp["ctype"])
    f["ct_" + kind] = 1.0
    f["nosniff"] = float(bool(resp.get("nosniff")))
    f["probe_reflected"] = float(probe["marker"] in probe["body"])
    sent = payload["value"].replace("{M}", marker)
    if "{M}" in payload["value"]:
        f["marker_reflected"] = float(marker in body)
        f["payload_raw_reflected"] = float(sent in body)
        f["payload_html_escaped"] = float(html.escape(sent, quote=True) in body or html.escape(sent, quote=False) in body) if sent != html.escape(sent) else 0.0
        f["payload_url_encoded"] = float((quote(sent) in body or quote_plus(sent) in body) and quote(sent) != sent)
        frac, angle, qk = specials_kept(body, sent, marker)
        f["specials_kept_frac"], f["angle_kept"], f["quote_kept"] = frac, float(angle), float(qk)
        f["redirect_marker"] = float(300 <= st < 400 and marker in (resp.get("location") or ""))
        f["ctx_" + (reflection_context(body, marker) if kind == "html" else "none")] = 1.0
    else:
        f["ctx_none"] = 1.0
    if pair is not None:
        tp = norm_tokens(pair["body"], pair.get("marker"))
        me_true = payload.get("truth", True)
        t_resp, f_resp = (tr, tp) if me_true else (tp, tr)
        t_st, f_st = (st, pair["status"]) if me_true else (pair["status"], st)
        f["pair_present"] = 1.0
        f["pair_sim_true_base"] = similarity(t_resp, tb1)
        f["pair_sim_false_base"] = similarity(f_resp, tb1)
        f["pair_gap"] = f["pair_sim_true_base"] - f["pair_sim_false_base"]
        f["pair_abs_gap"] = abs(f["pair_gap"])
        f["pair_sim_true_false"] = similarity(t_resp, f_resp)
        f["pair_diff_over_noise"] = min((1.0 - f["pair_sim_true_false"]) / (1.0 - f["baseline_self_sim"] + 0.01), 100.0) / 10.0
        f["pair_status_differs"] = float(t_st != f_st)
        f["pair_len_rel_diff"] = abs(len(body) - len(pair["body"])) / max(len(body), len(pair["body"]), 1)
    return f
