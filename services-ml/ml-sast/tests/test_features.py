from sastml.features import FEATURE_NAMES, explain, hand_features, normalize_tokens, string_category


def feats(code):
    return dict(zip(FEATURE_NAMES, hand_features(code)))


def test_renaming_locals_does_not_change_tokens():
    a = 'def load_user(uid):\n    rows = cursor.execute("SELECT * FROM users WHERE id = " + uid)\n    return rows\n'
    b = 'def fetch_account(account_ref):\n    out = cursor.execute("SELECT * FROM users WHERE id = " + account_ref)\n    return out\n'
    assert normalize_tokens(a) == normalize_tokens(b)


def test_string_categories():
    assert string_category('"SELECT * FROM t WHERE a = "')[0] == "STR_SQL"
    assert string_category("'<div>'")[0] == "STR_HTML"
    assert string_category("'ping -c 1 '")[0] == "STR_CMD"
    assert string_category('"AKIAABCDEFGHIJKLMNOP"')[0] == "STR_SECRET"
    assert string_category("'./uploads/'")[0] == "STR_PATH"
    assert string_category('f"hi {name}"') == ["STR", "FSTR"]
    assert "TPL_INTERP" in string_category("`x ${y}`")


def test_hand_features_fire_on_sinks_sources_and_sanitizers():
    sql = 'q = "SELECT * FROM t WHERE id = " + request.args.get("id")\ncur.execute(q)'
    f = feats(sql)
    assert f["sql_exec"] and f["sql_concat"] and f["src_py"]
    assert feats('cur.execute("SELECT * FROM t WHERE id = %s", (uid,))')["sql_safe"]
    assert feats("exec('ping -c 1 ' + req.query.host)")["cmd_concat"] and feats("x = req.query.a")["src_js"]
    assert feats("subprocess.call(cmd, shell=True)")["shell_true"]
    assert feats('password = "hunter2hunter2"')["secret_literal"]
    assert feats("data = pickle.loads(blob)")["deser_sink"] and feats("yaml.safe_load(s)")["deser_safe"]
    assert feats("h = hashlib.md5(p).hexdigest()")["weak_crypto"] and feats("bcrypt.hashpw(p, s)")["strong_crypto"]
    assert explain("cur.execute('SELECT * FROM t WHERE a=' + x)")[:2] == ["sql_exec", "sql_concat"]
