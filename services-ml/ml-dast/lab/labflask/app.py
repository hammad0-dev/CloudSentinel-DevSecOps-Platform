"""labflask: deliberately vulnerable AND safe endpoints for ml-dast ground truth.

LAB ONLY. Bound to the lab compose network and published on 127.0.0.1 only. Never deploy.
Every route is listed in services-ml/ml-dast/data/dast/ground_truth.json; the vulnerable and safe
variants differ only in the sink (string-built SQL vs parameters, raw vs escaped output).
"""
import html
import json
import os
import sqlite3
import subprocess
import time
import traceback

from flask import Flask, Response, jsonify, request

app = Flask(__name__)
DB = "/tmp/labflask.db"
FILES = "/srv/files"


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init():
    con = db()
    con.executescript("""
    DROP TABLE IF EXISTS products; DROP TABLE IF EXISTS users;
    CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL);
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
    INSERT INTO products (name, category, price) VALUES ('lamp','home',12.5),('desk','home',99),('pen','office',1.2),('stapler','office',7),('mug','kitchen',4);
    INSERT INTO users (username, password) VALUES ('alice','wonderland'),('bob','builder');
    """)
    con.commit()
    os.makedirs(FILES, exist_ok=True)
    for name, text in (("readme.txt", "lab file\n"), ("notes.txt", "more notes\n")):
        with open(os.path.join(FILES, name), "w") as fh:
            fh.write(text)


def page(title, body):
    return f"<!doctype html><html><head><title>{html.escape(title)}</title></head><body><h1>{html.escape(title)}</h1>{body}<p><a href='/'>home</a></p></body></html>"


def rows_html(rows):
    return "<ul>" + "".join(f"<li>{html.escape(str(r['name']))} ({html.escape(str(r['category']))})</li>" for r in rows) + "</ul>"


@app.get("/")
def index():
    links = ["/search?q=lamp", "/search-safe?q=lamp", "/item?id=1", "/item-safe?id=1", "/greet?name=guest", "/greet-safe?name=guest",
             "/profile?color=blue", "/profile-safe?color=blue", "/widget?cb=render", "/widget-safe?cb=render", "/api/echo?msg=hi",
             "/plain?msg=hi", "/calc?x=2", "/slow?n=1", "/ping?host=127.0.0.1", "/ping-safe?host=127.0.0.1",
             "/download?file=readme.txt", "/download-safe?file=readme.txt", "/login", "/login-safe", "/v2", "/v3"]
    return page("labflask", "<ul>" + "".join(f"<li><a href='{l}'>{l}</a></li>" for l in links) + "</ul>")


# ---------- CWE-89 SQL injection ----------
@app.get("/search")  # VULN CWE-89: string-built LIKE, database error shown
def search():
    q = request.args.get("q", "")
    try:
        rows = db().execute("SELECT name, category FROM products WHERE name LIKE '%" + q + "%'").fetchall()
    except sqlite3.Error as exc:
        return page("error", f"<pre>sqlite3.OperationalError: {html.escape(str(exc))}</pre>"), 500
    return page("search", rows_html(rows))


@app.get("/search-safe")  # SAFE: parameterized
def search_safe():
    q = request.args.get("q", "")
    rows = db().execute("SELECT name, category FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
    return page("search", rows_html(rows))


@app.get("/item")  # VULN CWE-89: numeric context, errors swallowed (boolean/blind)
def item():
    try:
        rows = db().execute("SELECT name, category FROM products WHERE id = " + request.args.get("id", "0")).fetchall()
    except sqlite3.Error:
        rows = []
    return page("item", rows_html(rows) if rows else "<p>no such item</p>")


@app.get("/item-safe")  # SAFE: int() cast
def item_safe():
    try:
        pid = int(request.args.get("id", "0"))
    except ValueError:
        return page("item", "<p>invalid id</p>"), 400
    rows = db().execute("SELECT name, category FROM products WHERE id = ?", (pid,)).fetchall()
    return page("item", rows_html(rows) if rows else "<p>no such item</p>")


LOGIN_FORM = "<form method='post'><input name='username'><input name='password' type='password'><button>login</button></form>"


@app.route("/login", methods=["GET", "POST"])  # VULN CWE-89 (username, password): generic error page
def login():
    if request.method == "GET":
        return page("login", LOGIN_FORM)
    u, p = request.form.get("username", ""), request.form.get("password", "")
    try:
        row = db().execute(f"SELECT username FROM users WHERE username = '{u}' AND password = '{p}'").fetchone()
    except sqlite3.Error:
        return page("login", "<p>Something went wrong.</p>"), 500
    return page("login", f"<p>welcome {html.escape(row['username'])}</p>" if row else "<p>invalid credentials</p>")


@app.route("/login-safe", methods=["GET", "POST"])  # SAFE: parameterized
def login_safe():
    if request.method == "GET":
        return page("login", LOGIN_FORM)
    row = db().execute("SELECT username FROM users WHERE username = ? AND password = ?",
                       (request.form.get("username", ""), request.form.get("password", ""))).fetchone()
    return page("login", f"<p>welcome {html.escape(row['username'])}</p>" if row else "<p>invalid credentials</p>")


# ---------- CWE-79 reflected XSS ----------
@app.get("/greet")  # VULN CWE-79: HTML body
def greet():
    return page("greet", "<p>Hello " + request.args.get("name", "") + "!</p>")


@app.get("/greet-safe")  # SAFE: escaped
def greet_safe():
    return page("greet", "<p>Hello " + html.escape(request.args.get("name", "")) + "!</p>")


@app.get("/profile")  # VULN CWE-79: double-quoted attribute, not escaped
def profile():
    return page("profile", '<div style="color: ' + request.args.get("color", "") + '">profile card</div>')


@app.get("/profile-safe")  # SAFE: attribute-escaped
def profile_safe():
    return page("profile", '<div style="color: ' + html.escape(request.args.get("color", ""), quote=True) + '">profile card</div>')


@app.get("/widget")  # VULN CWE-79: inside a <script> string
def widget():
    return page("widget", "<script>var cb = '" + request.args.get("cb", "") + "'; console.log(cb);</script>")


@app.get("/widget-safe")  # SAFE: JSON-encoded with <, >, & escaped
def widget_safe():
    cb = json.dumps(request.args.get("cb", "")).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return page("widget", f"<script>var cb = {cb}; console.log(cb);</script>")


@app.get("/api/echo")  # SAFE (hard negative): raw reflection, but application/json
def api_echo():
    return jsonify(msg=request.args.get("msg", ""))


@app.get("/plain")  # SAFE (hard negative): raw reflection, but text/plain + nosniff
def plain():
    return Response("you said: " + request.args.get("msg", ""), mimetype="text/plain", headers={"X-Content-Type-Options": "nosniff"})


# ---------- hard negatives for error/time features ----------
@app.get("/calc")  # SAFE (hard negative): non-SQL stack trace on bad input
def calc():
    try:
        return page("calc", f"<p>{int(request.args.get('x', '0')) * 2}</p>")
    except ValueError:
        return page("error", "<pre>" + html.escape(traceback.format_exc()) + "</pre>"), 500


@app.get("/slow")  # SAFE (hard negative): response time depends on a bounded numeric param
def slow():
    try:
        n = min(max(int(request.args.get("n", "0")), 0), 3)
    except ValueError:
        n = 0
    time.sleep(0.2 * n)
    return page("slow", f"<p>waited {n}</p>")


# ---------- CWE-78 / CWE-22 (added only after CWE-89 / CWE-79 work) ----------
@app.get("/ping")  # VULN CWE-78: shell string
def ping():
    out = subprocess.run("ping -c 1 -W 1 " + request.args.get("host", ""), shell=True, capture_output=True, text=True, timeout=5)
    return page("ping", "<pre>" + html.escape(out.stdout + out.stderr) + "</pre>")


@app.get("/ping-safe")  # SAFE: argument list, no shell
def ping_safe():
    host = request.args.get("host", "")
    if not host.replace(".", "").replace("-", "").isalnum():
        return page("ping", "<p>invalid host</p>"), 400
    out = subprocess.run(["ping", "-c", "1", "-W", "1", host], capture_output=True, text=True, timeout=5)
    return page("ping", "<pre>" + html.escape(out.stdout + out.stderr) + "</pre>")


@app.get("/download")  # VULN CWE-22: joined path, no containment check
def download():
    try:
        with open(os.path.join(FILES, request.args.get("file", "")), errors="replace") as fh:
            return Response(fh.read(4096), mimetype="text/plain")
    except OSError as exc:
        return page("error", f"<p>{html.escape(type(exc).__name__)}</p>"), 404


@app.get("/download-safe")  # SAFE: basename + realpath containment
def download_safe():
    path = os.path.realpath(os.path.join(FILES, os.path.basename(request.args.get("file", ""))))
    if not path.startswith(FILES + os.sep) or not os.path.isfile(path):
        return page("error", "<p>not found</p>"), 404
    with open(path, errors="replace") as fh:
        return Response(fh.read(4096), mimetype="text/plain")


# ---------- v2 additions (B3): realistic safe endpoints, and vulnerable twins where they make sense ----------
import re  # noqa: E402

from flask import redirect  # noqa: E402

FIND_FORM = "<form method='post'><input name='q' value='lamp'><button>find</button></form>"


@app.route("/find", methods=["GET", "POST"])  # VULN CWE-89: POST search form, string-built, errors swallowed (blind)
def find():
    if request.method == "GET":
        return page("find", FIND_FORM)
    try:
        rows = db().execute("SELECT name, category FROM products WHERE category = '" + request.form.get("q", "") + "'").fetchall()
    except sqlite3.Error:
        rows = []
    return page("find", rows_html(rows) if rows else "<p>nothing found</p>")


@app.route("/find-safe", methods=["GET", "POST"])  # SAFE: parameterized
def find_safe():
    if request.method == "GET":
        return page("find", FIND_FORM)
    rows = db().execute("SELECT name, category FROM products WHERE category = ?", (request.form.get("q", ""),)).fetchall()
    return page("find", rows_html(rows) if rows else "<p>nothing found</p>")


@app.get("/link")  # VULN CWE-79: HTML-escaped, but the scheme is not checked (javascript: URI in href)
def link():
    return page("link", f'<a href="{html.escape(request.args.get("url", "/"), quote=True)}">continue</a>')


@app.get("/link-safe")  # SAFE: only same-site relative paths, then escaped
def link_safe():
    url = request.args.get("url", "/")
    if not url.startswith("/") or url.startswith("//") or "\\" in url:
        url = "/"
    return page("link", f'<a href="{html.escape(url, quote=True)}">continue</a>')


@app.get("/next")  # VULN CWE-601: redirects to any value
def next_page():
    return redirect(request.args.get("next", "/"), code=302)


@app.get("/next-safe")  # SAFE: same-site paths only
def next_safe():
    nxt = request.args.get("next", "/")
    if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
        nxt = "/"
    return redirect(nxt, code=302)


@app.get("/api/items-safe")  # SAFE (hard negative): JSON API, input validated, 400 JSON on bad input (any quote count)
def api_items_safe():
    q = request.args.get("q", "")
    if not re.fullmatch(r"[\w ]{0,40}", q):
        return jsonify(error="invalid query"), 400
    rows = db().execute("SELECT name FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
    return jsonify(items=[r["name"] for r in rows])


LOOKUP_CACHE = {"localhost": "127.0.0.1", "lab": "10.0.0.1"}


@app.get("/lookup-safe")  # SAFE (hard negative): unknown names take ~1.2 s (slow upstream), whatever the input says
def lookup_safe():
    name = request.args.get("name", "localhost")
    if name not in LOOKUP_CACHE:
        time.sleep(1.2)
        return page("lookup", "<p>not found</p>")
    return page("lookup", f"<p>{html.escape(name)} = {LOOKUP_CACHE[name]}</p>")


@app.get("/notfound-safe")  # SAFE (hard negative): 404 page that echoes the requested name, escaped
def notfound_safe():
    return page("not found", f"<p>No page called {html.escape(request.args.get('page', ''))}.</p>"), 404


V2_LINKS = ["/find", "/find-safe", "/link?url=/search", "/link-safe?url=/search", "/next?next=/search", "/next-safe?next=/search",
            "/api/items-safe?q=lamp", "/lookup-safe?name=localhost", "/notfound-safe?page=help"]
_index = index


@app.get("/v2")
def index_v2():
    return page("labflask v2", "<ul>" + "".join(f"<li><a href='{l}'>{l}</a></li>" for l in V2_LINKS) + "</ul>")


# ---------- v3: targeted twins (docs/ml-dast-v3-plan.md, B/D1). Each VULN route has a SAFE twin that
# differs only in the sink. Patterns the v2 data lacked: SQL errors as text/plain or JSON, SQLi whose
# only signal is quote parity or ORDER BY, safe endpoints that answer bad input with text/JSON/500
# errors, XSS in an unquoted attribute / a JS string / an error page, stored XSS and CSRF forms.
def init_v3():
    con = db()
    con.executescript("""
    DROP TABLE IF EXISTS notes; DROP TABLE IF EXISTS guestbook;
    CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);
    CREATE TABLE guestbook (id INTEGER PRIMARY KEY, name TEXT, message TEXT, safe INTEGER);
    """)
    con.commit()


def text(body, status=200):
    return Response(body, status, mimetype="text/plain")


@app.get("/v3/item-text")  # VULN CWE-89: string-built (numeric); the database error comes back as a text/plain 500
def v3_item_text():
    try:
        r = db().execute("SELECT name FROM products WHERE id = " + request.args.get("id", "1")).fetchone()
    except sqlite3.Error as exc:
        return text(f"query failed: {exc}\n", 500)
    return text((r["name"] if r else "no such item") + "\n")


@app.get("/v3/item-text-safe")  # SAFE (hard negative): parameterized; bad input -> text/plain 400 with the parse error
def v3_item_text_safe():
    try:
        item_id = int(request.args.get("id", "1"))
    except ValueError as exc:
        return text(f"bad request: {exc}\n", 400)
    r = db().execute("SELECT name FROM products WHERE id = ?", (item_id,)).fetchone()
    return text((r["name"] if r else "no such item") + "\n")


@app.get("/v3/api/item")  # VULN CWE-89: string-built (string context); the database error comes back as JSON 500
def v3_api_item():
    try:
        r = db().execute("SELECT name, price FROM products WHERE name = '" + request.args.get("name", "lamp") + "'").fetchone()
    except sqlite3.Error as exc:
        return jsonify(error=str(exc)), 500
    return jsonify(item=dict(r) if r else None)


@app.get("/v3/api/price-safe")  # SAFE (hard negative): parameterized; bad input -> JSON 500 with a non-SQL error
def v3_api_price_safe():
    try:
        limit = float(request.args.get("max", "20"))
    except ValueError as exc:
        return jsonify(error=f"internal error: {exc}"), 500
    rows = db().execute("SELECT name FROM products WHERE price <= ?", (limit,)).fetchall()
    return jsonify(items=[r["name"] for r in rows])


@app.get("/v3/note")  # VULN CWE-89: INSERT built from a string; errors are swallowed (only saved / not saved)
def v3_note():
    con = db()
    try:
        con.execute("INSERT INTO notes (body) VALUES ('" + request.args.get("body", "hello") + "')")
        con.commit()
        msg = "saved"
    except sqlite3.Error:
        msg = "could not save the note"
    return page("note", f"<p>{msg}</p>")


@app.get("/v3/note-safe")  # SAFE: parameterized INSERT
def v3_note_safe():
    con = db()
    con.execute("INSERT INTO notes (body) VALUES (?)", (request.args.get("body", "hello"),))
    con.commit()
    return page("note", "<p>saved</p>")


@app.get("/v3/sort")  # VULN CWE-89: ORDER BY built from a string; errors fall back to the default order
def v3_sort():
    try:
        rows = db().execute("SELECT name, category FROM products ORDER BY " + request.args.get("order", "name")).fetchall()
    except sqlite3.Error:
        rows = db().execute("SELECT name, category FROM products ORDER BY id").fetchall()
    return page("sorted", rows_html(rows))


@app.get("/v3/sort-safe")  # SAFE: column whitelist, anything else -> default order
def v3_sort_safe():
    order = request.args.get("order", "name")
    order = order if order in ("name", "price", "category") else "id"
    return page("sorted", rows_html(db().execute(f"SELECT name, category FROM products ORDER BY {order}").fetchall()))


@app.get("/v3/convert-safe")  # SAFE (hard negative): no SQL; bad input -> text/plain 500 with a Python traceback
def v3_convert_safe():
    try:
        return text(f"{float(request.args.get('amount', '1')) * 1.1:.2f}\n")
    except ValueError:
        return text(traceback.format_exc(), 500)


@app.get("/v3/tag")  # VULN CWE-79: raw into an UNQUOTED attribute
def v3_tag():
    return page("tag", f"<p><span class={request.args.get('label', 'info')}>tagged</span></p>")


@app.get("/v3/tag-safe")  # SAFE: quoted and escaped
def v3_tag_safe():
    return page("tag", f'<p><span class="{html.escape(request.args.get("label", "info"), quote=True)}">tagged</span></p>')


@app.get("/v3/js")  # VULN CWE-79: raw into a double-quoted JS string
def v3_js():
    return page("js", '<script>var term = "' + request.args.get("term", "lamp") + '"; console.log(term);</script>')


@app.get("/v3/js-safe")  # SAFE: JS-string escaping (backslash, both quotes, <)
def v3_js_safe():
    t = request.args.get("term", "lamp").replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'").replace("<", "\\x3c")
    return page("js", f'<script>var term = "{t}"; console.log(term);</script>')


@app.get("/v3/lookup")  # VULN CWE-79: unknown names -> 404 HTML error page with the raw name
def v3_lookup():
    q = request.args.get("q", "lamp")
    if db().execute("SELECT 1 FROM products WHERE name = ?", (q,)).fetchone():
        return page("lookup", "<p>found</p>")
    return page("not found", f"<p>No product called {q}</p>"), 404


@app.get("/v3/lookup-safe")  # SAFE: same, escaped
def v3_lookup_safe():
    q = request.args.get("q", "lamp")
    if db().execute("SELECT 1 FROM products WHERE name = ?", (q,)).fetchone():
        return page("lookup", "<p>found</p>")
    return page("not found", f"<p>No product called {html.escape(q)}</p>"), 404


def _guestbook(path, safe):
    rows = db().execute("SELECT name, message FROM guestbook WHERE safe = ? ORDER BY id DESC LIMIT 20", (int(safe),)).fetchall()
    show = html.escape if safe else (lambda s: s)
    items = "".join(f"<li><b>{html.escape(r['name'])}</b>: {show(r['message'])}</li>" for r in rows)
    form = (f"<form method='post' action='{path}'><input name='name' value='guest'>"
            "<textarea name='message'>hello</textarea><button>sign</button></form>")
    return page("guestbook", f"<ul>{items}</ul>{form}")


@app.route("/v3/guestbook", methods=["GET", "POST"])  # VULN CWE-79 (stored): message shown raw on this page (name escaped)
def v3_guestbook():
    if request.method == "POST":
        con = db()
        con.execute("INSERT INTO guestbook (name, message, safe) VALUES (?, ?, 0)", (request.form.get("name", ""), request.form.get("message", "")))
        con.commit()
        return redirect("/v3/guestbook", code=303)
    return _guestbook("/v3/guestbook", safe=False)


@app.route("/v3/guestbook-safe", methods=["GET", "POST"])  # SAFE: both fields escaped
def v3_guestbook_safe():
    if request.method == "POST":
        con = db()
        con.execute("INSERT INTO guestbook (name, message, safe) VALUES (?, ?, 1)", (request.form.get("name", ""), request.form.get("message", "")))
        con.commit()
        return redirect("/v3/guestbook-safe", code=303)
    return _guestbook("/v3/guestbook-safe", safe=True)


SETTINGS = {"display_name": "guest"}
CSRF_TOKEN = "lab-v3-" + os.urandom(8).hex()


def _with_session(resp):
    """Lab session cookie: HttpOnly, but no SameSite (so a cross-site POST carries it)."""
    resp.set_cookie("lf_session", "lab-session", httponly=True)
    return resp


@app.route("/v3/settings", methods=["GET", "POST"])  # VULN CWE-352 (heuristic): state-changing form, no token, cookie without SameSite
def v3_settings():
    if request.method == "POST":
        SETTINGS["display_name"] = request.form.get("display_name", "")[:40]
    form = f"<form method='post' action='/v3/settings'><input name='display_name' value='{html.escape(SETTINGS['display_name'], quote=True)}'><button>save</button></form>"
    return _with_session(app.make_response(page("settings", form)))


@app.route("/v3/settings-safe", methods=["GET", "POST"])  # SAFE: anti-CSRF token field, checked on POST
def v3_settings_safe():
    if request.method == "POST":
        if request.form.get("csrf_token") != CSRF_TOKEN:
            return page("settings", "<p>invalid token</p>"), 403
        SETTINGS["display_name"] = request.form.get("display_name", "")[:40]
    form = (f"<form method='post' action='/v3/settings-safe'><input type='hidden' name='csrf_token' value='{CSRF_TOKEN}'>"
            f"<input name='display_name' value='{html.escape(SETTINGS['display_name'], quote=True)}'><button>save</button></form>")
    return _with_session(app.make_response(page("settings", form)))


V3_LINKS = ["/v3/item-text?id=1", "/v3/item-text-safe?id=1", "/v3/api/item?name=lamp", "/v3/api/price-safe?max=20",
            "/v3/note?body=hello", "/v3/note-safe?body=hello", "/v3/sort?order=name", "/v3/sort-safe?order=name",
            "/v3/convert-safe?amount=1", "/v3/tag?label=info", "/v3/tag-safe?label=info", "/v3/js?term=lamp", "/v3/js-safe?term=lamp",
            "/v3/lookup?q=lamp", "/v3/lookup-safe?q=lamp", "/v3/guestbook", "/v3/guestbook-safe", "/v3/settings", "/v3/settings-safe"]


@app.get("/v3")
def index_v3():
    return page("labflask v3", "<ul>" + "".join(f"<li><a href='{l}'>{l}</a></li>" for l in V3_LINKS) + "</ul>")


init()
init_v3()

if __name__ == "__main__":
    from waitress import serve
    serve(app, listen="*:8080")
