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
             "/download?file=readme.txt", "/download-safe?file=readme.txt", "/login", "/login-safe"]
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


init()

if __name__ == "__main__":
    from waitress import serve
    serve(app, listen="*:8080")
