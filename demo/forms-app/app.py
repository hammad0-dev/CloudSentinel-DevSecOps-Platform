"""Small product catalogue with a feedback form: the CloudSentinel DAST demo target.

INTENTIONALLY VULNERABLE. Two endpoints have bugs on purpose and each has a correct twin:

  GET  /search?q=...          SQL injection (CWE-89): the search term is concatenated into SQL
  GET  /search-safe?q=...     same feature with a parameterized query
  POST /feedback              reflected XSS (CWE-79): the name is echoed into HTML unescaped
  POST /feedback-safe         same feature, escaped by the template engine

Run it only on localhost or in an isolated staging cluster.
"""
import os
import sqlite3

from flask import Flask, g, render_template_string, request

DB_PATH = os.environ.get("DEMO_DB_PATH", "/tmp/catalogue.db")
PRODUCTS = [
    (1, "Desk lamp", "lighting", 24.0),
    (2, "Floor lamp", "lighting", 59.0),
    (3, "Oak desk", "furniture", 210.0),
    (4, "Office chair", "furniture", 145.0),
    (5, "Notebook", "stationery", 3.5),
    (6, "Fountain pen", "stationery", 18.0),
]

app = Flask(__name__)

LAYOUT = """<!doctype html>
<html><head><meta charset="utf-8"><title>{{ title }}</title></head>
<body>
<nav><a href="/">Home</a> | <a href="/search?q=lamp">Search</a> | <a href="/search-safe?q=lamp">Search (safe)</a>
 | <a href="/feedback">Feedback</a> | <a href="/feedback-safe">Feedback (safe)</a></nav>
<h1>{{ title }}</h1>
{{ body | safe }}
</body></html>"""

SEARCH_FORM = """<form method="get" action="{action}">
  <input type="text" name="q" value="">
  <button type="submit">Search</button>
</form>"""

FEEDBACK_FORM = """<form method="post" action="{action}">
  <label>Name <input type="text" name="name"></label>
  <label>Message <textarea name="message"></textarea></label>
  <button type="submit">Send</button>
</form>"""


def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL)")
        db.executemany("INSERT OR IGNORE INTO products VALUES (?, ?, ?, ?)", PRODUCTS)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def page(title, body):
    return render_template_string(LAYOUT, title=title, body=body)


def product_table(rows):
    if not rows:
        return "<p>No products found.</p>"
    cells = "".join(
        render_template_string("<tr><td>{{ n }}</td><td>{{ c }}</td><td>{{ '%.2f' % p }}</td></tr>", n=n, c=c, p=p)
        for n, c, p in rows
    )
    return f"<table><tr><th>Name</th><th>Category</th><th>Price</th></tr>{cells}</table>"


@app.get("/")
def index():
    body = ("<p>Browse the catalogue or send us feedback.</p>"
            + SEARCH_FORM.format(action="/search")
            + "<p>Popular: <a href='/search?q=desk'>desks</a>, <a href='/search-safe?q=pen'>pens</a></p>")
    return page("Catalogue", body)


@app.get("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE (CWE-89): user input concatenated into the SQL string
    sql = "SELECT name, category, price FROM products WHERE name LIKE '%" + q + "%' ORDER BY id"
    rows = get_db().execute(sql).fetchall()
    return page("Search", SEARCH_FORM.format(action="/search") + product_table(rows))


@app.get("/search-safe")
def search_safe():
    q = request.args.get("q", "")
    rows = get_db().execute(
        "SELECT name, category, price FROM products WHERE name LIKE ? ORDER BY id", (f"%{q}%",)
    ).fetchall()
    return page("Search", SEARCH_FORM.format(action="/search-safe") + product_table(rows))


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "GET":
        return page("Feedback", FEEDBACK_FORM.format(action="/feedback"))
    name = request.form.get("name", "")
    # VULNERABLE (CWE-79): the name is inserted into the HTML without escaping
    return page("Feedback", "<p>Thank you, " + name + "! We read every message.</p>")


@app.route("/feedback-safe", methods=["GET", "POST"])
def feedback_safe():
    if request.method == "GET":
        return page("Feedback", FEEDBACK_FORM.format(action="/feedback-safe"))
    thanks = render_template_string("<p>Thank you, {{ name }}! We read every message.</p>", name=request.form.get("name", ""))
    return page("Feedback", thanks)


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8080")))
