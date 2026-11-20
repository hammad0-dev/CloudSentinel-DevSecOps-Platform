"""labfastapi: deliberately vulnerable AND safe endpoints for ml-dast ground truth (FastAPI + MySQL + Jinja2).

LAB ONLY. Published on 127.0.0.1 only through the lab compose file. Never deploy.
Every route is listed in services-ml/ml-dast/data/dast/ground_truth.json.
"""
import html
import os
import time

import pymysql
from fastapi import FastAPI, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from jinja2 import Environment

app = FastAPI()
env = Environment(autoescape=True)
LAYOUT = "<!doctype html><html><head><title>{{ title }}</title></head><body><h3>{{ title }}</h3>{% block b %}{% endblock %}<p><a href='/'>home</a></p></body></html>"
T_LIST = env.from_string(LAYOUT.replace("{% block b %}{% endblock %}", "<ol>{% for r in rows %}<li>{{ r[0] }} - {{ r[1] }}</li>{% endfor %}</ol>{{ note }}"))
T_NOTE_RAW = env.from_string(LAYOUT.replace("{% block b %}{% endblock %}", "<div class='note'>{{ note|safe }}</div>"))
T_NOTE = env.from_string(LAYOUT.replace("{% block b %}{% endblock %}", "<div class='note'>{{ note }}</div>"))
T_HREF_RAW = env.from_string(LAYOUT.replace("{% block b %}{% endblock %}", "<a href=\"/docs?topic={{ topic|safe }}\">read more about {{ topic }}</a>"))
T_HREF = env.from_string(LAYOUT.replace("{% block b %}{% endblock %}", "<a href=\"/docs?topic={{ topic|urlencode }}\">read more about {{ topic }}</a>"))


def conn():
    return pymysql.connect(host=os.environ.get("DB_HOST", "mysql"), user="lab", password=os.environ.get("DB_PASSWORD", "lab"), database="lab", autocommit=True)


@app.on_event("startup")
def init():
    for _ in range(60):
        try:
            c = conn().cursor()
            break
        except pymysql.err.OperationalError:
            time.sleep(1)
    for stmt in ("DROP TABLE IF EXISTS orders", "CREATE TABLE orders (id INT AUTO_INCREMENT PRIMARY KEY, item VARCHAR(40), status VARCHAR(20))",
                 "INSERT INTO orders (item, status) VALUES ('kettle','shipped'),('toaster','pending'),('fridge','shipped'),('oven','cancelled')"):
        c.execute(stmt)


def rows_page(title, rows, note=""):
    return HTMLResponse(T_LIST.render(title=title, rows=rows, note=note))


@app.get("/", response_class=HTMLResponse)
def index():
    links = ["/orders?status=shipped", "/orders-safe?status=shipped", "/order?id=1", "/order-safe?id=1", "/note?text=hi", "/note-safe?text=hi",
             "/docs-link?topic=intro", "/docs-link-safe?topic=intro", "/api/status?item=kettle", "/api/status-safe?item=kettle", "/text?msg=hi", "/report", "/report-safe", "/v2"]
    return "<!doctype html><html><body><h3>labfastapi</h3><ul>" + "".join(f"<li><a href='{l}'>{l}</a></li>" for l in links) + "</ul></body></html>"


# ---------- CWE-89 ----------
@app.get("/orders")  # VULN CWE-89: string-built, MySQL error shown
def orders(status: str = ""):
    try:
        c = conn().cursor()
        c.execute("SELECT item, status FROM orders WHERE status = '%s'" % status)
        return rows_page("orders", c.fetchall())
    except pymysql.MySQLError as exc:
        return HTMLResponse(f"<pre>pymysql.err.ProgrammingError: {html.escape(str(exc))}</pre>", status_code=500)


@app.get("/orders-safe")  # SAFE
def orders_safe(status: str = ""):
    c = conn().cursor()
    c.execute("SELECT item, status FROM orders WHERE status = %s", (status,))
    return rows_page("orders", c.fetchall())


@app.get("/order")  # VULN CWE-89: numeric, errors hidden (boolean/blind)
def order(id: str = "0"):
    try:
        c = conn().cursor()
        c.execute("SELECT item, status FROM orders WHERE id = " + id)
        rows = c.fetchall()
    except pymysql.MySQLError:
        rows = ()
    return rows_page("order", rows, "" if rows else "nothing found")


@app.get("/order-safe")  # SAFE: typed int param (FastAPI returns 422 on bad input)
def order_safe(id: int = 0):
    c = conn().cursor()
    c.execute("SELECT item, status FROM orders WHERE id = %s", (id,))
    rows = c.fetchall()
    return rows_page("order", rows, "" if rows else "nothing found")


@app.get("/api/status")  # VULN CWE-89: JSON API, string-built, generic error JSON
def api_status(item: str = ""):
    try:
        c = conn().cursor()
        c.execute(f"SELECT status FROM orders WHERE item = '{item}'")
        r = c.fetchone()
        return {"item": item, "status": r[0] if r else None}
    except pymysql.MySQLError:
        return JSONResponse({"error": "query failed"}, status_code=500)


@app.get("/api/status-safe")  # SAFE (hard negative: reflects item raw in JSON)
def api_status_safe(item: str = ""):
    c = conn().cursor()
    c.execute("SELECT status FROM orders WHERE item = %s", (item,))
    r = c.fetchone()
    return {"item": item, "status": r[0] if r else None}


REPORT_FORM = "<form method='post'><input name='region'><button>run</button></form>"


@app.get("/report", response_class=HTMLResponse)
def report_form():
    return REPORT_FORM


@app.get("/report-safe", response_class=HTMLResponse)
def report_safe_form():
    return REPORT_FORM


@app.post("/report")  # VULN CWE-89: form body, MySQL error shown
def report(region: str = Form("")):
    try:
        c = conn().cursor()
        c.execute("SELECT item, status FROM orders WHERE item LIKE '" + region + "%'")
        return rows_page("report", c.fetchall())
    except pymysql.MySQLError as exc:
        return HTMLResponse(f"<pre>{html.escape(str(exc))}</pre>", status_code=500)


@app.post("/report-safe")  # SAFE
def report_safe(region: str = Form("")):
    c = conn().cursor()
    c.execute("SELECT item, status FROM orders WHERE item LIKE %s", (region + "%",))
    return rows_page("report", c.fetchall())


# ---------- CWE-79 ----------
@app.get("/note")  # VULN CWE-79: Jinja2 |safe
def note(text: str = ""):
    return HTMLResponse(T_NOTE_RAW.render(title="note", note=text))


@app.get("/note-safe")  # SAFE: autoescape
def note_safe(text: str = ""):
    return HTMLResponse(T_NOTE.render(title="note", note=text))


@app.get("/docs-link")  # VULN CWE-79: href attribute via |safe
def docs_link(topic: str = ""):
    return HTMLResponse(T_HREF_RAW.render(title="docs", topic=topic))


@app.get("/docs-link-safe")  # SAFE: urlencode in href, autoescape in text
def docs_link_safe(topic: str = ""):
    return HTMLResponse(T_HREF.render(title="docs", topic=topic))


@app.get("/text")  # SAFE (hard negative): raw reflection as text/plain
def text(msg: str = Query("")):
    return PlainTextResponse("echo: " + msg)


# ---------- v2 additions (B3): realistic safe endpoints ----------
import re  # noqa: E402

T_ERR = env.from_string(LAYOUT.replace("{% block b %}{% endblock %}", "<p>No page called {{ page }}.</p>"))
T_LINK = env.from_string(LAYOUT.replace("{% block b %}{% endblock %}", "<a href=\"{{ url }}\">continue</a>"))


@app.get("/v2", response_class=HTMLResponse)
def index_v2():
    links = ["/api/orders-safe?item=kettle", "/notfound-safe?page=help", "/link?url=/orders", "/link-safe?url=/orders", "/carrier-safe?code=dhl"]
    return "<!doctype html><html><body><h3>labfastapi v2</h3><ul>" + "".join(f"<li><a href='{l}'>{l}</a></li>" for l in links) + "</ul></body></html>"


@app.get("/api/orders-safe")  # SAFE (hard negative): validated JSON API, 400 JSON on bad input (any quote count)
def api_orders_safe(item: str = ""):
    if not re.fullmatch(r"[\w ]{0,40}", item):
        return JSONResponse({"error": "invalid item"}, status_code=400)
    c = conn().cursor()
    c.execute("SELECT item, status FROM orders WHERE item LIKE %s", (f"%{item}%",))
    return {"orders": [list(r) for r in c.fetchall()]}


@app.get("/notfound-safe", response_class=HTMLResponse)  # SAFE (hard negative): 404 page echoing the name, autoescaped
def notfound_safe(page: str = ""):
    return HTMLResponse(T_ERR.render(title="not found", page=page), status_code=404)


@app.get("/link", response_class=HTMLResponse)  # VULN CWE-79: autoescaped, but the scheme is not checked (javascript: in href)
def link(url: str = "/"):
    return HTMLResponse(T_LINK.render(title="link", url=url))


@app.get("/link-safe", response_class=HTMLResponse)  # SAFE: same-site relative paths only, autoescaped
def link_safe(url: str = "/"):
    ok = url.startswith("/") and not url.startswith("//") and "\\" not in url
    return HTMLResponse(T_LINK.render(title="link", url=url if ok else "/"))


CARRIERS = {"dhl": "DHL", "ups": "UPS"}


@app.get("/carrier-safe", response_class=HTMLResponse)  # SAFE (hard negative): unknown codes wait ~1.2 s for a slow upstream
def carrier_safe(code: str = ""):
    if code in CARRIERS:
        return HTMLResponse(T_NOTE.render(title="carrier", note=CARRIERS[code]))
    time.sleep(1.2)
    return HTMLResponse(T_NOTE.render(title="carrier", note="unknown carrier"))
