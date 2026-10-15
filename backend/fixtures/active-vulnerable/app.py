"""Deliberately vulnerable disposable WSGI fixture. Never bind production data."""
import json
import sqlite3
import tempfile
from contextlib import closing
from urllib.parse import parse_qs


def application(environ, start_response):
    path = environ.get("PATH_INFO", "")
    query = parse_qs(environ.get("QUERY_STRING", ""))
    if path == "/health":
        body, content_type = "fixture-ready", "text/plain"
    elif path == "/test/sqli":
        # Deliberate CWE-89: per-request tmpfs data, never a host database/DSN.
        with tempfile.TemporaryDirectory(prefix="cs-sqli-", dir="/tmp") as directory, closing(sqlite3.connect(directory + "/fixture.db")) as db:
            db.execute("CREATE TABLE items(id INTEGER, name TEXT)")
            db.executemany("INSERT INTO items VALUES (?,?)", [(1, "demo-one"), (2, "demo-two")])
            try:
                body = json.dumps(db.execute("SELECT name FROM items WHERE id=" + query.get("id", ["1"])[0][:512]).fetchall())
            except sqlite3.Error:
                body = "fixture SQL error"
        content_type = "application/json"
    elif path == "/test/xss":
        # Deliberate CWE-79, only synthetic reflected input.
        body = "<html><body>fixture: " + query.get("q", ["hello"])[0][:512] + "</body></html>"
        content_type = "text/html"
    else:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"not found"]
    start_response("200 OK", [("Content-Type", content_type), ("Cache-Control", "no-store")])
    return [body.encode("utf-8")]


if __name__ == "__main__":
    from wsgiref.simple_server import make_server
    # Only future isolated-container execution; no host port publication.
    with make_server("0.0.0.0", 18080, application) as server:
        server.serve_forever()
