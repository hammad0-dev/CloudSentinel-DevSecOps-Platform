"""A tiny local app with a login, for the authenticated-scanning tests (127.0.0.1, random port).

* GET /login shows a login form with a per-session CSRF token; POST /login checks it and the demo
  credentials and sets a session cookie.
* /account (protected) shows a search form; /account/search?q= reflects q unescaped (XSS) when
  logged in; logged-out requests are redirected to /login.
* /account/delete (link and form with a "Delete account" button) and /logout must never be requested
  by an authenticated scan.
* Sessions can be expired from the test (``APP.expire_all()``).
* Every request is recorded in ``APP.log`` (method, path, query, body).
"""
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

USER, PASSWORD = "demo", "Demo-Pass-7731"  # test-only demo account of this fake app


class State:
    def __init__(self):
        self.log, self.sessions, self.csrf = [], set(), {}
        self.lock = threading.Lock()
        self.logins = 0

    def expire_all(self):
        with self.lock:
            self.sessions.clear()


APP = State()


def page(body):
    return f"<html><body>{body}</body></html>"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _cookie(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid":
                return v
        return None

    def _send(self, body, status=200, headers=()):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _record(self, body=""):
        u = urlsplit(self.path)
        with APP.lock:
            APP.log.append({"method": self.command, "path": u.path, "query": u.query, "body": body,
                            "auth": self.headers.get("Authorization", "")})
        return u, {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}

    def _logged_in(self):
        sid = self._cookie()
        return sid is not None and sid in APP.sessions

    def do_GET(self):
        u, q = self._record()
        if u.path == "/":
            return self._send(page("<a href='/login'>login</a> <a href='/public?name=x'>public</a>"))
        if u.path == "/public":
            return self._send(page("<p>public " + q.get("name", "").replace("<", "&lt;") + "</p>"))
        if u.path == "/login":
            pre = self._cookie() or secrets.token_hex(8)
            token = secrets.token_hex(8)
            APP.csrf[pre] = token
            form = (f"<form method='post' action='/login'><input type='hidden' name='csrf_token' value='{token}'>"
                    "<input name='username'><input name='password' type='password'><button>Log in</button></form>")
            return self._send(page(form), headers=[("Set-Cookie", f"pre={pre}; Path=/")])
        if u.path == "/api/me":  # bearer-token API (JSON login)
            token = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
            if token not in APP.sessions:
                return self._send('{"error": "token required"}', 401)
            return self._send('{"user": "demo"}')
        if u.path.startswith("/account") or u.path == "/logout":
            if not self._logged_in():
                return self._send("", 302, [("Location", "/login")])
            if u.path == "/logout":
                APP.sessions.discard(self._cookie())
                return self._send("", 302, [("Location", "/")])
            if u.path == "/account":
                body = ("<p>Welcome, demo</p><form action='/account/search'><input name='q' value='x'><button>Search</button></form>"
                        "<a href='/account/orders?id=1'>orders</a> <a href='/logout'>Log out</a> "
                        "<a href='/account/delete'>Delete my account</a>"
                        "<form method='post' action='/account/close'><input name='confirm' value='yes'><button>Delete account</button></form>")
                return self._send(page(body))
            if u.path == "/account/search":
                return self._send(page("<p>results for " + q.get("q", "") + "</p>"))  # reflected XSS (logged in)
            if u.path == "/account/orders":
                return self._send(page("<p>order " + q.get("id", "").replace("<", "&lt;") + "</p>"))
            if u.path == "/account/delete":
                return self._send(page("<p>account deleted</p>"))
        return self._send(page("not found"), 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode()
        u, _ = self._record(raw)
        form = {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}
        if u.path == "/api/login":
            import json
            try:
                body = json.loads(raw or "{}")
            except ValueError:
                body = {}
            if body.get("username") == USER and body.get("password") == PASSWORD:
                token = secrets.token_hex(16)
                with APP.lock:
                    APP.sessions.add(token)
                    APP.logins += 1
                return self._send(json.dumps({"token": token}))
            return self._send('{"error": "bad credentials"}', 401)
        if u.path == "/login":
            pre = None
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "pre":
                    pre = v
            if not pre or APP.csrf.get(pre) != form.get("csrf_token"):
                return self._send(page("<p>bad csrf token</p>"), 403)
            if form.get("username") == USER and form.get("password") == PASSWORD:
                sid = secrets.token_hex(12)
                with APP.lock:
                    APP.sessions.add(sid)
                    APP.logins += 1
                return self._send("", 302, [("Location", "/account"), ("Set-Cookie", f"sid={sid}; Path=/; HttpOnly")])
            return self._send(page("<p>invalid credentials</p>"), 401)
        if u.path == "/account/close":
            return self._send(page("<p>account closed</p>"))
        return self._send(page("not found"), 404)


def start():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
