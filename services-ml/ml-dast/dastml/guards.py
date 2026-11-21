"""Safety guards for every request the ml-dast crawler and payload sender make.

* Target allowlist: exact host names (default ``127.0.0.1`` and ``localhost``) and an explicit port
  set (default 5101-5108, the lab compose ports). No DNS tricks: the host string must match exactly;
  alternative spellings of loopback (``127.1``, ``0x7f000001``, ``[::1]``), userinfo and other
  schemes are refused.
* Same origin only: every request must have the scan's scheme, host and port.
* Budgets: at most ``max_pages`` crawled pages and ``max_requests`` requests in total.
* Rate limit: at least ``1 / rate`` seconds between requests.
* Redirects are never followed automatically; :meth:`GuardedClient.request` follows only same-origin
  redirects, each one counted against the budget.
* Proxies from the environment are ignored, so traffic cannot be routed elsewhere.
* ``skip`` paths (endpoints that must never be attacked) are refused, and so are (path, parameter)
  pairs on ``skip_params``.
* A request whose query or body parameters carry a URL (``scheme://`` raw or %-encoded) is refused,
  so a crawled link can never make the target fetch another host (SSRF / remote include).

Configuration (service): ML_DAST_ALLOWED_HOSTS (comma list), ML_DAST_ALLOWED_PORTS (comma list of
ports or ranges, e.g. ``5101-5108,8080``), ML_DAST_RATE_PER_SEC.
"""
import os
import re
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlsplit

import requests

DEFAULT_HOSTS = ("127.0.0.1", "localhost")
DEFAULT_PORTS = "5101-5108"


class GuardError(Exception):
    """A request was refused by a guard. Never retried."""


class BudgetExceeded(GuardError):
    pass


# Widest single range accepted: the Kubernetes default NodePort range 30000-32767 (2768 ports), because
# a pipeline's staging NodePort is assigned at deploy time. Anything wider is refused.
MAX_RANGE_WIDTH = 32767 - 30000


def parse_ports(spec):
    ports = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if not (1 <= lo <= hi <= 65535) or hi - lo > MAX_RANGE_WIDTH:
                raise ValueError(f"bad port range {part}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError(f"bad port {part}")
            ports.add(p)
    return frozenset(ports)


_HOST_RE = re.compile(r"^[a-z0-9.-]+$")


@dataclass
class TargetPolicy:
    allowed_hosts: frozenset = frozenset(DEFAULT_HOSTS)
    allowed_ports: frozenset = field(default_factory=lambda: parse_ports(DEFAULT_PORTS))
    max_pages: int = 50
    max_requests: int = 500
    rate_per_sec: float = 20.0
    max_redirects: int = 3
    timeout_sec: float = 10.0
    skip_paths: tuple = ()
    # (path pattern, parameter) pairs: a request to that path carrying that query parameter is
    # refused (endpoints that share a path with others, e.g. DSVW's "/?object=" pickle RCE).
    skip_params: tuple = ()

    @classmethod
    def from_env(cls, **kw):
        hosts = os.environ.get("ML_DAST_ALLOWED_HOSTS")
        ports = os.environ.get("ML_DAST_ALLOWED_PORTS")
        rate = os.environ.get("ML_DAST_RATE_PER_SEC")
        if hosts:
            kw.setdefault("allowed_hosts", frozenset(h.strip().lower() for h in hosts.split(",") if h.strip()))
        if ports:
            kw.setdefault("allowed_ports", parse_ports(ports))
        if rate:
            kw.setdefault("rate_per_sec", float(rate))
        return cls(**kw)

    def origin_of(self, url):
        """Validate a scan target and return its (scheme, host, port) origin, or raise GuardError."""
        if not isinstance(url, str) or len(url) > 2000:
            raise GuardError("target must be a URL string")
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise GuardError(f"scheme {parts.scheme!r} not allowed")
        if "@" in parts.netloc:
            raise GuardError("credentials in URL not allowed")
        host = (parts.hostname or "").lower()
        if not host or not _HOST_RE.match(host) or parts.netloc.lower().startswith("["):
            raise GuardError(f"host {host!r} not allowed")
        if host not in self.allowed_hosts:
            raise GuardError(f"host {host!r} is not in the allowlist")
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError as exc:
            raise GuardError("invalid port") from exc
        if port not in self.allowed_ports:
            raise GuardError(f"port {port} is not in the allowlist")
        return (parts.scheme, host, port)

    @staticmethod
    def _path_matches(pattern, path):
        regex = "^" + re.escape(pattern).replace(r"\{", "{").replace(r"\}", "}")
        regex = re.sub(r"\{[^}]+\}", "[^/]+", regex)
        return re.match(regex + r"(/|$|\?)", path) is not None

    def skipped(self, path, query=""):
        if any(self._path_matches(p, path) for p in self.skip_paths):
            return True
        names = {k for k, _ in parse_qsl(query, keep_blank_values=True)}
        return any(param in names and self._path_matches(p, path) for p, param in self.skip_params)


# A request whose parameters carry a URL could make the target fetch another host (SSRF, remote
# include). ml-dast payloads never contain one; crawled links that do are refused.
_URL_IN_PARAMS = re.compile(r"[a-z][a-z0-9+.-]*:(//|%2f%2f)", re.I)


def carries_url(query):
    if _URL_IN_PARAMS.search(query):
        return True
    return any(_URL_IN_PARAMS.search(v) for _, v in parse_qsl(query, keep_blank_values=True))


class GuardedClient:
    """The only way ml-dast sends HTTP requests. Enforces origin, budgets, rate and skip list."""

    def __init__(self, base_url, policy: TargetPolicy, auth=None):
        self.policy = policy
        self.origin = policy.origin_of(base_url)
        self.base_url = base_url
        self.requests_sent = 0
        self.pages = 0
        self._last = 0.0
        self._lock = threading.Lock()
        self.session = requests.Session()
        self.session.trust_env = False  # ignore HTTP(S)_PROXY / .netrc
        self.session.headers["User-Agent"] = "cloudsentinel-ml-dast/0.2 (lab scanner)"
        # v5: optional dastml.auth.AuthSession. None (the default) keeps the exact pre-v5 behaviour:
        # no login, no re-login and no destructive-action skip list.
        self.auth = auth

    def check_url(self, url):
        absolute = urljoin(self.base_url, url)
        if self.policy.origin_of(absolute) != self.origin:
            raise GuardError(f"{absolute} is not same-origin with {self.base_url}")
        parts = urlsplit(absolute)
        path = parts.path or "/"
        if self.policy.skipped(path, parts.query):
            raise GuardError(f"{path} is on the skip list")
        if carries_url(parts.query):
            raise GuardError(f"{path}: a parameter carries a URL (possible SSRF); refused")
        if self.auth is not None:
            from .auth import destructive_path
            if destructive_path(path, [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]):
                raise GuardError(f"{path} is on the destructive-action skip list (authenticated scan)")
        return absolute

    def login(self):
        """Log in with the attached AuthSession (no-op without one)."""
        if self.auth is not None:
            self.auth.login(self)

    def check_body(self, data):
        """Query/form/JSON parameter dicts are checked like query strings: no URL-carrying values."""
        values = data.values() if isinstance(data, dict) else []
        if any(isinstance(v, str) and _URL_IN_PARAMS.search(v) for v in values):
            raise GuardError("a parameter carries a URL (possible SSRF); refused")

    def count_page(self):
        if self.pages >= self.policy.max_pages:
            raise BudgetExceeded(f"max_pages={self.policy.max_pages} reached")
        self.pages += 1

    def _throttle(self):
        with self._lock:
            if self.requests_sent >= self.policy.max_requests:
                raise BudgetExceeded(f"max_requests={self.policy.max_requests} reached")
            wait = self._last + 1.0 / self.policy.rate_per_sec - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            self.requests_sent += 1

    def request(self, method, url, **kw):
        """Send one request (plus same-origin redirects). Returns (final response, elapsed seconds).

        v5, with an AuthSession: DELETE and destructive parameter names are refused, and a response
        that shows the session expired triggers one re-login and one resend (never during a login)."""
        if self.auth is None:
            return self._request(method, url, **kw)
        from .auth import AuthError, destructive_path
        if method.upper() == "DELETE":
            raise GuardError("DELETE is never sent by an authenticated scan")
        names = [k for key in ("params", "data", "json") if isinstance(kw.get(key), dict) for k in kw[key]]
        if names and destructive_path("/", names):
            raise GuardError("a parameter name is on the destructive-action skip list (authenticated scan)")
        resp, elapsed = self._request(method, url, **kw)
        path = urlsplit(urljoin(self.base_url, url)).path or "/"
        if self.auth.in_login or self.auth.suspended or self.auth.is_login_request(path) or not self.auth.expired(resp):
            return resp, elapsed
        if not self.auth.can_relogin():
            return resp, elapsed  # recorded as it is; the cap stops login loops
        self.auth.relogins += 1
        self.auth.events.append(("relogin", path))
        try:
            self.auth.login(self)
        except AuthError:
            return resp, elapsed
        return self._request(method, url, **kw)

    def _request(self, method, url, **kw):
        url = self.check_url(url)
        for key in ("params", "data", "json"):
            if key in kw:
                self.check_body(kw[key])
        kw.pop("allow_redirects", None)
        kw.setdefault("timeout", self.policy.timeout_sec)
        started = time.monotonic()
        hops = []  # earlier responses of a same-origin redirect chain (their Set-Cookie headers matter)
        for _ in range(self.policy.max_redirects + 1):
            self._throttle()
            resp = self.session.request(method, url, allow_redirects=False, **kw)
            resp.cs_hops = list(hops)
            if resp.status_code not in (301, 302, 303, 307, 308) or "location" not in resp.headers:
                return resp, time.monotonic() - started
            hops.append(resp)
            try:
                url = self.check_url(resp.headers["location"])
            except GuardError:
                return resp, time.monotonic() - started  # off-origin redirect: report it, never follow
            if resp.status_code in (301, 302, 303):
                method, kw = "GET", {k: v for k, v in kw.items() if k not in ("data", "json")}
        return resp, time.monotonic() - started
