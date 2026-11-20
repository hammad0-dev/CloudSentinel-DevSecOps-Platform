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
* ``skip`` paths (endpoints that must never be attacked) are refused.

Configuration (service): ML_DAST_ALLOWED_HOSTS (comma list), ML_DAST_ALLOWED_PORTS (comma list of
ports or ranges, e.g. ``5101-5108,8080``), ML_DAST_RATE_PER_SEC.
"""
import os
import re
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

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

    def skipped(self, path):
        for pattern in self.skip_paths:
            regex = "^" + re.escape(pattern).replace(r"\{", "{").replace(r"\}", "}")
            regex = re.sub(r"\{[^}]+\}", "[^/]+", regex)
            if re.match(regex + r"(/|$|\?)", path):
                return True
        return False


class GuardedClient:
    """The only way ml-dast sends HTTP requests. Enforces origin, budgets, rate and skip list."""

    def __init__(self, base_url, policy: TargetPolicy):
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

    def check_url(self, url):
        absolute = urljoin(self.base_url, url)
        if self.policy.origin_of(absolute) != self.origin:
            raise GuardError(f"{absolute} is not same-origin with {self.base_url}")
        path = urlsplit(absolute).path or "/"
        if self.policy.skipped(path):
            raise GuardError(f"{path} is on the skip list")
        return absolute

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
        """Send one request (plus same-origin redirects). Returns (final response, elapsed seconds)."""
        url = self.check_url(url)
        kw.pop("allow_redirects", None)
        kw.setdefault("timeout", self.policy.timeout_sec)
        started = time.monotonic()
        for _ in range(self.policy.max_redirects + 1):
            self._throttle()
            resp = self.session.request(method, url, allow_redirects=False, **kw)
            if resp.status_code not in (301, 302, 303, 307, 308) or "location" not in resp.headers:
                return resp, time.monotonic() - started
            try:
                url = self.check_url(resp.headers["location"])
            except GuardError:
                return resp, time.monotonic() - started  # off-origin redirect: report it, never follow
            if resp.status_code in (301, 302, 303):
                method, kw = "GET", {k: v for k, v in kw.items() if k not in ("data", "json")}
        return resp, time.monotonic() - started
