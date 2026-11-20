"""Same-origin crawler: discovers injection points (query, form, JSON and numeric path parameters).

All traffic goes through :class:`dastml.guards.GuardedClient`, so the allowlist, same-origin rule,
budgets, rate limit and skip list apply to every request. ``seeds`` add API endpoints that cannot
be discovered from HTML (single-page apps); each seed is an InjectionPoint description.
"""
import re
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit

from .guards import BudgetExceeded, GuardError

NUMERIC_SEGMENT = re.compile(r"^\d{1,9}$")


@dataclass(frozen=True)
class InjectionPoint:
    method: str            # GET / POST
    path: str              # concrete path, e.g. /book/1
    param: str             # parameter name; for path params "{seg<i>}"
    location: str          # query | form | json | path
    params: tuple = ()     # all (name, value) pairs sent with the request (baseline values)
    template: str = ""     # path with the injected segment as {param}, for path params

    @property
    def key(self):
        return (self.method, self.template or self.path, self.param, self.location)


@dataclass
class _Form:
    action: str
    method: str
    fields: list = field(default_factory=list)


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self._form = [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = _Form(a.get("action") or "", (a.get("method") or "get").upper())
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            if (a.get("type") or "").lower() not in ("submit", "button", "file", "image", "reset"):
                self._form.fields.append((a["name"], a.get("value") or ""))

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def points_from_url(url, method="GET"):
    parts = urlsplit(url)
    pairs = tuple(parse_qsl(parts.query, keep_blank_values=True))
    points = [InjectionPoint(method, parts.path, name, "query", pairs) for name, _ in pairs]
    segs = parts.path.split("/")
    for i, seg in enumerate(segs):
        if NUMERIC_SEGMENT.match(seg):
            template = "/".join(segs[:i] + ["{seg%d}" % i] + segs[i + 1:])
            points.append(InjectionPoint(method, parts.path, "{seg%d}" % i, "path", (("{seg%d}" % i, seg),), template))
    return points


def points_from_form(page_url, form):
    action = urljoin(page_url, form.action or page_url)
    parts = urlsplit(action)
    tokens = ("_csrf", "csrfmiddlewaretoken", "csrf_token")
    pairs = tuple((n, v if (v or n in tokens) else "test") for n, v in form.fields)
    loc = "form" if form.method == "POST" else "query"
    return [InjectionPoint(form.method, parts.path, name, loc, pairs) for name, _ in pairs if name not in tokens]


def crawl(client, start="/", seeds=(), max_depth=3, start_paths=()):
    """BFS over same-origin HTML pages. Returns (injection points, list of visited paths).

    ``start_paths`` are extra pages crawled at depth 0 (configured seed paths such as
    ``/search?q=x``); like every discovered link they go through ``client.check_url``, so an
    off-origin or skip-listed seed is never requested."""
    seen, visited, points = set(), [], {}
    queue = deque([(start, 0)] + [(p, 0) for p in start_paths])
    for p in seeds:
        points.setdefault(p.key, p)
    while queue:
        url, depth = queue.popleft()
        try:
            url = client.check_url(url)
        except GuardError:
            continue
        norm = url.split("#")[0]
        if norm in seen:
            continue
        seen.add(norm)
        try:
            client.count_page()
            resp, _ = client.request("GET", norm)
        except BudgetExceeded:
            break
        except Exception:  # unreachable page: skip it, keep crawling
            continue
        visited.append(urlsplit(norm).path)
        for p in points_from_url(norm):
            points.setdefault(p.key, p)
        if "html" not in resp.headers.get("content-type", ""):
            continue
        parser = _Parser()
        try:
            parser.feed(resp.text[:500_000])
        except Exception:
            continue
        for form in parser.forms:
            for p in points_from_form(norm, form):
                try:
                    client.check_url(p.path)
                except GuardError:
                    continue
                points.setdefault(p.key, p)
        if depth < max_depth:
            for href in parser.links:
                if href.startswith(("mailto:", "javascript:", "tel:")):
                    continue
                queue.append((urljoin(norm, href), depth + 1))
    return list(points.values()), visited
