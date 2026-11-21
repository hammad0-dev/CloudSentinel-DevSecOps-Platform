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
    buttons: list = field(default_factory=list)  # v5: submit button texts (destructive-action skip list)


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self._form = [], [], None
        # v5: link texts parallel to ``links`` (one entry per link), for the authenticated skip list
        self.link_texts, self._a, self._button = [], None, None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
            self.link_texts.append("")
            self._a = len(self.links) - 1
        elif tag == "form":
            self._form = _Form(a.get("action") or "", (a.get("method") or "get").upper())
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            if (a.get("type") or "").lower() not in ("submit", "button", "file", "image", "reset"):
                self._form.fields.append((a["name"], a.get("value") or ""))
        if self._form is not None:
            if tag == "button":
                self._button = len(self._form.buttons)
                self._form.buttons.append(a.get("value") or "")
            elif tag == "input" and (a.get("type") or "").lower() in ("submit", "button", "image"):
                self._form.buttons.append(a.get("value") or a.get("alt") or "")

    def handle_data(self, data):
        if self._a is not None:
            self.link_texts[self._a] += data
        if self._button is not None and self._form is not None:
            self._form.buttons[self._button] += data

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
            self._button = None
        elif tag == "a":
            self._a = None
        elif tag == "button":
            self._button = None


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


def crawl(client, start="/", seeds=(), max_depth=3, start_paths=(), forms_out=None, pages_out=None):
    """BFS over same-origin HTML pages. Returns (injection points, list of visited paths).

    ``start_paths`` are extra pages crawled at depth 0 (configured seed paths such as
    ``/search?q=x``); like every discovered link they go through ``client.check_url``, so an
    off-origin or skip-listed seed is never requested.

    v3 (optional): ``forms_out`` receives every form as {"page", "action", "method", "fields"} (token-only
    forms included; the CSRF heuristic needs them) and ``pages_out`` every visited HTML page as a
    path with its query string (the stored-XSS rule re-fetches these)."""
    seen, visited, points = set(), [], {}
    authed = getattr(client, "auth", None) is not None  # v5: destructive links/forms are skipped only when logged in
    if authed:
        from .auth import destructive_text
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
        if pages_out is not None:
            parts = urlsplit(norm)
            pages_out.append(parts.path + ("?" + parts.query if parts.query else ""))
        for form in parser.forms:
            if forms_out is not None:
                action = urlsplit(urljoin(norm, form.action or norm))
                forms_out.append({"page": urlsplit(norm).path, "action": action.path, "method": form.method,
                                  "fields": [n for n, _ in form.fields]})
            if authed and any(destructive_text(b) for b in form.buttons):
                continue  # never submitted or probed (the CSRF heuristic only reads it, it sends nothing)
            for p in points_from_form(norm, form):
                try:
                    client.check_url(p.path)
                except GuardError:
                    continue
                points.setdefault(p.key, p)
        if depth < max_depth:
            for i, href in enumerate(parser.links):
                if href.startswith(("mailto:", "javascript:", "tel:")):
                    continue
                if authed and destructive_text(parser.link_texts[i]):
                    continue
                queue.append((urljoin(norm, href), depth + 1))
    return list(points.values()), visited
