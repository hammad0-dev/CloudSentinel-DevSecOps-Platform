"""Injection points from an OpenAPI 3 / Swagger 2 document (JSON only).

The document is fetched through the scan's :class:`dastml.guards.GuardedClient`, so it must be
same-origin with the target and its request counts against the budget. Every operation path is
resolved against the scan origin; a ``servers``/``host`` entry naming another host is never used
as a destination, only its path prefix.

Only GET and POST operations are probed (the same methods the HTML crawler uses); PUT, PATCH and
DELETE are skipped because sending payloads to them can destroy data. Parameters: ``query`` and
``path`` (one injection point per parameter, the other path parameters get example values);
request bodies with ``application/json`` or ``application/x-www-form-urlencoded`` object schemas
(one point per top-level property). Local ``$ref`` (``#/...``) are resolved; remote ones are ignored.
"""
import json
import re
from urllib.parse import quote, urlsplit

from .crawl import InjectionPoint
from .guards import GuardError

MAX_SPEC_BYTES = 2_000_000
MAX_POINTS = 300
METHODS = ("get", "post")


class OpenAPIError(Exception):
    """The OpenAPI document could not be fetched or parsed."""


def _ref(spec, node, depth=0):
    while isinstance(node, dict) and isinstance(node.get("$ref"), str) and depth < 10:
        ref = node["$ref"]
        if not ref.startswith("#/"):
            return {}
        target = spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            target = target.get(part, {}) if isinstance(target, dict) else {}
        node, depth = target, depth + 1
    return node if isinstance(node, dict) else {}


def _example(spec, param_or_schema):
    node = _ref(spec, param_or_schema)
    schema = _ref(spec, node.get("schema", node))
    for source in (node, schema):
        for key in ("example", "default"):
            value = source.get(key)
            if isinstance(value, (str, int, float, bool)):
                return str(value).lower() if isinstance(value, bool) else str(value)
        if isinstance(source.get("enum"), list) and source["enum"]:
            return str(source["enum"][0])
    kind = schema.get("type") or node.get("type")
    return {"integer": "1", "number": "1", "boolean": "true"}.get(kind, "test")


def _base_path(spec):
    if isinstance(spec.get("basePath"), str):  # Swagger 2
        return spec["basePath"].rstrip("/")
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = str(servers[0].get("url", ""))
        path = urlsplit(url).path if "://" in url else url
        return re.sub(r"\{[^}]*\}", "", path).rstrip("/")
    return ""


def _body_points(spec, op):
    """(location, [(name, example), ...]) for the operation's request body, or None."""
    body = _ref(spec, op.get("requestBody"))
    content = body.get("content") if isinstance(body.get("content"), dict) else {}
    for ctype, location in (("application/json", "json"), ("application/x-www-form-urlencoded", "form")):
        if ctype in content:
            schema = _ref(spec, (content[ctype] or {}).get("schema"))
            props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
            return location, [(name, _example(spec, s)) for name, s in props.items()]
    params = [_ref(spec, p) for p in op.get("parameters", []) or []]
    for p in params:  # Swagger 2 body parameter
        if p.get("in") == "body":
            schema = _ref(spec, p.get("schema"))
            props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
            return "json", [(name, _example(spec, s)) for name, s in props.items()]
    form = [(p["name"], _example(spec, p)) for p in params if p.get("in") == "formData" and p.get("name")]
    return ("form", form) if form else None


def points_from_spec(spec):
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        raise OpenAPIError("not an OpenAPI/Swagger document (no 'paths' object)")
    prefix = _base_path(spec)
    points = {}
    for raw_path, item in spec["paths"].items():
        item = _ref(spec, item)
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            continue
        shared = item.get("parameters", []) or []
        for method in METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params = {}
            for p in list(shared) + list(op.get("parameters", []) or []):
                p = _ref(spec, p)
                if p.get("name") and p.get("in") in ("query", "path"):
                    params[(p["in"], p["name"])] = p  # operation-level overrides path-level
            values = {key: _example(spec, p) for key, p in params.items()}
            path_values = {name: v for (loc, name), v in values.items() if loc == "path"}
            full = prefix + raw_path
            concrete = re.sub(r"\{([^}]+)\}", lambda m: quote(path_values.get(m.group(1), "1"), safe=""), full)
            query = tuple((name, v) for (loc, name), v in values.items() if loc == "query")
            M = method.upper()
            for name, _ in query:
                pt = InjectionPoint(M, concrete, name, "query", query)
                points.setdefault(pt.key, pt)
            # same shape as the crawler's numeric path points: param "{seg<i>}", i indexes concrete.split("/")
            concrete_segs = concrete.split("/")
            for i, seg in enumerate(full.split("/")):
                m = re.fullmatch(r"\{([^}]+)\}", seg)
                if not m:
                    continue
                key = "{seg%d}" % i
                template = "/".join(concrete_segs[:i] + [key] + concrete_segs[i + 1:])
                pt = InjectionPoint(M, concrete, key, "path", ((key, path_values.get(m.group(1), "1")),), template)
                points.setdefault(pt.key, pt)
            body = _body_points(spec, op) if M == "POST" else None
            if body:
                location, pairs = body
                pairs = tuple(pairs)
                for name, _ in pairs:
                    pt = InjectionPoint(M, concrete, name, location, pairs)
                    points.setdefault(pt.key, pt)
            if len(points) >= MAX_POINTS:
                return list(points.values())[:MAX_POINTS]
    return list(points.values())


def load_points(client, url):
    """Fetch the document through the guarded client and return its injection points."""
    try:
        resp, _ = client.request("GET", url)
    except GuardError:  # refused or over budget: never retried, surfaces as "target refused"
        raise
    except Exception as exc:
        raise OpenAPIError(f"could not fetch {url}: {type(exc).__name__}") from exc
    if resp.status_code != 200:
        raise OpenAPIError(f"{url} returned HTTP {resp.status_code}")
    if len(resp.content) > MAX_SPEC_BYTES:
        raise OpenAPIError(f"{url} is larger than {MAX_SPEC_BYTES} bytes")
    try:
        spec = json.loads(resp.content)
    except ValueError as exc:
        raise OpenAPIError(f"{url} is not JSON (YAML documents are not supported)") from exc
    return points_from_spec(spec)
