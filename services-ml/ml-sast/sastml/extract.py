"""Split Python and JavaScript sources into function-level units.

A *unit* is what the model classifies and what a finding points at:

* every function/method whose enclosing functions are all *containers*;
* a function is a container when it is >= 15 lines and >= 50% of its lines belong to nested functions
  (NodeGoat-style ``function Handler(db) { this.a = (req, res) => {...}; ... }`` or Flask app factories),
  so the nested handlers become units instead of one giant block;
* nested callbacks inside a non-container function stay part of their parent unit;
* ``<module>``: top-level statements outside any unit (config constants, hardcoded secrets).

Python uses the stdlib ``ast`` (files that do not parse yield no units). JavaScript uses tree-sitter
(``tree-sitter-javascript``), which is error-tolerant, so partly invalid files still yield units. When
tree-sitter is not installed, a documented fallback finds ``function``/arrow heads with a regex and matches
braces while skipping strings and comments (less precise; recorded as ``parser="fallback"``).

``start_line`` is the ``def``/``function`` line (1-based); ``code`` includes decorators and, for a callback
passed directly to a call such as ``app.get('/x', (req, res) => {...})``, the whole call statement.
"""
import ast
import re
from dataclasses import dataclass, field

PY_EXT = (".py",)
JS_EXT = (".js", ".mjs", ".cjs", ".jsx")
MAX_FILE_BYTES = 512 * 1024


@dataclass
class Unit:
    name: str
    start_line: int
    end_line: int
    code: str
    lang: str
    parser: str = "ast"
    meta: dict = field(default_factory=dict)


def language_of(path):
    p = path.lower()
    if p.endswith(PY_EXT):
        return "python"
    if p.endswith(JS_EXT) or p.endswith((".ts", ".tsx")):
        return "javascript"
    return None


def looks_minified(text):
    lines = text.splitlines() or [""]
    return len(text) > 2000 and (sum(len(x) for x in lines) / len(lines) > 250)


def extract(path, text):
    lang = language_of(path)
    if lang is None or len(text.encode("utf-8", "ignore")) > MAX_FILE_BYTES or looks_minified(text):
        return []
    return extract_python(text) if lang == "python" else extract_javascript(text)


# ------------------------------------------------------------------ python ---

def _select(funcs, n_lines_of, children_of, member=lambda n: True):
    """Apply the container rule to a function tree. funcs: list of root nodes.

    Only *member* children (named/assigned nested functions) make a parent a container; anonymous
    callbacks (``.then(x => ...)``, ``forEach``) stay inside their parent unit.
    """
    out = []

    def visit(node):
        kids = [k for k in children_of(node) if member(k)]
        span = n_lines_of(node)
        nested = sum(n_lines_of(k) for k in kids)
        if kids and span >= 15 and nested >= 0.5 * span:
            for k in kids:
                visit(k)
        else:
            out.append(node)

    for f in funcs:
        visit(f)
    return out


def extract_python(text):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    lines = text.splitlines()
    FN = (ast.FunctionDef, ast.AsyncFunctionDef)

    def direct_funcs(node):
        found = []
        for child in ast.iter_child_nodes(node):
            if isinstance(child, FN):
                found.append(child)
            elif not isinstance(child, ast.Lambda):
                found.extend(direct_funcs(child))
        return found

    roots = direct_funcs(tree)
    span = lambda n: (n.end_lineno or n.lineno) - n.lineno + 1
    units = []
    for f in _select(roots, span, direct_funcs):
        first = min([d.lineno for d in f.decorator_list] + [f.lineno])
        code = "\n".join(lines[first - 1:f.end_lineno])
        units.append(Unit(f.name, f.lineno, f.end_lineno, _dedent(code), "python"))
    covered = set()
    for f in roots:
        first = min([d.lineno for d in f.decorator_list] + [f.lineno])
        covered.update(range(first, (f.end_lineno or f.lineno) + 1))
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            covered.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    units += _module_unit(lines, covered, "python", (ast.Import, ast.ImportFrom), tree)
    return units


def _module_unit(lines, covered, lang, skip_types=(), tree=None):
    keep = []
    if tree is not None:
        for node in tree.body:
            if isinstance(node, skip_types) or node.lineno in covered:
                continue
            keep.extend(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    else:
        keep = [i for i in range(1, len(lines) + 1) if i not in covered]
    body = [(i, lines[i - 1]) for i in sorted(set(keep)) if lines[i - 1].strip() and not _is_import(lines[i - 1], lang)]
    if not body or not any(re.search(r"=|:", t) for _, t in body):
        return []
    return [Unit("<module>", body[0][0], body[-1][0], "\n".join(t for _, t in body), lang, "ast" if lang == "python" else "tree-sitter",
                 {"lines": [i for i, _ in body]})]


def _is_import(line, lang):
    s = line.strip()
    if lang == "python":
        return s.startswith(("import ", "from ")) or s.startswith("#")
    return bool(re.match(r"(import\s|export\s+\*|//|/\*|\*|'use strict'|\"use strict\")", s)) or bool(re.match(r"(const|let|var)\s+[\w{}\s,]+=\s*require\(['\"][^'\"]+['\"]\)\s*;?$", s))


def _dedent(code):
    rows = code.split("\n")
    pad = min((len(r) - len(r.lstrip()) for r in rows if r.strip()), default=0)
    return "\n".join(r[pad:] for r in rows)


# -------------------------------------------------------------- javascript ---

_JS_PARSER = None
JS_FN_TYPES = {"function_declaration", "generator_function_declaration", "function_expression", "function",
               "arrow_function", "method_definition", "generator_function"}


def _js_parser():
    global _JS_PARSER
    if _JS_PARSER is None:
        try:
            import tree_sitter_javascript as tsjs
            from tree_sitter import Language, Parser
            _JS_PARSER = Parser(Language(tsjs.language()))
        except Exception:  # tree-sitter not installed -> fallback
            _JS_PARSER = False
    return _JS_PARSER


def js_parses(code):
    p = _js_parser()
    if not p:
        return True
    return not p.parse(code.encode("utf-8")).root_node.has_error


def extract_javascript(text):
    parser = _js_parser()
    if parser:
        tree = parser.parse(text.encode("utf-8"))
        if not tree.root_node.has_error or tree.root_node.child_count:
            return _extract_js_ts(text, tree)
    return _extract_js_fallback(text)


def _txt(src, node):
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _js_name(src, fn):
    p = fn.parent
    if fn.type in ("function_declaration", "generator_function_declaration", "method_definition"):
        n = fn.child_by_field_name("name")
        if n:
            return _txt(src, n)
    if fn.type in ("function_expression", "function") and fn.child_by_field_name("name"):
        return _txt(src, fn.child_by_field_name("name"))
    if p is None:
        return "<anonymous>"
    if p.type == "variable_declarator" and p.child_by_field_name("name"):
        return _txt(src, p.child_by_field_name("name"))
    if p.type == "assignment_expression" and p.child_by_field_name("left"):
        return _txt(src, p.child_by_field_name("left"))[:80]
    if p.type == "pair" and p.child_by_field_name("key"):
        return _txt(src, p.child_by_field_name("key"))
    if p.type == "arguments" and p.parent is not None and p.parent.type == "call_expression":
        callee = _txt(src, p.parent.child_by_field_name("function"))[:60]
        first = next((c for c in p.named_children if c.type in ("string", "template_string")), None)
        return f"{callee} {_txt(src, first)[:60]}" if first is not None else callee
    return "<anonymous>"


def _extract_js_ts(text, tree):
    src = text.encode("utf-8")
    lines = text.splitlines()

    def direct_funcs(node):
        found = []
        for c in node.children:
            if c.type in JS_FN_TYPES:
                found.append(c)
            else:
                found.extend(direct_funcs(c))
        return found

    span = lambda n: n.end_point[0] - n.start_point[0] + 1
    member = lambda n: n.type in ("function_declaration", "generator_function_declaration", "method_definition") or (
        n.parent is not None and n.parent.type in ("variable_declarator", "assignment_expression", "pair"))
    roots = direct_funcs(tree.root_node)
    units = []
    for fn in _select(roots, span, direct_funcs, member):
        node = fn
        # route registration / callback argument: take the whole call statement for context
        p = fn.parent
        if p is not None and p.type == "arguments" and p.parent is not None and p.parent.type == "call_expression" \
                and p.parent.parent is not None and p.parent.parent.type == "expression_statement":
            node = p.parent.parent
        elif p is not None and p.type in ("variable_declarator", "assignment_expression", "pair"):
            node = p.parent if p.parent is not None and p.parent.type in ("lexical_declaration", "variable_declaration", "expression_statement") else p
        code = _dedent("\n".join(lines[node.start_point[0]:node.end_point[0] + 1]))
        units.append(Unit(_js_name(src, fn), fn.start_point[0] + 1, fn.end_point[0] + 1, code, "javascript", "tree-sitter"))
    covered = set()
    for fn in roots:
        node = fn.parent if fn.parent is not None and fn.parent.type in ("variable_declarator", "assignment_expression", "arguments", "pair") else fn
        while node.parent is not None and node.parent.type not in ("program",) and node.type not in ("expression_statement", "lexical_declaration", "variable_declaration"):
            node = node.parent
        covered.update(range(node.start_point[0] + 1, node.end_point[0] + 2))
    units += _module_unit(lines, covered, "javascript")
    return units


_JS_HEAD = re.compile(r"(?:(?:async\s+)?function\s*\*?\s*([\w$]*)\s*\([^)]*\)\s*\{|(?:async\s+)?(?:\([^()]*\)|[\w$]+)\s*=>\s*\{)")


def _extract_js_fallback(text):
    """Regex head + brace matching. Strings, template literals and comments are skipped while counting."""
    units, lines = [], text.splitlines()
    i, n = 0, len(text)
    taken_until = -1
    for m in _JS_HEAD.finditer(text):
        if m.start() < taken_until:
            continue
        depth, j, end = 0, m.end() - 1, None
        while j < n:
            ch = text[j]
            if ch in "'\"`":
                q, j = ch, j + 1
                while j < n and text[j] != q:
                    j += 2 if text[j] == "\\" else 1
            elif text.startswith("//", j):
                j = text.find("\n", j)
                j = n if j < 0 else j
            elif text.startswith("/*", j):
                j = text.find("*/", j + 2)
                j = n if j < 0 else j + 1
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
            j += 1
        if end is None:
            continue
        s_line = text.count("\n", 0, m.start()) + 1
        e_line = text.count("\n", 0, end) + 1
        units.append(Unit(m.group(1) or "<anonymous>", s_line, e_line, _dedent("\n".join(lines[s_line - 1:e_line])), "javascript", "fallback"))
        taken_until = end
    return units
