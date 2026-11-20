"""Features for function-level SAST classification.

1. ``normalize_tokens``: a code token stream for TF-IDF. API names (called functions, attributes,
   modules) and security-relevant words are kept; local identifiers become ``ID``; numbers become
   ``NUM``; string literals become a category token (``STR_SQL``, ``STR_HTML``, ``STR_CMD``, ``STR_PATH``,
   ``STR_SECRET``, ``STR``) and interpolation is marked (``FSTR``, ``TPL_INTERP``). Renaming variables
   therefore does not change the features, and the model cannot memorize names.
2. ``hand_features``: counts of dangerous sinks, user-input sources, sanitizers and risky combinations
   (SQL/command strings built by concatenation or formatting, secrets in literals, weak hashes, pickle,
   yaml.load, ...). Kept small and readable so findings can be explained.
"""
import math
import re

import numpy as np

KEEP_WORDS = {
    # input sources / web objects
    "request", "req", "res", "args", "form", "values", "json", "cookies", "headers", "query", "body", "params", "files",
    "GET", "POST", "argv", "input", "environ", "env", "getenv", "process", "session", "user",
    # security vocabulary
    "password", "passwd", "pwd", "secret", "token", "key", "apikey", "api_key", "apiKey", "credentials", "auth",
    "salt", "hash", "cipher", "iv", "nonce", "admin", "root", "SECRET_KEY",
    # keywords that shape data flow
    "return", "if", "else", "for", "while", "try", "except", "catch", "with", "def", "function", "async", "await",
    "const", "let", "var", "new", "import", "from", "require", "lambda", "class", "self", "this", "True", "False",
    "None", "null", "undefined", "true", "false", "in", "not", "and", "or", "raise", "throw", "shell",
}
STRING_RE = r"(?P<str>[rRbBuUfF]{0,2}(?:'''[\s\S]*?'''|\"\"\"[\s\S]*?\"\"\"|'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\")|`(?:\\.|[^`\\])*`)"
TOKEN_RE = re.compile(STRING_RE + r"|(?P<com>#[^\n]*|//[^\n]*|/\*[\s\S]*?\*/)|(?P<num>\b\d[\d_.xXa-fA-F]*\b)|(?P<id>[A-Za-z_$][\w$]*)|(?P<op>==|!=|<=|>=|=>|\+=|\*\*|&&|\|\||[+\-*/%=<>!&|^~?:.,;()\[\]{}@])")

SQL_RE = re.compile(r"\b(select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from|where\s+\w+\s*(=|like|in)|order\s+by|union\s+select|drop\s+table|create\s+table)\b", re.I | re.S)
HTML_RE = re.compile(r"<\s*/?\s*(h\d|p|div|span|li|ul|b|i|a|script|html|body|img|td|tr|table|pre|code|form|input)\b", re.I)
CMD_RE = re.compile(r"^\s*(ping|nslookup|whois|host|traceroute|ls|cat|grep|tar|zip|unzip|git|curl|wget|convert|ffmpeg|rm|cp|mv|sh|bash|cmd|powershell|echo|find|chmod)\b(\s|$)")
PATH_RE = re.compile(r"(^\.{0,2}/|^/[\w.-]+|uploads?/|files?/|static/|/tmp/|\\\\|\.\./|\.(txt|pdf|csv|log|json|ya?ml|png|jpg)$)", re.I)
SECRET_PREFIX_RE = re.compile(r"^(AKIA[0-9A-Z]{12,}|sk_(live|test)_|ghp_|xox[bp]-|AIza|-----BEGIN)")


def _entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def string_category(lit):
    m = re.match(r"([rRbBuUfF]{0,2})('''|\"\"\"|'|\"|`)", lit)
    prefix, q = (m.group(1), m.group(2)) if m else ("", "")
    inner = lit[len(prefix) + len(q):len(lit) - len(q)] if q else lit
    toks = []
    if "f" in prefix.lower() and "{" in inner:
        toks.append("FSTR")
    if q == "`" and "${" in inner:
        toks.append("TPL_INTERP")
    if SQL_RE.search(inner):
        cat = "STR_SQL"
    elif HTML_RE.search(inner):
        cat = "STR_HTML"
    elif CMD_RE.search(inner):
        cat = "STR_CMD"
    elif SECRET_PREFIX_RE.search(inner) or (len(inner) >= 8 and " " not in inner and _entropy(inner) >= 3.3 and re.search(r"\d", inner) and re.search(r"[A-Za-z]", inner)):
        cat = "STR_SECRET"
    elif PATH_RE.search(inner):
        cat = "STR_PATH"
    elif inner.lower() in ("md5", "sha1", "des", "rc4", "des-ede3", "aes-128-ecb", "aes-256-ecb", "aes-128-cbc", "rc4-md5"):
        cat = "STR_WEAKALG"
    elif inner == "":
        cat = "STR_EMPTY"
    else:
        cat = "STR"
    return [cat] + toks


def normalize_tokens(code):
    out = []
    prev = ""
    for m in TOKEN_RE.finditer(code):
        kind = m.lastgroup
        t = m.group(kind)
        if kind == "com":
            continue
        if kind == "str":
            out.extend(string_category(t))
        elif kind == "num":
            out.append("NUM")
        elif kind == "id":
            nxt = code[m.end():m.end() + 1]
            if prev in ("def", "function", "class") and t not in KEEP_WORDS:
                out.append("ID")  # the unit's own name is not a signal (and is randomized in synthetic data)
            elif t in KEEP_WORDS or prev == "." or nxt == "(" or nxt == "." or t[:1].isupper():
                out.append(t)
            else:
                out.append("ID")
        else:
            out.append(t)
        prev = t
    return out


def token_string(code):
    return " ".join(normalize_tokens(code))


# ---------------------------------------------------------------- hand features ---

_SRC_PY = r"request\.(args|form|values|json|get_json|cookies|files|data|GET|POST|headers|query_params|body)|sys\.argv|\binput\("
_SRC_JS = r"\breq\.(query|body|params|cookies|headers|files)|location\.(search|hash)|document\.cookie|process\.argv"
_SQL_EXEC = r"\.(execute|executescript|executemany|raw|query|exec)\s*\(|\bknex\.raw\(|\bsequelize\.query\(|\btext\("
_CMD = r"\bos\.(system|popen|exec\w*|spawn\w*)\(|subprocess\.\w+\(|commands\.getoutput|\bgetoutput\(|\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\(|child_process|\bcp\.exec"
_FILE = r"\bopen\(|send_file\(|send_from_directory\(|\bfs\.\w+\(|sendFile\(|\.download\(|createReadStream|unlink|Path\(|os\.path\.join|path\.join\(|readFile"
_DESER = r"pickle\.loads?\(|cPickle|dill\.loads|marshal\.loads|jsonpickle\.decode|shelve\.open|yaml\.(load|unsafe_load|full_load)\(|torch\.load|unserialize\(|deepDeserialize|cryo\.parse|serializeJs|v8\.deserialize"
_DESER_SAFE = r"yaml\.safe_load|SafeLoader|JSON_SCHEMA|safeLoad|json\.loads?\(|JSON\.parse\(|literal_eval"
_WEAK = r"\bmd5\b|\bsha1\b|hashlib\.new\(\s*['\"](md5|sha1)|\bDES\b|DES3|ARC4|\brc4\b|Blowfish|MODE_ECB|-ecb['\"]|createCipher\(|random\.random\(|random\.randint\(|random\.choices?\(|getrandbits|Math\.random\("
_STRONG = r"bcrypt|scrypt|argon2|pbkdf2|sha256|sha512|MODE_GCM|aes-256-gcm|secrets\.|randomBytes|randomUUID|os\.urandom"
_XSS_SINK = r"render_template_string|Markup\(|mark_safe|\|safe|HttpResponse\(|make_response\(|Response\(|res\.(send|write|end)\(|innerHTML|outerHTML|document\.write|\.html\(|insertAdjacentHTML"
_XSS_SAFE = r"escape\(|escapeHtml|he\.encode|DOMPurify|textContent|innerText|\.text\(|render_template\(|res\.render\(|res\.json\(|encodeURIComponent|bleach"
_PATH_SAFE = r"secure_filename|basename|realpath|abspath|startswith|startsWith|path\.resolve|normpath|send_from_directory|root:"
_SQL_SAFE = r"%s['\"]\s*,|\?\s*['\"]?\s*,\s*[\[(]|\$\d|:\w+['\"]\s*,|replacements|\.filter\(|findAll\(|findOne\(|where\(\{|\.where\("
_CMD_SAFE = r"shlex\.quote|shell\s*=\s*False|execFile|\[\s*['\"][\w./-]+['\"]\s*,"
_SECRET_NAME = r"(?i)(password|passwd|pwd|secret|token|api_?key|apikey|access_?key|private_?key|client_?secret|cookie_?secret|crypto_?key)\w*['\"]?\s*[:=]\s*[\"'`]([^\"'`\s]{4,})[\"'`]"
_ENV = r"os\.environ|os\.getenv|process\.env|config\.get|settings\.|current_app\.config|getSecret|keyring|vault"
_CONCAT_SQL = r"(?i)[\"'`][^\"'`]*\b(select|insert|update|delete|where|order by|from)\b[^\"'`]*[\"'`]\s*(\+|%)|\b(select|insert|update|delete)\b[^\"'`]*(\{|\$\{)|\b(select|insert|update|delete|where)\b[^\"'`]*[\"']\s*\.format\("
_CONCAT_CMD = r"[\"'`](ping|nslookup|whois|host|ls|cat|grep|tar|zip|unzip|git|curl|wget|convert|ffmpeg|rm|sh -c|bash -c)\b[^\"'`]*[\"'`]\s*(\+|%)|[\"'`](ping|nslookup|ls|cat|grep|tar|git|curl|unzip|convert)\b[^\"'`]*(\{|\$\{)"
_CONCAT_HTML = r"[\"'`][^\"'`]*<\s*/?\s*\w+[^\"'`]*[\"'`]\s*(\+|%)|[\"'`][^\"'`]*<\w+[^\"'`]*(\{|\$\{)"

FEATURES = [
    ("src_py", _SRC_PY), ("src_js", _SRC_JS), ("sql_exec", _SQL_EXEC), ("sql_concat", _CONCAT_SQL), ("sql_safe", _SQL_SAFE),
    ("cmd_sink", _CMD), ("cmd_concat", _CONCAT_CMD), ("shell_true", r"shell\s*[=:]\s*(True|true)|['\"](sh|bash)['\"]\s*,\s*\[\s*['\"]-c"), ("cmd_safe", _CMD_SAFE),
    ("file_sink", _FILE), ("path_safe", _PATH_SAFE), ("path_traversal_str", r"\.\./"),
    ("xss_sink", _XSS_SINK), ("html_concat", _CONCAT_HTML), ("xss_safe", _XSS_SAFE),
    ("secret_literal", _SECRET_NAME), ("secret_prefix", r"AKIA[0-9A-Z]{12,}|sk_(live|test)_\w+|ghp_\w{20,}|-----BEGIN [A-Z ]*PRIVATE KEY"), ("env_lookup", _ENV),
    ("conn_password_literal", r"(?i)password\s*[=:]\s*['\"][^'\"]{3,}['\"]"), ("jwt_literal", r"jwt\.(sign|encode)\([^)]*,\s*['\"][^'\"]{4,}['\"]"),
    ("deser_sink", _DESER), ("deser_safe", _DESER_SAFE), ("eval_exec", r"\beval\(|\bexec\(|new Function\(|vm\.run"),
    ("weak_crypto", _WEAK), ("strong_crypto", _STRONG),
    ("fstring_or_template", r"\bf[\"']|`[^`]*\$\{"), ("format_call", r"\.format\(|%\s*\(|%\s*\w"), ("string_plus", r"[\"'`]\s*\+|\+\s*[\"'`]"),
    ("route_decorator", r"@\w+\.route\(|\b(app|router)\.(get|post|put|delete|all|use)\("),
]
_COMPILED = [(n, re.compile(p)) for n, p in FEATURES]
FEATURE_NAMES = [n for n, _ in FEATURES] + ["n_lines", "n_tokens"]


def hand_features(code):
    v = [len(rx.findall(code)) for _, rx in _COMPILED]
    v += [code.count("\n") + 1, len(code.split())]
    return v


def hand_matrix(codes):
    return np.log1p(np.array([hand_features(c) for c in codes], dtype=np.float32))


def explain(code, top=4):
    """Names of the hand features that fired, for finding messages."""
    return [n for (n, rx) in _COMPILED if rx.search(code)][:top]
