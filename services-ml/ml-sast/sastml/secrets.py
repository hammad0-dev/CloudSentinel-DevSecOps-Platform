"""Rule-based hardcoded-secret detector (CWE-798). NOT machine learning.

Part of the v2 hybrid: the ML model handles the other classes. CWE-798 findings can come from these
rules, which are reported as ``detector: rule-based`` everywhere (findings, /model-info, reports).

Rules (each hit has a fixed confidence):
* ``known-format`` (0.95): provider key formats (AWS AKIA/ASIA, Stripe sk_/rk_, GitHub ghp_/gho_/ghs_/
  github_pat_, Slack xox*, Google AIza, GitLab glpat-, private-key PEM blocks, literal JWTs).
* ``secret-assignment`` (0.85): a secret-like name assigned a string literal, in Python or JS:
  ``SECRET_KEY = '...'``, ``app.config['SECRET_KEY'] = '...'``, ``{password: '...'}``, ``"api_key": "..."``,
  ``app.secret_key = b'...'``.
* ``env-fallback`` (0.85): a secret-like env var with a literal default, e.g.
  ``process.env.JWT_SECRET || "..."`` or ``os.getenv("SECRET", "...")``.
* ``credential-call`` (0.85): a literal secret passed to a signing/crypto/session/DB call:
  ``jwt.sign(x, '...')``, ``jwt.encode(x, '...')``, ``Fernet('...')``, ``session({secret: '...'})``,
  ``connect(..., password='...')``.
* ``url-credentials`` (0.8): ``scheme://user:password@host`` with a non-trivial password.

Values that are clearly not secrets are skipped: empty or very short strings, sentences, template
placeholders (``{{x}}``, ``${x}``, ``%s``), env/config lookups, file paths to key files, and names that
describe a secret without holding one (``password_hash``, ``token_url``, ``PASSWORD_HASHERS``...).
"""
import re
from dataclasses import dataclass

NAME = r"(?:[\w$.]*?(?:secret|passw(?:or)?d|pwd|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|bearer|private[_-]?key|client[_-]?secret|signing[_-]?key|crypto[_-]?key|encryption[_-]?key|session[_-]?key|token)[\w$]*)"
NOT_A_SECRET_NAME = re.compile(r"(?i)(hash(er)?s?|_?field|_?url|_?uri|_?path|_?file|_?name|_?type|_?length|_?len|_?min|_?max|_?re|regex|pattern|label|placeholder|prompt|message|msg|header|expir\w*|ttl|_?id|policy|validator|reset|confirm|_?count|_?prefix)$")
STR = r"""(?P<q>['"`])(?P<val>(?:\\.|(?!(?P=q)).){0,300})(?P=q)"""
KNOWN = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,}|\bgh[pousr]_[0-9A-Za-z]{30,}|\bgithub_pat_[0-9A-Za-z_]{30,}|\bxox[abprs]-[0-9A-Za-z-]{10,}|\bAIza[0-9A-Za-z_-]{30,}|\bglpat-[0-9A-Za-z_-]{20,}|-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----|\beyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}")
ASSIGN = re.compile(r"(?i)(?P<name>" + NAME + r")['\"`\]]?\s*(?::|=(?!=)|\]\s*=)\s*b?" + STR)
SUBSCRIPT = re.compile(r"""(?i)\[\s*['"](?P<name>""" + NAME + r""")['"]\s*\]\s*=\s*b?""" + STR)
ENV_FALLBACK = re.compile(r"(?i)(?:process\.env\.(?P<n1>" + NAME + r")\s*(?:\|\||\?\?)\s*" + STR.replace("q>", "q1>").replace("val>", "v1>").replace("(?P=q)", "(?P=q1)") +
                          r"|(?:os\.getenv|os\.environ\.get|environ\.get|config\.get)\(\s*['\"](?P<n2>" + NAME + r")['\"]\s*,\s*b?" + STR.replace("q>", "q2>").replace("val>", "v2>").replace("(?P=q)", "(?P=q2)") + r")")
CALLS = re.compile(r"(?i)(?:jwt\.(?:sign|encode)\s*\([^;\n]*?,\s*|Fernet\(\s*b?|createHmac\(\s*['\"]\w+['\"]\s*,\s*|hmac\.new\(\s*b?|session\(\s*\{[^}]*?secret\s*:\s*|\bsecret\s*:\s*|(?:connect|createConnection|createPool|Pool|Sequelize|MongoClient)\([^)]*?password\s*[=:]\s*)b?" + STR)
URL_CREDS = re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@'\"`]{1,64}:(?P<pw>[^\s@/'\"`]{4,128})@[\w.-]+")


@dataclass
class SecretHit:
    line: int        # 1-based, relative to the unit code
    rule: str
    confidence: float
    name: str


def _plausible(value, name=""):
    v = value.strip()
    if len(v) < 6 or len(v) > 300:
        return False
    if re.search(r"\{\{|\$\{|%s|%\(|<%|\{\w*\}", v):
        return False
    if len(v.split()) > 2:            # sentences / messages ("Invalid password")
        return False
    if re.fullmatch(r"[\w./\\-]+\.(pem|key|crt|p12|pfx|json|txt|env)", v, re.I) or v.startswith(("/", "./", "~/")):
        return False
    if v.lower() in {"password", "secret", "token", "apikey", "api_key", "undefined", "null", "none", "string", "bearer"}:
        return False
    if name and v.lower() == name.lower().split(".")[-1]:
        return False
    if re.fullmatch(r"(?i)(env|process\.env|os\.environ)\b.*", v):
        return False
    return True


def _name_ok(name):
    tail = name.split(".")[-1]
    return not NOT_A_SECRET_NAME.search(tail)


def scan(code):
    """Return SecretHit list for a unit's code (line numbers relative to the code)."""
    hits = []

    def add(m, rule, conf, name=""):
        hits.append(SecretHit(code.count("\n", 0, m.start()) + 1, rule, conf, name))

    for m in KNOWN.finditer(code):
        add(m, "known-format", 0.95)
    for rx, rule in ((ASSIGN, "secret-assignment"), (SUBSCRIPT, "secret-assignment")):
        for m in rx.finditer(code):
            name, val = m.group("name"), m.group("val")
            if _name_ok(name) and _plausible(val, name):
                add(m, rule, 0.85, name)
    for m in ENV_FALLBACK.finditer(code):
        name = m.group("n1") or m.group("n2")
        val = m.group("v1") if m.group("v1") is not None else m.group("v2")
        if _name_ok(name) and _plausible(val, name):
            add(m, "env-fallback", 0.85, name)
    for m in CALLS.finditer(code):
        if _plausible(m.group("val")):
            add(m, "credential-call", 0.85)
    for m in URL_CREDS.finditer(code):
        if _plausible(m.group("pw")) and m.group("pw").lower() not in {"password", "pass"}:
            add(m, "url-credentials", 0.8)
    seen, out = set(), []
    for h in sorted(hits, key=lambda h: (h.line, -h.confidence)):
        if h.line not in seen:
            seen.add(h.line)
            out.append(h)
    return out


def unit_confidence(code):
    hits = scan(code)
    return (max(h.confidence for h in hits), hits) if hits else (0.0, [])
