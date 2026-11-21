"""Authenticated scanning (v5): log in to the target, keep the session, log in again when it expires.

Credentials (username and password) never come from the target or from a scan request. They are read
only from a local credential file (``ML_DAST_AUTH_FILE``) or from the environment
(``ML_DAST_AUTH_<REF>_USERNAME`` / ``_PASSWORD`` / ``_ORIGINS``), and every credential profile is bound
to the origins it may be sent to. Logins go through the scan's GuardedClient (allowlist, same origin),
are never written to raw records, and errors are reported by exception type only (a message can carry
a URL with the credentials in it).

With an AuthConfig the scan also refuses destructive actions (``DESTRUCTIVE``): logout, delete,
password change and database-reset paths and query parameters, links and forms whose text says so, and
the DELETE method. Without one, nothing here is used and scans behave exactly as before.
"""
import json
import os
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

# Whole path segments / words (case-insensitive). Documented in docs/ml-dast-auth-plan.md section 3.
DESTRUCTIVE_WORDS = (
    "logout", "log-out", "log_out", "logoff", "signout", "sign-out", "sign_out",
    "delete", "remove", "destroy", "drop", "purge", "wipe", "erase", "truncate", "deactivate", "unregister",
    "close-account", "change-password", "changepassword", "password", "passwd", "new-password", "forgot",
    "forgotpw", "account-recovery", "reset", "resetdb", "reset-db", "createdb", "initdb", "init-db", "setup",
    "install", "seed",
)
DESTRUCTIVE = re.compile(r"(?:^|[/_.\-?=&\s])(" + "|".join(re.escape(w) for w in DESTRUCTIVE_WORDS) + r")(?=$|[/_.\-?=&\s])", re.I)
# Query/body parameter NAMES that trigger a destructive action (e.g. "/danger?delete=1"). "password" is not
# here: login forms carry it.
PARAM_WORDS = ("logout", "delete", "remove", "destroy", "drop", "purge", "wipe", "reset", "deactivate")
DESTRUCTIVE_PARAM = re.compile(r"^(?:.*[_\-.])?(" + "|".join(PARAM_WORDS) + r")(?:[_\-.].*)?$", re.I)
DESTRUCTIVE_TEXT = re.compile(r"\b(log ?out|sign ?out|log off|delete|remove|reset|change password|deactivate|drop|wipe|destroy)\b", re.I)
CSRF_NAMES = ("csrf_token", "_csrf", "csrfmiddlewaretoken", "authenticity_token", "_token", "csrf")
REF_RE = re.compile(r"^[A-Za-z0-9_]{1,40}$")
DEFAULT_FILE = Path(__file__).resolve().parents[1] / "lab/auth.local.json"


class AuthError(Exception):
    """Login failed or the configuration is invalid. The message never contains credentials."""


def destructive_path(path, query_names=()):
    path = path or "/"
    return bool(DESTRUCTIVE.search(path)) or any(DESTRUCTIVE_PARAM.match(str(n)) for n in query_names)


def destructive_text(text):
    return bool(text and DESTRUCTIVE_TEXT.search(" ".join(text.split())))


@dataclass(frozen=True)
class Credentials:
    username: str = field(repr=False)
    password: str = field(repr=False)
    origins: tuple = ()

    def __repr__(self):
        return f"Credentials(origins={self.origins!r}, username=***, password=***)"


def _norm_origin(url):
    p = urlsplit(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    return f"{p.scheme}://{(p.hostname or '').lower()}:{port}"


def load_credentials(ref, target, path=None, environ=None):
    """Resolve a credential profile from the environment or the local file; refuse it for any origin it is not bound to."""
    if not isinstance(ref, str) or not REF_RE.match(ref):
        raise AuthError("credentialRef must match ^[A-Za-z0-9_]{1,40}$")
    env = os.environ if environ is None else environ
    key = ref.upper()
    user, pw = env.get(f"ML_DAST_AUTH_{key}_USERNAME"), env.get(f"ML_DAST_AUTH_{key}_PASSWORD")
    if user is not None and pw is not None:
        origins = tuple(o.strip() for o in env.get(f"ML_DAST_AUTH_{key}_ORIGINS", "").split(",") if o.strip())
    else:
        file = Path(path or env.get("ML_DAST_AUTH_FILE") or DEFAULT_FILE)
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
            entry = data[ref]
            user, pw, origins = entry["username"], entry["password"], tuple(entry.get("origins", ()))
        except FileNotFoundError:
            raise AuthError(f"no credentials for {ref!r}: set ML_DAST_AUTH_{key}_USERNAME/_PASSWORD or ML_DAST_AUTH_FILE") from None
        except (KeyError, TypeError, ValueError):
            raise AuthError(f"no usable credential profile {ref!r} in the credential file") from None
    if not origins:
        raise AuthError(f"credential profile {ref!r} is not bound to any origin")
    if _norm_origin(target) not in {_norm_origin(o) for o in origins}:
        raise AuthError(f"credential profile {ref!r} is not bound to the scan target's origin")
    return Credentials(str(user), str(pw), origins)


@dataclass
class AuthConfig:
    login_path: str
    credentials: Credentials = field(repr=False)
    method: str = "POST"
    body: str = "form"                      # form | json
    username_field: str = "username"
    password_field: str = "password"
    extra_fields: dict = field(default_factory=dict)
    login_page: str = ""                    # GET first (CSRF token / pre-session cookie)
    csrf_field: str = ""                    # name, or "auto"
    success_cookie: str = ""
    success_text: str = ""
    token_json: str = ""                    # JSON key of a bearer token in the login response
    logged_out_status: tuple = ()
    logged_out_redirect: str = ""           # Location path that means "logged out" (default: login_path)
    logged_out_text: str = ""
    login_redirect: bool = True             # False: a redirect to the login path is NOT an expiry sign (login at "/")
    max_relogins: int = 20

    def __post_init__(self):
        for name in ("login_path", "login_page", "logged_out_redirect"):
            v = getattr(self, name)
            if v and (not v.startswith("/") or v.startswith("//") or "://" in v or len(v) > 500):
                raise AuthError(f"{name} must be a same-origin path starting with '/'")
        self.method = self.method.upper()
        if self.method not in ("POST", "GET"):
            raise AuthError("method must be POST or GET")
        if self.body not in ("form", "json"):
            raise AuthError("body must be form or json")
        if len(self.extra_fields) > 10 or not all(isinstance(k, str) and isinstance(v, str) for k, v in self.extra_fields.items()):
            raise AuthError("extra_fields: at most 10 string fields")
        if not (self.success_cookie or self.success_text or self.token_json):
            raise AuthError("a success indicator (cookie, text or tokenJson) is required")
        if self.max_relogins < 0 or self.max_relogins > 200:
            raise AuthError("max_relogins must be 0-200")
        self.logged_out_status = tuple(int(s) for s in self.logged_out_status)
        if destructive_path(self.login_path):
            raise AuthError("login_path matches the destructive-action list")

    def __repr__(self):  # never show credentials
        return f"AuthConfig(login_path={self.login_path!r}, method={self.method!r}, body={self.body!r})"

    @classmethod
    def from_spec(cls, spec, target, credential_file=None, environ=None):
        """Build from the camelCase /scan (or lab) spec; credentials are resolved by credentialRef."""
        creds = load_credentials(spec.get("credentialRef"), target, credential_file, environ)
        success = spec.get("success") or {}
        out = spec.get("loggedOut") or {}
        return cls(login_path=spec["loginPath"], credentials=creds, method=spec.get("method", "POST"),
                   body=spec.get("body", "form"), username_field=spec.get("usernameField", "username"),
                   password_field=spec.get("passwordField", "password"), extra_fields=dict(spec.get("extraFields") or {}),
                   login_page=spec.get("loginPagePath", ""), csrf_field=spec.get("csrfField", ""),
                   success_cookie=success.get("cookie", ""), success_text=success.get("text", ""),
                   token_json=success.get("tokenJson", ""), logged_out_status=tuple(out.get("status", ())),
                   logged_out_redirect=out.get("redirectTo", ""), logged_out_text=out.get("text", ""),
                   login_redirect=bool(out.get("loginRedirect", True)), max_relogins=int(spec.get("maxRelogins", 20)))


class _FormInputs(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.inputs = []

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            a = dict(attrs)
            if a.get("name"):
                self.inputs.append((a["name"], a.get("value") or ""))


class AuthSession:
    """Attached to a GuardedClient (``client.auth``). The client calls :meth:`expired` on every final
    response and, if it says so, :meth:`login` and one resend."""

    def __init__(self, config: AuthConfig):
        self.config = config
        self.logins = 0
        self.relogins = 0
        self.in_login = False
        self.suspended = False  # True: no re-login (the passive pass deliberately runs without cookies)
        self.landing = ""  # path of the page the first successful login landed on
        self.last_response = None
        self.events = []  # ("login", ok) / ("relogin", path): no credentials, no bodies

    def _csrf(self, client):
        c = self.config
        page = c.login_page or (c.login_path if c.csrf_field else "")
        if not page:
            return {}
        resp, _ = client.request("GET", page)
        if not c.csrf_field:
            return {}
        parser = _FormInputs()
        try:
            parser.feed(resp.text[:500_000])
        except Exception:  # noqa: BLE001
            pass
        names = CSRF_NAMES if c.csrf_field == "auto" else (c.csrf_field,)
        for name, value in parser.inputs:
            if name in names:
                return {name: value}
        raise AuthError("login form CSRF token not found")

    def login(self, client):
        c = self.config
        self.in_login = True
        try:
            fields = {**self._csrf(client), **c.extra_fields,
                      c.username_field: c.credentials.username, c.password_field: c.credentials.password}
            if c.method == "GET":
                kw = {"params": fields}
            else:
                kw = {"json": fields} if c.body == "json" else {"data": fields}
            resp, _ = client.request(c.method, c.login_path, **kw)
            self.last_response = resp  # the collector's passive pass keeps its HEADERS only
            ok = self._succeeded(client, resp)
        except AuthError:
            self.events.append(("login", False))
            raise
        except Exception as exc:  # noqa: BLE001 - type only: a message could carry the credentials
            self.events.append(("login", False))
            raise AuthError(f"login request failed ({type(exc).__name__})") from None
        finally:
            self.in_login = False
        self.events.append(("login", ok))
        if not ok:
            raise AuthError("login failed: the success indicator was not found")
        self.logins += 1
        if not self.landing:
            # the page the login lands on (after same-origin redirects) is crawled as an extra start page
            landing = urlsplit(resp.url)
            path = (landing.path or "/") + ("?" + landing.query if landing.query and c.method != "GET" else "")
            self.landing = path if path != c.login_path else ""
        return True

    def _succeeded(self, client, resp):
        c = self.config
        if c.token_json:
            try:
                token = resp.json().get(c.token_json)
            except ValueError:
                token = None
            if not isinstance(token, str) or not token or len(token) > 8192:
                return False
            client.session.headers["Authorization"] = f"Bearer {token}"
            return True
        if c.success_cookie:
            return c.success_cookie in client.session.cookies.keys()
        if c.success_text:
            bodies = [resp.text[:500_000]]
            return any(c.success_text in b for b in bodies)
        return False

    def is_login_request(self, path):
        """Requests to the login path or login page are never checked for expiry: a failed login
        (e.g. a probe payload sent to the login form) redirects to the login page by design."""
        return path in {self.config.login_path, self.config.login_page} - {""}

    def expired(self, resp):
        """True if this final response (or its redirect chain) shows the session is gone."""
        c = self.config
        if c.logged_out_status and resp.status_code in c.logged_out_status:
            return True
        target = c.logged_out_redirect or (c.login_path if c.login_redirect else "")
        for hop in list(getattr(resp, "cs_hops", [])) + [resp]:
            loc = hop.headers.get("location", "")
            if target and loc and urlsplit(loc).path == target and hop.status_code in (301, 302, 303, 307, 308):
                return True
        if c.logged_out_text and c.logged_out_text in resp.text[:500_000]:
            return True
        return False

    def can_relogin(self):
        return self.relogins < self.config.max_relogins
