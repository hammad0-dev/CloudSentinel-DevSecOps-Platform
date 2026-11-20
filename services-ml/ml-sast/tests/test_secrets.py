import numpy as np

from sastml import CLASSES
from sastml.hybrid import HybridModel
from sastml.secrets import scan, unit_confidence

POSITIVES = [
    ("SECRET_KEY = 'x8#kq2!zz09_ab'", "secret-assignment"),
    ("app.config['SECRET_KEY'] = 'your-secret-key-here'", "secret-assignment"),
    ("app.secret_key = b'k3y-material-123'", "secret-assignment"),
    ("const db = { password: 'hunter2hunter2' };", "secret-assignment"),
    ("jwtSecret: process.env.JWT_SECRET || \"jwt-super-secret\",", "env-fallback"),
    ("key = os.getenv('API_KEY', 'sk-dev-123456')", "env-fallback"),
    ("const t = jwt.sign(user, 'jwt-hardcoded-secret', { expiresIn: '1y' });", "credential-call"),
    ("aws = 'AKIAIOSFODNN7EXAMPLE'", "known-format"),
    ("url = 'postgres://admin:S3cretPw@db.internal/app'", "url-credentials"),
]
NEGATIVES = [
    "password = request.form['password']",
    "SECRET_KEY = os.environ['SECRET_KEY']",
    "const secret = process.env.JWT_SECRET;",
    "PASSWORD_HASHERS = ['django.contrib.auth.hashers.PBKDF2PasswordHasher']",
    "flash('Invalid password, please try again')",
    "token_url = 'https://auth.example.com/token'",
    "key_path = './keys/server.pem'",
    "password = ''",
    "html = '<input type=\"password\" name=\"password\">'",
    "msg = f'token {token_id} expired'",
]


def test_detects_secret_patterns():
    for code, rule in POSITIVES:
        hits = scan(code)
        assert hits, code
        assert rule in {h.rule for h in hits}, (code, [h.rule for h in hits])


def test_ignores_non_secrets():
    for code in NEGATIVES:
        assert scan(code) == [], code


def test_hits_report_unit_relative_lines():
    conf, hits = unit_confidence("def f():\n    x = 1\n    api_key = 'abcd1234efgh'\n    return x\n")
    assert conf == 0.85 and hits[0].line == 3


class Const:
    def __init__(self, cls, p):
        self.cls, self.p = cls, p

    def predict_proba(self, codes, langs):
        out = np.zeros((len(codes), len(CLASSES)), dtype=np.float32)
        out[:, 0] = 1 - self.p
        out[:, CLASSES.index(self.cls)] = self.p
        return out


def test_hybrid_rules_mode_marks_rule_based_secret_and_ignores_ml_798():
    ml = Const("CWE-798", 0.9)
    m = HybridModel(ml, ml, weight=0.5, thresholds={c: 0.5 for c in CLASSES[1:]}, secrets_mode="rules")
    codes = ["SECRET_KEY = 'x8#kq2!zz09_ab'", "x = compute()"]
    cands = m.candidates(codes, ["python", "python"])
    assert cands[0] == [(CLASSES.index("CWE-798"), 0.85, "rule-based")]
    assert cands[1] == [], "ML CWE-798 is ignored in rules mode"
    union = HybridModel(ml, ml, 0.5, {c: 0.5 for c in CLASSES[1:]}, "union").candidates(codes, ["python"] * 2)
    (cls, conf, detector), = union[1]
    assert cls == CLASSES.index("CWE-798") and abs(conf - 0.9) < 1e-6 and detector == "ml"
