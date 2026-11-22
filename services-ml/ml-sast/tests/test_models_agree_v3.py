"""v3 response format: ensemble findings carry models_agree (and name the models in the message); v2-style
models (3-tuple candidates) produce exactly the old response, with no models_agree key at all."""
import numpy as np
from fastapi.testclient import TestClient

import app as service
from sastml import CLASSES

CODE = "def view(request):\n    q = request.GET['q']\n    cursor.execute('SELECT * FROM t WHERE a = ' + q)\n"


class V2Like:
    info = {}

    def predict_proba(self, codes, langs):
        return np.zeros((len(codes), len(CLASSES)))

    def candidates(self, codes, langs):
        return [[(CLASSES.index("CWE-89"), 0.9, "ml")] for _ in codes]


class V3Like(V2Like):
    def candidates(self, codes, langs):
        return [[(CLASSES.index("CWE-89"), 0.66, "ml", ["rf", "lgbm"])] for _ in codes]


def scan(monkeypatch, model):
    monkeypatch.setattr(service, "MODEL", model)
    r = TestClient(service.app).post("/scan", json={"files": [{"path": "app/views.py", "content": CODE}]})
    assert r.status_code == 200, r.text
    return r.json()["findings"]


def test_v2_like_response_has_no_models_agree(monkeypatch):
    f = scan(monkeypatch, V2Like())
    assert f and "models_agree" not in f[0]
    assert set(f[0]) == {"rule", "cwe_id", "severity", "message", "file_path", "line_number", "confidence"}


def test_v3_findings_carry_models_agree(monkeypatch):
    f = scan(monkeypatch, V3Like())
    assert f[0]["models_agree"] == ["rf", "lgbm"]
    assert "flagged by 2 of 3 models: rf, lgbm" in f[0]["message"]
