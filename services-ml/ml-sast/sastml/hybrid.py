"""v2 hybrid: RF+LightGBM probability ensemble (ML) + rule-based secrets detector for CWE-798.

Per unit:
1. ML: ``p = w * rf.predict_proba + (1 - w) * lgbm.predict_proba``.
2. ML candidates: every vulnerable class c with ``p[c] >= thresholds[c]``. With
   ``secrets_mode="rules"`` the ML's own CWE-798 output is ignored.
3. Rules (``secrets_mode`` in {"rules", "union"}): if ``sastml.secrets`` fires, CWE-798 is added with the
   rule confidence, marked ``detector="rule-based"``.
The service reports every candidate (several findings per unit are possible). Single-label metrics use
the candidate with the highest confidence, or ``safe`` if there is none.
"""
import numpy as np

from . import CLASSES
from .secrets import unit_confidence

SECRET = CLASSES.index("CWE-798")


class HybridModel:
    def __init__(self, rf, lgbm, weight=0.5, thresholds=None, secrets_mode="rules", info=None):
        self.rf, self.lgbm, self.weight = rf, lgbm, float(weight)
        self.thresholds = dict(thresholds or {c: 0.5 for c in CLASSES[1:]})
        self.secrets_mode = secrets_mode
        self.info = dict(info or {})
        self.classes = list(CLASSES)

    def predict_proba(self, codes, langs):
        p = np.zeros((len(codes), len(CLASSES)), dtype=np.float32)
        if self.weight > 0:
            p += self.weight * self.rf.predict_proba(codes, langs)
        if self.weight < 1:
            p += (1 - self.weight) * self.lgbm.predict_proba(codes, langs)
        return p

    def candidates(self, codes, langs, proba=None):
        """List per unit of (class_index, confidence, detector) sorted by confidence."""
        proba = self.predict_proba(codes, langs) if proba is None else proba
        out = []
        for code, p in zip(codes, proba):
            cands = {}
            for i, c in enumerate(CLASSES[1:], start=1):
                if i == SECRET and self.secrets_mode == "rules":
                    continue
                if p[i] >= self.thresholds[c]:
                    cands[i] = (float(p[i]), "ml")
            if self.secrets_mode in ("rules", "union"):
                conf, hits = unit_confidence(code)
                if hits and conf >= cands.get(SECRET, (0, ""))[0]:
                    cands[SECRET] = (conf, "rule-based")
            out.append(sorted(((i, c, d) for i, (c, d) in cands.items()), key=lambda x: -x[1]))
        return out

    def decide(self, codes, langs, proba=None):
        return np.array([c[0][0] if c else 0 for c in self.candidates(codes, langs, proba)])
