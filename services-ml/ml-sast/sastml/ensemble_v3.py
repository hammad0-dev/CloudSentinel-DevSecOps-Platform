"""ml-sast v3 runtime system: every scan runs all three base models, a pre-registered combination rule turns their
per-class decisions into findings, and the rule-based secrets detector reports CWE-798 (v2 'rules' mode).

Base models (reports/v3/selection_preregistration.json): A = RF, B = LightGBM (both SastModel over the v2 features),
C = frozen CodeBERT embeddings + XGBoost. Each has per-class thresholds. Rules:
  R1 per-class routing: class c is decided by the base model routes[c] alone;
  R2 majority: c is flagged iff >= 2 of the 3 models flag it;
  R3 union: c is flagged iff any model flags it; confidence = agreeing models / 3.
candidates() returns, per unit, (class_index, confidence, detector, models_agree) sorted by confidence, like v2's
HybridModel (plus models_agree). The ML models' own CWE-798 output is ignored; the secrets rule reports it.
"""
import numpy as np

from . import CLASSES
from .secrets import unit_confidence

SECRET = CLASSES.index("CWE-798")
NAMES = ("rf", "lgbm", "codebert_xgb")


class EnsembleV3:
    def __init__(self, models, thresholds, rule, routes=None, info=None):
        """models: {name: model with predict_proba(codes, langs)}; thresholds: {name: {class: t}};
        rule: 'R1' | 'R2' | 'R3'; routes (R1): {class: name}."""
        self.models, self.thresholds, self.rule = dict(models), {k: dict(v) for k, v in thresholds.items()}, rule
        self.routes = dict(routes or {})
        self.info = dict(info or {})
        self.classes = list(CLASSES)

    def all_proba(self, codes, langs):
        return {n: np.asarray(self.models[n].predict_proba(codes, langs)) for n in NAMES}

    def predict_proba(self, codes, langs, probas=None):
        """Mean probability of the three models (used only as a fallback score; decisions come from candidates)."""
        probas = probas or self.all_proba(codes, langs)
        return np.mean([probas[n] for n in NAMES], axis=0)

    def flags(self, probas):
        """{name: bool array (n, classes)} of each model's own per-class decisions."""
        out = {}
        for n in NAMES:
            p = probas[n]
            t = np.array([1.1] + [self.thresholds[n][c] for c in CLASSES[1:]])
            out[n] = p >= t
        return out

    def candidates(self, codes, langs, probas=None):
        probas = probas or self.all_proba(codes, langs)
        fl = self.flags(probas)
        res = []
        for i, code in enumerate(codes):
            cands = {}
            for ci, c in enumerate(CLASSES[1:], start=1):
                if ci == SECRET:
                    continue
                agree = [n for n in NAMES if fl[n][i, ci]]
                if self.rule == "R1":
                    owner = self.routes.get(c, NAMES[0])
                    ok = fl[owner][i, ci]
                    agree_used = agree if ok else []
                elif self.rule == "R2":
                    ok = len(agree) >= 2
                    agree_used = agree
                else:
                    ok = bool(agree)
                    agree_used = agree
                if not ok:
                    continue
                mean_p = float(np.mean([probas[n][i, ci] for n in agree_used])) if agree_used else 0.0
                conf = len(agree_used) / 3 if self.rule == "R3" else mean_p
                cands[ci] = (conf, mean_p, "ml", agree_used)
            sconf, hits = unit_confidence(code)
            if hits:
                cands[SECRET] = (sconf, sconf, "rule-based", [])
            ordered = sorted(cands.items(), key=lambda kv: (-kv[1][0], -kv[1][1]))
            res.append([(ci, float(min(1.0, v[0])), v[2], v[3]) for ci, v in ordered])
        return res

    def decide(self, codes, langs, probas=None):
        return np.array([c[0][0] if c else 0 for c in self.candidates(codes, langs, probas)])
