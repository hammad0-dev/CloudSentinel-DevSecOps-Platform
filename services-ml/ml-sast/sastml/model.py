"""Classical models over TF-IDF code tokens + hand-made security features.

``SastModel`` is the object saved with joblib and loaded by the ml-sast service. It owns the
featurizer so the service and the evaluation run exactly the same pipeline.
"""
import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

from . import CLASSES
from .features import FEATURE_NAMES, hand_matrix, token_string


class Featurizer:
    def __init__(self, max_features=40000, ngram_range=(1, 3), min_df=2):
        self.tfidf = TfidfVectorizer(token_pattern=r"\S+", lowercase=False, ngram_range=tuple(ngram_range), min_df=min_df,
                                     max_features=max_features, sublinear_tf=True)
        self.scaler = StandardScaler(with_mean=False)

    def _langs(self, langs):
        return sparse.csr_matrix(np.array([[l == "python", l == "javascript"] for l in langs], dtype=np.float32))

    def fit_transform(self, codes, langs):
        toks = [token_string(c) for c in codes]
        t = self.tfidf.fit_transform(toks)
        h = self.scaler.fit_transform(hand_matrix(codes))
        return sparse.hstack([t, sparse.csr_matrix(h), self._langs(langs)]).tocsr()

    def transform(self, codes, langs):
        toks = [token_string(c) for c in codes]
        t = self.tfidf.transform(toks)
        h = self.scaler.transform(hand_matrix(codes))
        return sparse.hstack([t, sparse.csr_matrix(h), self._langs(langs)]).tocsr()

    def feature_names(self):
        return list(self.tfidf.get_feature_names_out()) + [f"hand:{n}" for n in FEATURE_NAMES] + ["lang:python", "lang:javascript"]


class SastModel:
    """kind: 'lr' | 'rf' | 'lgbm'. predict_proba returns columns in CLASSES order."""

    def __init__(self, kind, params=None, featurizer_params=None):
        self.kind, self.params = kind, dict(params or {})
        self.featurizer = Featurizer(**(featurizer_params or {}))
        self.classes = list(CLASSES)
        self.estimator = None
        self.info = {}

    def _make(self, y):
        counts = np.bincount(y, minlength=len(self.classes)).astype(float)
        weights = {i: len(y) / (len(self.classes) * c) for i, c in enumerate(counts) if c > 0}
        if self.kind == "lr":
            from sklearn.linear_model import LogisticRegression
            return LogisticRegression(max_iter=4000, class_weight=weights, C=self.params.get("C", 3.0), solver="saga")
        if self.kind == "rf":
            from sklearn.ensemble import RandomForestClassifier
            return RandomForestClassifier(n_estimators=self.params.get("n_estimators", 400), max_depth=self.params.get("max_depth"),
                                          min_samples_leaf=self.params.get("min_samples_leaf", 1), max_features=self.params.get("max_features", "sqrt"),
                                          class_weight="balanced_subsample", n_jobs=-1, random_state=0)
        if self.kind == "lgbm":
            import lightgbm as lgb
            return lgb.LGBMClassifier(objective="multiclass", n_estimators=self.params.get("n_estimators", 400), learning_rate=self.params.get("learning_rate", 0.05),
                                      num_leaves=self.params.get("num_leaves", 31), min_child_samples=self.params.get("min_child_samples", 10),
                                      colsample_bytree=self.params.get("colsample_bytree", 0.3), subsample=0.8, subsample_freq=1, max_bin=63,
                                      class_weight=weights, n_jobs=-1, random_state=0, verbose=-1)
        raise ValueError(self.kind)

    def fit(self, codes, langs, labels):
        y = np.array([self.classes.index(l) for l in labels])
        X = self.featurizer.fit_transform(codes, langs)
        self.estimator = self._make(y)
        self.estimator.fit(X.astype(np.float32), y)
        return self

    def predict_proba(self, codes, langs):
        X = self.featurizer.transform(codes, langs).astype(np.float32)
        p = self.estimator.predict_proba(X)
        out = np.zeros((len(codes), len(self.classes)), dtype=np.float32)
        out[:, list(self.estimator.classes_)] = p
        return out
