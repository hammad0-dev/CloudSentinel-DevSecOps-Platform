"""Classifier wrapper: LR / RF / LightGBM over the response features, class-weighted."""
import numpy as np

from . import CLASSES

GRIDS = {
    "lr": [{"C": 0.1}, {"C": 1.0}, {"C": 10.0}],
    "rf": [{"n_estimators": 300, "max_depth": 6, "min_samples_leaf": 3}, {"n_estimators": 300, "max_depth": None, "min_samples_leaf": 5},
           {"n_estimators": 300, "max_depth": None, "min_samples_leaf": 1}],
    "lgbm": [{"n_estimators": 200, "num_leaves": 7, "learning_rate": 0.05}, {"n_estimators": 300, "num_leaves": 15, "learning_rate": 0.05},
             {"n_estimators": 150, "num_leaves": 31, "learning_rate": 0.1}],
}
THRESHOLDS = [round(x, 2) for x in np.arange(0.2, 0.91, 0.05)]
# v3 (F6): every v2 LR fold chose 0.9, the top of the grid, so the grid was a boundary. Fixed before
# any v3 training; still chosen by inner leave-one-app-out only. v1/v2 runs keep THRESHOLDS.
THRESHOLDS_V3 = [round(x, 2) for x in np.arange(0.2, 0.96, 0.05)]


class DastModel:
    def __init__(self, kind, params, seed=0):
        self.kind, self.params, self.seed = kind, dict(params), seed
        self.est = None

    def _make(self):
        if self.kind == "lr":
            from sklearn.linear_model import LogisticRegression
            from sklearn.pipeline import make_pipeline
            from sklearn.preprocessing import StandardScaler
            return make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, class_weight="balanced", random_state=self.seed, **self.params))
        if self.kind == "rf":
            from sklearn.ensemble import RandomForestClassifier
            return RandomForestClassifier(class_weight="balanced_subsample", n_jobs=-1, random_state=self.seed, **self.params)
        if self.kind == "lgbm":
            from lightgbm import LGBMClassifier
            return LGBMClassifier(class_weight="balanced", random_state=self.seed, verbose=-1, n_jobs=4, **self.params)
        raise ValueError(self.kind)

    def fit(self, X, y):
        self.est = self._make().fit(X, y)
        return self

    def predict_proba(self, X):
        """Probabilities for all CLASSES, even if a class was absent from the training data."""
        p = self.est.predict_proba(X)
        out = np.zeros((len(X), len(CLASSES)), dtype=np.float64)
        for j, c in enumerate(self.est.classes_):
            out[:, int(c)] = p[:, j]
        return out
