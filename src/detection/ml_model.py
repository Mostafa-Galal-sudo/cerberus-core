import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

META_COLUMNS = ("category", "is_attack", "source_file", "source_folder", "device_id", "window_start")
CLIP = 5.0


def feature_columns(df):
    return [c for c in df.columns if c not in META_COLUMNS and pd.api.types.is_numeric_dtype(df[c])]


def clean(df, columns, fill_values=None, center=None, spread=None):
    x = df[columns].replace([np.inf, -np.inf], np.nan)
    if fill_values is None:
        fill_values = x.median(numeric_only=True).fillna(0.0)
    x = x.fillna(fill_values)
    if center is not None and spread is not None:
        x = (x - center) / spread
        x = x.clip(-CLIP, CLIP)
    return x, fill_values


class AnomalyModel:
    def __init__(self, contamination=0.02, n_estimators=200, random_state=0, max_features=1.0):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.max_features = max_features
        self.columns_ = []
        self.fill_ = None
        self.center_ = None
        self.spread_ = None
        self.model_ = None
        self.limit_ = None

    def _transform(self, df):
        x, _ = clean(df, self.columns_, self.fill_, self.center_, self.spread_)
        return x

    def fit(self, benign):
        self.columns_ = feature_columns(benign)
        raw, self.fill_ = clean(benign, self.columns_)
        self.center_ = raw.median()
        q1 = raw.quantile(0.25)
        q3 = raw.quantile(0.75)
        iqr = (q3 - q1).replace(0.0, np.nan)
        self.spread_ = iqr.fillna(raw.std().replace(0.0, np.nan)).fillna(1.0)

        x = self._transform(benign)
        self.model_ = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            max_features=self.max_features,
            n_jobs=-1,
        )
        self.model_.fit(x)
        train_scores = -self.model_.score_samples(x)
        self.limit_ = float(np.quantile(train_scores, 1.0 - self.contamination))
        return self

    def anomaly_score(self, df):
        return -self.model_.score_samples(self._transform(df))

    def predict(self, df):
        scores = self.anomaly_score(df)
        return (scores > self.limit_).astype(int), scores
