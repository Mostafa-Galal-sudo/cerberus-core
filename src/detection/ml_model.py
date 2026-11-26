import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

META_COLUMNS = ("category", "is_attack", "source_file", "source_folder")


def feature_columns(df):
    return [c for c in df.columns if c not in META_COLUMNS and pd.api.types.is_numeric_dtype(df[c])]


def clean(df, columns, fill_values=None):
    x = df[columns].replace([np.inf, -np.inf], np.nan)
    if fill_values is None:
        fill_values = x.median(numeric_only=True).fillna(0.0)
    x = x.fillna(fill_values)
    return x, fill_values


class AnomalyModel:
    def __init__(self, contamination=0.05, n_estimators=200, random_state=0):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.columns_ = []
        self.fill_ = None
        self.model_ = None
        self.limit_ = None

    def fit(self, benign):
        self.columns_ = feature_columns(benign)
        x, self.fill_ = clean(benign, self.columns_)
        self.model_ = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model_.fit(x)
        train_scores = -self.model_.score_samples(x)
        self.limit_ = float(np.quantile(train_scores, 1.0 - self.contamination))
        return self

    def anomaly_score(self, df):
        x, _ = clean(df, self.columns_, self.fill_)
        return -self.model_.score_samples(x)

    def predict(self, df):
        scores = self.anomaly_score(df)
        return (scores > self.limit_).astype(int), scores
