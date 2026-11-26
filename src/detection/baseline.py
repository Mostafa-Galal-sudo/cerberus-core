import numpy as np
import pandas as pd

from src.detection.ml_model import clean, feature_columns

SCORE_CLIP = 20.0


class DeviationBaseline:
    def __init__(self, quantile=0.995, top_k=3):
        self.quantile = quantile
        self.top_k = top_k
        self.columns_ = []
        self.fill_ = None
        self.center_ = None
        self.scale_ = None
        self.limit_ = None

    def _transform(self, df):
        x, _ = clean(df, self.columns_, self.fill_)
        return x

    def fit(self, benign):
        self.columns_ = feature_columns(benign)
        raw = benign[self.columns_].replace([np.inf, -np.inf], np.nan)
        self.fill_ = raw.median().fillna(0.0)
        x = raw.fillna(self.fill_)
        self.center_ = x.median()
        mad = (x - self.center_).abs().median() * 1.4826
        std = x.std().replace(0.0, np.nan)
        self.scale_ = mad.where(mad > 0, std).fillna(1.0)
        train_scores = self.score(benign)
        self.limit_ = float(np.quantile(train_scores, self.quantile))
        return self

    def z_matrix(self, df, clip=True):
        x = self._transform(df)
        z = ((x - self.center_) / self.scale_).abs()
        if clip:
            z = z.clip(0.0, SCORE_CLIP)
        return z.fillna(0.0)

    def score(self, df):
        return self.z_matrix(df).mean(axis=1).to_numpy()

    def predict(self, df):
        scores = self.score(df)
        return (scores > self.limit_).astype(int), scores

    def drivers(self, df):
        z = self.z_matrix(df, clip=False)
        names = list(z.columns)
        out = []
        for _, row in z.iterrows():
            order = row.to_numpy().argsort()[::-1][: self.top_k]
            out.append([(names[i], float(min(row.iloc[i], SCORE_CLIP))) for i in order if row.iloc[i] > 1.0])
        return out
