"""Unsupervised ML anomaly detectors (Isolation Forest + autoencoder).

Both detectors are trained on benign traffic only and produce anomaly scores
in [0, 1] calibrated with benign-distribution quantiles: q05 maps to 0, q99
maps to 1. Benign traffic therefore stays in the low range while attacks
saturate at 1, without a tuning round-trip.

Detectors remember their fitted feature list; scoring frames missing columns
reindex with zeros so partial CSVs still work. Matrices are passed to sklearn
as plain numpy (no feature-name strictness).
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from detection.schema import FEATURE_COLUMNS


def feature_matrix(df: pd.DataFrame, columns: list[str] | None = None) -> pd.DataFrame:
    """Numeric feature matrix restricted to schema features present in `df`."""
    cols = columns or [c for c in FEATURE_COLUMNS if c in df.columns]
    if not cols:
        raise ValueError("No known CICIoT2023 feature columns in input")
    return df.reindex(columns=cols).fillna(0.0).astype("float64")


def _quantile_score(raw: np.ndarray, lo: float, hi: float) -> np.ndarray:
    if hi - lo <= 1e-12:  # degenerate baseline: flag only above it
        return (raw > hi).astype(float)
    return np.clip((raw - lo) / (hi - lo), 0.0, 1.0)


class IsolationForestDetector:
    def __init__(self, n_estimators: int = 200, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=n_estimators, random_state=random_state, n_jobs=-1,
        )
        self.columns_: list[str] | None = None
        self.lo_: float = 0.0
        self.hi_: float = 1.0

    def fit(self, benign: pd.DataFrame) -> IsolationForestDetector:
        X = feature_matrix(benign)
        self.columns_ = list(X.columns)
        X_np = X.to_numpy()
        self.model.fit(X_np)
        raw = -self.model.decision_function(X_np)
        self.lo_, self.hi_ = np.quantile(raw, [0.05, 0.99])
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        if self.columns_ is None:
            raise RuntimeError("IsolationForestDetector must be fitted before scoring")
        raw = -self.model.decision_function(feature_matrix(df, self.columns_).to_numpy())
        return _quantile_score(raw, self.lo_, self.hi_)


class AutoencoderDetector:
    """MLP autoencoder: reconstruction error of benign traffic as anomaly score.

    Features are standardized internally — raw CICIoT2023 ranges span several
    orders of magnitude, which destabilizes an unscaled MLP.
    """

    def __init__(self, hidden=(32, 16, 32), random_state: int = 42):
        self.model = MLPRegressor(
            hidden_layer_sizes=hidden, activation="relu", max_iter=800,
            early_stopping=True, random_state=random_state,
        )
        self.scaler = StandardScaler()
        self.columns_: list[str] | None = None
        self.lo_: float = 0.0
        self.hi_: float = 1.0

    def fit(self, benign: pd.DataFrame) -> AutoencoderDetector:
        X = feature_matrix(benign)
        self.columns_ = list(X.columns)
        X_s = self.scaler.fit_transform(X)
        self.model.fit(X_s, X_s)  # reconstruct inputs — the autoencoder contract
        raw = np.mean((self.model.predict(X_s) - X_s) ** 2, axis=1)
        self.lo_, self.hi_ = np.quantile(raw, [0.05, 0.99])
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        if self.columns_ is None:
            raise RuntimeError("AutoencoderDetector must be fitted before scoring")
        X_s = self.scaler.transform(feature_matrix(df, self.columns_))
        raw = np.mean((self.model.predict(X_s) - X_s) ** 2, axis=1)
        return _quantile_score(raw, self.lo_, self.hi_)
