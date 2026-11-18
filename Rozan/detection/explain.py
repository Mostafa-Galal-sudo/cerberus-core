"""SHAP/LIME explainability for the hybrid detection engine.

Produces per-alert feature attributions and merges them with the engine's
rule/fingerprint reasons into a single explanation record. SHAP (TreeExplainer
on the Isolation Forest) is the primary method and is exact for tree models;
LIME is available as a noisy local-surrogate cross-check (the IF decision
function is piecewise-constant, so LIME's local linear fit scatters
attributions across correlated features).

Explanations reference the raw Isolation Forest decision function, which is
monotonically equivalent to the calibrated anomaly score.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
import shap
from lime.lime_tabular import LimeTabularExplainer
from sklearn.preprocessing import StandardScaler

from detection.ml_detector import IsolationForestDetector, feature_matrix


@dataclass
class Explanation:
    method: str  # "shap" | "lime"
    top_features: list[tuple[str, float]]  # (feature, signed contribution)
    base_value: float
    score: float
    summary: str


class Explainer:
    """Wraps a fitted IsolationForestDetector and produces explanations."""

    def __init__(self, detector: IsolationForestDetector, background: pd.DataFrame):
        if detector.columns_ is None:
            raise RuntimeError("detector must be fitted before building an explainer")
        self.detector = detector
        self.columns = list(detector.columns_)
        self.background = feature_matrix(background, self.columns).to_numpy()
        # TreeExplainer on the IF's tree ensemble: no background data needed.
        self._shap = shap.TreeExplainer(detector.model)
        # LIME runs in standardized space — raw CICIoT2023 magnitudes (IAT ~1e8)
        # otherwise dominate the distance kernel and degenerate the local fit.
        self._scaler = StandardScaler().fit(self.background)
        self._background_scaled = self._scaler.transform(self.background)

    def _anomaly_fn(self, X: np.ndarray) -> np.ndarray:
        return -self.detector.model.decision_function(X)

    def _anomaly_fn_scaled(self, X_scaled: np.ndarray) -> np.ndarray:
        return self._anomaly_fn(self._scaler.inverse_transform(X_scaled))

    def explain_shap(self, df: pd.DataFrame, k: int = 5) -> list[Explanation]:
        """SHAP attributions for every row of `df` (vectorized)."""
        X = feature_matrix(df, self.columns).to_numpy()
        values = np.asarray(self._shap.shap_values(X, check_additivity=False))
        expected = float(np.ravel(self._shap.expected_value)[0])
        scores = self._anomaly_fn(X)
        out = []
        for i in range(len(X)):
            contrib = [
                (self.columns[j], float(values[i, j]))
                for j in np.argsort(-np.abs(values[i]))[:k]
            ]
            out.append(Explanation(
                method="shap", top_features=contrib, base_value=expected,
                score=float(scores[i]), summary=_summary("shap", contrib, scores[i]),
            ))
        return out

    def explain_lime(self, df: pd.DataFrame, k: int = 5, seed: int = 42) -> list[Explanation]:
        """LIME attributions per row (local surrogate model, slower than SHAP)."""
        lime = LimeTabularExplainer(
            self._background_scaled, feature_names=self.columns, mode="regression",
            discretize_continuous=False, random_state=seed,
            # Without this, LIME perturbs around the background MEAN, so the
            # neighborhood of an attack row is entirely benign-like and the
            # local model collapses to zero coefficients.
            sample_around_instance=True,
        )
        out = []
        for _, row in feature_matrix(df, self.columns).iterrows():
            x_scaled = self._scaler.transform(row.to_numpy().reshape(1, -1))[0]
            exp = lime.explain_instance(
                x_scaled, self._anomaly_fn_scaled, num_features=k, num_samples=500,
            )
            contrib = [(name, float(weight)) for name, weight in exp.as_list()]
            score = float(self._anomaly_fn_scaled(x_scaled.reshape(1, -1))[0])
            out.append(Explanation(
                method="lime", top_features=contrib, base_value=exp.intercept[1],
                score=score, summary=_summary("lime", contrib, score),
            ))
        return out


def _summary(method: str, contrib: list[tuple[str, float]], score: float) -> str:
    drivers = ", ".join(f"{name} ({val:+.2f})" for name, val in contrib[:3])
    # score is the RAW Isolation Forest decision function (not the calibrated
    # anomaly score shown in the UI) — label it as such to avoid confusion.
    return f"[{method}] raw IF score {score:.2f} driven by: {drivers}"


def annotate_alerts(
    df: pd.DataFrame,
    alerts: pd.DataFrame,
    explainer: Explainer,
    k: int = 3,
) -> pd.DataFrame:
    """Attach ML attributions to engine alert records.

    `alerts` is the output of HybridDetector.score(df) on the same `df`.
    Returns the alert frame with `ml_top_features` and `explanation` columns
    added for alert rows.
    """
    out = alerts.copy()
    out["ml_top_features"] = None
    out["explanation"] = None
    alert_rows = df.loc[out["is_alert"].values]
    if alert_rows.empty:
        return out
    explanations = explainer.explain_shap(alert_rows, k=k)
    for idx, explanation in zip(alert_rows.index, explanations):
        out.at[idx, "ml_top_features"] = explanation.top_features
        merged = [explanation.summary, *out.at[idx, "reasons"]]
        out.at[idx, "explanation"] = merged
    return out
