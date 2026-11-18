"""Hybrid detection engine: rules + ML anomaly + fingerprint fusion.

Fuses three evidence sources into one alert decision with an explainable
reason list. The fused score is the alert confidence; the SHAP/LIME layer
(detection/explain.py, next plan item) enriches ML-driven alerts with
per-feature attributions on top of these reasons.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from detection.fingerprint import DeviceFingerprint
from detection.ml_detector import (
    AutoencoderDetector,
    IsolationForestDetector,
    feature_matrix,
)
from detection.rules import run_rules
from detection.schema import BINARY_COLUMN

DEFAULT_WEIGHTS = {"ml": 0.5, "rules": 0.35, "fingerprint": 0.15}
DEFAULT_THRESHOLD = 0.5


class HybridDetector:
    def __init__(
        self,
        threshold: float = DEFAULT_THRESHOLD,
        weights: dict[str, float] | None = None,
        use_autoencoder: bool = True,
    ):
        self.threshold = threshold
        self.weights = {**DEFAULT_WEIGHTS, **(weights or {})}
        self.forest = IsolationForestDetector()
        self.autoencoder = AutoencoderDetector() if use_autoencoder else None
        self.fingerprint = DeviceFingerprint()

    def fit(self, benign: pd.DataFrame) -> HybridDetector:
        """Train on benign traffic only (rows where is_attack == 0)."""
        if BINARY_COLUMN in benign.columns:
            benign = benign[benign[BINARY_COLUMN] == 0]
        self.forest.fit(benign)
        if self.autoencoder is not None:
            self.autoencoder.fit(benign)
        if "device_id" in benign.columns:
            self.fingerprint.fit(benign)
        return self

    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        """Score all rows; returns alert records with fused score + reasons."""
        anomaly = self.forest.score(df)
        if self.autoencoder is not None:
            anomaly = 0.5 * anomaly + 0.5 * self.autoencoder.score(df)
        rules = run_rules(df)
        rule_scores = np.asarray(rules.score, dtype=float)

        fused = self.weights["ml"] * anomaly + self.weights["rules"] * rule_scores
        fp = None
        if "device_id" in df.columns and hasattr(self.fingerprint, "profile_"):
            fp = self.fingerprint.score(df)
            fused = fused + self.weights["fingerprint"] * fp["fingerprint_score"].to_numpy()
        else:
            fused = fused / (1 - self.weights["fingerprint"])  # renormalize

        out = pd.DataFrame(index=df.index)
        out["anomaly_score"] = anomaly
        out["rule_score"] = rules.score
        out["rule_hits"] = [[name for name, _ in hits] for hits in rules.hits]
        out["fingerprint_score"] = (
            fp["fingerprint_score"].to_numpy() if fp is not None else None
        )
        out["fused_score"] = fused.clip(0.0, 1.0)
        out["is_alert"] = out["fused_score"] >= self.threshold
        out["confidence"] = out["fused_score"]
        out["reasons"] = _reasons(rules.hits, fp)
        return out

    def explain_features(self, df: pd.DataFrame) -> dict:
        """Inputs the SHAP/LIME layer needs: feature matrix + scored rows."""
        return {"X": feature_matrix(df), "scores": self.score(df)}


def _reasons(rule_hits: list[list[tuple[str, str]]], fp: pd.DataFrame | None) -> list[list[str]]:
    """Merge rule reasons (+ fingerprint reasons) into per-row lists."""
    merged = [[reason for _, reason in hits] for hits in rule_hits]
    if fp is not None:
        for reasons, fp_reason in zip(merged, fp["fingerprint_reason"]):
            if fp_reason:
                reasons.append(fp_reason)
    return merged
