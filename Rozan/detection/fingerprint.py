"""Device behavioral fingerprinting.

Builds per-device baselines over a compact feature subset and scores how far
each row deviates. Devices never seen in training get flagged with a
"new_device" reason — unknown endpoints on the network are themselves a signal.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

# Compact, high-signal subset for behavioral profiles.
FINGERPRINT_FEATURES = [
    "Rate", "Srate", "Drate", "Header_Length", "Tot_sum", "Tot_size",
    "Min", "Max", "AVG", "Std", "IAT", "Variance", "Weight",
]

DEVICE_COLUMN = "device_id"


class DeviceFingerprint:
    def fit(self, benign: pd.DataFrame) -> DeviceFingerprint:
        if DEVICE_COLUMN not in benign.columns:
            raise ValueError(f"fingerprinting requires a {DEVICE_COLUMN!r} column")
        cols = _present(benign)
        stats = benign.groupby(DEVICE_COLUMN)[cols].agg(["mean", "std"])
        self.profile_ = stats
        self.global_mean_ = benign[cols].mean()
        self.global_std_ = benign[cols].std().replace(0, 1.0)
        return self

    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        """Per-row fingerprint deviation score in [0, 1] plus reason strings."""
        cols = _present(df)
        scores, reasons = [], []
        for _, row in df.iterrows():
            device = row.get(DEVICE_COLUMN)
            if device in self.profile_.index:
                mean = self.profile_.loc[device, (cols, "mean")]
                std = self.profile_.loc[device, (cols, "std")].replace(0, 1.0)
            else:
                mean, std = self.global_mean_, self.global_std_
            z = ((row[cols] - mean) / std).abs().fillna(0.0)
            worst = z.idxmax()
            score = float(np.tanh(z.max() / 10.0))  # cap; 10 sigma ~ 1.0
            if device not in self.profile_.index:
                # Unknown endpoints are themselves a signal: enforce a floor.
                score = max(score, 0.8)
                reasons.append(f"new_device: {device} not in benign baseline")
            elif score > 0.5:
                reasons.append(f"device_deviation: {worst} z={z[worst]:.1f}")
            else:
                reasons.append("")
            scores.append(score)
        return pd.DataFrame({"fingerprint_score": scores, "fingerprint_reason": reasons},
                            index=df.index)


def _present(df: pd.DataFrame) -> list[str]:
    cols = [c for c in FINGERPRINT_FEATURES if c in df.columns]
    if not cols:
        raise ValueError("No fingerprint feature columns in input")
    return cols
