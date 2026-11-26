from collections import defaultdict

import numpy as np

from src.detection.features import FEATURE_NAMES

MAD_SCALE = 1.4826
SCORE_CAP = 20.0


class DeviceFingerprint:
    def __init__(self, top_k=3, min_threshold=3.5, quantile=0.995, min_windows=5):
        self.top_k = top_k
        self.min_threshold = min_threshold
        self.quantile = quantile
        self.min_windows = min_windows
        self.baselines_ = {}
        self.global_ = None
        self.threshold_ = min_threshold

    @staticmethod
    def _baseline(rows):
        matrix = np.array([[r[name] for name in FEATURE_NAMES] for r in rows], dtype=float)
        median = np.median(matrix, axis=0)
        mad = np.median(np.abs(matrix - median), axis=0) * MAD_SCALE
        std = np.std(matrix, axis=0)
        floor = np.maximum(np.abs(median) * 0.05, 1e-3)
        scale = np.where(mad > 0, mad, np.where(std > 0, std, floor))
        return {"median": median, "scale": scale, "count": len(rows)}

    def fit(self, rows):
        by_device = defaultdict(list)
        for row in rows:
            by_device[row["device_id"]].append(row)

        for device_id, items in by_device.items():
            if len(items) >= self.min_windows:
                self.baselines_[device_id] = self._baseline(items)

        self.global_ = self._baseline(rows)
        self.threshold_ = max(self.min_threshold, float(np.quantile(self.deviation(rows), self.quantile)))
        return self

    def deviation(self, rows):
        return self._score(rows)[0]

    def _score(self, rows):
        matrix = np.array([[r[name] for name in FEATURE_NAMES] for r in rows], dtype=float)
        scores = np.zeros(len(rows), dtype=float)
        drivers = []
        for i, row in enumerate(rows):
            baseline = self.baselines_.get(row["device_id"], self.global_)
            z = np.abs(matrix[i] - baseline["median"]) / baseline["scale"]
            z = np.clip(z, 0.0, SCORE_CAP)
            top = np.argsort(z)[::-1][: self.top_k]
            scores[i] = float(np.mean(z[top]))
            drivers.append([FEATURE_NAMES[j] for j in top if z[j] >= self.min_threshold])
        return scores, drivers

    def predict(self, rows, threshold=None):
        limit = self.threshold_ if threshold is None else threshold
        scores, drivers = self._score(rows)
        preds = (scores > limit).astype(int)
        return preds, scores, drivers

    def known(self, device_id):
        return device_id in self.baselines_
