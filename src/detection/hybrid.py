import numpy as np
import pandas as pd

from src.detection.baseline import DeviationBaseline
from src.detection.rules_engine import RuleEngine

RULE_WEIGHT = 0.45
DEVIATION_WEIGHT = 0.35
FINGERPRINT_WEIGHT = 0.20
FAST_PATH_HITS = 1
HIGH_SEVERITY_HITS = 2
HIGH_SEVERITY_CONFIDENCE = 0.60


def _rule_evidence(hits):
    return np.clip(np.asarray(hits, dtype=float) / 2.0, 0.0, 1.0)


def _ratio_evidence(scores, limit):
    if scores is None or limit is None or limit <= 0:
        return None
    ratio = np.asarray(scores, dtype=float) / limit
    return np.clip((ratio - 1.0) / 1.5, 0.0, 1.0)


class HybridDetector:
    def __init__(self, quantile=0.995, fingerprint=None, feature_set="ciciot"):
        self.quantile = quantile
        self.feature_set = feature_set
        self.rules = RuleEngine(feature_set=feature_set)
        self.baseline = DeviationBaseline(quantile=quantile)
        self.fingerprint = fingerprint

    def fit(self, benign):
        self.rules.fit(benign)
        self.baseline.fit(benign)
        return self

    def confidence(self, hits, dev_scores, dev_limit, fp_scores=None, fp_limit=None):
        rule_ev = _rule_evidence(hits)
        dev_ev = _ratio_evidence(dev_scores, dev_limit)
        fp_ev = _ratio_evidence(fp_scores, fp_limit)

        if dev_ev is None:
            dev_ev = np.zeros(len(rule_ev))
        if fp_ev is None:
            total = RULE_WEIGHT + DEVIATION_WEIGHT
            return (RULE_WEIGHT * rule_ev + DEVIATION_WEIGHT * dev_ev) / total
        return RULE_WEIGHT * rule_ev + DEVIATION_WEIGHT * dev_ev + FINGERPRINT_WEIGHT * fp_ev

    def predict(self, df, fp_scores=None, fp_limit=None):
        _, hits, reasons = self.rules.predict(df, min_hits=1)
        dev_preds, dev_scores = self.baseline.predict(df)
        drivers = self.baseline.drivers(df)

        unknown_path = np.zeros(len(df), dtype=bool)
        if self.fingerprint is not None and "device_id" in df.columns:
            unknown_path = ~df["device_id"].map(self.fingerprint.known).to_numpy(dtype=bool)
            if fp_scores is None and self.fingerprint.baselines_:
                _, fp_scores, _ = self.fingerprint.predict(df.to_dict("records"))
                if fp_limit is None:
                    fp_limit = self.fingerprint.threshold_

        score = self.confidence(hits, dev_scores, self.baseline.limit_, fp_scores, fp_limit)
        score = np.where(unknown_path, np.maximum(score, HIGH_SEVERITY_CONFIDENCE), score)
        fast_path = hits >= FAST_PATH_HITS
        slow_path = dev_preds.astype(bool)
        fingerprint_path = np.zeros(len(df), dtype=bool) if fp_scores is None else (np.asarray(fp_scores) > fp_limit)
        alert = fast_path | slow_path | fingerprint_path | unknown_path

        severity = np.where((hits >= HIGH_SEVERITY_HITS) | (score >= HIGH_SEVERITY_CONFIDENCE), "high", "medium")
        out = pd.DataFrame({
            "rule_hits": hits,
            "deviation_score": dev_scores,
            "confidence": score,
            "alert": alert.astype(int),
            "severity": severity,
        }, index=df.index)
        devices = df["device_id"].tolist() if "device_id" in df.columns else [None] * len(df)
        out["explanation"] = [
            self._explain(hits[i], reasons[i], drivers[i], score[i], unknown_path[i], devices[i])
            for i in range(len(out))
        ]
        return out

    def _explain(self, hits, rule_reasons, driver_list, score, unknown=False, device_id=None):
        parts = [f"rules:{'+'.join(rule_reasons) if hits else 'none'}"]
        if unknown:
            parts.append(f"unknown_device:{device_id}" if device_id else "unknown_device")
        if driver_list:
            parts.append("deviation:" + ",".join(f"{name}={value:.1f}" for name, value in driver_list))
        parts.append(f"confidence:{score:.2f}")
        return " ".join(parts)
