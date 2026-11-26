import numpy as np
import pandas as pd

CICIOT_RULES = (
    ("rate_spike", "Rate", "high"),
    ("interarrival_collapse", "IAT", "low"),
    ("syn_saturation", "syn_flag_number", "high"),
    ("ack_saturation", "ack_flag_number", "high"),
    ("icmp_share", "ICMP", "high"),
    ("packet_burst", "Number", "high"),
    ("header_bloat", "Header_Length", "high"),
    ("size_dispersion", "Std", "high"),
)

MQTT_RULES = (
    ("rate_spike", "rate_per_sec", "high"),
    ("interarrival_collapse", "gap_mean", "low"),
    ("payload_bloat", "payload_max", "high"),
    ("size_dispersion", "payload_std", "high"),
    ("topic_burst", "topic_count", "high"),
    ("gap_jitter", "gap_cv", "high"),
)

RULE_SETS = {"ciciot": CICIOT_RULES, "mqtt": MQTT_RULES}
RULES = CICIOT_RULES


class RuleEngine:
    def __init__(self, feature_set="ciciot", high_q=0.999, low_q=0.001):
        self.rules = RULE_SETS[feature_set]
        self.high_q = high_q
        self.low_q = low_q
        self.thresholds_ = {}

    def fit(self, benign):
        for name, column, direction in self.rules:
            values = benign[column].replace([np.inf, -np.inf], np.nan).dropna().to_numpy()
            q = self.high_q if direction == "high" else self.low_q
            self.thresholds_[name] = float(np.quantile(values, q))
        return self

    def score(self, df):
        hits = np.zeros(len(df), dtype=int)
        reasons = [[] for _ in range(len(df))]
        for name, column, direction in self.rules:
            values = df[column].replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy()
            limit = self.thresholds_[name]
            fired = values > limit if direction == "high" else values < limit
            hits += fired.astype(int)
            for idx in np.flatnonzero(fired):
                reasons[idx].append(name)
        return hits, reasons

    def predict(self, df, min_hits=1):
        hits, reasons = self.score(df)
        preds = hits >= min_hits
        return preds.astype(int), hits, reasons
