import numpy as np
import pandas as pd

from src.detection.dataset import split_by_file
from src.detection.ml_model import AnomalyModel
from src.detection.rules_engine import RULES, RuleEngine

COLUMNS = [col for _, col, _ in RULES]


def frame(n, rate, iat, syn, ack, icmp, number, header, std):
    return pd.DataFrame({
        "Rate": np.full(n, rate, dtype=float),
        "IAT": np.full(n, iat, dtype=float),
        "syn_flag_number": np.full(n, syn, dtype=float),
        "ack_flag_number": np.full(n, ack, dtype=float),
        "ICMP": np.full(n, icmp, dtype=float),
        "Number": np.full(n, number, dtype=float),
        "Header_Length": np.full(n, header, dtype=float),
        "Std": np.full(n, std, dtype=float),
    })


def benign_frame(n=500, jitter=1.0):
    rng = np.random.default_rng(0)
    base = frame(n, 400.0, 0.002, 0.0, 0.6, 0.0, 10.0, 22.0, 170.0)
    for col in base.columns:
        base[col] = base[col] + rng.normal(0, jitter * base[col].abs().mean() * 0.05, n)
    return base.abs()


def test_rule_engine_near_silent_on_benign():
    benign = benign_frame()
    engine = RuleEngine().fit(benign)
    preds, hits, _ = engine.predict(benign)
    assert preds.mean() <= 0.05
    assert hits.max() <= 1


def test_rule_engine_min_hits_trades_recall_for_precision():
    benign = benign_frame()
    engine = RuleEngine().fit(benign)
    attack = frame(20, 25_000.0, 0.00001, 0.0, 0.0, 0.0, 500.0, 60.0, 4000.0)
    mixed = pd.concat([benign, attack], ignore_index=True)
    loose, _, _ = engine.predict(mixed, min_hits=1)
    strict, _, _ = engine.predict(mixed, min_hits=3)
    assert strict[: len(benign)].sum() <= loose[: len(benign)].sum()
    assert strict[len(benign):].sum() == 20


def test_rule_engine_flags_rate_spike():
    engine = RuleEngine().fit(benign_frame())
    attack = frame(3, 25_000.0, 0.00001, 0.0, 0.0, 0.0, 500.0, 60.0, 4000.0)
    preds, hits, reasons = engine.predict(attack)
    assert preds.sum() == 3
    assert hits.min() >= 2
    assert "rate_spike" in reasons[0]
    assert "interarrival_collapse" in reasons[0]


def test_rule_engine_returns_one_reason_list_per_row():
    engine = RuleEngine().fit(benign_frame())
    rows = pd.concat([benign_frame(4), frame(4, 25_000.0, 0.00001, 0, 0, 0, 500.0, 60.0, 4000.0)])
    _, _, reasons = engine.predict(rows)
    assert len(reasons) == len(rows)
    assert all(isinstance(r, list) for r in reasons)


def test_isolation_forest_flags_shifted_rows():
    benign = benign_frame()
    model = AnomalyModel(contamination=0.01, n_estimators=64).fit(benign)
    attack = frame(10, 25_000.0, 0.00001, 0.0, 0.0, 0.0, 500.0, 60.0, 4000.0)
    preds, scores = model.predict(attack)
    assert preds.mean() >= 0.8
    assert scores.min() > model.limit_


def test_isolation_forest_stays_quiet_on_training_distribution():
    benign = benign_frame()
    model = AnomalyModel(contamination=0.01, n_estimators=64).fit(benign)
    preds, _ = model.predict(benign_frame(n=300, jitter=0.5))
    assert preds.mean() <= 0.1


def test_split_covers_single_file_folders_in_test():
    df = pd.DataFrame({
        "source_file": ["web.csv"] * 5 + ["ddos_a.csv"] * 5 + ["ddos_b.csv"] * 5,
        "source_folder": ["Web"] * 5 + ["DDoS"] * 10,
        "value": range(15),
    })
    train, test = split_by_file(df, test_fraction=0.3, seed=0)
    assert "web.csv" in set(test["source_file"])
    assert len(train) > 0
    assert set(train["source_file"]).isdisjoint(set(test["source_file"]))
