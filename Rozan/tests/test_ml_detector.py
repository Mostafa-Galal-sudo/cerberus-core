"""Tests for the ML anomaly detectors."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection.ml_detector import (
    AutoencoderDetector,
    IsolationForestDetector,
    feature_matrix,
)
from detection.simulator import generate_traffic


@pytest.fixture(scope="module")
def traffic():
    benign = generate_traffic({"mqtt_benign": 300}, seed=11)
    attacks = generate_traffic({"mqtt_flood": 40, "wifi_rogue_ap": 40}, seed=11)
    return benign, attacks


def test_feature_matrix_rejects_empty():
    import pandas as pd
    with pytest.raises(ValueError):
        feature_matrix(pd.DataFrame({"not_a_feature": [1]}))


def test_isolation_forest_separates(traffic):
    benign, attacks = traffic
    det = IsolationForestDetector().fit(benign)
    benign_scores = det.score(benign)
    attack_scores = det.score(attacks)
    # Quantile calibration: benign sits low, attacks saturate high.
    assert benign_scores.mean() < 0.45
    assert attack_scores.mean() > 0.8
    assert ((0 <= benign_scores) & (benign_scores <= 1)).all()
    assert benign_scores.mean() + 0.3 < attack_scores.mean()


def test_autoencoder_separates(traffic):
    benign, attacks = traffic
    det = AutoencoderDetector(hidden=(32, 16, 32)).fit(benign)
    attack_scores = det.score(attacks)
    benign_scores = det.score(benign)
    assert attack_scores.mean() > benign_scores.mean()
    assert attack_scores.mean() > 0.4


def test_percentile_calibration(traffic):
    benign, attacks = traffic
    det = IsolationForestDetector().fit(benign)
    scores = det.score(attacks)
    # quantile calibration: attacks should saturate near 1.0
    assert scores.mean() > 0.8
    benign_scores = det.score(benign)
    assert benign_scores.mean() < 0.45
