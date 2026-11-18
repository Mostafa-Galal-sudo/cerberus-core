"""End-to-end tests for the hybrid detection engine."""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection.engine import HybridDetector
from detection.simulator import generate_traffic


@pytest.fixture(scope="module")
def engine():
    benign = generate_traffic({"mqtt_benign": 300}, seed=5)
    det = HybridDetector().fit(benign)
    return det, benign


def test_benign_traffic_yields_no_alerts(engine):
    det, _ = engine
    fresh_benign = generate_traffic({"mqtt_benign": 50}, seed=6)
    out = det.score(fresh_benign)
    assert out["is_alert"].mean() < 0.05


def test_flood_alerts_with_reasons(engine):
    det, _ = engine
    flood = generate_traffic({"mqtt_flood": 30}, seed=6)
    out = det.score(flood)
    assert out["is_alert"].mean() > 0.8
    assert out.loc[out["is_alert"], "reasons"].str.len().gt(0).all()
    assert (out.loc[out["is_alert"], "confidence"] >= det.threshold).all()


def test_scores_bounded_and_ordered(engine):
    det, _ = engine
    mix = generate_traffic({"mqtt_benign": 20, "mqtt_flood": 20, "wifi_rogue_ap": 20}, seed=7)
    out = det.score(mix)
    for col in ("anomaly_score", "rule_score", "fused_score", "confidence"):
        assert ((0 <= out[col]) & (out[col] <= 1)).all(), col


def test_renormalization_without_device_id(engine):
    det, benign = engine
    # No device_id column: weights must still sum to 1 via renormalization.
    out = det.score(benign.head(10))
    assert out["fused_score"].between(0, 1).all()


def test_works_with_device_id_column(engine):
    _det, benign = engine
    benign_d = benign.copy()
    benign_d["device_id"] = "cam-1"
    det_with_fp = HybridDetector().fit(benign_d)
    attack = generate_traffic({"mqtt_flood": 10}, seed=8)
    attack["device_id"] = "cam-1"
    out = det_with_fp.score(attack)
    assert out["is_alert"].all()
    assert any("new_device" not in r for reasons in out["reasons"] for r in reasons)


def test_partial_feature_frame_supported(engine):
    det, _ = engine
    # Real CSVs may lack some columns; engine must tolerate the subset.
    slim = generate_traffic({"mqtt_flood": 10}, seed=9).drop(columns=["IAT", "Weight"])
    out = det.score(slim)
    assert out["is_alert"].all()


def test_binary_column_filtering_in_fit():
    # Mixed fit data: only benign rows may shape the baselines.
    mixed = generate_traffic({"mqtt_benign": 100, "mqtt_flood": 100}, seed=10)
    det = HybridDetector().fit(mixed)
    benign = generate_traffic({"mqtt_benign": 50}, seed=10)
    assert det.score(benign)["is_alert"].mean() < 0.1
    assert det.forest.columns_ is not None  # forest was fitted (benign-only)


def test_no_autoencoder_option():
    benign = generate_traffic({"mqtt_benign": 100}, seed=12)
    det = HybridDetector(use_autoencoder=False).fit(benign)
    assert det.autoencoder is None
    out = det.score(generate_traffic({"mqtt_flood": 10}, seed=12))
    assert out["is_alert"].all()
    assert np.isfinite(out["fused_score"]).all()
