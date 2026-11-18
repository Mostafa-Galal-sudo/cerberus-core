"""Tests for device behavioral fingerprinting."""
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection.fingerprint import DeviceFingerprint
from detection.simulator import generate_traffic


def _with_devices(df: pd.DataFrame, devices: list[str]) -> pd.DataFrame:
    out = df.copy()
    out["device_id"] = [devices[i % len(devices)] for i in range(len(out))]
    return out


def test_fit_requires_device_column():
    df = generate_traffic({"mqtt_benign": 5})
    with pytest.raises(ValueError):
        DeviceFingerprint().fit(df)


def test_known_device_stays_low():
    benign = _with_devices(generate_traffic({"mqtt_benign": 300}, seed=3), ["cam-1", "cam-2"])
    fp = DeviceFingerprint().fit(benign)
    scored = fp.score(_with_devices(generate_traffic({"mqtt_benign": 20}, seed=3), ["cam-1"]))
    assert (scored["fingerprint_score"] < 0.5).all()


def test_attack_deviation_scores_high():
    benign = _with_devices(generate_traffic({"mqtt_benign": 300}, seed=3), ["cam-1"])
    fp = DeviceFingerprint().fit(benign)
    attack = _with_devices(generate_traffic({"mqtt_flood": 20}, seed=3), ["cam-1"])
    scored = fp.score(attack)
    assert scored["fingerprint_score"].mean() > 0.5


def test_unknown_device_flagged():
    benign = _with_devices(generate_traffic({"mqtt_benign": 100}, seed=3), ["cam-1"])
    fp = DeviceFingerprint().fit(benign)
    scored = fp.score(_with_devices(generate_traffic({"mqtt_benign": 5}, seed=3), ["cam-99"]))
    assert scored["fingerprint_score"].mean() > 0.5
    assert scored["fingerprint_reason"].str.contains("new_device").all()
