"""Tests for the simulated traffic generator."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import pytest

from detection.schema import (
    BINARY_COLUMN,
    CATEGORY_COLUMN,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
)
from detection.simulator import (
    SIM_SCENARIOS,
    generate_traffic,
)


def test_generates_all_scenarios():
    scenarios = {"mqtt_benign": 10, "mqtt_flood": 10, "wifi_deauth": 10,
                 "wifi_rogue_ap": 10, "mqtt_injection": 10, "mqtt_spoof": 10}
    df = generate_traffic(scenarios)
    assert len(df) == 60
    assert set(df[LABEL_COLUMN]) == {SIM_SCENARIOS[s][0] for s in scenarios}
    assert set(df[CATEGORY_COLUMN]) <= {"BenignTraffic", "DoS", "Spoofing"}
    assert df[BINARY_COLUMN].sum() == 50  # 10 benign of 60


def test_schema_matches_ciciot():
    df = generate_traffic({"mqtt_benign": 3})
    assert list(df.columns) == [*FEATURE_COLUMNS, LABEL_COLUMN, CATEGORY_COLUMN, BINARY_COLUMN]
    numeric = df[FEATURE_COLUMNS].dtypes
    assert (numeric == "float64").all()


def test_deterministic_with_seed():
    a = generate_traffic({"mqtt_flood": 5}, seed=7)
    b = generate_traffic({"mqtt_flood": 5}, seed=7)
    pd.testing.assert_frame_equal(a, b)


def test_unknown_scenario_raises():
    with pytest.raises(ValueError):
        generate_traffic({"not_real": 5})


def test_attack_profiles_differ_from_benign():
    benign = generate_traffic({"mqtt_benign": 20}, seed=1)
    flood = generate_traffic({"mqtt_flood": 20}, seed=1)
    assert flood["Rate"].mean() > benign["Rate"].mean() * 100
    assert flood["syn_flag_number"].mean() > benign["syn_flag_number"].mean()
