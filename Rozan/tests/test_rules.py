"""Tests for the rule-based detection layer."""
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection.rules import RULES, RulesResult, run_rules
from detection.simulator import generate_traffic


def _row(**overrides):
    benign = generate_traffic({"mqtt_benign": 1}, seed=0).iloc[0]
    row = benign.copy()
    for key, value in overrides.items():
        row[key] = value
    return row


def test_benign_row_fires_no_rules():
    result = run_rules(generate_traffic({"mqtt_benign": 20}, seed=1))
    assert not any(h for h in result.hits)
    assert all(s == 0.0 for s in result.score)


def test_flood_row_fires_flood_rule():
    row = _row(Rate=200_000.0, syn_flag_number=1.0)
    hits = run_rules(pd.DataFrame([row])).hits[0]
    names = [name for name, _ in hits]
    assert "flood_rate" in names


def test_reasons_contain_feature_values():
    row = _row(Rate=200_000.0, syn_flag_number=1.0)
    hits = run_rules(pd.DataFrame([row])).hits[0]
    reason = next(text for name, text in hits if name == "flood_rate")
    assert "Rate=200000" in reason
    assert "syn_flag_number=1" in reason


def test_rules_result_to_frame():
    result = RulesResult(hits=[[("flood_rate", "r")]], score=[1.0])
    frame = result.to_frame(pd.RangeIndex(1))
    assert frame["rule_score"].tolist() == [1.0]


def test_rule_score_capped_at_one():
    # A row that trips every rule still yields at most 1.0.
    row = _row(Rate=200_000.0, syn_flag_number=1.0, ack_flag_number=0.0,
               rst_count=10, Header_Length=600, Tot_sum=10_000,
               ICMP=1.0, ARP=1.0)
    score = run_rules(pd.DataFrame([row])).score[0]
    assert score <= 1.0


def test_all_rules_have_unique_names_and_valid_severity():
    names = [r.name for r in RULES]
    assert len(names) == len(set(names))
    assert all(r.severity in ("low", "medium", "high") for r in RULES)
    assert all(0 < r.weight <= 1 for r in RULES)


def test_unknown_device_key_is_ignored():
    row = _row(Rate=200_000.0, syn_flag_number=1.0, nonexistent_feature=9)
    hits = run_rules(pd.DataFrame([row])).hits[0]
    assert hits  # rule still fires on known features
