"""Tests for label taxonomy normalization."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from detection.schema import (
    BENIGN_LABEL,
    FEATURE_COLUMNS,
    binary_target,
    label_to_category,
    normalize_column,
)


@pytest.mark.parametrize("raw,expected", [
    ("BenignTraffic", BENIGN_LABEL),
    ("BenignTraffic_D1", BENIGN_LABEL),
    ("DDoS-SYN_Flood", "DDoS"),
    ("DDoS-ICMP_Flood", "DDoS"),
    ("DoS-TCP_Flood", "DoS"),
    ("DoS-UDP_Flood", "DoS"),
    ("Mirai-greip_flood", "Mirai"),
    ("Recon-PingSweep", "Recon"),
    ("VulnerabilityScan", "Recon"),
    ("PortScan", "Recon"),
    ("DictionaryBruteForce", "BruteForce"),
    ("MITM-ArpSpoofing", "Spoofing"),
    ("DNS_Spoofing", "Spoofing"),
    ("XSS", "Web-based"),
    ("SqlInjection", "Web-based"),
    ("CommandInjection", "Web-based"),
    ("Backdoor_Malware", "Web-based"),
    ("Uploading_Attack", "Web-based"),
    ("BrowserHijacking", "Web-based"),
])
def test_label_to_category(raw, expected):
    assert label_to_category(raw) == expected


def test_label_to_category_unknown_raises():
    with pytest.raises(ValueError):
        label_to_category("NotARealAttack")


def test_binary_target():
    assert binary_target(BENIGN_LABEL) == 0
    assert binary_target("DDoS") == 1


def test_normalize_column():
    assert normalize_column("Protocol Type") == "Protocol_Type"
    assert normalize_column("protocol_type") == "Protocol_Type"
    assert normalize_column("Magnitue") == "Magnitue"
    assert normalize_column("label") == "label"


def test_feature_columns_count():
    # Official releases ship 46-48 numeric features depending on the directory;
    # the loader tolerates missing columns, so just require the known minimum
    # and uniqueness.
    assert len(FEATURE_COLUMNS) == len(set(FEATURE_COLUMNS))
    assert len(FEATURE_COLUMNS) >= 46
