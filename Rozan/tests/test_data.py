"""Tests for the CICIoT2023 CSV loader."""
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection.data import (
    BINARY_COLUMN,
    CATEGORY_COLUMN,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    load_ciciot,
    summarize,
)


@pytest.fixture()
def sample_csv(tmp_path):
    """A tiny CSV mimicking raw CICIoT2023 column spellings."""
    raw = pd.DataFrame({
        "flow_duration": [0.5, 1.2, 0.1],
        "Header_Length": [54.0, 280.0, 54.0],
        "Protocol Type": [6, 6, 6],
        "Time_To_Live": [64, 128, 64],
        "label": ["BenignTraffic", "DDoS-SYN_Flood", "DoS-TCP_Flood"],
        "Weight": [141.5, 141.5, 141.5],
    })
    path = tmp_path / "sample.csv"
    raw.to_csv(path, index=False)
    return path


def test_load_normalizes_columns_and_labels(sample_csv):
    df = load_ciciot(sample_csv, data_dir=sample_csv.parent)
    assert "Protocol_Type" in df.columns
    assert LABEL_COLUMN in df.columns
    assert CATEGORY_COLUMN in df.columns
    assert BINARY_COLUMN in df.columns
    assert df[BINARY_COLUMN].tolist() == [0, 1, 1]
    assert df[CATEGORY_COLUMN].tolist() == ["BenignTraffic", "DDoS", "DoS"]


def test_load_rows_limit(sample_csv):
    df = load_ciciot(sample_csv, rows=2, data_dir=sample_csv.parent)
    assert len(df) == 2


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_ciciot("nonexistent.csv", data_dir=tmp_path)


def test_summarize(sample_csv):
    df = load_ciciot(sample_csv, data_dir=sample_csv.parent)
    dist = summarize(df)
    assert dist["BenignTraffic"] == 1
    assert dist["DDoS"] == 1


def test_feature_columns_present_in_output(sample_csv):
    df = load_ciciot(sample_csv, data_dir=sample_csv.parent)
    # Only the features present in the CSV survive; label columns always added.
    assert {LABEL_COLUMN, CATEGORY_COLUMN, BINARY_COLUMN}.issubset(df.columns)
    assert set(FEATURE_COLUMNS) >= set(df.columns) - {
        LABEL_COLUMN, CATEGORY_COLUMN, BINARY_COLUMN,
    }
