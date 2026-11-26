from pathlib import Path

import pandas as pd

from src.detection.dataset import category_of, class_files, load_sample, split_by_file
from src.detection.features import FEATURE_NAMES, device_windows, to_matrix
from src.storage import db


def test_windows_from_simulated_db(tmp_path):
    conn = db.open_db(tmp_path / "t.db")
    base = 1_760_000_000.0
    for i in range(60):
        db.save_event(conn, {
            "ts_utc": pd.Timestamp(base + i * 10, unit="s", tz="UTC").isoformat(),
            "device_id": "esp32_temp_01",
            "device_type": "climate",
            "topic": "lab/room1/climate",
            "qos": 0,
            "payload_size": 180,
            "payload_preview": "{}",
            "direction": "publish",
        })
    rows = device_windows(conn)
    assert rows
    assert all(r["device_id"] == "esp32_temp_01" for r in rows)
    x, meta = to_matrix(rows)
    assert x.shape[1] == len(FEATURE_NAMES)
    assert len(meta) == len(rows)


def test_category_mapping_covers_every_folder():
    root = Path("data/raw/ciciot2023/CSV")
    if not root.is_dir():
        import pytest
        pytest.skip("dataset not downloaded")
    entries = class_files(root)
    assert len(entries) >= 30
    assert {e["category"] for e in entries} >= {"Benign", "DDoS", "DoS", "Mirai", "Recon"}


def test_sample_loads_both_classes_and_drops_constants():
    root = Path("data/raw/ciciot2023/CSV")
    if not root.is_dir():
        import pytest
        pytest.skip("dataset not downloaded")
    df = load_sample(root, rows_per_file=50, categories={"Benign", "DDoS"})
    assert set(df["category"].unique()) == {"Benign", "DDoS"}
    assert df["is_attack"].nunique() == 2
    numeric = [c for c in df.columns if pd.api.types.is_numeric_dtype(df[c])]
    assert all(df[c].nunique(dropna=False) > 1 for c in numeric)


def test_split_never_shares_a_capture_file():
    df = pd.DataFrame({
        "source_file": ["a.csv"] * 10 + ["b.csv"] * 10 + ["c.csv"] * 10 + ["d.csv"] * 10,
        "value": range(40),
    })
    train, test = split_by_file(df, test_fraction=0.5, seed=1)
    assert set(train["source_file"]).isdisjoint(set(test["source_file"]))
    assert len(train) + len(test) == len(df)
