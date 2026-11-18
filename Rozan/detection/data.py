"""CICIoT2023 loader.

The full dataset is ~13 GB uncompressed, so CSVs are read in chunks by default
and callers can either stream or collect. Files are expected under `data/`
(git-ignored). Supports both the official UNB CSVs and the preprocessed
HuggingFace variants (they differ only in column spelling and label counts).
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pandas as pd

from detection.schema import (
    BINARY_COLUMN,
    CATEGORY_COLUMN,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    binary_target,
    label_to_category,
    normalize_column,
)

DEFAULT_DATA_DIR = Path("data")


def _normalize(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [normalize_column(c) for c in df.columns]
    if LABEL_COLUMN not in df.columns:
        raise ValueError(f"CSV is missing the {LABEL_COLUMN!r} column")
    df[CATEGORY_COLUMN] = df[LABEL_COLUMN].astype(str).map(label_to_category)
    df[BINARY_COLUMN] = df[CATEGORY_COLUMN].map(binary_target).astype(int)
    # Coerce features to numeric; unparseable cells become NaN and are dropped.
    present = [c for c in FEATURE_COLUMNS if c in df.columns]
    df[present] = df[present].apply(pd.to_numeric, errors="coerce")
    return df.dropna(subset=present).reset_index(drop=True)


def iter_ciciot(
    csv_path: str | Path,
    chunksize: int = 100_000,
    data_dir: Path = DEFAULT_DATA_DIR,
) -> Iterator[pd.DataFrame]:
    """Stream normalized CICIoT2023 chunks (normalized columns + label columns)."""
    path = Path(csv_path)
    if not path.is_absolute():
        path = data_dir / path
    if not path.is_file():
        raise FileNotFoundError(
            f"Dataset not found: {path}. Place CICIoT2023 CSV files in {data_dir}/ "
            "(git-ignored). See docs/PLAN.md Phase 1."
        )
    for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False):
        yield _normalize(chunk)


def load_ciciot(
    csv_path: str | Path,
    rows: int | None = None,
    data_dir: Path = DEFAULT_DATA_DIR,
) -> pd.DataFrame:
    """Load (up to) `rows` normalized records; None = entire file."""
    chunks = []
    remaining = rows
    for chunk in iter_ciciot(csv_path, data_dir=data_dir):
        if remaining is None:
            chunks.append(chunk)
            continue
        chunks.append(chunk.head(remaining))
        remaining -= len(chunk)
        if remaining <= 0:
            break
    df = pd.concat(chunks, ignore_index=True) if chunks else pd.DataFrame()
    if remaining is not None and 0 < remaining:
        pass  # file shorter than requested — return what exists
    return df


def summarize(df: pd.DataFrame) -> pd.Series:
    """Class distribution for quick sanity checks."""
    return df[CATEGORY_COLUMN].value_counts()
