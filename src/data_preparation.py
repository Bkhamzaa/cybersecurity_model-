from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


IDENTIFIER_COLUMNS = [
    "Flow ID",
    "Src IP",
    "Dst IP",
    "Timestamp",
]


ATTACK_FAMILY_MAP = {
    "BENIGN": "BENIGN",
    "Bot": "Bot",
    "Bot - Attempted": "Bot",
    "DDoS": "DoS_DDoS",
    "DoS GoldenEye": "DoS_DDoS",
    "DoS GoldenEye - Attempted": "DoS_DDoS",
    "DoS Hulk": "DoS_DDoS",
    "DoS Hulk - Attempted": "DoS_DDoS",
    "DoS Slowhttptest": "DoS_DDoS",
    "DoS Slowhttptest - Attempted": "DoS_DDoS",
    "DoS slowloris": "DoS_DDoS",
    "DoS slowloris - Attempted": "DoS_DDoS",
    "FTP-Patator": "BruteForce",
    "FTP-Patator - Attempted": "BruteForce",
    "SSH-Patator": "BruteForce",
    "SSH-Patator - Attempted": "BruteForce",
    "PortScan": "PortScan",
    "Infiltration": "Infiltration",
    "Infiltration - Attempted": "Infiltration",
    "Heartbleed": "Heartbleed",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - Brute Force - Attempted": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Web Attack - XSS - Attempted": "WebAttack",
}


def normalize_label(label: str, mode: str) -> str:
    value = str(label).strip()
    if mode == "binary":
        return "BENIGN" if value == "BENIGN" else "ATTACK"
    if mode == "family":
        return ATTACK_FAMILY_MAP.get(value, value)
    return value


def load_csv_files(data_dir: Path) -> list[Path]:
    csv_files = sorted(data_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    return csv_files


def load_dataset(
    data_dir: Path,
    mode: str = "binary",
    sample_frac: float | None = None,
    random_state: int = 42,
) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []

    for csv_file in load_csv_files(data_dir):
        frame = pd.read_csv(csv_file, low_memory=False)
        if sample_frac is not None and 0 < sample_frac < 1:
            frame = frame.sample(frac=sample_frac, random_state=random_state)

        frame["Label"] = frame["Label"].map(lambda item: normalize_label(item, mode))
        frames.append(frame)
        print(f"Loaded {csv_file.name}: {len(frame):,} rows")

    dataset = pd.concat(frames, ignore_index=True)
    dataset = dataset.replace([np.inf, -np.inf], np.nan)
    dataset.columns = [column.strip() for column in dataset.columns]
    return dataset


def clean_dataset(dataset: pd.DataFrame) -> pd.DataFrame:
    cleaned = dataset.copy()
    cleaned = cleaned.drop_duplicates()
    return cleaned


def split_features_and_target(
    dataset: pd.DataFrame,
    drop_identifier_columns: bool = True,
) -> tuple[pd.DataFrame, pd.Series]:
    columns_to_drop: list[str] = ["Label"]

    if drop_identifier_columns:
        columns_to_drop.extend(
            [column for column in IDENTIFIER_COLUMNS if column in dataset.columns]
        )

    x = dataset.drop(columns=columns_to_drop)
    y = dataset["Label"]
    return x, y


def summarize_dataset(dataset: pd.DataFrame) -> None:
    print(f"\nDataset shape: {dataset.shape}")
    print("\nLabel distribution:")
    print(dataset["Label"].value_counts())

    missing = dataset.isna().sum()
    missing = missing[missing > 0].sort_values(ascending=False)
    if not missing.empty:
        print("\nColumns with missing values:")
        print(missing.head(10))
    else:
        print("\nNo missing values found.")
