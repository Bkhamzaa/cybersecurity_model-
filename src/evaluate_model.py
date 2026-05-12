from __future__ import annotations

import argparse
from pathlib import Path

from train_ids_model import main as train_main


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Shortcut entry point for training and evaluating the baseline IDS model."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("dataset"),
        help="Directory containing the dataset CSV files.",
    )
    parser.add_argument(
        "--mode",
        choices=("binary", "multiclass", "family"),
        default="binary",
        help="Classification mode.",
    )
    parser.add_argument(
        "--sample-frac",
        type=float,
        default=0.05,
        help="Fraction of rows sampled from each CSV file.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    train_main()
