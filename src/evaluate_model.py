from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read saved metrics for the 8263181 Wazuh models."
    )
    parser.add_argument(
        "--metrics-path",
        type=Path,
        required=True,
        help="Path to a saved metrics.json file under results/.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    metrics = json.loads(args.metrics_path.read_text(encoding="utf-8"))
    for key, value in metrics.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
