from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from data_preparation import clean_dataset, load_dataset, split_features_and_target, summarize_dataset


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train an anomaly-detection layer on 8263181 Wazuh alerts."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("8263181"),
        help="Directory containing labels.csv and ait_ads/*.json.",
    )
    parser.add_argument(
        "--sample-frac",
        type=float,
        default=0.02,
        help="Fraction of Wazuh events sampled from each file.",
    )
    parser.add_argument(
        "--max-records-per-file",
        type=int,
        default=None,
        help="Optional hard cap on the number of sampled records per file.",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed.",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.12,
        help="Expected fraction of anomalies for IsolationForest.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results"),
        help="Directory where reports, metrics, and trained models will be saved.",
    )
    return parser.parse_args()


def build_pipeline(x: pd.DataFrame, random_state: int, contamination: float) -> Pipeline:
    numeric_columns = x.select_dtypes(include=[np.number]).columns.tolist()
    categorical_columns = [column for column in x.columns if column not in numeric_columns]

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "num",
                Pipeline([("imputer", SimpleImputer(strategy="median"))]),
                numeric_columns,
            ),
            (
                "cat",
                Pipeline(
                    [
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("encoder", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                categorical_columns,
            ),
        ]
    )

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )

    return Pipeline([("preprocessor", preprocessor), ("model", model)])


def save_outputs(
    output_dir: Path,
    metrics: dict[str, object],
    report_text: str,
    confusion: np.ndarray,
    pipeline: Pipeline,
) -> None:
    result_dir = output_dir / "wazuh_anomaly"
    result_dir.mkdir(parents=True, exist_ok=True)

    (result_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (result_dir / "classification_report.txt").write_text(report_text, encoding="utf-8")
    pd.DataFrame(
        confusion,
        index=["true_benign", "true_attack"],
        columns=["pred_benign", "pred_attack"],
    ).to_csv(result_dir / "confusion_matrix.csv")
    joblib.dump(pipeline, result_dir / "model.joblib")


def main() -> None:
    args = parse_args()

    dataset = load_dataset(
        data_dir=args.data_dir,
        mode="binary",
        sample_frac=args.sample_frac,
        random_state=args.random_state,
        max_records_per_file=args.max_records_per_file,
    )
    dataset = clean_dataset(dataset)
    summarize_dataset(dataset)

    x, y = split_features_and_target(dataset)
    y_binary = (y == "ATTACK").astype(int)

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y_binary,
        test_size=0.2,
        random_state=args.random_state,
        stratify=y_binary,
    )

    x_train_benign = x_train.loc[y_train == 0]
    pipeline = build_pipeline(
        x=x_train_benign,
        random_state=args.random_state,
        contamination=args.contamination,
    )
    pipeline.fit(x_train_benign)

    predicted_raw = pipeline.predict(x_test)
    anomaly_pred = np.where(predicted_raw == -1, 1, 0)
    anomaly_scores = -pipeline.decision_function(x_test)

    accuracy = accuracy_score(y_test, anomaly_pred)
    f1_binary = f1_score(y_test, anomaly_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, anomaly_scores)
    confusion = confusion_matrix(y_test, anomaly_pred, labels=[0, 1])
    report_text = classification_report(
        y_test,
        anomaly_pred,
        labels=[0, 1],
        target_names=["BENIGN", "ATTACK"],
        zero_division=0,
    )

    print(f"\nBenign training rows: {len(x_train_benign):,}")
    print(f"Test rows: {len(x_test):,}")
    print(f"\nAccuracy: {accuracy:.4f}")
    print(f"F1-score: {f1_binary:.4f}")
    print(f"AUC-ROC: {roc_auc:.4f}")
    print("\nClassification report:")
    print(report_text)
    print("Confusion matrix:")
    print(confusion)

    metrics = {
        "dataset_type": "wazuh_alerts_8263181",
        "mode": "binary_anomaly",
        "sample_frac": args.sample_frac,
        "max_records_per_file": args.max_records_per_file,
        "random_state": args.random_state,
        "contamination": args.contamination,
        "dataset_rows": int(len(dataset)),
        "train_rows": int(len(x_train)),
        "benign_train_rows": int(len(x_train_benign)),
        "test_rows": int(len(x_test)),
        "accuracy": float(accuracy),
        "f1_score": float(f1_binary),
        "auc_roc": float(roc_auc),
        "label_distribution": {
            "BENIGN": int((y_binary == 0).sum()),
            "ATTACK": int((y_binary == 1).sum()),
        },
    }
    save_outputs(
        output_dir=args.output_dir,
        metrics=metrics,
        report_text=report_text,
        confusion=confusion,
        pipeline=pipeline,
    )
    print(f"\nSaved outputs to: {args.output_dir / 'wazuh_anomaly'}")


if __name__ == "__main__":
    main()
