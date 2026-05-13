from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from anomaly_detection import build_pipeline as build_anomaly_pipeline
from data_preparation import clean_dataset, load_dataset, split_features_and_target
from train_ids_model import get_stratify_labels
from train_ids_model import build_pipeline as build_classifier_pipeline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train a simple arbiter that combines supervised classification and anomaly detection."
    )
    parser.add_argument("--data-dir", type=Path, default=Path("8263181"))
    parser.add_argument("--sample-frac", type=float, default=0.02)
    parser.add_argument("--max-records-per-file", type=int, default=None)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dataset = load_dataset(
        data_dir=args.data_dir,
        mode="family",
        sample_frac=args.sample_frac,
        random_state=args.random_state,
        max_records_per_file=args.max_records_per_file,
    )
    dataset = clean_dataset(dataset)
    x, y = split_features_and_target(dataset)

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    stratify_labels = get_stratify_labels(y_encoded)
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y_encoded,
        test_size=0.2,
        random_state=args.random_state,
        stratify=stratify_labels,
    )

    classifier = build_classifier_pipeline(x, random_state=args.random_state, n_estimators=200)
    classifier.fit(x_train, y_train)

    benign_label_id = int(np.where(label_encoder.classes_ == "BENIGN")[0][0])
    anomaly_train_mask = y_train == benign_label_id
    anomaly_model = build_anomaly_pipeline(
        x=x_train.loc[anomaly_train_mask],
        random_state=args.random_state,
        contamination=0.12,
    )
    anomaly_model.fit(x_train.loc[anomaly_train_mask])

    classifier_pred = classifier.predict(x_test)
    classifier_proba = classifier.predict_proba(x_test)
    anomaly_scores = -anomaly_model.decision_function(x_test)
    anomaly_flags = np.where(anomaly_model.predict(x_test) == -1, 1, 0)

    arbiter_pred = classifier_pred.copy()
    classifier_confidence = classifier_proba.max(axis=1)
    suspicious_mask = (
        (classifier_pred == benign_label_id)
        & (anomaly_flags == 1)
        & (classifier_confidence < 0.90)
    )

    attack_probabilities = classifier_proba.copy()
    attack_probabilities[:, benign_label_id] = -1
    fallback_attack = attack_probabilities.argmax(axis=1)
    arbiter_pred[suspicious_mask] = fallback_attack[suspicious_mask]

    report_text = classification_report(
        y_test,
        arbiter_pred,
        labels=list(range(len(label_encoder.classes_))),
        target_names=label_encoder.classes_,
        zero_division=0,
    )
    confusion = confusion_matrix(
        y_test,
        arbiter_pred,
        labels=list(range(len(label_encoder.classes_))),
    )

    result_dir = args.output_dir / "wazuh_arbiter"
    result_dir.mkdir(parents=True, exist_ok=True)
    (result_dir / "classification_report.txt").write_text(report_text, encoding="utf-8")
    pd.DataFrame(confusion).to_csv(result_dir / "confusion_matrix.csv", index=False)
    (result_dir / "metrics.json").write_text(
        json.dumps(
            {
                "dataset_type": "wazuh_alerts_8263181",
                "mode": "family_arbiter",
                "sample_frac": args.sample_frac,
                "max_records_per_file": args.max_records_per_file,
                "test_rows": int(len(x_test)),
                "arbiter_reassigned_rows": int(suspicious_mask.sum()),
                "classes": label_encoder.classes_.tolist(),
                "mean_anomaly_score": float(anomaly_scores.mean()),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print(report_text)
    print(f"Saved outputs to: {result_dir}")


if __name__ == "__main__":
    main()
