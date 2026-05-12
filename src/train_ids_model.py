from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, OneHotEncoder

from data_preparation import clean_dataset, load_dataset, split_features_and_target, summarize_dataset


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train a baseline intrusion detection model on CIC-IDS-2018."
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
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed.",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=150,
        help="Number of trees used by the Random Forest.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results"),
        help="Directory where reports, metrics, and trained models will be saved.",
    )
    return parser.parse_args()


def build_pipeline(x: pd.DataFrame, random_state: int, n_estimators: int) -> Pipeline:
    numeric_columns = x.select_dtypes(include=[np.number]).columns.tolist()
    categorical_columns = [column for column in x.columns if column not in numeric_columns]

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "num",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="median")),
                    ]
                ),
                numeric_columns,
            ),
            (
                "cat",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("encoder", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                categorical_columns,
            ),
        ]
    )

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )

    return Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", model),
        ]
    )


def print_top_features(pipeline: Pipeline, x: pd.DataFrame, top_n: int = 15) -> None:
    numeric_columns = x.select_dtypes(include=[np.number]).columns.tolist()
    categorical_columns = [column for column in x.columns if column not in numeric_columns]

    preprocessor: ColumnTransformer = pipeline.named_steps["preprocessor"]
    model: RandomForestClassifier = pipeline.named_steps["model"]

    feature_names = list(numeric_columns)
    if categorical_columns:
        encoder: OneHotEncoder = (
            preprocessor.named_transformers_["cat"].named_steps["encoder"]
        )
        feature_names.extend(encoder.get_feature_names_out(categorical_columns).tolist())

    importances = pd.Series(model.feature_importances_, index=feature_names)
    print("\nTop feature importances:")
    print(importances.sort_values(ascending=False).head(top_n))


def get_top_features(pipeline: Pipeline, x: pd.DataFrame, top_n: int = 15) -> pd.Series:
    numeric_columns = x.select_dtypes(include=[np.number]).columns.tolist()
    categorical_columns = [column for column in x.columns if column not in numeric_columns]

    preprocessor: ColumnTransformer = pipeline.named_steps["preprocessor"]
    model: RandomForestClassifier = pipeline.named_steps["model"]

    feature_names = list(numeric_columns)
    if categorical_columns:
        encoder: OneHotEncoder = (
            preprocessor.named_transformers_["cat"].named_steps["encoder"]
        )
        feature_names.extend(encoder.get_feature_names_out(categorical_columns).tolist())

    importances = pd.Series(model.feature_importances_, index=feature_names)
    return importances.sort_values(ascending=False).head(top_n)


def save_outputs(
    output_dir: Path,
    mode: str,
    metrics: dict[str, object],
    report_text: str,
    confusion: np.ndarray,
    top_features: pd.Series,
    pipeline: Pipeline,
    label_encoder: LabelEncoder,
) -> None:
    mode_dir = output_dir / mode
    mode_dir.mkdir(parents=True, exist_ok=True)

    metrics_path = mode_dir / "metrics.json"
    report_path = mode_dir / "classification_report.txt"
    confusion_path = mode_dir / "confusion_matrix.csv"
    features_path = mode_dir / "top_features.csv"
    model_path = mode_dir / "model.joblib"
    encoder_path = mode_dir / "label_encoder.joblib"

    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    report_path.write_text(report_text, encoding="utf-8")
    pd.DataFrame(confusion).to_csv(confusion_path, index=False)
    top_features.rename("importance").to_csv(features_path, header=True)
    joblib.dump(pipeline, model_path)
    joblib.dump(label_encoder, encoder_path)


def main() -> None:
    args = parse_args()

    dataset = load_dataset(
        data_dir=args.data_dir,
        mode=args.mode,
        sample_frac=args.sample_frac,
        random_state=args.random_state,
    )
    dataset = clean_dataset(dataset)
    summarize_dataset(dataset)

    x, y = split_features_and_target(dataset)

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y_encoded,
        test_size=0.2,
        random_state=args.random_state,
        stratify=y_encoded,
    )

    pipeline = build_pipeline(
        x=x,
        random_state=args.random_state,
        n_estimators=args.n_estimators,
    )
    pipeline.fit(x_train, y_train)

    y_pred = pipeline.predict(x_test)
    accuracy = accuracy_score(y_test, y_pred)
    labels = list(range(len(label_encoder.classes_)))
    report_text = classification_report(
        y_test,
        y_pred,
        labels=labels,
        target_names=label_encoder.classes_,
        zero_division=0,
    )
    confusion = confusion_matrix(y_test, y_pred, labels=labels)
    top_features = get_top_features(pipeline, x)

    print("\nClasses:")
    for index, label in enumerate(label_encoder.classes_):
        print(f"{index}: {label}")

    print(f"\nAccuracy: {accuracy:.4f}")
    print("\nClassification report:")
    print(report_text)

    print("Confusion matrix:")
    print(confusion)

    print("\nTop feature importances:")
    print(top_features)

    metrics = {
        "mode": args.mode,
        "sample_frac": args.sample_frac,
        "random_state": args.random_state,
        "n_estimators": args.n_estimators,
        "dataset_rows": int(len(dataset)),
        "dataset_columns": int(dataset.shape[1]),
        "train_rows": int(len(x_train)),
        "test_rows": int(len(x_test)),
        "accuracy": float(accuracy),
        "classes": label_encoder.classes_.tolist(),
        "label_distribution": {str(k): int(v) for k, v in y.value_counts().items()},
    }
    save_outputs(
        output_dir=args.output_dir,
        mode=args.mode,
        metrics=metrics,
        report_text=report_text,
        confusion=confusion,
        top_features=top_features,
        pipeline=pipeline,
        label_encoder=label_encoder,
    )
    print(f"\nSaved outputs to: {args.output_dir / args.mode}")


if __name__ == "__main__":
    main()
