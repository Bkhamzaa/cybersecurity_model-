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
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, OneHotEncoder

from data_preparation import clean_dataset, load_dataset, split_features_and_target, summarize_dataset


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train a Wazuh alert classifier on the 8263181 dataset."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("8263181"),
        help="Directory containing labels.csv and ait_ads/*.json.",
    )
    parser.add_argument(
        "--mode",
        choices=("binary", "multiclass", "family"),
        default="family",
        help="Classification mode.",
    )
    parser.add_argument(
        "--sample-frac",
        type=float,
        default=0.02,
        help="Fraction of JSON events sampled from each Wazuh file.",
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
        "--n-estimators",
        type=int,
        default=200,
        help="Number of trees used by the Random Forest.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results"),
        help="Directory where reports, metrics, and trained models will be saved.",
    )
    parser.add_argument(
        "--min-class-count",
        type=int,
        default=20,
        help="Drop classes with fewer than this many samples after loading.",
    )
    parser.add_argument(
        "--drop-benign",
        action="store_true",
        help="Train only on attack samples and remove BENIGN from the dataset.",
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


def get_top_features(pipeline: Pipeline, x: pd.DataFrame, top_n: int = 20) -> pd.Series:
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


def compute_auc(
    label_encoder: LabelEncoder,
    y_test: np.ndarray,
    y_proba: np.ndarray,
) -> dict[str, float | None]:
    metrics: dict[str, float | None] = {
        "auc_roc": None,
        "auc_roc_weighted_ovr": None,
        "auc_roc_macro_ovo": None,
    }

    if len(label_encoder.classes_) == 2:
        metrics["auc_roc"] = float(roc_auc_score(y_test, y_proba[:, 1]))
        return metrics

    present_labels = sorted(np.unique(y_test).tolist())
    if len(present_labels) >= 2:
        aucs: list[float] = []
        for label_id in present_labels:
            y_true_binary = (y_test == label_id).astype(int)
            aucs.append(roc_auc_score(y_true_binary, y_proba[:, label_id]))
        metrics["auc_roc"] = float(np.mean(aucs))
        metrics["auc_roc_weighted_ovr"] = float(
            roc_auc_score(
                y_test,
                y_proba,
                multi_class="ovr",
                average="weighted",
                labels=list(range(len(label_encoder.classes_))),
            )
        )
        metrics["auc_roc_macro_ovo"] = float(
            roc_auc_score(
                y_test,
                y_proba,
                multi_class="ovo",
                average="macro",
                labels=list(range(len(label_encoder.classes_))),
            )
        )
    return metrics


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
    mode_dir = output_dir / f"wazuh_{mode}"
    mode_dir.mkdir(parents=True, exist_ok=True)

    (mode_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (mode_dir / "classification_report.txt").write_text(report_text, encoding="utf-8")
    pd.DataFrame(confusion).to_csv(mode_dir / "confusion_matrix.csv", index=False)
    top_features.rename("importance").to_csv(mode_dir / "top_features.csv", header=True)
    joblib.dump(pipeline, mode_dir / "model.joblib")
    joblib.dump(label_encoder, mode_dir / "label_encoder.joblib")


def get_stratify_labels(y_encoded: np.ndarray) -> np.ndarray | None:
    _, counts = np.unique(y_encoded, return_counts=True)
    if counts.min() < 2:
        print(
            "\nWarning: at least one class has fewer than 2 samples. "
            "Falling back to a non-stratified train/test split."
        )
        return None
    return y_encoded


def filter_training_labels(
    dataset: pd.DataFrame,
    min_class_count: int,
    drop_benign: bool,
) -> pd.DataFrame:
    filtered = dataset.copy()

    if drop_benign:
        filtered = filtered[filtered["Label"] != "BENIGN"].copy()

    counts = filtered["Label"].value_counts()
    keep_labels = counts[counts >= min_class_count].index
    dropped_labels = counts[counts < min_class_count]

    if not dropped_labels.empty:
        print("\nDropping rare classes:")
        for label, count in dropped_labels.items():
            print(f"- {label}: {count}")

    filtered = filtered[filtered["Label"].isin(keep_labels)].copy()
    if filtered.empty:
        raise ValueError("No rows remain after class filtering. Lower --min-class-count.")

    return filtered


def main() -> None:
    args = parse_args()

    dataset = load_dataset(
        data_dir=args.data_dir,
        mode=args.mode,
        sample_frac=args.sample_frac,
        random_state=args.random_state,
        max_records_per_file=args.max_records_per_file,
    )
    dataset = clean_dataset(dataset)
    dataset = filter_training_labels(
        dataset=dataset,
        min_class_count=args.min_class_count,
        drop_benign=args.drop_benign,
    )
    summarize_dataset(dataset)

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

    pipeline = build_pipeline(x, random_state=args.random_state, n_estimators=args.n_estimators)
    pipeline.fit(x_train, y_train)

    y_pred = pipeline.predict(x_test)
    y_proba = pipeline.predict_proba(x_test)
    labels = list(range(len(label_encoder.classes_)))
    accuracy = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average="macro", zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    auc_metrics = compute_auc(label_encoder, y_test, y_proba)
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
    print(f"F1 macro: {f1_macro:.4f}")
    print(f"F1 weighted: {f1_weighted:.4f}")
    if auc_metrics["auc_roc"] is not None:
        print(f"AUC-ROC: {auc_metrics['auc_roc']:.4f}")

    print("\nClassification report:")
    print(report_text)
    print("Confusion matrix:")
    print(confusion)
    print("\nTop feature importances:")
    print(top_features)

    metrics: dict[str, object] = {
        "dataset_type": "wazuh_alerts_8263181",
        "mode": args.mode,
        "sample_frac": args.sample_frac,
        "max_records_per_file": args.max_records_per_file,
        "random_state": args.random_state,
        "n_estimators": args.n_estimators,
        "min_class_count": args.min_class_count,
        "drop_benign": args.drop_benign,
        "dataset_rows": int(len(dataset)),
        "dataset_columns": int(dataset.shape[1]),
        "train_rows": int(len(x_train)),
        "test_rows": int(len(x_test)),
        "accuracy": float(accuracy),
        "f1_macro": float(f1_macro),
        "f1_weighted": float(f1_weighted),
        "classes": label_encoder.classes_.tolist(),
        "label_distribution": {str(k): int(v) for k, v in y.value_counts().items()},
    }
    metrics.update({key: value for key, value in auc_metrics.items() if value is not None})

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
    print(f"\nSaved outputs to: {args.output_dir / f'wazuh_{args.mode}'}")


if __name__ == "__main__":
    main()
