from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


WAZUH_SUFFIX = "_wazuh.json"

ATTACK_FAMILY_MAP = {
    "BENIGN": "BENIGN",
    "network_scans": "Scanning",
    "service_scans": "Scanning",
    "dirb": "WebAttack",
    "wpscan": "WebAttack",
    "webshell": "WebAttack",
    "cracking": "CredentialAccess",
    "reverse_shell": "Execution",
    "privilege_escalation": "PrivilegeEscalation",
    "service_stop": "Impact",
    "dnsteal": "Exfiltration",
}


def normalize_label(label: str, mode: str) -> str:
    value = str(label).strip()
    if mode == "binary":
        return "BENIGN" if value == "BENIGN" else "ATTACK"
    if mode == "family":
        return ATTACK_FAMILY_MAP.get(value, value)
    return value


def safe_get(data: dict[str, Any], *path: str, default: Any = None) -> Any:
    current: Any = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def normalize_value(value: Any) -> Any:
    if isinstance(value, list):
        return "|".join(str(item) for item in value)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped == "":
            return np.nan
        try:
            if "." in stripped:
                return float(stripped)
            return int(stripped)
        except ValueError:
            return stripped
    return value


def scenario_from_path(path: Path) -> str:
    if not path.name.endswith(WAZUH_SUFFIX):
        raise ValueError(f"Unsupported file name: {path.name}")
    return path.name[: -len(WAZUH_SUFFIX)]


def load_labels(data_dir: Path) -> pd.DataFrame:
    labels_path = data_dir / "labels.csv"
    if not labels_path.exists():
        raise FileNotFoundError(f"Missing labels file: {labels_path}")

    labels = pd.read_csv(labels_path)
    labels["start"] = labels["start"].astype(float)
    labels["end"] = labels["end"].astype(float)
    return labels.sort_values(["scenario", "start"]).reset_index(drop=True)


def build_label_index(labels: pd.DataFrame) -> dict[str, list[tuple[float, float, str]]]:
    label_index: dict[str, list[tuple[float, float, str]]] = {}
    for row in labels.itertuples(index=False):
        label_index.setdefault(row.scenario, []).append((row.start, row.end, row.attack))
    return label_index


def lookup_attack(
    scenario: str,
    event_timestamp: float,
    label_index: dict[str, list[tuple[float, float, str]]],
) -> str:
    for start, end, attack in label_index.get(scenario, []):
        if start <= event_timestamp <= end:
            return attack
    return "BENIGN"


def extract_wazuh_features(event: dict[str, Any], scenario: str, label: str) -> dict[str, Any]:
    timestamp = pd.to_datetime(event["@timestamp"], utc=True)
    features: dict[str, Any] = {
        "scenario": scenario,
        "timestamp_hour": int(timestamp.hour),
        "timestamp_weekday": int(timestamp.weekday()),
        "location": safe_get(event, "location"),
        "input_type": safe_get(event, "input", "type"),
        "agent_name": safe_get(event, "agent", "name"),
        "agent_id": safe_get(event, "agent", "id"),
        "predecoder_hostname": safe_get(event, "predecoder", "hostname"),
        "predecoder_program_name": safe_get(event, "predecoder", "program_name"),
        "decoder_name": safe_get(event, "decoder", "name"),
        "decoder_parent": safe_get(event, "decoder", "parent"),
        "rule_id": safe_get(event, "rule", "id"),
        "rule_level": safe_get(event, "rule", "level", default=0),
        "rule_description": safe_get(event, "rule", "description"),
        "rule_groups": normalize_value(safe_get(event, "rule", "groups", default=[])),
        "rule_firedtimes": safe_get(event, "rule", "firedtimes", default=0),
        "rule_mail": normalize_value(safe_get(event, "rule", "mail", default=False)),
        "data_event_type": safe_get(event, "data", "event_type"),
        "data_app_proto": safe_get(event, "data", "app_proto"),
        "data_proto": safe_get(event, "data", "proto"),
        "data_srcip": safe_get(event, "data", "srcip") or safe_get(event, "data", "src_ip"),
        "data_dstip": safe_get(event, "data", "dstip") or safe_get(event, "data", "dest_ip"),
        "data_src_port": safe_get(event, "data", "src_port"),
        "data_dest_port": safe_get(event, "data", "dest_port"),
        "data_alert_signature_id": safe_get(event, "data", "alert", "signature_id"),
        "data_alert_severity": safe_get(event, "data", "alert", "severity"),
        "data_alert_category": safe_get(event, "data", "alert", "category"),
        "data_alert_action": safe_get(event, "data", "alert", "action"),
        "data_http_hostname": safe_get(event, "data", "http", "hostname"),
        "data_http_method": safe_get(event, "data", "http", "http_method"),
        "data_http_status": safe_get(event, "data", "http", "status"),
        "data_dns_rrtype": safe_get(event, "data", "dns", "rrtype"),
        "data_flow_pkts_toserver": safe_get(event, "data", "flow", "pkts_toserver"),
        "data_flow_pkts_toclient": safe_get(event, "data", "flow", "pkts_toclient"),
        "data_flow_bytes_toserver": safe_get(event, "data", "flow", "bytes_toserver"),
        "data_flow_bytes_toclient": safe_get(event, "data", "flow", "bytes_toclient"),
        "Label": label,
    }
    return {key: normalize_value(value) for key, value in features.items()}


def load_csv_files(data_dir: Path) -> list[Path]:
    wazuh_files = sorted((data_dir / "ait_ads").glob(f"*{WAZUH_SUFFIX}"))
    if not wazuh_files:
        raise FileNotFoundError(f"No Wazuh JSON files found under {data_dir / 'ait_ads'}")
    return wazuh_files


def load_dataset(
    data_dir: Path,
    mode: str = "multiclass",
    sample_frac: float | None = None,
    random_state: int = 42,
    max_records_per_file: int | None = None,
) -> pd.DataFrame:
    labels = load_labels(data_dir)
    label_index = build_label_index(labels)
    rng = np.random.default_rng(random_state)
    records: list[dict[str, Any]] = []

    for wazuh_file in load_csv_files(data_dir):
        scenario = scenario_from_path(wazuh_file)
        kept = 0
        with wazuh_file.open("r", encoding="utf-8") as handle:
            for line in handle:
                if sample_frac is not None and 0 < sample_frac < 1 and rng.random() > sample_frac:
                    continue

                event = json.loads(line)
                event_timestamp = pd.to_datetime(event["@timestamp"], utc=True).timestamp()
                raw_label = lookup_attack(scenario, event_timestamp, label_index)
                label = normalize_label(raw_label, mode)
                records.append(extract_wazuh_features(event, scenario, label))
                kept += 1

                if max_records_per_file is not None and kept >= max_records_per_file:
                    break

        print(f"Loaded {wazuh_file.name}: {kept:,} events")

    if not records:
        raise ValueError("No records were loaded. Increase sample_frac or check the dataset path.")

    dataset = pd.DataFrame(records)
    dataset = dataset.replace([np.inf, -np.inf], np.nan)
    dataset.columns = [column.strip() for column in dataset.columns]
    return dataset


def clean_dataset(dataset: pd.DataFrame) -> pd.DataFrame:
    cleaned = dataset.copy()
    cleaned = cleaned.drop_duplicates()

    sparse_columns = [
        column
        for column in cleaned.columns
        if column != "Label" and cleaned[column].isna().mean() > 0.98
    ]
    if sparse_columns:
        cleaned = cleaned.drop(columns=sparse_columns)
    return cleaned


def split_features_and_target(dataset: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    x = dataset.drop(columns=["Label"])
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
