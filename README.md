# Arbiter Model for Cybersecurity

This project builds a machine learning pipeline for cybersecurity alert analysis using the `8263181` dataset.

The dataset is based on:

- `Wazuh` alert logs in JSON format
- scenario labels from `labels.csv`

The project goal is to classify cybersecurity events into attack categories and support an `Arbiter Model` for final decision-making.

## Dataset

Main dataset folder:

- [8263181](./8263181)

Important files:

- [8263181/labels.csv](./8263181/labels.csv)
- `8263181/ait_ads/*_wazuh.json`

## Attack Classes Found

The dataset contains labeled attack windows for:

- `network_scans`
- `service_scans`
- `dirb`
- `wpscan`
- `webshell`
- `cracking`
- `reverse_shell`
- `privilege_escalation`
- `service_stop`
- `dnsteal`

In the machine learning pipeline, these can be used as:

- `multiclass` attack labels
- grouped `family` labels such as:
  - `WebAttack`
  - `Scanning`
  - `CredentialAccess`
  - `Exfiltration`
  - `PrivilegeEscalation`
  - `Execution`

## Project Structure

- [src/data_preparation.py](./src/data_preparation.py): load Wazuh JSON files, map timestamps to scenario labels, clean the dataset
- [src/train_ids_model.py](./src/train_ids_model.py): supervised classifier training
- [src/anomaly_detection.py](./src/anomaly_detection.py): anomaly detection with `IsolationForest`
- [src/arbiter_model.py](./src/arbiter_model.py): simple arbiter combining classifier and anomaly detector
- [src/evaluate_model.py](./src/evaluate_model.py): read saved metrics
- [docs](./docs): Cyber-Data Science Process notes
- [results](./results): saved model outputs

## Requirements

Install dependencies:

```powershell
pip install -r requirements.txt
```

## Main Training Commands

### 1. Family Attack Classifier

Recommended main model:

```powershell
python .\src\train_ids_model.py --data-dir .\8263181 --mode family --drop-benign --min-class-count 20 --output-dir .\results
```

### 2. Exact Attack-Type Classifier

```powershell
python .\src\train_ids_model.py --data-dir .\8263181 --mode multiclass --drop-benign --min-class-count 20 --output-dir .\results
```

### 3. Anomaly Detection Layer

```powershell
python .\src\anomaly_detection.py --data-dir .\8263181 --output-dir .\results
```

### 4. Arbiter Model

```powershell
python .\src\arbiter_model.py --data-dir .\8263181 --output-dir .\results
```

## Current Best Model

The most stable model for this dataset is the `family` classifier trained without `BENIGN` and with rare classes removed.

Saved outputs:

- [results/wazuh_family/metrics.json](./results/wazuh_family/metrics.json)
- [results/wazuh_family/classification_report.txt](./results/wazuh_family/classification_report.txt)
- [results/wazuh_family/confusion_matrix.csv](./results/wazuh_family/confusion_matrix.csv)
- [results/wazuh_family/top_features.csv](./results/wazuh_family/top_features.csv)

## Notes

- labels are assigned by matching each Wazuh event timestamp to the attack windows in `labels.csv`
- some attack classes are extremely rare and may be dropped during training
- the `family` model is more stable than the raw full attack-label model
- anomaly detection is weaker than the supervised classifier, but it is useful as part of the arbiter design

## Authoring Workflow

For this PFE project, the recommended order is:

1. analyze the dataset
2. train the `family` classifier
3. evaluate performance
4. compare with anomaly detection
5. integrate the arbiter model
