# Full Pipeline Documentation

Complete technical reference for the Wazuh alert classification system.

---

## Table of Contents

1. [Project Goal](#1-project-goal)
2. [Dataset](#2-dataset)
3. [Data Preparation](#3-data-preparation)
4. [Feature Extraction](#4-feature-extraction)
5. [Label Modes](#5-label-modes)
6. [Supervised Classifier — Random Forest](#6-supervised-classifier--random-forest)
7. [Anomaly Detection — IsolationForest](#7-anomaly-detection--isolationforest)
8. [Arbiter Model](#8-arbiter-model)
9. [Live Prediction](#9-live-prediction)
10. [Results Summary](#10-results-summary)
11. [How to Run](#11-how-to-run)
12. [File Reference](#12-file-reference)

---

## 1. Project Goal

Automatically classify Wazuh SIEM alerts into attack categories using machine learning, without requiring manual analyst review for every alert.

The system answers two questions for every incoming alert:

- **Is this alert an attack or normal traffic?** → answered by the anomaly detector
- **What type of attack is it?** → answered by the supervised classifier

A third component, the **arbiter**, combines both answers into a final verdict.

---

## 2. Dataset

### Source

The `8263181` dataset — a labeled collection of Wazuh JSON alert logs from the AIT-ADS (Attack Investigation Tool — Attack Dataset Simulator) project. It simulates 8 users on a corporate network under various attack scenarios.

### Files

```
8263181/
├── labels.csv                  ← attack time windows per scenario
└── ait_ads/
    ├── fox_wazuh.json          ← Wazuh alerts for user "fox"
    ├── harrison_wazuh.json     ← Wazuh alerts for user "harrison"
    ├── russellmitchell_wazuh.json
    ├── santos_wazuh.json
    ├── shaw_wazuh.json
    ├── wardbeck_wazuh.json
    ├── wheeler_wazuh.json
    └── wilson_wazuh.json
```

Each `*_wazuh.json` file contains one JSON object per line (NDJSON format).

### labels.csv structure

```
scenario,start,end,attack
fox,1583000000.0,1583003600.0,network_scans
fox,1583007200.0,1583010800.0,webshell
harrison,1583000000.0,1583003600.0,cracking
...
```

Each row defines an attack window: alerts from `scenario` between `start` and `end` (Unix timestamps) are labeled `attack`. Everything outside a window is labeled `BENIGN`.

### Attack types in the dataset

| Raw label | Family label |
|---|---|
| `BENIGN` | BENIGN |
| `network_scans` | Scanning |
| `service_scans` | Scanning |
| `dirb` | WebAttack |
| `wpscan` | WebAttack |
| `webshell` | WebAttack |
| `cracking` | CredentialAccess |
| `reverse_shell` | Execution |
| `privilege_escalation` | PrivilegeEscalation |
| `service_stop` | Impact |
| `dnsteal` | Exfiltration |

---

## 3. Data Preparation

**File:** [`src/data_preparation.py`](../src/data_preparation.py)

This module does all the heavy lifting before training starts.

### Step 1 — Load labels

```python
labels = load_labels(data_dir)          # reads labels.csv
label_index = build_label_index(labels) # builds a dict: scenario → [(start, end, attack), ...]
```

The label index is a lookup structure:

```python
{
  "fox": [(1583000000.0, 1583003600.0, "network_scans"),
          (1583007200.0, 1583010800.0, "webshell"), ...],
  "harrison": [...]
}
```

### Step 2 — Match each alert to its label

For every Wazuh event, the function `lookup_attack()` extracts the event's Unix timestamp and checks whether it falls inside any attack window for that scenario:

```python
def lookup_attack(scenario, event_timestamp, label_index):
    for start, end, attack in label_index.get(scenario, []):
        if start <= event_timestamp <= end:
            return attack
    return "BENIGN"
```

**Example:**
- Event timestamp: `1583001800.0` in scenario `fox`
- Falls inside window `(1583000000.0, 1583003600.0, "network_scans")`
- Label assigned: `network_scans`

### Step 3 — Sample events (speed control)

Reading all events from all files would be too slow. The `sample_frac` parameter randomly keeps a fraction of events:

```python
load_dataset(data_dir, sample_frac=0.02)  # keep 2% of events
```

With `sample_frac=0.02` and the 8263181 dataset, ~51,000 events are loaded.

### Step 4 — Clean the dataset

```python
dataset = clean_dataset(dataset)
```

- Removes duplicate rows
- Drops columns where more than 98% of values are missing (too sparse to be useful)

---

## 4. Feature Extraction

**File:** [`src/data_preparation.py`](../src/data_preparation.py) — `extract_wazuh_features()`

Each Wazuh JSON event is flattened into a fixed set of 36 features:

### Numeric features (15)

| Feature | Source in JSON | Description |
|---|---|---|
| `timestamp_hour` | `@timestamp` | Hour of day (0–23) |
| `timestamp_weekday` | `@timestamp` | Day of week (0=Mon, 6=Sun) |
| `agent_id` | `agent.id` | Agent ID number |
| `rule_id` | `rule.id` | Wazuh rule number |
| `rule_level` | `rule.level` | Alert severity (0–15) |
| `rule_firedtimes` | `rule.firedtimes` | How many times this rule fired |
| `rule_mail` | `rule.mail` | Whether email alert was sent (0/1) |
| `data_src_port` | `data.src_port` | Source port |
| `data_dest_port` | `data.dest_port` | Destination port |
| `data_alert_signature_id` | `data.alert.signature_id` | Suricata signature ID |
| `data_alert_severity` | `data.alert.severity` | Suricata severity |
| `data_flow_pkts_toserver` | `data.flow.pkts_toserver` | Packets sent to server |
| `data_flow_pkts_toclient` | `data.flow.pkts_toclient` | Packets sent to client |
| `data_flow_bytes_toserver` | `data.flow.bytes_toserver` | Bytes sent to server |
| `data_flow_bytes_toclient` | `data.flow.bytes_toclient` | Bytes sent to client |

### Categorical features (17)

| Feature | Source in JSON | Example values |
|---|---|---|
| `scenario` | filename | fox, harrison, santos |
| `location` | `location` | /var/log/auth.log |
| `input_type` | `input.type` | log |
| `agent_name` | `agent.name` | ubuntu |
| `predecoder_hostname` | `predecoder.hostname` | mail, ubuntu |
| `predecoder_program_name` | `predecoder.program_name` | sshd, kernel, sudo |
| `decoder_name` | `decoder.name` | sshd, web-accesslog, pam |
| `decoder_parent` | `decoder.parent` | sshd, kernel |
| `rule_description` | `rule.description` | "Port scan detected" |
| `rule_groups` | `rule.groups` (joined with `\|`) | web\|accesslog\|attack |
| `data_event_type` | `data.event_type` | alert |
| `data_app_proto` | `data.app_proto` | http, dns |
| `data_proto` | `data.proto` | TCP, UDP |
| `data_srcip` | `data.srcip` | 10.237.1.238 |
| `data_dstip` | `data.dstip` | 10.182.193.181 |
| `data_alert_category` | `data.alert.category` | Web Application Attack |
| `data_alert_action` | `data.alert.action` | allowed, blocked |

### Feature example — port scan event

```json
{
  "@timestamp": "2026-05-22T10:28:20.000+0000",
  "location": "/var/log/iptables.log",
  "predecoder": { "program_name": "kernel" },
  "decoder": { "parent": "kernel", "name": "kernel" },
  "rule": { "id": "100200", "level": 8, "firedtimes": 1, "groups": ["iptables","portscan","recon"] },
  "data": { "srcip": "192.168.1.50", "dstip": "192.168.1.212", "src_port": "33444", "dest_port": "9999" }
}
```

Becomes:

```python
{
  "timestamp_hour": 10,       "timestamp_weekday": 4,
  "rule_id": 100200,          "rule_level": 8,
  "rule_firedtimes": 1,       "rule_mail": 0,
  "data_src_port": 33444,     "data_dest_port": 9999,
  "location": "/var/log/iptables.log",
  "predecoder_program_name": "kernel",
  "decoder_name": "kernel",   "decoder_parent": "kernel",
  "rule_description": "iptables: Port scan detected",
  "rule_groups": "iptables|portscan|recon",
  "data_srcip": "192.168.1.50",
  "data_dstip": "192.168.1.212",
  # all other features → NaN
  "Label": "Scanning"
}
```

---

## 5. Label Modes

The pipeline supports three labeling modes controlled by `--mode`:

### binary

Every alert is either `BENIGN` or `ATTACK`.

```
network_scans → ATTACK
webshell      → ATTACK
BENIGN        → BENIGN
```

Used by: anomaly detection training.

### multiclass

Keep the exact raw attack label.

```
network_scans → network_scans
webshell      → webshell
cracking      → cracking
BENIGN        → BENIGN
```

Used by: `wazuh_multiclass` model.

### family

Group raw labels into broader attack families.

```
network_scans  → Scanning
service_scans  → Scanning
dirb           → WebAttack
wpscan         → WebAttack
webshell       → WebAttack
cracking       → CredentialAccess
dnsteal        → Exfiltration
reverse_shell  → Execution
BENIGN         → BENIGN
```

Used by: the best model `wazuh_family`.

---

## 6. Supervised Classifier — Random Forest

**File:** [`src/train_ids_model.py`](../src/train_ids_model.py)

### Algorithm

**Random Forest** — an ensemble of 200 decision trees, each trained on a random subset of data and features. Final prediction = majority vote across all trees.

### Preprocessing pipeline (sklearn Pipeline)

```
Raw DataFrame (36 columns, mixed types)
        │
        ▼
ColumnTransformer
    ├── Numeric columns (15)
    │       └── SimpleImputer(strategy="median")   ← fills NaN with median
    └── Categorical columns (17)
            ├── SimpleImputer(strategy="most_frequent")  ← fills NaN with mode
            └── OneHotEncoder(handle_unknown="ignore")   ← converts to binary columns
        │
        ▼
RandomForestClassifier(
    n_estimators=200,
    class_weight="balanced_subsample",   ← compensates for class imbalance
    n_jobs=-1                            ← uses all CPU cores
)
```

### Train/test split

```
Total dataset: 45,053 rows
    ├── Train: 36,042 rows (80%)
    └── Test:   9,011 rows (20%)
```

Stratified split — each class keeps the same proportion in train and test.

### Class filtering

Rare classes (< 20 samples) are automatically dropped before training.
`PrivilegeEscalation` (5 samples) and `Execution` (1 sample) were dropped.

### Training command

```powershell
python .\src\train_ids_model.py `
    --data-dir .\8263181 `
    --mode family `
    --drop-benign `
    --min-class-count 20 `
    --output-dir .\results
```

### Results

```
                  precision    recall    f1-score   support
CredentialAccess    0.99       0.99        0.99       622
Exfiltration        0.99       1.00        0.99       636
Scanning            0.99       0.99        0.99       614
WebAttack           1.00       1.00        1.00      7139

accuracy                                   1.00      9011
macro avg           0.99       1.00        0.99      9011
```

| Metric | Value |
|---|---|
| Accuracy | **99.80%** |
| F1 macro | **99.50%** |
| F1 weighted | **99.80%** |
| AUC-ROC | **99.99%** |

### Top 10 most important features

| Feature | Importance |
|---|---|
| `rule_id` | 7.67% |
| `rule_firedtimes` | 4.27% |
| `location_/var/log/apache2/intranet-access.log` | 4.09% |
| `decoder_name_web-accesslog` | 4.04% |
| `agent_id` | 3.72% |
| `predecoder_program_name_kernel` | 3.71% |
| `data_dest_port` | 3.34% |
| `predecoder_program_name_named` | 3.17% |
| `predecoder_program_name_suricata` | 3.07% |
| `data_flow_bytes_toclient` | 2.85% |

### Saved outputs

```
results/wazuh_family/
├── model.joblib                ← trained pipeline (preprocessor + RandomForest)
├── label_encoder.joblib        ← maps class names ↔ integers
├── metrics.json                ← all scores and config
├── classification_report.txt   ← per-class precision/recall/F1
├── confusion_matrix.csv        ← prediction matrix
└── top_features.csv            ← feature importance ranking
```

---

## 7. Anomaly Detection — IsolationForest

**File:** [`src/anomaly_detection.py`](../src/anomaly_detection.py)

### Why anomaly detection?

The supervised classifier needs labeled data to train. Anomaly detection is **unsupervised** — it learns only what normal (BENIGN) traffic looks like, then flags anything that deviates.

This makes it useful as a second opinion on alerts the classifier is uncertain about, and as a safety net for attack patterns never seen in training.

### Algorithm — IsolationForest

IsolationForest works by randomly building trees that try to isolate each data point. Anomalies (rare, unusual) are isolated faster (fewer splits needed) and get a high anomaly score. Normal points need many splits and get a low score.

```
Score > threshold  →  ATTACK (anomalous)
Score ≤ threshold  →  BENIGN (normal)
```

### Key design choices

#### Train on BENIGN only

```python
x_train_benign = x_train.loc[y_train == 0]   # keep only BENIGN rows
pipeline.fit(x_train_benign)                  # learn what "normal" looks like
```

The model never sees attack data during training. It learns the distribution of normal alerts and flags deviations.

#### Threshold tuning (critical fix)

The naive approach uses `contamination=0.12`, which means "assume 12% of data is anomalous." But the real attack rate is 66%. This makes the threshold completely wrong.

**Solution:** use a labeled validation split to find the best threshold by maximising F1:

```python
# 60 / 20 / 20 split
x_temp, x_test   = train_test_split(..., test_size=0.20)
x_train, x_val   = train_test_split(x_temp, test_size=0.25)

# train on benign only
pipeline.fit(x_train_benign)

# tune threshold on the labeled validation set
val_scores = -pipeline.decision_function(x_val)
best_threshold = tune_threshold(val_scores, y_val)
# → best_threshold = -0.1558
```

`tune_threshold()` iterates over all candidate thresholds from the ROC curve and picks the one with the highest F1 score on the validation set.

### Results (before vs after threshold tuning)

| Metric | Before (contamination=0.12) | After (tuned threshold) |
|---|---|---|
| Accuracy | 29.9% | **83.9%** |
| F1 (ATTACK) | 0.00 | **0.889** |
| AUC-ROC | 0.629 | 0.650 |

```
              precision    recall    f1-score   support
BENIGN           0.92       0.58        0.71      3517
ATTACK           0.82       0.97        0.89      6812

accuracy                               0.84     10329
```

### Saved outputs

```
results/wazuh_anomaly/
├── model.joblib                ← trained IsolationForest pipeline
├── metrics.json                ← scores + tuned_threshold (-0.1558)
├── classification_report.txt
└── confusion_matrix.csv
```

### Training command

```powershell
python .\src\anomaly_detection.py `
    --data-dir .\8263181 `
    --output-dir .\results
```

---

## 8. Arbiter Model

**File:** [`src/arbiter_model.py`](../src/arbiter_model.py)

### Purpose

Combine the supervised classifier and the anomaly detector into a single, more reliable decision. The arbiter uses the anomaly detector as a **safety net** for alerts the classifier is uncertain about.

### Decision logic

```
IF   classifier predicts BENIGN
AND  anomaly detector flags the alert as suspicious
AND  classifier confidence < 90%
THEN override → assign the most probable ATTACK class

ELSE keep the classifier's original prediction
```

In code:

```python
suspicious_mask = (
    (classifier_pred == benign_label_id)    # classifier said BENIGN
    & (anomaly_flags == 1)                  # anomaly detector disagrees
    & (classifier_confidence < 0.90)        # classifier is not sure
)

# pick the highest-probability attack class (exclude BENIGN)
attack_probabilities = classifier_proba.copy()
attack_probabilities[:, benign_label_id] = -1
fallback_attack = attack_probabilities.argmax(axis=1)

arbiter_pred[suspicious_mask] = fallback_attack[suspicious_mask]
```

### Example — arbiter overrides

```
Alert: rule_level=5, rule_firedtimes=2, decoder=kernel, src_port=4444

Classifier:  BENIGN  (confidence 71%)
Anomaly:     SUSPICIOUS

→ All 3 conditions met → OVERRIDE

Arbiter final: WebAttack
```

### Example — arbiter does NOT override

```
Alert: rule_level=12, decoder=web-accesslog, rule_groups=web|accesslog|attack

Classifier:  WebAttack  (confidence 99%)
Anomaly:     SUSPICIOUS

→ Classifier did not say BENIGN → NO OVERRIDE

Arbiter final: WebAttack  (unchanged)
```

### When each model wins

| Classifier | Anomaly | Confidence | Arbiter result |
|---|---|---|---|
| BENIGN | suspicious | < 90% | **Override → attack class** |
| BENIGN | suspicious | ≥ 90% | Keep BENIGN |
| BENIGN | normal | any | Keep BENIGN |
| Attack | any | any | Keep attack class |

### Results

In the test set of 10,329 alerts, the arbiter **reassigned 14 alerts** from BENIGN to an attack class. These are the exact cases where the classifier was uncertain and the anomaly detector caught something suspicious.

### Training command

```powershell
python .\src\arbiter_model.py `
    --data-dir .\8263181 `
    --output-dir .\results
```

---

## 9. Live Prediction

**Files:** [`src/predict_live.py`](../src/predict_live.py) — [`src/test_mixed.py`](../src/test_mixed.py)

### How a live alert is classified

Each incoming Wazuh alert goes through the same feature extraction as training data, then through both models:

```
Wazuh JSON alert
      │
      ▼
Feature extraction (36 columns)
      │
      ├──────────────────────────────────┐
      ▼                                  ▼
Family Classifier                 Anomaly Detector
(Random Forest)                   (IsolationForest)
      │                                  │
      │  class + confidence              │  anomaly score
      └─────────────┬────────────────────┘
                    ▼
             Dual-signal combiner
             ┌────────────────────────────────────────────┐
             │ IF anomaly_score >= -0.1558                │
             │ OR family_confidence >= 97%                │
             │ THEN verdict = family_class (ATTACK)       │
             │ ELSE verdict = BENIGN                      │
             └────────────────────────────────────────────┘
                    │
                    ▼
             Final verdict + severity
```

### Live test results — 10 mixed alerts

| # | Alert | True Class | Anomaly | Confidence | Verdict | Correct |
|---|---|---|---|---|---|---|
| 1 | SSH login success | BENIGN | NO | 90% | BENIGN | YES |
| 2 | Normal web GET 200 | BENIGN | NO | 96% | BENIGN | YES |
| 3 | APT package update | BENIGN | NO | 50% | BENIGN | YES |
| 4 | Nmap OS detection | Scanning | NO | 55% | BENIGN | NO |
| 5 | iptables port scan | Scanning | NO | 100% | Scanning | YES |
| 6 | SSH brute force | CredentialAccess | NO | 100% | CredentialAccess | YES |
| 7 | PAM login failed | CredentialAccess | NO | 80% | BENIGN | NO |
| 8 | DNS tunneling | Exfiltration | YES | 100% | Exfiltration | YES |
| 9 | SQL injection | WebAttack | NO | 98% | WebAttack | YES |
| 10 | Web shell | WebAttack | NO | 99% | WebAttack | YES |

**Score: 8/10**

### Why logs 4 and 7 fail

**Log 4 — Nmap via suricata (55% confidence):**
The `suricata` decoder is shared between Scanning and Exfiltration alerts. Without specific Nmap-only features, the model splits its vote. Confidence stays below 97%, anomaly detector sees nothing unusual → verdict = BENIGN.

**Log 7 — Single PAM failure (80% confidence):**
A single authentication failure shares the same `location`, `decoder`, and `program_name` as a successful SSH login. The difference is only in `rule_id` and `rule_level`, which is not strong enough to push confidence above 97%.

Both cases represent an **inherent trade-off**: lowering the threshold from 97% would fix these two but would mislabel normal SSH logins (Log 1, 90% confidence) as CredentialAccess.

### How to run live prediction

```powershell
# test the 6 pre-defined real alerts
python .\src\predict_live.py

# test all 10 mixed alerts (BENIGN + attacks + edge cases)
python .\src\test_mixed.py
```

---

## 10. Results Summary

### Model comparison

| Model | Type | Accuracy | F1 Macro | AUC-ROC |
|---|---|---|---|---|
| `wazuh_family` | Supervised — Random Forest | **99.80%** | **99.50%** | **99.99%** |
| `wazuh_multiclass` | Supervised — Random Forest | ~97% | ~85% | ~99% |
| `wazuh_anomaly` | Unsupervised — IsolationForest | 83.90% | 80.00% | 64.96% |
| `wazuh_arbiter` | Hybrid — RF + IsolationForest | depends on input | — | — |

### Why family > multiclass

The multiclass model tries to distinguish `network_scans` from `service_scans`, or `dirb` from `wpscan`. These look nearly identical in Wazuh alert features. Grouping them into families (Scanning, WebAttack) reduces noise and makes the classification problem easier and more stable.

### Live alert performance

| Alert type | Result | Confidence |
|---|---|---|
| Port scan (iptables) | CORRECT — Scanning | 100% |
| Nmap scan (suricata) | MISSED — edge case | 55% |
| SSH brute force | CORRECT — CredentialAccess | 100% |
| Unauthorized sudo | CORRECT — CredentialAccess | 97% |
| PAM failure (single) | MISSED — edge case | 80% |
| DNS tunneling | CORRECT — Exfiltration | 100% |
| SQL injection | CORRECT — WebAttack | 98.5% |
| Nikto web scanner | CORRECT — WebAttack | 94.5% |
| Web shell | CORRECT — WebAttack | 99% |

---

## 11. How to Run

### Prerequisites

```powershell
pip install -r requirements.txt
```

### Step-by-step training

#### 1. Family classifier (recommended — best model)

```powershell
python .\src\train_ids_model.py `
    --data-dir .\8263181 `
    --mode family `
    --drop-benign `
    --min-class-count 20 `
    --output-dir .\results
```

#### 2. Exact attack-type classifier

```powershell
python .\src\train_ids_model.py `
    --data-dir .\8263181 `
    --mode multiclass `
    --drop-benign `
    --min-class-count 20 `
    --output-dir .\results
```

#### 3. Anomaly detection layer

```powershell
python .\src\anomaly_detection.py `
    --data-dir .\8263181 `
    --output-dir .\results
```

#### 4. Arbiter model

```powershell
python .\src\arbiter_model.py `
    --data-dir .\8263181 `
    --output-dir .\results
```

### Evaluate saved models

```powershell
python .\src\evaluate_model.py --metrics-path .\results\wazuh_family\metrics.json
python .\src\evaluate_model.py --metrics-path .\results\wazuh_anomaly\metrics.json
python .\src\evaluate_model.py --metrics-path .\results\wazuh_arbiter\metrics.json
```

### Run live tests

```powershell
# 6 real-world alerts (port scan, sudo, SQLi, nikto, PAM, brute force)
python .\src\predict_live.py

# 10 mixed alerts (3 BENIGN + 7 attacks across all families)
python .\src\test_mixed.py
```

### CLI arguments reference

#### train_ids_model.py

| Argument | Default | Description |
|---|---|---|
| `--data-dir` | `8263181` | Dataset directory |
| `--mode` | `family` | `binary`, `multiclass`, or `family` |
| `--sample-frac` | `0.02` | Fraction of events to load (1.0 = all) |
| `--n-estimators` | `200` | Number of trees in the Random Forest |
| `--min-class-count` | `20` | Drop classes with fewer than N samples |
| `--drop-benign` | False | Exclude BENIGN from training |
| `--random-state` | `42` | Random seed for reproducibility |
| `--output-dir` | `results` | Where to save model and reports |

#### anomaly_detection.py

| Argument | Default | Description |
|---|---|---|
| `--data-dir` | `8263181` | Dataset directory |
| `--sample-frac` | `0.02` | Fraction of events to load |
| `--contamination` | `auto` | IsolationForest contamination (or `auto` to tune) |
| `--top-features` | None | Restrict to top-N features from family model |
| `--output-dir` | `results` | Where to save model and reports |

---

## 12. File Reference

```
cybersecurity_model-/
├── 8263181/                          ← dataset
│   ├── labels.csv                    ← attack time windows
│   └── ait_ads/                      ← raw Wazuh JSON logs
│       └── *_wazuh.json (x8)
│
├── src/                              ← source code
│   ├── data_preparation.py           ← load, label, extract features
│   ├── train_ids_model.py            ← train Random Forest classifier
│   ├── anomaly_detection.py          ← train IsolationForest detector
│   ├── arbiter_model.py              ← combine both models
│   ├── evaluate_model.py             ← print saved metrics
│   ├── predict_live.py               ← test individual live alerts
│   └── test_mixed.py                 ← test 10 mixed BENIGN + attack alerts
│
├── results/                          ← saved models and reports
│   ├── wazuh_family/                 ← best model (family classifier)
│   │   ├── model.joblib
│   │   ├── label_encoder.joblib
│   │   ├── metrics.json
│   │   ├── classification_report.txt
│   │   ├── confusion_matrix.csv
│   │   └── top_features.csv
│   ├── wazuh_multiclass/             ← exact attack-type classifier
│   ├── wazuh_anomaly/                ← IsolationForest detector
│   └── wazuh_arbiter/                ← combined arbiter results
│
├── docs/                             ← documentation
│   ├── pipeline.md                   ← this file
│   ├── arbiter_explained.md          ← arbiter logic with examples
│   └── mixed_test_logs.md            ← 10 test logs with expected results
│
├── README.md                         ← quick start guide
└── requirements.txt                  ← pandas, numpy, scikit-learn, joblib
```
