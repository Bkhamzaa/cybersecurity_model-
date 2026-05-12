# Step 2: Data Understanding

## Objective of This Step

The goal of this step is to understand the structure, content, and security relevance of the dataset before starting data preparation and modeling.

For this project, the selected dataset is `CIC-IDS-2018`, which contains labeled network flow records representing both normal traffic and multiple cyberattack scenarios.

## Dataset Location

Project dataset folder:

`C:\Users\Hamza\Desktop\amin\dataset`

## Files in the Dataset

The dataset currently contains 5 CSV files:

- `Friday-WorkingHours.csv`
- `Monday-WorkingHours.csv`
- `Thursday-WorkingHours.csv`
- `Tuesday-WorkingHours.csv`
- `Wednesday-WorkingHours.csv`

## Number of Rows per File

- `Friday-WorkingHours.csv`: `547,915` rows
- `Monday-WorkingHours.csv`: `371,749` rows
- `Thursday-WorkingHours.csv`: `362,368` rows
- `Tuesday-WorkingHours.csv`: `322,003` rows
- `Wednesday-WorkingHours.csv`: `496,779` rows

## Total Dataset Size

Total number of rows:

`2,100,814`

## Dataset Schema

All five CSV files use the same schema.

Number of columns:

`84`

The target variable is:

- `Label`

The dataset includes:

- flow identifiers
- source and destination information
- protocol and port information
- packet statistics
- timing-based flow statistics
- flag-based traffic features
- activity and idle-time features
- attack labels

## Important Column Categories

### Identifier and Context Columns

These columns describe the communication context, but some of them may not be suitable as direct learning features:

- `Flow ID`
- `Src IP`
- `Src Port`
- `Dst IP`
- `Dst Port`
- `Protocol`
- `Timestamp`

### Traffic and Statistical Features

These features describe the flow behavior and are likely to be important for machine learning:

- packet lengths
- forward and backward packet counts
- bytes per second
- packets per second
- inter-arrival times
- header lengths
- TCP flag counts
- segment statistics
- active and idle time values

### Target Column

- `Label`

This column defines whether the traffic is benign or belongs to a specific attack class.

## Label Distribution

The dataset contains the following labels:

- `BENIGN`: `1,657,693`
- `Bot`: `738`
- `Bot - Attempted`: `1,470`
- `DDoS`: `95,123`
- `DoS GoldenEye`: `7,567`
- `DoS GoldenEye - Attempted`: `80`
- `DoS Hulk`: `158,469`
- `DoS Hulk - Attempted`: `593`
- `DoS Slowhttptest`: `1,742`
- `DoS Slowhttptest - Attempted`: `3,369`
- `DoS slowloris`: `4,001`
- `DoS slowloris - Attempted`: `1,731`
- `FTP-Patator`: `3,973`
- `FTP-Patator - Attempted`: `11`
- `Heartbleed`: `11`
- `Infiltration`: `32`
- `Infiltration - Attempted`: `16`
- `PortScan`: `159,151`
- `SSH-Patator`: `2,980`
- `SSH-Patator - Attempted`: `8`
- `Web Attack - Brute Force`: `151`
- `Web Attack - Brute Force - Attempted`: `1,214`
- `Web Attack - Sql Injection`: `12`
- `Web Attack - XSS`: `27`
- `Web Attack - XSS - Attempted`: `652`

## Initial Observations

### 1. The Dataset Is Highly Imbalanced

The `BENIGN` class is much larger than many attack classes. Some classes contain only a very small number of samples, such as:

- `Heartbleed`
- `Web Attack - Sql Injection`
- `SSH-Patator - Attempted`
- `FTP-Patator - Attempted`
- `Infiltration - Attempted`

This means class imbalance must be addressed carefully during modeling and evaluation.

### 2. Some Attack Labels Include "Attempted" Variants

Several attack families appear in two forms:

- confirmed attack
- attempted attack

This creates an important design decision for the project:

- keep them as separate multiclass labels
- merge them into their main attack families
- simplify the problem into binary classification: `BENIGN` vs `ATTACK`

### 3. Some Columns Are Likely Not Suitable as Direct Features

Columns such as:

- `Flow ID`
- `Src IP`
- `Dst IP`
- `Timestamp`

may introduce noise, leakage, or unnecessary complexity and will likely be removed during preprocessing.

### 4. Most Useful Features Will Likely Be Numeric Flow Statistics

The dataset contains many network-flow statistics that are typically effective for intrusion detection tasks, including:

- length-based features
- rate-based features
- inter-arrival time features
- TCP flag counters
- active and idle time measurements

## Data Understanding from a Cybersecurity Perspective

From a cybersecurity viewpoint, the dataset is appropriate for intrusion detection because it contains both normal traffic and multiple categories of malicious behavior, such as:

- `DDoS`
- `DoS`
- `PortScan`
- `Bot`
- `Brute Force`
- `Infiltration`
- `Heartbleed`
- `Web Attacks`

This makes it suitable for:

- binary intrusion detection
- multiclass attack classification
- model comparison
- arbiter-based decision making

## Risks Identified at This Stage

- severe class imbalance
- rare labels with very few samples
- potential missing or infinite values in flow-based features
- possible redundant or non-informative columns
- possible overfitting if train/test splitting is not handled carefully

## Output of This Step

At the end of the data understanding phase, we confirmed:

- the dataset contains 5 CSV files
- all files share the same 84-column schema
- the target variable is `Label`
- the dataset contains both benign and multiple attack classes
- the dataset is strongly imbalanced
- preprocessing and label strategy will be important before modeling

## Next Step

The next phase is `Data Preparation`, where the dataset will be cleaned, transformed, and made ready for machine learning.
