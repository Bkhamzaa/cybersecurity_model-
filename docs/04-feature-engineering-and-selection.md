# Step 4: Feature Engineering and Feature Selection

## Objective of This Step

The goal of this step is to improve the representation of the network traffic data before training the machine learning models.

In intrusion detection, not every column contributes equally to attack detection. Some features are highly informative, while others may be redundant, noisy, or too specific to generalize well.

## Why This Step Matters

Feature engineering and feature selection are important because they can:

- improve model performance
- reduce overfitting
- reduce training time
- improve model interpretability
- help the future arbiter model combine stronger base learners

## Initial Feature Categories

Based on the dataset structure, the features can be grouped into:

### 1. Identifier and Context Features

- `Flow ID`
- `Src IP`
- `Dst IP`
- `Timestamp`

These are generally not suitable as direct learning features and are expected to be removed.

### 2. Network Context Features

- `Src Port`
- `Dst Port`
- `Protocol`

These may contain useful information and should be tested during modeling.

### 3. Packet-Length Features

Examples:

- `Fwd Packet Length Max`
- `Fwd Packet Length Mean`
- `Bwd Packet Length Max`
- `Packet Length Mean`
- `Average Packet Size`

These features describe packet-size behavior and can be useful for distinguishing attacks such as flooding, web attacks, and brute-force traffic.

### 4. Rate-Based Features

Examples:

- `Flow Bytes/s`
- `Flow Packets/s`
- `Fwd Packets/s`
- `Bwd Packets/s`

These features often capture abnormal traffic intensity and are especially useful for `DoS`, `DDoS`, and scanning behavior.

### 5. Time-Based Features

Examples:

- `Flow IAT Mean`
- `Flow IAT Std`
- `Fwd IAT Mean`
- `Bwd IAT Mean`
- `Active Mean`
- `Idle Mean`

These features describe the temporal behavior of traffic flows and may help distinguish automated attacks from benign traffic.

### 6. Flag and Control Features

Examples:

- `SYN Flag Count`
- `ACK Flag Count`
- `RST Flag Count`
- `PSH Flag Count`

These are important for representing TCP behavior and may be useful for identifying scanning or abnormal connection patterns.

## Feature Engineering Strategy

For this PFE, the initial feature engineering strategy will focus on:

- cleaning and preserving the original flow-statistics features
- comparing performance with and without some context variables such as ports and protocol
- avoiding overly complex engineered features in the first baseline

This keeps the first models interpretable and makes later arbiter analysis easier.

## Candidate Feature Decisions

### Features to Remove

These columns are strong candidates for removal:

- `Flow ID`
- `Src IP`
- `Dst IP`
- `Timestamp`

Reason:

- they identify flows or hosts directly
- they may not generalize well
- they may cause leakage or memorization

### Features to Keep Initially

These should be kept in the baseline feature set:

- flow duration
- packet counts
- packet-length statistics
- bytes-per-second and packets-per-second features
- inter-arrival time features
- flag counts
- active and idle time features
- port and protocol features

## Feature Selection Strategy

Feature selection can be done in stages:

### 1. Domain-Based Selection

Remove columns known to be non-generalizable or non-predictive from a cybersecurity perspective.

### 2. Variance and Redundancy Analysis

Check whether some columns:

- have near-zero variance
- repeat the same information
- are highly correlated with many other features

### 3. Model-Based Importance

Use a tree-based model such as `Random Forest` to estimate feature importance and rank the most useful columns.

### 4. Comparative Evaluation

Compare:

- all cleaned features
- selected feature subsets
- merged-label vs full-label strategies

## Planned Experiments for Feature Selection

The project can compare several feature configurations:

### Configuration A: Full Cleaned Feature Set

Use all cleaned features except removed identifier columns.

### Configuration B: Statistical Features Only

Use mostly flow statistics and exclude direct network-context variables if needed.

### Configuration C: Top-N Important Features

Use the top features ranked by model importance or correlation analysis.

## Relationship to the Arbiter Model

Feature engineering affects the arbiter stage in two ways:

- better features improve the quality of each base model
- different feature subsets could be assigned to different base classifiers, making the arbiter more robust

For example:

- one model may focus on rate-based features
- another may focus on timing-based features
- the arbiter may combine their predictions

## Expected Output of This Step

At the end of this step, the project should define:

- the final baseline feature set
- the columns removed from the dataset
- the rationale for feature retention and removal
- a plan for importance-based refinement during modeling

## Next Step

The next phase is `Modeling`, where baseline machine learning models and the future arbiter design will be specified and trained.
