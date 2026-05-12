# Step 5: Modeling

## Objective of This Step

The goal of this step is to build machine learning models that can detect intrusions from network-flow data and then extend the system toward the proposed `Arbiter Model`.

## Modeling Strategy

The modeling process should be done in stages, from simple to more advanced:

### Stage 1: Baseline Binary Classification

Train a first model to classify:

- `BENIGN`
- `ATTACK`

This provides a simple and important baseline for intrusion detection.

### Stage 2: Multiclass Attack Classification

Train a model to classify the specific attack labels or grouped attack families.

This helps evaluate how well the system distinguishes different cyberattack behaviors.

### Stage 3: Arbiter Model

Build an arbiter layer that combines several base classifiers and produces the final decision.

## Candidate Base Models

The following algorithms are suitable for the project:

- `Random Forest`
- `Decision Tree`
- `Logistic Regression`
- `Support Vector Machine`
- `K-Nearest Neighbors`
- `XGBoost` or `LightGBM` if later available
- `Multi-Layer Perceptron`

## Recommended Starting Point

The recommended first baseline is:

- `Random Forest`

Reason:

- strong performance on tabular data
- robust to noisy features
- handles nonlinear patterns
- gives feature-importance information
- does not require strict feature scaling

## Binary Modeling Plan

In the binary task:

- `BENIGN` remains `BENIGN`
- every malicious label is mapped to `ATTACK`

This model will answer the main IDS question:

`Is the observed traffic benign or malicious?`

## Multiclass Modeling Plan

In the multiclass task, there are two options:

### Option 1: Full Label Classification

Keep all labels as separate classes.

Advantage:

- more detailed detection

Limitation:

- some classes are extremely small

### Option 2: Grouped Attack Families

Merge labels into broader families such as:

- `BENIGN`
- `DoS/DDoS`
- `PortScan`
- `Bot`
- `Brute Force`
- `Web Attack`
- `Infiltration`
- `Heartbleed`

Advantage:

- reduces sparsity
- more stable training
- easier interpretation

This grouping strategy may be more appropriate for the PFE.

## Arbiter Model Design

The `Arbiter Model` is the main innovation of the project.

Its role is not to replace the base models, but to make the final decision using their outputs.

## Possible Arbiter Strategies

### 1. Majority Voting

Several base models vote, and the final class is selected by majority.

### 2. Weighted Voting

Each model receives a weight based on its validation performance.

### 3. Stacking

Predictions from base models become inputs to a meta-model, which learns how to make the final decision.

### 4. Confidence-Based Arbitration

If base models disagree, the arbiter selects the decision with the highest confidence or flags the sample for special handling.

## Recommended Arbiter Approach

For this project, a practical progression is:

1. build strong baseline models
2. compare their predictions
3. implement a weighted-voting or stacking arbiter

This keeps the methodology clear and scientifically defensible.

## Training Considerations

During modeling, the following points must be controlled:

- use stratified train/test split
- use a validation strategy for model comparison
- address class imbalance with class weights or resampling
- monitor overfitting
- keep preprocessing consistent across models

## Expected Output of This Step

At the end of this phase, the project should produce:

- one or more trained baseline models
- binary and possibly multiclass results
- a defined arbiter strategy
- a comparison between single-model and arbiter-based performance

## Next Step

The next phase is `Evaluation`, where the trained models will be measured using machine learning and cybersecurity-oriented metrics.
