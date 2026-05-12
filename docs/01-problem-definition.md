# Step 1: Problem Definition

## Project Title

Arbiter Model for Cybersecurity using the CIC-IDS-2018 Dataset

## Problem Statement

The growing volume and complexity of cyberattacks make traditional intrusion detection systems less effective in identifying malicious network traffic with high accuracy. A machine learning-based approach can improve detection performance by learning patterns from network flow data. However, relying on a single model may lead to misclassification, especially in complex or imbalanced attack scenarios.

This project proposes an Arbiter Model for cybersecurity that uses the CIC-IDS-2018 dataset to detect and classify malicious traffic. The arbiter concept will be used to improve final decision-making, especially when multiple models produce different predictions.

## General Objective

Build an intelligent intrusion detection system based on machine learning that can detect cyberattacks in network traffic and use an arbiter mechanism to improve the final classification decision.

## Specific Objectives

- Detect whether a network flow is `BENIGN` or `ATTACK`.
- Classify the type of attack when malicious traffic is detected.
- Reduce false negatives so malicious traffic is not missed.
- Reduce false positives so normal traffic is not flagged too often.
- Compare baseline machine learning models before designing the arbiter layer.
- Develop an arbiter strategy that improves reliability and overall performance.

## Cybersecurity Objective

From a cybersecurity perspective, the system should support intrusion detection by identifying suspicious behavior in network traffic and helping analysts or automated systems react more accurately to threats.

## Analytical Objective

From a data science perspective, the project should transform raw network traffic data into a clean and trainable dataset, build classification models, evaluate them with relevant IDS metrics, and design an arbiter layer for better decision-making.

## Main Research Question

How can an Arbiter Model improve intrusion detection performance on the CIC-IDS-2018 dataset compared with a single machine learning classifier?

## Sub-Questions

- What preprocessing steps are required for the CIC-IDS-2018 dataset?
- Which features are most useful for attack detection?
- Which machine learning models perform best as base classifiers?
- Can an arbiter layer improve precision, recall, and F1-score?
- How should the arbiter behave when base models disagree?

## Expected Deliverables

- A cleaned and prepared version of the dataset for machine learning.
- One or more baseline machine learning models.
- An arbiter model or decision layer.
- A full evaluation using cybersecurity-oriented metrics.
- A documented methodology following the Cyber-Data Science Process.

## Notes

- This file documents only Step 1 of the process.
- The following steps will be written in separate Markdown files.
