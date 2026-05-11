"""
Dataset builder for ML training.

This module collects feature vectors from real scans (fake drone, future real drones,
ISOT dataset, etc.) and stores them as rows in training CSV.
"""

from __future__ import annotations

import csv
import os
from dataclasses import asdict

from ai.features import AnalysisFeatures


DATASET_PATH = "drone_security_tool/ai/training/data.csv"


def save_features(features: AnalysisFeatures, label: str) -> None:
    """
    Append one feature vector + label into the CSV dataset.
    """
    row = asdict(features)
    row["label"] = label  # target class

    file_exists = os.path.exists(DATASET_PATH)

    with open(DATASET_PATH, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())

        # Write header if file didn't exist
        if not file_exists:
            writer.writeheader()

        writer.writerow(row)

    print(f"[Dataset] Added one training example to {DATASET_PATH}")
