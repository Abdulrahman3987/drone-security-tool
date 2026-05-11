"""
ML Training Pipeline for Drone Security Assessment Tool
========================================================
Trains a Random Forest classifier on the ISOT DJI Tello dataset
to replace static rule-based risk scoring with learned behavior.

Outputs:
    ml/model.pkl           - trained Random Forest model
    ml/scaler.pkl          - fitted StandardScaler
    ml/label_encoder.pkl   - fitted LabelEncoder
    ml/feature_defaults.pkl- median defaults per feature (for inference alignment)

Usage:
    python -m ml.train_model <dataset_root> [--multiclass] [--evaluate]

Example:
    python -m ml.train_model ./ISOT_dataset --evaluate
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure drone_security_tool/ is on sys.path regardless of where the
# script is invoked from (GPtool root, drone_security_tool/, etc.)
_THIS_FILE = Path(__file__).resolve()
_DST_ROOT = _THIS_FILE.parent.parent  # drone_security_tool/
if str(_DST_ROOT) not in sys.path:
    sys.path.insert(0, str(_DST_ROOT))

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

from ml.preprocess import full_preprocess

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_CONFIG_PATH = Path(__file__).parent / "config.json"
_ML_DIR = Path(__file__).parent


def _load_config() -> dict:
    with open(_CONFIG_PATH, "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train(
    dataset_root: str,
    binary: bool = True,
    evaluate: bool = True,
) -> None:
    """
    End-to-end training pipeline.

    1. Preprocess the ISOT dataset.
    2. Split into train / test.
    3. Train a Random Forest.
    4. Evaluate (optional).
    5. Save model artefacts.
    """
    cfg = _load_config()

    # ---- Preprocess ----
    print("=" * 60)
    print("STEP 1: Preprocessing ISOT dataset")
    print("=" * 60)
    X, y, scaler, le, feature_names, feature_defaults = full_preprocess(
        dataset_root, binary=binary
    )

    # ---- Train/Test split ----
    print("\n" + "=" * 60)
    print("STEP 2: Train / Test split")
    print("=" * 60)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=cfg["test_size"],
        random_state=cfg["random_state"],
        stratify=y,
    )
    print(f"  Train: {X_train.shape[0]} samples")
    print(f"  Test : {X_test.shape[0]} samples")

    # ---- Train Random Forest ----
    print("\n" + "=" * 60)
    print("STEP 3: Training Random Forest")
    print("=" * 60)
    rf_params = cfg["random_forest_params"]
    model = RandomForestClassifier(**rf_params)
    model.fit(X_train, y_train)
    print("  Training complete.")

    # ---- Evaluate ----
    if evaluate:
        print("\n" + "=" * 60)
        print("STEP 4: Evaluation")
        print("=" * 60)
        y_pred = model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        print(f"\n  Accuracy: {acc:.4f}")
        print(f"\n  Classification Report:\n")
        print(classification_report(
            y_test, y_pred,
            target_names=le.classes_,
        ))
        print("  Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))

        # Feature importance (top 15)
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1][:15]
        print("\n  Top 15 Important Features:")
        for rank, idx in enumerate(indices, 1):
            print(f"    {rank:2d}. {feature_names[idx]:35s} = {importances[idx]:.4f}")

    # ---- Save artefacts ----
    print("\n" + "=" * 60)
    print("STEP 5: Saving model artefacts")
    print("=" * 60)

    model_path = _ML_DIR / "model.pkl"
    scaler_path = _ML_DIR / "scaler.pkl"
    le_path = _ML_DIR / "label_encoder.pkl"
    defaults_path = _ML_DIR / "feature_defaults.pkl"

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(le, le_path)
    joblib.dump(
        {"feature_names": feature_names, "defaults": feature_defaults},
        defaults_path,
    )

    print(f"  Model         -> {model_path}")
    print(f"  Scaler        -> {scaler_path}")
    print(f"  LabelEncoder  -> {le_path}")
    print(f"  Defaults      -> {defaults_path}")
    print("\nDone! Model is ready for inference.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m ml.train_model <dataset_root> [--multiclass] [--evaluate]")
        print()
        print("Arguments:")
        print("  dataset_root   Path to ISOT dataset folder with subfolders")
        print("                 (Regular/, DoS/, MITM/, etc.)")
        print("  --multiclass   Use per-attack-type labels instead of binary")
        print("  --evaluate     Print accuracy, classification report, confusion matrix")
        print()
        print("Example:")
        print("  python -m ml.train_model ./ISOT_dataset --evaluate")
        sys.exit(1)

    root = sys.argv[1]
    binary = "--multiclass" not in sys.argv
    evaluate = "--evaluate" in sys.argv

    train(dataset_root=root, binary=binary, evaluate=evaluate)
