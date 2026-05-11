"""
Train a RandomForest classifier on the local 10-feature dataset.

This model is aligned with what the tool actually collects — unlike the
ISOT model which was trained on hundreds of flow-level CICFlowMeter
columns that don't match the tool's feature vector.

Usage:
    python -m ml.train_local_model

Produces:
    ml/local_model.pkl
    ml/local_scaler.pkl
    ml/local_label_encoder.pkl

After running this, the tool will automatically use the local model
instead of the broken ISOT alignment path.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

DATASET_PATH  = Path(__file__).resolve().parent.parent / "ai" / "training" / "data.csv"
MODEL_DIR     = Path(__file__).resolve().parent
MODEL_PATH    = MODEL_DIR / "local_model.pkl"
SCALER_PATH   = MODEL_DIR / "local_scaler.pkl"
ENCODER_PATH  = MODEL_DIR / "local_label_encoder.pkl"
META_PATH     = MODEL_DIR / "local_model_meta.pkl"

FEATURE_COLS = [
    "open_ports_count",
    "has_control_port",
    "has_telemetry_port",
    "has_video_port",
    "has_mavlink",
    "has_unknown_protocol",
    "wifi_security_level",
    "ping_loss",
    "avg_latency_ms",
    "diag_success",
]


def train() -> None:
    # ------------------------------------------------------------------ Load
    if not DATASET_PATH.exists():
        print(f"ERROR: {DATASET_PATH} not found.")
        print("Run first:  python -m ml.generate_training_data")
        sys.exit(1)

    df = pd.read_csv(DATASET_PATH)
    print(f"Loaded {len(df)} rows from {DATASET_PATH.name}")

    if len(df) < 50:
        print("WARNING: Very few samples. Run generate_training_data with --samples 2000 first.")

    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        print(f"ERROR: Missing columns in CSV: {missing}")
        sys.exit(1)
    if "label" not in df.columns:
        print("ERROR: No 'label' column in CSV.")
        sys.exit(1)

    # ------------------------------------------------------------------ Clean
    df = df.dropna(subset=FEATURE_COLS + ["label"])
    df[FEATURE_COLS] = df[FEATURE_COLS].apply(pd.to_numeric, errors="coerce")
    df = df.dropna(subset=FEATURE_COLS)

    # Replace -1 sentinel values (unknown) with column medians
    for col in ["ping_loss", "avg_latency_ms"]:
        median = df.loc[df[col] >= 0, col].median()
        df[col] = df[col].where(df[col] >= 0, median)

    X = df[FEATURE_COLS].values.astype(np.float64)
    y_raw = df["label"].values

    # ------------------------------------------------------------------ Encode
    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    print(f"Classes: {list(le.classes_)}")

    # Label distribution
    from collections import Counter
    counts = Counter(y_raw)
    for label in sorted(counts):
        print(f"  {label:<12} {counts[label]:>5}")

    # ------------------------------------------------------------------ Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train)}  Test: {len(X_test)}")

    # ------------------------------------------------------------------ Scale
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # ------------------------------------------------------------------ Train
    print("\nTraining RandomForest...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train_s, y_train)

    # ------------------------------------------------------------------ Evaluate
    y_pred = clf.predict(X_test_s)
    acc = (y_pred == y_test).mean()
    print(f"\nTest accuracy: {acc:.1%}\n")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    print("Confusion matrix:")
    cm = confusion_matrix(y_test, y_pred)
    header = "         " + "  ".join(f"{c:>10}" for c in le.classes_)
    print(header)
    for i, row in enumerate(cm):
        print(f"  {le.classes_[i]:>8} " + "  ".join(f"{v:>10}" for v in row))

    # Feature importance
    print("\nTop feature importances:")
    importances = sorted(
        zip(FEATURE_COLS, clf.feature_importances_),
        key=lambda x: x[1], reverse=True,
    )
    for fname, imp in importances:
        bar = "|" * int(imp * 40)
        print(f"  {fname:<25} {imp:.4f}  {bar}")

    # ------------------------------------------------------------------ Save
    joblib.dump(clf,    MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le,     ENCODER_PATH)
    joblib.dump({
        "feature_names": FEATURE_COLS,
        "classes":       list(le.classes_),
        "accuracy":      acc,
        "n_samples":     len(df),
    }, META_PATH)

    print(f"\nSaved:")
    print(f"  {MODEL_PATH}")
    print(f"  {SCALER_PATH}")
    print(f"  {ENCODER_PATH}")
    print(f"  {META_PATH}")
    print("\nThe tool will now use this local model automatically.")


if __name__ == "__main__":
    train()
