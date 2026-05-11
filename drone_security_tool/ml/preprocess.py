"""
ISOT DJI Tello Dataset Preprocessor
====================================
Loads CSV files from multiple attack/normal folders, labels them,
cleans the data, and returns train-ready numpy arrays.

Expected folder structure:
    dataset_root/
        Regular/       <- normal traffic
        DoS/           <- denial of service
        MITM/          <- man in the middle
        Injection/     <- packet injection
        Replay/        <- replay attacks
        Spoofing/      <- spoofing attacks
        ...

Each subfolder contains one or more .csv files exported from
CICFlowMeter or similar flow-based feature extractors.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Ensure drone_security_tool/ is on sys.path regardless of invocation location
_THIS_FILE = Path(__file__).resolve()
_DST_ROOT = _THIS_FILE.parent.parent  # drone_security_tool/
if str(_DST_ROOT) not in sys.path:
    sys.path.insert(0, str(_DST_ROOT))

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_CONFIG_PATH = Path(__file__).parent / "config.json"


def _load_config() -> dict:
    with open(_CONFIG_PATH, "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# 1. Load CSVs from folders and assign labels
# ---------------------------------------------------------------------------
def load_dataset(
    dataset_root: str,
    binary: bool = True,
) -> pd.DataFrame:
    """
    Walk *dataset_root*, read every CSV found in recognized subfolders,
    and append a ``label`` column based on the folder name.

    Parameters
    ----------
    dataset_root : str
        Path to the top-level folder that contains subfolders like
        ``Regular/``, ``DoS/``, ``MITM/``, etc.
    binary : bool
        If True  -> labels are "Normal" / "Attack" (binary classification).
        If False -> labels are the folder name itself (multi-class).

    Returns
    -------
    pd.DataFrame
        Concatenated DataFrame with an extra ``label`` column.
    """
    cfg = _load_config()
    label_map = cfg["dataset_folders"] if binary else cfg["multiclass_labels"]

    frames: List[pd.DataFrame] = []
    root = Path(dataset_root)

    for folder_name, label in label_map.items():
        folder_path = root / folder_name
        if not folder_path.is_dir():
            print(f"[preprocess] Skipping missing folder: {folder_path}")
            continue

        csv_files = list(folder_path.glob("*.csv"))
        if not csv_files:
            print(f"[preprocess] No CSV files in {folder_path}")
            continue

        for csv_file in csv_files:
            print(f"[preprocess] Loading {csv_file} -> label={label}")
            try:
                df = pd.read_csv(csv_file, low_memory=False)
                df.columns = df.columns.str.strip()
                df["label"] = label
                frames.append(df)
            except Exception as exc:
                print(f"[preprocess] ERROR reading {csv_file}: {exc}")

    if not frames:
        raise FileNotFoundError(
            f"No CSV data found under {dataset_root}. "
            "Make sure subfolders match config (Regular, DoS, etc.)."
        )

    combined = pd.concat(frames, ignore_index=True)
    print(f"[preprocess] Total samples loaded: {len(combined)}")
    print(f"[preprocess] Label distribution:\n{combined['label'].value_counts()}")
    return combined


# ---------------------------------------------------------------------------
# 2. Clean the data
# ---------------------------------------------------------------------------
def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    - Drop columns listed in config (IDs, timestamps).
    - Replace infinities with NaN then fill NaN with column median.
    - Convert all feature columns to numeric where possible.
    - Drop constant columns (zero variance).
    """
    cfg = _load_config()
    drop_cols = cfg["drop_columns"]

    # Drop columns that exist in the dataframe
    existing_drops = [c for c in drop_cols if c in df.columns]
    df = df.drop(columns=existing_drops, errors="ignore")

    # Separate label before numeric conversion
    labels = df.pop("label")

    # Force numeric, coercing errors to NaN
    df = df.apply(pd.to_numeric, errors="coerce")

    # Replace inf / -inf with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Fill NaN with column median (robust to outliers)
    medians = df.median()
    df.fillna(medians, inplace=True)

    # Drop constant (zero variance) columns
    nunique = df.nunique()
    constant_cols = nunique[nunique <= 1].index.tolist()
    if constant_cols:
        print(f"[preprocess] Dropping {len(constant_cols)} constant columns")
        df.drop(columns=constant_cols, inplace=True)

    # Re-attach labels
    df["label"] = labels.values

    print(f"[preprocess] After cleaning: {df.shape[0]} rows, {df.shape[1]} columns")
    return df


# ---------------------------------------------------------------------------
# 3. Normalize and encode
# ---------------------------------------------------------------------------
def prepare_for_training(
    df: pd.DataFrame,
) -> Tuple[np.ndarray, np.ndarray, StandardScaler, LabelEncoder, List[str], Dict[str, float]]:
    """
    Split features / labels, scale features, encode labels.

    Returns
    -------
    X : np.ndarray  - scaled feature matrix
    y : np.ndarray  - encoded label vector
    scaler : StandardScaler
    le : LabelEncoder
    feature_names : list[str]
    feature_defaults : dict  - median value per feature (for inference alignment)
    """
    labels = df.pop("label")

    feature_names = df.columns.tolist()

    # Compute medians BEFORE scaling (used later to fill missing features at inference)
    feature_defaults = df.median().to_dict()

    # Scale
    scaler = StandardScaler()
    X = scaler.fit_transform(df.values)

    # Encode labels
    le = LabelEncoder()
    y = le.fit_transform(labels.values)

    print(f"[preprocess] Features: {len(feature_names)}")
    print(f"[preprocess] Classes : {list(le.classes_)}")
    return X, y, scaler, le, feature_names, feature_defaults


# ---------------------------------------------------------------------------
# Convenience: full pipeline
# ---------------------------------------------------------------------------
def full_preprocess(
    dataset_root: str,
    binary: bool = True,
) -> Tuple[np.ndarray, np.ndarray, StandardScaler, LabelEncoder, List[str], Dict[str, float]]:
    """Load -> clean -> prepare.  One-call convenience wrapper."""
    df = load_dataset(dataset_root, binary=binary)
    df = clean_data(df)
    return prepare_for_training(df)


# ---------------------------------------------------------------------------
# CLI entry point (for standalone testing)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python preprocess.py <dataset_root> [--multiclass]")
        sys.exit(1)

    root = sys.argv[1]
    binary = "--multiclass" not in sys.argv

    df = load_dataset(root, binary=binary)
    df = clean_data(df)
    X, y, scaler, le, names, defaults = prepare_for_training(df)

    print(f"\nReady for training: X={X.shape}, y={y.shape}")
    print(f"Feature names ({len(names)}): {names[:10]} ...")
    print(f"Label classes: {list(le.classes_)}")
