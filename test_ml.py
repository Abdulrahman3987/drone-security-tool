"""
Test script: loads real ISOT dataset rows and runs them through the ML pipeline.

Picks one random sample from each attack category and Regular, feeds
the raw CSV row directly into the trained model, and prints the
predicted class + confidence.

Usage (from GPtool/):
    python test_ml.py
"""
import sys
from pathlib import Path

# -- path setup --
DST_ROOT = Path(__file__).resolve().parent / "drone_security_tool"
sys.path.insert(0, str(DST_ROOT))

import joblib
import numpy as np
import pandas as pd

# ---- Load model artefacts ----
ML_DIR = DST_ROOT / "ml"
model = joblib.load(ML_DIR / "model.pkl")
scaler = joblib.load(ML_DIR / "scaler.pkl")
label_encoder = joblib.load(ML_DIR / "label_encoder.pkl")
defaults_data = joblib.load(ML_DIR / "feature_defaults.pkl")
FEATURE_NAMES = defaults_data["feature_names"]
FEATURE_DEFAULTS = defaults_data["defaults"]

# ---- Dataset root ----
DATASET_ROOT = Path(r"C:\Users\mddm7\Desktop\ISOT Drone Dataset\Dataset\new_feature_csv")

# Categories to test (folder name -> display label)
CATEGORIES = {
    "Regular":           "Normal",
    "DoS":               "DoS Attack",
    "MITM":              "MITM Attack",
    "Injection":         "Injection Attack",
    "Replay":            "Replay Attack",
    "Ip Spoofing":       "IP Spoofing Attack",
    "Manipulation":      "Manipulation Attack",
    "Password Cracking": "Password Cracking",
}


def load_one_sample(folder: Path) -> pd.Series:
    """Load the first CSV in *folder* and return one random row."""
    csvs = sorted(folder.glob("*.csv"))
    if not csvs:
        raise FileNotFoundError(f"No CSVs in {folder}")
    df = pd.read_csv(csvs[0], low_memory=False, nrows=500)
    df.columns = df.columns.str.strip()
    return df.sample(n=1, random_state=42).iloc[0]


def prepare_row(row: pd.Series) -> np.ndarray:
    """Align a raw CSV row to the trained feature vector and scale it."""
    vector = np.array(
        [FEATURE_DEFAULTS.get(f, 0.0) for f in FEATURE_NAMES],
        dtype=np.float64,
    )
    for i, fname in enumerate(FEATURE_NAMES):
        if fname in row.index:
            val = row[fname]
            try:
                vector[i] = float(val)
            except (ValueError, TypeError):
                pass  # keep the default
    # Replace inf / NaN with defaults
    for i in range(len(vector)):
        if not np.isfinite(vector[i]):
            vector[i] = FEATURE_DEFAULTS.get(FEATURE_NAMES[i], 0.0)
    return scaler.transform(vector.reshape(1, -1))


def predict(X_scaled: np.ndarray) -> dict:
    """Run the model and return prediction details."""
    pred_idx = model.predict(X_scaled)[0]
    probs = model.predict_proba(X_scaled)[0]
    label = label_encoder.inverse_transform([pred_idx])[0]
    prob_dict = {
        label_encoder.inverse_transform([i])[0]: round(float(p), 4)
        for i, p in enumerate(probs)
    }
    attack_prob = sum(p for l, p in prob_dict.items() if l != "Normal")
    risk_score = int(round(attack_prob * 100))
    return {
        "prediction": label,
        "confidence": float(probs.max()),
        "risk_score": risk_score,
        "probabilities": prob_dict,
    }


def main():
    print("=" * 70)
    print("  ISOT Drone Dataset -> ML Inference Test")
    print("=" * 70)
    print(f"  Model features : {len(FEATURE_NAMES)}")
    print(f"  Model classes  : {list(label_encoder.classes_)}")
    print(f"  Dataset root   : {DATASET_ROOT}")
    print("=" * 70)

    for folder_name, display_label in CATEGORIES.items():
        folder = DATASET_ROOT / folder_name
        if not folder.is_dir():
            print(f"\n  [{display_label}] SKIPPED - folder not found: {folder}")
            continue

        try:
            row = load_one_sample(folder)
            X = prepare_row(row)
            result = predict(X)

            status = "CORRECT" if (
                (result["prediction"] == "Normal" and folder_name == "Regular")
                or (result["prediction"] == "Attack" and folder_name != "Regular")
            ) else "WRONG"

            print(f"\n  [{display_label}]")
            print(f"    Source file row : {folder_name}/*.csv")
            print(f"    Prediction      : {result['prediction']}")
            print(f"    Confidence      : {result['confidence']:.1%}")
            print(f"    Risk Score      : {result['risk_score']}/100")
            print(f"    Probabilities   : {result['probabilities']}")
            print(f"    Verdict         : {status}")

        except Exception as exc:
            print(f"\n  [{display_label}] ERROR: {exc}")

    print("\n" + "=" * 70)
    print("  Test complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
