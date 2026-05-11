"""
ML Inference Module for Drone Security Assessment Tool.

Two model paths (in priority order):

  1. LOCAL model  (ml/local_model.pkl)
     Trained on the tool's own 10 features using generate_training_data +
     train_local_model.  Feature-aligned — no approximation needed.
     Use this path whenever the file exists.

  2. ISOT model   (ml/model.pkl)
     Trained on hundreds of CICFlowMeter flow columns.  Feature alignment
     is approximate (medians fill most columns), so confidence values are
     often unreliable.  Kept as a fallback only.

Run once to build the local model:
    python -m ml.generate_training_data --samples 2000
    python -m ml.train_local_model
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict

_DST_ROOT = Path(__file__).resolve().parent.parent
if str(_DST_ROOT) not in sys.path:
    sys.path.insert(0, str(_DST_ROOT))

import joblib
import numpy as np

_ML_DIR = Path(__file__).parent

# ---- Local model (preferred) ----
_LOCAL_MODEL_PATH   = _ML_DIR / "local_model.pkl"
_LOCAL_SCALER_PATH  = _ML_DIR / "local_scaler.pkl"
_LOCAL_ENCODER_PATH = _ML_DIR / "local_label_encoder.pkl"
_LOCAL_META_PATH    = _ML_DIR / "local_model_meta.pkl"

# ---- ISOT model (fallback) ----
_ISOT_MODEL_PATH    = _ML_DIR / "model.pkl"
_ISOT_SCALER_PATH   = _ML_DIR / "scaler.pkl"
_ISOT_LE_PATH       = _ML_DIR / "label_encoder.pkl"
_ISOT_DEFAULTS_PATH = _ML_DIR / "feature_defaults.pkl"

# Lazy-loaded globals
_local_model = _local_scaler = _local_le = _local_meta = None
_isot_model  = _isot_scaler  = _isot_le  = None
_isot_feature_names = _isot_defaults = None

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


# ---------------------------------------------------------------------------
# Availability checks
# ---------------------------------------------------------------------------

def is_local_model_ready() -> bool:
    return (
        _LOCAL_MODEL_PATH.exists()
        and _LOCAL_SCALER_PATH.exists()
        and _LOCAL_ENCODER_PATH.exists()
    )


def is_isot_model_ready() -> bool:
    return _ISOT_MODEL_PATH.exists() and _ISOT_SCALER_PATH.exists()


def is_model_ready() -> bool:
    """True if any model is available (local preferred)."""
    return is_local_model_ready() or is_isot_model_ready()


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _load_local() -> None:
    global _local_model, _local_scaler, _local_le, _local_meta
    if _local_model is not None:
        return
    _local_model  = joblib.load(_LOCAL_MODEL_PATH)
    _local_scaler = joblib.load(_LOCAL_SCALER_PATH)
    _local_le     = joblib.load(_LOCAL_ENCODER_PATH)
    _local_meta   = joblib.load(_LOCAL_META_PATH) if _LOCAL_META_PATH.exists() else {}


def _load_isot() -> None:
    global _isot_model, _isot_scaler, _isot_le, _isot_feature_names, _isot_defaults
    if _isot_model is not None:
        return
    if not is_isot_model_ready():
        raise FileNotFoundError(
            f"No model found. Run:\n"
            "  python -m ml.generate_training_data\n"
            "  python -m ml.train_local_model"
        )
    _isot_model  = joblib.load(_ISOT_MODEL_PATH)
    _isot_scaler = joblib.load(_ISOT_SCALER_PATH)
    _isot_le     = joblib.load(_ISOT_LE_PATH)
    defaults_data        = joblib.load(_ISOT_DEFAULTS_PATH)
    _isot_feature_names  = defaults_data["feature_names"]
    _isot_defaults       = defaults_data["defaults"]


# ---------------------------------------------------------------------------
# Local model prediction  (10 features, direct)
# ---------------------------------------------------------------------------

def _predict_local(fv: Dict[str, float]) -> Dict:
    _load_local()

    vec = np.array(
        [fv.get(col, 0.0) for col in FEATURE_COLS],
        dtype=np.float64,
    ).reshape(1, -1)

    # Replace -1 sentinels with 0 (unknown → treat as zero)
    vec[vec < 0] = 0.0

    vec_s = _local_scaler.transform(vec)
    pred_idx = _local_model.predict(vec_s)[0]
    probs    = _local_model.predict_proba(vec_s)[0]
    label    = _local_le.inverse_transform([pred_idx])[0]

    prob_dict = {
        _local_le.inverse_transform([i])[0]: round(float(p), 4)
        for i, p in enumerate(probs)
    }

    # Weighted midpoint formula — each band contributes its midpoint score:
    #   Normal     →  15  (mid of 0-30)
    #   Suspicious →  50  (mid of 31-69)
    #   Attack     →  85  (mid of 70-100)
    # This keeps Suspicious predictions in the 31-69 range, not 100.
    _band_midpoint = {"Normal": 15, "Suspicious": 50, "Attack": 85}
    risk_score = int(round(sum(
        prob_dict.get(lbl, 0.0) * mid
        for lbl, mid in _band_midpoint.items()
    )))
    risk_score = max(0, min(risk_score, 100))
    attack_prob = prob_dict.get("Attack", 0.0) + 0.5 * prob_dict.get("Suspicious", 0.0)

    return {
        "prediction":        label,
        "confidence":        round(float(probs.max()), 4),
        "attack_probability":round(attack_prob, 4),
        "risk_score":        risk_score,
        "probabilities":     prob_dict,
        "model_used":        "local",
    }


# ---------------------------------------------------------------------------
# ISOT model prediction  (approximate alignment)
# ---------------------------------------------------------------------------

def _align_isot(fv: Dict[str, float]) -> np.ndarray:
    """Map 10 tool features → ISOT feature vector using medians for unknowns."""
    _load_isot()
    vec = np.array(
        [_isot_defaults.get(fname, 0.0) for fname in _isot_feature_names],
        dtype=np.float64,
    )
    rules: Dict[str, float] = {}
    open_ports = fv.get("open_ports_count", 0)
    rules["Total Fwd Packets"] = max(open_ports * 50, 1)
    rules["Total Backward Packets"] = max(open_ports * 30, 1)
    if fv.get("has_control_port", 0):
        rules["Dst Port"] = 8889.0
    elif fv.get("has_telemetry_port", 0):
        rules["Dst Port"] = 8890.0
    elif fv.get("has_video_port", 0):
        rules["Dst Port"] = 11111.0
    rules["Protocol"] = 17.0 if fv.get("has_mavlink", 0) else 0.0
    latency = fv.get("avg_latency_ms", -1)
    if latency > 0:
        iat = latency * 1000.0
        for col in ("Flow IAT Mean", "Fwd IAT Mean", "Bwd IAT Mean"):
            rules[col] = iat
    for col_name, value in rules.items():
        if col_name in _isot_feature_names:
            vec[_isot_feature_names.index(col_name)] = value
    np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0, copy=False)
    return _isot_scaler.transform(vec.reshape(1, -1))


def _predict_isot(fv: Dict[str, float]) -> Dict:
    _load_isot()
    X   = _align_isot(fv)
    idx = _isot_model.predict(X)[0]
    prbs = _isot_model.predict_proba(X)[0]
    lbl  = _isot_le.inverse_transform([idx])[0]
    prob_dict = {
        _isot_le.inverse_transform([i])[0]: round(float(p), 4)
        for i, p in enumerate(prbs)
    }
    attack_prob = sum(p for l, p in prob_dict.items() if l != "Normal")
    return {
        "prediction":        lbl,
        "confidence":        round(float(prbs.max()), 4),
        "attack_probability":round(attack_prob, 4),
        "risk_score":        int(round(attack_prob * 100)),
        "probabilities":     prob_dict,
        "model_used":        "isot",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def predict_risk(feature_vector: Dict[str, float]) -> Dict:
    """
    Predict drone risk from the 10 tool features.

    Prefers the local model (trained on aligned features).
    Falls back to the ISOT model if no local model exists.
    """
    if is_local_model_ready():
        return _predict_local(feature_vector)
    return _predict_isot(feature_vector)
