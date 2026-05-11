"""
Training data generator for the local (10-feature) ML model.

Runs FakeDroneScenario many times, scores each one with the
ISOT-informed rule-based engine, and saves the labelled feature
vectors to ai/training/data.csv.

Usage:
    python -m ml.generate_training_data [--samples 2000]

Labels assigned:
    Normal      risk_score  0-30
    Suspicious  risk_score 31-69
    Attack      risk_score 70-100
"""
from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path

# Make sure the project root is on the path when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.fake_scan import FakeDroneScenario
from ai.vulnerability_engine import VulnerabilityEngine
from ai.features import build_features

DATASET_PATH = Path(__file__).resolve().parent.parent / "ai" / "training" / "data.csv"

FIELDNAMES = [
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
    "label",
]


def _band(score: int) -> str:
    if score <= 30:
        return "Normal"
    if score <= 69:
        return "Suspicious"
    return "Attack"


def generate(n_samples: int = 2000, seed: int = 42) -> None:
    engine = VulnerabilityEngine()
    rng = random.Random(seed)

    rows: list[dict] = []

    print(f"Generating {n_samples} random drone scenarios...")
    for i in range(n_samples):
        # Use a different seed per sample so every one is unique
        scenario = FakeDroneScenario(seed=rng.randint(0, 10_000_000)).generate()

        report = engine.analyze(
            fingerprint=scenario.fingerprint,
            wifi_data=scenario.wifi,
            ports=scenario.ports,
            protocols=scenario.protocols,
            safe_tests=scenario.tests,
            force_rule_based=True,
        )

        features = build_features(
            fingerprint=scenario.fingerprint,
            wifi_data=scenario.wifi,
            ports=scenario.ports,
            protocols=scenario.protocols,
            safe_tests=scenario.tests,
        )

        label = _band(report.risk_score)
        rows.append({
            "open_ports_count":    features.open_ports_count,
            "has_control_port":    features.has_control_port,
            "has_telemetry_port":  features.has_telemetry_port,
            "has_video_port":      features.has_video_port,
            "has_mavlink":         features.has_mavlink,
            "has_unknown_protocol":features.has_unknown_protocol,
            "wifi_security_level": features.wifi_security_level,
            "ping_loss":           features.ping_loss,
            "avg_latency_ms":      features.avg_latency_ms,
            "diag_success":        features.diag_success,
            "label":               label,
        })

        if (i + 1) % 500 == 0:
            print(f"  {i + 1}/{n_samples} done...")

    # ---- Label distribution summary ----
    from collections import Counter
    counts = Counter(r["label"] for r in rows)
    print("\nLabel distribution:")
    for label, count in sorted(counts.items()):
        pct = count / len(rows) * 100
        print(f"  {label:<12} {count:>5}  ({pct:.1f}%)")

    # ---- Write CSV ----
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(DATASET_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved {len(rows)} rows → {DATASET_PATH}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate training data for the local ML model.")
    parser.add_argument("--samples", type=int, default=2000,
                        help="Number of random drone scenarios to generate (default: 2000)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Master random seed for reproducibility (default: 42)")
    args = parser.parse_args()
    generate(n_samples=args.samples, seed=args.seed)
