"""
Root-level launcher for the ML training pipeline.
Run this from anywhere:
    python train_model.py <dataset_root> [--multiclass] [--evaluate]

Example:
    python train_model.py "C:/Users/mddm7/Desktop/ISOT Drone Dataset" --evaluate
"""
import sys
from pathlib import Path

# Add drone_security_tool/ to path so all project modules resolve correctly
_ROOT = Path(__file__).resolve().parent
_DST = _ROOT / "drone_security_tool"
sys.path.insert(0, str(_DST))

from ml.train_model import train

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python train_model.py <dataset_root> [--multiclass] [--evaluate]")
        print()
        print("Example:")
        print('  python train_model.py "C:\\Users\\mddm7\\Desktop\\ISOT Drone Dataset" --evaluate')
        sys.exit(1)

    dataset_root = sys.argv[1]
    binary = "--multiclass" not in sys.argv
    evaluate = "--evaluate" in sys.argv

    train(dataset_root=dataset_root, binary=binary, evaluate=evaluate)
