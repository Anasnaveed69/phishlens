"""Train the ML classifier from a labeled folder (pages + labels.csv).

Usage:  python scripts/train_model.py --data fixtures/synthetic
Writes models/model.joblib and models/model.meta.json (with test metrics + sha256).
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from engine.features import extract  # noqa: E402
from engine.model import train  # noqa: E402


def load_labeled(folder: Path) -> tuple[list[list[float]], list[int]]:
    X, y = [], []
    with (folder / "labels.csv").open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            html = (folder / Path(row["filename"]).name).read_text(encoding="utf-8", errors="replace")
            X.append(extract(html, row.get("source_url") or None).vector())
            y.append(1 if row["label"] == "phishing" else 0)
    return X, y


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="fixtures/synthetic")
    ap.add_argument("--out", default=str(settings.model_path))
    args = ap.parse_args()
    X, y = load_labeled(Path(args.data))
    meta = train(X, y, Path(args.out), dataset_note=f"{args.data} ({len(y)} pages)")
    print(json.dumps({k: meta[k] for k in ("version", "n_train", "n_test", "test_metrics")}, indent=2))


if __name__ == "__main__":
    main()
