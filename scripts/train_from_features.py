"""Rebuild the served model from reports/features.csv (no raw pages needed).

scripts/evaluate.py writes the feature matrix with the exact train/test split it used. This script
retrains the same algorithm with the same seed on the train rows, so the result is the identical
model; it then checks that its test-set probabilities match reports/test_predictions.csv.

Usage:  python scripts/train_from_features.py --reports reports
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import joblib  # noqa: E402
import numpy as np  # noqa: E402

from app.config import settings  # noqa: E402
from engine import model as model_mod  # noqa: E402
from engine.features import FEATURE_VERSION, NUMERIC_FEATURES  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default=str(ROOT / "reports"))
    ap.add_argument("--out", default=str(settings.model_path))
    args = ap.parse_args()
    rep = Path(args.reports)
    ev = json.loads((rep / "evaluation.json").read_text(encoding="utf-8"))
    rows = list(csv.DictReader((rep / "features.csv").open(encoding="utf-8")))
    header = list(rows[0].keys())[4:]
    if header != NUMERIC_FEATURES:
        sys.exit("features.csv was produced by a different feature version; re-run scripts/evaluate.py")
    train = [r for r in rows if r["split"] == "train"]
    test = [r for r in rows if r["split"] == "test"]
    X = np.array([[float(r[n]) for n in NUMERIC_FEATURES] for r in train])
    y = np.array([int(r["y"]) for r in train])
    algo = ev["served_algorithm"]
    seed = ev["dataset"]["seed"]
    pipe = model_mod.make_pipeline(algo, seed).fit(X, y)

    # Verify against the predictions recorded by evaluate.py
    recorded = {r["file"]: float(r["p_served"]) for r in csv.DictReader((rep / "test_predictions.csv").open(encoding="utf-8"))}
    Xt = np.array([[float(r[n]) for n in NUMERIC_FEATURES] for r in test])
    mine = pipe.predict_proba(Xt)[:, 1]
    diff = max(abs(mine[k] - recorded[r["file"]]) for k, r in enumerate(test))
    print(f"retrained {algo} on {len(train)} pages; max |Δp| vs recorded test predictions = {diff:.2e}")
    if diff > 2e-3:
        sys.exit("predictions differ from the evaluation run — not saving")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, out)
    meta = {
        "version": ev.get("saved_model") or f"{algo}-{datetime.now(timezone.utc):%Y%m%d%H%M%S}",
        "algorithm": model_mod.ALGORITHM_LABELS[algo], "algorithm_id": algo,
        "feature_version": FEATURE_VERSION, "feature_order": NUMERIC_FEATURES,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "n_train": len(train), "n_test": len(test), "seed": seed,
        "dataset": f"{ev['dataset']['name']} ({ev['dataset']['pages']} pages)",
        "recommended_config": ev["config"], "cross_validation": ev["cross_validation"],
        "test_metrics": ev["results"]["served@suspicious"],
        "rebuilt_from": "reports/features.csv (verified against reports/test_predictions.csv)",
        "sha256": model_mod._sha256(out),
    }
    model_mod.meta_path(out).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"saved {out} ({meta['version']})")


if __name__ == "__main__":
    main()
