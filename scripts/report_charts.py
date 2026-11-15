"""Re-draw the evaluation charts from reports/evaluation.json + reports/test_predictions.csv
(no raw pages needed). Usage: python scripts/report_charts.py"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import numpy as np  # noqa: E402

from scripts.evaluate import charts  # noqa: E402


def main() -> None:
    rep = ROOT / "reports"
    ev = json.loads((rep / "evaluation.json").read_text(encoding="utf-8"))
    rows = list(csv.DictReader((rep / "test_predictions.csv").open(encoding="utf-8")))
    col = lambda k: np.array([float(r[k]) for r in rows])  # noqa: E731
    y = col("y").astype(int)
    hybrid = col("hybrid")
    pred = (hybrid >= ev["config"]["suspicious_threshold"]).astype(int)
    top = [(t["feature"], t["coef"]) for t in ev["top_features_lr"]]
    charts(rep, y, col("p_lr"), col("p_rf"), col("rule_score"), hybrid, pred, ev["rule_coverage"], top)
    print("charts written to", rep)


if __name__ == "__main__":
    main()
