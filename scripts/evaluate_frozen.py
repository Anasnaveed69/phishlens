"""Score a dataset with the SHIPPED model and its calibrated config — no training, no tuning.

This is the final, untouched holdout evaluation: the model, rules, features and thresholds are frozen
before these pages are ever looked at. Usage:
    python scripts/evaluate_frozen.py --data phreshphish_holdout --name "PhreshPhish fresh holdout"
Writes reports/holdout.json, reports/holdout.md and reports/holdout_errors.csv.
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402

from app.config import settings  # noqa: E402
from engine import model as model_mod  # noqa: E402
from engine.pipeline import analyze  # noqa: E402
from scripts.evaluate import defang  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--name", default=None)
    ap.add_argument("--out", default=str(ROOT / "reports"))
    args = ap.parse_args()
    data, out = Path(args.data), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    meta = json.loads(model_mod.meta_path(settings.model_path).read_text(encoding="utf-8"))
    model = model_mod.load(settings.model_path)
    cfg = meta["recommended_config"]
    rows = list(csv.DictReader((data / "labels.csv").open(encoding="utf-8")))
    y, score, lat, errors, rule_hits = [], [], [], [], {}
    for i, row in enumerate(rows, 1):
        html = (data / Path(row["filename"]).name).read_text(encoding="utf-8", errors="replace")
        t0 = time.perf_counter()
        r = analyze(html, row.get("source_url") or None, cfg, model)
        lat.append((time.perf_counter() - t0) * 1000)
        label = int(row["label"] == "phishing")
        y.append(label)
        score.append(r["score"])
        for f in r["rules"]["fired"]:
            rule_hits.setdefault(f["id"], [0, 0])[label] += 1
        flagged = r["decision"] != "benign"
        if flagged != bool(label):
            errors.append({"type": "false_positive" if flagged else "false_negative", "file": row["filename"],
                           "url": defang((row.get("source_url") or "")[:120]), "decision": r["decision"],
                           "score": r["score"], "ml": r["ml"]["probability"] if r["ml"] else None,
                           "rules": " ".join(f["id"] for f in r["rules"]["fired"]),
                           "top_features": "; ".join(f"{t['feature']}={t['value']:g}" for t in (r["ml"] or {}).get("top_features", [])[:3])})
        if i % 250 == 0:
            print(f"  {i}/{len(rows)}", flush=True)

    y, score = np.array(y), np.array(score)
    res = {
        "served@suspicious": model_mod.metrics(y, (score >= cfg["suspicious_threshold"]).astype(int)),
        "served@phishing": model_mod.metrics(y, (score >= cfg["phishing_threshold"]).astype(int)),
    }
    for m in res.values():
        m["roc_auc"] = round(float(roc_auc_score(y, score)), 4)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": {"path": str(data), "name": args.name or data.name, "pages": len(rows),
                    "phishing": int(y.sum()), "benign": int(len(y) - y.sum())},
        "model_version": meta["version"], "config": cfg, "results": res,
        "latency_ms": {"mean": round(statistics.mean(lat), 2), "median": round(statistics.median(lat), 2),
                       "p95": round(float(np.percentile(lat, 95)), 2), "max": round(max(lat), 2)},
        "rule_hits": {k: {"benign": v[0], "phishing": v[1]} for k, v in sorted(rule_hits.items())},
        "errors": {"false_positives": sum(e["type"] == "false_positive" for e in errors),
                   "false_negatives": sum(e["type"] == "false_negative" for e in errors)},
    }
    (out / "holdout.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    with (out / "holdout_errors.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(errors[0]) if errors else ["type"])
        w.writeheader()
        w.writerows(errors)
    s, h = res["served@suspicious"], res["served@phishing"]
    md = [f"# Fresh holdout — {report['dataset']['name']}", "",
          f"{len(rows)} pages never seen during development ({report['dataset']['phishing']} phishing / {report['dataset']['benign']} benign), "
          f"scored with the frozen model `{meta['version']}` and config {cfg}. Nothing was tuned on these pages.", "",
          "| Band | Precision | Recall | F1 | FPR | ROC-AUC | TP | FP | FN | TN |", "|---|---|---|---|---|---|---|---|---|---|"]
    for k, m in res.items():
        c = m["confusion_matrix"]
        md.append(f"| {k} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['false_positive_rate']:.3f} | "
                  f"{m['roc_auc']:.3f} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} |")
    md += ["", f"Latency: mean {report['latency_ms']['mean']} ms, p95 {report['latency_ms']['p95']} ms. "
           f"Errors: {report['errors']['false_positives']} FP, {report['errors']['false_negatives']} FN (holdout_errors.csv)."]
    (out / "holdout.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({k: {m: v[m] for m in ("precision", "recall", "f1", "false_positive_rate", "roc_auc")} for k, v in res.items()}, indent=2))
    print("latency", report["latency_ms"])


if __name__ == "__main__":
    main()
