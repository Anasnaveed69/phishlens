"""Evaluate PhishLens on a labeled dataset (T1–T5) and train the served model.

Usage:
    python scripts/evaluate.py --data phreshphish_sample            # evaluate + save model
    python scripts/evaluate.py --data fixtures/synthetic --no-save

What it does
  1. Extracts features for every page (timed), stratified train/test split (default 70/30).
  2. Trains the served model (LogisticRegression) and a RandomForest for comparison.
  3. Scores the held-out test set four ways: rules only, LR only, RF only, and the
     production hybrid (default config). Reports precision, recall, F1, accuracy, FPR,
     confusion matrix and ROC-AUC (T1–T3).
  4. False-positive / false-negative analysis for the hybrid: every error with the rules
     that fired and the top model contributions (T4) -> reports/errors.csv.
  5. Rule coverage: how often each rule fires on phishing vs benign pages and its precision.
  6. Decision latency (full pipeline per page: parse + features + rules + model).
  7. Writes reports/evaluation.json, reports/evaluation.md and PNG charts.

The model saved to models/ is the exact LR model evaluated here (trained on the train split),
so the numbers in the report describe the model the app serves.
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

import joblib  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from app.config import settings  # noqa: E402
from app.db import DEFAULT_CONFIG  # noqa: E402
from engine import model as model_mod  # noqa: E402
from engine.features import FEATURE_VERSION, NUMERIC_FEATURES, extract  # noqa: E402
from engine.pipeline import decide  # noqa: E402
from engine.rules import RULES, RULESET_VERSION, evaluate as eval_rules  # noqa: E402


def load(folder: Path, limit: int | None):
    rows = list(csv.DictReader((folder / "labels.csv").open(encoding="utf-8")))
    if limit:
        rows = rows[:limit]
    items, times, skipped = [], [], 0
    for i, row in enumerate(rows, 1):
        path = folder / Path(row["filename"]).name
        try:
            html = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue
        t0 = time.perf_counter()
        fr = extract(html, row.get("source_url") or None)
        rr = eval_rules(fr)
        times.append((time.perf_counter() - t0) * 1000)
        items.append({"file": path.name, "url": row.get("source_url") or "", "y": int(row["label"] == "phishing"),
                      "fr": fr, "rules": rr, "size": len(html)})
        if i % 250 == 0:
            print(f"  features: {i}/{len(rows)}", flush=True)
    return items, times, skipped


def metrics(y, pred, score=None) -> dict:
    m = model_mod.metrics(y, pred)
    if score is not None and len(set(y)) == 2:
        m["roc_auc"] = round(float(roc_auc_score(y, score)), 4)
    return m


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--test-size", type=float, default=0.3)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", default=str(ROOT / "reports"))
    ap.add_argument("--no-save", action="store_true", help="don't overwrite models/model.joblib")
    ap.add_argument("--name", default=None, help="dataset name for the report")
    args = ap.parse_args()

    data = Path(args.data)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    print(f"loading {data} ...")
    items, feat_times, skipped = load(data, args.limit)
    y = np.array([it["y"] for it in items])
    X = np.array([it["fr"].vector() for it in items], dtype=float)
    idx = np.arange(len(items))
    tr, te = train_test_split(idx, test_size=args.test_size, random_state=args.seed, stratify=y)

    # ---- models ---------------------------------------------------------
    lr = Pipeline([("scaler", StandardScaler()),
                   ("clf", LogisticRegression(max_iter=5000, class_weight="balanced", random_state=args.seed))])
    lr.fit(X[tr], y[tr])
    rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=args.seed, n_jobs=-1)
    rf.fit(X[tr], y[tr])

    p_lr = lr.predict_proba(X[te])[:, 1]
    p_rf = rf.predict_proba(X[te])[:, 1]
    rule_scores = np.array([items[i]["rules"]["score"] for i in te])
    w = DEFAULT_CONFIG["ml_weight"]
    hybrid = w * p_lr + (1 - w) * rule_scores
    yt = y[te]

    def flag(scores, thr):
        return (scores >= thr).astype(int)

    pthr, sthr = DEFAULT_CONFIG["phishing_threshold"], DEFAULT_CONFIG["suspicious_threshold"]
    results = {
        "rules_only@phishing": metrics(yt, flag(rule_scores, pthr), rule_scores),
        "rules_only@suspicious": metrics(yt, flag(rule_scores, sthr), rule_scores),
        "logistic_regression@0.5": metrics(yt, flag(p_lr, 0.5), p_lr),
        "random_forest@0.5": metrics(yt, flag(p_rf, 0.5), p_rf),
        "hybrid@phishing (served)": metrics(yt, flag(hybrid, pthr), hybrid),
        "hybrid@suspicious (served)": metrics(yt, flag(hybrid, sthr), hybrid),
    }

    # ---- full-pipeline latency on test pages ------------------------------
    loaded = model_mod.LoadedModel(pipeline=lr, meta={"version": "eval", "feature_order": NUMERIC_FEATURES})
    from engine.pipeline import analyze
    lat = []
    for i in te[: min(len(te), 300)]:
        html = (data / items[i]["file"]).read_text(encoding="utf-8", errors="replace")
        t0 = time.perf_counter()
        analyze(html, items[i]["url"] or None, DEFAULT_CONFIG, loaded)
        lat.append((time.perf_counter() - t0) * 1000)
    latency = {"pages_timed": len(lat), "mean_ms": round(statistics.mean(lat), 2),
               "median_ms": round(statistics.median(lat), 2),
               "p95_ms": round(float(np.percentile(lat, 95)), 2), "max_ms": round(max(lat), 2)}

    # ---- rule coverage (whole dataset) ----------------------------------------
    coverage = []
    n_ph, n_bn = int(y.sum()), int(len(y) - y.sum())
    for rule in RULES:
        on_ph = sum(1 for it in items if it["y"] == 1 and any(f["id"] == rule.id for f in it["rules"]["fired"]))
        on_bn = sum(1 for it in items if it["y"] == 0 and any(f["id"] == rule.id for f in it["rules"]["fired"]))
        coverage.append({"id": rule.id, "name": rule.name, "weight": rule.weight,
                         "fires_on_phishing_pct": round(100 * on_ph / max(n_ph, 1), 1),
                         "fires_on_benign_pct": round(100 * on_bn / max(n_bn, 1), 1),
                         "precision": round(on_ph / (on_ph + on_bn), 3) if on_ph + on_bn else None})

    # ---- error analysis for the served hybrid (T4) --------------------------
    contrib_model = model_mod.LoadedModel(pipeline=lr, meta={"version": "eval", "feature_order": NUMERIC_FEATURES})
    errors = []
    pred_h = flag(hybrid, pthr)
    for k, i in enumerate(te):
        if pred_h[k] != yt[k]:
            ml = contrib_model.predict(items[i]["fr"], top_k=3)
            errors.append({
                "type": "false_positive" if pred_h[k] == 1 else "false_negative",
                "file": items[i]["file"], "url": items[i]["url"][:120],
                "hybrid_score": round(float(hybrid[k]), 3), "ml_prob": round(float(p_lr[k]), 3),
                "rule_score": round(float(rule_scores[k]), 3),
                "rules_fired": " ".join(f["id"] for f in items[i]["rules"]["fired"]),
                "top_model_features": "; ".join(f"{t['feature']}={t['value']:g} ({t['contribution']:+.2f})"
                                                for t in ml["top_features"]),
                "decision_at_suspicious": decide(float(hybrid[k]), DEFAULT_CONFIG),
            })
    with (out / "errors.csv").open("w", newline="", encoding="utf-8") as f:
        wri = csv.DictWriter(f, fieldnames=list(errors[0].keys()) if errors else ["type"])
        wri.writeheader()
        wri.writerows(errors)
    fp_rules: dict[str, int] = {}
    for e in errors:
        if e["type"] == "false_positive":
            for rid in e["rules_fired"].split():
                fp_rules[rid] = fp_rules.get(rid, 0) + 1

    # ---- top global features (LR coefficients, RF importances) --------------
    coefs = lr.named_steps["clf"].coef_[0]
    top_lr = sorted(zip(NUMERIC_FEATURES, coefs), key=lambda t: abs(t[1]), reverse=True)[:12]
    top_rf = sorted(zip(NUMERIC_FEATURES, rf.feature_importances_), key=lambda t: t[1], reverse=True)[:12]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": {"path": str(data), "name": args.name or data.name, "pages": len(items),
                    "phishing": n_ph, "benign": n_bn, "skipped": skipped,
                    "train": int(len(tr)), "test": int(len(te)), "test_size": args.test_size, "seed": args.seed},
        "versions": {"features": FEATURE_VERSION, "rules": RULESET_VERSION},
        "config": DEFAULT_CONFIG,
        "results": results,
        "latency_full_pipeline": latency,
        "feature_extraction_ms": {"mean": round(statistics.mean(feat_times), 2),
                                  "p95": round(float(np.percentile(feat_times, 95)), 2)},
        "rule_coverage": coverage,
        "errors": {"false_positives": sum(e["type"] == "false_positive" for e in errors),
                   "false_negatives": sum(e["type"] == "false_negative" for e in errors),
                   "rules_in_false_positives": dict(sorted(fp_rules.items(), key=lambda t: -t[1]))},
        "top_features_lr": [{"feature": n, "coef": round(float(c), 3)} for n, c in top_lr],
        "top_features_rf": [{"feature": n, "importance": round(float(v), 4)} for n, v in top_rf],
    }

    # ---- save the evaluated model as the served model -------------------------
    if not args.no_save:
        mp = settings.model_path
        mp.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(lr, mp)
        meta = {
            "version": "lr-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
            "algorithm": "StandardScaler + LogisticRegression(class_weight=balanced)",
            "feature_version": FEATURE_VERSION, "feature_order": NUMERIC_FEATURES,
            "trained_at": report["generated_at"], "n_train": int(len(tr)), "n_test": int(len(te)), "seed": args.seed,
            "dataset": f"{report['dataset']['name']} ({len(items)} pages)",
            "test_metrics": results["logistic_regression@0.5"], "sha256": model_mod._sha256(mp),
        }
        model_mod.meta_path(mp).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        report["saved_model"] = meta["version"]
        print(f"saved model {meta['version']} -> {mp}")

    (out / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    charts(out, yt, p_lr, p_rf, rule_scores, hybrid, pred_h, coverage, top_lr)
    (out / "evaluation.md").write_text(markdown(report), encoding="utf-8")
    print(json.dumps({k: {m: v[m] for m in ("precision", "recall", "f1", "false_positive_rate")}
                      for k, v in results.items()}, indent=2))
    print("latency:", latency)


def charts(out: Path, yt, p_lr, p_rf, rules, hybrid, pred_h, coverage, top_lr) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import precision_recall_curve, roc_curve

    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    colors = {"Hybrid (served)": "#2f5bea", "Logistic regression": "#1e7a3c", "Random forest": "#b26a00", "Rules only": "#8a94a6"}
    series = {"Hybrid (served)": hybrid, "Logistic regression": p_lr, "Random forest": p_rf, "Rules only": rules}

    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for name, s in series.items():
        fpr, tpr, _ = roc_curve(yt, s)
        axes[0].plot(fpr, tpr, label=name, color=colors[name], lw=2)
        pr, rc, _ = precision_recall_curve(yt, s)
        axes[1].plot(rc, pr, label=name, color=colors[name], lw=2)
    axes[0].plot([0, 1], [0, 1], ":", color="#bbb")
    axes[0].set(title="ROC curve (test set)", xlabel="False positive rate", ylabel="True positive rate")
    axes[1].set(title="Precision–recall (test set)", xlabel="Recall", ylabel="Precision", ylim=(0, 1.02))
    axes[1].legend(loc="lower left", frameon=False)
    fig.tight_layout()
    fig.savefig(out / "roc_pr.png", dpi=150)
    plt.close(fig)

    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(yt, pred_h, labels=[0, 1])
    fig, ax = plt.subplots(figsize=(4, 3.6))
    ax.imshow(cm, cmap="Blues")
    for (r, c), v in np.ndenumerate(cm):
        ax.text(c, r, str(v), ha="center", va="center", fontsize=14, color="white" if v > cm.max() / 2 else "black")
    ax.set_xticks([0, 1], ["benign", "phishing"])
    ax.set_yticks([0, 1], ["benign", "phishing"])
    ax.set(xlabel="Predicted", ylabel="Actual", title="Served hybrid @ phishing threshold")
    fig.tight_layout()
    fig.savefig(out / "confusion_matrix.png", dpi=150)
    plt.close(fig)

    cov = sorted(coverage, key=lambda c: c["fires_on_phishing_pct"])
    fig, ax = plt.subplots(figsize=(8, 6))
    ys = np.arange(len(cov))
    ax.barh(ys + 0.2, [c["fires_on_phishing_pct"] for c in cov], height=0.4, color="#c62828", label="phishing pages")
    ax.barh(ys - 0.2, [c["fires_on_benign_pct"] for c in cov], height=0.4, color="#1e7a3c", label="benign pages")
    ax.set_yticks(ys, [f"{c['id']} {c['name'][:34]}" for c in cov])
    ax.set(xlabel="% of pages where the rule fires", title="Rule coverage")
    ax.legend(frameon=False, loc="lower right")
    fig.tight_layout()
    fig.savefig(out / "rule_coverage.png", dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 4.5))
    names = [n for n, _ in top_lr][::-1]
    vals = [c for _, c in top_lr][::-1]
    ax.barh(names, vals, color=["#c62828" if v > 0 else "#1e7a3c" for v in vals])
    ax.axvline(0, color="#999", lw=0.8)
    ax.set(title="Logistic regression weights (red → phishing)", xlabel="coefficient (standardised features)")
    fig.tight_layout()
    fig.savefig(out / "lr_coefficients.png", dpi=150)
    plt.close(fig)


def markdown(r: dict) -> str:
    d = r["dataset"]
    lines = [f"# Evaluation report — {d['name']}", "",
             f"Generated {r['generated_at']} · features `{r['versions']['features']}` · rules `{r['versions']['rules']}`"
             + (f" · served model `{r['saved_model']}`" if r.get("saved_model") else ""), "",
             f"Dataset: **{d['pages']} pages** ({d['phishing']} phishing, {d['benign']} benign); "
             f"stratified split {d['train']} train / {d['test']} test (seed {d['seed']}).", "",
             "## T1–T3: precision, recall, F1 (held-out test set)", "",
             "| Method | Precision | Recall | F1 | Accuracy | FPR | ROC-AUC | TP | FP | FN | TN |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, m in r["results"].items():
        c = m["confusion_matrix"]
        lines.append(f"| {name} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['accuracy']:.3f} | "
                     f"{m['false_positive_rate']:.3f} | {m.get('roc_auc', float('nan')):.3f} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} |")
    lat = r["latency_full_pipeline"]
    e = r["errors"]
    lines += ["", "`@phishing` = flagged only when the score reaches the phishing threshold "
              f"({r['config']['phishing_threshold']}); `@suspicious` = flagged at the suspicious threshold "
              f"({r['config']['suspicious_threshold']}). FPR = false-positive rate on benign pages.", "",
              "![ROC and PR curves](roc_pr.png)", "", "![Confusion matrix](confusion_matrix.png)", "",
              "## T4: false-positive analysis", "",
              f"Served hybrid at the phishing threshold: **{e['false_positives']} false positives**, "
              f"**{e['false_negatives']} false negatives** on the test set. Every error is listed in `errors.csv` "
              "with the rules that fired and the model's top contributing features.", "",
              "Rules present in false positives: " + (", ".join(f"{k} ×{v}" for k, v in e["rules_in_false_positives"].items()) or "none"), "",
              "## Rule coverage (whole dataset)", "",
              "| Rule | Weight | Fires on phishing | Fires on benign | Precision |", "|---|---|---|---|---|"]
    for c in r["rule_coverage"]:
        lines.append(f"| {c['id']} {c['name']} | {c['weight']} | {c['fires_on_phishing_pct']}% | {c['fires_on_benign_pct']}% | "
                     f"{c['precision'] if c['precision'] is not None else '—'} |")
    lines += ["", "![Rule coverage](rule_coverage.png)", "",
              "## Decision latency", "",
              f"Full pipeline (parse → features → rules → model → decision) on {lat['pages_timed']} test pages: "
              f"mean **{lat['mean_ms']} ms**, median {lat['median_ms']} ms, p95 {lat['p95_ms']} ms, max {lat['max_ms']} ms.", "",
              "## Most influential features", "", "![LR coefficients](lr_coefficients.png)", "",
              "| Logistic regression | coef | Random forest | importance |", "|---|---|---|---|"]
    for a, b in zip(r["top_features_lr"], r["top_features_rf"]):
        lines.append(f"| {a['feature']} | {a['coef']} | {b['feature']} | {b['importance']} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
