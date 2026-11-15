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
        try:
            fr = extract(html, row.get("source_url") or None)
            rr = eval_rules(fr)
        except Exception as exc:  # a crash here is a robustness bug worth reporting
            print(f"  extraction failed for {path.name}: {type(exc).__name__}: {exc}")
            skipped += 1
            continue
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
    ap.add_argument("--max-fpr", type=float, default=0.02, help="target false-positive rate for the phishing threshold")
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

    # ---- model selection + calibration on the TRAIN split only (5-fold CV) ----
    from sklearn.model_selection import StratifiedKFold
    from sklearn.metrics import f1_score
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.seed)
    rules_all = np.array([it["rules"]["score"] for it in items])
    cv = {}
    oof = {}
    for algo in ("logistic_regression", "random_forest"):
        probs = np.zeros(len(tr))
        for a, b in skf.split(X[tr], y[tr]):
            m = model_mod.make_pipeline(algo, args.seed).fit(X[tr][a], y[tr][a])
            probs[b] = m.predict_proba(X[tr][b])[:, 1]
        oof[algo] = probs
        cv[algo] = {"oof_f1@0.5": round(float(f1_score(y[tr], probs >= 0.5)), 4),
                    "oof_roc_auc": round(float(roc_auc_score(y[tr], probs)), 4)}
    served_algo = max(cv, key=lambda k: (cv[k]["oof_f1@0.5"], cv[k]["oof_roc_auc"]))
    print("cross-validation:", cv, "-> serving", served_algo)

    # Grid-search the hybrid weight and thresholds on out-of-fold predictions (never on test).
    rtr = rules_all[tr]
    best = None
    for w in (0.5, 0.6, 0.7, 0.8, 0.9, 1.0):
        hy = w * oof[served_algo] + (1 - w) * rtr
        for ts in np.arange(0.20, 0.81, 0.02):
            f1 = f1_score(y[tr], hy >= ts)
            # ties: prefer the threshold closest to 0.5 and the larger ML weight (more stable)
            if best is None or f1 > best[0] + 1e-9 or (abs(f1 - best[0]) <= 1e-9 and abs(ts - 0.5) < abs(best[2] - 0.5)):
                best = (f1, w, round(float(ts), 2), hy)
    _, w_best, ts_best, hy_best = best
    neg = hy_best[y[tr] == 0]
    tp_best = next((round(float(t), 2) for t in np.arange(ts_best, 0.99, 0.01)
                    if (neg >= t).mean() <= args.max_fpr), 0.95)
    recommended = {"phishing_threshold": max(tp_best, round(ts_best + 0.05, 2)), "suspicious_threshold": ts_best,
                   "ml_weight": w_best, "disabled_rules": []}
    print("recommended config (from CV):", recommended)

    # ---- final models on the full train split, scored once on the held-out test split ----
    lr = model_mod.make_pipeline("logistic_regression", args.seed).fit(X[tr], y[tr])
    rf = model_mod.make_pipeline("random_forest", args.seed).fit(X[tr], y[tr])
    served = lr if served_algo == "logistic_regression" else rf

    p_lr = lr.predict_proba(X[te])[:, 1]
    p_rf = rf.predict_proba(X[te])[:, 1]
    p_served = served.predict_proba(X[te])[:, 1]
    rule_scores = rules_all[te]
    yt = y[te]

    def flag(scores, thr):
        return (scores >= thr).astype(int)

    d = DEFAULT_CONFIG
    hybrid_default = d["ml_weight"] * p_lr + (1 - d["ml_weight"]) * rule_scores
    hybrid = w_best * p_served + (1 - w_best) * rule_scores
    results = {
        "rules_only@0.40": metrics(yt, flag(rule_scores, 0.4), rule_scores),
        "logistic_regression@0.5": metrics(yt, flag(p_lr, 0.5), p_lr),
        "random_forest@0.5": metrics(yt, flag(p_rf, 0.5), p_rf),
        "hybrid_untuned@0.40 (LR, w=0.6)": metrics(yt, flag(hybrid_default, 0.4), hybrid_default),
        "served@suspicious": metrics(yt, flag(hybrid, ts_best), hybrid),
        "served@phishing": metrics(yt, flag(hybrid, recommended["phishing_threshold"]), hybrid),
    }
    pthr = recommended["phishing_threshold"]
    lr = served  # the model used for explanations / error analysis below is the served one

    # ---- full-pipeline latency on test pages ------------------------------
    loaded = model_mod.LoadedModel(pipeline=served, meta={"version": "eval", "feature_order": NUMERIC_FEATURES})
    from engine.pipeline import analyze
    lat = []
    for i in te[: min(len(te), 300)]:
        html = (data / items[i]["file"]).read_text(encoding="utf-8", errors="replace")
        t0 = time.perf_counter()
        analyze(html, items[i]["url"] or None, recommended, loaded)
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
    contrib_model = model_mod.LoadedModel(pipeline=served, meta={"version": "eval", "feature_order": NUMERIC_FEATURES})
    errors = []
    pred_h = flag(hybrid, ts_best)  # errors = anything the served config does not flag / wrongly flags
    for k, i in enumerate(te):
        if pred_h[k] != yt[k]:
            ml = contrib_model.predict(items[i]["fr"], top_k=3)
            errors.append({
                "type": "false_positive" if pred_h[k] == 1 else "false_negative",
                "file": items[i]["file"], "url": items[i]["url"][:120],
                "hybrid_score": round(float(hybrid[k]), 3), "ml_prob": round(float(p_served[k]), 3),
                "rule_score": round(float(rule_scores[k]), 3),
                "rules_fired": " ".join(f["id"] for f in items[i]["rules"]["fired"]),
                "top_model_features": "; ".join(f"{t['feature']}={t['value']:g} ({t['contribution']:+.3f})"
                                                for t in ml["top_features"]),
                "decision": decide(float(hybrid[k]), recommended),
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
    lr_model = model_mod.make_pipeline("logistic_regression", args.seed).fit(X[tr], y[tr])
    coefs = lr_model.named_steps["clf"].coef_[0]
    top_lr = sorted(zip(NUMERIC_FEATURES, coefs), key=lambda t: abs(t[1]), reverse=True)[:12]
    top_rf = sorted(zip(NUMERIC_FEATURES, rf.named_steps['clf'].feature_importances_), key=lambda t: t[1], reverse=True)[:12]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": {"path": str(data), "name": args.name or data.name, "pages": len(items),
                    "phishing": n_ph, "benign": n_bn, "skipped": skipped,
                    "train": int(len(tr)), "test": int(len(te)), "test_size": args.test_size, "seed": args.seed},
        "versions": {"features": FEATURE_VERSION, "rules": RULESET_VERSION},
        "config_default": DEFAULT_CONFIG,
        "config": recommended,
        "cross_validation": cv,
        "served_algorithm": served_algo,
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
        joblib.dump(served, mp)
        meta = {
            "version": ("rf-" if served_algo == "random_forest" else "lr-") + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
            "algorithm": model_mod.ALGORITHM_LABELS[served_algo],
            "algorithm_id": served_algo,
            "recommended_config": recommended,
            "cross_validation": cv,
            "feature_version": FEATURE_VERSION, "feature_order": NUMERIC_FEATURES,
            "trained_at": report["generated_at"], "n_train": int(len(tr)), "n_test": int(len(te)), "seed": args.seed,
            "dataset": f"{report['dataset']['name']} ({len(items)} pages)",
            "test_metrics": results["served@suspicious"], "sha256": model_mod._sha256(mp),
        }
        model_mod.meta_path(mp).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        report["saved_model"] = meta["version"]
        print(f"saved model {meta['version']} -> {mp}")

    with (out / "test_predictions.csv").open("w", newline="", encoding="utf-8") as f:
        wri = csv.writer(f)
        wri.writerow(["file", "y", "p_lr", "p_rf", "p_served", "rule_score", "hybrid"])
        for k, i in enumerate(te):
            wri.writerow([items[i]["file"], int(yt[k]), round(float(p_lr[k]), 5), round(float(p_rf[k]), 5),
                          round(float(p_served[k]), 5),
                          round(float(rule_scores[k]), 5), round(float(hybrid[k]), 5)])
    (out / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    charts(out, yt, p_lr, p_rf, rule_scores, hybrid, pred_h, coverage, top_lr)
    (out / "evaluation.md").write_text(markdown(report), encoding="utf-8")
    print(json.dumps({k: {m: v[m] for m in ("precision", "recall", "f1", "false_positive_rate", "roc_auc")}
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
    cvt = ", ".join(f"{k}: OOF F1 {v['oof_f1@0.5']}, AUC {v['oof_roc_auc']}" for k, v in r["cross_validation"].items())
    cfg = r["config"]
    lines += ["", f"**Served configuration** (chosen by 5-fold cross-validation on the training split only — "
              f"the test split was not used for any choice): model `{r['served_algorithm']}` ({cvt}); "
              f"score = {cfg['ml_weight']} × ML + {round(1 - cfg['ml_weight'], 2)} × rules; "
              f"suspicious ≥ {cfg['suspicious_threshold']}, phishing ≥ {cfg['phishing_threshold']} "
              f"(phishing threshold set for ≤ 2% false positives on training folds).", "",
              "`served@suspicious` = page flagged as suspicious or phishing (the analyst queue); "
              "`served@phishing` = high-confidence phishing only. `hybrid_untuned` = the hand-set starter config "
              "(LR, weight 0.6, threshold 0.4) for comparison. FPR = false-positive rate on benign pages.", "",
              "![ROC and PR curves](roc_pr.png)", "", "![Confusion matrix](confusion_matrix.png)", "",
              "## T4: false-positive analysis", "",
              f"Served configuration at the suspicious threshold: **{e['false_positives']} false positives**, "
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
