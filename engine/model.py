"""ML classifier (FR-4).

Two explainable model families are supported; scripts/evaluate.py picks the better one by
5-fold cross-validation on the training split only:

* LogisticRegression (with StandardScaler): contribution of feature i = coef_i * scaled_x_i
  (log-odds units). Sum of contributions + intercept = the model's log-odds exactly.
* RandomForest: per-feature contributions via path decomposition (Saabas / "treeinterpreter"):
  walking each tree from root to leaf, the change in P(phishing) at every split is credited to
  the split feature. Bias + sum of contributions = the forest's probability exactly.

Integrity: joblib files are pickles and can run code when loaded, so we only load a
model whose SHA-256 matches the value recorded in its metadata file next to it, and
both files live in a folder only the app owner can write to.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_VERSION, NUMERIC_FEATURES, FeatureResult


class ModelIntegrityError(Exception):
    pass


@dataclass
class LoadedModel:
    pipeline: Pipeline
    meta: dict

    @property
    def version(self) -> str:
        return self.meta["version"]

    def predict(self, features: FeatureResult, top_k: int = 6) -> dict:
        order = self.meta["feature_order"]
        x = np.array([[float(features.values[n]) for n in order]])
        prob = float(self.pipeline.predict_proba(x)[0, 1])
        contrib, unit = explain_contributions(self.pipeline, x)
        ranked = sorted(zip(order, contrib, x[0]), key=lambda t: abs(t[1]), reverse=True)
        top = [
            {"feature": name, "value": round(float(val), 4), "contribution": round(float(c), 4),
             "direction": "towards phishing" if c > 0 else "towards benign"}
            for name, c, val in ranked[:top_k] if abs(c) > 1e-6
        ]
        return {"probability": round(prob, 4), "model_version": self.version, "algorithm": self.meta.get("algorithm"),
                "contribution_unit": unit, "top_features": top}


def explain_contributions(pipe, x: np.ndarray) -> tuple[np.ndarray, str]:
    """Per-feature contributions for one sample (shape (1, n_features))."""
    clf = pipe.named_steps["clf"]
    if isinstance(clf, LogisticRegression):
        scaler: StandardScaler = pipe.named_steps["scaler"]
        return scaler.transform(x)[0] * clf.coef_[0], "log-odds"
    if isinstance(clf, RandomForestClassifier):
        return _forest_contributions(clf, pipe.named_steps["scaler"].transform(x)[0]), "probability"
    raise TypeError(f"no explainer for {type(clf).__name__}")


def _forest_contributions(forest: RandomForestClassifier, x: np.ndarray) -> np.ndarray:
    pos = list(forest.classes_).index(1)
    total = np.zeros(x.shape[0])
    for est in forest.estimators_:
        tree = est.tree_
        values = tree.value[:, 0, :]
        p1 = values[:, pos] / values.sum(axis=1)
        node = 0
        while tree.children_left[node] != -1:
            feat = tree.feature[node]
            child = tree.children_left[node] if x[feat] <= tree.threshold[node] else tree.children_right[node]
            total[feat] += p1[child] - p1[node]
            node = child
    return total / len(forest.estimators_)


def make_pipeline(algorithm: str, seed: int = 42) -> Pipeline:
    if algorithm == "random_forest":
        clf = RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced",
                                     random_state=seed, n_jobs=-1)
    else:
        clf = LogisticRegression(max_iter=5000, class_weight="balanced", random_state=seed)
    return Pipeline([("scaler", StandardScaler()), ("clf", clf)])


ALGORITHM_LABELS = {
    "logistic_regression": "StandardScaler + LogisticRegression(class_weight=balanced)",
    "random_forest": "RandomForest(300 trees, min_samples_leaf=2, class_weight=balanced) + path-decomposition explanations",
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def meta_path(model_path: Path) -> Path:
    return model_path.with_suffix(".meta.json")


def metrics(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def train(X: list[list[float]], y: list[int], model_path: Path, dataset_note: str, seed: int = 42) -> dict:
    X_arr, y_arr = np.array(X, dtype=float), np.array(y, dtype=int)
    X_tr, X_te, y_tr, y_te = train_test_split(X_arr, y_arr, test_size=0.25, random_state=seed, stratify=y_arr)
    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed)),
    ])
    pipe.fit(X_tr, y_tr)
    test_metrics = metrics(y_te, pipe.predict(X_te))

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, model_path)
    version = "lr-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    meta = {
        "version": version,
        "algorithm": "StandardScaler + LogisticRegression(class_weight=balanced)",
        "feature_version": FEATURE_VERSION,
        "feature_order": NUMERIC_FEATURES,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "n_train": int(len(y_tr)),
        "n_test": int(len(y_te)),
        "seed": seed,
        "dataset": dataset_note,
        "test_metrics": test_metrics,
        "sha256": _sha256(model_path),
    }
    meta_path(model_path).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def load(model_path: Path) -> LoadedModel | None:
    """Return the model, or None if no model has been trained yet (rules-only mode)."""
    mp = meta_path(model_path)
    if not model_path.exists() or not mp.exists():
        return None
    meta = json.loads(mp.read_text(encoding="utf-8"))
    if _sha256(model_path) != meta.get("sha256"):
        raise ModelIntegrityError("Model file hash does not match its metadata; refusing to load.")
    order = meta.get("feature_order") or []
    if not order or not set(order) <= set(NUMERIC_FEATURES):
        raise ModelIntegrityError("Model was trained with a different feature set; retrain it.")
    pipe = joblib.load(model_path)
    clf = pipe.named_steps.get("clf")
    if hasattr(clf, "n_jobs"):
        clf.n_jobs = 1  # single-page predictions: thread start-up costs more than it saves
    return LoadedModel(pipeline=pipe, meta=meta)
