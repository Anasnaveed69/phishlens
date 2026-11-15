"""End-to-end analysis: validated page -> features -> rules -> ML -> explainable decision.

The output stores every version, threshold and reason needed to reproduce the decision.
"""
from __future__ import annotations

import time

from .features import FEATURE_VERSION, extract
from .model import LoadedModel
from .rules import evaluate

ACTIONS = {
    "phishing": "Block the page and report it. Do not enter any credentials.",
    "suspicious": "Have an analyst review the evidence before allowing access.",
    "benign": "No action needed. Keep monitoring.",
}


def decide(score: float, config: dict) -> str:
    if score >= config["phishing_threshold"]:
        return "phishing"
    if score >= config["suspicious_threshold"]:
        return "suspicious"
    return "benign"


def analyze(html: str, url: str | None, config: dict, model: LoadedModel | None) -> dict:
    started = time.perf_counter()
    features = extract(html, url)
    rule_result = evaluate(features, config.get("disabled_rules"))

    ml_result = model.predict(features) if model else None
    if ml_result is not None:
        w = float(config["ml_weight"])
        score = w * ml_result["probability"] + (1 - w) * rule_result["score"]
        mode = "hybrid"
    else:
        score = rule_result["score"]
        mode = "rules_only"  # safe degradation when no model is available
    score = round(score, 4)
    decision = decide(score, config)

    severity = "none"
    if rule_result["fired"]:
        order = {"low": 1, "medium": 2, "high": 3}
        severity = max((r["severity"] for r in rule_result["fired"]), key=order.get)

    return {
        "decision": decision,
        "score": score,
        "confidence": round(abs(score - 0.5) * 2, 4),  # 0 = on the fence, 1 = very sure
        "severity": severity,
        "mode": mode,
        "recommended_action": ACTIONS[decision],
        "rules": rule_result,
        "ml": ml_result,
        "thresholds": {
            "phishing": config["phishing_threshold"],
            "suspicious": config["suspicious_threshold"],
            "ml_weight": config["ml_weight"] if ml_result else 0.0,
        },
        "features": features.values,
        "page_domain": features.page_domain,
        "brands_found": features.brands_found,
        "versions": {
            "features": FEATURE_VERSION,
            "rules": rule_result["ruleset_version"],
            "model": ml_result["model_version"] if ml_result else None,
        },
        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
    }
