"""Dashboard summary: status, severity, recent high-risk results, latency, feedback."""
from __future__ import annotations

import json
import statistics
from collections import Counter
from datetime import datetime, timedelta, UTC

from fastapi import APIRouter, Depends

from .. import services
from ..db import current_config, read_conn
from ..security.deps import Principal, require

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("")
def dashboard(principal: Principal = Depends(require("result:read"))):
    since_24h = (datetime.now(UTC) - timedelta(hours=24)).isoformat(timespec="seconds")
    with read_conn() as conn:
        by_decision = {r["decision"]: r["n"] for r in conn.execute(
            "SELECT decision, COUNT(*) AS n FROM analyses GROUP BY decision")}
        last_24h = conn.execute("SELECT COUNT(*) AS n FROM analyses WHERE created_at >= ?", (since_24h,)).fetchone()["n"]
        recent = conn.execute(
            """SELECT a.id, a.created_at, a.decision, a.score, a.latency_ms, a.result_json, s.filename
               FROM analyses a JOIN samples s ON s.id = a.sample_id ORDER BY a.created_at DESC, a.rowid DESC LIMIT 500"""
        ).fetchall()
        feedback = {r["verdict"]: r["n"] for r in conn.execute(
            "SELECT verdict, COUNT(*) AS n FROM feedback GROUP BY verdict")}
        samples = conn.execute(
            "SELECT COUNT(*) AS n, SUM(label IS NOT NULL) AS labeled FROM samples").fetchone()
        config_version, _ = current_config(conn)

    severity: Counter = Counter()
    rule_hits: Counter = Counter()
    rule_names: dict[str, str] = {}
    high_risk = []
    latencies = []
    for row in recent:
        res = json.loads(row["result_json"])
        severity[res.get("severity", "none")] += 1
        latencies.append(row["latency_ms"])
        for f in res["rules"]["fired"]:
            rule_hits[f["id"]] += 1
            rule_names[f["id"]] = f["name"]
        if row["decision"] == "phishing" and len(high_risk) < 8:
            item = {"id": row["id"], "created_at": row["created_at"], "score": row["score"], "severity": res.get("severity")}
            if principal.role != "viewer":
                item["filename"] = row["filename"]
                item["top_reason"] = res["rules"]["fired"][0]["name"] if res["rules"]["fired"] else None
            high_risk.append(item)

    latency = None
    if latencies:
        ordered = sorted(latencies)
        latency = {"mean_ms": round(statistics.mean(latencies), 2),
                   "p95_ms": round(ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))], 2),
                   "sample": len(latencies)}
    model = services.model_info()
    return {
        "status": {"model": model.get("status"), "model_version": model.get("version"), "config_version": config_version},
        "totals": {"analyses": sum(by_decision.values()), "last_24h": last_24h,
                   "samples": samples["n"], "labeled_samples": samples["labeled"] or 0},
        "by_decision": by_decision,
        "by_severity": dict(severity),
        "top_rules": [{"id": k, "name": rule_names[k], "count": v} for k, v in rule_hits.most_common(6)],
        "recent_high_risk": high_risk,
        "latency": latency,
        "feedback": feedback if principal.role != "viewer" else None,
    }
