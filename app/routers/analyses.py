"""Results, explanation data (FR-5), analyst feedback and export (FR-6)."""
from __future__ import annotations

import csv
import io
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from engine.features import NUMERIC_FEATURES

from .. import audit
from ..db import get_conn, new_id, now_iso, read_conn
from ..errors import INVALID_INPUT, NOT_FOUND, err
from ..security.deps import Principal, client_ip, require

router = APIRouter(prefix="/api/analyses", tags=["analyses"])

DECISIONS = {"phishing", "suspicious", "benign"}


def _row_to_result(row, principal: Principal) -> dict:
    result = json.loads(row["result_json"])
    base = {
        "id": row["id"], "sample_id": row["sample_id"], "created_at": row["created_at"],
        "filename": row["filename"], "source_url": row["source_url"], "label": row["label"],
        "config_version": row["config_version"], **result,
    }
    if principal.role == "viewer":
        # Restricted view: decision + reasons only, no raw evidence, features or source URL.
        return {
            "id": base["id"], "created_at": base["created_at"], "decision": base["decision"],
            "score": base["score"], "severity": base["severity"], "recommended_action": base["recommended_action"],
            "reasons": [{"name": r["name"], "reason": r["reason"]} for r in base["rules"]["fired"]],
            "restricted_view": True,
        }
    return base


_SELECT = """SELECT a.*, s.filename, s.source_url, s.label FROM analyses a JOIN samples s ON s.id = a.sample_id"""


@router.get("")
def list_analyses(decision: str | None = None, q: str | None = None, sample_id: str | None = None,
                  limit: int = 50, offset: int = 0, principal: Principal = Depends(require("result:read"))):
    limit, offset = max(1, min(limit, 200)), max(0, offset)
    where, params = [], []
    if decision:
        if decision not in DECISIONS:
            raise err(INVALID_INPUT, fields=["decision"])
        where.append("a.decision = ?")
        params.append(decision)
    if sample_id:
        where.append("a.sample_id = ?")
        params.append(sample_id)
    if q and principal.role != "viewer":
        where.append("(s.filename LIKE ? ESCAPE '\\' OR s.source_url LIKE ? ESCAPE '\\')")
        like = "%" + q[:100].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        params += [like, like]
    sql = _SELECT + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY a.created_at DESC, a.rowid DESC LIMIT ? OFFSET ?"
    with read_conn() as conn:
        rows = conn.execute(sql, params + [limit, offset]).fetchall()
        counts = {r["decision"]: r["n"] for r in conn.execute("SELECT decision, COUNT(*) AS n FROM analyses GROUP BY decision")}
    items = []
    for row in rows:
        full = _row_to_result(row, principal)
        items.append({k: full.get(k) for k in ("id", "sample_id", "created_at", "filename", "source_url", "decision",
                                                "score", "severity", "mode", "config_version", "label", "restricted_view")
                      if k in full})
    return {"items": items, "counts": counts}


@router.get("/{analysis_id}")
def get_analysis(analysis_id: str, principal: Principal = Depends(require("result:read"))):
    with read_conn() as conn:
        row = conn.execute(_SELECT + " WHERE a.id = ?", (analysis_id,)).fetchone()
        if row is None:
            raise err(NOT_FOUND)
        result = _row_to_result(row, principal)
        if principal.role != "viewer":
            result["feedback"] = [dict(f) for f in conn.execute(
                """SELECT f.id, f.verdict, f.comment, f.created_at, u.username FROM feedback f
                   JOIN users u ON u.id = f.user_id WHERE f.analysis_id = ? ORDER BY f.created_at""", (analysis_id,))]
    return result


class FeedbackIn(BaseModel):
    verdict: str = Field(pattern="^(correct|false_positive|false_negative)$")
    comment: str | None = Field(default=None, max_length=500)


@router.post("/{analysis_id}/feedback")
def add_feedback(analysis_id: str, body: FeedbackIn, request: Request,
                 principal: Principal = Depends(require("feedback:write"))):
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM analyses WHERE id = ?", (analysis_id,)).fetchone() is None:
            raise err(NOT_FOUND)
        fid = new_id()
        conn.execute("INSERT INTO feedback (id, analysis_id, verdict, comment, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                     (fid, analysis_id, body.verdict, (body.comment or "").strip() or None, principal.user_id, now_iso()))
        audit.record(conn, action="feedback.submit", actor=principal.username, role=principal.role, target=analysis_id,
                     ip=client_ip(request), details={"verdict": body.verdict})
    return {"id": fid, "verdict": body.verdict}


def _sanitized_report(row) -> dict:
    """Report for sharing: decision, reasons and versions. No raw HTML, evidence is already truncated."""
    r = json.loads(row["result_json"])
    return {
        "report_type": "phishlens.analysis", "analysis_id": row["id"], "analyzed_at": row["created_at"],
        "sample": {"filename": row["filename"], "declared_url": row["source_url"], "sha256": row["sha256"]},
        "decision": r["decision"], "score": r["score"], "confidence": r["confidence"], "severity": r["severity"],
        "recommended_action": r["recommended_action"], "mode": r["mode"],
        "rules_fired": [{k: f[k] for k in ("id", "name", "severity", "weight", "reason", "evidence")} for f in r["rules"]["fired"]],
        "rule_score": r["rules"]["score"],
        "ml": r["ml"], "thresholds": r["thresholds"], "versions": r["versions"],
        "config_version": row["config_version"], "latency_ms": r["latency_ms"],
    }


@router.get("/{analysis_id}/export")
def export_one(analysis_id: str, request: Request, format: str = "json",
               principal: Principal = Depends(require("export:run"))):
    if format not in {"json", "csv"}:
        raise err(INVALID_INPUT, fields=["format"])
    with get_conn() as conn:
        row = conn.execute("""SELECT a.*, s.filename, s.source_url, s.sha256 FROM analyses a
                              JOIN samples s ON s.id = a.sample_id WHERE a.id = ?""", (analysis_id,)).fetchone()
        if row is None:
            raise err(NOT_FOUND)
        report = _sanitized_report(row)
        audit.record(conn, action="report.export", actor=principal.username, role=principal.role, target=analysis_id,
                     ip=client_ip(request), details={"format": format})
    if format == "json":
        return Response(json.dumps(report, indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="phishlens-{analysis_id[:8]}.json"'})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["field", "value"])
    for key in ("analysis_id", "analyzed_at", "decision", "score", "confidence", "severity", "recommended_action",
                "mode", "rule_score", "config_version", "latency_ms"):
        w.writerow([key, _csv_safe(report[key])])
    for f in report["rules_fired"]:
        w.writerow([f"rule {f['id']}", _csv_safe(f"{f['name']}: {f['reason']} {'; '.join(f['evidence'])}")])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="phishlens-{analysis_id[:8]}.csv"'})


@router.get("/export/history.csv")
def export_history(request: Request, principal: Principal = Depends(require("export:run"))):
    with get_conn() as conn:
        rows = conn.execute(_SELECT + " ORDER BY a.created_at DESC LIMIT 5000").fetchall()
        audit.record(conn, action="report.export", actor=principal.username, role=principal.role, target="history",
                     ip=client_ip(request), details={"format": "csv", "rows": len(rows)})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["analysis_id", "created_at", "filename", "declared_url", "label", "decision", "score", "rule_score",
                "ml_probability", "model_version", "ruleset_version", "config_version", "latency_ms", "rules_fired"])
    for r in rows:
        fired = ";".join(f["id"] for f in json.loads(r["result_json"])["rules"]["fired"])
        w.writerow([_csv_safe(v) for v in (r["id"], r["created_at"], r["filename"], r["source_url"], r["label"],
                                           r["decision"], r["score"], r["rule_score"], r["ml_probability"],
                                           r["model_version"], r["ruleset_version"], r["config_version"],
                                           r["latency_ms"], fired)])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="phishlens-history.csv"'})


def _csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection (=, +, -, @ at the start of a cell)."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@router.get("/meta/features")
def feature_names(principal: Principal = Depends(require("result:read"))):
    return {"features": NUMERIC_FEATURES}
