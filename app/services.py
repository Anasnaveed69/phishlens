"""Business logic shared by routers — storing samples and running analyses."""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading

from datetime import UTC

from engine import model as model_mod
from engine.pipeline import analyze

from . import audit
from .config import settings
from .db import current_config, new_id, now_iso, read_conn

log = logging.getLogger("phishlens")

_model_lock = threading.Lock()
_model: model_mod.LoadedModel | None = None
_model_status = "not_loaded"


def load_model() -> str:
    """(Re)load the model from disk. Never crashes the app: falls back to rules-only."""
    global _model, _model_status
    with _model_lock:
        try:
            _model = model_mod.load(settings.model_path, settings.model_sha256)
            _model_status = "loaded" if _model else "missing"
        except model_mod.ModelIntegrityError as exc:
            log.error("Model integrity check failed: %s", exc)
            _model, _model_status = None, "integrity_failed"
        except Exception:  # corrupt metadata/pickle, version mismatch, ... -> keep serving in rules-only mode
            log.exception("Model could not be loaded")
            _model, _model_status = None, "load_failed"
    return _model_status


def model_info() -> dict:
    if _model is None:
        return {"status": _model_status, "version": None}
    meta = {k: v for k, v in _model.meta.items() if k not in {"feature_order"}}
    return {"status": _model_status, **meta}


def sample_path(sha256: str):
    # Server-generated name (hash) -> no user-controlled paths on disk.
    return settings.sample_dir / f"{sha256}.html.txt"


def store_sample(conn: sqlite3.Connection, *, filename: str, html: str, size: int,
                 source_url: str | None, label: str | None, user_id: str) -> tuple[dict, bool]:
    """Insert a sample, or return the existing one if identical content was uploaded before."""
    digest = hashlib.sha256(html.encode("utf-8", errors="replace")).hexdigest()
    existing = conn.execute("SELECT * FROM samples WHERE sha256 = ?", (digest,)).fetchone()
    if existing:
        row = dict(existing)
        changes = {}
        if row.get("purged_at"):  # the same page uploaded again after a purge: store it again
            sample_path(digest).write_text(html, encoding="utf-8")
            conn.execute("UPDATE samples SET purged_at = NULL WHERE id = ?", (row["id"],))
            row["purged_at"] = None
        # Same bytes, newly declared URL/label: the submitter's latest declaration wins (and is audited),
        # instead of silently analysing with the old URL (independent review finding S4).
        if source_url and source_url != row["source_url"]:
            changes["source_url"] = {"from": row["source_url"], "to": source_url}
        if label and label != row["label"]:
            changes["label"] = {"from": row["label"], "to": label}
        if changes:
            conn.execute("UPDATE samples SET source_url = COALESCE(?, source_url), label = COALESCE(?, label) WHERE id = ?",
                         (source_url, label, row["id"]))
            audit.record(conn, action="sample.update", actor=None, target=row["id"], details=changes)
            row = dict(conn.execute("SELECT * FROM samples WHERE id = ?", (row["id"],)).fetchone())
        return row, True
    sample_id = new_id()
    settings.sample_dir.mkdir(parents=True, exist_ok=True)
    sample_path(digest).write_text(html, encoding="utf-8")
    conn.execute(
        """INSERT INTO samples (id, filename, sha256, source_url, label, size_bytes, uploaded_by, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (sample_id, filename, digest, source_url, label, size, user_id, now_iso()),
    )  # writers are serialised (BEGIN IMMEDIATE in db.get_conn), so the sha256 check above cannot race
    row = conn.execute("SELECT * FROM samples WHERE id = ?", (sample_id,)).fetchone()
    return dict(row), False


def compute_analysis(html: str, source_url: str | None, conn: sqlite3.Connection | None = None) -> tuple[int, dict]:
    """Parse, features, rules, model -> (config_version, result). Reads the config through `conn`
    when given (same transaction as the save), otherwise through a read-only snapshot."""
    if conn is not None:
        config_version, config = current_config(conn)
    else:
        with read_conn() as rc:
            config_version, config = current_config(rc)
    result = analyze(html, source_url, config, _model)
    result["config_version"] = config_version
    return config_version, result


def save_analysis(conn: sqlite3.Connection, sample: dict, prepared: tuple[int, dict], user_id: str,
                  username: str, role: str, ip: str | None) -> dict:
    """Short write: store a computed result and its audit event."""
    config_version, result = prepared
    analysis_id = new_id()
    created = now_iso()
    conn.execute(
        """INSERT INTO analyses (id, sample_id, decision, score, rule_score, ml_probability, model_version,
               ruleset_version, config_version, result_json, latency_ms, created_by, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (analysis_id, sample["id"], result["decision"], result["score"], result["rules"]["score"],
         result["ml"]["probability"] if result["ml"] else None, result["versions"]["model"],
         result["versions"]["rules"], config_version, json.dumps(result), result["latency_ms"], user_id, created),
    )
    audit.record(conn, action="analysis.decision", actor=username, role=role, target=analysis_id, ip=ip,
                 details={"sample_id": sample["id"], "decision": result["decision"], "score": result["score"],
                          "rules_fired": [r["id"] for r in result["rules"]["fired"]],
                          "model_version": result["versions"]["model"], "config_version": config_version})
    return {"id": analysis_id, "sample_id": sample["id"], "created_at": created, **result}


def run_analysis(conn: sqlite3.Connection, sample: dict, user_id: str, username: str, role: str,
                 ip: str | None) -> dict:
    """Compute + save inside the caller's write transaction (config read in the same transaction)."""
    html = read_sample_html(sample)
    return save_analysis(conn, sample, compute_analysis(html, sample["source_url"], conn), user_id, username, role, ip)


def purge_raw_pages(conn: sqlite3.Connection, older_than_days: int) -> int:
    """Remove stored HTML for samples older than N days (data minimisation). Returns how many."""
    from datetime import datetime, timedelta
    cutoff = (datetime.now(UTC) - timedelta(days=older_than_days)).isoformat(timespec="seconds")
    rows = conn.execute("SELECT id, sha256 FROM samples WHERE created_at <= ? AND purged_at IS NULL", (cutoff,)).fetchall()
    for r in rows:
        sample_path(r["sha256"]).unlink(missing_ok=True)
        conn.execute("UPDATE samples SET purged_at = ? WHERE id = ?", (now_iso(), r["id"]))
    return len(rows)


def read_sample_html(sample: dict) -> str:
    if sample.get("purged_at"):
        from .errors import SAMPLE_PURGED, err
        raise err(SAMPLE_PURGED)
    return sample_path(sample["sha256"]).read_text(encoding="utf-8")
