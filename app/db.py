"""Repository layer: SQLite connection + schema.

Rules for everyone touching this file:
  * ALWAYS use parameterized queries (`?` placeholders). Never build SQL with f-strings.
  * IDs are generated server-side (uuid4), never taken from the client.
  * audit_events is append-only: triggers below block UPDATE and DELETE.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

from .config import settings

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,          -- sha256 of the cookie value; raw token never stored
    user_id     TEXT NOT NULL REFERENCES users(id),
    csrf_token  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS samples (
    id          TEXT PRIMARY KEY,
    filename    TEXT NOT NULL,             -- sanitized display name only
    sha256      TEXT NOT NULL UNIQUE,      -- duplicate submissions map to the same sample
    source_url  TEXT,                      -- as declared by the user; never fetched
    label       TEXT CHECK (label IN ('phishing', 'benign') OR label IS NULL),
    size_bytes  INTEGER NOT NULL,
    uploaded_by TEXT NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyses (
    id              TEXT PRIMARY KEY,
    sample_id       TEXT NOT NULL REFERENCES samples(id),
    decision        TEXT NOT NULL,         -- phishing | suspicious | benign
    score           REAL NOT NULL,
    rule_score      REAL NOT NULL,
    ml_probability  REAL,                  -- NULL when no model is loaded (rules-only mode)
    model_version   TEXT,
    ruleset_version TEXT NOT NULL,
    config_version  INTEGER NOT NULL,
    result_json     TEXT NOT NULL,         -- full explainable result (evidence, thresholds, reasons)
    latency_ms      REAL NOT NULL,
    created_by      TEXT NOT NULL REFERENCES users(id),
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feedback (
    id          TEXT PRIMARY KEY,
    analysis_id TEXT NOT NULL REFERENCES analyses(id),
    verdict     TEXT NOT NULL CHECK (verdict IN ('correct', 'false_positive', 'false_negative')),
    comment     TEXT,
    user_id     TEXT NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL
);

-- Every config change creates a new version row; old versions are kept so any
-- analysis can be reproduced with the exact settings it used.
CREATE TABLE IF NOT EXISTS config_versions (
    version     INTEGER PRIMARY KEY AUTOINCREMENT,
    config_json TEXT NOT NULL,
    changed_by  TEXT,
    reason      TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    id         TEXT NOT NULL UNIQUE,
    ts         TEXT NOT NULL,
    actor      TEXT,                       -- username or NULL for anonymous
    role       TEXT,
    action     TEXT NOT NULL,              -- e.g. auth.login, sample.upload, config.update
    target     TEXT,
    outcome    TEXT NOT NULL,              -- success | denied | failure
    ip         TEXT,
    details    TEXT NOT NULL,              -- redacted JSON
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL               -- sha256(prev_hash + canonical event) -> tamper-evident chain
);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;

CREATE INDEX IF NOT EXISTS idx_analyses_sample ON analyses(sample_id);
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
"""

DEFAULT_CONFIG = {
    "phishing_threshold": 0.70,    # final score >= this -> phishing
    "suspicious_threshold": 0.40,  # final score >= this -> suspicious
    "ml_weight": 0.60,             # final = ml_weight * ml + (1 - ml_weight) * rules
    "disabled_rules": [],          # rule ids an admin has switched off
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id() -> str:
    return str(uuid.uuid4())


def connect() -> sqlite3.Connection:
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    settings.sample_dir.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        row = conn.execute("SELECT COUNT(*) AS n FROM config_versions").fetchone()
        if row["n"] == 0:
            cfg, reason = _initial_config()
            conn.execute(
                "INSERT INTO config_versions (config_json, changed_by, reason, created_at) VALUES (?, ?, ?, ?)",
                (json.dumps(cfg), None, reason, now_iso()),
            )


def _initial_config() -> tuple[dict, str]:
    """Use the thresholds calibrated by scripts/evaluate.py (stored in the model metadata) when a
    trained model is present; otherwise fall back to the hand-set defaults."""
    meta_file = settings.model_path.with_suffix(".meta.json")
    try:
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        rec = meta.get("recommended_config")
        if rec and {"phishing_threshold", "suspicious_threshold", "ml_weight"} <= set(rec):
            return {**DEFAULT_CONFIG, **rec}, f"calibrated for model {meta.get('version')} (cross-validation)"
    except (OSError, ValueError):
        pass
    return dict(DEFAULT_CONFIG), "initial defaults"


def current_config(conn: sqlite3.Connection) -> tuple[int, dict]:
    row = conn.execute(
        "SELECT version, config_json FROM config_versions ORDER BY version DESC LIMIT 1"
    ).fetchone()
    return row["version"], json.loads(row["config_json"])
