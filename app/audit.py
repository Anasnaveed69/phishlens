"""Append-only, hash-chained audit log.

Each event stores hash = sha256(prev_hash || canonical_json(event)). If anyone edits
or removes a row directly in the DB file, verify_chain() reports where the chain breaks.
The DB triggers in db.py additionally block UPDATE/DELETE through SQLite.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from typing import Any

from .db import new_id, now_iso

GENESIS = "0" * 64

# Keys whose values must never reach the log.
_SECRET_KEYS = re.compile(r"pass(word)?|secret|token|csrf|cookie|session|authorization|api[_-]?key", re.I)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_MAX_STR = 200


def redact(value: Any) -> Any:
    """Recursively strip secrets, mask e-mail addresses and truncate long strings."""
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if _SECRET_KEYS.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value][:50]
    if isinstance(value, str):
        v = _EMAIL.sub("[email]", value)
        return v if len(v) <= _MAX_STR else v[:_MAX_STR] + "…"
    return value


def _canonical(event: dict) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"))


def _event_hash(prev_hash: str, event: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(event)).encode("utf-8")).hexdigest()


def record(
    conn: sqlite3.Connection,
    action: str,
    outcome: str = "success",
    actor: str | None = None,
    role: str | None = None,
    target: str | None = None,
    ip: str | None = None,
    details: dict | None = None,
) -> str:
    last = conn.execute("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
    prev_hash = last["hash"] if last else GENESIS
    event = {
        "id": new_id(),
        "ts": now_iso(),
        "actor": actor,
        "role": role,
        "action": action,
        "target": target,
        "outcome": outcome,
        "ip": ip,
        "details": json.dumps(redact(details or {}), sort_keys=True),
    }
    h = _event_hash(prev_hash, event)
    conn.execute(
        """INSERT INTO audit_events (id, ts, actor, role, action, target, outcome, ip, details, prev_hash, hash)
           VALUES (:id, :ts, :actor, :role, :action, :target, :outcome, :ip, :details, :prev_hash, :hash)""",
        {**event, "prev_hash": prev_hash, "hash": h},
    )
    return event["id"]


def record_separately(**kwargs: Any) -> None:
    """Write an audit event in its own transaction (used for denials/failures where
    the main request transaction is about to be rolled back)."""
    from .db import get_conn

    with get_conn() as conn:
        record(conn, **kwargs)


def verify_chain(conn: sqlite3.Connection) -> dict:
    prev = GENESIS
    count = 0
    for row in conn.execute("SELECT * FROM audit_events ORDER BY seq ASC"):
        event = {k: row[k] for k in ("id", "ts", "actor", "role", "action", "target", "outcome", "ip", "details")}
        if row["prev_hash"] != prev or _event_hash(prev, event) != row["hash"]:
            return {"valid": False, "events_checked": count, "broken_at_seq": row["seq"]}
        prev = row["hash"]
        count += 1
    return {"valid": True, "events_checked": count, "broken_at_seq": None}
