"""Append-only, HMAC-chained audit log.

Each event stores hash = HMAC-SHA256(key, prev_hash || canonical_json(event)). The key lives in
secrets/audit.key, outside the data folder, so someone holding only the database cannot edit rows
and recompute the chain. verify_chain() reports where the chain breaks; DB triggers additionally
block UPDATE/DELETE through SQLite. Limitation: deleting the newest rows (tail truncation) is only
detectable against an external copy of the last hash, which /api/admin/audit/verify returns.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets as _secrets
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


_KEY: bytes | None = None


def _key() -> bytes:
    global _KEY
    if _KEY is None:
        from .config import settings
        path = settings.secret_dir / "audit.key"
        if not path.exists():
            settings.secret_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(_secrets.token_hex(32), encoding="utf-8")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        _KEY = bytes.fromhex(path.read_text(encoding="utf-8").strip())
    return _KEY


def _event_hash(prev_hash: str, event: dict) -> str:
    return hmac.new(_key(), (prev_hash + _canonical(event)).encode("utf-8"), hashlib.sha256).hexdigest()


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
            return {"valid": False, "events_checked": count, "broken_at_seq": row["seq"], "head": None}
        prev = row["hash"]
        count += 1
    # "head" is the newest hash: keep a copy elsewhere to also detect deletion of the newest rows.
    return {"valid": True, "events_checked": count, "broken_at_seq": None, "head": prev}
