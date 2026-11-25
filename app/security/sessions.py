"""Server-side sessions.

The browser gets a random token in an HttpOnly, SameSite=Strict cookie. The DB stores
only sha256(token), so a leaked DB file can't be used to hijack sessions. Each session
also has its own CSRF token that the frontend must echo in the X-CSRF-Token header.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, UTC

from ..config import settings
from ..db import now_iso

COOKIE_NAME = "phishlens_session"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(conn: sqlite3.Connection, user_id: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    expires = datetime.now(UTC) + timedelta(minutes=settings.session_ttl_minutes)
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (_hash(token), user_id, csrf, now_iso(), expires.isoformat(timespec="seconds")),
    )
    return token, csrf


def load_session(conn: sqlite3.Connection, token: str | None, purge: bool = True) -> sqlite3.Row | None:
    """Return the session row, or None. Expired rows are deleted only when purge=True (write
    transactions); read-only callers just ignore them and purge_expired() cleans up at login."""
    if not token or len(token) > 128:
        return None
    row = conn.execute(
        """SELECT s.token_hash, s.csrf_token, s.expires_at, u.id AS user_id, u.username, u.role, u.disabled
           FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?""",
        (_hash(token),),
    ).fetchone()
    if row is None:
        return None
    if row["disabled"] or datetime.fromisoformat(row["expires_at"]) < datetime.now(UTC):
        if purge:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
        return None
    return row


def delete_session(conn: sqlite3.Connection, token: str | None) -> None:
    if token:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash(token),))


def delete_user_sessions(conn: sqlite3.Connection, user_id: str) -> None:
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def purge_expired(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now_iso(),))


def csrf_matches(expected: str, supplied: str | None) -> bool:
    return bool(supplied) and secrets.compare_digest(expected, supplied)
