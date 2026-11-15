"""Test fixtures: each test session gets a throwaway DB and sample folder."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_tmp = tempfile.mkdtemp(prefix="phishlens-test-")
os.environ["PHISHLENS_DB"] = os.path.join(_tmp, "test.db")
os.environ["PHISHLENS_SAMPLE_DIR"] = os.path.join(_tmp, "samples")
os.environ["PHISHLENS_LOGIN_RATE"] = "5"
os.environ["PHISHLENS_ANALYZE_RATE"] = "1000"
os.environ["PHISHLENS_MAX_UPLOAD_BYTES"] = str(200 * 1024)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

FIXTURES = ROOT / "fixtures" / "tests"
PASSWORDS = {"admin": "Admin-pass-123", "analyst": "Analyst-pass-123", "viewer": "Viewer-pass-123"}


@pytest.fixture(scope="session")
def client():
    from app.db import get_conn, init_db, new_id, now_iso
    from app.main import app
    from app.security.passwords import hash_password

    init_db()
    with get_conn() as conn:
        for role, pw in PASSWORDS.items():
            conn.execute("INSERT OR IGNORE INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                         (new_id(), role, hash_password(pw), role, now_iso()))
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _reset_limits():
    from app.routers.auth import login_limiter
    login_limiter.reset()
    yield


def login(client: TestClient, role: str) -> dict:
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"username": role, "password": PASSWORDS[role]})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": r.json()["csrf_token"]}


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()
