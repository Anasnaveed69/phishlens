"""Create a user from the command line (used to bootstrap the first admin).

Usage:
  python scripts/create_user.py admin --role admin          (prompts for a password)
  python scripts/create_user.py --demo                      (creates admin/analyst/viewer with random passwords)
"""
from __future__ import annotations

import argparse
import getpass
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import audit  # noqa: E402
from app.db import get_conn, init_db, new_id, now_iso  # noqa: E402
from app.security.passwords import hash_password, password_problems  # noqa: E402


def create(username: str, password: str, role: str) -> bool:
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            print(f"user '{username}' already exists, skipping")
            return False
        conn.execute("INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                     (new_id(), username, hash_password(password), role, now_iso()))
        audit.record(conn, action="user.create", actor="cli", role="system", target=username, details={"role": role})
    return True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("username", nargs="?")
    ap.add_argument("--role", choices=["admin", "analyst", "viewer"], default="analyst")
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()
    init_db()

    if args.demo:
        print("Demo users (passwords shown ONCE — save them somewhere safe):")
        for name in ("admin", "analyst", "viewer"):
            pw = secrets.token_urlsafe(9) + "7!"
            if create(name, pw, name):
                print(f"  {name:8s} {pw}")
        return

    if not args.username:
        ap.error("username is required (or use --demo)")
    pw = getpass.getpass("Password: ")
    problems = password_problems(pw)
    if problems:
        sys.exit("Password must have " + ", ".join(problems))
    if pw != getpass.getpass("Repeat: "):
        sys.exit("Passwords do not match")
    if create(args.username.lower(), pw, args.role):
        print(f"created {args.role} '{args.username.lower()}'")


if __name__ == "__main__":
    main()
