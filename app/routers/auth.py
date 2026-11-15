"""Authentication endpoints: login, logout, current user."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from .. import audit
from ..config import settings
from ..db import get_conn
from ..errors import INVALID_CREDENTIALS, INVALID_INPUT, RATE_LIMITED, err
from ..security.deps import PERMISSIONS, Principal, client_ip, get_principal
from ..security.passwords import hash_password, password_problems, verify_password
from ..security.ratelimit import RateLimiter
from ..security.sessions import COOKIE_NAME, _hash, create_session, delete_session, purge_expired

router = APIRouter(prefix="/api/auth", tags=["auth"])
login_limiter = RateLimiter(settings.login_rate_limit, 60)


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response):
    ip = client_ip(request)
    username = body.username.strip().lower()
    if not login_limiter.allow(f"{ip}:{username}"):
        audit.record_separately(action="auth.login", outcome="denied", actor=username, ip=ip,
                                details={"reason": "rate_limited"})
        raise err(RATE_LIMITED)

    with get_conn() as conn:
        purge_expired(conn)
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        ok = verify_password(user["password_hash"] if user else None, body.password)
        if not ok or user["disabled"]:
            audit.record(conn, action="auth.login", outcome="failure", actor=username, ip=ip,
                         details={"reason": "bad_credentials" if not ok else "disabled"})
            conn.commit()
            raise err(INVALID_CREDENTIALS)  # same message for unknown user / wrong password / disabled
        token, csrf = create_session(conn, user["id"])
        audit.record(conn, action="auth.login", actor=user["username"], role=user["role"], ip=ip)

    response.set_cookie(
        COOKIE_NAME, token, httponly=True, samesite="strict", secure=settings.cookie_secure,
        max_age=settings.session_ttl_minutes * 60, path="/",
    )
    return {"username": user["username"], "role": user["role"], "csrf_token": csrf,
            "permissions": sorted(PERMISSIONS[user["role"]]), "session_ttl_minutes": settings.session_ttl_minutes}


@router.post("/logout")
def logout(request: Request, response: Response, principal: Principal = Depends(get_principal)):
    with get_conn() as conn:
        delete_session(conn, request.cookies.get(COOKIE_NAME))
        audit.record(conn, action="auth.logout", actor=principal.username, role=principal.role, ip=client_ip(request))
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me")
def me(principal: Principal = Depends(get_principal)):
    return {"username": principal.username, "role": principal.role, "csrf_token": principal.csrf_token,
            "permissions": sorted(PERMISSIONS[principal.role])}


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


@router.post("/password")
def change_password(body: PasswordChangeIn, request: Request, principal: Principal = Depends(get_principal)):
    ip = client_ip(request)
    if not login_limiter.allow(f"pwchange:{principal.user_id}"):
        raise err(RATE_LIMITED)
    problems = password_problems(body.new_password)
    if problems:
        raise err(INVALID_INPUT, "New password must have " + ", ".join(problems) + ".", fields=["new_password"])
    if body.new_password == body.current_password:
        raise err(INVALID_INPUT, "New password must differ from the current one.", fields=["new_password"])
    with get_conn() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (principal.user_id,)).fetchone()
        if not verify_password(row["password_hash"], body.current_password):
            audit.record(conn, action="auth.password_change", outcome="failure", actor=principal.username,
                         role=principal.role, ip=ip, details={"reason": "wrong_current_password"})
            conn.commit()
            raise err(INVALID_CREDENTIALS, "Current password is incorrect.")
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(body.new_password), principal.user_id))
        # End every other session of this user; keep the current one.
        current = request.cookies.get(COOKIE_NAME) or ""
        conn.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (principal.user_id, _hash(current)))
        audit.record(conn, action="auth.password_change", actor=principal.username, role=principal.role, ip=ip)
    return {"ok": True}
