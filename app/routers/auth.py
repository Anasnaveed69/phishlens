"""Authentication endpoints: login, logout, current user."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from .. import audit
from ..config import settings
from ..db import get_conn
from ..errors import INVALID_CREDENTIALS, RATE_LIMITED, err
from ..security.deps import PERMISSIONS, Principal, client_ip, get_principal
from ..security.passwords import verify_password
from ..security.ratelimit import RateLimiter
from ..security.sessions import COOKIE_NAME, create_session, delete_session, purge_expired

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
