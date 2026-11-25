"""Authentication, authorization (RBAC) and CSRF as FastAPI dependencies.

Every protected route declares the permission it needs, e.g.
    principal: Principal = Depends(require("sample:write"))
The check happens on the server; hiding buttons in the UI is NOT security.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from .. import audit
from ..db import read_conn
from ..errors import AUTH_REQUIRED, CSRF_FAILED, FORBIDDEN, err
from .sessions import COOKIE_NAME, csrf_matches, load_session

# Least privilege: each role gets only what its job needs.
PERMISSIONS: dict[str, set[str]] = {
    "viewer": {"result:read"},
    "analyst": {"result:read", "sample:read", "sample:write", "analysis:run", "feedback:write", "export:run"},
    "admin": {
        "result:read", "sample:read", "sample:write", "analysis:run", "feedback:write", "export:run",
        "config:read", "config:write", "user:manage", "audit:read",
    },
}

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass(frozen=True)
class Principal:
    user_id: str
    username: str
    role: str
    csrf_token: str

    def can(self, permission: str) -> bool:
        return permission in PERMISSIONS.get(self.role, set())


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def get_principal(request: Request) -> Principal:
    token = request.cookies.get(COOKIE_NAME)
    with read_conn() as conn:
        row = load_session(conn, token, purge=False)
    if row is None:
        raise err(AUTH_REQUIRED)
    principal = Principal(row["user_id"], row["username"], row["role"], row["csrf_token"])

    if request.method in UNSAFE_METHODS and not csrf_matches(principal.csrf_token, request.headers.get("X-CSRF-Token")):
        audit.record_separately(
            action="security.csrf_failed", outcome="denied", actor=principal.username,
            role=principal.role, target=request.url.path, ip=client_ip(request),
        )
        raise err(CSRF_FAILED)
    return principal


def require(permission: str):
    def _dep(request: Request) -> Principal:
        principal = get_principal(request)
        if not principal.can(permission):
            # Generic denial to the client; specifics only in the audit log.
            audit.record_separately(
                action="authz.denied", outcome="denied", actor=principal.username, role=principal.role,
                target=f"{request.method} {request.url.path}", ip=client_ip(request),
                details={"permission": permission},
            )
            raise err(FORBIDDEN)
        return principal

    return _dep
