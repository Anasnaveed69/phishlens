"""Administration: versioned config, users, audit log, model status. Admin role only."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, model_validator

from engine.rules import RULES, RULES_BY_ID

from .. import audit, services
from ..db import current_config, get_conn, new_id, now_iso, read_conn
from ..errors import CONFLICT, INVALID_INPUT, NOT_FOUND, err
from ..security.deps import Principal, client_ip, require
from ..security.passwords import hash_password, password_problems
from ..security.sessions import delete_user_sessions

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ---------------------------------------------------------------- config
class ConfigIn(BaseModel):
    phishing_threshold: float = Field(ge=0.05, le=1.0)
    suspicious_threshold: float = Field(ge=0.0, le=1.0)
    ml_weight: float = Field(ge=0.0, le=1.0)
    disabled_rules: list[str] = Field(default_factory=list, max_length=len(RULES))
    reason: str = Field(min_length=3, max_length=200)
    confirm: bool = False  # high-impact change: client must explicitly confirm

    @model_validator(mode="after")
    def _check(self):
        if self.suspicious_threshold >= self.phishing_threshold:
            raise ValueError("suspicious_threshold must be below phishing_threshold")
        unknown = [r for r in self.disabled_rules if r not in RULES_BY_ID]
        if unknown:
            raise ValueError("unknown rule id")
        return self


@router.get("/config")
def get_config(principal: Principal = Depends(require("config:read"))):
    with read_conn() as conn:
        version, cfg = current_config(conn)
    return {"version": version, "config": cfg,
            "rules": [{"id": r.id, "name": r.name, "weight": r.weight, "severity": r.severity} for r in RULES]}


@router.put("/config")
def update_config(body: ConfigIn, request: Request, principal: Principal = Depends(require("config:write"))):
    if not body.confirm:
        raise err(INVALID_INPUT, "Config changes must be confirmed.", fields=["confirm"])
    new_cfg = {"phishing_threshold": round(body.phishing_threshold, 4),
               "suspicious_threshold": round(body.suspicious_threshold, 4),
               "ml_weight": round(body.ml_weight, 4), "disabled_rules": sorted(set(body.disabled_rules))}
    with get_conn() as conn:
        old_version, old_cfg = current_config(conn)
        if new_cfg == old_cfg:
            raise err(CONFLICT, "No changes to save.")
        cur = conn.execute("INSERT INTO config_versions (config_json, changed_by, reason, created_at) VALUES (?, ?, ?, ?)",
                           (json.dumps(new_cfg), principal.username, body.reason, now_iso()))
        changes = {k: {"from": old_cfg.get(k), "to": v} for k, v in new_cfg.items() if old_cfg.get(k) != v}
        audit.record(conn, action="config.update", actor=principal.username, role=principal.role,
                     target=f"config:v{cur.lastrowid}", ip=client_ip(request),
                     details={"from_version": old_version, "changes": changes, "reason": body.reason})
    return {"version": cur.lastrowid, "config": new_cfg}


@router.get("/config/history")
def config_history(principal: Principal = Depends(require("config:read"))):
    with read_conn() as conn:
        rows = conn.execute("SELECT * FROM config_versions ORDER BY version DESC LIMIT 100").fetchall()
    return {"items": [{**dict(r), "config_json": json.loads(r["config_json"])} for r in rows]}


# ---------------------------------------------------------------- users
class UserIn(BaseModel):
    username: str = Field(pattern=r"^[a-z0-9_.-]{3,32}$")
    password: str = Field(min_length=1, max_length=256)
    role: str = Field(pattern="^(admin|analyst|viewer)$")


class UserPatch(BaseModel):
    role: str | None = Field(default=None, pattern="^(admin|analyst|viewer)$")
    disabled: bool | None = None
    confirm: bool = False  # high-impact: changes privileges / ends sessions, so the client must confirm


class Confirm(BaseModel):
    confirm: bool = False


@router.get("/users")
def list_users(principal: Principal = Depends(require("user:manage"))):
    with read_conn() as conn:
        rows = conn.execute("SELECT id, username, role, disabled, created_at FROM users ORDER BY created_at").fetchall()
    return {"items": [dict(r) for r in rows]}


@router.post("/users")
def create_user(body: UserIn, request: Request, principal: Principal = Depends(require("user:manage"))):
    problems = password_problems(body.password)
    if problems:
        raise err(INVALID_INPUT, "Password must have " + ", ".join(problems) + ".", fields=["password"])
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (body.username,)).fetchone():
            raise err(CONFLICT, "That username is taken.")
        uid = new_id()
        conn.execute("INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                     (uid, body.username, hash_password(body.password), body.role, now_iso()))
        audit.record(conn, action="user.create", actor=principal.username, role=principal.role, target=body.username,
                     ip=client_ip(request), details={"role": body.role})
    return {"id": uid, "username": body.username, "role": body.role}


@router.patch("/users/{user_id}")
def update_user(user_id: str, body: UserPatch, request: Request, principal: Principal = Depends(require("user:manage"))):
    if not body.confirm:
        raise err(INVALID_INPUT, "Role or status changes must be confirmed.", fields=["confirm"])
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise err(NOT_FOUND)
        if user_id == principal.user_id:
            raise err(CONFLICT, "You cannot change your own role or disable yourself.")
        changes = {}
        if body.role is not None and body.role != row["role"]:
            conn.execute("UPDATE users SET role = ? WHERE id = ?", (body.role, user_id))
            changes["role"] = {"from": row["role"], "to": body.role}
        if body.disabled is not None and bool(row["disabled"]) != body.disabled:
            conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(body.disabled), user_id))
            changes["disabled"] = {"from": bool(row["disabled"]), "to": body.disabled}
        if changes:
            delete_user_sessions(conn, user_id)  # force re-login so new privileges apply immediately
            audit.record(conn, action="user.update", actor=principal.username, role=principal.role,
                         target=row["username"], ip=client_ip(request), details=changes)
    return {"id": user_id, "changes": changes}


# ---------------------------------------------------------------- audit + model
@router.get("/audit")
def list_audit(action: str | None = None, outcome: str | None = None, actor: str | None = None,
               limit: int = 100, offset: int = 0, principal: Principal = Depends(require("audit:read"))):
    limit, offset = max(1, min(limit, 500)), max(0, offset)
    where, params = [], []
    for col, val in (("action", action), ("outcome", outcome), ("actor", actor)):
        if val:
            where.append(f"{col} = ?")  # column names are fixed above, values are parameterized
            params.append(val[:64])
    # Column names come from the fixed tuple above, never from the request; values are bound parameters.
    sql = "SELECT * FROM audit_events" + (" WHERE " + " AND ".join(where) if where else "")  # noqa: S608  # nosec B608
    sql += " ORDER BY seq DESC LIMIT ? OFFSET ?"
    with read_conn() as conn:
        rows = conn.execute(sql, params + [limit, offset]).fetchall()
    return {"items": [{**dict(r), "details": json.loads(r["details"])} for r in rows]}


@router.get("/audit/verify")
def verify_audit(request: Request, principal: Principal = Depends(require("audit:read"))):
    with get_conn() as conn:
        result = audit.verify_chain(conn)
        audit.record(conn, action="audit.verify", actor=principal.username, role=principal.role,
                     ip=client_ip(request), outcome="success" if result["valid"] else "failure", details=result)
    return result


@router.get("/model")
def get_model(principal: Principal = Depends(require("config:read"))):
    return services.model_info()


@router.post("/model/reload")
def reload_model(body: Confirm, request: Request, principal: Principal = Depends(require("config:write"))):
    if not body.confirm:
        raise err(INVALID_INPUT, "Reloading the model must be confirmed.", fields=["confirm"])
    status = services.load_model()
    with get_conn() as conn:
        audit.record(conn, action="model.reload", actor=principal.username, role=principal.role, ip=client_ip(request),
                     outcome="success" if status == "loaded" else "failure",
                     details={"status": status, "version": services.model_info().get("version")})
    return services.model_info()


# ---------------------------------------------------------------- data retention
class PurgeIn(BaseModel):
    older_than_days: int = Field(ge=0, le=3650)
    confirm: bool = False


@router.post("/samples/purge")
def purge_samples(body: PurgeIn, request: Request, principal: Principal = Depends(require("config:write"))):
    """Delete stored raw pages older than N days. Analyses (decision, reasons, short evidence) are kept,
    so history and reports still work; re-analysing a purged page is no longer possible."""
    if not body.confirm:
        raise err(INVALID_INPUT, "Purging stored pages must be confirmed.", fields=["confirm"])
    with get_conn() as conn:
        purged = services.purge_raw_pages(conn, body.older_than_days)
        audit.record(conn, action="sample.purge", actor=principal.username, role=principal.role, ip=client_ip(request),
                     details={"older_than_days": body.older_than_days, "purged": purged})
    return {"purged": purged, "older_than_days": body.older_than_days}
