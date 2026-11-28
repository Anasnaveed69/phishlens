"""Dataset import + labeling (FR-1) and analysis submission."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from pydantic import BaseModel

from engine.validation import InputError, read_dataset_zip, validate_label, validate_page, validate_url

from .. import audit, services
from ..config import settings
from ..db import get_conn, read_conn
from ..errors import FILE_TOO_LARGE, INVALID_INPUT, NOT_FOUND, RATE_LIMITED, UNSUPPORTED_TYPE, err
from ..security.deps import Principal, client_ip, require
from ..security.ratelimit import RateLimiter

router = APIRouter(prefix="/api/samples", tags=["samples"])
analyze_limiter = RateLimiter(settings.analyze_rate_limit, 60)

_CODE_MAP = {"FILE_TOO_LARGE": FILE_TOO_LARGE, "UNSUPPORTED_TYPE": UNSUPPORTED_TYPE, "INVALID_INPUT": INVALID_INPUT}


def _reject(exc: InputError, principal: Principal, request: Request, action: str):
    audit.record_separately(action=action, outcome="failure", actor=principal.username, role=principal.role,
                            ip=client_ip(request), details={"code": exc.code, "reason": exc.message})
    return err(_CODE_MAP.get(exc.code, INVALID_INPUT), exc.message)


def _read_limited(upload: UploadFile, limit: int) -> bytes:
    data = upload.file.read(limit + 1)  # read at most limit+1 bytes, never the whole stream
    if len(data) > limit:
        raise InputError("FILE_TOO_LARGE", f"The file exceeds {limit // 1024} KB.")
    return data


def _check_rate(principal: Principal, request: Request):
    if not analyze_limiter.allow(principal.user_id):
        audit.record_separately(action="analysis.submit", outcome="denied", actor=principal.username,
                                role=principal.role, ip=client_ip(request), details={"reason": "rate_limited"})
        raise err(RATE_LIMITED)


@router.post("")
def submit_page(
    request: Request,
    file: UploadFile = File(...),
    source_url: str | None = Form(None),
    label: str | None = Form(None),
    principal: Principal = Depends(require("sample:write")),
):
    """Upload one saved page, validate it, and analyze it immediately."""
    _check_rate(principal, request)
    try:
        content = _read_limited(file, settings.max_upload_bytes)
        page = validate_page(file.filename or "", content, settings.max_upload_bytes)
        url = validate_url(source_url)
        lab = validate_label(label)
    except InputError as exc:
        raise _reject(exc, principal, request, "sample.upload") from None

    ip = client_ip(request)
    # The analysis runs inside the (fair, in-process) write lock: with Python's GIL, serialising the
    # CPU work gave the best throughput and the tightest tail latency in scripts/load_test.py.
    with get_conn() as conn:
        sample, duplicate = services.store_sample(conn, filename=page.filename, html=page.html, size=page.size_bytes,
                                                  source_url=url, label=lab, user_id=principal.user_id)
        audit.record(conn, action="sample.upload", actor=principal.username, role=principal.role, target=sample["id"],
                     ip=ip, details={"filename": page.filename, "size": page.size_bytes, "duplicate": duplicate})
        result = services.run_analysis(conn, sample, principal.user_id, principal.username, principal.role, ip)
    return {"sample": _public_sample(sample), "duplicate": duplicate, "analysis": result}


@router.post("/import")
def import_dataset(
    request: Request,
    file: UploadFile = File(...),
    analyze: bool = Form(False),
    principal: Principal = Depends(require("sample:write")),
):
    """Import a labeled dataset: a .zip of .html pages plus optional labels.csv."""
    try:
        if not (file.filename or "").lower().endswith(".zip"):
            raise InputError("UNSUPPORTED_TYPE", "Dataset imports must be a .zip file.")
        content = _read_limited(file, settings.max_import_bytes)
        items = read_dataset_zip(content, settings.max_import_bytes, settings.max_import_files, settings.max_upload_bytes)
    except InputError as exc:
        raise _reject(exc, principal, request, "dataset.import") from None

    # Imports count against the same per-user analysis budget: 1 request, plus 1 per page analysed.
    if not analyze_limiter.allow(principal.user_id, 1 + (len(items) if analyze else 0)):
        audit.record_separately(action="dataset.import", outcome="denied", actor=principal.username,
                                role=principal.role, ip=client_ip(request),
                                details={"reason": "rate_limited", "pages": len(items), "analyze": analyze})
        raise err(RATE_LIMITED, "Too many analyses for one minute. Import without 'analyze', "
                                "or split the dataset into smaller archives.")
    ip = client_ip(request)
    created = duplicates = analyzed = 0
    with get_conn() as conn:
        for item in items:
            sample, dup = services.store_sample(conn, filename=item.filename, html=item.html, size=item.size_bytes,
                                                source_url=item.source_url, label=item.label, user_id=principal.user_id)
            duplicates += dup
            created += not dup
            if analyze:
                services.run_analysis(conn, sample, principal.user_id, principal.username, principal.role, ip)
                analyzed += 1
        summary = {"pages": len(items), "created": created, "duplicates": duplicates, "analyzed": analyzed,
                   "labeled": sum(1 for i in items if i.label)}
        audit.record(conn, action="dataset.import", actor=principal.username, role=principal.role, ip=ip,
                     details={"filename": file.filename, **summary})
    return summary


@router.get("")
def list_samples(limit: int = 50, offset: int = 0, label: str | None = None,
                 principal: Principal = Depends(require("sample:read"))):
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    sql = "SELECT * FROM samples"
    params: list = []
    if label in {"phishing", "benign"}:
        sql += " WHERE label = ?"
        params.append(label)
    elif label == "unlabeled":
        sql += " WHERE label IS NULL"
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    with read_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
    return {"items": [_public_sample(dict(r)) for r in rows]}


class LabelIn(BaseModel):
    label: str | None


@router.patch("/{sample_id}/label")
def set_label(sample_id: str, body: LabelIn, request: Request,
              principal: Principal = Depends(require("sample:write"))):
    try:
        lab = validate_label(body.label)
    except InputError as exc:
        raise _reject(exc, principal, request, "sample.label") from None
    with get_conn() as conn:
        row = conn.execute("SELECT id, label FROM samples WHERE id = ?", (sample_id,)).fetchone()
        if row is None:
            raise err(NOT_FOUND)
        conn.execute("UPDATE samples SET label = ? WHERE id = ?", (lab, sample_id))
        audit.record(conn, action="sample.label", actor=principal.username, role=principal.role, target=sample_id,
                     ip=client_ip(request), details={"from": row["label"], "to": lab})
    return {"id": sample_id, "label": lab}


@router.post("/{sample_id}/analyze")
def reanalyze(sample_id: str, request: Request, principal: Principal = Depends(require("analysis:run"))):
    """Re-run analysis with the CURRENT config/model (e.g. after an admin changes a threshold)."""
    _check_rate(principal, request)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM samples WHERE id = ?", (sample_id,)).fetchone()
        if row is None:
            raise err(NOT_FOUND)
        return services.run_analysis(conn, dict(row), principal.user_id, principal.username, principal.role,
                                     client_ip(request))


def _public_sample(s: dict) -> dict:
    out = {k: s[k] for k in ("id", "filename", "sha256", "source_url", "label", "size_bytes", "created_at")}
    out["purged"] = bool(s.get("purged_at"))
    return out
