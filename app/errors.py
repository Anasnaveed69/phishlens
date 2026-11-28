"""Stable API error codes and global exception handlers.

Clients rely on the `code` field; messages are intentionally generic.
Never include stack traces, SQL, file paths, or internal details in a response.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("phishlens")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, fields: list[str] | None = None):
        self.status = status
        self.code = code
        self.message = message
        self.fields = fields or []


# Stable codes — add new ones at the bottom, never rename.
AUTH_REQUIRED = (401, "AUTH_REQUIRED", "Please sign in.")
INVALID_CREDENTIALS = (401, "INVALID_CREDENTIALS", "Invalid username or password.")
FORBIDDEN = (403, "FORBIDDEN", "You are not permitted to perform this action.")
CSRF_FAILED = (403, "CSRF_FAILED", "Request could not be verified. Refresh and try again.")
NOT_FOUND = (404, "NOT_FOUND", "Resource not found.")
INVALID_INPUT = (422, "INVALID_INPUT", "The request contains invalid input.")
FILE_TOO_LARGE = (413, "FILE_TOO_LARGE", "The file exceeds the allowed size.")
UNSUPPORTED_TYPE = (415, "UNSUPPORTED_TYPE", "Only .html / .htm files (or a .zip dataset) are accepted.")
RATE_LIMITED = (429, "RATE_LIMITED", "Too many requests. Please wait and try again.")
CONFLICT = (409, "CONFLICT", "The request conflicts with the current state.")
INTERNAL_ERROR = (500, "INTERNAL_ERROR", "Something went wrong. The error has been logged.")
SAMPLE_PURGED = (410, "SAMPLE_PURGED", "The stored page was deleted by the retention policy; upload it again to re-analyse.")


def err(spec: tuple[int, str, str], message: str | None = None, fields: list[str] | None = None) -> ApiError:
    status, code, default_msg = spec
    return ApiError(status, code, message or default_msg, fields)


def _body(code: str, message: str, fields: list[str] | None = None, ref: str | None = None) -> dict:
    body: dict = {"error": {"code": code, "message": message}}
    if fields:
        body["error"]["fields"] = fields
    if ref:
        body["error"]["ref"] = ref
    return body


def install_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError):
        return JSONResponse(_body(exc.code, exc.message, exc.fields), status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        # Only report which fields failed, not the submitted values.
        fields = sorted({".".join(str(p) for p in e.get("loc", []) if p != "body") for e in exc.errors()})
        return JSONResponse(_body(*INVALID_INPUT[1:], fields=fields), status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException):
        if exc.status_code == 404:
            return JSONResponse(_body(*NOT_FOUND[1:]), status_code=404)
        if exc.status_code == 405:
            return JSONResponse(_body("METHOD_NOT_ALLOWED", "Method not allowed."), status_code=405)
        return JSONResponse(_body("HTTP_ERROR", "Request failed."), status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        ref = uuid.uuid4().hex[:12]
        log.exception("Unhandled error ref=%s", ref)  # full trace stays in server logs only
        try:  # failures are security-relevant events too; record them without internal details
            from . import audit
            audit.record_separately(action="system.error", outcome="failure",
                                    target=f"{request.method} {request.url.path}",
                                    ip=request.client.host if request.client else None,
                                    details={"ref": ref, "type": type(exc).__name__})
        except Exception:  # never let logging failures mask the original error
            log.exception("could not audit error ref=%s", ref)
        return JSONResponse(_body(*INTERNAL_ERROR[1:], ref=ref), status_code=500)
