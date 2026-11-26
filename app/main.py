"""PhishLens — API entry point.

Run locally:
    uvicorn app.main:app --reload
Then open http://127.0.0.1:8000 (API docs at /api/docs).
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import services
from .config import BASE_DIR, settings
from .db import init_db, read_conn
from .errors import install_handlers
from .routers import admin, analyses, auth, dashboard, samples

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

FRONTEND = BASE_DIR / "frontend"


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()                          # idempotent: safe after a crash/restart (also migrates old DBs)
    if settings.retention_days > 0:
        from . import audit
        from .db import get_conn
        with get_conn() as conn:
            n = services.purge_raw_pages(conn, settings.retention_days)
            if n:
                audit.record(conn, action="sample.purge", actor="system", role="system",
                             details={"older_than_days": settings.retention_days, "purged": n})
    status = services.load_model()     # falls back to rules-only if missing or tampered
    logging.getLogger("phishlens").info("startup complete, model status=%s", status)
    yield


app = FastAPI(title="PhishLens", version="1.1.0", lifespan=lifespan, redoc_url=None,
              docs_url="/api/docs" if settings.api_docs else None,
              openapi_url="/api/openapi.json" if settings.api_docs else None)
install_handlers(app)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if settings.cookie_secure:  # only meaningful (and only safe to send) behind HTTPS
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if not request.url.path.startswith("/api/docs"):
        # No inline scripts and nothing loaded from other origins.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


app.include_router(auth.router)
app.include_router(samples.router)
app.include_router(analyses.router)
app.include_router(admin.router)
app.include_router(dashboard.router)


@app.get("/api/health")
def health():
    with read_conn() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "model": services.model_info().get("status")}


app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(FRONTEND / "index.html")
