"""PhishLens API entry point.

Run locally:  uvicorn app.main:app --reload   (then open http://127.0.0.1:8000)
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import services
from .config import BASE_DIR
from .db import get_conn, init_db
from .errors import install_handlers
from .routers import admin, analyses, auth, dashboard, samples

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
FRONTEND = BASE_DIR / "frontend"


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()                          # idempotent: safe after a crash/restart
    status = services.load_model()     # falls back to rules-only if missing or tampered
    logging.getLogger("phishlens").info("startup complete, model status=%s", status)
    yield


app = FastAPI(title="PhishLens", version="0.1.0", lifespan=lifespan,
              docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
install_handlers(app)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
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
    with get_conn() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "model": services.model_info().get("status")}


app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(FRONTEND / "index.html")
