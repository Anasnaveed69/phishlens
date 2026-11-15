"""Application settings, loaded from environment variables (or a local .env file).

Nothing secret is hard-coded here. Copy .env.example to .env for local runs.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Tiny .env loader so we don't need an extra dependency."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(BASE_DIR / ".env")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    db_path: Path = field(default_factory=lambda: Path(os.environ.get("PHISHLENS_DB", BASE_DIR / "data" / "phishlens.db")))
    sample_dir: Path = field(default_factory=lambda: Path(os.environ.get("PHISHLENS_SAMPLE_DIR", BASE_DIR / "data" / "samples")))
    model_path: Path = field(default_factory=lambda: Path(os.environ.get("PHISHLENS_MODEL", BASE_DIR / "models" / "model.joblib")))

    session_ttl_minutes: int = field(default_factory=lambda: _int("PHISHLENS_SESSION_TTL_MIN", 30))
    max_upload_bytes: int = field(default_factory=lambda: _int("PHISHLENS_MAX_UPLOAD_BYTES", 2 * 1024 * 1024))
    max_import_bytes: int = field(default_factory=lambda: _int("PHISHLENS_MAX_IMPORT_BYTES", 20 * 1024 * 1024))
    max_import_files: int = field(default_factory=lambda: _int("PHISHLENS_MAX_IMPORT_FILES", 500))

    login_rate_limit: int = field(default_factory=lambda: _int("PHISHLENS_LOGIN_RATE", 5))       # attempts / minute
    analyze_rate_limit: int = field(default_factory=lambda: _int("PHISHLENS_ANALYZE_RATE", 30))  # requests / minute

    # Secret key for the audit chain HMAC. Kept OUTSIDE data/ so a copy of the database alone cannot
    # be re-chained. Generated on first run if missing.
    secret_dir: Path = field(default_factory=lambda: Path(os.environ.get("PHISHLENS_SECRET_DIR", BASE_DIR / "secrets")))
    # Optional: pin the expected SHA-256 of models/model.joblib (e.g. in .env) so a swapped model is refused
    # even if its .meta.json was edited too.
    model_sha256: str = field(default_factory=lambda: os.environ.get("PHISHLENS_MODEL_SHA256", "").strip().lower())

    # Set to "1" only when served over HTTPS. Locally we run on http://127.0.0.1.
    cookie_secure: bool = field(default_factory=lambda: os.environ.get("PHISHLENS_COOKIE_SECURE", "0") == "1")


settings = Settings()
