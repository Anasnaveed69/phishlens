"""Input validation for uploaded pages, declared URLs and dataset archives.

Pure functions: no DB, no web framework, so they're easy to unit test.
Nothing here ever executes, renders or fetches the submitted content.
"""
from __future__ import annotations

import csv
import io
import re
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import urlsplit

ALLOWED_PAGE_EXT = {".html", ".htm"}
MAX_URL_LENGTH = 2048
_HTML_MARKERS = re.compile(rb"<\s*(!doctype\s+html|html|head|body|form|div|title)\b", re.I)
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class InputError(Exception):
    """Raised for any rejected input. `code` maps to an API error code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class ValidatedPage:
    filename: str
    html: str
    size_bytes: int


def safe_filename(name: str) -> str:
    base = PurePosixPath(name.replace("\\", "/")).name  # drop any directory parts
    cleaned = _SAFE_NAME.sub("_", base).strip("._") or "page.html"
    return cleaned[:100]


def validate_page(filename: str, content: bytes, max_bytes: int) -> ValidatedPage:
    name = safe_filename(filename or "")
    ext = PurePosixPath(name).suffix.lower()
    if ext not in ALLOWED_PAGE_EXT:
        raise InputError("UNSUPPORTED_TYPE", "Only .html or .htm files are accepted.")
    if len(content) == 0:
        raise InputError("INVALID_INPUT", "The file is empty.")
    if len(content) > max_bytes:
        raise InputError("FILE_TOO_LARGE", f"The file exceeds {max_bytes // 1024} KB.")
    if b"\x00" in content[:4096]:
        raise InputError("UNSUPPORTED_TYPE", "The file looks binary, not HTML.")
    if not _HTML_MARKERS.search(content[:65536]):
        raise InputError("UNSUPPORTED_TYPE", "The file does not contain HTML markup.")
    try:
        html = content.decode("utf-8")
    except UnicodeDecodeError:
        html = content.decode("latin-1")  # never fails; keeps analysis possible for legacy pages
    return ValidatedPage(filename=name, html=html, size_bytes=len(content))


def validate_url(url: str | None) -> str | None:
    """Validate a *declared* source URL. It is only parsed for features, never requested."""
    if url is None:
        return None
    url = url.strip()
    if not url:
        return None
    if len(url) > MAX_URL_LENGTH or any(ord(c) < 32 for c in url):
        raise InputError("INVALID_INPUT", "The URL is too long or contains control characters.")
    try:
        parts = urlsplit(url)
        host = parts.hostname
        _ = parts.port  # raises ValueError for a malformed port
    except ValueError:
        raise InputError("INVALID_INPUT", "The URL is malformed.")
    if parts.scheme.lower() not in {"http", "https"} or not host:
        raise InputError("INVALID_INPUT", "The URL must start with http:// or https:// and include a host.")
    return url


def validate_label(label: str | None) -> str | None:
    if label in (None, ""):
        return None
    label = label.strip().lower()
    if label not in {"phishing", "benign"}:
        raise InputError("INVALID_INPUT", "Label must be 'phishing' or 'benign'.")
    return label


@dataclass
class DatasetItem:
    filename: str
    html: str
    size_bytes: int
    label: str | None
    source_url: str | None


def read_dataset_zip(content: bytes, max_total_bytes: int, max_files: int, max_file_bytes: int) -> list[DatasetItem]:
    """Read a dataset archive *in memory* without extracting to disk.

    Expected layout: any number of .html/.htm files plus an optional labels.csv with
    columns: filename,label[,source_url]. Protects against zip-slip (we never use
    archive paths on disk) and zip bombs (declared + actual size limits).
    """
    if len(content) > max_total_bytes:
        raise InputError("FILE_TOO_LARGE", "The archive is too large.")
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise InputError("UNSUPPORTED_TYPE", "The archive is not a valid .zip file.")

    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > max_files + 1:
        raise InputError("INVALID_INPUT", f"The archive has more than {max_files} files.")
    if sum(i.file_size for i in infos) > max_total_bytes:
        raise InputError("FILE_TOO_LARGE", "The archive expands beyond the allowed size.")

    labels: dict[str, tuple[str | None, str | None]] = {}
    label_info = next((i for i in infos if PurePosixPath(i.filename).name.lower() == "labels.csv"), None)
    if label_info:
        text = zf.read(label_info).decode("utf-8", errors="replace")
        for row in csv.DictReader(io.StringIO(text)):
            fname = safe_filename(row.get("filename", ""))
            labels[fname] = (validate_label(row.get("label")), validate_url(row.get("source_url")))

    items: list[DatasetItem] = []
    total = 0
    for info in infos:
        if info is label_info:
            continue
        if PurePosixPath(info.filename).suffix.lower() not in ALLOWED_PAGE_EXT:
            continue  # silently skip non-page files (reported as skipped by the caller)
        data = zf.read(info)
        total += len(data)
        if total > max_total_bytes:  # actual size check, in case headers lied
            raise InputError("FILE_TOO_LARGE", "The archive expands beyond the allowed size.")
        page = validate_page(info.filename, data, max_file_bytes)
        label, url = labels.get(page.filename, (None, None))
        items.append(DatasetItem(page.filename, page.html, page.size_bytes, label, url))
    if not items:
        raise InputError("INVALID_INPUT", "The archive contains no .html/.htm pages.")
    return items
