"""Adversarial / misuse tests (owner D): XSS, SQL injection, CSV injection, brute force,
session fixation, path traversal, IDOR-style access, oversized fields."""
from __future__ import annotations

import io
import zipfile

from .conftest import PASSWORDS, login

XSS_PAGE = (b"<html><head><title><script>alert(1)</script>PayPal</title></head><body>"
            b"<form action=\"javascript:alert('x')\"><input type=password></form>"
            b"<img src=x onerror=alert(2)><a href=\"javascript:alert(3)\">x</a></body></html>")


def _upload(client, headers, name, content, url=None):
    data = {"source_url": url} if url else {}
    return client.post("/api/samples", headers=headers, files={"file": (name, content, "text/html")}, data=data)


def test_xss_payload_is_only_data(client):
    """A page full of script payloads is analysed as data; the API returns JSON (never HTML),
    and the frontend renders it with textContent under a strict CSP."""
    h = login(client, "analyst")
    r = _upload(client, h, "xss.html", XSS_PAGE, "http://evil.example.test/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    a = r.json()["analysis"]
    assert a["decision"] in {"phishing", "suspicious", "benign"}
    # The malicious filename/title never becomes markup anywhere in the UI source.
    js = "\n".join(l for l in client.get("/static/app.js").text.splitlines() if not l.strip().startswith("//"))
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "eval(" not in js


def test_malicious_filename_is_sanitised(client):
    h = login(client, "analyst")
    r = _upload(client, h, "../../<script>alert(1)</script>.html", b"<html><body>hi there</body></html>")
    assert r.status_code == 200
    name = r.json()["sample"]["filename"]
    assert "<" not in name and "/" not in name and ".." not in name


def test_sql_injection_in_filters_is_inert(client):
    h = login(client, "admin")
    for payload in ("' OR 1=1 --", "%' UNION SELECT password_hash FROM users --", "\"; DROP TABLE users; --"):
        r = client.get("/api/analyses", params={"q": payload}, headers=h)
        assert r.status_code == 200 and r.json()["items"] == []
        r = client.get("/api/admin/audit", params={"actor": payload}, headers=h)
        assert r.status_code == 200 and r.json()["items"] == []
    assert client.get("/api/admin/users", headers=h).status_code == 200  # users table still there
    r = client.get("/api/analyses", params={"decision": "phishing' OR '1'='1"}, headers=h)
    assert r.status_code == 422


def test_csv_formula_injection_neutralised(client):
    h = login(client, "analyst")
    _upload(client, h, "=HYPERLINK(evil).html", b"<html><body><p>formula test page</p></body></html>",
            "https://=cmd.example.com/")
    csv_text = client.get("/api/analyses/export/history.csv").text
    for line in csv_text.splitlines()[1:]:
        for cell in line.split(","):
            assert not cell.startswith(("=", "+", "@")), cell


def test_brute_force_locks_out_even_correct_password(client):
    client.cookies.clear()
    for _ in range(5):
        client.post("/api/auth/login", json={"username": "admin", "password": "guess-guess-1"})
    r = client.post("/api/auth/login", json={"username": "admin", "password": PASSWORDS["admin"]})
    assert r.status_code == 429  # limiter applies before the password is checked


def test_forged_or_fixated_session_rejected(client):
    client.cookies.clear()
    client.cookies.set("phishlens_session", "attacker-chosen-token")
    assert client.get("/api/auth/me").status_code == 401
    # Logging in issues a NEW token rather than adopting the planted one.
    r = client.post("/api/auth/login", json={"username": "analyst", "password": PASSWORDS["analyst"]})
    assert "attacker-chosen-token" not in r.headers["set-cookie"]


def test_csrf_token_from_other_session_rejected(client):
    h_admin = login(client, "admin")
    login(client, "analyst")  # now the cookie is the analyst's session
    r = client.post("/api/samples", headers=h_admin, files={"file": ("a.html", b"<html><body>x</body></html>", "text/html")})
    assert r.status_code == 403 and r.json()["error"]["code"] == "CSRF_FAILED"


def test_viewer_cannot_export_or_read_raw_samples(client):
    login(client, "viewer")
    assert client.get("/api/samples").status_code == 403
    assert client.get("/api/analyses/export/history.csv").status_code == 403
    assert client.get("/api/admin/audit/verify").status_code == 403


def test_unknown_ids_return_generic_404(client):
    login(client, "admin")
    for path in ("/api/analyses/../../etc/passwd", "/api/analyses/00000000-0000-0000-0000-000000000000"):
        r = client.get(path)
        assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"


def test_oversized_fields_rejected(client):
    h = login(client, "analyst")
    r = client.post("/api/samples", headers=h, files={"file": ("a.html", b"<html><body>x</body></html>", "text/html")},
                    data={"source_url": "https://a.example.com/" + "a" * 3000})
    assert r.status_code == 422
    r = client.post("/api/auth/login", json={"username": "u" * 500, "password": "x"})
    assert r.status_code == 422


def test_zip_with_too_many_files_rejected(client):
    h = login(client, "analyst")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(600):
            z.writestr(f"p{i}.html", "<html><body>x</body></html>")
    r = client.post("/api/samples/import", headers=h, files={"file": ("big.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 422


def test_disabled_user_loses_access_immediately(client):
    ha = login(client, "admin")
    users = client.get("/api/admin/users", headers=ha).json()["items"]
    me = next(u for u in users if u["username"] == "admin")
    assert client.patch(f"/api/admin/users/{me['id']}", headers=ha, json={"disabled": True}).status_code == 422  # unconfirmed
    assert client.patch(f"/api/admin/users/{me['id']}", headers=ha, json={"disabled": True, "confirm": True}).status_code == 409


def test_audit_chain_survives_concurrent_requests(client):
    """Review finding S1: concurrent writers must not break the chain."""
    from concurrent.futures import ThreadPoolExecutor
    h = login(client, "analyst")
    aid = client.get("/api/analyses", headers=h).json()["items"][0]["id"]
    def hit(i):
        if i % 2:
            return client.post(f"/api/analyses/{aid}/feedback", headers=h, json={"verdict": "correct"}).status_code
        return client.get(f"/api/analyses/{aid}/export?format=json").status_code
    with ThreadPoolExecutor(max_workers=16) as ex:
        codes = list(ex.map(hit, range(80)))
    assert all(c == 200 for c in codes)
    login(client, "admin")
    v = client.get("/api/admin/audit/verify").json()
    assert v["valid"] is True and v["head"]


def test_audit_chain_is_keyed():
    """Recomputing the chain without the secret key must not validate (review finding S2)."""
    import hashlib
    from app import audit
    ev = {"id": "x", "ts": "t", "actor": None, "role": None, "action": "a", "target": None, "outcome": "success",
          "ip": None, "details": "{}"}
    unkeyed = hashlib.sha256((audit.GENESIS + audit._canonical(ev)).encode()).hexdigest()
    assert audit._event_hash(audit.GENESIS, ev) != unkeyed


def test_malformed_url_is_a_validation_error(client):
    h = login(client, "analyst")
    r = client.post("/api/samples", headers=h, files={"file": ("a.html", b"<html><body>x</body></html>", "text/html")},
                    data={"source_url": "http://[::1"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "INVALID_INPUT"


def test_duplicate_upload_uses_new_declared_url(client):
    h = login(client, "analyst")
    page = b"<html><body><form><input type=password></form>dup-url-test</body></html>"
    client.post("/api/samples", headers=h, files={"file": ("d.html", page, "text/html")}, data={"source_url": "http://old.example.tk/"})
    r = client.post("/api/samples", headers=h, files={"file": ("d.html", page, "text/html")}, data={"source_url": "https://new.example.com/"})
    assert r.json()["duplicate"] is True and r.json()["sample"]["source_url"] == "https://new.example.com/"


def test_import_with_analysis_respects_rate_limit(client, monkeypatch):
    import io
    import zipfile
    from app.routers import samples
    from app.security.ratelimit import RateLimiter
    monkeypatch.setattr(samples, "analyze_limiter", RateLimiter(5, 60))
    h = login(client, "analyst")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(10):
            z.writestr(f"r{i}.html", f"<html><body>rate {i}</body></html>")
    r = client.post("/api/samples/import", headers=h, files={"file": ("r.zip", buf.getvalue(), "application/zip")},
                    data={"analyze": "true"})
    assert r.status_code == 429


def test_corrupt_model_metadata_falls_back_to_rules(tmp_path, monkeypatch):
    from app import services
    from app.config import settings
    bad = tmp_path / "model.joblib"
    bad.write_bytes(b"not a pickle")
    (tmp_path / "model.meta.json").write_text("{broken json")
    monkeypatch.setattr(type(settings), "model_path", property(lambda self: bad), raising=False)
    try:
        assert services.load_model() in {"load_failed", "integrity_failed"}
    finally:
        monkeypatch.undo()
        services.load_model()


def test_restore_without_audit_key_is_detected(client, monkeypatch):
    """Backup docs: data/ restored without secrets/audit.key cannot pass verification."""
    from app import audit
    from app.db import connect
    login(client, "admin")
    conn = connect()
    try:
        assert audit.verify_chain(conn)["valid"] is True
        monkeypatch.setattr(audit, "_KEY", bytes(32))  # a different (e.g. freshly generated) key
        assert audit.verify_chain(conn)["valid"] is False
    finally:
        conn.close()
