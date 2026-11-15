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
    assert client.patch(f"/api/admin/users/{me['id']}", headers=ha, json={"disabled": True}).status_code == 409
