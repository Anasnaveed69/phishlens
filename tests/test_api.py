"""API tests: auth, authorization, CSRF, validation, workflow, audit (T-final cases)."""
from __future__ import annotations

import json

from .conftest import PASSWORDS, fixture_bytes, login


def _upload(client, headers, name="phish_brand_clone.html", url="http://paypal-secure-verify.tk/webscr/signin", label="phishing"):
    return client.post("/api/samples", headers=headers,
                       files={"file": (name, fixture_bytes(name), "text/html")},
                       data={"source_url": url, "label": label})


# ---------------------------------------------------------------- auth
def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_unauthenticated_request_rejected(client):
    client.cookies.clear()
    r = client.get("/api/analyses")
    assert r.status_code == 401 and r.json()["error"]["code"] == "AUTH_REQUIRED"


def test_wrong_password_generic_error(client):
    client.cookies.clear()
    r1 = client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password-1"})
    r2 = client.post("/api/auth/login", json={"username": "nobody", "password": "wrong-password-1"})
    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json()  # no username enumeration


def test_login_rate_limited(client):
    client.cookies.clear()
    codes = [client.post("/api/auth/login", json={"username": "viewer", "password": "nope-nope-1"}).status_code for _ in range(7)]
    assert codes[-1] == 429


def test_session_cookie_flags(client):
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"username": "analyst", "password": PASSWORDS["analyst"]})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert "csrf_token" in r.json()


def test_logout_invalidates_session(client):
    h = login(client, "analyst")
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/auth/me").status_code == 401


# ---------------------------------------------------------------- CSRF + authz
def test_csrf_required_on_state_change(client):
    login(client, "analyst")
    r = client.post("/api/samples", files={"file": ("a.html", b"<html></html>", "text/html")})
    assert r.status_code == 403 and r.json()["error"]["code"] == "CSRF_FAILED"


def test_viewer_cannot_upload_and_is_logged(client):
    h = login(client, "viewer")
    r = _upload(client, h)
    assert r.status_code == 403 and r.json()["error"] == {"code": "FORBIDDEN", "message": "You are not permitted to perform this action."}
    ha = login(client, "admin")
    events = client.get("/api/admin/audit?action=authz.denied", headers=ha).json()["items"]
    assert any(e["actor"] == "viewer" for e in events)


def test_analyst_cannot_access_admin(client):
    login(client, "analyst")
    assert client.get("/api/admin/config").status_code == 403
    assert client.get("/api/admin/audit").status_code == 403


# ---------------------------------------------------------------- validation (T-final)
def test_malformed_and_oversized_input_rejected(client):
    h = login(client, "analyst")
    r = client.post("/api/samples", headers=h, files={"file": ("x.exe", b"MZ\x00\x00", "application/octet-stream")})
    assert r.status_code == 415 and r.json()["error"]["code"] == "UNSUPPORTED_TYPE"
    big = b"<html>" + b"A" * (300 * 1024) + b"</html>"
    r = client.post("/api/samples", headers=h, files={"file": ("big.html", big, "text/html")})
    assert r.status_code == 413 and r.json()["error"]["code"] == "FILE_TOO_LARGE"
    r = client.post("/api/samples", headers=h, files={"file": ("a.html", b"<html></html>", "text/html")},
                    data={"source_url": "javascript:alert(1)"})
    assert r.status_code == 422


def test_errors_never_leak_internals(client):
    h = login(client, "analyst")
    r = client.post("/api/analyses/does-not-exist/feedback", headers=h, json={"verdict": "maybe"})
    body = json.dumps(r.json())
    assert r.status_code == 422 and "Traceback" not in body and "maybe" not in body


# ---------------------------------------------------------------- workflow
def test_full_workflow_and_repeated_submission(client):
    h = login(client, "analyst")
    r = _upload(client, h)
    assert r.status_code == 200, r.text
    data = r.json()
    a = data["analysis"]
    assert a["decision"] == "phishing" and a["rules"]["fired"]
    assert all(f["reason"] for f in a["rules"]["fired"])

    again = _upload(client, h).json()  # same bytes -> same sample, fresh analysis
    assert again["duplicate"] is True and again["sample"]["id"] == data["sample"]["id"]

    assert client.post(f"/api/analyses/{a['id']}/feedback", headers=h, json={"verdict": "correct"}).status_code == 200
    exp = client.get(f"/api/analyses/{a['id']}/export?format=json")
    assert exp.status_code == 200
    report = exp.json()
    assert report["decision"] == "phishing" and "<form" not in json.dumps(report)  # no raw page content
    assert "features" not in report  # sanitized: no raw feature dump / page content
    assert client.get("/api/analyses/export/history.csv").status_code == 200


def test_viewer_gets_restricted_view(client):
    h = login(client, "analyst")
    aid = _upload(client, h, name="phish_ip_host.html", url="http://185.22.91.7/office365/login.php").json()["analysis"]["id"]
    login(client, "viewer")
    r = client.get(f"/api/analyses/{aid}").json()
    assert r["restricted_view"] is True and "features" not in r and "source_url" not in r


def test_admin_threshold_change_is_traceable(client):
    h = login(client, "analyst")
    sid = _upload(client, h, name="edge_brand_mention_article.html",
                  url="https://security-blog.example.org/fake-payment-pages", label="benign").json()["sample"]["id"]
    ha = login(client, "admin")
    cfg = client.get("/api/admin/config", headers=ha).json()
    unconfirmed = {**cfg["config"], "disabled_rules": ["R04"], "reason": "R04 false positive on blog", "confirm": False}
    assert client.put("/api/admin/config", headers=ha, json=unconfirmed).status_code == 422
    r = client.put("/api/admin/config", headers=ha, json={**unconfirmed, "confirm": True})
    assert r.status_code == 200
    new_version = r.json()["version"]

    rerun = client.post(f"/api/samples/{sid}/analyze", headers=ha).json()
    assert rerun["config_version"] == new_version and "R04" in rerun["rules"]["disabled"]
    events = client.get("/api/admin/audit?action=config.update", headers=ha).json()["items"]
    assert events and events[0]["details"]["changes"]["disabled_rules"]["to"] == ["R04"]
    # restore default for other tests
    client.put("/api/admin/config", headers=ha, json={**cfg["config"], "reason": "restore", "confirm": True})


def test_dataset_import(client):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name in ("benign_article.html", "phish_ip_host.html"):
            z.writestr(name, fixture_bytes(name))
        z.writestr("labels.csv", fixture_bytes("labels.csv"))
    h = login(client, "analyst")
    r = client.post("/api/samples/import", headers=h, files={"file": ("ds.zip", buf.getvalue(), "application/zip")},
                    data={"analyze": "true"})
    assert r.status_code == 200, r.text
    assert r.json()["pages"] == 2 and r.json()["labeled"] == 2


# ---------------------------------------------------------------- audit integrity
def test_audit_chain_valid_and_append_only(client):
    import sqlite3

    import pytest

    from app.db import connect
    ha = login(client, "admin")
    assert client.get("/api/admin/audit/verify", headers=ha).json()["valid"] is True
    conn = connect()
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM audit_events")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE audit_events SET actor = 'x'")
    conn.close()


def test_audit_redacts_secrets():
    from app.audit import redact
    out = redact({"password": "hunter2", "nested": {"csrf_token": "abc"}, "note": "mail me at a.b@example.com"})
    assert out["password"] == "[REDACTED]" and out["nested"]["csrf_token"] == "[REDACTED]"
    assert "example.com" not in out["note"]


def test_security_headers(client):
    r = client.get("/")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


def test_recovery_after_restart(client):
    """Simulate a restart: re-run startup on the same DB; data and chain survive."""
    from app import services
    from app.db import init_db
    init_db()
    services.load_model()
    ha = login(client, "admin")
    assert client.get("/api/analyses", headers=ha).json()["items"]
    assert client.get("/api/admin/audit/verify", headers=ha).json()["valid"] is True


# ---------------------------------------------------------------- dashboard + account
def test_dashboard_for_all_roles(client):
    for role in ("admin", "analyst", "viewer"):
        login(client, role)
        r = client.get("/api/dashboard")
        assert r.status_code == 200
        body = r.json()
        assert {"status", "totals", "by_decision", "top_rules", "latency"} <= set(body)
        if role == "viewer":
            assert body["feedback"] is None and all("filename" not in x for x in body["recent_high_risk"])


def test_password_change_flow(client):
    from .conftest import PASSWORDS
    h = login(client, "viewer")
    bad = client.post("/api/auth/password", headers=h, json={"current_password": "wrong-one-123", "new_password": "Brand-new-pass-9"})
    assert bad.status_code == 401
    weak = client.post("/api/auth/password", headers=h, json={"current_password": PASSWORDS["viewer"], "new_password": "short"})
    assert weak.status_code == 422
    ok = client.post("/api/auth/password", headers=h, json={"current_password": PASSWORDS["viewer"], "new_password": "Brand-new-pass-9"})
    assert ok.status_code == 200
    assert client.get("/api/auth/me").status_code == 200  # current session survives
    # change it back so other tests keep working
    client.post("/api/auth/password", headers=h, json={"current_password": "Brand-new-pass-9", "new_password": PASSWORDS["viewer"]})
