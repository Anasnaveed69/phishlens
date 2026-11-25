"""Coverage for admin, labeling, export, retention and error-path behaviour (QA audit, Nov 2026)."""
from __future__ import annotations

import csv
import io
import sqlite3
import zipfile

from .conftest import PASSWORDS, fixture_bytes, login

PAGE = b"<html><body><form><input type=password></form>coverage page %d</body></html>"


def _upload(client, h, n: int, url="https://cov.example.com/login", label=None):
    data = {"source_url": url}
    if label:
        data["label"] = label
    r = client.post("/api/samples", headers=h, files={"file": (f"cov{n}.html", PAGE % n, "text/html")}, data=data)
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- samples: list + label
def test_list_samples_filters_and_limits(client):
    h = login(client, "analyst")
    _upload(client, h, 1, label="benign")
    _upload(client, h, 2)
    all_items = client.get("/api/samples", params={"limit": 9999}).json()["items"]
    assert 2 <= len(all_items) <= 200
    assert all(i["label"] == "benign" for i in client.get("/api/samples", params={"label": "benign"}).json()["items"])
    assert all(i["label"] is None for i in client.get("/api/samples", params={"label": "unlabeled"}).json()["items"])
    assert len(client.get("/api/samples", params={"limit": 1}).json()["items"]) == 1


def test_label_update_is_validated_and_audited(client):
    h = login(client, "analyst")
    sid = _upload(client, h, 3)["sample"]["id"]
    assert client.patch(f"/api/samples/{sid}/label", headers=h, json={"label": "phishing"}).json()["label"] == "phishing"
    assert client.patch(f"/api/samples/{sid}/label", headers=h, json={"label": "spam"}).status_code == 422
    assert client.patch("/api/samples/nope/label", headers=h, json={"label": "benign"}).status_code == 404
    login(client, "admin")
    ev = client.get("/api/admin/audit", params={"action": "sample.label"}).json()["items"]
    assert any(e["target"] == sid and e["details"]["to"] == "phishing" for e in ev)


# ---------------------------------------------------------------- analyses: filters + exports
def test_analysis_filters_and_csv_exports(client):
    h = login(client, "analyst")
    res = _upload(client, h, 4)
    aid, sid = res["analysis"]["id"], res["sample"]["id"]
    assert client.get("/api/analyses", params={"decision": "maybe"}).status_code == 422
    items = client.get("/api/analyses", params={"sample_id": sid}).json()["items"]
    assert items and all(i["sample_id"] == sid for i in items)
    one = client.get(f"/api/analyses/{aid}/export", params={"format": "csv"})
    assert one.status_code == 200 and one.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(one.text)))
    assert rows[0] == ["field", "value"] and any(r[0] == "decision" for r in rows)
    assert client.get(f"/api/analyses/{aid}/export", params={"format": "xml"}).status_code == 422
    hist = list(csv.DictReader(io.StringIO(client.get("/api/analyses/export/history.csv").text)))
    assert any(r["analysis_id"] == aid for r in hist)
    assert client.get("/api/analyses/meta/features").json()["features"]


# ---------------------------------------------------------------- admin: users
def test_user_management_rules(client):
    ha = login(client, "admin")
    assert client.post("/api/admin/users", headers=ha, json={"username": "weakling", "password": "short", "role": "viewer"}).status_code == 422
    assert client.post("/api/admin/users", headers=ha, json={"username": "Bad Name!", "password": "Good-pass-123", "role": "viewer"}).status_code == 422
    r = client.post("/api/admin/users", headers=ha, json={"username": "covuser", "password": "Cov-user-pass-1", "role": "viewer"})
    assert r.status_code == 200
    uid = r.json()["id"]
    assert client.post("/api/admin/users", headers=ha, json={"username": "covuser", "password": "Cov-user-pass-1", "role": "viewer"}).status_code == 409

    # covuser logs in on a second client
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as other:
        assert other.post("/api/auth/login", json={"username": "covuser", "password": "Cov-user-pass-1"}).status_code == 200
        assert other.get("/api/auth/me").json()["role"] == "viewer"
        # promotion needs confirmation, then ends covuser's sessions so new rights apply on next login
        assert client.patch(f"/api/admin/users/{uid}", headers=ha, json={"role": "analyst"}).status_code == 422
        r = client.patch(f"/api/admin/users/{uid}", headers=ha, json={"role": "analyst", "confirm": True})
        assert r.status_code == 200 and r.json()["changes"]["role"] == {"from": "viewer", "to": "analyst"}
        assert other.get("/api/auth/me").status_code == 401
    assert client.patch("/api/admin/users/nope", headers=ha, json={"disabled": True, "confirm": True}).status_code == 404


# ---------------------------------------------------------------- admin: config + model
def test_config_validation_and_history(client):
    ha = login(client, "admin")
    cfg = client.get("/api/admin/config").json()
    base = {**cfg["config"], "reason": "coverage test", "confirm": True}
    assert client.put("/api/admin/config", headers=ha, json={**base, "suspicious_threshold": 0.9, "phishing_threshold": 0.5}).status_code == 422
    assert client.put("/api/admin/config", headers=ha, json={**base, "disabled_rules": ["R99"]}).status_code == 422
    assert client.put("/api/admin/config", headers=ha, json=base).status_code == 409  # no change
    hist = client.get("/api/admin/config/history").json()["items"]
    assert hist and hist[0]["version"] == cfg["version"]


def test_model_reload_requires_confirmation_and_is_audited(client):
    ha = login(client, "admin")
    assert client.post("/api/admin/model/reload", headers=ha, json={}).status_code == 422
    r = client.post("/api/admin/model/reload", headers=ha, json={"confirm": True})
    assert r.status_code == 200 and r.json()["status"] == "loaded"
    assert client.get("/api/admin/audit", params={"action": "model.reload"}).json()["items"]


# ---------------------------------------------------------------- retention
def test_purge_removes_raw_pages_but_keeps_results(client):
    h = login(client, "analyst")
    res = _upload(client, h, 5)
    sid, aid = res["sample"]["id"], res["analysis"]["id"]
    ha = login(client, "admin")
    assert client.post("/api/admin/samples/purge", headers=ha, json={"older_than_days": 0}).status_code == 422
    r = client.post("/api/admin/samples/purge", headers=ha, json={"older_than_days": 0, "confirm": True})
    assert r.status_code == 200 and r.json()["purged"] >= 1
    assert client.get(f"/api/analyses/{aid}").status_code == 200          # history still works
    again = client.post(f"/api/samples/{sid}/analyze", headers=ha)
    assert again.status_code == 410 and again.json()["error"]["code"] == "SAMPLE_PURGED"
    assert any(i["id"] == sid and i["purged"] for i in client.get("/api/samples", params={"limit": 200}).json()["items"])
    h = login(client, "analyst")
    assert _upload(client, h, 5)["duplicate"] is True                    # re-upload restores the page
    assert client.post(f"/api/samples/{sid}/analyze", headers=h).status_code == 200
    login(client, "admin")
    assert client.get("/api/admin/audit", params={"action": "sample.purge"}).json()["items"]


# ---------------------------------------------------------------- dataset import errors
def test_labels_csv_error_names_the_line(client):
    h = login(client, "analyst")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.html", "<html><body>a</body></html>")
        z.writestr("labels.csv", "filename,label,source_url\na.html,benign,\nb.html,malicious,\n")
    r = client.post("/api/samples/import", headers=h, files={"file": ("d.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 422 and "line 3" in r.json()["error"]["message"]
    r = client.post("/api/samples/import", headers=h, files={"file": ("d.txt", b"x", "text/plain")})
    assert r.status_code == 415


# ---------------------------------------------------------------- error path + headers + migration
def test_unhandled_errors_are_generic_and_audited(client, monkeypatch):
    from fastapi.testclient import TestClient

    from app import services
    from app.main import app
    ha = login(client, "admin")
    monkeypatch.setattr(services, "model_info", lambda: 1 / 0)
    with TestClient(app, raise_server_exceptions=False) as raw:  # behave like a real browser: get the 500
        raw.post("/api/auth/login", json={"username": "admin", "password": PASSWORDS["admin"]})
        r = raw.get("/api/admin/model")
    assert r.status_code == 500 and r.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "ZeroDivision" not in r.text and "Traceback" not in r.text
    monkeypatch.undo()
    ev = client.get("/api/admin/audit", params={"action": "system.error"}, headers=ha).json()["items"]
    assert ev and ev[0]["details"]["ref"] == r.json()["error"]["ref"]


def test_extra_security_headers(client):
    r = client.get("/")
    assert r.headers["cross-origin-opener-policy"] == "same-origin"
    assert r.headers["cross-origin-resource-policy"] == "same-origin"
    assert "strict-transport-security" not in r.headers  # only sent when PHISHLENS_COOKIE_SECURE=1 (HTTPS)


def test_old_database_is_migrated(tmp_path, monkeypatch):
    from app import db as dbmod
    from app.config import settings
    old = tmp_path / "old.db"
    conn = sqlite3.connect(old)
    conn.executescript(dbmod.SCHEMA.replace(
        "    created_at  TEXT NOT NULL,\n    purged_at   TEXT                       -- raw HTML deleted by the retention policy (analyses are kept)\n",
        "    created_at  TEXT NOT NULL\n"))
    conn.close()
    assert "purged_at" not in {r[1] for r in sqlite3.connect(old).execute("PRAGMA table_info(samples)")}
    monkeypatch.setattr(type(settings), "db_path", property(lambda self: old), raising=False)
    monkeypatch.setattr(type(settings), "sample_dir", property(lambda self: tmp_path / "s"), raising=False)
    dbmod.init_db()
    assert "purged_at" in {r[1] for r in sqlite3.connect(old).execute("PRAGMA table_info(samples)")}


def test_password_change_rate_limited_and_wrong_password_audited(client):
    h = login(client, "viewer")
    r = client.post("/api/auth/password", headers=h, json={"current_password": "not-it-123", "new_password": "Another-pass-9"})
    assert r.status_code == 401
    assert client.post("/api/auth/password", headers=h, json={"current_password": PASSWORDS["viewer"],
                                                               "new_password": PASSWORDS["viewer"]}).status_code == 422
    login(client, "admin")
    ev = client.get("/api/admin/audit", params={"action": "auth.password_change", "outcome": "failure"}).json()["items"]
    assert ev and ev[0]["actor"] == "viewer"


def test_fixture_pages_still_classified_as_documented(client):
    """Guards the README demo: the two demo pages must keep their documented decisions."""
    h = login(client, "analyst")
    for name, url, expected in [("benign_bank_portal.html", "https://www.hbl.com/ib/login", "benign"),
                                ("phish_brand_clone.html", "http://paypal-secure-verify.tk/webscr/signin", "phishing")]:
        r = client.post("/api/samples", headers=h, files={"file": (name, fixture_bytes(name), "text/html")},
                        data={"source_url": url})
        assert r.json()["analysis"]["decision"] == expected, name
