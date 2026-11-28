"""Comprehensive QA End-to-End and Security Test Suite for PhishLens.
Tests Phases 3, 4, and 5 using conftest's clean isolated environment and fixtures.
"""
from __future__ import annotations

import io
import zipfile
import pytest
from fastapi.testclient import TestClient

from .conftest import FIXTURES, PASSWORDS, login

# --- TEST 1: Authentication & Sessions ---
def test_qa_authentication_flows(client: TestClient):
    client.cookies.clear()
    # 1. Invalid credentials
    r = client.post("/api/auth/login", json={"username": "analyst", "password": "WrongPassword123!"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "INVALID_CREDENTIALS"

    # 2. Unknown user
    r = client.post("/api/auth/login", json={"username": "unknown_user", "password": "WrongPassword123!"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "INVALID_CREDENTIALS"

    # 3. Empty form
    r = client.post("/api/auth/login", json={})
    assert r.status_code == 422

    # 4. Valid login & session persistence
    headers = login(client, "analyst")
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "analyst"
    assert me.json()["role"] == "analyst"

    # 5. Logout
    r = client.post("/api/auth/logout", headers=headers)
    assert r.status_code == 200
    r = client.get("/api/auth/me")
    assert r.status_code == 401

# --- TEST 2: Dashboard ---
def test_qa_dashboard_stats(client: TestClient):
    login(client, "analyst")
    r = client.get("/api/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert "totals" in data
    assert "by_decision" in data
    assert "recent_high_risk" in data
    assert "status" in data
    assert isinstance(data["recent_high_risk"], list)

# --- TEST 3: Dataset Import & Validations ---
def test_qa_dataset_import_workflow(client: TestClient):
    headers = login(client, "analyst")
    
    # 1. Non-zip upload should fail
    r = client.post("/api/samples/import", headers=headers,
                    files={"file": ("dataset.txt", b"invalid content", "text/plain")})
    assert r.status_code in (415, 422)

    # 2. Valid zip with labels.csv
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("test1.html", "<html><head><title>Test 1</title></head><body><h1>Hello</h1></body></html>")
        zf.writestr("test2.html", "<html><head><title>Test 2</title></head><body><form action='http://evil.com/login'><input type='password'></form></body></html>")
        zf.writestr("labels.csv", "filename,url,label\ntest1.html,http://example.com/1,benign\ntest2.html,http://evil.com/login,phishing\n")
    buf.seek(0)

    r = client.post("/api/samples/import", headers=headers,
                    files={"file": ("valid_data.zip", buf.getvalue(), "application/zip")},
                    data={"analyze": "true"})
    assert r.status_code == 200
    res = r.json()
    assert "pages" in res
    assert res["pages"] == 2
    assert "created" in res
    assert "analyzed" in res

    # 3. Duplicate import detection
    buf.seek(0)
    r = client.post("/api/samples/import", headers=headers,
                    files={"file": ("valid_data.zip", buf.getvalue(), "application/zip")},
                    data={"analyze": "false"})
    assert r.status_code == 200
    assert r.json()["duplicates"] >= 1

# --- TEST 4: HTML Upload Fixtures & Script Non-Execution ---
def test_qa_html_upload_fixtures(client: TestClient):
    headers = login(client, "analyst")
    fixtures = [
        ("benign_bank_portal.html", "https://www.hbl.com/ib/login", "benign"),
        ("phish_brand_clone.html", "http://paypal-secure-verify.tk/webscr/signin", "phishing"),
        ("phish_ip_host.html", "http://192.168.1.50/account/verify", "phishing"),
    ]
    for filename, url, label in fixtures:
        with open(FIXTURES / filename, "rb") as f:
            content = f.read()
        r = client.post("/api/samples", headers=headers,
                        files={"file": (filename, content, "text/html")},
                        data={"source_url": url, "label": label})
        assert r.status_code == 200, f"Upload failed for {filename}: {r.text}"
        data = r.json()
        assert "sample" in data
        assert "analysis" in data
        analysis = data["analysis"]
        assert "decision" in analysis
        assert "score" in analysis
        assert "rules" in analysis

    # Upload hostile JS page to ensure inertness (never executes script tags)
    xss_html = b"<html><head><script>alert('XSS'); document.location='http://attacker.com';</script></head><body><h1>Login</h1></body></html>"
    r = client.post("/api/samples", headers=headers,
                    files={"file": ("hostile.html", xss_html, "text/html")},
                    data={"source_url": "http://safe-site.test/login", "label": "phishing"})
    assert r.status_code == 200
    res = r.json()["analysis"]
    assert res["decision"] in ("phishing", "suspicious", "benign")

# --- TEST 5 & 6: Feature Extraction & Detection Engine ---
def test_qa_engine_known_cases(client: TestClient):
    headers = login(client, "analyst")
    with open(FIXTURES / "phish_brand_clone.html", "rb") as f:
        content = f.read()
    r = client.post("/api/samples", headers=headers,
                    files={"file": ("phish_brand_clone.html", content, "text/html")},
                    data={"source_url": "http://paypal-secure-verify.tk/webscr/signin"})
    assert r.status_code == 200
    res = r.json()["analysis"]
    assert res["decision"] == "phishing"
    assert res["score"] >= 0.54
    fired_ids = [r["id"] for r in res["rules"]["fired"]]
    assert any(rule_id in fired_ids for rule_id in ["R03", "R05", "R12", "R23"])

# --- TEST 7: Explainability Panel Response ---
def test_qa_explainability_fields(client: TestClient):
    headers = login(client, "analyst")
    with open(FIXTURES / "phish_brand_clone.html", "rb") as f:
        content = f.read()
    r = client.post("/api/samples", headers=headers,
                    files={"file": ("explain_test.html", content, "text/html")},
                    data={"source_url": "http://paypal-secure-verify.tk/login"})
    assert r.status_code == 200
    res = r.json()["analysis"]
    for field in ["decision", "score", "confidence", "severity", "recommended_action",
                  "rules", "ml", "thresholds", "features", "versions", "latency_ms"]:
        assert field in res, f"Missing field {field}"
    assert "top_features" in res["ml"]
    assert "ruleset_version" in res["rules"]

# --- TEST 8: Analyst Feedback ---
def test_qa_analyst_feedback(client: TestClient):
    headers = login(client, "analyst")
    analyses = client.get("/api/analyses").json()["items"]
    assert len(analyses) > 0
    analysis_id = analyses[0]["id"]

    # Submit feedback
    fb = {"verdict": "correct", "comment": "Confirmed phishing page."}
    r = client.post(f"/api/analyses/{analysis_id}/feedback", headers=headers, json=fb)
    assert r.status_code == 200
    assert r.json()["verdict"] == "correct"

    # Verify feedback appears on record
    res = client.get(f"/api/analyses/{analysis_id}")
    assert res.status_code == 200
    feedbacks = res.json().get("feedback", [])
    assert any(f["verdict"] == "correct" and f["comment"] == "Confirmed phishing page." for f in feedbacks)

# --- TEST 9: History & Search ---
def test_qa_history_search_and_filter(client: TestClient):
    login(client, "analyst")
    r = client.get("/api/analyses")
    assert r.status_code == 200
    data = r.json()
    assert "items" in data
    assert "counts" in data
    
    # Filter by decision
    r_phish = client.get("/api/analyses?decision=phishing")
    assert r_phish.status_code == 200
    for item in r_phish.json()["items"]:
        assert item["decision"] == "phishing"

# --- TEST 10: Reports and Sanitized Export ---
def test_qa_exports_and_sanitization(client: TestClient):
    login(client, "analyst")
    analyses = client.get("/api/analyses").json()["items"]
    analysis_id = analyses[0]["id"]

    # JSON export
    r_json = client.get(f"/api/analyses/{analysis_id}/export?format=json")
    assert r_json.status_code == 200
    exp_json = r_json.json()
    assert "decision" in exp_json
    assert "html" not in exp_json  # Raw HTML must not leak

    # CSV export
    r_csv = client.get(f"/api/analyses/{analysis_id}/export?format=csv")
    assert r_csv.status_code == 200
    assert "text/csv" in r_csv.headers["content-type"]

    # History CSV export
    r_hist = client.get("/api/analyses/export/history.csv")
    assert r_hist.status_code == 200
    assert "text/csv" in r_hist.headers["content-type"]

# --- TEST 11: Admin Configurations, Users & Audit Verification ---
def test_qa_admin_capabilities(client: TestClient):
    headers = login(client, "admin")

    # 1. Config Read & Update
    cfg = client.get("/api/admin/config").json()
    assert "rules" in cfg
    orig_threshold = cfg["config"]["phishing_threshold"]

    new_cfg = {
        "phishing_threshold": 0.55,
        "suspicious_threshold": 0.40,
        "ml_weight": 0.8,
        "disabled_rules": ["R06"],
        "reason": "QA Test config version change",
        "confirm": True
    }
    r = client.put("/api/admin/config", headers=headers, json=new_cfg)
    assert r.status_code == 200
    assert r.json()["config"]["disabled_rules"] == ["R06"]

    # Revert config
    revert_cfg = {
        "phishing_threshold": orig_threshold,
        "suspicious_threshold": 0.42,
        "ml_weight": 0.8,
        "disabled_rules": [],
        "reason": "QA Test config revert",
        "confirm": True
    }
    r = client.put("/api/admin/config", headers=headers, json=revert_cfg)
    assert r.status_code == 200

    # 2. User Management
    users = client.get("/api/admin/users").json()["items"]
    assert any(u["username"] == "admin" for u in users)

    # 3. Model Reload
    r = client.post("/api/admin/model/reload", headers=headers)
    assert r.status_code == 200
    assert r.json()["status"] == "loaded"

    # 4. Audit Log & Hash Chain Verification
    audit = client.get("/api/admin/audit?limit=50").json()
    assert len(audit["items"]) > 0
    verify = client.get("/api/admin/audit/verify").json()
    assert verify["valid"] is True
    assert verify["events_checked"] >= len(audit["items"])

# --- TEST 12: Viewer Role Restrictions ---
def test_qa_viewer_role_restrictions(client: TestClient):
    headers = login(client, "viewer")

    # Viewer can read analyses
    r = client.get("/api/analyses")
    assert r.status_code == 200
    for item in r.json()["items"]:
        # Sensitive raw URLs and filenames are hidden in viewer projection
        assert item.get("restricted_view") is True

    # Viewer CANNOT upload
    r = client.post("/api/samples", headers=headers, files={"file": ("v.html", b"<html></html>", "text/html")})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "FORBIDDEN"

    # Viewer CANNOT submit feedback
    analyses = client.get("/api/analyses").json()["items"]
    analysis_id = analyses[0]["id"]
    r = client.post(f"/api/analyses/{analysis_id}/feedback", headers=headers, json={"verdict": "correct"})
    assert r.status_code == 403

    # Viewer CANNOT access admin config or audit
    assert client.get("/api/admin/config").status_code == 403
    assert client.get("/api/admin/audit").status_code == 403
    assert client.get("/api/admin/users").status_code == 403

    # Viewer CANNOT export history CSV
    assert client.get("/api/analyses/export/history.csv").status_code == 403
