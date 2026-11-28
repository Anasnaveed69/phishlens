"""End-to-end browser tests: every screen, every role, in a real Chromium.

Run:  pip install playwright && playwright install chromium
      pytest tests/e2e -q            (skipped automatically if Playwright/Chromium is missing)

Each test session starts its own server on a throw-away database, so it never touches data/.
"""
from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import pytest

pw = pytest.importorskip("playwright.sync_api")

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "fixtures" / "tests"
PASSWORDS = {"admin": "Admin-e2e-pass-1", "analyst": "Analyst-e2e-pass-1", "viewer": "Viewer-e2e-pass-1"}
PHISH = ("phish_brand_clone.html", "http://paypal-secure-verify.tk/webscr/signin")
BENIGN = ("benign_bank_portal.html", "https://www.hbl.com/ib/login")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def server():
    tmp = tempfile.mkdtemp(prefix="phishlens-e2e-")
    env = {**os.environ, "PHISHLENS_DB": f"{tmp}/e2e.db", "PHISHLENS_SAMPLE_DIR": f"{tmp}/samples",
           "PHISHLENS_SECRET_DIR": f"{tmp}/secrets", "PHISHLENS_LOGIN_RATE": "50", "PHISHLENS_ANALYZE_RATE": "500"}
    seed = (
        "import sys; sys.path.insert(0, '.');"
        "from scripts.create_user import create; from app.db import init_db; init_db();"
        + "".join(f"create({u!r}, {p!r}, {u!r});" for u, p in PASSWORDS.items())
    )
    subprocess.run([sys.executable, "-c", seed], cwd=ROOT, env=env, check=True, capture_output=True)
    port = _free_port()
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port)], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.25)
    yield base
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture(scope="session")
def browser():
    try:
        with pw.sync_playwright() as p:
            b = p.chromium.launch()
            yield b
            b.close()
    except Exception as exc:  # Chromium not installed
        pytest.skip(f"Chromium unavailable: {exc}")


@pytest.fixture
def page(browser, server):
    ctx = browser.new_context(viewport={"width": 1280, "height": 900}, accept_downloads=True)
    pg = ctx.new_page()
    errors: list[str] = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    # Expected HTTP errors (401 before login, 4xx for rejected input) show up as "Failed to load resource";
    # only real script errors count.
    pg.on("console", lambda m: errors.append(m.text)
          if m.type == "error" and not m.text.startswith("Failed to load resource") else None)
    pg.accept_dialogs = False

    def on_dialog(d):
        if pg.accept_dialogs and d.type == "confirm":
            d.accept()
        else:  # alert()/prompt() never happen in PhishLens; one would mean injected script ran
            errors.append(f"unexpected dialog: {d.type} {d.message}")
            d.dismiss()

    pg.on("dialog", on_dialog)
    pg.base = server
    pg.js_errors = errors
    yield pg
    ctx.close()
    assert not errors, f"browser errors: {errors}"


def login(pg, role: str) -> None:
    pg.goto(pg.base + "/")
    pg.fill("#username", role)
    pg.fill("#password", PASSWORDS[role])
    pg.click("button[type=submit]")
    pg.wait_for_selector("#who-name")


def analyze(pg, fixture: tuple[str, str]) -> None:
    pg.goto(pg.base + "/#/analyze")
    pg.set_input_files("#file", str(FIX / fixture[0]))
    pg.fill("#source_url", fixture[1])
    pg.click("button[type=submit]")
    pg.wait_for_selector(".verdict")


# ------------------------------------------------------------------ auth + navigation
def test_login_failure_shows_generic_message(page):
    page.goto(page.base + "/")
    page.fill("#username", "analyst")
    page.fill("#password", "wrong-password-1")
    page.click("button[type=submit]")
    page.wait_for_selector(".error:has-text('Invalid username or password')")
    assert page.locator("#who").is_hidden()


@pytest.mark.parametrize("role,visible,hidden", [
    ("admin", ["Dashboard", "Analyze", "History", "Dataset", "Admin"], []),
    ("analyst", ["Dashboard", "Analyze", "History", "Dataset"], ["Admin"]),
    ("viewer", ["Dashboard", "History"], ["Analyze", "Dataset", "Admin"]),
])
def test_navigation_matches_role(page, role, visible, hidden):
    login(page, role)
    page.wait_for_selector(".stats")  # dashboard is the landing page
    for name in visible:
        assert page.locator(f"#nav a:has-text('{name}')").is_visible(), name
    for name in hidden:
        assert page.locator(f"#nav a:has-text('{name}')").is_hidden(), name


def test_logout_returns_to_login_and_kills_session(page):
    login(page, "analyst")
    page.click("#logout")
    page.wait_for_selector("#username")
    assert page.evaluate("async () => (await fetch('/api/auth/me')).status") == 401


# ------------------------------------------------------------------ analyst workflow
def test_benign_page_shows_no_unjustified_warning(page):
    login(page, "analyst")
    analyze(page, BENIGN)
    assert page.locator(".verdict.benign").is_visible()
    assert "No rule fired" in page.inner_text("main")


def test_phishing_page_shows_specific_indicators_and_explanation(page):
    login(page, "analyst")
    analyze(page, PHISH)
    assert page.locator(".verdict.phishing").is_visible()
    names = page.locator(".rule .name").all_inner_texts()
    assert any("Password form posts to another domain" in n for n in names)
    assert page.locator(".evidence").count() > 0                      # evidence from the page
    assert page.locator(".bar").count() >= 3                          # model contributions
    text = page.inner_text("main")
    for needle in ("Config version", "Analysis ID", "Thresholds", "rf-"):
        assert needle in text, needle


def test_invalid_upload_is_rejected_in_the_ui(page):
    login(page, "analyst")
    page.goto(page.base + "/#/analyze")
    page.set_input_files("#file", {"name": "x.exe", "mimeType": "application/octet-stream", "buffer": b"MZ\x90\x00"})
    page.click("button[type=submit]")
    page.wait_for_selector(".error:not(:empty)")
    assert ".html" in page.inner_text(".error")


def test_feedback_and_exports(page):
    login(page, "analyst")
    analyze(page, PHISH)
    page.select_option("#verdict", "correct")
    page.fill("#comment", "confirmed by analyst")
    page.click("button:has-text('Submit feedback')")
    page.wait_for_selector("li:has-text('confirmed by analyst')")
    with page.expect_download() as dl:
        page.click("button:has-text('Export JSON')")
    report = json.loads(Path(dl.value.path()).read_text())
    assert report["decision"] == "phishing" and "<form" not in json.dumps(report)
    with page.expect_download() as dl:
        page.click("button:has-text('Export CSV')")
    assert "decision" in Path(dl.value.path()).read_text()


def test_history_filter_search_and_compare(page):
    login(page, "analyst")
    analyze(page, BENIGN)
    analyze(page, PHISH)
    page.goto(page.base + "/#/history?decision=phishing")
    page.wait_for_selector("tbody tr")
    assert all(t == "phishing" for t in page.locator("tbody .pill.phishing, tbody td:nth-child(4) .pill").all_inner_texts()
               if t in {"phishing", "benign", "suspicious"})
    page.goto(page.base + "/#/history?q=bank_portal")
    page.wait_for_selector("tbody tr:has-text('benign_bank_portal')")
    assert "phish_brand_clone" not in page.inner_text("tbody")
    page.goto(page.base + "/#/history")
    page.wait_for_selector("tbody tr")
    boxes = page.locator("tbody input[type=checkbox]")
    boxes.nth(0).check()
    boxes.nth(1).check()
    page.click("button:has-text('Compare selected')")
    page.wait_for_selector(".verdict >> nth=1")
    assert page.locator(".verdict").count() == 2
    assert "Features that differ" in page.inner_text("main")


def test_dataset_import_via_ui(page):
    login(page, "analyst")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.html", "<html><body><p>e2e import page a</p></body></html>")
        z.writestr("b.html", "<html><body><p>e2e import page b</p></body></html>")
        z.writestr("labels.csv", "filename,label,source_url\na.html,benign,https://a.example.com/\nb.html,benign,\n")
    page.goto(page.base + "/#/dataset")
    page.set_input_files("#zip", {"name": "ds.zip", "mimeType": "application/zip", "buffer": buf.getvalue()})
    page.check("input[name=analyze]")
    page.click("button:has-text('Import')")
    page.wait_for_selector("dl.kv")
    text = page.inner_text("dl.kv")
    assert "pages" in text and "labeled" in text


# ------------------------------------------------------------------ viewer restrictions
def test_viewer_sees_restricted_result_and_is_denied_admin(page, browser, server):
    # make sure at least one analysis exists
    analyst = browser.new_page()
    analyst.base = server
    login(analyst, "analyst")
    analyze(analyst, PHISH)
    analyst.close()

    login(page, "viewer")
    page.goto(page.base + "/#/history")
    page.wait_for_selector("tbody tr")
    page.locator("tbody tr").first.click()
    page.wait_for_selector(".verdict")
    text = page.inner_text("main")
    assert "Why" in text and "Analysis ID" not in text and ".evidence" not in page.content()
    page.goto(page.base + "/#/admin/audit")
    page.wait_for_selector(".error")
    assert "not permitted" in page.inner_text(".error")


# ------------------------------------------------------------------ admin
def test_admin_config_change_is_versioned_and_audited(page):
    login(page, "admin")
    page.goto(page.base + "/#/admin/config")
    page.wait_for_selector("input[name=reason]")
    before = page.inner_text("main")
    page.uncheck("input[name=rule][value=R07]")
    page.fill("input[name=reason]", "e2e: disable R07")
    page.accept_dialogs = True  # the app asks "Save config v2?" — the confirmation step under test
    page.click("button:has-text('Save new version')")
    page.wait_for_selector("td:has-text('e2e: disable R07')")
    assert "e2e: disable R07" in page.inner_text("main") and before != page.inner_text("main")
    page.goto(page.base + "/#/admin/audit")
    page.wait_for_selector("tbody tr")
    assert "config.update" in page.inner_text("tbody")
    page.click("button:has-text('Verify hash chain')")
    page.wait_for_selector("text=Chain intact")


def test_admin_user_management_disable_blocks_login(page, browser, server):
    login(page, "admin")
    page.goto(page.base + "/#/admin/users")
    page.wait_for_selector("input[name=username]")
    page.fill("input[name=username]", "tempuser")
    page.fill("input[name=password]", "Temp-user-pass-1")
    page.select_option("select[name=role]", "viewer")
    page.click("button:has-text('Add user')")
    page.wait_for_selector("td:has-text('tempuser')")
    page.accept_dialogs = True
    page.locator("tr:has-text('tempuser') button:has-text('Disable')").click()
    page.wait_for_selector("tr:has-text('tempuser') td:has-text('disabled')")
    other = browser.new_page()
    other.goto(server + "/")
    other.fill("#username", "tempuser")
    other.fill("#password", "Temp-user-pass-1")
    other.click("button[type=submit]")
    other.wait_for_selector(".error:not(:empty)")
    other.close()


def test_admin_model_tab_shows_loaded_model(page):
    login(page, "admin")
    page.goto(page.base + "/#/admin/model")
    page.wait_for_selector("dl.kv")
    text = page.inner_text("main")
    assert "loaded" in text and "rf-" in text


# ------------------------------------------------------------------ account
def test_password_change_validation_and_success(page):
    login(page, "viewer")
    page.goto(page.base + "/#/account")
    page.fill("#cp", PASSWORDS["viewer"])
    page.fill("#np", "Viewer-e2e-pass-2")
    page.fill("#rp", "mismatch-pass-2")
    page.click("button:has-text('Change password')")
    page.wait_for_selector(".error:has-text('do not match')")
    page.fill("#rp", "Viewer-e2e-pass-2")
    page.click("button:has-text('Change password')")
    page.wait_for_selector("#toast:has-text('Password changed')")
    # change it back for other tests
    page.fill("#cp", "Viewer-e2e-pass-2")
    page.fill("#np", PASSWORDS["viewer"])
    page.fill("#rp", PASSWORDS["viewer"])
    page.click("button:has-text('Change password')")
    page.wait_for_selector("#toast:has-text('Password changed')")


# ------------------------------------------------------------------ security in the browser
def test_xss_payload_in_page_is_rendered_as_text(page, tmp_path):
    login(page, "analyst")
    evil = tmp_path / "evil.html"
    evil.write_text("<html><head><title><img src=x onerror=alert(1)>PayPal login</title></head><body>"
                    "<form action=\"https://x.test/<script>alert(2)</script>\"><input type=password></form></body></html>")
    page.goto(page.base + "/#/analyze")
    page.set_input_files("#file", str(evil))
    page.fill("#source_url", "http://evil.example.tk/")
    page.click("button[type=submit]")
    page.wait_for_selector(".verdict")
    assert page.evaluate("document.querySelectorAll('main img, main script').length") == 0
    # (the page fixture fails the test if any alert() dialog fired)


def test_security_headers_on_ui(page):
    resp = page.goto(page.base + "/")
    h = resp.headers
    assert "default-src 'self'" in h["content-security-policy"] and h["x-frame-options"] == "DENY"


# ------------------------------------------------------------------ accessibility + responsive
AXE = None


def _axe(page) -> list[dict]:
    global AXE
    if AXE is None:
        try:
            import axe_playwright_python
            AXE = (Path(axe_playwright_python.__file__).parent / "axe.min.js").read_text()
        except ImportError:
            pytest.skip("axe-playwright-python not installed")
    page.evaluate(AXE)  # via DevTools: the app's CSP (correctly) blocks injected <script> tags
    res = page.evaluate("async () => await axe.run(document, {resultTypes: ['violations']})")
    return [v for v in res["violations"] if v["impact"] in {"serious", "critical"}]


@pytest.mark.parametrize("route,ready", [
    ("/", "#username"), ("/#/dashboard", ".stats"), ("/#/analyze", "#file"), ("/#/history", "table"),
    ("/#/admin/config", "input[name=reason]"), ("/#/account", "#cp"),
])
def test_no_serious_accessibility_violations(page, route, ready):
    if route != "/":
        login(page, "admin")
    page.goto(page.base + route)
    page.wait_for_selector(ready)
    violations = _axe(page)
    assert not violations, [(v["id"], v["help"], len(v["nodes"])) for v in violations]


@pytest.mark.parametrize("route,ready", [("/#/dashboard", ".stats"), ("/#/history", "table")])
def test_mobile_layout_has_no_horizontal_scroll(page, route, ready):
    page.set_viewport_size({"width": 375, "height": 812})
    login(page, "analyst")
    page.goto(page.base + route)
    page.wait_for_selector(ready)
    overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
    assert overflow <= 1, f"page is {overflow}px wider than a phone screen"
