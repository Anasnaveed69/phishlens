"""Record a reproducible walkthrough video of the full demo scenario (proposal page 3).

Requires: pip install playwright && playwright install chromium; ffmpeg for the .mp4.
Usage:
    uvicorn app.main:app --port 8000          (in another terminal, fresh data/ folder)
    python scripts/record_demo.py --admin-pass ... --analyst-pass ... --viewer-pass ...
Output: dist/demo/phishlens_demo.mp4 (+ the raw .webm) and one PNG per step.

Each step shows a caption bar at the top so the video can be watched without narration.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures" / "tests"
OUT = ROOT / "dist" / "demo"

CAPTION_JS = """(text) => {
  let el = document.getElementById('__demo_caption');
  if (!el) { el = document.createElement('div'); el.id = '__demo_caption'; document.body.appendChild(el); }
  el.textContent = text;
  Object.assign(el.style, {position:'fixed', left:'0', right:'0', top:'0', zIndex:'9999', padding:'12px 20px',
    pointerEvents:'none', background:'rgba(20,24,35,.92)', color:'#fff', font:'600 18px system-ui, sans-serif', textAlign:'center'});
}"""

STEP = 0


def caption(page: Page, text: str, hold: float = 2.5) -> None:
    global STEP
    STEP += 1
    page.evaluate(CAPTION_JS, f"Step {STEP}: {text}")
    page.wait_for_timeout(int(hold * 1000))
    page.screenshot(path=str(OUT / f"step_{STEP:02d}.png"))


def login(page: Page, base: str, user: str, pw: str) -> None:
    page.goto(base + "/")
    page.wait_for_selector("#username")
    page.fill("#username", user)
    page.wait_for_timeout(300)
    page.fill("#password", pw)
    page.click("button[type=submit]")
    page.wait_for_selector("#who-name")


def logout(page: Page) -> None:
    page.click("#logout")
    page.wait_for_selector("#username")


def upload(page: Page, base: str, name: str, url: str) -> None:
    page.goto(base + "/#/analyze")
    page.wait_for_selector("#file")
    page.set_input_files("#file", str(FIX / name))
    page.fill("#source_url", url)
    page.wait_for_timeout(600)
    page.click("button[type=submit]")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--admin-pass", required=True)
    ap.add_argument("--analyst-pass", required=True)
    ap.add_argument("--viewer-pass", required=True)
    args = ap.parse_args()
    base = args.base
    OUT.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1280, "height": 800}, record_video_dir=str(OUT),
                                  record_video_size={"width": 1280, "height": 800})
        page = ctx.new_page()

        login(page, base, "analyst", args.analyst_pass)
        caption(page, "Analyst signs in — dashboard shows status, model version and config version", 4)

        upload(page, base, "benign_bank_login.html", "https://www.hbl.com/login")
        page.wait_for_selector(".verdict")
        caption(page, "Normal sample (bank login on its own domain) → BENIGN, no unjustified warning", 5)

        upload(page, base, "phish_brand_clone.html", "http://paypal-secure-verify.tk/webscr/signin")
        page.wait_for_selector(".verdict")
        caption(page, "Seeded adverse sample → PHISHING with the specific indicators, not just 'unsafe'", 4)
        page.mouse.wheel(0, 650)
        caption(page, "Every rule shows its reason and evidence; the model shows which features pushed it", 5)
        page.mouse.wheel(0, 900)
        caption(page, "Reproducibility: analysis id, config version, rule/model versions, thresholds", 4)

        page.goto(base + "/#/analyze")
        page.wait_for_selector("#file")
        page.set_input_files("#file", {"name": "invoice.exe", "mimeType": "application/octet-stream",
                                       "buffer": b"MZ\x90\x00 not a web page"})
        page.click("button[type=submit]")
        page.wait_for_selector(".error:not(:empty)")
        caption(page, "Invalid input (.exe) is rejected before processing and the attempt is logged", 4)

        upload(page, base, "phish_brand_clone.html", "http://paypal-secure-verify.tk/webscr/signin")
        page.wait_for_selector(".verdict")
        caption(page, "Repeated submission → recognised as duplicate, fresh analysis on the stored copy", 3)

        page.goto(base + "/#/history")
        page.wait_for_selector("table tbody tr")
        boxes = page.locator("tbody input[type=checkbox]")
        boxes.nth(0).check()
        boxes.nth(boxes.count() - 1).check()
        caption(page, "History with filters — select the adverse and the normal result to compare", 3)
        page.click("text=Compare selected")
        page.wait_for_selector(".verdict")
        caption(page, "Side-by-side comparison, including the features that differ", 5)

        page.goto(base + "/#/history")
        page.wait_for_selector("table tbody tr")
        with page.expect_download() as dl:
            page.click("text=Export history CSV")
        dl.value.save_as(OUT / "history_export.csv")
        caption(page, "Sanitized export (CSV/JSON) — no page content, formula-injection safe", 3)
        logout(page)

        login(page, base, "viewer", args.viewer_pass)
        page.goto(base + "/#/history")
        page.wait_for_selector("table tbody tr")
        page.locator("tbody tr").first.click()
        page.wait_for_selector(".verdict")
        caption(page, "Viewer gets a restricted view: decision and reasons only, no evidence or URLs", 4)
        status = page.evaluate("""async () => (await fetch('/api/samples')).status""")
        page.goto(base + "/#/admin/config")
        page.wait_for_timeout(800)
        caption(page, f"Viewer calling an analyst/admin API gets a generic denial (HTTP {status}), and it is logged", 4)
        logout(page)

        login(page, base, "admin", args.admin_pass)
        page.goto(base + "/#/admin/config")
        page.wait_for_selector("input[name=reason]")
        caption(page, "Admin: thresholds, model weight and rules are versioned configuration", 3)
        page.fill("input[name=suspicious_threshold]", "0.3")
        page.fill("input[name=reason]", "Demo: stricter suspicious threshold")
        page.once("dialog", lambda d: d.accept())
        page.click("text=Save new version")
        page.wait_for_timeout(1200)
        caption(page, "High-impact change needs a reason + confirmation → new config version", 4)

        page.goto(base + "/#/history")
        page.wait_for_selector("table tbody tr")
        page.locator("tbody tr").last.click()
        page.wait_for_selector(".verdict")
        page.click("text=Re-analyze with current config")
        page.wait_for_timeout(1500)
        caption(page, "Re-running the test uses the new config version — the result records which one", 4)

        page.goto(base + "/#/admin/audit")
        page.wait_for_selector("table tbody tr")
        page.click("text=Verify hash chain")
        page.wait_for_timeout(800)
        caption(page, "Append-only, hash-chained audit log: logins, denials, uploads, decisions, config change", 6)

        page.goto(base + "/#/dashboard")
        page.wait_for_selector(".stats")
        caption(page, "Dashboard: decisions, severity, top indicators, latency, analyst feedback", 5)
        video = page.video.path()
        ctx.close()
        browser.close()

    webm = OUT / "phishlens_demo.webm"
    shutil.move(video, webm)
    if shutil.which("ffmpeg"):
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-i", str(webm), "-c:v", "libx264", "-preset", "veryfast",
                        "-crf", "26", "-pix_fmt", "yuv420p", str(OUT / "phishlens_demo.mp4")], check=True)
    print(f"done: {OUT}")


if __name__ == "__main__":
    main()
