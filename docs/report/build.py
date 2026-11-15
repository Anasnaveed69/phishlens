"""Build the final report: facts -> docx (pass 1) -> PDF -> find heading pages -> docx with
contents page numbers (pass 2) -> PDF.  Usage: python docs/report/build.py"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REP = ROOT / "docs" / "report"
DOCX = REP / "PhishLens_Final_Report.docx"
SOFFICE = Path("/root/.claude/skills") .glob("**/docx/scripts/office/soffice.py")


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def to_pdf() -> Path:
    helper = next(SOFFICE, None)
    cmd = [sys.executable, str(helper)] if helper else ["soffice"]
    subprocess.run(cmd + ["--headless", "--convert-to", "pdf", "--outdir", str(REP), str(DOCX)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return DOCX.with_suffix(".pdf")


def pages_text(pdf: Path) -> list[str]:
    n = int(re.search(r"Pages:\s+(\d+)", subprocess.run(["pdfinfo", str(pdf)], capture_output=True, text=True).stdout).group(1))
    return [subprocess.run(["pdftotext", "-f", str(i), "-l", str(i), "-layout", str(pdf), "-"], capture_output=True,
                           text=True).stdout for i in range(1, n + 1)]


def main() -> None:
    run([sys.executable, "docs/report/make_facts.py"])
    toc_file = REP / "toc.json"
    headings = None
    for attempt in range(2):
        if attempt == 0:
            # placeholder TOC with the right number of lines so pagination matches pass 2
            if headings is None and (REP / "headings.json").exists():
                headings = json.loads((REP / "headings.json").read_text())
            toc_file.write_text(json.dumps([[t, lvl, "00"] for t, lvl in (headings or [])]))
        run(["node", "docs/report/build_report.js"])
        headings = json.loads((REP / "headings.json").read_text())
        pdf = to_pdf()
        texts = pages_text(pdf)
        toc = []
        start = 2  # PDF page 1 is the cover; body page numbering starts at PDF page 2
        for title, lvl in headings:
            norm = re.sub(r"\s+", " ", title).strip()
            page = next((i for i in range(start, len(texts) + 1)
                         if any(re.sub(r"\s+", " ", ln).strip() == norm for ln in texts[i - 1].splitlines())), None)
            if page:
                start = page
            toc.append([title, lvl, str(page - 1) if page else "?"])
        toc_file.write_text(json.dumps(toc))
    run(["node", "docs/report/build_report.js"])
    pdf = to_pdf()
    print("report:", DOCX, pdf, json.loads(toc_file.read_text())[:4])


if __name__ == "__main__":
    main()
