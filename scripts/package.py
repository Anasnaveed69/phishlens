"""Build the submission zip from the git-tracked files (so secrets, .venv, data/ and
the real phishing dataset can never slip in), plus the generated evaluation reports.

Usage:  python scripts/package.py            -> dist/PhishLens_Class1_Group01.zip
"""
from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = "PhishLens_Class1_Group01"
BLOCKED = ("data/", ".venv/", "phreshphish_sample", "secrets/", "TASKS.md")


def main() -> None:
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    files = [f for f in files if not f.startswith(BLOCKED) and not (f.startswith(".env") and f != ".env.example")]
    extra = [p.relative_to(ROOT).as_posix() for p in (ROOT / "models").glob("model*") if p.is_file()]
    out = ROOT / "dist" / f"{NAME}.zip"
    out.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for f in sorted(set(files + extra)):
            z.write(ROOT / f, arcname=f"{NAME}/{f}")
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
    leaked = [n for n in names if any(b in n for b in (".env", "/data/", "phishlens.db"))
              and not n.endswith(".env.example")]
    if leaked:
        sys.exit(f"refusing: sensitive files in zip: {leaked}")
    print(f"{out} — {len(names)} files, {out.stat().st_size / 1e6:.2f} MB")


if __name__ == "__main__":
    main()
