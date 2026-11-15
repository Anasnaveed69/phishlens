"""Pack reports/ (json, md, csv) into a compressed base64 blob printed to stdout.

Used to move evaluation results out of a notebook session where only text output is
available. Restore with:  python scripts/export_reports.py --restore blob.txt
"""
from __future__ import annotations

import argparse
import base64
import io
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default=str(ROOT / "reports"))
    ap.add_argument("--restore", help="file containing the printed blob")
    ap.add_argument("--sizes", action="store_true", help="only print the packed size")
    args = ap.parse_args()
    rep = Path(args.reports)
    if args.restore:
        text = Path(args.restore).read_text().strip()
        text = text.split("PHISHLENS_BLOB_START", 1)[-1].split("PHISHLENS_BLOB_END", 1)[0].strip()
        with tarfile.open(fileobj=io.BytesIO(base64.b85decode(text)), mode="r:xz") as t:
            rep.mkdir(parents=True, exist_ok=True)
            for m in t.getmembers():
                if not m.isfile() or "/" in m.name or m.name.startswith("."):
                    continue  # only flat, regular files — never paths
                (rep / m.name).write_bytes(t.extractfile(m).read())
                print("restored", m.name)
        return
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:xz") as t:
        for p in sorted(rep.iterdir()):
            if p.suffix in {".json", ".md", ".csv"}:
                t.add(p, arcname=p.name)
    blob = base64.b85encode(buf.getvalue()).decode()
    if args.sizes:
        print(f"packed {len(buf.getvalue())} bytes -> {len(blob)} chars")
        return
    sys.stdout.write("PHISHLENS_BLOB_START" + blob + "PHISHLENS_BLOB_END\n")


if __name__ == "__main__":
    main()
