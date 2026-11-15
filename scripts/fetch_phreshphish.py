"""Download a balanced sample of the PhreshPhish dataset into PhishLens' import format.

PhreshPhish (Dalton et al., 2025, CC BY 4.0, for anti-phishing research) contains real phishing
and benign pages collected as URL + HTML pairs. We STREAM the official test split so only the
sampled rows are downloaded (the full dataset is ~37 GB).

Run on any laptop with internet:
    pip install datasets
    python scripts/fetch_phreshphish.py --per-class 1000

Output: phreshphish_sample/ (pages + labels.csv) and phreshphish_sample.zip, ready for
`python scripts/train_model.py --data phreshphish_sample` or Dataset → Import in the UI.

Safety: the HTML is written to disk as text only. Never open these files in a browser.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import zipfile
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-class", type=int, default=1000, help="pages per class (benign / phishing)")
    ap.add_argument("--split", default="test", help="dataset split to sample from")
    ap.add_argument("--max-kb", type=int, default=1024, help="skip pages larger than this")
    ap.add_argument("--lang", default="en", help="keep only this language ('' for all)")
    ap.add_argument("--out", default="phreshphish_sample")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--exclude-dir", action="append", default=[],
                    help="skip any page whose HTML already appears in this folder (build a fresh, unseen holdout)")
    args = ap.parse_args()

    from datasets import load_dataset  # imported here so --help works without the package

    ds = load_dataset("phreshphish/phreshphish", split=args.split, streaming=True)
    ds = ds.shuffle(seed=args.seed, buffer_size=20_000)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    counts = {"benign": 0, "phishing": 0}
    seen: set[str] = set()
    for d in args.exclude_dir:
        for p in Path(d).glob("*.htm*"):
            seen.add(hashlib.sha256(p.read_text(encoding="utf-8", errors="replace").encode("utf-8", "replace")).hexdigest())
    if args.exclude_dir:
        print(f"excluding {len(seen)} previously used pages")
    rows = []
    for rec in ds:
        label = "phishing" if rec["label"] == "phish" else "benign"
        if counts[label] >= args.per_class:
            if all(c >= args.per_class for c in counts.values()):
                break
            continue
        html = rec.get("html") or ""
        if not html.strip() or len(html.encode("utf-8", "replace")) > args.max_kb * 1024:
            continue
        if args.lang and rec.get("lang") != args.lang:
            continue
        digest = hashlib.sha256(html.encode("utf-8", "replace")).hexdigest()
        if digest in seen:  # drop exact duplicate pages
            continue
        seen.add(digest)
        counts[label] += 1
        name = f"{label}_{counts[label]:05d}.html"
        (out / name).write_text(html, encoding="utf-8", errors="replace")
        rows.append({"filename": name, "label": label, "source_url": (rec.get("url") or "")[:2048],
                     "date": str(rec.get("date") or ""), "target": rec.get("target") or ""})
        if sum(counts.values()) % 200 == 0:
            print(f"  {counts}")

    with (out / "labels.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["filename", "label", "source_url", "date", "target"])
        w.writeheader()
        w.writerows(rows)

    zpath = Path(f"{args.out}.zip")
    with zipfile.ZipFile(zpath, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in sorted(out.iterdir()):
            z.write(p, arcname=p.name)
    print(f"done: {counts} -> {out}/ and {zpath} ({zpath.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
