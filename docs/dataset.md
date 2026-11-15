# Dataset

## Format PhishLens expects
A folder (for training) or `.zip` (for import) containing `.html`/`.htm` pages and a `labels.csv`:

```csv
filename,label,source_url
page_0001.html,phishing,http://paypal-secure-verify.tk/webscr
page_0002.html,benign,https://news.example.com/article
```

`label` is `phishing` or `benign`. `source_url` is optional and is never requested.

## Sources
| Source | Status | Notes |
|---|---|---|
| `scripts/generate_synthetic.py` | in use (starter) | 300 + 300 template pages, safe by construction |
| `fixtures/tests/` | in use (tests) | 6 hand-written pages incl. edge cases |
| **PhreshPhish** (Dalton et al., 2025) — `phreshphish/phreshphish` on Hugging Face, official *test* split | **used for evaluation** | CC BY 4.0, anti-phishing research use. 2,000-page balanced English sample (1,000 phishing / 1,000 benign), seed 42, pages ≤ 1 MB, exact duplicates removed. Get it with `python scripts/fetch_phreshphish.py --per-class 1000` (or in Colab). Not committed. |
| Instructor-approved archived samples | confirm with instructor | any dataset in the format above can be evaluated with the same command |

## Rules for handling samples
* Never open archived phishing pages in a normal browser; analyze them only through PhishLens.
* Keep the real dataset out of git if it is large or licensed — share it through the course drive and
  record the download link + checksum here instead.

## What is committed
* `reports/features.csv` — the numeric feature matrix of the 2,000 pages with the train/test split
  (no URLs, no page content), enough to rebuild and audit the model.
* `reports/errors.csv` — test-set errors with **defanged** URLs (`hxxp://example[.]com`).
* The raw HTML stays out of git.
