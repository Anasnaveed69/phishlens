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
| Instructor-approved archived phishing/benign HTML dataset | **ask instructor** | convert to the format above; record name, version, licence and size here |

## Rules for handling samples
* Never open archived phishing pages in a normal browser; analyze them only through PhishLens.
* Keep the real dataset out of git if it is large or licensed — share it through the course drive and
  record the download link + checksum here instead.
