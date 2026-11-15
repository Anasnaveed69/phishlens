# Limitations and ethics

## Limitations
* **Development estimates vs final result.** Rules were designed with error analysis that saw the development
  test split; the headline numbers therefore come from a separate fresh holdout of unseen pages.
* **One dataset, one period.** Numbers come from a 2000-page sample of PhreshPhish (2024–2025, English).
  Other periods, languages or targeted phishing may behave differently.
* **Dataset shortcut.** In the data, benign pages are big full websites and phishing pages are small, so models
  learn "small page = phishing". We serve a model without pure page-size features (equal cross-validated F1),
  but minimal legitimate pages (e.g. a bare intranet login) can still be scored *suspicious*; analysts see why.
* **Static analysis only.** Pages are never executed, so content built entirely by JavaScript at runtime,
  or pages that differ per visitor, can be missed. This is a deliberate safety trade-off.
* **Visual-risk features are markup-based** (external logo/favicon, brand in title, hidden elements), not
  screenshot or image similarity.
* **Brand list is fixed** in `engine/features.py`; unknown brands are not detected as impersonated.
* **Domain parsing is approximate** (no full public-suffix list, to avoid network access).
* **Rate limiter is in-memory** and per-process; it resets on restart.
* **Local demo runs over HTTP.** Set `PHISHLENS_COOKIE_SECURE=1` and use TLS for any real deployment.
* The audit chain is HMAC-keyed (`secrets/audit.key`, outside `data/`): a copied or edited database cannot be
  re-chained without the key, but someone holding both could rewrite it, and deleting the newest rows is only
  detectable against an external copy of the chain head (returned by `/api/admin/audit/verify`).
* A model file plus its metadata can be swapped together unless `PHISHLENS_MODEL_SHA256` pins the hash.
* The login limiter is keyed on IP; on a shared machine (all 127.0.0.1) repeated bad logins temporarily lock an
  account — a deliberate trade-off against brute force.

## Ethics
* Only safe, synthetic or **instructor-approved archived** samples are used. We never visit live phishing
  sites and never submit data to them.
* All test collection endpoints use the reserved `.test` TLD; no real credentials appear anywhere.
* No real attacks are deployed and no external targets are scanned.
* The system is decision support: analysts can override and the feedback is recorded.
* Stored data is minimised: exports omit page content, logs are redacted, passwords are hashed.
