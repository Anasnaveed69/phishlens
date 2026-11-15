# Limitations and ethics

## Limitations
* **Synthetic starter data.** The bundled generator produces easy, template-based pages; metrics on it are
  optimistic. Final numbers must come from the instructor-approved dataset.
* **Static analysis only.** Pages are never executed, so content built entirely by JavaScript at runtime,
  or pages that differ per visitor, can be missed. This is a deliberate safety trade-off.
* **Visual-risk features are markup-based** (external logo/favicon, brand in title, hidden elements), not
  screenshot or image similarity.
* **Brand list is fixed** in `engine/features.py`; unknown brands are not detected as impersonated.
* **Domain parsing is approximate** (no full public-suffix list, to avoid network access).
* **Rate limiter is in-memory** and per-process; it resets on restart.
* **Local demo runs over HTTP.** Set `PHISHLENS_COOKIE_SECURE=1` and use TLS for any real deployment.
* Someone with OS-level access to the machine can still replace files; the audit hash chain detects edits
  but cannot prevent them.

## Ethics
* Only safe, synthetic or **instructor-approved archived** samples are used. We never visit live phishing
  sites and never submit data to them.
* All test collection endpoints use the reserved `.test` TLD; no real credentials appear anywhere.
* No real attacks are deployed and no external targets are scanned.
* The system is decision support: analysts can override and the feedback is recorded.
* Stored data is minimised: exports omit page content, logs are redacted, passwords are hashed.
