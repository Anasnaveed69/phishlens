# PhishLens Security Audit Report

## Audit Scope & Methodology
A defensive security assessment was conducted against PhishLens adhering to the STRIDE threat modeling framework and OWASP Top 10 guidelines. Testing was performed locally using automated security misuse suites and live browser testing.

---

## 1. Security Findings Matrix

| Threat Category | Test / Vector | Severity | Finding & Verification | Remediation Status |
|---|---|:---:|---|:---:|
| **Authentication & Sessions** | Brute Force / Password Spraying | Medium | Rate limiter locks out IP after 5 attempts/min; errors return generic messages preventing user enumeration. | VERIFIED SECURE |
| **Authentication & Sessions** | Session Fixation & Hijacking | High | Session tokens are 256-bit cryptographic values; stored as SHA-256 in DB; delivered via `HttpOnly`, `SameSite=Strict` cookies. | VERIFIED SECURE |
| **Access Control (RBAC)** | Privilege Escalation | High | All endpoints protected via FastAPI `require(permission)`. Viewer role gets restricted projections and cannot access administrative routes or raw samples. | VERIFIED SECURE |
| **CSRF Defense** | State-changing Cross-Origin POST | High | Validated per-session CSRF token required in `X-CSRF-Token` header for all mutating actions. Cross-session CSRF tokens rejected. | VERIFIED SECURE |
| **Injection Defense** | SQL Injection | Critical | All database operations use SQLite parameterized queries (`?`). Wildcards in search queries are strictly escaped. | VERIFIED SECURE |
| **Injection Defense** | Stored XSS via Malicious Pages | High | Frontend SPA strictly uses `textContent` via the helper `h()`. Content Security Policy enforces `script-src 'self'`. No inline JavaScript executed. | VERIFIED SECURE |
| **Injection Defense** | CSV Formula Injection | Medium | Exported CSV fields beginning with `=`, `+`, `-`, or `@` are sanitized with leading single quotes. | VERIFIED SECURE |
| **Malicious File Handling** | ZIP Slip & Path Traversal | High | Directory names in uploaded archives are discarded; storage filenames are server-generated UUIDs or content hashes. | VERIFIED SECURE |
| **Malicious File Handling** | ZIP Bomb & Resource Exhaustion | High | Max archive decompressed size, max file count, and individual file size caps strictly enforced before processing. | VERIFIED SECURE |
| **Hostile Code Execution** | Phishing JavaScript & External Beacons | Critical | Uploaded HTML is parsed purely via BeautifulSoup in memory. No rendering engine or headless JS executor is invoked; declared URLs are never fetched over the network. | VERIFIED SECURE |
| **Audit Log Integrity** | Log Tampering & Record Deletion | High | SQLite triggers prohibit UPDATE and DELETE on `audit_events`. HMAC-SHA256 keyed hash chain ensures tamper-evidence. | VERIFIED SECURE |
| **Model Integrity** | Tampered / Corrupted ML Weights | High | SHA-256 checksum verified against metadata on load. Corrupted files trigger graceful fallback to rules-only mode without crashing. | VERIFIED SECURE |

---

## 2. In-Depth Technical Verification

### A. Non-Execution of Untrusted HTML & Safe Parsing
PhishLens accepts hostile HTML files by design. Testing verified that:
- Hostile scripts (`<script>alert(1)</script>`, `document.location=...`) are parsed purely as text nodes.
- No network requests are dispatched by the server to inspect or fetch external assets.
- Rendered UI displays extracted evidence using DOM `textContent` nodes, ensuring zero payload execution in the analyst's browser.

### B. Audit Trail Hash Chain Integrity
The audit subsystem computes an HMAC-SHA256 chain:
$$\text{hash}_n = \text{HMAC-SHA256}(K, \text{hash}_{n-1} \parallel \text{canonical\_event}_n)$$
Verification via `GET /api/admin/audit/verify` recomputes the entire chain from genesis to head. Tested with 12+ live logged actions; verification returned `valid: true`.

### C. Information Leakage & Error Handling
Error responses across all endpoints adhere to the format:
```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable, non-revealing explanation."
  }
}
```
Stack traces and internal database schemas are never returned to clients.
