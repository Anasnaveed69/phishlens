# PhishLens Functional Test Report

## Overview
Comprehensive test report mapping every user journey and feature verified across Phases 3 and 4.

---

### Test Cases Summary Table

| ID | Module / Journey | Description | Steps | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|:---:|
| TC-01 | Auth | Valid Analyst Login | Post valid credentials for analyst | Auth 200, session cookie set, redirect to dashboard | Cookie set (HttpOnly, SameSite=Strict), CSRF token issued, dashboard loaded | PASS |
| TC-02 | Auth | Invalid Password | Post wrong password for analyst | Auth 401 with generic error | 401 Unauthorized, code INVALID_CREDENTIALS, no username leak | PASS |
| TC-03 | Auth | Unknown Username | Post non-existent username | Auth 401 with same error message | Identical 401 response preventing user enumeration | PASS |
| TC-04 | Auth | Empty Login Form | Post empty credentials payload | HTTP 422 Unprocessable Entity | 422 validation error returned | PASS |
| TC-05 | Auth | Session Logout | POST /api/auth/logout with session | Session invalidated in DB and cookies cleared | Session dropped; subsequent /api/auth/me returns 401 | PASS |
| TC-06 | Dashboard | Metric Counters | GET /api/dashboard as Analyst | Return totals, by_decision, by_severity, recent_high_risk | Full statistics object returned with correct status and counts | PASS |
| TC-07 | Dataset | Valid ZIP Import | Upload ZIP containing HTML pages & labels.csv | Validated, stored, and analyzed | 2 pages imported, duplicates identified, metrics updated | PASS |
| TC-08 | Dataset | Invalid Import | Upload non-zip file (e.g. .txt/.exe) | Reject with HTTP 415/422 | Rejected with UNSUPPORTED_TYPE error code | PASS |
| TC-09 | Analysis | Brand Phishing Fixture | Analyze `phish_brand_clone.html` | Verdict: phishing, score >= 0.54, rules fired | Verdict: phishing, score 0.80, fired R03, R05, R12, R23 | PASS |
| TC-10 | Analysis | Benign Bank Fixture | Analyze `benign_bank_portal.html` | Verdict: benign, low risk score | Verdict: benign, score 0.30, no critical rules fired | PASS |
| TC-11 | Analysis | IP Host Phishing | Analyze `phish_ip_host.html` | Verdict: phishing, rules R01/R20 fired | Verdict: phishing, score 0.63, fired R01, R04, R20 | PASS |
| TC-12 | Analysis | Hostile Script Inertness | Upload HTML with inline script alerts/redirects | Parsed as data, never executed | Parsed safely; zero script execution, no outgoing requests | PASS |
| TC-13 | Engine | Explainability Payload | Inspect analysis result schema | Top features, contributions, rule details present | Full explainable payload populated with SHAP feature values | PASS |
| TC-14 | Feedback | Submit Analyst Feedback | POST /api/analyses/{id}/feedback | Stored in database linked to analysis | Feedback saved as `correct`, recorded in DB & analysis view | PASS |
| TC-15 | History | Filter by Decision | GET /api/analyses?decision=phishing | Return only phishing items | Filtered list containing exclusively phishing verdicts | PASS |
| TC-16 | Reports | Sanitized JSON Export | GET /api/analyses/{id}/export?format=json | JSON with findings, no raw HTML | Clean JSON exported without leaking uploaded HTML bytes | PASS |
| TC-17 | Reports | Sanitized CSV Export | GET /api/analyses/{id}/export?format=csv | Valid CSV with formula injection defense | CSV generated with headers, sensitive formula chars escaped | PASS |
| TC-18 | Admin | Update Config & Thresholds | PUT /api/admin/config with confirmation | Version incremented, audit logged | Config saved as v2, new analyses reflect updated rules | PASS |
| TC-19 | Admin | Model Status & Reload | POST /api/admin/model/reload | Model integrity verified and reloaded | Model status: loaded, RF metadata verified | PASS |
| TC-20 | Admin | Audit Hash Chain | GET /api/admin/audit/verify | Cryptographic chain verification | Valid=True, intact HMAC-SHA256 chain over all events | PASS |
| TC-21 | Viewer | Restricted Projection | GET /api/analyses as Viewer | Sensitive URLs redacted, restricted_view=True | URL/filename omitted/redacted, restricted_view confirmed | PASS |
| TC-22 | Viewer | Action Denials | Attempt POST /api/samples and admin routes | HTTP 403 Forbidden | Denied with generic 403, logged to audit events | PASS |
