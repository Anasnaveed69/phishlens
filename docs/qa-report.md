# PhishLens — QA audit and test report

| | |
|---|---|
| **Scope** | Whole system: API, security engine, browser UI, documentation, deployment steps, CI |
| **Version tested** | `main` before this audit (`2b18e11`) → fixes in the commit that adds this report |
| **Date** | 26 November 2026 |
| **Environment** | Linux, Python 3.13 (CI: 3.11, 3.12, 3.13), Chromium 153 (Playwright), scikit-learn 1.6.1 |
| **Verdict** | All functional requirements work as documented. 15 findings: none critical, **8 medium, 5 low, 2 informational — all fixed and covered by tests**. |

## 1. Summary

| Area | Before audit | After audit |
|---|---|---|
| Automated tests | 71 (unit, API, security) | **222**: 196 unit/API/security/fuzz + 26 browser end-to-end |
| Line + branch coverage (`app`, `engine`) | 87% (admin 67%, samples 69%) | **92.6%**, enforced ≥ 90% in CI |
| Lint (ruff) / security scan (bandit) | 39 findings / 2 findings | **0 / 0** (one verified false positive annotated) |
| Known-vulnerable dependencies (pip-audit) | 0 | 0 |
| Accessibility (axe, WCAG 2 AA, 6 screens) | contrast, labels, headings failing | **0 serious/critical violations** |
| Phone layout (375 px) | 75–346 px sideways scroll | **no horizontal scroll** |
| Read latency, 20 concurrent users (p95) | 1,152–1,243 ms | **41–63 ms** |
| Worst request under load | 5.4 s | **2.3 s** |
| Errors under load / audit chain after load | 0 / valid | 0 / valid |
| CI | 1 job (tests) | 3 jobs: lint + security + dependency audit, tests ×3 Python versions with coverage floor, browser E2E + accessibility |

## 2. Method

1. **Static analysis** — `ruff` (pyflakes, bugbear, bandit rules, pyupgrade), `bandit`, `pip-audit`, `pytest-cov` with branch coverage.
2. **Clean install** — fresh `git clone` from GitHub, new virtualenv, README quick start followed literally.
3. **Browser end-to-end** (`tests/e2e/test_ui_e2e.py`, Playwright/Chromium) — every screen for every role, failing
   the test on any JavaScript error or unexpected `alert()`; axe-core accessibility scan; 375 px phone viewport.
4. **Authorization matrix** (`tests/test_authz_matrix.py`) — every API route discovered from the app × admin /
   analyst / viewer / anonymous, compared with the documented role table; CSRF on every state-changing route.
5. **Property-based fuzzing** (`tests/test_fuzz.py`, Hypothesis) — ~1,500 generated HTML documents, URLs, byte
   strings and zip archives against the parser and validators.
6. **Load and concurrency** (`scripts/load_test.py`) — 20 concurrent analysts for 30 s on a real server
   (upload + analyze, history, detail, export), then audit-chain verification.
7. **Documentation traceability** — every claim in README, architecture, user guide, threat model and test plan
   and every requirement of the project brief checked against code and tests (section 5).

## 3. Findings

Severity: **High** = wrong result or data loss in normal use; **Medium** = requirement gap, degraded behaviour or
operational risk; **Low** = quality, accessibility or hardening; **Info** = documentation.

| ID | Sev. | Area | Finding | Fix | Evidence (test) |
|---|---|---|---|---|---|
| F1 | Medium | UI | Dataset-import summary and Admin → Model details rendered as `[object HTMLElement]` (the element helper only flattened one level of nesting). | `h()` flattens children fully. | `test_dataset_import_via_ui`, `test_admin_model_tab_shows_loaded_model` |
| F2 | Medium | UI | Race in client routing: a slow earlier request could overwrite a newer screen (history filter showed stale rows). | Navigation token; superseded renders are dropped. | `test_history_filter_search_and_compare` |
| F3 | Medium | Performance | Every request, including page views and the per-request session check, took the database write lock; reads queued behind uploads (p95 ≈ 1.2 s at 20 users). | Read-only deferred transactions (`db.read_conn`) for reads and session checks. | load test: read p95 41–63 ms |
| F4 | Medium | Performance | SQLite's busy back-off starved some writers (worst request 5.4 s). | Fair in-process write queue before `BEGIN IMMEDIATE`; analysis kept inside it (A/B-tested: best throughput and tail under the GIL). | load test: worst 2.3 s, 0 errors |
| F5 | Medium | Brief: "high-impact actions require confirmation" | Disabling a user, changing a role and reloading the model were confirmed only in the browser, not by the server. | Server requires `confirm: true`; UI sends it after its dialog. | `test_user_management_rules`, `test_model_reload_requires_confirmation_and_is_audited` |
| F6 | Medium | Brief: "log … failure" | Unhandled server errors were not written to the audit log. | `system.error` audit event with reference id and exception type only. | `test_unhandled_errors_are_generic_and_audited` |
| F7 | Medium | FR-1 data minimisation | Raw uploaded pages were kept forever. | Admin purge (confirmed, audited), `PHISHLENS_RETENTION_DAYS` auto-purge, 410 `SAMPLE_PURGED` on re-analysis, automatic DB migration. | `test_purge_removes_raw_pages_but_keeps_results`, `test_old_database_is_migrated` |
| F8 | Medium | Operations | Backup instructions omitted `secrets/audit.key`; a restore without it makes every audit event fail verification. | User guide corrected. | `test_restore_without_audit_key_is_detected` |
| F9 | Low | Accessibility | Contrast 4.36:1 and 3.88:1 (AA needs 4.5:1); four config inputs without labels; no page-level heading; empty table header. | Darker text tokens, linked labels, per-screen `h1` and document title, screen-reader header text. | `test_no_serious_accessibility_violations` (6 screens) |
| F10 | Low | Responsive | Navigation and tables overflowed a 375 px screen by 75–346 px. | Wrapping navigation, scrollable table containers, small-screen layout rules. | `test_mobile_layout_has_no_horizontal_scroll` |
| F11 | Low | UX | A bad row in `labels.csv` rejected the import without saying which row. | Error names the line and file. | `test_labels_csv_error_names_the_line` |
| F12 | Low | Hardening | No COOP/CORP headers; no HSTS option; API docs always public. | COOP/CORP added; HSTS when `PHISHLENS_COOKIE_SECURE=1`; `PHISHLENS_API_DOCS=0` hides docs. | `test_extra_security_headers` |
| F13 | Low | Code quality | 39 lint findings (unused code, missing exception chaining), an `assert` guarding the feature vector in production code. | Clean ruff config; explicit `RuntimeError`; `raise … from`. | CI `quality` job |
| F14 | Info | Docs | Endpoints (`/api/analyses/meta/features`) and audit actions (`auth.password_change`, `sample.update`) undocumented; stale test counts. | Architecture, threat model (T17–T19), user guide, README synced. | this report |
| F15 | Info | Tests | Sample listing/labeling, user role changes, config validation, CSV exports and error paths untested. | 13 new API tests + matrix + fuzz + E2E. | coverage 87% → 92.6% |

### Verified with no defect found

* **Authorization**: 23 protected routes × 3 roles + anonymous (90 combinations) match the documented role table;
  no route lacks a permission check.
* **CSRF**: every state-changing route refuses requests without the session's token.
* **Robustness**: no crash in ~1,500 fuzzed inputs; every input is either rejected with a stable error code or
  produces a complete, finite feature vector and a decision.
* **XSS**: a page whose title and form contain `<img onerror>` / `<script>` payloads renders as text; no dialog fires.
* **Concurrency**: 0 errors in 2,109 requests from 20 concurrent users; audit chain valid over 1,543 events.
* **Install**: fresh clone → install (8 s) → server up with the model loaded → tests pass, on Python 3.13.

## 4. Performance (20 concurrent analysts, 30 s, single server process, 2 CPU cores)

| Request | Before: median / p95 / max (ms) | After: median / p95 / max (ms) |
|---|---|---|
| Upload + analyze | 69 / 1,292 / 4,181 | 619 / 792 / 2,258 |
| Analysis detail | 43 / 1,152 / 5,379 | 23 / 41 / 70 |
| History list | 40 / 1,243 / 3,757 | 35 / 63 / 100 |
| Export (audited write) | 44 / 1,396 / 4,153 | 572 / 708 / 864 |
| Throughput | 76 req/s | 70 req/s |

The trade-off is deliberate: uploads and exports now wait in a fair queue (higher median, much tighter tail),
reads no longer wait at all, and nobody waits seconds behind a starved lock. Throughput is CPU-bound (parsing +
random forest under Python's GIL); a variant computing outside the lock was measured at 56 req/s and rejected.

## 5. Requirements traceability (project brief)

| Requirement | Status | Where |
|---|---|---|
| FR-1 Dataset import and labelling | Met | `samples.py`, `validation.py`; retention added (F7) |
| FR-2 Safe HTML/URL feature extraction | Met | `features.py`; fuzzing |
| FR-3 Baseline rules | Met | `rules.py` (26 rules) |
| FR-4 ML classifier | Met | `model.py`; exact explanations tested |
| FR-5 Explanation panel | Met | result view; E2E |
| FR-6 Feedback and export | Met | `analyses.py`; E2E downloads |
| Five-layer architecture | Met | `docs/architecture.md` |
| Stable error codes, no stack traces | Met | `errors.py`; F6 |
| Server-side validation, server IDs, parameterised SQL, CSRF | Met | matrix + fuzz tests |
| Dashboard: status, severity/confidence, evidence, action, history, filters | Met | dashboard, result, history views |
| High-impact actions authorised **and confirmed** | Met (after F5) | server-side `confirm` |
| Logging incl. failures; redaction | Met (after F6) | `audit.py` |
| Least privilege, hashing, expiry, rate limits, secrets, safe errors, recovery | Met | threat model; user guide (F8) |
| DFD + ≥ 8 threats | Met | 19 threats |
| T1–T5, T-final | Met | `docs/test-plan.md`, fresh holdout |
| ≥ 80% tests passing, no open critical defects | Met | 222/222 passing |
| Deliverables (guide, data, diagrams, threat model, tests, guides, ethics, report, demo) | Met | `docs/`, `reports/` |

## 6. Recommendations (not done in this audit)

| Priority | Recommendation | Why |
|---|---|---|
| 1 | Each team member commits their own work from `TASKS.md` before submission | Commits are graded per member; all commits so far are from one account |
| 2 | Confirm with the instructor that PhreshPhish counts as approved archived samples | T5 wording in the brief |
| 3 | Forced password change on first login (open item in `TASKS.md`) | Demo passwords are printed to the console once |
| 4 | Retrain periodically with analyst feedback and a recent holdout | Phishing infrastructure changes quickly; the model is from Nov 2026 data |
| 5 | Add a visual similarity signal (logo/screenshot hashing) | Biggest remaining false negatives are brand clones on ordinary domains |
| 6 | Redis-backed rate limits and lock for multi-worker deployments; TLS reverse proxy | The supported setup is one local process |
| 7 | Dependency lockfile (e.g. pip-tools) | Fully reproducible installs beyond the pinned scikit-learn |
| 8 | Idle session timeout in addition to the 30-minute absolute expiry | Usability for long analyst sessions |

## 7. How to reproduce

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m playwright install chromium
ruff check . && bandit -q -r app engine && pip-audit -r requirements.txt
pytest -q --cov=app --cov=engine --cov-branch          # 222 tests incl. browser E2E
# load test (separate terminal: PHISHLENS_ANALYZE_RATE=100000 uvicorn app.main:app)
python scripts/load_test.py --password <analyst> --admin-password <admin> --workers 20 --seconds 30
```
