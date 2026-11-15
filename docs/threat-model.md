# Threat model

Method: STRIDE over the data-flow diagram in [architecture.md](architecture.md).
Assets: user credentials and sessions, uploaded pages, analysis results and labels,
configuration (thresholds/rules), the trained model file, and the audit log.

## Trust boundaries
1. **Browser ↔ API** — everything from the browser is untrusted (forms, files, headers, cookies).
2. **API ↔ security engine** — the uploaded HTML is hostile content; the engine treats it as data only.
3. **App ↔ disk** — SQLite DB, stored samples and model file; only the app process should write here.
4. **Admin ↔ configuration** — config changes alter every future decision.

## Threats and mitigations

| # | Threat (STRIDE) | Where | Mitigation in code | Test / evidence |
|---|---|---|---|---|
| T1 | **Password guessing / brute force** (S) | `/api/auth/login` | Argon2id hashes; 5 attempts/min per IP+user; same error for unknown user and wrong password; constant-ish timing with dummy hash | `test_login_rate_limited`, `test_wrong_password_generic_error` |
| T2 | **Session hijacking** (S) | cookies | Random 256-bit token, HttpOnly + SameSite=Strict cookie, only sha256 stored in DB, 30-min expiry, sessions killed on logout/role change | `test_session_cookie_flags`, `test_logout_invalidates_session` |
| T3 | **CSRF** (T) | state-changing endpoints | Per-session CSRF token required in `X-CSRF-Token` for POST/PUT/PATCH/DELETE, plus SameSite=Strict | `test_csrf_required_on_state_change` |
| T4 | **Privilege escalation / broken access control** (E) | all endpoints | Server-side RBAC (`require(permission)`), least privilege per role, viewer gets a restricted projection, denials audited with generic message | `test_viewer_cannot_upload_and_is_logged`, `test_analyst_cannot_access_admin`, `test_viewer_gets_restricted_view` |
| T5 | **Stored XSS from uploaded page content** (T/E) | evidence shown in UI | UI renders with `textContent` only (no `innerHTML`), strict CSP (`script-src 'self'`, no inline), evidence truncated | `test_security_headers`; manual XSS fixture (member D) |
| T6 | **Malicious page executes / beacons out** (I/E) | feature extraction | Pure-Python parser, no rendering, no JS engine, no network requests; declared URL is parsed, never fetched | `test_scripts_are_not_executed` |
| T7 | **Unsafe file handling: zip slip, zip bomb, huge uploads** (D/T) | upload & import | Extension + content sniffing, size cap read with `read(limit+1)`, archive read in memory only, archive paths discarded, declared and actual expanded size limits, file-count limit, server-generated storage names | `test_zip_slip_and_labels`, `test_zip_bomb_declared_size_rejected`, `test_malformed_and_oversized_input_rejected` |
| T8 | **SQL injection** (T/I) | repository | Only parameterized queries; filter column names are fixed in code; LIKE wildcards escaped | code review; search with `' OR 1=1 --` returns nothing |
| T9 | **Tampering with audit records** (R) | audit log | Append-only triggers block UPDATE/DELETE; SHA-256 hash chain detects edits to the DB file; verify endpoint | `test_audit_chain_valid_and_append_only` |
| T10 | **Tampered or swapped model file** (T/E) | `models/` | Model loaded only if SHA-256 matches metadata and feature order matches; otherwise rules-only + logged | model status in Admin → Model |
| T11 | **Sensitive data leaking into logs/reports** (I) | audit, export | Recursive redaction of secret-like keys, e-mail masking, string truncation; exports exclude raw HTML and feature dumps | `test_audit_redacts_secrets`, export test |
| T12 | **Error messages leaking internals** (I) | all | Stable error codes, generic messages, stack traces logged server-side only with a reference id | `test_errors_never_leak_internals` |
| T13 | **CSV/formula injection in exports** (T) | CSV export | Cells starting with `= + - @` are prefixed with `'` | member D test |
| T14 | **Unreviewed config change silently alters decisions** (R/T) | admin config | Versioned config with reason, explicit confirmation, audit entry with before/after, each analysis stores its config version | `test_admin_threshold_change_is_traceable` |
| T15 | **Denial of service via analysis flooding** (D) | analyze endpoints | 30 analyses/min per user, size limits | config `PHISHLENS_ANALYZE_RATE` |

## Residual risks
See [limitations-ethics.md](limitations-ethics.md): single-process rate limiter, local HTTP
(no TLS) in the demo, admin with OS access can still replace files, synthetic data bias.
