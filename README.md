# PhishLens — Explainable Phishing Page Classifier

Information Security course project · Class 1, Group 01

PhishLens scores **saved or locally hosted web pages** using URL, DOM, text and visual-risk
features, combines a baseline rule engine with an ML classifier, and **explains every
decision** (which rules fired, with evidence, and which features pushed the model).
Pages are only parsed: they are never rendered, executed, or fetched.

| Member | Roll no. |
|---|---|
| Abdul Hadi | 23L-0923 |
| Anas Naveed | 23L-0764 |
| Mohib Ali | 23L-0763 |
| Abbas Haider | 23L-0525 |

## Quick start (VS Code, any laptop)

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate     macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

python scripts/generate_synthetic.py          # safe sample dataset -> fixtures/synthetic/
python scripts/train_model.py                 # trains models/model.joblib (+ .meta.json)
python scripts/create_user.py --demo          # creates admin / analyst / viewer, prints passwords ONCE

uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. API docs: <http://127.0.0.1:8000/api/docs>.
Run the tests with `pytest -q`.

> Without a trained model the app still works in **rules-only** mode (shown in the UI).

## Demo script (10–15 min)

1. Sign in as **analyst** → upload `fixtures/tests/benign_bank_login.html` with URL
   `https://www.hbl.com/login` → *benign*, no critical warning.
2. Upload `fixtures/tests/phish_brand_clone.html` with URL `http://paypal-secure-verify.tk/webscr/signin`
   → *phishing*, with specific indicators (R03 external password form, R04 brand impersonation, ...).
3. Upload a `.exe` or a >2 MB file → rejected with a clear error, logged.
4. Upload the same page again → recognised as a duplicate, fresh analysis on the stored copy.
5. Compare both results in **History**, give feedback, **Export** a sanitized JSON/CSV report.
6. Sign in as **viewer** → restricted view only; try to upload via API → generic 403, logged.
7. Sign in as **admin** → change a threshold / disable a rule (with reason + confirmation)
   → re-analyze a page → the result shows the new config version; the audit log shows the change.
8. Admin → Audit log → **Verify hash chain**. Restart the server → data and chain survive.

## Architecture (layered)

```
frontend/   browser UI (validated input, explainable output; textContent only, strict CSP)
app/        API layer: auth, sessions, CSRF, RBAC, rate limits, safe errors (FastAPI)
engine/     security engine: validation, feature extraction, rules, ML model, pipeline
app/db.py   repository: SQLite, parameterized queries, append-only hash-chained audit log
fixtures/   safe test inputs (hand-written) + synthetic dataset generator
```

More: [docs/architecture.md](docs/architecture.md) · [docs/threat-model.md](docs/threat-model.md) ·
[docs/test-plan.md](docs/test-plan.md) · [docs/user-guide.md](docs/user-guide.md) ·
[docs/limitations-ethics.md](docs/limitations-ethics.md) · [docs/dataset.md](docs/dataset.md)

## Roles

| Permission | viewer | analyst | admin |
|---|:-:|:-:|:-:|
| View results (restricted for viewer) | ✓ | ✓ | ✓ |
| Upload / import / label / analyze | | ✓ | ✓ |
| Feedback, export reports | | ✓ | ✓ |
| Config, users, audit log, model reload | | | ✓ |

All checks are enforced on the server (`app/security/deps.py`).
