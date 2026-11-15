# PhishLens — Explainable Phishing Page Classifier

Information Security course project · Class 1, Group 01 · [Final report (PDF)](docs/report/PhishLens_Final_Report.pdf)

PhishLens scores **saved web pages** for phishing using URL, DOM, text and visual-risk features,
combines 26 named rules with a random-forest classifier, and **explains every decision**:
which rules fired (with the evidence from the page) and exactly how much each feature pushed the model.
Pages are only parsed — never rendered, executed or fetched.

| Member | Roll no. |
|---|---|
| Abdul Hadi | 23L-0923 |
| Anas Naveed | 23L-0764 |
| Mohib Ali | 23L-0763 |
| Abbas Haider | 23L-0525 |

## Results on real phishing data

600 held-out real pages from the PhreshPhish 2025 research dataset (never used for any tuning):

| | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| PhishLens — flag for review (suspicious + phishing) | 0.936 | 0.883 | **0.909** | 6.0% |
| PhishLens — high-confidence phishing only | **0.976** | 0.807 | 0.883 | **2.0%** |
| Rules alone | 0.883 | 0.327 | 0.477 | 4.3% |

Mean decision latency 91.56 ms · 65/65 automated tests passing.
Details, charts and the false-positive analysis: [reports/evaluation.md](reports/evaluation.md) · [docs/test-plan.md](docs/test-plan.md).

## Quick start (VS Code, any laptop)

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate     macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

python scripts/create_user.py --demo          # creates admin / analyst / viewer, prints passwords ONCE
uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000> (API docs at `/api/docs`). The trained model is in `models/` and its calibrated
thresholds are applied automatically on first start. Run the tests with `pytest -q`.

## Demo (10–15 min)

A captioned recording of the whole scenario is produced by `python scripts/record_demo.py ...`
(see [docs/demo/phishlens_demo.mp4](docs/demo/phishlens_demo.mp4)). To present it live:

1. **analyst** → Analyze `fixtures/tests/benign_bank_portal.html`, URL `https://www.hbl.com/ib/login` → *benign*, no rule fired.
2. Analyze `fixtures/tests/phish_brand_clone.html`, URL `http://paypal-secure-verify.tk/webscr/signin` → *phishing*
   with specific indicators (password form posting elsewhere, brand impersonation, hot-linked PayPal logo, …).
3. Upload a `.exe` → rejected and logged. Upload the phishing page again → duplicate detected.
4. **History** → tick both results → **Compare selected**. Export a sanitized JSON/CSV report.
5. **viewer** → restricted view only; admin pages and raw samples → generic denial, logged.
6. **admin** → Config → untick **R06** (the rule coverage report shows it fires more on benign pages) with a reason →
   re-analyze the phishing page → the result records config v2 and R06 as disabled.
7. Admin → Audit log → **Verify hash chain**. Restart the server → data and chain survive.

## Reproduce the evaluation

```bash
pip install datasets
python scripts/fetch_phreshphish.py --per-class 1000                       # 2,000 real pages (~74 MB)
python scripts/evaluate.py --data phreshphish_sample --drop-size-features  # metrics, charts, model
```
Without downloading the pages, `python scripts/train_from_features.py` rebuilds the shipped model from
`reports/features.csv` and checks it against the recorded test predictions.

## Architecture

```
frontend/   browser UI: dashboard, analyze, explainable result, history/compare, dataset import, admin
app/        API: auth (Argon2id), sessions, CSRF, RBAC, rate limits, safe errors, audit log (FastAPI + SQLite)
engine/     security engine: validation, features, rules, ML model with exact explanations, decision pipeline
scripts/    dataset fetch, evaluation, model rebuild, demo recording, packaging
reports/    evaluation output on real data (metrics, charts, errors, feature matrix)
docs/       report, architecture + DFD, threat model, test plan, user guide, dataset, limitations & ethics
```

More: [architecture](docs/architecture.md) · [threat model](docs/threat-model.md) · [user & admin guide](docs/user-guide.md) ·
[dataset](docs/dataset.md) · [limitations & ethics](docs/limitations-ethics.md)

## Roles

| Permission | viewer | analyst | admin |
|---|:-:|:-:|:-:|
| Dashboard, results (restricted for viewer) | ✓ | ✓ | ✓ |
| Upload / import / label / analyze, feedback, export | | ✓ | ✓ |
| Config, users, audit log, model reload | | | ✓ |

All checks are enforced on the server (`app/security/deps.py`).
