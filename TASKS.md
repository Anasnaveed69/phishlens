# Work split

> Status: the items ticked below are implemented on `main`. Remaining items are open for the owners.

The starter (week 1–2 slice) is in place and runs end to end. Each member now **owns one
area**, works on a branch, and opens pull requests. Commits are checked per member, so:

* set `git config user.email` to the email on **your own** GitHub account before committing;
* commit small and often (one feature/fix per commit), with clear messages;
* don't push other people's work from your machine.

Write your name next to a role.

## A — Backend, data, authentication · owner: ______
- [x] Password change endpoint + forced change on first login
- [ ] Session refresh / "remember me" decision (document it either way)
- [ ] Pagination totals for `/api/analyses` and `/api/samples`
- [ ] Sample deletion for admins (soft delete, audited, confirmation)
- [ ] Backup / restore instructions for `data/` (recovery section of user guide)

## B — Security engine & evaluation · owner: ______
- [x] Get the **instructor-approved dataset** and convert it to `pages + labels.csv` (see docs/dataset.md)
- [x] `scripts/evaluate.py`: precision, recall, F1, FPR, confusion matrix, latency (T1–T4) on a held-out set
- [x] Compare LogisticRegression vs RandomForest; keep the served model explainable
- [x] False-positive analysis: list FPs, which rules caused them, tune weights (T4)
- [x] Add 3–5 more rules (e.g. look-alike characters, data: URIs, form to IP address)

## C — Frontend, reporting, integration · owner: ______
- [x] Dashboard page: counts by decision, recent high-severity results, latency stats
- [x] Side-by-side compare of two analyses (normal vs adverse sample)
- [x] Printable HTML/PDF report export
- [ ] Accessibility pass (keyboard navigation, labels, contrast) + responsive check on phone
- [ ] Screenshots for the final report

## D — Automation, security testing, packaging, QA · owner: ______
- [x] GitHub Actions workflow running `pytest` on every push
- [x] Adversarial/misuse tests: XSS payloads in uploaded pages, CSV injection, oversized zip, brute force
- [x] Fill in docs/test-plan.md results table (input, expected, actual, evidence, pass/fail)
- [x] `scripts/package.py` that builds the submission zip (no `.env`, `data/`, `.venv`)
- [ ] Demo rehearsal checklist + final QA

## Everyone
- [ ] Read the whole codebase once — everyone must be able to explain the full system in the viva
- [ ] Review at least two PRs from other members
