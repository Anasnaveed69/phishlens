# User & administrator guide

## Everyone
* **Dashboard** (start page) — system status (model, config version), decisions, severity, most frequent
  indicators, recent phishing detections, latency and analyst feedback.
* **Account** (click your name, top right) — change your password; your other sessions are signed out.

## Analyst
1. **Analyze** → choose a saved `.html`/`.htm` page (max 2 MB). Optionally add the page's original URL
   (only used for URL features — it is never visited) and a ground-truth label.
2. The result page shows the **decision**, risk score against the thresholds, the **rules that fired**
   with evidence, and the **model explanation** (red bars push towards phishing, green towards benign).
3. Use **Feedback** to mark the decision correct / false positive / false negative.
4. **Export JSON/CSV** for a sanitized report (no page content), or **Print / save as PDF**.
   **History** lists all runs with filters; tick two rows and press **Compare selected** to see
   two results side by side, including the features that differ.
5. **Dataset** imports a `.zip` of pages plus `labels.csv` (`filename,label,source_url`).

## Viewer
Read-only, restricted view: decision, score, recommended action and reasons. No evidence, URLs or uploads.

## Administrator
* **Config** — thresholds, ML weight and enabled rules. Every save needs a reason and a confirmation,
  creates a new config version, and is written to the audit log. Re-analyze a sample to see the effect.
* **Users** — create users (10+ character passwords), disable/enable users or change roles (confirmed; the
  user's sessions end immediately so new rights apply at their next sign-in).
* **Audit log** — every login, denial, upload, decision, export and config change. **Verify hash chain**
  checks that no record was altered.
* **Model** — version, training metrics and integrity status; reload after retraining (asks for confirmation).
* **Data retention** (Model tab) — delete stored raw pages older than N days. Decisions, reasons and short
  evidence stay in history and reports; a purged page can be re-analysed only by uploading it again.
  `PHISHLENS_RETENTION_DAYS=N` in `.env` does this automatically at every start.

## Retraining and evaluation
```bash
python scripts/evaluate.py --data path/to/dataset --drop-size-features   # pages + labels.csv
```
This chooses the model by cross-validation, calibrates thresholds on the training split, scores the
held-out split once, writes `reports/` and saves the model. Then Admin → Model → *Reload model from disk*.
Without the raw pages, `python scripts/train_from_features.py` rebuilds the shipped model from
`reports/features.csv` and verifies it against the recorded predictions.

## Recovery
* Restarting the server is safe: the DB, sessions, config versions and audit chain persist in `data/`.
* Backup: stop the server and copy **`data/`, `secrets/` and `models/`** together. Restore by copying all three
  back. `secrets/audit.key` is required: without it the audit log cannot be verified after a restore
  (every event would show as tampered).
* If the model file is missing or fails its integrity check, the app keeps working in rules-only mode.
* Lost admin password: `python scripts/create_user.py newadmin --role admin` from the server machine.
