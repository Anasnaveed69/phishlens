# User & administrator guide

## Analyst
1. **Analyze** → choose a saved `.html`/`.htm` page (max 2 MB). Optionally add the page's original URL
   (only used for URL features — it is never visited) and a ground-truth label.
2. The result page shows the **decision**, risk score against the thresholds, the **rules that fired**
   with evidence, and the **model explanation** (red bars push towards phishing, green towards benign).
3. Use **Feedback** to mark the decision correct / false positive / false negative.
4. **Export JSON/CSV** for a sanitized report (no page content). **History** lists all runs with filters.
5. **Dataset** imports a `.zip` of pages plus `labels.csv` (`filename,label,source_url`).

## Viewer
Read-only, restricted view: decision, score, recommended action and reasons. No evidence, URLs or uploads.

## Administrator
* **Config** — thresholds, ML weight and enabled rules. Every save needs a reason and a confirmation,
  creates a new config version, and is written to the audit log. Re-analyze a sample to see the effect.
* **Users** — create users (10+ character passwords), disable/enable users (their sessions end immediately).
* **Audit log** — every login, denial, upload, decision, export and config change. **Verify hash chain**
  checks that no record was altered.
* **Model** — version, training metrics and integrity status; reload after retraining.

## Retraining
```bash
python scripts/train_model.py --data path/to/approved_dataset   # folder with pages + labels.csv
```
Then Admin → Model → *Reload model from disk*.

## Recovery
* Restarting the server is safe: the DB, sessions, config versions and audit chain persist in `data/`.
* Backup: stop the server and copy the `data/` folder and `models/`. Restore by copying them back.
* If the model file is missing or fails its integrity check, the app keeps working in rules-only mode.
* Lost admin password: `python scripts/create_user.py newadmin --role admin` from the server machine.
