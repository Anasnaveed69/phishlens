# Test plan

Automated tests: `pytest -q` (43 tests at the starter stage, all passing).
Acceptance: ≥ 80% automated tests passing and no open critical authorization, injection,
secret-exposure or unsafe-file-handling defects.

## Mandatory evaluation cases

Fill the results tables with real numbers once the approved dataset is in (owner: B + D).

| ID | Goal | How | Status |
|---|---|---|---|
| T1 | Precision | `scripts/evaluate.py` on held-out approved dataset | TODO |
| T2 | Recall | same run | TODO |
| T3 | F1 score | same run | TODO |
| T4 | False-positive analysis | list every FP, which rules/features caused it, fix or justify | TODO (example below) |
| T5 | Benign pages + approved archived samples | import dataset zip, analyze all, export history CSV | TODO |
| T-final | Malformed/oversized input, unauthorized request, repeated submission, safe failure, restart recovery | `tests/test_api.py` | ✅ automated |

### Baseline numbers (synthetic data — NOT the final evaluation)

The synthetic generator is easy to separate, so the model scores 1.0 on its own held-out split.
This only proves the pipeline works; real numbers must come from the approved dataset.

### T4 example — a real false positive found during development

| Input | Expected | Actual | Evidence | Result |
|---|---|---|---|---|
| `fixtures/tests/edge_brand_mention_article.html` (security blog that mentions PayPal/Amazon) — rules only | benign | **suspicious** (0.50) | R04 "Brand impersonation" fired: brand named, page not on brand domain, but there is no form or credential request | FP → candidate fix: require a form or credential terms for R04. With ML enabled the final score is 0.21 → benign |

## Results log template

| ID | Input | Expected | Actual | Evidence (screenshot/log/test) | Pass/Fail |
|---|---|---|---|---|---|
| T-final.1 | `x.exe` upload | 415 UNSUPPORTED_TYPE, logged | 415, `sample.upload` failure event | `test_malformed_and_oversized_input_rejected` | Pass |
| T-final.2 | 300 KB page with 200 KB limit | 413 FILE_TOO_LARGE | 413 | same test | Pass |
| T-final.3 | viewer uploads | generic 403, `authz.denied` logged | 403 + event | `test_viewer_cannot_upload_and_is_logged` | Pass |
| T-final.4 | same page twice | duplicate detected, new analysis | `duplicate: true`, same sample id | `test_full_workflow_and_repeated_submission` | Pass |
| T-final.5 | model missing | rules-only mode, no crash | `mode: rules_only` | `test_rules_only_mode_when_no_model` | Pass |
| T-final.6 | restart on same DB | data + audit chain intact | valid chain | `test_recovery_after_restart` | Pass |
