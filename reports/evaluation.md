# Evaluation report — PhreshPhish-2000

Generated 2026-11-15T12:34:03+00:00 · features `features-2.2` · rules `rules-2.1` · served model `rf-20261115123403`

Dataset: **2000 pages** (1000 phishing, 1000 benign); stratified split 1400 train / 600 test (seed 42).

## T1–T3: precision, recall, F1 (held-out test set)

| Method | Precision | Recall | F1 | Accuracy | FPR | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|---|
| rules_only@0.40 | 0.883 | 0.327 | 0.477 | 0.642 | 0.043 | 0.810 | 98 | 13 | 202 | 287 |
| logistic_regression@0.5 | 0.943 | 0.823 | 0.879 | 0.887 | 0.050 | 0.937 | 247 | 15 | 53 | 285 |
| random_forest@0.5 | 0.920 | 0.877 | 0.898 | 0.900 | 0.077 | 0.972 | 263 | 23 | 37 | 277 |
| hybrid_untuned@0.40 (LR, w=0.6) | 0.952 | 0.797 | 0.868 | 0.878 | 0.040 | 0.943 | 239 | 12 | 61 | 288 |
| served@suspicious | 0.936 | 0.883 | 0.909 | 0.912 | 0.060 | 0.974 | 265 | 18 | 35 | 282 |
| served@phishing | 0.976 | 0.807 | 0.883 | 0.893 | 0.020 | 0.974 | 242 | 6 | 58 | 294 |

**Served configuration** (chosen by 5-fold cross-validation on the training split only — the test split was not used for any choice): model `random_forest` (logistic_regression: OOF F1 0.8996, AUC 0.9654, random_forest: OOF F1 0.9328, AUC 0.9793); score = 0.8 × ML + 0.2 × rules; suspicious ≥ 0.42, phishing ≥ 0.54 (phishing threshold set for ≤ 2% false positives on training folds).

`served@suspicious` = page flagged as suspicious or phishing (the analyst queue); `served@phishing` = high-confidence phishing only. `hybrid_untuned` = the hand-set starter config (LR, weight 0.6, threshold 0.4) for comparison. FPR = false-positive rate on benign pages.

![ROC and PR curves](roc_pr.png)

![Confusion matrix](confusion_matrix.png)

## T4: false-positive analysis

Served configuration at the suspicious threshold: **18 false positives**, **35 false negatives** on the test set. Every error is listed in `errors.csv` with the rules that fired and the model's top contributing features.

Rules present in false positives: R05 ×2, R15 ×2, R21 ×1, R26 ×1, R20 ×1, R11 ×1, R13 ×1, R09 ×1

## Rule coverage (whole dataset)

| Rule | Weight | Fires on phishing | Fires on benign | Precision |
|---|---|---|---|---|
| R01 IP address used as host | 0.45 | 0.0% | 0.0% | — |
| R02 '@' symbol in URL | 0.35 | 1.6% | 0.5% | 0.762 |
| R03 Password form posts to another domain | 0.6 | 1.5% | 0.3% | 0.833 |
| R04 Brand impersonation | 0.5 | 20.4% | 0.8% | 0.962 |
| R05 Credential request with urgency language | 0.4 | 9.5% | 3.4% | 0.736 |
| R06 Hidden iframe on a login page | 0.25 | 1.8% | 4.3% | 0.295 |
| R07 Obfuscated JavaScript on a login page | 0.25 | 1.1% | 0.4% | 0.733 |
| R08 Suspicious top-level domain | 0.2 | 11.9% | 0.1% | 0.992 |
| R09 Excessive subdomains | 0.2 | 1.8% | 0.9% | 0.667 |
| R10 Punycode host | 0.35 | 0.1% | 0.0% | 1.0 |
| R11 Login page without HTTPS | 0.25 | 1.2% | 0.4% | 0.75 |
| R12 Brand logo hot-linked from the real brand | 0.35 | 2.2% | 0.2% | 0.917 |
| R13 Brand in title but not in domain | 0.25 | 25.1% | 0.6% | 0.977 |
| R14 Meta-refresh redirect | 0.15 | 1.1% | 0.8% | 0.579 |
| R15 Mostly dead links | 0.15 | 5.8% | 1.1% | 0.841 |
| R16 Form submits to an IP address | 0.45 | 0.0% | 0.0% | — |
| R17 Embedded data: / blob: document | 0.3 | 0.8% | 1.3% | 0.381 |
| R18 Look-alike brand domain | 0.5 | 0.0% | 0.0% | — |
| R19 Brand name in an unrelated domain's subdomain | 0.45 | 4.8% | 0.0% | 1.0 |
| R20 Bare login page | 0.2 | 1.7% | 1.0% | 0.63 |
| R21 Free / anonymous hosting platform | 0.2 | 52.5% | 0.1% | 0.998 |
| R22 Link shortener or redirect service | 0.3 | 0.5% | 0.0% | 1.0 |
| R23 Brand name in an unrelated host | 0.5 | 5.3% | 0.1% | 0.981 |
| R24 Misspelled brand in host | 0.5 | 4.8% | 0.2% | 0.96 |
| R25 Wallet recovery phrase requested | 0.6 | 16.3% | 0.3% | 0.982 |
| R26 Login page on free hosting | 0.4 | 27.6% | 0.1% | 0.996 |

![Rule coverage](rule_coverage.png)

## Decision latency

Full pipeline (parse → features → rules → model → decision) on 300 test pages: mean **91.56 ms**, median 60.98 ms, p95 245.04 ms, max 715.17 ms.

## Most influential features

![LR coefficients](lr_coefficients.png)

| Logistic regression | coef | Random forest | importance |
|---|---|---|---|
| free_hosting | 2.804 | path_depth | 0.1172 |
| query_length | 1.846 | free_hosting | 0.1115 |
| suspicious_tld | 1.296 | external_resource_ratio | 0.0718 |
| hidden_iframes | -1.181 | external_link_ratio | 0.0681 |
| num_subdomains | -1.166 | url_length | 0.068 |
| hyphens_in_host | 1.02 | hidden_iframes | 0.0621 |
| url_length | 0.997 | hidden_elements | 0.0513 |
| uses_https | -0.698 | host_entropy | 0.051 |
| num_forms | -0.696 | num_inputs | 0.0332 |
| title_brand_mismatch | 0.605 | num_iframes | 0.0325 |
| digits_in_host | 0.589 | query_length | 0.0304 |
| host_entropy | 0.538 | hyphens_in_host | 0.0301 |
