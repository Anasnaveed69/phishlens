# Fresh holdout — PhreshPhish-fresh-holdout-1000

1000 pages never seen during development (500 phishing / 500 benign), scored with the frozen model `rf-20261115123403` and config {'phishing_threshold': 0.54, 'suspicious_threshold': 0.42, 'ml_weight': 0.8, 'disabled_rules': []}. Nothing was tuned on these pages.

| Band | Precision | Recall | F1 | FPR | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| served@suspicious | 0.964 | 0.904 | 0.933 | 0.034 | 0.984 | 452 | 17 | 48 | 483 |
| served@phishing | 0.998 | 0.814 | 0.896 | 0.002 | 0.984 | 407 | 1 | 93 | 499 |

Latency: mean 93.84 ms, p95 263.89 ms. Errors: 17 FP, 48 FN (holdout_errors.csv).
