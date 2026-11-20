# ml-dast vs offline ZAP (same endpoint-param clusters)

ZAP: unmodified `zap-full-scan.py` (ZAP 2.17.0, offline image), unauthenticated, no seeds. ML: pooled leave-one-app-out predictions.

| Set | System | macro-F1 [95% CI] | SQLi TP/FP/FN | XSS TP/FP/FN |
|---|---|---|---|---|
| all | ml_lr | 0.871 [0.790, 0.945] | 16/3/2 | 17/3/2 |
| all | zap | 0.917 [0.846, 0.971] | 14/0/4 | 17/0/2 |
| all | difference ML - ZAP | -0.045 [-0.130, +0.040] | | |
| own | ml_lr | 0.833 [0.695, 0.926] | 10/3/2 | 7/3/0 |
| own | zap | 0.960 [0.890, 1.000] | 10/0/2 | 7/0/0 |
| own | difference ML - ZAP | -0.133 [-0.269, -0.018] | | |
| third-party | ml_lr | 0.928 [0.811, 1.000] | 6/0/0 | 10/0/2 |
| third-party | zap | 0.829 [0.636, 0.965] | 4/0/2 | 10/0/2 |
| third-party | difference ML - ZAP | +0.107 [+0.000, +0.258] | | |

Per app (TP/FP/FN, SQLi then XSS):

| App | ML | ZAP |
|---|---|---|
| juice-shop | 2/0/0 ; 0/0/0 | 0/0/2 ; 0/0/0 |
| labexpress | 3/2/1 ; 2/0/0 | 2/0/2 ; 2/0/0 |
| labfastapi | 3/0/1 ; 2/1/0 | 4/0/0 ; 2/0/0 |
| labflask | 4/1/0 ; 3/2/0 | 4/0/0 ; 3/0/0 |
| nodegoat | 0/0/0 ; 10/0/2 | 0/0/0 ; 10/0/2 |
| vulpy-bad | 4/0/0 ; 0/0/0 | 4/0/0 ; 0/0/0 |
| vulpy-good | 0/0/0 ; 0/0/0 | 0/0/0 ; 0/0/0 |
