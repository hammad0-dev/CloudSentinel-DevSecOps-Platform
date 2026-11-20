# ml-dast leave-one-app-out (main evaluation): v2 features and data

Data v2, labels v2. Rows: 3900. Test folds (each app group unseen once): juice-shop, labexpress, labfastapi, labflask, nodegoat, vulpy. DVNA is not part of this table.
Endpoint-param level (headline): a parameter is flagged for a class if any of its rows of that payload class passes the threshold.

## all (78 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.877 [0.799, 0.938] | 0.69/1.00/0.82 (18) [0.65, 0.93] | 0.89/1.00/0.94 (17) [0.85, 1.00] | 0.87 (43) | 0.78/1.00 | 0.819 |
| rf | 0.933 [0.868, 0.984] | 0.94/0.89/0.91 (18) [0.80, 1.00] | 0.94/0.94/0.94 (17) [0.84, 1.00] | 0.94 (43) | 0.94/0.91 | 0.676 |
| lgbm | 0.900 [0.831, 0.965] | 0.74/0.94/0.83 (18) [0.68, 0.95] | 0.94/1.00/0.97 (17) [0.90, 1.00] | 0.90 (43) | 0.83/0.97 | 0.752 |

- lr - rf: -0.056 [-0.144, +0.026]
- lr - lgbm: -0.024 [-0.106, +0.056]
- rf - lgbm: +0.032 [-0.041, +0.106]

## own (53 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.818 [0.679, 0.913] | 0.60/1.00/0.75 (12) [0.55, 0.90] | 0.78/1.00/0.88 (7) [0.60, 1.00] | 0.83 (34) | 0.66/1.00 | 0.776 |
| rf | 0.935 [0.833, 1.000] | 0.92/0.92/0.92 (12) [0.78, 1.00] | 0.88/1.00/0.93 (7) [0.70, 1.00] | 0.96 (34) | 0.90/0.95 | 0.760 |
| lgbm | 0.901 [0.794, 0.979] | 0.79/0.92/0.85 (12) [0.67, 0.97] | 0.88/1.00/0.93 (7) [0.70, 1.00] | 0.92 (34) | 0.82/0.95 | 0.771 |

- lr - rf: -0.121 [-0.240, -0.014]
- lr - lgbm: -0.085 [-0.190, +0.012]
- rf - lgbm: +0.036 [-0.032, +0.111]

## third-party (25 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 1.000 [1.000, 1.000] | 1.00/1.00/1.00 (6) [1.00, 1.00] | 1.00/1.00/1.00 (10) [1.00, 1.00] | 1.00 (9) | 1.00/1.00 | 0.888 |
| rf | 0.919 [0.779, 1.000] | 1.00/0.83/0.91 (6) [0.67, 1.00] | 1.00/0.90/0.95 (10) [0.80, 1.00] | 0.90 (9) | 1.00/0.88 | 0.580 |
| lgbm | 0.867 [0.698, 1.000] | 0.67/1.00/0.80 (6) [0.50, 1.00] | 1.00/1.00/1.00 (10) [1.00, 1.00] | 0.80 (9) | 0.84/1.00 | 0.703 |

- lr - rf: +0.085 [+0.000, +0.221]
- lr - lgbm: +0.141 [+0.000, +0.302]
- rf - lgbm: +0.056 [-0.129, +0.261]

## Per fold (endpoint-param macro-F1)

| Test app | lr | rf | lgbm |
|---|---|---|---|
| juice-shop | 1.000 (t=0.9, all) | 0.733 (t=0.7, no_loc) | 1.000 (t=0.9, all) |
| labexpress | 0.784 (t=0.85, all) | 1.000 (t=0.7, no_loc) | 0.948 (t=0.9, no_loc) |
| labfastapi | 0.937 (t=0.9, all) | 0.930 (t=0.7, all) | 0.930 (t=0.9, no_loc) |
| labflask | 0.799 (t=0.9, no_loc) | 0.892 (t=0.7, all) | 0.849 (t=0.9, no_loc) |
| nodegoat | 1.000 (t=0.9, all) | 0.902 (t=0.7, all) | 0.500 (t=0.9, all) |
| vulpy | 1.000 (t=0.9, all) | 1.000 (t=0.75, all) | 1.000 (t=0.9, all) |
