# ml-dast leave-one-app-out (main evaluation): v2 features and data

Data v2, labels v2. Rows: 3900. Test folds (each app group unseen once): juice-shop, labexpress, labfastapi, labflask, nodegoat, vulpy. DVNA is not part of this table.
Endpoint-param level (headline): a parameter is flagged for a class if any of its rows of that payload class passes the threshold.

## all (78 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.897 [0.824, 0.962] | 0.86/1.00/0.92 (18) [0.82, 1.00] | 0.77/1.00/0.87 (17) [0.74, 0.97] | 0.90 (43) | 0.81/1.00 | 0.824 |
| rf | 0.676 [0.565, 0.782] | 0.80/0.89/0.84 (18) [0.69, 0.95] | 0.50/0.41/0.45 (17) [0.22, 0.67] | 0.74 (43) | 0.68/0.66 | 0.611 |
| lgbm | 0.864 [0.788, 0.931] | 0.68/0.94/0.79 (18) [0.63, 0.91] | 0.89/1.00/0.94 (17) [0.84, 1.00] | 0.86 (43) | 0.77/0.97 | 0.741 |

- lr - rf: +0.223 [+0.108, +0.337]
- lr - lgbm: +0.034 [-0.061, +0.126]
- rf - lgbm: -0.189 [-0.302, -0.068]

## own (53 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.831 [0.694, 0.927] | 0.80/1.00/0.89 (12) [0.73, 1.00] | 0.58/1.00/0.74 (7) [0.43, 0.92] | 0.87 (34) | 0.70/1.00 | 0.777 |
| rf | 0.812 [0.685, 0.915] | 0.92/0.92/0.92 (12) [0.78, 1.00] | 0.50/1.00/0.67 (7) [0.36, 0.88] | 0.85 (34) | 0.69/0.95 | 0.754 |
| lgbm | 0.844 [0.711, 0.939] | 0.69/0.92/0.79 (12) [0.57, 0.93] | 0.78/1.00/0.88 (7) [0.60, 1.00] | 0.87 (34) | 0.72/0.95 | 0.752 |

- lr - rf: +0.019 [-0.079, +0.116]
- lr - lgbm: -0.011 [-0.147, +0.121]
- rf - lgbm: -0.030 [-0.166, +0.101]

## third-party (25 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 1.000 [1.000, 1.000] | 1.00/1.00/1.00 (6) [1.00, 1.00] | 1.00/1.00/1.00 (10) [1.00, 1.00] | 1.00 (9) | 1.00/1.00 | 0.896 |
| rf | 0.392 [0.244, 0.516] | 0.62/0.83/0.71 (6) [0.36, 0.92] | 0.00/0.00/0.00 (10) [0.00, 0.00] | 0.46 (9) | 0.62/0.31 | 0.394 |
| lgbm | 0.867 [0.698, 1.000] | 0.67/1.00/0.80 (6) [0.50, 1.00] | 1.00/1.00/1.00 (10) [1.00, 1.00] | 0.80 (9) | 0.84/1.00 | 0.699 |

- lr - rf: +0.615 [+0.484, +0.756]
- lr - lgbm: +0.141 [+0.000, +0.302]
- rf - lgbm: -0.474 [-0.582, -0.402]

## Per fold (endpoint-param macro-F1)

| Test app | lr | rf | lgbm |
|---|---|---|---|
| juice-shop | 1.000 (t=0.9, all) | 0.733 (t=0.7, all) | 1.000 (t=0.9, all) |
| labexpress | 0.948 (t=0.9, no_loc) | 0.859 (t=0.7, all) | 0.903 (t=0.9, all) |
| labfastapi | 0.841 (t=0.9, all) | 0.764 (t=0.7, no_loc) | 0.838 (t=0.9, all) |
| labflask | 0.763 (t=0.9, no_loc) | 0.801 (t=0.7, all) | 0.810 (t=0.85, no_loc) |
| nodegoat | 1.000 (t=0.9, all) | 0.000 (t=0.8, all) | 0.500 (t=0.9, no_loc) |
| vulpy | 1.000 (t=0.9, no_loc) | 1.000 (t=0.65, all) | 1.000 (t=0.9, all) |
