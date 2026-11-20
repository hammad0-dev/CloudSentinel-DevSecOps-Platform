# ml-dast leave-one-app-out (main evaluation): v2 features and data

Data v2, labels v2. Rows: 5468. Test folds (each app group unseen once): juice-shop, labexpress, labfastapi, labflask, nodegoat, vulnerable-node, vulpy. DVNA is not part of this table.
Endpoint-param level (headline): a parameter is flagged for a class if any of its rows of that payload class passes the threshold.

## all (111 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.827 [0.744, 0.894] | 0.85/0.96/0.90 (23) [0.80, 0.98] | 0.71/0.71/0.71 (21) [0.54, 0.85] | 0.87 (67) | 0.79/0.84 | 0.685 |
| rf | 0.696 [0.592, 0.778] | 0.69/0.87/0.77 (23) [0.62, 0.88] | 0.58/0.52/0.55 (21) [0.34, 0.72] | 0.77 (67) | 0.65/0.70 | 0.646 |
| lgbm | 0.731 [0.633, 0.810] | 0.71/0.96/0.81 (23) [0.68, 0.92] | 0.65/0.52/0.58 (21) [0.37, 0.75] | 0.80 (67) | 0.69/0.75 | 0.655 |

- lr - rf: +0.131 [+0.050, +0.214]
- lr - lgbm: +0.097 [+0.027, +0.176]
- rf - lgbm: -0.034 [-0.108, +0.034]

## own (73 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.871 [0.767, 0.945] | 0.76/1.00/0.87 (13) [0.70, 0.97] | 0.71/1.00/0.83 (10) [0.60, 0.97] | 0.91 (50) | 0.74/1.00 | 0.734 |
| rf | 0.787 [0.661, 0.884] | 0.63/0.92/0.75 (13) [0.56, 0.90] | 0.62/1.00/0.77 (10) [0.53, 0.93] | 0.84 (50) | 0.63/0.96 | 0.705 |
| lgbm | 0.845 [0.735, 0.930] | 0.68/1.00/0.81 (13) [0.62, 0.94] | 0.71/1.00/0.83 (10) [0.63, 0.96] | 0.89 (50) | 0.70/1.00 | 0.750 |

- lr - rf: +0.084 [-0.017, +0.187]
- lr - lgbm: +0.026 [-0.042, +0.095]
- rf - lgbm: -0.058 [-0.171, +0.048]

## third-party (38 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.757 [0.609, 0.884] | 1.00/0.90/0.95 (10) [0.80, 1.00] | 0.71/0.45/0.56 (11) [0.20, 0.80] | 0.77 (17) | 0.88/0.67 | 0.620 |
| rf | 0.521 [0.382, 0.647] | 0.80/0.80/0.80 (10) [0.55, 0.96] | 0.33/0.09/0.14 (11) [0.00, 0.42] | 0.62 (17) | 0.69/0.43 | 0.524 |
| lgbm | 0.520 [0.393, 0.656] | 0.75/0.90/0.82 (10) [0.59, 0.96] | 0.33/0.09/0.14 (11) [0.00, 0.42] | 0.60 (17) | 0.67/0.48 | 0.511 |

- lr - rf: +0.237 [+0.105, +0.383]
- lr - lgbm: +0.235 [+0.073, +0.391]
- rf - lgbm: -0.002 [-0.127, +0.113]

## Per fold (endpoint-param macro-F1)

| Test app | lr | rf | lgbm |
|---|---|---|---|
| juice-shop | 1.000 (t=0.9, no_loc) | 1.000 (t=0.55, no_loc) | 1.000 (t=0.9, no_loc) |
| labexpress | 0.953 (t=0.9, no_loc) | 0.734 (t=0.6, no_loc) | 0.953 (t=0.9, all) |
| labfastapi | 0.937 (t=0.9, no_loc) | 0.775 (t=0.65, no_loc) | 1.000 (t=0.85, all) |
| labflask | 0.780 (t=0.9, no_loc) | 0.845 (t=0.65, no_loc) | 0.692 (t=0.65, all) |
| nodegoat | 0.571 (t=0.9, no_loc) | 0.222 (t=0.75, no_loc) | 0.222 (t=0.9, no_loc) |
| vulnerable-node | 0.695 (t=0.9, no_loc) | 0.467 (t=0.65, no_loc) | 0.617 (t=0.9, all) |
| vulpy | 1.000 (t=0.9, no_loc) | 1.000 (t=0.7, no_loc) | 0.733 (t=0.85, no_loc) |
