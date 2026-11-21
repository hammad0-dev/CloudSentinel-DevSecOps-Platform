# ml-dast leave-one-app-out (main evaluation): v3 features and data

Data v3, labels v3. Rows: 9402. Test folds (each app group unseen once): dsvw, juice-shop, labexpress, labfastapi, labflask, node-api-goat, nodegoat, vampi, vulnerable-node, vulpy. DVNA is not part of this table.
Endpoint-param level (headline): a parameter is flagged for a class if any of its rows of that payload class passes the threshold.

## all (169 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.863 [0.805, 0.914] | 0.84/0.91/0.87 (34) [0.78, 0.95] | 0.71/1.00/0.83 (32) [0.72, 0.91] | 0.88 (103) | 0.77/0.95 | 0.756 |
| rf | 0.813 [0.746, 0.870] | 0.74/0.76/0.75 (34) [0.62, 0.85] | 0.75/0.94/0.83 (32) [0.72, 0.92] | 0.85 (103) | 0.75/0.85 | 0.691 |
| lgbm | 0.831 [0.761, 0.890] | 0.76/0.76/0.76 (34) [0.64, 0.87] | 0.77/0.94/0.85 (32) [0.74, 0.92] | 0.88 (103) | 0.79/0.88 | 0.731 |

- lr - rf: +0.050 [-0.009, +0.115]
- lr - lgbm: +0.033 [-0.036, +0.101]
- rf - lgbm: -0.018 [-0.076, +0.042]

## own (105 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.825 [0.746, 0.896] | 0.90/0.90/0.90 (20) [0.78, 0.98] | 0.55/1.00/0.71 (16) [0.54, 0.84] | 0.86 (69) | 0.69/0.94 | 0.732 |
| rf | 0.814 [0.723, 0.887] | 0.82/0.90/0.86 (20) [0.72, 0.96] | 0.61/0.88/0.72 (16) [0.52, 0.85] | 0.87 (69) | 0.71/0.89 | 0.716 |
| lgbm | 0.868 [0.785, 0.930] | 0.90/0.90/0.90 (20) [0.79, 0.98] | 0.70/0.88/0.78 (16) [0.59, 0.90] | 0.93 (69) | 0.82/0.92 | 0.742 |

- lr - rf: +0.012 [-0.063, +0.089]
- lr - lgbm: -0.043 [-0.127, +0.045]
- rf - lgbm: -0.054 [-0.128, +0.016]

## third-party (64 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.921 [0.843, 0.982] | 0.76/0.93/0.84 (14) [0.67, 0.96] | 1.00/1.00/1.00 (16) [1.00, 1.00] | 0.92 (34) | 0.88/0.97 | 0.768 |
| rf | 0.795 [0.684, 0.890] | 0.62/0.57/0.59 (14) [0.34, 0.79] | 0.94/1.00/0.97 (16) [0.89, 1.00] | 0.82 (34) | 0.80/0.80 | 0.655 |
| lgbm | 0.762 [0.642, 0.852] | 0.57/0.57/0.57 (14) [0.30, 0.76] | 0.84/1.00/0.91 (16) [0.79, 1.00] | 0.80 (34) | 0.76/0.83 | 0.695 |

- lr - rf: +0.127 [+0.031, +0.226]
- lr - lgbm: +0.162 [+0.058, +0.278]
- rf - lgbm: +0.035 [-0.056, +0.136]

## Per fold (endpoint-param macro-F1)

| Test app | lr | rf | lgbm |
|---|---|---|---|
| dsvw | 0.780 (t=0.95, no_loc) | 0.911 (t=0.75, no_loc) | 0.911 (t=0.95, no_loc) |
| juice-shop | 1.000 (t=0.95, no_loc) | 0.762 (t=0.75, no_loc) | 0.762 (t=0.95, no_loc) |
| labexpress | 0.818 (t=0.95, no_loc) | 0.911 (t=0.8, no_loc) | 1.000 (t=0.95, no_loc) |
| labfastapi | 0.906 (t=0.95, no_loc) | 0.900 (t=0.85, no_loc) | 0.844 (t=0.95, no_loc) |
| labflask | 0.788 (t=0.95, no_loc) | 0.732 (t=0.7, no_loc) | 0.810 (t=0.95, all) |
| node-api-goat | 0.929 (t=0.95, no_loc) | 0.929 (t=0.75, no_loc) | 0.833 (t=0.95, no_loc) |
| nodegoat | 1.000 (t=0.95, no_loc) | 0.700 (t=0.8, no_loc) | 1.000 (t=0.95, no_loc) |
| vampi | 1.000 (t=0.95, no_loc) | 1.000 (t=0.75, no_loc) | 0.286 (t=0.95, all) |
| vulnerable-node | 0.937 (t=0.95, no_loc) | 0.695 (t=0.75, no_loc) | 0.694 (t=0.95, no_loc) |
| vulpy | 1.000 (t=0.95, no_loc) | 0.733 (t=0.75, no_loc) | 0.733 (t=0.95, no_loc) |
