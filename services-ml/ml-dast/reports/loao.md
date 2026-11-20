# ml-dast leave-one-app-out (main evaluation)

Rows: 3432. Test folds (each app group unseen once): juice-shop, labexpress, labfastapi, labflask, nodegoat, vulpy. DVNA is not part of this table.
Endpoint-param level (headline): a parameter is flagged for a class if any of its rows of that payload class passes the threshold.

## all (78 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) | XSS P/R/F1 (n) | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.871 [0.790, 0.945] | 0.84/0.89/0.86 (18) | 0.85/0.89/0.87 (19) | 0.88 (41) | 0.85/0.89 | 0.801 |
| rf | 0.643 [0.524, 0.747] | 0.74/0.78/0.76 (18) | 0.54/0.37/0.44 (19) | 0.74 (41) | 0.72/0.62 | 0.582 |
| lgbm | 0.774 [0.672, 0.862] | 0.57/0.94/0.71 (18) | 0.81/0.89/0.85 (19) | 0.76 (41) | 0.71/0.97 | 0.739 |

- lr - rf: +0.230 [+0.111, +0.354]
- lr - lgbm: +0.098 [+0.016, +0.179]
- rf - lgbm: -0.133 [-0.256, -0.008]

## own (53 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) | XSS P/R/F1 (n) | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.833 [0.695, 0.926] | 0.77/0.83/0.80 (12) | 0.70/1.00/0.82 (7) | 0.87 (34) | 0.74/0.89 | 0.757 |
| rf | 0.788 [0.643, 0.891] | 0.82/0.75/0.78 (12) | 0.58/1.00/0.74 (7) | 0.84 (34) | 0.70/0.84 | 0.760 |
| lgbm | 0.724 [0.579, 0.835] | 0.52/0.92/0.67 (12) | 0.64/1.00/0.78 (7) | 0.73 (34) | 0.56/0.95 | 0.761 |

- lr - rf: +0.045 [-0.084, +0.182]
- lr - lgbm: +0.109 [+0.012, +0.215]
- rf - lgbm: +0.064 [-0.067, +0.202]

## third-party (25 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) | XSS P/R/F1 (n) | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.928 [0.811, 1.000] | 1.00/1.00/1.00 (6) | 1.00/0.83/0.91 (12) | 0.88 (7) | 1.00/0.89 | 0.884 |
| rf | 0.383 [0.239, 0.505] | 0.62/0.83/0.71 (6) | 0.00/0.00/0.00 (12) | 0.43 (7) | 0.78/0.39 | 0.365 |
| lgbm | 0.877 [0.713, 1.000] | 0.67/1.00/0.80 (6) | 1.00/0.83/0.91 (12) | 0.92 (7) | 0.95/1.00 | 0.689 |

- lr - rf: +0.551 [+0.430, +0.696]
- lr - lgbm: +0.057 [-0.033, +0.196]
- rf - lgbm: -0.494 [-0.620, -0.384]

## Per fold (endpoint-param macro-F1)

| Test app | lr | rf | lgbm |
|---|---|---|---|
| juice-shop | 1.000 (t=0.9) | 0.733 (t=0.75) | 1.000 (t=0.9) |
| labexpress | 0.845 (t=0.9) | 0.722 (t=0.8) | 0.903 (t=0.9) |
| labfastapi | 0.838 (t=0.85) | 0.694 (t=0.7) | 0.711 (t=0.9) |
| labflask | 0.843 (t=0.9) | 0.892 (t=0.75) | 0.603 (t=0.65) |
| nodegoat | 0.705 (t=0.9) | 0.000 (t=0.8) | 0.455 (t=0.9) |
| vulpy | 1.000 (t=0.9) | 0.929 (t=0.7) | 1.000 (t=0.9) |
