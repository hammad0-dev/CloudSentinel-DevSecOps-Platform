# ml-dast leave-one-app-out (main evaluation): v2 features (v2 system) on the enlarged v3 data

Data v3, labels v3. Rows: 9402. Test folds (each app group unseen once): dsvw, juice-shop, labexpress, labfastapi, labflask, node-api-goat, nodegoat, vampi, vulnerable-node, vulpy. DVNA is not part of this table.
Endpoint-param level (headline): a parameter is flagged for a class if any of its rows of that payload class passes the threshold.

## all (169 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.808 [0.745, 0.864] | 0.70/0.97/0.81 (34) [0.72, 0.89] | 0.65/1.00/0.79 (32) [0.68, 0.88] | 0.82 (103) | 0.68/0.98 | 0.748 |


## own (105 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.799 [0.720, 0.872] | 0.83/0.95/0.88 (20) [0.77, 0.97] | 0.52/1.00/0.68 (16) [0.51, 0.82] | 0.83 (69) | 0.65/0.97 | 0.748 |


## third-party (64 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) | vuln P/R | row macro-F1 |
|---|---|---|---|---|---|---|
| lr | 0.821 [0.719, 0.899] | 0.58/1.00/0.74 (14) [0.55, 0.87] | 0.89/1.00/0.94 (16) [0.82, 1.00] | 0.79 (34) | 0.71/1.00 | 0.735 |


## Per fold (endpoint-param macro-F1)

| Test app | lr |
|---|---|
| dsvw | 0.861 (t=0.9, no_loc) |
| juice-shop | 1.000 (t=0.9, no_loc) |
| labexpress | 0.816 (t=0.9, all) |
| labfastapi | 0.866 (t=0.9, no_loc) |
| labflask | 0.761 (t=0.9, no_loc) |
| node-api-goat | 0.700 (t=0.85, all) |
| nodegoat | 1.000 (t=0.9, all) |
| vampi | 0.333 (t=0.9, no_loc) |
| vulnerable-node | 0.761 (t=0.9, no_loc) |
| vulpy | 1.000 (t=0.9, all) |
