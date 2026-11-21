# ml-dast leave-one-app-out: the v2 system on the v4 data

Rows 13402 ({'own': 5250, 'third-party': 4152, 'benchmark': 4000}). Groups: benchmark, dsvw, juice-shop, labexpress, labfastapi, labflask, node-api-goat, nodegoat, vampi, vulnerable-node, vulpy. Feature sets: {'v2_all': 74, 'v2_no_loc': 70}. Thresholds: [np.float64(0.2), np.float64(0.25), np.float64(0.3), np.float64(0.35), np.float64(0.4), np.float64(0.45), np.float64(0.5), np.float64(0.55), np.float64(0.6), np.float64(0.65), np.float64(0.7), np.float64(0.75), np.float64(0.8), np.float64(0.85), np.float64(0.9)].
**real** = own + third-party apps (the headline). **benchmark** = BenchmarkPython, one group, in-benchmark numbers only: they say nothing about generalization to real apps.

## real (169 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) |
|---|---|---|---|---|
| lr | 0.836 [0.773, 0.891] | 0.72/0.97/0.82 (34) [0.73, 0.91] | 0.71/1.00/0.83 (32) [0.72, 0.91] | 0.85 (103) |


## own (105 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) |
|---|---|---|---|---|
| lr | 0.833 [0.754, 0.903] | 0.83/0.95/0.88 (20) [0.77, 0.97] | 0.59/1.00/0.74 (16) [0.57, 0.88] | 0.87 (69) |


## third-party (64 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) |
|---|---|---|---|---|
| lr | 0.835 [0.727, 0.911] | 0.61/1.00/0.76 (14) [0.56, 0.89] | 0.89/1.00/0.94 (16) [0.82, 1.00] | 0.81 (34) |


## benchmark (80 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) |
|---|---|---|---|---|
| lr | 0.812 [0.677, 0.938] | 0.43/1.00/0.60 (3) [0.00, 0.89] | 0.84/1.00/0.91 (21) [0.81, 0.98] | 0.92 (56) |


## Per fold

| Test group | lr |
|---|---|
| benchmark | 0.812 (t=0.9, v2_all) |
| dsvw | 0.861 (t=0.9, v2_no_loc) |
| juice-shop | 1.000 (t=0.9, v2_no_loc) |
| labexpress | 0.787 (t=0.9, v2_no_loc) |
| labfastapi | 0.866 (t=0.9, v2_no_loc) |
| labflask | 0.848 (t=0.9, v2_no_loc) |
| node-api-goat | 0.929 (t=0.9, v2_no_loc) |
| nodegoat | 1.000 (t=0.9, v2_no_loc) |
| vampi | 0.333 (t=0.9, v2_all) |
| vulnerable-node | 0.689 (t=0.85, v2_no_loc) |
| vulpy | 1.000 (t=0.9, v2_no_loc) |
