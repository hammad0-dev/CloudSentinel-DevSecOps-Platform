# ml-dast leave-one-app-out: v4 candidates on the v4 data

Rows 13402 ({'own': 5250, 'third-party': 4152, 'benchmark': 4000}). Groups: benchmark, dsvw, juice-shop, labexpress, labfastapi, labflask, node-api-goat, nodegoat, vampi, vulnerable-node, vulpy. Feature sets: {'v2_all': 74, 'v2_no_loc': 70, 'v3_all': 67, 'v3_no_loc': 63}. Thresholds: [np.float64(0.2), np.float64(0.25), np.float64(0.3), np.float64(0.35), np.float64(0.4), np.float64(0.45), np.float64(0.5), np.float64(0.55), np.float64(0.6), np.float64(0.65), np.float64(0.7), np.float64(0.75), np.float64(0.8), np.float64(0.85), np.float64(0.9), np.float64(0.95), 0.97, 0.98, 0.99, 0.995].
**real** = own + third-party apps (the headline). **benchmark** = BenchmarkPython, one group, in-benchmark numbers only: they say nothing about generalization to real apps.

## real (169 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) |
|---|---|---|---|---|
| lr | 0.933 [0.887, 0.969] | 0.94/0.85/0.89 (34) [0.81, 0.97] | 0.91/1.00/0.96 (32) [0.89, 1.00] | 0.95 (103) |
| lgbm | 0.826 [0.756, 0.883] | 0.74/0.74/0.74 (34) [0.61, 0.84] | 0.83/0.91/0.87 (32) [0.77, 0.94] | 0.88 (103) |

- lr - lgbm: +0.110 [+0.044, +0.173]

## own (105 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) |
|---|---|---|---|---|
| lr | 0.919 [0.854, 0.970] | 0.94/0.85/0.89 (20) [0.76, 0.98] | 0.84/1.00/0.91 (16) [0.80, 1.00] | 0.95 (69) |
| lgbm | 0.859 [0.771, 0.924] | 0.85/0.85/0.85 (20) [0.71, 0.95] | 0.81/0.81/0.81 (16) [0.61, 0.94] | 0.91 (69) |

- lr - lgbm: +0.063 [-0.008, +0.142]

## third-party (64 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) |
|---|---|---|---|---|
| lr | 0.948 [0.881, 1.000] | 0.92/0.86/0.89 (14) [0.73, 1.00] | 1.00/1.00/1.00 (16) [1.00, 1.00] | 0.96 (34) |
| lgbm | 0.762 [0.630, 0.854] | 0.57/0.57/0.57 (14) [0.31, 0.77] | 0.84/1.00/0.91 (16) [0.79, 1.00] | 0.80 (34) |

- lr - lgbm: +0.192 [+0.081, +0.317]

## benchmark (80 endpoint-params)

| Model | macro-F1 [95% CI] | SQLi P/R/F1 (n) [F1 CI] | XSS P/R/F1 (n) [F1 CI] | safe F1 (n) |
|---|---|---|---|---|
| lr | 1.000 [1.000, 1.000] | 1.00/1.00/1.00 (3) [0.00, 1.00] | 1.00/1.00/1.00 (21) [1.00, 1.00] | 1.00 (56) |
| lgbm | 0.930 [0.661, 1.000] | 1.00/0.67/0.80 (3) [0.00, 1.00] | 1.00/1.00/1.00 (21) [1.00, 1.00] | 0.99 (56) |

- lr - lgbm: +0.079 [+0.000, +0.339]

## Per fold

| Test group | lr | lgbm |
|---|---|---|
| benchmark | 1.000 (t=0.98, v3_no_loc) | 0.930 (t=0.98, v3_no_loc) |
| dsvw | 0.911 (t=0.995, v3_no_loc) | 0.780 (t=0.99, v3_no_loc) |
| juice-shop | 1.000 (t=0.99, v3_all) | 0.762 (t=0.95, v3_no_loc) |
| labexpress | 0.966 (t=0.995, v3_no_loc) | 0.945 (t=0.995, v3_no_loc) |
| labfastapi | 0.950 (t=0.97, v3_no_loc) | 0.900 (t=0.95, v3_no_loc) |
| labflask | 0.873 (t=0.995, v3_no_loc) | 0.785 (t=0.98, v3_all) |
| node-api-goat | 0.929 (t=0.995, v3_no_loc) | 0.929 (t=0.95, v3_all) |
| nodegoat | 1.000 (t=0.995, v3_no_loc) | 1.000 (t=0.95, v3_no_loc) |
| vampi | 1.000 (t=0.995, v3_no_loc) | 0.444 (t=0.98, v3_all) |
| vulnerable-node | 0.930 (t=0.995, v3_no_loc) | 0.626 (t=0.99, v2_no_loc) |
| vulpy | 1.000 (t=0.97, v3_no_loc) | 0.733 (t=0.99, v3_no_loc) |
