# ml-dast v4 vs offline ZAP (real training apps, pooled leave-one-app-out predictions)

ZAP: unmodified zap-full-scan.py (offline image), unauthenticated, no seeds. Sources: labflask: v3 scan; labexpress: v3 scan; labfastapi: v3 scan; juice-shop: v1 scan (app unchanged since v1); nodegoat: v1 scan (app unchanged since v1); vulpy-bad: v1 scan (app unchanged since v1); vulpy-good: v1 scan (app unchanged since v1); dsvw: v3 scan NOT USED (excluded parameters were requested by ZAP (172.18.0.18): 398 requests with include/object/xml/size/path, 204 of them include=; global excludes did not hold); vulnerable-node: v3 scan; vampi: v3 scan; node-api-goat: v3 scan

## SQLi / XSS (ML) on the same endpoint-params

| Set | System | macro-F1 [95% CI] | SQLi TP/FP/FN | XSS TP/FP/FN |
|---|---|---|---|---|
| all (157) | ml-dast | 0.935 [0.886, 0.972] | 27/2/4 | 30/3/0 |
| all (157) | ZAP | 0.915 [0.858, 0.961] | 23/0/8 | 27/0/3 |
| all | difference ml-dast - ZAP | +0.020 [-0.037, +0.081] | | |
| own (105) | ml-dast | 0.919 [0.854, 0.970] | 17/1/3 | 16/3/0 |
| own (105) | ZAP | 0.954 [0.903, 0.990] | 16/0/4 | 16/0/0 |
| own | difference ml-dast - ZAP | -0.035 [-0.101, +0.026] | | |
| third-party (52) | ml-dast | 0.957 [0.893, 1.000] | 10/1/1 | 14/0/0 |
| third-party (52) | ZAP | 0.848 [0.704, 0.941] | 7/0/4 | 11/0/3 |
| third-party | difference ml-dast - ZAP | +0.115 [+0.000, +0.248] | | |

## Rule classes (counts)

| Class | Known | ml-dast rule found | ZAP found | ml-dast false alarms | ZAP alerts on listed safe endpoints | Safe units |
|---|---|---|---|---|---|---|
| CWE-78 | 3 | 2 | 2 | 0 | 0 | 175 |
| CWE-22 | 4 | 3 | 2 | 0 | 1 | 174 |
| CWE-601 | 4 | 3 | 3 | 0 | 0 | 174 |

## Passive checks (per app, counts)

| Check | Apps with the issue | ml-dast found | ZAP found | ml-dast false alarms | ZAP false alarms | Apps without |
|---|---|---|---|---|---|---|
| missing-csp | 8 | 8 | 7 | 0 | 0 | 1 |
| missing-nosniff | 9 | 9 | 8 | 0 | 0 | 1 |
| missing-frame-protection | 8 | 8 | 7 | 0 | 0 | 1 |
| cookie-no-httponly | 0 | 0 | 0 | 0 | 0 | 6 |
| cookie-no-samesite | 3 | 3 | 2 | 0 | 2 | 3 |
| cors-any-origin | 0 | 0 | 0 | 0 | 1 | 10 |

## Stored XSS and CSRF (counts)

| Check | Known | ml-dast found | ZAP found | ml-dast false alarms | Safe units |
|---|---|---|---|---|---|
| stored_xss | 8 | 2 | 1 | 0 | 8 |
| csrf_heuristic | 20 | 13 | 9 | 0 | 6 |
