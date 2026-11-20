# ml-dast v2 vs offline ZAP (training apps, pooled leave-one-app-out predictions)

ZAP: unmodified zap-full-scan.py (offline image), unauthenticated, no seeds. Sources: labflask: v2 scan; labexpress: v2 scan; labfastapi: v2 scan; juice-shop: v1 scan (app unchanged in v2); nodegoat: v1 scan (app unchanged in v2); vulpy-bad: v1 scan (app unchanged in v2); vulpy-good: v1 scan (app unchanged in v2); vulnerable-node: v2 scan

## SQLi / XSS (ML) on the same endpoint-params

| Set | System | macro-F1 [95% CI] | SQLi TP/FP/FN | XSS TP/FP/FN |
|---|---|---|---|---|
| all (111) | ml-dast | 0.827 [0.744, 0.894] | 22/4/1 | 15/6/6 |
| all (111) | ZAP | 0.937 [0.882, 0.979] | 18/0/5 | 21/1/0 |
| all | difference ml-dast - ZAP | -0.112 [-0.202, -0.028] | | |
| own (73) | ml-dast | 0.871 [0.767, 0.945] | 13/4/0 | 10/4/0 |
| own (73) | ZAP | 0.966 [0.910, 1.000] | 11/0/2 | 10/0/0 |
| own | difference ml-dast - ZAP | -0.098 [-0.208, +0.004] | | |
| third-party (38) | ml-dast | 0.757 [0.609, 0.884] | 9/0/1 | 5/2/6 |
| third-party (38) | ZAP | 0.890 [0.760, 0.975] | 7/0/3 | 11/1/0 |
| third-party | difference ml-dast - ZAP | -0.130 [-0.287, +0.034] | | |

## Rule classes (counts)

| Class | Known | ml-dast rule found | ZAP found | ml-dast false alarms | ZAP alerts on listed safe endpoints | Safe units |
|---|---|---|---|---|---|---|
| CWE-78 | 3 | 2 | 2 | 0 | 0 | 107 |
| CWE-22 | 4 | 3 | 2 | 0 | 0 | 106 |
| CWE-601 | 4 | 3 | 3 | 0 | 0 | 106 |

## Passive checks (per app, counts)

| Check | Apps with the issue | ml-dast found | ZAP found | ml-dast false alarms | ZAP false alarms | Apps without |
|---|---|---|---|---|---|---|
| missing-csp | 7 | 7 | 7 | 0 | 0 | 1 |
| missing-nosniff | 7 | 7 | 7 | 0 | 0 | 1 |
| missing-frame-protection | 7 | 7 | 7 | 0 | 0 | 1 |
| cookie-no-httponly | 0 | 0 | 0 | 0 | 0 | 6 |
| cookie-no-samesite | 2 | 2 | 2 | 0 | 2 | 4 |
| cors-any-origin | 0 | 0 | 0 | 0 | 1 | 8 |
