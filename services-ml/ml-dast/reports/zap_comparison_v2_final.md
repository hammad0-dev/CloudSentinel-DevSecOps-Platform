# ml-dast v2 vs offline ZAP (DSVW, final held-out)

ZAP: unmodified zap-full-scan.py (offline image), unauthenticated, no seeds. Sources: dsvw: v2 scan

## SQLi / XSS (ML) on the same endpoint-params

| Set | System | macro-F1 [95% CI] | SQLi TP/FP/FN | XSS TP/FP/FN |
|---|---|---|---|---|
| all (12) | ml-dast | 0.608 [0.368, 1.000] | 0/0/3 | 2/0/0 |
| all (12) | ZAP | 0.246 [0.167, 0.455] | 0/0/3 | 0/0/2 |
| all | difference ml-dast - ZAP | +0.330 [+0.000, +0.441] | | |
| own (0) | ml-dast | 0.000 [0.000, 0.000] | 0/0/0 | 0/0/0 |
| own (0) | ZAP | 0.000 [0.000, 0.000] | 0/0/0 | 0/0/0 |
| own | difference ml-dast - ZAP | +0.000 [+0.000, +0.000] | | |
| third-party (12) | ml-dast | 0.608 [0.368, 1.000] | 0/0/3 | 2/0/0 |
| third-party (12) | ZAP | 0.246 [0.167, 0.455] | 0/0/3 | 0/0/2 |
| third-party | difference ml-dast - ZAP | +0.330 [+0.000, +0.441] | | |

## Rule classes (counts)

| Class | Known | ml-dast rule found | ZAP found | ml-dast false alarms | ZAP alerts on listed safe endpoints | Safe units |
|---|---|---|---|---|---|---|
| CWE-78 | 1 | 1 | 0 | 0 | 0 | 11 |
| CWE-22 | 1 | 1 | 0 | 0 | 0 | 11 |
| CWE-601 | 1 | 1 | 0 | 0 | 0 | 11 |

## Passive checks (per app, counts)

| Check | Apps with the issue | ml-dast found | ZAP found | ml-dast false alarms | ZAP false alarms | Apps without |
|---|---|---|---|---|---|---|
| missing-csp | 1 | 1 | 1 | 0 | 0 | 0 |
| missing-nosniff | 1 | 1 | 1 | 0 | 0 | 0 |
| missing-frame-protection | 1 | 1 | 1 | 0 | 0 | 0 |
| cookie-no-httponly | 1 | 1 | 0 | 0 | 0 | 0 |
| cookie-no-samesite | 1 | 1 | 0 | 0 | 0 | 0 |
| cors-any-origin | 0 | 0 | 0 | 0 | 0 | 1 |
