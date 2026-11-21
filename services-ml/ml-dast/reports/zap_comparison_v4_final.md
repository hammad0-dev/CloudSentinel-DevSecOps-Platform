# ml-dast v4 vs offline ZAP (DVPWA, final held-out)

ZAP: unmodified zap-full-scan.py (offline image), unauthenticated, no seeds. Sources: dvpwa: v4 scan

## SQLi / XSS (ML) on the same endpoint-params

| Set | System | macro-F1 [95% CI] | SQLi TP/FP/FN | XSS TP/FP/FN |
|---|---|---|---|---|
| all (8) | ml-dast | 1.000 [1.000, 1.000] | 0/0/0 | 1/0/0 |
| all (8) | ZAP | 0.795 [0.564, 1.000] | 0/0/0 | 1/1/0 |
| all | difference ml-dast - ZAP | +0.125 [+0.000, +0.436] | | |
| own (0) | ml-dast | 0.000 [0.000, 0.000] | 0/0/0 | 0/0/0 |
| own (0) | ZAP | 0.000 [0.000, 0.000] | 0/0/0 | 0/0/0 |
| own | difference ml-dast - ZAP | +0.000 [+0.000, +0.000] | | |
| third-party (8) | ml-dast | 1.000 [1.000, 1.000] | 0/0/0 | 1/0/0 |
| third-party (8) | ZAP | 0.795 [0.564, 1.000] | 0/0/0 | 1/1/0 |
| third-party | difference ml-dast - ZAP | +0.125 [+0.000, +0.436] | | |

## Rule classes (counts)

| Class | Known | ml-dast rule found | ZAP found | ml-dast false alarms | ZAP alerts on listed safe endpoints | Safe units |
|---|---|---|---|---|---|---|
| CWE-78 | 0 | 0 | 0 | 0 | 0 | 12 |
| CWE-22 | 0 | 0 | 0 | 0 | 0 | 12 |
| CWE-601 | 0 | 0 | 0 | 0 | 0 | 12 |

## Passive checks (per app, counts)

| Check | Apps with the issue | ml-dast found | ZAP found | ml-dast false alarms | ZAP false alarms | Apps without |
|---|---|---|---|---|---|---|
| missing-csp | 1 | 1 | 1 | 0 | 0 | 0 |
| missing-nosniff | 1 | 1 | 1 | 0 | 0 | 0 |
| missing-frame-protection | 1 | 1 | 1 | 0 | 0 | 0 |
| cookie-no-httponly | 1 | 1 | 1 | 0 | 0 | 0 |
| cookie-no-samesite | 1 | 1 | 1 | 0 | 0 | 0 |
| cors-any-origin | 0 | 0 | 0 | 0 | 0 | 1 |

## Stored XSS and CSRF (counts)

| Check | Known | ml-dast found | ZAP found | ml-dast false alarms | Safe units |
|---|---|---|---|---|---|
| stored_xss | 4 | 1 | 1 | 0 | 1 |
| csrf_heuristic | 5 | 0 | 0 | 0 | 0 |
