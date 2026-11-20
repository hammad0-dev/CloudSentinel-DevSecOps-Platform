# ml-dast rule-based checks (deterministic, NOT machine learning) - v2

Apps: labflask, labexpress, labfastapi, juice-shop, nodegoat, vulpy-bad, vulpy-good, vulnerable-node. Counts, not rates: n is too small for precision/recall.

| Check | Known instances | False alarms | Missed |
|---|---|---|---|
| CWE-78 | found 2 of 3 known instances | 0 false alarms on 107 safe endpoints | vulnerable-node|POST|/tools/ping|host |
| CWE-22 | found 3 of 4 known instances | 0 false alarms on 106 safe endpoints | juice-shop|GET|/ftp/{file}|file |
| CWE-601 | found 3 of 4 known instances | 0 false alarms on 106 safe endpoints | vulnerable-node|POST|/login/auth|returnurl |
| missing-csp | found 7 of 7 known instances | 0 false alarms on 1 apps without the issue | - |
| missing-nosniff | found 7 of 7 known instances | 0 false alarms on 1 apps without the issue | - |
| missing-frame-protection | found 7 of 7 known instances | 0 false alarms on 1 apps without the issue | - |
| cookie-no-httponly | found 0 of 0 known instances | 0 false alarms on 6 apps without the issue | - |
| cookie-no-samesite | found 2 of 2 known instances | 0 false alarms on 4 apps without the issue | - |
| cors-any-origin | found 0 of 0 known instances | 0 false alarms on 8 apps without the issue | - |

False alarms:
- none
