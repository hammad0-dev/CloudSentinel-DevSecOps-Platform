# ml-dast rule-based checks (deterministic, NOT machine learning) - v4

Counts, not rates: n is too small for precision/recall. BenchmarkPython is reported separately (synthetic, in-benchmark).

## Real training apps

Apps: labflask, labexpress, labfastapi, juice-shop, nodegoat, vulpy-bad, vulpy-good, dsvw, vulnerable-node, vampi, node-api-goat.

| Check | Known instances | False alarms | Missed |
|---|---|---|---|
| CWE-78 | found 3 of 4 known instances | 0 false alarms on 186 safe endpoints | vulnerable-node|POST|/tools/ping|host |
| CWE-22 | found 4 of 5 known instances | 0 false alarms on 185 safe endpoints | juice-shop|GET|/ftp/{file}|file |
| CWE-601 | found 4 of 5 known instances | 0 false alarms on 185 safe endpoints | vulnerable-node|POST|/login/auth|returnurl |
| missing-csp | found 9 of 9 known instances | 0 false alarms on 1 apps without the issue | - |
| missing-nosniff | found 10 of 10 known instances | 0 false alarms on 1 apps without the issue | - |
| missing-frame-protection | found 9 of 9 known instances | 0 false alarms on 1 apps without the issue | - |
| cookie-no-httponly | found 1 of 1 known instances | 0 false alarms on 6 apps without the issue | - |
| cookie-no-samesite | found 4 of 4 known instances | 0 false alarms on 3 apps without the issue | - |
| cors-any-origin | found 0 of 0 known instances | 0 false alarms on 11 apps without the issue | - |
| stored XSS (CWE-79) | found 2 of 8 known instances | 0 false alarms on 8 safe endpoints | nodegoat|POST /profile [lastName], nodegoat|POST /profile [ssn], nodegoat|POST /profile [dob], nodegoat|POST /profile [bankAcc], nodegoat|POST /profile [bankRouting], nodegoat|POST /profile [address] |
| CSRF heuristic (CWE-352) | found 13 of 20 known instances | 0 false alarms on 6 safe endpoints | nodegoat|POST /login (hidden _csrf field present but never validated (csurf commented out): the heuristic counts it as protected), nodegoat|POST /signup (same unvalidated _csrf field), nodegoat|POST /profile (same unvalidated _csrf field), nodegoat|POST /memos (no token field), vulnerable-node|POST /register (not reported), vulnerable-node|POST /account (not reported), vulnerable-node|POST /account/token (not reported) |

False alarms:
- none

Findings on unlabelled units:
- none

## BenchmarkPython (in-benchmark)

Apps: benchmarkpython.

| Check | Known instances | False alarms | Missed |
|---|---|---|---|
| CWE-78 | found 8 of 8 known instances | 0 false alarms on 147 safe endpoints | - |
| CWE-22 | found 0 of 39 known instances | 0 false alarms on 116 safe endpoints | benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00085|BenchmarkTest00085, benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00087|BenchmarkTest00087, benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00089|BenchmarkTest00089, benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00092|BenchmarkTest00092, benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00171|BenchmarkTest00171, benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00172|BenchmarkTest00172, benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00173|BenchmarkTest00173, benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00175|BenchmarkTest00175, benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00177|BenchmarkTest00177, benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00178|BenchmarkTest00178, benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00180|BenchmarkTest00180, benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00182|BenchmarkTest00182, benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00273|BenchmarkTest00273, benchmarkpython|POST|/benchmark/pathtraver-00/BenchmarkTest00277|BenchmarkTest00277, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00662|BenchmarkTest00662, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00665|BenchmarkTest00665, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00667|BenchmarkTest00667, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00737|BenchmarkTest00737, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00739|BenchmarkTest00739, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00741|BenchmarkTest00741, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00742|BenchmarkTest00742, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00749|BenchmarkTest00749, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00750|BenchmarkTest00750, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00751|BenchmarkTest00751, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00831|BenchmarkTest00831, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00834|BenchmarkTest00834, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00835|BenchmarkTest00835, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00906|BenchmarkTest00906, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00907|BenchmarkTest00907, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00910|BenchmarkTest00910, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00914|BenchmarkTest00914, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00915|BenchmarkTest00915, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00916|BenchmarkTest00916, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00918|BenchmarkTest00918, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest00920|BenchmarkTest00920, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest01179|BenchmarkTest01179, benchmarkpython|POST|/benchmark/pathtraver-01/BenchmarkTest01181|BenchmarkTest01181, benchmarkpython|POST|/benchmark/pathtraver-02/BenchmarkTest01183|BenchmarkTest01183, benchmarkpython|POST|/benchmark/pathtraver-02/BenchmarkTest01214|BenchmarkTest01214 |
| CWE-601 | found 0 of 0 known instances | 0 false alarms on 155 safe endpoints | - |
| missing-csp | found 1 of 1 known instances | 0 false alarms on 0 apps without the issue | - |
| missing-nosniff | found 1 of 1 known instances | 0 false alarms on 0 apps without the issue | - |
| missing-frame-protection | found 1 of 1 known instances | 0 false alarms on 0 apps without the issue | - |
| cors-any-origin | found 0 of 0 known instances | 0 false alarms on 1 apps without the issue | - |
| stored XSS (CWE-79) | found 0 of 0 known instances | 0 false alarms on 0 safe endpoints | - |
| CSRF heuristic (CWE-352) | found 0 of 0 known instances | 0 false alarms on 0 safe endpoints | - |

False alarms:
- none

Findings on unlabelled units:
- none

