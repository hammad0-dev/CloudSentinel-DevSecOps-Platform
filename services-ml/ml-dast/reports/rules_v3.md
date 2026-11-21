# ml-dast rule-based checks (deterministic, NOT machine learning) - v3

Apps: labflask, labexpress, labfastapi, juice-shop, nodegoat, vulpy-bad, vulpy-good, dsvw, vulnerable-node, vampi, node-api-goat. Counts, not rates: n is too small for precision/recall.

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

Stored XSS instances outside the rule's scope (not counted above):
- nodegoat|POST /memos [memo]: {{ marked(doc.memo) }} with marked sanitize:true: HTML tags are escaped, the known bypass is a markdown javascript: link
- vulpy-bad|POST /posts/ [text]: bad/templates/posts.view.html line 23 '{{ post.text | safe }}'; posting needs a login, and vulpy's login fails in the la
- vulpy-good|POST /posts/ [text]: good/templates/posts.view.html line 23 also '| safe'; behind login as above
- dsvw|GET / [comment]: dsvw.py @ 9ca3c9a line 46: stored comments shown raw; written by a GET, outside the rule (POST/PUT only)

CSRF: apps not evaluable in the lab:
- vulpy-bad: vulpy_session never set in the lab (login 500, v2 note)
- vulpy-good: as vulpy-bad

Findings on unlabelled units (checked against the source, see GROUND_TRUTH.md):
- none

False alarms:
- none
