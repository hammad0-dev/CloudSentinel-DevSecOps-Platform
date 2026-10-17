# SAST type and severity

Migration 016 is prepared, not applied. Apply it through a separately authorized
migration workflow before loading this source. Missing columns fail the scan;
there is no fallback to severity-only security classification. Historical rows
remain UNKNOWN and are blocked pending new genuine scan evidence. Scan 59 and
execution 35 are not rewritten.

Severity totals include all findings for inventory consistency. The execution
security gate uses independently persisted issue_type: only VULNERABILITY at
BLOCKER/CRITICAL or MAJOR/HIGH blocks as a confirmed security vulnerability.
CODE_SMELL is maintainability and BUG is reliability. SECURITY_HOTSPOT requires
review: only SonarQube REVIEWED with SAFE/FIXED is cleared; ACKNOWLEDGED still
requires review. Unknown types fail closed. The hotspot endpoint is retrieved
separately, scoped to the exact Sonar project. Incomplete issue/hotspot inventory
fails scanning rather than silently omitting findings.

The previous route did not explicitly evaluate Sonar's quality gate. This source
now rejects ERROR or unavailable/unrecognized quality-gate results before scan
completion. OK passes; NONE denotes no assigned quality gate and does not bypass
the independent CloudSentinel security gate. Failed scans cannot satisfy the
orchestrator's completed-linked-evidence requirement.

No security policy, project repository, infrastructure or historical findings
were modified. A separately authorized migration and backend restart are needed
before a new authorized execution can exercise this change.
