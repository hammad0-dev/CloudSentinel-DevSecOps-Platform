# Incident walkthrough: one denied API call followed across the logs (Module 11)

A real event from this run (not staged): on 2026-11-25 the project-infrastructure engine, running as the scoped IAM
user `cloudsentinel-dev`, was denied `rds:DescribeDBInstances` while applying project 9103. Times are UTC
(PKT = UTC+5). Values are from the queries in `06-cloudwatch-logs-insights.txt` and the commands below; source IPs
and key IDs are masked.

## 1. Alert (CloudWatch alarm -> SNS -> email)

| Time (UTC) | Source | Record |
|---|---|---|
| 14:13:21 | CloudTrail (`/cloudsentinel/cloudtrail`) | `cloudsentinel-dev` `rds:DescribeDBInstances` -> `AccessDenied`, user agent `HashiCorp Terraform/1.16.6`, temporary key `ASIA****` |
| 14:13-14:14 | metric filter `cloudsentinel-unauthorized-api-calls` | `CloudSentinel/Security UnauthorizedAPICalls` = 1 |
| 14:14:50 | alarm history | `Alarm updated from OK to ALARM` |
| 14:14:51 | alarm history | `Successfully executed action arn:aws:sns:ap-south-1:229032674007:cloudsentinel-security-alerts` (email to the confirmed subscription) |
| 14:19:50 | alarm history | `ALARM to OK` (no further denials in the 5-minute period) |

## 2. Triage: who, what, from where (saved query `cloudsentinel/denied-api-calls`)

```
fields eventTime, userIdentity.arn, eventSource, eventName, errorCode, awsRegion, sourceIPAddress
| filter errorCode like /UnauthorizedOperation|AccessDenied/ | sort eventTime desc | limit 50
```

- Principal: `arn:aws:iam::229032674007:user/cloudsentinel-dev` (the scoped automation user, not root or admin).
- Action: `rds:DescribeDBInstances`, resource `arn:aws:rds:ap-south-1:229032674007:db:*`.
- Client: Terraform from the operator workstation (the same source IP as every other engine call).
- Same denial 11 minutes earlier (14:02:25) during the 9102 destroy-plan: a pattern, not a one-off.
- No other principal had RDS denials in the window: no sign of credential misuse.

## 3. Correlate with the application side (engine audit log)

`~/.cloudsentinel/eks-run/eks-workloads/9103/audit.jsonl` (and 9102 for the 14:02 event):

```
13:53:44 apply-start   planHash 403136c2...   (9102)
13:59:44 apply-failed  (exported credentials expired while waiting for RDS)
14:02:27 destroy-plan  REJECTED  "Terraform destroy-plan failed"     <- CloudTrail 14:02:25 denial
14:05:15 apply-start   (9103)    ...  14:13:21 apply-failed          <- CloudTrail 14:13:21 denial
```

The Terraform log of that step (stored redacted with the plan) has the full message:
`not authorized to perform: rds:DescribeDBInstances on resource: arn:aws:rds:ap-south-1:229032674007:db:*`.

## 4. Kubernetes side (EKS audit log, saved query `cloudsentinel/eks-audit-secrets-and-exec`)

Checked over the last 3 hours (query run 2026-11-25 ~14:50 UTC):
- `exec`: only four calls, all by `user/cloudsentinel-admin` into `cloudsentinel-p-9101/p9101-app-6965589576-8hprk`
  at 14:40:30-14:41:27: the Falco tests (`10-falco.txt`). None by project service accounts or the dev user.
- Secrets by non-`system:` users: only `cloudsentinel-admin` Helm releases (ESO, Kyverno, Loki, the generated
  `grafana-admin` Secret) at 13:00-13:51 and EKS's own `eks:kms-storage-migrator`. Expected platform activity.
So the cluster was not involved in the incident.

## 5. Network side (VPC flow logs)

Checked over the last 3 hours: 30 REJECT records, all from internet source addresses toward addresses inside the VPC
(10.40.0.0/16); **none to port 5432** (the databases). The flow log does not say what those senders were; they are
unsolicited inbound connections dropped by the security groups, unrelated to this incident.

## 6. Root cause, fix, verification

- Root cause: the AWS provider (6.70) reads an RDS instance by its resource ID with a `DescribeDBInstances` filter;
  IAM authorizes that call on `db:*`, but the dev policy allowed it only on `db:cloudsentinel-p*-db`.
- Fix: dev policy v3 adds a read-only `DescribeDbInstancesReadOnly` statement (`rds:DescribeDBInstances` on `db:*`);
  published by the account owner, verified identical to `terraform/docs/policies/cloudsentinel-dev-container.json`.
- Recovery: both projects went through the engine's scoped recovery destroy (only resources in the saved state and the
  approved plan) and a fresh plan -> approval -> apply.
- Verification: rerun the `cloudsentinel/denied-api-calls` query after the fix; the alarm returns to OK.

Second finding from the same query: `cloudsentinel-cloudtrail-to-logs` was denied `kms:GenerateDataKey` every ~5
minutes (13:00-14:09). Cause: the CloudTrail log group is KMS-encrypted and the delivery role had no key permission.
Fixed in Terraform (one in-place update, 14:09 UTC); `08-kms-fix-check.txt` shows no denials after it.
