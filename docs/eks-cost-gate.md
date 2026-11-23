# EKS cost gate (STOP 1) - 2026-11-23 15:10 PKT

**Nothing billable exists. Waiting for "go". Silence is not "go".**

The saved plan cannot be applied as it stands: `TF_VAR_alert_email` was not set in the WSL login shell, so the plan
used the placeholder `alert-email-not-set@example.invalid`. Re-plan (free) with your variable set before Stage 4.

## What would be created

| Item | Value | Why / evidence |
|---|---|---|
| Account / region | 229032674007 / **ap-south-1** (pinned in the provider: `allowed_account_ids`) | brief |
| Kubernetes | **1.36**, EKS standard support until 2027-08-02 | `aws eks describe-cluster-versions`: 1.34-1.37 STANDARD, 1.30-1.33 EXTENDED (paid). 1.34 standard ends 2026-12-02; 1.37 is the newest; 1.36 chosen as the newest-but-one |
| Nodes | **2 x m7i-flex.large** (2 vCPU, 8 GiB), managed node group min 2 / max 3, AL2023, 20 GiB gp3 encrypted, IMDSv2 hop limit 1 | listed by `describe-instance-types --filters Name=free-tier-eligible,Values=true` (t3.micro, t3.small, t4g.micro, t4g.small, t8i.micro, t8i.small, c7i-flex.large, m7i-flex.large); offered in ap-south-1a/b/c. Minikube: Kyverno 290 Mi + ESO 110 Mi + monitoring 940 Mi + EKS system pods; memory fits one node, but the 29-pod VPC CNI limit and 2 replicas on separate nodes need 2 |
| RDS (Stage 5, per two/three-tier project) | **db.t3.micro**, PostgreSQL 17.11 / MySQL 8.4.13, 20 GiB gp2, single AZ, private, encrypted | `describe-orderable-db-instance-options`: db.t3.micro orderable, **db.t4g.micro not orderable** in ap-south-1. Whether the Free plan accepts it is only known at create time |
| Network | VPC 10.40.0.0/16 (10.0.0.0/16 is project 13's), 2 private + 2 public subnets, **1 NAT gateway**, flow logs (ALL, 60 s) to CloudWatch | |
| API endpoint | public, limited to your current IP /32 (gitignored `local.tfvars`), plus private | an open 0.0.0.0/0 endpoint is a CRITICAL Trivy finding |
| Logging / detection | EKS control-plane logs api, audit, authenticator (7 days); multi-region CloudTrail with KMS, S3 bucket (7-day expiry) and CloudWatch Logs; metric filter + alarm on UnauthorizedOperation/AccessDenied -> SNS email | |
| GuardDuty | **not created** (`enable_guardduty = false`) | `aws guardduty list-detectors` -> `SubscriptionRequiredException` = needs a Paid plan. Per your rule not worked around; GuardDuty findings evidence in Stage 6 is therefore blocked unless you upgrade |
| Keys / IAM | 2 KMS keys (EKS secrets; CloudTrail/SNS/log group), OIDC provider, ESO IRSA role (cloudsentinel/* and rds!db-*), permissions boundary `cloudsentinel-workload-boundary` | |
| Add-ons | vpc-cni, kube-proxy, coredns, metrics-server; **no EBS CSI** (no PVCs) | |

Plan: `terraform plan` with profile cloudsentinel-admin, **82 to add, 0 to change, 0 to destroy**, all actions
`create`, every taggable resource tagged Project=cloudsentinel. Resource counts by type:
`docs/evidence/eks/stage3/shared-plan.txt`. Trivy: `docs/evidence/eks/stage3/shared-trivy.txt`.

## Hourly cost (ap-south-1, USD)

Unit prices are from the AWS Price List API (`aws pricing get-products`, 2026-11-23). Quantities marked **est.** are
my estimates, not measurements.

| Line | Unit price (API) | Quantity | $/hour |
|---|---|---|---|
| EKS control plane | $0.10 / cluster-hour | 1 | 0.1000 |
| Nodes m7i-flex.large | $0.10075 / hour | 2 | 0.2015 |
| Node EBS gp3 | $0.0912 / GB-month | 40 GB | 0.0050 |
| NAT gateway (hours) | $0.056 / hour | 1 | 0.0560 |
| NAT gateway (data) | $0.056 / GB | **est.** 0.4 GB/h (image pulls, Helm charts) | 0.0224 |
| Public IPv4 | $0.005 / address-hour | NAT 1 + **est.** 2 NLBs x 2 AZs = 5 | 0.0250 |
| Network Load Balancers (Stage 5 apps) | $0.0239 / hour + $0.006 / LCU-hour | **est.** 2 NLBs, 1 LCU each | 0.0598 |
| RDS db.t3.micro PostgreSQL + 20 GB gp2 | $0.026 / hour + $0.131 / GB-month | 1 instance (two-tier project) | 0.0296 |
| CloudWatch Logs ingestion (control plane, CloudTrail, app) | $0.67 / GB | **est.** 0.15 GB/h (audit log volume is the main unknown) | 0.1005 |
| CloudWatch vended logs (VPC flow logs) | $0.67 / GB (first 10 TB) | **est.** 0.05 GB/h | 0.0335 |
| CloudWatch storage, 1 alarm | $0.03 / GB-month, $0.10 / alarm-month | small | 0.0003 |
| KMS keys | $1 / key-month | 2 (prorated) | 0.0027 |
| Secrets Manager | $0.40 / secret-month, $0.05 / 10k calls | **est.** 3 secrets, ESO refresh every 1 min | 0.0025 |
| ECR storage, S3 trail bucket, CloudTrail | $0.10/GB-mo; management events first copy free | < 1 GB | 0.0005 |
| Data transfer out | $0.1093 / GB | **est.** 0.2 GB/h (curl, Grafana via port-forward) | 0.0219 |
| GuardDuty | n/a (not created) | 0 | 0.0000 |
| **Total (with Stage 5 apps running)** | | | **about 0.66** |

- Shared environment alone (Stage 4, before any project): about **$0.53/hour** (no NLB, RDS, extra IPs).
- **5-hour session: about $3.30** (estimate). If EKS audit logging is 3x my estimate (0.45 GB/h), add about
  $0.20/hour: **upper estimate about $0.86/hour, $4.30 for 5 hours.**
- Credit assumption: **$94** remaining (Free plan, ends 2027-02-14). A 5-hour session uses about 3.5-4.6 % of it.
- Not included: anything left running after the session (the main risk). Destroy commands are in
  `docs/eks-progress.md`; Stage 7 checks for leftovers.
- Risks I cannot check without creating something: whether the Free plan accepts EKS, NAT gateways and RDS
  db.t3.micro (GuardDuty is known to be refused). Per your rule, if AWS asks for a Paid plan I stop.

## To say "go"

1. In the WSL shell that runs Terraform: `export TF_VAR_alert_email=<your address>` (do not paste it into chat).
2. Run `aws login --profile cloudsentinel-admin` if the session is older than its expiry.
3. Reply "go". Stage 4 will then re-plan (because of the placeholder), show the new plan hash, apply exactly that
   plan, record the start time here and in `docs/eks-progress.md`, and remind you to click the SNS confirmation link.
