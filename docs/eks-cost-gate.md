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
| Public IPv4 | $0.005 / address-hour | NAT 1 + 3 NLBs x 2 public subnets = 7 | 0.0350 |
| Network Load Balancers (Stage 5 apps) | $0.0239 / hour + $0.006 / LCU-hour | 3 NLBs (one per public Service: one-tier app, two-tier app, three-tier frontend; the three-tier backend is ClusterIP, Grafana is port-forward only), **est.** 1 LCU each | 0.0897 |
| RDS db.t3.micro PostgreSQL + 20 GB gp2 | $0.026 / hour + $0.131 / GB-month (= $0.0036 / hour for 20 GB) | 2 instances (two-tier Flask fixture and three-tier backend; both detected as PostgreSQL) | 0.0592 |
| CloudWatch Logs ingestion (control plane, CloudTrail, app) | $0.67 / GB | **est.** 0.15 GB/h (audit log volume is the main unknown) | 0.1005 |
| CloudWatch vended logs (VPC flow logs) | $0.67 / GB (first 10 TB) | **est.** 0.05 GB/h | 0.0335 |
| CloudWatch storage, 1 alarm | $0.03 / GB-month, $0.10 / alarm-month | small | 0.0003 |
| KMS keys | $1 / key-month | 2 (prorated) | 0.0027 |
| Secrets Manager | $0.40 / secret-month, $0.05 / 10k calls | 4 project secrets (one-tier 1, two-tier 1, three-tier 2) + 2 RDS-managed master secrets; **est.** 6 ExternalSecrets refreshing every 1 min | 0.0051 |
| ECR storage, S3 trail bucket, CloudTrail | $0.10/GB-mo; management events first copy free | < 1 GB | 0.0005 |
| Data transfer out | $0.1093 / GB | **est.** 0.2 GB/h (curl, Grafana via port-forward) | 0.0219 |
| GuardDuty | n/a (not created) | 0 | 0.0000 |
| **Total (all three architectures applied in Stage 5)** | | | **about 0.73** |

Updated 2026-11-25 after "go": the first version priced 1 RDS instance, 2 NLBs and 5 public IPv4 addresses (total
about $0.66/hour). You asked to apply one-tier, two-tier and three-tier, which needs **2 RDS instances and 3 NLBs**;
the static site is planned and checked only (not applied), so it adds nothing.

- Shared environment alone (Stage 4, before any project): about **$0.53/hour** (no NLB, RDS, extra IPs).
- **5-hour session: about $3.70** (estimate). If EKS audit logging is 3x my estimate (0.45 GB/h), add about
  $0.20/hour: **upper estimate about $0.93/hour, $4.70 for 5 hours.**
- Credit assumption: **$94** remaining (Free plan, ends 2027-02-14). A 5-hour session uses about 4-5 % of it.
- Capacity check for all three apps: 8 app pods at 2 replicas (16 at the HPA maximum of 4) plus about 29 platform
  pods, against 2 x 29 pods (VPC CNI limit for m7i-flex.large); memory about 2 GiB of 2 x 8 GiB.
- Not included: anything left running after the session (the main risk). Destroy commands are in
  `docs/eks-progress.md`; Stage 7 checks for leftovers.
- Risks I cannot check without creating something: whether the Free plan accepts EKS, NAT gateways and RDS
  db.t3.micro (GuardDuty is known to be refused). Per your rule, if AWS asks for a Paid plan I stop.

## Pre-apply checks after "go" (2026-11-25)

| Check | Result |
|---|---|
| GuardDuty EventBridge rule | removed from the code (rule, target, and the `events.amazonaws.com` grants in the SNS and KMS policies); verification plan: 0 event rules, 0 GuardDuty resources |
| EKS add-ons | were unpinned (`{}` = latest); now pinned to the EKS default builds for 1.36: vpc-cni v1.22.4-eksbuild.14, kube-proxy v1.36.0-eksbuild.65, coredns v1.14.7-eksbuild.35, metrics-server v0.9.1-eksbuild.2 |
| Kyverno | **1.19 does not support 1.36** (supports 1.33-1.35). Pinned 1.20.0 / chart 3.10.0 (supports 1.34-1.37; published 2026-11-12, one day under the two-week rule; no older release supports 1.36). 1.20 no longer runs ClusterPolicy: the seven policies were ported to CEL ValidatingPolicy (`k8s/kyverno/eks-cel/`), same CLI results |
| External Secrets | 2.14.0 kept (tested up to Kubernetes 1.37) |
| kube-prometheus-stack | was unpinned; pinned 93.1.2 (2026-11-10; kube-state-metrics 2.20 = client-go 1.36) |
| Logs | Promtail chart is deprecated; Loki 7.5.0 + Grafana Alloy 1.14.4 pinned instead |
| Falco | was unpinned; pinned 9.2.2 / 0.45.2 (2026-10-29; kernel-based, no Kubernetes constraint) |

Pins: `k8s/eks/versions.env`. Verification plan (placeholder email, never applied): 82 to add, all tagged, sha256
`76b49e65e0d7fecb61b8478c7415e4aebafcc4c6bc48888943bbf5c5127321e2`.

## To say "go"

1. In the WSL shell that runs Terraform: `export TF_VAR_alert_email=<your address>` (do not paste it into chat).
2. Run `aws login --profile cloudsentinel-admin` if the session is older than its expiry.
3. Reply "go". Stage 4 will then re-plan (because of the placeholder), show the new plan hash, apply exactly that
   plan, record the start time here and in `docs/eks-progress.md`, and remind you to click the SNS confirmation link.
