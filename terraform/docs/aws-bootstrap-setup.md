# Module 8: proposed IAM and separate S3 bootstrap

PLANNING ONLY. None of the AWS-changing commands below were executed. JSON files
under `policies/` are exact policy *templates*, not attached policies. Replace all
APPROVED_* values with explicitly approved inputs. Do not paste unresolved
placeholders into IAM. Generated files are private local planning artifacts.

## 1. Decide and approve inputs

Account 229032674007, region ap-south-1, existing user cloudsentinel-dev.
Environment is development; policies intentionally do not authorize production.
Project ID is UNSELECTED: choose an approved positive integer other than 11/17;
Module 8 is not itself proof that database project 8 is authorized.
AZ candidate ap-south-1a is UNVERIFIED: DescribeAvailabilityZones is denied.
10.0.1.0/24 and 10.0.2.0/24 lie inside 10.0.0.0/16 and do not overlap each other.
Host route inspection found no overlap; AWS-wide overlap remains UNVERIFIED
because DescribeVpcs is denied. Check VPN, peering, connected on-premise and
planned future ranges too. Overlapping unconnected VPCs are allowed by AWS but
would prevent later connectivity; do not treat successful creation as validation.

Proposed names, NOT verified globally unique or approved:

- cloudsentinel-229032674007-ap-south-1-state-<8-random-hex>
- cloudsentinel-229032674007-ap-south-1-flow-<8-random-hex>

Generate suffixes locally with `python3 -c 'import secrets; print(secrets.token_hex(4))'`.
S3 names are globally unique in the partition. HeadBucket 403 does not establish
availability or ownership; even 404 does not reserve a name. Verify final account,
region and bucket owner. Pick an explicit state administrator IAM user/role ARN;
no administrator permission is granted to cloudsentinel-dev by this guide.

## 2. Render policy JSON locally (no AWS changes)

After choosing approved values, fill these shell values literally. These are names
and IDs, not credentials; do not export access keys or tokens.

```bash
cd /home/hammad/CloudSentinel
PROJECT_ID='REPLACE_WITH_APPROVED_INTEGER'
AZ='REPLACE_WITH_VERIFIED_AZ'
STATE_BUCKET='REPLACE_WITH_APPROVED_STATE_BUCKET'
FLOW_BUCKET='REPLACE_WITH_APPROVED_FLOW_LOG_BUCKET'
STATE_ADMIN_ARN='REPLACE_WITH_APPROVED_ADMIN_USER_OR_ROLE_ARN'
SETUP_DIR="$HOME/cs-module8-approved-setup"
python3 terraform/docs/render_aws_setup.py \
  --project-id "$PROJECT_ID" --az "$AZ" \
  --state-bucket "$STATE_BUCKET" --flow-log-bucket "$FLOW_BUCKET" \
  --state-admin-arn "$STATE_ADMIN_ARN" --output "$SETUP_DIR"
```

Renderer rejects invalid inputs, protected project IDs, shared state/log buckets,
and an existing output directory. It uses 0700/0600 and never calls AWS. It omits
the default-SG-adoption policy unless `--default-sg-arn` is explicitly provided.
The default SG ARN must refer to the newly approved VPC, never an existing VPC.
Read exact policies with `cat "$SETUP_DIR/network-create-read.json"` etc. No
state, credentials, plan or authentication data is present in these JSON files.

## 3. IAM Console procedure — requires separate IAM-change approval

Sign in as an administrator authorized to manage this user's permissions (not
root for routine operations). Confirm account 229032674007. Open IAM → Policies
→ Create policy → JSON. Paste one fully rendered runtime JSON at a time; review
IAM editor validation/security warnings, then create customer-managed policies:

1. CloudSentinelNetworkCreateRead — network-create-read.json
2. CloudSentinelNetworkManage — network-manage.json
3. CloudSentinelFlowLogDelivery — flow-log-delivery-runtime.json
4. CloudSentinelTerraformState — terraform-state-runtime.json
5. CloudSentinelDefaultSGAdoption — default-sg-adoption.json, ONLY after exact ARN review

Then IAM → Users → cloudsentinel-dev → Permissions → Add permissions → Attach
policies directly → select only those reviewed customer-managed policies → Add
permissions. Do not attach bucket resource policies or S3 configuration files as
identity policies. Check existing user/group policies, permission boundary and
SCPs for broader grants or explicit denies. A narrow new policy does not constrain
an existing broad allow. Check attachment quotas and account-specific organization
controls. No AdministratorAccess, ec2:*, IAM modification, PassRole, bucket-policy
mutation or SG ingress/egress authorize permission is included for the runtime.

Do not blindly add broad permissions when an operation fails: inspect the denied
action and resource. IAM Access Analyzer's ValidatePolicy and the IAM Policy
Simulator can be used by an already authorized administrator; this task did not
grant those tools' permissions. Simulate with real resource ARNs plus request
region and required tags; simulation is not proof that S3 bucket policies or
organization controls permit execution. No create/delete dry-run is executed here. AWS CLI login success is not proof that the pinned Terraform/provider SDK recognizes the login_session credential format. Verify SDK-compatible, short-lived authentication privately before real remote init/plan; do not print/export credentials to logs or embed tokens in backend files.

### Resource scope and first-apply constraint

The action/resource mapping was checked against AWS's official programmatic EC2
service authorization reference. New resource ARNs use resource-ID wildcards
because IDs do not exist yet, restricted to this account/region and mandatory
ProjectId, Module, ManagedBy, Environment request tags. Related parent VPCs and
subsequent mutations require those matching resource tags. Tag-on-create is
restricted with ec2:CreateAction; runtime cannot retag arbitrary unowned resources
or remove ownership tags. Only Name/NetworkTier descriptive tags may be updated.

Resource "*" is used only for the used EC2 Describe operations lacking resource
scoping and logs:CreateLogDelivery/logs:DeleteLogDelivery, whose documented model
requires it. Both are restricted to ap-south-1. DescribeVpcAttribute supports VPC
ARN scoping and is scoped accordingly. STS GetCallerIdentity needs no identity
Allow and is not added as a wildcard statement. No account-wide IAM simulation
permission is added just to make a diagnostic command succeed.

IMPORTANT: aws_default_security_group revokes its untagged default rules before
project tagging. ABAC alone cannot safely authorize adoption of that unknown SG.
The separate adoption policy scopes CreateTags/Revoke to its exact ARN; no broad
permission to claim unrelated untagged SGs is supplied. Before the first complete
apply, choose a separately approved bootstrap strategy:

- A separately authorized VPC-only Terraform bootstrap, followed by read-only
  discovery and administrator approval of that new VPC's default SG ARN; then
  attach its exact adoption policy and review a fresh complete plan. Targeted
  apply is exceptional, not a normal deployment shortcut, and is not authorized
  or executed by this planning task.
- Alternatively an administrator-reviewed execution mechanism that can approve
  that exact SG after creation. Do not replace the exact ARN with security-group/*.

Without resolving this prerequisite, a one-shot complete initial apply is BLOCKED
under the least-privilege policy. A plan can still validate configuration after
read/state/log prerequisites pass, but planning does not verify mutation rights.
The AWS log-delivery documentation additionally specifies publishing-principal
requirements; administrator must verify them for the existing IAM-user workflow
(or separately approve a role-based alternative) before claiming apply readiness.

## 4. Separate S3 bootstrap — requires explicit bucket/policy/cost approval

Use a separately authorized state/log administrator profile. Do NOT use
cloudsentinel-dev to bootstrap the buckets or change bucket policies. The runtime
policies deliberately omit these permissions. Bootstrap via AWS CLI/Console avoids
a Terraform-state circular dependency. Buckets are not network-stack resources;
network destroy must never delete state or retained logs.

The following is a PROPOSED future command sequence, not executed now:

```bash
ADMIN_PROFILE='REPLACE_WITH_APPROVED_BOOTSTRAP_ADMIN_PROFILE'
(
set -euo pipefail
# Run once for each approved bucket; stop if any command fails.
for BUCKET in "$STATE_BUCKET" "$FLOW_BUCKET"; do
  aws --profile "$ADMIN_PROFILE" --region ap-south-1 s3api create-bucket \
    --bucket "$BUCKET" --object-ownership BucketOwnerEnforced \
    --create-bucket-configuration LocationConstraint=ap-south-1 || exit 1
  aws --profile "$ADMIN_PROFILE" --region ap-south-1 s3api put-public-access-block \
    --bucket "$BUCKET" --public-access-block-configuration "file://$SETUP_DIR/bucket-public-access.json" || exit 1
  aws --profile "$ADMIN_PROFILE" --region ap-south-1 s3api put-bucket-encryption \
    --bucket "$BUCKET" --server-side-encryption-configuration "file://$SETUP_DIR/bucket-encryption.json" || exit 1
  aws --profile "$ADMIN_PROFILE" --region ap-south-1 s3api put-bucket-versioning \
    --bucket "$BUCKET" --versioning-configuration Status=Enabled || exit 1
done
# Run these ONLY after both buckets and all preceding protections are verified.
aws --profile "$ADMIN_PROFILE" --region ap-south-1 s3api put-bucket-policy \
  --bucket "$STATE_BUCKET" --policy "file://$SETUP_DIR/state-bucket-policy.json"
aws --profile "$ADMIN_PROFILE" --region ap-south-1 s3api put-bucket-policy \
  --bucket "$FLOW_BUCKET" --policy "file://$SETUP_DIR/flow-log-bucket-policy.json"
aws --profile "$ADMIN_PROFILE" --region ap-south-1 s3api put-bucket-lifecycle-configuration \
  --bucket "$FLOW_BUCKET" --lifecycle-configuration "file://$SETUP_DIR/flow-log-retention.json"
)
```

These are dedicated NEW buckets. Never overwrite an existing unrelated bucket's
policy. Administrator bootstrap needs CreateBucket, PutBucketPublicAccessBlock,
PutEncryptionConfiguration, PutBucketVersioning, PutBucketPolicy,
PutLifecycleConfiguration, and corresponding verification reads on the approved
bucket ARNs. BucketOwnerEnforced disables ACLs; no object ACL grants are needed.
Do not add DeleteBucket or IAM-change rights to the Terraform runtime.

State bucket: SSE-S3 AES256, versioning Enabled, all four public blocks, TLS-only.
Its data-access deny permits only the runtime user and the explicit state admin
ARN. Admin may restore old versions; runtime cannot delete state or versions,
only its exact lock object. Native `use_lockfile=true` is already in main.tf;
no DynamoDB table. Do not configure lifecycle expiration on state versions
without a separately approved recovery/retention policy. The state administrator
must be correctly specified before installing its deny policy; wrong identity
can block recovery until an authorized administrator corrects the bucket policy.

Flow bucket: separate SSE-S3/versioned/private storage, TLS-only. Only the
service principal delivery.logs.amazonaws.com receives PutObject to
AWSLogs/229032674007/* and GetBucketAcl; SourceAccount and Mumbai logs SourceArn
conditions prevent cross-account/region confused-deputy use. It requires the
bucket-owner-full-control ACL header supported with BucketOwnerEnforced. The
runtime cannot read logs or alter the delivery policy. Proposed retention is
30 days for current/noncurrent log objects and 7 days for incomplete multipart
uploads, subject to explicit approval. Lifecycle expiry is asynchronous, not an
exact deletion timer. State and logs must not share lifecycle rules.

## 5. Read-only verification (after administrator setup)

```bash
export AWS_PROFILE=cloudsentinel-dev AWS_REGION=ap-south-1 AWS_PAGER=''
aws sts get-caller-identity
aws ec2 describe-availability-zones --filters Name=state,Values=available \
  --query 'AvailabilityZones[].{Name:ZoneName,Id:ZoneId,State:State,OptIn:OptInStatus}'
aws ec2 describe-vpcs --query 'Vpcs[].CidrBlockAssociationSet[].CidrBlock'
```

Check that the chosen AZ is enabled for THIS account. AZ letters can map to
different physical zones across accounts; record its AZ ID. Verify all VPC CIDRs
plus separately documented peering/VPN/on-premise address spaces. Do not infer
non-overlap from only host routes. Use an authorized inventory reader if the
runtime does not need access to organization-wide topology.

Use the approved administrator for bucket-protection reads; these are intentionally
not added to the minimal runtime state policy:

```bash
for BUCKET in "$STATE_BUCKET" "$FLOW_BUCKET"; do
  aws --profile "$ADMIN_PROFILE" --region ap-south-1 s3api get-bucket-location --bucket "$BUCKET"
  aws --profile "$ADMIN_PROFILE" --region ap-south-1 s3api get-bucket-versioning --bucket "$BUCKET"
  aws --profile "$ADMIN_PROFILE" --region ap-south-1 s3api get-bucket-encryption --bucket "$BUCKET"
  aws --profile "$ADMIN_PROFILE" --region ap-south-1 s3api get-public-access-block --bucket "$BUCKET"
  aws --profile "$ADMIN_PROFILE" --region ap-south-1 s3api get-bucket-ownership-controls --bucket "$BUCKET"
done
```

Expected region ap-south-1, versioning Enabled, AES256, BucketOwnerEnforced and all
four public blocks true. Inspect bucket policies and lifecycle locally without
printing any state or credentials. Review effective state and lock-object access
with the administrator; a new key normally has no state object yet, so a missing
GetObject is not proof of denied access. Terraform init/plan acquires/releases
locks and can write state/backend metadata: separately authorize this state use.

## 6. Cost and approvals

The declared VPC/subnets/IGW/routes/SGs add no EC2, NAT, public IPv4, EKS or LB
hourly resources. S3 storage, state versions, requests, and flow-log vended-log
ingestion/archival are usage-billed. Log cost depends on traffic and volume,
not merely having a small VPC. Monthly estimate = state/log GB-month × Mumbai S3
rate + PUT/GET requests × published rate + flow-log delivery GB × vended-log rate.
No workload volume, credit balance or account Free-plan eligibility is verified,
so a numeric total or zero-cost guarantee would be fabricated. Verify Billing
plan, remaining credits/expiry, account/service availability and a cost ceiling;
new-customer credit terms do not prove this particular account is free.

Required approvals, still missing:

1. Project ID, environment, enabled AZ and non-overlapping CIDRs.
2. Reviewed IAM attachment to the existing user, including the default-SG bootstrap
   strategy and log-delivery principal requirements; do not auto-broaden policies.
3. Creation of the TWO specifically named S3 buckets, policies, retention, admin
   identity and usage-cost ceiling. No bucket creation is approved by this task.
4. Remote backend initialization and one real plan with state/lock writes, following
   independent state protection and permission verification.
5. After review of that real plan, separate explicit authorization for the exact
   first apply (and any VPC-only bootstrap apply if that strategy was chosen).
   Any eventual destroy requires its own scope/recovery review.

No commands here authorize themselves. No pipeline, backend restart, Minikube,
Project 11/17, DAST configuration, IAM policy or AWS resource was changed.

Official sources:
- https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html
- https://servicereference.us-east-1.amazonaws.com/v1/ec2/ec2.json
- https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3-create-flow-log.html
- https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3-permissions.html
- https://developer.hashicorp.com/terraform/language/backend/s3
- https://aws.amazon.com/s3/pricing/
- https://aws.amazon.com/cloudwatch/pricing/
- https://aws.amazon.com/free/free-tier-faqs/
