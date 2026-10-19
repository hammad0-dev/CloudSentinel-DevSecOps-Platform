# Module 8 network-only preparation

Status: source preparation, never an apply/destroy. The existing aws-demo/EKS/NAT
module is unrelated and must not be initialized or executed for this phase.
Neither backend code, security gates, DAST configuration nor Minikube is changed.

## Topology and scope

`environments/aws-network` calls only `modules/aws-network`. Defaults: VPC
10.0.0.0/16, public subnet 10.0.1.0/24, private subnet 10.0.2.0/24. Both subnets
share one explicitly selected enabled Mumbai AZ. A public route table has
0.0.0.0/0 to the IGW. The private table has only AWS's implicit local VPC route.
VPC flow logs capture ALL traffic with a 60-second aggregation interval to a separately approved existing S3 log bucket. No NAT, instances, EKS, EIPs, IPv6, endpoints or load balancers. Public IP assignment
is false even in the public subnet. Two dedicated SGs and the *new* VPC's default
SG have no ingress/egress. Subnet membership alone does not attach an SG to future
workloads. Future workload permissions require separate design and review.

Every managed resource has Project, ProjectId, Environment, Module and ManagedBy
tags. Project ID has no default, must be approved, and excludes protected projects
11/17. Confirm the /16 does not overlap other networks before planning. The only
outputs are AWS network IDs. No kubeconfig, credentials or state output.

Terraform >=1.16.6,<1.17.0; official hashicorp/aws ~>5.100.0. Commit the generated
.terraform.lock.hcl checksum lock. Account and region are pinned to 229032674007
and ap-south-1; authentication uses the named cloudsentinel-dev profile. Do not
use root, credential arguments, skip-account checks, or a local-state fallback.

## Safe source validation (performed without remote state)

    terraform fmt -check terraform/modules/aws-network terraform/environments/aws-network
    terraform -chdir=terraform/environments/aws-network init -backend=false -input=false
    terraform -chdir=terraform/environments/aws-network validate

`init -backend=false` downloads the official provider and initializes the local
module only. It does not approve or initialize S3, create AWS resources or produce
a deployable plan. Provider binaries under .terraform are Git-ignored; the lock
file is intentionally tracked. State, plans and real tfvars/backend files are
ignored. Never print or commit a plan/state: both can contain sensitive values.

## Separate state bootstrap — approval required, NOT performed

No state bucket name or project state key is currently approved. The partial S3
backend intentionally cannot initialize without those choices. An authorized
state administrator must provision a dedicated private bucket *outside* this
network stack, using AWS CLI/console or an independently managed bootstrap stack.
A CLI bootstrap has no Terraform state dependency, removing circular ownership.
Do not let the network stack own, destroy or replace its own state store.

Required configuration, verified before remote init:

1. Dedicated globally unique bucket in account 229032674007, ap-south-1.
2. All four S3 public-access-block settings true; BucketOwnerEnforced ownership
   (ACLs disabled); versioning Enabled; default SSE-S3 AES256 encryption.
3. Bucket policy denies insecure transport and grants no public access. Access
   restricted to explicitly approved runtime and state-administrator identities,
   exact state prefix and lock object. Runtime IAM must not allow changing bucket
   protections, deleting the bucket or deleting version history. Account-level
   controls/SCPs and bucket policies must also allow the intended operations.
4. Version retention/recovery policy approved; do not auto-expire all old state
   versions. Backups and access audits retained according to the owner's policy.
5. Use default Terraform workspace and a unique project/environment state key.
   Reusing a key for another project is prohibited. Cross-check ProjectId tfvars
   with the state-key project segment before any plan.
6. Bucket encryption/versioning/access controls and S3 lockfile read/write/delete
   permissions verified by the state administrator. No fake lock or force-unlock.

Copy state.backend.hcl.example to an ignored *.backend.hcl outside Git, replace
both placeholders, and protect it and any real tfvars with 0600. Do not embed
secrets. Following *separate approval* of bucket, project, AZ, IAM and state access:

    export AWS_PROFILE=cloudsentinel-dev AWS_REGION=ap-south-1
    terraform -chdir=terraform/environments/aws-network init -reconfigure -input=false -backend-config=/private/approved.backend.hcl
    terraform -chdir=terraform/environments/aws-network plan -input=false -lock-timeout=60s -var-file=/private/approved.tfvars -out=/private/network.tfplan

No apply/destroy command is part of this task. A real plan acquires/releases an S3
lock object, so it requires authorized state-object writes even though it does not
provision network resources. Never use -lock=false or substitute local state.

## IAM requirements

See aws-network-permissions.json for the finite operation set. It is an action
inventory for administrator review, NOT an installed IAM policy. Describes need
Resource "*" because EC2 describes generally lack resource-level scoping; restrict
aws:RequestedRegion to ap-south-1. Scope mutations to this account/region and the
approved project tags/resource ARNs; use aws:RequestTag at creation and
aws:ResourceTag/ec2:ResourceTag on supported subsequent operations. EC2 creation
and associations authorize multiple related resource types; administrator must
check each action's supported condition keys and related VPC/subnet/route/SG ARNs
before producing a policy. Do not blindly apply a universal tag condition to
unrelated resource types. Flow-log publication additionally needs logs:CreateLogDelivery and logs:DeleteLogDelivery (AWS documents Resource "*" for these delivery operations); review the publishing principal requirements before deployment. No ec2:*, iam:*, AdministratorAccess or iam:PassRole is
needed for this configuration. SG authorize permissions are deliberately absent:
this phase never adds traffic rules, only revokes defaults.

Backend runtime: ListBucket restricted to exact state prefix; GetObject/PutObject
on the exact state key, GetObject/PutObject/DeleteObject on its .tflock key.
Deleting state itself is unnecessary. SSE-S3 requires no KMS key permissions. If
an organization mandates SSE-KMS, a separately approved key/policy and Encrypt,
Decrypt, GenerateDataKey permissions are needed before changing this design.

State administrator bootstrap permissions (separate identity): s3:CreateBucket,
s3:PutBucketVersioning, s3:PutEncryptionConfiguration,
s3:PutBucketPublicAccessBlock, s3:PutBucketOwnershipControls, s3:PutBucketPolicy,
s3:PutBucketTagging, and corresponding reads (GetBucketLocation,
GetBucketVersioning, GetEncryptionConfiguration, GetBucketPublicAccessBlock,
GetBucketOwnershipControls, GetBucketPolicy, GetBucketTagging). Bucket deletion
or IAM policy changes are not authorized by this preparation task.

Observed preflight: STS identity succeeds; ec2:DescribeVpcs is explicitly denied
by the account's current IAM permissions. iam:SimulatePrincipalPolicy is also
denied, so mutation and state permissions remain UNVERIFIED, not inferred denied
or allowed. No IAM policies were changed. A state bucket is not approved.

## Cost and security limitations

No hourly compute, NAT, EIP, EKS or LB resources are declared. S3 state storage,
versions, requests and any future audit/log storage can incur charges. Networking
traffic and future services may also incur charges; free-plan eligibility,
remaining credits and expiry must be verified in Billing. No zero-bill guarantee.
VPC flow logging is declared after the initial scanner identified AVD-AWS-0178. It requires an approved private encrypted S3 log bucket, source-scoped delivery.logs.amazonaws.com bucket policy, retention and budget, all provisioned separately. Do not give the runtime broad s3:PutBucketPolicy permission or rely on automatic policy creation. Verify the preconfigured destination and delivery policy before planning. Flow-log ingestion and S3 log storage/requests can incur charges. No ignore/suppression or scanner threshold was changed. Review retained scanner results before first apply.

Sources:
- https://developer.hashicorp.com/terraform/language/backend/s3
- https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html
- https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html
- https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3-create-flow-log.html
- https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3-permissions.html
- https://aws.amazon.com/vpc/pricing/
- https://aws.amazon.com/s3/pricing/
- https://aws.amazon.com/free/free-tier-faqs/
