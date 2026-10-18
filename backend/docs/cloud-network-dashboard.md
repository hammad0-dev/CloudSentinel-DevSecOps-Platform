# Cloud network inventory

GET /api/cloud/projects/:projectId/network requires the existing JWT authentication
and projects.user_id ownership. Authorization precedes AWS reads. No database
migration, persistence, state access, Terraform invocation or AWS mutation occurs.

The backend uses the existing AWS CLI with bounded execFile calls (no shell),
profile CLOUD_AWS_PROFILE (default cloudsentinel-dev), region CLOUD_AWS_REGION
(default ap-south-1), account CLOUD_AWS_ACCOUNT_ID (default 229032674007).
The backend process owner needs valid credentials for that profile and AWS CLI.
Never put credentials in frontend environment variables.

Read permissions: sts:GetCallerIdentity; ec2:DescribeVpcs, DescribeSubnets,
DescribeRouteTables, DescribeSecurityGroups, DescribeInternetGateways,
DescribeFlowLogs. Existing runtime network-read policies cover EC2 reads.

Discovery requires ProjectId=<authorized project>, Module=8-network and
ManagedBy=Terraform tags. VPC-bound child resources are ownership checked.
Only tagged route tables are included, excluding AWS-created untagged main
route tables. This is a scoped inventory, not an exhaustive security audit.
Ambiguous VPCs, account mismatches and failed/incomplete AWS reads yield an
unavailable status; no successful cached fallback or historical live claim.
AWS status is observed on page selection, not continuously monitored. Terraform
provenance is inferred from ownership tags, not verified by reading state.
GCP, Azure and security assessment findings remain not connected/configured.

Restart the backend under separately authorized normal operations to register
the new route; load the rebuilt frontend through the existing hosting process.
No restart was performed during implementation.
