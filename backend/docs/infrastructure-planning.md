Current runner implementation and activation contract: see terraform-plan-runner.md.
The preparation-only notes below describe the default disabled-gate behavior; the
controlled production runner is now available behind BOTH explicit server gates.

# Registered-repository infrastructure preparation

Implemented: authenticated owner-only GET /api/infrastructure/:projectId and
POST /analyze, /plan, /approve. POST /apply always rejects. No webhook integration.
The existing Cloud selector scopes the workflow. Analyze reads only bounded
GitHub manifests at an immutable commit using the registered repository URL and
server-held token; no clones, package installation, repository Terraform or code
execution. One/two/three-tier/custom are recommendations, not deployable apps.
Manifest hints are incomplete (no arbitrary code inference); confirmation required.

Production /plan currently PREPARES CONFIGURATION ONLY. It does not execute
Terraform, validate provider authentication, scan IaC or produce a saved plan.
Status stays ANALYZED, configuration PREPARED_NOT_PLANNED. The injected runner
used by offline tests is NOT exposed through configuration or the browser.
Real apply is disabled regardless of approval. No cloud operation was executed.

Server prerequisites: INFRA_STATE_BUCKET and INFRA_FLOW_LOG_BUCKET_ARN must identify
approved existing protected buckets. INFRA_RESERVED_CIDRS is a server-controlled
JSON array of known connected/reserved networks. Collision checks reject these,
but completeness must be independently verified before enabling any real planner.
Default empty inventory is NOT evidence of no collisions. New keys are
cloudsentinel/projects/<id>/development/network/terraform.tfstate, never the deployed
Project 13 key. Projects 11, 13, 17 cannot prepare modifications. Other projects
are eligible for analysis, not automatically authorized for AWS creation.

Private durable filesystem records at INFRA_ARTIFACT_ROOT (default
~/.cloudsentinel/infrastructure), directories 0700, metadata 0600; atomic rename,
exclusive per-project job locks, no browser file paths. Keep storage persistent
and backed up. Lock after a crash intentionally blocks: administrator must inspect
job/process state before manually recovering it; no automatic stale-lock removal.
Not suitable for multiple backend hosts without shared locking/database migration.
No database migration is applied or required for this single-host implementation.

Configuration hashes cover generated JSON and copied module source. Mock-tested
real-plan review contract: validation, IaC, collision/account/lock evidence mandatory,
create-only resource allowlist/project identity, SHA256 exact plan, 15-minute review
expiry, current repository commit check and one approval maximum. Saved mock plan
files are 0400 and never returned to browser. The controlled runner now exists; see terraform-plan-runner.md.
NOT_CONFIGURED/ANALYZED are real preparation states. PLANNED/AWAITING_APPROVAL are
reserved for a verified real runner (tested via mocks); APPLYING/APPLIED/FAILED/
VERIFICATION_PENDING constants are future executor states, not deployed behavior.

Before real planning: add and test a controlled runner with bounded process-group
termination; terraform init without migration on the approved new key; pinned
provider lock/checksums; terraform validate and offline IaC scanning; complete
AWS/connected-network CIDR inventory and global reservation locking; refreshable
short-lived AWS credentials, exact per-project ABAC and S3 permissions; fail closed
on auth expiry/lock failures. Never use the historical Project 13 plan for new IDs.

Before apply: separately authorize VPC-only bootstrap in SAME state, inspect actual
new default SG and grant temporary exact-SG tag/revoke access; produce a fresh full
plan afterward. No permanent wildcard SG takeover. Add tested single-use execution
approval, fresh state lineage/serial check, revalidation of all artifact hashes,
deadline/cancellation, durable failure recording and ownership-safe recovery.
Current review approval cannot authorize apply. Do not enable apply without this.

Activation requires separately managed backend restart; frontend Vite HMR/build
normal process. No restart, migration or AWS mutation performed by this task.

## Architecture analysis revision

Recommendations use detected component roles, not a count of all Compose services.
HTML source must contain an HTML document marker. JS and Python manifest dependency
names identify UI/backend/client roles; PostgreSQL/Redis clients remain dependencies,
not confirmed servers. Simple Compose services/image declarations identify declared
services only. Top-level volumes/networks do not count as services. YAML anchors,
interpolation and advanced syntax remain explicitly unverified. Missing role evidence
returns unknown/low confidence even if a language or Dockerfile exists. Custom is
reserved for ambiguous multi-service declarations. Every decision includes its
reason and file-level evidence; all require user confirmation. Reanalyze historical
records explicitly; existing records are not silently rewritten.

CIDR checks POST /api/infrastructure/:id/cidr-check read local INFRA_RESERVED_CIDRS
plus visible AWS VPC/route/peering inventory with bounded AWS CLI requests. Responses
return only conflict/check status, not unrelated project resource IDs. No CIDR is
allocated or reserved, and no default 10.0.0.0/16 is suggested. A clear visible-range
check is not complete connected-network discovery (VPN/transit/on-premise remote
ranges require verification). Real planning remains disabled; the test-only runner
now also requires connectedDiscoveryComplete and cidrReserved. Configuration records
explicitly state TENTATIVE_NOT_RESERVED, and old records display unverified status.
