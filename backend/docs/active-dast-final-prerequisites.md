# Active DAST execution prerequisites

Prepared by source inspection and offline tests only. These commands are for a
separately authorized operation; none were executed during preparation. Keep
`DAST_ACTIVE_ENABLED=false` throughout the containment diagnostic.

## Next bounded operation: restore and diagnose

Use the existing immutable archive, without rebuilding or registry resolution:

```bash
cd /home/hammad/CloudSentinel
export DAST_ACTIVE_ENABLED=false
printf '%s  %s\n' \
  3e3604f70c39e65b2637e179b1fc2835c7165e3ff7cc53636f07c3fb01e125f8 \
  /tmp/cs-zap-offline-cwa6clxp/assembly-1.tar | sha256sum --check --strict
```

Before import/provisioning, independently capture full Docker container/network
IDs and inspection records; require the established original nine containers and
four networks, not counts alone. Record `docker info`, `curl --fail
http://localhost:3000/api/health`, `pg_isready`, `minikube status -o json` and
`kubectl get pods -n cloudsentinel-p-17 -o json`. Require Project 17 readiness and
retain pod UIDs/restart counts. Check `ip -j -4 route show table all` and all Docker
network IPAM subnets. The allocator repeats overlap inspection before creating
each owned internal IPv4 network; no candidate subnet is asserted safe offline.

Require unused tag `cloudsentinel/zap-offline:verified-closure`, an absent
replacement image ID before importing, and no resources with scan label
`zpd-fast-20261016-a1`. Stop on collision, missing archive, changed baseline,
unhealthy workload or changed artifact. Verify the retained Python fixture,
Squid and Nginx pins described in `zap-containment-diagnostic.md`, and audited
native source/binary hashes through the existing staging verifier. Operator
UID/GID must be 1000:1000. Then perform exactly one import and one diagnostic:

```bash
docker load --input /tmp/cs-zap-offline-cwa6clxp/assembly-1.tar
docker image inspect sha256:c6b328f0dd03c127670d3b6802e74c89c1350addfd44abbfd4e90c36e5894550
DAST_ACTIVE_ENABLED=false node backend/scripts/zap-containment-diagnostic.js \
  --execute --scope zap-python-containment --scan zpd-fast-20261016-a1 \
  --project 18 --execution 1 --ttl 600
```

The CLI verifies image configuration/layers before provisioning. Project and
execution here are diagnostic labels, not enrollment. The lifecycle creates two
internal networks and four containers (Python, Squid, ZAP, namespace helper).
No fixture port is published. Existing native binary and policy/work mounts are
read-only and privately staged. The helper's live network namespace inode must
equal ZAP's; exact parent NIC/IP/MAC and ownership are inspected before/after.
Benign SQLi/XSS default requests, strict path/destination denials, same-socket
CONNECT, verbose direct TCP and IPv4/IPv6 route/address/listener checks run.
No Active Scan, spider or target beyond the disposable fixture is invoked.

Cleanup is in the diagnostic's finally path: helper, ZAP, then lifecycle-owned
fixture/gateway/networks and staging. Evidence is retained intentionally in a
0700 directory/0600 file. Independently compare original immutable resources,
Project 17 UIDs/restarts and health afterwards; require zero scan-owned resources
and staging leftovers. If the image was newly imported by this operation, remove
only its verified newly introduced tag/image after confirming no containers use
it; never force, prune, or remove the retained fixture/base. Image cleanup is an
operator responsibility; the CLI does not own imported images.

Diagnostic PASS proves shared-namespace helper behavior. It does not prove ZAP
application proxy use, genuine redirect following, scan rate enforcement,
completion/cancellation, or packet-level IPv6 prevention. The Python fixture
currently has no redirect endpoint. Diagnostic records cannot enter production
registration, even after PASS.

## Database and authorization (separate future approval)

012 requires existing users/projects/pipeline_executions and their earlier
migrations; 013 requires 012. Source schema tests cover composite execution
ownership, statuses including CLEANUP_FAILED, unique execution grants and atomic
single-use consumption. Live schema/drift/backup readiness has not been checked
or changed by this offline pass. After database backup and schema verification,
using an existing protected libpq connection configuration (no secrets on the
command line), the application order is:

```bash
psql -X -v ON_ERROR_STOP=1 --single-transaction \
  -f backend/migrations/012_active_dast_execution_records.sql \
  -f backend/migrations/013_active_dast_grants.sql
```

Operator enrollment, after verifying the intended existing owner, requires an
explicit numeric `operator_id` supplied to psql; there is no enrollment CLI:

```sql
INSERT INTO active_dast_operators(user_id,enabled)
SELECT id,TRUE FROM users WHERE id=:'operator_id'::integer
ON CONFLICT(user_id) DO UPDATE SET enabled=TRUE;
```

Verify exactly one intended row changed. This enables a security operator and
requires separate approval. Project ownership and exact execution association
are checked again on issuance/consumption; Project 17 is rejected.

Target enrollment is **not operationally wired**: the only implementation is
`activeRuntimeRegistry.enroll(pool, {projectId, executionId, userId},
{lifecycle, adapter, scanId})`. No production caller exists. It requires a genuine
READY Active lifecycle and verified catalog, and keeps that lifecycle in an
in-process registry. A standalone SQL insert or separate Node process cannot
replace it. A trusted same-backend-process provisioning/enrollment and
execution coordination entry point is required before a valid grant can be
issued and consumed by Module 2. Do not invent target rows or reuse diagnostic
resources. Execution identity must already exist; issuance is single-use and
expires within the enrolled target's short lifetime.

Once that entry point exists and returns a genuine target UUID, the existing
authenticated grant contract is:

```http
POST /api/dast/active/<projectId>/executions/<executionId>/grants
Authorization: Bearer <existing authenticated owner JWT>
Content-Type: application/json

{"targetId":"<server-enrolled target UUID>"}
```

Do not send pipeline-orchestrator credentials as operator authorization. Grant
issuance/rejection/consumption is audited; atomic consumption and uniqueness
protect replay/concurrency.

## Production gates and stage order

The production catalog still references the original ZAP base, has null ZAP
capabilities and `containmentAdapterValidated:false`. Future evidence-backed
registration must bind the replacement image's actual immutable identity, loaded
versions/seven rules and verified runtime contract. Never flip flags to bypass
missing evidence. Actual job completion, timeout/cancellation and rate/scope
enforcement still need controlled runtime validation; non-scanning API readback
does not establish them. The present catalog requires those proofs before
production enrollment, so the diagnostic is not an end-to-end scan launcher.
The production `trustedNetworkEvidence()` currently compares its observation's
scanner ID with the acceptance-client ID. Unlike this diagnostic, that check
does not bind shared-namespace evidence to the newly created production ZAP
container. Production must acquire and validate that binding before scan start;
promoting this diagnostic's result alone would not repair the interface.

Module 2 order remains SAST, dependencies, IaC, deployment, passive DAST, optional
Active DAST. A missing staging URL now records Active BLOCKED without consuming
a grant. Passive failure already terminates the pipeline. The real orchestrator
needs a successful deployment/staging baseline and its exact existing execution,
plus same-process enrollment/registration before Active invocation. There is no
safe executable first-scan command yet. Keep Active disabled until those gates
and migrations/enrollment are independently approved and satisfied.
