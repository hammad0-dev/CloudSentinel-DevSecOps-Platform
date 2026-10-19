# AWS discovery and local CIDR reservation

No real Terraform planning/apply enabled. No AWS resource mutation. The existing
owner-authorized infrastructure routes expose:

- GET /api/infrastructure/:projectId/cidrs — discover and propose; never reserves.
- POST /cidrs/reserve {"cidr":"10.x.0.0/16"} — explicit one-hour local reservation.
- POST /cidrs/release {"reservationId":"<owned reservation UUID>"} — explicit release.
- Existing /cidr-check now shares the same discovery service.

Set INFRA_CIDR_POOLS to an administrator-approved JSON array, e.g.
["10.16.0.0/12"], ONLY if that pool has actually been approved. No default pool is
silently allocated. Canonical 10/8 pools /8 through /16 yield deterministic /16s,
excluding INFRA_RESERVED_CIDRS, visible discovered networks and active reservations.
Never include or repurpose Project 13's deployed 10.0.0.0/16.

Discovery verifies STS account 229032674007 and fixes region ap-south-1; reads VPCs
and IPv4 associations, route tables, both sides of peering, VPN static routes,
TGW attachments/route tables and bounded active TGW routes. Max 20 transit tables,
1000 routes per table: truncation/permission failures are explicit incomplete
coverage. Default routes are not allocations. On-premise BGP, other accounts,
transit peering remote inventories and future networks cannot be proven complete
by these APIs. Therefore complete is always false in this automatic discovery.
Read-only IAM needs the relevant EC2 Describe* and SearchTransitGatewayRoutes.
Missing permissions are reported; this implementation grants none.

Snapshots/internal ranges stay server-side; UI gets only candidate/conflict status,
coverage operation names and its own reservation. No unrelated resource IDs,
project owners, secrets or kubeconfig. Unavailable account/VPC/routes prevents new
reservations. Partial connected discovery can support a LOCAL reserved-unverified
range, never a real-plan readiness claim. Raw AWS errors are withheld.

Store: INFRA_CIDR_RESERVATION_ROOT, default ~/.cloudsentinel/cidr-reservations.
Owned 0700 directory, 0600 validated records, O_EXCL global lock and atomic rename.
This serializes all projects sharing this store. Multi-host use requires genuinely
shared atomic storage or a separately approved database locking migration.
Duplicate same-owner/project/environment/CIDR reserve is idempotent and DOES NOT
extend expiry. A different active CIDR for same project is rejected. All historical
reservations remain in the ledger after expiration/release. Expired ranges become
eligible only for a NEW explicit reserve request with fresh discovery; no auto
renewal. Protected projects 11/13/17 cannot reserve new ranges.

Crash recovery: the lock intentionally remains after a process crash. Administrator
must confirm no live writer, back up the private ledger, validate record integrity
and explicitly authorize removal of that specific stale lock; no automated lock
stealing or arbitrary filesystem cleanup. Expired reservation recovery uses normal
authenticated reserve endpoint. Ownership transfer may require administrator review
or waiting for expiry. The UI Analyze action never reserves/renews.

Production runner additionally requires durable active reservation with at least
240 seconds remaining, plus existing administrator approval and complete connected
inventory attestations. All live gates remain disabled. Before ever enabling apply,
convert reservations to deployed allocation records that cannot expire/release;
this lifecycle is not implemented because apply remains unavailable. Do not treat
one-hour local reservations as permanent AWS allocations.

Read-only verification on this environment: STS, VPCs, route tables, peering and TGW
attachments readable. VPN and TGW route-table discovery unavailable. Visible ranges
include Project 13 10.0.0.0/16 and existing 172.31.0.0/16; full discovery BLOCKED.
No real CIDR reservations were created by this implementation; tests use private
short-lived fixtures and mocked AWS. No backend restart was performed.
