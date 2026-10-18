# ISOLATED_VPC — explicit target policy, not absence evidence

Modes: CONNECTED_NETWORK retains existing full external-evidence rules.
ISOLATED_VPC is account 229032674007 / ap-south-1 / development / network-only /
new VPC only. Project/environment state keys and durable CIDR leases remain required.
Protected projects 11/13/17 cannot prepare new infrastructure. No peering, transit,
VPN, Direct Connect, on-premise or cross-account network resources/route targets.
Approved existing public-subnet IGW default route remains permitted; this mode is
not a claim of no internet gateway. SGs remain deny-all and no compute is deployed.

Template inventory, route targets and VPC references are checked from trusted server
source; copied configuration hash now binds policy mode. Regional identity, VPC,
route, peering, VPN and transit-attachment reads are mandatory and fresh. Existing
VPC adoption/associations always block this new-VPC workflow and require separate
review, not inferred absence. Unexpected route targets/resources fail closed.

Account-wide external completeness is distinct from template/new-VPC isolation.
An independent new VPC cannot be attached by this allowlisted template, so Direct
Connect/other-region/on-premise account-wide absence is not required to claim only
that narrow TEMPLATE property. It is NOT waived silently or converted into
NOT_APPLICABLE. Unknown external CIDRs, subscription blockers and original source
records remain unchanged. Complete CONNECTED_NETWORK evidence still blocks as before.

Private unsigned package: /tmp/cs-isolated-network-review-E8X75o.
The sources.directConnect SERVICE_SUBSCRIPTION_BLOCKED evidence was copied intact.
Candidate pool stays 10.16.0.0/12 PROPOSED_NOT_APPROVED. Administrator ARN/timestamps
and signature remain absent. New networkPolicy fields declare mode, fixed scope,
newVpcOnly, existingVpcId=null, forbidden connectivity and explicit review decisions:

- administratorDecision APPROVE_ISOLATED_SCOPE (template currently PENDING)
- poolDecision APPROVE_CANDIDATE_POOL (currently PENDING)
- evidenceReference actual private review record
- acceptsUnverifiedAccountWideConnectivity true ONLY after real administrator review

These are design approvals, not assertions that unknown networks don't exist.
The existing local validate-network-review.js selects the narrower validator only
for explicit ISOLATED_VPC, still requires snapshot hash, fresh discovery, real
administrator timestamps/expiry, trusted signature mapping and pool non-overlap.
It never enables planning, approves pools or changes reservation status. Missing
signature/approval/freshness remains BLOCKED. Do not fabricate a trust mapping.

Signed-review/pool admission is now implemented; see signed-network-admission.md.
Planner and runner require admitted, current, signed scope; gate enablement alone
cannot bypass missing admission. This prevents treating the local document validator as production
authorization. CONNECTED_NETWORK runner behavior is unchanged. Real gates remain off.
Temporary reservations remain RESERVED_UNVERIFIED. No new reservation created.
Permanent deployed allocation conversion remains future work before apply.

Next: authenticated administrator reviews precise target-scope restrictions, known
network overlap, candidate pool and unknown-source acknowledgement; completes and
signs evidence via approved identity/key mapping. Refresh the snapshot read-only;
validate locally. Then implement/test actual approval admission before separately
requesting real planning authorization. Apply remains unavailable.
