# Network discovery readiness — BLOCKED, no AWS mutations

Current private evidence: /tmp/cs-discovery-readiness-3D7QgT/discovery.json and
pool-review.json. Account 229032674007, ap-south-1, runtime cloudsentinel-dev.

DescribeVpnConnections and DescribeTransitGatewayRouteTables both returned
UnauthorizedOperation (ACCESS_DENIED). They are not absent/empty or unsupported.
DescribeVpcPeeringConnections and DescribeTransitGatewayAttachments returned EMPTY
(count 0). Two visible VPCs (10.0.0.0/16 and 172.31.0.0/16) and four route tables
were read. Empty local attachment lists do not prove external/account-wide absence.
VPN existence remains UNKNOWN; transit route-table existence UNKNOWN. No route
search was attempted without a discovered route-table ID. Direct Connect, remote
accounts, on-premise BGP and planned networks require external evidence.

Proposed amendment: terraform/docs/policies/network-discovery-amendment.json.
Only ec2:DescribeVpnConnections and ec2:DescribeTransitGatewayRouteTables, Resource
"*", aws:RequestedRegion ap-south-1. AWS does not support resource ARN scoping for
these two Describe actions. No ec2:* or administrator policy needed. Administrator
may review/attach ONLY under separate IAM-change authorization; nothing attached.

If actual transit tables are discovered, prepare a SEPARATE exact-resource Allow:

    Action: ec2:SearchTransitGatewayRoutes
    Resource: arn:aws:ec2:ap-south-1:229032674007:transit-gateway-route-table/<actual-ID>
    Condition: StringEquals aws:RequestedRegion=ap-south-1

Use real approved table IDs; no permanent wildcard required. Existing runtime
DescribeVpcs/RouteTables/Peering/TransitGatewayAttachments permissions already read
successfully. Shared/remote tables require review with their owning account; don't
invent ARNs or widen permissions. No unsupported search against fabricated IDs.
Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html

Proposed pools (NOT configured/approved): 10.16.0.0/12 or 10.32.0.0/12. Both are
canonical /12s, exclude deployed Project13 10.0.0.0/16 and visible 172.31.0.0/16,
and have no conflict with the inspected local active ledger (0 reservations).
External overlap remains unverified. Prefer ONE reviewed pool, not both by default.
After explicit administrator review, configuration proposal is:

    INFRA_CIDR_POOLS='["10.16.0.0/12"]'

No environment configuration or restart performed. Preserve
INFRA_REAL_PLAN_ENABLED=false and INFRA_REMOTE_PLAN_AUTHORIZED=false.
Unknown other-runtime overrides/stores require review before using this evidence.

Administrator evidence schema (private 0600 document, real authenticated identity):

    {
      "account":"229032674007", "region":"ap-south-1",
      "administratorArn":"<actual IAM user/role ARN including :user/ or :role/>",
      "reviewedAt":"<ISO timestamp>", "expiresAt":"<explicit ISO deadline <=24h>",
      "sources":{
        "vpn":{"status":"UNKNOWN","cidrs":[],"evidenceReference":"<private review reference>"},
        "transit":{"status":"UNKNOWN","cidrs":[],"evidenceReference":"<reference>"},
        "peering":{"status":"UNKNOWN","cidrs":[],"evidenceReference":"<reference>"},
        "directConnect":{"status":"UNKNOWN","cidrs":[],"evidenceReference":"<reference>"},
        "remoteAccounts":{"status":"UNKNOWN","cidrs":[],"evidenceReference":"<reference>"},
        "onPremise":{"status":"UNKNOWN","cidrs":[],"evidenceReference":"<reference>"},
        "plannedNetworks":{"status":"UNKNOWN","cidrs":[],"evidenceReference":"<reference>"}
      },
      "unknownRanges":["<unverifiable or undisclosed ranges/source descriptions>"]
    }

This example intentionally FAILS validation. UNKNOWN is never treated as empty.
Use VERIFIED only with actual complete source evidence/ranges; NOT_APPLICABLE needs
an administrator-reviewed absence rationale/reference and empty cidrs. Include
static and BGP advertised VPN ranges, transit/peering remote ranges, Direct Connect,
organization/on-premise allocations and planned networks. Missing/unknown sources,
expired evidence, API denials, truncation, unresolved prefix-list routes all block.
Local validator networkDiscoveryEvidence.validateExternalEvidence assesses document
shape/freshness plus current API coverage; it does NOT authenticate an administrator,
issue approval, mutate discovery.complete, enable planning or upgrade reservations.
A future approval integration must independently authenticate author and scope.

Discovery handlers now distinguish EMPTY/NONEMPTY, ACCESS_DENIED, UNSUPPORTED_API,
ABSENT_RESOURCE, TIMEOUT and FAILED with safe AWS error codes; raw stderr, encoded
authorization messages and secrets are withheld. Transit search covers active and
blackhole routes, detects incomplete search results and preserves earlier failures
across tables. Existing VPN routes trigger BGP-completeness blocker. Unresolved
managed prefix-list destinations explicitly block completeness.

Next administrator action: review the TWO-action amendment and, with separate IAM
approval, grant these read permissions or supply trustworthy read-only exports.
Then repeat only missing discovery and collect external network attestations.
Approve one pool only after all overlap sources are reviewed. Keep every current
CIDR RESERVED_UNVERIFIED and all live planning/apply gates disabled.
