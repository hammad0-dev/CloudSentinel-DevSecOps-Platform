# Signed administrator network review admission

Code implemented; NO real administrator trust/key, review, pool approval or
reservation created in development. Live Terraform flags remain disabled. Apply
always rejects. Test fixtures use ephemeral Ed25519 keys in temporary directories.

Existing JWT auth is reused. Administrator privilege is NOT inferred from a JWT
role or username. Independently configure an owned, regular, private (0600) file
at INFRA_NETWORK_REVIEW_TRUST_FILE with version 1:

    {
      "version":1,
      "administratorUserIds":[<actual authenticated application administrator ID>],
      "keys":[{
        "id":"<unique independently approved key ID>",
        "administratorArn":"<actual authorized IAM user/role ARN>",
        "userIds":[<application administrator ID>],
        "publicKeyPem":"<approved Ed25519 public PEM, escaped newlines>",
        "sha256":"<SHA256 of exact PEM bytes>",
        "expiresAt":"<explicit valid ISO expiry>", "revoked":false
      }]
    }

This replaces the offline CLI's older single-key mapping for SERVER admission.
Do not invent identities or create/approve keys automatically. An operator verifies
application identity, actual administrator authority and key fingerprint out-of-band.
No access key/password/private signing key belongs in this file or browser.
Trust is reread on every admission and execution; key expiry, revocation/removal
or administrator allowlist removal immediately prevents future verification.
Missing configuration fails closed. Shared-storage multi-host limitations below.

Authenticated administrator-only API (existing /api/infrastructure mount):
POST /admin/network-reviews/:projectId/challenge with {}.
POST /admin/network-reviews/:projectId/admit with
{"keyId":"<approved-key>","reviewBase64":"<EXACT signed JSON bytes base64>",
 "signatureBase64":"<64-byte Ed25519 detached signature base64>"}.
POST /admin/network-reviews/:projectId/revoke with {"reviewId":"<admission ID>"}.
Owner-only GET /:projectId/review-status returns safe scope/expiry/signature status.
Non-administrator denial occurs before project lookup/discovery on admin routes.
Protected projects 11/13/17 cannot obtain a new-VPC review challenge.

Genuine signing procedure (not executed):
1. Log in using the existing genuine administrator login; store session privately.
   Use an already-approved authenticated HTTP client; don't print the bearer token.
2. Request a challenge. Server collects mandatory fresh discovery, pins project and
   current owner, development state key, trusted template digest and snapshot hash.
3. Complete a real review with unique reviewId and returned challengeId, projectId,
   ownerId, environment, stateKey, templateHash, discoveryEvidence.reference.sha256.
   Preserve account/region/mode constraints and all original source statuses.
4. Isolated schema must explicitly approve scope and pool; candidatePool is
   {"cidr":"<reviewed canonical /12>","status":"APPROVED_FOR_ISOLATED_SCOPE"}.
   Include scopeException {"sources":["directConnect","remoteAccounts","onPremise",
   "plannedNetworks"],"reason":"<actual documented new-VPC-only rationale>"}.
   Direct Connect SERVICE_SUBSCRIPTION_BLOCKED and other UNKNOWN statuses remain;
   acceptance NEVER asserts absence or connected completeness. Add real ARN,
   reviewedAt/expiresAt and private evidenceReference. No arbitrary source waivers.
5. With the EXISTING approved administrator private Ed25519 key, locally:

       umask 077
       openssl pkeyutl -sign -rawin -inkey /approved/private/admin-ed25519.pem \
         -in /approved/private/review.json -out /approved/private/review.sig

   No key generation step is supplied. Package exact review/signature bytes in the
   API body and submit with the actual administrator session. Never regenerate JSON
   between signing and Base64 packaging. Client paths/keys are never accepted.

Challenge validity is 5 minutes; admitted expiry is earliest review/challenge expiry,
never renewed. Snapshot hash matches server-retained exact bytes. Fresh network
fingerprint and trusted template digest must still match on admission/execution.
Changes conservatively invalidate review, including benign AWS ordering differences.
A new authenticated challenge/review is required after changes/expiry. Successful
admission atomically consumes challenge and reviewId (replay rejected). Concurrent
admission admits at most once; no automatic retries. Full signed bytes/signature,
checksums, expiry/scope and audit events are private, never serialized to owner UI.

Store INFRA_REVIEW_ADMISSION_ROOT (default ~/.cloudsentinel/network-reviews), 0700,
ledger 0600, global O_EXCL file lock and atomic rename. Audit records challenge,
admission and explicit revocation events. Denied requests use safe API errors;
no raw secrets logged. A stale crash lock requires explicit operator investigation,
not automatic deletion. One shared durable filesystem required across instances;
separate roots DO NOT provide cluster-wide replay protection. Production database
locking/revocation replication would require separately approved migration/work.

Planner AND runner verify admission independently. Execution checks current DB owner,
trusted keys, signatures, expiry, original bytes, template digest, fresh discovery
fingerprint, explicit pool containment and known/reserved CIDR overlap. Durable
reservation lease still required; no approval creates a reservation. Runner requires
>=240 seconds review validity before starting, and rechecks before remote init.
Signed-review admission replaces only the isolated account-wide completeness demand;
CONNECTED_NETWORK still requires full connected evidence. Separate real-plan
administrator authorization, state/IAM/FlowLog permissions, toolchain/mirror trust,
credentials and deadline checks all remain mandatory. Current gates stay false.

Known prerequisites: independently configured real administrator identities/keys,
fresh actual signed evidence and pool review, short remaining challenge window,
shared durable replay store, reviewed provider/S3/IAM prerequisites, no apply support.
Neither these instructions nor a local validation PASS authorizes live Terraform.
