'use strict';
function validate(review,snapshot,now=Date.now()){
 const blockers=[],p=review.networkPolicy||{};
 if(p.mode!=='ISOLATED_VPC'||review.account!=='229032674007'||review.region!=='ap-south-1'||p.template!=='network-only'||p.newVpcOnly!==true||p.existingVpcId!==null)blockers.push('ISOLATED_SCOPE_INVALID');
 for(const k of ['peering','transit','vpn','directConnect','onPremiseRouting','crossAccountConnectivity'])if(p.allowedConnectivity?.[k]!==false)blockers.push('CONNECTIVITY_CONSTRAINT_MISSING');
 if(!/^arn:aws:iam::229032674007:(user|role)\/[\w+=,.@/-]+$/.test(review.administratorArn||''))blockers.push('ADMINISTRATOR_IDENTITY_MISSING');
 for(const [name,value] of [['reviewedAt',review.reviewedAt],['expiresAt',review.expiresAt]])if(!Number.isFinite(Date.parse(value)))blockers.push('REVIEW_TIMESTAMPS_INVALID');
 if(Date.parse(review.reviewedAt)>now||now-Date.parse(review.reviewedAt)>86400000||Date.parse(review.expiresAt)<=now||Date.parse(review.expiresAt)>now+86400000)blockers.push('REVIEW_EXPIRED_OR_INVALID');
 if(!snapshot?.coreVerified||!Number.isFinite(Date.parse(snapshot.observedAt))||now-Date.parse(snapshot.observedAt)>300000||Date.parse(snapshot.observedAt)>now)blockers.push('DISCOVERY_STALE_OR_MISSING');
 for(const op of ['get-caller-identity','describe-vpcs','describe-route-tables','describe-vpc-peering-connections','describe-vpn-connections','describe-transit-gateway-attachments'])if(snapshot?.coverage?.[op]!=='READ')blockers.push('MANDATORY_ISOLATION_DISCOVERY_MISSING');
 if(p.administratorDecision!=='APPROVE_ISOLATED_SCOPE'||!p.evidenceReference||p.poolDecision!=='APPROVE_CANDIDATE_POOL')blockers.push('ISOLATED_SCOPE_OR_POOL_APPROVAL_MISSING');
 if(p.acceptsUnverifiedAccountWideConnectivity!==true)blockers.push('REDUCED_SCOPE_ACKNOWLEDGEMENT_MISSING');
 return {accepted:!blockers.length,blockers}; // Signature verification remains mandatory in existing CLI. Never grants planning readiness.
}
module.exports={validate};
