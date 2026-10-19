'use strict';
const requiredSources=['vpn','transit','peering','directConnect','remoteAccounts','onPremise','plannedNetworks'];
function validateExternalEvidence(e,snapshot,now=Date.now()){
 const blockers=[];
 if(!e)return {accepted:false,blockers:['ADMINISTRATOR_EVIDENCE_MISSING']};
 if(e.account!=='229032674007'||e.region!=='ap-south-1'||!/^arn:aws:iam::229032674007:(user|role)\/[\w+=,.@/-]+$/.test(e.administratorArn||''))blockers.push('ADMINISTRATOR_IDENTITY_OR_SCOPE_INVALID');
 if(!Number.isFinite(Date.parse(e.expiresAt))||Date.parse(e.expiresAt)<=now||Date.parse(e.expiresAt)>now+86400000||!Number.isFinite(Date.parse(e.reviewedAt))||Date.parse(e.reviewedAt)>now||now-Date.parse(e.reviewedAt)>86400000)blockers.push('EVIDENCE_EXPIRED_OR_INVALID');
 for(const source of requiredSources){const s=e.sources?.[source];if(!s||!['VERIFIED','NOT_APPLICABLE'].includes(s.status)||!Array.isArray(s.cidrs)||typeof s.evidenceReference!=='string'||!s.evidenceReference.trim())blockers.push(`${source.toUpperCase()}_UNVERIFIED`);else{try{for(const c of s.cidrs){if(typeof c!=='string'||!/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(c))throw Error();require('./infrastructurePlanning').collision('10.0.0.0/16',[c]);}if(s.status==='NOT_APPLICABLE'&&s.cidrs.length)throw Error()}catch{blockers.push(`${source.toUpperCase()}_CIDRS_INVALID`)}}}
 if(!snapshot?.coreVerified||['get-caller-identity','describe-vpcs','describe-route-tables','describe-vpc-peering-connections','describe-transit-gateway-attachments','describe-vpn-connections','describe-transit-gateway-route-tables'].some(op=>snapshot?.coverage?.[op]!=='READ')||Object.values(snapshot?.coverage||{}).some(s=>s!=='READ')||!Number.isFinite(Date.parse(snapshot?.observedAt))||Date.parse(snapshot.observedAt)>now||now-Date.parse(snapshot.observedAt)>300000||(snapshot.blocked||[]).some(b=>/PREFIX_LIST|BOUND_EXCEEDED|TRANSIT_ROUTES/.test(b)))blockers.push('AWS_DISCOVERY_INCOMPLETE_OR_STALE');
 if(e.unknownRanges?.length||!Array.isArray(e.unknownRanges))blockers.push('UNKNOWN_EXTERNAL_RANGES');
 return {accepted:blockers.length===0,blockers}; // Assessment only; never enables planning or changes reservation states.
}
module.exports={validateExternalEvidence,requiredSources};
