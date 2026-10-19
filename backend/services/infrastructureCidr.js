'use strict';
const {discover}=require('./awsNetworkDiscovery');
async function checkCidr(cidr,run){
 const {collision}=require('./infrastructurePlanning'),{valid}=require('./cidrReservations');
 if(!valid(cidr))throw Object.assign(Error('Use a canonical 10.x.0.0/16 CIDR'),{safe:true,status:400});
 const d=await discover(run),base={cidr,reserved:false,connectedDiscoveryComplete:false,realPlanningAllowed:false,observedAt:d.observedAt,coverage:d.coverage,outcomes:d.outcomes,blockedCoverage:d.blocked};
 try{const local=JSON.parse(process.env.INFRA_RESERVED_CIDRS||'[]');if(!Array.isArray(local))throw Error('Local ranges');return {...base,status:collision(cidr,[...local,...d.ranges])?'COLLISION':d.coreVerified?'VISIBLE_RANGES_CLEAR_NOT_RESERVED':'UNVERIFIED',localRangesChecked:true,awsInventoryRead:d.coreVerified,limitation:'Read-only visible inventory only. No reservation; connected discovery incomplete, real planning blocked.'}}
 catch{return {...base,status:'UNVERIFIED',awsInventoryRead:false,limitation:'Invalid or unavailable network inventory; real planning blocked.'}}
}
module.exports={checkCidr};
