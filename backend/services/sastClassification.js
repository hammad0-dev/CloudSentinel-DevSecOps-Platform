'use strict';
const TYPES=new Set(['CODE_SMELL','BUG','VULNERABILITY','SECURITY_HOTSPOT']);
function classify(issue){
 const type=TYPES.has(issue.type)?issue.type:'UNKNOWN';
 const review=type==='SECURITY_HOTSPOT'&&issue.status==='REVIEWED'&&['SAFE','FIXED'].includes(issue.resolution)?issue.resolution:type==='SECURITY_HOTSPOT'?'TO_REVIEW':'NOT_APPLICABLE';
 return {type,review,classification:{CODE_SMELL:'Maintainability',BUG:'Reliability',VULNERABILITY:'Security vulnerability',SECURITY_HOTSPOT:'Security hotspot — review required',UNKNOWN:'Unclassified — verification required'}[type]};
}
function gate(row){
 const names=['security_critical','security_high','hotspots_pending','unknown_types'];
 if(!names.every(n=>Number.isSafeInteger(Number(row[n]))&&row[n]!==null&&row[n]!==undefined&&Number(row[n])>=0))return {classificationVerified:false,hasCritical:true,hasHigh:true,requiresReview:true};
 return {classificationVerified:true,hasCritical:Number(row.security_critical)>0,hasHigh:Number(row.security_high)>0,requiresReview:Number(row.hotspots_pending)>0||Number(row.unknown_types)>0};
}
function qualityGate(data){const status=data?.projectStatus?.status;if(!['OK','ERROR','NONE'].includes(status))throw Error('SAST_QUALITY_GATE_UNVERIFIED');if(status==='ERROR')throw Error('SAST_QUALITY_GATE_FAILED');return status;}
module.exports={classify,gate,qualityGate};
