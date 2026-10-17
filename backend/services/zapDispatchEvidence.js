'use strict';
// Offline verifier for a future independently verified in-JVM collector.
// This module neither issues collector trust nor manufactures observations.
const crypto=require('crypto');
const SOURCE='https://raw.githubusercontent.com/zaproxy/zap-extensions/network-v0.29.0/addOns/network/src/main/java/org/zaproxy/addon/network/internal/ratelimit/RateLimiterImpl.java';
function verify(trace,expected){
 const errors=[];const add=x=>{if(!errors.includes(x))errors.push(x);};
 if(!expected||expected.collectorVerified!==true)add('COLLECTOR_UNVERIFIED');
 if(!trace||trace.complete!==true||!Array.isArray(trace.records)||trace.records.length<2||trace.records.length>600)add('MISSING_OR_INCOMPLETE_RECORDS');
 if(!trace||trace.source!=='ZAP_NETWORK_RATE_LIMITER_ADMISSION'||trace.algorithm!=='SERIAL_MINIMUM_SPACING'||trace.groupBy!=='HOST'||trace.intervalMs!==500||trace.timestampPrecisionMs!==1)add('UNSUPPORTED_OBSERVATION');
 if(!trace||trace.bypassChecked!==true||trace.allSendersCovered!==true||trace.transportCount!==trace.records?.length)add('BYPASS_OR_COVERAGE_UNVERIFIED');
 const safe=[];let previous=null;
 for(const [i,r] of (Array.isArray(trace?.records)?trace.records:[]).slice(0,600).entries()){
  if(!r||r.sequence!==i+1){add('SEQUENCE_GAP');continue;}
  if(r.projectId!==expected?.projectId||r.executionId!==expected?.executionId||r.scannerId!==expected?.scannerId||r.collectorId!==expected?.collectorId||r.origin!==expected?.origin||!['/test/sqli','/test/xss'].includes(r.path)||r.initiator!=='ACTIVE_SCANNER'){add('MIXED_OR_UNAUTHORIZED_SOURCE');continue;}
  if(!Number.isSafeInteger(r.wallAtMs)||!/^[0-9]{1,20}$/.test(r.monotonicNs||'')||!Number.isSafeInteger(r.waitedMs)||r.waitedMs<0||!['ADMIT','WAIT_THEN_ADMIT'].includes(r.decision)){add('MALFORMED_CLOCK_OR_DECISION');continue;}
  const mono=BigInt(r.monotonicNs);
  if(previous){const wall=r.wallAtMs-previous.wall,ns=mono-previous.mono;
   if(wall<0||ns<0n||Math.abs(Number(ns)/1e6-wall)>2)add('CLOCK_ANOMALY');
   if(wall<500||ns<499000000n)add('EXCESSIVE_ADMISSION_BURST');
   else if(ns<500000000n)add('PRECISION_CANNOT_ESTABLISH_STRICT_LIMIT');
   if(r.waitedMs>0&&r.decision!=='WAIT_THEN_ADMIT'||r.waitedMs===0&&r.decision!=='ADMIT')add('CONTRADICTORY_DECISION');
  }
  if((r.waitedMs>0&&r.decision!=='WAIT_THEN_ADMIT')||(r.waitedMs===0&&r.decision!=='ADMIT'))add('CONTRADICTORY_DECISION');
  previous={wall:r.wallAtMs,mono};safe.push({sequence:r.sequence,wallAtMs:r.wallAtMs,monotonicNs:r.monotonicNs,path:r.path,initiator:r.initiator,decision:r.decision,waitedMs:r.waitedMs});
 }
 const violation=errors.includes('EXCESSIVE_ADMISSION_BURST');
 return {schemaVersion:1,state:violation?'VIOLATION':errors.length?'UNVERIFIED':'VERIFIED',source:SOURCE,configuredRequestsPerSecond:2,algorithm:'SERIAL_MINIMUM_SPACING',intervalMs:500,timestampPrecisionMs:1,failedPredicates:errors,records:safe,sha256:crypto.createHash('sha256').update(JSON.stringify(safe)).digest('hex')};
}
module.exports={verify,SOURCE};
