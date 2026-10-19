"use strict";
const {checkId}=require('./registry');
// Capture only provenance and check outcomes: never source code, raw report bodies,
// secret snippets, provider credentials or target resource configuration values.
const text=value=>require('./normalize').clean(value).slice(0,1000);
function captureConfiguration(report) {
 report=require('../trivyReport').filesystemReport(report);
 const targets=[];
 for(const r of report.Results) {
  if(r.Type!=='dockerfile'||(r.Class&&r.Class!=='config'))continue;
  if(typeof r.Target!=='string'||!r.Target.trim())throw Error('Configuration evidence is missing its target');
  if(r.Misconfigurations!==undefined&&!Array.isArray(r.Misconfigurations))throw Error('Invalid configuration check array');
  targets.push({resource:text(r.Target),technology:'dockerfile',complete:true,checks:(r.Misconfigurations||[]).map(m=>({
   checkId:checkId(m.ID||m.AVDID),status:['PASS','FAIL'].includes(m.Status)?m.Status:'ERROR',
   originalStatus:text(m.Status||'MISSING'),line:Number.isInteger(m.CauseMetadata?.StartLine)?m.CauseMetadata.StartLine:null,
   reference:'https://trivy.dev/docs/latest/scanner/misconfiguration/'
  })).filter(m=>m.checkId)});
 }
 return {schemaVersion:1,adapter:'trivy-config-v1',targets};
}
function state(observation) {
 if(!observation||!observation.evidence||!observation.evidence.rule||!observation.evidence.resource||!observation.evidence.scanId||!Number.isFinite(Date.parse(observation.evidence.sourceTimestamp)))return 'NOT_ASSESSED';
 if(observation.status==='NOT_APPLICABLE') {
  const a=observation.evidence.applicability;
  return a?.verified===true&&a.reason&&a.sourceReference?'NOT_APPLICABLE':'ERROR';
 }
 return ['PASS','FAIL','ERROR','NOT_ASSESSED'].includes(observation.status)?observation.status:'ERROR';
}
function combine(statuses) {
 if(!statuses.length)return 'NOT_ASSESSED';
 if(statuses.includes('FAIL'))return 'FAIL';
 if(statuses.includes('ERROR'))return 'ERROR';
 if(statuses.includes('NOT_ASSESSED'))return 'NOT_ASSESSED';
 if(statuses.every(s=>s==='NOT_APPLICABLE'))return 'NOT_APPLICABLE';
 return statuses.every(s=>s==='PASS'||s==='NOT_APPLICABLE')?'PASS':'ERROR';
}
function metrics(controls) {
 const counts=Object.fromEntries(['PASS','FAIL','NOT_ASSESSED','NOT_APPLICABLE','ERROR'].map(s=>[s,controls.filter(c=>c.status===s).length]));
 const assessed=counts.PASS+counts.FAIL,applicable=controls.length-counts.NOT_APPLICABLE;
 return {...counts,assessed,applicable,total:controls.length,passRate:assessed?Math.round(10000*counts.PASS/assessed)/100:null,coverage:applicable?Math.round(10000*assessed/applicable)/100:null,
  methodology:'Pass rate = PASS / (PASS + FAIL). Coverage = (PASS + FAIL) / (registered project-control slots minus verified NOT_APPLICABLE). ERROR and missing evidence remain in the coverage denominator. Only a registered image/build-file subset is represented; these are internal metrics, not CIS certification.'};
}
module.exports={captureConfiguration,state,combine,metrics};
