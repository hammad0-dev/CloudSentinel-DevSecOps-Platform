'use strict';
const {metrics}=require('./configuration');
// Cross-scanner collapse requires an exact vulnerability identity AND exact resource.
// A shared CWE or scanner rule is never sufficient evidence of the same vulnerability.
function uniqueFindings(rows){
 const groups=new Map();
 for(const row of rows){
  const key=/^CVE-\d{4}-\d+$/i.test(row.identity||'')&&row.location?JSON.stringify([String(row.project_id),row.identity.toUpperCase(),row.location]):JSON.stringify([String(row.project_id),row.source,row.fingerprint||row.id||[row.identity,row.location]]);
  if(!groups.has(key))groups.set(key,{...row,mappings:[],observations:[],memberIds:[]});
  const group=groups.get(key);group.memberIds.push(...(row.memberIds||[String(row.id)]));if(row.observations)group.observations.push(...row.observations);else group.observations.push({findingId:String(row.id),projectId:String(row.project_id),source:row.source,scanId:row.scan_id,observedAt:row.observed_at,status:row.status,location:row.location});
  for(const m of row.mappings||[])if(!group.mappings.some(x=>x.frameworkId===m.frameworkId&&x.id===m.id))group.mappings.push(m);
  if(['OPEN','ACCEPTED_RISK'].includes(row.status))group.status=row.status;
  const ranks=['CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN'];if(ranks.indexOf(row.severity)<ranks.indexOf(group.severity))group.severity=row.severity;
 }
 return [...groups.values()];
}
const unresolved=f=>['OPEN','ACCEPTED_RISK'].includes(f.status)&&!['HOTSPOT_REVIEW','UNCLASSIFIED_REVIEW'].includes(f.classification);
function result(findings,projects,owasp,projectControls){
 const unique=uniqueFindings(findings);
 const owaspSlots=projects.flatMap(p=>owasp.map(c=>{
  const violations=unique.filter(f=>String(f.project_id)===String(p.id)&&unresolved(f)&&f.mappings.some(m=>m.framework===c.framework&&m.id===c.id));
  // No positive whole-category evidence adapter exists. Clean scans cannot prove PASS.
  return {project_id:p.id,project_name:p.name,id:c.id,status:violations.length?'FAIL':'NOT_ASSESSED',findingIds:violations.flatMap(f=>f.memberIds)};
 }));
 const benchmark=projectControls.map(c=>{
  const violations=unique.filter(f=>String(f.project_id)===String(c.project_id)&&f.source==='IAC'&&Boolean(f.location)&&unresolved(f)&&f.mappings.some(m=>m.frameworkId===c.frameworkId&&m.id===c.id));
  const status=violations.length?'FAIL':c.status;
  return {...c,status,assessment:status==='FAIL'?'FAILED':status==='PASS'?'PASSED':status,violationFindingIds:violations.flatMap(f=>f.memberIds)};
 });
 // OWASP category violations and Docker checks are incompatible assessment units.
 // Keep framework metrics separate and use only explicit Docker requirement slots
 // for the overall supported-check pass rate; never count the same evidence twice.
 const overall={...metrics(benchmark),assessmentBasis:'CIS Docker Benchmark 1.6.0 registered project-control slots'};
 overall.methodology='Supported assessment pass rate = Docker PASS / (PASS + FAIL). Coverage = assessed Docker project-control slots / applicable registered Docker slots. OWASP category matching and category assessments are reported separately, not added to Docker checks. Null means no assessed requirements. Pipeline success and missing findings do not create PASS. Unresolved exact violations override positive checks; accepted risk remains unresolved. This registered subset is not certification.';

 const owaspMetrics=metrics(owaspSlots);owaspMetrics.methodology='OWASP pass rate = passed project-category slots / (passed + failed slots). Coverage = assessed / applicable project-category slots. Only unresolved confirmed mapped violations establish FAIL; no whole-category positive adapter exists. Distinct category matching uses a separate denominator of ten.';
 return {unique,owaspSlots,benchmark,owaspMetrics,benchmarkMetrics:metrics(benchmark),overall};
}
module.exports={uniqueFindings,unresolved,result};
