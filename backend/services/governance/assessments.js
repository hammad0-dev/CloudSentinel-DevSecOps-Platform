"use strict";
const crypto=require('crypto');
const {cis,docker,mapFinding,checkId,categories,OWASP_VERSIONS}=require('./registry');
const {state,combine,metrics}=require('./configuration');
const {scope}=require('./query');
const revision=crypto.createHash('sha256').update(JSON.stringify({categories,cis,associationRules:1})).digest('hex');
const resourceOf=f=>f.location.replace(/:\d+$/,'');
async function refreshMappings(db,userId) {
 const rows=(await db.query('SELECT f.* FROM governance_findings f JOIN projects p ON p.id=f.project_id WHERE p.user_id=$1',[userId])).rows;
 let updated=0;
 for(const f of rows){const mappings=JSON.stringify(mapFinding(f));const result=await db.query('UPDATE governance_findings SET mappings=$1::jsonb WHERE id=$2 AND mappings IS DISTINCT FROM $1::jsonb',[mappings,f.id]);updated+=result.rowCount;}
 return updated;
}
async function importAssessments(db,userId) {
 const scans=(await db.query(`SELECT g.*,to_jsonb(s)->'configuration_evidence' AS capture FROM governance_scans g
 JOIN iac_scans s ON s.id::text=g.scan_id AND s.project_id=g.project_id JOIN projects p ON p.id=g.project_id
 WHERE p.user_id=$1 AND g.source='IAC' ORDER BY g.scanned_at,g.id`,[userId])).rows;
 let inserted=0;
 for(const scan of scans) {
  const findings=(await db.query(`SELECT f.*,o.source_record_id FROM governance_observations o JOIN governance_findings f ON f.id=o.finding_id WHERE o.governance_scan_id=$1 AND f.project_id=$2 AND f.source='IAC'`,[scan.id,scan.project_id])).rows;
  const captured=scan.capture?.schemaVersion===1&&scan.capture.adapter==='trivy-config-v1'&&Array.isArray(scan.capture.targets);
  const legacy=new Map();
  if(!captured)for(const f of findings){const control=cis.find(c=>c.check===checkId(f.identity));if(!control)continue;const resource=resourceOf(f);if(!resource)continue;if(!legacy.has(resource))legacy.set(resource,{resource,technology:'dockerfile',complete:false,checks:[]});legacy.get(resource).checks.push({checkId:control.check,status:'FAIL',originalStatus:'LEGACY_FAILURE_ONLY',findingId:f.id,sourceRecordId:f.source_record_id});}
  for(const target of captured?scan.capture.targets:[...legacy.values()]) {
   if(target.technology!=='dockerfile'||typeof target.resource!=='string'||!target.resource||!Array.isArray(target.checks))continue;
   const targetId=(await db.query(`INSERT INTO governance_configuration_targets(governance_scan_id,resource,technology,capture_complete) VALUES($1,$2,'dockerfile',$3)
    ON CONFLICT(governance_scan_id,resource) DO UPDATE SET capture_complete=governance_configuration_targets.capture_complete OR EXCLUDED.capture_complete RETURNING id`,[scan.id,target.resource,target.complete===true])).rows[0].id;
   const checks=new Map();
   for(const check of target.checks) {
    const control=cis.find(c=>c.check&&c.check===checkId(check.checkId));if(!control)continue;
    const related=findings.find(f=>checkId(f.identity)===control.check&&resourceOf(f)===target.resource);
    const evidence={rule:control.check,resource:target.resource,scanId:scan.scan_id,sourceTable:'iac_scans',sourceRecordId:check.sourceRecordId||scan.scan_id,
     sourceTimestamp:new Date(scan.scanned_at).toISOString(),originalStatus:check.originalStatus,provenance:captured?'trivy-config-v1':'legacy-failure-only',
     line:Number.isInteger(check.line)?check.line:null,reference:docker.reference,registryRevision:revision};
    // Trivy currently emits PASS/FAIL; EXCEPTION and unknown outcomes are ERROR.
    // N/A needs a future trusted applicability adapter, not a client-supplied flag.
    const status=state({status:check.status,evidence});
    const previous=checks.get(control.id);
    if(previous&&previous.status!==status)evidence.conflictingOutcomes=[previous.status,status];
    checks.set(control.id,{control,evidence,status:previous&&previous.status!==status?'ERROR':status,findingId:check.findingId||related?.id||null});
   }
   for(const {control,evidence,status,findingId} of checks.values()) {
    const result=await db.query(`INSERT INTO governance_control_assessments(target_id,benchmark_id,benchmark_version,control_id,check_id,status,evidence,finding_id)
    VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8) ON CONFLICT(target_id,benchmark_id,benchmark_version,control_id,check_id) DO NOTHING`,[targetId,docker.id,docker.version,control.id,control.check,status,JSON.stringify(evidence),findingId]);inserted+=result.rowCount;
   }
  }
 }
 return inserted;
}
function buildCompliance(findings,projects=[],targets=[],observations=[],f={},assessmentFindings=findings) {
 findings=require('./complianceResult').uniqueFindings(findings);
 const version=f.owaspVersion||'2021';
 const framework=`OWASP Top 10:${version}`;
 const owasp=categories.filter(c=>c.version===version).map(c=>{
  const matched=findings.filter(row=>row.mappings.some(m=>m.framework===framework&&m.id===c.id));
  return {...c,findings:matched.length,bySeverity:severityCounts(matched),projects:uniqueProjects(matched),findingIds:matched.flatMap(r=>r.memberIds||[String(r.id)])};
 });
 const isMapped=row=>row.mappings.some(m=>m.framework===framework);
 const projectControls=[];
 for(const project of projects) {
  const resources=targets.filter(t=>String(t.project_id)===String(project.id));
  for(const control of cis) {
   const evidence=observations.filter(o=>String(o.project_id)===String(project.id)&&o.control_id===control.id&&o.benchmark_id===docker.id&&o.benchmark_version===docker.version);
   const resourceResults=resources.map(t=>{const check=evidence.filter(e=>String(e.target_id)===String(t.id));return {resource:t.resource,status:combine(check.map(state)),evidence:check};});
   const status=control.check?combine(resourceResults.map(r=>r.status)):'NOT_ASSESSED';
   projectControls.push({...control,project_id:project.id,project_name:project.name,status,assessment:status==='FAIL'?'FAILED':status==='PASS'?'PASSED':status,
    assessedAt:evidence.length?evidence.map(e=>e.scanned_at).sort((a,b)=>new Date(b)-new Date(a))[0]:null,
    resources:resourceResults,evidence,findings:findings.filter(row=>String(row.project_id)===String(project.id)&&row.mappings.some(m=>m.frameworkId===docker.id&&m.id===control.id)).length});
  }
 }
 const controls=cis.map(control=>{
  const scoped=projectControls.filter(c=>c.id===control.id);const status=combine(scoped.map(c=>c.status));
  const matched=findings.filter(row=>row.mappings.some(m=>m.frameworkId===docker.id&&m.id===control.id));
  return {...control,status,bySeverity:severityCounts(matched),assessment:status==='FAIL'?'FAILED':status==='PASS'?'PASSED':status,findings:scoped.reduce((n,c)=>n+c.findings,0),projects:scoped.map(c=>({id:c.project_id,name:c.project_name,status:c.status})),
   assessedAt:scoped.map(c=>c.assessedAt).filter(Boolean).sort((a,b)=>new Date(b)-new Date(a))[0]||null};
 });
 const evaluation=require('./complianceResult').result(assessmentFindings,projects,owasp,projectControls);
 const assessedControls=evaluation.benchmark;
 for(const c of controls){const slots=assessedControls.filter(x=>x.id===c.id);c.projects=slots.map(x=>({id:x.project_id,name:x.project_name,status:x.status}));c.status=combine(slots.map(x=>x.status));c.assessment=c.status==='FAIL'?'FAILED':c.status==='PASS'?'PASSED':c.status;}
 for(const c of owasp){c.status=combine(evaluation.owaspSlots.filter(x=>x.id===c.id).map(x=>x.status));}
 const associations=['CIS-3','CIS-4','CIS-16'].map(id=>{
  const matched=evaluation.unique.filter(row=>row.mappings.some(m=>m.frameworkId==='cis-controls-v8'&&m.id===id));
  const mapping=matched.flatMap(row=>row.mappings).find(m=>m.frameworkId==='cis-controls-v8'&&m.id===id);
  return {id,name:mapping?.name||({'CIS-3':'Data Protection','CIS-4':'Secure Configuration','CIS-16':'Application Software Security'}[id]),framework:'CIS Controls',version:'8',findings:matched.length,bySeverity:severityCounts(matched),unresolved:matched.filter(require('./complianceResult').unresolved).length,status:matched.some(require('./complianceResult').unresolved)?'CONTROL_GAP':'NOT_ASSESSED',findingIds:matched.flatMap(r=>r.memberIds)};
 });
 const matching={
  owasp:{framework:framework,matched:owasp.filter(c=>c.findings>0).length,total:10,percentage:Math.round(owasp.filter(c=>c.findings>0).length*1000)/100,meaning:'Distinct categories with mapped findings; not compliance'},
  cisControls:{framework:'CIS Controls',version:'8',matched:associations.filter(c=>c.findings>0).length,total:18,supportedMappingControls:associations.length,percentage:Math.round(associations.filter(c=>c.findings>0).length*10000/18)/100,meaning:'Distinct top-level controls with finding associations; not benchmark assessments'},
  docker:{framework:docker.name,version:docker.version,matched:controls.filter(c=>c.findings>0).length,total:cis.length,percentage:Math.round(controls.filter(c=>c.findings>0).length*10000/cis.length)/100,meaning:'Registered Docker requirements with mapped findings; not the full benchmark'}
 };
 const totals=evaluation.benchmarkMetrics;
 const selected=f.assessment?assessedControls.filter(c=>c.status===f.assessment):assessedControls;
 const benchmarks=[{id:docker.id,name:docker.name,version:docker.version,targetTechnology:docker.targetTechnology,scope:docker.scope,reference:docker.reference,supportedControls:cis.filter(c=>c.check).length,registeredControls:cis.length,metrics:totals}];
 return {version:framework,owaspVersion:version,availableOwaspVersions:OWASP_VERSIONS,owasp,cis:controls,unmapped:findings.filter(row=>!isMapped(row)).length,
  matching,overall:evaluation.overall,owaspMetrics:evaluation.owaspMetrics,owaspProjectCategories:evaluation.owaspSlots,cisControls:associations,uniqueVulnerabilities:evaluation.unique.length,sourceObservations:evaluation.unique.flatMap(r=>r.observations),
  unmappedFindingIds:findings.filter(row=>!isMapped(row)).flatMap(row=>row.memberIds||[String(row.id)]),benchmarks,metrics:totals,
  projectControls:selected,byProject:projects.map(p=>{const rows=assessedControls.filter(c=>String(c.project_id)===String(p.id));return {id:p.id,name:p.name,...metrics(rows)};}),
  gaps:assessedControls.filter(c=>c.status==='FAIL'||c.status==='ERROR'),
  cisSummary:{PASSED:totals.PASS,FAILED:totals.FAIL,NOT_ASSESSED:totals.NOT_ASSESSED,NOT_APPLICABLE:totals.NOT_APPLICABLE,ERROR:totals.ERROR},
  limitations:'Registered Docker image/build-file subset only. PASS requires an explicit recorded check on every known target in the latest project assessment. Missing checks remain Not Assessed; missing targets do not imply Not Applicable. Legacy failure evidence does not establish positive coverage. Kubernetes audit ownership, host/runtime and full benchmark coverage remain unavailable. Finding filters affect mapped counts; project/source/date scope selects assessments independently. No official CIS certification is claimed.'};
}
function severityCounts(rows){const out={};for(const r of rows)out[r.severity]=(out[r.severity]||0)+1;return out;}
function uniqueProjects(rows){return [...new Map(rows.map(r=>[String(r.project_id),{id:r.project_id,name:r.project_name}])).values()];}
async function loadCompliance(db,userId,findings,projects,f) {
 const s=scope(userId,f);
 const latest=`SELECT DISTINCT ON (g.project_id) g.id,g.project_id,g.scanned_at,g.scan_id FROM governance_scans g JOIN projects p ON p.id=g.project_id WHERE ${s.where} AND g.source='IAC' ORDER BY g.project_id,g.scanned_at DESC,g.id DESC`;
 const targets=(await db.query(`WITH latest AS (${latest}) SELECT t.*,l.project_id,l.scanned_at,l.scan_id FROM governance_configuration_targets t JOIN latest l ON l.id=t.governance_scan_id`,s.params)).rows;
 const observations=(await db.query(`WITH latest AS (${latest}) SELECT a.*,t.resource,l.project_id,l.scanned_at,l.scan_id FROM governance_control_assessments a JOIN governance_configuration_targets t ON t.id=a.target_id JOIN latest l ON l.id=t.governance_scan_id`,s.params)).rows;
 const full=require('./query').selection(userId,{project:f.project,source:f.source,from:f.from,to:f.to});
 const assessmentFindings=(await db.query(full.sql,full.params)).rows;
 return buildCompliance(findings,projects,targets,observations,f,assessmentFindings);
}
module.exports={refreshMappings,importAssessments,buildCompliance,loadCompliance,revision};
