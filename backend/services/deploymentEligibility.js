'use strict';
const crypto=require('node:crypto'),fs=require('node:fs');
const STAGES=['SAST','Dependency','IaC','Deploy','DAST'];
function canonical(value){if(value instanceof Date)return value.toISOString();if(Array.isArray(value))return value.map(canonical);if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().filter(k=>value[k]!==undefined).map(k=>[k,canonical(value[k])]));return value;}
const digest=value=>crypto.createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
function policyFromEnvironment(){
 const file=process.env.DEPLOYMENT_ELIGIBILITY_POLICY_FILE;if(!file)return null;
 const st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o077))throw Error('Unsafe deployment policy');
 if(st.size>16384)throw Error('Oversized deployment policy');return JSON.parse(fs.readFileSync(file,'utf8'));
}
function evaluate(e,p,now=Date.now()){
 const reasons=[];let pending=false,unsupported=false;
 const missing=s=>{pending=true;reasons.push(s)};
 const validTime=t=>Number.isFinite(Date.parse(t));
 if(!p||p.version!==1||p.approved!==true||typeof p.approvalReference!=='string'||!p.approvalReference.trim()||!p.id||!Number.isSafeInteger(p.approvedBy)||!validTime(p.expiresAt)||Date.parse(p.expiresAt)<=now||!Number.isSafeInteger(p.maxAgeSeconds)||p.maxAgeSeconds<1||p.maxAgeSeconds>86400||p.requireActive!==false||!p.stages){missing('APPROVED_POLICY_MISSING_OR_EXPIRED');p=null;}
 if(!e||!Number.isSafeInteger(e.projectId)||!Number.isSafeInteger(e.executionId)||!Number.isSafeInteger(e.ownerId)||e.projectId<1||e.executionId<1||e.ownerId<1)missing('EXECUTION_IDENTITY_MISSING');
 e=e||{};
 if(e.status!=='COMPLETED')reasons.push('PIPELINE_NOT_COMPLETED');
 if(!e.binding)missing('EXECUTION_REVISION_AND_ARTIFACT_BINDING_MISSING');
 const b=e.binding;
 if(b){
  if(p&&b.policy_digest!==digest(p))reasons.push('EXECUTION_POLICY_MISMATCH');
  if(b.profile!=='STATIC_HTML'){unsupported=true;reasons.push('UNSUPPORTED_DEPLOYMENT_PROFILE');}
  if(b.project_id!==e.projectId||b.owner_id!==e.ownerId||b.pipeline_execution_id!==e.executionId||!Number.isSafeInteger(Number(b.repository_id))||Number(b.repository_id)<1||!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(b.repository_identity)||b.repository_identity!==e.repository||!/^([a-f0-9]{40})$/.test(b.commit_sha)||!/^([a-f0-9]{64})$/.test(b.artifact_sha256))reasons.push('REVISION_IDENTITY_MISMATCH');
  if(p&&(!Array.isArray(p.projects)||!p.projects.some(x=>x.projectId===e.projectId&&x.ownerId===e.ownerId&&x.repositoryId===Number(b.repository_id)&&x.repository===b.repository_identity&&x.branch===b.branch)))reasons.push('OWNER_REPOSITORY_BRANCH_NOT_APPROVED');
 }
 for(const name of STAGES){
  const s=e.stages?.[name],bound=b?.evidence?.[name];
  if(!s||!bound){missing(`${name}_EVIDENCE_MISSING`);continue;}
  if(s.status!==(name==='Deploy'?'SUCCESS':'COMPLETED')||!e.completedStages?.includes(name))reasons.push(`${name}_NOT_COMPLETED`);
  if(!validTime(s.completedAt)||Date.parse(s.completedAt)>now||(p&&now-Date.parse(s.completedAt)>p.maxAgeSeconds*1000))reasons.push(`${name}_STALE_EVIDENCE`);
  if(bound.id!==s.id||bound.sha256!==digest(s)||bound.commit!==b.commit_sha||bound.artifact!==b.artifact_sha256)reasons.push(`${name}_UNCORRELATED_EVIDENCE`);
  if(name==='SAST'&&(s.classificationVerified!==true||s.qualityGate!=='OK'))reasons.push('SAST_CLASSIFICATION_OR_QUALITY_GATE_UNVERIFIED');
  if(name==='Dependency'&&(s.sbomVerified!==true||s.coverageVerified!==true))reasons.push('DEPENDENCY_SBOM_OR_COVERAGE_UNVERIFIED');
  if(name==='DAST'&&s.reportVerified!==true)reasons.push('PASSIVE_DAST_REPORT_UNVERIFIED');
  if(s.reviewsResolved!==true||s.consistent!==true)reasons.push(`${name}_UNVERIFIED_OR_REVIEW_REQUIRED`);
  if(name==='Deploy'||name==='DAST'){
   try{const u=new URL(s.url);if(!['http:','https:'].includes(u.protocol)||u.username||u.password)throw Error();}catch{reasons.push(`${name}_URL_INVALID`);}
  }
  if(name==='DAST'&&(s.mode!=='BASELINE'||s.url!==e.stages?.Deploy?.url))reasons.push('PASSIVE_DAST_TARGET_OR_MODE_MISMATCH');
  if(name!=='Deploy'&&p){const rule=p.stages[name];if(!rule||!Array.isArray(rule.block)||!rule.block.includes('CRITICAL')||!rule.block.includes('HIGH')||rule.block.some(x=>!['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL'].includes(x))||!s.counts||['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL'].some(k=>!Number.isSafeInteger(s.counts[k])||s.counts[k]<0))missing(`${name}_POLICY_OR_COUNTS_INVALID`);else if(rule.block.some(k=>s.counts[k]>0))reasons.push(`${name}_FINDINGS_BLOCKED`);}
 }
 if(p&&(!validTime(e.completedAt)||Date.parse(e.completedAt)>now||now-Date.parse(e.completedAt)>p.maxAgeSeconds*1000))reasons.push('EXECUTION_STALE');
 return {decision:reasons.length?(unsupported?'UNSUPPORTED':pending?'PENDING_EVIDENCE':'BLOCKED'):'ELIGIBLE',reasons:[...new Set(reasons)],projectId:e.projectId,executionId:e.executionId,ownerId:e.ownerId,repository:e.repository,binding:b?Object.fromEntries(['project_id','owner_id','pipeline_execution_id','repository_id','repository_identity','branch','commit_sha','artifact_sha256','profile','policy_digest'].map(k=>[k,b[k]])):null,stages:Object.fromEntries(Object.entries(e.stages||{}).map(([name,s])=>[name,{id:s.id,status:s.status,completedAt:s.completedAt,sha256:digest(s),counts:s.counts}])),policyDigest:p?digest(p):null,policyId:p?.id||null,expiresAt:new Date(Math.min(p?Date.parse(p.expiresAt):now+60000,...Object.values(e.stages||{}).map(s=>validTime(s.completedAt)?Date.parse(s.completedAt)+(p?.maxAgeSeconds||60)*1000:now+60000),validTime(e.completedAt)?Date.parse(e.completedAt)+(p?.maxAgeSeconds||60)*1000:now+60000)).toISOString()};
}
async function record(pool,context,{policy,now=Date.now(),loadEvidence}={}){
 if(policy===undefined){try{policy=policyFromEnvironment()}catch{policy=null}}
 const c=await pool.connect();let integrityFailure=false;try{
  await c.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
  await c.query('SELECT pg_advisory_xact_lock($1,$2)',[context.projectId,8]);
  const r=await c.query('SELECT p.user_id,p.repo_url,e.status,e.completed_at,e.stages_completed FROM projects p JOIN pipeline_executions e ON e.project_id=p.id WHERE p.id=$1 AND e.id=$2 FOR SHARE OF p,e',[context.projectId,context.executionId]);
  if(r.rows.length!==1||r.rows[0].user_id!==context.userId)throw Error('Deployment execution ownership mismatch');
  const row=r.rows[0],bindings=await c.query('SELECT * FROM deployment_revision_bindings WHERE pipeline_execution_id=$1 AND project_id=$2',[context.executionId,context.projectId]);
  // Binding producers must attest exact normalized persisted stage snapshots. No browser input is admitted.
  const b=bindings.rows[0];const evidence={...context,ownerId:row.user_id,repository:row.repo_url.replace(/\.git\/?$/,'').replace(/\/$/,''),status:row.status,completedAt:row.completed_at,completedStages:(row.stages_completed||'').split(/,\s*/),binding:b,stages:{}};
  for(const [name,table] of [['SAST','scan_history'],['Dependency','dependency_scans'],['IaC','iac_scans'],['Deploy','deployment_history'],['DAST','dast_scans']]){
   const rows=await c.query(`SELECT to_jsonb(t) AS record FROM ${table} t WHERE project_id=$1 AND pipeline_execution_id=$2 ORDER BY id DESC LIMIT 1`,[context.projectId,context.executionId]);
   const s=rows.rows[0]?.record;
   if(s)evidence.stages[name]={id:s.id,status:s.status,completedAt:s.completed_at||s.deployed_at,url:s.staging_url||s.target_url||null,mode:s.scan_mode||null,counts:{CRITICAL:s.critical,HIGH:s.high,MEDIUM:s.medium,LOW:s.low,INFORMATIONAL:s.informational},consistent:false,reviewsResolved:false,recordDigest:digest(s)};
  }
  if(b){
   const source=(await c.query('SELECT * FROM pipeline_source_revisions WHERE pipeline_execution_id=$1 AND project_id=$2',[context.executionId,context.projectId])).rows[0];
   if(!source||['owner_id','repository_identity','branch','commit_sha','policy_digest','profile'].some(k=>source[k]!==b[k])||String(source.repository_id)!==String(b.repository_id)){integrityFailure=true;throw Error('SOURCE_ARTIFACT_BINDING_MISMATCH');}
   try{require('./staticArtifact').verify({projectId:context.projectId,executionId:context.executionId,commit:b.commit_sha,sha256:b.artifact_sha256})}catch(e){integrityFailure=true;throw e}
   const attestations=await c.query('SELECT * FROM deployment_stage_attestations WHERE pipeline_execution_id=$1 AND project_id=$2',[context.executionId,context.projectId]);
   b.evidence={};
   for(const a of attestations.rows){const stored=evidence.stages[a.stage];const details=await require('./stageProvenance').detailRecords(c,context,a.stage,a.record_id);if(a.snapshot.detailsDigest!==digest(details))continue;
    try{const ref=a.snapshot.reports;if(!ref||ref.projectId!==context.projectId||ref.executionId!==context.executionId||ref.stage!==a.stage||ref.recordId!==a.record_id||ref.commit!==b.commit_sha||ref.artifact!==b.artifact_sha256||a.snapshot.reportHash!==ref.manifestSha256)continue;require('./securityReports').verify(ref)}catch{continue;}
    if(!stored||a.record_id!==stored.id||a.commit_sha!==b.commit_sha||a.artifact_sha256!==b.artifact_sha256||digest(a.snapshot)!==a.fingerprint||a.snapshot.recordDigest!==stored.recordDigest)continue;
    evidence.stages[a.stage]=a.snapshot;b.evidence[a.stage]={id:a.record_id,sha256:a.fingerprint,commit:a.commit_sha,artifact:a.artifact_sha256};
   }
  }

  const result=evaluate(loadEvidence?await loadEvidence(c,context):evidence,policy,now),key=digest({project:context.projectId,execution:context.executionId,environment:'development',policy:result.policyDigest,evidence:digest({binding:result.binding,stages:result.stages,reasons:result.reasons})});
  if(result.decision!=='ELIGIBLE')await c.query("UPDATE deployment_outbox o SET status='blocked',claim_token=NULL,claim_until=NULL FROM deployment_eligibility d WHERE o.decision_id=d.id AND d.project_id=$1 AND d.pipeline_execution_id=$2 AND o.status IN ('pending','claimed')",[context.projectId,context.executionId]);
  const inserted=await c.query("INSERT INTO deployment_eligibility(project_id,pipeline_execution_id,environment,idempotency_key,decision,evidence,expires_at) VALUES($1,$2,'development',$3,$4,$5,$6) ON CONFLICT(idempotency_key) DO NOTHING RETURNING id",[context.projectId,context.executionId,key,result.decision,result,result.expiresAt]);
  if(result.decision==='ELIGIBLE'&&inserted.rows.length)await c.query('INSERT INTO deployment_outbox(decision_id,idempotency_key) VALUES($1,$2) ON CONFLICT(idempotency_key) DO NOTHING',[inserted.rows[0].id,key]);
  let persisted=result;
  if(!inserted.rows.length){const existing=await c.query('SELECT evidence FROM deployment_eligibility WHERE idempotency_key=$1',[key]);if(existing.rows.length!==1)throw Error('Eligibility decision conflict');persisted=existing.rows[0].evidence;}
  await c.query('COMMIT');return persisted;
 }catch(e){await c.query('ROLLBACK').catch(()=>{});if(integrityFailure)await c.query("UPDATE deployment_outbox o SET status='blocked',claim_token=NULL,claim_until=NULL FROM deployment_eligibility d,projects p WHERE o.decision_id=d.id AND p.id=d.project_id AND p.user_id=$3 AND d.project_id=$1 AND d.pipeline_execution_id=$2 AND o.status IN ('pending','claimed')",[context.projectId,context.executionId,context.userId]).catch(()=>{});throw e}finally{c.release()}
}
module.exports={evaluate,record,digest,STAGES,policyFromEnvironment};
