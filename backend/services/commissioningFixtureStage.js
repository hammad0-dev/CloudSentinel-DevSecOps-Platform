'use strict';
const crypto=require('crypto'),live=new Map(),preparing=new Set();
const key=c=>`${c.projectId}:${c.executionId}:${c.userId}`;
const fail=code=>Object.assign(new Error(code),{code,nonRetryable:true,status:403});
function lookup(context){const r=live.get(key(context));if(!r||r.expiresAt<=Date.now())return null;return r;}
function binding(context){const r=lookup(context);return r?{baselineScanId:r.baselineScanId,stagingEvidenceSha256:r.sha256,expiresAt:r.expiresAt}:{};}
async function verify(pool,context){
 const r=lookup(context);if(!r)throw fail('COMMISSIONING_STAGING_BLOCKED');
 const row=(await pool.query("SELECT d.staging_url,s.target_authorization FROM deployment_history d JOIN dast_scans s ON s.project_id=d.project_id AND s.pipeline_execution_id=d.pipeline_execution_id WHERE d.id=$1 AND s.id=$2 AND d.project_id=$3 AND d.pipeline_execution_id=$4 AND d.status='SUCCESS' AND s.status='COMPLETED' AND s.scan_mode='BASELINE' AND s.target_url=d.staging_url",[r.deploymentId,r.baselineScanId,context.projectId,context.executionId])).rows;
 const a=row[0]?.target_authorization;
 if(row.length!==1||row[0].staging_url!==r.origin||a?.type!=='COMMISSIONING_FIXTURE_PASSIVE_BASELINE'||a.fixtureContainerId!==r.fixtureContainerId||a.evidenceSha256!==r.sha256)throw fail('COMMISSIONING_BASELINE_BLOCKED');
 return {stagingUrl:r.origin};
}
async function prepare(pool,context,{signal}={}){
 if(!require('./activeDastCommissioning').setupAllowed(context)||preparing.has(key(context))||lookup(context))throw fail('COMMISSIONING_STAGING_BLOCKED');
 preparing.add(key(context));let staged;
 try{
  staged=await require('./activeTargetEnrollment').prepareStaging(pool,context,{signal});
  const a=staged.authorization,b=staged.baseline;
  if(b.completed!==true||b.exitCode!==0||b.commissioningTraffic?.verified!==true||!Array.isArray(b.report?.site))throw fail('COMMISSIONING_BASELINE_BLOCKED');
  if(signal?.aborted)throw fail('ACTIVE_CANCELLED');
  const origin=`http://${a.hostname}:18080/`,baseline=require('./dastBaselineScanner'),findings=baseline.extractFindings(b.report);
  for(const f of findings){const u=new URL(f.endpoint);if(u.origin!==origin.slice(0,-1)||!require('./module2ActiveDast').ROUTES.includes(u.pathname))throw fail('ACTIVE_REPORT_OUT_OF_SCOPE');}
  const sha256=crypto.createHash('sha256').update(JSON.stringify(b.report)).digest('hex');
  const deployment=await pool.query("INSERT INTO deployment_history (project_id,pipeline_execution_id,deployment_attempt,status,deployed_at,staging_url,image_tag) VALUES ($1,$2,1,'SUCCESS',NOW(),$3,$4) RETURNING id",[context.projectId,context.executionId,origin,require('./activeRuntimeArtifacts').artifacts.fixture.imageId]);
  const created=await pool.query("INSERT INTO dast_scans (project_id,pipeline_execution_id,target_url,status,started_at,scan_mode,scan_group_id,policy_name,policy_version,target_authorization) VALUES ($1,$2,$3,'RUNNING',NOW(),'BASELINE',$4,'Commissioning fixture passive baseline','v1',$5) RETURNING id",[context.projectId,context.executionId,origin,crypto.randomUUID(),JSON.stringify({type:'COMMISSIONING_FIXTURE_PASSIVE_BASELINE',fixtureContainerId:a.fixtureContainerId,fixtureImageDigest:a.fixtureImageDigest,evidenceSha256:sha256,runtimeTimings:b.timings||null})]);
  try{await baseline.persistCompletedScan(pool,created.rows[0].id,context.projectId,findings,baseline.summarize(findings));}
  catch(error){await pool.query("UPDATE dast_scans SET status='FAILED',failure_reason='COMMISSIONING_BASELINE_PERSISTENCE_FAILED',completed_at=NOW() WHERE id=$1 AND project_id=$2 AND status='RUNNING'",[created.rows[0].id,context.projectId]);throw error;}
  const record={origin,sha256,fixtureContainerId:a.fixtureContainerId,baselineScanId:created.rows[0].id,deploymentId:deployment.rows[0].id,expiresAt:a.expiresAt};live.set(key(context),record);
  await verify(pool,context);
  const enrolled=await require('./activeRuntimeRegistry').enroll(pool,context,staged);record.target=enrolled;
  return {stagingUrl:origin,baselineScanId:record.baselineScanId,target:enrolled,fixtureOnly:true};
 }catch(error){live.delete(key(context));if(staged)try{const c=staged.runtime?await staged.runtime.cleanup().then(r=>({state:r.cleaned?'CLEANED':'FAILED',residual:r.residual})):await staged.lifecycle.cleanup(staged.scanId);if(c.state!=='CLEANED'||c.residual?.length)throw Error();}catch(_){require('./activeRuntimeRegistry').noteCleanupFailure(context,staged);throw fail('ACTIVE_CLEANUP_FAILED');}throw error;}
 finally{preparing.delete(key(context));}
}
function release(context){live.delete(key(context));}
module.exports={prepare,verify,binding,lookup,release,has:context=>live.has(key(context))};
