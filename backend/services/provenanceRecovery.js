'use strict';
const {randomUUID}=require('node:crypto');
const {digest,policyFromEnvironment}=require('./deploymentEligibility');
const {canonical,validBranch}=require('./pipelineProvenance');
const enabled=()=>process.env.PIPELINE_PROVENANCE_ENABLED==='true'&&process.env.PIPELINE_PROVENANCE_RECOVERY_ENABLED==='true';
let activeDispatcher=null;
const observedPools=new WeakSet();
function sourceMatches(source,project,expected=null,policy=null){
 if(!source||!project||source.owner_id!==project.user_id||source.project_id!==project.id||source.repository_identity!==canonical(project.repo_url)||!Number.isSafeInteger(Number(source.repository_id))||Number(source.repository_id)<1||!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(source.repository_identity)||!validBranch(source.branch)||!/^[a-f0-9]{40}$/.test(source.commit_sha||'')||/^0+$/.test(source.commit_sha))return false;
 if(expected&&(expected.projectId!==source.project_id||expected.userId!==source.owner_id||expected.repository!==source.repository_identity||Number(expected.repositoryId)!==Number(source.repository_id)||expected.branch!==source.branch||expected.commit!==source.commit_sha))return false;
 if(source.profile===null&&source.policy_digest===null)return true; // Evidence collection, never deployment authorization.
 return source.profile==='STATIC_HTML'&&policy?.approved===true&&Date.parse(policy.expiresAt)>Date.now()&&digest(policy)===source.policy_digest&&Array.isArray(policy.projects)&&policy.projects.some(p=>p.projectId===source.project_id&&p.ownerId===source.owner_id&&p.repositoryId===Number(source.repository_id)&&canonical(p.repository)===source.repository_identity&&p.branch===source.branch);
}
class Dispatcher{
 constructor({pool,runner,authorize=enabled,policy=policyFromEnvironment,leaseSeconds=30,maxAgeSeconds=900,intervalMs=15000}={}){
  if(!Number.isInteger(leaseSeconds)||leaseSeconds<1||leaseSeconds>60||!Number.isInteger(maxAgeSeconds)||maxAgeSeconds<60||maxAgeSeconds>3600||!Number.isInteger(intervalMs)||intervalMs<1000||intervalMs>60000)throw Error('Invalid recovery bounds');
  this.pool=pool;this.runner=runner;this.authorize=authorize;this.policy=policy;this.leaseSeconds=leaseSeconds;this.maxAgeSeconds=maxAgeSeconds;this.intervalMs=intervalMs;this.ready=false;this.busy=false;this.timer=null;
 }
 async initialize(){if(!this.authorize())return false;if(this.pool.on&&!observedPools.has(this.pool)){this.pool.on('error',()=>console.error('[provenance-recovery] Idle database connection lost; unfinished starts will not be replayed'));observedPools.add(this.pool);}const r=await this.pool.query("SELECT to_regclass('public.provenance_dispatch_claims') IS NOT NULL AS present");if(!r.rows[0]?.present)throw Error('PROVENANCE_RECOVERY_MIGRATION_REQUIRED');if((this.pool.options?.max||10)<2)throw Error('PROVENANCE_RECOVERY_POOL_TOO_SMALL');await this.pool.query('SELECT pipeline_execution_id,project_id,source_sha256,claim_token,state,attempts,lease_until,started_at,completed_at,reason FROM public.provenance_dispatch_claims LIMIT 0');const privileges=await this.pool.query("SELECT has_table_privilege(current_user,'public.provenance_dispatch_claims','INSERT') AND has_table_privilege(current_user,'public.provenance_dispatch_claims','UPDATE') AS writable");if(!privileges.rows[0]?.writable)throw Error('PROVENANCE_RECOVERY_WRITE_PRIVILEGES_REQUIRED');this.ready=true;return true;}
 async start(){if(!await this.initialize())return;this.timer=setInterval(()=>this.wake(),this.intervalMs);this.timer.unref?.();this.wake();}
 stop(){clearInterval(this.timer);this.timer=null;this.ready=false;}
 wake(executionId=null,expected=null){if(!this.ready||!this.authorize())return;setImmediate(()=>this.dispatch(executionId,expected).catch(()=>console.error('[provenance-recovery] Dispatch unavailable; no automatic scan retry')));}
 async claim(executionId=null,expected=null){
  if(!this.ready||!this.authorize())return null;
  const c=await this.pool.connect();let lock=null,retained=false,lost=false;const onLost=()=>{lost=true};c.on?.('error',onLost);
  try{
   await c.query('BEGIN');await c.query("SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'");
   const r=await c.query(`SELECT e.id,e.project_id,p.user_id,p.repo_url,to_jsonb(s) AS source,q.state,q.attempts,q.source_sha256,
      s.created_at>NOW()-$2*INTERVAL '1 second' AS fresh
     FROM pipeline_executions e JOIN pipeline_source_revisions s ON s.pipeline_execution_id=e.id AND s.project_id=e.project_id
     JOIN projects p ON p.id=e.project_id LEFT JOIN provenance_dispatch_claims q ON q.pipeline_execution_id=e.id
     WHERE e.status='TRIGGERED' AND e.triggered_by='webhook' AND ($1::integer IS NULL OR e.id=$1)
      AND EXISTS(SELECT 1 FROM github_delivery_receipts d WHERE d.pipeline_execution_id=e.id AND d.project_id=e.project_id)
      AND (q.pipeline_execution_id IS NULL OR (q.state='claimed' AND q.lease_until<=NOW()))
      AND NOT EXISTS(SELECT 1 FROM pipeline_executions other WHERE other.project_id=e.project_id AND other.id<>e.id AND other.status='RUNNING')
     ORDER BY (s.created_at>NOW()-$2*INTERVAL '1 second') DESC,s.created_at,e.id FOR UPDATE OF e SKIP LOCKED LIMIT 1`,[executionId,this.maxAgeSeconds]);
   if(!r.rows.length){await c.query('ROLLBACK');return null;}const row=r.rows[0];
   const acquired=await c.query('SELECT pg_try_advisory_lock($1,$2) AS acquired',[row.project_id,9]);if(!acquired.rows[0]?.acquired){await c.query('ROLLBACK');return null;}lock=row.project_id;
   const project={id:row.project_id,user_id:row.user_id,repo_url:row.repo_url};
   // A mismatched replay hint cannot poison the legitimate durable queue item.
   if(expected&&!sourceMatches(row.source,project,expected,this.policy())){await c.query('ROLLBACK');return null;}
   const fingerprint=digest(row.source),token=randomUUID(),attempts=Number(row.attempts||0)+1;
   let reason=null;try{if(!sourceMatches(row.source,project,null,this.policy()))reason='SOURCE_OR_AUTHORIZATION_CHANGED';}catch{reason='APPROVAL_UNAVAILABLE';}
   if(!row.fresh)reason='RECOVERY_WINDOW_EXPIRED';if(attempts>3)reason='RECOVERY_ATTEMPTS_EXHAUSTED';if(row.source_sha256&&row.source_sha256!==fingerprint)reason='SOURCE_FINGERPRINT_MISMATCH';
   const state=reason?'blocked':'claimed';
   await c.query(`INSERT INTO provenance_dispatch_claims(pipeline_execution_id,project_id,source_sha256,claim_token,state,attempts,lease_until,reason)
     VALUES($1,$2,$3,$4,$5,$6,NOW()+$7*INTERVAL '1 second',$8)
     ON CONFLICT(pipeline_execution_id) DO UPDATE SET claim_token=EXCLUDED.claim_token,state=EXCLUDED.state,attempts=EXCLUDED.attempts,lease_until=EXCLUDED.lease_until,reason=EXCLUDED.reason
     WHERE provenance_dispatch_claims.state='claimed' AND provenance_dispatch_claims.lease_until<=NOW()`,[row.id,row.project_id,fingerprint,token,state,Math.min(attempts,3),this.leaseSeconds,reason]);
   await c.query('COMMIT');if(reason)return null;
   retained=true;return {client:c,token,executionId:row.id,projectId:row.project_id,userId:row.user_id,sourceSha256:fingerprint,policy:this.policy,authorize:()=>this.ready&&this.authorize()&&!lost,connectionLost:()=>lost,onLost,maxAgeSeconds:this.maxAgeSeconds};
  }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e}
  finally{if(!retained){if(lock!==null)await c.query('SELECT pg_advisory_unlock($1,$2)',[lock,9]).catch(()=>{});c.removeListener?.('error',onLost);c.release(lost);}}
 }
 async dispatch(executionId=null,expected=null){
  if(this.busy||!this.ready||!this.authorize())return false;this.busy=true;let claim;
  try{claim=await this.claim(executionId,expected);if(!claim)return false;const result=await this.runner(claim.executionId,claim.projectId,claim.userId,{provenanceClaim:claim});if(result?.status==='NOT_ADMITTED')return false;
   // Finishing dispatch is not pipeline success; the execution keeps its real outcome.
   const finished=await claim.client.query("UPDATE provenance_dispatch_claims SET state='finished',completed_at=NOW() WHERE pipeline_execution_id=$1 AND claim_token=$2 AND state='started' RETURNING pipeline_execution_id",[claim.executionId,claim.token]);return finished.rows.length===1;
  }finally{if(claim){await claim.client.query('SELECT pg_advisory_unlock($1,$2)',[claim.projectId,9]).catch(()=>{});claim.client.removeListener?.('error',claim.onLost);claim.client.release(claim.connectionLost());}this.busy=false;}
 }
}
async function admit(claim,context){
 if(!claim||!claim.authorize?.()||claim.executionId!==context.executionId||claim.projectId!==context.projectId||claim.userId!==context.userId)return false;
 const c=claim.client;try{
  await c.query('BEGIN');await c.query("SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'");
  const r=await c.query(`SELECT to_jsonb(s) AS source,p.id,p.user_id,p.repo_url FROM provenance_dispatch_claims q
   JOIN pipeline_executions e ON e.id=q.pipeline_execution_id AND e.project_id=q.project_id
   JOIN pipeline_source_revisions s ON s.pipeline_execution_id=e.id JOIN projects p ON p.id=e.project_id
   WHERE q.pipeline_execution_id=$1 AND q.claim_token=$2 AND q.state='claimed' AND q.lease_until>NOW() AND q.source_sha256=$4 AND q.project_id=$5
    AND e.status='TRIGGERED' AND e.triggered_by='webhook' AND s.created_at>NOW()-$3*INTERVAL '1 second'
    AND NOT EXISTS(SELECT 1 FROM pipeline_executions other WHERE other.project_id=e.project_id AND other.id<>e.id AND other.status='RUNNING')
   FOR UPDATE OF q,e FOR SHARE OF p`,[context.executionId,claim.token,claim.maxAgeSeconds,claim.sourceSha256,context.projectId]);
  const row=r.rows[0];if(!row||digest(row.source)!==claim.sourceSha256||!sourceMatches(row.source,row,null,claim.policy())){await c.query('ROLLBACK');return false;}
  const changed=await c.query("UPDATE pipeline_executions SET status='RUNNING' WHERE id=$1 AND project_id=$2 AND status='TRIGGERED' RETURNING id",[context.executionId,context.projectId]);if(changed.rows.length!==1){await c.query('ROLLBACK');return false;}
  await c.query("UPDATE provenance_dispatch_claims SET state='started',started_at=NOW() WHERE pipeline_execution_id=$1 AND claim_token=$2 AND state='claimed'",[context.executionId,claim.token]);await c.query('COMMIT');return true;
 }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e}
}
async function start(pool,runner){if(!enabled())return;const dispatcher=new Dispatcher({pool,runner});try{await dispatcher.start();activeDispatcher=dispatcher}catch{dispatcher.stop();console.error('[provenance-recovery] Not ready; check migration 018 and dispatch configuration')}}
function ready(){return enabled()&&activeDispatcher?.ready===true;}
function wake(executionId,expected){if(ready())activeDispatcher.wake(executionId,expected);}
module.exports={Dispatcher,admit,start,ready,wake,enabled,sourceMatches};
