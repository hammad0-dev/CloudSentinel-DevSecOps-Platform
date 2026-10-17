'use strict';
const fail=code=>Object.assign(new Error(code),{code,status:403,nonRetryable:true});
async function assertSchema(pool){const r=await pool.query("SELECT to_regclass('public.active_dast_commissioning_phases') AS phase_table");if(!r.rows[0]?.phase_table)throw fail('COMMISSIONING_PHASE_MIGRATION_REQUIRED');}
async function beginSetup(pool,context){
 if(!require('./activeDastCommissioning').setupAllowed(context))throw fail('COMMISSIONING_SETUP_BLOCKED');
 await assertSchema(pool);const db=await pool.connect();
 try{await db.query('BEGIN');await require('./activeOperatorEnrollment').assertProjectRole(db,context);
 const r=await db.query("UPDATE pipeline_executions e SET status='RUNNING' FROM projects p,active_dast_operators o WHERE e.id=$1 AND e.project_id=$2 AND e.status='TRIGGERED' AND p.id=e.project_id AND p.user_id=$3 AND o.user_id=p.user_id AND o.enabled=TRUE RETURNING e.id",[context.executionId,context.projectId,context.userId]);
 if(r.rows.length!==1)throw fail('COMMISSIONING_EXECUTION_BLOCKED');
 const overall=require('./activeDastCommissioning').selection(context).expiresAt;
 await db.query("INSERT INTO active_dast_commissioning_phases (project_id,pipeline_execution_id,operator_id,phase,expires_at,overall_deadline) VALUES ($1,$2,$3,'PASSIVE_SETUP',to_timestamp($4/1000.0),to_timestamp($4/1000.0))",[context.projectId,context.executionId,context.userId,overall]);
 await db.query('COMMIT');return {phase:'PASSIVE_SETUP',executionId:context.executionId};
 }catch(e){await db.query('ROLLBACK').catch(()=>{});throw e;}finally{db.release();}
}
async function row(pool,c){require('./activeDastPrerequisites').context(c);const rows=(await pool.query("SELECT c.* FROM active_dast_commissioning_phases c JOIN projects p ON p.id=c.project_id JOIN pipeline_executions e ON e.id=c.pipeline_execution_id AND e.project_id=p.id JOIN active_dast_operators o ON o.user_id=c.operator_id WHERE c.project_id=$1 AND c.pipeline_execution_id=$2 AND c.operator_id=$3 AND p.user_id=c.operator_id AND o.enabled=TRUE AND e.status='RUNNING' AND c.expires_at>NOW()",[c.projectId,c.executionId,c.userId])).rows;if(rows.length!==1)throw fail('COMMISSIONING_PHASE_BLOCKED');return rows[0];}
async function invalidate(pool,c,phase){
 if(!['EXPIRED','INVALIDATED','CLEANUP_FAILED'].includes(phase))throw fail('COMMISSIONING_PHASE_BLOCKED');
 await pool.query('UPDATE active_dast_commissioning_phases SET phase=$4,runtime_retained=FALSE,updated_at=NOW() WHERE project_id=$1 AND pipeline_execution_id=$2 AND operator_id=$3 AND phase NOT IN (\'COMPLETED\',\'FAILED\')',[c.projectId,c.executionId,c.userId,phase]);
 await pool.query('UPDATE active_dast_grants SET expires_at=LEAST(expires_at,NOW()) WHERE project_id=$1 AND pipeline_execution_id=$2 AND operator_id=$3 AND consumed_at IS NULL',[c.projectId,c.executionId,c.userId]);
 await pool.query('UPDATE active_dast_targets t SET verified_until=LEAST(verified_until,NOW()) WHERE t.project_id=$1 AND t.pipeline_execution_id=$2 AND EXISTS(SELECT 1 FROM active_dast_commissioning_phases c WHERE c.project_id=t.project_id AND c.pipeline_execution_id=t.pipeline_execution_id AND c.operator_id=$3)',[c.projectId,c.executionId,c.userId]);
 await pool.query("UPDATE pipeline_executions e SET status='STAGE_FAILED',failure_reason=$4,completed_at=NOW() WHERE e.project_id=$1 AND e.id=$2 AND e.status='RUNNING' AND EXISTS(SELECT 1 FROM active_dast_commissioning_phases c WHERE c.project_id=e.project_id AND c.pipeline_execution_id=e.id AND c.operator_id=$3 AND c.phase=$5)",[c.projectId,c.executionId,c.userId,'COMMISSIONING_'+phase,phase]);
}
async function pause(pool,c){
 if(!require('./activeDastCommissioning').setupAllowed(c))throw fail('COMMISSIONING_SETUP_BLOCKED');
 const stage=require('./commissioningFixtureStage');await stage.verify(pool,c);const r=stage.lookup(c);
 if(!r?.target?.targetId)throw fail('COMMISSIONING_STAGING_BLOCKED');
 const registry=require('./activeRuntimeRegistry'),a=registry.pendingFor(c,r.target.targetId);await registry.verifyPending(a);
 const result=await pool.query("UPDATE active_dast_commissioning_phases SET phase='AWAITING_ACTIVE_AUTHORIZATION',target_id=$4,fixture_container_id=$5,baseline_scan_id=$6,baseline_sha256=$7,runtime_retained=TRUE,expires_at=to_timestamp($8/1000.0),updated_at=NOW() WHERE project_id=$1 AND pipeline_execution_id=$2 AND operator_id=$3 AND phase='PASSIVE_SETUP' AND expires_at>NOW() RETURNING phase",[c.projectId,c.executionId,c.userId,r.target.targetId,r.fixtureContainerId,r.baselineScanId,r.sha256,Math.min(r.expiresAt,a.expiresAt)]);
 if(result.rows.length!==1)throw fail('COMMISSIONING_PHASE_BLOCKED');
 registry.watchCleanup(c,r.target.targetId,async(cleanup,expired)=>{await invalidate(pool,c,cleanup.cleaned?(expired?'EXPIRED':'INVALIDATED'):'CLEANUP_FAILED');stage.release(c);});
 return {phase:'AWAITING_ACTIVE_AUTHORIZATION',executionId:c.executionId,targetId:r.target.targetId,expiresAt:Math.min(r.expiresAt,a.expiresAt),runtimeRetained:true,activeScanCount:0,grantConsumed:false};
}
function assertBinding(c,r){const s=require('./commissioningFixtureStage').lookup(c);if(!s||s.fixtureContainerId!==r.fixture_container_id||s.baselineScanId!==r.baseline_scan_id||s.sha256!==r.baseline_sha256||s.target?.targetId!==r.target_id)throw fail('COMMISSIONING_PHASE_IDENTITY_BLOCKED');}
async function assertIssuable(pool,c){const r=await row(pool,c);if(r.phase!=='AWAITING_ACTIVE_AUTHORIZATION'||r.runtime_retained!==true)throw fail('COMMISSIONING_PHASE_BLOCKED');assertBinding(c,r);const a=require('./activeRuntimeRegistry').pendingFor(c,r.target_id);await require('./activeRuntimeRegistry').verifyPending(a);return r;}
async function assertActive(pool,c){if(!require('./activeDastCommissioning').activeAllowed(c))throw fail('COMMISSIONING_ACTIVE_AUTHORIZATION_BLOCKED');const r=await row(pool,c);if(r.phase!=='ACTIVE_COMMISSIONING'||r.runtime_retained!==true)throw fail('COMMISSIONING_PHASE_BLOCKED');assertBinding(c,r);return r;}
async function resume(pool,c){
 const started=require('perf_hooks').performance.now();
 if(!require('./activeDastCommissioning').activeAllowed(c))throw fail('COMMISSIONING_ACTIVE_AUTHORIZATION_BLOCKED');
 const current=await row(pool,c);if(current.phase!=='AWAITING_ACTIVE_AUTHORIZATION')throw fail('COMMISSIONING_PHASE_BLOCKED');
 let r;
 try{r=await assertIssuable(pool,c);await require('./activeDastPrerequisites').check(pool,c);}
 catch(error){await cleanup(pool,c);throw error;}
 const grants=(await pool.query('SELECT id,expires_at FROM active_dast_grants WHERE project_id=$1 AND pipeline_execution_id=$2 AND operator_id=$3 AND target_id=$4 AND consumed_at IS NULL AND expires_at>NOW()',[c.projectId,c.executionId,c.userId,r.target_id])).rows;
 if(grants.length!==1)throw fail('ACTIVE_GRANT_MISSING_OR_CONSUMED');
 try{
  const budget=require('./commissioningBudget'),pending=require('./activeRuntimeRegistry').pendingFor(c,r.target_id);
  budget.requireTime(budget.approvedDeadline(c,[new Date(r.expires_at).getTime(),pending.expiresAt,new Date(grants[0].expires_at).getTime()]),budget.minimumFor(pending));
 }catch(error){await cleanup(pool,c);throw error;}
 const control=require('./commissioningControl').read(c);if(control?.leaseId)await require('./commissioningPhaseLease').consume(pool,c,control.leaseId);
 const updated=await pool.query("UPDATE active_dast_commissioning_phases SET phase='ACTIVE_COMMISSIONING',updated_at=NOW() WHERE project_id=$1 AND pipeline_execution_id=$2 AND operator_id=$3 AND phase='AWAITING_ACTIVE_AUTHORIZATION' AND runtime_retained AND expires_at>NOW() RETURNING phase",[c.projectId,c.executionId,c.userId]);
 if(updated.rows.length!==1)throw fail('COMMISSIONING_PHASE_BLOCKED');return {phase:'ACTIVE_COMMISSIONING',executionId:c.executionId,durationMs:Math.round(require('perf_hooks').performance.now()-started)};
}
async function cleanup(pool,c){
 require('./activeDastPrerequisites').context(c);
 const rows=(await pool.query('SELECT target_id,runtime_retained,phase FROM active_dast_commissioning_phases WHERE project_id=$1 AND pipeline_execution_id=$2 AND operator_id=$3',[c.projectId,c.executionId,c.userId])).rows;
 if(rows[0]?.phase==='ACTIVE_COMMISSIONING')throw fail('COMMISSIONING_ACTIVE_CANCELLATION_NOT_SUPPORTED');
 let r;
 if(rows[0]?.runtime_retained===true){try{require('./activeRuntimeRegistry').pendingFor(c,rows[0].target_id);}catch(_){r={cleaned:false,residual:[{type:'untracked-paused-runtime',targetId:rows[0].target_id}]};}}
 if(!r)r=await require('./activeRuntimeRegistry').cancelPending(c);
 await invalidate(pool,c,r.cleaned?'INVALIDATED':'CLEANUP_FAILED');require('./commissioningFixtureStage').release(c);return r;
}
async function finish(pool,c,result){await pool.query('UPDATE active_dast_commissioning_phases SET phase=$4,runtime_retained=FALSE,updated_at=NOW() WHERE project_id=$1 AND pipeline_execution_id=$2 AND operator_id=$3 AND phase=\'ACTIVE_COMMISSIONING\'',[c.projectId,c.executionId,c.userId,result.cleanup?.cleaned!==true?'CLEANUP_FAILED':result.status.startsWith('COMPLETED')?'COMPLETED':'FAILED']);}
async function failSetup(pool,c,cleanupFailed=false){await pool.query("UPDATE active_dast_commissioning_phases SET phase=$4,runtime_retained=FALSE,updated_at=NOW() WHERE project_id=$1 AND pipeline_execution_id=$2 AND operator_id=$3 AND phase IN ('PASSIVE_SETUP','AWAITING_ACTIVE_AUTHORIZATION')",[c.projectId,c.executionId,c.userId,cleanupFailed?'CLEANUP_FAILED':'FAILED']);}
module.exports={assertSchema,beginSetup,pause,resume,assertIssuable,assertActive,cleanup,finish,failSetup};
