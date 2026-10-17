'use strict';
const crypto=require('crypto');
const executionScopes=new Map();
const scopeKey=c=>`${c.projectId}:${c.executionId}:${c.userId}`;
function scopeFor(context,{includeExpired=false}={}){const scope=executionScopes.get(scopeKey(context));return scope&&(includeExpired||scope.expiresAt>Date.now())?scope:null;}
async function assertProjectRole(pool,context){
 const approvals=(await pool.query("SELECT project_id,pipeline_execution_id FROM active_dast_audit WHERE operator_id=$1 AND event='ISSUED' AND reason LIKE 'COMMISSIONING_OPERATOR_APPROVED:%'",[context.userId])).rows;
 // Schema 013's operator role is global. An operator enabled by this private
 // commissioning workflow must not inherit that global scope for other projects.
 if(approvals.length&&(!require('./activeDastCommissioning').selection(context)||!approvals.some(r=>r.project_id===context.projectId&&r.pipeline_execution_id===context.executionId)))throw fail();
}
const fail=()=>Object.assign(new Error('COMMISSIONING_OPERATOR_APPROVAL_BLOCKED'),{code:'COMMISSIONING_OPERATOR_APPROVAL_BLOCKED',status:403});
async function enroll(pool,context,approval){
 require('./activeDastPrerequisites').context(context);
 if(!require('./activeDastCommissioning').selection(context)||typeof approval!=='string'||!/^[a-f0-9]{64}$/.test(approval))throw fail();
 const expected=process.env.DAST_ACTIVE_OPERATOR_APPROVAL_SHA256;
 const digest=crypto.createHash('sha256').update(approval).digest('hex');
 if(!/^[a-f0-9]{64}$/.test(expected||'')||!crypto.timingSafeEqual(Buffer.from(digest,'hex'),Buffer.from(expected,'hex')))throw fail();
 await require('./commissioningPhases').assertSchema(pool);
 const db=await pool.connect();
 try{
  await db.query('BEGIN');
  await db.query('SELECT pg_advisory_xact_lock(hashtext($1))',['commissioning-operator:'+digest]);
  const owned=await db.query("SELECT u.id FROM users u JOIN projects p ON p.user_id=u.id JOIN pipeline_executions e ON e.project_id=p.id WHERE u.id=$1 AND p.id=$2 AND e.id=$3 AND e.status IN ('TRIGGERED','RUNNING') FOR SHARE OF u,p,e",[context.userId,context.projectId,context.executionId]);
  if(owned.rows.length!==1)throw fail();
  const reason='COMMISSIONING_OPERATOR_APPROVED:'+digest;
  if((await db.query('SELECT id FROM active_dast_audit WHERE reason=$1',[reason])).rows.length)throw fail();
  await db.query('INSERT INTO active_dast_operators (user_id,enabled) VALUES ($1,TRUE) ON CONFLICT (user_id) DO UPDATE SET enabled=TRUE',[context.userId]);
  await db.query("INSERT INTO active_dast_audit (operator_id,project_id,pipeline_execution_id,event,reason) VALUES ($1,$2,$3,'ISSUED',$4)",[context.userId,context.projectId,context.executionId,reason]);
  await db.query('COMMIT');return {enabled:true,authorizationState:'COMMISSIONING',projectId:context.projectId,executionId:context.executionId};
 }catch(error){await db.query('ROLLBACK').catch(()=>{});await pool.query("INSERT INTO active_dast_audit (operator_id,project_id,pipeline_execution_id,event,reason) VALUES ($1,$2,$3,'REJECTED','COMMISSIONING_OPERATOR_REJECTED')",[context.userId,context.projectId,context.executionId]);throw error;}finally{db.release();}
}
async function createExecution(pool,{projectId,userId},approval){
 let scope;try{scope=JSON.parse(process.env.DAST_ACTIVE_COMMISSIONING_ENROLLMENT_CONTEXT||'');}catch(_){throw fail();}
 if(process.env.DAST_ACTIVE_COMMISSIONING_ENABLED!=='true'||process.env.DAST_COMMISSIONING_SETUP_ENABLED!=='true'||
    !scope||Object.keys(scope).sort().join(',')!=='expiresAt,projectId,userId'||scope.projectId!==projectId||scope.userId!==userId||
    ![projectId,userId].every(n=>Number.isSafeInteger(n)&&n>0)||projectId===17||!Number.isSafeInteger(scope.expiresAt)||scope.expiresAt<=Date.now()||scope.expiresAt>Date.now()+900000||
    !/^[a-f0-9]{64}$/.test(approval||''))throw fail();
 const digest=crypto.createHash('sha256').update(approval).digest('hex'),expected=process.env.DAST_ACTIVE_OPERATOR_APPROVAL_SHA256;
 if(!/^[a-f0-9]{64}$/.test(expected||'')||!crypto.timingSafeEqual(Buffer.from(digest,'hex'),Buffer.from(expected,'hex')))throw fail();
 await require('./commissioningPhases').assertSchema(pool);
 const db=await pool.connect();let executionId;
 try{
  await db.query('BEGIN');await db.query('SELECT pg_advisory_xact_lock(hashtext($1))',['commissioning-operator:'+digest]);
  const owned=await db.query('SELECT u.id FROM users u JOIN projects p ON p.user_id=u.id WHERE u.id=$1 AND p.id=$2 FOR UPDATE OF p',[userId,projectId]);
  if(owned.rows.length!==1||(await db.query('SELECT id FROM active_dast_audit WHERE reason=$1',['COMMISSIONING_OPERATOR_APPROVED:'+digest])).rows.length||
    (await db.query("SELECT id FROM pipeline_executions WHERE project_id=$1 AND status IN ('TRIGGERED','RUNNING')",[projectId])).rows.length)throw fail();
  executionId=(await db.query("INSERT INTO pipeline_executions (project_id,status,triggered_by) VALUES ($1,'TRIGGERED','commissioning') RETURNING id",[projectId])).rows[0]?.id;
  if(!Number.isSafeInteger(executionId)||executionId<=0)throw fail();
  await db.query('INSERT INTO active_dast_operators (user_id,enabled) VALUES ($1,TRUE) ON CONFLICT (user_id) DO UPDATE SET enabled=TRUE',[userId]);
  await db.query("INSERT INTO active_dast_audit (operator_id,project_id,pipeline_execution_id,event,reason) VALUES ($1,$2,$3,'ISSUED',$4)",[userId,projectId,executionId,'COMMISSIONING_OPERATOR_APPROVED:'+digest]);
  await db.query('COMMIT');
 }catch(error){await db.query('ROLLBACK').catch(()=>{});throw error;}finally{db.release();}
 const bound=Object.freeze({projectId,userId,executionId,expiresAt:scope.expiresAt,authorizationState:'COMMISSIONING'});executionScopes.set(scopeKey(bound),bound);
 return {executionId,projectId,userId,expiresAt:scope.expiresAt,authorizationState:'COMMISSIONING',status:'TRIGGERED'};
}
function audited(operation){return async(pool,context,...args)=>{try{return await operation(pool,context,...args);}catch(error){
 await pool.query("INSERT INTO active_dast_audit (operator_id,project_id,pipeline_execution_id,event,reason) VALUES ($1,$2,$3,'REJECTED','COMMISSIONING_OPERATOR_REQUEST_REJECTED')",['userId','projectId','executionId'].map(k=>Number.isSafeInteger(context?.[k])?context[k]:null));throw error;
}};}
module.exports={enroll:audited(enroll),createExecution:audited(createExecution),scopeFor,assertProjectRole};
