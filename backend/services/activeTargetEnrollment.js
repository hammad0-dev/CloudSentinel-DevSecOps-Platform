'use strict';
const prereq=require('./activeDastPrerequisites'),registry=require('./activeRuntimeRegistry');
const pending=new Set();
const scopes=new WeakMap();
async function prepareStaging(pool,context,{signal}={}){
 prereq.context(context);
 if(!require('./activeDastCommissioning').setupAllowed(context))throw prereq.blocked('COMMISSIONING_CONTEXT_BLOCKED');
 const op=await pool.query("SELECT o.user_id FROM active_dast_operators o JOIN projects p ON p.user_id=o.user_id JOIN pipeline_executions e ON e.project_id=p.id WHERE o.enabled=TRUE AND o.user_id=$1 AND p.id=$2 AND e.id=$3 AND e.status='RUNNING'",[context.userId,context.projectId,context.executionId]);
 if(op.rows.length!==1)throw prereq.blocked('ACTIVE_OPERATOR_OR_EXECUTION_BLOCKED');
 await require('./activeOperatorEnrollment').assertProjectRole(pool,context);
 const catalog=require('./activeDastCommissioning').assertContextReady(context),scanId='act-'+require('crypto').randomUUID().replaceAll('-','').slice(0,24),scope=Object.freeze({});
 scopes.set(scope,{...context,scanId,signal,passive:true,expiresAt:Date.now()+300000});let lifecycle,runtime;
 try{
  lifecycle=require('../scripts/dast-acceptance').createLifecycle();await require('./activeRuntimeArtifacts').verifyAvailable(lifecycle.adapter);
  await lifecycle.provision({...context,scanId,fixtureKind:require('./dastFixture').PYTHON_KIND,nativeConnect:true,mode:'full',productionScope:scope,signal,target:{hostname:scanId+'.test',port:18080}});
  const r=lifecycle.resources.get(scanId),e=r?.runtimeObservation;
  if(!require('./runtimeObservation').runtimeReady(e)||e.profile!=='active')throw prereq.blocked('COMMISSIONING_STAGING_BLOCKED');
  const a=require('./module2ActiveDast').issueBaselineAuthorization({...context,...require('./activeDastCommissioning').bind(context,catalog),fixtureKind:require('./dastFixture').PYTHON_KIND,hostname:e.target.hostname,ip:e.target.ip,port:18080,scheme:'http',routes:[...require('./module2ActiveDast').ROUTES],policies:['SQLI','XSS'],zapImageDigest:catalog.zap.imageId,fixtureContainerId:r.fixtureResource.id,scannerNetworkId:e.scannerNetworkId,gatewayContainerId:r.gatewayId},context);
  runtime=new(require('./activeZapRuntime').ActiveZapRuntime)({lifecycle,adapter:lifecycle.adapter,scanId});
  const baseline=await runtime.baseline({authorization:a,signal});
  return {lifecycle,adapter:lifecycle.adapter,scanId,authorization:a,baseline,runtime};
 }catch(error){if(lifecycle)try{const r=runtime?await runtime.cleanup().then(r=>({state:r.cleaned?'CLEANED':'FAILED',residual:r.residual})):await lifecycle.cleanup(scanId);if(r.state!=='CLEANED'||r.residual?.length)throw Error();}catch(_){registry.noteCleanupFailure(context,{lifecycle,scanId,runtime});throw prereq.blocked('ACTIVE_CLEANUP_FAILED');}throw error;}
 finally{scopes.delete(scope);}
}
function isPreparation(scope,input){const r=scopes.get(scope);return !!r&&!r.signal?.aborted&&r.expiresAt>Date.now()&&(r.passive?require('./activeDastCommissioning').setupAllowed(r):process.env.DAST_ACTIVE_ENABLED==='true')&&['projectId','executionId','userId','scanId'].every(k=>r[k]===input[k])&&input.fixtureKind===require('./dastFixture').PYTHON_KIND&&input.nativeConnect===true&&input.mode==='full'&&input.target?.hostname===r.scanId+'.test'&&input.target?.port===18080;}
async function prepare(pool,context,{fixtureKind,signal}={}){
 const started=require('perf_hooks').performance.now();
 prereq.context(context);
 if(fixtureKind!==require('./dastFixture').PYTHON_KIND||(process.env.DAST_ACTIVE_ENABLED!=='true'&&!require('./activeDastCommissioning').setupAllowed(context)))throw prereq.blocked('ACTIVE_RUNTIME_BLOCKED');
 await prereq.check(pool,context);require('./activeDastCommissioning').assertContextReady(context);
 const staged=require('./commissioningFixtureStage').lookup(context);
 if(staged?.target)return {...staged.target,origin:staged.origin,routes:[...require('./module2ActiveDast').ROUTES],durationMs:Math.round(require('perf_hooks').performance.now()-started)};
 if(process.env.DAST_ACTIVE_ENABLED!=='true')throw prereq.blocked('ACTIVE_RUNTIME_BLOCKED');
 if((await pool.query('SELECT id FROM active_dast_targets WHERE project_id=$1 AND pipeline_execution_id=$2',[context.projectId,context.executionId])).rows.length)throw prereq.blocked('ACTIVE_TARGET_ALREADY_ENROLLED');
 const key=`${context.projectId}:${context.executionId}`;if(pending.has(key))throw prereq.blocked('ACTIVE_ENROLLMENT_IN_PROGRESS');pending.add(key);
 const scanId='act-'+require('crypto').randomUUID().replaceAll('-','').slice(0,24);
 const scope=Object.freeze({});scopes.set(scope,{...context,scanId,signal,expiresAt:Date.now()+300000});
 let lifecycle,registered=false;
 try{
  if(signal?.aborted)throw prereq.blocked('ACTIVE_CANCELLED');
  lifecycle=require('../scripts/dast-acceptance').createLifecycle();
  await require('./activeRuntimeArtifacts').verifyAvailable(lifecycle.adapter);
  await lifecycle.provision({...context,scanId,fixtureKind,nativeConnect:true,mode:'full',productionScope:scope,signal,target:{hostname:scanId+'.test',port:18080}});
  if(signal?.aborted)throw prereq.blocked('ACTIVE_CANCELLED');
  await prereq.check(pool,context);
  const result=await registry.enroll(pool,context,{lifecycle,adapter:lifecycle.adapter,scanId});registered=true;
  return {...result,scanId,origin:`http://${scanId}.test:18080`,routes:[...require('./module2ActiveDast').ROUTES]};
 }finally{
  pending.delete(key);
  scopes.delete(scope);
  if(lifecycle&&!registered)try{const cleanup=await lifecycle.cleanup(scanId);if(cleanup.state!=='CLEANED'||!Array.isArray(cleanup.residual)||cleanup.residual.length)throw Error('cleanup incomplete');}catch(_){registry.noteCleanupFailure(context,{lifecycle,scanId});throw Object.assign(prereq.blocked('ACTIVE_CLEANUP_FAILED'),{status:503});}
 }
}
module.exports={prepare,isPreparation,prepareStaging};
