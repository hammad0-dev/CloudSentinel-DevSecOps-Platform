'use strict';
const live=new Map();
const failedCleanup=new Map();
const fail=()=>Object.assign(new Error('No live grant-bound Active lifecycle'),{code:'ACTIVE_RUNTIME_BLOCKED',nonRetryable:true});
function key(a){return `${a.projectId}:${a.executionId}:${a.targetId}`;}
async function cleanupEntry(entry){
 if(entry.runtime){const r=await entry.runtime.cleanup();return {state:r.cleaned?'CLEANED':'FAILED',residual:r.residual};}
 return entry.lifecycle.cleanup(entry.scanId);
}
function register(authorization,{lifecycle,adapter,scanId,runtime}) {
  require('./activeDastCommissioning').assertAuthorizationReady(authorization);
  require('./module2ActiveDast').validateAuthorization(authorization,authorization);
  if(!(lifecycle instanceof require('./dastGateway').SecureGatewayLifecycle)||!require('./dockerAdapter').isRuntimeAdapter(adapter)||lifecycle.adapter!==adapter)throw fail();
  const resources=lifecycle.resources.get(scanId);
  if(!resources||resources.diagnosticOnly===true||lifecycle.states.get(scanId)!=='READY'||resources.fixtureResource?.fixtureKind!==require('./dastFixture').PYTHON_KIND||resources.fixtureResource?.id!==authorization.fixtureContainerId||!resources.owned?.networks.some(n=>n.id===authorization.scannerNetworkId)||live.has(key(authorization)))throw fail();
  if(runtime&&(!(runtime instanceof require('./activeZapRuntime').ActiveZapRuntime)||runtime.lifecycle!==lifecycle||runtime.adapter!==adapter||runtime.scanId!==scanId||runtime.retainedIdentity(authorization).scannerId!==authorization.retainedScannerId))throw fail();
  if(authorization.retainedScannerId&&!runtime)throw fail();
  const entry={lifecycle,adapter,scanId,authorization,runtime};
  entry.timer=setTimeout(()=>{if(live.get(key(authorization))!==entry)return;live.delete(key(authorization));failedCleanup.set(key(authorization),entry);entry.expiryCleanup=(async()=>{try{const r=await cleanupEntry(entry);const cleaned=r.state==='CLEANED'&&Array.isArray(r.residual)&&!r.residual.length;if(entry.onCleanup)await entry.onCleanup({cleaned,residual:r.residual||[]},true);if(cleaned)failedCleanup.delete(key(authorization));}catch(_){/* retained for the execution's CLEANUP_FAILED report */}})();},Math.max(1,authorization.expiresAt-Date.now()));entry.timer.unref();
  live.set(key(authorization),entry);
}
// Trusted server-side enrollment only. No request-body snapshots or standalone
// scan endpoint. The catalog and genuine observed lifecycle must already pass.
async function enroll(pool,context,{lifecycle,adapter,scanId,runtime}) {
  const catalog=require('./activeDastCommissioning').assertContextReady(context);
  if(![context.projectId,context.executionId,context.userId].every(v=>Number.isSafeInteger(v)&&v>0)||context.projectId===17)throw fail();
  if(!(lifecycle instanceof require('./dastGateway').SecureGatewayLifecycle)||!require('./dockerAdapter').isRuntimeAdapter(adapter)||lifecycle.adapter!==adapter)throw fail();
  const r=lifecycle.resources.get(scanId),e=r?.runtimeObservation;
  if(lifecycle.states.get(scanId)!=='READY'||!require('./runtimeObservation').runtimeReady(e)||e.profile!=='active'||e.projectId!==context.projectId||e.executionId!==context.executionId||e.scanId!==scanId||r.fixtureResource?.fixtureKind!==require('./dastFixture').PYTHON_KIND)throw fail();
  await require('./activeRuntimeArtifacts').verifyAvailable(adapter,catalog);
  const raw=await adapter.run(['inspect','--format','{{json .}}',r.fixtureResource.id]);
  if(raw.exitCode!==0||raw.stderr!=='')throw fail();
  const fixture=JSON.parse(raw.stdout);
  require('./dastFixture').verifyPythonRuntime(fixture,r.fixtureResource);
  const reference=r.owned?.networks.find(n=>n.id===r.fixtureResource.networkId);
  const network=await require('./ownedDockerNetworks').inspectOwnedNetwork(adapter,reference);
  require('./ownedDockerNetworks').verifyMemberships({networks:fixture.NetworkSettings.Networks},[network]);
  if(fixture.NetworkSettings.Networks[network.name]?.IPAddress!==e.target.ip)throw fail();
  const authorization={...context,targetId:require('crypto').randomUUID(),fixtureKind:require('./dastFixture').PYTHON_KIND,hostname:e.target.hostname,ip:e.target.ip,port:e.target.port,scheme:'http',routes:[...require('./module2ActiveDast').ROUTES],policies:['SQLI','XSS'],zapImageDigest:catalog.zap.imageId,fixtureContainerId:r.fixtureResource.id,scannerNetworkId:e.scannerNetworkId,expiresAt:Date.now()+300000,...require('./activeDastCommissioning').bind(context,catalog),...(require('./activeDastCommissioning').selection(context)?{gatewayContainerId:r.gatewayId}:{})};
  require('./module2ActiveDast').validateAuthorization(authorization,context);
  Object.assign(authorization,require('./commissioningFixtureStage').binding(context));
  if(runtime){
    if(!(runtime instanceof require('./activeZapRuntime').ActiveZapRuntime)||runtime.lifecycle!==lifecycle||runtime.adapter!==adapter||runtime.scanId!==scanId)throw fail();
    authorization.retainedScannerId=runtime.retainedIdentity(authorization).scannerId;
    await runtime.verifyRetained(authorization);
  }
  const db=await pool.connect();let registered=false;
  try {
    await db.query('BEGIN');
    await require('./activeOperatorEnrollment').assertProjectRole(db,context);
    const operator=await db.query("SELECT o.user_id FROM active_dast_operators o JOIN projects p ON p.user_id=o.user_id JOIN pipeline_executions e ON e.project_id=p.id WHERE o.user_id=$1 AND o.enabled=TRUE AND p.id=$2 AND e.id=$3 AND e.status='RUNNING' FOR SHARE OF o,p,e",[context.userId,context.projectId,context.executionId]);
    if(operator.rows.length!==1)throw fail();
    await db.query('INSERT INTO active_dast_targets (id,project_id,pipeline_execution_id,fixture_container_id,scanner_network_id,"authorization",verified_until) VALUES ($1,$2,$3,$4,$5,$6,to_timestamp($7/1000.0))',[authorization.targetId,context.projectId,context.executionId,authorization.fixtureContainerId,authorization.scannerNetworkId,JSON.stringify(authorization),authorization.expiresAt]);
    if(authorization.authorizationState==='COMMISSIONING')await db.query("INSERT INTO active_dast_audit (operator_id,project_id,pipeline_execution_id,event,reason) VALUES ($1,$2,$3,'ISSUED','COMMISSIONING_TARGET_ENROLLED')",[context.userId,context.projectId,context.executionId]);
    register(authorization,{lifecycle,adapter,scanId,runtime});registered=true;
    await db.query('COMMIT');return {targetId:authorization.targetId,expiresAt:authorization.expiresAt,...(authorization.authorizationState?{authorizationState:authorization.authorizationState,productionReady:false}:{})};
  } catch(error) {
    if(registered){clearTimeout(live.get(key(authorization))?.timer);live.delete(key(authorization));}
    await db.query('ROLLBACK').catch(()=>{});throw error;
  } finally {db.release();}
}
function consume(authorization) {
  const k=key(authorization),entry=live.get(k);if(!entry)throw fail();
  if(entry.authorization.expiresAt<=Date.now()||entry.authorization.userId!==authorization.userId||entry.authorization.fixtureContainerId!==authorization.fixtureContainerId||entry.authorization.scannerNetworkId!==authorization.scannerNetworkId)throw fail();
  if(['hostname','ip','port','scheme','routes','policies','zapImageDigest','authorizationState','fixtureImageDigest','gatewayImageDigest','gatewayContainerId','baselineScanId','stagingEvidenceSha256','retainedScannerId'].some(k=>JSON.stringify(entry.authorization[k])!==JSON.stringify(authorization[k])))throw fail();
  if(entry.runtime)entry.runtime.retainedIdentity(authorization);
  const runtime=entry.runtime||new (require('./activeZapRuntime').ActiveZapRuntime)(entry);
  clearTimeout(entry.timer);
  live.delete(k);
  return runtime;
}
async function waitForGrant(pool,context,signal){
  require('./activeDastPrerequisites').context(context);const deadline=Date.now()+300000;
  while(Date.now()<deadline){
    if(signal?.aborted)throw Object.assign(fail(),{code:'ACTIVE_CANCELLED'});
    if(process.env.DAST_ACTIVE_ENABLED!=='true'&&!require('./activeDastCommissioning').activeAllowed(context))throw fail();
    const rows=(await pool.query('SELECT target_id FROM active_dast_grants WHERE project_id=$1 AND pipeline_execution_id=$2 AND operator_id=$3 AND consumed_at IS NULL AND expires_at>NOW()',[context.projectId,context.executionId,context.userId])).rows;
    const entry=rows.length===1?live.get(key({...context,targetId:rows[0].target_id})):null;
    if(entry&&entry.authorization.userId===context.userId&&entry.authorization.expiresAt>Date.now())return entry.authorization;
    await new Promise(resolve=>{const finish=()=>{clearTimeout(timer);signal?.removeEventListener('abort',finish);resolve();};const timer=setTimeout(finish,1000);signal?.addEventListener('abort',finish,{once:true});});
  }
  throw Object.assign(fail(),{code:'ACTIVE_AUTHORIZATION_WAIT_BLOCKED'});
}
async function cancel(context,targetId){
  require('./activeDastPrerequisites').context(context);const k=key({...context,targetId}),entry=live.get(k);
  if(!entry||entry.authorization.userId!==context.userId)throw fail();clearTimeout(entry.timer);live.delete(k);
  try{const cleanup=await cleanupEntry(entry);if(cleanup.state!=='CLEANED'||!Array.isArray(cleanup.residual)||cleanup.residual.length)throw Object.assign(fail(),{code:'ACTIVE_CLEANUP_FAILED'});if(entry.onCleanup)await entry.onCleanup({cleaned:true,residual:[]},false);return cleanup;}catch(error){failedCleanup.set(k,entry);throw error;}
}
async function cancelPending(context){
 const matching=entry=>['projectId','executionId','userId'].every(k=>entry.authorization[k]===context[k]);const residual=[];
 for(const entry of [...live.values()].filter(matching))try{await cancel(context,entry.authorization.targetId);}catch(_){residual.push({type:'active-enrollment',scanId:entry.scanId});}
 for(const entry of [...failedCleanup.values()])if(matching(entry)){await entry.expiryCleanup;if(failedCleanup.has(key(entry.authorization)))residual.push({type:entry.phase||'expired-active-enrollment',scanId:entry.scanId});}
 return {cleaned:residual.length===0,residual};
}
async function verifyPending(authorization){const entry=live.get(key(authorization));if(!entry||entry.authorization!==authorization||authorization.expiresAt<=Date.now())throw fail();return entry.runtime?entry.runtime.verifyRetained(authorization):new(require('./activeZapRuntime').ActiveZapRuntime)(entry).preflight(authorization);}
function noteCleanupFailure(context,{lifecycle,scanId,runtime}){require('./activeDastPrerequisites').context(context);const authorization={...context,targetId:'preparation:'+scanId};failedCleanup.set(key(authorization),{authorization,lifecycle,scanId,runtime,phase:'active-preparation'});}
function pendingFor(context,targetId){const entry=live.get(key({...context,targetId}));if(!entry||entry.authorization.userId!==context.userId||entry.authorization.expiresAt<=Date.now())throw fail();return entry.authorization;}
function watchCleanup(context,targetId,listener){const a=pendingFor(context,targetId);if(typeof listener!=='function')throw fail();live.get(key(a)).onCleanup=listener;}
module.exports={register,consume,enroll,waitForGrant,verifyPending,cancel,cancelPending,noteCleanupFailure,pendingFor,watchCleanup};
