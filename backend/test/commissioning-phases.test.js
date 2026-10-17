'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const ctx={projectId:42,executionId:100,userId:7},phases=require('../services/commissioningPhases'),commission=require('../services/activeDastCommissioning');
function setup(t){const keys=['DAST_ACTIVE_ENABLED','DAST_ACTIVE_COMMISSIONING_ENABLED','DAST_ACTIVE_COMMISSIONING_CONTEXT','DAST_COMMISSIONING_SETUP_ENABLED','DAST_ACTIVE_COMMISSIONING_PHASE','DAST_ACTIVE_COMMISSIONING_CONTINUATION_CONTEXT'];const old=keys.map(k=>process.env[k]);t.after(()=>keys.forEach((k,i)=>{if(old[i]===undefined)delete process.env[k];else process.env[k]=old[i];}));process.env.DAST_ACTIVE_ENABLED='false';process.env.DAST_ACTIVE_COMMISSIONING_ENABLED='true';process.env.DAST_COMMISSIONING_SETUP_ENABLED='true';process.env.DAST_ACTIVE_COMMISSIONING_CONTEXT=JSON.stringify({...ctx,expiresAt:Date.now()+600000});delete process.env.DAST_ACTIVE_COMMISSIONING_PHASE;delete process.env.DAST_ACTIVE_COMMISSIONING_CONTINUATION_CONTEXT;t.mock.method(require('../services/commissioningFixtureStage'),'lookup',()=>({fixtureContainerId:'a'.repeat(64),baselineScanId:12,sha256:'b'.repeat(64),target:{targetId:'target'}}));}
function enableActive(){process.env.DAST_ACTIVE_ENABLED='true';process.env.DAST_ACTIVE_COMMISSIONING_PHASE='ACTIVE_COMMISSIONING';process.env.DAST_ACTIVE_COMMISSIONING_CONTINUATION_CONTEXT=JSON.stringify({...ctx,expiresAt:Date.now()+240000});}
function database(scenario='ok'){
 const calls=[];let phase=scenario==='active'?'ACTIVE_COMMISSIONING':'AWAITING_ACTIVE_AUTHORIZATION';
 const db={calls,async query(sql,args){calls.push({sql,args});
  if(sql.includes('to_regclass'))return {rows:scenario==='schema'?[]:[{phase_table:'active_dast_commissioning_phases'}]};
  if(sql.startsWith('SELECT c.*'))return {rows:['expired','owner'].includes(scenario)?[]:[{expires_at:new Date(Date.now()+300000),phase,runtime_retained:scenario!=='gone',target_id:'target',fixture_container_id:'a'.repeat(64),baseline_scan_id:12,baseline_sha256:'b'.repeat(64)}]};
  if(sql.startsWith('SELECT target_id,runtime_retained'))return {rows:[{target_id:'target',runtime_retained:scenario==='untracked'}]};
  if(sql.startsWith('UPDATE pipeline_executions'))return {rows:scenario==='execution'?[]:[{id:100}]};
  if(sql.startsWith('SELECT id,expires_at FROM active_dast_grants'))return {rows:scenario==='grant'?[]:[{id:'grant',expires_at:new Date(Date.now()+300000)}]};
  if(sql.startsWith('UPDATE active_dast_commissioning_phases')&&sql.includes('RETURNING phase')){if(phase==='ACTIVE_COMMISSIONING'&&sql.includes("phase='ACTIVE_COMMISSIONING'"))return {rows:[]};if(scenario==='race')return {rows:[]};if(sql.includes("SET phase='ACTIVE_COMMISSIONING'"))phase='ACTIVE_COMMISSIONING';return {rows:[{phase}]};}
  return {rows:[]};},async connect(){return {...db,release(){}};}};return db;
}
test('passive setup flag is independent; explicit Active authorization cannot be inferred from API parameters',t=>{
 setup(t);assert.equal(commission.setupAllowed(ctx),true);assert.equal(commission.activeAllowed(ctx),false);
 process.env.DAST_ACTIVE_ENABLED='true';assert.equal(commission.activeAllowed(ctx),false);enableActive();assert.equal(commission.activeAllowed(ctx),true);
 assert.equal(commission.activeAllowed({...ctx,projectId:17}),false);
 process.env.DAST_ACTIVE_COMMISSIONING_CONTINUATION_CONTEXT=JSON.stringify({...ctx,expiresAt:Date.now()-1});assert.equal(commission.activeAllowed(ctx),false);
});
test('passive authorization permits only baseline runtime while Active is disabled',t=>{
 setup(t);const c=require('../services/activeRuntimeArtifacts').artifacts,m=require('../services/module2ActiveDast');
 const input={...ctx,...commission.bind(ctx,c),gatewayContainerId:'a'.repeat(64),fixtureKind:'cloudsentinel-vulnerable-v1',hostname:'fixture.test',ip:'172.30.1.2',port:18080,scheme:'http',routes:m.ROUTES,zapImageDigest:c.zap.imageId};
 const passive=m.issueBaselineAuthorization(input,ctx),active=m.issueAuthorization(input,ctx);
 assert.equal(commission.runtimeAllowed(passive),true);assert.equal(commission.runtimeAllowed(active),false);assert.equal(m.isBaselineAuthorization({...passive}),false);
 const plan=require('../services/dastActiveScanner').commissioningPlan('http://fixture.test:18080',{baseline:true});assert.equal(plan.includes('type: activeScan'),false);
});
test('disabled Active service cannot consume a grant or execute a scanner during passive setup',async t=>{
 setup(t);let scans=0,queries=0;const result=await require('../services/module2ActiveDast').execute({...ctx,pool:{async query(){queries++;throw Error('unexpected database operation');}}},{async scan(){scans++;}});
 assert.equal(result.status,'DISABLED');assert.equal(scans,0);assert.equal(queries,0);
});
test('legitimate setup transition works with Active false and rolls back wrong execution',async t=>{
 setup(t);const db=database();await phases.beginSetup(db,ctx);assert.ok(db.calls.some(c=>c.sql.includes("'PASSIVE_SETUP'")));assert.ok(db.calls.some(c=>c.sql==='COMMIT'));assert.ok(!db.calls.some(c=>c.sql.includes('consumed_at')));
 const bad=database('execution');await assert.rejects(phases.beginSetup(bad,ctx));assert.ok(bad.calls.some(c=>c.sql==='ROLLBACK'));
 await assert.rejects(phases.beginSetup(database('schema'),ctx),{code:'COMMISSIONING_PHASE_MIGRATION_REQUIRED'});
});
test('pause needs genuine staging and inspected runtime, retains resources and never consumes grants',async t=>{
 setup(t);const db=database(),stage=require('../services/commissioningFixtureStage'),registry=require('../services/activeRuntimeRegistry');let hook;
 t.mock.method(stage,'verify',async()=>({stagingUrl:'http://fixture.test:18080/'}));t.mock.method(stage,'lookup',()=>({target:{targetId:'target'},fixtureContainerId:'a'.repeat(64),baselineScanId:12,sha256:'b'.repeat(64),expiresAt:Date.now()+60000}));
 t.mock.method(registry,'pendingFor',()=>({...ctx,expiresAt:Date.now()+60000}));t.mock.method(registry,'verifyPending',async()=>({verified:true}));t.mock.method(registry,'watchCleanup',(c,id,callback)=>{hook=callback;});t.mock.method(stage,'release',()=>{});
 const result=await phases.pause(db,ctx);assert.equal(result.phase,'AWAITING_ACTIVE_AUTHORIZATION');assert.equal(result.activeScanCount,0);assert.equal(result.grantConsumed,false);assert.equal(result.runtimeRetained,true);assert.ok(!db.calls.some(c=>c.sql.startsWith('UPDATE active_dast_grants')));
 await hook({cleaned:true,residual:[]},true);assert.ok(db.calls.some(c=>c.args?.includes('EXPIRED')));
});
test('failed staging cannot create a resumable pause',async t=>{
 setup(t);const db=database();t.mock.method(require('../services/commissioningFixtureStage'),'verify',async()=>{throw Error('baseline missing');});await assert.rejects(phases.pause(db,ctx));assert.equal(db.calls.length,0);
});
test('contradictory persisted fixture/baseline identity cannot issue or resume a grant',async t=>{
 setup(t);const db=database();t.mock.method(require('../services/commissioningFixtureStage'),'lookup',()=>({fixtureContainerId:'f'.repeat(64),baselineScanId:99,sha256:'c'.repeat(64),target:{targetId:'other'}}));
 await assert.rejects(phases.assertIssuable(db,ctx),{code:'COMMISSIONING_PHASE_IDENTITY_BLOCKED'});
});
test('resume rejects disabled Active or absent separate scope before touching grants',async t=>{
 setup(t);const db=database();await assert.rejects(phases.resume(db,ctx),{code:'COMMISSIONING_ACTIVE_AUTHORIZATION_BLOCKED'});assert.equal(db.calls.length,0);
 process.env.DAST_ACTIVE_ENABLED='true';await assert.rejects(phases.resume(db,ctx));assert.equal(db.calls.length,0);
});
for(const scenario of ['expired','owner','gone','grant','race'])test('resume fails closed for '+scenario,async t=>{
 setup(t);enableActive();const db=database(scenario),registry=require('../services/activeRuntimeRegistry');
 t.mock.method(registry,'pendingFor',()=>({...ctx,expiresAt:Date.now()+60000}));t.mock.method(registry,'verifyPending',async()=>({verified:true}));t.mock.method(registry,'cancelPending',async()=>({cleaned:true,residual:[]}));t.mock.method(require('../services/activeDastPrerequisites'),'check',async()=>({}));
 await assert.rejects(phases.resume(db,ctx));assert.ok(!db.calls.some(c=>c.sql.startsWith('UPDATE active_dast_grants')&&c.sql.includes('consumed_at=NOW()')));
});
test('resume is a single atomic phase transition; it does not consume the grant',async t=>{
 setup(t);enableActive();const db=database(),registry=require('../services/activeRuntimeRegistry');t.mock.method(registry,'pendingFor',()=>({...ctx,expiresAt:Date.now()+300000}));t.mock.method(registry,'verifyPending',async()=>({verified:true}));t.mock.method(require('../services/activeDastPrerequisites'),'check',async()=>({}));
 assert.equal((await phases.resume(db,ctx)).phase,'ACTIVE_COMMISSIONING');await assert.rejects(phases.resume(db,ctx));assert.ok(db.calls.every(c=>!c.sql.includes('SET consumed_at')));
});
test('lost private runtime registry is a cleanup failure and cannot preserve eligibility',async t=>{
 setup(t);const db=database('untracked');t.mock.method(require('../services/activeRuntimeRegistry'),'pendingFor',()=>{throw Error('lost registry');});const r=await phases.cleanup(db,ctx);assert.equal(r.cleaned,false);assert.equal(r.residual[0].type,'untracked-paused-runtime');assert.ok(db.calls.some(c=>c.args?.includes('CLEANUP_FAILED')));
});
test('insufficient retained lifetime cleans the pause without transitioning or consuming a grant',async t=>{
 setup(t);enableActive();const db=database(),registry=require('../services/activeRuntimeRegistry');let cleaned=0;
 t.mock.method(registry,'pendingFor',()=>({...ctx,expiresAt:Date.now()+173000}));
 t.mock.method(registry,'verifyPending',async()=>({verified:true}));
 t.mock.method(registry,'cancelPending',async()=>{cleaned++;return {cleaned:true,residual:[]};});
 t.mock.method(require('../services/activeDastPrerequisites'),'check',async()=>({}));
 await assert.rejects(phases.resume(db,ctx),{code:'COMMISSIONING_TIME_BUDGET_BLOCKED'});
 assert.equal(cleaned,1);assert.ok(!db.calls.some(c=>c.sql.includes("SET phase='ACTIVE_COMMISSIONING'")));
 assert.ok(!db.calls.some(c=>c.sql.includes('SET consumed_at')));
});
test('source-only migration binds paused state to execution, target, baseline and owner',()=>{
 const sql=require('fs').readFileSync(require('path').join(__dirname,'../migrations/014_active_dast_commissioning_phases.sql'),'utf8');
 for(const field of ['AWAITING_ACTIVE_AUTHORIZATION','runtime_retained','fixture_container_id','baseline_scan_id','baseline_sha256','expires_at','FOREIGN KEY (pipeline_execution_id,project_id)','FOREIGN KEY (target_id,project_id,pipeline_execution_id)','project_id <> 17'])assert.ok(sql.includes(field));
});
