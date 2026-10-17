'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const budget=require('../services/commissioningBudget');
const context={projectId:42,executionId:100,userId:7};
test('all independent deadlines are required; earliest expiry wins, including boundaries',()=>{
 for(let i=0;i<5;i++){const values=Array(5).fill(500000);values[i]=300000;assert.equal(budget.earliest(values),300000);}
 for(const values of [[],[NaN],[undefined],[Infinity],[0],[123.5]])assert.throws(()=>budget.earliest(values));
 assert.equal(budget.minimumMs,225000);
 assert.equal(budget.requireTime(226000,225000,1000),226000);
 assert.throws(()=>budget.requireTime(225999,225000,1000),{code:'COMMISSIONING_TIME_BUDGET_BLOCKED'});
});
test('validated execution approval and signed continuation further restrict grant/runtime deadlines',t=>{
 const c=require('../services/activeDastCommissioning'),control=require('../services/commissioningControl');
 t.mock.method(c,'activeAllowed',()=>true);t.mock.method(c,'selection',()=>({expiresAt:400000}));
 t.mock.method(control,'read',()=>({expiresAt:350000}));
 assert.equal(budget.approvedDeadline(context,[500000,450000,360000],1000),350000);
 assert.equal(budget.approvedDeadline(context,[500000,450000,340000],1000),340000);
 t.mock.method(c,'activeAllowed',()=>false);
 assert.throws(()=>budget.approvedDeadline(context,[500000],1000),{code:'COMMISSIONING_ACTIVE_AUTHORIZATION_BLOCKED'});
});
function clock(){let now=1000,callback;const cleared=[];return {get now(){return now;},advance(ms){now+=ms;},fire(){callback();},cleared,options:{now:()=>now,setTimer:(f,ms)=>{callback=f;assert.equal(ms,195000);return 7;},clearTimer:id=>cleared.push(id)}};}
test('deadline aborts before expiry and reserves cleanup time during startup and scan',async()=>{
 for(const phase of ['startup','scan']){
  const time=clock(),lease=budget.start(time.now+budget.minimumMs,time.options);let drained=false;
  await assert.rejects(lease.run(async()=>{
   assert.equal(lease.signal.aborted,false);if(phase==='scan')budget.beforePlan(lease.signal);
   time.advance(195000);time.fire();await Promise.resolve();drained=true;
  }),{code:'ACTIVE_TIMED_OUT'});
  assert.equal(drained,true);assert.equal(lease.signal.aborted,true);assert.equal(lease.deadline-time.now,30000);
  lease.close();assert.deepEqual(time.cleared,[7]);
 }
});
test('insufficient time after startup prevents starting the Active plan',()=>{
 const time=clock(),lease=budget.start(time.now+budget.minimumMs,time.options);
 time.advance(120001);assert.throws(()=>budget.beforePlan(lease.signal),{code:'COMMISSIONING_TIME_BUDGET_BLOCKED'});lease.close();
 assert.throws(()=>budget.beforePlan(lease.signal),{code:'COMMISSIONING_DEADLINE_BLOCKED'});
});
test('external cancellation drains pending startup before cleanup and releases listeners',async()=>{
 const parent=new AbortController(),time=clock(),lease=budget.start(time.now+budget.minimumMs,{...time.options,signal:parent.signal});let stopped=false;
 await assert.rejects(lease.run(async()=>{parent.abort();await Promise.resolve();stopped=true;}),{code:'ACTIVE_CANCELLED'});
 assert.equal(stopped,true);lease.close();
});
function environment(t){
 const env={NODE_ENV:'test',DAST_ACTIVE_ENABLED:'true',DAST_ACTIVE_COMMISSIONING_ENABLED:'true',DAST_ACTIVE_COMMISSIONING_PHASE:'ACTIVE_COMMISSIONING',DAST_ACTIVE_COMMISSIONING_CONTEXT:JSON.stringify({...context,expiresAt:Date.now()+600000}),DAST_ACTIVE_COMMISSIONING_CONTINUATION_CONTEXT:JSON.stringify({...context,expiresAt:Date.now()+240000})};
 for(const [key,value] of Object.entries(env)){const old=process.env[key];process.env[key]=value;t.after(()=>old===undefined?delete process.env[key]:process.env[key]=old);}
}
function authorization(){const m=require('../services/module2ActiveDast');return m.issueAuthorization({...context,...require('../services/activeDastCommissioning').bind(context,require('../services/activeRuntimeArtifacts').artifacts),gatewayContainerId:'f'.repeat(64),targetId:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',fixtureKind:'cloudsentinel-vulnerable-v1',hostname:'fixture.test',ip:'172.30.1.2',port:18080,scheme:'http',routes:m.ROUTES,zapImageDigest:require('../services/activeRuntimeArtifacts').artifacts.zap.imageId},context);}
for(const phase of ['startup','scan','report','cleanup'])test(`expiry during ${phase} cannot persist successful findings; cleanup runs`,async t=>{
 environment(t);let now=Date.now(),cleaned=0,scanned=0;const initial=now;
 t.mock.method(Date,'now',()=>now);
 const a=authorization(),expire=()=>{now=initial+240000;};
 const report={site:[{alerts:['40018','40012'].map((id,i)=>({pluginid:id,riskcode:3,name:'fixture',instances:[{uri:`http://fixture.test:18080/test/${i?'xss':'sqli'}`}]}))}]};
 const runtime={async provision({signal}){assert.ok(signal);if(phase==='startup')expire();return {};},async verify(){},async scan(){scanned++;if(phase==='scan')expire();return {completed:true,exitCode:0,commissioningTraffic:{verified:true},report};},async cleanup(){cleaned++;if(phase==='cleanup')expire();return {cleaned:true,residual:[]};}};
 const pool={async query(sql){if(sql.includes('deployment_history'))return {rows:[{id:1}]};if(phase==='report')expire();return {rows:[]};}};
 const result=await require('../services/module2ActiveDast').execute({...context,pool,authorization:a},runtime);
 assert.equal(result.status,'TIMED_OUT');assert.equal(result.reason,'ACTIVE_TIMED_OUT');assert.equal(result.findings,undefined);assert.equal(cleaned,1);if(phase==='startup')assert.equal(scanned,0);
});
test('one-minute cap uses the genuine integer-minute schema and preserves seven rules and normal defaults',()=>{
 const source=require('../config/zap-diagnostic-contracts.json');assert.match(JSON.stringify(source),/maxScanDurationInMins:.*Int:/);
 const plans=require('../services/dastActiveScanner'),plan=plans.commissioningPlan('http://fixture.test:18080');
 assert.match(plan,/maxScanDurationInMins: 1\n/);assert.match(plan,/threadPerHost: 1/);assert.match(plan,/delayInMs: 500/);
 for(const id of plans.POLICY.approvedPluginIds)assert.equal((plan.match(new RegExp('id: '+id+'\\n','g'))||[]).length,1);
 assert.match(plans.automationPlan('http://fixture.test:18080/test/sqli'),/maxScanDurationInMins: 10/);
});
test('grant issuance checks every deadline before INSERT; insufficient time rolls back and audits',async t=>{
 environment(t);
 const c=require('../services/activeDastCommissioning'),phases=require('../services/commissioningPhases'),catalog=require('../services/activeRuntimeArtifacts').artifacts;
 const now=Date.now(),scope={...context,expiresAt:now+600000,authorizationState:'COMMISSIONING'};
 t.mock.method(c,'selection',()=>scope);t.mock.method(c,'activeAllowed',()=>true);t.mock.method(c,'assertContextReady',()=>catalog);
 t.mock.method(require('../services/commissioningControl'),'read',()=>({...context,expiresAt:now+240000}));
 t.mock.method(require('../services/activeOperatorEnrollment'),'assertProjectRole',async()=>{});
 t.mock.method(require('../services/activeDastPrerequisites'),'check',async()=>{});
 let phaseExpiry=now+300000;t.mock.method(phases,'assertIssuable',async()=>({expires_at:new Date(phaseExpiry)}));
 const targetId='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
 for(const scenario of ['complete','short-target','short-execution']){
  phaseExpiry=now+(scenario==='short-execution'?173000:300000);
  const expiresAt=now+(scenario==='short-target'?173000:300000);
  const a={...context,...c.bind(context,catalog),targetId,expiresAt,gatewayContainerId:'f'.repeat(64),fixtureContainerId:'b'.repeat(64),scannerNetworkId:'c'.repeat(64),fixtureKind:'cloudsentinel-vulnerable-v1',hostname:'fixture.test',ip:'172.30.1.2',port:18080,scheme:'http',routes:['/test/sqli','/test/xss'],zapImageDigest:catalog.zap.imageId};
  const calls=[];const db={async query(sql){calls.push(sql);return {rows:sql.startsWith('SELECT o.user_id')?[{user_id:7}]:sql.startsWith('SELECT * FROM active_dast_targets')?[{authorization:a,fixture_container_id:a.fixtureContainerId,scanner_network_id:a.scannerNetworkId,verified_until:new Date(expiresAt)}]:[]};},async connect(){return {...db,release(){}};}};
  const task=require('../services/activeDastGrants').issue(db,context,targetId);
  if(scenario==='complete'){await task;assert.ok(calls.includes('COMMIT'));assert.equal(calls.filter(s=>s.startsWith('INSERT INTO active_dast_grants')).length,1);}
  else{await assert.rejects(task,{code:'COMMISSIONING_TIME_BUDGET_BLOCKED'});assert.ok(calls.includes('ROLLBACK'));assert.ok(!calls.some(s=>s.startsWith('INSERT INTO active_dast_grants')));assert.ok(calls.some(s=>s.startsWith('INSERT INTO active_dast_audit')));}
 }
});
test('startup cancellation prevents scanning and cleanup failures remain visible',async t=>{
 environment(t);
 for(const cleanupFails of [false,true]){
  const controller=new AbortController();let scans=0,cleaned=0;
  const runtime={async provision({signal}){controller.abort();assert.equal(signal.aborted,true);return {};},async verify(){},async scan(){scans++;},async cleanup(){cleaned++;return {cleaned:!cleanupFails,residual:cleanupFails?[{type:'owned-scanner'}]:[]};}};
  const result=await require('../services/module2ActiveDast').execute({...context,authorization:authorization(),signal:controller.signal,pool:{async query(){return {rows:[{id:1}]};}}},runtime);
  assert.equal(result.status,cleanupFails?'CLEANUP_FAILED':'CANCELLED');assert.equal(result.reason,'ACTIVE_CANCELLED');assert.equal(result.findings,undefined);assert.equal(scans,0);assert.equal(cleaned,1);
 }
});
test('warm path admits only the 165-second reserve and retains cancellation/cleanup margins',()=>{
 const a={retainedScannerId:'5'.repeat(64)},now=1000;
 assert.equal(budget.minimumFor(a),165000);assert.equal(budget.minimumFor({retainedScannerId:'forged'}),225000);
 assert.throws(()=>budget.start(now+164999,{authorization:a,now:()=>now}),{code:'COMMISSIONING_TIME_BUDGET_BLOCKED'});
 let callback,delay;const lease=budget.start(now+165000,{authorization:a,now:()=>now,setTimer:(f,ms)=>{callback=f;delay=ms;return 1;},clearTimer:()=>{}});
 assert.equal(delay,135000);lease.beforePlan();callback();assert.equal(lease.signal.aborted,true);assert.throws(()=>lease.check(),{code:'ACTIVE_TIMED_OUT'});lease.close();
});
test('insufficient admission records actual remaining and required time without weakening the reserve',()=>{
 let error;assert.throws(()=>budget.requireTime(174761,165000,10000),e=>{error=e;return e.code==='COMMISSIONING_TIME_BUDGET_BLOCKED';});
 assert.deepEqual(error.budget,{remainingMs:164761,requiredMs:165000});
 assert.equal(budget.minimumFor({retainedScannerId:'5'.repeat(64)}),165000);
});
test('fresh verification consuming admission margin blocks before grant consumption and persists timing/cleanup evidence',async t=>{
 environment(t);process.env.NODE_ENV='production';const c=require('../services/activeDastCommissioning'),registry=require('../services/activeRuntimeRegistry');let consumed=0,cleaned=0;
 t.mock.method(c,'assertContextReady',()=>({}));t.mock.method(require('../services/activeDastPrerequisites'),'check',async()=>({}));
 t.mock.method(require('../services/commissioningPhases'),'assertActive',async()=>({expires_at:new Date(Date.now()+240000)}));
 t.mock.method(registry,'waitForGrant',async()=>({authorizationState:'COMMISSIONING',expiresAt:Date.now()+164000,retainedScannerId:'5'.repeat(64)}));
 t.mock.method(registry,'verifyPending',async()=>({verified:true}));
 t.mock.method(registry,'cancelPending',async()=>{cleaned++;return {cleaned:true,residual:[]};});
 t.mock.method(require('../services/activeDastGrants'),'consume',async()=>{consumed++;throw Error('must not consume');});
 const result=await require('../services/module2ActiveDast').execute({...context,pool:{}});
 assert.equal(result.status,'BLOCKED');assert.equal(result.reason,'COMMISSIONING_TIME_BUDGET_BLOCKED');assert.equal(consumed,0);assert.equal(cleaned,1);assert.equal(result.cleanup.cleaned,true);
 assert.equal(result.admission.requiredMs,165000);assert.ok(result.admission.remainingMs<=164000);assert.ok(result.continuationTimings.freshPendingVerificationMs>=0);assert.ok(result.continuationTimings.cleanupMs>=0);assert.equal(result.continuationTimings.source,'MONOTONIC_RUNTIME_CLOCK');
});
