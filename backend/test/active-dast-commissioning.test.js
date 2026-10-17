'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const service=require('../services/activeDastCommissioning');
const artifacts=require('../services/activeRuntimeArtifacts');
const context={projectId:42,executionId:100,userId:7};
function enabled(t){
 const keys=['DAST_ACTIVE_COMMISSIONING_ENABLED','DAST_ACTIVE_COMMISSIONING_CONTEXT','DAST_ACTIVE_ENABLED','NODE_ENV','DAST_COMMISSIONING_SETUP_ENABLED','DAST_ACTIVE_COMMISSIONING_PHASE','DAST_ACTIVE_COMMISSIONING_CONTINUATION_CONTEXT'];
 const saved=keys.map(k=>process.env[k]);t.after(()=>keys.forEach((k,i)=>{if(saved[i]===undefined)delete process.env[k];else process.env[k]=saved[i];}));
 process.env.DAST_ACTIVE_COMMISSIONING_ENABLED='true';process.env.DAST_ACTIVE_COMMISSIONING_CONTEXT=JSON.stringify({...context,expiresAt:Date.now()+600000});process.env.DAST_ACTIVE_ENABLED='true';process.env.NODE_ENV='test';process.env.DAST_COMMISSIONING_SETUP_ENABLED='true';process.env.DAST_ACTIVE_COMMISSIONING_PHASE='ACTIVE_COMMISSIONING';process.env.DAST_ACTIVE_COMMISSIONING_CONTINUATION_CONTEXT=JSON.stringify({...context,expiresAt:Date.now()+240000});
}
function authorization(){return {...context,...service.bind(context,artifacts.artifacts),gatewayContainerId:'f'.repeat(64),targetId:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',fixtureKind:'cloudsentinel-vulnerable-v1',hostname:'fixture.test',ip:'172.30.1.2',port:18080,scheme:'http',routes:['/test/sqli','/test/xss'],zapImageDigest:artifacts.artifacts.zap.imageId};}
function catalog(){const c=structuredClone(artifacts.artifacts);c.zap.capabilities={verified:true,imageId:c.zap.imageId,activeRuleIds:require('../config/zap-active-policy-v1.json').approvedPluginIds,commands:['automation','spider','activeScan','report','proxy','rateLimit','sha256sum','python3'],initialization:require('./helpers/zapInitializationEvidence')(c.zap.imageId),runtimeContract:{apiBinding:'LOOPBACK_ONLY',apiAuthentication:'REQUIRED',maxRequestsPerSecond:2,maxConcurrency:1,spiderRateLimited:true,exactPathScope:true,exportFormat:'traditional-json',evidenceSha256:'e'.repeat(64)}};return c;}
test('commissioning is disabled by default and never changes production readiness',t=>{
 enabled(t);delete process.env.DAST_ACTIVE_COMMISSIONING_ENABLED;assert.equal(service.selection(context),null);
 const c=catalog();assert.throws(()=>artifacts.assertReady(c));assert.equal(c.containmentAdapterValidated,false);
});
test('commissioning scope is explicit, expiring, and execution/operator bound',t=>{
 enabled(t);assert.equal(service.selection(context).authorizationState,'COMMISSIONING');
 for(const k of ['projectId','executionId','userId'])assert.equal(service.selection({...context,[k]:context[k]+1}),null);
 const now=Date.now();
 for(const scope of [{...context,projectId:17,expiresAt:now+5000},{...context,expiresAt:now-1},{...context,expiresAt:now+900001},{...context,expiresAt:now+5000,url:'http://external.test'}]){
  process.env.DAST_ACTIVE_COMMISSIONING_CONTEXT=JSON.stringify(scope);assert.throws(()=>service.selection(context,now));
 }
});
test('commissioning accepts only scan-dependent unknowns and never mutates a capability record',()=>{
 const c=catalog(),before=JSON.stringify(c);assert.equal(service.assertReady(c),c);assert.equal(JSON.stringify(c),before);assert.throws(()=>artifacts.assertReady(c));
 for(const field of service.UNKNOWN){const bad=catalog();bad.zap.capabilities.runtimeContract[field]=false;assert.throws(()=>service.assertReady(bad));}
});
for(const [name,mutate] of [
 ['wrong image',c=>c.zap.imageId='sha256:'+'a'.repeat(64)],
 ['wrong fixture',c=>c.fixture.imageId='sha256:'+'b'.repeat(64)],
 ['missing namespace evidence',c=>c.verifiedConfiguration.diagnosticCasesPassed=11],
 ['missing rules',c=>c.zap.capabilities.activeRuleIds=['40018']],
 ['missing authentication',c=>c.zap.capabilities.runtimeContract.apiAuthentication='OPTIONAL'],
 ['unsafe rate',c=>c.zap.capabilities.runtimeContract.maxRequestsPerSecond=100],
 ['unsafe concurrency',c=>c.zap.capabilities.runtimeContract.maxConcurrency=2],
 ['missing path scope',c=>c.zap.capabilities.runtimeContract.exactPathScope=false],
 ['incomplete initialization',c=>c.zap.capabilities.initialization.complete=false],
 ['missing policy',c=>c.zap.capabilities.initialization.policy.xmlParsed=false]
])test('commissioning blocks '+name,()=>{const c=catalog();mutate(c);assert.throws(()=>service.assertReady(c));});
test('commissioning authorization binds pinned images and gateway and rejects ordinary grants in its scope',t=>{
 enabled(t);const a=authorization(),validate=require('../services/module2ActiveDast').validateAuthorization;
 assert.equal(validate(a,context),a);
 for(const k of ['zapImageDigest','fixtureImageDigest','gatewayImageDigest','gatewayContainerId'])assert.throws(()=>validate({...a,[k]:'wrong'},context));
 for(const patch of [{hostname:'example.com'},{port:80},{routes:['/']},{projectId:17},{expiresAt:Date.now()-1},{authorizationState:undefined}])assert.throws(()=>validate({...a,...patch},context));
 assert.throws(()=>validate(a,{...context,executionId:101}));
});
test('benign request is exact, bounded and cannot follow a redirect',t=>{
 enabled(t);const plan=service.benignRequest(authorization());assert.equal(plan.name,'sendRequest');assert.equal(plan.followRedirects,false);assert.equal(plan.timeoutMs,10000);assert.match(plan.request,/^GET http:\/\/fixture.test:18080\/test\/sqli\?id=1 HTTP\/1.1\r\n/);
 assert.throws(()=>service.benignRequest({...authorization(),hostname:'fixture.test\r\nInjected: true'}));
});
test('missing trusted application evidence blocks completion and always cleans the session',async t=>{
 enabled(t);const module2=require('../services/module2ActiveDast'),a=module2.issueAuthorization(authorization(),context),calls=[];
 const runtime={async provision(){calls.push('provision');return {};},async verify(){calls.push('verify');},async verifyCommissioningTraffic(){calls.push('traffic');throw Object.assign(Error(),{code:'COMMISSIONING_APPLICATION_COLLECTOR_BLOCKED'});},async scan(){calls.push('scan');throw Object.assign(Error(),{code:'COMMISSIONING_APPLICATION_TRAFFIC_BLOCKED'});},async cleanup(){calls.push('cleanup');return {cleaned:true,residual:[]};}};
 const pool={async query(){return {rows:[{id:1}]};}};
 const r=await module2.execute({...context,pool,authorization:a},runtime);assert.equal(r.status,'BLOCKED');assert.ok(calls.includes('scan'));assert.equal(calls.at(-1),'cleanup');assert.equal(r.commissioning.productionReady,false);assert.equal(r.commissioning.cancellation,'NOT_EXERCISED');
 const reused=await module2.execute({...context,pool,authorization:a},runtime);assert.equal(reused.reason,'ACTIVE_AUTHORIZATION_BLOCKED');
});
test('cleanup failure dominates commissioning failure without promoting evidence',async t=>{
 enabled(t);const m=require('../services/module2ActiveDast'),a=m.issueAuthorization(authorization(),context);
 const runtime={async provision(){throw Object.assign(Error(),{code:'ACTIVE_CANCELLED'});},async cleanup(){return {cleaned:false,residual:[{type:'owned'}]};}};
 const r=await m.execute({...context,pool:{async query(){return {rows:[{id:1}]};}},authorization:a},runtime);assert.equal(r.status,'CLEANUP_FAILED');assert.equal(r.reason,'ACTIVE_CANCELLED');assert.equal(r.commissioning.productionReady,false);
});
test('normal completion never proves rate, concurrency, cancellation or timeout',()=>{
 const r=service.evidenceSummary({completed:true},{cleaned:true});assert.equal(r.completion,'OBSERVED');assert.equal(r.rateEnforcement,'UNVERIFIED');assert.equal(r.cancellation,'NOT_EXERCISED');assert.equal(r.timeout,'NOT_EXERCISED');assert.equal(r.productionReady,false);
});
test('one commissioning job seeds both parameterized endpoints with an exact two-path context',t=>{
 enabled(t);const p=require('../services/module2ActiveDast').plans(authorization());assert.equal(p.length,1);
 assert.equal((p[0].match(/  - type: activeScan\n/g)||[]).length,1);assert.ok(!p[0].includes('type: spider'));
 assert.match(p[0],/sqli\?id=1/);assert.match(p[0],/xss\?q=hello/);
 const line=p[0].split('\n').find(s=>s.includes('includePaths:'));const patterns=JSON.parse(line.split('includePaths: ')[1]);
 for(const url of ['http://fixture.test:18080/test/sqli?id=2','http://fixture.test:18080/test/xss?q=payload'])assert.ok(patterns.some(p=>new RegExp(p).test(url)));
 for(const url of ['http://fixture.test:18080/health','http://external.test:18080/test/sqli?id=1'])assert.ok(patterns.every(p=>!new RegExp(p).test(url)));
});
test('commissioning grant consumption remains atomic and independently compares commissioning scope',async t=>{
 enabled(t);t.mock.method(require('../services/activeDastPrerequisites'),'check',async()=>({stagingUrl:'http://fixture.test:18080/'}));t.mock.method(require('../services/commissioningPhases'),'assertActive',async()=>({phase:'ACTIVE_COMMISSIONING'}));const a={...authorization(),fixtureContainerId:'b'.repeat(64),scannerNetworkId:'c'.repeat(64),policies:['SQLI','XSS']};let taken=false;const calls=[];
 const db={async query(){return {rows:[]};},async connect(){return {async query(sql,params){calls.push({sql,params});if(!sql.startsWith('UPDATE active_dast_grants'))return {rows:[]};if(taken)return {rows:[]};taken=true;return {rows:[{authorization:a,grant_expires_at:new Date(Date.now()+300000),target_verified_until:new Date(Date.now()+300000),target_authorization:{...a},target_id:a.targetId,fixture_container_id:a.fixtureContainerId,scanner_network_id:a.scannerNetworkId}]};},release(){}};}};
 const grants=require('../services/activeDastGrants');const results=await Promise.allSettled([grants.consume(db,context),grants.consume(db,context)]);
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1);assert.ok(calls.some(c=>c.params?.includes('COMMISSIONING_ATOMIC_SINGLE_USE')));
 for(const field of ['authorizationState','fixtureImageDigest','gatewayContainerId']){
  const bad={async query(){return {rows:[]};},async connect(){return {async query(sql){return sql.startsWith('UPDATE active_dast_grants')?{rows:[{authorization:a,grant_expires_at:new Date(Date.now()+300000),target_verified_until:new Date(Date.now()+300000),target_authorization:{...a,[field]:'wrong'},target_id:a.targetId,fixture_container_id:a.fixtureContainerId,scanner_network_id:a.scannerNetworkId}]}:{rows:[]};},release(){}};}};
  await assert.rejects(grants.consume(bad,context));
 }
});
for(const scenario of ['complete','missing-traffic','missing-xss','cancelled','timeout'])test('Module 2 commissioning '+scenario+' preserves findings/evidence and cleanup',async t=>{
 enabled(t);const m=require('../services/module2ActiveDast'),a=m.issueAuthorization(authorization(),context);let cleaned=0;
 const runtime={async provision(){return {};},async verify(){},async scan(){
  if(['cancelled','timeout'].includes(scenario))throw Object.assign(Error(),{code:scenario==='cancelled'?'ACTIVE_CANCELLED':'ACTIVE_TIMED_OUT'});
  const ids=scenario==='missing-xss'?['40018']:['40018','40012'];
  return {completed:true,exitCode:0,commissioningTraffic:{verified:scenario!=='missing-traffic'},report:{site:[{alerts:ids.map(id=>({pluginid:id,riskcode:3,cweid:id==='40018'?89:79,name:id==='40018'?'SQL Injection':'Reflected XSS',instances:[{uri:`http://fixture.test:18080/test/${id==='40018'?'sqli?id=1':'xss?q=hello'}`}]}))}]}};
 },async cleanup(){cleaned++;return {cleaned:true,residual:[]};}};
 const r=await m.execute({...context,pool:{async query(sql){return {rows:sql.includes('deployment_history')?[{id:1}]:[]};}},authorization:a},runtime);
 assert.equal(r.status,{complete:'COMPLETED_WITH_FINDINGS','missing-traffic':'BLOCKED','missing-xss':'FAILED',cancelled:'CANCELLED',timeout:'TIMED_OUT'}[scenario]);
 assert.equal(cleaned,1);assert.equal(r.productionReady,false);
 if(scenario==='complete'){assert.deepEqual(r.findings.map(f=>f.cwe_id),[89,79]);assert.equal(r.commissioning.cancellation,'NOT_EXERCISED');}
 if(scenario==='timeout')assert.equal(r.commissioning.timeout,'EXERCISED_UNVERIFIED');
});
test('global commissioning availability does not select ordinary executions',t=>{
 enabled(t);delete process.env.DAST_ACTIVE_COMMISSIONING_CONTEXT;
 assert.equal(service.selection(context),null);assert.equal(service.setupAllowed(context),false);
 assert.equal(service.selection({...context,projectId:17}),null);
 assert.throws(()=>service.validate({...context,authorizationState:'COMMISSIONING'},context),{code:'COMMISSIONING_AUTHORIZATION_BLOCKED'});
});
test('expired registered commissioning scope never falls back to ordinary execution',t=>{
 enabled(t);delete process.env.DAST_ACTIVE_COMMISSIONING_CONTEXT;
 t.mock.method(require('../services/activeOperatorEnrollment'),'scopeFor',()=>({...context,expiresAt:Date.now()-1}));
 assert.throws(()=>service.selection(context),{code:'COMMISSIONING_CONTEXT_BLOCKED'});
});
test('malformed explicit commissioning configuration remains blocked',t=>{
 enabled(t);process.env.DAST_ACTIVE_COMMISSIONING_CONTEXT='{broken';
 assert.throws(()=>service.selection(context),{code:'COMMISSIONING_CONTEXT_BLOCKED'});
});
