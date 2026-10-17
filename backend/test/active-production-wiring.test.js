'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const prereq=require('../services/activeDastPrerequisites'),ctx={projectId:42,executionId:100,userId:7};
function db(scenario='ok'){const calls=[];return {calls,async query(sql){calls.push(sql);if(sql.startsWith('SELECT o.user_id'))return {rows:scenario==='operator'?[]:[{user_id:7}]};if(sql.includes('FROM deployment_history'))return {rows:scenario==='deployment'?[]:[{staging_url:scenario==='staging'?'http://minikube-url-unavailable':'http://staging.test:18080/'}]};if(sql.includes('FROM dast_scans'))return {rows:scenario==='baseline'?[]:[{target_url:scenario==='wrong-baseline'?'http://other.test/':'http://staging.test:18080/'}]};return {rows:[]};}};}
function enabled(t,node='test'){const old={flag:process.env.DAST_ACTIVE_ENABLED,node:process.env.NODE_ENV};process.env.DAST_ACTIVE_ENABLED='true';process.env.NODE_ENV=node;t.after(()=>{if(old.flag===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old.flag;if(old.node===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=old.node;});}
test('exact enabled owner/running execution, staging and completed matching baseline are prerequisites',async()=>{
 assert.equal((await prereq.check(db(),ctx)).stagingUrl,'http://staging.test:18080/');
 for(const scenario of ['operator','deployment','staging','baseline','wrong-baseline'])await assert.rejects(prereq.check(db(scenario),ctx));
 const d=db();await assert.rejects(prereq.check(d,{...ctx,projectId:17}));assert.equal(d.calls.length,0);
 for(const url of ['ftp://example.test','http://u:p@example.test','http://example.test/#x','bad'])assert.throws(()=>prereq.staging(url));
});
test('failed prerequisites, capability gate and pre-cancellation never consume a grant',async t=>{
 enabled(t,'production');let consumed=0;
 t.mock.method(require('../services/activeDastGrants'),'consume',async()=>{consumed++;throw Error('must not consume');});
 for(const scenario of ['operator','staging','baseline','wrong-baseline','ok']){
  const result=await require('../services/module2ActiveDast').execute({...ctx,pool:db(scenario)});assert.equal(result.status,'BLOCKED');assert.equal(consumed,0);
 }
 const controller=new AbortController();controller.abort();const r=await require('../services/module2ActiveDast').execute({...ctx,pool:db(),signal:controller.signal});assert.equal(r.status,'CANCELLED');assert.equal(consumed,0);
});
test('target preparation cannot provision on invalid target, Project 17, disabled default or missing capabilities',async t=>{
 enabled(t);let created=0;t.mock.method(require('../scripts/dast-acceptance'),'createLifecycle',()=>{created++;throw Error('unexpected provisioning');});
 const prepare=require('../services/activeTargetEnrollment').prepare;
 await assert.rejects(prepare(db(),ctx,{fixtureKind:'arbitrary-url'}));
 await assert.rejects(prepare(db(),{...ctx,projectId:17},{fixtureKind:'cloudsentinel-vulnerable-v1'}));
 await assert.rejects(prepare(db(),ctx,{fixtureKind:'cloudsentinel-vulnerable-v1'}),{code:'ACTIVE_RUNTIME_BLOCKED'});
 process.env.DAST_ACTIVE_ENABLED='false';await assert.rejects(prepare(db(),ctx,{fixtureKind:'cloudsentinel-vulnerable-v1'}));assert.equal(created,0);
});
test('production namespace permits bind issued authorization to one adapter, image and immutable parent',t=>{
 enabled(t);const binding=require('../services/activeScannerBinding'),a={},other={},parent='a'.repeat(64),image='sha256:'+'b'.repeat(64);
 t.mock.method(require('../services/dockerAdapter'),'isRuntimeAdapter',v=>v===a);
 const issued=require('../services/module2ActiveDast').issueAuthorization({...ctx,targetId:'c'.repeat(36),fixtureKind:'cloudsentinel-vulnerable-v1',hostname:'fixture.test',ip:'172.30.1.2',port:18080,scheme:'http',routes:['/test/sqli','/test/xss'],zapImageDigest:image,expiresAt:Date.now()+60000},ctx);
 assert.throws(()=>binding.permit(a,{...issued},'scan',parent,image,'/tmp/cs-active-unit'));
 assert.throws(()=>binding.permit(a,issued,'scan',parent,'sha256:'+'d'.repeat(64),'/tmp/cs-active-unit'));
 const token=binding.permit(a,issued,'scan',parent,image,'/tmp/cs-active-unit');assert.equal(binding.requirement(token,a,'scan',parent).imageId,image);
 for(const [ad,scan,id] of [[other,'scan',parent],[a,'other',parent],[a,'scan','c'.repeat(64)]])assert.equal(binding.requirement(token,ad,scan,id),null);
 binding.revoke(token);assert.equal(binding.requirement(token,a,'scan',parent),null);
});
test('shared-namespace claims without a privately registered trusted helper never verify',async()=>{
 await assert.rejects(require('../services/activeScannerBinding').verify({},null,'a'.repeat(64)),{code:'ACTIVE_NAMESPACE_BLOCKED'});
 await assert.rejects(require('../services/activeScannerBinding').verify({}, {helper:{id:'a'.repeat(64)}},'a'.repeat(64)),{code:'INVALID_CLIENT'});
});
test('read-only readiness parser cannot accept executable options or fabricated context',()=>{
 const parse=require('../scripts/active-dast-readiness').parse;assert.equal(parse([]),undefined);
 assert.deepEqual(parse(['--project','42','--execution','100','--operator','7']),ctx);
 for(const args of [['--execute'],['--project','17','--execution','1','--operator','7'],['--project','42'],['--project','42','--project','43'],['--project','42x']])assert.throws(()=>parse(args));
});
test('readiness independently reports blockers and makes only read-only database/Docker calls',async t=>{
 const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';t.after(()=>{if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;});
 const sql=[],docker=[],pool={async query(q){sql.push(q);return {rows:[]};}},adapter={async run(args){docker.push(args);throw Object.assign(Error('absent'),{code:'MISSING_RESOURCE'});}};
 const r=await require('../services/activeDastReadiness').inspect({pool,adapter});assert.equal(r.status,'BLOCKED');assert.equal(r.scanStarted,false);assert.equal(r.grantIssued,false);assert.equal(r.productionReady,false);
 assert.ok(sql.every(q=>q.startsWith('SELECT ')));assert.ok(docker.every(a=>a[0]==='image'&&a[1]==='inspect'));
 assert.ok(r.unverifiedScanDependentCapabilities.includes('ACTUAL_RATE_ENFORCEMENT'));
 assert.equal(r.verifiedConfiguration.scope,'ZAP_SHARED_NETWORK_NAMESPACE_HELPER');assert.equal(r.verifiedConfiguration.zapApplicationRequestsVerified,false);
});
test('atomic grant consume includes running execution and matching successful deployment/baseline',()=>{
 const s=require('fs').readFileSync(require.resolve('../services/activeDastGrants'),'utf8');
 for(const part of ["e.status='RUNNING'","s.status='COMPLETED'","s.scan_mode='BASELINE'",'s.target_url=d.staging_url'])assert.ok(s.includes(part));
});
test('server target caller reuses the real enrollment interface and cleans failed preparation',async t=>{
 enabled(t);const artifacts=require('../services/activeRuntimeArtifacts'),registry=require('../services/activeRuntimeRegistry');
 t.mock.method(artifacts,'assertReady',()=>({}));t.mock.method(artifacts,'verifyAvailable',async()=>true);
 const calls=[];let failEnrollment=false;
 const lifecycle={adapter:{},async provision(input){calls.push(['provision',input]);},async cleanup(scanId){calls.push(['cleanup',scanId]);return {state:'CLEANED',residual:[]};}};
 t.mock.method(require('../scripts/dast-acceptance'),'createLifecycle',()=>lifecycle);
 t.mock.method(registry,'enroll',async(pool,c,entry)=>{assert.deepEqual(c,ctx);assert.equal(entry.lifecycle,lifecycle);assert.equal(entry.adapter,lifecycle.adapter);if(failEnrollment)throw Object.assign(Error('enrollment'),{code:'ACTIVE_RUNTIME_BLOCKED'});return {targetId:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',expiresAt:Date.now()+60000};});
 const prepare=require('../services/activeTargetEnrollment').prepare;
 const r=await prepare(db(),ctx,{fixtureKind:'cloudsentinel-vulnerable-v1'});assert.match(r.scanId,/^act-[a-f0-9]{24}$/);assert.equal(r.origin,`http://${r.scanId}.test:18080`);assert.deepEqual(r.routes,['/test/sqli','/test/xss']);assert.equal(calls[0][1].target.hostname,r.scanId+'.test');assert.ok(!calls.some(x=>x[0]==='cleanup'));
 failEnrollment=true;await assert.rejects(prepare(db(),ctx,{fixtureKind:'cloudsentinel-vulnerable-v1'}));assert.equal(calls.at(-1)[0],'cleanup');
});
test('cancelled or missing in-process registration cannot release a grant to execution',async t=>{
 enabled(t);const registry=require('../services/activeRuntimeRegistry'),controller=new AbortController();controller.abort();
 await assert.rejects(registry.waitForGrant(db(),ctx,controller.signal),{code:'ACTIVE_CANCELLED'});
 assert.throws(()=>registry.consume({...ctx,targetId:'missing'}),{code:'ACTIVE_RUNTIME_BLOCKED'});
 assert.deepEqual(await registry.cancelPending(ctx),{cleaned:true,residual:[]});
});
test('production binding rejects wrong namespace evidence and revokes a partially provisioned permit',async t=>{
 enabled(t);const binding=require('../services/activeScannerBinding'),client=require('../services/dastAcceptanceClient'),a={},parent='a'.repeat(64),image='sha256:'+'b'.repeat(64),scanId='binding-test';
 t.mock.method(require('../services/dockerAdapter'),'isRuntimeAdapter',v=>v===a);
 const authorization=require('../services/module2ActiveDast').issueAuthorization({...ctx,fixtureKind:'cloudsentinel-vulnerable-v1',hostname:'fixture.test',ip:'172.30.1.2',port:18080,scheme:'http',routes:['/test/sqli','/test/xss'],zapImageDigest:image,expiresAt:Date.now()+60000,scannerNetworkId:'c'.repeat(64),fixtureContainerId:'d'.repeat(64)},ctx);
 const resources={owned:{networks:[{id:authorization.scannerNetworkId,name:'scanner',role:'scanner'},{id:'e'.repeat(64),role:'fixture'}]},gatewayId:'f'.repeat(64),staged:{},nativeArtifact:{}};let token;
 t.mock.method(client,'provision',async(adapter,opts)=>{token=opts.namespaceScope;const helper={id:'1'.repeat(64)};opts.onCreated(helper);return helper;});
 a.inspect=async()=>({normalized:{networks:{scanner:{IPAddress:'172.30.1.3'}}}});
 const lifecycle={resources:new Map([[scanId,resources]]),observation:{bindAcceptanceClient(){},async collectActiveFixture(){return {namespaceScope:'ACCEPTANCE_CLIENT_ONLY'};}}};
 await assert.rejects(binding.bind({adapter:a,lifecycle,scanId,authorization,scannerId:parent,imageId:image,directory:'/tmp/cs-active-binding-test'}),{code:'ACTIVE_NAMESPACE_BLOCKED'});
 assert.ok(resources.clientResource);assert.equal(binding.requirement(token,a,scanId,parent),null);
});
test('native production preparation requires an unforgeable authenticated scope',async t=>{
 enabled(t);const enroll=require('../services/activeTargetEnrollment');
 assert.equal(enroll.isPreparation({}, {...ctx,scanId:'fake'}),false);
 let calls=0;const gateway=new(require('../services/dastGateway').SecureGatewayLifecycle)({adapter:{run(){calls++;throw Error('must not execute');}}});
 await assert.rejects(gateway.provision({...ctx,scanId:'fake',productionScope:{},fixtureKind:'cloudsentinel-vulnerable-v1',nativeConnect:true,mode:'full',target:{hostname:'fake.test',port:18080}}),{code:'ACTIVE_AUTHORIZATION_BLOCKED'});assert.equal(calls,0);
});
test('server production preparation scope is revoked after completion and cancellation cleans owned resources',async t=>{
 enabled(t);const service=require('../services/activeTargetEnrollment');let observed,cleaned=0;const controller=new AbortController();
 t.mock.method(require('../services/activeRuntimeArtifacts'),'assertReady',()=>({}));t.mock.method(require('../services/activeRuntimeArtifacts'),'verifyAvailable',async()=>true);
 t.mock.method(require('../scripts/dast-acceptance'),'createLifecycle',()=>({adapter:{},async provision(input){observed=input;assert.equal(service.isPreparation(input.productionScope,input),true);assert.equal(service.isPreparation(input.productionScope,{...input,projectId:17}),false);controller.abort();},async cleanup(){cleaned++;return {state:'CLEANED',residual:[]};}}));
 await assert.rejects(service.prepare(db(),ctx,{fixtureKind:'cloudsentinel-vulnerable-v1',signal:controller.signal}),{code:'ACTIVE_CANCELLED'});
 assert.equal(cleaned,1);assert.equal(service.isPreparation(observed.productionScope,observed),false);
});
test('pipeline baseline uses its verified staging deployment, while manual baseline keeps owner configuration',async()=>{
 assert.equal(await prereq.baselineTarget(db(),{projectId:42,executionId:100,configuredTarget:'http://wrong.test'}),'http://staging.test:18080/');
 assert.equal(await prereq.baselineTarget({query(){throw Error('must not query');}},{projectId:42,executionId:null,configuredTarget:' http://manual.test/ '}),'http://manual.test/');
 await assert.rejects(prereq.baselineTarget(db('deployment'),{projectId:42,executionId:100}));
});
test('failed fresh target preflight cannot consume a pending execution grant',async t=>{
 enabled(t,'production');let consumed=0;const registry=require('../services/activeRuntimeRegistry');
 t.mock.method(require('../services/activeRuntimeArtifacts'),'assertReady',()=>({}));t.mock.method(registry,'waitForGrant',async()=>({}));t.mock.method(registry,'verifyPending',async()=>{throw Object.assign(Error('missing fixture'),{code:'ACTIVE_TARGET_IDENTITY_MISMATCH'});});
 t.mock.method(require('../services/activeDastGrants'),'consume',async()=>{consumed++;throw Error('must not consume');});
 const result=await require('../services/module2ActiveDast').execute({...ctx,pool:db()});assert.equal(result.reason,'ACTIVE_TARGET_IDENTITY_MISMATCH');assert.equal(consumed,0);
});
test('failed target-preparation cleanup remains visible to the owning pipeline as CLEANUP_FAILED',async t=>{
 enabled(t);const context={projectId:43,executionId:101,userId:7};
 t.mock.method(require('../services/activeRuntimeArtifacts'),'assertReady',()=>({}));t.mock.method(require('../services/activeRuntimeArtifacts'),'verifyAvailable',async()=>true);
 t.mock.method(require('../scripts/dast-acceptance'),'createLifecycle',()=>({adapter:{},async provision(){throw Error('partial provisioning');},async cleanup(){return {state:'CLEANUP_FAILED',residual:[{type:'owned-network'}]};}}));
 await assert.rejects(require('../services/activeTargetEnrollment').prepare(db(),context,{fixtureKind:'cloudsentinel-vulnerable-v1'}),{code:'ACTIVE_CLEANUP_FAILED'});
 const result=await require('../services/activeRuntimeRegistry').cancelPending(context);assert.equal(result.cleaned,false);assert.equal(result.residual[0].type,'active-preparation');
});
