'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('crypto');
const ctx={projectId:42,executionId:100,userId:7};
function env(t){const keys=['DAST_ACTIVE_ENABLED','DAST_ACTIVE_COMMISSIONING_ENABLED','DAST_ACTIVE_COMMISSIONING_CONTEXT','DAST_ACTIVE_OPERATOR_APPROVAL_SHA256','DAST_ACTIVE_COMMISSIONING_ENROLLMENT_CONTEXT','DAST_COMMISSIONING_SETUP_ENABLED'];const old=keys.map(k=>process.env[k]);t.after(()=>keys.forEach((k,i)=>{if(old[i]===undefined)delete process.env[k];else process.env[k]=old[i];}));process.env.DAST_ACTIVE_ENABLED='true';process.env.DAST_COMMISSIONING_SETUP_ENABLED='true';process.env.DAST_ACTIVE_COMMISSIONING_ENABLED='true';process.env.DAST_ACTIVE_COMMISSIONING_CONTEXT=JSON.stringify({...ctx,expiresAt:Date.now()+600000});process.env.DAST_ACTIVE_OPERATOR_APPROVAL_SHA256=crypto.createHash('sha256').update('a'.repeat(64)).digest('hex');}
function operatorDb(scenario='ok'){const calls=[];let consumed=false;return {calls,async query(sql,args){calls.push({sql,args});return {rows:sql.includes('to_regclass')?[{phase_table:'active_dast_commissioning_phases'}]:[]};},async connect(){return {async query(sql,args){calls.push({sql,args});if(sql.includes('SELECT u.id'))return {rows:scenario==='owner'?[]:[{id:7}]};if(sql.includes('SELECT id FROM active_dast_audit'))return {rows:consumed||scenario==='replay'?[{id:1}]:[]};if(sql.startsWith('INSERT INTO active_dast_audit'))consumed=true;if(sql.startsWith('INSERT INTO pipeline_executions'))return {rows:[{id:100}]};return {rows:[]};},release(){}};}};}
test('one exact seven-rule job, both seeds, no spider and a bounded context',()=>{
 const plans=require('../services/dastActiveScanner'),plan=plans.commissioningPlan('http://fixture.test:18080');
 assert.equal((plan.match(/  - type: activeScan\n/g)||[]).length,1);assert.equal((plan.match(/  - type: activeScan-policy\n/g)||[]).length,1);assert.equal((plan.match(/  - type: requestor\n/g)||[]).length,1);assert.ok(!plan.includes('type: spider'));
 for(const id of plans.POLICY.approvedPluginIds)assert.equal((plan.match(new RegExp('id: '+id+'\\n','g'))||[]).length,1);
 assert.ok(plan.includes('defaultThreshold: "Off"'));assert.ok(plan.includes('threadPerHost: 1'));assert.ok(plan.includes('delayInMs: 500'));assert.ok(plan.includes('maxScanDurationInMins: 1'));
 const baseline=plans.commissioningPlan('http://fixture.test:18080',{baseline:true});assert.ok(!baseline.includes('type: activeScan'));assert.ok(baseline.includes('type: passiveScan-wait'));
 for(const u of ['http://example.com:18080','http://172.30.1.2:18080','http://fixture.test:80','http://fixture.test:18080/extra'])assert.throws(()=>plans.commissioningPlan(u));
 const schema=require('./fixtures/zap-commissioning-job-schemas.json');assert.equal(schema.archiveSha256,'e02c90abea15cb5802be1aa1adb959e5f76c4c517494087388732d71345e4ea9');assert.ok(schema.schemas.some(s=>s.text.includes('responseCode:')));assert.ok(schema.schemas.some(s=>s.text.includes('type: passiveScan-wait')));
});
test('private operator enrollment requires server approval, owning authenticated user and a real execution',async t=>{
 env(t);const service=require('../services/activeOperatorEnrollment'),db=operatorDb();const result=await service.enroll(db,ctx,'a'.repeat(64));assert.equal(result.enabled,true);assert.ok(db.calls.some(c=>c.sql==='COMMIT'));assert.ok(db.calls.some(c=>c.sql.includes('pg_advisory_xact_lock')));assert.ok(!JSON.stringify(result).includes('a'.repeat(64)));
 await assert.rejects(service.enroll(db,ctx,'a'.repeat(64)));assert.equal(db.calls.filter(c=>c.sql.startsWith('INSERT INTO active_dast_operators')).length,1);
 for(const scenario of ['owner','replay'])await assert.rejects(service.enroll(operatorDb(scenario),ctx,'a'.repeat(64)));
 for(const c of [{...ctx,projectId:17},{...ctx,userId:8},{...ctx,executionId:101}])await assert.rejects(service.enroll(operatorDb(),c,'a'.repeat(64)));
 await assert.rejects(service.enroll(operatorDb(),ctx,'b'.repeat(64)));
});
test('new execution IDs come from INSERT RETURNING and are bound after ownership and private approval',async t=>{
 env(t);process.env.DAST_ACTIVE_COMMISSIONING_ENROLLMENT_CONTEXT=JSON.stringify({projectId:42,userId:7,expiresAt:Date.now()+600000});
 const service=require('../services/activeOperatorEnrollment'),db=operatorDb();const result=await service.createExecution(db,{projectId:42,userId:7},'a'.repeat(64));assert.equal(result.executionId,100);assert.equal(result.status,'TRIGGERED');assert.equal(service.scopeFor(ctx).executionId,100);
 assert.ok(db.calls.find(c=>c.sql.startsWith('INSERT INTO pipeline_executions')).sql.includes("'TRIGGERED'"));
 assert.ok(!db.calls.some(c=>c.sql.includes('INSERT INTO deployment_history')||c.sql.includes('INSERT INTO dast_scans')));
 await assert.rejects(service.createExecution(db,{projectId:42,userId:7},'a'.repeat(64)));
});
test('missing or forged fixture staging evidence cannot satisfy the commissioning staging gate',async t=>{
 env(t);const stage=require('../services/commissioningFixtureStage');const db={async query(){return {rows:[]};}};
 await assert.rejects(stage.verify(db,ctx),{code:'COMMISSIONING_STAGING_BLOCKED'});assert.equal(stage.lookup(ctx),null);
});
test('fixture staging only writes completion after real runtime baseline and reuses the exact fixture enrollment',async t=>{
 env(t);const stage=require('../services/commissioningFixtureStage'),target=require('../services/activeTargetEnrollment'),registry=require('../services/activeRuntimeRegistry');const calls=[];let failBaseline=false,cleaned=0;
 const evidence={completed:true,exitCode:0,commissioningTraffic:{verified:true},report:{site:[]}};
 const fixtureId='f'.repeat(64),record={authorization:{...ctx,hostname:'fixture.test',fixtureContainerId:fixtureId,fixtureImageDigest:require('../services/activeRuntimeArtifacts').artifacts.fixture.imageId,expiresAt:Date.now()+60000},baseline:evidence,lifecycle:{async cleanup(){cleaned++;return {state:'CLEANED',residual:[]};}},scanId:'unit'};
 t.mock.method(target,'prepareStaging',async()=>({...record,baseline:failBaseline?{completed:false}:evidence}));
 let stored;
 const db={async query(sql,args){calls.push(sql);if(sql.startsWith('INSERT INTO deployment_history'))return {rows:[{id:1}]};if(sql.startsWith('INSERT INTO dast_scans')){stored=JSON.parse(args[4]);return {rows:[{id:2}]};}if(sql.startsWith('SELECT d.staging_url'))return {rows:[{staging_url:'http://fixture.test:18080/',target_authorization:stored}]};return {rows:[]};}};
 t.mock.method(require('../services/dastBaselineScanner'),'persistCompletedScan',async()=>{calls.push('persist-real-baseline');});
 t.mock.method(registry,'enroll',async()=>{calls.push('enroll-target');assert.equal(stage.binding(ctx).baselineScanId,2);return {targetId:'target',expiresAt:Date.now()+60000};});
 try{const result=await stage.prepare(db,ctx);assert.equal(result.fixtureOnly,true);assert.equal(stage.lookup(ctx).fixtureContainerId,fixtureId);assert.ok(calls.indexOf('persist-real-baseline')<calls.indexOf('enroll-target'));stored.evidenceSha256='wrong';await assert.rejects(stage.verify(db,ctx));}finally{stage.release(ctx);}
 failBaseline=true;calls.length=0;await assert.rejects(stage.prepare(db,ctx));assert.ok(!calls.some(c=>c.startsWith('INSERT')));assert.equal(cleaned,1);
});
test('fixture staging rejects missing operator before provisioning any resources',async t=>{
 env(t);let calls=0;t.mock.method(require('../scripts/dast-acceptance'),'createLifecycle',()=>{calls++;throw Error();});
 await assert.rejects(require('../services/activeTargetEnrollment').prepareStaging({async query(){return {rows:[]};}},ctx));assert.equal(calls,0);
});
test('commissioning-enabled operator does not acquire a cross-project global role',async t=>{
 env(t);const service=require('../services/activeOperatorEnrollment');
 const db={async query(){return {rows:[{project_id:42,pipeline_execution_id:100}]};}};
 await service.assertProjectRole(db,ctx);
 for(const c of [{...ctx,projectId:43},{...ctx,executionId:101}])await assert.rejects(service.assertProjectRole(db,c));
 process.env.DAST_ACTIVE_COMMISSIONING_ENABLED='false';await assert.rejects(service.assertProjectRole(db,ctx));
});
test('missing fixture image or containment evidence cannot create successful deployment or baseline records',async t=>{
 env(t);const stage=require('../services/commissioningFixtureStage');let writes=0;
 const db={async query(sql){if(sql.startsWith('INSERT'))writes++;return {rows:[]};}};
 t.mock.method(require('../services/activeTargetEnrollment'),'prepareStaging',async()=>{throw Object.assign(Error(),{code:'ACTIVE_NAMESPACE_BLOCKED'});});
 await assert.rejects(stage.prepare(db,ctx));assert.equal(writes,0);
});
