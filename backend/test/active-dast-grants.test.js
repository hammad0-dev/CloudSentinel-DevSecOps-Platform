'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const grants=require('../services/activeDastGrants'),artifacts=require('../services/activeRuntimeArtifacts');
const context={projectId:42,executionId:100,userId:7};
function authorization(){return {...context,targetId:'target-1',fixtureContainerId:'b'.repeat(64),scannerNetworkId:'c'.repeat(64),policies:['SQLI','XSS'],expiresAt:Date.now()+60000,fixtureKind:'cloudsentinel-vulnerable-v1',hostname:'cs-active.test',ip:'172.30.1.2',port:18080,scheme:'http',routes:['/test/sqli','/test/xss'],zapImageDigest:'sha256:'+'a'.repeat(64)};}
function database(expiries={}){let taken=false;const calls=[];return {calls,query:async(s)=>{calls.push(s);return {rows:[]};},connect:async()=>({async query(s){calls.push(s);if(s.startsWith('UPDATE active_dast_grants')){if(taken)return {rows:[]};taken=true;return {rows:[{authorization:authorization(),grant_expires_at:new Date(Date.now()+300000),target_verified_until:new Date(Date.now()+300000),target_authorization:authorization(),target_id:'target-1',fixture_container_id:'b'.repeat(64),scanner_network_id:'c'.repeat(64),...expiries}]};}if(s.startsWith('SELECT o.user_id'))return {rows:[{user_id:7}]};return {rows:[]};},release(){calls.push('release');}})};}
test('local artifact catalog fails closed without fixture or policy capabilities',()=>{assert.throws(()=>artifacts.assertReady(),e=>e.code==='ACTIVE_RUNTIME_BLOCKED'&&e.missing.includes('ZAP_NAMESPACE_CONTAINMENT_UNVERIFIED')&&e.missing.includes('ZAP_POLICY_CAPABILITIES_UNVERIFIED'));assert.equal(artifacts.artifacts.zap.imageId,require('../config/zap-containment-diagnostic.json').imageId);});
test('operator issuance cannot grant an unverified runtime and records rejection',async()=>{const db=database();await assert.rejects(grants.issue(db,context,'a'.repeat(8)+'-'+'a'.repeat(4)+'-'+'a'.repeat(4)+'-'+'a'.repeat(4)+'-'+'a'.repeat(12)),{code:'ACTIVE_RUNTIME_BLOCKED'});assert.ok(db.calls.includes('ROLLBACK'));assert.ok(db.calls.some(s=>s.startsWith('INSERT INTO active_dast_audit')));assert.ok(!db.calls.some(s=>s.startsWith('INSERT INTO active_dast_grants')));});
test('Project 17 and malformed issuance are blocked and audited before a transaction',async()=>{for(const c of [{...context,projectId:17},{...context,userId:NaN}]){const db=database();await assert.rejects(grants.issue(db,c,'bad'));assert.ok(!db.calls.includes('BEGIN'));assert.ok(db.calls.some(s=>s.includes('active_dast_audit')));}});
test('single atomic consume admits one concurrent consumer and rejects replay',async()=>{const db=database();const results=await Promise.allSettled([grants.consume(db,context),grants.consume(db,context)]);assert.equal(results.filter(x=>x.status==='fulfilled').length,1);assert.equal(results.filter(x=>x.status==='rejected').length,1);const sql=db.calls.find(s=>s.startsWith('UPDATE active_dast_grants'));for(const part of ['consumed_at IS NULL','expires_at>NOW()','o.enabled=TRUE','p.user_id=g.operator_id','t.verified_until>NOW()'])assert.ok(sql.includes(part));});
test('consumed authorization cannot outlive actual grant or target database expiry',async()=>{
 const now=Date.now();
 for(const field of ['grant_expires_at','target_verified_until']){
  const expires=now+20000,db=database({[field]:new Date(expires)}),result=await grants.consume(db,context);
  assert.equal(result.expiresAt,expires);
  const invalid=database({[field]:null});await assert.rejects(grants.consume(invalid,context));assert.ok(invalid.calls.includes('ROLLBACK'));
 }
});
test('source-only migrations align with Active persistence and grant auditing',()=>{const fs=require('fs'),path=require('path');const m=fs.readFileSync(path.join(__dirname,'../migrations/012_active_dast_execution_records.sql'),'utf8'),g=fs.readFileSync(path.join(__dirname,'../migrations/013_active_dast_grants.sql'),'utf8');for(const status of ['BLOCKED','FAILED','TIMED_OUT','CANCELLED','COMPLETED_WITH_FINDINGS','COMPLETED_NO_FINDINGS'])assert.ok(m.includes(status));assert.ok(g.includes('UNIQUE(project_id,pipeline_execution_id)'));assert.ok(g.includes('project_id <> 17'));});
test('production path ignores generic mock runtimes when capabilities are missing',async()=>{const old=process.env.DAST_ACTIVE_ENABLED,node=process.env.NODE_ENV;process.env.DAST_ACTIVE_ENABLED='true';process.env.NODE_ENV='production';try{const r=await require('../services/module2ActiveDast').execute({...context,pool:database()});assert.equal(r.status,'BLOCKED');assert.equal(r.reason,'ACTIVE_OPERATOR_OR_EXECUTION_BLOCKED');}finally{if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;if(node===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=node;}});
test('authenticated operator issuance commits exact target and audit after runtime validation',async t=>{
  t.mock.method(artifacts,'assertReady',()=>({}));const calls=[];const target='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  const client={async query(sql,params){calls.push({sql,params});if(sql.startsWith('SELECT o.user_id'))return {rows:[{user_id:7}]};if(sql.startsWith('SELECT * FROM active_dast_targets'))return {rows:[{fixture_container_id:'b'.repeat(64),scanner_network_id:'c'.repeat(64),authorization:authorization(),verified_until:new Date(Date.now()+60000)}]};return {rows:[]};},release(){}};
  const db={connect:async()=>client,query:client.query};
  const r=await grants.issue(db,context,target);assert.match(r.grantId,/^[a-f0-9-]{36}$/);const inserted=calls.find(c=>c.sql.startsWith('INSERT INTO active_dast_grants'));const a=JSON.parse(inserted.params[5]);assert.equal(a.targetId,target);assert.equal(a.fixtureContainerId,'b'.repeat(64));assert.deepEqual(a.policies,['SQLI','XSS']);assert.ok(calls.some(c=>c.sql==='COMMIT'));assert.ok(calls.some(c=>c.sql.includes('active_dast_audit')&&c.params[3]==='ISSUED'));
});
test('missing database operator cannot use JWT role claims to issue authorization',async()=>{
  const calls=[];const db={connect:async()=>({query:async sql=>{calls.push(sql);return {rows:[]};},release(){}}),query:async sql=>{calls.push(sql);return {rows:[]};}};
  await assert.rejects(grants.issue(db,{...context,role:'admin'},'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),{code:'ACTIVE_OPERATOR_REQUIRED'});assert.ok(calls.includes('ROLLBACK'));assert.ok(!calls.some(s=>s.startsWith('INSERT INTO active_dast_grants')));
});
test('expired or mismatched target grants roll back and audit rejection',async()=>{
  for(const replacement of [{expiresAt:0},{executionId:999},{fixtureContainerId:'d'.repeat(64)},{hostname:'other.test'},{zapImageDigest:'sha256:'+'e'.repeat(64)},{policies:['XSS']}]){
    const calls=[];const db={connect:async()=>({query:async sql=>{calls.push(sql);return sql.startsWith('UPDATE active_dast_grants')?{rows:[{authorization:{...authorization(),...replacement},grant_expires_at:new Date(Date.now()+300000),target_verified_until:new Date(Date.now()+300000),target_authorization:authorization(),target_id:'target-1',fixture_container_id:'b'.repeat(64),scanner_network_id:'c'.repeat(64)}]}:{rows:[]};},release(){}}),query:async sql=>{calls.push(sql);return {rows:[]};}};
    await assert.rejects(grants.consume(db,context));assert.ok(calls.includes('ROLLBACK'));assert.ok(!calls.includes('COMMIT'));assert.ok(calls.some(s=>s.includes('active_dast_audit')));
  }
});
test('PostgreSQL reserved authorization identifier is quoted in schema and INSERT column lists',()=>{
 const fs=require('fs');
 const migration=fs.readFileSync(require('path').join(__dirname,'../migrations/013_active_dast_grants.sql'),'utf8');
 assert.equal((migration.match(/"authorization" JSONB NOT NULL/g)||[]).length,2);
 assert.ok(!/^\s+authorization JSONB/m.test(migration));
 for(const module of ['activeDastGrants','activeRuntimeRegistry']){
  const source=fs.readFileSync(require.resolve('../services/'+module),'utf8');
  const insert=source.split('\n').find(l=>l.includes('INSERT INTO active_dast_')&&l.includes('authorization'));
  assert.ok(insert?.includes(',"authorization",'),module);
 }
});
