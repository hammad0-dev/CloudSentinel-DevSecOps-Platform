'use strict';
// Creates only a private disposable PostgreSQL cluster; never loads backend/.env.
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),{execFile}=require('node:child_process'),{promisify}=require('node:util'),assert=require('node:assert/strict');
const run=promisify(execFile),{Pool}=require('pg');
(async()=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'cs-m017-isolated-'));await fs.chmod(root,0o700);
 const bin='/usr/lib/postgresql/15/bin',data=path.join(root,'data'),socket=path.join(root,'socket');await fs.mkdir(socket,{mode:0o700});let started=false,pool;
 try{
  await run(path.join(bin,'initdb'),['-D',data,'--auth=trust','--no-locale','--encoding=UTF8'],{timeout:30000});
  await run(path.join(bin,'pg_ctl'),['-D',data,'-l',path.join(root,'postgres.log'),'-o',`-k ${socket} -p 55439 -c listen_addresses=''`,'-w','start'],{timeout:30000});started=true;
  pool=new Pool({host:socket,port:55439,user:os.userInfo().username,database:'postgres'});pool.on('error',()=>{}); // Expected in the isolated connection-crash test; never print client secrets.
  await pool.query('CREATE TABLE users(id INTEGER PRIMARY KEY); CREATE TABLE projects(id INTEGER PRIMARY KEY,user_id INTEGER REFERENCES users(id),repo_url TEXT); CREATE TABLE pipeline_executions(id SERIAL PRIMARY KEY,project_id INTEGER REFERENCES projects(id),status TEXT,triggered_by TEXT,completed_at TIMESTAMPTZ,stages_completed TEXT,UNIQUE(id,project_id)); INSERT INTO users VALUES(3),(4); INSERT INTO projects VALUES(20,3,\'https://github.com/owner/site\'),(13,3,\'protected\'); INSERT INTO pipeline_executions(id,project_id,status,completed_at,stages_completed) VALUES(40,20,\'COMPLETED\',NOW(),\'\'),(41,20,\'COMPLETED\',NOW(),\'\');');
  const migration=await fs.readFile(path.join(__dirname,'../migrations/017_deployment_eligibility.sql'),'utf8');
  const rollback=await pool.connect();try{await rollback.query('BEGIN; CREATE SCHEMA rollback_probe; SET LOCAL search_path=rollback_probe,public');await rollback.query(migration.replace(/^BEGIN;$/m,'').replace(/^COMMIT;$/m,''));await rollback.query('ROLLBACK')}finally{rollback.release()}
  assert.equal((await pool.query("SELECT to_regclass('rollback_probe.deployment_outbox') AS name")).rows[0].name,null);
  await pool.query(migration);
  await pool.query(await fs.readFile(path.join(__dirname,'../migrations/018_provenance_dispatch_claims.sql'),'utf8'));
  const {registerPush}=require('../services/pipelineProvenance'),project={id:20,user_id:3,repo_url:'https://github.com/owner/site'},body={repository:{id:100,full_name:'owner/site',default_branch:'main'},ref:'refs/heads/main',after:'a'.repeat(40)},delivery='11111111-1111-4111-8111-111111111111';
  const pushed=await Promise.all([registerPush(pool,project,body,delivery,Buffer.from('signed-test-only'),{policy:null}),registerPush(pool,project,body,delivery,Buffer.from('signed-test-only'),{policy:null})]);
  assert.equal(pushed.filter(x=>x.duplicate).length,1);assert.equal(pushed[0].executionId,pushed[1].executionId);
  await assert.rejects(registerPush(pool,project,body,delivery,Buffer.from('altered-test-only'),{policy:null}),/replay/);
  const {Dispatcher,admit}=require('../services/provenanceRecovery');let simulatedStarts=0;
  const runner=async(executionId,projectId,userId,options)=>{if(await admit(options.provenanceClaim,{executionId,projectId,userId})){simulatedStarts++;await pool.query("UPDATE pipeline_executions SET status='COMPLETED' WHERE id=$1",[executionId]);}};
  const worker=()=>new Dispatcher({pool,runner,authorize:()=>true,policy:()=>null,leaseSeconds:1});
  const firstWorker=worker();await firstWorker.initialize();
  const expected={projectId:20,userId:3,repository:'https://github.com/owner/site',repositoryId:100,branch:'main',commit:body.after};
  assert.equal(await firstWorker.claim(pushed[0].executionId,{...expected,commit:'f'.repeat(40)}),null);
  const stranded=await firstWorker.claim(pushed[0].executionId,expected);assert.ok(stranded);
  // Actual isolated backend connection termination models a crash before the start fence.
  stranded.client.on('error',()=>{});await pool.query('SELECT pg_terminate_backend($1)',[stranded.client.processID]);stranded.client.release(true);
  await pool.query("UPDATE provenance_dispatch_claims SET lease_until=NOW()-INTERVAL '1 second' WHERE pipeline_execution_id=$1",[pushed[0].executionId]);
  const restarted=worker(),concurrent=worker();await restarted.initialize();await concurrent.initialize();
  await Promise.all([restarted.dispatch(pushed[0].executionId,expected),concurrent.dispatch(pushed[0].executionId,expected)]);assert.equal(simulatedStarts,1);
  assert.equal(await restarted.dispatch(pushed[0].executionId,expected),false);assert.equal(simulatedStarts,1);
  const next=await registerPush(pool,project,{...body,after:'b'.repeat(40)},'22222222-2222-4222-8222-222222222222',Buffer.from('second-test-only'),{policy:null});
  const uncertain=new Dispatcher({pool,authorize:()=>true,policy:()=>null,runner:async(id,projectId,userId,options)=>{assert.equal(await admit(options.provenanceClaim,{executionId:id,projectId,userId}),true);throw Error('SIMULATED_PROCESS_LOSS_AFTER_START');}});await uncertain.initialize();
  await assert.rejects(uncertain.dispatch(next.executionId),/SIMULATED_PROCESS_LOSS/);assert.equal(await restarted.dispatch(next.executionId),false);
  assert.equal((await pool.query('SELECT state FROM provenance_dispatch_claims WHERE pipeline_execution_id=$1',[next.executionId])).rows[0].state,'started');
  // Test-only terminal reconciliation; never performed by the production recovery dispatcher.
  await pool.query("UPDATE pipeline_executions SET status='ERROR' WHERE id=$1",[next.executionId]);

  const decision=async(key,id=40)=>pool.query("INSERT INTO deployment_eligibility(project_id,pipeline_execution_id,environment,idempotency_key,decision,evidence,expires_at) VALUES(20,$2,'development',$1,'ELIGIBLE',$3,NOW()+INTERVAL '5 minutes') RETURNING id",[key,id,{policyDigest:'a'.repeat(64)}]);
  await assert.rejects(pool.query("INSERT INTO deployment_eligibility(project_id,pipeline_execution_id,environment,idempotency_key,decision,evidence,expires_at) VALUES(13,40,'development','cross','ELIGIBLE','{}',NOW())"),e=>e.code==='23503');
  const simultaneous=await Promise.allSettled([decision('same'),decision('same')]);assert.equal(simultaneous.filter(x=>x.status==='fulfilled').length,1);assert.equal(simultaneous.find(x=>x.status==='rejected').reason.code,'23505');
  const id=simultaneous.find(x=>x.status==='fulfilled').value.rows[0].id;
  await assert.rejects(pool.query("UPDATE deployment_eligibility SET decision='BLOCKED' WHERE id=$1",[id]),/immutable/);
  const c=await pool.connect();try{await c.query('BEGIN');await c.query("INSERT INTO deployment_eligibility(project_id,pipeline_execution_id,environment,idempotency_key,decision,evidence,expires_at) VALUES(20,40,'development','rollback','BLOCKED','{}',NOW())");await c.query('ROLLBACK')}finally{c.release()}
  assert.equal((await pool.query("SELECT * FROM deployment_eligibility WHERE idempotency_key='rollback'")).rows.length,0);
  await pool.query('INSERT INTO deployment_outbox(decision_id,idempotency_key) VALUES($1,$2)',[id,'same']);
  const {claim,abandon}=require('../services/deploymentOutbox');
  const claims=await Promise.all([claim(pool,{enabled:true,policyDigest:'a'.repeat(64),leaseSeconds:1}),claim(pool,{enabled:true,policyDigest:'a'.repeat(64),leaseSeconds:1})]);assert.equal(claims.filter(Boolean).length,1);const first=claims.find(Boolean);
  await pool.query("UPDATE deployment_outbox SET claim_until=NOW()-INTERVAL '1 second' WHERE id=$1",[first.id]);
  const recovered=await claim(pool,{enabled:true,policyDigest:'a'.repeat(64),leaseSeconds:1});assert.ok(recovered);assert.notEqual(recovered.claim_token,first.claim_token);await assert.rejects(abandon(pool,first.id,first.claim_token),/Stale/);
  await abandon(pool,recovered.id,recovered.claim_token,'pending');
  const expired=await decision('expired',41);await pool.query('INSERT INTO deployment_outbox(decision_id,idempotency_key) VALUES($1,$2)',[expired.rows[0].id,'expired']);
  const token=await claim(pool,{enabled:true,policyDigest:'b'.repeat(64)});assert.equal(token,null);
  assert.equal(Number((await pool.query('SELECT COUNT(*) AS count FROM projects')).rows[0].count),2);assert.equal((await pool.query('SELECT repo_url FROM projects WHERE id=13')).rows[0].repo_url,'protected');
  await fs.writeFile(path.join(root,'result.json'),JSON.stringify({status:'PASS',checks:['migrations 017 and 018 applied only in isolated cluster','pre-start connection crash recovery','restart recovery with null deployment policy','concurrent dispatcher exclusion','duplicate dispatch exclusion','started execution never retried','whole migration rollback','composite FK','concurrent uniqueness','concurrent webhook delivery deduplication','delivery replay rejection','immutable decisions','transaction rollback','concurrent claims','lease crash recovery','stale claim rejection','policy fencing','protected sentinel preservation'],liveDatabaseTouched:false}),{mode:0o600});
  console.log(JSON.stringify({status:'PASS',evidence:path.join(root,'result.json')}));
 }catch(e){console.error('ISOLATED_MIGRATION_FAILED:',e.message);process.exitCode=1}
 finally{if(pool)await pool.end();if(started)await run(path.join(bin,'pg_ctl'),['-D',data,'-m','fast','-w','stop'],{timeout:30000});await fs.rm(data,{recursive:true,force:true});await fs.rm(socket,{recursive:true,force:true});}
})().catch(e=>{console.error('Isolated PostgreSQL cleanup failed:',e.message);process.exitCode=1});
