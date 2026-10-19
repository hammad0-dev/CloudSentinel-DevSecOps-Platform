'use strict';
// Isolated PostgreSQL schema; no public fixture rows and no scanner invocation.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
require('dotenv').config({path:path.join(__dirname,'../.env')});
test('migration 016 preserves legacy evidence and enables complete typed SAST persistence',{skip:process.env.SAST_DB_TEST!=='1'},async()=>{
 const base=require('../db'),{Pool}=require('pg');const schema=`sast_migration_test_${process.pid}_${Date.now()}`;const admin=await base.connect();let db;
 try{
  await admin.query(`CREATE SCHEMA ${schema}`);db=new Pool({...base.options,password:base.options.password,options:`-c search_path=${schema}`,connectionTimeoutMillis:3000});
  await db.query(fs.readFileSync(path.join(__dirname,'../../schema.sql'),'utf8'));
  await db.query(fs.readFileSync(path.join(__dirname,'../migrations/010_scan_results_scan_history_linkage.sql'),'utf8'));
  await db.query("INSERT INTO users(id,full_name,email,password_hash) VALUES(1,'TEST FIXTURE','sast-migration@example.test','unused-fixture')");
  await db.query("INSERT INTO projects(id,user_id,name,repo_url) VALUES(1,1,'TEST FIXTURE','https://example.test/repository')");
  await db.query("INSERT INTO scan_results(project_id,rule,severity,message) VALUES(1,'legacy','MAJOR','TEST FIXTURE historical row')");
  const migration=fs.readFileSync(path.join(__dirname,'../migrations/016_sast_issue_classification.sql'),'utf8');await db.query(migration);await db.query(migration);
  const legacy=(await db.query("SELECT issue_type,hotspot_review FROM scan_results WHERE rule='legacy'")).rows[0];assert.equal(legacy.issue_type,'UNKNOWN');assert.equal(legacy.hotspot_review,'NOT_APPLICABLE');
  await db.query("INSERT INTO scan_history(id,project_id,scan_type,status) VALUES(1,1,'SAST','RUNNING')");
  const issues=[{rule:'fixture-style',type:'CODE_SMELL',severity:'MAJOR',message:'TEST FIXTURE naming',component:'cloudsentinel_1:app.js',line:1},{rule:'fixture-sqli',type:'VULNERABILITY',severity:'HIGH',message:'TEST FIXTURE injection',component:'cloudsentinel_1:app.js',line:2},{rule:'fixture-hotspot',type:'SECURITY_HOTSPOT',severity:'INFO',status:'TO_REVIEW',message:'TEST FIXTURE review required',component:'cloudsentinel_1:app.js',line:3}];
  const summary=await require('../services/sastEvidence').persistSastEvidence(db,{projectId:1,scanHistoryId:1,issues,coerceIssueRow:require('../routes/sast/config').coerceIssueRow});
  assert.equal(summary.total,3);const stored=(await db.query('SELECT issue_type,hotspot_review FROM scan_results WHERE scan_history_id=1 ORDER BY line_number')).rows;assert.deepEqual(stored.map(r=>r.issue_type),['CODE_SMELL','VULNERABILITY','SECURITY_HOTSPOT']);assert.equal(stored[2].hotspot_review,'TO_REVIEW');
  const scan=(await db.query('SELECT status,sast_details_linked,total_issues FROM scan_history WHERE id=1')).rows[0];assert.equal(scan.status,'COMPLETED');assert.equal(scan.sast_details_linked,true);assert.equal(scan.total_issues,3);assert.equal(Number((await db.query("SELECT COUNT(*)::int AS n FROM scan_results WHERE rule='legacy'")).rows[0].n),1);
 }finally{if(db)await db.end();await admin.query(`DROP SCHEMA ${schema} CASCADE`);admin.release();await base.end();}
});
