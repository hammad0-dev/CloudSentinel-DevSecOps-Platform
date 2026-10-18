'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const {detailRecords}=require('../services/stageProvenance'),{digest}=require('../services/deploymentEligibility');
test('successive same-project scans retain independently verifiable details and isolate other projects',async()=>{
 const rows=[{id:1,scan_id:10,project_id:18,message:'original'},{id:2,scan_id:20,project_id:18,message:'new'},{id:3,scan_id:10,project_id:19,message:'foreign'}];
 const pool={query:async(sql,[id,project])=>{assert.match(sql,/scan_id=\$1 AND project_id=\$2 ORDER BY id/);return {rows:rows.filter(r=>r.scan_id===id&&r.project_id===project).map(record=>({record}))}}};
 const context={projectId:18},before=digest(await detailRecords(pool,context,'IaC',10));rows.push({id:4,scan_id:20,project_id:18,message:'later'});
 assert.equal(digest(await detailRecords(pool,context,'IaC',10)),before);assert.equal((await detailRecords(pool,context,'IaC',10)).length,1);
});
test('scanners replace only the current scan; retention migration protects duplicate writes and completed cascades',()=>{
 for(const [file,table] of [['dependency','sbom_components'],['iac','iac_findings']])assert.match(fs.readFileSync(`backend/routes/${file}.js`,'utf8'),new RegExp(`DELETE FROM ${table} WHERE project_id = \\$1 AND scan_id = \\$2`));
 const sql=fs.readFileSync('backend/migrations/019_scan_evidence_retention.sql','utf8');assert.match(sql,/FOR UPDATE/);assert.match(sql,/COMPLETED_SCAN_EVIDENCE_IMMUTABLE/);assert.match(sql,/ATTESTED_SCAN_RECORD_IMMUTABLE/);assert.match(sql,/SCAN_EVIDENCE_PARENT_MISMATCH/);assert.equal((sql.match(/CREATE TRIGGER/g)||[]).length,8);assert.doesNotMatch(sql,/DROP|ALTER.*immutable_|UPDATE\s+deployment_stage_attestations/);
});
