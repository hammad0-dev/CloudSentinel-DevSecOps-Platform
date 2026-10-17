'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),vm=require('vm'),{spawnSync}=require('child_process'),{createRequire}=require('module');
// SQLite's JSON tuple models PostgreSQL's composite DISTINCT value, including
// the unmatched LEFT JOIN tuple. No PostgreSQL connection is used by these tests.
function aggregate(sql,params,scans,findings){
 assert.match(sql,/COUNT\(sr\.id\)::int AS persisted_total/);
 assert.match(sql,/COUNT\(DISTINCT \(sr\.rule, sr\.severity, sr\.message, sr\.file_path, sr\.line_number\)\) FILTER \(WHERE sr\.id IS NOT NULL\)/);
 const translated=sql.replaceAll('::int','').replace(/COUNT\(DISTINCT \((sr\.rule, sr\.severity, sr\.message, sr\.file_path, sr\.line_number)\)\)/,'COUNT(DISTINCT json_array($1))').replaceAll('$1','?1').replaceAll('$2','?2');
 const result=spawnSync('python3',['-c',`
import json,sqlite3,sys
x=json.load(sys.stdin); db=sqlite3.connect(':memory:'); db.row_factory=sqlite3.Row
db.execute('CREATE TABLE scan_history (id INTEGER PRIMARY KEY, project_id INTEGER, pipeline_execution_id INTEGER, status TEXT, sast_details_linked BOOLEAN, critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, total_issues INTEGER)')
db.execute('CREATE TABLE scan_results (id INTEGER PRIMARY KEY, project_id INTEGER, scan_history_id INTEGER, rule TEXT, severity TEXT, message TEXT, file_path TEXT, line_number INTEGER, issue_type TEXT, hotspot_review TEXT)')
for table in ['scan_history','scan_results']:
 for r in x[table]: db.execute('INSERT INTO '+table+' ('+','.join(r)+') VALUES ('+','.join('?' for _ in r)+')',list(r.values()))
print(json.dumps([dict(r) for r in db.execute(x['sql'],x['params'])]))
`],{input:JSON.stringify({sql:translated,params,scan_history:scans,scan_results:findings}),encoding:'utf8',timeout:5000});
 assert.equal(result.status,0,result.stderr);return JSON.parse(result.stdout);
}
const scan=(overrides={})=>({id:49,project_id:11,pipeline_execution_id:23,status:'COMPLETED',sast_details_linked:true,critical:0,high:0,medium:0,low:0,total_issues:0,...overrides});
const finding=(id,severity='MINOR',overrides={})=>({id,project_id:11,scan_history_id:49,rule:'r'+id,issue_type:'VULNERABILITY',hotspot_review:'NOT_APPLICABLE',severity,message:'m'+id,file_path:'f.js',line_number:id,...overrides});
function harness(scans,findings,{overrideRow}={}){
 const file=require.resolve('../services/orchestrator'),local=createRequire(file),calls=[],writes=[];let raw;
 const pool={async query(sql,params){if(sql.includes('FROM scan_history sh')){const rows=aggregate(sql,params,scans,findings);raw=rows[0];return {rows:overrideRow?[overrideRow]:rows};}if(sql.startsWith('SELECT critical'))return {rows:[{critical:0}]};writes.push({sql,params});return {rows:[],rowCount:1};}};
 const stubs={'../db':pool,'./deployment':{async deployProject(){calls.push('deploy');return {stagingUrl:'http://fixture.invalid'};}},'axios':{async post(url){calls.push(url.split('/api/')[1].split('/')[0]);return {data:{}};}},'jsonwebtoken':{sign(){return 'offline';}},'./activeDastCommissioning':{selection(){return null;}},'./commissioningFixtureStage':{has(){return false;}}};
 const module={exports:{}};vm.runInNewContext(fs.readFileSync(file,'utf8'),{module,exports:module.exports,require:id=>Object.hasOwn(stubs,id)?stubs[id]:local(id),process:{env:{DAST_ACTIVE_ENABLED:'false'}},console:{log(){},warn(){},error(){}},setTimeout});
 return {gate:()=>module.exports.checkCriticalFindings(11,23,'SAST'),pipeline:()=>module.exports.runPipeline(23,11,3),calls,writes,raw:()=>raw};
}
test('execution 23 zero-finding shape yields zero distinct rows and passes consistency',async()=>{const h=harness([scan()],[]),r=await h.gate();assert.equal(h.raw().persisted_total,0);assert.equal(h.raw().distinct_total,0);assert.equal(r.evidenceConsistent,true);assert.equal(r.hasCritical,false);assert.equal(r.hasHigh,false);});
test('one real finding is counted once',async()=>{const h=harness([scan({total_issues:1,medium:1})],[finding(1)]);assert.equal((await h.gate()).evidenceConsistent,true);assert.equal(h.raw().distinct_total,1);});
test('multiple severities retain exact grouping and counts',async()=>{const h=harness([scan({total_issues:7,critical:1,high:2,medium:3,low:1})],['CRITICAL','MAJOR','HIGH','MINOR','MEDIUM','LOW','INFO'].map((s,i)=>finding(i+1,s)));const r=await h.gate();assert.equal(r.evidenceConsistent,true);assert.equal(r.hasCritical,true);assert.equal(r.hasHigh,true);assert.equal(h.raw().distinct_total,7);});
test('duplicate evidence remains blocked despite different finding IDs',async()=>{const a=finding(1),b={...a,id:2};const h=harness([scan({total_issues:2,medium:2})],[a,b]);assert.equal((await h.gate()).evidenceConsistent,false);assert.equal(h.raw().persisted_total,2);assert.equal(h.raw().distinct_total,1);});
test('missing findings cannot match a nonzero scan summary',async()=>{const h=harness([scan({total_issues:1,medium:1})],[]);assert.equal((await h.gate()).evidenceConsistent,false);});
for(const state of ['FAILED','RUNNING','CANCELLED'])test(`${state} SAST is not completed evidence`,async()=>{const r=await harness([scan({status:state})],[]).gate();assert.equal(r.evidenceFound,false);assert.equal(r.evidenceConsistent,false);});
test('missing scan or incomplete linkage fails closed',async()=>{for(const scans of [[],[scan({sast_details_linked:false})]]){const r=await harness(scans,[]).gate();assert.equal(r.evidenceFound,false);}});
test('other project/execution/scan findings cannot contaminate this gate',async()=>{const h=harness([scan(),scan({id:50,project_id:17,total_issues:1,critical:1}),scan({id:51,pipeline_execution_id:24,total_issues:1,critical:1})],[finding(1,'CRITICAL',{project_id:17,scan_history_id:50}),finding(2,'CRITICAL',{scan_history_id:51})]);assert.equal((await h.gate()).evidenceConsistent,true);assert.equal(h.raw().persisted_total,0);});
test('severity mismatch and missing severity remain inconsistent',async()=>{for(const severity of ['HIGH',null]){const r=await harness([scan({total_issues:1,medium:1})],[finding(1,severity)]).gate();assert.equal(r.evidenceConsistent,false);}});
test('malformed or incomplete aggregate counts fail closed',async()=>{const zero={total_issues:0,critical:0,high:0,medium:0,low:0,persisted_total:0,distinct_total:0,persisted_critical:0,persisted_high:0,persisted_medium:0,persisted_low:0};for(const value of [null,undefined,-1,0.5,'bad']){const r=await harness([scan()],[],{overrideRow:{...zero,distinct_total:value}}).gate();assert.equal(r.evidenceConsistent,false);}});
test('valid empty scan advances through the unchanged static stages',async()=>{const h=harness([scan()],[]);await h.pipeline();assert.deepEqual(h.calls,['sast','dependencies','iac','deploy','dast']);});
for(const severity of ['CRITICAL','HIGH','MAJOR'])test(`${severity} evidence stops pipeline before dependency or deployment`,async()=>{const h=harness([scan({total_issues:1,...(severity==='CRITICAL'?{critical:1}:{high:1})})],[finding(1,severity)]);await h.pipeline();assert.deepEqual(h.calls,['sast']);assert(h.writes.some(x=>x.sql.includes("status = 'STAGE_FAILED'")));});
test('MAJOR CODE_SMELL stays in severity totals but never becomes security HIGH',async()=>{const h=harness([scan({total_issues:2,high:2})],[finding(1,'MAJOR',{issue_type:'CODE_SMELL'}),finding(2,'MAJOR',{issue_type:'CODE_SMELL'})]);const r=await h.gate();assert.equal(r.evidenceConsistent,true);assert.equal(r.hasHigh,false);assert.equal(r.requiresReview,false);await h.pipeline();assert(h.calls.includes('dependencies'));});
test('mixed maintainability and security findings still block genuine vulnerability',async()=>{const h=harness([scan({total_issues:2,high:2})],[finding(1,'MAJOR',{issue_type:'CODE_SMELL'}),finding(2,'MAJOR',{issue_type:'VULNERABILITY'})]);assert.equal((await h.gate()).hasHigh,true);});
test('hotspots require review independently of severity',async()=>{for(const review of ['TO_REVIEW','SAFE','FIXED']){const h=harness([scan({total_issues:1,low:1})],[finding(1,'INFO',{issue_type:'SECURITY_HOTSPOT',hotspot_review:review})]);const r=await h.gate();assert.equal(r.hasHigh,false);assert.equal(r.requiresReview,review==='TO_REVIEW');}});
test('unclassified historical findings cannot silently pass',async()=>{const r=await harness([scan({total_issues:1,high:1})],[finding(1,'MAJOR',{issue_type:'UNKNOWN'})]).gate();assert.equal(r.requiresReview,true);});
