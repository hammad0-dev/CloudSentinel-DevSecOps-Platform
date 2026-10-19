// Explicit opt-in. Creates a dedicated temporary PostgreSQL schema, never inserts
// fixtures into public tables and never invokes scanners/deployments.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs'),path=require('path');
require('dotenv').config({path:path.join(__dirname,'../.env')});
test('PostgreSQL end-to-end governance: isolation, ingestion, API, reports and lifecycle',{skip:process.env.GOVERNANCE_DB_TEST!=='1'},async()=>{
 const {Pool}=require('pg'),base=require('../db');
 const schema=`governance_test_${process.pid}_${Date.now()}`;
 const admin=await base.connect();let db,server;
 try {
  await admin.query(`CREATE SCHEMA ${schema}`);
  db=new Pool({...base.options,password:base.options.password,connectionTimeoutMillis:3000,options:`-c search_path=${schema},public -c timezone=UTC`});
  await db.query(fs.readFileSync(path.join(__dirname,'../../schema.sql'),'utf8'));
  for(const table of ['iac_scans','iac_findings','image_scans','image_vulnerabilities','dast_scans','dast_findings'])await db.query(`CREATE TABLE ${table} (LIKE public.${table} INCLUDING DEFAULTS)`);
  await db.query('ALTER TABLE scan_results ADD COLUMN scan_history_id INTEGER');
  const classification=fs.readFileSync(path.join(__dirname,'../migrations/016_sast_issue_classification.sql'),'utf8');await db.query(classification);await db.query(classification);
  await db.query(`CREATE TABLE active_dast_executions(id INTEGER,project_id INTEGER,status TEXT,result JSONB,created_at TIMESTAMPTZ)`);
  const migration=fs.readFileSync(path.join(__dirname,'../migrations/017_governance.sql'),'utf8');await db.query(migration);await db.query(migration);
  const fe3=fs.readFileSync(path.join(__dirname,'../migrations/018_compliance_assessments.sql'),'utf8');await db.query(fe3);await db.query(fe3);
  await db.query("INSERT INTO users(id,full_name,email,password_hash) VALUES(1,'Fixture owner','fixture1@example.test','unused-test-only'),(2,'Other owner','fixture2@example.test','unused-test-only')");
  await db.query("INSERT INTO projects(id,user_id,name,repo_url) VALUES(1,1,'Fixture alpha','https://example.test/alpha'),(2,2,'Fixture private','https://example.test/private'),(3,1,'Fixture beta','https://example.test/beta')");
  await db.query("INSERT INTO scan_history(id,project_id,scan_type,status,total_issues,completed_at) VALUES(1,1,'SAST','COMPLETED',2,'2026-01-01'),(2,1,'SAST','COMPLETED',1,'2026-01-02'),(3,2,'SAST','COMPLETED',1,'2026-01-03')");
  await db.query("INSERT INTO scan_results(id,project_id,scan_history_id,rule,severity,message,file_path,line_number,issue_type) VALUES(1,1,1,'CWE-89','MAJOR','Injection','app.js',12,'VULNERABILITY'),(2,1,1,'style','MAJOR','Naming','app.js',1,'CODE_SMELL'),(3,1,2,'CWE-89','CRITICAL','Injection','app.js',12,'VULNERABILITY'),(4,2,3,'private','HIGH','Private finding','private.js',1,'VULNERABILITY')");
  await db.query("INSERT INTO dependency_scans(id,project_id,status,total_packages,completed_at) VALUES(1,1,'COMPLETED',2,'2026-01-03'),(2,3,'COMPLETED',0,'2026-01-04'),(3,1,'COMPLETED',2,'2025-01-01')");
  await db.query("INSERT INTO sbom_components(id,scan_id,project_id,pkg_name,pkg_version,cve_id,severity) VALUES(1,1,1,'pkg','1','CVE-2026-1234','HIGH'),(2,1,1,'safe','1',NULL,'UNKNOWN')");
  await db.query("INSERT INTO iac_scans(id,project_id,status,total_findings,completed_at) VALUES(1,1,'COMPLETED',1,'2026-01-03')");
  await db.query("INSERT INTO iac_findings(id,scan_id,project_id,config_file,misconfig_id,severity,description) VALUES(1,1,1,'Dockerfile','DS002','HIGH','Non-root user missing')");
  await db.query("INSERT INTO image_scans(id,project_id,image_tag,status,total_vulnerabilities,completed_at) VALUES(1,1,'fixture:v1','BLOCKED',1,'2026-01-04')");
  await db.query("INSERT INTO image_vulnerabilities(id,image_scan_id,project_id,vulnerability_id,severity,package_name) VALUES(1,1,1,'CVE-2026-9876','CRITICAL','libssl')");
  await db.query("INSERT INTO dast_scans(id,project_id,status,total_findings,completed_at) VALUES(1,1,'COMPLETED',1,'2026-01-05')");
  await db.query("INSERT INTO dast_findings(id,scan_id,project_id,alert,attack_type,severity,endpoint,cwe_id) VALUES(1,1,1,'Cross-site scripting','plugin 40012','HIGH','http://example.test/x?token=secret',79)");
  await db.query(`INSERT INTO active_dast_executions VALUES(1,1,'COMPLETED_NO_FINDINGS','{"findings":[]}', '2026-01-06')`);
  // Inject only the isolated test pool into the route module; real JWT middleware.
  const dbPath=require.resolve('../db');const cached=require.cache[dbPath].exports;require.cache[dbPath].exports=db;
  const express=require('express'),app=express();app.use(express.json());app.use('/api/governance',require('../routes/governance'));app.use('/api/sast',require('../routes/sast'));require.cache[dbPath].exports=cached;
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
  const url=`http://127.0.0.1:${server.address().port}/api/governance`;
  const jwt=require('jsonwebtoken');const token=jwt.sign({id:1},process.env.JWT_SECRET);
  const call=(p,opts={})=>fetch(url+p,{...opts,headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json',...opts.headers}});
  assert.equal((await fetch(url+'/summary')).status,401);
  let r=await call('/sync',{method:'POST'});assert.equal(r.status,200);const first=await r.json();assert.equal(first.importedObservations,6);
  r=await call('/sync',{method:'POST'});assert.equal((await r.json()).importedObservations,0);
  const summary=await(await call('/summary')).json();assert.equal(summary.total,5);assert.equal(summary.projects.length,2);assert.equal(summary.compliance.cisSummary.FAILED,1);assert.equal(summary.score.assessedSlots,6);assert.equal(summary.score.totalSlots,10);assert.equal(summary.recentScans.find(s=>s.source==='IMAGE').source_status,'BLOCKED');
  assert.equal((await call('/summary?project=2')).status,404);
  const untouched=await(await call('/summary',{headers:{Authorization:`Bearer ${jwt.sign({id:2},process.env.JWT_SECRET)}`}})).json();assert.equal(untouched.total,0);assert.equal(untouched.score.value,null);
  assert.equal((await call('/findings?source=bogus')).status,400);
  const listing=await(await call('/findings?pageSize=2')).json();assert.equal(listing.findings.length,2);assert.equal(listing.total,5);
  const second=await(await call('/findings?pageSize=2&page=2')).json();assert.ok(!second.findings.some(f=>listing.findings.some(g=>f.id===g.id)));
  const filtered=await(await call('/findings?search=CVE-2026-1234')).json();assert.equal(filtered.total,1);
  const mapped=await(await call('/findings?mapping=A03:2021')).json();assert.equal(mapped.total,2);
  const dated=await(await call('/summary?from=2026-01-02&to=2026-01-02&severity=CRITICAL')).json();assert.equal(dated.total,1);assert.deepEqual(dated.trend,[{day:'2026-01-02',value:1}]);
  const sast=(await(await call('/findings?source=SAST')).json()).findings[0];assert.equal(sast.severity,'CRITICAL');
  let detail=await(await call(`/findings/${sast.id}`)).json();assert.equal(detail.observations.length,2);assert.ok(detail.finding.mappings.every(m=>m.findingId===String(sast.id)));assert.equal(new Set(detail.finding.mappings.map(m=>m.frameworkId+m.id)).size,detail.finding.mappings.length);
  r=await call(`/findings/${sast.id}/status`,{method:'PATCH',body:JSON.stringify({status:'RESOLVED',reason:'Fixture owner review'})});assert.equal(r.status,200);
  await call('/sync',{method:'POST'});detail=await(await call(`/findings/${sast.id}`)).json();assert.equal(detail.finding.status,'RESOLVED');assert.equal(detail.history.length,1);
  const otherToken=jwt.sign({id:2},process.env.JWT_SECRET);assert.equal((await call(`/findings/${sast.id}`,{headers:{Authorization:`Bearer ${otherToken}`}})).status,404);assert.equal((await call(`/findings/${sast.id}/status`,{method:'PATCH',headers:{Authorization:`Bearer ${otherToken}`},body:JSON.stringify({status:'OPEN',reason:'Unauthorized'})})).status,404);
  for(const kind of ['security','compliance']){r=await call(`/export/${kind}?project=1`);assert.equal(r.status,200);assert.ok(r.headers.get('content-type').includes('application/pdf'));assert.equal(Buffer.from(await r.arrayBuffer()).subarray(0,5).toString(),'%PDF-');}
  r=await call('/export/csv?source=SAST');const csv=await r.text();assert.ok(csv.includes('Fixture alpha'));assert.ok(!csv.includes('Fixture private'));
  // Empty authorized project has no findings and a genuine completed empty scan.
  const empty=await(await call('/summary?project=3')).json();assert.equal(empty.total,0);assert.equal(empty.score.value,19);
  // Absence in a later complete scan does not silently resolve an older finding.
  await db.query("INSERT INTO scan_history(id,project_id,scan_type,status,total_issues,completed_at) VALUES(5,1,'SAST','COMPLETED',0,'2026-01-07')");await call('/sync',{method:'POST'});assert.equal((await(await call(`/findings/${sast.id}`)).json()).finding.status,'RESOLVED');
  const beforeIac=(await(await call('/findings?source=IAC')).json()).findings[0];
  await db.query('DELETE FROM iac_findings WHERE project_id=1');
  await db.query("INSERT INTO iac_scans(id,project_id,status,total_findings,completed_at) VALUES(8,1,'COMPLETED',0,'2026-01-08')");
  const parallel=await Promise.all([call('/sync',{method:'POST'}),call('/sync',{method:'POST'})]);for(const response of parallel)assert.equal(response.status,200);
  assert.equal((await(await call(`/findings/${beforeIac.id}`)).json()).finding.status,'OPEN');
  // Clearly labeled fixture of explicit Trivy non-failure output: never public data.
  const rawFixture={SchemaVersion:2,Results:[{Class:'config',Type:'dockerfile',Target:'Dockerfile',Misconfigurations:[
    {ID:'DS002',Status:'PASS'},{ID:'DS002',Status:'PASS'},{ID:'DS026',Status:'FAIL'},{ID:'DS017',Status:'EXCEPTION'}]}]};
  const capture=require('../services/governance/configuration').captureConfiguration(rawFixture);
  await db.query("INSERT INTO iac_scans(id,project_id,status,total_findings,completed_at,configuration_evidence) VALUES(9,1,'COMPLETED',1,'2026-01-09',$1::jsonb)",[JSON.stringify(capture)]);
  await db.query("INSERT INTO iac_findings(id,scan_id,project_id,config_file,misconfig_id,severity,description) VALUES(9,9,1,'Dockerfile','DS026','LOW','TEST FIXTURE missing health check')");
  const synced=await(await call('/sync',{method:'POST'})).json();assert.equal(synced.importedAssessments,3);
  assert.equal((await(await call('/sync',{method:'POST'})).json()).importedAssessments,0);
  // A new PASS cannot silently resolve a retained OPEN failure on the same requirement.
  const conflict=await(await call('/compliance?project=1&owaspVersion=2025')).json();
  assert.equal(conflict.metrics.PASS,0);assert.equal(conflict.metrics.FAIL,2);
  assert.equal(conflict.projectControls.find(c=>c.id==='4.1').status,'FAIL');
  await call(`/findings/${beforeIac.id}/status`,{method:'PATCH',body:JSON.stringify({status:'RESOLVED',reason:'Fixture verified remediation of historical Dockerfile violation'})});
  const compliance=await(await call('/compliance?project=1&owaspVersion=2025')).json();
  assert.equal(compliance.overall.passRate,Math.round(10000*compliance.overall.PASS/compliance.overall.assessed)/100);
  assert.equal(compliance.matching.owasp.total,10);assert.equal(compliance.matching.cisControls.total,18);assert.equal(compliance.matching.docker.total,12);assert.equal(compliance.matching.owasp.matched,compliance.owasp.filter(c=>c.findings>0).length);assert.ok(compliance.owaspMetrics.FAIL>0);assert.ok(compliance.cisControls.some(c=>c.id==='CIS-16'&&c.unresolved>0));
  const baselineAll=await(await call('/summary')).json();
  const betaCompliance=await(await call('/compliance?project=3')).json();assert.equal(betaCompliance.overall.passRate,null);
  const allAfter=await(await call('/summary')).json();assert.equal(allAfter.total,baselineAll.total);assert.deepEqual(allAfter.score,baselineAll.score);assert.deepEqual(allAfter.projects.map(p=>p.id),[1,3]);
  assert.equal((await call('/compliance',{headers:{Authorization:`Bearer ${otherToken}`}})).status,200);
  assert.equal(compliance.version,'OWASP Top 10:2025');assert.equal(compliance.metrics.PASS,1);assert.equal(compliance.metrics.FAIL,1);assert.equal(compliance.metrics.ERROR,1);assert.equal(compliance.metrics.NOT_ASSESSED,9);assert.equal(compliance.metrics.passRate,50);assert.equal(compliance.metrics.coverage,16.67);
  const selectedSummary=await(await call('/summary?project=1&owaspVersion=2025')).json();assert.deepEqual(selectedSummary.compliance.metrics,compliance.metrics);
  assert.equal((await call('/compliance?project=2')).status,404);
  assert.equal((await call('/compliance/controls/4.1?project=2')).status,404);
  assert.equal((await call('/compliance?benchmark=unsupported')).status,400);
  const isolatedControl=await(await call('/compliance/controls/4.1',{headers:{Authorization:`Bearer ${otherToken}`}})).json();assert.equal(isolatedControl.total,0);
  const history=await(await call('/compliance/controls/4.1?project=1&pageSize=1')).json();assert.equal(history.total,2);assert.equal(history.history.length,1);assert.equal(history.history[0].status,'PASS');assert.equal(history.current[0].status,'PASS');assert.equal(history.history[0].evidence.scanId,'9');
  const older=await(await call('/compliance/controls/4.1?project=1&page=2&pageSize=1')).json();assert.equal(older.history[0].status,'FAIL');
  const past=await(await call('/compliance?project=1&to=2026-01-03')).json();assert.equal(past.metrics.FAIL,1);assert.equal(past.metrics.PASS,0);
  const unrelatedFilters=await(await call('/compliance?project=1&severity=CRITICAL&status=RESOLVED')).json();assert.equal(unrelatedFilters.metrics.passRate,50);
  const emptyControl=await(await call('/compliance/controls/4.5?project=1')).json();assert.equal(emptyControl.total,0);assert.equal(emptyControl.current[0].status,'NOT_ASSESSED');
  const legacy=await fetch(url.replace('/governance','/sast/compliance/1'),{headers:{Authorization:`Bearer ${token}`}});assert.equal(legacy.status,200);const legacyBody=await legacy.json();assert.equal(legacyBody.summary.complianceScore,legacyBody.overall.passRate);assert.equal(legacyBody.summary.assessmentCoverage,legacyBody.overall.coverage);
  const mapped2025=await(await call('/findings?project=1&mapping=A05:2025&owaspVersion=2025')).json();assert.equal(mapped2025.total,2);
  const unmapped=await(await call('/findings?project=1&mapping=UNMAPPED&owaspVersion=2025')).json();assert.equal(unmapped.total,0);
  const csvReport=await(await call('/export/compliance-csv?project=1&owaspVersion=2025')).text();assert.ok(csvReport.includes('"50","16.67"'));assert.ok(csvReport.includes('"PASS"'));assert.ok(csvReport.includes('"FAIL"'));assert.ok(!csvReport.includes('Fixture private'));
  const pdfBuffer=Buffer.from(await(await call('/export/compliance?project=1&owaspVersion=2025')).arrayBuffer());
  const zlib=require('node:zlib');let extracted='';const encoded=pdfBuffer.toString('latin1');for(const match of encoded.matchAll(/stream\r?\n([\s\S]*?)\r?\nendstream/g)){try{const stream=zlib.inflateSync(Buffer.from(match[1],'latin1')).toString('latin1');for(const hex of stream.matchAll(/<([0-9a-f]+)>/gi))extracted+=Buffer.from(hex[1],'hex').toString('latin1');}catch{}}
  assert.ok(extracted.includes(`Compliance pass rate: ${compliance.overall.passRate}%`));assert.ok(extracted.includes('CIS Controls v8 associations'));assert.ok(extracted.includes(`OWASP categories matched: ${compliance.matching.owasp.matched}/10`));assert.ok(extracted.includes(`CIS Controls v8 matched: ${compliance.matching.cisControls.matched}/18`));assert.ok(extracted.includes('Pass rate: 50%'));assert.ok(extracted.includes('Assessment coverage: 16.67%'));assert.ok(extracted.includes('OWASP Top 10:2025'));
  // Unsupported N/A is never inferred. A labeled future-adapter fixture demonstrates
  // persistence/metrics only with explicit verified applicability evidence.
  const targetId=(await db.query("SELECT id FROM governance_configuration_targets WHERE governance_scan_id=(SELECT id FROM governance_scans WHERE project_id=1 AND source='IAC' AND scan_id='9')")).rows[0].id;
  await db.query("INSERT INTO governance_control_assessments(target_id,benchmark_id,benchmark_version,control_id,check_id,status,evidence) VALUES($1,'docker-cis-1.6.0','1.6.0','4.9','DS0005','NOT_APPLICABLE',$2::jsonb)",[targetId,JSON.stringify({rule:'DS0005',resource:'Dockerfile',scanId:'9',sourceTimestamp:'2026-01-09T00:00:00Z',applicability:{verified:true,reason:'TEST FIXTURE future adapter scope exclusion',sourceReference:'test-fixture:explicit-scope'}})]);
  const withNa=await(await call('/compliance?project=1')).json();assert.equal(withNa.metrics.NOT_APPLICABLE,1);assert.equal(withNa.metrics.applicable,11);assert.equal(withNa.metrics.coverage,18.18);
  // Main-dashboard regression with real findings in BOTH authorized projects.
  await db.query("INSERT INTO scan_history(id,project_id,scan_type,status,total_issues,completed_at) VALUES(6,3,'SAST','COMPLETED',1,'2026-01-10')");
  await db.query("INSERT INTO scan_results(id,project_id,scan_history_id,rule,severity,message,file_path,line_number,issue_type) VALUES(6,3,6,'CWE-89','HIGH','TEST FIXTURE beta vulnerability','beta.js',3,'VULNERABILITY')");
  await call('/sync',{method:'POST'});
  await call('/sync',{method:'POST',headers:{Authorization:`Bearer ${otherToken}`}});
  const allProjects=await(await call('/summary')).json();
  assert.ok(allProjects.byProject.some(p=>String(p.id)==='1'&&p.value>0));
  assert.ok(allProjects.byProject.some(p=>String(p.id)==='3'&&p.value>0));
  assert.ok(!allProjects.byProject.some(p=>String(p.id)==='2'));assert.equal(allProjects.compliance.matching.owasp.total,10);assert.equal(allProjects.compliance.matching.owasp.matched,allProjects.compliance.owasp.filter(c=>c.findings>0).length);assert.equal(allProjects.compliance.matching.cisControls.total,18);
  const selectedProject=await(await call('/summary?project=3')).json();assert.equal(selectedProject.total,1);
  assert.equal(selectedProject.compliance.uniqueVulnerabilities,1);
  const afterSelection=await(await call('/summary')).json();assert.equal(afterSelection.total,allProjects.total);assert.deepEqual(afterSelection.score,allProjects.score);
  const foreign=await(await call('/summary',{headers:{Authorization:`Bearer ${otherToken}`}})).json();assert.equal(foreign.total,1);assert.equal(foreign.projects.length,1);assert.equal(String(foreign.projects[0].id),'2');
  console.log('Isolated DB workflow verified: 6 observations, 5 deduplicated findings, six sources, owner isolation, date filters, lifecycle and PDF/CSV.');
 } finally {if(server)await new Promise(r=>server.close(r));if(db)await db.end();await admin.query(`DROP SCHEMA ${schema} CASCADE`);admin.release();await base.end();}
});
