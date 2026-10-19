'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {filesystemReport,cycloneDxReport}=require('../services/trivyReport');
const {coverage}=require('../services/dependencyRuntime');
const envelope={SchemaVersion:2,ArtifactType:'filesystem',ArtifactName:'/isolated/test-fixture'};
test('actual Trivy 0.75 static HTML report may omit Results',()=>{const parsed=filesystemReport(envelope);assert.deepEqual(parsed.Results,[]);assert.equal(parsed.ArtifactName,envelope.ArtifactName);assert.equal(Object.hasOwn(envelope,'Results'),false);});
test('explicit empty inventory and real vulnerability evidence remain intact',()=>{assert.deepEqual(filesystemReport({...envelope,Results:[]}).Results,[]);const results=[{Target:'package-lock.json',Packages:[{Name:'fixture'}],Vulnerabilities:[{VulnerabilityID:'CVE-2026-1234',PkgName:'fixture'}]}];assert.deepEqual(filesystemReport({...envelope,Results:results}).Results,results);});
test('missing envelope, malformed arrays and wrong report kinds cannot become clean scans',()=>{for(const report of [null,{},[],{SchemaVersion:2},{...envelope,SchemaVersion:1},{...envelope,ArtifactName:''},{...envelope,ArtifactType:'container_image'}, {...envelope,Results:null},{...envelope,Results:{}},{...envelope,Results:[null]},{...envelope,Results:[{Vulnerabilities:'not an array'}]}])assert.throws(()=>filesystemReport(report),/Invalid Trivy report/);});
test('empty CycloneDX inventory is supported without accepting malformed or unrelated JSON',()=>{assert.deepEqual(cycloneDxReport({bomFormat:'CycloneDX',specVersion:'1.7',metadata:{component:{type:'application',name:'fixture'}},components:[]}).components,[]);assert.deepEqual(cycloneDxReport({bomFormat:'CycloneDX',specVersion:'1.6',metadata:{component:{type:'application',name:'fixture'}}}).components,[]);for(const report of [{},{bomFormat:'CycloneDX',specVersion:'1.7'},{bomFormat:'CycloneDX',specVersion:'1.7',components:null},{bomFormat:'SPDX',specVersion:'1.7',components:[]}])assert.throws(()=>cycloneDxReport(report),/Invalid CycloneDX/);});
test('HTML-only coverage stays explicitly unassessed; a missed manifest still blocks',()=>{const root=fs.mkdtempSync(path.join(os.tmpdir(),'trivy-report-fixture-'));try{fs.writeFileSync(path.join(root,'index.html'),'<title>TEST FIXTURE</title>');const report=filesystemReport({...envelope,ArtifactName:root});assert.equal(coverage(root,report).status,'NO_SUPPORTED_MANIFESTS_OBSERVED');fs.writeFileSync(path.join(root,'package-lock.json'),'{}');assert.equal(coverage(root,report).status,'MANIFESTS_WITHOUT_INVENTORY');}finally{fs.rmSync(root,{recursive:true,force:true});}});
test('IaC shares valid omitted-results handling without fabricating passed controls',()=>{const capture=require('../services/governance/configuration').captureConfiguration(envelope);assert.deepEqual(capture.targets,[]);assert.throws(()=>require('../services/governance/configuration').captureConfiguration({SchemaVersion:2}),/Invalid Trivy/);});

test('committed Git checkout reports are accepted without inventing inventory or IaC controls',()=>{
 const report={...envelope,ArtifactType:'repository'};
 assert.deepEqual(filesystemReport(report).Results,[]);
 assert.deepEqual(require('../services/governance/configuration').captureConfiguration(report).targets,[]);
 assert.throws(()=>filesystemReport({...report,ArtifactName:''}),/missing filesystem artifact evidence/);
 const results=[{Target:'package-lock.json',Packages:[{Name:'fixture'}]}];
 assert.deepEqual(filesystemReport({...report,Results:results}).Results,results);
});
test('Trivy accepts a real committed HTML checkout through production validation', {skip:!fs.existsSync('/usr/local/bin/trivy')},()=>{
 const {spawnSync}=require('node:child_process');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'trivy-committed-html-'));
 try {
  fs.writeFileSync(path.join(root,'index.html'),'<title>Offline test fixture</title>');
  for(const args of [['init','-q'],['add','.'],['-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture']]) assert.equal(spawnSync('git',args,{cwd:root}).status,0);
  const run=spawnSync('/usr/local/bin/trivy',['fs','--format','json','--offline-scan','--skip-db-update','--skip-java-db-update','--skip-check-update','--scanners','vuln,license','--list-all-pkgs','.'],{cwd:root,encoding:'utf8',timeout:30000});
  assert.equal(run.status,0,'offline fixture scan must succeed');
  const report=filesystemReport(JSON.parse(run.stdout));
  assert.equal(report.ArtifactType,'repository');
  assert.deepEqual(report.Results,[]);
  assert.equal(coverage(root,report).status,'NO_SUPPORTED_MANIFESTS_OBSERVED');
 } finally {fs.rmSync(root,{recursive:true,force:true});}
});
