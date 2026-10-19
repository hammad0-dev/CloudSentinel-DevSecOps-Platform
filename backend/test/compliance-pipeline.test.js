const test=require('node:test'),assert=require('node:assert/strict');
const {buildCompliance}=require('../services/governance/assessments');
const {mapFinding,docker}=require('../services/governance/registry');
const {uniqueFindings}=require('../services/governance/complianceResult');
const p=[{id:1,name:'Fixture A'}];
function finding(source,extra={}){const f={id:source,project_id:1,source,identity:'CWE-89',location:`${source}/file:1`,references:['CWE-89'],classification:'VULNERABILITY',status:'OPEN',severity:'CRITICAL',scan_id:'fixture-scan',...extra};f.mappings=mapFinding(f);return f;}
test('every supported stage uses one OWASP engine; CIS association is not a benchmark assessment',()=>{
 for(const source of ['SAST','DEPENDENCY','IMAGE','DAST','ACTIVE_DAST']){
  const f=finding(source),c=buildCompliance([f],p);
  assert.equal(c.owasp.find(x=>x.id==='A03:2021').status,'FAIL');assert.equal(c.owaspMetrics.FAIL,1);
  assert.equal(c.cisControls.find(x=>x.id==='CIS-16').status,'CONTROL_GAP');assert.equal(c.metrics.FAIL,0);assert.equal(c.metrics.PASS,0);
  assert.equal(c.overall.passRate,null);assert.equal(c.overall.assessed,0);assert.equal(c.overall.coverage,0);assert.equal(c.owaspMetrics.passRate,0);assert.equal(c.matching.owasp.percentage,10);
 }
 const i=finding('IAC',{identity:'DS0002',references:[],classification:'MISCONFIGURATION',location:'Dockerfile:1'}),c=buildCompliance([i],p);
 assert.equal(c.metrics.FAIL,1);assert.equal(c.cisControls.find(x=>x.id==='CIS-4').unresolved,1);assert.equal(c.owasp.find(x=>x.id==='A05:2021').status,'FAIL');
});
test('no evidence is unassessed; clean scans and resolved observations never create positive categories',()=>{
 assert.equal(buildCompliance([],p).overall.passRate,null);
 for(const status of ['RESOLVED','FALSE_POSITIVE']){const c=buildCompliance([finding('DAST',{status})],p);assert.equal(c.overall.FAIL,0);assert.equal(c.overall.PASS,0);assert.equal(c.overall.passRate,null);assert.equal(c.owasp[2].findings,1);}
 assert.equal(buildCompliance([finding('DAST',{status:'ACCEPTED_RISK'})],p).owaspMetrics.FAIL,1);
 assert.equal(buildCompliance([finding('SAST',{classification:'HOTSPOT_REVIEW'})],p).overall.FAIL,0);
});
test('cross-source duplicate requires same CVE and exact resource; evidence and unresolved lifecycle survive',()=>{
 const a=finding('DEPENDENCY',{identity:'CVE-2026-1234',references:['CVE-2026-1234'],location:'npm:pkg@1',status:'RESOLVED'}),b=finding('IMAGE',{identity:a.identity,references:a.references,location:a.location});
 const grouped=uniqueFindings([a,b]);assert.equal(grouped.length,1);assert.equal(grouped[0].observations.length,2);assert.equal(grouped[0].status,'OPEN');
 assert.equal(buildCompliance([a,b],p).owasp.find(c=>c.id==='A06:2021').findings,1);
 assert.equal(uniqueFindings([a,{...b,location:'another-image / npm:pkg@1'}]).length,2);
 assert.equal(uniqueFindings([a,{...b,project_id:2}]).length,2);
 assert.equal(uniqueFindings([finding('SAST'),finding('DAST')]).length,2);
});
test('critical exact requirement violation overrides recorded PASS until reviewed',()=>{
 const t=[{id:1,project_id:1,resource:'Dockerfile'}],o=[{project_id:1,target_id:1,benchmark_id:docker.id,benchmark_version:docker.version,control_id:'4.1',status:'PASS',evidence:{rule:'DS0002',resource:'Dockerfile',scanId:'1',sourceTimestamp:'2026-01-01T00:00:00Z'}}];
 const f=finding('IAC',{identity:'DS0002',location:'Dockerfile:1',references:[],classification:'MISCONFIGURATION'});
 const c=buildCompliance([f],p,t,o);assert.equal(c.metrics.PASS,0);assert.equal(c.metrics.FAIL,1);assert.equal(c.projectControls.find(x=>x.id==='4.1').status,'FAIL');
 const resolved=buildCompliance([{...f,status:'RESOLVED'}],p,t,o);assert.equal(resolved.metrics.PASS,1);assert.equal(resolved.owaspMetrics.PASS,0);
});
test('unmapped uncertainty stays visible and version selection changes only the selected framework',()=>{
 const f=finding('DAST',{identity:'unknown',references:[]});const c=buildCompliance([f],p);assert.equal(c.unmapped,1);assert.equal(c.overall.passRate,null);
 const mapped=buildCompliance([finding('DAST')],p,[],[],{owaspVersion:'2025'});assert.equal(mapped.owasp.find(c=>c.id==='A05:2025').status,'FAIL');
 assert.equal(mapped.sourceObservations[0].scanId,'fixture-scan');
});

test('five distinct findings and overlapping projects match one category out of ten',()=>{
 const rows=Array.from({length:5},(_,i)=>finding(i%2?'SAST':'DAST',{id:String(i),location:`file-${i}:1`,project_id:i===4?2:1}));
 const c=buildCompliance([...rows,rows[0]], [...p,{id:2,name:'Fixture B'}]);
 assert.equal(c.matching.owasp.matched,1);assert.equal(c.matching.owasp.total,10);assert.equal(c.matching.owasp.percentage,10);
 assert.equal(c.owasp.find(x=>x.id==='A03:2021').findings,5);assert.equal(c.owaspMetrics.FAIL,2);assert.equal(c.owaspMetrics.total,20);
 assert.equal(c.matching.cisControls.matched,1);assert.equal(c.matching.cisControls.total,18);assert.equal(c.matching.cisControls.percentage,5.56);
 assert.equal(c.matching.docker.total,12);assert.equal(c.metrics.total,24);
});
test('positive and failing checks change assessment rate without counting their OWASP mappings twice',()=>{
 const targets=[{id:1,project_id:1,resource:'Dockerfile'}];
 const checks=['4.1','4.6'].map((control_id,i)=>({project_id:1,target_id:1,benchmark_id:docker.id,benchmark_version:docker.version,control_id,status:i?'FAIL':'PASS',evidence:{rule:i?'DS0026':'DS0002',resource:'Dockerfile',scanId:'1',sourceTimestamp:'2026-01-01T00:00:00Z'}}));
 const f=finding('IAC',{identity:'DS0026',references:[],classification:'MISCONFIGURATION',location:'Dockerfile:1'});
 const c=buildCompliance([f],p,targets,checks);assert.equal(c.overall.PASS,1);assert.equal(c.overall.FAIL,1);assert.equal(c.overall.passRate,50);assert.equal(c.overall.coverage,16.67);
 assert.equal(c.owaspMetrics.FAIL,1);assert.equal(c.matching.docker.matched,1);
 assert.equal(c.matching.cisControls.matched,1);assert.equal(c.cisControls.find(x=>x.id==='CIS-4').status,'CONTROL_GAP');
});
