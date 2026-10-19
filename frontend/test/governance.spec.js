// Explicit browser-only fixtures; never imported by application code or persisted.
import {test,expect} from '@playwright/test';
import {readFile} from 'node:fs/promises';
const fixture={id:'1',project_id:1,project_name:'TEST FIXTURE Alpha',source:'SAST',identity:'CWE-89',title:'TEST FIXTURE Injection',severity:'HIGH',status:'OPEN',classification:'VULNERABILITY',location:'app.js:12',description:'Fixture evidence',remediation:'Use parameterized queries',references_json:['CWE-89'],mappings:[{framework:'OWASP Top 10:2021',id:'A03:2021',name:'Injection',basis:'Explicit CWE-89',reference:'https://top10.owasp.org/2021/'}],first_seen:'2026-01-01T12:00:00Z',last_seen:'2026-01-02T12:00:00Z',scan_id:'1',observed_at:'2026-01-02T12:00:00Z'};
const summary={total:26,bySeverity:[{name:'HIGH',value:26}],byStatus:[{name:'OPEN',value:26},{name:'RESOLVED',value:0}],byProject:[{name:'TEST FIXTURE Alpha',value:26}],bySource:[{name:'SAST',value:26}],score:{value:12,assessedSlots:1,totalSlots:5,methodology:'TEST FIXTURE deterministic score'},trend:[{day:'2026-01-01',value:1},{day:'2026-01-02',value:2}],trendLabel:'Unique findings observed per UTC day',recentScans:[],priority:[fixture],compliance:{version:'OWASP Top 10:2021',owasp:[{id:'A03:2021',name:'Injection',findings:26}],cis:[{id:'4.1',name:'Non-root user',assessment:'NOT_ASSESSED',findings:0,remediation:'Set USER'}],cisSummary:{FAILED:0,NOT_ASSESSED:1,PASSED:0,NOT_APPLICABLE:0},unmapped:0,limitations:'Registered subset; no certification.'}};
// Enrich the existing browser fixture with the canonical FE-3 API contract.
Object.assign(summary.compliance,{
 matching:{owasp:{matched:1,total:10,percentage:10},cisControls:{matched:1,total:18,percentage:5.56}},overall:{PASS:1,FAIL:1,assessed:2,applicable:12,passRate:50,coverage:16.67,methodology:'TEST FIXTURE combined registered slot calculation'},owaspMetrics:{PASS:0,FAIL:2,NOT_ASSESSED:8,passRate:0,coverage:20},cisControls:[{id:'CIS-16',name:'Application Software Security',findings:26,bySeverity:{HIGH:26},unresolved:26,status:'CONTROL_GAP'}],availableOwaspVersions:['2021','2025'],metrics:{PASS:1,FAIL:1,NOT_ASSESSED:10,NOT_APPLICABLE:0,ERROR:0,assessed:2,applicable:12,total:12,passRate:50,coverage:16.67,methodology:'Pass rate and coverage use separate denominators; internal subset metrics.'},
 benchmarks:[{id:'docker-cis-1.6.0',name:'CIS Docker Benchmark',version:'1.6.0',supportedControls:4,registeredControls:12,scope:'Static Dockerfile checks only.',reference:'https://github.com/aquasecurity/trivy-checks/'}],
 byProject:[{id:1,name:'TEST FIXTURE Alpha',FAIL:1}],gaps:[],
});
Object.assign(summary.compliance.cis[0],{status:'PASS',supportStatus:'SUPPORTED_STATIC_CHECK',summary:'Check declared user',assessedAt:fixture.observed_at,projects:[{id:1,name:'TEST FIXTURE Alpha',status:'PASS'}]});
Object.assign(summary.compliance.owasp[0],{bySeverity:{HIGH:26},projects:[{id:1,name:'TEST FIXTURE Alpha'}]});
async function setup(page,{fail=false,delay=0}={}) {
 const seen=[];let failure=fail;
 await page.addInitScript(()=>localStorage.setItem('cloudsentinel_token','browser-fixture-only'));
 await page.route('**/api/**',async route=>{
  const url=new URL(route.request().url()),p=url.pathname;seen.push({path:p,query:url.search,method:route.request().method()});
  const json=body=>route.fulfill({json:body});
  if(p==='/api/auth/me')return json({user:{id:1,fullName:'Fixture user'}});
  if(p==='/api/projects')return json({projects:[{id:1,name:'TEST FIXTURE Alpha'},{id:3,name:'TEST FIXTURE Beta'}]});
  if(p.endsWith('/sync'))return json({sources:[],importedObservations:0});
  if(p.includes('/compliance/controls/'))return json({control:{id:'4.1',expectedEvidence:'Explicit DS0002 configuration result'},current:[{project_id:1,project_name:'TEST FIXTURE Alpha',status:'PASS',resources:[{resource:'Dockerfile',status:'PASS'}]}],history:[{id:1,project_name:'TEST FIXTURE Alpha',resource:'Dockerfile',status:'PASS',scan_id:'7',scanned_at:fixture.observed_at,evidence:{rule:'DS0002',sourceTimestamp:fixture.observed_at}}],total:1,page:1,pageSize:10});
  if(p.endsWith('/summary')){if(delay)await new Promise(r=>setTimeout(r,delay));if(failure){failure=false;return route.fulfill({status:500,json:{error:'TEST FIXTURE database unavailable'}});}const view=structuredClone(summary);if(url.searchParams.get('owaspVersion')==='2025'){view.compliance.version='OWASP Top 10:2025';view.compliance.owasp[0].id='A05:2025';}return json(url.searchParams.get('project')==='3'?{...summary,total:0,bySeverity:[],priority:[],trend:[],byProject:[],bySource:[],score:{...summary.score,value:null}}:view);}
  if(p.includes('/export/'))return route.fulfill({contentType:p.endsWith('csv')?'text/csv':'application/pdf',headers:{'Content-Disposition':'attachment; filename="fixture.pdf"'},body:p.endsWith('csv')?'id,title\n1,Fixture':'%PDF-1.7\nTEST FIXTURE'});
  if(p.endsWith('/status'))return json({id:1,status:'RESOLVED'});
  if(p.endsWith('/findings/1'))return json({finding:fixture,observations:[{source:'SAST',scan_id:1,observed_at:fixture.observed_at,details_complete:true,evidence:{rule:'CWE-89'}}],history:[]});
  if(p.endsWith('/findings'))return json({findings:url.searchParams.get('project')==='3'?[]:[{...fixture,title:url.searchParams.get('page')==='2'?'TEST FIXTURE Page two':fixture.title}],total:26,page:Number(url.searchParams.get('page')||1),pageSize:25});
  return json({});
 });return seen;
}
test('dashboard renders stored metrics, charts, loading and project/date filters',async({page})=>{
 const seen=await setup(page,{delay:250});await page.goto('/dashboard');await expect(page.getByRole('status')).toBeVisible();await expect(page.getByRole('heading',{name:'Severity distribution'})).toBeVisible();await expect(page.locator('.recharts-wrapper')).toHaveCount(7);
 await page.getByLabel('Project',{exact:true}).selectOption('3');await expect(page.getByText('Not assessed',{exact:true})).toBeVisible();await page.getByLabel('from',{exact:true}).fill('2026-01-01');await expect.poll(()=>seen.some(r=>r.query.includes('project=3')&&r.query.includes('from=2026-01-01'))).toBeTruthy();await expect(page.getByText('No findings match this selection.',{exact:false})).toBeVisible();
});
test('API failure presents retry and successful recovery',async({page})=>{await setup(page,{fail:true});await page.goto('/dashboard');await expect(page.getByRole('alert')).toContainText('database unavailable');await page.getByRole('button',{name:'Retry',exact:true}).click();await expect(page.getByRole('heading',{name:'Severity distribution'})).toBeVisible();});
test('findings support search, sort, paging, scanner/status filters and reviewed details',async({page})=>{
 const seen=await setup(page);await page.goto('/findings');await page.getByRole('button',{name:'Next',exact:true}).click();await expect(page.getByText('TEST FIXTURE Page two')).toBeVisible();
 await page.getByLabel('Search findings').fill('CWE-89');await page.getByLabel('source',{exact:true}).selectOption('SAST');await page.getByLabel('status',{exact:true}).selectOption('OPEN');await page.getByLabel('Sort',{exact:true}).selectOption('oldest');await expect.poll(()=>seen.some(r=>r.query.includes('search=CWE-89')&&r.query.includes('sort=oldest'))).toBeTruthy();
 await page.getByRole('button',{name:'View details',exact:true}).click();const dialog=page.getByRole('dialog');await expect(dialog).toContainText('Use parameterized queries');await expect(dialog).toContainText('Explicit CWE-89');await page.getByLabel('Finding status').selectOption('RESOLVED');await page.getByLabel('Review reason').fill('Validated local fixture fix');await page.getByRole('button',{name:'Save reviewed status'}).click();await expect(dialog).toHaveCount(0);expect(seen.some(r=>r.method==='PATCH')).toBeTruthy();
});
test('compliance layout and PDF/JSON exports preserve project scope',async({page})=>{
 const seen=await setup(page);await page.goto('/compliance?project=1');
 await expect(page.getByRole('heading',{name:'Compliance Dashboard',exact:true})).toBeVisible();
 await expect(page.getByRole('heading',{name:'Mapped OWASP Controls'})).toBeVisible();
 await expect(page.getByRole('heading',{name:'Mapped CIS Controls'})).toBeVisible();
 for(const name of ['Export Readable Report','Export JSON']){const wait=page.waitForEvent('download');await page.getByRole('button',{name,exact:true}).click();const download=await wait;expect(download.suggestedFilename()).toContain('cloudsentinel-compliance');if(name==='Export JSON'){const exported=JSON.parse(await readFile(await download.path(),'utf8'));expect(exported.compliance.overall).toEqual(summary.compliance.overall);expect(exported.compliance.cisControls).toEqual(summary.compliance.cisControls);}}
 expect(seen.filter(r=>r.path.includes('/export/')).every(r=>r.query.includes('project=1'))).toBeTruthy();
 await page.getByLabel('Project',{exact:true}).selectOption('3');
 await expect.poll(()=>seen.some(r=>r.path.endsWith('/summary')&&r.query.includes('project=3'))).toBeTruthy();
});
test('mobile layout contains charts and tables within viewport and details close with Escape',async({page})=>{
 await page.setViewportSize({width:390,height:844});await setup(page);await page.goto('/findings');await expect(page.getByRole('heading',{name:'Vulnerability Findings',exact:true})).toBeVisible();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBeTruthy();await page.getByRole('button',{name:'View details',exact:true}).click();await expect(page.getByRole('dialog')).toBeVisible();await page.keyboard.press('Escape');await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('compliance version selection updates mapped controls',async({page})=>{
 const seen=await setup(page);await page.goto('/compliance?project=1');
 await page.getByText('Pipeline evidence and assessment details',{exact:true}).click();
 await page.getByLabel('OWASP version',{exact:true}).selectOption('2025');
 await expect(page.getByRole('heading',{name:'OWASP Top 10:2025',exact:true})).toBeVisible();
 await expect(page.getByRole('cell',{name:'A05:2025',exact:true})).toBeVisible();
 await expect.poll(()=>seen.some(r=>r.query.includes('owaspVersion=2025')&&r.query.includes('project=1'))).toBeTruthy();
});
test('compliance renders backend pass rate and coverage without frontend scoring',async({page})=>{
 await setup(page);await page.goto('/compliance?project=1');
 await expect(page.getByText('10%',{exact:true})).toBeVisible();await expect(page.getByText('5.56%',{exact:true})).toBeVisible();
 await expect(page.getByText('50%',{exact:true})).toBeVisible();
 await expect(page.getByText('Sources:',{exact:false})).toContainText('SAST 26 · Dependencies 0 · IaC 0 · Image 0 · DAST 0 · Active DAST 0');
 await expect(page.getByText('Assessed controls:',{exact:false})).toContainText('Coverage: 16.67%');
 await expect(page.getByRole('heading',{name:'Mapped CIS Controls'})).toBeVisible();
 await page.getByText('Pipeline evidence and assessment details',{exact:true}).click();
 await expect(page.getByText('Missing scans and zero findings do not establish compliance.',{exact:false})).toBeVisible();
});
test('compliance load errors are visible and retryable on mobile',async({page})=>{
 await page.setViewportSize({width:390,height:844});await setup(page,{fail:true});await page.goto('/compliance?project=1');
 await expect(page.getByRole('alert')).toContainText('database unavailable');
 await page.getByRole('button',{name:'Retry',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Mapped OWASP Controls'})).toBeVisible();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBeTruthy();
});

test('missing assessments render Not Assessed rather than a manufactured percentage',async({page})=>{
 await setup(page);await page.route('**/api/governance/summary?**',route=>{const view=structuredClone(summary);Object.assign(view.compliance.metrics,{PASS:0,FAIL:0,assessed:0,passRate:null,coverage:0,NOT_ASSESSED:12});Object.assign(view.compliance.owaspMetrics,{passRate:null});Object.assign(view.compliance.overall,{PASS:0,FAIL:0,assessed:0,passRate:null,coverage:0});return route.fulfill({json:view});});
 await page.goto('/compliance?project=1');await expect(page.getByText('Not assessed',{exact:true})).toHaveCount(1);
 await expect(page.getByText('Docker assessment pass rate',{exact:false})).toContainText('Failed controls: 0');
});
