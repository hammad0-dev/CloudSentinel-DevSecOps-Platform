'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs/promises'),path=require('path');
const policy=require('../services/activeSquidPolicy');
const target={hostname:'fixture.test',ip:'172.30.26.2',port:18080};
test('Active profile stages exact path/origin policy while baseline policy remains unchanged',async()=>{
  const base=require('../services/squidPolicy'),normal=base.canonicalPolicy(target);assert.ok(!normal.includes('urlpath_regex'));
  const staged=await policy.stagePolicy({scanId:'active-policy-test',target});
  try {assert.equal((await policy.verifyStagedPolicy(staged)).verified,true);const bytes=staged.policy;
    assert.ok(bytes.includes('acl protocol proto HTTP'));assert.ok(bytes.includes('acl methods method GET POST'));assert.ok(bytes.includes('http_access deny connect'));assert.ok(bytes.includes('http_access deny all'));
    const expression=bytes.split('\n').find(l=>l.startsWith('acl paths ')).slice('acl paths urlpath_regex '.length);const re=new RegExp(expression);
    for(const value of ['/test/sqli','/test/xss?q=%3Cscript%3E'])assert.equal(re.test(value),true);
    for(const value of ['/health','/admin','/test/xss/escape','/test/xss%2fescape','/test/xss#fragment','/redirect/host'])assert.equal(re.test(value),false);
    await fs.writeFile(staged.filePath,bytes.replace('http_access deny all','http_access allow all'));
    await assert.rejects(policy.verifyStagedPolicy(staged),{code:'POLICY_TAMPERED'});
  } finally {await policy.cleanupPolicy(staged);}
  for(const changed of [{hostname:'169.254.169.254'},{ip:'8.8.8.8'},{port:31646}])assert.throws(()=>base.activePolicy({...target,...changed}));
});
test('fixture recipe requires explicit pinned base and nonroot standard-library execution',async()=>{
  const root=path.join(__dirname,'../fixtures/active-vulnerable'),recipe=await fs.readFile(path.join(root,'Dockerfile'),'utf8');
  assert.match(recipe,/ARG PYTHON_BASE\nFROM \$\{PYTHON_BASE\}/);assert.match(recipe,/USER 10001:10001/);assert.match(recipe,/HEALTHCHECK/);assert.ok(recipe.includes('sha256:'));assert.ok(!/pip install|apt-get|apk add|EXPOSE/i.test(recipe));
  const app=await fs.readFile(path.join(root,'app.py'),'utf8');assert.ok(app.includes('TemporaryDirectory'));assert.ok(app.includes('dir="/tmp"'));assert.ok(app.includes('"/health"'));
});
test('unverified API, rate, completion, cancellation and export capabilities block before execution',()=>{
  const {capabilities}=require('../services/activeZapRuntime');const catalog=require('../config/active-runtime-artifacts.json');assert.throws(()=>capabilities(catalog),{code:'ACTIVE_POLICY_CAPABILITIES_BLOCKED'});
  const source=['activeZapRuntime','activeDastCommissioning'].map(name=>require('fs').readFileSync(require.resolve('../services/'+name),'utf8')).join('\n');for(const field of ['apiBinding','apiAuthentication','spiderRateLimited','jobCompletionVerified','timeoutVerified','cancellationVerified','exportFormat','evidenceSha256'])assert.ok(source.includes(field));
});
test('unapplied schemas enforce execution/project/target association and cleanup failure records',async()=>{
  const a=await fs.readFile(path.join(__dirname,'../migrations/012_active_dast_execution_records.sql'),'utf8'),b=await fs.readFile(path.join(__dirname,'../migrations/013_active_dast_grants.sql'),'utf8');
  assert.ok(a.includes('CLEANUP_FAILED'));assert.ok(a.includes('result JSONB NOT NULL'));
  for(const schema of [a,b])assert.ok(schema.includes('FOREIGN KEY(pipeline_execution_id,project_id) REFERENCES pipeline_executions(id,project_id)'));
  assert.ok(b.includes('FOREIGN KEY(target_id,project_id,pipeline_execution_id)'));assert.ok(b.includes('UNIQUE(project_id,pipeline_execution_id)'));assert.ok(b.includes('consumed_at TIMESTAMPTZ'));
});
