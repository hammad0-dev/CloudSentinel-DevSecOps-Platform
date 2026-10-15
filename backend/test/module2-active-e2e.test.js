'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const paths=['../db','../services/deployment','axios','../services/orchestrator','../services/module2ActiveDast'].map(p=>require.resolve(p));
function mock(id,exports){require.cache[id]={id,filename:id,loaded:true,exports,children:[],paths:[]};}
test('genuine Module 2 ordering and Active terminal persistence under mocked scanner execution',async()=>{
  const saved=paths.map(p=>require.cache[p]);const old={flag:process.env.DAST_ACTIVE_ENABLED,node:process.env.NODE_ENV,jwt:process.env.JWT_SECRET};
  process.env.NODE_ENV='test';process.env.JWT_SECRET='offline-pipeline-secret';
  const actualService=require(paths[4]);
  try {
    for(const scenario of ['disabled','complete','cancelled','containment','cleanup','project17']){
      const real=actualService;const calls=[];let scanCalls=0,record;
      const projectId=scenario==='project17'?17:42;
      const pool={query:async(sql,args)=>{calls.push(sql);if(sql.includes('FROM scan_history sh'))return {rows:[{total_issues:0,critical:0,high:0,medium:0,low:0,persisted_total:0,distinct_total:0,persisted_critical:0,persisted_high:0,persisted_medium:0,persisted_low:0}]};if(sql.includes('SELECT critical'))return {rows:[{critical:0}]};if(sql.includes('deployment_history'))return {rows:[{id:1}]};if(sql.startsWith('INSERT INTO active_dast_executions'))record=JSON.parse(args[4]);return {rows:[],rowCount:1};}};
      const runtime={async provision(){return {};},async verify(){if(scenario==='containment')throw Error('ownership');},async scan(){scanCalls++;if(scenario==='cancelled')throw Object.assign(Error('cancelled'),{code:'ACTIVE_CANCELLED'});return {completed:true,exitCode:0,report:{site:[{alerts:[{pluginid:'40012',riskcode:3,cweid:79,name:'Reflected XSS',instances:[{uri:'http://fixture.test:18080/test/xss?q=x'}]},{pluginid:'40018',riskcode:3,cweid:89,name:'SQL Injection',instances:[{uri:'http://fixture.test:18080/test/sqli?id=1'}]}]}]}};},async cleanup(){return scenario==='cleanup'?{cleaned:false,residual:['owned']}:{cleaned:true,residual:[]};}};
      mock(paths[0],pool);mock(paths[1],{deployProject:async()=>{calls.push('deploy');return {stagingUrl:'http://staging.invalid'};}});mock(paths[2],{post:async url=>{calls.push(url);return {data:{}};}});
      mock(paths[4],{...real,execute:async options=>{
        if(projectId===17)return real.execute({...options,authorization:{}},runtime);
        const authorization=real.issueAuthorization({...options,expiresAt:Date.now()+60000,fixtureKind:'cloudsentinel-vulnerable-v1',hostname:'fixture.test',ip:'172.30.1.2',port:18080,scheme:'http',routes:real.ROUTES,zapImageDigest:'sha256:'+'a'.repeat(64)},options);
        return real.execute({...options,authorization},runtime);
      }});
      delete require.cache[paths[3]];process.env.DAST_ACTIVE_ENABLED=scenario==='disabled'?'false':'true';
      await require(paths[3]).runPipeline(100,projectId,7);
      const endpoints=calls.filter(s=>s.startsWith('http://'));assert.deepEqual(endpoints.map(s=>s.split('/api/')[1].split('/scan/')[0]),['sast','dependencies','iac','dast']);
      assert.ok(calls.indexOf('deploy')<calls.findIndex(s=>s.includes('/api/dast/')));
      if(scenario==='disabled'){assert.equal(record,undefined);assert.equal(scanCalls,0);}
      else {assert.ok(record);assert.equal(record.status,{complete:'COMPLETED_WITH_FINDINGS',cancelled:'CANCELLED',containment:'FAILED',cleanup:'CLEANUP_FAILED',project17:'BLOCKED'}[scenario]);
        if(scenario==='complete'){assert.deepEqual(record.findings.map(f=>f.classification),['XSS','SQLI']);assert.equal(record.summary.total,2);}else assert.ok(calls.some(s=>s.includes("status='STAGE_FAILED'")));
        if(['project17','containment'].includes(scenario))assert.equal(scanCalls,0);
      }
    }
  } finally {paths.forEach((p,i)=>{if(saved[i])require.cache[p]=saved[i];else delete require.cache[p];});for(const [key,env] of [['flag','DAST_ACTIVE_ENABLED'],['node','NODE_ENV'],['jwt','JWT_SECRET']]){if(old[key]===undefined)delete process.env[env];else process.env[env]=old[key];}}
});
