const test=require('node:test'); const assert=require('node:assert/strict'); const {validate,runAcceptance}=require('../scripts/dast-acceptance');
const input={projectId:'p1',executionId:'e1',scanId:'s1',target:{hostname:'fixture.test',ip:'192.0.2.10',port:8080}};
test('runner validates and invokes lifecycle with cleanup',async()=>{const calls=[];const lifecycle={async provision(v){calls.push(['provision',v]);return {state:'READY'};},async cleanup(id){calls.push(['cleanup',id]);return {state:'CLEANED',residual:[]};}};const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';const r=await runAcceptance(input,lifecycle);if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;assert.equal(r.state,'READY');assert.deepEqual(calls.map(x=>x[0]),['provision','cleanup']);});
test('runner rejects unsafe configuration before lifecycle',()=>{assert.throws(()=>validate({projectId:'p;rm',executionId:'e',scanId:'s',target:{hostname:'x',port:1}}),/unsafe/);});
test('native opt-in supports full and diagnostic acceptance with strict boolean validation',()=>{
  assert.throws(()=>validate({...input,nativeConnect:'true',mode:'connect-diagnostic'}),/invalid native/);
  assert.doesNotThrow(()=>validate({...input,nativeConnect:true}));
  assert.doesNotThrow(()=>validate({...input,nativeConnect:true,mode:'full'}));
  assert.doesNotThrow(()=>validate({...input,nativeConnect:true,mode:'connect-diagnostic'}));
  assert.doesNotThrow(()=>validate({...input,nativeConnect:false}));
});
test('runner rejects unknown modes and diagnostic full-containment results, with cleanup',async()=>{
  assert.throws(()=>validate({...input,mode:'connect-only-typo'}),/unsupported acceptance mode/);
  const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';let cleaned=false;
  try {await assert.rejects(runAcceptance({...input,mode:'connect-diagnostic'},{async provision(){return {state:'READY'};},async cleanup(){cleaned=true;return {state:'CLEANED',residual:[]};}}),{code:'INVALID_DIAGNOSTIC'});assert.equal(cleaned,true);}
  finally {if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
});
test('runner cleans up after provisioning failure',async()=>{let cleaned=false;const lifecycle={async provision(){throw new Error('fail');},async cleanup(){cleaned=true;}};const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';await assert.rejects(runAcceptance(input,lifecycle));if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;assert.equal(cleaned,true);});

test('production graph constructs without runtime commands or placeholder executors',()=>{
  const {createLifecycle}=require('../scripts/dast-acceptance');
  const lifecycle=createLifecycle();
  assert.equal(lifecycle.observation.probeExecutor,undefined);
  assert.equal(typeof lifecycle.networks.observe,'function');
  assert.equal(lifecycle.client,require('../services/dastAcceptanceClient'));
});
test('allocation observation collects native inventory and host route evidence',async()=>{
  const {observeEnvironment}=require('../scripts/dast-acceptance');const calls=[];
  const result=await observeEnvironment(async(bin,args)=>{calls.push([bin,...args]);return {stdout:bin==='ip'?JSON.stringify([{dst:'default'},{dst:'192.168.240.0/20'}]):args.includes('ls')?'abcdef123456\n':JSON.stringify([{Id:'abcdef123456'+'0'.repeat(52),Name:'bridge',IPAM:{Config:[{Subnet:'172.17.0.0/16'}]}}])};});
  assert.deepEqual(result,{usedSubnets:['172.17.0.0/16'],hostRoutes:['192.168.240.0/20'],existingNames:['bridge'],complete:true});
  assert.ok(calls.every(c=>!c.includes('create')&&!c.includes('run')));
});
test('runner reports residual cleanup as failure',async()=>{
  const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';
  try {await assert.rejects(runAcceptance(input,{async provision(){return {state:'READY'};},async cleanup(){return {residual:[{id:'owned'}]};}}),{code:'CLEANUP_FAILED'});}
  finally {if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
});
test('runner rejects missing cleanup confirmation instead of returning READY',async()=>{
  const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';
  try {await assert.rejects(runAcceptance(input,{async provision(){return {state:'READY'};},async cleanup(){}}),e=>e.code==='CLEANUP_FAILED'&&e.cleanup.residual[0].error==='CLEANUP_UNVERIFIED');}
  finally {if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
});
test('runner preserves inconclusive evidence alongside cleanup failures and sanitizes output',async()=>{
  const {failureReport}=require('../scripts/dast-acceptance');const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';
  try {
    await assert.rejects(runAcceptance(input,{async provision(){throw Object.assign(new Error('password=abc'),{code:'PROBE_INCONCLUSIVE',probes:[{name:'direct',actual:'INCONCLUSIVE',expected:'DENY',complete:false,exitCode:1}]});},async cleanup(){throw Object.assign(new Error('token=abc'),{code:'CLEANUP_FAILED'});}}),e=>{
      const report=failureReport(e);assert.equal(report.code,'PROBE_INCONCLUSIVE');assert.equal(report.probes[0].actual,'INCONCLUSIVE');assert.equal(report.cleanup.cleaned,false);assert.ok(!JSON.stringify(report).includes('abc'));return true;
    });
  } finally {if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
});
test('TCP diagnostic accepts explicit mode but cannot return full READY and always cleans',async()=>{
  assert.doesNotThrow(()=>validate({...input,mode:'tcp-diagnostic'}));
  const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';let cleaned=false;
  try {await assert.rejects(runAcceptance({...input,mode:'tcp-diagnostic'},{async provision(){return {state:'READY',fullContainment:true};},async cleanup(){cleaned=true;return {state:'CLEANED',residual:[]};}}),{code:'INVALID_DIAGNOSTIC'});assert.equal(cleaned,true);}
  finally {if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
});
