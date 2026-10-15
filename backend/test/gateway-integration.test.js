"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {SecureGatewayLifecycle}=require("../services/dastGateway");
const {RuntimeObservation}=require("../services/runtimeObservation");
const {mockDocker}=require("./helpers/runtimeDocker");
function deps() {
  const d=mockDocker();let cleaned=false;
  const networks={async create(){return {networks:d.refs};},async cleanup(){cleaned=true;return {cleaned:true,residual:[]};}};
  const policyService={async stagePolicy(){return {filePath:"/tmp/policy",containerPath:"/etc/squid/cloudsentinel/squid.conf",policyDigest:"sha256:"+d.state.digest};},async verifyStagedPolicy(){},async cleanupPolicy(){}};
  const fixture={async provision(a,o){return {id:"f".repeat(64),ip:"172.30.26.2",owner:"cloudsentinel-s1"};},async cleanup(){return {cleaned:true,residual:[]};}};
  return {...d,networks,fixture,policyService,observation:new RuntimeObservation({adapter:d.adapter}),isCleaned:()=>cleaned};
}
const input={projectId:"17",executionId:"accept",scanId:"s1",target:{hostname:"fixture.test",port:8080}};
test('full native CONNECT preserves every probe and fails closed with lifecycle cleanup',async(t)=>{
  const artifacts=require('../services/nativeConnectArtifact'),fs=require('fs/promises');
  const stage=artifacts.stage;let staged;
  t.mock.method(artifacts,'stage',async scan=>{staged=await stage(scan);return staged;});
  const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';
  try {
    for(const scenario of ['valid','wrong-peer','missing','tunnel','later-failure','public-failure','metadata-failure','redirect-failure']) {
      const d=deps(),l=new SecureGatewayLifecycle(d);let evidence;
      const collect=d.observation.collect.bind(d.observation);
      d.observation.collect=async args=>{evidence=await collect(args);return evidence;};
      d.state.probe=(a,cb)=>{
        if(a[2]==='/opt/cloudsentinel/connect-peer') {
          const value={schemaVersion:1,peerIp:scenario==='wrong-peer'?'172.30.25.9':'172.30.25.3',peerPort:3128,requestedAuthority:'fixture.test:8080',responseStatus:403,connected:true,squidServer:true,accessDenied:true,headersValid:true,complete:true,error:null};
          if(scenario==='missing')delete value.peerIp;
          if(scenario==='tunnel')Object.assign(value,{responseStatus:200,accessDenied:false,complete:false,error:'UNEXPECTED_TUNNEL'});
          return cb(scenario==='tunnel'?Object.assign(new Error('tunnel'),{code:1}):null,JSON.stringify(value),'');
        }
        if(a[2]==='nc')return cb(Object.assign(new Error('unreachable'),{code:1}),'',scenario==='later-failure'?'nc: timed out':'nc: network is unreachable');
        assert.ok(!a.at(-1).startsWith('https:'),'native replaces only CONNECT');
        if((scenario==='public-failure'&&a.at(-1)==='http://198.51.100.9:80/health') || (scenario==='metadata-failure'&&a.at(-1)==='http://169.254.169.254:80/health') || (scenario==='redirect-failure'&&a.at(-1)==='http://fixture.test:8080/redirect/same'))return cb(Object.assign(new Error('timeout'),{code:28}),'000 000 ','Operation timed out');
        if (['http://198.51.100.9:80/health','http://169.254.169.254:80/health'].includes(a.at(-1))) return cb(null,'403 000 172.30.25.3','HTTP/1.1 403 Forbidden\r\nServer: squid/6.14\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\n\r\n');
        if(a.at(-1)==='http://fixture.test:8080/redirect/host')return cb(null,'403 000 172.30.25.3 http://unauthorized.test:8080/health 1','HTTP/1.1 302 Found\r\nLocation: http://unauthorized.test:8080/health\r\n\r\nHTTP/1.1 403 Forbidden\r\nServer: squid/6.14\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\n\r\n');
        if(a.at(-1)==='http://fixture.test:8080/redirect/same')return cb(null,'200 000 172.30.25.3 http://fixture.test:8080/health 1','HTTP/1.1 302 Found\r\nLocation: http://fixture.test:8080/health\r\n\r\nHTTP/1.1 200 OK\r\n\r\n');
        const positive=a.at(-1)==='http://fixture.test:8080/health';
        cb(null,`${positive?200:403} 000 172.30.25.3`,positive?'HTTP/1.1 200 OK':'HTTP/1.1 403 Forbidden\r\nX-Squid-Error: ERR_ACCESS_DENIED 0');
      };
      await assert.rejects(l.provision({...input,mode:'full',nativeConnect:true}),e=>{
        if(scenario==='valid')return e.code==='GATEWAY_EVIDENCE_INVALID'; // mocked evidence never grants READY
        return e.probe?.name===({'later-failure':'negative-direct-bypass','public-failure':'negative-public','metadata-failure':'negative-metadata','redirect-failure':'positive-same-redirect'}[scenario]||'negative-connect') && ['PROBE_INCONCLUSIVE','CONNECTIVITY_FAILED'].includes(e.code);
      });
      assert.equal(d.calls.filter(a=>a[2]==='/opt/cloudsentinel/connect-peer').length,1);
      assert.equal(d.calls.some(a=>a[2]==='nc'),['valid','later-failure','public-failure','metadata-failure','redirect-failure'].includes(scenario));
      if(scenario==='valid')assert.deepEqual(evidence.probes.map(p=>p.name),['positive-fixture','negative-proxy','negative-connect','negative-direct-bypass','negative-redirect','negative-alternate-host','negative-port','negative-public','negative-metadata','positive-same-redirect','negative-ipv6-bypass']);
      assert.equal(d.isCleaned(),true);assert.equal(l.resources.size,0);
      await assert.rejects(fs.stat(staged.directory),{code:'ENOENT'});
    }
  } finally {if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
});
test("gateway uses allowlisted network connect and verifies names/IDs before probes",async()=>{
  const d=deps(),l=new SecureGatewayLifecycle(d);
  await assert.rejects(l.provision(input),{code:"GATEWAY_EVIDENCE_INVALID"}); // mocks cannot establish real READY
  assert.ok(d.calls.some(a=>a[0]==="network"&&a[1]==="connect"&&a[2]===d.ids.fixture&&a[3]===d.ids.gateway));
  assert.ok(!d.calls.some(a=>a[0]==="connect"));assert.equal(d.isCleaned(),true);
  assert.ok(d.calls.some(a=>a[0]==="exec"&&a[5]==="cloudsentinel-curl"));
  const gatewayRun=d.calls.find(a=>a[0]==='run'&&a.includes(require('../services/dastGateway').IMAGE));
  assert.equal(gatewayRun[gatewayRun.indexOf('--entrypoint')+1],'/usr/sbin/squid');
  assert.equal(gatewayRun[gatewayRun.indexOf(require('../services/dastGateway').IMAGE)+1],'-N');
  assert.ok(gatewayRun.includes('--pull=never'));
});
test("inconclusive TCP evidence propagates through lifecycle and stops later probes",async()=>{
  const d=deps(),l=new SecureGatewayLifecycle(d);
  d.state.probe=(a,cb)=>{
    if(a[2]==='nc')return cb(Object.assign(new Error('timeout'),{code:1}),'','nc: timed out');
    if(a.at(-1).startsWith('https:')){const r=require('./fixtures/connect-denied.json');return cb(Object.assign(new Error('CONNECT'),{code:56}),r.stdout,r.stderr);}
    const positive=a.at(-1)==='http://fixture.test:8080/health';cb(null,`${positive?200:403} 000 172.30.25.3`,positive?'':'X-Squid-Error: ERR_ACCESS_DENIED');
  };
  await assert.rejects(l.provision(input),e=>e.code==='PROBE_INCONCLUSIVE'&&e.probe.actual==='INCONCLUSIVE'&&e.probe.name==='negative-direct-bypass');
  assert.notEqual(l.states.get('s1'),'READY');assert.equal(d.isCleaned(),true);
  assert.ok(!d.calls.some(a=>a.at(-1)==='http://fixture.test:8080/redirect/host'));
});
test("network creation failures retain cleanup responsibility before provisioning returns",async()=>{
  const d=deps();let cleaned=0;d.networks.create=async()=>{throw Object.assign(new Error('network create failed'),{code:'NETWORK_FAILED'});};d.networks.cleanup=async()=>{cleaned++;return {cleaned:false,residual:[{id:d.ids.scanner,reason:'BUSY'}]};};
  const l=new SecureGatewayLifecycle(d);await assert.rejects(l.provision(input),e=>e.code==='NETWORK_FAILED'&&e.cleanup.residual.length===1);assert.equal(cleaned,1);assert.equal(l.resources.has('s1'),true);
});
test("cleanup retry retains only residual responsibility and never removes cleaned containers twice",async()=>{
  const d=deps();let count=0;
  d.networks.cleanup=async()=>++count===1?{cleaned:false,residual:[{id:d.ids.scanner,reason:'BUSY'}]}:{cleaned:true,residual:[]};
  const l=new SecureGatewayLifecycle(d);await assert.rejects(l.provision(input),e=>e.cleanup.residual.length===1);
  const before=d.calls.filter(a=>a[0]==='rm').length;
  assert.equal((await l.cleanup('s1')).state,'CLEANED');assert.equal(d.calls.filter(a=>a[0]==='rm').length,before);
});
test("foreign network and unexpected gateway attachments fail before client probes",async()=>{
  for(const mutate of [d=>{d.state.foreign=true;},d=>{d.state.gatewayNetworks.extra={NetworkID:"9".repeat(64)};}]){
    const d=deps();mutate(d);const l=new SecureGatewayLifecycle(d);await assert.rejects(l.provision(input));
    assert.ok(!d.calls.some(a=>a[0]==="exec"&&a[5]==="cloudsentinel-curl"));assert.equal(d.isCleaned(),true);
  }
});
test("gateway cleanup rechecks ownership and preserves residual failures",async()=>{
  const d=deps(),l=new SecureGatewayLifecycle(d);const original=d.adapter.inspect.bind(d.adapter);
  d.adapter.inspect=async(args,kind)=>{const r=await original(args,kind);if(kind==="container"&&args[0]===d.ids.gateway)r.normalized.labels["cloudsentinel.owner"]="foreign";return r;};
  await assert.rejects(l.provision(input),e=>e.code==="OWNERSHIP_MISMATCH"&&e.cleanup.residual.some(r=>r.type==="gateway"));
  assert.ok(!d.calls.some(a=>a[0]==="rm"&&a[1]===d.ids.gateway));
});
test("malformed native routes and inconclusive probes clean exact owned container IDs",async()=>{
  for(const mutate of [d=>{d.state.route="unrecognized route output";},d=>{d.state.probe=(a,cb)=>cb(Object.assign(new Error("DNS failure"),{code:6}),"000 000","Could not resolve host");}]){
    const d=deps();mutate(d);const l=new SecureGatewayLifecycle(d);await assert.rejects(l.provision(input));
    assert.equal(d.isCleaned(),true);
    assert.ok(d.calls.some(a=>a[0]==="rm"&&a[1]===d.ids.client));
    assert.ok(d.calls.some(a=>a[0]==="rm"&&a[1]===d.ids.gateway));
    assert.equal(l.resources.size,0);
  }
});
test('incomplete CONNECT headers stop subsequent probes and clean owned resources',async()=>{
  const d=deps(),l=new SecureGatewayLifecycle(d);
  d.state.probe=(a,cb)=>{
    if(a.at(-1).startsWith('https:'))return cb(Object.assign(new Error('CONNECT'),{code:56}),'000 403 172.30.25.3','curl: (56) CONNECT tunnel failed, response 403');
    const positive=a.at(-1)==='http://fixture.test:8080/health';cb(null,`${positive?200:403} 000 172.30.25.3`,positive?'':'X-Squid-Error: ERR_ACCESS_DENIED');
  };
  await assert.rejects(l.provision(input),e=>e.code==='PROBE_INCONCLUSIVE'&&e.probe.name==='negative-connect'&&e.probe.connectEvidence.responseComplete===false);
  assert.equal(d.isCleaned(),true);assert.equal(l.resources.size,0);
  assert.ok(!d.calls.some(a=>a[2]==='nc'));
});
test('missing CONNECT socket peer stops probes and preserves ownership-safe cleanup',async()=>{
  const d=deps(),l=new SecureGatewayLifecycle(d),r=require('./fixtures/connect-denied.json');
  d.state.probe=(a,cb)=>{
    if(a.at(-1).startsWith('https:'))return cb(Object.assign(new Error('CONNECT'),{code:56}),'000 403 ',r.stderr);
    const positive=a.at(-1)==='http://fixture.test:8080/health';cb(null,`${positive?200:403} 000 172.30.25.3`,positive?'':'X-Squid-Error: ERR_ACCESS_DENIED');
  };
  await assert.rejects(l.provision(input),e=>e.code==='PROBE_INCONCLUSIVE'&&e.probe.connectEvidence.peerEvidenceStatus==='MISSING');
  assert.equal(d.isCleaned(),true);assert.equal(l.resources.size,0);
  assert.ok(d.calls.some(a=>a[0]==='rm'&&a[1]===d.ids.client));
  assert.ok(d.calls.some(a=>a[0]==='rm'&&a[1]===d.ids.gateway));
  assert.ok(!d.calls.some(a=>a[2]==='nc'));
});
test('diagnostic runner shares real lifecycle provisioning and always cleans owned resources',async()=>{
  const {runAcceptance}=require('../scripts/dast-acceptance'),fs=require('fs/promises'),path=require('path');
  const d=deps(),l=new SecureGatewayLifecycle(d),old=process.env.DAST_ACTIVE_ENABLED;
  process.env.DAST_ACTIVE_ENABLED='false';let result;
  try {
    result=await runAcceptance({...input,mode:'connect-diagnostic'},l);
    assert.equal(result.state,'DIAGNOSTIC_COMPLETE');assert.equal(result.fullContainment,false);
    assert.equal(l.states.get('s1'),'CLEANED');assert.equal(l.resources.size,0);assert.equal(d.isCleaned(),true);
    assert.equal(d.calls.filter(a=>a[5]==='cloudsentinel-curl').length,1);
    assert.ok(!d.calls.some(a=>a[2]==='nc'));
  } finally {
    if(result)await fs.rm(path.dirname(result.diagnosticFile),{recursive:true,force:true});
    if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;
  }
});
test('diagnostic file-write errors remove partial files and clean the lifecycle',async(t)=>{
  const {runAcceptance}=require('../scripts/dast-acceptance'),fs=require('fs/promises'),path=require('path');
  const write=fs.writeFile.bind(fs);let failedFile;
  t.mock.method(fs,'writeFile',async(file,...args)=>{if(String(file).includes('cloudsentinel-connect-diagnostic-')){failedFile=file;throw new Error('password=private-value');}return write(file,...args);});
  const d=deps(),l=new SecureGatewayLifecycle(d),old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';
  try {
    await assert.rejects(runAcceptance({...input,mode:'connect-diagnostic'},l),{code:'DIAGNOSTIC_WRITE_FAILED'});
    assert.equal(d.isCleaned(),true);assert.equal(l.resources.size,0);
    await assert.rejects(fs.stat(path.dirname(failedFile)),{code:'ENOENT'});
  } finally {if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
});
test('native opt-in diagnostic delivers only the audited client and cleans staged binary',async(t)=>{
  const {runAcceptance}=require('../scripts/dast-acceptance'),artifacts=require('../services/nativeConnectArtifact'),fs=require('fs/promises'),path=require('path');
  const d=deps(),l=new SecureGatewayLifecycle(d);let staged;const stage=artifacts.stage;
  t.mock.method(artifacts,'stage',async scan=>{staged=await stage(scan);return staged;});
  d.state.probe=(a,cb)=>{assert.equal(a[2],'/opt/cloudsentinel/connect-peer');cb(null,JSON.stringify({schemaVersion:1,peerIp:'172.30.25.3',peerPort:3128,requestedAuthority:'fixture.test:8080',responseStatus:403,connected:true,squidServer:true,accessDenied:true,headersValid:true,complete:true,error:null}),'');};
  const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';let result;
  try {
    result=await runAcceptance({...input,mode:'connect-diagnostic',nativeConnect:true},l);
    assert.equal(result.actual,'DENY');assert.equal(result.fullContainment,false);assert.equal(result.clientImplementation,'native');
    assert.equal(result.nativeEvidence.peerIp,'172.30.25.3');assert.equal(d.isCleaned(),true);assert.equal(l.resources.size,0);
    assert.ok(!d.calls.some(a=>a[5]==='cloudsentinel-curl'||a[2]==='nc'));
    await assert.rejects(fs.stat(staged.directory),{code:'ENOENT'});
  } finally {if(result)await fs.rm(path.dirname(result.diagnosticFile),{recursive:true,force:true});if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
});
test('native opt-in requires the isolated active-disabled process before provisioning',async()=>{
  const d=deps(),l=new SecureGatewayLifecycle(d);
  const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='true';
  try {await assert.rejects(l.provision({...input,nativeConnect:true}),{code:'INVALID_MODE'});}
  finally {if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
  assert.equal(d.calls.length,0);
});
test('partial native provisioning failures remove only their staged artifacts',async(t)=>{
  const artifacts=require('../services/nativeConnectArtifact'),fs=require('fs/promises');
  const stage=artifacts.stage;let staged;t.mock.method(artifacts,'stage',async scan=>{staged=await stage(scan);return staged;});
  const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';
  try {
    for(const point of ['network','mount']) {
      const d=deps(),l=new SecureGatewayLifecycle(d);
      if(point==='network')d.networks.create=async()=>{throw Object.assign(new Error('mock create failed'),{code:'NETWORK_FAILED'});};
      else {const inspect=d.adapter.inspect.bind(d.adapter);d.adapter.inspect=async(args,kind)=>{const r=await inspect(args,kind);if(kind==='container'&&args[0]===d.ids.client)r.normalized.mounts[0].RW=true;return r;};}
      await assert.rejects(l.provision({...input,mode:'connect-diagnostic',nativeConnect:true}));
      assert.equal(d.isCleaned(),true);await assert.rejects(fs.stat(staged.directory),{code:'ENOENT'});
    }
  } finally {if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
});
test('client removal failure retains mounted native artifact until ownership-verified cleanup succeeds',async(t)=>{
  const artifacts=require('../services/nativeConnectArtifact'),fs=require('fs/promises');
  const stage=artifacts.stage;let staged;t.mock.method(artifacts,'stage',async scan=>{staged=await stage(scan);return staged;});
  const d=deps(),l=new SecureGatewayLifecycle(d),run=d.adapter.run.bind(d.adapter);let busy=true;
  d.adapter.run=async args=>{if(busy&&args[0]==='rm'&&args[1]===d.ids.client)throw Object.assign(new Error('mock busy'),{code:'DOCKER_COMMAND_FAILED'});return run(args);};
  d.state.probe=(a,cb)=>cb(null,'invalid native JSON','');
  const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';let result;
  try {
    result=await l.provision({...input,mode:'connect-diagnostic',nativeConnect:true});
    const residual=await l.cleanup('s1');assert.ok(residual.residual.some(r=>r.type==='native-artifact'&&r.error==='CLIENT_STILL_PRESENT'));
    assert.ok((await fs.stat(staged.directory)).isDirectory());
    busy=false;assert.equal((await l.cleanup('s1')).state,'CLEANED');await assert.rejects(fs.stat(staged.directory),{code:'ENOENT'});
  } finally {
    busy=false;await l.cleanup('s1');if(result)await fs.rm(require('path').dirname(result.diagnosticFile),{recursive:true,force:true});
    if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;
  }
});
test('inconclusive TCP keeps private diagnostics while lifecycle-owned resources are cleaned',async()=>{
  const d=deps(),l=new SecureGatewayLifecycle(d),fs=require('fs/promises'),path=require('path');let file;
  d.state.probe=(a,cb)=>{
    if(a[2]==='nc')return cb(Object.assign(new Error('failed'),{code:1}),'','');
    if(a.at(-1).startsWith('https:')){const r=require('./fixtures/connect-denied.json');return cb(Object.assign(new Error('CONNECT'),{code:56}),r.stdout,r.stderr);}
    const positive=a.at(-1)==='http://fixture.test:8080/health';cb(null,`${positive?200:403} 000 172.30.25.3`,positive?'':'X-Squid-Error: ERR_ACCESS_DENIED');
  };
  try {
    await assert.rejects(l.provision(input),error=>{
      const report=require('../scripts/dast-acceptance').failureReport(error);file=report.diagnosticFile;
      assert.equal(report.tcpDiagnostic.errorCategory,'EMPTY');assert.ok(report.tcpDiagnostic.failedPredicates.includes('explicitUnreachable'));
      return error.code==='PROBE_INCONCLUSIVE';
    });
    assert.equal(d.isCleaned(),true);assert.equal(l.resources.size,0);
    const saved=JSON.parse(await fs.readFile(file,'utf8'));assert.equal(saved.stdoutText,'');assert.equal(saved.stderrText,'');
    assert.equal((await fs.stat(file)).mode&0o777,0o600);
  } finally {if(file)await fs.rm(path.dirname(file),{recursive:true,force:true});}
});

test('TCP-only lifecycle runner cleans all owned resources for every probe verdict',async()=>{
  const {runAcceptance}=require('../scripts/dast-acceptance'),fs=require('fs/promises'),path=require('path');
  const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';
  try {for(const [code,err,actual] of [[1,'nc: network is unreachable','DENY'],[1,'','INCONCLUSIVE'],[1,'nc: connection refused','INCONCLUSIVE'],[1,'nc: timed out','INCONCLUSIVE'],[127,'nc: not found','INCONCLUSIVE'],[0,'','ALLOW']]) {
    const d=deps(),l=new SecureGatewayLifecycle(d);d.state.probe=(a,cb)=>{assert.equal(a[2],'nc');cb(code?Object.assign(new Error('failed'),{code}):null,'',err);};
    const r=await runAcceptance({...input,mode:'tcp-diagnostic'},l);
    try {assert.equal(r.actual,actual);assert.equal(r.fullContainment,false);assert.equal(d.isCleaned(),true);assert.equal(l.resources.size,0);assert.equal(d.calls.filter(a=>a[2]==='nc').length,1);assert.ok(!d.calls.some(a=>a[5]==='cloudsentinel-curl'));}
    finally {await fs.rm(path.dirname(r.diagnosticFile),{recursive:true,force:true});}
  }} finally {if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
});
test('TCP diagnostic artifact write failure still cleans lifecycle resources',async(t)=>{
  const fs=require('fs/promises'),write=fs.writeFile.bind(fs);let file;
  t.mock.method(fs,'writeFile',async(f,...args)=>{if(String(f).includes('cloudsentinel-tcp-diagnostic-')){file=f;throw new Error('failed');}return write(f,...args);});
  const d=deps(),l=new SecureGatewayLifecycle(d);await assert.rejects(l.provision({...input,mode:'tcp-diagnostic'}),{code:'DIAGNOSTIC_WRITE_FAILED'});
  assert.equal(d.isCleaned(),true);assert.equal(l.resources.size,0);await assert.rejects(fs.stat(require('path').dirname(file)),{code:'ENOENT'});
});
