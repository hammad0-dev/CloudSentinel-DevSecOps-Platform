"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {RuntimeObservation,runtimeReady,routeCheck}=require("../services/runtimeObservation");
const client=require("../services/dastAcceptanceClient");
const {mockDocker}=require("./helpers/runtimeDocker");
async function setup() {
  const d=mockDocker(),c=await client.provision(d.adapter,{scanId:"s1",networkId:d.ids.scanner,networkReference:d.refs[0]});
  const observation=new RuntimeObservation({adapter:d.adapter});observation.bindAcceptanceClient(client,c);
  const input={projectId:"17",executionId:"accept",scanId:"s1",gatewayContainerId:d.ids.gateway,scannerContainerId:c.id,scannerNetworkId:d.ids.scanner,fixtureNetworkId:d.ids.fixture,networkReferences:d.refs,target:{hostname:"fixture.test",ip:"172.30.26.2",port:8080,proxy:"http://172.30.25.3:3128"},stagedPolicy:{containerPath:"/etc/squid/cloudsentinel/squid.conf",policyDigest:"sha256:"+d.state.digest}};
  return {...d,observation,input};
}
test("collects actual command contracts but marks mocked adapters unverified",async()=>{
  const d=await setup(),e=await d.observation.collect(d.input);
  assert.equal(e.probes.length,11);assert.ok(e.probes.every(p=>p.complete&&Number.isInteger(p.exitCode)));
  assert.equal(e.verification,"MOCK_ONLY_NOT_VERIFIED");assert.equal(runtimeReady(e),false);
  const commands=d.calls.filter(a=>a[0]==="exec"&&a[2]==="ip").map(a=>a.slice(2));
  assert.deepEqual(commands,[["ip","route","list"],["ip","-f","inet6","route","list"],["ip","address","show"]]);
  assert.equal(e.routes.source,"busybox-ip-text");
});
test('gateway binding accepts only the exact independently inspected numeric endpoint',async()=>{
 const d=await setup();const e=await d.observation.collect(d.input);assert.equal(e.probes.length,11);
 for(const proxy of ['http://172.30.25.9:3128','http://172.30.26.3:3128','http://172.30.25.3:3129','http://gateway:3128','http://secret:credential@172.30.25.3:3128','http://172.30.25.3:3128/']){
  const x=await setup();await assert.rejects(x.observation.collect({...x.input,target:{...x.input.target,proxy}}),e=>{assert.equal(e.code,'INVALID_PROBE');assert.equal(e.gatewayDiagnostic.proxyMatches,false);assert.equal(JSON.stringify(e.gatewayDiagnostic).includes('credential'),false);assert.equal(e.gatewayDiagnostic.inspectedGatewayIp,'172.30.25.3');return true;});
  assert.ok(!x.calls.some(a=>a[0]==='exec'));
 }
});
test('stale gateway address fails without rebinding the expected proxy',async()=>{
 const d=await setup();d.state.gatewayNetworks['cs-scanner'].IPAddress='172.30.25.9';
 await assert.rejects(d.observation.collect(d.input),e=>e.code==='INVALID_PROBE'&&e.gatewayDiagnostic.expectedProxyIp==='172.30.25.3'&&e.gatewayDiagnostic.inspectedGatewayIp==='172.30.25.9');
 assert.ok(!d.calls.some(a=>a[0]==='exec'));
});
test('stopped gateway and missing addresses are distinguished before traffic',async()=>{
 for(const stopped of [true,false]){
  const d=await setup(),run=d.adapter.run.bind(d.adapter);
  d.adapter.run=async args=>{const r=await run(args);if(args[0]==='inspect'&&args.at(-1)===d.ids.gateway){const raw=JSON.parse(r.stdout);raw.State={Running:!stopped,ExitCode:stopped?1:0,OOMKilled:false};if(!stopped)delete raw.NetworkSettings.Networks['cs-scanner'].IPAddress;return {...r,stdout:JSON.stringify(raw)};}return r;};
  await assert.rejects(d.observation.collect(d.input),e=>e.code===(stopped?'GATEWAY_NOT_RUNNING':'GATEWAY_ENDPOINT_INVALID')&&e.gatewayDiagnostic.gatewayRunning===!stopped);
  assert.ok(!d.calls.some(a=>a[0]==='exec'));
 }
});
test('spoofed gateway container, ownership and scanner network identities stay rejected',async()=>{
 for(const change of [raw=>raw.Id='9'.repeat(64),raw=>raw.Config.Labels['cloudsentinel.owner']='foreign',raw=>raw.NetworkSettings.Networks['cs-scanner'].NetworkID='9'.repeat(64)]){
  const d=await setup(),run=d.adapter.run.bind(d.adapter);d.adapter.run=async args=>{const r=await run(args);if(args[0]==='inspect'&&args.at(-1)===d.ids.gateway){const raw=JSON.parse(r.stdout);change(raw);return {...r,stdout:JSON.stringify(raw)};}return r;};
  await assert.rejects(d.observation.collect(d.input));assert.ok(!d.calls.some(a=>a[0]==='exec'));
 }
});
test("captured M-DOWN grammar reaches trusted probe contracts only with matching mocked endpoint",async()=>{
  const capture=require('./fixtures/nginx-address-internal-248470e9.json');
  const d=await setup();
  // Adapt only disposable addresses/MAC to this mock's inspected endpoint;
  // retain the captured interface header, flags and address-line grammar.
  d.state.addresses=capture.stdout.replaceAll('172.30.250.', '172.30.25.').replaceAll('56:f2:65:38:29:5d', '02:42:ac:1e:19:02');
  const evidence=await d.observation.collect(d.input);
  assert.equal(evidence.probes.length,11);
  assert.ok(evidence.routes.addresses.find(n=>n.ifname==='eth0').flags.includes('M-DOWN'));
  assert.equal(evidence.verification,'MOCK_ONLY_NOT_VERIFIED');
  assert.equal(runtimeReady(evidence),false);
  d.state.clientNetworks['cs-scanner'].NetworkID='9'.repeat(64);
  await assert.rejects(d.observation.collect(d.input));
});
test("generic injected executors and unverified clients cannot produce runtime evidence",async()=>{
  const d=mockDocker();assert.throws(()=>new RuntimeObservation({adapter:d.adapter,probeExecutor:async()=>({ready:true})}),{code:"INVALID_PROBE"});
  const o=new RuntimeObservation({adapter:d.adapter});assert.throws(()=>o.bindAcceptanceClient({probe:async()=>({actual:"ALLOW"})},{id:d.ids.client}),{code:"INVALID_PROBE"});
});
test("native default and IPv6 routes fail closed",()=>{for(const route of [{dst:"default"},{dst:"0.0.0.0/0"},{dst:"::/0"},{defaultRoute:true}])assert.throws(()=>routeCheck([route]),{code:"UNSAFE_ROUTE"});});
test("rejects changed memberships, IPv6 and wrong policy digests",async()=>{
  for(const mutate of [d=>{d.state.gatewayNetworks.extra={NetworkID:"9".repeat(64)};},d=>{d.state.route="default via 172.30.25.1 dev eth0\n";},d=>{d.state.addresses += "    inet6 fe80::42/64 scope link\n       valid_lft forever preferred_lft forever\n";},d=>{d.state.digest="b".repeat(64);}]) {
    const d=await setup();mutate(d);await assert.rejects(d.observation.collect(d.input));
  }
});
test("missing utilities, proxy evidence or successful bypass cannot pass",async()=>{
  for(const mutate of [d=>{d.state.commandFailure=true;},d=>{d.state.probe=(a,cb)=>cb(null,"200 000 172.30.25.3","");},d=>{d.state.probe=(a,cb)=>cb(null,"","");}]) {
    const d=await setup();mutate(d);await assert.rejects(d.observation.collect(d.input));
  }
});
test("forged and cloned evidence never qualify runtime readiness",()=>{
  assert.equal(runtimeReady({complete:true,independent:true,verification:"RUNTIME_OBSERVED",directTcpBypass:false,ipv6:false}),false);
});
test('CONNECT diagnostic uses normal preconditions, executes only CONNECT and saves private redacted evidence',async()=>{
  const fs=require('fs/promises'),path=require('path');
  const d=await setup(),fixture=require('./fixtures/connect-denied.json');
  d.state.probe=(a,cb)=>cb(Object.assign(new Error('CONNECT'),{code:56}),'000 403 ', '* Connected to 172.30.25.3 (172.30.25.3) port 3128\n'+fixture.stderr.replace('< Content-Length:', '< Authorization: secret=private-value\r\n< X-Secret: token=private-value\r\n< Content-Length:')+'* Uses env variable SECRET=private-value\n');
  const result=await d.observation.collect({...d.input,mode:'connect-diagnostic'});
  try {
    assert.equal(result.state,'DIAGNOSTIC_COMPLETE');assert.equal(result.fullContainment,false);assert.equal(result.diagnosticOnly,true);
    assert.equal(result.actual,'DENY');assert.equal(runtimeReady(result),false);
    const probes=d.calls.filter(a=>a[5]==='cloudsentinel-curl'||a[2]==='nc');assert.equal(probes.length,1);assert.ok(probes[0].at(-1).startsWith('https:'));
    assert.ok(d.calls.some(a=>a[2]==='sha256sum'));assert.equal(d.calls.filter(a=>a[2]==='ip').length,3);
    assert.equal((await fs.stat(result.diagnosticFile)).mode&0o777,0o600);
    assert.equal((await fs.stat(path.dirname(result.diagnosticFile))).mode&0o777,0o700);
    const bytes=await fs.readFile(result.diagnosticFile,'utf8'),saved=JSON.parse(bytes);
    assert.equal(saved.provenance,'MOCK_ONLY_NOT_VERIFIED');assert.equal(saved.gateway.id,d.ids.gateway);
    assert.equal(saved.connectEvidence.socketPeerObserved,true);assert.equal(saved.connectEvidence.socketPrecedesConnect,true);
    assert.ok(saved.native.verboseEvidenceLines.some(line=>line.startsWith('* Connected to ')));
    assert.ok(!bytes.includes('private-value'));assert.ok(!JSON.stringify(result).includes('Connected to'));
  } finally {await fs.rm(path.dirname(result.diagnosticFile),{recursive:true,force:true});}
});
test('diagnostic captures missing or malformed peer without issuing full evidence',async()=>{
  const fs=require('fs/promises'),path=require('path'),fixture=require('./fixtures/connect-denied.json');
  for(const prefix of ['','* Connected to unknown socket syntax\n']) {
    const d=await setup();d.state.probe=(a,cb)=>cb(Object.assign(new Error('CONNECT'),{code:56}),'000 403 ',prefix+fixture.stderr);
    const result=await d.observation.collect({...d.input,mode:'connect-diagnostic'});
    try {
      assert.equal(result.actual,'INCONCLUSIVE');assert.equal(result.complete,false);assert.equal(runtimeReady(result),false);
      const saved=JSON.parse(await fs.readFile(result.diagnosticFile,'utf8'));
      assert.equal(saved.connectEvidence.peerEvidenceStatus,prefix?'MALFORMED':'MISSING');
    } finally {await fs.rm(path.dirname(result.diagnosticFile),{recursive:true,force:true});}
  }
});
test('diagnostic route, policy and gateway failures run no CONNECT',async()=>{
  for(const mutate of [d=>{d.state.route='default via 172.30.25.1 dev eth0\n';},d=>{d.state.digest='b'.repeat(64);},d=>{d.state.gatewayNetworks.extra={NetworkID:'9'.repeat(64)};}]) {
    const d=await setup();mutate(d);await assert.rejects(d.observation.collect({...d.input,mode:'connect-diagnostic'}));
    assert.ok(!d.calls.some(a=>a[5]==='cloudsentinel-curl'||a[2]==='nc'));
  }
});
test("each malformed native observation retains its exact rule and safe command evidence",async()=>{
  const {failureReport}=require('../scripts/dast-acceptance');
  for(const [field,kind,value,rule] of [
    ['route','ipv4','password=private-value\n','UNRECOGNIZED_NATIVE_ROUTE_FORMAT'],
    ['ipv6','ipv6','unknown route token=private-value\n','UNRECOGNIZED_NATIVE_ROUTE_FORMAT'],
    ['addresses','addresses','inet 1.2.3.4/24 scope global\n','ADDRESS_OUTPUT_HAS_NO_INTERFACE_HEADER'],
    ['addresses','addresses','','MISSING_NATIVE_INTERFACE_EVIDENCE'],
  ]) {
    const d=await setup();d.state[field]=value;
    await assert.rejects(d.observation.collect(d.input),error=>{
      assert.equal(error.code,'MALFORMED_ROUTES');
      const report=failureReport(error),diag=report.networkDiagnostic;
      assert.equal(diag.observation,kind);assert.equal(diag.validationRule,rule);
      assert.equal(diag.exitCode,0);assert.equal(diag.stdout.bytes,Buffer.byteLength(value));
      assert.equal(diag.stdout.category,value?'TEXT':'EMPTY');
      assert.ok(!JSON.stringify(report).includes('private-value'));
      assert.equal(d.calls.some(a=>a.includes('curl')||a.includes('nc')),false);
      assert.equal(runtimeReady(report),false);return true;
    });
  }
});
test("observation command failures retain exit evidence without treating stderr as route stdout",async()=>{
  const d=await setup();d.state.commandFailure=true;
  await assert.rejects(d.observation.collect(d.input),error=>{
    assert.equal(error.networkDiagnostic.observation,'ipv4');
    assert.equal(error.networkDiagnostic.exitCode,127);
    assert.equal(error.networkDiagnostic.stdout.category,'EMPTY');
    assert.equal(error.networkDiagnostic.stderr.category,'TEXT');return true;
  });
});
test("malformed observations survive runner reporting and ownership-verified client cleanup",async()=>{
  const {runAcceptance,failureReport}=require('../scripts/dast-acceptance');
  const d=await setup();d.state.route='unrecognized route\n';
  const old=process.env.DAST_ACTIVE_ENABLED;process.env.DAST_ACTIVE_ENABLED='false';
  try {
    await assert.rejects(runAcceptance({projectId:'17',executionId:'accept',scanId:'s1',target:{hostname:'fixture.test',port:8080}}, {
      provision:()=>d.observation.collect(d.input),
      cleanup:()=>client.cleanup(d.adapter,d.observation.acceptanceClient.resource),
    }),error=>{
      assert.equal(failureReport(error).networkDiagnostic.observation,'ipv4');
      assert.equal(error.code,'MALFORMED_ROUTES');return true;
    });
    assert.ok(d.calls.some(a=>a[0]==='stop'&&a[1]===d.ids.client));
    assert.ok(d.calls.some(a=>a[0]==='rm'&&a[1]===d.ids.client));
    assert.ok(d.calls.filter(a=>['stop','rm'].includes(a[0])).every(a=>a[1]===d.ids.client));
  } finally {if(old===undefined)delete process.env.DAST_ACTIVE_ENABLED;else process.env.DAST_ACTIVE_ENABLED=old;}
});
test("missing stdout, nonzero status and stderr warnings cannot establish isolation",async()=>{
  for(const change of [{stdout:undefined},{exitCode:1},{stderr:'password=private-value warning'}]) {
    const d=await setup(),run=d.adapter.run.bind(d.adapter);
    d.adapter.run=async args=>{const result=await run(args);return args[0]==='exec'&&args[2]==='ip'?{...result,...change}:result;};
    await assert.rejects(d.observation.collect(d.input),error=>{
      assert.equal(error.code,'INCOMPLETE_PROBES');
      assert.equal(error.networkDiagnostic.validationRule,'COMMAND_OUTPUT_NOT_CLEAN');
      assert.equal(error.networkDiagnostic.observation,'ipv4');
      assert.ok(!JSON.stringify(error.networkDiagnostic).includes('private-value'));
      assert.equal(runtimeReady(error),false);return true;
    });
  }
});

test('TCP-only diagnostic collects one trusted probe and complete private namespace evidence',async()=>{
  const fs=require('fs/promises'),path=require('path');
  for(const [code,out,err,actual] of [[1,'','nc: network is unreachable','DENY'],[1,'','','INCONCLUSIVE'],[1,'','nc: connection refused','INCONCLUSIVE'],[1,'','nc: timed out','INCONCLUSIVE'],[127,'','nc: not found','INCONCLUSIVE'],[0,'','','ALLOW']]) {
    const d=await setup();d.state.probe=(a,cb)=>{assert.equal(a[2],'nc');cb(code?Object.assign(new Error('failed'),{code}):null,out,err);};
    const r=await d.observation.collect({...d.input,mode:'tcp-diagnostic'});
    try {
      assert.equal(r.actual,actual);assert.equal(r.diagnosticOnly,true);assert.equal(r.fullContainment,false);assert.equal(runtimeReady(r),false);
      const commands=d.calls.filter(a=>a[2]==='nc'||a[5]==='cloudsentinel-curl'||a[2]==='/opt/cloudsentinel/connect-peer');
      assert.equal(commands.length,1);assert.deepEqual(commands[0].slice(2),['nc','-n','-v','-z','-w','5','172.30.26.2','8080']);
      const data=JSON.parse(await fs.readFile(r.diagnosticFile,'utf8'));
      assert.equal(data.observations.client.id,d.ids.client);assert.equal(data.observations.client.networkId,d.ids.scanner);
      assert.equal(data.observations.client.memberships[0][1].MacAddress,'02:42:ac:1e:19:02');
      assert.equal(data.observations.routes.raw.ipv4,d.state.route);assert.equal(data.observations.routes.raw.addresses,d.state.addresses);
      assert.equal(data.observations.interpretation.effectiveKernelDecision,'UNKNOWN');assert.equal(data.observations.interpretation.explicitKernelProhibitionObserved,false);
      assert.equal((await fs.stat(r.diagnosticFile)).mode&0o777,0o600);assert.equal((await fs.stat(path.dirname(r.diagnosticFile))).mode&0o777,0o700);
    } finally {await fs.rm(path.dirname(r.diagnosticFile),{recursive:true,force:true});}
  }
});
test('TCP diagnostic mismatched identity or route evidence fails before any probe',async()=>{
  for(const mutate of [d=>{d.state.clientNetworks['cs-scanner'].NetworkID=d.ids.fixture;},d=>{d.state.clientNetworks['cs-scanner'].MacAddress='02:00:00:00:00:99';},d=>{d.state.route='default via 172.30.25.1 dev eth0\n';},d=>{d.state.addresses='';}]) {
    const d=await setup();mutate(d);await assert.rejects(d.observation.collect({...d.input,mode:'tcp-diagnostic'}));
    assert.ok(!d.calls.some(a=>a[2]==='nc'||a[5]==='cloudsentinel-curl'));
  }
});
