"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const client = require("../services/dastAcceptanceClient");
const { mockDocker } = require("./helpers/runtimeDocker");
const target = { hostname: "fixture.test", ip: "172.30.26.2", port: 8080 };
const proxy = "http://172.30.25.3:3128";
async function provision(d) { return client.provision(d.adapter, { scanId: "s1", networkId: d.ids.scanner, networkReference: d.refs[0] }); }
test("client resolves Docker name keys against independently inspected immutable IDs", async () => {
  const d = mockDocker(), c = await provision(d);
  assert.equal(c.networkId, d.ids.scanner); assert.equal(c.networkName, "cs-scanner");
  assert.ok(d.calls.some(a=>a[0]==="network"&&a[1]==="inspect"));
});
test("rejects name/ID substitution, unexpected attachments and foreign networks", async () => {
  for (const mutate of [d=>{d.state.clientNetworks["cs-scanner"].NetworkID=d.ids.fixture;},d=>{d.state.clientNetworks.extra={NetworkID:d.ids.fixture};},d=>{d.state.clientNetworks.wrong=d.state.clientNetworks["cs-scanner"];delete d.state.clientNetworks["cs-scanner"];},d=>{d.state.foreign=true;}]) {
    const d=mockDocker();mutate(d);await assert.rejects(provision(d), /mismatch|membership/);
  }
});
test("probes require bound lifecycle identity and structured targets", async () => {
  const d=mockDocker();await assert.rejects(client.probe(d.adapter,{id:d.ids.client},"http",target,{proxy}),{code:"INVALID_CLIENT"});
  const c=await provision(d);await assert.rejects(client.probe(d.adapter,c,"http","http://fixture/health",{proxy}),{code:"INVALID_PROBE"});
});
test("HTTP probes record explicit proxy, actual exit code/status and source", async () => {
  const d=mockDocker(),c=await provision(d);const r=await client.probe(d.adapter,c,"http",target,{proxy});
  assert.equal(r.actual,"ALLOW");assert.equal(r.httpStatus,200);assert.equal(r.exitCode,0);assert.equal(r.sourceId,c.id);
  const command=d.calls.find(a=>a[0]==="exec"&&a[5]==="cloudsentinel-curl");assert.ok(command.includes(proxy));assert.equal(command.at(-1),"http://fixture.test:8080/health");
  assert.equal(command[2], "/bin/sh");
  assert.match(command[4], /^unset no_proxy NO_PROXY http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY; exec curl "\$@"$/);
  assert.equal(command[6], "-q");
  assert.equal(command[command.indexOf("--proxy") + 1], proxy);
  assert.ok(!command.some(arg => arg.startsWith("--noproxy")));
});
test("direct bypass uses independently verified nc with numeric destination and no proxy", async () => {
  const d=mockDocker(),c=await provision(d);
  const result=await client.probe(d.adapter,c,"tcp",target,{proxy});
  assert.equal(result.actual,"INCONCLUSIVE");assert.equal(result.exitCode,1);
  assert.deepEqual(d.calls.find(a=>a[0]==="exec"&&a[2]==="nc"),["exec",c.id,"nc","-n","-v","-z","-w","5",target.ip,"8080"]);
  await assert.rejects(client.probe(d.adapter,c,"tcp",{...target,ip:"fixture.test"},{proxy}),{code:"INVALID_PROBE"});
});
test("fixed shell clears inherited proxy settings and preserves curl argv without making requests",async()=>{
  const fs=require("fs/promises"),path=require("path"),os=require("os");
  const execFile=require("util").promisify(require("child_process").execFile);
  const d=mockDocker(),c=await provision(d);await client.probe(d.adapter,c,"http",target,{proxy});
  const command=d.calls.find(a=>a[5]==="cloudsentinel-curl");
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),"cs-curl-argv-"));
  try {
    await fs.writeFile(path.join(directory,"curl"),'#!/bin/sh\nprintf "%s\\n" "${no_proxy-UNSET}" "${NO_PROXY-UNSET}" "${http_proxy-UNSET}" "${HTTP_PROXY-UNSET}" "${https_proxy-UNSET}" "${HTTPS_PROXY-UNSET}" "${all_proxy-UNSET}" "${ALL_PROXY-UNSET}" "$@"\n',{mode:0o700});
    const env={...process.env,PATH:directory+":"+process.env.PATH,no_proxy:"*",NO_PROXY:"*",http_proxy:"http://wrong",HTTP_PROXY:"http://wrong",https_proxy:"http://wrong",HTTPS_PROXY:"http://wrong",all_proxy:"http://wrong",ALL_PROXY:"http://wrong"};
    const result=await execFile(command[2],command.slice(3),{env});
    const lines=result.stdout.trim().split("\n");assert.deepEqual(lines.slice(0,8),Array(8).fill("UNSET"));
    assert.deepEqual(lines.slice(8),command.slice(6));
  } finally {await fs.rm(directory,{recursive:true,force:true});}
});
test("mocked pinned utilities reject the recorded unsupported flags",async()=>{
  const d=mockDocker();
  for(const command of [["ip","-j","route"],["curl","--noproxy="]])await assert.rejects(d.adapter.run(["exec",d.ids.client,...command]),e=>e.exitCode===2&&e.code==="DOCKER_COMMAND_FAILED");
});
test("DNS errors and unsupported command flags remain inconclusive, never policy denial",async()=>{
  const d=mockDocker(),c=await provision(d);
  for(const [code,message] of [[5,"Could not resolve proxy"],[6,"Could not resolve host"],[2,"option --noproxy=: is unknown"]]){
    d.state.probe=(a,cb)=>cb(Object.assign(new Error(message),{code}),"000 000",message);
    const r=await client.probe(d.adapter,c,"http",target,{proxy});assert.equal(r.actual,"INCONCLUSIVE");assert.equal(r.complete,false);
  }
});
test("explicit proxy denial and CONNECT 403 require observed evidence", async () => {
  const d=mockDocker(),c=await provision(d);
  assert.equal((await client.probe(d.adapter,c,"proxy",{...target,hostname:"bad.test"},{proxy})).actual,"DENY");
  const r=await client.probe(d.adapter,c,"connect",target,{proxy,expected:'DENY',gatewayContainerId:d.ids.gateway});assert.equal(r.actual,"DENY");assert.equal(r.connectStatus,403);assert.equal(r.exitCode,56);
});
test("missing utilities, HTTP evidence and generic failures stay inconclusive", async () => {
  const d=mockDocker(),c=await provision(d);
  for (const response of [(a,cb)=>cb(null,"", ""),(a,cb)=>cb(null,"403 000 172.30.25.3", ""),(a,cb)=>cb(null,"403 000 10.0.0.1", ""),(a,cb)=>cb(Object.assign(new Error("missing"),{code:127}),"","not found"),(a,cb)=>cb(Object.assign(new Error("failure"),{code:1}),"", "unknown error")]) {
    d.state.probe=response;const r=await client.probe(d.adapter,c,"proxy",target,{proxy});assert.equal(r.complete,false);assert.equal(r.actual,"INCONCLUSIVE");
  }
});
test("cleanup refuses foreign client", async () => {
  const d=mockDocker();await assert.rejects(client.cleanup(d.adapter,{id:d.ids.client,owner:"foreign"}),{code:"OWNERSHIP_MISMATCH"});
});
test('CONNECT requires request, response, proxy identity and consistent statuses',async()=>{
  const r=require('./fixtures/connect-denied.json'),d=mockDocker(),c=await provision(d);
  const options={proxy,expected:'DENY',gatewayContainerId:d.ids.gateway};
  const attempt=async(stdout,stderr,code=56,opts=options,destination=target)=>{
    d.state.probe=(a,cb)=>cb(code?Object.assign(new Error('mock curl failure'),{code}):null,stdout,stderr);
    return client.probe(d.adapter,c,'connect',destination,opts);
  };
  assert.equal((await attempt(r.stdout,r.stderr)).actual,'DENY');
  const variants=[
    [r.stdout,''],[r.stdout,r.stderr.replace('< Server: squid/6.14\r\n','')],
    [r.stdout,r.stderr.replace('< X-Squid-Error: ERR_ACCESS_DENIED 0\r\n','')],
    [r.stdout,r.stderr.replace('< \r\n','')],
    ['000 000 172.30.25.3',r.stderr],['200 403 172.30.25.3',r.stderr],
    ['000 403',r.stderr],['000 403 10.0.0.1',r.stderr],
    [r.stdout,r.stderr.replaceAll('fixture.test:8080','other.test:8080')],
    [r.stdout,r.stderr.replace('403 Forbidden','200 Connection established')],
    [r.stdout,r.stderr.replace('< Content-Length:', '< Location: http://unexpected.test/\r\n< Content-Length:')],
    [r.stdout,r.stderr.replace('< Content-Length:', '< X-Squid-Error: ERR_DNS_FAIL 0\r\n< Content-Length:')],
    [r.stdout,r.stderr+'Could not resolve host',56],
    [r.stdout,r.stderr+'Connection refused',56],
    [r.stdout,r.stderr+'Operation timed out',28],
    [r.stdout,r.stderr+'unknown option',2],
  ];
  for(const [stdout,stderr,code] of variants){const result=await attempt(stdout,stderr,code);assert.equal(result.complete,false);assert.notEqual(result.actual,'DENY');}
  for(const opts of [{proxy},{...options,gatewayContainerId:undefined},{...options,proxy:'http://10.0.0.1:3128'},{...options,expected:'ALLOW'}])assert.notEqual((await attempt(r.stdout,r.stderr,56,opts)).actual,'DENY');
  assert.equal((await attempt('200 200 172.30.25.3','',0)).actual,'ALLOW');
  assert.equal((await attempt(r.stdout,r.stderr,56,options,{...target,port:8081})).actual,'INCONCLUSIVE');
});
test('CONNECT diagnostics preserve failed predicates without header secrets',async()=>{
  const {failureReport}=require('../scripts/dast-acceptance');
  const d=mockDocker(),c=await provision(d),r=require('./fixtures/connect-denied.json');
  d.state.probe=(a,cb)=>cb(Object.assign(new Error('CONNECT'),{code:56}),r.stdout,r.stderr.replace('< Server: squid/6.14\r\n','')+'password=private-value\n');
  const probe=await client.probe(d.adapter,c,'connect',target,{proxy,expected:'DENY',gatewayContainerId:d.ids.gateway});
  const report=failureReport({code:'PROBE_INCONCLUSIVE',probes:[{...probe,name:'negative-connect',expected:'DENY'}]});
  assert.equal(report.probes[0].connectEvidence.squidServer,false);
  assert.equal(report.probes[0].connectEvidence.gatewayIdentity,true);
  assert.match(report.probes[0].connectEvidence.outputSha256,/^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(report).includes('private-value'));
});
test('CONNECT socket-peer trace can corroborate absent write-out IP but never contradict it',async()=>{
  const fixture=require('./fixtures/connect-denied.json'),d=mockDocker(),c=await provision(d);
  const trace='* Connected to 172.30.25.3 (172.30.25.3) port 3128\n';
  const opts={proxy,expected:'DENY',gatewayContainerId:d.ids.gateway};
  const attempt=async(stdout,stderr)=>{
    d.state.probe=(a,cb)=>cb(Object.assign(new Error('CONNECT'),{code:56}),stdout,stderr);
    return client.probe(d.adapter,c,'connect',target,opts);
  };
  for(const suffix of ['',' (#0)']) {
    const result=await attempt('000 403 ',trace.replace('port 3128','port 3128'+suffix)+fixture.stderr);
    assert.equal(result.actual,'DENY');assert.equal(result.connectEvidence.curlRemoteIpPresent,false);
    assert.equal(result.connectEvidence.curlRemoteIpMatches,false);
    assert.equal(result.connectEvidence.observedPeerSource,'CURL_VERBOSE_SOCKET');
    assert.equal(result.connectEvidence.observedPeerMatches,true);
  }
  const cases=[
    ['000 403',fixture.stderr,'MISSING'],
    ['000 403 10.0.0.1',trace+fixture.stderr,'MISMATCH'],
    ['000 403',trace.replaceAll('172.30.25.3','10.0.0.1')+fixture.stderr,'MISMATCH'],
    [fixture.stdout,trace.replace('3128','3129')+fixture.stderr,'MISMATCH'],
    ['000 403 proxy.test',trace+fixture.stderr,'MALFORMED'],
    ['000 403',trace.replace('(172.30.25.3)','(10.0.0.1)')+fixture.stderr,'MALFORMED'],
    ['000 403',trace+trace+fixture.stderr,'MALFORMED'],
    ['000 403',fixture.stderr+trace,'MALFORMED'],
    ['000 403','* Trying 172.30.25.3:3128...\n'+fixture.stderr,'MISSING'],
    ['000 403','< X-Fake: '+trace+fixture.stderr,'MISSING'],
    ['000 403 extra extra',trace+fixture.stderr,'MALFORMED'],
  ];
  const {failureReport}=require('../scripts/dast-acceptance');
  for(const [stdout,stderr,status] of cases) {
    const result=await attempt(stdout,stderr);assert.equal(result.actual,'INCONCLUSIVE');
    assert.equal(result.connectEvidence.peerEvidenceStatus,status);
    const diag=failureReport({code:'PROBE_INCONCLUSIVE',probes:[result]}).probes[0].connectEvidence;
    assert.equal(diag.peerEvidenceStatus,status);assert.equal(diag.observedPeerMatches,false);
  }
});
test('CONNECT peer evidence cannot override gateway container or network identity mismatch',async()=>{
  for(const field of ['objectId','network']) {
    const d=mockDocker(),c=await provision(d),r=require('./fixtures/connect-denied.json');
    d.state.probe=(a,cb)=>cb(Object.assign(new Error('CONNECT'),{code:56}),r.stdout,r.stderr);
    const inspect=d.adapter.inspect.bind(d.adapter);
    d.adapter.inspect=async(args,kind)=>{const result=await inspect(args,kind);if(args[0]===d.ids.gateway){if(field==='objectId')result.normalized.objectId='9'.repeat(64);else result.normalized.networks['cs-scanner'].NetworkID='9'.repeat(64);}return result;};
    const result=await client.probe(d.adapter,c,'connect',target,{proxy,expected:'DENY',gatewayContainerId:d.ids.gateway});
    assert.equal(result.actual,'INCONCLUSIVE');assert.equal(result.connectEvidence.gatewayIdentity,false);
    assert.equal(result.connectEvidence[field==='objectId'?'expectedGatewayContainerIdMatches':'expectedGatewayNetworkIdMatches'],false);
  }
});

test("timeout, refusal, DNS errors, missing tools and unexpected TCP failures never prove denial",async()=>{
  const d=mockDocker(),c=await provision(d);
  for(const [code,stderr] of [[1,"nc: timed out"],[1,"nc: connection refused"],[1,"nc: network is unreachable"],[6,"Could not resolve host"],[127,"nc: not found"],[3,"network failure"]]){
    d.state.probe=(a,cb)=>cb(Object.assign(new Error(stderr),{code}),"",stderr);
    const r=await client.probe(d.adapter,c,"tcp",target,{});assert.equal(r.actual,"INCONCLUSIVE");assert.equal(r.complete,false);assert.notEqual(r.evidenceType,"squid-policy");
  }
});
test("TCP success is ALLOW, invalid arguments are ERROR and contradictory evidence is inconclusive",async()=>{
  const d=mockDocker(),c=await provision(d);
  d.state.probe=(a,cb)=>cb(null,"","");assert.equal((await client.probe(d.adapter,c,"tcp",target)).actual,"ALLOW");
  d.state.probe=(a,cb)=>cb(Object.assign(new Error("invalid option"),{code:2}),"","nc: invalid option");assert.equal((await client.probe(d.adapter,c,"tcp",target)).actual,"ERROR");
  d.state.probe=(a,cb)=>cb(null,"","connection refused");assert.equal((await client.probe(d.adapter,c,"tcp",target)).actual,"INCONCLUSIVE");
  d.state.probe=(a,cb)=>cb(Object.assign(new Error("DNS"),{code:6}),"403 000 172.30.25.3","Could not resolve host X-Squid-Error: ERR_ACCESS_DENIED");assert.equal((await client.probe(d.adapter,c,"http",target,{proxy})).actual,"INCONCLUSIVE");
  for(const [stdout,stderr] of [["200 000 172.30.25.3","X-Squid-Error: ERR_ACCESS_DENIED"],["403 000 172.30.25.3","X-Squid-Error: ERR_ACCESS_DENIED X-Squid-Error: ERR_DNS_FAIL"],["200 403 172.30.25.3",""]]){
    d.state.probe=(a,cb)=>cb(null,stdout,stderr);assert.equal((await client.probe(d.adapter,c,"http",target,{proxy})).actual,"INCONCLUSIVE");
  }
});
test("direct-network denial requires a current route proof for the same inspected client",async()=>{
  const {verifyNetworkText}=require("../services/runtimeNetworkText");const text=require("./helpers/busyboxNetwork");
  const d=mockDocker(),c=await provision(d);
  const routeEvidence=verifyNetworkText(text,d.refs[0],d.state.clientNetworks['cs-scanner']);
  const r=await client.probe(d.adapter,c,"tcp",target,{routeEvidence});assert.equal(r.actual,"DENY");assert.equal(r.evidenceType,"direct-network-isolation");assert.equal(r.proxyDenied,false);
  assert.equal((await client.probe(d.adapter,c,"tcp",target,{routeEvidence:{...routeEvidence}})).actual,"INCONCLUSIVE");
  assert.equal((await client.probe(d.adapter,c,"tcp",{...target,ip:'172.30.25.8'},{routeEvidence})).actual,"INCONCLUSIVE");
  for(const stderr of ['nc: timed out','nc: connection refused']){
    d.state.probe=(a,cb)=>cb(Object.assign(new Error(stderr),{code:1}),"",stderr);
    assert.equal((await client.probe(d.adapter,c,"tcp",target,{routeEvidence})).actual,"INCONCLUSIVE");
  }
});

test('public and metadata denials require complete policy response from verified proxy',async()=>{
  for(const hostname of ['198.51.100.9','169.254.169.254']) {
    const d=mockDocker(),c=await provision(d);
    const good='HTTP/1.1 403 Forbidden\r\nServer: squid/6.14\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\n\r\n';
    for(const [exit,stdout,stderr,expected] of [
      [0,'403 000 172.30.25.3',good,'DENY'],
      [0,'403 000 172.30.25.3',good.replace('Server: squid/6.14\r\n',''),'INCONCLUSIVE'],
      [0,'403 000 172.30.25.3',good.trim(),'INCONCLUSIVE'],
      [0,'403 000 172.30.25.9',good,'INCONCLUSIVE'],
      [6,'000 000 ','Could not resolve host','INCONCLUSIVE'],
      [28,'000 000 ','Operation timed out','INCONCLUSIVE'],
    ]) {
      d.state.probe=(a,cb)=>cb(exit?Object.assign(new Error('failed'),{code:exit}):null,stdout,stderr);
      const r=await client.probe(d.adapter,c,'proxy',{...target,hostname,port:80},{proxy,strictPolicy:true,expected:'DENY'});
      assert.equal(r.actual,expected);assert.equal(r.complete,expected==='DENY');
    }
  }
});
test('same-origin redirect requires actual full response chain and final URL',async()=>{
  const d=mockDocker(),c=await provision(d),final='http://fixture.test:8080/health';
  const headers=`HTTP/1.1 302 Found\r\nLocation: ${final}\r\n\r\nHTTP/1.1 200 OK\r\n\r\n`;
  for(const [out,err,expected] of [
    [`200 000 172.30.25.3 ${final} 1`,headers,'ALLOW'],
    [`200 000 172.30.25.3 ${final} 1`,headers.replace(final,'http://unauthorized.test:8080/health'),'INCONCLUSIVE'],
    ['200 000 172.30.25.3 http://unauthorized.test:8080/health 1',headers,'INCONCLUSIVE'],
    [`200 000 172.30.25.3 ${final} 0`,headers,'INCONCLUSIVE'],
    [`200 000 172.30.25.3 ${final} 1`,headers.trim(),'INCONCLUSIVE'],
  ]) {
    d.state.probe=(a,cb)=>cb(null,out,err);
    const r=await client.probe(d.adapter,c,'http',target,{proxy,follow:true,sameOrigin:true,path:'/redirect/same'});
    assert.equal(r.actual,expected);assert.equal(r.complete,expected==='ALLOW');
  }
});
test('cross-origin redirect requires the observed chain ending in explicit Squid rejection',async()=>{
  const d=mockDocker(),c=await provision(d),final='http://unauthorized.test:8080/health';
  const headers=`HTTP/1.1 302 Found\r\nLocation: ${final}\r\n\r\nHTTP/1.1 403 Forbidden\r\nServer: squid/6.14\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\n\r\n`;
  for(const [out,err,expected] of [
    [`403 000 172.30.25.3 ${final} 1`,headers,'DENY'],
    [`403 000 172.30.25.3 ${final} 1`,headers.replace('Server: squid/6.14\r\n',''),'INCONCLUSIVE'],
    [`403 000 172.30.25.3 ${final} 1`,headers.replace(final,'http://fixture.test:8080/health'),'INCONCLUSIVE'],
  ]) {
    d.state.probe=(a,cb)=>cb(null,out,err);
    const r=await client.probe(d.adapter,c,'http',target,{proxy,follow:true,crossOrigin:true,path:'/redirect/host'});
    assert.equal(r.actual,expected);assert.equal(r.complete,expected==='DENY');
  }
});

test('TCP diagnostics retain actual native output privately and expose only failed predicates and fingerprints',async()=>{
  const diag=require('../services/tcpDiagnostic'),{failureReport}=require('../scripts/dast-acceptance');
  const fs=require('fs/promises'),path=require('path');
  const {verifyNetworkText}=require('../services/runtimeNetworkText'),text=require('./helpers/busyboxNetwork');
  const d=mockDocker(),c=await provision(d),routeEvidence=verifyNetworkText(text,d.refs[0],d.state.clientNetworks['cs-scanner']);
  for(const [code,stdout,stderr,actual,category] of [
    [1,'','nc: network is unreachable','DENY','NETWORK_UNREACHABLE'],
    [1,'','','INCONCLUSIVE','EMPTY'],
    [0,'','','ALLOW','EMPTY'],
    [1,'','nc: timed out','INCONCLUSIVE','TIMEOUT'],
    [1,'unexpected','nc: network is unreachable','INCONCLUSIVE','NETWORK_UNREACHABLE'],
    [1,'','nc: network is unreachable\0','INCONCLUSIVE','NETWORK_UNREACHABLE'],
    [1,'','nc: network is unreachable'+'x'.repeat(5000),'INCONCLUSIVE','NETWORK_UNREACHABLE'],
    [127,'','nc: not found','INCONCLUSIVE','EXECUTION_ERROR'],
    [1,'','nc: unknown failure password=do-not-expose','INCONCLUSIVE','UNRECOGNIZED'],
  ]) {
    d.state.probe=(a,cb)=>cb(code?Object.assign(new Error('command failed'),{code}):null,stdout,stderr);
    const r=await client.probe(d.adapter,c,'tcp',target,{routeEvidence});
    assert.equal(r.actual,actual);const summary=diag.diagnostic(r);assert.equal(summary.exitCode,code);assert.equal(summary.errorCategory,category);
    assert.deepEqual(summary.command,['nc','-n','-v','-z','-w','5',target.ip,String(target.port)]);
    assert.equal(summary.predicates.routeMatches,true);
    assert.ok(!JSON.stringify(summary).includes('do-not-expose'));
    const file=await diag.save(r,'tcp-test');
    try {
      assert.equal((await fs.stat(file)).mode&0o777,0o600);assert.equal((await fs.stat(path.dirname(file))).mode&0o777,0o700);
      const saved=JSON.parse(await fs.readFile(file,'utf8'));
      assert.equal(saved.stdout.bytes,Buffer.byteLength(stdout));assert.ok(!JSON.stringify(saved).includes('do-not-expose'));
      const error={code:'PROBE_INCONCLUSIVE',probe:r,probes:[r],diagnosticFile:file};
      const report=failureReport(error);assert.deepEqual(report.tcpDiagnostic,summary);assert.equal(report.diagnosticFile,file);
      assert.equal('stderrText' in report.tcpDiagnostic,false);
      assert.ok(!JSON.stringify(report).includes('do-not-expose'));
    } finally {await fs.rm(path.dirname(file),{recursive:true,force:true});}
    assert.equal(diag.diagnostic({...r}),undefined,'caller-provided clones cannot supply trusted capture');
  }
});
test('TCP adapter timeout preserves missing-output diagnostics without inventing a command exit',async()=>{
  const d=mockDocker(),c=await provision(d),original=d.adapter.run.bind(d.adapter);
  d.adapter.run=async args=>{if(args[0]==='exec'&&args[2]==='nc')throw new (require('../services/dockerAdapter').DockerAdapterError)('TIMEOUT','timed out');return original(args);};
  const r=await client.probe(d.adapter,c,'tcp',target);
  assert.equal(r.actual,'INCONCLUSIVE');assert.equal(r.complete,false);
  const summary=require('../services/tcpDiagnostic').diagnostic(r);
  assert.equal(summary.exitCode,null);assert.equal(summary.stdout.category,'MISSING');assert.equal(summary.stderr.category,'MISSING');
  assert.equal(summary.adapterError,'TIMEOUT');assert.equal(summary.predicates.nativeOutputPresent,false);
});
test('sanitized adapter fallback is never substituted for missing native TCP output',async()=>{
  const d=mockDocker(),c=await provision(d),original=d.adapter.run.bind(d.adapter);
  d.adapter.run=async args=>{if(args[0]==='exec'&&args[2]==='nc')throw new (require('../services/dockerAdapter').DockerAdapterError)('DOCKER_COMMAND_FAILED','failed',{exitCode:1,commandStdout:'',commandStderr:'nc: network is unreachable'});return original(args);};
  const {verifyNetworkText}=require('../services/runtimeNetworkText');
  const routeEvidence=verifyNetworkText(require('./helpers/busyboxNetwork'),d.refs[0],d.state.clientNetworks['cs-scanner']);
  const r=await client.probe(d.adapter,c,'tcp',target,{routeEvidence});assert.equal(r.actual,'INCONCLUSIVE');
  const summary=require('../services/tcpDiagnostic').diagnostic(r);
  assert.equal(summary.stdout.category,'MISSING');assert.equal(summary.stderr.category,'MISSING');assert.equal(summary.predicates.nativeOutputPresent,false);
});

test('numeric verbose nc flags are supported by genuine saved pinned-image help',()=>{
  const fixture=require('./fixtures/nginx-nc-help-41d2bf36.json');
  assert.equal(fixture.image,client.IMAGE);assert.equal(fixture.exitCode,1);
  for(const flag of ['-n','-v','-z','-w'])assert.ok(fixture.stderr.includes('\t'+flag+'\t') || fixture.stderr.includes('\t'+flag+' '));
  const command=client.buildProbeCommand('tcp',target);
  assert.deepEqual(command,['nc','-n','-v','-z','-w','5',target.ip,String(target.port)]);
});
test('verbose numeric TCP preserves fail-closed verdicts and exact endpoint-bound route evidence',async()=>{
  const d=mockDocker(),c=await provision(d),{verifyNetworkText}=require('../services/runtimeNetworkText');
  const routeEvidence=verifyNetworkText(require('./helpers/busyboxNetwork'),d.refs[0],d.state.clientNetworks['cs-scanner']);
  // Mocked examples exercise predicates, not claimed captured verbose formats.
  for(const [code,stderr,actual] of [[1,'nc: network is unreachable','DENY'],[1,'','INCONCLUSIVE'],[1,'nc: connection refused','INCONCLUSIVE'],[1,'nc: timed out','INCONCLUSIVE'],[2,'nc: unsupported option','ERROR'],[0,'','ALLOW'],[1,'unrecognized verbose failure','INCONCLUSIVE']]) {
    d.state.probe=(args,cb)=>{assert.deepEqual(args.slice(2),['nc','-n','-v','-z','-w','5',target.ip,String(target.port)]);cb(code?Object.assign(new Error('command'),{code}):null,'',stderr);};
    const r=await client.probe(d.adapter,c,'tcp',target,{routeEvidence});assert.equal(r.actual,actual);
    if(actual==='DENY')assert.equal((await client.probe(d.adapter,c,'tcp',target,{routeEvidence:{...routeEvidence}})).actual,'INCONCLUSIVE');
  }
});
test('TCP private snapshot redacts sensitive values and rejects oversized observations',async()=>{
  const d=mockDocker(),c=await provision(d),diag=require('../services/tcpDiagnostic'),fs=require('fs/promises'),path=require('path');
  d.state.probe=(a,cb)=>cb(Object.assign(new Error('failed'),{code:1}),'','password=private-value');
  const probe=await client.probe(d.adapter,c,'tcp',target);
  const file=await diag.save(probe,'redaction',{token:'hidden-token',raw:'authorization: hidden-auth'});
  try {const data=await fs.readFile(file,'utf8');for(const value of ['private-value','hidden-token','hidden-auth'])assert.ok(!data.includes(value));}
  finally {await fs.rm(path.dirname(file),{recursive:true,force:true});}
  await assert.rejects(diag.save(probe,'bounded',{raw:'x'.repeat(16385)}),{code:'DIAGNOSTIC_WRITE_FAILED'});
});
