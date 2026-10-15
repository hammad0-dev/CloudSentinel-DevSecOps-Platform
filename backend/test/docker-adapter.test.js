"use strict";const assert=require("node:assert/strict"),test=require("node:test"),{DockerAdapter,DockerAdapterError,normalizeInspect}=require("../services/dockerAdapter");
const valid={Id:"abcdef1234567890",Name:"/owned",Config:{Labels:{"cloudsentinel.owner":"x"},Image:"ubuntu/squid@sha256:x"},State:{Status:"running"},Mounts:[],NetworkSettings:{Networks:{}},HostConfig:{Privileged:false,CapAdd:[]}};
test('failed-command native streams remain private and retain complete header framing',async()=>{
  const {commandOutput}=require('../services/dockerAdapter');
  const stderr='HTTP/1.1 403 Forbidden\r\nX-Test: '+ 'a'.repeat(5000)+'\r\nAuthorization: token=private-value\r\n\r\n';
  const adapter=new DockerAdapter({executor:(b,a,o,cb)=>cb(Object.assign(new Error('curl failure'),{code:56}),'000 403 172.30.25.3',stderr)});
  await assert.rejects(adapter.run(['exec','1'.repeat(64),'curl']),error=>{
    assert.deepEqual(commandOutput(error),{stdout:'000 403 172.30.25.3',stderr});
    assert.ok(!error.commandStderr.includes('\n'));assert.ok(error.commandStderr.length<=4096);
    assert.ok(!JSON.stringify(error).includes('private-value'));return true;
  });
  assert.equal(commandOutput(new Error('forged')),undefined);
});
test("injected executors, subclasses and replaced methods cannot claim native runtime provenance",()=>{
  const {isRuntimeAdapter}=require("../services/dockerAdapter");
  const native=new DockerAdapter();assert.equal(isRuntimeAdapter(native),true);
  assert.equal(isRuntimeAdapter(new DockerAdapter({executor:()=>{}})),false);
  class Fake extends DockerAdapter { run(){return Promise.resolve({exitCode:0});} }
  assert.equal(isRuntimeAdapter(new Fake()),false);
  native.run=()=>Promise.resolve({exitCode:0});assert.equal(isRuntimeAdapter(native),false);
});
test("adapter executes strict arrays with typed result",async()=>{const a=new DockerAdapter({executor:(bin,args,opt,cb)=>{assert.equal(bin,"docker");assert.equal(opt.shell,false);cb(null,"ok","");}});const r=await a.run(["inspect","x"]);assert.equal(r.exitCode,0);assert.ok(r.operationId);});
test("rejects unsafe operations and arguments",async()=>{const a=new DockerAdapter({executor:()=>{throw Error("must not run")}});assert.throws(()=>a.run(["network","ls"]),/allowlisted/);assert.throws(()=>a.run(["run","--privileged"]),/Unsafe Docker argument rejected/);});
test("normalizes valid inspect JSON",async()=>{const a=new DockerAdapter({executor:(b,args,o,cb)=>cb(null,JSON.stringify(valid),"")});const r=await a.inspect(["owned"]);assert.equal(r.normalized.objectId,valid.Id);assert.equal(r.normalized.labels["cloudsentinel.owner"],"x");});
test("rejects malformed and missing inspect fields",async()=>{for(const v of ["{",JSON.stringify({...valid,Id:"bad"}),JSON.stringify({...valid,Config:undefined})]){const a=new DockerAdapter({executor:(b,args,o,cb)=>cb(null,v,"")});await assert.rejects(()=>a.inspect(["owned"]),/Missing|Invalid|JSON/);}});
test("classifies command errors, permission, daemon and timeout",async()=>{for(const [err,msg] of [[Object.assign(Error("x"),{code:1}),/failed/],[Object.assign(Error("x"),{code:1}),/permission/],[Object.assign(Error("docker daemon"),{code:1}),/daemon/],[Object.assign(Error("timeout"),{code:"ETIMEDOUT"}),/timed out/]]){const a=new DockerAdapter({executor:(b,args,o,cb)=>cb(err,"",msg.test?msg.source:"permission denied")});await assert.rejects(()=>a.run(["inspect","x"]));}});
test("executor timeout is bounded",async()=>{const a=new DockerAdapter({timeoutMs:100,executor:()=>{}});await assert.rejects(()=>a.run(["inspect","x"]),e=>e.code==="TIMEOUT");});
test("preserves sanitized failure diagnostics",async()=>{const a=new DockerAdapter({executor:(b,args,o,cb)=>cb(Object.assign(Error("permission denied token=abc"),{code:13}),"", "permission denied token=abc /tmp/secret")});await assert.rejects(()=>a.run(["network","create","/tmp/secret"]),e=>e.code==="PERMISSION_DENIED"&&e.operation==="network"&&e.subcommand==="create"&&e.exitCode===13&&e.stderrExcerpt.length<=240&&!e.stderrExcerpt.includes("abc")&&!e.stderrExcerpt.includes("/tmp/secret"));});
test("OS spawn failures cannot be returned as successful Docker commands",async()=>{
  const adapter=new DockerAdapter({executor:(b,a,o,cb)=>cb(Object.assign(new Error('spawn token=abc'),{code:'ENOENT'}),'','')});
  await assert.rejects(adapter.run(['inspect','owned']),e=>e.exitCode===null&&e.code==='DOCKER_COMMAND_FAILED'&&!e.message.includes('abc'));
});
test("synchronous failures and command metadata are sanitized",async()=>{
  const adapter=new DockerAdapter({executor:()=>{throw new Error('password=abc');}});
  await assert.rejects(adapter.run(['inspect','owned']),e=>!e.message.includes('abc'));
  const output=new DockerAdapter({executor:(b,a,o,cb)=>cb(Object.assign(new Error('fail'),{code:1}),'token=abc','password=def')});
  // Random UUIDs can coincidentally contain these hexadecimal test secrets.
  // Check the diagnostic payload rather than treating the UUID as leaked text.
  await assert.rejects(output.run(['exec','owned','nc']),e=>{
    const {operationId,...diagnostic}=e;
    return typeof operationId==='string'&&!JSON.stringify(diagnostic).includes('abc')&&!JSON.stringify(diagnostic).includes('def');
  });
});
test("nc network rejection remains a command result, not a Docker daemon error",async()=>{
  const adapter=new DockerAdapter({executor:(b,a,o,cb)=>cb(Object.assign(new Error('nc'),{code:1}),'','nc: cannot connect: Network unreachable')});
  await assert.rejects(adapter.run(['exec','owned','nc']),{code:'DOCKER_COMMAND_FAILED',exitCode:1});
});

const network = {
  Name: "cs-net-17-accept-fixture", Id: "b".repeat(64),
  Created: "2026-10-14T08:00:00Z", Scope: "local", Driver: "bridge",
  EnableIPv6: false, Internal: true, Attachable: false, Ingress: false,
  IPAM: { Driver: "default", Options: null, Config: [{ Subnet: "172.30.25.0/28", Gateway: "172.30.25.1" }] },
  Labels: { "cloudsentinel.owner": "cloudsentinel-accept", "cloudsentinel.scan": "accept" },
  Options: {}, Containers: { ["c".repeat(64)]: { Name: "cs-fixture-accept", EndpointID: "d".repeat(64), MacAddress: "02:42:ac:1e:19:02", IPv4Address: "172.30.25.2/28", IPv6Address: "" } },
};
test("network inspection uses typed Docker command and preserves genuine evidence", async () => {
  for (const raw of [network, [network]]) {
    const a = new DockerAdapter({ executor: (bin, args, options, callback) => {
      assert.equal(bin, "docker"); assert.equal(options.shell, false);
      assert.deepEqual(args, ["network", "inspect", "--format", "{{json .}}", network.Id]);
      callback(null, JSON.stringify(raw), "");
    } });
    const r = await a.inspect([network.Id], "network");
    const n = r.normalized;
    assert.equal(n.objectType, "network"); assert.equal(n.objectId, network.Id); assert.equal(n.id, network.Id);
    assert.equal(n.name, network.Name); assert.equal(n.driver, "bridge");
    assert.equal(n.internal, true); assert.equal(n.ipv6, false);
    assert.equal(n.subnet, "172.30.25.0/28"); assert.equal(n.gateway, "172.30.25.1");
    assert.deepEqual(n.labels, network.Labels); assert.deepEqual(n.ipam, network.IPAM);
    assert.deepEqual(n.containers, network.Containers); assert.deepEqual(n.containerIds, Object.keys(network.Containers));
    const { parseNetwork, verifyNetwork } = require("../services/ownedDockerNetworks");
    const parsed = parseNetwork(r.stdout);
    assert.equal(verifyNetwork({ ...n, scanIdentity: { scanId: "accept" } }, n).verified, true);
    for (const key of ["id", "name", "driver", "internal", "ipv6", "subnet", "gateway", "labels", "containerIds"]) assert.deepEqual(n[key], parsed[key]);
    assert.equal(n.complete, true);
  }
});
test("network normalization preserves false settings and absent container listings", () => {
  const n = normalizeInspect({ ...network, Internal: false, EnableIPv6: true, Containers: undefined }, "network");
  assert.equal(n.internal, false); assert.equal(n.ipv6, true); assert.deepEqual(n.containerIds, []);
});
test("rejects missing or malformed network identity, settings, labels and IPAM", () => {
  const variants = [null, [], { Id: "bad" }, { Id: "b".repeat(12) }, { Name: "bad name" },
    { Driver: undefined }, { Internal: undefined }, { Internal: "true" }, { EnableIPv6: undefined }, { EnableIPv6: "false" },
    { Labels: null }, { Labels: [] }, { Labels: { owner: 17 } },
    { IPAM: undefined }, { IPAM: { Config: [] } }, { IPAM: { Config: [{}] } },
    { Containers: [] }, { Containers: { bad: {} } }, { Options: { "com.docker.network.enable_ipv6": "true" } },
  ];
  for (const v of variants) assert.throws(() => normalizeInspect(v === null || Array.isArray(v) ? v : { ...network, ...v }, "network"), { code: "MALFORMED_OUTPUT" });
  for (const config of [
    { Subnet: "172.30.25.16/28", Gateway: "172.30.25.1" },
    { Subnet: "172.30.25.0/28", Gateway: "172.30.25.0" },
    { Subnet: "172.30.25.0/28", Gateway: "172.30.25.15" },
    { Subnet: "172.30.25.2/28", Gateway: "172.30.25.3" },
    { Subnet: "172.300.25.0/28", Gateway: "172.30.25.1" },
    { Subnet: "172.30.25.0/33", Gateway: "172.30.25.1" },
    { Subnet: "172.30.25.0/28", Gateway: undefined },
  ]) assert.throws(() => normalizeInspect({ ...network, IPAM: { Config: [config] } }, "network"), { code: "MALFORMED_OUTPUT" });
});
test("inspection rejects empty or ambiguous responses and unsupported kinds", async () => {
  for (const raw of [[], [network, network], "bad-json"]) {
    const a = new DockerAdapter({ executor: (bin, args, options, cb) => cb(null, typeof raw === "string" ? raw : JSON.stringify(raw), "") });
    await assert.rejects(a.inspect([network.Id], "network"), { code: "MALFORMED_OUTPUT" });
  }
  const a = new DockerAdapter({ executor: () => assert.fail("must not execute") });
  await assert.rejects(a.inspect([network.Id], "volume"), { code: "INVALID_OPERATION" });
});
test('image inspection allowlist permits immutable metadata only, never image mutation',()=>{
  const {operation}=require('../services/dockerAdapter');
  assert.deepEqual(operation(['image','inspect','zap/test@sha256:'+'a'.repeat(64)]),['image','inspect','zap/test@sha256:'+'a'.repeat(64)]);
  for(const args of [['image','pull','zap/test'],['image','rm','zap/test'],['image','inspect','zap/test:latest'],['image','inspect','zap/test@sha256:'+'a'.repeat(64),'extra']])assert.throws(()=>operation(args),{code:'INVALID_OPERATION'});
});
