"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),f=require("../services/dastFixture");
const target={host:"fixture.allowed.test",port:8080,unauthorizedHost:"bad.test",unauthorizedIp:"10.0.0.9",unauthorizedPort:8081,scanId:"s1",networkId:"net1",filePath:"/tmp/nginx.conf"};
test("generates scoped redirect fixture config",()=>{const c=f.nginxConfig(target);assert.match(c,/listen 8080/);assert.match(c,/redirect\/same/);assert.match(c,/169\.254\.169\.254/);});
test("rejects invalid fixture config",()=>assert.throws(()=>f.stage({...target,port:0}),(e) => e.message.includes("invalid fixture")));
test("provisions and verifies immutable identity",async()=>{const id="a".repeat(64);const a={calls:[],async run(x){this.calls.push(x);return {objectId:id};},async inspect(args,kind){if(kind==="network")return {normalized:{id:"net1",name:"net1",subnet:"172.30.0.0/28",gateway:"172.30.0.1",labels:{}}};return {normalized:{objectId:id,imageDigest:f.IMAGE,labels:{"cloudsentinel.owner":"cloudsentinel-s1","cloudsentinel.role":"fixture"},mounts:[{Type:"bind",Source:this.calls[0][this.calls[0].indexOf("--mount")+1].split(",")[1].slice(4),Destination:"/etc/nginx/nginx.conf",RW:false}],networks:{net1:{NetworkID:"net1",IPAddress:"172.30.0.2"}}}};}};const r=await f.provision(a,target);assert.equal(r.id,id);assert.ok(a.calls[0].includes("--read-only"));});
test("rejects identity mismatch",async()=>{const id="a".repeat(64);const a={async run(){return {objectId:id};},async inspect(){return {normalized:{objectId:id,imageDigest:"wrong",labels:{}}};}};await assert.rejects(()=>f.provision(a,target),(e) => e.message.includes("identity evidence"));});
test("cleanup is ownership verified",async()=>{const id="a".repeat(64);const a={async inspect(){return {normalized:{objectId:id,labels:{"cloudsentinel.owner":"other","cloudsentinel.role":"fixture"}}};}};await assert.rejects(()=>f.cleanup(a,{id,owner:"cloudsentinel-s1"}),(e) => e.message.includes("unowned cleanup"));});

test("real adapter network normalization reaches fixture IPv4 verification", async () => {
  const { DockerAdapter } = require("../services/dockerAdapter");
  const containerId = "a".repeat(64), networkId = "b".repeat(64);
  const calls = [];
  const adapter = new DockerAdapter({ executor: (bin, args, options, cb) => {
    calls.push(args); assert.equal(options.shell, false);
    if (args[0] === "run") return cb(null, containerId, "");
    if (args[0] === "network") return cb(null, JSON.stringify({
      Id: networkId, Name: "cs-fixture-net", Driver: "bridge", Internal: true,
      EnableIPv6: false, Labels: { "cloudsentinel.owner": "cloudsentinel-s1", "cloudsentinel.scan": "s1" },
      IPAM: { Driver: "default", Options: null, Config: [{ Subnet: "172.30.25.0/28", Gateway: "172.30.25.1" }] },
      Containers: { [containerId]: { Name: "cs-fixture-s1", IPv4Address: "172.30.25.2/28" } }, Options: {},
    }), "");
    cb(null, JSON.stringify({ Id: containerId, Name: "/cs-fixture-s1",
      Mounts: [{ Type: "bind", Source: calls.find(a=>a[0]==="run")[calls.find(a=>a[0]==="run").indexOf("--mount")+1].split(",")[1].slice(4), Destination: "/etc/nginx/nginx.conf", RW: false }],
      Config: { Image: f.IMAGE, Labels: { "cloudsentinel.owner": "cloudsentinel-s1", "cloudsentinel.role": "fixture" } },
      NetworkSettings: { Networks: { "cs-fixture-net": { NetworkID: networkId, IPAddress: "172.30.25.2" } } },
    }), "");
  } });
  const resource = await f.provision(adapter, { ...target, networkId });
  try {
    assert.equal(resource.ip, "172.30.25.2");
    const args = calls.find(a => a[0] === "run");
    assert.equal(args[args.indexOf("--mount") + 1], resource.staged.mount);
    assert.equal(args.filter(a => a === "--mount").length, 1);
    assert.equal(args[args.indexOf("--user") + 1], `${process.getuid()}:${process.getgid()}`);
    assert.equal(args[args.indexOf("--entrypoint") + 1], "/usr/sbin/nginx");
    assert.equal(args[args.indexOf(f.IMAGE) + 1], "-g");
    assert.ok(args.includes("--pull=never"));
    assert.ok(args.includes("/tmp:rw,noexec,nosuid,size=16m,mode=1777"));
    assert.ok(!args.includes("STAGED_POLICY"));
    await f.verifyArtifact(resource.staged);
    assert.equal(resource.networkId, networkId);
    assert.ok(calls.some(args => args[0] === "network" && args[1] === "inspect" && args.at(-1) === networkId));
  } finally { await f.cleanupArtifact(resource.staged); }
});

test("artifact verification rejects tampering, wrong modes, ownership and mount destinations", async () => {
  const fs = require("fs/promises");
  const artifact = await f.stageOwned(target);
  try {
    await f.verifyArtifact(artifact);
    await assert.rejects(f.verifyArtifact({ ...artifact, containerPath: "/tmp/wrong" }), { code: "ARTIFACT_INVALID" });
    await assert.rejects(f.verifyArtifact({ ...artifact, ownership: { owned: true, scanId: "foreign" } }), { code: "ARTIFACT_INVALID" });
    await fs.chmod(artifact.filePath, 0o644);
    await assert.rejects(f.verifyArtifact(artifact), { code: "ARTIFACT_INVALID" });
    await fs.chmod(artifact.filePath, 0o600);
    await fs.writeFile(artifact.filePath, "tampered");
    await assert.rejects(f.verifyArtifact(artifact), { code: "ARTIFACT_TAMPERED" });
  } finally { await f.cleanupArtifact(artifact); }
});

test("writable or substituted observed configuration mounts fail fixture verification", async () => {
  for (const rw of [true, false]) {
    const id="a".repeat(64); let artifact;
    const adapter={ async run(){return {objectId:id};}, async inspect(){return {normalized:{objectId:id,imageDigest:f.IMAGE,labels:{"cloudsentinel.owner":"cloudsentinel-s1","cloudsentinel.role":"fixture"},mounts:[{Type:"bind",Source:rw?artifact.filePath:"/tmp/foreign",Destination:artifact.containerPath,RW:rw}]}};} };
    try { await assert.rejects(f.provision(adapter,{...target,onStaged:s=>{artifact=s;}}),{code:"MOUNT_MISMATCH"}); }
    finally { if(artifact)await f.cleanupArtifact(artifact); }
  }
});
