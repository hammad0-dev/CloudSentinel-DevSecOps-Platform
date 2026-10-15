"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { OwnedDockerNetworks, parseNetwork, verifyNetwork, subnetFor } = require("../services/ownedDockerNetworks");

const scan = { projectId: "12", executionId: "20", scanId: "scan-1" };
function fakeAdapter() {
  const objects = new Map(); let n = 0; const calls = [];
  return { calls, async run(args) { calls.push(args); if (args[0] === "network" && args[1] === "create") { const id = ("a".repeat(63 - String(++n).length) + n); const name = args.at(-1); const subnet = args[args.indexOf("--subnet") + 1]; const gateway = args[args.indexOf("--gateway") + 1]; const labels = {}; for (let i = 0; i < args.length; i++) if (args[i] === "--label") { const [k, v] = args[i + 1].split("="); labels[k] = v; } objects.set(id, { Id: id, Name: name, Labels: labels, Driver: "bridge", Internal: true, EnableIPv6: false, IPAM: { Config: [{ Subnet: subnet, Gateway: gateway }] }, Containers: {}, Options: {} }); return { objectId: id, stdout: id }; } if (args[0] === "inspect") return { stdout: JSON.stringify(objects.get(args.at(-1))) }; if (args[0] === "network" && args[1] === "rm") { objects.delete(args[2]); return { stdout: "" }; } return { stdout: "" }; } };
}
test("selects private IPv4 subnets and rejects overlap evidence", () => { const s = subnetFor({ hash: "abcdef" }, []); assert.match(s.subnet, /^172\.30\./); assert.throws(() => subnetFor({ hash: "abcdef" }, [s.subnet]), /overlaps/); });
test("creates two owned internal IPv4-only networks and verifies fresh inspect", async () => { const adapter = fakeAdapter(); const svc = new OwnedDockerNetworks({ adapter }); const result = await svc.create(scan); assert.equal(result.networks.length, 2); for (const n of result.networks) { assert.equal(n.internal, true); assert.equal(n.ipv6, false); assert.equal(n.provenance, "trusted-docker-inspect"); } assert.equal(adapter.calls.filter(x => x[1] === "create").length, 2); });
test("fails closed on incomplete subnet/route evidence", async () => { const svc = new OwnedDockerNetworks({ adapter: fakeAdapter(), observe: async () => ({ complete: false }) }); await assert.rejects(svc.create(scan), { code: "EVIDENCE_INCOMPLETE" }); });
test("rejects malformed or foreign network observations", () => { assert.throws(() => parseNetwork("{}"), /network identity/); const ref = { id: "a".repeat(64), name: "safe", labels: { "cloudsentinel.owner": "x", "cloudsentinel.scan": "scan-1" }, scanIdentity: { scanId: "scan-1" }, subnet: "172.30.1.0/28", gateway: "172.30.1.1" }; const obs = { ...ref, labels: { "cloudsentinel.owner": "foreign", "cloudsentinel.scan": "scan-1" }, ipv6: false, internal: true }; assert.equal(verifyNetwork(ref, obs).verified, false); });
test("cleanup re-inspects exact IDs and refuses mismatched ownership", async () => { const adapter = fakeAdapter(); const svc = new OwnedDockerNetworks({ adapter }); const result = await svc.create(scan); const original = adapter.run; adapter.run = async args => { if (args[0] === "inspect") { const r = await original(args); const v = JSON.parse(r.stdout); v.Labels["cloudsentinel.owner"] = "foreign"; return { stdout: JSON.stringify(v) }; } return original(args); }; const cleaned = await svc.cleanup("scan-1"); assert.equal(cleaned.cleaned, false); assert.equal(cleaned.residual.length, 2); assert.equal(adapter.calls.filter(x => x[1] === "rm").length, 0); });

const { DockerAdapter } = require("../services/dockerAdapter");
const numericIp = ip => ip.split(".").reduce((n, octet) => n * 256 + Number(octet), 0);
test("all 4096 /28 blocks have aligned subnets and an in-subnet gateway", () => {
  const seen = new Set();
  for (let offset = 0; offset < 4096; offset++) {
    const { subnet, gateway } = subnetFor({ hash: offset.toString(16).padStart(6, "0") });
    const base = numericIp(subnet.split("/")[0]);
    assert.equal(base % 16, 0);
    assert.equal(numericIp(gateway), base + 1);
    seen.add(subnet);
  }
  assert.equal(seen.size, 4096);
  assert.deepEqual(subnetFor({ hash: "000190" }), { subnet: "172.30.25.0/28", gateway: "172.30.25.1" });
  assert.deepEqual(subnetFor({ hash: "000191" }), { subnet: "172.30.25.16/28", gateway: "172.30.25.17" });
});
test("detects broad, narrow and noncanonical overlaps while allowing adjacent blocks", () => {
  const candidate = { hash: "000191" };
  for (const conflict of ["172.30.0.0/16", "172.16.0.0/12", "172.30.25.16/28", "172.30.25.23/32", "172.30.25.23/24"]) {
    assert.throws(() => subnetFor(candidate, [conflict]), { code: "SUBNET_CONFLICT" });
  }
  assert.doesNotThrow(() => subnetFor(candidate, ["172.30.25.0/28", "172.30.25.32/28", "192.168.240.0/20"]));
  for (const invalid of [null, {}, "bad", "172.30.0.0/33", "172.300.0.0/16"]) {
    assert.throws(() => subnetFor(candidate, [invalid]), { code: "EVIDENCE_INCOMPLETE" });
  }
});
test("DockerAdapter forwards consistent IPAM arguments without invoking Docker", async () => {
  const fake = fakeAdapter();
  const adapter = new DockerAdapter({ executor: (bin, args, options, callback) => {
    assert.equal(options.shell, false);
    fake.run(args).then(result => callback(null, result.stdout, ""), callback);
  } });
  const service = new OwnedDockerNetworks({ adapter });
  const result = await service.create(scan);
  for (const args of fake.calls.filter(args => args[1] === "create")) {
    const base = numericIp(args[args.indexOf("--subnet") + 1].split("/")[0]);
    assert.equal(numericIp(args[args.indexOf("--gateway") + 1]), base + 1);
  }
  assert.equal(new Set(result.networks.map(network => network.subnet)).size, 2);
  assert.equal((await service.cleanup(scan.scanId)).cleaned, true);
  assert.equal(fake.calls.filter(args => args[0] === "network" && args[1] === "rm").length, 2);
});
test("Docker allocation and WSL route conflicts prevent create", async () => {
  for (const field of ["usedSubnets", "hostRoutes"]) {
    const adapter = fakeAdapter();
    const service = new OwnedDockerNetworks({ adapter, observe: async () => ({ usedSubnets: [], hostRoutes: [], [field]: ["172.30.0.0/16"] }) });
    await assert.rejects(service.create(scan), { code: "SUBNET_CONFLICT" });
    assert.equal(adapter.calls.length, 0);
  }
});
test("cleanup failure retains only residual networks and supports retry", async () => {
  const adapter = fakeAdapter(), original = adapter.run;
  const service = new OwnedDockerNetworks({ adapter });
  const result = await service.create(scan);
  const failedId = result.networks[1].id;
  adapter.run = async args => {
    if (args[1] === "rm" && args[2] === failedId) throw Object.assign(new Error("busy"), { code: "BUSY" });
    return original(args);
  };
  const cleanup = await service.cleanup(scan.scanId);
  assert.deepEqual(cleanup, { cleaned: false, residual: [{ id: failedId, reason: "BUSY" }] });
  assert.equal(service.active.get(scan.scanId).resources.length, 1);
  adapter.run = original;
  assert.equal((await service.cleanup(scan.scanId)).cleaned, true);
});
test("inspect failure after create tracks the resource and exposes rollback failure", async () => {
  const adapter = fakeAdapter(), original = adapter.run;
  let failInspect = true;
  adapter.run = async args => {
    if (args[0] === "inspect" && failInspect) { failInspect = false; throw new Error("inspect failed"); }
    if (args[1] === "rm") throw Object.assign(new Error("busy"), { code: "BUSY" });
    return original(args);
  };
  const service = new OwnedDockerNetworks({ adapter });
  await assert.rejects(service.create(scan), err => err.message === "inspect failed" && err.cleanup.cleaned === false && err.cleanup.residual[0].reason === "BUSY");
  assert.equal(service.active.get(scan.scanId).resources.length, 1);
  adapter.run = original;
  assert.equal((await service.cleanup(scan.scanId)).cleaned, true);
});

test("rejects malformed allocation hashes instead of producing invalid IPAM", () => {
  for (const input of [undefined, {}, { hash: "" }, { hash: "xyz123" }, { hash: "00019" }]) {
    assert.throws(() => subnetFor(input), { code: "INVALID_IDENTITY" });
  }
});
test("overlong derived names are hashed with full identity labels and safe cleanup",async()=>{
  const adapter=fakeAdapter(),service=new OwnedDockerNetworks({adapter});
  const result=await service.create({...scan,projectId:'p'.repeat(63)});
  assert.ok(result.networks.every(n=>n.name.length<=63 && n.labels['cloudsentinel.project']==='p'.repeat(63)));
  await assert.rejects(service.create({...scan,projectId:'p'.repeat(63)}),{code:'DUPLICATE_SCAN'});
  assert.equal((await service.cleanup(scan.scanId)).cleaned,true);
});
test('name boundaries preserve short names and hash distinct long identities deterministically',()=>{
  const {names}=require('../services/ownedDockerNetworks'),{containerName,validateNames}=require('../services/acceptanceNames');
  const i={projectId:'p',executionId:'e',scanId:'s'.repeat(31),hash:'a'.repeat(12)};
  assert.equal(names(i,'scanner').length,63);
  const long={...i,scanId:i.scanId+'s'};
  assert.equal(names(long,'scanner'),names(long,'scanner'));
  assert.notEqual(names(long,'scanner'),names({...long,scanId:long.scanId+'x'},'scanner'));
  assert.ok(names(long,'scanner').length<=63);
  assert.equal(containerName('s'.repeat(52),'fixture').length,63);
  assert.ok(containerName('s'.repeat(63),'fixture').length<=63);
  for(const scanId of ['../bad','A','s'.repeat(64),''])assert.throws(()=>validateNames({...scan,scanId}),{code:'INVALID_ID'});
});
test('duplicate roles fail before any network is created',async()=>{
  const adapter=fakeAdapter(),service=new OwnedDockerNetworks({adapter});
  await assert.rejects(service.create(scan,{roles:['scanner','scanner']}),{code:'INVALID_ROLE'});
  assert.equal(adapter.calls.length,0);
});
test('an observed colliding name fails without removing the existing network',async()=>{
  const adapter=fakeAdapter();let service;
  service=new OwnedDockerNetworks({adapter,observe:async()=>({usedSubnets:[],hostRoutes:[],existingNames:[require('../services/ownedDockerNetworks').names(service.active.get(scan.scanId).identity,'scanner')]})});
  await assert.rejects(service.create(scan),{code:'NAME_CONFLICT'});
  assert.equal(adapter.calls.length,0);
});
test("inspect rejects the reported gateway paired with a different /28 block", () => {
  const raw = { Id: "a".repeat(64), Name: "owned-test", Labels: {}, IPAM: { Config: [] } };
  for (const [subnet, gateway] of [
    ["172.30.25.16/28", "172.30.25.1"],
    ["172.30.25.16/28", "172.30.25.16"],
    ["172.30.25.16/28", "172.30.25.31"],
    ["172.30.25.16/28", "172.30.25.17/32"],
    ["172.30.25.16/28", "172.300.25.17"],
    ["172.30.25.16", "172.30.25.17"],
  ]) {
    raw.IPAM.Config = [{ Subnet: subnet, Gateway: gateway }];
    assert.throws(() => parseNetwork(raw), { code: "MALFORMED_OUTPUT" });
  }
  raw.IPAM.Config = [{ Subnet: "172.30.25.0/28", Gateway: "172.30.25.1" }];
  assert.equal(parseNetwork(raw).gateway, "172.30.25.1");
});
