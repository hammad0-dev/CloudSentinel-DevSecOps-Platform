"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs/promises");
const os = require("os");
const path = require("path");
const {
  CONTAINER_CONFIG_PATH, canonicalPolicy, digest, stagePolicy, verifyStagedPolicy,
  cleanupPolicy, runtimeVerificationContract,
} = require("../services/squidPolicy");

const target = { hostname: "fixture.allowed.test", ip: "192.0.2.10", port: 8080 };

test("generates deterministic exact allowlist and denies CONNECT/all", () => {
  const policy = canonicalPolicy(target);
  assert.match(policy, /dstdomain fixture\.allowed\.test/);
  assert.match(policy, /dst 192\.0\.2\.10\/32/);
  assert.match(policy, /port 8080/);
  assert.match(policy, /http_access deny cloudsentinel_connect/);
  assert.match(policy, /http_access deny all/);
  assert.equal(digest(policy), digest(canonicalPolicy(target)));
  assert.doesNotMatch(policy, /\r|\0/);
});

test("rejects malformed targets and policy injection", async () => {
  assert.throws(() => canonicalPolicy({ ...target, hostname: "ok.test\nhttp_access allow all" }), /invalid fixture hostname/);
  assert.throws(() => canonicalPolicy({ ...target, ip: "192.0.2.999" }), /invalid fixture IPv4/);
  assert.throws(() => canonicalPolicy({ ...target, port: 0 }), /invalid fixture port/);
  await assert.rejects(stagePolicy({ scanId: "bad/id", target }), { code: "INVALID_SCAN_ID" });
});

test("stages privately, verifies bytes/digest/mount, and detects tampering", async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), "cs-policy-test-"));
  const staged = await stagePolicy({ scanId: "scan-1", target, baseDir: base });
  const dirMode = (await fs.stat(staged.directory)).mode & 0o777;
  const fileMode = (await fs.stat(staged.filePath)).mode & 0o777;
  // UNC/Windows mounts do not expose POSIX mode bits; exact checks run on Linux.\n  if (process.platform !== "win32") {\n    assert.equal(dirMode, 0o700); assert.equal(fileMode, 0o600);\n  }
  assert.equal(staged.containerPath, CONTAINER_CONFIG_PATH);
  assert.equal((await verifyStagedPolicy(staged)).verified, true);
  await fs.appendFile(staged.filePath, "# tamper\n");
  await assert.rejects(verifyStagedPolicy(staged), { code: "POLICY_TAMPERED" });
  await fs.rm(base, { recursive: true, force: true });
});

test("supports concurrent scan staging and ownership-safe cleanup", async () => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), "cs-policy-concurrent-"));
  const [a, b] = await Promise.all([
    stagePolicy({ scanId: "scan-a", target, baseDir: base }),
    stagePolicy({ scanId: "scan-b", target, baseDir: base }),
  ]);
  assert.notEqual(a.directory, b.directory);
  await assert.rejects(cleanupPolicy({ ...a, ownership: { ...a.ownership, owned: false } }), { code: "CLEANUP_UNOWNED" });
  assert.deepEqual((await cleanupPolicy(a)).residual, []);
  assert.deepEqual((await cleanupPolicy(b)).residual, []);
  await fs.rm(base, { recursive: true, force: true });
});

test("never treats staged files as runtime activation", () => {
  const staged = { policyDigest: digest(canonicalPolicy(target)) };
  assert.equal(runtimeVerificationContract({ staged, observedConfigPath: CONTAINER_CONFIG_PATH, observedDigest: staged.policyDigest, processReady: false }).verified, false);
  assert.equal(runtimeVerificationContract({ staged, observedConfigPath: CONTAINER_CONFIG_PATH, observedDigest: staged.policyDigest, processReady: true }).verified, true);
  assert.equal(runtimeVerificationContract({ staged, observedConfigPath: "/etc/squid/squid.conf", observedDigest: staged.policyDigest, processReady: true }).verified, false);
});


test("only synthetic Active policy preserves query terms for strict transaction correlation",async()=>{
 const policy=require('../services/squidPolicy');
 const activeTarget={hostname:'fixture.test',ip:'172.30.19.146',port:18080};
 const generated=policy.activePolicy(activeTarget);
 assert.match(generated,/^strip_query_terms off$/m);
 assert.match(generated,/^logformat cs_active %ts\.%03tu %>a %rm %ru %>Hs %Ss\/%Sh$/m);
 assert.match(generated,/^http_access deny connect$/m);
 assert.match(generated,/^http_access allow host destination port protocol methods paths$/m);
 assert.match(generated,/^http_access deny all$/m);
 assert.doesNotMatch(policy.canonicalPolicy(target),/strip_query_terms/);
 const staged=await policy.stagePolicy({scanId:'query-correlation',target:activeTarget,profile:'active'});
 try{assert.equal((await policy.verifyStagedPolicy(staged)).verified,true);assert.equal(staged.policyDigest,policy.digest(generated));}finally{assert.deepEqual((await policy.cleanupPolicy(staged)).residual,[]);}
});
