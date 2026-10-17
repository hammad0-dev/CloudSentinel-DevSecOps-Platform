"use strict";

const fs = require("fs/promises");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const CONTAINER_CONFIG_PATH = "/etc/squid/cloudsentinel/squid.conf";
const SAFE_HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const SAFE_IPV4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const SAFE_ID = /^[a-z0-9][a-z0-9_.-]{0,62}$/;

class SquidPolicyError extends Error {
  constructor(code, message, meta = {}) {
    super(message);
    this.name = "SquidPolicyError";
    this.code = code;
    Object.assign(this, meta);
  }
}

function reject(code, message) {
  throw new SquidPolicyError(code, message);
}

function validateTarget(target) {
  if (!target || typeof target !== "object") reject("INVALID_TARGET", "fixture target is required");
  const hostname = String(target.hostname || "").toLowerCase();
  const ip = String(target.ip || "");
  const port = target.port;
  if (!SAFE_HOST.test(hostname) || hostname.includes("..")) reject("INVALID_HOSTNAME", "invalid fixture hostname");
  if (!SAFE_IPV4.test(ip)) reject("INVALID_IP", "invalid fixture IPv4 address");
  if (!Number.isInteger(port) || port < 1 || port > 65535) reject("INVALID_PORT", "invalid fixture port");
  return Object.freeze({ hostname, ip, port });
}

function canonicalPolicy(target) {
  const t = validateTarget(target);
  // Keep this representation deterministic.  CONNECT is explicitly denied before
  // the positive rule; Squid therefore cannot tunnel to an unapproved destination.
  return [
    "# CloudSentinel Squid policy v1",
    "http_port 3128",
    "acl cloudsentinel_connect method CONNECT",
    "acl cloudsentinel_host dstdomain " + t.hostname,
    "acl cloudsentinel_ip dst " + t.ip + "/32",
    "acl cloudsentinel_port port " + t.port,
    "http_access deny cloudsentinel_connect",
    "http_access allow cloudsentinel_host cloudsentinel_ip cloudsentinel_port",
    "http_access deny all",
    "cache deny all",
    "",
  ].join("\n");
}

function digest(bytes) {
  return "sha256:" + crypto.createHash("sha256").update(bytes, "utf8").digest("hex");
}
function activePolicy(target) {
  const t=validateTarget(target);
  if(!/^[a-z0-9-]+\.test$/.test(t.hostname)||!/^172\.30\./.test(t.ip)||t.port!==18080)reject('ACTIVE_SCOPE_BLOCKED','invalid disposable Active origin');
  return ['# CloudSentinel Active route policy v1','http_port 3128',
    // Correlation requires the exact nonce-bearing query. Squid's default strips
    // it before logging; this policy is restricted to the synthetic fixture.
    'strip_query_terms off',
    'logformat cs_active %ts.%03tu %>a %rm %ru %>Hs %Ss/%Sh',
    'access_log stdio:/tmp/cloudsentinel-active-access.log cs_active',
    'buffered_logs off','logfile_rotate 0',
    'acl connect method CONNECT',`acl host dstdomain ${t.hostname}`,`acl destination dst ${t.ip}/32`,`acl port port ${t.port}`,
    'acl protocol proto HTTP','acl methods method GET POST',
    'acl paths urlpath_regex ^/test/(sqli|xss)([?][^#]*)?$',
    'http_access deny connect','http_access allow host destination port protocol methods paths','http_access deny all','cache deny all',''].join('\n');
}

function validateScanId(scanId) {
  if (!SAFE_ID.test(String(scanId || ""))) reject("INVALID_SCAN_ID", "invalid scan identity");
  return String(scanId);
}

async function stagePolicy({ scanId, target, profile = 'containment', baseDir = os.tmpdir(), fsImpl = fs } = {}) {
  const safeScanId = validateScanId(scanId);
  if(!['containment','active'].includes(profile))reject('INVALID_POLICY','unknown policy profile');
  const policy = profile==='active'?activePolicy(target):canonicalPolicy(target);
  const policyDigest = digest(policy);
  const directory = await fsImpl.mkdtemp(path.join(baseDir, `cloudsentinel-squid-${safeScanId}-`));
  try {
    await fsImpl.chmod(directory, 0o700);
    const filePath = path.join(directory, "squid.conf");
    await fsImpl.writeFile(filePath, policy, { encoding: "utf8", mode: 0o600, flag: "wx" });
    await fsImpl.chmod(filePath, 0o600);
    return {
      scanId: safeScanId,
      target: validateTarget(target),
      policy,
      policyDigest,
      directory,
      filePath,
      containerPath: CONTAINER_CONFIG_PATH,
      mount: `${filePath}:${CONTAINER_CONFIG_PATH}:ro`,
      ownership: { directory, filePath, owned: true },
      runtimeActivation: "UNVERIFIED",
    };
  } catch (err) {
    try { await fsImpl.rm(directory, { recursive: true, force: true }); } catch (_) { /* report original failure */ }
    if (err instanceof SquidPolicyError) throw err;
    throw new SquidPolicyError("STAGING_FAILED", "unable to stage Squid policy", { cause: err.message });
  }
}

async function verifyStagedPolicy(staged, { fsImpl = fs } = {}) {
  if (!staged || staged.ownership?.owned !== true || typeof staged.filePath !== "string") reject("INVALID_STAGE", "invalid staged policy");
  let bytes;
  try { bytes = await fsImpl.readFile(staged.filePath, "utf8"); } catch (_) { reject("POLICY_MISSING", "staged policy is unavailable"); }
  const actual = digest(bytes);
  if (actual !== staged.policyDigest || bytes !== staged.policy) reject("POLICY_TAMPERED", "staged policy digest or bytes mismatch");
  if (staged.mount !== `${staged.filePath}:${CONTAINER_CONFIG_PATH}:ro`) reject("INVALID_MOUNT", "policy mount is not read-only or uses wrong path");
  return { verified: true, policyDigest: actual, bytes, containerPath: CONTAINER_CONFIG_PATH, runtimeActivation: "UNVERIFIED" };
}

async function cleanupPolicy(staged, { fsImpl = fs } = {}) {
  if (!staged?.ownership?.owned || !staged.directory || !staged.filePath) reject("CLEANUP_UNOWNED", "refusing unowned policy cleanup");
  const failures = [];
  for (const target of [staged.filePath, staged.directory]) {
    try { await fsImpl.rm(target, { recursive: target === staged.directory, force: true }); }
    catch (err) { failures.push({ path: target, error: err.message }); }
  }
  if (failures.length) throw new SquidPolicyError("CLEANUP_FAILED", "policy cleanup left residual files", { failures });
  return { cleaned: true, residual: [] };
}

function runtimeVerificationContract({ staged, observedConfigPath, observedDigest, processReady } = {}) {
  if (!staged) reject("RUNTIME_UNVERIFIED", "staged policy is required");
  const verified = processReady === true && observedConfigPath === CONTAINER_CONFIG_PATH && observedDigest === staged.policyDigest;
  return { verified, runtimeActivation: verified ? "VERIFIED" : "UNVERIFIED", reason: verified ? null : "independent Squid process/config evidence required" };
}

module.exports = { CONTAINER_CONFIG_PATH, SquidPolicyError, validateTarget, canonicalPolicy, activePolicy, digest, stagePolicy, verifyStagedPolicy, cleanupPolicy, runtimeVerificationContract };
