'use strict';

const manifest = require('../config/active-zap-image-manifest.json');
const MiB = 1024 * 1024;
const STORAGE = Object.freeze({ homeMiB: 256, temporaryMiB: 256, diagnosticTemporaryMiB: 64,
  diagnosticWorkMiB: 64, memoryMiB: 1536, javaHeapMiB: 512, uid: 1000, gid: 1000 });
const expectedAddons = Object.freeze(Object.fromEntries(Object.entries({
  ...manifest.selection, ...manifest.dependencyResolution.transitiveEvidence,
}).map(([name, item]) => [name, item.version])));
const fail = code => Object.assign(new Error(code), { code, nonRetryable: true });

function homeTmpfs() {
  return `/home/zap/.ZAP:rw,noexec,nosuid,nodev,size=${STORAGE.homeMiB}m,uid=1000,gid=1000,mode=0700`;
}

// Pure argument generation. A future approved diagnostic must use this contract;
// this module never creates a container or starts a daemon.
function diagnosticStorageArguments() {
  return ['--network', 'none', '--read-only', '--user', '1000:1000', '--memory', `${STORAGE.memoryMiB}m`,
    '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=1777',
    '--tmpfs', homeTmpfs(),
    '--tmpfs', '/zap/wrk:rw,noexec,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=0700'];
}

function assertStorage(observed) {
  if (!observed || observed.homeWritable !== true || observed.uid !== 1000 || observed.gid !== 1000 ||
      observed.mode !== '0700' || observed.readOnlyRootfs !== true ||
      !Number.isSafeInteger(observed.homeCapacityBytes) || observed.homeCapacityBytes !== STORAGE.homeMiB * MiB ||
      !Number.isSafeInteger(observed.homeAvailableBytes) || observed.homeAvailableBytes < 32 * MiB ||
      observed.homeAvailableBytes > observed.homeCapacityBytes ||
      observed.memoryLimitBytes !== STORAGE.memoryMiB * MiB ||
      !Number.isSafeInteger(observed.javaMaxHeapBytes) || observed.javaMaxHeapBytes <= 0 ||
      observed.javaMaxHeapBytes > STORAGE.javaHeapMiB * MiB ||
      ![384 * MiB, 512 * MiB].includes(observed.totalTmpfsLimitBytes) ||
      observed.totalTmpfsLimitBytes + observed.javaMaxHeapBytes + 448 * MiB > observed.memoryLimitBytes) {
    throw fail('ZAP_STORAGE_NOT_READY');
  }
  return true;
}

function startupFailure(stdout, stderr = '') {
  const text = `${stdout || ''}\n${stderr || ''}`;
  if (/No space left on device|\bENOSPC\b|Disk quota exceeded/i.test(text)) return 'ZAP_STORAGE_EXHAUSTED';
  if (/Premature end of file|SAXParseException|Error parsing.*\.policy|Broken JBroFuzz Installation/i.test(text)) return 'ZAP_INITIALIZATION_CORRUPT';
  if (/\bERROR\b|Failed to install|Failed to initialise|Failed to initialize|Unable to save the configuration|Exception/i.test(text)) return 'ZAP_INITIALIZATION_FAILED';
  return null;
}

function normalizedVersion(value) {
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)(\.(0|[1-9]\d*)){0,2}$/.test(value)) return null;
  return value.split('.').concat(['0', '0']).slice(0, 3).join('.');
}

function assertInitialized(evidence, imageId) {
  if (!evidence || evidence.imageId !== imageId || evidence.version !== '2.17.0' || evidence.complete !== true ||
      evidence.extensionsLoaded !== true || evidence.observationExitCode !== 0 ||
      evidence.logsComplete !== true || evidence.logsTruncated !== false ||
      typeof evidence.startupLog !== 'string' || !evidence.startupLog.trim() ||
      Buffer.byteLength(evidence.startupLog) > 1048576) throw fail('ZAP_INITIALIZATION_INCOMPLETE');
  const failure = startupFailure(evidence.startupLog);
  if (failure) throw fail(failure);
  if (!/Extensions loaded/.test(evidence.startupLog) || !/ZAP is now listening on 127\.0\.0\.1:/.test(evidence.startupLog)) {
    throw fail('ZAP_INITIALIZATION_INCOMPLETE');
  }
  assertStorage(evidence.storage);
  const policy = evidence.policy;
  // These fields must be collected from the actual complete policy file and
  // genuine policy/scanner API response; a version response is insufficient.
  if (!policy || policy.name !== 'Default Policy' || policy.xmlParsed !== true ||
      policy.apiLoaded !== true || policy.complete !== true || !Number.isSafeInteger(policy.bytes) || policy.bytes < 1 ||
      !/^[a-f0-9]{64}$/.test(policy.sha256 || '')) throw fail('ZAP_POLICY_NOT_INITIALIZED');
  if (!Array.isArray(evidence.installedAddons) || !Array.isArray(evidence.loadedAddonIds)) throw fail('ZAP_ADDONS_NOT_INITIALIZED');
  for (const [id, version] of Object.entries(expectedAddons)) {
    const matches = evidence.installedAddons.filter(addon => addon?.id === id);
    if (matches.length !== 1 || matches[0].installationStatus !== 'INSTALLED' ||
        normalizedVersion(matches[0].version) !== normalizedVersion(version) ||
        evidence.loadedAddonIds.filter(name => name === id).length !== 1) throw fail('ZAP_ADDONS_NOT_INITIALIZED');
  }
  if (!Array.isArray(evidence.activeRuleIds) || manifest.requiredPluginIds.some(id => !evidence.activeRuleIds.includes(id))) {
    throw fail('ZAP_REQUIRED_RULES_MISSING');
  }
  return true;
}

module.exports = { STORAGE, expectedAddons, homeTmpfs, diagnosticStorageArguments, assertStorage, startupFailure, assertInitialized };
