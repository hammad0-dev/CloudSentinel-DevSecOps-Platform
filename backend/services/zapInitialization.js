'use strict';

const manifest = require('../config/active-zap-image-manifest.json');
const writable = require('../config/zap-writable-paths.json');
const {isIP}=require('node:net');
const crypto=require('node:crypto');
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

function profileTmpfs() {
  return `${writable.profilePath}:rw,noexec,nosuid,nodev,size=${writable.profileMiB}m,uid=1000,gid=1000,mode=0700`;
}

function profileBootstrapArguments() {
  // O_EXCL/O_NOFOLLOW preserve ownership and reject stale or substituted files.
  // Each argument remains below the Docker adapter's 512-byte limit.
  const code="import os,sys,base64,hashlib;p,n,b,h=sys.argv[1:];d=base64.b64decode(b,validate=True);assert hashlib.sha256(d).hexdigest()==h;s=os.lstat(p);assert s.st_uid==s.st_gid==1000 and s.st_mode&511==448;fd=os.open(p,os.O_DIRECTORY|os.O_NOFOLLOW);f=os.open(n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,384,dir_fd=fd);w=os.fdopen(f,'wb');w.write(d);w.close();os.close(fd)";
  return ['python3','-I','-c',code,writable.profilePath,writable.profileSeed.name,writable.profileSeed.base64,writable.profileSeed.sha256];
}

function jvmProperties() {
  return `-Xmx${STORAGE.javaHeapMiB}m -Djava.util.prefs.userRoot=${writable.javaPreferencesRoot}\n`;
}

function jvmBootstrapArguments() {
  const bytes=Buffer.from(jvmProperties());
  const code=profileBootstrapArguments()[3];
  return ['python3','-I','-c',code,writable.javaPreferencesRoot,writable.jvmPropertiesName,
    bytes.toString('base64'),crypto.createHash('sha256').update(bytes).digest('hex')];
}

// Pure argument generation. A future approved diagnostic must use this contract;
// this module never creates a container or starts a daemon.
function diagnosticStorageArguments() {
  return ['--network', 'none', '--read-only', '--user', '1000:1000', '--memory', `${STORAGE.memoryMiB}m`,
    '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=1777',
    '--tmpfs', homeTmpfs(),
    '--tmpfs', '/zap/wrk:rw,noexec,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=0700',
    '--tmpfs', profileTmpfs()];
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
      ![(384+writable.profileMiB) * MiB, (512+writable.profileMiB) * MiB].includes(observed.totalTmpfsLimitBytes) ||
      observed.totalTmpfsLimitBytes + observed.javaMaxHeapBytes + 448 * MiB > observed.memoryLimitBytes) {
    throw fail('ZAP_STORAGE_NOT_READY');
  }
  const p=observed.profile,j=observed.javaPreferences;
  if(!p || p.path!==writable.profilePath || p.capacityBytes!==writable.profileMiB*MiB || p.uid!==1000 || p.gid!==1000 ||
      p.mode!=='0700' || p.writable!==true || p.seedSha256!==writable.profileSeed.sha256 || p.seedMode!=='0600')throw fail('ZAP_PROFILE_NOT_READY');
  if(!j || j.rootProperty!==writable.javaPreferencesRoot || j.path!==writable.javaPreferencesEffectivePath || j.uid!==1000 ||
      j.gid!==1000 || j.mode!=='0700' || j.writable!==true)throw fail('ZAP_PREFERENCES_NOT_READY');
  return true;
}

function startupFailure(stdout, stderr = '') {
  return require('./zapStartupLog').analyze(`${stdout||''}\n${stderr||''}`).failure;
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
  if (failure) throw fail(failure==='ZAP_STARTUP_LOG_UNVERIFIED'?'ZAP_INITIALIZATION_INCOMPLETE':failure);
  if (!/Extensions loaded/.test(evidence.startupLog) || !/ZAP is now listening on 127\.0\.0\.1:/.test(evidence.startupLog)) {
    throw fail('ZAP_INITIALIZATION_INCOMPLETE');
  }
  assertStorage(evidence.storage);
  assertListeners(evidence.listeners);
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

function assertListeners(observed) {
  if(!observed || observed.complete!==true || observed.tcpComplete!==true || observed.tcp6Complete!==true || observed.errorCode ||
      !Array.isArray(observed.listeners) || !observed.listeners.length)throw fail('ZAP_LISTENERS_UNVERIFIED');
  for(const listener of observed.listeners){
    const family=isIP(listener.address);
    if(!['IPv4','IPv6'].includes(listener.family) || !family || !Number.isInteger(listener.port) || listener.port<1 || listener.port>65535 ||
       !(family===4 ? listener.address.startsWith('127.') : listener.address==='::1'))throw fail('ZAP_NON_LOOPBACK_LISTENER');
    const width=listener.family==='IPv4'?8:32;
    if(typeof listener.nativeAddress!=='string' || !new RegExp(`^[a-fA-F0-9]{${width}}$`).test(listener.nativeAddress))throw fail('ZAP_LISTENERS_UNVERIFIED');
    const native=Buffer.from(listener.nativeAddress,'hex');
    const decoded=listener.family==='IPv4'?Buffer.from(native).reverse():Buffer.concat([0,4,8,12].map(i=>Buffer.from(native.subarray(i,i+4)).reverse()));
    const address=listener.family==='IPv4'?Array.from(decoded).join('.'):
      decoded.subarray(0,12).equals(Buffer.from('00000000000000000000ffff','hex'))?Array.from(decoded.subarray(12)).join('.'):
      decoded.equals(Buffer.from('00000000000000000000000000000001','hex'))?'::1':null;
    if(address!==listener.address)throw fail('ZAP_LISTENERS_UNVERIFIED');
  }
  if(!observed.listeners.some(listener=>listener.port===8090))throw fail('ZAP_API_LISTENER_MISSING');
  return true;
}

module.exports = { STORAGE, expectedAddons, homeTmpfs, profileTmpfs, profileBootstrapArguments, jvmBootstrapArguments,jvmProperties,
  diagnosticStorageArguments, assertStorage, startupFailure, assertInitialized, assertListeners };
