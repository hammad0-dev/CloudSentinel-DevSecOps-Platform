"use strict";
const { DockerAdapter, sanitizeDiagnostic } = require('../services/dockerAdapter');
const { OwnedDockerNetworks } = require('../services/ownedDockerNetworks');
const { SecureGatewayLifecycle } = require('../services/dastGateway');
const { RuntimeObservation } = require('../services/runtimeObservation');
const policy = require('../services/squidPolicy');
const { execFile } = require('child_process');
const { promisify } = require('util');
const readCommand = promisify(execFile);

async function observeEnvironment(execute = readCommand) {
  const read = async (bin, args) => (await execute(bin, args, { shell: false, timeout: 10000, maxBuffer: 2 * 1024 * 1024 })).stdout;
  const ids = (await read('docker', ['network', 'ls', '--quiet'])).trim().split(/\s+/).filter(Boolean);
  if (ids.some(id => !/^[a-f0-9]{12,64}$/i.test(id))) throw new Error('invalid Docker network inventory');
  const networks = ids.length ? JSON.parse(await read('docker', ['network', 'inspect', ...ids])) : [];
  if (!Array.isArray(networks) || networks.some(n=>typeof n.Name!=='string' || !n.Name)) throw new Error('missing Docker network names');
  const routes = JSON.parse(await read('ip', ['-j', '-4', 'route', 'show', 'table', 'all']));
  if (!Array.isArray(networks) || networks.length !== ids.length || !Array.isArray(routes)) throw new Error('incomplete allocation evidence');
  const usedSubnets = networks.flatMap((n, index) => {
    if (typeof n.Id !== 'string' || !n.Id.startsWith(ids[index])) throw new Error('network inventory identity mismatch');
    if (!n.IPAM || !Array.isArray(n.IPAM.Config ?? [])) throw new Error('invalid Docker IPAM inventory');
    return (n.IPAM.Config || []).map(c => {
      if (!c || typeof c.Subnet !== 'string') throw new Error('missing Docker subnet evidence');
      return c.Subnet;
    }).filter(s => !s.includes(':'));
  });
  const hostRoutes = routes.map(r => r.dst).filter(dst => dst !== 'default');
  if (hostRoutes.some(dst => typeof dst !== 'string')) throw new Error('invalid host route inventory');
  return { usedSubnets, hostRoutes, existingNames: networks.map(n=>n.Name), complete: true };
}

function validate(input) {
  require('../services/acceptanceNames').validateNames(input);
  if (input?.nativeConnect !== undefined && typeof input.nativeConnect !== 'boolean') throw new Error('invalid native CONNECT opt-in');
  if (input?.mode !== undefined && !['full','connect-diagnostic','tcp-diagnostic'].includes(input.mode)) throw new Error('unsupported acceptance mode');
  if (!input || !/^[-a-z0-9_.]+$/i.test(String(input.projectId || '')) || !/^[-a-z0-9_.]+$/i.test(String(input.executionId || '')) || !/^[-a-z0-9_.]+$/i.test(String(input.scanId || ''))) throw new Error('unsafe scan identity');
  if (!input.target || !/^[a-z0-9.-]+$/i.test(String(input.target.hostname || '')) || !Number.isInteger(input.target.port) || input.target.port < 1 || input.target.port > 65535) throw new Error('unsafe disposable target');
}
function createLifecycle() {
  const adapter = new DockerAdapter();
  const networks = new OwnedDockerNetworks({ adapter, observe: observeEnvironment });
  const observation = new RuntimeObservation({ adapter });
  return new SecureGatewayLifecycle({ adapter, networks, policyService: policy, observation });
}
async function runAcceptance(input, lifecycle = createLifecycle()) {
  validate(input);
  if (process.env.DAST_ACTIVE_ENABLED !== 'false') throw new Error('DAST_ACTIVE_ENABLED must be false');
  let failure;
  try {
    const result = await lifecycle.provision(input);
    if (['connect-diagnostic','tcp-diagnostic'].includes(input.mode) && (result?.mode !== input.mode || result.diagnosticOnly !== true || result.fullContainment !== false || result.state !== 'DIAGNOSTIC_COMPLETE')) throw Object.assign(new Error('diagnostic cannot establish full containment'), { code: 'INVALID_DIAGNOSTIC' });
    return result;
  }
  catch (e) { failure = e; throw e; }
  finally {
    let cleanup;
    try { cleanup = await lifecycle.cleanup(input.scanId); }
    catch (cleanupError) {
      cleanup = { cleaned: false, residual: [{ type: 'lifecycle', error: sanitizeDiagnostic(cleanupError.code || 'CLEANUP_FAILED') }] };
    }
    if (!Array.isArray(cleanup?.residual) || (!cleanup.residual.length && cleanup.cleaned !== true && cleanup.state !== 'CLEANED')) cleanup = { cleaned: false, residual: [{ type: 'lifecycle', error: 'CLEANUP_UNVERIFIED' }] };
    if (cleanup?.residual?.length) {
      if (failure) failure.cleanup = cleanup;
      else throw Object.assign(new Error('acceptance cleanup left owned resources'), { code: 'CLEANUP_FAILED', cleanup });
    }
  }
}
function failureReport(error) {
  const cleanCode = value => /^[A-Z][A-Z0-9_]{0,63}$/.test(String(value || '')) ? value : 'ACCEPTANCE_ERROR';
  const d = error.networkDiagnostic;
  const summary = value => ({ category: ['MISSING', 'EMPTY', 'TEXT', 'NUL_CONTAINING'].includes(value?.category) ? value.category : 'MISSING',
    ...(Number.isSafeInteger(value?.bytes) && value.bytes >= 0 ? { bytes: value.bytes } : {}),
    ...(Number.isSafeInteger(value?.lines) && value.lines >= 0 ? { lines: value.lines } : {}),
    ...(/^[a-f0-9]{64}$/.test(value?.sha256 || '') ? { sha256: value.sha256 } : {}) });
  const networkDiagnostic = d && ['ipv4', 'ipv6', 'addresses'].includes(d.observation) ? {
    observation: d.observation, validationRule: cleanCode(d.validationRule),
    command: require('../services/runtimeObservation').NETWORK_COMMANDS[d.observation],
    exitCode: Number.isInteger(d.exitCode) ? d.exitCode : null,
    stdout: summary(d.stdout), stderr: summary(d.stderr),
  } : null;
  const connectSummary = value => value ? {
    ...Object.fromEntries(['requestMatches','responseComplete','responseWellFormed','squidServer','accessDenied','noRedirect','expectedDenial','gatewayIdentity','proxyPeerMatches','statusConsistent','curlRemoteIpPresent','curlRemoteIpMatches','observedPeerMatches','socketPeerObserved','socketPeerMatches','socketPrecedesConnect','expectedGatewayNetworkIdMatches','expectedGatewayContainerIdMatches'].map(key => [key, value[key] === true])),
    observedPeerSource: ['CURL_REMOTE_IP','CURL_VERBOSE_SOCKET','CURL_REMOTE_IP_AND_VERBOSE_SOCKET'].includes(value.observedPeerSource) ? value.observedPeerSource : 'NONE',
    peerEvidenceStatus: ['MATCH','MISSING','MISMATCH','MALFORMED'].includes(value.peerEvidenceStatus) ? value.peerEvidenceStatus : 'MALFORMED',
    ...(Number.isSafeInteger(value.outputBytes) && value.outputBytes >= 0 ? { outputBytes: value.outputBytes } : {}),
    ...(/^[a-f0-9]{64}$/.test(value.outputSha256 || '') ? { outputSha256: value.outputSha256 } : {}),
  } : undefined;
  const probes = (error.probes || []).map(p => ({ name: sanitizeDiagnostic(p.name), actual: p.actual, expected: p.expected, complete: p.complete === true, exitCode: Number.isInteger(p.exitCode) ? p.exitCode : null, evidenceType: sanitizeDiagnostic(p.evidenceType), httpStatus: p.httpStatus ?? null, connectStatus: p.connectStatus ?? null, ...(p.connectEvidence ? { connectEvidence: connectSummary(p.connectEvidence) } : {}) }));
  const tcpDiagnostic = require('../services/tcpDiagnostic').diagnostic(error.probe);
  return { code: cleanCode(error.code), message: 'Containment acceptance failed.', diagnostic: sanitizeDiagnostic(error.stderrExcerpt || ''), networkDiagnostic, probes, ...(tcpDiagnostic?{tcpDiagnostic,diagnosticFile:typeof error.diagnosticFile==='string'?sanitizeDiagnostic(error.diagnosticFile,512):null}:{}), cleanup: error.cleanup ? { cleaned: error.cleanup.cleaned === true || error.cleanup.state === 'CLEANED', residual: (error.cleanup.residual || []).map(r => ({ id: /^[a-f0-9]{12,64}$/i.test(r.id || '') ? r.id : null, type: sanitizeDiagnostic(r.type || ''), error: sanitizeDiagnostic(r.error || r.reason || 'CLEANUP_FAILED') })) } : null };
}
if (require.main === module) {
  const input = { nativeConnect: process.env.CS_ACCEPT_NATIVE_CONNECT === undefined ? undefined : process.env.CS_ACCEPT_NATIVE_CONNECT === 'true' ? true : process.env.CS_ACCEPT_NATIVE_CONNECT === 'false' ? false : 'INVALID', mode: process.env.CS_ACCEPT_MODE, projectId: process.env.CS_ACCEPT_PROJECT, executionId: process.env.CS_ACCEPT_EXECUTION, scanId: process.env.CS_ACCEPT_SCAN, target: { hostname: process.env.CS_ACCEPT_HOST, port: Number(process.env.CS_ACCEPT_PORT) } };
  runAcceptance(input).then(r => { process.stdout.write(JSON.stringify(r)); if (r.diagnosticOnly && (!r.complete || r.actual !== 'DENY')) process.exitCode = 2; }).catch(e => { process.stderr.write(JSON.stringify(failureReport(e))); process.exitCode = 1; });
}
module.exports = { validate, createLifecycle, runAcceptance, observeEnvironment, failureReport };
