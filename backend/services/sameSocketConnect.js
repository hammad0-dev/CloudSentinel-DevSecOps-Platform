"use strict";
// Acceptance-only opt-in; this single probe never establishes full containment.
const clientService = require('./dastAcceptanceClient');
const { inspectOwnedNetwork, verifyMemberships } = require('./ownedDockerNetworks');
const EXECUTABLE = '/opt/cloudsentinel/connect-peer';
const { isIP } = require('net');

async function observeSameSocketConnect(adapter, client, { gatewayId, networkReferences, target }) {
  await clientService.verifyClient(adapter, client);
  await clientService.verifyNativeDelivery(adapter, client);
  if (!/^[a-f0-9]{64}$/i.test(gatewayId || '') || !Array.isArray(networkReferences) || networkReferences.length !== 2) throw Object.assign(new Error('owned gateway/network references required'), { code: 'INVALID_IDENTITY' });
  if (!target || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(target.hostname || '') || target.hostname.length > 253 || !Number.isInteger(target.port) || target.port < 1 || target.port > 65535) throw Object.assign(new Error('invalid CONNECT authority'), { code: 'INVALID_PROBE' });
  const networks = await Promise.all(networkReferences.map(ref => inspectOwnedNetwork(adapter, ref)));
  const gateway = (await adapter.inspect([gatewayId], 'container')).normalized;
  verifyMemberships(gateway, networks);
  const endpoint = gateway.networks?.[client.networkName];
  if (gateway.objectId !== gatewayId || gateway.labels?.['cloudsentinel.owner'] !== client.owner || gateway.labels?.['cloudsentinel.role'] !== 'gateway' || gateway.imageDigest !== require('./dastGateway').IMAGE || gateway.state?.Running !== true || endpoint?.NetworkID !== client.networkId || isIP(endpoint?.IPAddress || '') !== 4 || gateway.security?.privileged !== false || gateway.security?.networkMode === 'host' || gateway.security?.capAdd?.length || gateway.mounts?.some(m => String(m.Source).includes('docker.sock'))) throw Object.assign(new Error('gateway identity mismatch'), { code: 'OWNERSHIP_MISMATCH' });
  const authority = `${target.hostname}:${target.port}`;
  let command;
  try { command = await clientService.execute(adapter, client, [EXECUTABLE, endpoint.IPAddress, '3128', authority]); }
  catch (error) {
    const native = require('./dockerAdapter').commandOutput(error);
    command = { exitCode: error.exitCode ?? null, stdout: native?.stdout ?? '', stderr: native?.stderr ?? '' };
  }
  let evidence;
  try { if (typeof command.stdout !== 'string' || Buffer.byteLength(command.stdout) > 4096) throw new Error(); evidence = JSON.parse(command.stdout); if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) throw new Error(); }
  catch (_) { return { kind:'connect',sourceId:client.id,exitCode:Number.isInteger(command.exitCode)?command.exitCode:null,actual: 'INCONCLUSIVE', complete: false, fullContainment: false, verification: 'EXPERIMENTAL_NOT_ACCEPTANCE', reason: 'MALFORMED_CLIENT_OUTPUT', nativeEvidence:{error:'MALFORMED_CLIENT_OUTPUT',gatewayContainerId:gateway.objectId,gatewayNetworkId:client.networkId} }; }
  const peerMatches = evidence.peerIp === endpoint.IPAddress && evidence.peerPort === 3128;
  const coherent = command.stderr === '' && evidence.schemaVersion === 1 && evidence.connected === true && peerMatches && evidence.requestedAuthority === authority && evidence.headersValid === true;
  const complete = coherent && command.exitCode === 0 && evidence.responseStatus === 403 && evidence.squidServer === true && evidence.accessDenied === true && evidence.error === null && evidence.complete === true;
  const allowed = coherent && command.exitCode === 1 && evidence.responseStatus === 200 && evidence.accessDenied === false && evidence.complete === false && evidence.error === 'UNEXPECTED_TUNNEL';
  return { kind:'connect', sourceId:client.id, actual: complete ? 'DENY' : allowed ? 'ALLOW' : 'INCONCLUSIVE', complete, fullContainment: false, verification: 'EXPERIMENTAL_NOT_ACCEPTANCE', peerMatches, exitCode: command.exitCode, connectStatus:Number.isInteger(evidence.responseStatus) ? evidence.responseStatus : null, responseStatus: Number.isInteger(evidence.responseStatus) ? evidence.responseStatus : null,
    evidenceType: complete ? 'native-same-socket-squid-policy' : 'execution-failure',
    nativeEvidence: { peerIp: isIP(evidence.peerIp || '') === 4 ? evidence.peerIp : null, peerPort:Number.isInteger(evidence.peerPort) && evidence.peerPort>0 && evidence.peerPort<=65535 ? evidence.peerPort : null, requestedAuthority:evidence.requestedAuthority===authority ? evidence.requestedAuthority : null, authorityMatches:evidence.requestedAuthority===authority, headersValid:evidence.headersValid===true, squidServer:evidence.squidServer===true, accessDenied:evidence.accessDenied===true, connected:evidence.connected===true, error:/^[A-Z_]{1,64}$/.test(evidence.error||'') ? evidence.error : null, gatewayContainerId:gateway.objectId, gatewayNetworkId:client.networkId } };
}
module.exports = { EXECUTABLE, observeSameSocketConnect };
