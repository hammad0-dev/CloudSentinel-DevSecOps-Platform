"use strict";

const clientService = require("./dastAcceptanceClient");
const { inspectOwnedNetwork, verifyMemberships } = require("./ownedDockerNetworks");
const { isRuntimeAdapter } = require("./dockerAdapter");
const { verifyNetworkText } = require("./runtimeNetworkText");
const { createHash } = require("crypto");
const { isIP } = require('net');
const { saveConnectDiagnostic } = require('./connectDiagnostic');
const issuedEvidence = new WeakSet();
const ID = /^[a-f0-9]{12,64}$/i;
const NETWORK_COMMANDS = Object.freeze({ ipv4: Object.freeze(["ip", "route", "list"]), ipv6: Object.freeze(["ip", "-f", "inet6", "route", "list"]), addresses: Object.freeze(["ip", "address", "show"]) });

// Report shape and fingerprints only: native output can contain unrelated
// addresses or even credentials when a command returns unexpected text.
function outputSummary(value) {
  if (typeof value !== "string") return { category: "MISSING" };
  return { category: value.includes("\0") ? "NUL_CONTAINING" : !value.trim() ? "EMPTY" : "TEXT",
    bytes: Buffer.byteLength(value), lines: value.split(/\r?\n/).filter(Boolean).length,
    sha256: createHash("sha256").update(value).digest("hex") };
}
function networkDiagnostic(observation, rule, result = {}) {
  return { observation, validationRule: rule, command: NETWORK_COMMANDS[observation],
    exitCode: Number.isInteger(result.exitCode) ? result.exitCode : null,
    stdout: outputSummary(result.stdout), stderr: outputSummary(result.stderr) };
}

class ObservationError extends Error {
  constructor(code, message, meta = {}) { super(message); this.name = "ObservationError"; this.code = code; Object.assign(this, meta); }
}
const fail = (code, message, meta) => { throw new ObservationError(code, message, meta); };

function json(text, label) { try { return typeof text === "string" ? JSON.parse(text) : text; } catch (_) { fail("MALFORMED_OUTPUT", `${label} output is not JSON`); } }
function inspect(adapter, id, kind) {
  if (!ID.test(String(id || ""))) fail("INVALID_ID", `invalid ${kind} id`);
  return adapter.run(["inspect", "--format", "{{json .}}", String(id)]).then(r => json(r.stdout, `${kind} inspect`));
}
function routeCheck(routes) {
  if (!Array.isArray(routes)) fail("MALFORMED_ROUTES", "route observation is incomplete");
  if (routes.some(r => !r || r.dst === "default" || r.dst === "0.0.0.0/0" || r.dst === "::/0" || r.defaultRoute === true || r.family === 6 || r.ipv6 === true)) fail("UNSAFE_ROUTE", "default or IPv6 route detected");
  return true;
}

class RuntimeObservation {
  constructor({ adapter, probeExecutor } = {}) {
    if (!adapter || typeof adapter.run !== "function") fail("INVALID_ADAPTER", "Docker adapter is required");
    if (probeExecutor !== undefined) fail("INVALID_PROBE", "generic probe executors cannot establish containment");
    this.adapter = adapter;
    this.acceptanceClient = null;
  }
  bindAcceptanceClient(client, resource) {
    if (client !== clientService || !resource?.id) fail("INVALID_PROBE", "trusted acceptance client is required");
    this.acceptanceClient = { client, resource };
  }
  clearAcceptanceClient() { this.acceptanceClient = null; }
  async collectActiveFixture(input) {
    // This verifies the owned acceptance client against Python's exact paths.
    // It is not evidence of the future ZAP container's namespace or scan jobs.
    if(input.projectId===17 || !Number.isSafeInteger(input.projectId)||input.projectId<1||!Number.isSafeInteger(input.executionId)||input.executionId<1)fail('ACTIVE_SCOPE_BLOCKED','disposable execution required');
    if (input.mode && input.mode!=='full') fail('INVALID_MODE','Active fixture requires complete path/isolation checks');
    return this.collect({...input,profile:'active'});
  }
  async collect({ projectId, executionId, scanId, gatewayContainerId, scannerContainerId, scannerNetworkId, fixtureNetworkId, target, stagedPolicy, networkReferences, mode, nativeConnect, beforeProbe, profile='containment' }) {
    if(beforeProbe!==undefined&&typeof beforeProbe!=='function')fail('INVALID_MODE','invalid probe guard');
    beforeProbe?.();
    if(!['containment','active'].includes(profile)) fail('INVALID_MODE','unknown containment profile');
    if(profile==='active' && stagedPolicy?.policy!==require('./squidPolicy').activePolicy(target)) fail('POLICY_NOT_ACTIVE','exact Active path policy required');
    if (nativeConnect !== undefined && typeof nativeConnect !== 'boolean') fail('INVALID_MODE','invalid native opt-in');
    if (mode !== undefined && !['full','connect-diagnostic','tcp-diagnostic'].includes(mode)) fail('INVALID_MODE', 'unsupported acceptance mode');
    if (![projectId, executionId, scanId].every(v => /^[a-z0-9_.-]+$/i.test(String(v)))) fail("INVALID_IDENTITY", "scan identity is invalid");
    if (!stagedPolicy?.policyDigest) fail("MISSING_POLICY", "staged policy digest is required");
    const [gateway, scanner] = await Promise.all([inspect(this.adapter, gatewayContainerId, "gateway"), inspect(this.adapter, scannerContainerId, "scanner")]);
    if (!this.acceptanceClient || this.acceptanceClient.resource.id !== scannerContainerId) fail("INVALID_CLIENT", "bound lifecycle client must be the scanner");
    const verifiedClient=await clientService.verifyClient(this.adapter, this.acceptanceClient.resource);
    const namespace=verifiedClient.namespaceEvidence;
    if(namespace)scanner.NetworkSettings={...scanner.NetworkSettings,Networks:verifiedClient.networks};
    if (!Array.isArray(networkReferences) || networkReferences.length !== 2) fail("INVALID_IDENTITY", "owned network references required");
    const networks = await Promise.all(networkReferences.map(ref => inspectOwnedNetwork(this.adapter, ref)));
    const scannerNetwork = networks.find(n => n.id === scannerNetworkId);
    const fixtureNetwork = networks.find(n => n.id === fixtureNetworkId);
    if (!scannerNetwork || !fixtureNetwork || scannerNetworkId === fixtureNetworkId) fail("INVALID_IDENTITY", "network IDs mismatch");
    const scannerMemberships = verifyMemberships({ networks: scanner.NetworkSettings?.Networks }, [scannerNetwork]);
    const gatewayMemberships = verifyMemberships({ networks: gateway.NetworkSettings?.Networks }, networks);
    if (gateway.Id !== gatewayContainerId || scanner.Id !== scannerContainerId || gateway.Config?.Labels?.["cloudsentinel.owner"] !== `cloudsentinel-${scanId}` || gateway.Config?.Labels?.["cloudsentinel.role"] !== "gateway") fail("OWNERSHIP_MISMATCH", "gateway identity mismatch");
    const gatewayIp = gateway.NetworkSettings.Networks[scannerNetwork.name].IPAddress;
    // Never rebind an expected proxy to a changed inspection. Retain only safe
    // endpoint/state predicates, without copying arbitrary URL credentials.
    const proxyMatch=/^http:\/\/(\d{1,3}(?:\.\d{1,3}){3}):3128$/.exec(target.proxy || '');
    const gatewayDiagnostic={gatewayContainerId,scannerNetworkId,
      gatewayRunning:gateway.State?.Running===true,
      gatewayExitCode:Number.isInteger(gateway.State?.ExitCode)?gateway.State.ExitCode:null,
      gatewayOOMKilled:gateway.State?.OOMKilled===true,
      expectedProxyIp:proxyMatch&&isIP(proxyMatch[1])===4?proxyMatch[1]:null,
      inspectedGatewayIp:typeof gatewayIp==='string'&&isIP(gatewayIp)===4?gatewayIp:null,
      proxyEndpointWellFormed:!!proxyMatch&&isIP(proxyMatch[1])===4,
      inspectedEndpointPresent:typeof gatewayIp==='string'&&isIP(gatewayIp)===4,
      proxyMatches:target.proxy===`http://${gatewayIp}:3128`};
    if(!gatewayDiagnostic.gatewayRunning)fail('GATEWAY_NOT_RUNNING','inspected gateway is not running',{gatewayDiagnostic});
    if(!gatewayDiagnostic.inspectedEndpointPresent)fail('GATEWAY_ENDPOINT_INVALID','inspected gateway IPv4 is missing or malformed',{gatewayDiagnostic});
    if (!gatewayDiagnostic.proxyEndpointWellFormed || !gatewayDiagnostic.proxyMatches) fail("INVALID_PROBE", "proxy does not match inspected gateway",{gatewayDiagnostic});
    if (scanner.HostConfig?.Privileged === true || scanner.HostConfig?.NetworkMode === "host" || gateway.HostConfig?.Privileged === true || gateway.HostConfig?.NetworkMode === "host") fail("UNSAFE_CONTAINER", "privileged or host networking detected");
    for (const c of [scanner, gateway]) {
      if ((c.HostConfig?.CapAdd || []).length || (c.Mounts || []).some(x => String(x.Source || "").includes("docker.sock"))) fail("UNSAFE_CONTAINER", "added capabilities or Docker socket detected");
    }
    const native = {}, text = {};
    for (const [kind, args] of Object.entries(NETWORK_COMMANDS)) {
      let result;
      try { result = await clientService.execute(this.adapter, this.acceptanceClient.resource, args); }
      catch (error) {
        error.networkDiagnostic = networkDiagnostic(kind, "COMMAND_FAILED", { exitCode: error.exitCode, stdout: error.commandStdout, stderr: error.commandStderr });
        throw error;
      }
      native[kind] = result;
      if (result.exitCode !== 0 || typeof result.stdout !== "string" || typeof result.stderr !== "string" || result.stderr.trim()) fail("INCOMPLETE_PROBES", "runtime observation command is incomplete or ambiguous", { networkDiagnostic: networkDiagnostic(kind, "COMMAND_OUTPUT_NOT_CLEAN", result) });
      text[kind] = result.stdout;
    }
    let routeData;
    try { routeData = verifyNetworkText(text, scannerNetwork, scanner.NetworkSettings.Networks[scannerNetwork.name]); }
    catch (error) {
      const kind = error.observation;
      if (Object.hasOwn(NETWORK_COMMANDS, kind)) error.networkDiagnostic = networkDiagnostic(kind, error.validationRule, native[kind]);
      throw error;
    }
    routeCheck(routeData.ipv4); routeCheck(routeData.ipv6);
    if (!Array.isArray(routeData.addresses) || !routeData.addresses.length) fail("MALFORMED_ROUTES", "address evidence missing");
    if (routeData.ipv6.length || routeData.addresses.some(x => x.addr_info?.some(a => a.family === "inet6"))) fail("IPV6_EXPOSED", "IPv6 exposure detected");
    const digest = await this.adapter.run(["exec", gatewayContainerId, "sha256sum", stagedPolicy.containerPath]);
    const process = await this.adapter.run(["exec", gatewayContainerId, "cat", "/proc/1/cmdline"]);
    const processArgs = String(process.stdout || "").split("\0");
    if (digest.exitCode !== 0 || process.exitCode !== 0 || `sha256:${String(digest.stdout).split(/\s+/)[0]}` !== stagedPolicy.policyDigest || !processArgs.some(a => /(?:^|\/)squid$/.test(a)) || !processArgs.some((a, i) => a === "-f" && processArgs[i + 1] === stagedPolicy.containerPath) || gateway.State?.Running !== true) fail("POLICY_NOT_ACTIVE", "Squid process/config evidence mismatch");
    if (mode === 'tcp-diagnostic') {
      const probe = await clientService.probe(this.adapter, this.acceptanceClient.resource, 'tcp', target, {expected:'DENY',routeEvidence:routeData});
      const diagnosticFile = await require('./tcpDiagnostic').save(probe,String(scanId), {
        provenance:isRuntimeAdapter(this.adapter)?'RUNTIME_OBSERVED':'MOCK_ONLY_NOT_VERIFIED',
        client:{id:scannerContainerId,networkId:scannerNetworkId,memberships:scannerMemberships},
        fixture:{networkId:fixtureNetworkId,ip:target.ip,port:target.port},
        routes:routeData,
        interpretation:{observedMainTableRouteToDestination:'ABSENT',effectiveKernelDecision:'UNKNOWN',explicitKernelProhibitionObserved:false,limitation:'Main-table and interface observations corroborate identity but do not establish policy-routing lookup or a socket denial.'},
      });
      return {mode,diagnosticOnly:true,fullContainment:false,state:'DIAGNOSTIC_COMPLETE',actual:probe.actual,complete:probe.complete,exitCode:probe.exitCode,diagnosticFile,tcpDiagnostic:require('./tcpDiagnostic').diagnostic(probe)};
    }
    if (mode === 'connect-diagnostic') {
      const probe = nativeConnect ? await require('./sameSocketConnect').observeSameSocketConnect(this.adapter,this.acceptanceClient.resource,{gatewayId:gatewayContainerId,networkReferences,target}) : await clientService.probe(this.adapter, this.acceptanceClient.resource, 'connect', target, { expected: 'DENY', gatewayContainerId, proxy: target.proxy, routeEvidence: routeData });
      const diagnosticFile = await saveConnectDiagnostic(probe, { scanId, provenance: isRuntimeAdapter(this.adapter) ? 'RUNTIME_OBSERVED' : 'MOCK_ONLY_NOT_VERIFIED', gateway: { id: gateway.Id, networkId: scannerNetworkId, ip: gatewayIp, port: 3128 } });
      return { mode, diagnosticOnly: true, fullContainment: false, state: 'DIAGNOSTIC_COMPLETE', diagnosticFile,
        clientImplementation: nativeConnect ? 'native' : 'curl', nativeEvidence:probe.nativeEvidence,
        actual: probe.actual, complete: probe.complete, exitCode: probe.exitCode, httpStatus: probe.httpStatus, connectStatus: probe.connectStatus, connectEvidence: probe.connectEvidence };
    }
    const specs = profile==='active' ? [
      ['positive-sqli','http',target,{path:'/test/sqli'},'ALLOW'],
      ['positive-xss','http',target,{path:'/test/xss'},'ALLOW'],
      ['negative-proxy','proxy',{...target,hostname:'unauthorized.test'},{path:'/test/sqli',strictPolicy:true},'DENY'],
      ['negative-connect','connect',target,{},'DENY'],
      ['negative-direct-bypass','tcp',target,{},'DENY'],
      ['negative-path','proxy',target,{path:'/health',strictPolicy:true},'DENY'],
      ['negative-redirect-path','proxy',target,{path:'/redirect/host',strictPolicy:true},'DENY'],
      ['negative-alternate-host','proxy',{...target,hostname:target.ip},{path:'/test/sqli',strictPolicy:true},'DENY'],
      ['negative-port','proxy',{...target,port:18081},{path:'/test/sqli',strictPolicy:true},'DENY'],
      ['negative-public','proxy',{...target,hostname:'198.51.100.9',port:80},{strictPolicy:true},'DENY'],
      ['negative-metadata','proxy',{...target,hostname:'169.254.169.254',port:80},{strictPolicy:true},'DENY'],
    ] : [
      ["positive-fixture", "http", target, { path: "/health" }, "ALLOW"],
      ["negative-proxy", "proxy", { ...target, hostname: "unauthorized.test" }, {}, "DENY"],
      ["negative-connect", "connect", target, {}, "DENY"],
      ["negative-direct-bypass", "tcp", target, {}, "DENY"],
      ["negative-redirect", "http", target, { path: "/redirect/host", follow: true, crossOrigin: true }, "DENY"],
      ["negative-alternate-host", "proxy", { ...target, hostname: target.ip }, {}, "DENY"],
      ["negative-port", "proxy", { ...target, port: target.port === 65535 ? 1 : target.port + 1 }, {}, "DENY"],
      ["negative-public", "proxy", { ...target, hostname: "198.51.100.9", port: 80 }, { strictPolicy: true }, "DENY"],
      ["negative-metadata", "proxy", { ...target, hostname: "169.254.169.254", port: 80 }, { strictPolicy: true }, "DENY"],
      ["positive-same-redirect", "http", target, { path: "/redirect/same", follow: true, sameOrigin: true }, "ALLOW"],
    ];
    const probes = [];
    for (const [name, kind, destination, options, expected] of specs) {
      beforeProbe?.();
      const result = nativeConnect && kind === 'connect'
        ? await require('./sameSocketConnect').observeSameSocketConnect(this.adapter, this.acceptanceClient.resource, { gatewayId: gatewayContainerId, networkReferences, target: destination })
        : await clientService.probe(this.adapter, this.acceptanceClient.resource, kind, destination, { ...options, expected, gatewayContainerId, proxy: target.proxy, routeEvidence: routeData });
      const probe = Object.assign(result, { name, expected });
      probes.push(probe);
      beforeProbe?.();
      if(kind==='tcp' && (!probe.complete || probe.actual !== expected)) {
        let diagnosticFile;
        try {diagnosticFile=await require('./tcpDiagnostic').save(result,String(scanId));}
        catch(error) {fail(error.code||'DIAGNOSTIC_WRITE_FAILED','TCP diagnostic persistence failed',{probe,probes});}
        fail(probe.complete?'CONNECTIVITY_FAILED':'PROBE_INCONCLUSIVE','direct TCP evidence did not establish containment',{probe,probes,diagnosticFile});
      }
      if (!probe.complete || !["ALLOW", "DENY"].includes(probe.actual)) fail("PROBE_INCONCLUSIVE", "probe execution is inconclusive", { probe, probes });
      if (probe.actual !== expected) fail("CONNECTIVITY_FAILED", "connectivity result contradicts expectation", { probe, probes });
    }
    // IPv6 evidence is the actual successful route/address observations above,
    // not an unsupported nc -6 invocation or an inferred timeout verdict.
    probes.push({ name:'negative-ipv6-bypass', kind:'namespace-observation', sourceId:scannerContainerId, exitCode:native.ipv6.exitCode, actual:'DENY', expected:'DENY', complete:true, evidenceType:'verified-no-ipv6-routes-or-addresses', routes:routeData.ipv6, addresses:routeData.addresses });
    const required = specs.map(spec=>spec[0]).concat('negative-ipv6-bypass');
    if (!Array.isArray(probes) || probes.length < required.length) fail("INCOMPLETE_PROBES", "mandatory connectivity probes are missing");
    if (new Set(probes.map(p=>p.name)).size !== required.length || required.some(name=>!probes.some(p=>p.name===name))) fail('INCOMPLETE_PROBES','mandatory named probe missing or duplicated');
    for (const p of probes) if (!p || p.complete !== true || !Number.isInteger(p.exitCode) || p.sourceId !== scannerContainerId || !["ALLOW", "DENY"].includes(p.actual) || p.expected !== p.actual) fail("CONNECTIVITY_FAILED", "connectivity result contradicts expectation");
    if(namespace) {
      const after=(await clientService.verifyClient(this.adapter,this.acceptanceClient.resource)).namespaceEvidence;
      if(!after || JSON.stringify(after)!==JSON.stringify(namespace))fail('NAMESPACE_UNVERIFIED','namespace identity changed during observations');
    }
    beforeProbe?.();const complete = true;
    const evidence = Object.freeze({ schemaVersion: "1.1", profile, namespaceScope:namespace?'ZAP_SHARED_NETWORK_NAMESPACE':'ACCEPTANCE_CLIENT_ONLY', ...(namespace?{namespaceEvidence:namespace}:{}), projectId, executionId, scanId, gatewayContainerId, scannerContainerId, scannerNetworkId, fixtureNetworkId, memberships: { scanner: scannerMemberships, gateway: gatewayMemberships }, routes: routeData, ipv4: true, ipv6: false, defaultGateway: null, squidPolicyDigest: stagedPolicy.policyDigest, target, positiveConnectivity: true, negativeConnectivity: true, directTcpBypass: false, observedAt: new Date().toISOString(), provenance: ["docker-inspect", "docker-exec", "gateway-inspection", "connectivity-probe"], complete, independent: true, verification: isRuntimeAdapter(this.adapter) ? "RUNTIME_OBSERVED" : "MOCK_ONLY_NOT_VERIFIED", probes });
    if (isRuntimeAdapter(this.adapter)) issuedEvidence.add(evidence);
    return evidence;
  }
}

function runtimeReady(evidence) { return Boolean(evidence && issuedEvidence.has(evidence) && evidence.complete === true && evidence.independent === true && evidence.verification === "RUNTIME_OBSERVED" && evidence.directTcpBypass === false && evidence.ipv6 === false); }
module.exports = { RuntimeObservation, ObservationError, runtimeReady, routeCheck, NETWORK_COMMANDS };
