"use strict";
const IMAGE="nginx:1.27.5-alpine@sha256:62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8";
const { isIP } = require("net");
const ID=/^[a-f0-9]{12,64}$/i;
// Fixed POSIX shell program; destinations remain separate argv entries. Clear
// inherited proxy exclusions rather than sending curl an unsupported empty flag.
const CURL_ENV = 'unset no_proxy NO_PROXY http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY; exec curl "$@"';
function fail(code,msg){const e=new Error(msg);e.code=code;throw e;}
function validateIdentity(o){if(!o||!o.scanId||!o.networkId||!/^[a-z0-9_.-]+$/i.test(String(o.scanId)))fail("INVALID_IDENTITY","scan and network identity required");require('./acceptanceNames').containerName(String(o.scanId),'client');}
const { inspectOwnedNetwork, verifyMemberships } = require("./ownedDockerNetworks");
const { supportsDirectIsolation } = require("./runtimeNetworkText");
const { commandOutput } = require("./dockerAdapter");
const { createHash } = require("crypto");
const nativeArtifact = require('./nativeConnectArtifact');
const connectCaptures = new WeakMap();
function connectCapture(probe) { return connectCaptures.get(probe); }
function privateConnectCapture(result) {
  const redact = text => String(text).replace(/\b(?:password|token|secret|authorization|cookie|api[_-]?key)\s*[:=]\s*\S+/gi, '[REDACTED]').replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, '$1[REDACTED]@').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
  const lines = String(result.stderr || '').split(/\r?\n/).filter(line => /^\* .*\b(?:connected|connect|connection)\b|^> (?:CONNECT |Host:)|^< HTTP\/|^< (?:Server|X-Squid-Error|Via|X-Cache):|^<\s*$/i.test(line));
  return Object.freeze({ exitCode: result.exitCode, stdout: redact(result.stdout || '').slice(0,4096),
    verboseEvidenceLines: lines.slice(0,128).map(line => redact(line).slice(0,512)),
    truncated: lines.length > 128 || lines.some(line => line.length > 512) || String(result.stdout || '').length > 4096 });
}
function connectPeer(stdout, stderr, expectedIp) {
  const fields = stdout.trim().split(/\s+/);
  const curlRemoteIpPresent = fields.length >= 3;
  const malformedWriteout = ![2,3].includes(fields.length) || !/^\d{3}$/.test(fields[0]) || !/^\d{3}$/.test(fields[1]) || (curlRemoteIpPresent && isIP(fields[2]) !== 4);
  const curlRemoteIpMatches = !malformedWriteout && curlRemoteIpPresent && fields[2] === expectedIp;
  const lines = stderr.split(/\r?\n/);
  const connected = lines.filter(l => l.startsWith('* Connected to '));
  // Numeric endpoint only; this is curl's client-side successful socket log,
  // not a proxy header, configured address, or a mere "Trying" message.
  const match = connected.length === 1 ? /^\* Connected to (\d{1,3}(?:\.\d{1,3}){3}) \((\d{1,3}(?:\.\d{1,3}){3})\) port (\d+)(?: \(#\d+\))?$/.exec(connected[0]) : null;
  const malformedSocket = connected.length > 0 && (!match || isIP(match[1]) !== 4 || isIP(match[2]) !== 4 || match[1] !== match[2] || lines.indexOf(connected[0]) >= lines.findIndex(l => l.startsWith('> CONNECT ')));
  const socketMatches = !!match && !malformedSocket && match[2] === expectedIp && match[3] === '3128';
  let peerEvidenceStatus = 'MISSING';
  if (malformedWriteout || malformedSocket) peerEvidenceStatus = 'MALFORMED';
  else if ((curlRemoteIpPresent && !curlRemoteIpMatches) || (connected.length && !socketMatches)) peerEvidenceStatus = 'MISMATCH';
  else if (curlRemoteIpMatches || socketMatches) peerEvidenceStatus = 'MATCH';
  const observedPeerSource = curlRemoteIpPresent && !malformedWriteout ? (connected.length && !malformedSocket ? 'CURL_REMOTE_IP_AND_VERBOSE_SOCKET' : 'CURL_REMOTE_IP') : (connected.length && !malformedSocket ? 'CURL_VERBOSE_SOCKET' : 'NONE');
  return { curlRemoteIpPresent, curlRemoteIpMatches, observedPeerSource, observedPeerMatches: peerEvidenceStatus === 'MATCH', peerEvidenceStatus,
    socketPeerObserved: !!match && isIP(match[1]) === 4 && isIP(match[2]) === 4,
    socketPeerMatches: socketMatches, socketPrecedesConnect: !!match && lines.indexOf(connected[0]) < lines.findIndex(l => l.startsWith('> CONNECT ')) };
}
function connectHeaders(stderr, authority) {
  const lines = stderr.split(/\r?\n/);
  const requests = lines.filter(l => l.startsWith('> CONNECT '));
  const hosts = lines.filter(l => /^> Host:/i.test(l));
  const response = lines.filter(l => l === '<' || l.startsWith('< ')).map(l => l.slice(2));
  const statuses = response.filter(l => /^HTTP\//.test(l));
  const errors = response.filter(l => /^X-Squid-Error:/i.test(l));
  const servers = response.filter(l => /^Server:/i.test(l));
  const locations = response.filter(l => /^Location:/i.test(l));
  return {
    requestMatches: requests.length === 1 && requests[0] === `> CONNECT ${authority} HTTP/1.1` && hosts.length === 1 && hosts[0].toLowerCase() === `> host: ${authority}`.toLowerCase(),
    responseComplete: response.length > 0 && lines.some(l => /^<\s*$/.test(l)) && statuses.length === 1 && /^HTTP\/1\.[01] 403(?: .*)?$/.test(statuses[0]),
    responseWellFormed: /^HTTP\//.test(response[0] || '') && response.at(-1) === '' && response.slice(1,-1).every(l => /^[!#$%&'*+.^_`|~0-9A-Za-z-]+: [^\x00-\x1f\x7f]*$/.test(l)) && lines.indexOf(requests[0]) < lines.findIndex(l => l.startsWith('< HTTP/')),
    squidServer: servers.length === 1 && /^Server: squid\/[0-9]+(?:\.[0-9]+)*(?:\s*)$/i.test(servers[0]),
    accessDenied: errors.length === 1 && /^X-Squid-Error: ERR_ACCESS_DENIED 0\s*$/i.test(errors[0]),
    noRedirect: locations.length === 0,
  };
}
const verifiedClients = new WeakMap();
async function verifyClient(adapter, client) {
  const record = verifiedClients.get(client);
  if (!record || record.adapter !== adapter) fail("INVALID_CLIENT", "lifecycle-verified client required");
  const network = await inspectOwnedNetwork(adapter, record.reference);
  const n = (await adapter.inspect([client.id], "container")).normalized;
  if (!n || n.objectId !== client.id || n.imageDigest !== IMAGE || n.labels?.["cloudsentinel.owner"] !== client.owner || n.labels?.["cloudsentinel.role"] !== "acceptance-client" || n.security?.privileged !== false || n.security?.networkMode === "host" || n.security?.capAdd?.length || (n.mounts || []).some(m => String(m.Source || "").includes("docker.sock"))) fail("IDENTITY_MISMATCH", "client security or ownership mismatch");
  verifyMemberships(n, [network]);
  if (record.nativeArtifact) {
    await nativeArtifact.verify(record.nativeArtifact);
    const mounts = n.mounts;
    if (mounts.length !== 1 || mounts[0].Type !== 'bind' || mounts[0].Destination !== nativeArtifact.DESTINATION || mounts[0].Source !== record.nativeArtifact.filePath || mounts[0].RW !== false || n.security.user !== `${process.getuid()}:${process.getgid()}` || !n.security.readOnly || n.security.capDrop.length !== 1 || n.security.capDrop[0] !== 'ALL' || !n.security.securityOpt.includes('no-new-privileges:true')) fail('NATIVE_MOUNT_MISMATCH','native delivery security mismatch');
  }
  return n;
}
async function verifyNativeDelivery(adapter, client) {
  const record = verifiedClients.get(client);
  if (!record?.nativeArtifact) fail('NATIVE_OPT_IN_REQUIRED','verified native delivery required');
  await verifyClient(adapter,client);
  const result = await adapter.run(['exec',client.id,'sha256sum',nativeArtifact.DESTINATION]);
  if (result.exitCode !== 0 || result.stderr !== '' || !new RegExp(`^${nativeArtifact.BINARY_SHA}  ${nativeArtifact.DESTINATION}\\n?$`).test(result.stdout)) fail('NATIVE_BINARY_HASH_MISMATCH','container executable hash mismatch');
}
async function provision(adapter, o) {
  validateIdentity(o);
  if (!adapter || typeof adapter.run !== "function" || typeof adapter.inspect !== "function") fail("ADAPTER_GAP", "run and inspect are required");
  const network = await inspectOwnedNetwork(adapter, o.networkReference);
  if (network.id !== o.networkId || o.networkReference.scanIdentity.scanId !== String(o.scanId)) fail("IDENTITY_MISMATCH", "client network reference mismatch");
  const owner = "cloudsentinel-" + o.scanId;
  const runArgs = ["run", "-d", "--pull=never", "--name", require('./acceptanceNames').containerName(String(o.scanId),'client'), "--network", network.id, "--label", "cloudsentinel.owner=" + owner, "--label", "cloudsentinel.role=acceptance-client", "--read-only", "--sysctl", "net.ipv6.conf.all.disable_ipv6=1", "--sysctl", "net.ipv6.conf.default.disable_ipv6=1", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--entrypoint", "/bin/sh", IMAGE, "-c", "sleep 3600"];
  if (o.nativeArtifact) { await nativeArtifact.verify(o.nativeArtifact); if (o.nativeArtifact.scanId !== String(o.scanId)) fail("NATIVE_UNOWNED","native artifact scan mismatch"); runArgs.splice(runArgs.indexOf("--entrypoint"),0,"--user",`${process.getuid()}:${process.getgid()}`,"--mount",o.nativeArtifact.mount); }
  const run = await adapter.run(runArgs);
  const id = run.objectId || String(run.stdout || "").trim();
  if (!ID.test(id)) fail("IDENTITY_MISSING", "client ID missing");
  const client = Object.freeze({ id, owner, networkId: network.id, networkName: network.name, image: IMAGE });
  o.onCreated?.(client);
  verifiedClients.set(client, { adapter, reference: o.networkReference, nativeArtifact: o.nativeArtifact });
  await verifyClient(adapter, client);
  return client;
}
async function execute(adapter, client, command) {
  await verifyClient(adapter, client);
  return adapter.run(["exec", client.id, ...command]);
}
function buildProbeCommand(kind, target, opts = {}) {
  if (!target || typeof target !== "object" || !/^[a-z0-9.-]+$/i.test(target.hostname || "") || !Number.isInteger(target.port) || target.port < 1 || target.port > 65535) fail("INVALID_PROBE", "structured probe target required");
  const path = opts.path || "/health";
  if (!/^\/[a-z0-9/.-]*$/i.test(path)) fail("INVALID_PROBE", "invalid probe path");
  const proxy = opts.proxy;
  if (kind !== "tcp" && !/^http:\/\/\d{1,3}(?:\.\d{1,3}){3}:3128$/.test(proxy || "")) fail("INVALID_PROBE", "verified proxy endpoint required");
  if ((kind === "tcp" && isIP(target.ip) !== 4) || (kind !== "tcp" && isIP(new URL(proxy).hostname) !== 4)) fail("INVALID_PROBE", "verified numeric destination required");
  const url = `${kind === "connect" ? "https" : "http"}://${target.hostname}:${target.port}${path}`;
  // Both flags are present in captured help from the pinned BusyBox image.
  // Request diagnostics explicitly; silent exit 1 still proves nothing.
  const command = kind === "tcp" ? ["nc", "-n", "-v", "-z", "-w", "5", target.ip, String(target.port)] :
    ["/bin/sh", "-c", CURL_ENV, "cloudsentinel-curl", "-q", "--silent", "--show-error", "--max-time", "5", "--proxy", proxy, ...(kind === 'connect' ? ['--verbose'] : ["--dump-header", "/dev/stderr"]), "--output", "/dev/null", "--write-out", (opts.sameOrigin || opts.crossOrigin) ? "%{http_code} %{http_connect} %{remote_ip} %{url_effective} %{num_redirects}" : "%{http_code} %{http_connect} %{remote_ip}", ...(opts.follow ? ["--location", "--max-redirs", "2"] : []), url];
  if (!["http", "proxy", "connect", "tcp"].includes(kind)) fail("INVALID_PROBE", "unsupported probe");
  return command;
}
async function probe(adapter, client, kind, target, opts = {}) {
  const inspectedClient = await verifyClient(adapter, client);
  const command = buildProbeCommand(kind, target, opts);
  const proxy = opts.proxy;
  const started = new Date().toISOString();
  const endpoint = inspectedClient.networks[client.networkName];
  const routeMatches = () => kind === 'tcp' && supportsDirectIsolation(opts.routeEvidence, {networkId:client.networkId,sourceIp:endpoint.IPAddress,sourceMac:endpoint.MacAddress,destination:target.ip});
  let result;
  try { result = await execute(adapter, client, command); }
  catch (e) {
    if (e.code === "DOCKER_COMMAND_FAILED" && Number.isInteger(e.exitCode) && e.exitCode > 0 && e.exitCode !== 127) {
      const native = commandOutput(e);
      result = { exitCode: e.exitCode,
        stdout: kind==='tcp' ? native?.stdout : native?.stdout ?? e.commandStdout ?? "",
        stderr: kind==='tcp' ? native?.stderr : native?.stderr ?? e.commandStderr ?? e.stderrExcerpt ?? "" };
    } else {
      const actual = ["INVALID_ARGUMENTS", "INVALID_PROBE", "UNSAFE_ARGUMENTS"].includes(e.code) ? "ERROR" : "INCONCLUSIVE";
      const failed = { kind, target, started, sourceId: client.id, exitCode: e.exitCode ?? null, actual, decision: actual, complete: false, reason: e.code || "COMMAND_FAILED", evidenceType: "execution-failure" };
      if(kind==='tcp') {
        const native=commandOutput(e);
        require('./tcpDiagnostic').capture(failed,{exitCode:e.exitCode,stdout:native?.stdout,stderr:native?.stderr},{exitOne:e.exitCode===1,nativeOutputPresent:!!native,routeMatches:routeMatches(),explicitUnreachable:false,stdoutEmpty:false,noAmbiguousError:false}, {ip:target.ip,port:target.port},command,e.code||'COMMAND_FAILED');
      }
      return failed;
    }
  }
  if (!Number.isInteger(result.exitCode)) fail("INCOMPLETE_PROBE", "command exit code required");
  const fields = String(result.stdout || "").trim().split(/\s+/);
  const httpStatus = /^\d{3}$/.test(fields[0]) ? Number(fields[0]) : null;
  const connectStatus = /^\d{3}$/.test(fields[1]) ? Number(fields[1]) : null;
  const remoteIp = fields[2];
  const squidErrors = [...String(result.stderr || "").matchAll(/(?:^|\s)x-squid-error:\s*(ERR_[A-Z_]+)\b/gi)].map(m => m[1].toUpperCase());
  const proxyDenied = squidErrors.length === 1 && squidErrors[0] === "ERR_ACCESS_DENIED";
  let actual = "INCONCLUSIVE";
  let evidenceType = "execution-failure";
  const stderr = String(result.stderr || "");
  const setupError = /(?:invalid|unknown|unrecognized|unsupported) (?:option|argument)|usage:/i.test(stderr);
  const ambiguous = /timed?\s*out|timeout|refused|could not resolve|bad address|not found/i.test(stderr);
  const nativeOutputClean = [result.stdout,result.stderr].every(v=>typeof v==='string' && !v.includes('\0') && Buffer.byteLength(v)<=4096);
  if (setupError) actual = "ERROR";
  if (kind === "tcp" && nativeOutputClean && result.exitCode === 0 && !String(result.stdout || "").trim() && !stderr.trim()) { actual = "ALLOW"; evidenceType = "direct-network"; }
  if (kind === "tcp" && nativeOutputClean && result.exitCode === 1 && !ambiguous && !setupError && /network (?:is )?unreachable/i.test(stderr) && !String(result.stdout || "").trim()) {
    const endpoint = inspectedClient.networks[client.networkName];
    if (supportsDirectIsolation(opts.routeEvidence, { networkId: client.networkId, sourceIp: endpoint.IPAddress, sourceMac: endpoint.MacAddress, destination: target.ip })) { actual = "DENY"; evidenceType = "direct-network-isolation"; }
  }
  if (kind !== "tcp" && !ambiguous && !setupError && fields.length === ((opts.sameOrigin || opts.crossOrigin) ? 5 : 3) && result.exitCode === 0 && remoteIp === new URL(proxy).hostname) {
    if (httpStatus >= 200 && httpStatus < 300 && !squidErrors.length && (kind === "connect" ? connectStatus === 200 : connectStatus === 0)) actual = "ALLOW";
    if (kind !== "connect" && connectStatus === 0 && httpStatus === 403 && proxyDenied) actual = "DENY";
  }
  let policyEvidence, redirectEvidence;
  if (opts.strictPolicy) {
    const blocks = stderr.trim().split(/\r?\n\r?\n/);
    const lines = blocks[0].split(/\r?\n/);
    policyEvidence = { complete: /\r?\n\r?\n$/.test(stderr) && blocks.length === 1 && /^HTTP\/1\.[01] 403(?: .*)?$/.test(lines[0]) && lines.slice(1).every(l=>/^[!#$%&'*+.^_`|~0-9A-Za-z-]+: [^\x00-\x1f\x7f]*$/.test(l)) && lines.filter(l=>/^Server: squid\/[0-9.]+\s*$/i.test(l)).length===1 && lines.filter(l=>/^X-Squid-Error: ERR_ACCESS_DENIED 0\s*$/i.test(l)).length===1 && lines.filter(l=>/^Server:/i.test(l)).length===1 && lines.filter(l=>/^X-Squid-Error:/i.test(l)).length===1 && !lines.some(l=>/^Location:/i.test(l)) };
    if (!policyEvidence.complete || actual !== 'DENY') actual='INCONCLUSIVE';
  }
  if (opts.sameOrigin || opts.crossOrigin) {
    const blocks=stderr.trim().split(/\r?\n\r?\n/), finalUrl=`http://${opts.crossOrigin ? "unauthorized.test" : target.hostname}:${target.port}/health`;
    const first=blocks[0]?.split(/\r?\n/), last=blocks[1]?.split(/\r?\n/);
    redirectEvidence={ finalUrl:fields[3]||null, redirects:fields[4]||null, complete:blocks.length===2 && /\r?\n\r?\n$/.test(stderr) && /^HTTP\/1\.[01] 302(?: .*)?$/.test(first[0]) && (opts.crossOrigin ? /^HTTP\/1\.[01] 403(?: .*)?$/ : /^HTTP\/1\.[01] 200(?: .*)?$/).test(last?.[0]||'') && first.filter(l=>/^Location:/i.test(l)).length===1 && first.some(l=>l===`Location: ${finalUrl}`) && !last.some(l=>/^Location:/i.test(l)) && [first,last].every(block=>block.slice(1).every(l=>/^[!#$%&'*+.^_`|~0-9A-Za-z-]+: [^\x00-\x1f\x7f]*$/.test(l))) && fields[3]===finalUrl && fields[4]==='1' };
    if (opts.crossOrigin && (!last || last.filter(l=>/^Server: squid\/[0-9.]+\s*$/i.test(l)).length!==1 || last.filter(l=>/^X-Squid-Error: ERR_ACCESS_DENIED 0\s*$/i.test(l)).length!==1)) redirectEvidence.complete=false;
    if (!redirectEvidence.complete || actual!==(opts.crossOrigin?'DENY':'ALLOW')) actual='INCONCLUSIVE';
  }
  let connectEvidence;
  if (kind === 'connect') {
    const headers = connectHeaders(stderr, `${target.hostname}:${target.port}`);
    let gatewayIdentity = false;
    let expectedGatewayContainerIdMatches = false, expectedGatewayNetworkIdMatches = false;
    if (ID.test(opts.gatewayContainerId || '')) {
      const gateway = (await adapter.inspect([opts.gatewayContainerId], 'container')).normalized;
      const peer = gateway.networks?.[client.networkName];
      expectedGatewayContainerIdMatches = gateway.objectId === opts.gatewayContainerId;
      expectedGatewayNetworkIdMatches = peer?.NetworkID === client.networkId;
      gatewayIdentity = gateway.objectId === opts.gatewayContainerId && gateway.labels?.['cloudsentinel.owner'] === client.owner && gateway.labels?.['cloudsentinel.role'] === 'gateway' && gateway.imageDigest === require('./dastGateway').IMAGE && gateway.state?.Running === true && peer?.NetworkID === client.networkId && peer.IPAddress === new URL(proxy).hostname;
    }
    const peerEvidence = connectPeer(String(result.stdout || ''), stderr, new URL(proxy).hostname);
    connectEvidence = { ...headers, expectedDenial: opts.expected === 'DENY', gatewayIdentity,
      ...peerEvidence, expectedGatewayContainerIdMatches, expectedGatewayNetworkIdMatches,
      proxyPeerMatches: peerEvidence.observedPeerMatches,
      statusConsistent: result.exitCode === 56 && httpStatus === 0 && connectStatus === 403,
      outputBytes: Buffer.byteLength(stderr), outputSha256: createHash('sha256').update(stderr).digest('hex') };
    // A rejected tunnel has no destination HTTP response (000). This alone
    // proves nothing; all proxy/request/header/identity evidence must agree.
    const required = ['requestMatches','responseComplete','responseWellFormed','squidServer','accessDenied','noRedirect','expectedDenial','gatewayIdentity','proxyPeerMatches','statusConsistent','expectedGatewayContainerIdMatches','expectedGatewayNetworkIdMatches'];
    if (!ambiguous && !setupError && !/failed to connect|couldn't connect|connection reset|SSL connection error/i.test(stderr) && required.every(key => connectEvidence[key] === true)) actual = 'DENY';
  }
  if (kind !== "tcp" && ["ALLOW", "DENY"].includes(actual)) evidenceType = actual === "DENY" ? "squid-policy" : "proxied-http";
  const probeResult = { kind, target, started, sourceId: client.id, exitCode: result.exitCode, httpStatus, connectStatus, remoteIp, proxy, proxyDenied, actual, decision: actual, complete: ["ALLOW", "DENY"].includes(actual), evidenceType, ...(connectEvidence ? { connectEvidence } : {}), ...(policyEvidence ? { policyEvidence } : {}), ...(redirectEvidence ? { redirectEvidence } : {}) };
  if (kind === 'connect') connectCaptures.set(probeResult, privateConnectCapture(result));
  if(kind==='tcp') require('./tcpDiagnostic').capture(probeResult,result,{exitOne:result.exitCode===1,nativeOutputPresent:typeof result.stdout==='string'&&typeof result.stderr==='string',outputWellFormed:nativeOutputClean,routeMatches:routeMatches(),explicitUnreachable:/network (?:is )?unreachable/i.test(stderr),stdoutEmpty:!String(result.stdout||'').trim(),noAmbiguousError:!ambiguous&&!setupError}, {ip:target.ip,port:target.port},command);
  return probeResult;
}
async function cleanup(adapter,c){if(!c)return {cleaned:true,residual:[]};const x=await adapter.inspect([c.id],"container").catch(e=>{if(e.code==="MISSING_RESOURCE")return null;throw e;});if(!x)return {cleaned:true,residual:[]};const n=x.normalized||x;if(n.objectId!==c.id||n.labels?.["cloudsentinel.owner"]!==c.owner||n.labels?.["cloudsentinel.role"]!=="acceptance-client")fail("OWNERSHIP_MISMATCH","refusing unowned cleanup");const residual=[];for(const a of [["stop",c.id],["rm",c.id]])try{await adapter.run(a);}catch(e){residual.push({operation:a[0],error:e.code||e.message});}return {cleaned:!residual.length,residual};}
module.exports={IMAGE,provision,verifyClient,verifyNativeDelivery,execute,probe,cleanup,buildProbeCommand,connectCapture};
