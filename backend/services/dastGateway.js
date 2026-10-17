"use strict";
const crypto = require("crypto");
const IMAGE = "ubuntu/squid:6.6-24.04_edge@sha256:94f844158e12b52f51b4ae996515e37e8fb3e8d85e1c86caba1a297376e4ec4f";
const FIXTURE_IMAGE = "nginx:1.27.5-alpine@sha256:62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8";
const SAFE_ID = /^[a-z0-9][a-z0-9_.-]{0,62}$/;
const STATES = ["CREATED","PROVISIONING","VERIFYING","READY","FAILED","CLEANING","CLEANED"];
const { stagePolicy, verifyStagedPolicy, cleanupPolicy } = require("./squidPolicy");
const { OwnedDockerNetworks, inspectOwnedNetwork, verifyMemberships } = require("./ownedDockerNetworks");
const { RuntimeObservation, runtimeReady } = require("./runtimeObservation");
const fixtureService = require("./dastFixture");
const clientService = require("./dastAcceptanceClient");
function error(message, code="GATEWAY_CONTAINMENT_FAILED"){const e=new Error(message);e.code=code;e.nonRetryable=true;return e;}
function id(v){if(!SAFE_ID.test(String(v))||["host","bridge","none","minikube"].includes(String(v))) throw error("invalid resource identifier","GATEWAY_INVALID_ID");return String(v);}
function names(project,execution,scan){const suffix=crypto.createHash("sha256").update(project+"|"+execution+"|"+scan).digest("hex").slice(0,12);const prefix="cs-eg-"+id(project)+"-"+id(execution)+"-"+id(scan)+"-"+suffix;const {bounded}=require("./acceptanceNames");return {prefix,scanner:bounded(prefix+"-net","cs-eg",[project,execution,scan,suffix],"net"),gateway:bounded(prefix+"-gw","cs-eg",[project,execution,scan,suffix],"gw")};}
function policy({hostname,ip,port}){if(!/^[a-z0-9.-]+$/i.test(hostname)||!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)||!Number.isInteger(port)||port<1||port>65535)throw error("invalid fixture destination","GATEWAY_INVALID_TARGET");return ["http_port 3128","acl allowed_host dstdomain "+hostname,"acl allowed_ip dst "+ip+"/32","acl allowed_port port "+port,"acl CONNECT method CONNECT","http_access deny CONNECT","http_access allow allowed_host allowed_ip allowed_port","http_access deny all","cache deny all"].join("\n")+"\n";}
class DockerAdapter{constructor(exec,timeout=30000){if(typeof exec!=="function")throw error("docker executor required");this.exec=exec;this.timeout=timeout;} async run(args){if(!Array.isArray(args)||args.some(x=>typeof x!=="string"))throw error("docker arguments must be an array","GATEWAY_INVALID_ARGS");const r=await this.exec(args,this.timeout);if(!r||r.code!==0)throw error((r&&r.stderr)||"docker command failed","GATEWAY_DOCKER_FAILED");return r.stdout||"";}}
function attestation({projectId,executionId,scanId,target,policyDigest,observations}){if(!observations||observations.ready!==true||observations.directRoute===true||observations.ipv6===true||observations.membershipValid!==true||observations.negativePassed!==true||observations.positivePassed!==true)throw error("runtime containment evidence incomplete");return {projectId,executionId,scanId,hostname:target.hostname,ip:target.ip,port:target.port,policyDigest,verified:false,verification:"MOCK_ONLY_NOT_VERIFIED"};}
class GatewayLifecycle{constructor({adapter,probe}){this.adapter=adapter;this.probe=probe;this.owned=new Set();this.states=new Map();}
async provision({projectId,executionId,scanId,target,fixtureNetwork}){const n=names(projectId,executionId,scanId);id(fixtureNetwork);if(this.states.has(scanId))throw error("duplicate scan identity","GATEWAY_DUPLICATE_SCAN");this.states.set(scanId,"PROVISIONING");let net,gw;try{const conf=policy(target);const digest=crypto.createHash("sha256").update(conf).digest("hex");await this.adapter.run(["network","inspect",n.scanner]).catch(()=>{});net=n.scanner;await this.adapter.run(["network","create","--internal","--ipv6=false","--label","cloudsentinel.owner="+n.prefix,net]);this.owned.add(net);gw=n.gateway;await this.adapter.run(["run","-d","--name",gw,"--network",net,"--label","cloudsentinel.owner="+n.prefix,"--cap-drop","ALL","--security-opt","no-new-privileges:true","--network-alias","gateway",IMAGE,"squid","-N","-f","/etc/squid/squid.conf"]);this.owned.add(gw);await this.adapter.run(["network","connect",fixtureNetwork,gw]);this.states.set(scanId,"VERIFYING");const obs=await this.probe({network:net,gateway:gw,target,policyDigest:digest,owner:n.prefix});const evidence=attestation({projectId,executionId,scanId,target,policyDigest:digest,observations:obs});this.states.set(scanId,"READY");return {names:n,policy:conf,policyDigest:digest,evidence};}catch(e){this.states.set(scanId,"FAILED");try{await this.cleanup(scanId);}catch(cleanupError){e.cleanupError=cleanupError.message;}throw e;}}
async cleanup(scanId){const state=this.states.get(scanId);if(!state||state==="CLEANED")return {state:"CLEANED",residual:[]};this.states.set(scanId,"CLEANING");const residual=[];for(const resource of Array.from(this.owned).reverse()){try{await this.adapter.run(resource.endsWith("-net")?["network","rm",resource]:["rm","-f",resource]);this.owned.delete(resource);}catch(e){residual.push(resource);}}this.states.set(scanId,residual.length?"FAILED":"CLEANED");if(residual.length)throw error("cleanup left residual resources");return {state:"CLEANED",residual};}}
class SecureGatewayLifecycle {
  constructor({ adapter, networks, policyService = { stagePolicy, verifyStagedPolicy, cleanupPolicy }, observation, fixture = fixtureService, client = clientService } = {}) {
    if (!adapter || typeof adapter.run !== "function") throw error("docker adapter required", "GATEWAY_INVALID_ADAPTER");
    this.adapter = adapter; this.networks = networks || new OwnedDockerNetworks({ adapter });
    this.policyService = policyService; this.observation = observation; this.fixture = fixture; this.client = client;
    this.states = new Map(); this.resources = new Map();
  }
  async provision(input) {
    const { projectId, executionId, scanId, target } = input || {}; const key = String(scanId);
    const python = input.fixtureKind === fixtureService.PYTHON_KIND;
    const diagnostic=input.diagnosticScope!==undefined;
    const production=input.productionScope!==undefined;
    if(production&&!require('./activeTargetEnrollment').isPreparation(input.productionScope,input))throw error('invalid production preparation scope','ACTIVE_AUTHORIZATION_BLOCKED');
    if(diagnostic && (!python || !require('./zapContainmentDiagnostic').isScope(input.diagnosticScope,scanId))) throw error('invalid diagnostic scope','INVALID_DIAGNOSTIC_SCOPE');
    if(diagnostic && (projectId!==input.diagnosticScope.projectId||executionId!==input.diagnosticScope.executionId||target?.hostname!==`${scanId}.test`||target?.port!==18080||Object.keys(target).some(k=>!['hostname','port'].includes(k))||input.mode!=='full'||input.nativeConnect!==true))throw error('diagnostic origin/execution mismatch','INVALID_DIAGNOSTIC_SCOPE');
    const checkDiagnostic=()=>{if(input.signal?.aborted)throw error('execution cancelled','ACTIVE_CANCELLED');if(production&&!require('./activeTargetEnrollment').isPreparation(input.productionScope,input))throw error('preparation expired or cancelled','ACTIVE_AUTHORIZATION_BLOCKED');if(diagnostic&&!require('./zapContainmentDiagnostic').isScope(input.diagnosticScope,scanId))throw error('diagnostic expired or cancelled','DIAGNOSTIC_EXPIRED');};
    require('./acceptanceNames').validateNames(python ? {...input,projectId:String(projectId),executionId:String(executionId)} : input);
    if (input.fixtureKind !== undefined && !python) throw error('unknown fixture kind','ACTIVE_SCOPE_BLOCKED');
    if (python && input.mode!==undefined && input.mode!=='full') throw error('Active fixture requires full path/isolation observations','INVALID_MODE');
    if (python && (projectId===17 || !Number.isSafeInteger(projectId) || projectId<1 || !Number.isSafeInteger(executionId) || executionId<1 || target?.port!==18080 || !/^[a-z0-9-]+\.test$/.test(target?.hostname||''))) throw error('invalid disposable execution','ACTIVE_SCOPE_BLOCKED');
    // The Nginx acceptance matrix contains fixture-specific redirects/health.
    // Never attest Python/ZAP containment by reusing that matrix unchanged.
    if (python && typeof this.observation?.collectActiveFixture !== 'function') throw error('Python/ZAP containment collector not verified','ACTIVE_NAMESPACE_BLOCKED');
    if (python) await fixtureService.verifyPythonAvailable(this.adapter);
    if (input?.nativeConnect !== undefined && typeof input.nativeConnect !== 'boolean') throw error('invalid native opt-in','INVALID_MODE');
    if (input?.nativeConnect && process.env.DAST_ACTIVE_ENABLED !== 'false'&&!production) throw error('native CONNECT requires isolated acceptance or authorized production preparation','INVALID_MODE');
    if (input?.mode !== undefined && !['full','connect-diagnostic','tcp-diagnostic'].includes(input.mode)) throw error('unsupported acceptance mode', 'INVALID_MODE');
    if (this.states.has(key)) throw error("duplicate scan identity", "GATEWAY_DUPLICATE_SCAN");
    this.states.set(key, "CREATED"); let staged;
    try {
      this.states.set(key, "PROVISIONING");
      const resources = {}; this.resources.set(key, resources);
      if (input.nativeConnect) resources.nativeArtifact = await require('./nativeConnectArtifact').stage(String(scanId));
      checkDiagnostic();
      const owned = (diagnostic||production||input.signal)?await this.networks.create({ projectId, executionId, scanId },{beforeCreate:checkDiagnostic}):await this.networks.create({ projectId, executionId, scanId });
      resources.owned = owned;
      checkDiagnostic();
      const scanner = owned.networks.find(n => n.role === "scanner"); const fixture = owned.networks.find(n => n.role === "fixture");
      if (!scanner || !fixture) throw error("owned scanner and fixture networks are required", "GATEWAY_NETWORK_INVALID");
      const fixtureResource = await this.fixture.provision(this.adapter, { projectId, executionId, fixtureKind: input.fixtureKind, scanId, check: (diagnostic||production||input.signal)?checkDiagnostic:undefined, host: target.hostname, port: target.port, unauthorizedHost: target.unauthorizedHost || "unauthorized.test", unauthorizedIp: target.unauthorizedIp || "198.51.100.9", unauthorizedPort: target.unauthorizedPort || (target.port === 65535 ? 1 : target.port + 1), networkId: fixture.id, onStaged: staged => { resources.fixtureResource = { staged }; }, onCreated: resource => { resources.fixtureResource = resource;checkDiagnostic(); } });
      resources.fixtureResource = fixtureResource;
      if (!fixtureResource.ip || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(fixtureResource.ip)) throw error("verified fixture IPv4 is required", "GATEWAY_TARGET_INVALID");
      const verifiedTarget = { ...target, ip: fixtureResource.ip };
      checkDiagnostic();
      staged = await this.policyService.stagePolicy({ scanId, target: verifiedTarget, ...(python ? {profile:'active'} : {}) });
      resources.staged = staged;
      await this.policyService.verifyStagedPolicy(staged);
      const owner = `cloudsentinel-${scanId}`;
      const args = ["run", "-d", "--pull=never", "--name", require('./acceptanceNames').containerName(String(scanId),'gateway'), "--network", scanner.id, "--label", `cloudsentinel.owner=${owner}`, "--label", `cloudsentinel.scan=${scanId}`, "--label", "cloudsentinel.role=gateway", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--read-only", "--mount", `type=bind,src=${staged.filePath},dst=${staged.containerPath},readonly`, "--entrypoint", "/usr/sbin/squid", IMAGE, "-N", "-f", staged.containerPath];
      // Match private host artifact ownership without granting DAC override.
      const user = `${process.getuid()}:${process.getgid()}`;
      // Active-profile access logging uses /tmp; keep it bounded and private
      // rather than allowing writes to the read-only image filesystem.
      args.splice(args.indexOf(IMAGE), 0, "--sysctl", "net.ipv6.conf.all.disable_ipv6=1", "--sysctl", "net.ipv6.conf.default.disable_ipv6=1", "--user", user, ...["/run", "/var/log/squid", "/var/spool/squid", ...(python ? ["/tmp"] : [])].flatMap(dir => ["--tmpfs", `${dir}:rw,noexec,nosuid,uid=${process.getuid()},gid=${process.getgid()},mode=0700,size=16m`]));
      if(diagnostic||production)args.splice(args.indexOf(IMAGE),0,'--memory','256m','--cpus','1','--pids-limit','64');
      checkDiagnostic();
      const run = await this.adapter.run(args); const gatewayId = run.objectId || String(run.stdout || "").trim();
      if (!/^[a-f0-9]{12,64}$/i.test(gatewayId)) throw error("gateway identity is missing", "GATEWAY_ID_MISSING");
      resources.gatewayId = gatewayId; resources.owner = owner;
      checkDiagnostic();
      await this.adapter.run(["network", "connect", fixture.id, gatewayId]);
      const freshNetworks = await Promise.all([scanner, fixture].map(ref => inspectOwnedNetwork(this.adapter, ref)));
      const gateway = (await this.adapter.inspect([gatewayId], "container")).normalized;
      if (gateway.objectId !== gatewayId || gateway.imageDigest !== IMAGE || gateway.labels?.["cloudsentinel.owner"] !== owner || gateway.labels?.["cloudsentinel.scan"] !== String(scanId) || gateway.labels?.["cloudsentinel.role"] !== "gateway") throw error("gateway ownership mismatch", "OWNERSHIP_MISMATCH");
      verifyMemberships(gateway, freshNetworks);
      resources.gatewayBinding={networkId:scanner.id,networkName:scanner.name,ip:gateway.networks[scanner.name].IPAddress};
      if(diagnostic) {
        checkDiagnostic();
        resources.diagnosticOnly=true;
        resources.target=verifiedTarget;
        this.states.set(key,'DIAGNOSTIC_PROVISIONED');
        return {state:'DIAGNOSTIC_PROVISIONED',diagnosticOnly:true,fullContainment:false};
      }
      const clientResource = await this.client.provision(this.adapter, { scanId, networkId: scanner.id, networkReference: scanner, nativeArtifact: resources.nativeArtifact, bounded:production, onCreated: resource => { resources.clientResource = resource; } });
      resources.clientResource = clientResource;
      if (typeof this.observation.bindAcceptanceClient !== "function") throw error("trusted acceptance-client binding is unavailable", "GATEWAY_EVIDENCE_INVALID");
      this.observation.bindAcceptanceClient(this.client, clientResource);
      this.states.set(key, "VERIFYING");
      if (!this.observation || typeof this.observation.collect !== "function") throw error("runtime observation is required", "GATEWAY_EVIDENCE_INVALID");
      const gatewayIp = gateway.networks[scanner.name].IPAddress;
      const collector=python?'collectActiveFixture':'collect';
      const evidence = await this.observation[collector]({ projectId, executionId, scanId, mode: input.mode, nativeConnect: input.nativeConnect, beforeProbe:checkDiagnostic, gatewayContainerId: gatewayId, scannerContainerId: clientResource.id, fixtureContainerId: fixtureResource.id, scannerNetworkId: scanner.id, fixtureNetworkId: fixture.id, networkReferences: [scanner, fixture], target: { ...verifiedTarget, proxy: `http://${gatewayIp}:3128` }, stagedPolicy: staged });
      // Active ZAP cannot run namespace tools in the pinned image. Retain the
      // independently verified acceptance-client observation on the owned
      // lifecycle record so the runtime adapter can bind to that evidence.
      resources.runtimeObservation = evidence;
      resources.acceptanceClientId = clientResource.id;
      if (['connect-diagnostic','tcp-diagnostic'].includes(input.mode)) {
        if (evidence.mode !== input.mode || evidence.diagnosticOnly !== true || evidence.fullContainment !== false || evidence.state !== 'DIAGNOSTIC_COMPLETE') throw error('invalid diagnostic result', 'GATEWAY_EVIDENCE_INVALID');
        this.states.set(key, 'DIAGNOSTIC_COMPLETE');
        return evidence;
      }
      if (!runtimeReady(evidence)) throw error("runtime evidence is not independently verified", "GATEWAY_EVIDENCE_INVALID");
      this.states.set(key, "READY"); return { state: "READY", gateway: { id: gatewayId }, networks: owned, policyDigest: staged.policyDigest, evidence };
    } catch (e) {
      this.states.set(key, "FAILED");
      const resources=this.resources.get(key);
      if(resources?.gatewayId)try{
        e.gatewayEvidenceFile=await require('./gatewayFailureEvidence').save({adapter:this.adapter,resources,projectId,executionId,scanId:key,error:e});
      }catch(x){e.gatewayEvidenceError=x.code||'GATEWAY_EVIDENCE_WRITE_FAILED';}
      try { const cleanup = await this.cleanup(key); if (cleanup.residual.length) e.cleanup = cleanup; }
      catch (x) { e.cleanupError = x.code || "CLEANUP_FAILED"; }
      throw e;
    }
  }
  async cleanup(scanId) {
    const key = String(scanId), r = this.resources.get(key);
    this.observation?.clearAcceptanceClient?.();
    if (!r) return { state: "CLEANED", residual: [] };
    const residual = [];
    for (const [service, field] of [[this.client, "clientResource"], [this.fixture, "fixtureResource"]]) {
      const resource = r[field];
      if (!resource) continue;
      try { const result = await service.cleanup(this.adapter, resource); if (result?.cleaned !== true) residual.push(...(result?.residual?.length ? result.residual : [{ type: field, error: "CLEANUP_UNVERIFIED" }])); else delete r[field]; }
      catch (e) { residual.push({ type: "owned-container", error: e.code || "CLEANUP_FAILED" }); }
    }
    if (r.nativeArtifact && !r.clientResource) try { await require('./nativeConnectArtifact').cleanup(r.nativeArtifact); delete r.nativeArtifact; }
    catch (e) { residual.push({type:'native-artifact',error:e.code||'CLEANUP_FAILED'}); }
    else if (r.nativeArtifact) residual.push({type:'native-artifact',error:'CLIENT_STILL_PRESENT'});
    if (r.gatewayId) try {
      const n = (await this.adapter.inspect([r.gatewayId], "container")).normalized;
      if (n.objectId !== r.gatewayId || n.labels?.["cloudsentinel.owner"] !== r.owner || n.labels?.["cloudsentinel.scan"] !== key || n.labels?.["cloudsentinel.role"] !== "gateway") throw error("unowned gateway", "OWNERSHIP_MISMATCH");
      await this.adapter.run(["stop", r.gatewayId]); await this.adapter.run(["rm", r.gatewayId]);
      delete r.gatewayId;
    } catch (e) { if (e.code === "MISSING_RESOURCE") delete r.gatewayId; else residual.push({ type: "gateway", error: e.code || "CLEANUP_FAILED" }); }
    try { const n = await this.networks.cleanup(key); residual.push(...(n.residual || [])); }
    catch (e) { residual.push({ type: "network", error: e.code || "CLEANUP_FAILED" }); }
    if (!residual.length && r.staged) try { await this.policyService.cleanupPolicy(r.staged); }
    catch (e) { residual.push({ type: "policy", error: e.code || "CLEANUP_FAILED" }); }
    this.states.set(key, residual.length ? "FAILED" : "CLEANED");
    if (!residual.length) this.resources.delete(key);
    return { state: this.states.get(key), residual };
  }

}module.exports={IMAGE,STATES,names,policy,DockerAdapter,GatewayLifecycle,SecureGatewayLifecycle,attestation};
