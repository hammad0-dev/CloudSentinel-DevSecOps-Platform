"use strict";
const {execFile}=require("child_process");
const crypto=require("crypto");
const runtimeAdapters = new WeakMap();
const commandOutputs = new WeakMap();
function commandOutput(error) { return commandOutputs.get(error); }
function isRuntimeAdapter(adapter) { const saved = runtimeAdapters.get(adapter); return !!saved && Object.getPrototypeOf(adapter) === DockerAdapter.prototype && adapter.run === nativeRun && adapter.inspect === nativeInspect && adapter.executor === saved.executor && adapter.dockerBin === "docker"; }
const OPS=new Set(["inspect","create","run","exec","connect","stop","rm","network","image","logs"]);
const ID=/^[a-f0-9]{12,64}$/i;const NAME=/^[a-z0-9][a-z0-9_.-]{0,62}$/;
class DockerAdapterError extends Error{constructor(code,message,meta={}){super(message);this.name="DockerAdapterError";this.code=code;const {nativeOutput,...safeMeta}=meta;Object.assign(this,safeMeta);if(nativeOutput)commandOutputs.set(this,Object.freeze(nativeOutput));this.nonRetryable=code!=="DAEMON_UNAVAILABLE"&&code!=="TIMEOUT";}}
function validArg(a){return typeof a==="string"&&a.length>0&&a.length<512&&!/[\r\n\0]/.test(a);}
function operation(args){if(!Array.isArray(args)||!args.length||args.some(a=>!validArg(a)))throw new DockerAdapterError("INVALID_ARGUMENTS","Docker arguments must be non-empty strings");if(!OPS.has(args[0]))throw new DockerAdapterError('INVALID_OPERATION','Docker operation is not allowlisted');if(args[0]==='logs'&&(args.length!==4||args[1]!=='--tail'||args[2]!=='200'||!/^[a-f0-9]{64}$/i.test(args[3])))throw new DockerAdapterError('INVALID_OPERATION','Only bounded immutable-container logs are allowlisted');if(args[0]==='image'&&(args[1]!=='inspect'||args.length!==3||! /^(?:[-a-z0-9./_]+@)?sha256:[a-f0-9]{64}$/.test(args[2])))throw new DockerAdapterError('INVALID_OPERATION','Only immutable image inspect is allowlisted');if(args[0]==='network'&&!['create','connect','inspect','rm'].includes(args[1]))throw new DockerAdapterError('INVALID_OPERATION','Docker network operation is not allowlisted');if(args.includes("--privileged")||args.includes("--network=host")||args.includes("host")||args.includes("/var/run/docker.sock"))throw new DockerAdapterError("UNSAFE_ARGUMENTS","Unsafe Docker argument rejected");return args.slice();}
function sanitizeDiagnostic(value, limit=240) { return String(value || "").replace(/[\r\n]+/g," ").replace(/(token|password|secret|authorization|src=)[^ ]*/ig,"[redacted]").slice(0,limit); }
function classify(stderr,code,timedOut){if(timedOut)return "TIMEOUT";if(/permission denied|access denied/i.test(stderr))return "PERMISSION_DENIED";if(/cannot connect to (?:the )?docker daemon|is the docker daemon running|error during connect.*docker/i.test(stderr))return "DAEMON_UNAVAILABLE";if(/no such|not found/i.test(stderr))return "MISSING_RESOURCE";return code===0?null:"DOCKER_COMMAND_FAILED";}
function normalizeContainerInspect(value){if(!value||typeof value!=="object"||typeof value.Id!=="string"||!ID.test(value.Id))throw new DockerAdapterError("MALFORMED_OUTPUT","Missing immutable Docker ID");if(typeof value.Name!=="string"||!NAME.test(value.Name.replace(/^\//,"")))throw new DockerAdapterError("MALFORMED_OUTPUT","Invalid Docker name");if(!value.Config||typeof value.Config.Labels!=="object")throw new DockerAdapterError("MALFORMED_OUTPUT","Missing labels");return {schemaVersion:"1.1",source:"docker-inspect",objectType:"container",objectId:value.Id,name:value.Name.replace(/^\//,""),labels:value.Config.Labels||value.Labels||{},state:value.State||null,imageDigest:value.Config.Image||null,imageId:value.Image||null,mounts:value.Mounts||[],networks:value.NetworkSettings?.Networks||{},security:{privileged:value.HostConfig?.Privileged===true,capAdd:value.HostConfig?.CapAdd||[],networkMode:value.HostConfig?.NetworkMode||null,user:value.Config.User||"",readOnly:value.HostConfig?.ReadonlyRootfs===true,capDrop:value.HostConfig?.CapDrop||[],securityOpt:value.HostConfig?.SecurityOpt||[]},complete:true};}
function malformed(message) { throw new DockerAdapterError("MALFORMED_OUTPUT", message); }
function record(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function networkIpv4(value) {
  if (typeof value !== "string" || !/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value)) malformed("Invalid network IPv4 address");
  const octets = value.split(".").map(Number);
  if (octets.some(x => x > 255)) malformed("Invalid network IPv4 address");
  return octets.reduce((n, octet) => n * 256 + octet, 0);
}
function normalizeNetworkInspect(value) {
  if (!record(value) || typeof value.Id !== "string" || !/^[a-f0-9]{64}$/i.test(value.Id)) malformed("Missing immutable network ID");
  if (typeof value.Name !== "string" || !NAME.test(value.Name)) malformed("Invalid network name");
  if (typeof value.Driver !== "string" || !NAME.test(value.Driver) || typeof value.Internal !== "boolean" || typeof value.EnableIPv6 !== "boolean") malformed("Missing network security settings");
  if (!record(value.Labels) || Object.values(value.Labels).some(x => typeof x !== "string")) malformed("Missing or malformed network labels");
  if (!record(value.IPAM) || !Array.isArray(value.IPAM.Config) || !value.IPAM.Config.length) malformed("Missing network IPAM configuration");
  // This lifecycle uses one unambiguous IPv4 allocation per network.
  if (value.IPAM.Config.length !== 1) malformed("Ambiguous network IPAM configuration");
  const config = value.IPAM.Config[0];
  if (!record(config) || typeof config.Subnet !== "string") malformed("Missing network subnet");
  const match = /^([^/]+)\/(0|[1-9]\d?)$/.exec(config.Subnet);
  if (!match || Number(match[2]) > 30) malformed("Invalid network IPv4 subnet");
  const base = networkIpv4(match[1]);
  const size = 2 ** (32 - Number(match[2]));
  const gateway = networkIpv4(config.Gateway);
  if (base % size !== 0 || gateway <= base || gateway >= base + size - 1) malformed("Network gateway does not belong to its usable CIDR subnet");
  if (value.Options !== undefined && !record(value.Options)) malformed("Invalid network options");
  const ipv6Option = value.Options?.["com.docker.network.enable_ipv6"];
  if (ipv6Option !== undefined && ( !["true", "false"].includes(ipv6Option) || (ipv6Option === "true") !== value.EnableIPv6)) malformed("Inconsistent network IPv6 evidence");
  const containers = value.Containers ?? {};
  if (!record(containers) || Object.entries(containers).some(([id, entry]) => !/^[a-f0-9]{64}$/i.test(id) || !record(entry))) malformed("Invalid attached network containers");
  return {
    schemaVersion: "1.1", source: "docker-inspect", objectType: "network",
    objectId: value.Id, id: value.Id, name: value.Name, driver: value.Driver,
    internal: value.Internal, ipv6: value.EnableIPv6, labels: { ...value.Labels },
    subnet: config.Subnet, gateway: config.Gateway,
    ipam: { ...value.IPAM, Config: value.IPAM.Config.map(item => ({ ...item })) },
    containers: Object.fromEntries(Object.entries(containers).map(([id, entry]) => [id, { ...entry }])),
    containerIds: Object.keys(containers), complete: true,
  };
}
function normalizeInspect(value, kind = "container") {
  if (kind === "network") return normalizeNetworkInspect(value);
  if (kind === "container") return normalizeContainerInspect(value);
  throw new DockerAdapterError("INVALID_OPERATION", "Invalid inspect kind");
}
class DockerAdapter{constructor({executor=execFile,timeoutMs=30000,dockerBin="docker"}={}){if(typeof executor!=="function")throw new DockerAdapterError("INVALID_EXECUTOR","Executor required");if(!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>120000)throw new DockerAdapterError("INVALID_TIMEOUT","Timeout out of bounds");this.executor=executor;this.timeoutMs=timeoutMs;this.dockerBin=dockerBin;if(executor===execFile&&dockerBin==="docker")runtimeAdapters.set(this,{run:this.run,inspect:this.inspect,executor});}
run(args){const checked=operation(args),operationId=crypto.randomUUID(),started=Date.now();return new Promise((resolve,reject)=>{let done=false;const finish=(err,result)=>{if(done)return;done=true;err?reject(err):resolve(result);};const timer=setTimeout(()=>finish(new DockerAdapterError("TIMEOUT","Docker command timed out",{operationId,timedOut:true})),this.timeoutMs);try{this.executor(this.dockerBin,checked,{shell:false,timeout:this.timeoutMs,maxBuffer:2*1024*1024},(error,stdout="",stderr="")=>{clearTimeout(timer);const code=error ? (typeof error.code==="number"?error.code:null) : 0;const classification=classify(String(stderr),code,error?.code==="ETIMEDOUT"||error?.killed===true);if(classification)finish(new DockerAdapterError(classification,sanitizeDiagnostic(stderr||error?.message||"Docker command failed"),{nativeOutput:{stdout:String(stdout),stderr:String(stderr)},operationId,operation:checked[0],subcommand:checked[1]||null,exitCode:code,commandStdout:sanitizeDiagnostic(stdout,4096),commandStderr:sanitizeDiagnostic(stderr,4096),stderrCategory:classification,stderrExcerpt:String(stderr||error?.message||"").replace(/[\r\n]+/g," ").replace(/(token|password|secret|authorization|src=)[^ ]*/ig,"[redacted]").slice(0,240),timedOut:classification==="TIMEOUT"}));else finish(null,{operationId,operation:checked[0],args:checked,exitCode:0,stdout:String(stdout),stderr:String(stderr),durationMs:Date.now()-started,timedOut:false});});}catch(e){clearTimeout(timer);finish(new DockerAdapterError("DAEMON_UNAVAILABLE",sanitizeDiagnostic(e.message),{operationId}));}});}
inspect(args,kind="container"){if(!["container","network"].includes(kind))return Promise.reject(new DockerAdapterError("INVALID_OPERATION","Invalid inspect kind"));return this.run([...(kind==="network"?["network","inspect"]:["inspect"]),"--format","{{json .}}",...args]).then(r=>{let v;try{v=JSON.parse(r.stdout);}catch(_){throw new DockerAdapterError("MALFORMED_OUTPUT","Inspect output is not JSON",{operationId:r.operationId});}if(Array.isArray(v)){if(v.length!==1)throw new DockerAdapterError("MALFORMED_OUTPUT","Expected one inspected object",{operationId:r.operationId});v=v[0];}return {...r,normalized:normalizeInspect(v,kind)};});}}
const nativeRun = DockerAdapter.prototype.run;
const nativeInspect = DockerAdapter.prototype.inspect;
module.exports={commandOutput,DockerAdapter,DockerAdapterError,normalizeInspect,normalizeContainerInspect,normalizeNetworkInspect,isRuntimeAdapter,sanitizeDiagnostic,operation,OPS};
