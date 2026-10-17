'use strict';
const permits=new WeakMap(),client=require('./dastAcceptanceClient');
const fail=()=>Object.assign(new Error('ACTIVE_NAMESPACE_BLOCKED'),{code:'ACTIVE_NAMESPACE_BLOCKED',nonRetryable:true});
function permit(adapter,authorization,scanId,parentId,imageId,directory,signal){
 if(!require('./dockerAdapter').isRuntimeAdapter(adapter)||!require('./module2ActiveDast').isIssuedAuthorization(authorization)||!require('./activeDastCommissioning').runtimeAllowed(authorization)||!/^[a-f0-9]{64}$/.test(parentId)||!/^sha256:[a-f0-9]{64}$/.test(imageId))throw fail();
 require('./module2ActiveDast').validateAuthorization(authorization,authorization);
 if(imageId!==authorization.zapImageDigest)throw fail();
 if(typeof directory!=='string'||!directory.startsWith('/tmp/cs-active-')||/[\r\n,]/.test(directory))throw fail();
 const token=Object.freeze({});permits.set(token,{adapter,authorization,scanId,parentId,imageId,directory,signal});return token;
}
function requirement(token,adapter,scanId,parentId){
 const r=permits.get(token);
 if(!r||r.signal?.aborted||r.adapter!==adapter||r.scanId!==scanId||r.parentId!==parentId||r.authorization.expiresAt<=Date.now()||!require('./activeDastCommissioning').runtimeAllowed(r.authorization))return null;
 return {imageId:r.imageId,role:'active-zap',directory:r.directory,networkId:r.authorization.scannerNetworkId};
}
function revoke(token){permits.delete(token);}
async function bind({adapter,lifecycle,scanId,authorization,scannerId,imageId,directory,signal}){
 const resources=lifecycle.resources.get(scanId);if(!resources||resources.diagnosticOnly)throw fail();
 const reference=resources.owned.networks.find(n=>n.id===authorization.scannerNetworkId);if(!reference)throw fail();
 const token=permit(adapter,authorization,scanId,scannerId,imageId,directory,signal);
 try{
  if(resources.clientResource){const out=await client.cleanup(adapter,resources.clientResource);if(!out.cleaned)throw fail();delete resources.clientResource;}
  resources.activeHelperAttempted=true;
  const helper=await client.provision(adapter,{scanId,networkId:reference.id,networkReference:reference,nativeArtifact:resources.nativeArtifact,namespaceParent:scannerId,namespaceScope:token,onCreated:r=>{resources.clientResource=r;}});
  resources.clientResource=helper;resources.acceptanceClientId=helper.id;lifecycle.observation.bindAcceptanceClient(client,helper);
  const network=resources.owned.networks.find(n=>n.role==='fixture');
  const gateway=(await adapter.inspect([resources.gatewayId],'container')).normalized;
  const proxy=`http://${gateway.networks[reference.name].IPAddress}:3128`;
  const evidence=await lifecycle.observation.collectActiveFixture({projectId:authorization.projectId,executionId:authorization.executionId,scanId,mode:'full',nativeConnect:true,gatewayContainerId:resources.gatewayId,scannerContainerId:helper.id,fixtureContainerId:authorization.fixtureContainerId,scannerNetworkId:reference.id,fixtureNetworkId:network.id,networkReferences:resources.owned.networks,target:{hostname:authorization.hostname,port:authorization.port,ip:authorization.ip,proxy},stagedPolicy:resources.staged});
  if(!require('./runtimeObservation').runtimeReady(evidence)||evidence.namespaceScope!=='ZAP_SHARED_NETWORK_NAMESPACE'||evidence.namespaceEvidence?.zapContainerId!==scannerId||evidence.namespaceEvidence?.helperId!==helper.id||!evidence.namespaceEvidence?.equivalent)throw fail();
  resources.runtimeObservation=evidence;return {token,helper,reference};
 }catch(error){revoke(token);throw error;}
}
async function verify(adapter,binding,scannerId){
 if(!binding)throw fail();const n=await client.verifyClient(adapter,binding.helper);
 if(n.namespaceEvidence?.zapContainerId!==scannerId||n.namespaceEvidence?.equivalent!==true)throw fail();
 const ref=binding.reference;if(!ref||requirement(binding.token,adapter,ref.scanIdentity.scanId,scannerId)?.networkId!==ref.id)throw fail();
 const network=await require('./ownedDockerNetworks').inspectOwnedNetwork(adapter,ref),text={};
 const commands=Object.entries(require('./runtimeObservation').NETWORK_COMMANDS);
 const snapshots=await require('./verifiedReads')(commands.map(([,args])=>()=>client.execute(adapter,binding.helper,args)));
 for(const [index,[kind]] of commands.entries()){
  const result=snapshots[index];
  if(result.exitCode!==0||result.stderr!==''||typeof result.stdout!=='string'||Buffer.byteLength(result.stdout)>65536)throw fail();text[kind]=result.stdout;
 }
 binding.lastRoutes=require('./runtimeNetworkText').verifyNetworkText(text,network,n.networks[network.name]);
 binding.lastListeners=[];
 const tables=[['tcp',4,'tcp'],['tcp6',6,'tcp'],['udp',4,'udp'],['udp6',6,'udp']];
 const listeners=await require('./verifiedReads')(tables.map(([name])=>()=>client.execute(adapter,binding.helper,['cat',`/proc/net/${name}`])));
 for(const [index,[,family,protocol]] of tables.entries()){
  const result=listeners[index];
  if(result.exitCode!==0||result.stderr!=='')throw fail();binding.lastListeners.push(...require('./zapContainmentDiagnostic').listeners(result.stdout,family,protocol));
 }
 const after=(await client.verifyClient(adapter,binding.helper)).namespaceEvidence;if(JSON.stringify(after)!==JSON.stringify(n.namespaceEvidence))throw fail();
 return {...after,routes:binding.lastRoutes,listeners:binding.lastListeners};
}
async function cleanup(adapter,binding){if(!binding)return {cleaned:true,residual:[]};try{return await client.cleanup(adapter,binding.helper);}finally{revoke(binding.token);}}
module.exports={bind,verify,cleanup,requirement,permit,revoke};
