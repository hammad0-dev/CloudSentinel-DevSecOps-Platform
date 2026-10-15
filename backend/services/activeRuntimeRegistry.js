'use strict';
const live=new Map();
const fail=()=>Object.assign(new Error('No live grant-bound Active lifecycle'),{code:'ACTIVE_RUNTIME_BLOCKED',nonRetryable:true});
function key(a){return `${a.projectId}:${a.executionId}:${a.targetId}`;}
function register(authorization,{lifecycle,adapter,scanId}) {
  require('./activeRuntimeArtifacts').assertReady();
  if(!(lifecycle instanceof require('./dastGateway').SecureGatewayLifecycle)||!require('./dockerAdapter').isRuntimeAdapter(adapter)||lifecycle.adapter!==adapter)throw fail();
  const resources=lifecycle.resources.get(scanId);
  if(!resources||resources.fixtureResource?.id!==authorization.fixtureContainerId||!resources.owned?.networks.some(n=>n.id===authorization.scannerNetworkId)||live.has(key(authorization)))throw fail();
  live.set(key(authorization),{lifecycle,adapter,scanId});
}
function consume(authorization) {
  const k=key(authorization),entry=live.get(k);if(!entry)throw fail();
  live.delete(k);
  return new (require('./activeZapRuntime').ActiveZapRuntime)(entry);
}
module.exports={register,consume};
