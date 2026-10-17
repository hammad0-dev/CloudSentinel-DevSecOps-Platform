'use strict';
const artifacts=require('../config/active-runtime-artifacts.json');
function assertReady(catalog=artifacts) {
  const missing=[];
  if(!catalog.zap?.capabilities)missing.push('ZAP_POLICY_CAPABILITIES_UNVERIFIED');
  if(!catalog.fixture)missing.push('VULNERABLE_FIXTURE_IMAGE_UNVERIFIED');
  if(catalog.containmentAdapterValidated!==true)missing.push('ZAP_NAMESPACE_CONTAINMENT_UNVERIFIED');
  if(missing.length)throw Object.assign(new Error('Active runtime prerequisites missing'),{code:'ACTIVE_RUNTIME_BLOCKED',missing,nonRetryable:true});
  // This admits the catalog only; actual image/container/namespace checks are
  // mandatory in ActiveZapRuntime and cannot be replaced by catalog assertions.
  return require('./activeZapRuntime').capabilities(catalog);
}
async function verifyAvailable(adapter,catalog=artifacts) {
  await require('./verifiedReads')([
    ()=>verifyImage(adapter,catalog.zap,'zap'),
    ()=>verifyImage(adapter,catalog.fixture,'fixture')
  ]);
  return true;
}
async function verifyImage(adapter,item,kind){
    if(!item||!/^sha256:[a-f0-9]{64}$/.test(item.imageId||''))throw Object.assign(new Error('Missing immutable artifact'),{code:'ACTIVE_IMAGE_MISMATCH'});
    const out=await adapter.run(['image','inspect',item.reference]);
    const values=JSON.parse(out.stdout);
    if(out.exitCode!==0||out.stderr!==''||!Array.isArray(values)||values.length!==1)throw Object.assign(new Error('Image unavailable'),{code:'ACTIVE_IMAGE_MISMATCH'});
    const raw=values[0];
    if(raw.Id!==item.imageId||raw.Architecture!==item.architecture||raw.Os!==item.os)throw Object.assign(new Error('Image identity mismatch'),{code:'ACTIVE_IMAGE_MISMATCH'});
    if(kind==='fixture'&&item.reference.startsWith('sha256:'))require('./dastFixture').verifyPythonImage(raw);
    else if(kind==='zap'&&item.reference.startsWith('sha256:'))require('./zapContainmentDiagnostic').verifyZapImage(raw);
    else if(!raw.RepoDigests?.includes(item.reference))throw Object.assign(new Error('Repository identity mismatch'),{code:'ACTIVE_IMAGE_MISMATCH'});
  return true;
}
module.exports={artifacts,assertReady,verifyAvailable,verifyImage};
