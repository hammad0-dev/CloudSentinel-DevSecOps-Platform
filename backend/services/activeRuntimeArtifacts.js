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
module.exports={artifacts,assertReady};
