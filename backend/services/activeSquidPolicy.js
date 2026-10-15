'use strict';
const base=require('./squidPolicy');
module.exports={
  stagePolicy:options=>base.stagePolicy({...options,profile:'active'}),
  async verifyStagedPolicy(staged){
    await base.verifyStagedPolicy(staged);
    if(staged.policy!==base.activePolicy(staged.target))throw Object.assign(new Error('Active path policy mismatch'),{code:'ACTIVE_PATH_POLICY_BLOCKED'});
    return {verified:true,policyDigest:staged.policyDigest};
  },
  cleanupPolicy:base.cleanupPolicy,
};
