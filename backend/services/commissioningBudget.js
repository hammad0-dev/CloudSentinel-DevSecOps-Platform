'use strict';
// Scheduling reserves, not claims that a runtime has demonstrated these timings.
// Never increase an authorization expiry to make this budget fit.
const BUDGET=Object.freeze({startupMs:120000,scanMs:60000,reportMs:15000,cleanupMs:30000});
const minimumMs=Object.values(BUDGET).reduce((a,b)=>a+b,0);
const REUSE_BUDGET=Object.freeze({...BUDGET,startupMs:60000});
const reuseMinimumMs=Object.values(REUSE_BUDGET).reduce((a,b)=>a+b,0);
function minimumFor(a){return /^[a-f0-9]{64}$/.test(a?.retainedScannerId||'')?reuseMinimumMs:minimumMs;}
const fail=code=>Object.assign(new Error(code),{code,nonRetryable:true,status:403});
const leases=new WeakMap();
function earliest(values){
 if(!values.length||values.some(v=>!Number.isSafeInteger(v)||v<=0))throw fail('COMMISSIONING_DEADLINE_BLOCKED');
 return Math.min(...values);
}
function requireTime(deadline,required=minimumMs,now=Date.now()){
 if(!Number.isSafeInteger(deadline)||deadline-now<required){
  const error=fail('COMMISSIONING_TIME_BUDGET_BLOCKED');
  if(Number.isSafeInteger(deadline)&&Number.isSafeInteger(now)&&Number.isSafeInteger(required))error.budget={remainingMs:deadline-now,requiredMs:required};
  throw error;
 }
 return deadline;
}
function approvedDeadline(context,values,now=Date.now()){
 const commissioning=require('./activeDastCommissioning');
 if(!commissioning.activeAllowed(context,now))throw fail('COMMISSIONING_ACTIVE_AUTHORIZATION_BLOCKED');
 const scope=commissioning.selection(context,now);
 // activeAllowed has already validated the legacy environment continuation.
 const continuation=require('./commissioningControl').read(context,now)||JSON.parse(process.env.DAST_ACTIVE_COMMISSIONING_CONTINUATION_CONTEXT||'null');
 return earliest([...values,scope?.expiresAt,continuation?.expiresAt]);
}
function start(deadline,{signal,authorization,now=Date.now,setTimer=setTimeout,clearTimer=clearTimeout}={}){
 requireTime(deadline,minimumFor(authorization),now());
 const controller=new AbortController();let reason,timer;
 const abort=code=>{if(!reason){reason=fail(code);controller.abort(reason);}};
 const external=()=>abort('ACTIVE_CANCELLED');
 const check=()=>{if(now()>=deadline-BUDGET.cleanupMs)abort('ACTIVE_TIMED_OUT');if(reason)throw reason;};
 const arm=()=>{timer=setTimer(()=>abort('ACTIVE_TIMED_OUT'),Math.max(0,deadline-BUDGET.cleanupMs-now()));};
 signal?.addEventListener('abort',external,{once:true});if(signal?.aborted)external();arm();
 const lease={deadline,signal:controller.signal,check,
  beforePlan(){check();requireTime(deadline,BUDGET.scanMs+BUDGET.reportMs+BUDGET.cleanupMs,now());},
  async run(operation){
   check();let rejectAbort;
   const aborted=new Promise((_,reject)=>{rejectAbort=()=>reject(reason||fail('ACTIVE_CANCELLED'));controller.signal.addEventListener('abort',rejectAbort,{once:true});});
   // Drain bounded in-flight adapter calls before ownership-safe cleanup; never
   // leave a late provisioning promise creating resources behind cleanup.
   const task=Promise.resolve().then(()=>{check();return operation();});
   try{const result=await Promise.race([task,aborted]);check();return result;}
   finally{controller.signal.removeEventListener('abort',rejectAbort);await task.catch(()=>{});}
  },
  close(){clearTimer(timer);signal?.removeEventListener('abort',external);leases.delete(controller.signal);}
 };
 leases.set(controller.signal,lease);return lease;
}
function beforePlan(signal){const lease=leases.get(signal);if(!lease)throw fail('COMMISSIONING_DEADLINE_BLOCKED');lease.beforePlan();}
function fenceResult(result,now=Date.now()){
 if(result.timing&&result.status.startsWith('COMPLETED')&&(!Number.isSafeInteger(result.timing.deadline)||now>=result.timing.deadline)){
  result.status='TIMED_OUT';result.reason='ACTIVE_TIMED_OUT';delete result.findings;delete result.summary;return true;
 }
 return false;
}
module.exports={BUDGET,REUSE_BUDGET,minimumMs,reuseMinimumMs,minimumFor,earliest,requireTime,approvedDeadline,start,beforePlan,fenceResult};
