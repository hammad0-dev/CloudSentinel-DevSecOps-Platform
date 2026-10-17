'use strict';
// Diagnostic-only deadlines; never modifies production authorization.
const BUDGET=Object.freeze({startupMs:90000,activeMs:60000,reportMs:30000,cleanupReserveMs:30000});
function create({expiresAt,now=Date.now}){
 const start=now(),overall=expiresAt-BUDGET.cleanupReserveMs;
 if(overall-start<BUDGET.startupMs+BUDGET.activeMs+BUDGET.reportMs)throw Object.assign(Error('Insufficient diagnostic budget'),{code:'DIAGNOSTIC_BUDGET_INSUFFICIENT'});
 let phase='STARTUP',deadline=Math.min(overall,start+BUDGET.startupMs),previous=start,finished=false;
 function check(){const time=now();if(time>=overall||time>=deadline)throw Object.assign(Error('Diagnostic phase deadline'),{code:time>=overall?'DIAGNOSTIC_OVERALL_TIMEOUT':`DIAGNOSTIC_${phase}_TIMEOUT`});return time;}
 return {async run(operation){check();let timer;try{return await Promise.race([Promise.resolve().then(operation),new Promise((_,reject)=>{timer=setTimeout(()=>{try{check();}catch(error){reject(error);}},Math.max(1,Math.min(deadline,overall)-now()));})]);}finally{clearTimeout(timer);}},observe(text){const time=check();const starts=(text.match(/^Job activeScan started\r?$/gm)||[]).length,ends=(text.match(/^Job activeScan finished, time taken: .*$/gm)||[]).length;
 if(starts>1||ends>1||ends>starts)throw Object.assign(Error('Invalid Active job boundaries'),{code:'DIAGNOSTIC_JOB_BOUNDARY_INVALID'});
 if(phase==='STARTUP'&&starts){phase='ACTIVE';deadline=Math.min(overall,previous+BUDGET.activeMs);}
 if(phase==='ACTIVE'&&ends){const duration=text.match(/^Job activeScan finished, time taken: (\d{2,}):(\d{2}):(\d{2})\r?$/m);if(!duration||Number(duration[2])>59||Number(duration[3])>59||(Number(duration[1])*3600+Number(duration[2])*60+Number(duration[3]))>60)throw Object.assign(Error('Invalid Active duration'),{code:'DIAGNOSTIC_JOB_BOUNDARY_INVALID'});check();finished=true;phase='REPORT';deadline=Math.min(overall,time+BUDGET.reportMs);}
 previous=time;check();},check,complete(){check();if(!finished)throw Object.assign(Error('Missing completed Active job'),{code:'DIAGNOSTIC_ACTIVE_INCOMPLETE'});},get phase(){return phase;},budgets:BUDGET};
}
module.exports={create,BUDGET};
