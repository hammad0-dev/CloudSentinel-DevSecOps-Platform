'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
for(const scenario of ['complete','expired-before-insert','expired-during-insert','persistence-failure'])test(`Module 2 deadline-aware persistence: ${scenario}`,async t=>{
 const ids=['../db','../services/orchestrator'].map(p=>require.resolve(p)),saved=ids.map(id=>require.cache[id]);
 let now=1000,record,finished;
 t.mock.method(Date,'now',()=>now);
 const result={status:'COMPLETED_WITH_FINDINGS',durationMs:50,cleanup:{cleaned:true,residual:[]},timing:{deadline:2000},findings:[{cwe_id:79},{cwe_id:89}],summary:{total:2}};
 const module2=require('../services/module2ActiveDast'),phases=require('../services/commissioningPhases');
 t.mock.method(phases,'assertActive',async()=>({}));
 t.mock.method(phases,'finish',async(p,c,r)=>{finished=r;});
 t.mock.method(module2,'execute',async()=>{if(scenario==='expired-before-insert')now=2000;return result;});
 const pool={async query(sql,args){
  if(sql.startsWith('INSERT INTO active_dast_executions')){
   if(scenario==='persistence-failure')throw Error('offline persistence failure');
   record={status:args[2],result:JSON.parse(args[4])};if(scenario==='expired-during-insert')now=2000;
  }
  if(sql.startsWith('UPDATE active_dast_executions'))record={status:args[2],result:JSON.parse(args[3])};
  return {rows:[]};
 }};
 require.cache[ids[0]]={id:ids[0],filename:ids[0],loaded:true,exports:pool};delete require.cache[ids[1]];
 try{
  const task=require(ids[1]).resumeActive(100,42,7);
  if(scenario==='persistence-failure'){await assert.rejects(task,/offline persistence failure/);assert.equal(finished.status,'FAILED');assert.equal(finished.cleanup.cleaned,true);}
  else{await task;assert.equal(record.status,scenario==='complete'?'COMPLETED_WITH_FINDINGS':'TIMED_OUT');assert.equal(finished.status,record.status);assert.equal(finished.cleanup.cleaned,true);if(scenario!=='complete')assert.equal(record.result.findings,undefined);else assert.equal(record.result.findings.length,2);}
 }finally{ids.forEach((id,i)=>{if(saved[i])require.cache[id]=saved[i];else delete require.cache[id];});}
});
