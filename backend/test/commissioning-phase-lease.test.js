'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const lease=require('../services/commissioningPhaseLease');
const c={projectId:11,executionId:29,userId:3};
test('phase lease is bounded by overall expiry and the 165 second reserve',async()=>{
 const now=1_000_000,calls=[];const db={async query(sql,args){calls.push({sql,args});return {rows:[{active_lease_id:args[3],active_lease_expires_at:new Date(args[4]),overall_deadline:new Date(args[5])}]};}};
 const result=await lease.issue(db,c,now+240000,now+300000,now);
 assert.equal(result.expiresAt,now+240000);assert.match(result.leaseId,/^[0-9a-f-]{36}$/);assert.match(calls[0].sql,/active_lease_id IS NULL/);
 await assert.rejects(lease.issue(db,c,now+164999,now+300000,now),{code:'COMMISSIONING_TIME_BUDGET_BLOCKED'});
});
test('lease consumption is atomic, single-use and rejects expired leases',async()=>{
 let rows=[{active_lease_expires_at:new Date(Date.now()+200000),overall_deadline:new Date(Date.now()+220000)}];
 const db={async query(sql){assert.match(sql,/active_lease_consumed_at IS NULL/);return {rows:rows.splice(0)}}};
 const result=await lease.consume(db,c,'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');assert.ok(result.expiresAt>Date.now());
 await assert.rejects(lease.consume(db,c,'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),{code:'COMMISSIONING_PHASE_LEASE_BLOCKED'});
});
test('malformed or replayed lease identities fail closed',async()=>{
 await assert.rejects(lease.consume({query:async()=>({rows:[]})},c,'forged'),{code:'COMMISSIONING_PHASE_LEASE_BLOCKED'});
});
