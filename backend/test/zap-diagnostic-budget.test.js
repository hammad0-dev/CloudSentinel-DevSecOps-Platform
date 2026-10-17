'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{create}=require('../services/zapDiagnosticBudget');
function fixture(){let time=0;return {set:v=>time=v,b:create({expiresAt:300000,now:()=>time})};}
test('slow JVM startup does not consume Active job budget',()=>{const {set,b}=fixture();set(80000);b.observe('startup');set(80500);b.observe('Job activeScan started');set(139000);b.observe('Job activeScan started\nJob activeScan finished, time taken: 00:00:58');b.complete();});
test('startup deadline is finite',()=>{const {set,b}=fixture();set(90000);assert.throws(()=>b.check(),{code:'DIAGNOSTIC_STARTUP_TIMEOUT'});});
test('Active timeout rejects incomplete job',()=>{const {set,b}=fixture();set(1000);b.observe('Job activeScan started');set(60000);assert.throws(()=>b.check(),{code:'DIAGNOSTIC_ACTIVE_TIMEOUT'});});
test('report deadline is finite',()=>{const {set,b}=fixture();b.observe('Job activeScan started');set(1000);b.observe('Job activeScan started\nJob activeScan finished, time taken: 00:00:01');set(31000);assert.throws(()=>b.complete(),{code:'DIAGNOSTIC_REPORT_TIMEOUT'});});
test('incomplete and duplicate jobs cannot pass',()=>{const {b}=fixture();assert.throws(()=>b.complete(),{code:'DIAGNOSTIC_ACTIVE_INCOMPLETE'});assert.throws(()=>b.observe('Job activeScan started\nJob activeScan started'),{code:'DIAGNOSTIC_JOB_BOUNDARY_INVALID'});});
test('overall deadline reserves cleanup and never renews',()=>{let time=0;const b=create({expiresAt:210000,now:()=>time});time=180000;assert.throws(()=>b.check(),{code:'DIAGNOSTIC_OVERALL_TIMEOUT'});assert.throws(()=>create({expiresAt:209999,now:()=>0}),{code:'DIAGNOSTIC_BUDGET_INSUFFICIENT'});});
test('deadline interrupts stalled read-only observation',async()=>{const start=Date.now();const b=create({expiresAt:start+300000,now:Date.now}); // use an advancing clock to reach the real timer without waiting 90s
 let time=0;const fast=create({expiresAt:210000,now:()=>time});time=89995;
 setTimeout(()=>{time=90000;},1);await assert.rejects(fast.run(()=>new Promise(()=>{})),{code:'DIAGNOSTIC_STARTUP_TIMEOUT'});b.check();
});
