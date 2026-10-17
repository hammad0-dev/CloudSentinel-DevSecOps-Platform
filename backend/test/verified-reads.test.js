'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),reads=require('../services/verifiedReads');
function deferred(){let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};}
test('independent reads start together and results preserve input order',async()=>{
 const gate=deferred(),started=[];
 const result=reads([async()=>{started.push(1);await gate.promise;return 'first';},async()=>{started.push(2);gate.resolve();return 'second';}]);
 assert.deepEqual(await result,['first','second']);assert.deepEqual(started,[1,2]);
});
test('all failed/successful in-flight reads settle before failure cleanup is permitted',async()=>{
 const gate=deferred(),error=Error('ownership');let finished=false,rejected=false;
 const result=reads([()=>{throw error;},async()=>{await gate.promise;finished=true;}]);
 result.catch(()=>{rejected=true;});await Promise.resolve();await Promise.resolve();assert.equal(rejected,false);
 gate.resolve();await assert.rejects(result,e=>e===error);assert.equal(finished,true);
});
test('image inspections run concurrently without registry access and every identity is validated',async()=>{
 const catalog={zap:{reference:'zap@sha256:'+'a'.repeat(64),imageId:'sha256:'+'a'.repeat(64),architecture:'amd64',os:'linux'},fixture:{reference:'fixture@sha256:'+'b'.repeat(64),imageId:'sha256:'+'b'.repeat(64),architecture:'amd64',os:'linux'}};
 const gate=deferred(),seen=[];
 const adapter={async run(args){assert.deepEqual(args.slice(0,2),['image','inspect']);seen.push(args[2]);if(seen.length===2)gate.resolve();await gate.promise;const i=Object.values(catalog).find(i=>i.reference===args[2]);return {exitCode:0,stderr:'',stdout:JSON.stringify([{Id:i.imageId,Architecture:'amd64',Os:'linux',RepoDigests:[i.reference]}])};}};
 assert.equal(await require('../services/activeRuntimeArtifacts').verifyAvailable(adapter,catalog),true);assert.equal(seen.length,2);
 adapter.run=async args=>({exitCode:0,stderr:'',stdout:JSON.stringify([{Id:'sha256:'+'c'.repeat(64),Architecture:'amd64',Os:'linux',RepoDigests:[args[2]]}])});
 await assert.rejects(require('../services/activeRuntimeArtifacts').verifyAvailable(adapter,catalog),{code:'ACTIVE_IMAGE_MISMATCH'});
});
