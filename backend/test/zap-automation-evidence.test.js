'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('fs/promises'),os=require('os'),path=require('path'),crypto=require('crypto');
const {save}=require('../services/zapAutomationEvidence');
const input=output=>({authorization:{projectId:11,executionId:26},scannerId:'a'.repeat(64),index:0,reason:'ZAP_STARTUP_LOG_UNVERIFIED',output});
test('private evidence retains unknown lines, stream identity, exact native hashes and sanitized errors',async()=>{
 const stdout='100 [ZAP-daemon] INFO org.example - ready\nUnknown output\nAuthorization: Bearer private-secret\nRead-only file system /home/hammad/private',stderr='api.key=private-key\n';
 const file=await save({...input({exitCode:1,stdout,stderr,streamsCombined:true}),secrets:['private-key','private-secret']});
 try{
  const text=await fs.readFile(file,'utf8'),r=JSON.parse(text);
  assert.equal(r.exitCode,1);assert.equal(r.streamLayout,'COMBINED_IN_STDOUT');assert.equal(r.stdout.sha256,crypto.createHash('sha256').update(stdout).digest('hex'));assert.equal(r.stdout.unrecognized[0].lineNumber,2);assert.equal(r.stdout.unrecognized[0].text,'Unknown output');
  assert.equal(r.stderr.bytes,Buffer.byteLength(stderr));assert.equal(r.stdout.classification,'ZAP_INITIALIZATION_FAILED');
  for(const secret of ['private-secret','private-key','/home/hammad/private'])assert.ok(!text.includes(secret));
  assert.equal((await fs.stat(path.dirname(file))).mode&511,448);assert.equal((await fs.stat(file)).mode&511,384);
 }finally{await fs.rm(path.dirname(file),{recursive:true});}
});
test('large output, exact unknown lines and missing streams are bounded without manufacturing evidence',async()=>{
 for(const output of [{stdout:'x'.repeat(1048577),stderr:''},{stdout:Array.from({length:200},()=> 'unrecognized '+'x'.repeat(600)).join('\n'),stderr:''},{}]){
  const file=await save(input(output));try{const bytes=await fs.readFile(file),r=JSON.parse(bytes);assert.ok(bytes.length<=196608);
   if(output.stdout?.length>1048576){assert.equal(r.stdout.inputBounded,false);assert.equal(r.stdout.excerpt,null);}
   else if(output.stdout){assert.equal(r.stdout.unrecognized.length,64);assert.equal(r.stdout.unrecognizedTruncated,true);assert.equal(r.stdout.unrecognized[0].truncated,true);}
   else{assert.equal(r.stdout.available,false);assert.equal(r.stderr.available,false);assert.equal(r.exitCode,null);}
  }finally{await fs.rm(path.dirname(file),{recursive:true});}
 }
});
test('invalid identity, substituted private directory and storage failure reject evidence writes',async()=>{
 for(const authorization of [{projectId:17,executionId:26},{projectId:11,executionId:0}])await assert.rejects(save({...input({}),authorization}),{code:'ZAP_AUTOMATION_EVIDENCE_WRITE_FAILED'});
 const base=await fs.mkdtemp(path.join(os.tmpdir(),'cs-zap-evidence-test-'));
 try{
  for(const change of [s=>({...s,uid:process.getuid()+1}),s=>({...s,mode:0o777}),s=>({...s,isSymbolicLink:()=>true})]){
   const fsImpl={...fs,lstat:async p=>change(Object.assign({},await fs.lstat(p),{isDirectory:()=>true,isSymbolicLink:()=>false}))};await assert.rejects(save(input({stdout:'unknown',stderr:''}),{baseDir:base,fsImpl}),{code:'ZAP_AUTOMATION_EVIDENCE_WRITE_FAILED'});
  }
  await assert.rejects(save(input({}),{fsImpl:{...fs,mkdtemp:async()=>{throw Error('ENOSPC');}}}),{code:'ZAP_AUTOMATION_EVIDENCE_WRITE_FAILED'});
 }finally{await fs.rm(base,{recursive:true});}
});
