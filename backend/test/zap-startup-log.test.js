'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {analyze}=require('../services/zapStartupLog');
const {summarize}=require('../services/zapStartupEvidence');
const line=(level,message)=>`34974 [ZAP-daemon] ${level} org.zaproxy.Example - ${message}`;
test('genuine INFO rule titles and INFO/DEBUG Exception titles are harmless',()=>{
 const fixture=require('./fixtures/zap-startup-info-false-positive.json');
 assert.equal(analyze(fixture.excerpt).failure,null);assert.equal(fixture.historicalClassification,'ZAP_INITIALIZATION_FAILED');assert.equal(fixture.historicalStatus,'BLOCKED');
 for(const level of ['INFO','DEBUG'])for(const title of ['Application Error Disclosure','Information Disclosure - Debug Error Messages','Exception Disclosure'])assert.equal(analyze(line(level,'Loaded passive scan rule: '+title)).failure,null);
 assert.equal(summarize(fixture.excerpt).extensionsLoaded,false);
});
test('ERROR/FATAL and their multiline Java stack traces fail closed',()=>{
 for(const level of ['ERROR','FATAL']){
  const parsed=analyze(line(level,'startup failed')+'\njava.lang.IllegalStateException: broken\n\tat org.example.Main.start(Main.java:1)\nCaused by: java.io.IOException: broken');
  assert.equal(parsed.failure,'ZAP_INITIALIZATION_FAILED');assert.equal(parsed.failures[0].lines.length,4);
 }
});
test('known initialization-impacting messages fail regardless of format or severity',()=>{
 for(const [message,code] of [['No space left on device','ZAP_STORAGE_EXHAUSTED'],['SAXParseException: Premature end of file','ZAP_INITIALIZATION_CORRUPT'],['Permission denied','ZAP_INITIALIZATION_FAILED'],['Read-only file system','ZAP_INITIALIZATION_FAILED'],['Failed to load add-on','ZAP_INITIALIZATION_FAILED'],["WARNING: Couldn't create user preferences directory",'ZAP_PREFERENCES_NOT_READY'],['java.net.BindException: Address already in use','ZAP_INITIALIZATION_FAILED']])assert.equal(analyze(message).failure,code);
});
test('unknown, missing and truncated records never imply readiness',()=>{
 for(const text of ['', 'unrecognized output', '34974 [ZAP-daemon] INFO org.zaproxy.Example -'])assert.equal(analyze(text).failure,'ZAP_STARTUP_LOG_UNVERIFIED');
 const clean=summarize(line('INFO','Extensions loaded')+'\n'+line('INFO','ZAP is now listening on 127.0.0.1:8090'));
 assert.equal(clean.classification,null);assert.equal(clean.extensionsLoaded,true);assert.equal(clean.loopbackReady,true);
});
test('error diagnostics retain a middle-of-log failure and redact its path',()=>{
 const text=(line('INFO','normal progress')+'\n').repeat(1000)+line('ERROR','Permission denied /home/hammad/private')+'\n'+(line('INFO','normal progress')+'\n').repeat(1000);
 const summary=summarize(text);assert.match(summary.excerpt,/Permission denied/);assert.ok(!summary.excerpt.includes('/home/hammad'));
});
test('positive readiness command preserves adapter limits and is valid offline Python',()=>{
 const {READINESS_ARGS,READINESS_PROBE}=require('../services/zapStartupEvidence');
 for(const arg of READINESS_ARGS){assert.ok(arg.length<512);assert.ok(!/[\r\n\0]/.test(arg));}
 assert.equal(READINESS_ARGS.slice(4).join(''),READINESS_PROBE);
 const r=require('child_process').spawnSync('python3',['-I','-c','import ast,sys;ast.parse(sys.argv[1])',READINESS_PROBE],{encoding:'utf8'});
 assert.equal(r.status,0,r.stderr);
});
test('documented Automation 0.60.0 console formats are recognized without accepting arbitrary Job lines',()=>{
 // Source formats, NOT retained execution-26 observations:
 // https://github.com/zaproxy/zap-extensions/blob/automation-v0.60.0/addOns/automation/src/main/resources/org/zaproxy/addon/automation/resources/Messages.properties
 const valid='Job requestor started\n\tJob requestor finished, time taken: 00:00:01\nAutomation plan succeeded!';
 assert.equal(analyze(valid).failure,null);
 for(const text of ['Job requestor did something','Job requestor finished, time taken: invalid','Automation plan succeeded! junk','Automation plan warnings:','Automation plan failures:',valid+'\nunknown output',valid+'\n100 [ZAP-daemon] INFO org.example - malformed\0'])assert.ok(analyze(text).failure);
 for(const text of ['100 [ZAP-daemon] ERROR org.example - failed','No space left on device','SAXParseException: Premature end of file'])assert.notEqual(analyze(valid+'\n'+text).failure,null);
 const unknown=analyze('Job requestor started\nnew format');assert.equal(unknown.unknownRecords,1);assert.equal(unknown.records[1].lineNumber,2);
 const e=require('./helpers/zapInitializationEvidence')();e.startupLog=valid;assert.throws(()=>require('../services/zapInitialization').assertInitialized(e,e.imageId));
});

test('genuine passive diagnostic unsupported-file rejection remains a startup failure',()=>{
 assert.equal(analyze("File type is not supported 'zap.sh'\nUsage:\n\tzap.sh [Options]").failure,'ZAP_INITIALIZATION_FAILED');
});

test('all 13 genuine a2 progress records match their native bytes and classify harmlessly',()=>{
 const fixture=require('./fixtures/zap-passive-progress-a2.json'),crypto=require('crypto');
 assert.equal(fixture.historicalRunnerStatus,'BLOCKED');assert.equal(fixture.historicalRunnerExitCode,1);assert.equal(fixture.nativeProcessExitCode,0);
 for(const line of fixture.lines){assert.equal(Buffer.byteLength(line.text),line.bytes);assert.equal(crypto.createHash('sha256').update(line.text).digest('hex'),line.sha256);assert.equal(analyze(line.text).failure,null);}
 assert.equal(analyze(fixture.lines.map(x=>x.text).join('\n')).unknownRecords,0);
});
test('passive progress recognition rejects unauthorized values, jobs, paths and disguised failures',()=>{
 for(const line of ['Job requestor set method = POST','Job requestor set responseCode = 403','Job requestor set url = http://external.com:18080/test/sqli?id=1','Job requestor requesting URL http://fixture.test:18080/test/sqli?id=2','Job requestor requesting URL http://fixture.test:18080/test/xss?q=payload','Job requestor set headers = injected','Job passiveScan-wait set maxDuration = 0','Job report set reportDir = /home/zap','Job report generated report /etc/passwd','Job activeScan set threadPerHost = 100','Job report set template = traditional-json EXTRA','Job requestor set method = GET\nunknown output'])assert.notEqual(analyze(line).failure,null,line);
 for(const suffix of ['42 [ZAP] ERROR org.example - real error','No space left on device','Permission denied','SAXParseException: Premature end of file'])assert.notEqual(analyze('Job requestor set method = GET\n'+suffix).failure,null);
});

test('execution 32 Active policy/progress records replay with exact native fingerprints',()=>{
 const f=require('./fixtures/zap-active-progress-e32.json'),crypto=require('crypto');
 assert.equal(f.nativeExitCode,0);assert.equal(f.historicalFailure,'ZAP_STARTUP_LOG_UNVERIFIED');assert.equal(f.lines.length,27);
 for(const r of f.lines){assert.equal(Buffer.byteLength(r.text),r.bytes);assert.equal(crypto.createHash('sha256').update(r.text).digest('hex'),r.sha256);assert.equal(analyze(r.text).failure,null,r.text);}
 const replay=f.lines.map(r=>r.text).join('\n')+'\nJob activeScan started\nJob activeScan finished, time taken: 00:00:26\nAutomation plan succeeded!';
 assert.equal(analyze(replay).unknownRecords,0);assert.equal(analyze(replay).failure,null);
 // No complete daemon/rule/policy/listener evidence: progress is not readiness.
 const e=require('./helpers/zapInitializationEvidence')();e.startupLog=replay;assert.throws(()=>require('../services/zapInitialization').assertInitialized(e,e.imageId));
 for(const tail of ['unknown output','No space left on device','100 [ZAP] ERROR example - failed','Permission denied','SAXParseException: Premature end of file'])assert.notEqual(analyze(replay+'\n'+tail).failure,null);
});
test('Active progress parser rejects unsafe values, extra rules, malformed and missing output',()=>{
 for(const s of ['', 'Job activeScan set threadPerHost = 2','Job activeScan set delayInMs = 0','Job activeScan set maxScanDurationInMins = 10','Job activeScan set context = other','Job activeScan-policy set defaultThreshold = Low','Job activeScan-policy set rule 99999 threshold to LOW','Job activeScan set url = http://external.test','Job activeScan set policy = cloudsentinel-active-fixture-v1 EXTRA','Job activeScan finished, time taken: malformed','Job activeScan started\0'])assert.notEqual(analyze(s).failure,null,s);
});
