'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {sonarOrganizationArgs}=require('../routes/sast/config');
const initial=process.env.SONAR_ORGANIZATION;
test.afterEach(()=>{if(initial===undefined)delete process.env.SONAR_ORGANIZATION;else process.env.SONAR_ORGANIZATION=initial;});
test('Cloud receives the trimmed configured organization key',()=>{process.env.SONAR_ORGANIZATION=' fixture-org ';assert.deepEqual(sonarOrganizationArgs('https://sonarcloud.io'),['-Dsonar.organization=fixture-org']);});
test('missing Cloud organization fails before launching a scanner',()=>{delete process.env.SONAR_ORGANIZATION;for(const host of ['https://sonarcloud.io','https://sonarqube.us'])assert.throws(()=>sonarOrganizationArgs(host),/requires SONAR_ORGANIZATION/);});
test('self-hosted Sonar does not require Cloud organization',()=>{delete process.env.SONAR_ORGANIZATION;assert.deepEqual(sonarOrganizationArgs('http://localhost:9000'),[]);});
test('scanner invocation carries project identity, host and organization together without launching analysis',async()=>{
 process.env.SONAR_ORGANIZATION='fixture-org';const childProcess=require('node:child_process');const original=childProcess.spawn;const modulePath=require.resolve('../routes/sast/pipeline');let captured;
 childProcess.spawn=(command,args)=>{captured={command,args};const child=new EventEmitter();child.stdout=new EventEmitter();child.stderr=new EventEmitter();child.kill=()=>{};process.nextTick(()=>child.emit('close',0));return child;};delete require.cache[modulePath];
 try{const {runSonarScannerAsync}=require(modulePath);await runSonarScannerAsync(10,'/tmp/sonar-organization-test-nonexistent','https://sonarcloud.io','main');assert.ok(captured.args.includes('-Dsonar.organization=fixture-org'));assert.ok(captured.args.includes('-Dsonar.projectKey=cloudsentinel_10'));assert.ok(captured.args.includes('-Dsonar.host.url=https://sonarcloud.io'));}finally{childProcess.spawn=original;delete require.cache[modulePath];}
});

test('API failures identify the endpoint and validation error without including URL query secrets',()=>{
 const {sanitizeScanError}=require('../routes/sast/config');const result=sanitizeScanError({message:'Request failed with status code 400',config:{url:'https://sonarcloud.io/api/issues/search?token=do-not-display'},response:{status:400,data:{errors:[{msg:'A project filter is required'}]}}});assert.match(result,/Sonar HTTP 400.*api\/issues\/search.*project filter is required/);assert.ok(!result.includes('do-not-display'));
});
