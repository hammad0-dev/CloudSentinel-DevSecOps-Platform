'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('path');
const route=require('../routes/dependency');
test('dependency process timeout terminates the whole child process group',async()=>{
 const child=route.spawnWithTimeout('offline trivy','sh',['-c','(sleep 30)& wait'],{stdio:['ignore','pipe','pipe']},500);
 await assert.rejects(child,/offline trivy: timed out after/);
});
test('dependency command failures remain failures and do not become empty SBOM success',async()=>{
 await assert.rejects(route.spawnWithTimeout('trivy','sh',['-c','printf fail >&2; exit 2'],{stdio:['ignore','pipe','pipe']},1000),/fail/);
});
