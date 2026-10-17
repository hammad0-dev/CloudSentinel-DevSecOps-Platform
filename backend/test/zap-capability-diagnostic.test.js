'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
test('complete offline non-scanning ZAP diagnostic replay and failure branches',()=>{
  const result=spawnSync('python3',['-m','unittest','discover','-s','test','-p','zap_capability_diagnostic_test.py','-v'],{
    cwd:path.resolve(__dirname,'..'),encoding:'utf8',timeout:30000,
    env:{...process.env,DAST_ACTIVE_ENABLED:'false',PYTHONDONTWRITEBYTECODE:'1'},
  });
  assert.equal(result.status,0,result.stderr||result.error?.message);
});
