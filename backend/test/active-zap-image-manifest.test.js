'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const manifest=require('../config/active-zap-image-manifest.json');
test('active ZAP image manifest records verified closure while retaining duplicate source archives',()=>{
  assert.equal(manifest.base.zapVersion,'2.17.0');
  assert.equal(manifest.dependencyResolution.verified,true);
  assert.deepEqual(Object.keys(manifest.selection).sort(),['ascanrules','automation','network','reports']);
  assert.equal(manifest.selection.network.version,'0.29.0');
  assert.ok(manifest.dependencyResolution.transitiveEvidence);
  for(const name of ['ascanrules','automation','network','reports']){
    const versions=manifest.archives.filter(x=>x.name===name);
    assert.ok(versions.length>=2);
    assert.equal(new Set(versions.map(x=>x.version)).size,versions.length);
    for(const item of versions)assert.match(item.sha256,/^[a-f0-9]{64}$/);
  }
  assert.deepEqual(manifest.requiredPluginIds,['40012','40014','40016','40017','40018','40019','40020']);
});
