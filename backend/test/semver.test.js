'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {compare,satisfiesMinimum}=require('../services/semver');

test('ZAP add-on versions use semantic components, not decimal comparison',()=>{
 assert.equal(satisfiesMinimum('0.29.0','0.3.0'),true);
 assert.equal(satisfiesMinimum('0.25.0','0.3.0'),true);
 assert.equal(satisfiesMinimum('0.24.0','0.7.0'),true);
 assert.equal(compare('0.2.99','0.3.0'),-1);
 assert.equal(compare('1.43.0','1.40.0'),1);
 assert.equal(compare('2.17.0','2.17.0'),0);
});

test('semantic version boundaries reject lower major/minor/patch values',()=>{
 assert.equal(satisfiesMinimum('0.2.0','0.3.0'),false);
 assert.equal(satisfiesMinimum('1.39.9','1.40.0'),false);
 assert.equal(satisfiesMinimum('2.16.9','2.17.0'),false);
});
