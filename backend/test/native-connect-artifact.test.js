"use strict";
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('fs/promises'),path=require('path'),crypto=require('crypto');
const artifacts=require('../services/nativeConnectArtifact');
const client=require('../services/dastAcceptanceClient');
const {mockDocker}=require('./helpers/runtimeDocker');
async function staged(t) {const a=await artifacts.stage('native-test');t.after(()=>artifacts.cleanup(a));return a;}
test('audited native artifact stages privately with exact digest and unique ownership',async(t)=>{
  const a=await staged(t),b=await staged(t);
  assert.notEqual(a.directory,b.directory);
  assert.equal((await fs.stat(a.directory)).mode&0o777,0o700);
  assert.equal((await fs.stat(a.filePath)).mode&0o777,0o500);
  assert.equal(crypto.createHash('sha256').update(await fs.readFile(a.filePath)).digest('hex'),artifacts.BINARY_SHA);
  assert.equal(await artifacts.verify(a),a);
  await assert.rejects(artifacts.verify({...a}),{code:'NATIVE_UNOWNED'});
  await assert.rejects(artifacts.stage({scanId:'native-test',binaryPath:'/bin/sh'}),{code:'INVALID_IDENTITY'});
});
test('source and binary hash mismatches reject before staging',async(t)=>{
  const original=fs.open.bind(fs);
  for(const which of ['source','binary']) {
    const mocked=t.mock.method(fs,'open',async(file,...args)=>{
      const h=await original(file,...args);
      if((which==='source'&&String(file).endsWith('/native/connect-peer.c'))||(which==='binary'&&String(file).includes('cloudsentinel-connect-peer-build-')))return {stat:()=>h.stat(),close:()=>h.close(),async read(buffer,offset,...args){const result=await h.read(buffer,offset,...args);if(result.bytesRead)buffer[offset+result.bytesRead-1]^=1;return result;}};
      return h;
    });
    try {await assert.rejects(artifacts.stage('hash-test'),{code:which==='source'?'NATIVE_SOURCE_HASH_MISMATCH':'NATIVE_BINARY_HASH_MISMATCH'});}
    finally {mocked.mock.restore();}
  }
});
test('symlinks and directory substitutions cannot be verified or cleaned as owned',async(t)=>{
  const a=await staged(t),held=path.join(a.directory,'held');
  await fs.rename(a.filePath,held);await fs.symlink(held,a.filePath);
  await assert.rejects(artifacts.verify(a),{code:'NATIVE_UNOWNED'});
  await assert.rejects(artifacts.cleanup(a),{code:'NATIVE_UNOWNED'});
  await fs.unlink(a.filePath);await fs.rename(held,a.filePath);
  const backup=a.directory+'-held';await fs.rename(a.directory,backup);await fs.mkdir(a.directory,{mode:0o700});
  await assert.rejects(artifacts.verify(a),{code:'NATIVE_UNOWNED'});
  await assert.rejects(artifacts.cleanup(a),{code:'NATIVE_UNOWNED'});
  await fs.rmdir(a.directory);await fs.rename(backup,a.directory);
});
test('wrong ownership, permissions, architecture and modified bytes are rejected',async(t)=>{
  const a=await staged(t),original=fs.lstat.bind(fs);
  const mocked=t.mock.method(fs,'lstat',async(file)=>{const s=await original(file);if(file===a.directory)s.uid+=1;return s;});
  try {await assert.rejects(artifacts.verify(a),{code:'NATIVE_UNOWNED'});await assert.rejects(artifacts.cleanup(a),{code:'NATIVE_UNOWNED'});}finally{mocked.mock.restore();}
  await fs.chmod(a.filePath,0o4500);await assert.rejects(artifacts.verify(a),{code:'NATIVE_PATH_UNSAFE'});
  await fs.chmod(a.filePath,0o700);await assert.rejects(artifacts.verify(a),{code:'NATIVE_PATH_UNSAFE'});
  const bytes=await fs.readFile(a.filePath);bytes[bytes.length-1]^=1;await fs.writeFile(a.filePath,bytes);await fs.chmod(a.filePath,0o500);
  await assert.rejects(artifacts.verify(a),{code:'NATIVE_BINARY_HASH_MISMATCH'});
  const wrong=Buffer.from(bytes);wrong.writeUInt16LE(183,18);assert.throws(()=>artifacts.verifyElf(wrong),{code:'NATIVE_ARCHITECTURE_MISMATCH'});
});
test('owned cleanup removes staged artifacts and disallows stale reuse',async()=>{
  const a=await artifacts.stage('cleanup-test');await artifacts.cleanup(a);
  await assert.rejects(fs.stat(a.directory),{code:'ENOENT'});
  await assert.rejects(artifacts.verify(a),{code:'NATIVE_UNOWNED'});
  assert.equal((await artifacts.cleanup(a)).cleaned,true);
});
test('cleanup retries safely after partial deletion without touching foreign directory contents',async(t)=>{
  const a=await artifacts.stage('retry-test'),rmdir=fs.rmdir.bind(fs);
  const mocked=t.mock.method(fs,'rmdir',async(dir)=>{if(dir===a.directory)throw Object.assign(new Error('mock busy'),{code:'EBUSY'});return rmdir(dir);});
  try {await assert.rejects(artifacts.cleanup(a),{code:'EBUSY'});}finally{mocked.mock.restore();}
  assert.deepEqual(await fs.readdir(a.directory),[]);
  await artifacts.cleanup(a);await assert.rejects(fs.stat(a.directory),{code:'ENOENT'});
});
test('native container mount and security settings are constructed and inspected',async(t)=>{
  const a=await artifacts.stage('s1');t.after(()=>artifacts.cleanup(a));const d=mockDocker();
  const c=await client.provision(d.adapter,{scanId:'s1',networkId:d.ids.scanner,networkReference:d.refs[0],nativeArtifact:a});
  const args=d.calls.find(a=>a[0]==='run');
  assert.equal(args[args.indexOf('--mount')+1],a.mount);
  assert.equal(args[args.indexOf('--user')+1],`${process.getuid()}:${process.getgid()}`);
  await client.verifyNativeDelivery(d.adapter,c);
  for(const change of [()=>d.state.clientMounts[0].RW=true,()=>d.state.clientMounts[0].Source='/unexpected/path',()=>d.state.clientMounts.push({Destination:'/opt/cloudsentinel',RW:false}),()=>d.state.clientUser='0:0']) {
    const mounts=structuredClone(d.state.clientMounts),user=d.state.clientUser;
    change();await assert.rejects(client.verifyNativeDelivery(d.adapter,c),{code:'NATIVE_MOUNT_MISMATCH'});
    d.state.clientMounts=mounts;d.state.clientUser=user;
  }
  d.state.nativeDigest='0'.repeat(64);await assert.rejects(client.verifyNativeDelivery(d.adapter,c),{code:'NATIVE_BINARY_HASH_MISMATCH'});
});
test('default clients retain curl-only delivery with no native mount',async()=>{
  const d=mockDocker(),c=await client.provision(d.adapter,{scanId:'s1',networkId:d.ids.scanner,networkReference:d.refs[0]});
  assert.ok(!d.calls.find(a=>a[0]==='run').includes('--mount'));
  await assert.rejects(client.verifyNativeDelivery(d.adapter,c),{code:'NATIVE_OPT_IN_REQUIRED'});
});
