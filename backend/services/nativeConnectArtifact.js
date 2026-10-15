"use strict";
const fs = require('fs/promises');
const { constants } = require('fs');
const path = require('path'), os = require('os'), crypto = require('crypto');
const SOURCE = path.join(__dirname, '../native/connect-peer.c');
// Fixed audited artifact. No request, CLI or environment executable-path override.
const BINARY = '/tmp/cloudsentinel-connect-peer-build-lxZg6cbw/connect-peer';
const SOURCE_SHA = 'b2646e230e66286d00fc346b80cf605bc1bbda1c8d965712bb0d8e033714bc2b';
const BINARY_SHA = '278ca7f3071fbf9e253b5f5bed67325e2e7fa315ace823b6675c269112271f94';
const DESTINATION = '/opt/cloudsentinel/connect-peer';
const issued = new WeakMap();
const fail = code => { throw Object.assign(new Error('native CONNECT artifact verification failed'), { code }); };
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function verifyElf(bytes) {
  if (process.arch !== 'x64' || bytes.length < 64 || !bytes.subarray(0,4).equals(Buffer.from([127,69,76,70])) || bytes[4] !== 2 || bytes[5] !== 1 || bytes[6] !== 1 || bytes.readUInt16LE(16) !== 3 || bytes.readUInt16LE(18) !== 62 || bytes.readUInt32LE(20) !== 1) fail('NATIVE_ARCHITECTURE_MISMATCH');
}
async function parents(file) {
  for (let dir = path.dirname(file); ; dir = path.dirname(dir)) {
    const st = await fs.lstat(dir);
    if (!st.isDirectory() || st.isSymbolicLink() || ![0,process.getuid()].includes(st.uid)) fail('NATIVE_PATH_UNSAFE');
    if (dir === path.dirname(dir)) break;
  }
}
async function readFile(file, mode) {
  await parents(file);
  const st = await fs.lstat(file);
  if (!st.isFile() || st.isSymbolicLink() || st.uid !== process.getuid() || st.nlink !== 1 || (mode !== undefined && (st.mode & 0o7777) !== mode)) fail('NATIVE_PATH_UNSAFE');
  const handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const actual = await handle.stat();
    if (actual.dev !== st.dev || actual.ino !== st.ino || actual.uid !== st.uid || actual.nlink !== 1 || !actual.isFile() || actual.size > 2 * 1024 * 1024 || (mode !== undefined && (actual.mode & 0o7777) !== mode)) fail('NATIVE_PATH_UNSAFE');
    const buffer = Buffer.alloc(actual.size+1); let length=0;
    while (length < buffer.length) {
      const {bytesRead} = await handle.read(buffer,length,buffer.length-length,length);
      if (!bytesRead) break;
      length += bytesRead;
    }
    const bytes = buffer.subarray(0,length);
    const after = await fs.lstat(file);
    if (after.dev !== actual.dev || after.ino !== actual.ino || after.uid !== actual.uid || after.nlink !== 1 || after.mode !== actual.mode || after.size !== actual.size || after.isSymbolicLink() || bytes.length !== actual.size) fail('NATIVE_PATH_UNSAFE');
    return { bytes, stat: after };
  } finally { await handle.close(); }
}
async function stage(scanId) {
  if (!/^[a-z0-9_.-]{1,80}$/i.test(scanId || '')) fail('INVALID_IDENTITY');
  const source = await readFile(SOURCE);
  if (hash(source.bytes) !== SOURCE_SHA) fail('NATIVE_SOURCE_HASH_MISMATCH');
  const binary = await readFile(BINARY, 0o500); verifyElf(binary.bytes);
  if (hash(binary.bytes) !== BINARY_SHA) fail('NATIVE_BINARY_HASH_MISMATCH');
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), `cloudsentinel-native-${scanId}-`));
  try {
    await fs.chmod(directory,0o700);
    const filePath = path.join(directory,'connect-peer');
    if (/[,\r\n]/.test(filePath)) fail('NATIVE_PATH_UNSAFE');
    await fs.writeFile(filePath,binary.bytes,{ flag:'wx',mode:0o500 });
    await fs.chmod(filePath,0o500);
    const artifact = Object.freeze({ scanId,directory,filePath,containerPath:DESTINATION,digest:BINARY_SHA,mount:`type=bind,src=${filePath},dst=${DESTINATION},readonly` });
    issued.set(artifact,{ dir:await fs.lstat(directory), file:await fs.lstat(filePath), cleaned:false });
    await verify(artifact); return artifact;
  } catch (error) { await fs.rm(directory,{recursive:true,force:true}); throw error; }
}
async function owned(artifact, allowMissingFile = false) {
  const record = issued.get(artifact);
  if (!record || record.cleaned) fail('NATIVE_UNOWNED');
  const dir = await fs.lstat(artifact.directory);
  if (!dir.isDirectory() || dir.isSymbolicLink() || dir.ino !== record.dir.ino || dir.dev !== record.dir.dev || dir.uid !== process.getuid() || (dir.mode & 0o7777) !== 0o700) fail('NATIVE_UNOWNED');
  let st;
  try { st = await fs.lstat(artifact.filePath); }
  catch (error) { if (allowMissingFile && error.code === 'ENOENT') return record; throw error; }
  if (!st.isFile() || st.isSymbolicLink() || st.ino !== record.file.ino || st.dev !== record.file.dev || st.uid !== process.getuid() || st.nlink !== 1) fail('NATIVE_UNOWNED');
  return record;
}
async function verify(artifact) {
  await owned(artifact);
  const file = await readFile(artifact.filePath,0o500); verifyElf(file.bytes);
  if (hash(file.bytes) !== BINARY_SHA) fail('NATIVE_BINARY_HASH_MISMATCH');
  return artifact;
}
async function cleanup(artifact) {
  const record = issued.get(artifact);
  if (!record) fail('NATIVE_UNOWNED');
  if (record.cleaned) return { cleaned:true,residual:[] };
  await owned(artifact,true);
  const entries = await fs.readdir(artifact.directory);
  if (entries.length > 1 || (entries.length === 1 && entries[0] !== 'connect-peer')) fail('NATIVE_UNOWNED');
  if (entries.length) await fs.unlink(artifact.filePath);
  await fs.rmdir(artifact.directory);
  record.cleaned = true; return { cleaned:true,residual:[] };
}
module.exports = { stage,verify,cleanup,verifyElf,SOURCE_SHA,BINARY_SHA,DESTINATION };
