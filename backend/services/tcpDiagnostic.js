"use strict";
const fs = require('fs/promises'), os = require('os'), path = require('path');
const {createHash} = require('crypto');
const captures = new WeakMap();
function output(value) {
  if (typeof value !== 'string') return {category:'MISSING'};
  return {category:value.includes('\0')?'NUL_CONTAINING':value.length?'TEXT':'EMPTY',bytes:Buffer.byteLength(value),lines:value.length?value.split('\n').length:0,sha256:createHash('sha256').update(value).digest('hex')};
}
function capture(probe, result, predicates, destination, command, adapterError) {
  adapterError = adapterError ? (/^[A-Z][A-Z0-9_]{0,63}$/.test(adapterError)?adapterError:'EXECUTION_ERROR') : null;
  const stderr=typeof result.stderr==='string'?result.stderr:'';
  const category = adapterError ? 'EXECUTION_ERROR' : /invalid.*option|usage:/i.test(stderr)?'TOOL_ERROR':/timed?\s*out|timeout/i.test(stderr)?'TIMEOUT':/refused/i.test(stderr)?'REFUSED':/resolve|bad address/i.test(stderr)?'DNS_ERROR':/network (?:is )?unreachable/i.test(stderr)?'NETWORK_UNREACHABLE':!stderr?'EMPTY':'UNRECOGNIZED';
  const summary=Object.freeze({command, destination, exitCode:Number.isInteger(result.exitCode)?result.exitCode:null,commandLayer:'DOCKER_EXEC_NC',adapterError:adapterError||null,errorCategory:category,stdout:output(result.stdout),stderr:output(result.stderr),predicates,failedPredicates:Object.keys(predicates).filter(k=>!predicates[k])});
  // Bounded native evidence remains private; public summaries contain no text.
  captures.set(probe,{summary,stdout:typeof result.stdout==='string'?result.stdout.slice(0,4096):null,stderr:typeof result.stderr==='string'?result.stderr.slice(0,4096):null,truncated:[result.stdout,result.stderr].some(v=>typeof v==='string'&&v.length>4096)});
  return probe;
}
function diagnostic(probe) {return captures.get(probe)?.summary;}
async function save(probe, scanId, observations) {
  const record=captures.get(probe);
  if(!record || !/^[a-z0-9_.-]{1,63}$/.test(scanId)) throw Object.assign(new Error('invalid TCP diagnostic'),{code:'INVALID_DIAGNOSTIC'});
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),`cloudsentinel-tcp-diagnostic-${scanId}-`));
  const redact=value=>value===null?null:value.replace(/\b(?:password|token|secret|authorization|cookie|api[_-]?key)\s*[:=]\s*[^\r\n]*/gi,'[REDACTED]').replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi,'$1[REDACTED]@').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g,'');
  const bounded = (value, depth=0) => {
    if(depth>12) throw new Error('diagnostic nesting limit');
    if(typeof value==='string') {if(Buffer.byteLength(value)>16384)throw new Error('diagnostic value limit');return redact(value);}
    if(value===null || typeof value==='boolean' || typeof value==='number')return value;
    if(Array.isArray(value)){if(value.length>128)throw new Error('diagnostic array limit');return value.map(v=>bounded(v,depth+1));}
    if(value&&typeof value==='object'){const entries=Object.entries(value);if(entries.length>128)throw new Error('diagnostic object limit');return Object.fromEntries(entries.map(([k,v])=>[k,/password|token|secret|authorization|cookie/i.test(k)?'[REDACTED]':bounded(v,depth+1)]));}
    throw new Error('invalid diagnostic value');
  };
  try {
    await fs.chmod(directory,0o700);
    const file=path.join(directory,'tcp.json');
    const payload=JSON.stringify({scanId,...record.summary,stdoutText:redact(record.stdout),stderrText:redact(record.stderr),truncated:record.truncated,...(observations?{observations:bounded(observations)}:{})},null,2);
    if(Buffer.byteLength(payload)>65536)throw new Error('diagnostic size limit');
    await fs.writeFile(file,payload,{flag:'wx',mode:0o600});
    await fs.chmod(file,0o600);return file;
  } catch(error) {await fs.rm(directory,{recursive:true,force:true});throw Object.assign(new Error('TCP diagnostic write failed'),{code:'DIAGNOSTIC_WRITE_FAILED'});}
}
module.exports={capture,diagnostic,save};
