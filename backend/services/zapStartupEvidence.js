'use strict';
const crypto=require('crypto'),init=require('./zapInitialization');
function sanitize(value,secrets=[]){
 let text=String(value||'');for(const secret of secrets)if(secret)text=text.split(secret).join('[REDACTED]');
 return text.replace(/\b(?:api[._-]?key|token|password|secret|authorization|cookie)\b\s*[:=]\s*[^\s,;]+/gi,'[REDACTED]').replace(/Bearer\s+\S+/gi,'[REDACTED]').replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi,'$1[REDACTED]@').replace(/\/(?:tmp|home|zap|etc|var|opt|run)(?:\/[^\s:,'"<>]+)*/g,'[PATH]').replace(/[\x00-\x08\x0b-\x1f\x7f]/g,'?');
}
function summarize(text,secrets=[]){
 const raw=String(text||''),bytes=Buffer.byteLength(raw),parsed=require('./zapStartupLog').analyze(raw),categories=[];
 for(const [name,re] of Object.entries({filesystem:/Read-only file system|Permission denied|No space left|ENOSPC/i,addons:/Failed to (?:install|load)|add.?on.*(?:error|fail)/i,policy:/Premature end|SAXParseException|Error parsing.*policy/i,preferences:/preferences|BackingStoreException/i,listeners:/BindException|Address already in use|Cannot assign requested address/i,command:/not found|Invalid option|Unrecognized option/i}))if(re.test(raw))categories.push(name);
 const lines=raw.split(/\r?\n/),errors=parsed.failures.flatMap(r=>r.lines);
 return {bytes,sha256:crypto.createHash('sha256').update(raw).digest('hex'),classification:parsed.failure,extensionsLoaded:parsed.records.some(r=>r.level==='INFO'&&/Extensions loaded/.test(r.text)),loopbackReady:parsed.records.some(r=>r.level==='INFO'&&/ZAP is now listening on 127\.0\.0\.1:8090/.test(r.text)),unknownRecords:parsed.unknownRecords,categories,truncated:bytes>8192,excerpt:sanitize((errors.length?errors:lines.slice(-12)).join('\n'),secrets).slice(0,8192)};
}
// Fixed in-container paths only; read at most 1 MiB plus one byte regardless of log growth.
const PROBE="import os,json; p='/tmp/zap-diagnostic.log'; n=os.path.getsize(p) if os.path.isfile(p) else None; b=open(p,'rb').read(1048577) if n is not None else b''; e='/tmp/zap-diagnostic.exit'; s=open(e).read(16).strip() if os.path.isfile(e) else None; print(json.dumps({'log':b.decode('utf-8','replace'),'logBytes':n,'daemonExitCode':int(s) if s and s.isdigit() else None}))";
module.exports={sanitize,summarize,PROBE};
// Positive initialization observations, separate from the absence of log errors.
module.exports.READINESS_PROBE='exec('+JSON.stringify(`import os,json,tempfile,hashlib,xml.etree.ElementTree as ET
paths=['/home/zap/.ZAP','/tmp','/home/zap/.mozilla/firefox/1337hack.zap-client-profile','/home/zap/.ZAP/.java/.userPrefs']
writable=[]
for p in paths:
 try:
  st=os.stat(p)
  with tempfile.TemporaryFile(dir=p) as f:
   f.write(b'cs-readiness'); f.flush()
  writable.append(st.st_uid==1000 and st.st_gid==1000)
 except OSError: writable.append(False)
policy=None
try:
 with open('/home/zap/.ZAP/policies/Default Policy.policy','rb') as f: b=f.read(65537)
 if 0<len(b)<=65536:
  ET.fromstring(b); policy={'xmlParsed':True,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
except (OSError,ET.ParseError): pass
tables={}
for n in ['tcp','tcp6','udp','udp6']:
 with open('/proc/net/'+n) as f: tables[n]=f.read(65537)
print(json.dumps({'writable':writable,'policy':policy,'tables':tables}))`)+')';
module.exports.READINESS_ARGS=['python3','-I','-c','import sys;exec("".join(sys.argv[1:]))',...module.exports.READINESS_PROBE.match(/.{1,480}/g)];
