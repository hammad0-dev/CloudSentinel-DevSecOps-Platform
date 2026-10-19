'use strict';
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),{execFileSync}=require('node:child_process');
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const MAX_BYTES=25*1024*1024,MAX_FILES=2000,MAX_FILE=5*1024*1024;
const extension=/\.(html?|css|js|png|jpe?g|gif|webp|ico|svg|woff2?|ttf|txt|json|map)$/i;
const excluded=/(^|\/)(\.git[^/]*|\.github|\.env[^/]*|\.npmrc|\.ssh|\.aws|credentials(?:\.[^/]*)?|secrets?(?:\.[^/]*)?|README[^/]*|LICENSE[^/]*|Dockerfile[^/]*|sonar-project\.properties)$/i;
const unsupported=/(^|\/)(package(-lock)?\.json|requirements[^/]*\.txt|pyproject\.toml|compose[^/]*\.ya?ml|docker-compose[^/]*\.ya?ml)$/i;
function safePath(p){return typeof p==='string'&&p.length<=240&&!p.includes('\\')&&!/[\x00-\x1f\x7f]/.test(p)&&!path.posix.isAbsolute(p)&&p.split('/').every(x=>x&&x!=='.'&&x!=='..')}
function secret(data){return /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b|(?:password|secret|api[_-]?key|access[_-]?token)[\"']?\s*[:=]\s*[\"'][^\"'\r\n]{4,}[\"']/.test(data.toString('utf8'))}
function checkDirectory(dir){const s=fs.lstatSync(dir);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077))throw Error('Unsafe artifact directory')}
function rootPath(root){fs.mkdirSync(root,{recursive:true,mode:0o700});checkDirectory(root);const real=fs.realpathSync(root);if(real!==path.resolve(root))throw Error('Symlinked artifact ancestry');return real}
function collect(cwd,commit){
 if(!/^[a-f0-9]{40}$/.test(commit))throw Error('Invalid artifact commit');
 const git=args=>execFileSync('git',args,{cwd,timeout:30000,maxBuffer:MAX_BYTES+1024*1024});
 if(git(['rev-parse','HEAD']).toString().trim()!==commit)throw Error('Artifact checkout revision mismatch');
 const list=git(['ls-tree','-rz','--full-tree',commit]).toString().split('\0').filter(Boolean),files=[];let bytes=0;
 for(const item of list){const m=/^(\d+) blob ([a-f0-9]+)\t(.+)$/.exec(item);if(!m)throw Error('Unsupported Git tree entry');const [,mode,oid,name]=m;
  if(!safePath(name)||mode==='120000'||mode==='160000')throw Error('Unsafe artifact path or symlink');
  if(excluded.test(name))continue;
  if(name.split('/').some(p=>p.startsWith('.')))throw Error('Hidden static content unsupported');
  if(mode!=='100644'||unsupported.test(name)||!extension.test(name))throw Error('Unsupported static repository content');
  const data=git(['cat-file','blob',oid]);if(data.length>MAX_FILE||(bytes+=data.length)>MAX_BYTES||files.length>=MAX_FILES||secret(data))throw Error('Static artifact content exceeds policy or contains secrets');
  const disk=fs.lstatSync(path.join(cwd,name));if(!disk.isFile()||disk.isSymbolicLink()||hash(fs.readFileSync(path.join(cwd,name)))!==hash(data))throw Error('Working tree differs from execution commit');
  files.push({path:name,size:data.length,sha256:hash(data),data:data.toString('base64')});
 }
 files.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
 if(!files.some(f=>f.path==='index.html'))throw Error('Static root index.html required');
 return {version:1,profile:'STATIC_HTML',commit,files};
}
function create(cwd,{projectId,executionId,commit},root=process.env.STATIC_ARTIFACT_ROOT||path.join(os.homedir(),'.cloudsentinel','static-artifacts')){
 if(![projectId,executionId].every(n=>Number.isSafeInteger(n)&&n>0))throw Error('Invalid artifact identity');
 const artifact=collect(cwd,commit),bytes=Buffer.from(JSON.stringify(artifact)),sha256=hash(bytes),base=rootPath(root),dir=path.join(base,`${projectId}-${executionId}`);
 if(fs.existsSync(dir)){const ref={projectId,executionId,commit,sha256};verify(ref,root);return ref;}
 fs.mkdirSync(dir,{mode:0o700}); // Existing execution directory is never overwritten.
 try{const tmp=path.join(dir,`.${crypto.randomUUID()}.tmp`);const fd=fs.openSync(tmp,'wx',0o400);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}fs.renameSync(tmp,path.join(dir,'artifact.json'));fs.chmodSync(dir,0o500)}catch(e){fs.rmSync(dir,{recursive:true,force:true});throw e}
 return {projectId,executionId,commit,sha256};
}
function verify(ref,root=process.env.STATIC_ARTIFACT_ROOT||path.join(os.homedir(),'.cloudsentinel','static-artifacts')){
 if(![ref.projectId,ref.executionId].every(n=>Number.isSafeInteger(n)&&n>0)||!(/^[a-f0-9]{64}$/).test(ref.sha256))throw Error('Invalid artifact reference');
 checkDirectory(root);if(fs.realpathSync(root)!==path.resolve(root))throw Error('Symlinked artifact ancestry');const dir=path.join(root,`${ref.projectId}-${ref.executionId}`);checkDirectory(dir);
 const file=path.join(dir,'artifact.json'),st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o077)||st.size>MAX_BYTES*1.5+1024*1024)throw Error('Unsafe artifact file');
 const raw=fs.readFileSync(file);if(hash(raw)!==ref.sha256)throw Error('Artifact checksum mismatch');
 const a=JSON.parse(raw);if(a.version!==1||a.profile!=='STATIC_HTML'||a.commit!==ref.commit||!Array.isArray(a.files)||!a.files.length||a.files.length>MAX_FILES)throw Error('Invalid artifact manifest');
 let total=0,previous='';for(const f of a.files){if(!safePath(f.path)||f.path<=previous||!extension.test(f.path)||excluded.test(f.path)||unsupported.test(f.path)||typeof f.data!=='string')throw Error('Unsafe artifact manifest');previous=f.path;const b=Buffer.from(f.data,'base64');if(b.toString('base64')!==f.data||b.length!==f.size||b.length>MAX_FILE||(total+=b.length)>MAX_BYTES||hash(b)!==f.sha256||secret(b))throw Error('Artifact file integrity mismatch')}
 if(!a.files.some(f=>f.path==='index.html'))throw Error('Missing artifact index');return a;
}
function materialize(ref,destination,root){const a=verify(ref,root);fs.mkdirSync(destination,{mode:0o700});for(const f of a.files){const file=path.join(destination,f.path);fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});fs.writeFileSync(file,Buffer.from(f.data,'base64'),{flag:'wx',mode:0o600})}return a;}
module.exports={create,verify,materialize,collect,hash,safePath};
