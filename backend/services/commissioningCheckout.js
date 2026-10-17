'use strict';
const fs=require('fs'),path=require('path');
const fail=()=>Object.assign(new Error('COMMISSIONING_CHECKOUT_OWNERSHIP_FAILED'),{code:'COMMISSIONING_CHECKOUT_OWNERSHIP_FAILED'});
function directories(root,owned=true){
  const absolute=path.resolve(root);
  let current=path.parse(absolute).root;
  for(const part of absolute.slice(current.length).split(path.sep).filter(Boolean)){
    current=path.join(current,part);
    const s=fs.lstatSync(current);
    if(!s.isDirectory()||s.isSymbolicLink())throw fail();
    // Shared ancestors such as /tmp must be sticky; others cannot be writable by strangers.
    if((s.mode&0o022)&&!(s.mode&0o1000))throw fail();
  }
  const s=fs.lstatSync(absolute);
  if(owned&&s.uid!==process.getuid())throw fail();
  return {root:absolute,dev:s.dev,ino:s.ino};
}
function create(root,{projectId,executionId,userId}){
  if(![projectId,executionId,userId].every(n=>Number.isSafeInteger(n)&&n>0)||projectId===17||
    typeof root!=='string'||!path.isAbsolute(root)||root!==path.resolve(root))throw fail();
  // Validate ancestors before creating a missing root. Never traverse a symlink.
  if(!fs.existsSync(root)){
    const parent=directories(path.dirname(root),false);
    if(parent.root===root)throw fail();
    fs.mkdirSync(root,{mode:0o700});
  }
  const parent=directories(root);
  const directory=fs.mkdtempSync(path.join(root,`cs-p${projectId}-e${executionId}-u${userId}-`));
  fs.chmodSync(directory,0o700);
  const original=fs.lstatSync(directory);
  let cleaned=false;
  return Object.freeze({target:path.join(directory,'repo'),cleanup(){
    if(cleaned)return;
    const now=directories(root);
    if(now.dev!==parent.dev||now.ino!==parent.ino)throw fail();
    const s=fs.lstatSync(directory);
    if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||s.dev!==original.dev||s.ino!==original.ino||(s.mode&0o777)!==0o700)throw fail();
    fs.rmSync(directory,{recursive:true});
    cleaned=true;
  }});
}
function required(user,context){
  if(user?.commissioningStaticStage!==true)return false;
  if(user.pipelineOrchestrator!==true)throw fail();
  const selected=require('./activeDastCommissioning').selection(context);
  if(user?.commissioningStaticStage===true&&!selected)throw fail();
  return !!selected;
}
module.exports={create,required};
