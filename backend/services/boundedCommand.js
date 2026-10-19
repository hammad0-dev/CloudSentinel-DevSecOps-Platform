'use strict';
const {spawn}=require('node:child_process');
function run(command,args,{cwd,env=process.env,timeout=60000,maxBuffer=1024*1024}={}){
 return new Promise((resolve,reject)=>{
  const child=spawn(command,args,{cwd,env,shell:false,detached:process.platform!=='win32',stdio:['ignore','pipe','pipe']});let output='',bytes=0,failed=false;
  const kill=()=>{try{if(process.platform!=='win32'&&child.pid)process.kill(-child.pid,'SIGKILL');else child.kill('SIGKILL')}catch{}};
  const timer=setTimeout(()=>{failed=true;kill()},timeout);
  child.stdout.on('data',b=>{bytes+=b.length;if(bytes>maxBuffer){failed=true;kill()}else output+=b.toString()});
  child.stderr.on('data',b=>{bytes+=b.length;if(bytes>maxBuffer){failed=true;kill()}});
  child.on('error',()=>{clearTimeout(timer);kill();reject(Error('BOUNDED_COMMAND_FAILED'))});
  child.on('close',code=>{clearTimeout(timer);if(failed||code!==0)reject(Error('BOUNDED_COMMAND_FAILED'));else resolve(output.trim())});
 });
}
module.exports={run};
