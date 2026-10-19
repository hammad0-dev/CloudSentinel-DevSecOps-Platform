'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto'),{spawn}=require('node:child_process');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const error=message=>Object.assign(Error(message),{safe:true,status:409});
const TOOLS={terraform:'/usr/bin/terraform',aws:'/home/hammad/.local/bin/aws',trivy:'/snap/bin/trivy'};
function redact(text,secrets=[]){let s=String(text);for(const secret of secrets.filter(x=>typeof x==='string'&&x.length>3))s=s.split(secret).join('[REDACTED]');return s.replace(/(authorization|cookie)\s*[:=][^\r\n]*/gi,'$1=[REDACTED]').replace(/(?:AKIA|ASIA)[A-Z0-9]{16}/g,'[REDACTED]').replace(/((?:secret|token|password|authorization|cookie|access_key)[\w-]*\s*[:=]\s*)[^\s,]+/gi,'$1[REDACTED]').replace(/\/(?:home|tmp|mnt)\/[^\s"']+/g,'[PRIVATE_PATH]').slice(0,32768);}
function command(executable,args,{cwd,env,timeout=30000,limit=2*1024*1024}={}){
 return new Promise((resolve,reject)=>{
  const child=spawn(executable,args,{cwd,env,detached:true,stdio:['ignore','pipe','pipe']});let stdout=[],stderr=[],size=0,failure=null;
  const stop=reason=>{if(failure)return;failure=reason;try{process.kill(-child.pid,'SIGTERM')}catch{}kill=setTimeout(()=>{try{process.kill(-child.pid,'SIGKILL')}catch{}},500);};
  let kill;const timer=setTimeout(()=>stop('Process deadline exceeded'),timeout);
  for(const [stream,buffers] of [[child.stdout,stdout],[child.stderr,stderr]])stream.on('data',b=>{size+=b.length;if(size>limit)stop('Process output exceeded limit');else buffers.push(b)});
  child.on('error',()=>{clearTimeout(timer);clearTimeout(kill);reject(error('Planning tool unavailable'))});
  child.on('close',code=>{clearTimeout(timer);clearTimeout(kill);if(failure){try{process.kill(-child.pid,'SIGKILL')}catch{}return reject(error(failure));}resolve({code,stdout:Buffer.concat(stdout).toString(),stderr:Buffer.concat(stderr).toString()})});
 });
}
function summary(plan,id){
 if(plan.errored||!Array.isArray(plan.resource_changes))throw error('Malformed Terraform plan');
 const changes=plan.resource_changes.filter(r=>r.mode!=='data');
 const allowed=new Set(['aws_vpc','aws_subnet','aws_internet_gateway','aws_route_table','aws_route','aws_route_table_association','aws_security_group','aws_default_security_group','aws_flow_log']);
 if(changes.length!==13||changes.some(r=>!allowed.has(r.type)||!/^module\.network\.[a-z_]+\.[a-z_][a-z0-9_]*$/.test(r.address)||r.change?.actions?.join(',')!=='create'))throw error('Unexpected Terraform resource changes');
 const counts={aws_vpc:1,aws_subnet:2,aws_internet_gateway:1,aws_route_table:2,aws_route:1,aws_route_table_association:2,aws_security_group:2,aws_default_security_group:1,aws_flow_log:1};if(Object.entries(counts).some(([type,n])=>changes.filter(r=>r.type===type).length!==n))throw error('Unexpected network resource counts');
 for(const r of changes){const a=r.change.after||{};
  if(!['aws_route','aws_route_table_association'].includes(r.type)&&(a.tags?.ProjectId!==String(id)||a.tags?.Module!=='8-network'||a.tags?.Environment!=='development'||a.tags?.ManagedBy!=='Terraform'))throw error('Plan project tags do not match');
  if(['aws_security_group','aws_default_security_group'].includes(r.type)&&(!Array.isArray(a.ingress)||a.ingress.length||!Array.isArray(a.egress)||a.egress.length))throw error('Security group is not deny-all');
 }
 const provider=plan.configuration?.provider_config?.aws?.expressions;if(provider?.region?.constant_value!=='ap-south-1'||provider?.allowed_account_ids?.constant_value?.join(',')!=='229032674007')throw error('Plan provider account or region mismatch');
 return changes.map(r=>({address:r.address,type:r.type,actions:r.change.actions,projectId:id}));
}
async function privateFile(file){const s=await fs.lstat(file);if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077))throw error('Administrator planning configuration is unsafe');return fs.readFile(file);}
function enabled(){return process.env.INFRA_REAL_PLAN_ENABLED==='true'&&process.env.INFRA_REMOTE_PLAN_AUTHORIZED==='true';}
async function runPlan(input,{execute=command,config:provided}={}){
 if(!enabled())throw error('Real Terraform planning is disabled');
 let admissionDeadline=Infinity;
 const cfg=provided||JSON.parse(await privateFile(process.env.INFRA_PLAN_APPROVAL_FILE||''));
 const id=input.variables.project_id,key=`cloudsentinel/projects/${id}/development/network/terraform.tfstate`;
 if(!Number.isSafeInteger(id)||[11,13,17].includes(id)||input.stateKey!==key)throw error('Protected project or invalid state key');
 if(cfg.account!=='229032674007'||cfg.region!=='ap-south-1'||(input.networkPolicyMode!=='ISOLATED_VPC'&&!cfg.connectedDiscoveryComplete)||(!Number.isFinite(Date.parse(cfg.expiresAt))||Date.parse(cfg.expiresAt)<=Date.now()+240000)||!cfg.projects?.[id]||cfg.projects[id].cidr!==input.variables.vpc_cidr||cfg.projects[id].stateKey!==key||!cfg.projects[id].cidrReserved||!cfg.statePermissionsVerified||!cfg.flowDeliveryVerified)throw error('Planning approval, connected discovery or reservation incomplete/expired');
 if(!provided)await new (require('./cidrReservations').Reservations)().assertForPlan(id,input.variables.vpc_cidr);
 if(!provided&&input.networkPolicyMode==='ISOLATED_VPC'){const review=await new (require('./signedNetworkAdmission').Admission)().verify(id,input.ownerId,input.variables.vpc_cidr);admissionDeadline=Date.parse(review.expiresAt);if(admissionDeadline<=Date.now()+240000)throw error('Network review expires before planning deadline');}
 const otherReservations=Object.entries(cfg.projects).filter(([other])=>other!==String(id)).map(([,p])=>p.cidr);
 if(require('./infrastructurePlanning').collision(input.variables.vpc_cidr,otherReservations))throw error('CIDR reservation conflicts with another project');
 const real=await fs.realpath(input.job);const st=await fs.lstat(input.job);if(real!==path.resolve(input.job)||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o077))throw error('Unsafe planning workspace');
 const main=JSON.parse(await fs.readFile(path.join(real,'main.tf.json'))),backend=main.terraform?.backend?.s3;
 if(backend?.bucket!==cfg.stateBucket||backend?.key!==key||backend?.use_lockfile!==true||backend?.encrypt!==true||main.module?.network?.flow_log_destination_arn!==cfg.flowBucketArn)throw error('Approved backend/configuration mismatch');
 for(const [name,executable] of Object.entries(TOOLS)){if(!provided&&sha(await fs.readFile(executable))!==cfg.toolHashes?.[name])throw error('Planning tool checksum mismatch');}
 if(!provided){const cli=(await privateFile(cfg.terraformCliConfig)).toString();if(!/filesystem_mirror/.test(cli)||/direct\s*\{|network_mirror/.test(cli))throw error('Offline provider mirror configuration required');} // Approved offline provider mirror only.
 const env={PATH:'/usr/bin:/bin:/snap/bin',HOME:process.env.HOME,LANG:'C.UTF-8',TF_IN_AUTOMATION:'true',TF_INPUT:'0',TF_CLI_CONFIG_FILE:cfg.terraformCliConfig,AWS_REGION:'ap-south-1',AWS_DEFAULT_REGION:'ap-south-1',AWS_EC2_METADATA_DISABLED:'true',AWS_PAGER:''};
 const credential=await execute(TOOLS.aws,['configure','export-credentials','--profile',cfg.profile,'--format','process'],{env,cwd:real,timeout:15000});
 if(credential.code!==0)throw error('AWS credential refresh failed');
 let credentials;try{credentials=JSON.parse(credential.stdout)}catch{throw error('AWS credentials unavailable')}
 if(!credentials.AccessKeyId||!credentials.SecretAccessKey||!credentials.SessionToken||(!Number.isFinite(Date.parse(credentials.Expiration))||Date.parse(credentials.Expiration)<=Date.now()+240000))throw error('AWS credentials missing or expire before plan deadline');
 Object.assign(env,{AWS_ACCESS_KEY_ID:credentials.AccessKeyId,AWS_SECRET_ACCESS_KEY:credentials.SecretAccessKey,AWS_SESSION_TOKEN:credentials.SessionToken});
 const secrets=[credentials.AccessKeyId,credentials.SecretAccessKey,credentials.SessionToken];
 const identity=await execute(TOOLS.aws,['sts','get-caller-identity','--output','json'],{cwd:real,env,timeout:15000});
 if(identity.code!==0||JSON.parse(identity.stdout).Account!==cfg.account)throw error('AWS provider identity verification failed');
 const {collision}=require('./infrastructurePlanning');
 const inventory=await execute(TOOLS.aws,['ec2','describe-vpcs','--output','json'],{cwd:real,env,timeout:15000});
 if(inventory.code!==0)throw error('AWS CIDR discovery failed');
 const vpcs=JSON.parse(inventory.stdout).Vpcs;if(!Array.isArray(vpcs)||!Array.isArray(cfg.connectedCidrs))throw error('Connected network inventory incomplete');
 const ranges=[...cfg.connectedCidrs,...vpcs.flatMap(v=>v.CidrBlockAssociationSet?.map(c=>c.CidrBlock)||[v.CidrBlock])];
 if(collision(input.variables.vpc_cidr,ranges)||vpcs.some(v=>(v.Tags||[]).some(t=>t.Key==='ProjectId'&&t.Value===String(id))))throw error('CIDR collision or existing project VPC');
 const deadline=Date.now()+180000,logs=[];
 const step=async(name,exe,args)=>{const remaining=Math.min(deadline,admissionDeadline)-Date.now();if(remaining<=0)throw error('Overall planning deadline exceeded');const r=await execute(exe,args,{cwd:real,env,timeout:Math.min(60000,remaining)});if(Date.now()>=admissionDeadline)throw error('Signed network review expired during planning');logs.push({step:name,code:r.code,stdout:name==='show'?'[PLAN CONTENT WITHHELD]':redact(r.stdout,secrets),stderr:redact(r.stderr,secrets)});if(r.code!==0)throw error(`Terraform planning ${name} failed; no apply performed`);return r;};
 // Offline mirror lock file must already exist, preventing uncontrolled provider selection.
 const lock=await privateFile(cfg.providerLockFile);if(!provided&&sha(lock)!==cfg.providerLockSha256)throw error('Provider lock checksum mismatch');await fs.writeFile(path.join(real,'.terraform.lock.hcl'),lock,{mode:0o600,flag:'wx'});
 let primary;try{
  await step('fmt',TOOLS.terraform,['fmt','-check','-recursive']);
  if(!provided&&input.networkPolicyMode==='ISOLATED_VPC')await new (require('./signedNetworkAdmission').Admission)().verify(id,input.ownerId,input.variables.vpc_cidr);
  await step('init',TOOLS.terraform,['init','-input=false','-no-color','-lockfile=readonly']);
  await step('validate',TOOLS.terraform,['validate','-no-color']);
  const scan=await step('iac',TOOLS.trivy,['config','--skip-check-update','--format','json','--exit-code','1','--cache-dir',cfg.trivyCache,real]);
  const scanJson=JSON.parse(scan.stdout);if(!Array.isArray(scanJson.Results)||!scanJson.Results.some(r=>(r.MisconfSummary?.Successes||0)+(r.MisconfSummary?.Failures||0)>0))throw error('IaC result unverifiable or no checks executed');
  await step('plan',TOOLS.terraform,['plan','-input=false','-no-color','-lock=true','-lock-timeout=10s','-out=runner.tfplan']);
  const parsed=JSON.parse((await step('show',TOOLS.terraform,['show','-json','runner.tfplan'])).stdout);
  const changes=summary(parsed,id),plan=await fs.readFile(path.join(real,'runner.tfplan'));await fs.chmod(path.join(real,'runner.tfplan'),0o400);
  return {genuine:!provided,account:cfg.account,region:cfg.region,connectedDiscoveryComplete:true,cidrReserved:true,validated:true,iacPassed:true,collisionChecked:true,lockVerified:true,accountVerified:true,plan,summary:changes};
 }catch(e){primary=e;throw e;}finally{
  try{await fs.writeFile(path.join(real,'runner-log.json'),JSON.stringify(logs),{mode:0o600,flag:'wx'});}catch{if(!primary)throw error('Private plan log persistence failed');}
  for(const secret of ['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN'])delete env[secret];
 }
}
module.exports={runPlan,summary,redact,command,enabled};
