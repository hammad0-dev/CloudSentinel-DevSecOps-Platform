'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const axios=require('axios');
const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
const fail=(message,code=400)=>Object.assign(new Error(message),{safe:true,status:code});
const statuses=['NOT_CONFIGURED','ANALYZED','PLANNING','PLANNED','AWAITING_APPROVAL','APPLYING','APPLIED','FAILED','VERIFICATION_PENDING'];
const {analyze}=require('./repositoryArchitecture');
async function repositoryFiles(project){
 const m=/^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/.exec(project.repo_url||'');if(!m)throw fail('Only registered GitHub repositories are supported');
 const base=`https://api.github.com/repos/${m[1]}/${m[2]}`,headers={Accept:'application/vnd.github+json',...(project.github_token?{Authorization:`Bearer ${project.github_token}`}:{})};
 const get=async url=>(await axios.get(url,{headers,timeout:8000,maxContentLength:512*1024,maxRedirects:0})).data;
 const repo=await get(base);const commit=await get(`${base}/commits/${encodeURIComponent(repo.default_branch)}`);if(!/^[a-f0-9]{40}$/.test(commit.sha))throw fail('Repository revision unverified');
 const tree=await get(`${base}/git/trees/${commit.sha}?recursive=1`);if(tree.truncated)throw fail('Repository tree too large for bounded analysis');
 const files={};const candidates=tree.tree.filter(f=>f.type==='blob'&&/(^|\/)(package.json|requirements[^/]*\.txt|pyproject.toml|Pipfile|setup.cfg|pom.xml|build.gradle[^/]*|go.mod|Dockerfile[^/]*|(?:docker-)?compose[^/]*\.ya?ml|[^/]+\.html?)$/.test(f.path));
 if(candidates.length>20)throw fail('Repository needs manual analysis: too many manifests');
 for(const file of candidates){if(file.size>65536)throw fail('Repository manifest exceeds analysis bound');const data=await get(`${base}/git/blobs/${file.sha}`);if(data.encoding!=='base64')throw fail('Unsupported repository encoding');files[file.path]=Buffer.from(data.content,'base64').toString('utf8');}
 return {commit:commit.sha,files};
}
function variables(projectId,input){
 const keys=['environment','availabilityZone','cidr','architecture','networkPolicyMode'];if(!input||Object.keys(input).some(k=>!keys.includes(k)))throw fail('Unsupported planning variable');
 if(input.networkPolicyMode&&!require('./networkPolicy').MODES.includes(input.networkPolicyMode))throw fail('Unsupported network policy mode');
 if([11,13,17].includes(projectId))throw fail('Existing/protected project infrastructure is read-only',409);
 if(input.environment!=='development'||input.availabilityZone!=='ap-south-1a'||!/^10\.(\d{1,3})\.0\.0\/16$/.test(input.cidr)||+input.cidr.split('.')[1]>255)throw fail('Invalid or unapproved environment, AZ or CIDR');
 if(!['one-tier','two-tier','three-tier','custom'].includes(input.architecture))throw fail('Confirm an architecture recommendation');
 return {project_id:projectId,environment:input.environment,availability_zone:input.availabilityZone,vpc_cidr:input.cidr,flow_log_destination_arn:process.env.INFRA_FLOW_LOG_BUCKET_ARN};
}
function collision(cidr,networks){
 const number=ip=>ip.split('.').reduce((n,b)=>n*256+Number(b),0);
 const range=c=>{const [ip,b]=c.split('/');if(!/^\d+\.\d+\.\d+\.\d+$/.test(ip)||ip.split('.').some(x=>+x>255)||!Number.isInteger(+b)||+b<0||+b>32)throw fail('Unverifiable CIDR inventory');const size=2**(32-Number(b)),start=Math.floor(number(ip)/size)*size;return [start,start+size-1]};
 const [a,b]=range(cidr);return networks.some(c=>{const [x,y]=range(c);return a<=y&&x<=b});
}
class Planner{
 constructor({root=process.env.INFRA_ARTIFACT_ROOT||path.join(require('node:os').homedir(),'.cloudsentinel','infrastructure'),source=repositoryFiles,runner=null,discovery=require('./awsNetworkDiscovery').discover}={}){this.root=root;this.source=source;this.runner=runner;this.discovery=discovery;}
 async directory(id){await fs.mkdir(this.root,{recursive:true,mode:0o700});const st=await fs.lstat(this.root);if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o077))throw fail('Private artifact storage is unsafe',503);const dir=path.join(this.root,String(id));await fs.mkdir(dir,{mode:0o700,recursive:true});const ds=await fs.lstat(dir);if(ds.isSymbolicLink()||!ds.isDirectory()||ds.uid!==process.getuid()||(ds.mode&0o077))throw fail('Unsafe project artifact storage',503);return dir;}
 async save(dir,data){const tmp=path.join(dir,`.${crypto.randomUUID()}.tmp`);await fs.writeFile(tmp,JSON.stringify(data),{mode:0o600,flag:'wx'});await fs.rename(tmp,path.join(dir,'metadata.json'));}
 async get(id){try{return JSON.parse(await fs.readFile(path.join(this.root,String(id),'metadata.json'),'utf8'))}catch(e){if(e.code==='ENOENT')return {status:'NOT_CONFIGURED',history:[]};throw fail('Infrastructure history unavailable',503)}}
 async locked(id,fn){const dir=await this.directory(id);let lock;try{lock=await fs.open(path.join(dir,'job.lock'),'wx',0o600)}catch(e){if(e.code==='EEXIST')throw fail('A provisioning operation is already in progress',409);throw e}try{return await fn(dir)}finally{await lock.close();await fs.unlink(path.join(dir,'job.lock'));}}
 async analysis(project){return this.locked(project.id,async dir=>{const source=await this.source(project),previous=await this.get(project.id);const data={projectId:project.id,status:'ANALYZED',commit:source.commit,analysis:analyze(source.files),updatedAt:new Date().toISOString(),history:[...(previous.history||[]).slice(-19),{status:'ANALYZED',at:new Date().toISOString()}]};await this.save(dir,data);return data})}
 async plan(project,input){return this.locked(project.id,async dir=>{const v=variables(project.id,input),data=await this.get(project.id);if(!data.analysis||data.status!=='ANALYZED')throw fail('Analyze the registered repository before planning',409);
 const current=await this.source(project);if(current.commit!==data.commit)throw fail('Repository changed; analyze again',409);
 if(!/^arn:aws:s3:::[a-z0-9-]{3,63}$/.test(v.flow_log_destination_arn||''))throw fail('Administrator must configure an approved Flow Logs bucket',409);
 if(!/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(process.env.INFRA_STATE_BUCKET||''))throw fail('Administrator must configure an approved state bucket',409);
 const key=`cloudsentinel/projects/${project.id}/${v.environment}/network/terraform.tfstate`;
 const job=await fs.mkdtemp(path.join(dir,'plan-'));await fs.chmod(job,0o700);
 // Copy only trusted server-side template source. Never execute repository Terraform.
 const moduleDir=path.resolve(__dirname,'../../terraform/modules/aws-network');await fs.cp(moduleDir,path.join(job,'module'),{recursive:true});
 const main={terraform:{required_version:'>= 1.16.6, < 1.17.0',required_providers:{aws:{source:'hashicorp/aws',version:'= 5.100.0'}},backend:{s3:{bucket:process.env.INFRA_STATE_BUCKET,key,region:'ap-south-1',encrypt:true,use_lockfile:true,allowed_account_ids:['229032674007']}}},provider:{aws:{region:'ap-south-1',allowed_account_ids:['229032674007']}},module:{network:{source:'./module',...v}}};
 await fs.writeFile(path.join(job,'main.tf.json'),JSON.stringify(main,null,2),{mode:0o600,flag:'wx'});
 const sources=await Promise.all(['main.tf','variables.tf','outputs.tf','versions.tf'].map(async name=>[name,hash(await fs.readFile(path.join(job,'module',name)))]));
 const digest=hash(JSON.stringify({main,sources,networkPolicyMode:input.networkPolicyMode||'CONNECTED_NETWORK'}));
 const mode=input.networkPolicyMode||'CONNECTED_NETWORK';
 let policy={mode,planningReady:false,blockers:['CONNECTED_NETWORK_EVIDENCE_REQUIRED']};
 if(mode==='ISOLATED_VPC')policy=require('./networkPolicy').isolation({account:'229032674007',region:'ap-south-1',template:'network-only',resources:await require('./networkPolicy').trustedTemplate(),discovery:await this.discovery()});
 data.networkPolicy={...policy,administratorApproval:'MISSING',poolApproval:'MISSING'};
 if(mode==='ISOLATED_VPC'){const review=await new (require('./signedNetworkAdmission').Admission)().status(project.id,project.user_id);if(review.signatureVerified){data.networkPolicy.administratorApproval='SIGNED_ADMITTED';data.networkPolicy.poolApproval=review.approvedPool;data.networkPolicy.reviewExpiry=review.expiresAt;}}
 if(mode==='ISOLATED_VPC'&&this.runner){await new (require('./signedNetworkAdmission').Admission)().verify(project.id,project.user_id,v.vpc_cidr);}
 const reserved=JSON.parse(process.env.INFRA_RESERVED_CIDRS||'[]');if(!Array.isArray(reserved))throw fail('Invalid administrator CIDR inventory',409);if(collision(v.vpc_cidr,reserved))throw fail('CIDR overlaps an administrator-reserved or connected network',409);
 if(!this.runner){data.configuration={cidrStatus:'TENTATIVE_NOT_RESERVED',connectedNetworkDiscovery:'INCOMPLETE',localReservedRangesChecked:true,status:'PREPARED_NOT_PLANNED',hash:digest,stateKey:key,template:'network-only',cidr:v.vpc_cidr};data.blockers=['Real planning is disabled until per-project IAM, connected-network CIDR inventory, approved backend and default-SG bootstrap are validated'];await this.save(dir,data);return data;}
 // Runner remains unavailable in production. Tests can verify lifecycle without cloud operations.
 data.status='PLANNING';data.history.push({status:'PLANNING',at:new Date().toISOString()});await this.save(dir,data);
 let result;try{result=await this.runner({job,variables:v,stateKey:key,commit:data.commit,networkPolicyMode:mode,ownerId:project.user_id});}catch(e){data.status='FAILED';data.blockers=[e.safe?e.message:'Planning failed; inspect private evidence'];data.history.push({status:'FAILED',at:new Date().toISOString()});await this.save(dir,data);throw e;}

 if(!result.connectedDiscoveryComplete||!result.cidrReserved||!result.validated||!result.iacPassed||!result.collisionChecked||!result.lockVerified||!result.accountVerified||!Buffer.isBuffer(result.plan))throw fail('Plan verification incomplete',409);
 verifyResources(result.summary,project.id);
 const file=path.join(job,'reviewed.tfplan');await fs.writeFile(file,result.plan,{mode:0o400,flag:'wx'});
 data.status='AWAITING_APPROVAL';data.plan={genuine:result.genuine===true,evidenceType:result.genuine===true?'AWS_BACKED':'SIMULATED_TEST_ONLY',account:result.account||'Unverified test identity',region:result.region||'Unverified test region',templateVersion:digest,hash:hash(result.plan),configurationHash:digest,summary:result.summary,createdAt:new Date().toISOString(),expiresAt:new Date(Date.now()+15*60*1000).toISOString(),stateKey:key};data.artifact=file;data.history.push({status:data.status,at:data.plan.createdAt});await this.save(dir,data);return data;
 })}
 async approve(project,userId,input){return this.locked(project.id,async dir=>{const data=await this.get(project.id);if(data.approval)throw fail('Plan approval already consumed',409);if(data.status!=='AWAITING_APPROVAL'||(!Number.isFinite(Date.parse(data.plan.expiresAt))||Date.parse(data.plan.expiresAt)<=Date.now()))throw fail('Plan is stale or unavailable',409);if(input.hash!==data.plan.hash||hash(await fs.readFile(data.artifact))!==data.plan.hash)throw fail('Plan checksum mismatch',409);const source=await this.source(project);if(source.commit!==data.commit)throw fail('Repository changed; new plan required',409);data.approval={userId,hash:input.hash,at:new Date().toISOString()};data.blockers=['Apply is disabled; administrator execution and exact default-SG authorization required'];await this.save(dir,data);return data})}
}
function verifyResources(summary,id){const types=new Set(['aws_vpc','aws_subnet','aws_internet_gateway','aws_route_table','aws_route','aws_route_table_association','aws_security_group','aws_default_security_group','aws_flow_log']);if(!Array.isArray(summary)||!summary.length||summary.some(r=>!types.has(r.type)||r.actions?.length!==1||r.actions[0]!=='create'||r.projectId!==id))throw fail('Unexpected or destructive plan resources',409);}
async function ownedProject(pool,userId,id){if(!/^[1-9]\d*$/.test(String(id))||!Number.isSafeInteger(+id))throw fail('Invalid project');const {rows}=await pool.query('SELECT id, user_id, repo_url, github_token FROM projects WHERE id=$1 AND user_id=$2',[+id,userId]);if(!rows.length)throw fail('Project not found',404);return rows[0];}
function publicRecord(data){const {artifact,...safe}=data;return {...safe,applyEnabled:false,costNotice:'Network only; Flow Logs delivery and S3 storage/requests may incur charges. No Free Tier guarantee.'}}
module.exports={Planner,analyze,variables,collision,verifyResources,publicRecord,statuses,ownedProject};
