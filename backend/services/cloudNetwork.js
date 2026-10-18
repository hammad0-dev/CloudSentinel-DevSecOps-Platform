'use strict';
const {execFile}=require('node:child_process');
const {promisify}=require('node:util');
const execute=promisify(execFile);
const tags=r=>Object.fromEntries((r.Tags||[]).map(t=>[t.Key,t.Value]));
const owned=(r,id)=>{const t=tags(r);return t.ProjectId===String(id)&&t.Module==='8-network'&&t.ManagedBy==='Terraform';};
async function aws(service,operation,args=[]){
 const {stdout}=await execute('aws',['--profile',process.env.CLOUD_AWS_PROFILE||'cloudsentinel-dev','--region',process.env.CLOUD_AWS_REGION||'ap-south-1','--cli-connect-timeout','3','--cli-read-timeout','5',service,operation,...args,'--output','json'],{timeout:8000,maxBuffer:1024*1024,env:{...process.env,AWS_PAGER:''}});
 return JSON.parse(stdout);
}
async function readNetwork(projectId,run=aws){
 const base={projectId,status:'not_connected',source:'AWS read-only API',observedAt:new Date().toISOString(),findingsStatus:'Not configured; network inventory is not a security assessment'};
 try{
 const identity=await run('sts','get-caller-identity');
 if(identity.Account!==(process.env.CLOUD_AWS_ACCOUNT_ID||'229032674007'))return {...base,reason:'AWS account mismatch'};
 const filter=['--filters',`Name=tag:ProjectId,Values=${projectId}`,'Name=tag:Module,Values=8-network','Name=tag:ManagedBy,Values=Terraform'];
 const {Vpcs}=await run('ec2','describe-vpcs',filter);
 if(!Array.isArray(Vpcs))throw Error('Invalid inventory');
 if(!Vpcs.length)return {...base,status:'not_configured',reason:'No Terraform-tagged network found for this project'};
 if(Vpcs.length!==1||!owned(Vpcs[0],projectId))throw Error('Ambiguous ownership');
 const vpc=Vpcs[0],vf=['--filters',`Name=vpc-id,Values=${vpc.VpcId}`];
 const [subnets,routes,groups,gateways,flows]=await Promise.all([
 run('ec2','describe-subnets',vf),run('ec2','describe-route-tables',vf),run('ec2','describe-security-groups',vf),
 run('ec2','describe-internet-gateways',['--filters',`Name=attachment.vpc-id,Values=${vpc.VpcId}`]),
 run('ec2','describe-flow-logs',['--filter',`Name=resource-id,Values=${vpc.VpcId}`])]);
 const scoped=(items,key)=>{if(!Array.isArray(items)||items.some(r=>!owned(r,projectId)||r[key]!==vpc.VpcId))throw Error('Resource ownership not verified');return items;};
 return {...base,status:'observed',account:identity.Account,region:process.env.CLOUD_AWS_REGION||'ap-south-1',environment:tags(vpc).Environment||'Unknown',vpc:{id:vpc.VpcId,cidr:vpc.CidrBlock,state:vpc.State},
 subnets:scoped(subnets.Subnets,'VpcId').map(r=>({id:r.SubnetId,cidr:r.CidrBlock,tier:tags(r).NetworkTier||'Unknown',zone:r.AvailabilityZone,state:r.State,publicIpOnLaunch:r.MapPublicIpOnLaunch})),
 routeTables:scoped(routes.RouteTables.filter(r=>owned(r,projectId)),'VpcId').map(r=>({id:r.RouteTableId,routes:r.Routes.map(x=>({destination:x.DestinationCidrBlock||x.DestinationIpv6CidrBlock,target:x.GatewayId||x.NatGatewayId||'Other',state:x.State})),subnets:r.Associations.filter(x=>x.SubnetId).map(x=>x.SubnetId)})),
 securityGroups:scoped(groups.SecurityGroups,'VpcId').map(r=>({id:r.GroupId,name:r.GroupName,status:r.IpPermissions.length===0&&r.IpPermissionsEgress.length===0?'Deny all ingress/egress':'Rules present — review required'})),
 internetGateways:gateways.InternetGateways.filter(r=>owned(r,projectId)&&r.Attachments.some(a=>a.VpcId===vpc.VpcId)).map(r=>({id:r.InternetGatewayId})),
 flowLogs:scoped(flows.FlowLogs,'ResourceId').map(r=>({id:r.FlowLogId,status:r.FlowLogStatus,delivery:r.DeliverLogsStatus||'Unverified',trafficType:r.TrafficType,destinationType:r.LogDestinationType}))};
 }catch(e){const message=String(e.stderr||e.message||'');return {...base,reason:/AccessDenied|UnauthorizedOperation/.test(message)?'AWS read permission denied':/credentials|login|ExpiredToken|SSO|profile/.test(message)?'AWS credentials unavailable or expired':'AWS read failed or resource ownership could not be verified'};}
}
async function projectNetwork(pool,userId,id,read=readNetwork){
 if(!/^[1-9]\d*$/.test(String(id))||!Number.isSafeInteger(Number(id)))return {code:400,body:{error:'Invalid project ID'}};
 const {rows}=await pool.query('SELECT id FROM projects WHERE id = $1 AND user_id = $2',[Number(id),userId]);
 if(!rows.length)return {code:404,body:{error:'Project not found'}};
 return {code:200,body:await read(Number(id))};
}
module.exports={readNetwork,projectNetwork};
