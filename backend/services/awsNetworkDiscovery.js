'use strict';
const {execFile}=require('node:child_process'),execute=require('node:util').promisify(execFile);
async function aws(operation,args=[]){const service=operation==='get-caller-identity'?'sts':'ec2';const {stdout}=await execute('aws',['--profile',process.env.CLOUD_AWS_PROFILE||'cloudsentinel-dev','--region','ap-south-1','--cli-connect-timeout','3','--cli-read-timeout','5',service,operation,...args,'--output','json'],{timeout:10000,maxBuffer:2*1024*1024,env:{...process.env,AWS_PAGER:''}});return JSON.parse(stdout)}
function classifyError(e){
 const text=String(e.stderr||e.message||''),match=/An error occurred \(([^)]+)\)/.exec(text),code=match?.[1]||e.code||'UNKNOWN';
 const status=code==='SubscriptionRequiredException'?'SERVICE_SUBSCRIPTION_BLOCKED':/AccessDenied|UnauthorizedOperation|Forbidden/i.test(String(code))?'ACCESS_DENIED':/InvalidAction|UnsupportedOperation|UnknownOperation|invalid choice/i.test(text)?'UNSUPPORTED_API':/NotFound|NotFoundException/i.test(String(code))?'ABSENT_RESOURCE':e.killed||/timeout|ETIMEDOUT/i.test(text)?'TIMEOUT':'FAILED';
 return {status,errorCode:/^[A-Za-z0-9_.-]{1,80}$/.test(String(code))?String(code):'UNKNOWN'};
}
async function discover(run=aws){
 const coverage={},outcomes={},ranges=[],blocked=[];let coreVerified=true;
 const read=async(op,key,args=[])=>{try{const data=await run(op,args);if(key&&!Array.isArray(data[key]))throw Object.assign(Error('Malformed discovery response'),{code:'MALFORMED_RESPONSE'});coverage[op]='READ';outcomes[op]={status:key?(data[key].length?'NONEMPTY':'EMPTY'):'IDENTITY_READ',count:key?data[key].length:undefined};return key?data[key]:data}catch(e){coverage[op]='UNVERIFIED';outcomes[op]=classifyError(e);blocked.push(op);return null}};
 const identity=await read('get-caller-identity');if(identity?.Account!=='229032674007')return {observedAt:new Date().toISOString(),coreVerified:false,complete:false,ranges:[],coverage,outcomes,blocked:['ACCOUNT_IDENTITY_UNVERIFIED']};
 const results=await Promise.all([['describe-vpcs','Vpcs'],['describe-route-tables','RouteTables'],['describe-vpc-peering-connections','VpcPeeringConnections'],['describe-transit-gateway-attachments','TransitGatewayAttachments'],['describe-vpn-connections','VpnConnections'],['describe-transit-gateway-route-tables','TransitGatewayRouteTables']].map(async([op,key])=>[op,await read(op,key)]));
 const data=Object.fromEntries(results);coreVerified=!!data['describe-vpcs']&&!!data['describe-route-tables'];
 const add=c=>{if(c&&c!=='0.0.0.0/0')ranges.push(c)};
 for(const v of data['describe-vpcs']||[]){add(v.CidrBlock);for(const c of v.CidrBlockAssociationSet||[])add(c.CidrBlock)}
 for(const r of data['describe-route-tables']||[])for(const x of r.Routes||[]){add(x.DestinationCidrBlock);if(x.DestinationPrefixListId)blocked.push('MANAGED_PREFIX_LIST_RANGES_UNVERIFIED');}
 for(const p of data['describe-vpc-peering-connections']||[])for(const side of [p.RequesterVpcInfo,p.AccepterVpcInfo]){add(side?.CidrBlock);for(const c of side?.CidrBlockSet||[])add(c.CidrBlock)}
 for(const v of data['describe-vpn-connections']||[]){for(const r of v.Routes||[])add(r.DestinationCidrBlock);blocked.push('VPN_REMOTE_BGP_PREFIX_COMPLETENESS_UNVERIFIED')}
 const tables=data['describe-transit-gateway-route-tables']||[];
 if(tables.length>20)blocked.push('TRANSIT_ROUTE_TABLE_BOUND_EXCEEDED');
 for(const table of tables.slice(0,20)){
  const op='search-transit-gateway-routes';try{const d=await run(op,['--transit-gateway-route-table-id',table.TransitGatewayRouteTableId,'--filters','Name=state,Values=active,blackhole','--max-results','1000']);if(!Array.isArray(d.Routes)||d.AdditionalRoutesAvailable)throw Object.assign(Error('Incomplete transit routes'),{code:'TRUNCATED_OR_MALFORMED_RESPONSE'});for(const r of d.Routes)add(r.DestinationCidrBlock);if(coverage[op]!=='UNVERIFIED'){coverage[op]='READ';outcomes[op]={status:d.Routes.length?'NONEMPTY':'EMPTY',count:(outcomes[op]?.count||0)+d.Routes.length}}}catch(e){coverage[op]='UNVERIFIED';outcomes[op]=classifyError(e);blocked.push('TRANSIT_ROUTES_UNVERIFIED')}
 }
 // No AWS API proves future/on-premise ranges or all remote-account attachments.
 blocked.push('ON_PREMISE_REMOTE_ACCOUNTS_AND_PLANNED_NETWORKS_REQUIRE_ADMINISTRATOR_EVIDENCE');
 return {observedAt:new Date().toISOString(),account:'229032674007',region:'ap-south-1',coreVerified,complete:false,networkFingerprint:require('node:crypto').createHash('sha256').update(JSON.stringify(data)).digest('hex'),ranges:[...new Set(ranges)],coverage,outcomes,blocked:[...new Set(blocked)]};
}
module.exports={discover,aws,classifyError};
