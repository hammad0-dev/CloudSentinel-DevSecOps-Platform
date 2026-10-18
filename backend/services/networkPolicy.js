'use strict';
const fs=require('node:fs/promises'),path=require('node:path');
const MODES=['CONNECTED_NETWORK','ISOLATED_VPC'];
function isolation({account,region,template,resources=[],discovery,existingVpcId=null,requiresExternalConnectivity=false}){
 const blockers=[];
 if(account!=='229032674007')blockers.push('ACCOUNT_NOT_APPROVED');
 if(region!=='ap-south-1')blockers.push('REGION_NOT_APPROVED');
 if(template!=='network-only'||requiresExternalConnectivity)blockers.push('TEMPLATE_OR_CONNECTIVITY_NOT_APPROVED');
 const allowed=['aws_vpc','aws_subnet','aws_internet_gateway','aws_route_table','aws_route','aws_route_table_association','aws_security_group','aws_default_security_group','aws_flow_log'];
 if(resources.length!==13||resources.some(r=>!allowed.includes(r.type))||Object.entries({aws_vpc:1,aws_subnet:2,aws_internet_gateway:1,aws_route_table:2,aws_route:1,aws_route_table_association:2,aws_security_group:2,aws_default_security_group:1,aws_flow_log:1}).some(([type,n])=>resources.filter(r=>r.type===type).length!==n))blockers.push('ISOLATION_TEMPLATE_UNVERIFIED');
 if(resources.some(r=>r.type==='aws_route'&&(r.name!=='public_internet'||r.destination!=='0.0.0.0/0'||r.target!=='aws_internet_gateway.this.id')))blockers.push('EXTERNAL_ROUTE_NOT_APPROVED');
 const mandatory=['get-caller-identity','describe-vpcs','describe-route-tables','describe-vpc-peering-connections','describe-vpn-connections','describe-transit-gateway-attachments'];
 if(!discovery||discovery.coreVerified!==true||discovery.account!==account||discovery.region!==region||!Number.isFinite(Date.parse(discovery.observedAt))||Date.now()-Date.parse(discovery.observedAt)>300000||Date.parse(discovery.observedAt)>Date.now()||mandatory.some(op=>discovery.coverage?.[op]!=='READ'))blockers.push('MANDATORY_ISOLATION_DISCOVERY_MISSING');
 // New-VPC-only provisioning does not adopt or attach any existing VPC.
 if(existingVpcId)blockers.push('EXISTING_VPC_ASSOCIATIONS_REQUIRE_SEPARATE_REVIEW');
 return {mode:'ISOLATED_VPC',templateIsolationVerified:!blockers.some(b=>/TEMPLATE|ROUTE|CONNECTIVITY/.test(b)),isolationVerified:!blockers.length,accountWideCompleteness:discovery?.complete===true,blockers,planningReady:false,limitation:'New VPC only. Account-wide external connectivity is not proven absent; application hosting is unsupported.'};
}
async function trustedTemplate(){
 const text=await fs.readFile(path.resolve(__dirname,'../../terraform/modules/aws-network/main.tf'),'utf8');
 const resources=[...text.matchAll(/resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/g)].map(m=>({type:m[1],name:m[2]}));
 const route=resources.find(r=>r.type==='aws_route'&&r.name==='public_internet');
 if(route){route.destination=/destination_cidr_block\s*=\s*"([^"]+)"/.exec(text)?.[1];route.target=/gateway_id\s*=\s*([^\n]+)/.exec(text)?.[1].trim();}
 // Reject forbidden route targets regardless of resource allowlist.
 if(/\bmodule\s+"|\broute\s*\{/.test(text)||[...text.matchAll(/\bvpc_id\s*=\s*([^\n]+)/g)].some(m=>m[1].trim()!=='aws_vpc.this.id'))resources.push({type:'UNVERIFIED_EXISTING_NETWORK_REFERENCE'});
 if(/\b(?:transit_gateway_id|nat_gateway_id|vpc_peering_connection_id|vpn_gateway_id|network_interface_id)\s*=/.test(text))resources.push({type:'FORBIDDEN_ROUTE_TARGET'});
 return resources;
}
module.exports={MODES,isolation,trustedTemplate};
