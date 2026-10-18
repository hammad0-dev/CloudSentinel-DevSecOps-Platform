const test=require('node:test'),assert=require('node:assert/strict');
const {inventory,projectInventory,observations}=require('../services/kubernetesInventory');
const ns='custom-project-namespace';
const pod={metadata:{name:'pod',namespace:ns,labels:{app:'app'}},spec:{containers:[{name:'web',image:'nginx:latest'}]},status:{phase:'Running',conditions:[{type:'Ready',status:'True'}],containerStatuses:[{restartCount:2}]}};
function runner(args){
 if(args[0]==='config')return {'current-context':'minikube',contexts:[{name:'minikube',context:{cluster:'minikube'}}]};
 assert.ok(args.includes('--context'));const type=args[args.indexOf('get')+1];
 if(type==='namespaces')return {items:[{metadata:{name:ns,labels:{'cloudsentinel.io/project-id':'13','app.kubernetes.io/managed-by':'cloudsentinel'}}}]};
 if(type==='deployments')return {items:[{metadata:{name:'app',namespace:ns,labels:{'managed-by':'cloudsentinel'}},spec:{replicas:2},status:{readyReplicas:1,availableReplicas:1}}]};
 return {items:[pod]};
}
test('owner check precedes cluster reads; invalid IDs and other owners rejected',async()=>{const read=()=>assert.fail('must not read');assert.equal((await projectInventory({query:async()=>({rows:[]})},4,13,read)).code,404);assert.equal((await projectInventory({},3,'13;bad',read)).code,400)});
test('uses successful deployment mapping and authenticated owner',async()=>{let n=0;await projectInventory({query:async(sql,args)=>{n++;if(n===1){assert.deepEqual(args,[13,3]);return {rows:[{id:13}]}}assert.match(sql,/status='SUCCESS'/);return {rows:[{app_name:'app'}]}}},3,13,async(id,records)=>{assert.equal(id,13);assert.equal(records[0].app_name,'app')});assert.equal(n,2)});
test('custom namespace mapping, real pod counts and replicas',async()=>{const r=await inventory(13,[{app_name:'app'}],async a=>runner(a));assert.equal(r.status,'observed');assert.deepEqual(r.namespaces,[ns]);assert.equal(r.counts.ready,1);assert.equal(r.counts.desiredReplicas,2);assert.equal(r.pods[0].restarts,2);assert.equal(r.counts.readyReplicas,1)});
test('no deployment does not contact Kubernetes',async()=>{assert.equal((await inventory(13,[],()=>assert.fail())).status,'not_deployed')});
test('wrong context and failed connection redact native errors',async()=>{for(const run of [async()=>{throw Error('secret certificate token')},async()=>({'current-context':'eks',contexts:[]})]){const r=await inventory(13,[{app_name:'app'}],run);assert.equal(r.status,'not_connected');assert.doesNotMatch(JSON.stringify(r),/certificate token/);}});
test('mismatched namespace labels fail closed',async()=>{const r=await inventory(13,[{app_name:'app'}],async a=>{const r=runner(a);if(a.includes('namespaces'))r.items[0].metadata.labels['cloudsentinel.io/project-id']='17';return r});assert.equal(r.status,'not_connected')});
test('absence of non-root enforcement is unknown, not root proof',()=>{const r=observations([pod]);assert.ok(r.some(i=>i.severity==='INFO'&&/UID unknown/.test(i.issue)));assert.ok(!r.some(i=>/Explicit root/.test(i.issue)));assert.ok(r.some(i=>/limit missing/.test(i.issue)));assert.ok(r.some(i=>/readiness/i.test(i.issue)))});
test('explicit root and privileged configuration produce supported observations',()=>{const p=structuredClone(pod);p.spec.securityContext={runAsUser:0};p.spec.containers[0].securityContext={privileged:true};const r=observations([p]);assert.ok(r.some(i=>/Explicit root/.test(i.issue)));assert.ok(r.some(i=>/Privileged/.test(i.issue)))});
