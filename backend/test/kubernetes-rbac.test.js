const assert=require('node:assert/strict');
const test=require('node:test');
const {rbacManifests,analyzeRbac,projectRbac,SERVICE_ACCOUNT,ROLE}=require('../services/kubernetesRbac');

const ns='cloudsentinel-p-7';
const ownedNamespace={metadata:{name:ns,labels:{'app.kubernetes.io/managed-by':'cloudsentinel','cloudsentinel.io/project-id':'7'}}};
const pool=(owned=true)=>({query:async()=>({rows:owned?[{id:7}]:[]})});

test('generated RBAC is a non-mounting ServiceAccount with a least-privilege Role and RoleBinding',()=>{
 const {items}=rbacManifests(ns,7);
 assert.deepEqual(items.map(i=>i.kind),['ServiceAccount','Role','RoleBinding']);
 const [sa,role,binding]=items;
 assert.equal(sa.automountServiceAccountToken,false);
 assert.equal(sa.metadata.name,SERVICE_ACCOUNT);
 for(const item of items)assert.equal(item.metadata.namespace,ns);
 for(const rule of role.rules)for(const field of ['apiGroups','resources','verbs'])assert.ok(!rule[field].includes('*'),`${field} has wildcard`);
 assert.deepEqual(binding.roleRef,{apiGroup:'rbac.authorization.k8s.io',kind:'Role',name:ROLE});
 assert.deepEqual(binding.subjects,[{kind:'ServiceAccount',name:SERVICE_ACCOUNT,namespace:ns}]);
});

test('generated RBAC passes its own analyzer',()=>{
 const {items}=rbacManifests(ns,7);
 const result=analyzeRbac({roles:{items:items.filter(i=>i.kind==='Role')},roleBindings:{items:items.filter(i=>i.kind==='RoleBinding')}});
 assert.equal(result.summary.compliant,true);
 assert.deepEqual(result.roles[0].flags,[]);
 assert.deepEqual(result.bindings[0].flags,[]);
});

test('rejects namespaces outside CloudSentinel projects',()=>{
 assert.throws(()=>rbacManifests('kube-system',7),/valid CloudSentinel project namespace/);
});

test('flags wildcard verbs, resources, API groups and escalation verbs',()=>{
 const roles={items:[
  {kind:'Role',metadata:{name:'admin-ish',namespace:ns},rules:[{apiGroups:['*'],resources:['*'],verbs:['*']}]},
  {kind:'Role',metadata:{name:'escalator',namespace:ns},rules:[{apiGroups:['rbac.authorization.k8s.io'],resources:['roles'],verbs:['bind','escalate']}]},
  {kind:'Role',metadata:{name:'reader',namespace:ns},rules:[{apiGroups:[''],resources:['pods'],verbs:['get']}]},
 ]};
 const {roles:rows,summary}=analyzeRbac({roles,roleBindings:{items:[]}});
 assert.deepEqual(rows[0].flags,['Wildcard verb','Wildcard resource','Wildcard API group']);
 assert.deepEqual(rows[1].flags,['Privilege escalation verb: escalate','Privilege escalation verb: bind']);
 assert.deepEqual(rows[2].flags,[]);
 assert.equal(summary.wildcardRoles,1);
 assert.equal(summary.compliant,false);
});

test('flags cluster-admin bindings, other ClusterRole references and public groups',()=>{
 const roleBindings={items:[
  {metadata:{name:'oops',namespace:ns},roleRef:{kind:'ClusterRole',name:'cluster-admin'},subjects:[{kind:'ServiceAccount',name:'default',namespace:ns}]},
  {metadata:{name:'view',namespace:ns},roleRef:{kind:'ClusterRole',name:'view'},subjects:[{kind:'Group',name:'system:authenticated'}]},
 ]};
 const {bindings,summary}=analyzeRbac({roles:{items:[]},roleBindings});
 assert.deepEqual(bindings[0].flags,['Binds cluster-admin']);
 assert.deepEqual(bindings[1].flags,['References ClusterRole view','Grants access to all (un)authenticated users']);
 assert.equal(summary.clusterAdminBindings,1);
 assert.equal(summary.compliant,false);
});

test('endpoint reads roles and bindings only from the owned project namespace',async()=>{
 const calls=[];
 const run=async args=>{calls.push(args);if(args[1]==='namespace')return ownedNamespace;return args[1]==='roles'?{items:[{kind:'Role',metadata:{name:'r',namespace:ns},rules:[{apiGroups:[''],resources:['secrets'],verbs:['*']}]}]}:{items:[]};};
 const r=await projectRbac(pool(),1,'7',run);
 assert.equal(r.code,200);
 assert.equal(r.body.status,'observed');
 assert.equal(r.body.summary.wildcardRoles,1);
 assert.deepEqual(calls.slice(1).map(a=>a.slice(0,4)),[['get','roles','-n',ns],['get','rolebindings','-n',ns]]);
});

test('endpoint enforces ownership, validates ids and reports missing namespaces',async()=>{
 assert.equal((await projectRbac(pool(),1,'abc',async()=>({}))).code,400);
 assert.equal((await projectRbac(pool(false),1,'7',async()=>({}))).code,404);
 const missing=await projectRbac(pool(),1,'7',async()=>{throw Object.assign(Error('Error from server (NotFound): namespaces "x" not found'),{stderr:''});});
 assert.equal(missing.body.status,'not_deployed');
 const foreign=await projectRbac(pool(),1,'7',async()=>({metadata:{name:ns,labels:{}}}));
 assert.equal(foreign.body.status,'not_connected');
});
