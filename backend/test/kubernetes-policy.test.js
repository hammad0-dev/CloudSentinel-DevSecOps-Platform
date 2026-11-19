const assert=require('node:assert/strict');
const test=require('node:test');
const {parseKyvernoDenial,serverDryRun,summarizePolicyReports,blockedEvents,clusterPolicies,projectPolicies}=require('../services/kubernetesPolicy');
const {generateK8sManifests}=require('../services/deployment');

const ns='cloudsentinel-p-7';
const DENIAL=`kubectl server dry-run failed (exit 1): Error from server: error when creating ".cloudsentinel-rendered.json": admission webhook "validate.kyverno.svc-fail" denied the request:

resource Deployment/${ns}/demo was blocked due to the following policies

require-labels:
  autogen-check-app-owner-labels: 'validation error: The labels ''app'' and ''owner'' are required. rule autogen-check-app-owner-labels failed at path /spec/template/metadata/labels/owner/'
require-run-as-non-root:
  autogen-run-as-non-root: 'validation error: Running as root is not allowed. Set securityContext.runAsNonRoot to true on the Pod or every container.'
`;

test('parses Kyverno admission denials into policy/rule/message',()=>{
 const d=parseKyvernoDenial(DENIAL);
 assert.equal(d.blocked,true);
 assert.deepEqual(d.resources,[`Deployment/${ns}/demo`]);
 assert.deepEqual(d.violations.map(v=>[v.policy,v.rule]),[['require-labels','autogen-check-app-owner-labels'],['require-run-as-non-root','autogen-run-as-non-root']]);
 assert.match(d.violations[1].message,/^validation error: Running as root is not allowed/);
 assert.deepEqual(parseKyvernoDenial('error: unable to connect'),{blocked:false,resources:[],violations:[]});
});

test('server dry-run pass is recorded as passed evidence',async()=>{
 const calls=[];
 const r=await serverDryRun(async(...a)=>{calls.push(a);return 'deployment.apps/demo created (server dry run)';},ns,'/tmp/m.json','/tmp',()=>'T');
 assert.deepEqual(calls[0].slice(0,3),['kubectl server dry-run','kubectl',['apply','--dry-run=server','--namespace',ns,'-f','/tmp/m.json']]);
 assert.equal(r.passed,true);
 assert.equal(r.checkedAt,'T');
 assert.deepEqual(r.violations,[]);
});

test('Kyverno denial fails non-retryably with the denial as the reason',async()=>{
 await assert.rejects(serverDryRun(async()=>{throw Error(DENIAL);},ns,'/tmp/m.json','/tmp'),error=>{
  assert.equal(error.code,'KYVERNO_POLICY_BLOCKED');
  assert.equal(error.nonRetryable,true);
  assert.match(error.message,/^Kyverno policy blocked deployment: require-labels\/autogen-check-app-owner-labels: validation error: The labels/);
  assert.match(error.message,/require-run-as-non-root\/autogen-run-as-non-root: validation error: Running as root is not allowed/);
  assert.equal(error.policyValidation.passed,false);
  assert.equal(error.policyValidation.blockedByPolicy,true);
  assert.equal(error.policyValidation.violations.length,2);
  return true;
 });
});

test('other server dry-run errors stay retryable and are not labelled as policy blocks',async()=>{
 await assert.rejects(serverDryRun(async()=>{throw Error('The connection to the server was refused');},ns,'/f','/'),error=>{
  assert.equal(error.code,'SERVER_DRY_RUN_FAILED');
  assert.equal(error.nonRetryable,false);
  assert.equal(error.policyValidation.blockedByPolicy,false);
  return true;
 });
});

test('summarizes PolicyReports per policy for scope-style and resources-style reports',()=>{
 const reports={items:[
  {kind:'PolicyReport',metadata:{namespace:ns},scope:{kind:'Pod',name:'demo-1',namespace:ns},results:[
   {policy:'require-labels',rule:'check-app-owner-labels',result:'pass'},
   {policy:'require-run-as-non-root',rule:'run-as-non-root',result:'fail',message:'Running as root is not allowed.'}]},
  {kind:'PolicyReport',metadata:{namespace:ns},results:[
   {policy:'require-labels',rule:'check-app-owner-labels',result:'fail',message:'labels required',resources:[{kind:'Pod',name:'legacy',namespace:ns}]},
   {policy:'disallow-latest-tag',rule:'validate-image-tag',result:'skip'}]},
  {kind:'ClusterPolicyReport',results:[
   {policy:'require-labels',rule:'r',result:'fail',resources:[{kind:'Pod',name:'other',namespace:'cloudsentinel-p-8'}]},
   {policy:'require-labels',rule:'r',result:'pass',resources:[{kind:'Pod',name:'mine',namespace:ns}]}]},
 ]};
 const rows=summarizePolicyReports(reports,ns);
 const labels=rows.find(r=>r.policy==='require-labels');
 assert.deepEqual([labels.pass,labels.fail],[2,1]);
 assert.deepEqual(labels.failures,[{rule:'check-app-owner-labels',resource:'Pod/legacy',message:'labels required'}]);
 const root=rows.find(r=>r.policy==='require-run-as-non-root');
 assert.deepEqual([root.pass,root.fail],[0,1]);
 assert.equal(root.failures[0].resource,'Pod/demo-1');
 assert.equal(rows.find(r=>r.policy==='disallow-latest-tag').skip,1);
 assert.equal(rows[0].fail>=rows.at(-1).fail,true);
});

test('lists recent blocked PolicyViolation events for the project namespace only',()=>{
 const events={items:[
  {reason:'PolicyViolation',involvedObject:{kind:'ClusterPolicy',name:'require-run-as-non-root'},lastTimestamp:'2026-11-19T10:00:00Z',message:`Pod ${ns}/root-pod: [run-as-non-root] fail (blocked); validation error: Running as root is not allowed.`},
  {reason:'PolicyViolation',involvedObject:{name:'disallow-privileged'},lastTimestamp:'2026-11-19T11:00:00Z',message:`Pod ${ns}/priv: [privileged-containers] fail (blocked); privileged`},
  {reason:'PolicyViolation',involvedObject:{name:'require-labels'},lastTimestamp:'2026-11-19T12:00:00Z',message:'Pod cloudsentinel-p-8/x: [check] fail (blocked); labels'},
  {reason:'PolicyViolation',involvedObject:{name:'require-labels'},lastTimestamp:'2026-11-19T13:00:00Z',message:`Pod ${ns}/y: [check] fail; audit only`},
  {reason:'Created',message:`Pod ${ns}/z blocked`},
 ]};
 const rows=blockedEvents(events,ns);
 assert.deepEqual(rows.map(r=>r.policy),['disallow-privileged','require-run-as-non-root']);
 assert.equal(rows[1].count,1);
});

test('summarizes ClusterPolicy mode and readiness',()=>{
 const rows=clusterPolicies({items:[{metadata:{name:'p'},spec:{validationFailureAction:'Enforce',rules:[{},{}]},status:{conditions:[{type:'Ready',status:'True'}]}}]});
 assert.deepEqual(rows,[{name:'p',action:'Enforce',ready:true,rules:2}]);
});

test('policies endpoint reports a missing Kyverno install',async()=>{
 const pool={query:async()=>({rows:[{id:7}]})};
 const run=async args=>{
  if(args[1]==='namespace')return {metadata:{name:ns,labels:{'app.kubernetes.io/managed-by':'cloudsentinel','cloudsentinel.io/project-id':'7'}}};
  throw Object.assign(Error('error: the server doesn\'t have a resource type "clusterpolicies"'),{stderr:''});
 };
 const r=await projectPolicies(pool,1,'7',run);
 assert.equal(r.body.status,'kyverno_not_installed');
});

test('policies endpoint combines policies, reports and blocked events',async()=>{
 const pool={query:async()=>({rows:[{id:7}]})};
 const run=async args=>({
  namespace:{metadata:{name:ns,labels:{'app.kubernetes.io/managed-by':'cloudsentinel','cloudsentinel.io/project-id':'7'}}},
  clusterpolicies:{items:[{metadata:{name:'require-labels'},spec:{validationFailureAction:'Enforce',rules:[{}]}}]},
  policyreports:{items:[{kind:'PolicyReport',scope:{kind:'Pod',name:'a',namespace:ns},results:[{policy:'require-labels',result:'pass'}]}]},
  clusterpolicyreports:{items:[]},
  events:{items:[{reason:'PolicyViolation',involvedObject:{name:'require-labels'},message:`Pod ${ns}/b: [c] fail (blocked); x`}]},
 })[args[1]];
 const r=await projectPolicies(pool,1,'7',run);
 assert.equal(r.body.status,'observed');
 assert.deepEqual(r.body.results.map(x=>[x.policy,x.pass,x.fail]),[['require-labels',1,0]]);
 assert.equal(r.body.blocked.length,1);
 assert.equal(r.body.policies[0].action,'Enforce');
});

// FE-2: generated manifests satisfy every Kyverno policy in k8s/kyverno/policies.
for(const [stack,uid] of [['node',1000],['python',1000],['unknown',10001]]){
 test(`generated ${stack} manifest satisfies the Kyverno policies`,()=>{
  const {deployment,service}=generateK8sManifests('Demo App','cloudsentinel-p7:exec-1-abc',3000,stack,ns);
  const template=deployment.slice(deployment.indexOf('  template:'));
  assert.match(template,/labels:\n\s+app: demo-app\n\s+owner: project-7/,'require-labels');
  assert.match(service,/owner: project-7/);
  assert.match(template,/securityContext:\n\s+runAsNonRoot: true\n\s+runAsUser: (\d+)/,'require-run-as-non-root');
  assert.equal(Number(template.match(/runAsUser: (\d+)/)[1]),uid);
  assert.doesNotMatch(template,/runAsUser: 0\b/);
  assert.match(template,/privileged: false/,'disallow-privileged');
  assert.match(template,/allowPrivilegeEscalation: false/);
  assert.match(template,/readOnlyRootFilesystem: true/);
  assert.match(template,/drop:\n\s+- ALL/);
  assert.match(template,/limits:\n\s+cpu: "\d+m"\n\s+memory: "\d+Mi"/,'require-resource-limits');
  assert.match(template,/image: [^\s:]+:(?!latest\b)\S+/,'disallow-latest-tag');
  assert.match(template,/serviceAccountName: cloudsentinel-app\n\s+automountServiceAccountToken: false/);
 });
}
