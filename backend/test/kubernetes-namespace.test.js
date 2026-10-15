const assert = require("node:assert/strict");
const test = require("node:test");
const { getProjectNamespace, ensureProjectNamespace, assertNamespaceOwnership } = require("../services/kubernetesNamespace");
const { validateManifestSecurity } = require("../services/kubernetesSecurity");

function secureDeployment(name, namespace) {
  return { apiVersion:"apps/v1", kind:"Deployment", metadata:{name,namespace}, spec:{template:{spec:{
    automountServiceAccountToken:false,
    securityContext:{runAsNonRoot:true,runAsUser:10001,runAsGroup:10001,seccompProfile:{type:"RuntimeDefault"}},
    containers:[{name:"app",securityContext:{privileged:false,allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:["ALL"]}}}],
  }}}};
}

const ownedNamespace = id => JSON.stringify({metadata:{name:getProjectNamespace(id),labels:{"app.kubernetes.io/managed-by":"cloudsentinel","cloudsentinel.io/project-id":String(id)}}});

test("project namespace names are deterministic and distinct", () => {
  assert.equal(getProjectNamespace(12), "cloudsentinel-p-12");
  assert.equal(getProjectNamespace(25), "cloudsentinel-p-25");
  assert.notEqual(getProjectNamespace(12), getProjectNamespace(25));
  assert.throws(() => getProjectNamespace("12"), /trusted project ID/);
});

test("existing owned namespace is reused idempotently", async () => {
  const calls = [];
  const execute = async (label, _cmd, args) => { calls.push({label,args}); return ownedNamespace(12); };
  assert.deepEqual(await ensureProjectNamespace(12, execute), {namespace:"cloudsentinel-p-12",created:false});
  assert.deepEqual(await ensureProjectNamespace(12, execute), {namespace:"cloudsentinel-p-12",created:false});
  assert.equal(calls.every(call => call.label === "kubectl get namespace"), true);
});

test("missing namespace is created, labeled, and verified", async () => {
  const calls = [];
  let gets = 0;
  const execute = async (label, _cmd, args) => {
    calls.push({label,args});
    if (label === "kubectl get namespace" && gets++ === 0) throw new Error("NotFound");
    if (label === "kubectl verify namespace") return ownedNamespace(25);
    return "created";
  };
  assert.deepEqual(await ensureProjectNamespace(25, execute), {namespace:"cloudsentinel-p-25",created:true});
  assert.deepEqual(calls.map(call => call.label), ["kubectl get namespace","kubectl create namespace","kubectl label namespace","kubectl verify namespace"]);
});

test("conflicting namespace ownership labels are rejected", async () => {
  const execute = async () => JSON.stringify({metadata:{name:"cloudsentinel-p-12",labels:{"app.kubernetes.io/managed-by":"other","cloudsentinel.io/project-id":"99"}}});
  await assert.rejects(ensureProjectNamespace(12, execute), /without matching CloudSentinel project ownership labels/);
  assert.throws(() => assertNamespaceOwnership(JSON.parse(ownedNamespace(12)), 25), /ownership labels/);
});

test("namespace lookup failures other than NotFound fail closed", async () => {
  await assert.rejects(ensureProjectNamespace(12, async () => { throw new Error("API server unavailable"); }), /API server unavailable/);
});

test("custom resource in a conflicting namespace is rejected", () => {
  const deployment = secureDeployment("demo", "cloudsentinel-p-25");
  assert.throws(() => validateManifestSecurity(JSON.stringify(deployment), "demo", "cloudsentinel-p-12"), /does not match cloudsentinel-p-12/);
});

test("Namespace and unsupported cluster-scoped resources are rejected", () => {
  const deployment = secureDeployment("demo", "cloudsentinel-p-12");
  const resources = {kind:"List",items:[deployment,{apiVersion:"v1",kind:"Namespace",metadata:{name:"escape"}}]};
  assert.throws(() => validateManifestSecurity(JSON.stringify(resources), "demo", "cloudsentinel-p-12"), /cluster-scoped resource Namespace/);
});

test("same application name remains isolated by trusted project namespace", () => {
  const app = "same-repository-name";
  const first = secureDeployment(app, getProjectNamespace(12));
  const second = secureDeployment(app, getProjectNamespace(25));
  assert.equal(validateManifestSecurity(JSON.stringify(first), app, getProjectNamespace(12)).metadata.namespace, "cloudsentinel-p-12");
  assert.equal(validateManifestSecurity(JSON.stringify(second), app, getProjectNamespace(25)).metadata.namespace, "cloudsentinel-p-25");
});
