const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { generateDockerfileContent, generateK8sManifests, detectContainerPort } = require("../services/deployment");
const { validateDeploymentSecurity, validateManifestSecurity } = require("../services/kubernetesSecurity");

function tempRepo(files = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cloudsentinel-security-test-"));
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), content);
  return dir;
}

function secureDeployment(name = "demo") {
  return {
    apiVersion: "apps/v1", kind: "Deployment", metadata: { name },
    spec: { template: { spec: {
      automountServiceAccountToken: false,
      securityContext: { runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: { type: "RuntimeDefault" } },
      containers: [{ name: "app", securityContext: { privileged: false, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } } }],
    } } },
  };
}

test("generated static image and manifests are non-root and port-compatible", () => {
  const dir = tempRepo();
  try {
    const dockerfile = generateDockerfileContent("unknown", dir);
    const port = detectContainerPort("unknown", dir);
    const manifests = generateK8sManifests("Demo", "demo:latest", port, "unknown", "cloudsentinel-p-12");
    assert.equal(port, 8080);
    assert.match(dockerfile, /USER 10001:10001/);
    assert.match(dockerfile, /listen 8080/);
    assert.match(dockerfile, /EXPOSE 8080/);
    assert.match(manifests.deployment, /namespace: cloudsentinel-p-12/);
    assert.match(manifests.service, /namespace: cloudsentinel-p-12/);
    assert.match(manifests.deployment, /runAsNonRoot: true/);
    assert.match(manifests.deployment, /allowPrivilegeEscalation: false/);
    assert.match(manifests.deployment, /readOnlyRootFilesystem: true/);
    assert.match(manifests.deployment, /type: RuntimeDefault/);
    assert.match(manifests.deployment, /containerPort: 8080/);
    assert.match(manifests.deployment, /port: 8080/);
    assert.match(manifests.service, /targetPort: 8080/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("generated Node image uses npm start, ownership, non-root user, and detected port", () => {
  const dir = tempRepo({ "package.json": JSON.stringify({ scripts: { start: "node server.js --port=4100" } }) });
  try {
    const dockerfile = generateDockerfileContent("node", dir);
    assert.match(dockerfile, /COPY --chown=10001:10001/);
    assert.match(dockerfile, /USER 10001:10001/);
    assert.match(dockerfile, /CMD \["npm", "start"\]/);
    assert.match(dockerfile, /PORT=4100/);
    assert.equal(detectContainerPort("node", dir), 4100);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("generated Python image runs with owned files as non-root", () => {
  const dir = tempRepo();
  try {
    const dockerfile = generateDockerfileContent("python", dir);
    assert.match(dockerfile, /useradd --uid 10001/);
    assert.match(dockerfile, /COPY --chown=10001:10001/);
    assert.match(dockerfile, /PYTHONDONTWRITEBYTECODE=1/);
    assert.match(dockerfile, /USER 10001:10001/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("generated Maven and Gradle runtime images are non-root", () => {
  const dir = tempRepo();
  try {
    for (const stack of ["java-maven", "java-gradle"]) {
      const dockerfile = generateDockerfileContent(stack, dir);
      assert.match(dockerfile, /COPY --from=build --chown=10001:10001/);
      assert.match(dockerfile, /USER 10001:10001/);
      assert.match(dockerfile, /CMD \["java", "-jar", "app.jar"\]/);
    }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("existing secure Deployment is accepted without mutation", () => {
  const deployment = secureDeployment();
  const before = JSON.stringify(deployment);
  assert.deepEqual(validateManifestSecurity(JSON.stringify({ kind: "List", items: [deployment] }), "demo"), deployment);
  assert.equal(JSON.stringify(deployment), before);
});

test("existing manifest missing controls is rejected with useful errors", () => {
  const deployment = secureDeployment();
  delete deployment.spec.template.spec.automountServiceAccountToken;
  delete deployment.spec.template.spec.containers[0].securityContext.capabilities;
  assert.throws(() => validateDeploymentSecurity(deployment), /automountServiceAccountToken.*drop ALL capabilities/);
});

test("privileged and hostPath workloads are rejected", () => {
  const deployment = secureDeployment();
  deployment.spec.template.spec.containers[0].securityContext.privileged = true;
  deployment.spec.template.spec.volumes = [{ name: "host", hostPath: { path: "/" } }];
  assert.throws(() => validateDeploymentSecurity(deployment), /hostPath.*privileged/s);
});

test("security policy applies to every regular and init container", () => {
  const deployment = secureDeployment();
  deployment.spec.template.spec.containers.push({ name: "sidecar", securityContext: { privileged: false } });
  deployment.spec.template.spec.initContainers = [{ name: "init", securityContext: { privileged: true } }];
  assert.throws(() => validateDeploymentSecurity(deployment), /container init.*container sidecar/s);
});

test("generated manifests require an assigned project namespace", () => {
  assert.throws(() => generateK8sManifests("Demo", "demo:latest", 8080), /valid CloudSentinel project namespace/);
});
