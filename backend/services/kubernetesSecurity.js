function parseJsonDocuments(output) {
  const text = String(output || "").trim();
  if (!text) throw new Error("kubectl dry-run returned no resources");
  try { return [JSON.parse(text)]; } catch {}

  const documents = [];
  let start = -1, depth = 0, inString = false, escaped = false;
  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') { inString = true; continue; }
    if (char === "{") { if (depth === 0) start = index; depth++; }
    if (char === "}" && depth > 0) {
      depth--;
      if (depth === 0) { documents.push(JSON.parse(text.slice(start, index + 1))); start = -1; }
    }
  }
  if (!documents.length || depth !== 0) throw new Error("kubectl dry-run returned invalid JSON");
  return documents;
}

function flattenResources(documents) {
  return documents.flatMap(document => document.kind === "List" ? (document.items || []) : [document]);
}

function validateDeploymentSecurity(deployment) {
  if (deployment?.kind !== "Deployment") throw new Error("Security validation requires a Kubernetes Deployment");
  const name = deployment.metadata?.name || "unnamed";
  const pod = deployment.spec?.template?.spec || {};
  const podSecurity = pod.securityContext || {};
  const errors = [];
  if (pod.hostNetwork === true) errors.push("hostNetwork must not be enabled");
  if (pod.hostPID === true) errors.push("hostPID must not be enabled");
  if (pod.hostIPC === true) errors.push("hostIPC must not be enabled");
  if (pod.automountServiceAccountToken !== false) errors.push("automountServiceAccountToken must be false");
  if (podSecurity.runAsNonRoot !== true) errors.push("pod securityContext.runAsNonRoot must be true");
  if (!Number.isInteger(podSecurity.runAsUser) || podSecurity.runAsUser <= 0) errors.push("pod securityContext.runAsUser must be a non-root UID");
  if (!Number.isInteger(podSecurity.runAsGroup) || podSecurity.runAsGroup <= 0) errors.push("pod securityContext.runAsGroup must be a non-root GID");
  if (podSecurity.seccompProfile?.type !== "RuntimeDefault") errors.push("pod securityContext.seccompProfile.type must be RuntimeDefault");
  for (const volume of pod.volumes || []) if (volume.hostPath) errors.push(`volume ${volume.name || "unnamed"} must not use hostPath`);

  const containers = [...(pod.initContainers || []), ...(pod.containers || [])];
  if (!containers.length) errors.push("workload must define at least one container");
  for (const container of containers) {
    const label = `container ${container.name || "unnamed"}`;
    const security = container.securityContext || {};
    if (security.privileged !== false) errors.push(`${label} securityContext.privileged must be false`);
    if (security.allowPrivilegeEscalation !== false) errors.push(`${label} securityContext.allowPrivilegeEscalation must be false`);
    if (security.readOnlyRootFilesystem !== true) errors.push(`${label} securityContext.readOnlyRootFilesystem must be true`);
    if (!Array.isArray(security.capabilities?.drop) || !security.capabilities.drop.includes("ALL")) errors.push(`${label} must drop ALL capabilities`);
    const effectiveNonRoot = security.runAsNonRoot ?? podSecurity.runAsNonRoot;
    const effectiveUser = security.runAsUser ?? podSecurity.runAsUser;
    if (effectiveNonRoot !== true || !Number.isInteger(effectiveUser) || effectiveUser <= 0) errors.push(`${label} must run as a defined non-root user`);
    const seccomp = security.seccompProfile?.type || podSecurity.seccompProfile?.type;
    if (seccomp !== "RuntimeDefault") errors.push(`${label} must use RuntimeDefault seccomp`);
  }
  if (errors.length) throw new Error(`Kubernetes security policy rejected Deployment ${name}: ${errors.join("; ")}`);
  return true;
}

function validateManifestSecurity(dryRunOutput, expectedName, expectedNamespace) {
  const resources = flattenResources(parseJsonDocuments(dryRunOutput));
  if (expectedNamespace) {
    const supportedKinds = new Set(["Deployment", "Service"]);
    for (const resource of resources) {
      const kind = resource.kind || "Unknown";
      const name = resource.metadata?.name || "unnamed";
      if (!supportedKinds.has(kind)) throw new Error(`Kubernetes namespace policy rejected unsupported or cluster-scoped resource ${kind}/${name}`);
      if (resource.metadata?.namespace !== expectedNamespace) {
        throw new Error(`Kubernetes namespace policy rejected ${kind}/${name}: namespace ${resource.metadata?.namespace || "unspecified"} does not match ${expectedNamespace}`);
      }
    }
  }
  const deployments = resources.filter(resource => resource.kind === "Deployment");
  if (!deployments.length) throw new Error("Kubernetes security policy requires a Deployment manifest");
  const expected = deployments.find(deployment => deployment.metadata?.name === expectedName);
  if (!expected) throw new Error(`Expected Deployment ${expectedName} was not found in the manifests`);
  deployments.forEach(validateDeploymentSecurity);
  return expected;
}

function selectApplicationContainer(deployment, expectedName) {
  const containers = deployment?.spec?.template?.spec?.containers || [];
  const named = containers.filter(container => container.name === expectedName);
  if (named.length === 1) return named[0];
  if (named.length > 1) throw new Error(`Deployment ${expectedName} has duplicate application container names`);
  if (containers.length === 1) return containers[0];
  throw new Error(`Deployment ${expectedName} has an ambiguous multi-container application image`);
}

function renderManifestWithImage(dryRunOutput, expectedName, expectedNamespace, expectedImage) {
  validateManifestSecurity(dryRunOutput, expectedName, expectedNamespace);
  const resources = flattenResources(parseJsonDocuments(dryRunOutput));
  const deployment = resources.find(resource => resource.kind === "Deployment" && resource.metadata?.name === expectedName);
  const applicationContainer = selectApplicationContainer(deployment, expectedName);
  applicationContainer.image = expectedImage;
  validateDeploymentSecurity(deployment);
  return { resources, deployment, renderedJson: JSON.stringify({ apiVersion: "v1", kind: "List", items: resources }, null, 2) };
}

function assertDeploymentImage(deployment, expectedName, expectedImage) {
  const applicationContainer = selectApplicationContainer(deployment, expectedName);
  if (applicationContainer.image !== expectedImage) {
    throw new Error(`Deployment ${expectedName} uses ${applicationContainer.image || "no image"} instead of current image ${expectedImage}`);
  }
  return applicationContainer;
}

module.exports = { assertDeploymentImage, parseJsonDocuments, renderManifestWithImage, selectApplicationContainer, validateDeploymentSecurity, validateManifestSecurity };
