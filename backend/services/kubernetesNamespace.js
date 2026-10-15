const MANAGED_BY_LABEL = "app.kubernetes.io/managed-by";
const PROJECT_ID_LABEL = "cloudsentinel.io/project-id";

function getProjectNamespace(projectId) {
  if (!Number.isInteger(projectId) || projectId <= 0) throw new Error("A valid trusted project ID is required for namespace assignment");
  return `cloudsentinel-p-${projectId}`;
}

function assertNamespaceOwnership(namespaceObject, projectId) {
  const expectedName = getProjectNamespace(projectId);
  const labels = namespaceObject?.metadata?.labels || {};
  if (namespaceObject?.metadata?.name !== expectedName || labels[MANAGED_BY_LABEL] !== "cloudsentinel" || labels[PROJECT_ID_LABEL] !== String(projectId)) {
    throw new Error(`Namespace ${expectedName} exists without matching CloudSentinel project ownership labels`);
  }
  return expectedName;
}

function isNotFound(error) {
  return /notfound|not found/i.test(error?.message || "");
}

async function ensureProjectNamespace(projectId, execute, cwd) {
  const namespace = getProjectNamespace(projectId);
  try {
    const existing = JSON.parse(await execute("kubectl get namespace", "kubectl", ["get", "namespace", namespace, "-o", "json"], cwd, 30000));
    assertNamespaceOwnership(existing, projectId);
    return { namespace, created: false };
  } catch (error) {
    if (!isNotFound(error)) throw error;
  }

  try {
    await execute("kubectl create namespace", "kubectl", ["create", "namespace", namespace], cwd, 30000);
    await execute("kubectl label namespace", "kubectl", ["label", "namespace", namespace, `${MANAGED_BY_LABEL}=cloudsentinel`, `${PROJECT_ID_LABEL}=${projectId}`], cwd, 30000);
  } catch (error) {
    if (!/alreadyexists|already exists/i.test(error?.message || "")) throw error;
  }

  const created = JSON.parse(await execute("kubectl verify namespace", "kubectl", ["get", "namespace", namespace, "-o", "json"], cwd, 30000));
  assertNamespaceOwnership(created, projectId);
  return { namespace, created: true };
}

module.exports = { MANAGED_BY_LABEL, PROJECT_ID_LABEL, assertNamespaceOwnership, ensureProjectNamespace, getProjectNamespace };
