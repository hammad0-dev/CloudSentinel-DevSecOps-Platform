// Minikube staging URLs (http://<minikube ip>:<NodePort>) are reachable from the WSL host only, not from a
// Windows browser. kubectl port-forward on the WSL host exposes the Service on localhost, which WSL forwards
// to Windows. The Service is named after the app (deployment.js generateK8sManifests) and listens on port 80.
export const STAGING_SCOPE_LABEL = "reachable from the WSL host only";
const APP = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;

export function portForwardCommand(projectId, appName, localPort = 8080) {
  const id = Number(projectId);
  if (!Number.isInteger(id) || id < 1 || !APP.test(String(appName || ""))) return null;
  return `kubectl --context minikube -n cloudsentinel-p-${id} port-forward service/${appName} ${localPort}:80`;
}

export function stagingAccess({ projectId, appName, stagingUrl }) {
  const command = portForwardCommand(projectId, appName);
  return { url: stagingUrl || null, label: STAGING_SCOPE_LABEL, command, localUrl: command ? "http://localhost:8080" : null };
}
