// Monitoring page filters (Module 11): project selector scopes alerts, the live stream and log search.
export function alertMatches(alert, { severity = "", status = "", project = "" } = {}) {
  return (!severity || alert.severity === severity)
    && (!status || status.split(",").includes(alert.status))
    && (!project || alert.project_id === Number(project));
}

export function alertParams({ severity = "", status = "", project = "" } = {}) {
  return { severity: severity || undefined, status: status || undefined, projectId: project || undefined, limit: 200 };
}

// kyverno logs are cluster-wide, not per project, so they are not offered while a project is selected.
export function logSources(project) {
  return project ? ["backend", "k8s"] : ["backend", "k8s", "kyverno"];
}

export function logParams({ source = "", q = "", project = "", from, to } = {}) {
  const safeSource = source && logSources(project).includes(source) ? source : undefined;
  return { source: safeSource, q: q || undefined, projectId: project || undefined, from, to, limit: 300 };
}
