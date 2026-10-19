# Read-only Kubernetes dashboard

GET /api/kubernetes/projects/:projectId/inventory uses existing JWT authentication
and projects.user_id ownership, before querying successful deployment_history
app_name records. No deployment record means Not deployed.

The current kubeconfig context and cluster must both match
KUBERNETES_MINIKUBE_CONTEXT (default minikube). Subsequent commands explicitly pin
that context; no use-context writes. Kubeconfig is never serialized to the client.
Namespace mappings come from actual cloudsentinel.io/project-id and
app.kubernetes.io/managed-by=cloudsentinel labels, not generated namespace names.
Only recorded successful applications with managed-by=cloudsentinel are displayed.
All reads use execFile, 8-second process and 5-second API deadlines, 2 MiB output
limits. At most 20 project namespaces are accepted. Native failures are withheld.

Read permissions: namespaces list filtered by ownership labels; deployments and
pods list in those namespaces. No writes, scans, compliance persistence or exec.
The legacy summary endpoint now requires projectId and returns inventory;
legacy POST /scan returns 410. Its fabricated findings/compliance fallback and
unscoped reads have been removed. No historical database rows are changed.

Rules inspect regular/init container specs: explicit UID 0 and privileged=true
are HIGH configuration risks, absent non-root enforcement is INFO/unknown,
missing CPU/memory limits MEDIUM, mutable non-digest images and missing main
container readiness/liveness probes LOW. No claim of actual process UID or full
security assessment. Zero observations is not a compliance certificate.

AWS EKS is not configured. Data is an on-selection snapshot, not monitoring.
The backend process must have the existing server-side kubeconfig and kubectl.
No credentials belong in frontend variables. No migration needed.

Activation (not executed): in the backend's owning terminal/session, preserve its
existing private environment and approved Trivy/commissioning settings, stop only
the backend with Ctrl-C, then:

    cd /home/hammad/CloudSentinel/backend
    DAST_ACTIVE_ENABLED=false npm run start

In the frontend's terminal (Vite HMR normally reloads source automatically):

    cd /home/hammad/CloudSentinel/frontend
    npm run dev

For existing production frontend hosting, use npm run build from that directory
and deploy dist through its normal hosting process. Never launch a second backend
on occupied port 3000; no restart is performed by this implementation.
