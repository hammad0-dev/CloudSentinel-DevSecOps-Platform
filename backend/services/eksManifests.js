'use strict';
// Kubernetes manifests for one component of a project on the shared EKS cluster (Modules 8, 9, 10).
// Reuses services/deployment.js generateK8sManifests in target=eks mode for the Deployment and Service, and adds
// the objects EKS needs: Namespace (Pod Security "restricted"), the component's own IRSA ServiceAccount
// (automountServiceAccountToken: false), ConfigMap, ExternalSecrets and an HPA.
// Every interpolated value is validated first; nothing from the repository is copied into YAML.
const { generateK8sManifests } = require('./deployment');

const ACCOUNT = '229032674007', REGION = 'ap-south-1';
const STORE = 'cloudsentinel-aws';
const fail = m => Object.assign(new Error(m), { safe: true, status: 400 });
const q = v => JSON.stringify(String(v));

function check(re, value, what) { if (!re.test(String(value ?? ''))) throw fail(`Invalid ${what}`); return String(value); }

// component: an entry of classify().components; outputs: terraform output "components"[name];
// database: terraform output "database" (or null); tag: image tag (never "latest").
function generateEksManifests({ projectId, component, outputs, database = null, tag, backendHost = null, refreshInterval = '1m' }) {
  if (!Number.isSafeInteger(projectId) || projectId < 1) throw fail('Invalid project');
  const name = check(/^(app|frontend|backend)$/, component.name, 'component');
  const ns = `cloudsentinel-p-${projectId}`, app = `p${projectId}-${name}`;
  check(/^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/, tag, 'image tag');
  if (tag === 'latest') throw fail('The latest tag is not allowed');
  const repo = check(new RegExp(`^${ACCOUNT}\\.dkr\\.ecr\\.${REGION}\\.amazonaws\\.com/cloudsentinel/p-${projectId}-${name}$`), outputs.repository_url, 'repository URL');
  const role = check(new RegExp(`^arn:aws:iam::${ACCOUNT}:role/cloudsentinel-p${projectId}-${name}-irsa$`), outputs.role_arn, 'role ARN');
  const secretName = check(new RegExp(`^cloudsentinel/p-${projectId}/${name}$`), outputs.secret_name, 'secret name');
  if (outputs.service_account !== app || outputs.namespace !== ns) throw fail('Unexpected service account or namespace');
  if (!/^(30s|1m|5m|15m|1h)$/.test(refreshInterval)) throw fail('Invalid refresh interval');
  const port = component.port;
  const labels = `    app: ${app}\n    owner: project-${projectId}\n    managed-by: cloudsentinel`;
  const docs = [];

  docs.push(`apiVersion: v1
kind: Namespace
metadata:
  name: ${ns}
  labels:
    owner: project-${projectId}
    managed-by: cloudsentinel
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
`);
  docs.push(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${app}
  namespace: ${ns}
  labels:
${labels}
  annotations:
    eks.amazonaws.com/role-arn: ${role}
automountServiceAccountToken: false
`);

  // PORT is set by the Dockerfile (ENV PORT); it is not repeated here (Trivy KSV-01010 treats the key PORT as sensitive).
  const config = {};
  const useDb = component.usesDatabase && database;
  if (useDb) {
    config.DB_HOST = check(/^[a-z0-9][a-z0-9.-]{1,200}\.rds\.amazonaws\.com$/, database.address, 'database address');
    config.DB_PORT = String(check(/^(5432|3306)$/, database.port, 'database port'));
    config.DB_NAME = check(/^[a-z][a-z0-9_]{0,30}$/, database.db_name, 'database name');
  }
  if (backendHost) config.BACKEND_URL = `http://${check(new RegExp(`^p${projectId}-backend$`), backendHost, 'backend service')}.${ns}.svc.cluster.local`;
  docs.push(`apiVersion: v1
kind: ConfigMap
metadata:
  name: ${app}-config
  namespace: ${ns}
  labels:
${labels}
data:${Object.keys(config).length ? '\n' + Object.entries(config).map(([k, v]) => `  ${k}: ${q(v)}`).join('\n') : ' {}'}
`);

  const secrets = [];
  if ((component.secretKeys || []).length) {
    secrets.push(`${app}-secrets`);
    docs.push(`apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: ${app}-secrets
  namespace: ${ns}
  labels:
${labels}
spec:
  refreshInterval: ${refreshInterval}
  secretStoreRef:
    kind: ClusterSecretStore
    name: ${STORE}
  target:
    name: ${app}-secrets
    creationPolicy: Owner
  dataFrom:
    - extract:
        key: ${secretName}
`);
  }
  if (useDb) {
    const arn = check(new RegExp(`^arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:rds!db-[0-9a-f-]{36}-[A-Za-z0-9]{6}$`), database.master_user_secret_arn, 'RDS managed secret ARN');
    const scheme = database.engine === 'mysql' ? 'mysql' : 'postgresql';
    const url = (component.dbEnv || []).includes('DATABASE_URL');
    secrets.push(`${app}-db`);
    docs.push(`apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: ${app}-db
  namespace: ${ns}
  labels:
${labels}
spec:
  refreshInterval: ${refreshInterval}
  secretStoreRef:
    kind: ClusterSecretStore
    name: ${STORE}
  target:
    name: ${app}-db
    creationPolicy: Owner${url ? `
    template:
      engineVersion: v2
      mergePolicy: Merge
      data:
        DATABASE_URL: "${scheme}://{{ .DB_USER }}:{{ .DB_PASSWORD | urlquery }}@${config.DB_HOST}:${config.DB_PORT}/${config.DB_NAME}${scheme === 'postgresql' ? '?sslmode=require' : ''}"` : ''}
  data:
    - secretKey: DB_USER
      remoteRef:
        key: ${arn}
        property: username
    - secretKey: DB_PASSWORD
      remoteRef:
        key: ${arn}
        property: password
`);
  }

  const { deployment, service } = generateK8sManifests(app, `${repo}:${tag}`, port, component.stack, ns, {
    target: 'eks', serviceAccountName: app, secrets, serviceType: component.public ? 'LoadBalancer' : 'ClusterIP',
  });
  docs.push(deployment, service);
  docs.push(`apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ${app}
  namespace: ${ns}
  labels:
${labels}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ${app}
  minReplicas: 2
  maxReplicas: 4
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
`);
  return { name: app, namespace: ns, yaml: docs.map(d => d.trimEnd()).join('\n---\n') + '\n', secrets };
}

module.exports = { generateEksManifests, STORE };
