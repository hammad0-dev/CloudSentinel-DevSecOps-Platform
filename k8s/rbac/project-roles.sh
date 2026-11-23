#!/usr/bin/env bash
# Module 10 RBAC for one project namespace: two Roles and their bindings.
#   deployer: manages Deployments, Services, ConfigMaps, HPAs; reads pods, logs, events and ExternalSecret status.
#             NO access to Secrets, pods/exec, RBAC or ExternalSecret creation (an ExternalSecret could copy any
#             cloudsentinel/* secret into the namespace through the shared store, so only the platform creates them).
#   viewer:   read only (get/list/watch); no Secrets, no logs of other namespaces, no exec.
# Usage: k8s/rbac/project-roles.sh cloudsentinel-p-42 [deployer-subject-sa] [viewer-subject-sa] | kubectl apply -f -
# Subjects default to service accounts cs-deployer and cs-viewer in the namespace (for kubectl auth can-i --as).
set -euo pipefail
ns="${1:?namespace}"; dsa="${2:-cs-deployer}"; vsa="${3:-cs-viewer}"
[[ "$ns" =~ ^cloudsentinel-p-[1-9][0-9]*$ && "$dsa" =~ ^[a-z0-9-]{1,40}$ && "$vsa" =~ ^[a-z0-9-]{1,40}$ ]] || { echo "bad arguments" >&2; exit 1; }
cat <<EOF
apiVersion: v1
kind: ServiceAccount
metadata: {name: $dsa, namespace: $ns, labels: {managed-by: cloudsentinel}}
automountServiceAccountToken: false
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: $vsa, namespace: $ns, labels: {managed-by: cloudsentinel}}
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: cloudsentinel-deployer, namespace: $ns, labels: {managed-by: cloudsentinel}}
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["apps"]
    resources: ["replicasets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["services", "configmaps"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: [""]
    resources: ["pods", "pods/log", "events", "serviceaccounts"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["autoscaling"]
    resources: ["horizontalpodautoscalers"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["external-secrets.io"]
    resources: ["externalsecrets"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: cloudsentinel-viewer, namespace: $ns, labels: {managed-by: cloudsentinel}}
rules:
  - apiGroups: ["", "apps", "autoscaling", "external-secrets.io"]
    resources: ["pods", "services", "configmaps", "events", "serviceaccounts", "deployments", "replicasets", "horizontalpodautoscalers", "externalsecrets"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: cloudsentinel-deployer, namespace: $ns, labels: {managed-by: cloudsentinel}}
subjects: [{kind: ServiceAccount, name: $dsa, namespace: $ns}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: cloudsentinel-deployer}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: cloudsentinel-viewer, namespace: $ns, labels: {managed-by: cloudsentinel}}
subjects: [{kind: ServiceAccount, name: $vsa, namespace: $ns}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: cloudsentinel-viewer}
EOF
