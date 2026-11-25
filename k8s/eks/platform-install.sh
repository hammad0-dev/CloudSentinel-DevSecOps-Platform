#!/usr/bin/env bash
# Install the pinned platform components on the shared EKS cluster (Modules 9/10):
#   External Secrets Operator (IRSA) + ClusterSecretStore, Kyverno + the seven CEL policies (Enforce).
# Usage: k8s/eks/platform-install.sh <kube-context> <eso-role-arn>
# Monitoring and Falco are installed separately (k8s/eks/monitoring-install.sh, Stage 6).
set -euo pipefail
ctx="${1:?kube context}" role="${2:?ESO IRSA role ARN}"
[[ "$role" =~ ^arn:aws:iam::229032674007:role/cloudsentinel-eso-irsa$ ]] || { echo "unexpected ESO role" >&2; exit 2; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$root/k8s/eks/versions.env"
K=(kubectl --context "$ctx"); H=(helm --kube-context "$ctx")

"${H[@]}" repo add external-secrets https://charts.external-secrets.io >/dev/null 2>&1 || true
"${H[@]}" repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null 2>&1 || true
"${H[@]}" repo update external-secrets kyverno >/dev/null

"${H[@]}" upgrade --install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace \
  --version "$ESO_CHART" --wait --timeout 10m \
  --set installCRDs=true --set serviceAccount.name=external-secrets \
  --set-string "serviceAccount.annotations.eks\.amazonaws\.com/role-arn=$role" \
  --set resources.requests.cpu=50m --set resources.requests.memory=64Mi --set resources.limits.memory=256Mi
"${K[@]}" apply -f "$root/k8s/eks/cluster-secret-store.yaml"

"${H[@]}" upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace --version "$KYVERNO_CHART" \
  --wait --timeout 10m \
  --set admissionController.replicas=1 --set backgroundController.replicas=1 \
  --set cleanupController.replicas=1 --set reportsController.replicas=1
"${K[@]}" apply -f "$root/k8s/kyverno/eks-cel/"
"${K[@]}" get validatingpolicies.policies.kyverno.io
"${K[@]}" get clustersecretstore cloudsentinel-aws
