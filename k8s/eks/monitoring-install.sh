#!/usr/bin/env bash
# Install the pinned, reduced monitoring stack on EKS (Module 11): kube-prometheus-stack (Prometheus, Alertmanager,
# Grafana ClusterIP), Loki and Grafana Alloy. Usage: k8s/eks/monitoring-install.sh <kube-context>
# The Grafana admin password is generated here from random bytes into the Secret monitoring/grafana-admin and is
# never printed. Read it into your own shell with:
#   GRAFANA_PW=$(kubectl -n monitoring get secret grafana-admin -o jsonpath='{.data.admin-password}' | base64 -d)
set -euo pipefail
ctx="${1:?kube context}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "$root/k8s/eks/versions.env"
K=(kubectl --context "$ctx"); H=(helm --kube-context "$ctx")
for r in "prometheus-community https://prometheus-community.github.io/helm-charts" "grafana https://grafana.github.io/helm-charts"; do
  set -- $r; "${H[@]}" repo add "$1" "$2" >/dev/null 2>&1 || true
done
"${H[@]}" repo update prometheus-community grafana >/dev/null

"${K[@]}" create namespace monitoring --dry-run=client -o yaml | "${K[@]}" apply -f -
if ! "${K[@]}" -n monitoring get secret grafana-admin >/dev/null 2>&1; then
  umask 077; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32 > "$tmp/pw"
  printf admin > "$tmp/user"
  "${K[@]}" -n monitoring create secret generic grafana-admin --from-file=admin-user="$tmp/user" --from-file=admin-password="$tmp/pw" >/dev/null
  echo "secret monitoring/grafana-admin created (value not shown)"
fi

"${H[@]}" upgrade --install loki grafana/loki -n monitoring --version "$LOKI_CHART" -f "$root/k8s/eks/monitoring/loki-values.yaml" --wait --timeout 10m
"${H[@]}" upgrade --install kps prometheus-community/kube-prometheus-stack -n monitoring --version "$KPS_CHART" -f "$root/k8s/eks/monitoring/kps-values.yaml" --wait --timeout 15m
"${H[@]}" upgrade --install alloy grafana/alloy -n monitoring --version "$ALLOY_CHART" -f "$root/k8s/eks/monitoring/alloy-values.yaml" --wait --timeout 10m
"${K[@]}" -n monitoring get pods
