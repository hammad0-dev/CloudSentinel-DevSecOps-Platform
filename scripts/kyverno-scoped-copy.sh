#!/usr/bin/env bash
# Print the seven CloudSentinel Kyverno policies (k8s/kyverno/policies + k8s/kyverno/eks) as copies named
# eks-test-<name> that match ONE namespace only, so they can be tested on a shared cluster (Minikube) without
# affecting any other namespace. Usage: scripts/kyverno-scoped-copy.sh cloudsentinel-p-9001 | kubectl apply -f -
set -euo pipefail
ns="${1:?namespace}"
[[ "$ns" =~ ^cloudsentinel-p-[1-9][0-9]*$ ]] || { echo "namespace must be cloudsentinel-p-<n>" >&2; exit 1; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
first=1
for f in "$root"/k8s/kyverno/policies/*.yaml "$root"/k8s/kyverno/eks/*.yaml; do
  [[ $first -eq 1 ]] || echo '---'
  first=0
  sed -E -e "s/^  name: (.*)$/  name: eks-test-\1/" -e "s/namespaces: \[\"cloudsentinel-p-\*\"\]/namespaces: [\"$ns\"]/" "$f" | grep -v '^#'
done
