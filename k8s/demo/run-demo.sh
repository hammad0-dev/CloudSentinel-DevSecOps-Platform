#!/usr/bin/env bash
# Module 10 FE-5 demo: Kyverno blocks a root/privileged Pod and admits a compliant one.
# Prereqs: Kyverno installed and k8s/kyverno/policies applied (see k8s/kyverno/README.md).
# Usage: bash k8s/demo/run-demo.sh        (KEEP=1 to keep the demo namespace)
set -uo pipefail
cd "$(dirname "$0")"
NS=cloudsentinel-p-demo
step(){ printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "Preflight"
if ! kubectl get crd clusterpolicies.kyverno.io >/dev/null 2>&1; then
  echo "Kyverno is not installed. See k8s/kyverno/README.md"; exit 1
fi
kubectl get clusterpolicy require-run-as-non-root disallow-privileged disallow-latest-tag require-resource-limits require-labels || {
  echo "Apply the policies first: kubectl apply -f k8s/kyverno/policies/"; exit 1; }
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl delete pod -n "$NS" violation-root-pod compliant-pod --ignore-not-found --wait=true >/dev/null

step "1. Apply a root, privileged, :latest Pod with no limits or owner label (expect: BLOCKED)"
if out=$(kubectl apply -f violation-root-pod.yaml 2>&1); then
  echo "$out"; echo "UNEXPECTED: violating Pod was admitted. Are the policies in Enforce mode?"; result=1
else
  echo "$out"; echo; echo "RESULT: blocked by Kyverno (as expected)"; result=0
fi

step "2. Apply the compliant Pod (expect: ADMITTED)"
if kubectl apply -f compliant-pod.yaml; then
  kubectl wait -n "$NS" --for=condition=Ready pod/compliant-pod --timeout=120s && \
    kubectl exec -n "$NS" compliant-pod -- id
  echo "RESULT: admitted (as expected)"
else
  echo "UNEXPECTED: compliant Pod was denied"; result=1
fi

step "3. Kyverno evidence"
kubectl get events -A --field-selector reason=PolicyViolation --sort-by=.lastTimestamp 2>/dev/null | grep "$NS" | tail -5 || true
kubectl get policyreport -n "$NS" 2>/dev/null || true

if [ "${KEEP:-0}" != "1" ]; then step "Cleanup"; kubectl delete namespace "$NS" --wait=false; fi
exit "$result"
