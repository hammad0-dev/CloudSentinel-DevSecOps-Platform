# Kyverno policy enforcement (Module 10, FE-1)

CloudSentinel enforces Pod security in project namespaces (`cloudsentinel-p-*`) with Kyverno
ClusterPolicies in `Enforce` mode. System namespaces (`kube-system`, `kyverno`, ...) are not matched.

| Policy | Rule(s) |
|---|---|
| `require-run-as-non-root` | `runAsNonRoot: true` (pod or every container); `runAsUser` must not be 0 |
| `disallow-privileged` | `privileged` must be unset or `false` |
| `disallow-latest-tag` | image must have an explicit tag that is not `latest` |
| `require-resource-limits` | every container sets CPU and memory limits |
| `require-labels` | Pod labels `app` and `owner` are set |

Kyverno auto-generates matching rules for Deployments, StatefulSets, Jobs etc., so a violating
Deployment is denied at admission, including on `kubectl apply --dry-run=server` (used by the deploy stage, FE-4).

## Install

Helm is not installed on the dev host, so use the official manifest (pinned version):

```bash
kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.19.2/install.yaml
kubectl -n kyverno rollout status deploy/kyverno-admission-controller --timeout=5m
```

With Helm instead:

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm search repo kyverno/kyverno --versions | grep 'v1.19.2'   # pick the chart version for app v1.19.2
helm install kyverno kyverno/kyverno -n kyverno --create-namespace --version <chart-version>
```

## Apply policies

```bash
kubectl apply -f k8s/kyverno/policies/
kubectl get clusterpolicy        # READY should be True for all five
```

## Demo (FE-5)

```bash
bash k8s/demo/run-demo.sh
```

## Uninstall

```bash
kubectl delete -f k8s/kyverno/policies/
kubectl delete -f https://github.com/kyverno/kyverno/releases/download/v1.19.2/install.yaml
```
