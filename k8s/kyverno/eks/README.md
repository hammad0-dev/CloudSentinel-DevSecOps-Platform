# Kyverno policies for the shared EKS cluster (Module 10)

> The EKS cluster (Kubernetes 1.36) runs Kyverno 1.20, which no longer runs `ClusterPolicy`. Use the CEL port in
> `../eks-cel/` there. The ClusterPolicy files below are for Kyverno 1.19 (Minikube, `scripts/kyverno-scoped-copy.sh`).

On EKS apply both folders, all in `Enforce` mode, matching `cloudsentinel-p-*`:

```bash
kubectl apply -f k8s/kyverno/policies/ -f k8s/kyverno/eks/
```

| Policy | Rule |
|---|---|
| the five in `../policies/` | non-root, no privileged, explicit non-latest tag, CPU/memory limits, `app`/`owner` labels |
| `restrict-image-registries` | images only from `229032674007.dkr.ecr.ap-south-1.amazonaws.com/cloudsentinel/` |
| `disallow-privilege-escalation` | `allowPrivilegeEscalation: false` on every container |

`restrict-image-registries` is not in `../policies/` because on Minikube it would reject every local image.
`scripts/kyverno-scoped-copy.sh <namespace>` renders all seven as `eks-test-*` copies limited to one namespace
(used for the Minikube test in `docs/evidence/eks/minikube/`).
