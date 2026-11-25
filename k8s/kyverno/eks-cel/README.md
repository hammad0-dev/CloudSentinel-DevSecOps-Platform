# Kyverno policies for EKS (Kubernetes 1.36, Kyverno 1.20) - Module 10

Kyverno 1.19 supports Kubernetes 1.33-1.35 only, so the EKS cluster (1.36) runs Kyverno **1.20.0** (chart 3.10.0,
`k8s/eks/versions.env`). Kyverno 1.20 no longer runs `kyverno.io/v1 ClusterPolicy`, so the seven policies are ported
here one-to-one to `policies.kyverno.io/v1 ValidatingPolicy` (CEL):

| Policy | Rule (same as the ClusterPolicy it replaces) |
|---|---|
| `require-run-as-non-root` | `runAsNonRoot: true` on the Pod (no container overriding it) or on every container; `runAsUser` never 0 |
| `disallow-privileged` | `privileged` unset or false |
| `disallow-latest-tag` | explicit tag (or digest), never `:latest` |
| `require-resource-limits` | CPU and memory limits on every container and init container |
| `require-labels` | `app` and `owner` labels |
| `restrict-image-registries` | images only from `229032674007.dkr.ecr.ap-south-1.amazonaws.com/cloudsentinel/` |
| `disallow-privilege-escalation` | `allowPrivilegeEscalation: false` set explicitly on every container |

All are `validationActions: [Deny]` (Enforce) with background scans (policy reports), match Pods in
`cloudsentinel-p-*` namespaces only, and are generated for Deployments too (`autogen`).

```bash
kubectl apply -f k8s/kyverno/eks-cel/
```

Minikube keeps Kyverno 1.19.2 and the ClusterPolicy files in `../policies/` and `../eks/` (unchanged).
CLI evidence: `docs/evidence/eks/stage4/kyverno-1.20-cli.txt`.
