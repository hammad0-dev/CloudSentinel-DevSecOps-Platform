# Stage 2 evidence - Minikube (2026-11-23, 14:17-14:47 PKT)

Test namespace `cloudsentinel-p-9001` (project id 9001, not a real project). The seven policies were applied as
`eks-test-*` copies scoped to that namespace only; ESO 2.14.0 ran in `cs-eso-test` with the **fake** provider (random
test values, never printed); metrics-server was enabled for the test only. Everything was removed afterwards
(`09-cleanup.txt`); the existing `cloudsentinel-p-24`/`-26` pods kept the same UIDs. No AWS call was made.

| File | Shows |
|---|---|
| `00-preflight.txt` | cluster state before the test |
| `01-kyverno-cli.txt` | `kyverno apply` (CLI 1.19.2, checksum-verified): generated manifests pass 27/27 rules; six violating pods fail on the intended rule |
| `02-admission.txt` | policies Ready, generated Namespace (Pod Security restricted), image built with the generated Dockerfile, generated manifests admitted, three-tier server dry-run admitted. Contains the failed first attempt (see below) |
| `03-external-secrets.txt`, `03b-external-secrets-in-pod.txt` | ESO install, ClusterSecretStore, both ExternalSecrets synced; inside the pod the secret arrives as env var and as mounted file (12-char hashes only) |
| `04-rotation.txt` | new value in the store -> mounted file changed after 30 s, env var unchanged, no redeploy, 0 restarts; `rotate-secret.sh --dry-run`; project 13 refused |
| `05-violations-rejected.txt` | live admission: root, latest, no-limits, privileged, untrusted-registry and privilege-escalation pods denied by Kyverno; Pod Security as a second layer; policy reports 16 pass / 0 fail |
| `06-rbac.txt` | `kubectl auth can-i` table for deployer and viewer (no Secrets for either; no exec; no cross-namespace) |
| `07-hpa-scaling.txt` | HPA 2 -> 4 replicas under load (`SuccessfulRescale`, 129% of the CPU target) |
| `08-capacity.txt` | memory/CPU per namespace and component, used to size the EKS nodes |
| `generated/` | the generated manifests, Dockerfile, scoped policies and the violating pods |

Mistakes made during the run (kept in the files, not hidden):
- The first ClusterSecretStore gave every fake entry `version: v1`; ExternalSecrets without a version then failed with
  "Secret does not exist", so the pods could not start and the first in-pod and rotation checks in `03b`/`04` failed.
  They were re-run after removing the version field; the final results are at the end of each file.
- `06-rbac.txt`: the rows `get pods/log` and `create pods/exec` in the first table read `log`/`exec` as a pod **name**.
  The `--subresource` table at the end supersedes them (deployer may read logs, viewer may not; nobody may exec).
- `07-hpa-scaling.txt`: the per-10 s lines label the `kubectl get hpa` columns wrongly ("min=" is the CPU target,
  "replicas=" is MAXPODS). The real result is the `SuccessfulRescale ... New size: 4` event and the 4 running pods.
