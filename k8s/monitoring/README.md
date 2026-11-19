# Module 11 — Cloud-native monitoring and log aggregation

Scope follows limitation **LI-4**: cloud-native monitoring and log aggregation only. This is not a SOC/SIEM.

## Covered log sources (FE-1, FE-4)

| `source` label | What | How it reaches Loki |
|---|---|---|
| `backend` | CloudSentinel API structured JSON events (`ts, level, source, event, projectId, userId, ip, detail`): HTTP requests, login failures, webhook signature failures, pipeline stage start/finish/fail, deployment results | Promtail static job tailing `/var/log/cloudsentinel/app.log` (hostPath), **or** the backend push client (`LOKI_PUSH_URL`) when the API runs off-cluster. Use one, not both. |
| `k8s` | Pod/container logs from every project namespace `cloudsentinel-p-<id>` (labels `namespace`, `pod`, `container`, `project_id`) | Promtail DaemonSet (`kubernetes-pods` job) |
| `kyverno` | Kyverno admission-controller logs (`kyverno` namespace) | Promtail DaemonSet, same job, relabelled |

Kubernetes signals for detection (pod restart loops, Kyverno `PolicyViolation` events) are read by the
backend with `kubectl` every 30 s (`services/threatDetection.js`); set `K8S_SIGNALS=off` if no cluster access.

## Out of scope (LI-4)

AWS-native sources — **CloudTrail, GuardDuty**, VPC Flow Logs, CloudWatch Logs, Security Hub — are not
collected. They need paid AWS services/ingestion and are excluded by LI-4 for cost. No SOC workflows
(case management, threat intel enrichment, on-call paging) are provided.

## Files

- `loki-values.yaml` — Loki single binary, filesystem storage, 7-day retention, 24 h max query range.
- `promtail-values.yaml` — Promtail with the three labelled sources above.
- `kube-prometheus-stack-values.yaml` — Prometheus, Alertmanager, scrape of the backend `/metrics`, and
  three alert rules: `PodCrashLooping`, `DeploymentUnavailable`, `PipelineRunsFailing`. Grafana is disabled.

**Grafana is off by default.** On the 6 GB Minikube node Grafana was OOMKilled. Metrics are viewed in the
Prometheus UI; logs and alerts are in the CloudSentinel Monitoring page (`/api/monitoring/*`). To enable it on
a bigger node, uncomment the `grafana:` block in the values file (it needs about a 384Mi memory limit).

## Install

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
kubectl create namespace monitoring
helm upgrade --install loki grafana/loki -n monitoring -f k8s/monitoring/loki-values.yaml
helm upgrade --install promtail grafana/promtail -n monitoring -f k8s/monitoring/promtail-values.yaml
helm upgrade --install kps prometheus-community/kube-prometheus-stack -n monitoring -f k8s/monitoring/kube-prometheus-stack-values.yaml
# Backend -> Loki (LOKI_URL=http://localhost:3100 in backend/.env)
kubectl -n monitoring port-forward svc/loki-gateway 3100:80
# Prometheus UI (targets, metrics, alert rules): http://localhost:9090
kubectl -n monitoring port-forward svc/kps-kube-prometheus-stack-prometheus 9090:9090
```

Before installing, check the backend scrape target in `kube-prometheus-stack-values.yaml`
(`host.minikube.internal:3000` by default; use `host.docker.internal:3000` for kind/Docker Desktop) and, for the Promtail file job, make sure the node path
`/var/log/cloudsentinel` holds `app.log` (run the API with `APP_LOG_FILE=/var/log/cloudsentinel/app.log`).

## Backend settings (`backend/.env`)

| Variable | Purpose |
|---|---|
| `LOKI_URL` | Loki base URL for `/api/monitoring/logs` and alert context |
| `LOKI_PUSH_URL` | Optional: push backend events straight to Loki. Either the base URL (`http://localhost:3100`) or the full push URL (`http://localhost:3100/loki/api/v1/push`). Failed pushes log a `loki_push_failed` warn, at most once per minute. |
| `MONITORING_ADMIN_EMAILS` | Comma list of users who see platform-wide alerts/logs; others see only their projects |
| `METRICS_TOKEN` | Optional bearer token required on `/metrics` |
| `K8S_SIGNALS` | `off` disables kubectl-based detection rules |
| `APP_LOG_FILE` | Log file path (default `backend/logs/app.log`; `off` disables) |
