'use strict';
// SRS FR-16.2: CPU and memory usage from metrics-server (metrics.k8s.io), read-only, on the configured context
// (KUBERNETES_MINIKUBE_CONTEXT, default minikube). Node figures are cluster-wide; pod figures are limited to the
// project's CloudSentinel-owned namespace. When the metrics API is not served (metrics-server not running) the
// result says so instead of showing numbers.
const { execFile } = require('node:child_process');
const exec = require('node:util').promisify(execFile);
const { projectNamespace, kubectlJson } = require('./kubectlJson');

const context = () => process.env.KUBERNETES_MINIKUBE_CONTEXT || 'minikube';

async function rawJson(apiPath) {
  const { stdout } = await exec('kubectl', ['--context', context(), '--request-timeout=5s', 'get', '--raw', apiPath], { timeout: 10000, maxBuffer: 4 * 1024 * 1024 });
  return JSON.parse(stdout);
}

// "250m" -> 250, "1" -> 1000, "123456789n" -> 123.456789, "5u" -> 0.005 (millicores)
function cpuMillicores(q) {
  const m = String(q ?? '').trim().match(/^(\d+(?:\.\d+)?)([numk]?)$/);
  if (!m) return null;
  const v = Number(m[1]);
  return { n: v / 1e6, u: v / 1e3, m: v, k: v * 1e6, '': v * 1000 }[m[2]];
}

const MEM = { Ki: 2 ** 10, Mi: 2 ** 20, Gi: 2 ** 30, Ti: 2 ** 40, K: 1e3, k: 1e3, M: 1e6, G: 1e9, T: 1e12, '': 1 };
// "1048576Ki" -> 1024 (MiB)
function memoryMiB(q) {
  const m = String(q ?? '').trim().match(/^(\d+(?:\.\d+)?)(Ki|Mi|Gi|Ti|K|k|M|G|T|)$/);
  return m ? (Number(m[1]) * MEM[m[2]]) / 2 ** 20 : null;
}

const round = (n, d = 0) => (n === null || n === undefined || Number.isNaN(n) ? null : Math.round(n * 10 ** d) / 10 ** d);
const pct = (used, total) => (used === null || !total ? null : round((100 * used) / total, 1));
const unavailable = e => /could not find the requested resource|ServiceUnavailable|service unavailable|NotFound|no metrics|metrics.k8s.io/i.test(`${e?.stderr || ''} ${e?.message || ''}`);

function nodeUsage(metrics, nodes) {
  const alloc = new Map((nodes?.items || []).map(n => [n.metadata?.name, n.status?.allocatable || {}]));
  return (metrics?.items || []).map(m => {
    const a = alloc.get(m.metadata?.name) || {};
    const cpu = cpuMillicores(m.usage?.cpu), mem = memoryMiB(m.usage?.memory);
    const cpuAlloc = cpuMillicores(a.cpu), memAlloc = memoryMiB(a.memory);
    return { name: m.metadata?.name, cpuMillicores: round(cpu), memoryMiB: round(mem), allocatableCpuMillicores: round(cpuAlloc),
      allocatableMemoryMiB: round(memAlloc), cpuPercent: pct(cpu, cpuAlloc), memoryPercent: pct(mem, memAlloc), window: m.window || null };
  });
}

function podUsage(metrics, namespace) {
  return (metrics?.items || []).filter(p => p.metadata?.namespace === namespace).map(p => {
    const containers = p.containers || [];
    const cpu = containers.reduce((s, c) => s + (cpuMillicores(c.usage?.cpu) || 0), 0);
    const mem = containers.reduce((s, c) => s + (memoryMiB(c.usage?.memory) || 0), 0);
    return { namespace, name: p.metadata?.name, cpuMillicores: round(cpu, 1), memoryMiB: round(mem, 1), containers: containers.length };
  });
}

async function projectUsage(pool, userId, id, { run = kubectlJson, raw = rawJson } = {}) {
  const ns = await projectNamespace(pool, userId, id, run);
  if (ns.code) return ns;
  const base = { projectId: ns.projectId, namespace: ns.namespace, context: context(), observedAt: new Date().toISOString(), source: 'metrics-server (metrics.k8s.io/v1beta1)' };
  let nodeMetrics;
  try { nodeMetrics = await raw('/apis/metrics.k8s.io/v1beta1/nodes'); }
  catch (e) {
    return { code: 200, body: { ...base, status: unavailable(e) ? 'metrics_unavailable' : 'not_connected',
      reason: unavailable(e) ? `Not available on this cluster: metrics-server is not running on ${context()} (for Minikube: minikube addons enable metrics-server)` : 'Metrics API could not be read' } };
  }
  try {
    const [nodes, podMetrics] = await Promise.all([run(['get', 'nodes']), raw(`/apis/metrics.k8s.io/v1beta1/namespaces/${ns.namespace}/pods`)]);
    const n = nodeUsage(nodeMetrics, nodes), p = podUsage(podMetrics, ns.namespace);
    const sum = (rows, k) => round(rows.reduce((s, r) => s + (r[k] || 0), 0), 1);
    const cluster = { nodes: n.length, cpuMillicores: sum(n, 'cpuMillicores'), memoryMiB: sum(n, 'memoryMiB'),
      allocatableCpuMillicores: sum(n, 'allocatableCpuMillicores'), allocatableMemoryMiB: sum(n, 'allocatableMemoryMiB') };
    cluster.cpuPercent = pct(cluster.cpuMillicores, cluster.allocatableCpuMillicores);
    cluster.memoryPercent = pct(cluster.memoryMiB, cluster.allocatableMemoryMiB);
    return { code: 200, body: { ...base, status: 'observed', cluster, nodes: n, pods: p,
      project: { pods: p.length, cpuMillicores: sum(p, 'cpuMillicores'), memoryMiB: sum(p, 'memoryMiB') } } };
  } catch (e) {
    return { code: 200, body: { ...base, status: unavailable(e) ? 'metrics_unavailable' : 'not_connected', reason: 'Pod or node metrics could not be read' } };
  }
}

module.exports = { cpuMillicores, memoryMiB, nodeUsage, podUsage, projectUsage };
