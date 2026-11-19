// Module 11 FE-2: threshold rules over structured events (securityLog) and Kubernetes signals.
const { execFile } = require("child_process");

const MIN = 60 * 1000;
const PROJECT_NS = /^cloudsentinel-p-(\d+)$/;
const NAMESPACE_FILTER = new RegExp(process.env.MONITOR_NAMESPACE_REGEX || "^(cloudsentinel-p-\\d+|kyverno)$");

function inWindow(ts, now, windowMs) {
  const t = typeof ts === "number" ? ts : Date.parse(ts);
  return Number.isFinite(t) && t >= now - windowMs && t <= now;
}

function countBy(items, keyFn) {
  const groups = new Map();
  for (const item of items) {
    const key = keyFn(item);
    if (key === null || key === undefined || key === "") continue;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  return groups;
}

function projectFromNamespace(ns) {
  const m = PROJECT_NS.exec(ns || "");
  return m ? Number(m[1]) : null;
}

const RULES = [
  {
    name: "failed_login_burst",
    severity: "HIGH",
    source: "backend",
    threshold: 5,
    windowMs: 5 * MIN,
    description: ">=5 failed logins for one account or one IP within 5 minutes",
    evaluate({ events, now }) {
      const failed = events.filter((e) => e.event === "auth_login_failed" && inWindow(e.ts, now, this.windowMs));
      const out = [];
      for (const [dim, keyFn] of [["account", (e) => e.detail?.account], ["ip", (e) => e.ip]]) {
        for (const [value, hits] of countBy(failed, keyFn)) {
          if (hits.length >= this.threshold) {
            out.push({ key: `${dim}:${value}`, details: { [dim]: value, count: hits.length, firstSeen: hits[0].ts, lastSeen: hits[hits.length - 1].ts } });
          }
        }
      }
      return out;
    },
  },
  {
    name: "webhook_signature_burst",
    severity: "HIGH",
    source: "backend",
    threshold: 3,
    windowMs: 5 * MIN,
    description: ">=3 webhook invalid-signature events within 5 minutes",
    evaluate({ events, now }) {
      const hits = events.filter((e) => e.event === "webhook_signature_invalid" && inWindow(e.ts, now, this.windowMs));
      if (hits.length < this.threshold) return [];
      const ips = [...new Set(hits.map((e) => e.ip).filter(Boolean))];
      const repositories = [...new Set(hits.map((e) => e.detail?.repository).filter(Boolean))];
      const projectIds = [...new Set(hits.map((e) => e.projectId).filter((p) => p !== null && p !== undefined))];
      return [{
        key: "webhook",
        projectId: projectIds.length === 1 ? projectIds[0] : null,
        details: { count: hits.length, ips, repositories, firstSeen: hits[0].ts, lastSeen: hits[hits.length - 1].ts },
      }];
    },
  },
  {
    name: "pipeline_trigger_anomaly",
    severity: "MEDIUM",
    source: "backend",
    threshold: 6, // more than 5 runs
    windowMs: 10 * MIN,
    description: ">5 pipeline runs for one project within 10 minutes",
    evaluate({ events, now }) {
      const starts = events.filter((e) => e.event === "pipeline_started" && inWindow(e.ts, now, this.windowMs));
      const out = [];
      for (const [projectId, hits] of countBy(starts, (e) => e.projectId)) {
        if (hits.length >= this.threshold) {
          const last = hits[hits.length - 1];
          out.push({
            key: `project:${projectId}`,
            projectId,
            details: { count: hits.length, pipelineExecutionId: last.detail?.executionId ?? null, executionIds: hits.map((e) => e.detail?.executionId).filter(Boolean), firstSeen: hits[0].ts, lastSeen: last.ts },
          });
        }
      }
      return out;
    },
  },
  {
    name: "k8s_pod_restart_loop",
    severity: "HIGH",
    source: "k8s",
    threshold: 5,
    windowMs: 10 * MIN,
    description: "Container in CrashLoopBackOff, or >=5 restarts with a crash in the last 10 minutes",
    evaluate({ k8s, now }) {
      const out = [];
      for (const pod of k8s?.pods || []) {
        const ns = pod.metadata?.namespace;
        if (!NAMESPACE_FILTER.test(ns || "")) continue;
        for (const cs of pod.status?.containerStatuses || []) {
          const reason = cs.state?.waiting?.reason;
          const restarts = Number(cs.restartCount || 0);
          const recentCrash = inWindow(cs.lastState?.terminated?.finishedAt, now, this.windowMs);
          if (reason === "CrashLoopBackOff" || (restarts >= this.threshold && recentCrash)) {
            out.push({
              key: `${ns}/${pod.metadata?.name}/${cs.name}`,
              projectId: projectFromNamespace(ns),
              details: { namespace: ns, pod: pod.metadata?.name, container: cs.name, restarts, reason: reason || null },
            });
          }
        }
      }
      return out;
    },
  },
  {
    name: "kyverno_denied_spike",
    severity: "MEDIUM",
    source: "kyverno",
    threshold: 5,
    windowMs: 5 * MIN,
    description: ">=5 Kyverno policy-denied/violation events in one namespace within 5 minutes",
    evaluate({ k8s, now }) {
      const recent = (k8s?.kyvernoEvents || []).filter((e) =>
        e.reason === "PolicyViolation" &&
        inWindow(e.lastTimestamp || e.eventTime || e.metadata?.creationTimestamp, now, this.windowMs));
      const out = [];
      for (const [ns, hits] of countBy(recent, (e) => e.involvedObject?.namespace || e.metadata?.namespace)) {
        const count = hits.reduce((sum, e) => sum + Math.max(1, Number(e.count || 1)), 0);
        if (count >= this.threshold) {
          const policies = [...new Set(hits.map((e) => e.involvedObject?.name).filter(Boolean))];
          out.push({ key: `ns:${ns}`, projectId: projectFromNamespace(ns), details: { namespace: ns, count, policies, sample: String(hits[0].message || "").slice(0, 300) } });
        }
      }
      return out;
    },
  },
];

function evaluateRules({ events = [], k8s = null, now = Date.now(), rules = RULES } = {}) {
  const detections = [];
  for (const rule of rules) {
    for (const hit of rule.evaluate({ events, k8s, now })) {
      detections.push({
        rule: rule.name,
        severity: rule.severity,
        source: rule.source,
        projectId: hit.projectId ?? null,
        details: { ...hit.details, key: hit.key, threshold: rule.threshold, windowMs: rule.windowMs, description: rule.description },
      });
    }
  }
  return detections;
}

function kubectlJson(args, { run = execFile, timeoutMs = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    run("kubectl", args, { timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024 }, (err, stdout) => {
      if (err) return reject(err);
      try { resolve(JSON.parse(stdout)); } catch (e) { reject(e); }
    });
  });
}

async function collectK8sSignals(opts = {}) {
  const [pods, events] = await Promise.all([
    kubectlJson(["get", "pods", "-A", "-o", "json"], opts),
    kubectlJson(["get", "events", "-A", "--field-selector", "reason=PolicyViolation", "-o", "json"], opts),
  ]);
  return { pods: pods.items || [], kyvernoEvents: events.items || [] };
}

function start({ intervalMs = 30000, getEvents, createAlert, collectK8s = collectK8sSignals, onError = () => {} } = {}) {
  const k8sEnabled = process.env.K8S_SIGNALS !== "off";
  let running = false;
  const tick = async () => {
    if (running) return;
    running = true;
    try {
      let k8s = null;
      if (k8sEnabled) {
        try { k8s = await collectK8s(); } catch (e) { onError(e, "k8s"); }
      }
      for (const detection of evaluateRules({ events: getEvents(), k8s })) {
        try { await createAlert(detection); } catch (e) { onError(e, "alert"); }
      }
    } finally {
      running = false;
    }
  };
  const timer = setInterval(tick, intervalMs);
  timer.unref?.();
  return { tick, stop: () => clearInterval(timer) };
}

module.exports = { RULES, evaluateRules, collectK8sSignals, start, projectFromNamespace };
