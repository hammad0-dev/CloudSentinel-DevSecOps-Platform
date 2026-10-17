"use strict";

const crypto = require("crypto");

const RESERVED = new Set(["minikube", "bridge", "host", "none"]);
const NAME = /^[a-z0-9][a-z0-9_.-]{0,62}$/;
const ID = /^[a-f0-9]{12,64}$/i;
const POOL = { base: [172, 30, 0, 0], prefix: 16, size: 28 };

class NetworkProvisionError extends Error {
  constructor(code, message, meta = {}) { super(message); this.name = "NetworkProvisionError"; this.code = code; Object.assign(this, meta); }
}
const fail = (code, message, meta) => { throw new NetworkProvisionError(code, message, meta); };

function safePart(value, field) { const s = String(value || ""); if (!NAME.test(s)) fail("INVALID_ID", `invalid ${field}`); return s; }
function identity(scanIdentity) {
  if (!scanIdentity || typeof scanIdentity !== "object") fail("INVALID_IDENTITY", "scan identity is required");
  const project = safePart(scanIdentity.projectId, "project");
  const execution = safePart(scanIdentity.executionId, "execution");
  const scan = safePart(scanIdentity.scanId, "scan");
  const lifecycle = crypto.randomUUID();
  const hash = crypto.createHash("sha256").update(`${project}|${execution}|${scan}|${lifecycle}`).digest("hex").slice(0, 12);
  return Object.freeze({ projectId: project, executionId: execution, scanId: scan, lifecycleUuid: lifecycle, hash });
}
function labels(i, role) { return {
  "cloudsentinel.owner": `cloudsentinel-${i.hash}`,
  "cloudsentinel.project": i.projectId, "cloudsentinel.execution": i.executionId,
  "cloudsentinel.scan": i.scanId, "cloudsentinel.lifecycle": i.lifecycleUuid,
  "cloudsentinel.role": role, "cloudsentinel.contract": "1.1",
}; }
function names(i, role) {
  for (const key of ['projectId','executionId','scanId','hash']) safePart(i[key],key);
  if (!['scanner','fixture'].includes(role)) fail('INVALID_ROLE','unsupported network role');
  return require('./acceptanceNames').bounded(`cs-net-${i.projectId}-${i.executionId}-${i.scanId}-${i.hash}-${role}`, 'cs-net', [i.projectId,i.executionId,i.scanId,i.hash,role], role);
}
function ipToNumber(a) { return a.reduce((n, x) => (n * 256) + Number(x), 0); }
function ipv4Range(cidr) {
  if (typeof cidr !== "string") fail("EVIDENCE_INCOMPLETE", "invalid IPv4 allocation evidence");
  const match = /^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/.exec(cidr);
  if (!match) fail("EVIDENCE_INCOMPLETE", "invalid IPv4 allocation evidence");
  const octets = match[1].split(".").map(Number);
  const prefix = match[2] === undefined ? 32 : Number(match[2]);
  if (octets.some(x => x > 255) || prefix > 32) fail("EVIDENCE_INCOMPLETE", "invalid IPv4 allocation evidence");
  const size = 2 ** (32 - prefix);
  const start = Math.floor(ipToNumber(octets) / size) * size;
  return { start, end: start + size - 1 };
}
function numberToIp(value) {
  return [24, 16, 8, 0].map(shift => (value >>> shift) & 255).join(".");
}
function subnetFor(i, used = []) {
  if (!i || typeof i.hash !== "string" || !/^[a-f0-9]{6,}$/i.test(i.hash)) fail("INVALID_IDENTITY", "allocation hash must contain at least six hexadecimal digits");
  const blockSize = 2 ** (32 - POOL.size);
  const blockCount = 2 ** (POOL.size - POOL.prefix);
  const offset = parseInt(i.hash.slice(0, 6), 16) % blockCount;
  const base = ipToNumber(POOL.base) + offset * blockSize;
  const end = base + blockSize - 1;
  if (!Array.isArray(used)) fail("EVIDENCE_INCOMPLETE", "IPv4 allocation evidence is required");
  for (const cidr of used) {
    const range = ipv4Range(cidr);
    if (base <= range.end && range.start <= end) fail("SUBNET_CONFLICT", "candidate subnet overlaps observed allocation");
  }
  // Derive both values from the same aligned block, including its fourth octet.
  return { subnet: `${numberToIp(base)}/${POOL.size}`, gateway: numberToIp(base + 1) };
}
function parseNetwork(raw) {
  let value; try { value = typeof raw === "string" ? JSON.parse(raw) : raw; } catch (_) { fail("MALFORMED_OUTPUT", "network inspect is not JSON"); }
  if (Array.isArray(value)) value = value[0];
  if (!value || !ID.test(String(value.Id || "")) || typeof value.Name !== "string" || !NAME.test(value.Name.replace(/^\//, ""))) fail("MALFORMED_OUTPUT", "network identity is incomplete");
  const labelsValue = value.Labels;
  const config = value.IPAM?.Config;
  if (!labelsValue || typeof labelsValue !== "object" || !Array.isArray(config) || !config[0]?.Subnet || !config[0]?.Gateway) fail("MALFORMED_OUTPUT", "network security fields are incomplete");
  // Inspect evidence must itself describe a usable IPv4 gateway in its CIDR.
  const subnet = config[0].Subnet;
  const gateway = config[0].Gateway;
  let range, gatewayRange;
  try { range = ipv4Range(subnet); gatewayRange = ipv4Range(gateway); }
  catch (_) { fail("MALFORMED_OUTPUT", "network IPAM is not valid IPv4"); }
  if (!subnet.includes("/") || gateway.includes("/") ||
      gatewayRange.start <= range.start || gatewayRange.start >= range.end) {
    fail("MALFORMED_OUTPUT", "network gateway is not a usable address in its subnet");
  }
  const ipv6 = value.EnableIPv6 === true || value.Options?.["com.docker.network.enable_ipv6"] === "true";
  const containers = value.Containers && typeof value.Containers === "object" ? Object.keys(value.Containers) : [];
  return { id: value.Id, name: value.Name.replace(/^\//, ""), labels: labelsValue, driver: value.Driver, internal: value.Internal === true, ipv6, subnet: config[0].Subnet, gateway: config[0].Gateway, containerIds: containers };
}
function verifyNetwork(reference, observation) {
  if (!reference || !observation || reference.id !== observation.id) return { verified: false, reasons: ["ID_MISMATCH"] };
  const reasons = [];
  if (!reference.name || RESERVED.has(reference.name)) reasons.push("RESERVED_NETWORK");
  if (reference.labels["cloudsentinel.scan"] !== reference.scanIdentity.scanId || observation.labels["cloudsentinel.scan"] !== reference.scanIdentity.scanId) reasons.push("OWNERSHIP_MISMATCH");
  if (observation.labels["cloudsentinel.owner"] !== reference.labels["cloudsentinel.owner"]) reasons.push("OWNER_MISMATCH");
  if (observation.ipv6 !== false || observation.internal !== true || observation.subnet !== reference.subnet || observation.gateway !== reference.gateway) reasons.push("ISOLATION_MISMATCH");
  return { verified: reasons.length === 0, reasons };
}

class OwnedDockerNetworks {
  constructor({ adapter, observe = async () => ({ usedSubnets: [], hostRoutes: [] }) } = {}) {
    if (!adapter || typeof adapter.run !== "function") fail("INVALID_ADAPTER", "Docker adapter is required");
    this.adapter = adapter; this.observe = observe; this.active = new Map();
  }
  async create(scanIdentity, { roles = ["scanner", "fixture"], beforeCreate } = {}) {
    if(beforeCreate!==undefined&&typeof beforeCreate!=='function')fail('INVALID_IDENTITY','invalid provisioning guard');
    const i = identity(scanIdentity);
    if (!Array.isArray(roles) || !roles.length || new Set(roles).size !== roles.length) fail('INVALID_ROLE','duplicate or missing roles');
    const plannedNames = roles.map(role=>names(i,role));
    if (new Set(plannedNames).size !== plannedNames.length) fail('INVALID_ID','generated name collision');
    if (this.active.has(i.scanId)) fail("DUPLICATE_SCAN", "scan identity is already active");
    this.active.set(i.scanId, { identity: i, resources: [] });
    const created = [];
    try {
      const env = await this.observe();
      if (!env || env.complete === false || !Array.isArray(env.usedSubnets) || !Array.isArray(env.hostRoutes)) fail("EVIDENCE_INCOMPLETE", "subnet and route observations are required");
      if (env.existingNames !== undefined && (!Array.isArray(env.existingNames) || env.existingNames.some(n=>typeof n!=='string'))) fail('EVIDENCE_INCOMPLETE','invalid network name inventory');
      if (plannedNames.some(name=>env.existingNames?.includes(name))) fail('NAME_CONFLICT','network name already exists');
      const allocated = [];
      for (const role of roles) {
        beforeCreate?.();
        if (!["scanner", "fixture"].includes(role)) fail("INVALID_ROLE", "unsupported network role");
        const roleIdentity = { hash: crypto.createHash("sha256").update(i.hash + "|" + role).digest("hex") };
        const { subnet, gateway } = subnetFor(roleIdentity, env.usedSubnets.concat(env.hostRoutes, allocated));
        allocated.push(subnet);
        const name = names(i, role); const networkLabels = labels(i, role);
        if (!NAME.test(name)) fail("INVALID_ID", "generated network name exceeds inspectable name limit");
        const args = ["network", "create", "--driver", "bridge", "--internal", "--ipv6=false", "--subnet", subnet, "--gateway", gateway];
        for (const [key, value] of Object.entries(networkLabels)) args.push("--label", `${key}=${value}`);
        args.push(name);
        const result = await this.adapter.run(args);
        const id = result.objectId || String(result.stdout || "").trim();
        if (!ID.test(id)) fail("UNCERTAIN_CREATE", "network creation did not return an immutable ID");
        const reference = { id, name, labels: networkLabels, subnet, gateway, ipv6: false, internal: true, scanIdentity: i, role, provenance: "trusted-docker-inspect", createdAt: new Date().toISOString() };
        this.active.get(i.scanId).resources.push(reference);
        const inspected = parseNetwork((await this.adapter.run(["inspect", "--format", "{{json .}}", id])).stdout);
        const check = verifyNetwork(reference, inspected); if (!check.verified) fail("NETWORK_NOT_VERIFIED", check.reasons.join(","));
        created.push(reference);
      }
      return Object.freeze({ scanIdentity: i, networks: created.map(Object.freeze) });
    } catch (err) {
      try {
        const cleanup = await this.cleanup(i.scanId);
        if (!cleanup.cleaned) err.cleanup = cleanup;
      } catch (cleanupError) { err.cleanupError = cleanupError; }
      throw err;
    }
  }
  async cleanup(scanId) {
    const state = this.active.get(String(scanId)); if (!state) return { cleaned: true, residual: [] };
    const residual = [];
    for (const resource of [...state.resources].reverse()) {
      try {
        const current = parseNetwork((await this.adapter.run(["inspect", "--format", "{{json .}}", resource.id])).stdout);
        const check = verifyNetwork(resource, current); if (!check.verified) { residual.push({ id: resource.id, reason: check.reasons }); continue; }
        await this.adapter.run(["network", "rm", resource.id]);
        state.resources = state.resources.filter(item => item.id !== resource.id);
      } catch (err) { residual.push({ id: resource.id, reason: err.code || err.message }); }
    }
    if (!residual.length) this.active.delete(String(scanId));
    return { cleaned: residual.length === 0, residual };
  }
}

async function inspectOwnedNetwork(adapter, reference) {
  if (!reference?.scanIdentity || !ID.test(String(reference.id || ""))) fail("INVALID_IDENTITY", "owned network reference required");
  const observation = (await adapter.inspect([reference.id], "network")).normalized;
  if (!observation || observation.name !== reference.name || observation.driver !== "bridge" || !verifyNetwork(reference, observation).verified) fail("NETWORK_NOT_VERIFIED", "fresh network identity/ownership mismatch");
  return observation;
}
function verifyMemberships(container, networks) {
  const entries = Object.entries(container.networks || {});
  if (entries.length !== networks.length || networks.some(n => !entries.some(([name, endpoint]) => name === n.name && endpoint.NetworkID === n.id))) fail("NETWORK_MISMATCH", "unexpected network name/ID membership");
  return entries;
}
module.exports = { OwnedDockerNetworks, NetworkProvisionError, identity, labels, names, parseNetwork, verifyNetwork, subnetFor, inspectOwnedNetwork, verifyMemberships };
