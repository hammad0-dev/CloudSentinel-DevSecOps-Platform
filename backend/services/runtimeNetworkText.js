"use strict";
const { isIP } = require("net");
const isolationEvidence = new WeakMap();
function ipNumber(ip) { return ip.split(".").reduce((n, part) => n * 256 + Number(part), 0); }
function freeze(value) { if (value && typeof value === "object") { Object.values(value).forEach(freeze); Object.freeze(value); } return value; }

function reject(code, message) { throw Object.assign(new Error(message), { code, validationRule: message.replace(/[^a-z0-9]+/gi, "_").toUpperCase() }); }
function lines(text) {
  if (typeof text !== "string" || text.includes("\0")) reject("MALFORMED_ROUTES", "missing or malformed native network output");
  return text.split(/\r?\n/).map(line => line.trim().replace(/[ \t]+/g, " ")).filter(Boolean);
}
function cidr(value, family) {
  const parts = value.split("/");
  if (parts.length > 2 || isIP(parts[0]) !== family || (parts.length === 2 && (!/^\d+$/.test(parts[1]) || Number(parts[1]) > (family === 4 ? 32 : 128)))) reject("MALFORMED_ROUTES", "invalid native network prefix");
  return { local: parts[0], prefixlen: parts.length === 2 ? Number(parts[1]) : (family === 4 ? 32 : 128) };
}
function parseRoutes(text, family) {
  if (![4, 6].includes(family)) reject("MALFORMED_ROUTES", "invalid route family");
  return lines(text).map(line => {
    const match = /^(\S+)(?: via (\S+))? dev ([a-zA-Z0-9_.-]+)(?: proto (kernel|boot|static))?(?: scope (link|host|global))?(?: src (\S+))?(?: metric (\d+))?(?: pref (low|medium|high))?$/.exec(line);
    if (!match) reject("MALFORMED_ROUTES", "unrecognized native route format");
    const [, dst, gateway, dev, protocol, scope, src, metric] = match;
    if (dst !== "default") cidr(dst, family);
    if ((gateway && isIP(gateway) !== family) || (src && isIP(src) !== family)) reject("MALFORMED_ROUTES", "invalid native route address");
    return { dst, gateway: gateway || null, dev, protocol: protocol || null, scope: scope || null, src: src || null, metric: metric ? Number(metric) : null, family, defaultRoute: dst === "default" || dst === "0.0.0.0/0" || dst === "::/0" };
  });
}
function parseAddresses(text) {
  const result = []; let current, awaitingLifetime = false;
  for (const line of lines(text)) {
    const header = /^(\d+): ([a-zA-Z0-9_.-]+)(?:@[a-zA-Z0-9_.-]+)?: <((?:[A-Z0-9_]+|M-DOWN)(?:,(?:[A-Z0-9_]+|M-DOWN))*)> mtu (\d+)(?: qdisc [a-zA-Z0-9_-]+)?(?: state (UP|DOWN|UNKNOWN))?(?: group [a-zA-Z0-9_-]+)?(?: qlen \d+)?$/.exec(line);
    if (header) {
      if (awaitingLifetime) reject("MALFORMED_ROUTES", "missing native address lifetime");
      if (result.some(x => x.ifname === header[2] || x.ifindex === Number(header[1]))) reject("MALFORMED_ROUTES", "duplicate native interface");
      current = { ifindex: Number(header[1]), ifname: header[2], flags: header[3].split(","), state: header[5] || null, address: null, linkType: null, addr_info: [] };
      result.push(current); awaitingLifetime = false; continue;
    }
    if (!current) reject("MALFORMED_ROUTES", "address output has no interface header");
    const link = /^link\/(loopback|ether) ((?:[a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}) brd ((?:[a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})$/.exec(line);
    if (link && !current.address && !awaitingLifetime) { current.linkType = link[1]; current.address = link[2].toLowerCase(); continue; }
    const address = /^(inet6?) (\S+)(?: brd (\S+))? scope (host|link|global)(?: ([a-zA-Z0-9_.-]+))?$/.exec(line);
    if (address && current.address) {
      if (awaitingLifetime) reject("MALFORMED_ROUTES", "missing native address lifetime");
      const family = address[1] === "inet" ? 4 : 6;
      const parsed = cidr(address[2], family);
      if (!address[2].includes("/") || (address[3] && isIP(address[3]) !== family) || (address[5] && address[5] !== current.ifname)) reject("MALFORMED_ROUTES", "ambiguous native interface address");
      current.addr_info.push({ ...parsed, family: family === 4 ? "inet" : "inet6", scope: address[4], broadcast: address[3] || null });
      awaitingLifetime = true; continue;
    }
    if (awaitingLifetime && /^valid_lft (?:forever|\d+sec) preferred_lft (?:forever|\d+sec)$/.test(line)) { awaitingLifetime = false; continue; }
    reject("MALFORMED_ROUTES", "unrecognized or incomplete native address format");
  }
  if (awaitingLifetime) reject("MALFORMED_ROUTES", "missing native address lifetime");
  if (!result.length || result.some(n => !n.address || !n.addr_info.length)) reject("MALFORMED_ROUTES", "missing native interface evidence");
  return result;
}
function verifyNetworkText({ ipv4, ipv6, addresses }, network, endpoint) {
  const parse = (observation, fn) => {
    try { return fn(); }
    catch (error) { error.observation = observation; throw error; }
  };
  const routes = { ipv4: parse("ipv4", () => parseRoutes(ipv4, 4)), ipv6: parse("ipv6", () => parseRoutes(ipv6, 6)), addresses: parse("addresses", () => parseAddresses(addresses)), source: "busybox-ip-text", raw: { ipv4, ipv6, addresses } };
  if (routes.ipv6.length || routes.addresses.some(n => n.addr_info.some(a => a.family === "inet6"))) reject("IPV6_EXPOSED", "IPv6 paths or addresses detected");
  if (routes.ipv4.some(r => r.defaultRoute || r.gateway)) reject("UNSAFE_ROUTE", "default or gateway route detected");
  if (routes.addresses.length !== 2 || routes.addresses.some(n => !["lo", "eth0"].includes(n.ifname))) reject("UNEXPECTED_INTERFACE", "unauthorized network interface");
  const lo = routes.addresses.find(n => n.ifname === "lo"), eth = routes.addresses.find(n => n.ifname === "eth0");
  const prefix = Number(network.subnet.split("/")[1]);
  if (!lo || !eth || !endpoint || isIP(endpoint.IPAddress) !== 4 || !/^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/.test(endpoint.MacAddress || "")) parse("addresses", () => reject("MALFORMED_ROUTES", "missing inspected interface identity"));
  if (lo.linkType !== "loopback" || lo.address !== "00:00:00:00:00:00" || lo.flags.some(f => !["LOOPBACK", "UP", "LOWER_UP"].includes(f)) || !lo.flags.includes("LOOPBACK") || !lo.flags.includes("UP") || lo.addr_info.length !== 1 || lo.addr_info[0].local !== "127.0.0.1" || lo.addr_info[0].prefixlen !== 8 || lo.addr_info[0].scope !== "host") reject("UNEXPECTED_INTERFACE", "unexpected loopback evidence");
  // BusyBox reports M-DOWN on the captured Docker Ethernet interface. Record
  // it without deriving isolation or liveness from it; require positive link
  // flags and independently matching endpoint/address/route evidence below.
  if (eth.linkType !== "ether" || !eth.flags.includes("UP") || !eth.flags.includes("LOWER_UP") || ![null, "UP"].includes(eth.state) || eth.flags.some(f => !["BROADCAST", "MULTICAST", "UP", "LOWER_UP", "M-DOWN"].includes(f)) || eth.address !== endpoint.MacAddress.toLowerCase() || eth.addr_info.length !== 1 || eth.addr_info[0].local !== endpoint.IPAddress || eth.addr_info[0].prefixlen !== prefix || eth.addr_info[0].scope !== "global") reject("UNEXPECTED_INTERFACE", "native interface disagrees with inspected endpoint");
  if (routes.ipv4.length !== 1 || routes.ipv4[0].dst !== network.subnet || routes.ipv4[0].dev !== eth.ifname || ![null, "link"].includes(routes.ipv4[0].scope) || routes.ipv4[0].src !== endpoint.IPAddress) reject("UNSAFE_ROUTE", "routes do not match the owned connected subnet");
  isolationEvidence.set(routes, { networkId: network.id, sourceIp: endpoint.IPAddress, sourceMac: endpoint.MacAddress.toLowerCase(), subnet: network.subnet, observedAt: Date.now() });
  return freeze(routes);
}
function supportsDirectIsolation(evidence, { networkId, sourceIp, sourceMac, destination }) {
  const proof = isolationEvidence.get(evidence);
  if (!proof || !networkId || proof.networkId !== networkId || proof.sourceIp !== sourceIp || proof.sourceMac !== String(sourceMac).toLowerCase() || isIP(destination) !== 4 || Date.now() - proof.observedAt > 30000) return false;
  const [base, bits] = proof.subnet.split("/");
  const size = 2 ** (32 - Number(bits));
  const n = ipNumber(destination);
  // The observed table has only its connected route and no IPv6 paths.
  // This corroborates a socket-level rejection; it does not itself prove the
  // kernel's policy-routing lookup or establish a TCP denial.
  return n < ipNumber(base) || n >= ipNumber(base) + size;
}
module.exports = { parseRoutes, parseAddresses, verifyNetworkText, supportsDirectIsolation };
