"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const { parseRoutes, parseAddresses, verifyNetworkText } = require("../services/runtimeNetworkText");
const text = require("./helpers/busyboxNetwork");
const network = { subnet: "172.30.25.0/28" };
const endpoint = { IPAddress: "172.30.25.2", MacAddress: "02:42:ac:1e:19:02" };
const attached = require('./fixtures/nginx-address-internal-248470e9.json');
// Endpoint fields recorded by Docker inspect in the same genuine capture.
const attachedEndpoint = { IPAddress: '172.30.250.2', MacAddress: '56:f2:65:38:29:5d' };
const attachedNetwork = { id: '941da9031e8049856516722bacd0f2074fdee7220766912d913f260971fec12d', subnet: attached.network.subnet };
const attachedText = { ipv4: '172.30.250.0/28 dev eth0 scope link src 172.30.250.2\n', ipv6: '', addresses: attached.stdout };
test('genuine attached M-DOWN header and complete addresses match Docker endpoint evidence', () => {
  assert.equal(attached.exitCode, 0); assert.equal(attached.stderr, '');
  const addresses = parseAddresses(attached.stdout), eth = addresses.find(n => n.ifname === 'eth0');
  assert.equal(addresses.length, 2); assert.deepEqual(eth.flags, ['BROADCAST','MULTICAST','UP','LOWER_UP','M-DOWN']);
  assert.equal(eth.state, 'UP'); assert.equal(eth.address, attachedEndpoint.MacAddress);
  assert.equal(eth.addr_info[0].local, attachedEndpoint.IPAddress);
  assert.equal(eth.addr_info[0].prefixlen, 28);
  const verified = verifyNetworkText(attachedText, attachedNetwork, attachedEndpoint);
  assert.equal(verified.raw.addresses, attached.stdout);
  assert.equal(verified.ipv4[0].dev, eth.ifname);
  // Only addresses are captured: the connected-route string above is mocked.
});
test('M-DOWN recognition does not accept arbitrary hyphenated flags or missing link evidence', () => {
  for (const flag of ['M-UNKNOWN','M-DOWN-EXTRA','X-UP','M-DOWNUP']) {
    assert.throws(() => parseAddresses(attached.stdout.replace('M-DOWN', flag)), { code: 'MALFORMED_ROUTES' });
  }
  for (const addresses of [
    attached.stdout.replace(',UP,LOWER_UP,M-DOWN', ',LOWER_UP,M-DOWN'),
    attached.stdout.replace(',LOWER_UP,M-DOWN', ',M-DOWN'),
    attached.stdout.replace('state UP', 'state DOWN'),
    attached.stdout.replace('state UP', 'state UNKNOWN'),
    attached.stdout.replace('M-DOWN', 'PROMISC'),
    attached.stdout.replaceAll('eth0', 'eth1'),
  ]) assert.throws(() => verifyNetworkText({ ...attachedText, addresses }, attachedNetwork, attachedEndpoint), { code: 'UNEXPECTED_INTERFACE' });
});
test('genuine M-DOWN addresses cannot override unsafe routes, IPv6 or conflicting identity', () => {
  for (const change of [
    { ipv4: attachedText.ipv4 + 'default via 172.30.250.1 dev eth0\n' },
    { ipv6: 'default via fe80::1 dev eth0\n' },
    { addresses: attached.stdout + '    inet6 2001:db8::2/64 scope global\n       valid_lft forever preferred_lft forever\n' },
    { addresses: '' }, { addresses: undefined },
    { addresses: attached.stdout.replace(/       valid_lft forever preferred_lft forever\n$/, '') },
    { addresses: attached.stdout.replace('172.30.250.2/28', 'invalid/28') },
    { ipv4: '' },
  ]) assert.throws(() => verifyNetworkText({ ...attachedText, ...change }, attachedNetwork, attachedEndpoint));
  for (const endpoint of [{ ...attachedEndpoint, IPAddress: '172.30.250.3' }, { ...attachedEndpoint, MacAddress: '02:42:ac:1e:19:99' }, {}]) assert.throws(() => verifyNetworkText(attachedText, attachedNetwork, endpoint));
  assert.throws(() => verifyNetworkText(attachedText, { ...attachedNetwork, subnet: '172.30.251.0/28' }, attachedEndpoint), { code: 'UNSAFE_ROUTE' });
});
test("production parser accepts genuine network-none output without inventing a scanner interface",()=>{
  const capture=require('./fixtures/nginx-network-none.json');
  const ipv4=parseRoutes(capture.commands.ipv4.stdout,4),ipv6=parseRoutes(capture.commands.ipv6.stdout,6),addresses=parseAddresses(capture.commands.addresses.stdout);
  assert.deepEqual(ipv4,[]);assert.deepEqual(ipv6,[]);assert.equal(addresses.length,1);assert.equal(addresses[0].ifname,'lo');assert.equal(addresses[0].addr_info[1].local,'::1');
  assert.throws(()=>verifyNetworkText(Object.fromEntries(Object.entries(capture.commands).map(([name,r])=>[name,r.stdout])),network,endpoint));
});
test("BusyBox connected routes and interface text agree with Docker endpoint evidence", () => {
  const parsed = verifyNetworkText(text, network, endpoint);
  assert.equal(parsed.ipv4[0].dev, "eth0"); assert.equal(parsed.addresses.length, 2);
  assert.equal(parsed.raw.addresses, text.addresses); assert.equal(parsed.source, "busybox-ip-text");
  assert.equal(parseRoutes(text.ipv4.replace("scope", "proto kernel scope"), 4)[0].protocol, "kernel");
  assert.equal(verifyNetworkText({ ...text, ipv4: "172.30.25.0/28 dev eth0  src 172.30.25.2\n" }, network, endpoint).ipv4[0].src, endpoint.IPAddress);
  assert.deepEqual(parseRoutes("", 6), []);
  assert.throws(() => parseAddresses(text.addresses.replace(/       valid_lft[^\n]+\n/g, "")), { code: "MALFORMED_ROUTES", validationRule: "MISSING_NATIVE_ADDRESS_LIFETIME" });
});
test("new genuine network-none capture parses but cannot establish containment", () => {
  const capture = require('./fixtures/nginx-address-network-none.json');
  assert.deepEqual(capture.command, ['ip', 'address', 'show']);
  assert.equal(capture.exitCode, 0); assert.equal(capture.stderr, '');
  const parsed = parseAddresses(capture.stdout);
  assert.equal(parsed.length, 1); assert.equal(parsed[0].ifname, 'lo');
  assert.deepEqual(parsed[0].addr_info.map(a => [a.family, a.local, a.prefixlen, a.scope]), [['inet', '127.0.0.1', 8, 'host'], ['inet6', '::1', 128, 'host']]);
  assert.throws(() => verifyNetworkText({ ipv4: '', ipv6: '', addresses: capture.stdout }, network, endpoint), { code: 'IPV6_EXPOSED' });
});
test("captured lifetime grammar requires complete lines and address ownership", () => {
  const capture = require('./fixtures/nginx-address-network-none.json');
  for (const addresses of [
    capture.stdout.replace(/       valid_lft forever preferred_lft forever\n$/, ''),
    capture.stdout.replace('preferred_lft forever', 'preferred_lft'),
    capture.stdout.replace('inet6 ::1/128', 'inet6 invalid/128'),
    capture.stdout.replace('scope host lo', 'scope host eth0'),
    capture.stdout.replace('00:00:00:00:00:00', '0:000:00:00:00:00'),
    capture.stdout.replace(/       valid_lft forever preferred_lft forever\n/, ''),
  ]) assert.throws(() => parseAddresses(addresses), { code: 'MALFORMED_ROUTES' });
  assert.equal(parseAddresses(capture.stdout.replaceAll('valid_lft forever preferred_lft forever', 'valid_lft 120sec preferred_lft 60sec'))[0].addr_info.length, 2);
  assert.throws(() => parseAddresses(text.addresses.replace(/       valid_lft forever preferred_lft forever\n/, '')), { code: 'MALFORMED_ROUTES', validationRule: 'MISSING_NATIVE_ADDRESS_LIFETIME' });
});
test("modeled attached interfaces remain strict; they are not real capture evidence", () => {
  const variants = [
    text.addresses.replace(/    inet 172\.30\.25\.2[^\n]*\n       valid_lft[^\n]*\n/, ''),
    text.addresses.replace(/2: eth0[\s\S]*/, ''),
    text.addresses + text.addresses.replaceAll('eth0', 'eth1').replaceAll('2:', '3:'),
    text.addresses + '    inet6 2001:db8::1/64 scope global\n       valid_lft forever preferred_lft forever\n',
    text.addresses.replace('172.30.25.2/28', '172.30.25.99/28'),
    text.addresses.replace('02:42:ac:1e:19:02', '02:42:ac:1e:19:99'),
    text.addresses.trimEnd().replace(/preferred_lft forever$/, 'preferred_lft'),
    text.addresses + 'unexpected native line\n',
  ];
  for (const addresses of variants) assert.throws(() => verifyNetworkText({ ...text, addresses }, network, endpoint));
});
test("IPv6 routes parse explicitly but never establish isolated readiness", () => {
  const ipv6 = "fe80::/64 dev eth0 proto kernel metric 256 pref medium\n";
  assert.equal(parseRoutes(ipv6, 6)[0].family, 6);
  assert.throws(() => verifyNetworkText({ ...text, ipv6 }, network, endpoint), { code: "IPV6_EXPOSED" });
  const addresses = text.addresses + "    inet6 fe80::42/64 scope link\n       valid_lft forever preferred_lft forever\n";
  assert.throws(() => verifyNetworkText({ ...text, addresses }, network, endpoint), { code: "IPV6_EXPOSED" });
});
test("default routes, gateway routes, foreign prefixes and route devices fail closed", () => {
  for (const ipv4 of ["default via 172.30.25.1 dev eth0\n", "0.0.0.0/0 dev eth0\n", text.ipv4.replace(" dev ", " via 172.30.25.1 dev "), text.ipv4.replace("172.30.25.0/28", "10.0.0.0/8"), text.ipv4.replace("eth0", "eth1"), ""]) {
    assert.throws(() => verifyNetworkText({ ...text, ipv4 }, network, endpoint));
  }
});
test("unknown, duplicate and incomplete native observations are rejected", () => {
  for (const ipv4 of [undefined, "[]", "Usage: ip [OPTIONS]", "172.30.25.0/28 dev eth0 magic 1", text.ipv4 + text.ipv4, "999.1.2.0/24 dev eth0", "172.30.25.0/99 dev eth0"]) assert.throws(() => verifyNetworkText({ ...text, ipv4 }, network, endpoint));
  for (const addresses of ["", "inet 172.30.25.2/28 scope global eth0", text.addresses + text.addresses, text.addresses.replace("inet 172.30.25.2/28", "inet garbage"), text.addresses.replace("    link/ether", "    mystery/ether"), text.addresses.replace("2: eth0@if8:", "1: eth0@if8:"), text.addresses.replace(/2: eth0[\s\S]*/, "")]) assert.throws(() => verifyNetworkText({ ...text, addresses }, network, endpoint));
});
test("interface names, MACs, addresses, prefixes and flags must match trusted inspection", () => {
  for (const addresses of [text.addresses.replaceAll("eth0", "eth1"), text.addresses.replace("02:42:ac:1e:19:02", "02:42:ac:1e:19:99"), text.addresses.replace("172.30.25.2/28", "172.30.25.3/28"), text.addresses.replace("172.30.25.2/28", "172.30.25.2/24"), text.addresses.replace("BROADCAST,MULTICAST,UP,LOWER_UP", "BROADCAST,MULTICAST,UP,PROMISC"), text.addresses + "3: tun0: <UP> mtu 1500\n    link/ether 02:42:ac:1e:19:99 brd ff:ff:ff:ff:ff:ff\n    inet 10.0.0.2/24 scope global tun0\n"]) assert.throws(() => verifyNetworkText({ ...text, addresses }, network, endpoint));
  assert.throws(() => verifyNetworkText(text, network, { IPAddress: endpoint.IPAddress }), { code: "MALFORMED_ROUTES" });
});
