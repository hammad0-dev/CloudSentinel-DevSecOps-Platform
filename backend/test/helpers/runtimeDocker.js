"use strict";
const { DockerAdapter } = require("../../services/dockerAdapter");
const client = require("../../services/dastAcceptanceClient");
const squid = require("../../services/dastGateway");
const busybox = require("./busyboxNetwork");
const ids = { scanner: "1".repeat(64), fixture: "2".repeat(64), gateway: "3".repeat(64), client: "4".repeat(64) };
function network(role) {
  return { id: ids[role], name: `cs-${role}`, role, driver: "bridge", internal: true, ipv6: false,
    subnet: role === "scanner" ? "172.30.25.0/28" : "172.30.26.0/28", gateway: role === "scanner" ? "172.30.25.1" : "172.30.26.1",
    labels: { "cloudsentinel.owner": "cloudsentinel-owned", "cloudsentinel.scan": "s1" }, scanIdentity: { scanId: "s1" } };
}
function mockDocker() {
  const refs = [network("scanner"), network("fixture")], calls = [];
  const state = { clientNetworks: { "cs-scanner": { NetworkID: ids.scanner, IPAddress: "172.30.25.2", IPPrefixLen: 28, MacAddress: "02:42:ac:1e:19:02" } }, gatewayNetworks: {
    "cs-scanner": { NetworkID: ids.scanner, IPAddress: "172.30.25.3" }, "cs-fixture": { NetworkID: ids.fixture, IPAddress: "172.30.26.3" },
  }, route: busybox.ipv4, ipv6: busybox.ipv6, addresses: busybox.addresses, digest: "a".repeat(64), probe: null, foreign: false, commandFailure: false };
  state.clientMounts=[];state.clientUser='';state.nativeDigest=require('../../services/nativeConnectArtifact').BINARY_SHA;
  const adapter = new DockerAdapter({ executor: (bin, args, options, cb) => {
    calls.push(args);
    if (state.commandFailure && args[0] === "exec") return cb(Object.assign(new Error("missing"), { code: 127 }), "", "utility not found");
    if (args[0] === "network" && args[1] === "inspect") {
      const n = refs.find(n => n.id === args.at(-1));
      return cb(null, JSON.stringify({ Id: n.id, Name: n.name, Driver: "bridge", Internal: true, EnableIPv6: false, Labels: { ...n.labels, ...(state.foreign ? { "cloudsentinel.owner": "foreign" } : {}) }, IPAM: { Config: [{ Subnet: n.subnet, Gateway: n.gateway }] }, Containers: {}, Options: {} }), "");
    }
    if (args[0] === "run") {
      if(args.includes(client.IMAGE)) {
        const spec=args.includes('--mount')?args[args.indexOf('--mount')+1]:null;
        state.clientMounts=spec?[{Type:'bind',Source:spec.split('src=')[1].split(',')[0],Destination:spec.split('dst=')[1].split(',')[0],RW:false}]:[];
        state.clientUser=args.includes('--user')?args[args.indexOf('--user')+1]:'';
      }
      return cb(null, args.includes(client.IMAGE) ? ids.client : ids.gateway, "");
    }
    if (args[0] === "inspect") {
      const gateway = args.at(-1) === ids.gateway;
      return cb(null, JSON.stringify({ Id: args.at(-1), Name: gateway ? "/cs-gateway-s1" : "/cs-client-s1", Config: { User:gateway?'':state.clientUser, Image: gateway ? squid.IMAGE : client.IMAGE, Labels: { "cloudsentinel.owner": "cloudsentinel-s1", "cloudsentinel.scan": "s1", "cloudsentinel.role": gateway ? "gateway" : "acceptance-client" } }, State: { Running: true }, HostConfig: { Privileged: false, NetworkMode: ids.scanner, CapAdd: [],ReadonlyRootfs:true,CapDrop:['ALL'],SecurityOpt:['no-new-privileges:true'] }, Mounts: gateway?[]:state.clientMounts, NetworkSettings: { Networks: gateway ? state.gatewayNetworks : state.clientNetworks } }), "");
    }
    if (args[0] === "exec") {
      if (args.includes("-j") || args.includes("--noproxy=")) return cb(Object.assign(new Error("unsupported option"), { code: 2 }), "", "unsupported option");
      if (args[2] === "ip") return cb(null, args.includes("address") ? state.addresses : args.includes("inet6") ? state.ipv6 : state.route, "");
      if (args[2] === "sha256sum") return cb(null, args.at(-1)==='/opt/cloudsentinel/connect-peer'?`${state.nativeDigest}  /opt/cloudsentinel/connect-peer\n`:`${state.digest}  /etc/squid/cloudsentinel/squid.conf`, "");
      if (args[2] === "cat") return cb(null, "squid\0-N\0-f\0/etc/squid/cloudsentinel/squid.conf\0", "");
      if (state.probe) return state.probe(args, cb);
      if (args[2] === "nc") return cb(Object.assign(new Error("unreachable"), { code: 1 }), "", "nc: network is unreachable");
      if (args.at(-1).startsWith("https:")) { const r = require('../fixtures/connect-denied.json'); return cb(Object.assign(new Error("CONNECT"), { code: r.exitCode }), r.stdout, r.stderr); }
      if (['http://198.51.100.9:80/health','http://169.254.169.254:80/health'].includes(args.at(-1))) return cb(null,'403 000 172.30.25.3','HTTP/1.1 403 Forbidden\r\nServer: squid/6.14\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\n\r\n');
      if (args.at(-1)==='http://fixture.test:8080/redirect/host') return cb(null,'403 000 172.30.25.3 http://unauthorized.test:8080/health 1','HTTP/1.1 302 Found\r\nLocation: http://unauthorized.test:8080/health\r\n\r\nHTTP/1.1 403 Forbidden\r\nServer: squid/6.14\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\n\r\n');
      if (args.at(-1)==='http://fixture.test:8080/redirect/same') return cb(null,'200 000 172.30.25.3 http://fixture.test:8080/health 1','HTTP/1.1 302 Found\r\nLocation: http://fixture.test:8080/health\r\n\r\nHTTP/1.1 200 OK\r\n\r\n');
      const positive = args.at(-1) === "http://fixture.test:8080/health";
      return cb(null, `${positive ? 200 : 403} 000 172.30.25.3`, positive ? "HTTP/1.1 200 OK" : "HTTP/1.1 403 Forbidden\r\nX-Squid-Error: ERR_ACCESS_DENIED 0");
    }
    cb(null, "", "");
  } });
  return { adapter, refs, calls, state, ids };
}
module.exports = { mockDocker, ids };
