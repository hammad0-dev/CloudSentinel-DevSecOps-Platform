"use strict";
// Modeled BusyBox 1.37 ip text fixtures. These are not live acceptance evidence.
const ipv4 = "172.30.25.0/28 dev eth0 scope link src 172.30.25.2\n";
const ipv6 = "";
const addresses = [
  "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue qlen 1000",
  "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00",
  "    inet 127.0.0.1/8 scope host lo",
  "       valid_lft forever preferred_lft forever",
  "2: eth0@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue",
  "    link/ether 02:42:ac:1e:19:02 brd ff:ff:ff:ff:ff:ff",
  "    inet 172.30.25.2/28 brd 172.30.25.15 scope global eth0",
  "       valid_lft forever preferred_lft forever", "",
].join("\n");
module.exports = { ipv4, ipv6, addresses };
