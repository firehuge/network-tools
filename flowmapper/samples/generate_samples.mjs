#!/usr/bin/env node
/* Generates synthetic PAN-OS configs (documentation/private ranges only, no real data). */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const OUT = path.dirname(fileURLToPath(import.meta.url));

const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
const m = (arr) => arr.map((x) => `<member>${esc(x)}</member>`).join("");
const ent = (name, inner) => `<entry name="${esc(name)}">${inner}</entry>`;

function eth(name, ip, units = []) {
  const u = units.length ? `<units>${units.map(([n, uip, tag]) => ent(n, `<ip>${ent(uip, "")}</ip><tag>${tag}</tag>`)).join("")}</units>` : "";
  return ent(name, `<layer3>${ip ? `<ip>${ent(ip, "")}</ip>` : ""}${u}</layer3>`);
}
function ifaces({ ethernet = [], ae = [], tunnel = [], loopback = [], vlan = [] }) {
  const units = (list) => list.length ? `<units>${list.map(([n, ip]) => ent(n, ip ? `<ip>${ent(ip, "")}</ip>` : "")).join("")}</units>` : "";
  return `<interface><ethernet>${ethernet.join("")}</ethernet>${ae.length ? `<aggregate-ethernet>${ae.join("")}</aggregate-ethernet>` : ""}<tunnel>${units(tunnel)}</tunnel><loopback>${units(loopback)}</loopback><vlan>${units(vlan)}</vlan></interface>`;
}
function route(name, dest, { ip, nextVr, iface, metric = 10, discard } = {}) {
  let nh = "";
  if (ip) nh = `<nexthop><ip-address>${ip}</ip-address></nexthop>`;
  if (nextVr) nh = `<nexthop><next-vr>${nextVr}</next-vr></nexthop>`;
  if (discard) nh = `<nexthop><discard/></nexthop>`;
  return ent(name, `${nh}<metric>${metric}</metric><destination>${dest}</destination>${iface ? `<interface>${iface}</interface>` : ""}<route-table><unicast/></route-table>`);
}
function vr(name, ifs, routes, { bgp = false, ospf = false } = {}) {
  return ent(name, `<protocol><bgp><enable>${bgp ? "yes" : "no"}</enable></bgp><ospf><enable>${ospf ? "yes" : "no"}</enable></ospf><rip><enable>no</enable></rip></protocol><interface>${m(ifs)}</interface><routing-table><ip><static-route>${routes.join("")}</static-route></ip></routing-table>`);
}
function zone(name, type, mem) { return ent(name, `<network><${type}>${m(mem)}</${type}></network>`); }
function addr(name, kind, val, tags = []) { return ent(name, `<${kind}>${val}</${kind}>${tags.length ? `<tag>${m(tags)}</tag>` : ""}`); }
function agrp(name, members) { return ent(name, `<static>${m(members)}</static>`); }
function dgrp(name, filter) { return ent(name, `<dynamic><filter>${esc(filter)}</filter></dynamic>`); }
function svc(name, proto, port) { return ent(name, `<protocol><${proto}><port>${port}</port></${proto}></protocol>`); }
function sgrp(name, members) { return ent(name, `<members>${m(members)}</members>`); }
function sec(name, { from, to, src = ["any"], dst = ["any"], app = ["any"], svc: s = ["application-default"], action = "allow", disabled, user, ruleType, negDst }) {
  return ent(name, `<to>${m(to)}</to><from>${m(from)}</from><source>${m(src)}</source><destination>${m(dst)}</destination><source-user>${m(user || ["any"])}</source-user><category>${m(["any"])}</category><application>${m(app)}</application><service>${m(s)}</service><action>${action}</action>${disabled ? "<disabled>yes</disabled>" : ""}${ruleType ? `<rule-type>${ruleType}</rule-type>` : ""}${negDst ? "<negate-destination>yes</negate-destination>" : ""}`);
}
function nat(name, { from, to, src = ["any"], dst = ["any"], service = "any", snatIf, snatIp, snatAddr, staticIp, bidir, dnat, dport, toIf }) {
  let st = "";
  if (snatIf) st = `<source-translation><dynamic-ip-and-port><interface-address><interface>${snatIf}</interface>${snatIp ? `<ip>${snatIp}</ip>` : ""}</interface-address></dynamic-ip-and-port></source-translation>`;
  if (snatAddr) st = `<source-translation><dynamic-ip-and-port><translated-address>${m([snatAddr])}</translated-address></dynamic-ip-and-port></source-translation>`;
  if (staticIp) st = `<source-translation><static-ip><translated-address>${staticIp}</translated-address>${bidir ? "<bi-directional>yes</bi-directional>" : ""}</static-ip></source-translation>`;
  const dt = dnat ? `<destination-translation><translated-address>${dnat}</translated-address>${dport ? `<translated-port>${dport}</translated-port>` : ""}</destination-translation>` : "";
  return ent(name, `${st}${dt}<to>${m(to)}</to><from>${m(from)}</from><source>${m(src)}</source><destination>${m(dst)}</destination><service>${service}</service>${toIf ? `<to-interface>${toIf}</to-interface>` : ""}`);
}
function vsys(name, { display, zones = [], ifs = [], vrs = [], visible = [], addrs = [], agroups = [], svcs = [], sgroups = [], rules = [], nats = [], pbf = [] }) {
  return ent(name, `${display ? `<display-name>${display}</display-name>` : ""}<import><network><interface>${m(ifs)}</interface>${vrs.length ? `<virtual-router>${m(vrs)}</virtual-router>` : ""}</network>${visible.length ? `<visible-vsys>${m(visible)}</visible-vsys>` : ""}</import><zone>${zones.join("")}</zone><address>${addrs.join("")}</address><address-group>${agroups.join("")}</address-group><service>${svcs.join("")}</service><service-group>${sgroups.join("")}</service-group><rulebase><security><rules>${rules.join("")}</rules></security><nat><rules>${nats.join("")}</rules></nat>${pbf.length ? `<pbf><rules>${pbf.join("")}</rules></pbf>` : ""}</rulebase>`);
}
function fwConfig({ hostname, network, vsysXml, sharedGw = "", shared = "" }) {
  return `<?xml version="1.0"?>
<config version="11.1.0" urldb="paloaltonetworks" detail-version="11.1.4">
  <mgt-config><users>${ent("admin", "<phash>$5$SYNTHETICHASHVALUE$abcdefghijklmnop</phash><permissions><role-based><superuser>yes</superuser></role-based></permissions>")}</users></mgt-config>
  <shared>${shared}</shared>
  <devices>${ent("localhost.localdomain", `<network>${network}${sharedGw}<ike><gateway>${ent("synthetic-peer", "<authentication><pre-shared-key><key>-AQ==SYNTHETICPSK0000000000=</key></pre-shared-key></authentication>")}</gateway></ike></network><deviceconfig><system><hostname>${hostname}</hostname><ip-address>192.0.2.10</ip-address></system></deviceconfig><vsys>${vsysXml}</vsys>`)}</devices>
</config>
`;
}

/* 1. single-vsys branch firewall (also used for the cross-device test) */
const single = fwConfig({
  hostname: "branch-fw1",
  network: ifaces({
    ethernet: [eth("ethernet1/1", "203.0.113.2/29"), eth("ethernet1/2", "10.10.0.1/24", [["ethernet1/2.20", "10.10.20.1/24", 20]]), eth("ethernet1/3", "172.16.10.1/24"), eth("ethernet1/4", "10.255.0.1/30")],
    tunnel: [["tunnel.1", "169.254.10.1/30"]], loopback: [["loopback.1", "10.10.255.1/32"]],
  }) + `<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2", "ethernet1/2.20", "ethernet1/3", "ethernet1/4", "tunnel.1", "loopback.1"], [
    route("default", "0.0.0.0/0", { ip: "203.0.113.1", iface: "ethernet1/1" }),
    route("to-core", "10.50.0.0/16", { ip: "10.255.0.2" }),
    route("vpn-partner", "172.31.200.0/24", { iface: "tunnel.1" }),
    route("blackhole-rfc1918", "10.99.0.0/16", { discard: true }),
  ])}</virtual-router>`,
  vsysXml: vsys("vsys1", {
    zones: [zone("untrust", "layer3", ["ethernet1/1"]), zone("trust", "layer3", ["ethernet1/2"]), zone("voice", "layer3", ["ethernet1/2.20"]), zone("dmz", "layer3", ["ethernet1/3"]), zone("core", "layer3", ["ethernet1/4"]), zone("vpn", "layer3", ["tunnel.1"]), zone("mgmt-lo", "layer3", ["loopback.1"])],
    ifs: ["ethernet1/1", "ethernet1/2", "ethernet1/2.20", "ethernet1/3", "ethernet1/4", "tunnel.1", "loopback.1"],
    addrs: [addr("net-users", "ip-netmask", "10.10.0.0/24"), addr("net-voice", "ip-netmask", "10.10.20.0/24"), addr("h-web01", "ip-netmask", "172.16.10.20", ["web", "prod"]), addr("h-web02", "ip-netmask", "172.16.10.21", ["web"]),
      addr("r-printers", "ip-range", "10.10.0.200-10.10.0.220"), addr("fqdn-updates", "fqdn", "updates.example.com"), addr("net-core-apps", "ip-netmask", "10.50.10.0/24"), addr("net-partner", "ip-netmask", "172.31.200.0/24")],
    agroups: [agrp("grp-inside", ["net-users", "net-voice"]), agrp("grp-all-inside", ["grp-inside", "r-printers"]), dgrp("dag-web-prod", "'web' and 'prod'")],
    svcs: [svc("tcp-8443", "tcp", "8443"), svc("tcp-5060-5061", "tcp", "5060-5061")],
    sgroups: [sgrp("sg-web", ["service-http", "service-https", "tcp-8443"])],
    rules: [
      sec("block-bad", { from: ["any"], to: ["untrust"], dst: ["fqdn-updates"], action: "deny" }),
      sec("users-web-out", { from: ["trust", "voice"], to: ["untrust"], src: ["grp-inside"], app: ["web-browsing", "ssl"], svc: ["application-default"] }),
      sec("users-dns", { from: ["trust"], to: ["untrust"], src: ["net-users"], app: ["dns"], svc: ["application-default"] }),
      sec("users-to-dmz-web", { from: ["trust"], to: ["dmz"], src: ["grp-all-inside"], dst: ["dag-web-prod"], svc: ["sg-web"] }),
      sec("users-to-core", { from: ["trust"], to: ["core"], src: ["net-users"], dst: ["net-core-apps"], svc: ["service-https"] }),
      sec("partner-vpn", { from: ["trust"], to: ["vpn"], src: ["net-users"], dst: ["net-partner"], app: ["ssh"], svc: ["application-default"] }),
      sec("old-rule-disabled", { from: ["trust"], to: ["dmz"], svc: ["any"], disabled: true }),
      sec("deny-dmz", { from: ["any"], to: ["dmz"], action: "deny", svc: ["any"] }),
    ],
    nats: [nat("outbound-pat", { from: ["trust", "voice"], to: ["untrust"], src: ["grp-inside"], snatIf: "ethernet1/1", snatIp: "203.0.113.2/29" })],
  }),
});

/* 2. core firewall behind branch-fw1 (cross-device test) */
const core = fwConfig({
  hostname: "core-fw1",
  network: ifaces({ ethernet: [eth("ethernet1/1", "10.255.0.2/30"), eth("ethernet1/2", "10.50.10.1/24"), eth("ethernet1/3", "10.50.20.1/24")] }) +
    `<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2", "ethernet1/3"], [route("default", "0.0.0.0/0", { ip: "10.255.0.1" })], { ospf: true })}</virtual-router>`,
  vsysXml: vsys("vsys1", {
    zones: [zone("transit", "layer3", ["ethernet1/1"]), zone("apps", "layer3", ["ethernet1/2"]), zone("db", "layer3", ["ethernet1/3"])],
    ifs: ["ethernet1/1", "ethernet1/2", "ethernet1/3"],
    addrs: [addr("net-apps", "ip-netmask", "10.50.10.0/24")],
    rules: [sec("branch-to-apps", { from: ["transit"], to: ["apps"], dst: ["net-apps"], svc: ["service-https"] })],
  }),
});

/* 3. multi-vsys DC firewall: vsys1 Corp, vsys2 PCI, vsys3 Lab; inter-vsys via next-vr + external zones */
const multi = fwConfig({
  hostname: "dc-fw-mv1",
  network: ifaces({
    ethernet: [eth("ethernet1/1", "198.51.100.2/28"), eth("ethernet1/5", "10.3.0.1/24")],
    ae: [eth("ae1", null, [["ae1.100", "10.1.1.1/24", 100], ["ae1.110", "10.1.10.1/24", 110], ["ae1.200", "10.2.2.1/24", 200], ["ae1.210", "10.2.10.1/24", 210]])],
    tunnel: [["tunnel.10", "169.254.20.1/30"]],
  }) + `<virtual-router>
    ${vr("vr-corp", ["ethernet1/1", "ae1.100", "ae1.110", "tunnel.10"], [
      route("default", "0.0.0.0/0", { ip: "198.51.100.1", iface: "ethernet1/1" }),
      route("to-pci-db", "10.2.2.0/24", { nextVr: "vr-pci" }),
      route("to-lab-via-pci", "10.3.0.0/16", { nextVr: "vr-pci" }),
      route("remote-site", "10.180.0.0/16", { iface: "tunnel.10" }),
    ], { bgp: true })}
    ${vr("vr-pci", ["ae1.200", "ae1.210"], [
      route("to-corp-users", "10.1.1.0/24", { nextVr: "vr-corp" }),
      route("to-lab", "10.3.0.0/16", { nextVr: "vr-lab" }),
      route("default", "0.0.0.0/0", { nextVr: "vr-corp" }),
    ])}
    ${vr("vr-lab", ["ethernet1/5"], [route("to-pci", "10.2.0.0/16", { nextVr: "vr-pci" })])}
  </virtual-router>`,
  vsysXml:
    vsys("vsys1", {
      display: "Corp", ifs: ["ethernet1/1", "ae1.100", "ae1.110", "tunnel.10"], vrs: ["vr-corp"], visible: ["vsys2"],
      zones: [zone("corp-untrust", "layer3", ["ethernet1/1"]), zone("corp-users", "layer3", ["ae1.100"]), zone("corp-servers", "layer3", ["ae1.110"]), zone("corp-vpn", "layer3", ["tunnel.10"]), zone("ext-to-pci", "external", ["vsys2"])],
      addrs: [addr("corp-users-net", "ip-netmask", "10.1.1.0/24"), addr("corp-jump01", "ip-netmask", "10.1.10.5"), addr("pci-db01", "ip-netmask", "10.2.2.20"), addr("pci-app-net", "ip-netmask", "10.2.10.0/24")],
      agroups: [agrp("pci-targets", ["pci-db01", "pci-app-net"])],
      svcs: [svc("tcp-1433", "tcp", "1433"), svc("tcp-8443", "tcp", "8443")],
      rules: [
        sec("corp-web-out", { from: ["corp-users"], to: ["corp-untrust"], app: ["web-browsing", "ssl"] }),
        sec("users-to-pci-sql", { from: ["corp-users"], to: ["ext-to-pci"], src: ["corp-users-net"], dst: ["pci-targets"], svc: ["tcp-1433"] }),
        sec("jump-to-pci-ssh", { from: ["corp-servers"], to: ["ext-to-pci"], src: ["corp-jump01"], dst: ["pci-targets"], app: ["ssh"] }),
        sec("deny-to-pci", { from: ["any"], to: ["ext-to-pci"], svc: ["any"], action: "deny" }),
      ],
      nats: [nat("corp-outbound", { from: ["corp-users", "corp-servers"], to: ["corp-untrust"], snatIf: "ethernet1/1", snatIp: "198.51.100.2/28" })],
    }) +
    vsys("vsys2", {
      display: "PCI", ifs: ["ae1.200", "ae1.210"], vrs: ["vr-pci"], visible: ["vsys1", "vsys3"],
      zones: [zone("pci-db", "layer3", ["ae1.200"]), zone("pci-app", "layer3", ["ae1.210"]), zone("ext-from-corp", "external", ["vsys1"]), zone("ext-to-lab", "external", ["vsys3"])],
      addrs: [addr("pci-db01", "ip-netmask", "10.2.2.20"), addr("pci-app-net", "ip-netmask", "10.2.10.0/24"), addr("corp-jump01", "ip-netmask", "10.1.10.5")],
      svcs: [svc("tcp-1433", "tcp", "1433")],
      rules: [
        sec("app-to-db", { from: ["pci-app"], to: ["pci-db"], src: ["pci-app-net"], dst: ["pci-db01"], svc: ["tcp-1433"] }),
        sec("jump-ssh-in", { from: ["ext-from-corp"], to: ["pci-db", "pci-app"], src: ["corp-jump01"], app: ["ssh"] }),
        sec("pci-deny-all", { from: ["any"], to: ["any"], svc: ["any"], action: "deny", ruleType: "interzone" }),
      ],
    }) +
    vsys("vsys3", {
      display: "Lab", ifs: ["ethernet1/5"], vrs: ["vr-lab"], visible: ["vsys2"],
      zones: [zone("lab", "layer3", ["ethernet1/5"]), zone("ext-from-pci", "external", ["vsys2"])],
    }),
});

/* 4. shared gateway firewall (modelled on the PAN-OS shared gateway design) */
const sgw = fwConfig({
  hostname: "mt-fw-sg1",
  network: ifaces({ ethernet: [eth("ethernet1/1", "10.0.0.1/24"), eth("ethernet1/2", "10.1.0.1/24"), eth("ethernet1/3", "198.51.100.2/24")] }) +
    `<virtual-router>
      ${vr("v1-default", ["ethernet1/1"], [route("dg", "0.0.0.0/0", { nextVr: "sharedVR" }), route("to-vsys2", "10.1.0.0/24", { nextVr: "v2-default" })])}
      ${vr("v2-default", ["ethernet1/2"], [route("dg", "0.0.0.0/0", { nextVr: "sharedVR" })])}
      ${vr("sharedVR", ["ethernet1/3"], [route("default", "0.0.0.0/0", { ip: "198.51.100.1" }), route("to-vsys1", "10.0.0.0/24", { nextVr: "v1-default" })])}
    </virtual-router>`,
  sharedGw: `<shared-gateway>${ent("sg1", `<display-name>SharedGW</display-name><zone>${zone("SGuntrust", "layer3", ["ethernet1/3"])}${zone("to-vsys1", "external", ["vsys1"])}${zone("to-vsys2", "external", ["vsys2"])}</zone><import><network><interface>${m(["ethernet1/3"])}</interface></network></import><address>${addr("pub-web", "ip-netmask", "198.51.100.4")}</address><rulebase><nat><rules>${
    nat("vsys1-out", { from: ["to-vsys1"], to: ["SGuntrust"], snatIf: "ethernet1/3", snatIp: "198.51.100.2/24" }) +
    nat("vsys2-out", { from: ["to-vsys2"], to: ["SGuntrust"], snatIf: "ethernet1/3", snatIp: "198.51.100.2/24" }) +
    nat("inbound-web-vsys1", { from: ["SGuntrust"], to: ["SGuntrust"], dst: ["pub-web"], service: "service-https", dnat: "10.0.0.4" })
  }</rules></nat></rulebase>`)}</shared-gateway>`,
  vsysXml:
    vsys("vsys1", { display: "TenantA", ifs: ["ethernet1/1"], vrs: ["v1-default"], visible: ["vsys2"], zones: [zone("A-trust", "layer3", ["ethernet1/1"]), zone("A-to-SG", "external", ["sg1"]), zone("A-to-B", "external", ["vsys2"])],
      addrs: [addr("A-web01", "ip-netmask", "10.0.0.4")],
      rules: [sec("A-internet", { from: ["A-trust"], to: ["A-to-SG"], app: ["ssl", "web-browsing"] }), sec("A-web-inbound", { from: ["A-to-SG"], to: ["A-trust"], dst: ["A-web01"], app: ["ssl"] })] }) +
    vsys("vsys2", { display: "TenantB", ifs: ["ethernet1/2"], vrs: ["v2-default"], visible: ["vsys1"], zones: [zone("B-trust", "layer3", ["ethernet1/2"]), zone("B-to-SG", "external", ["sg1"])], rules: [] }),
});

/* 5. DNAT / bidirectional NAT / PBF edge firewall */
const dnatFw = fwConfig({
  hostname: "edge-fw-dnat",
  network: ifaces({ ethernet: [eth("ethernet1/1", "203.0.113.2/24"), eth("ethernet1/2", "172.16.10.1/24"), eth("ethernet1/3", "10.20.0.1/24"), eth("ethernet1/4", "192.0.2.2/30")] }) +
    `<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2", "ethernet1/3", "ethernet1/4"], [route("default", "0.0.0.0/0", { ip: "203.0.113.1" })])}</virtual-router>`,
  vsysXml: vsys("vsys1", {
    ifs: ["ethernet1/1", "ethernet1/2", "ethernet1/3", "ethernet1/4"],
    zones: [zone("untrust", "layer3", ["ethernet1/1"]), zone("dmz", "layer3", ["ethernet1/2"]), zone("trust", "layer3", ["ethernet1/3"]), zone("isp2", "layer3", ["ethernet1/4"])],
    addrs: [addr("pub-web", "ip-netmask", "203.0.113.10"), addr("pub-ssh", "ip-netmask", "203.0.113.11"), addr("pub-mail", "ip-netmask", "203.0.113.12"), addr("dmz-web", "ip-netmask", "172.16.10.20"), addr("dmz-ssh", "ip-netmask", "172.16.10.21"), addr("dmz-mail", "ip-netmask", "172.16.10.25"), addr("trust-net", "ip-netmask", "10.20.0.0/24"), addr("guest-pc", "ip-netmask", "10.20.0.99")],
    rules: [
      sec("web-inbound", { from: ["untrust"], to: ["dmz"], dst: ["pub-web"], svc: ["service-https"] }),
      sec("ssh-inbound-WRONG", { from: ["untrust"], to: ["dmz"], dst: ["dmz-ssh"], svc: ["any"], app: ["ssh"] }),
      sec("trust-out", { from: ["trust"], to: ["untrust", "isp2"], src: ["trust-net"], svc: ["service-https", "service-http"] }),
    ],
    nats: [
      nat("dnat-web", { from: ["untrust"], to: ["untrust"], dst: ["pub-web"], service: "service-https", dnat: "dmz-web", dport: 8443 }),
      nat("dnat-ssh", { from: ["untrust"], to: ["untrust"], dst: ["pub-ssh"], dnat: "dmz-ssh" }),
      nat("mail-static-bidir", { from: ["dmz"], to: ["untrust"], src: ["dmz-mail"], staticIp: "203.0.113.12", bidir: true }),
      nat("trust-out", { from: ["trust"], to: ["untrust", "isp2"], src: ["trust-net"], snatIf: "ethernet1/1", snatIp: "203.0.113.2/24" }),
    ],
    pbf: [ent("guest-via-isp2", `<from><zone>${m(["trust"])}</zone></from><source>${m(["guest-pc"])}</source><destination>${m(["any"])}</destination><service>${m(["any"])}</service><application>${m(["any"])}</application><action><forward><egress-interface>ethernet1/4</egress-interface><nexthop><ip-address>192.0.2.1</ip-address></nexthop></forward></action>`)],
  }),
});

/* 6. Panorama export: DG hierarchy + template stack with variables */
const pano = `<?xml version="1.0"?>
<config version="11.1.0" detail-version="11.1.4">
  <mgt-config><users>${ent("admin", "<phash>$5$SYNTHETIC$panoramahash</phash>")}</users><devices>${ent("013201009999", "")}</devices></mgt-config>
  <shared>
    <address>${addr("shared-dns", "ip-netmask", "10.40.0.53")}${addr("shared-bad-net", "ip-netmask", "198.18.66.0/24")}</address>
    <pre-rulebase><security><rules>${sec("shared-block-bad", { from: ["any"], to: ["any"], dst: ["shared-bad-net"], svc: ["any"], action: "deny" })}</rules></security></pre-rulebase>
    <post-rulebase><security><rules>${sec("shared-deny-log", { from: ["any"], to: ["any"], svc: ["any"], action: "deny", ruleType: "interzone" })}</rules></security></post-rulebase>
  </shared>
  <devices>${ent("localhost.localdomain", `
    <deviceconfig><system><hostname>pano-synth</hostname></system></deviceconfig>
    <device-group>
      ${ent("Branches", `<address>${addr("branch-users", "ip-netmask", "10.60.1.0/24")}</address><pre-rulebase><security><rules>${sec("branches-dns", { from: ["inside"], to: ["dc"], src: ["branch-users"], dst: ["shared-dns"], app: ["dns"] })}</rules></security></pre-rulebase>`)}
      ${ent("Branch-East", `<devices>${ent("013201009999", "")}</devices><address>${addr("east-printer", "ip-netmask", "10.60.1.50")}${addr("dc-apps", "ip-netmask", "10.40.10.0/24")}</address><service>${svc("tcp-9100", "tcp", "9100")}</service>
        <pre-rulebase><nat><rules>${nat("east-pat", { from: ["inside"], to: ["outside"], snatIf: "ethernet1/1" })}</rules></nat></pre-rulebase>
        <post-rulebase><security><rules>${sec("east-web-out", { from: ["inside"], to: ["outside"], src: ["branch-users"], app: ["ssl", "web-browsing"] })}${sec("east-to-dc-apps", { from: ["inside"], to: ["dc"], src: ["branch-users"], dst: ["dc-apps"], svc: ["service-https"] })}</rules></security></post-rulebase>`)}
    </device-group>
    <template>
      ${ent("Base-Net", `<variable>${ent("$wan-ip", "<type><ip-netmask>203.0.113.66/29</ip-netmask></type>")}</variable><config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/1", "$wan-ip"), eth("ethernet1/2", "10.60.1.1/24"), eth("ethernet1/3", "10.255.9.1/30")] })}<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2", "ethernet1/3"], [route("default", "0.0.0.0/0", { ip: "203.0.113.65" }), route("to-dc", "10.40.0.0/16", { ip: "10.255.9.2" })])}</virtual-router></network><vsys>${vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/2", "ethernet1/3"], zones: [zone("outside", "layer3", ["ethernet1/1"]), zone("inside", "layer3", ["ethernet1/2"])] })}</vsys>`)}</devices></config>`)}
      ${ent("Branch-East-Zones", `<config><devices>${ent("localhost.localdomain", `<vsys>${ent("vsys1", `<zone>${zone("dc", "layer3", ["ethernet1/3"])}</zone>`)}</vsys>`)}</devices></config>`)}
    </template>
    <template-stack>
      ${ent("Stack-East", `<templates>${m(["Branch-East-Zones", "Base-Net"])}</templates><devices>${ent("013201009999", "")}</devices>`)}
    </template-stack>
  `)}</devices>
  <readonly><devices>${ent("localhost.localdomain", `<device-group>${ent("Branches", "<id>11</id>")}${ent("Branch-East", "<id>12</id><parent-dg>Branches</parent-dg>")}</device-group>`)}</devices></readonly>
</config>
`;

const files = { "fw-single-vsys.xml": single, "fw-core-peer.xml": core, "fw-multi-vsys.xml": multi, "fw-shared-gateway.xml": sgw, "fw-dnat-pbf.xml": dnatFw, "panorama-dg-stack.xml": pano };

/* 7. Large Panorama: 67 managed firewalls (60 branches, 4 multi-vsys DC, 3 edge), DG hierarchy, stacks with per-device variables */
function bigPanorama() {
  const v = (n, val) => ent(n, `<type><ip-netmask>${val}</ip-netmask></type>`);
  const branches = [], dcs = [], edges = [];
  for (let n = 1; n <= 60; n++) branches.push({ n, serial: "0079010000" + String(n).padStart(2, "0"), host: (n <= 30 ? "br-east-" : "br-west-") + String(n).padStart(2, "0"), dc: n % 4 });
  for (let k = 0; k < 4; k++) dcs.push({ k, serial: "0079020000" + String(k).padStart(2, "0"), host: "dc-mv-" + (k + 1) });
  for (let e = 1; e <= 3; e++) edges.push({ e, serial: "0079030000" + String(e).padStart(2, "0"), host: "edge-" + e });
  const all = branches.concat(dcs, edges);
  // shared objects: lots of filler to make the file realistic in size
  let sharedAddr = addr("shared-dns", "ip-netmask", "10.200.0.53") + addr("rfc1918-10", "ip-netmask", "10.0.0.0/8") + addr("bad-net", "ip-netmask", "198.51.100.0/24");
  for (let i = 0; i < 6000; i++) sharedAddr += addr("h-filler-" + i, "ip-netmask", "172." + (16 + (i >> 12) % 16) + "." + ((i >> 4) % 256) + "." + (i % 16 + 1), i % 7 === 0 ? ["filler"] : []);
  let sharedGrp = agrp("grp-dc-nets", ["rfc1918-10"]);
  for (let i = 0; i < 300; i++) sharedGrp += agrp("grp-filler-" + i, ["h-filler-" + i, "h-filler-" + (i + 300)]);
  let sharedSvc = svc("tcp-1433", "tcp", "1433") + svc("tcp-8443", "tcp", "8443");
  for (let i = 0; i < 400; i++) sharedSvc += svc("tcp-" + (20000 + i), "tcp", String(20000 + i));
  const fillerRules = (prefix, count, from, to) => { let r = ""; for (let i = 0; i < count; i++) r += sec(prefix + "-legacy-" + i, { from, to, src: ["h-filler-" + (i * 3)], dst: ["h-filler-" + (i * 3 + 1)], svc: ["tcp-" + (20000 + (i % 400))] }); return r; };
  const dgDevs = (list, vsys) => list.map((d) => ent(d.serial, vsys ? `<vsys>${ent(vsys, "")}</vsys>` : "")).join("");
  const dgs = [
    ent("All-Sites", `<pre-rulebase><security><rules>${sec("allow-dns-to-dc", { from: ["any"], to: ["any"], dst: ["shared-dns"], app: ["dns"] })}</rules></security></pre-rulebase>`),
    ent("Branches", `<pre-rulebase><security><rules>${sec("branch-web-out", { from: ["inside"], to: ["outside"], app: ["ssl", "web-browsing"] })}${sec("branch-to-dc-https", { from: ["inside"], to: ["to-dc"], dst: ["grp-dc-nets"], svc: ["service-https"] })}</rules></security><nat><rules>${nat("branch-pat", { from: ["inside"], to: ["outside"], snatIf: "ethernet1/1" })}</rules></nat></pre-rulebase>`),
    ent("Branch-East", `<devices>${dgDevs(branches.filter((b) => b.n <= 30))}</devices><post-rulebase><security><rules>${fillerRules("east", 150, ["inside"], ["outside"])}</rules></security></post-rulebase>`),
    ent("Branch-West", `<devices>${dgDevs(branches.filter((b) => b.n > 30))}</devices><post-rulebase><security><rules>${fillerRules("west", 150, ["inside"], ["outside"])}</rules></security></post-rulebase>`),
    ent("Datacenter", `<address>${addr("dc-branch-nets", "ip-netmask", "10.100.0.0/16")}</address>`),
    ent("DC-Corp", `<devices>${dgDevs(dcs, "vsys1")}</devices><pre-rulebase><security><rules>${sec("branches-to-corp-https", { from: ["dc-transit"], to: ["corp-servers"], src: ["dc-branch-nets"], svc: ["service-https"] })}${sec("deny-to-pci", { from: ["any"], to: ["ext-to-pci"], svc: ["any"], action: "deny" })}${fillerRules("corp", 200, ["corp-servers"], ["dc-transit"])}</rules></security></pre-rulebase>`),
    ent("DC-PCI", `<devices>${dgDevs(dcs, "vsys2")}</devices><pre-rulebase><security><rules>${sec("corp-jump-to-pci", { from: ["ext-from-corp"], to: ["pci-db"], src: ["h-filler-1"], app: ["ssh"] })}${fillerRules("pci", 100, ["pci-db"], ["ext-from-corp"])}</rules></security></pre-rulebase>`),
    ent("DC-Lab", `<devices>${dgDevs(dcs, "vsys3")}</devices>`),
    ent("Internet-Edge", `<devices>${dgDevs(edges)}</devices><pre-rulebase><security><rules>${sec("edge-out", { from: ["trust"], to: ["untrust"], app: ["ssl"] })}</rules></security></pre-rulebase>`),
  ];
  const parents = { "Branches": "All-Sites", "Branch-East": "Branches", "Branch-West": "Branches", "Datacenter": "All-Sites", "DC-Corp": "Datacenter", "DC-PCI": "Datacenter", "DC-Lab": "Datacenter", "Internet-Edge": "All-Sites" };
  const roDg = Object.keys(parents).concat(["All-Sites"]).map((n, i) => ent(n, `<id>${i + 11}</id>${parents[n] ? `<parent-dg>${parents[n]}</parent-dg>` : ""}`)).join("");
  const tplBranch = ent("T-Branch-Base", `<variable>${v("$wan-ip", "198.18.0.2/30")}${v("$wan-gw", "198.18.0.1")}${v("$lan-ip", "10.100.0.1/24")}${v("$transit-ip", "10.254.0.10/24")}${v("$dc-nh", "10.254.0.1")}</variable><config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/1", "$wan-ip"), eth("ethernet1/2", "$lan-ip"), eth("ethernet1/3", "$transit-ip")] })}<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2", "ethernet1/3"], [route("default", "0.0.0.0/0", { ip: "$wan-gw" }), route("to-dc", "10.200.0.0/16", { ip: "$dc-nh" }), route("other-branches", "10.100.0.0/16", { ip: "$dc-nh" })])}</virtual-router></network><vsys>${vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/2", "ethernet1/3"], zones: [zone("outside", "layer3", ["ethernet1/1"]), zone("inside", "layer3", ["ethernet1/2"]), zone("to-dc", "layer3", ["ethernet1/3"])] })}</vsys>`)}</devices></config>`);
  const tplCommon = ent("T-Common", `<config><devices>${ent("localhost.localdomain", `<deviceconfig><system><dns-setting><servers><primary>10.200.0.53</primary></servers></dns-setting></system></deviceconfig>`)}</devices></config>`);
  const tplDc = ent("T-DC-MultiVsys", `<variable>${v("$transit-ip", "10.254.0.1/24")}${v("$corp-ip", "10.200.1.1/24")}${v("$pci-ip", "10.200.2.1/24")}${v("$lab-ip", "10.200.3.1/24")}${v("$core-gw", "10.254.0.254")}</variable><config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/1", "$transit-ip"), eth("ethernet1/5", "$lab-ip")], ae: [eth("ae1", null, [["ae1.100", "$corp-ip", 100], ["ae1.200", "$pci-ip", 200]])] })}<virtual-router>
    ${vr("vr-corp", ["ethernet1/1", "ae1.100"], [route("branches", "10.100.0.0/16", { ip: "$core-gw" }), route("dmz-nets", "172.30.0.0/16", { ip: "$core-gw" }), route("to-pci", "10.200.0.0/16", { nextVr: "vr-pci", metric: 20 })], { bgp: true })}
    ${vr("vr-pci", ["ae1.200"], [route("to-corp", "0.0.0.0/0", { nextVr: "vr-corp" })])}
    ${vr("vr-lab", ["ethernet1/5"], [route("to-corp", "0.0.0.0/0", { nextVr: "vr-corp" })])}</virtual-router></network><vsys>${
    vsys("vsys1", { display: "Corp", ifs: ["ethernet1/1", "ae1.100"], vrs: ["vr-corp"], visible: ["vsys2", "vsys3"], zones: [zone("dc-transit", "layer3", ["ethernet1/1"]), zone("corp-servers", "layer3", ["ae1.100"]), zone("ext-to-pci", "external", ["vsys2"]), zone("ext-to-lab", "external", ["vsys3"])] }) +
    vsys("vsys2", { display: "PCI", ifs: ["ae1.200"], vrs: ["vr-pci"], visible: ["vsys1"], zones: [zone("pci-db", "layer3", ["ae1.200"]), zone("ext-from-corp", "external", ["vsys1"])] }) +
    vsys("vsys3", { display: "Lab", ifs: ["ethernet1/5"], vrs: ["vr-lab"], visible: ["vsys1"], zones: [zone("lab", "layer3", ["ethernet1/5"]), zone("ext-from-corp", "external", ["vsys1"])] })}</vsys>`)}</devices></config>`);
  const tplEdge = ent("T-Edge", `<variable>${v("$out-ip", "203.0.113.2/28")}${v("$in-ip", "10.254.100.1/24")}${v("$dmz-ip", "172.30.0.1/24")}${v("$wan-ip", "10.250.0.1/30")}${v("$mpls-pe", "10.250.0.2")}</variable><config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/1", "$out-ip"), eth("ethernet1/2", "$in-ip"), eth("ethernet1/3", "$dmz-ip"), eth("ethernet1/4", "$wan-ip")] })}<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2", "ethernet1/3", "ethernet1/4"], [route("default", "0.0.0.0/0", { ip: "203.0.113.1" }), route("dc-via-mpls", "10.200.0.0/16", { ip: "$mpls-pe" })])}</virtual-router></network><vsys>${vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/2", "ethernet1/3", "ethernet1/4"], zones: [zone("untrust", "layer3", ["ethernet1/1"]), zone("trust", "layer3", ["ethernet1/2"]), zone("dmz", "layer3", ["ethernet1/3"]), zone("mpls", "layer3", ["ethernet1/4"])] })}</vsys>`)}</devices></config>`);
  const devVars = (d, vars) => ent(d.serial, `<variable>${Object.entries(vars).map(([k, x]) => v(k, x)).join("")}</variable>`);
  const stBranch = ent("S-Branch", `<templates>${m(["T-Branch-Base", "T-Common"])}</templates><devices>${branches.map((b) => devVars(b, { "$wan-ip": `198.18.${b.n}.2/30`, "$wan-gw": `198.18.${b.n}.1`, "$lan-ip": `10.100.${b.n}.1/24`, "$transit-ip": `10.254.${b.dc}.${10 + b.n}/24`, "$dc-nh": `10.254.${b.dc}.1` })).join("")}</devices>`);
  const stDc = ent("S-DC", `<templates>${m(["T-DC-MultiVsys", "T-Common"])}</templates><devices>${dcs.map((d) => devVars(d, { "$transit-ip": `10.254.${d.k}.1/24`, "$corp-ip": `10.200.${d.k * 10 + 1}.1/24`, "$pci-ip": `10.200.${d.k * 10 + 2}.1/24`, "$lab-ip": `10.200.${d.k * 10 + 3}.1/24`, "$core-gw": `10.254.${d.k}.254` })).join("")}</devices>`);
  const stEdge = ent("S-Edge", `<templates>${m(["T-Edge", "T-Common"])}</templates><devices>${edges.map((e) => devVars(e, { "$out-ip": `203.0.113.${e.e * 16 + 2}/28`, "$in-ip": `10.254.${100 + e.e}.1/24`, "$dmz-ip": `172.30.${e.e}.1/24`, "$wan-ip": `10.250.${e.e}.1/30`, "$mpls-pe": `10.250.${e.e}.2` })).join("")}</devices>`);
  const mgt = all.map((d) => ent(d.serial, `<hostname>${d.host}</hostname>`)).join("");
  return `<?xml version="1.0"?>
<config version="11.1.0" detail-version="11.1.4">
  <mgt-config><users>${ent("admin", "<phash>$5$SYNTHETIC$bigpanorama</phash>")}</users><devices>${mgt}</devices></mgt-config>
  <shared><address>${sharedAddr}</address><address-group>${sharedGrp}</address-group><service>${sharedSvc}</service>
    <pre-rulebase><security><rules>${sec("shared-block-bad", { from: ["any"], to: ["any"], dst: ["bad-net"], svc: ["any"], action: "deny" })}</rules></security></pre-rulebase>
    <post-rulebase><security><rules>${sec("shared-deny-all", { from: ["any"], to: ["any"], svc: ["any"], action: "deny", ruleType: "interzone" })}</rules></security></post-rulebase></shared>
  <devices>${ent("localhost.localdomain", `<deviceconfig><system><hostname>pano-synth-67</hostname></system></deviceconfig><device-group>${dgs.join("")}</device-group><template>${tplBranch}${tplCommon}${tplDc}${tplEdge}</template><template-stack>${stBranch}${stDc}${stEdge}</template-stack>`)}</devices>
  <readonly><devices>${ent("localhost.localdomain", `<device-group>${roDg}</device-group>`)}</devices></readonly>
</config>
`;
}
files["panorama-67-devices.xml"] = bigPanorama();
/* 8. Panorama: DMZ firewall -> MPLS routers (not in config) -> core multi-vsys firewall; plus two sites sharing a subnet (ambiguous) */
function dmzMplsCore() {
  const v = (n, val) => ent(n, `<type><ip-netmask>${val}</ip-netmask></type>`);
  const devVars = (serial, vars) => ent(serial, `<variable>${Object.entries(vars).map(([k, x]) => v(k, x)).join("")}</variable>`);
  const S = { dmz: "009901000001", core: "009902000001", site1: "009903000001", site2: "009903000002" };
  const tDmz = ent("T-DMZ", `<config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/1", "203.0.113.34/29"), eth("ethernet1/2", "172.18.10.1/24"), eth("ethernet1/3", "10.250.1.1/30")] })}<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2", "ethernet1/3"], [
    route("default", "0.0.0.0/0", { ip: "203.0.113.33" }), route("corp-via-mpls", "10.0.0.0/8", { ip: "10.250.1.2" })], { bgp: true })}</virtual-router></network><vsys>${vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/2", "ethernet1/3"], zones: [zone("internet", "layer3", ["ethernet1/1"]), zone("dmz", "layer3", ["ethernet1/2"]), zone("mpls", "layer3", ["ethernet1/3"])] })}</vsys>`)}</devices></config>`);
  const tCore = ent("T-CORE", `<config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/5", "10.250.9.1/30")], ae: [eth("ae1", null, [["ae1.100", "10.30.1.1/24", 100], ["ae1.200", "10.30.2.1/24", 200]])] })}<virtual-router>
    ${vr("vr-corp", ["ethernet1/5", "ae1.100"], [route("dmz-and-sites", "172.16.0.0/12", { ip: "10.250.9.2" }), route("sites", "10.60.0.0/16", { ip: "10.250.9.2" }), route("to-pci", "10.30.2.0/24", { nextVr: "vr-pci" })], { ospf: true })}
    ${vr("vr-pci", ["ae1.200"], [route("to-corp", "10.30.1.0/24", { nextVr: "vr-corp" })])}</virtual-router></network><vsys>${
    vsys("vsys1", { display: "Corp", ifs: ["ethernet1/5", "ae1.100"], vrs: ["vr-corp"], visible: ["vsys2"], zones: [zone("wan", "layer3", ["ethernet1/5"]), zone("corp", "layer3", ["ae1.100"]), zone("ext-to-pci", "external", ["vsys2"])] }) +
    vsys("vsys2", { display: "PCI", ifs: ["ae1.200"], vrs: ["vr-pci"], visible: ["vsys1"], zones: [zone("pci", "layer3", ["ae1.200"]), zone("ext-from-corp", "external", ["vsys1"])] })}</vsys>`)}</devices></config>`);
  const tSite = ent("T-SITE", `<variable>${v("$wan-ip", "10.250.20.1/30")}${v("$pe", "10.250.20.2")}</variable><config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/1", "$wan-ip"), eth("ethernet1/2", "10.60.5.1/24")] })}<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2"], [route("all-corp", "10.0.0.0/8", { ip: "$pe" }), route("dmz", "172.16.0.0/12", { ip: "$pe" })])}</virtual-router></network><vsys>${vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/2"], zones: [zone("wan", "layer3", ["ethernet1/1"]), zone("site-lan", "layer3", ["ethernet1/2"])] })}</vsys>`)}</devices></config>`);
  const dgs = [
    ent("DG-DMZ", `<devices>${ent(S.dmz, "")}</devices><address>${addr("dmz-web01", "ip-netmask", "172.18.10.50")}</address><pre-rulebase><security><rules>${sec("dmz-web-to-internet", { from: ["dmz"], to: ["internet"], app: ["ssl"] })}${sec("dmz-deny-mpls", { from: ["dmz"], to: ["mpls"], svc: ["any"], action: "deny" })}</rules></security></pre-rulebase>`),
    ent("DG-Core", `<address>${addr("pci-db01", "ip-netmask", "10.30.2.20")}</address>`),
    ent("DG-Core-Corp", `<devices>${ent(S.core, `<vsys>${ent("vsys1", "")}</vsys>`)}</devices><pre-rulebase><security><rules>${sec("wan-to-corp-https", { from: ["wan"], to: ["corp"], svc: ["service-https"] })}</rules></security></pre-rulebase>`),
    ent("DG-Core-PCI", `<devices>${ent(S.core, `<vsys>${ent("vsys2", "")}</vsys>`)}</devices><pre-rulebase><security><rules>${sec("pci-deny-all", { from: ["any"], to: ["pci"], svc: ["any"], action: "deny" })}</rules></security></pre-rulebase>`),
    ent("DG-Sites", `<devices>${ent(S.site1, "")}${ent(S.site2, "")}</devices>`),
  ];
  return `<?xml version="1.0"?>
<config version="11.1.0" detail-version="11.1.4">
  <mgt-config><users>${ent("admin", "<phash>$5$SYNTHETIC$mpls</phash>")}</users><devices>${ent(S.dmz, "<hostname>fw-dmz</hostname>")}${ent(S.core, "<hostname>fw-core</hostname>")}${ent(S.site1, "<hostname>fw-site1</hostname>")}${ent(S.site2, "<hostname>fw-site2</hostname>")}</devices></mgt-config>
  <shared><service>${svc("tcp-1433", "tcp", "1433")}</service></shared>
  <devices>${ent("localhost.localdomain", `<deviceconfig><system><hostname>pano-mpls</hostname></system></deviceconfig><device-group>${dgs.join("")}</device-group><template>${tDmz}${tCore}${tSite}</template><template-stack>
    ${ent("S-DMZ", `<templates>${m(["T-DMZ"])}</templates><devices>${ent(S.dmz, "")}</devices>`)}
    ${ent("S-CORE", `<templates>${m(["T-CORE"])}</templates><devices>${ent(S.core, "")}</devices>`)}
    ${ent("S-SITE", `<templates>${m(["T-SITE"])}</templates><devices>${devVars(S.site1, { "$wan-ip": "10.250.21.1/30", "$pe": "10.250.21.2" })}${devVars(S.site2, { "$wan-ip": "10.250.22.1/30", "$pe": "10.250.22.2" })}</devices>`)}
  </template-stack>`)}</devices>
  <readonly><devices>${ent("localhost.localdomain", `<device-group>${ent("DG-DMZ", "<id>11</id>")}${ent("DG-Core", "<id>12</id>")}${ent("DG-Core-Corp", "<id>13</id><parent-dg>DG-Core</parent-dg>")}${ent("DG-Core-PCI", "<id>14</id><parent-dg>DG-Core</parent-dg>")}${ent("DG-Sites", "<id>15</id>")}</device-group>`)}</devices></readonly>
</config>
`;
}
files["panorama-dmz-mpls-core.xml"] = dmzMplsCore();

/* MPLS + hub-and-spoke + DMZ -> MPLS -> multi-vsys hub -> B2B -> vendor (routers are not in any config). */
function mplsHub() {
  const v = (n, val) => ent(n, `<type><ip-netmask>${val}</ip-netmask></type>`);
  const devVars = (serial, vars) => ent(serial, `<variable>${Object.entries(vars).map(([k, x]) => v(k, x)).join("")}</variable>`);
  const S = { dmz: "011001000001", hub: "011002000001", b2b: "011003000001", vendor: "011004000001", e1: "011005000001", w1: "011005000002", lab: "011006000001", sp1: "011007000001", sp2: "011007000002" };
  const T = (name, net, vsysXml, vars = "") => ent(name, `${vars}<config><devices>${ent("localhost.localdomain", `<network>${net}</network><vsys>${vsysXml}</vsys>`)}</devices></config>`);
  const one = (zones, ifs) => vsys("vsys1", { ifs, zones });
  const tpls = [
    T("T-DMZ2", ifaces({ ethernet: [eth("ethernet1/1", "203.0.113.66/29"), eth("ethernet1/2", "172.18.10.1/24"), eth("ethernet1/3", "10.250.9.1/30")] }) +
      `<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2", "ethernet1/3"], [route("default", "0.0.0.0/0", { ip: "203.0.113.65" }), route("rfc1918-10-via-mpls", "10.0.0.0/8", { ip: "10.250.9.2" })])}</virtual-router>`,
      one([zone("internet", "layer3", ["ethernet1/1"]), zone("dmz", "layer3", ["ethernet1/2"]), zone("mpls", "layer3", ["ethernet1/3"])], ["ethernet1/1", "ethernet1/2", "ethernet1/3"])),
    T("T-HUB", ifaces({ ethernet: [eth("ethernet1/1", "10.250.0.1/29"), eth("ethernet1/7", "10.40.0.1/30")], ae: [eth("ae1", null, [["ae1.100", "10.30.1.1/24", 100], ["ae1.200", "10.30.2.1/24", 200]])], tunnel: [["tunnel.11", "169.254.11.1/30"], ["tunnel.12", "169.254.12.1/30"]] }) +
      `<virtual-router>${vr("vr-corp", ["ethernet1/1", "ae1.100", "tunnel.11", "tunnel.12"], [
        route("dmz", "172.18.0.0/16", { ip: "10.250.0.2" }), route("east-branches", "10.61.0.0/16", { ip: "10.250.0.2" }), route("west-branches", "10.62.0.0/16", { ip: "10.250.0.3" }), route("labs", "10.70.0.0/16", { ip: "10.250.0.3" }),
        route("spoke1", "10.181.0.0/16", { ip: "169.254.11.2", iface: "tunnel.11" }), route("spoke2", "10.182.0.0/16", { ip: "169.254.12.2", iface: "tunnel.12" }),
        route("to-pci", "10.30.2.0/24", { nextVr: "vr-pci" }), route("to-vendors", "10.41.0.0/16", { nextVr: "vr-pci" })], { bgp: true })}
      ${vr("vr-pci", ["ae1.200", "ethernet1/7"], [route("vendors", "10.41.0.0/16", { ip: "10.40.0.2" }), route("default-to-corp", "0.0.0.0/0", { nextVr: "vr-corp" })])}</virtual-router>`,
      vsys("vsys1", { display: "Corp", ifs: ["ethernet1/1", "ae1.100", "tunnel.11", "tunnel.12"], vrs: ["vr-corp"], visible: ["vsys2"], zones: [zone("mpls", "layer3", ["ethernet1/1"]), zone("corp", "layer3", ["ae1.100"]), zone("vpn", "layer3", ["tunnel.11", "tunnel.12"]), zone("ext-to-pci", "external", ["vsys2"])] }) +
      vsys("vsys2", { display: "PCI", ifs: ["ae1.200", "ethernet1/7"], vrs: ["vr-pci"], visible: ["vsys1"], zones: [zone("pci", "layer3", ["ae1.200"]), zone("b2b-transit", "layer3", ["ethernet1/7"]), zone("ext-from-corp", "external", ["vsys1"])] })),
    T("T-B2B", ifaces({ ethernet: [eth("ethernet1/1", "10.40.0.2/30"), eth("ethernet1/2", "10.43.0.1/30")] }) +
      `<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2"], [route("vendors", "10.41.0.0/16", { ip: "10.43.0.2" }), route("default", "0.0.0.0/0", { ip: "10.40.0.1" })])}</virtual-router>`,
      one([zone("hub", "layer3", ["ethernet1/1"]), zone("vendor", "layer3", ["ethernet1/2"])], ["ethernet1/1", "ethernet1/2"])),
    T("T-VENDOR", ifaces({ ethernet: [eth("ethernet1/1", "10.43.0.2/30"), eth("ethernet1/2", "10.41.5.1/24"), eth("ethernet1/3", "198.51.100.10/29")] }) +
      `<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2", "ethernet1/3"], [route("default", "0.0.0.0/0", { ip: "198.51.100.9" }), route("customer-10", "10.0.0.0/8", { ip: "10.43.0.1" })])}</virtual-router>`,
      one([zone("b2b", "layer3", ["ethernet1/1"]), zone("vendor-lan", "layer3", ["ethernet1/2"]), zone("internet", "layer3", ["ethernet1/3"])], ["ethernet1/1", "ethernet1/2", "ethernet1/3"])),
    T("T-MPLS-BRANCH", ifaces({ ethernet: [eth("ethernet1/1", "$wan-ip"), eth("ethernet1/2", "$lan-ip")] }) +
      `<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2"], [route("default", "0.0.0.0/0", { ip: "$pe" })])}</virtual-router>`,
      one([zone("mpls", "layer3", ["ethernet1/1"]), zone("lan", "layer3", ["ethernet1/2"])], ["ethernet1/1", "ethernet1/2"]),
      `<variable>${v("$wan-ip", "10.250.160.1/30")}${v("$lan-ip", "10.60.0.1/24")}${v("$pe", "10.250.160.2")}</variable>`),
    T("T-LAB", ifaces({ ethernet: [eth("ethernet1/1", "203.0.113.130/29"), eth("ethernet1/2", "10.250.170.1/30"), eth("ethernet1/3", "10.70.1.1/24")] }) +
      `<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2", "ethernet1/3"], [route("default", "0.0.0.0/0", { ip: "203.0.113.129" })])}</virtual-router>`,
      one([zone("internet", "layer3", ["ethernet1/1"]), zone("mpls", "layer3", ["ethernet1/2"]), zone("lab", "layer3", ["ethernet1/3"])], ["ethernet1/1", "ethernet1/2", "ethernet1/3"])),
    T("T-SPOKE", ifaces({ ethernet: [eth("ethernet1/1", "$wan-ip"), eth("ethernet1/2", "$lan-ip")], tunnel: [["tunnel.1", "$tun-ip"]] }) +
      `<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2", "tunnel.1"], [route("default", "0.0.0.0/0", { ip: "$isp" }), route("corp-via-hub", "10.0.0.0/8", { ip: "$hub-tun", iface: "tunnel.1" })])}</virtual-router>`,
      one([zone("internet", "layer3", ["ethernet1/1"]), zone("lan", "layer3", ["ethernet1/2"]), zone("vpn", "layer3", ["tunnel.1"])], ["ethernet1/1", "ethernet1/2", "tunnel.1"]),
      `<variable>${v("$wan-ip", "198.51.100.34/30")}${v("$lan-ip", "10.180.0.1/24")}${v("$tun-ip", "169.254.10.2/30")}${v("$hub-tun", "169.254.10.1")}${v("$isp", "198.51.100.33")}</variable>`),
  ];
  const stacks = [
    ent("S-DMZ2", `<templates>${m(["T-DMZ2"])}</templates><devices>${ent(S.dmz, "")}</devices>`),
    ent("S-HUB", `<templates>${m(["T-HUB"])}</templates><devices>${ent(S.hub, "")}</devices>`),
    ent("S-B2B", `<templates>${m(["T-B2B"])}</templates><devices>${ent(S.b2b, "")}</devices>`),
    ent("S-VENDOR", `<templates>${m(["T-VENDOR"])}</templates><devices>${ent(S.vendor, "")}</devices>`),
    ent("S-MPLS-BRANCH", `<templates>${m(["T-MPLS-BRANCH"])}</templates><devices>${devVars(S.e1, { "$wan-ip": "10.250.161.1/30", "$lan-ip": "10.61.1.1/24", "$pe": "10.250.161.2" })}${devVars(S.w1, { "$wan-ip": "10.250.162.1/30", "$lan-ip": "10.62.1.1/24", "$pe": "10.250.162.2" })}</devices>`),
    ent("S-LAB", `<templates>${m(["T-LAB"])}</templates><devices>${ent(S.lab, "")}</devices>`),
    ent("S-SPOKE", `<templates>${m(["T-SPOKE"])}</templates><devices>${devVars(S.sp1, { "$wan-ip": "198.51.100.34/30", "$lan-ip": "10.181.1.1/24", "$tun-ip": "169.254.11.2/30", "$hub-tun": "169.254.11.1", "$isp": "198.51.100.33" })}${devVars(S.sp2, { "$wan-ip": "198.51.100.38/30", "$lan-ip": "10.182.1.1/24", "$tun-ip": "169.254.12.2/30", "$hub-tun": "169.254.12.1", "$isp": "198.51.100.37" })}</devices>`),
  ];
  const dgs = [
    ent("DG-DMZ2", `<devices>${ent(S.dmz, "")}</devices><address>${addr("dmz-api01", "ip-netmask", "172.18.10.50")}</address><pre-rulebase><security><rules>${sec("dmz-to-internet", { from: ["dmz"], to: ["internet"], app: ["ssl", "web-browsing"] })}</rules></security></pre-rulebase>`),
    ent("DG-Hub", `<address>${addr("vendor-api", "ip-netmask", "10.41.5.20")}${addr("corp-app01", "ip-netmask", "10.30.1.20")}</address>`),
    ent("DG-Hub-Corp", `<devices>${ent(S.hub, `<vsys>${ent("vsys1", "")}</vsys>`)}</devices><pre-rulebase><security><rules>${sec("branches-to-corp-web", { from: ["mpls", "vpn"], to: ["corp"], svc: ["service-https"] })}</rules></security></pre-rulebase>`),
    ent("DG-Hub-PCI", `<devices>${ent(S.hub, `<vsys>${ent("vsys2", "")}</vsys>`)}</devices>`),
    ent("DG-B2B", `<devices>${ent(S.b2b, "")}${ent(S.vendor, "")}</devices>`),
    ent("DG-Branches", `<devices>${ent(S.e1, "")}${ent(S.w1, "")}${ent(S.lab, "")}${ent(S.sp1, "")}${ent(S.sp2, "")}</devices><pre-rulebase><security><rules>${sec("lan-out", { from: ["lan", "lab"], to: ["mpls", "vpn", "internet"] })}</rules></security></pre-rulebase>`),
  ];
  const names = { dmz: "fw-dmz2", hub: "fw-hub", b2b: "fw-b2b", vendor: "fw-vendor", e1: "fw-br-east1", w1: "fw-br-west1", lab: "fw-lab", sp1: "fw-spoke1", sp2: "fw-spoke2" };
  return `<?xml version="1.0"?>
<config version="11.1.0" detail-version="11.1.4">
  <mgt-config><users>${ent("admin", "<phash>$5$SYNTHETIC$hub</phash>")}</users><devices>${Object.entries(S).map(([k, sn]) => ent(sn, `<hostname>${names[k]}</hostname>`)).join("")}</devices></mgt-config>
  <shared><service>${svc("tcp-1433", "tcp", "1433")}</service></shared>
  <devices>${ent("localhost.localdomain", `<deviceconfig><system><hostname>pano-hub</hostname></system></deviceconfig><device-group>${dgs.join("")}</device-group><template>${tpls.join("")}</template><template-stack>${stacks.join("")}</template-stack>`)}</devices>
  <readonly><devices>${ent("localhost.localdomain", `<device-group>${ent("DG-DMZ2", "<id>21</id>")}${ent("DG-Hub", "<id>22</id>")}${ent("DG-Hub-Corp", "<id>23</id><parent-dg>DG-Hub</parent-dg>")}${ent("DG-Hub-PCI", "<id>24</id><parent-dg>DG-Hub</parent-dg>")}${ent("DG-B2B", "<id>25</id>")}${ent("DG-Branches", "<id>26</id>")}</device-group>`)}</devices></readonly>
</config>
`;
}
files["panorama-mpls-hub.xml"] = mplsHub();

/* HA pairs, an internet edge with DNAT to a DMZ, a multi-vsys MPLS hub and addresses known only from rules.
 * Synthetic estate with patterns common in large Panorama deployments (all values made up). */
function haEdge() {
  const S = { ia: "013100000001", ib: "013100000002", da: "013100000003", db: "013100000004", hub: "013100000005", xa: "013100000006", xb: "013100000007", br: "013100000008" };
  const T = (name, net, vsysXml) => ent(name, `<config><devices>${ent("localhost.localdomain", `<network>${net}</network><vsys>${vsysXml}</vsys>`)}</devices></config>`);
  const tpls = [
    T("T-INET", ifaces({ ethernet: [eth("ethernet1/1", "10.240.1.230/28"), eth("ethernet1/2", "10.240.2.5/24")] }) +
      `<virtual-router>${vr("vr-inet", ["ethernet1/1", "ethernet1/2"], [route("default", "0.0.0.0/0", { ip: "10.240.1.225" }), route("dmz-web", "10.240.3.96/27", { ip: "10.240.2.20" }), route("rfc1918", "10.0.0.0/8", { ip: "10.240.2.1" })])}</virtual-router>`,
      vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/2"], zones: [zone("untrust", "layer3", ["ethernet1/1"]), zone("trust", "layer3", ["ethernet1/2"])] })),
    T("T-DMZ", ifaces({ ethernet: [eth("ethernet1/1", "10.240.2.20/24"), eth("ethernet1/5", "10.240.3.97/27")] }) +
      `<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/5"], [route("default", "0.0.0.0/0", { ip: "10.240.2.5" }), route("rfc1918", "10.0.0.0/8", { ip: "10.240.2.1" })])}</virtual-router>`,
      vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/5"], zones: [zone("dmz_ext", "layer3", ["ethernet1/1"]), zone("web", "layer3", ["ethernet1/5"])] })),
    T("T-HUB", ifaces({ ae: [eth("ae1", null, [["ae1.921", "10.240.9.1/29", 921], ["ae1.922", "10.240.10.1/29", 922]]), eth("ae4", null, [["ae4.321", "10.240.6.2/29", 321], ["ae4.322", "10.240.7.2/29", 322]])] }) +
      `<virtual-router>${vr("vr-a", ["ae1.921", "ae4.321"], [route("branches", "10.221.0.0/16", { ip: "10.240.9.2" }), route("default", "0.0.0.0/0", { ip: "10.240.6.1" })])}${vr("vr-b", ["ae1.922", "ae4.322"], [route("branches", "10.222.0.0/16", { ip: "10.240.10.2" }), route("default", "0.0.0.0/0", { ip: "10.240.7.1" })])}</virtual-router>`,
      vsys("vsys1", { display: "VSYS_MPLS_A", ifs: ["ae1.921", "ae4.321"], vrs: ["vr-a"], zones: [zone("mpls", "layer3", ["ae1.921"]), zone("mpls_core", "layer3", ["ae4.321"])] }) +
      vsys("vsys2", { display: "VSYS_MPLS_B", ifs: ["ae1.922", "ae4.322"], vrs: ["vr-b"], zones: [zone("mpls", "layer3", ["ae1.922"]), zone("mpls_core", "layer3", ["ae4.322"])] })),
    T("T-SITEX", ifaces({ ethernet: [eth("ethernet1/1", "10.240.2.40/24"), eth("ethernet1/2", "10.240.4.1/30")] }) +
      `<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2"], [route("default", "0.0.0.0/0", { ip: "10.240.2.1" }), route("site-lans", "10.240.5.192/26", { ip: "10.240.4.2" })])}</virtual-router>`,
      vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/2"], zones: [zone("untrust", "layer3", ["ethernet1/1"]), zone("trust", "layer3", ["ethernet1/2"])] })),
    T("T-BR", ifaces({ ethernet: [eth("ethernet1/1", "10.240.8.2/30"), eth("ethernet1/2", "10.221.5.1/24")] }) +
      `<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2"], [route("default", "0.0.0.0/0", { ip: "10.240.8.1" })])}</virtual-router>`,
      vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/2"], zones: [zone("mpls", "layer3", ["ethernet1/1"]), zone("lan", "layer3", ["ethernet1/2"])] })),
  ];
  const st = (n, t, serials) => ent(n, `<templates>${m([t])}</templates><devices>${serials.map((x) => ent(x, "")).join("")}</devices>`);
  const stacks = [st("S-INET", "T-INET", [S.ia, S.ib]), st("S-DMZ", "T-DMZ", [S.da, S.db]), st("S-HUB", "T-HUB", [S.hub]), st("S-SITEX", "T-SITEX", [S.xa, S.xb]), st("S-BR", "T-BR", [S.br])];
  const dg = (n, serials, inner) => ent(n, `<devices>${serials.map((x) => ent(x, "")).join("")}</devices>${inner}`);
  const dgs = [
    ent("Global", `<address>${addr("branch-nets", "ip-netmask", "10.221.0.0/16")}${addr("branch-b-nets", "ip-netmask", "10.222.0.0/16")}${addr("web-pub", "ip-netmask", "198.51.100.10")}${addr("web-srv", "ip-netmask", "10.240.3.110")}${addr("saas", "ip-netmask", "198.51.100.128/26")}${addr("saas2", "ip-netmask", "198.51.100.192/26")}${addr("x-client", "ip-netmask", "10.240.5.140")}${addr("branch-host", "ip-netmask", "10.221.5.20")}${addr("x-server", "ip-netmask", "10.240.5.210")}</address>`),
    dg("Internet", [S.ia, S.ib], `<pre-rulebase><security><rules>${sec("web-in", { from: ["untrust"], to: ["trust"], dst: ["web-pub"], svc: ["service-https"] })}${sec("branches-to-saas", { from: ["trust"], to: ["untrust"], src: ["branch-nets"], dst: ["saas"], svc: ["service-https"] })}${sec("branches-b-to-saas", { from: ["trust"], to: ["untrust"], src: ["branch-b-nets"], dst: ["saas2"], svc: ["tcp-6500"] })}</rules></security><nat><rules>${nat("web-in-dnat", { from: ["untrust"], to: ["untrust"], dst: ["web-pub"], dnat: "web-srv" })}</rules></nat></pre-rulebase>`),
    dg("DMZ", [S.da, S.db], `<pre-rulebase><security><rules>${sec("web-allow", { from: ["dmz_ext"], to: ["web"], dst: ["web-srv"], svc: ["service-https"] })}${sec("branch-ssh-web", { from: ["dmz_ext"], to: ["web"], src: ["branch-nets"], dst: ["web-srv"], svc: ["tcp-22"] })}</rules></security></pre-rulebase>`),
    dg("Hub", [], `<pre-rulebase><security><rules>${sec("branch-out", { from: ["mpls"], to: ["mpls_core"], src: ["branch-nets", "branch-b-nets"], dst: ["saas", "saas2", "web-srv"], svc: ["any"] })}</rules></security></pre-rulebase>`),
    ent("Hub-A", `<devices>${ent(S.hub, `<vsys>${ent("vsys1", "")}${ent("vsys2", "")}</vsys>`)}</devices>`),
    dg("SiteX", [S.xa, S.xb], `<pre-rulebase><security><rules>${sec("x-client-to-server", { from: ["untrust"], to: ["trust"], src: ["x-client"], dst: ["x-server"], svc: ["service-http"] })}${sec("old-branch-to-web", { from: ["untrust"], to: ["untrust"], src: ["branch-host"], dst: ["web-srv"], svc: ["service-https"] })}</rules></security></pre-rulebase>`),
    dg("Branch", [S.br], `<pre-rulebase><security><rules>${sec("lan-out", { from: ["lan"], to: ["mpls"], src: ["branch-nets"], dst: ["saas", "web-srv"], svc: ["any"] })}</rules></security></pre-rulebase>`),
  ];
  const names = { ia: "fw-inet-a", ib: "fw-inet-b", da: "fw-dmz-a", db: "fw-dmz-b", hub: "fw-mpls-hub", xa: "fw-site-x-a", xb: "fw-site-x-b", br: "fw-branch-5" };
  return `<?xml version="1.0"?>
<config version="11.1.0" detail-version="11.1.13">
  <mgt-config><users>${ent("admin", "<phash>$5$SYNTHETIC$ha</phash>")}</users><devices>${Object.entries(S).map(([k, sn]) => ent(sn, `<hostname>${names[k]}</hostname>`)).join("")}</devices></mgt-config>
  <shared><service>${svc("tcp-22", "tcp", "22")}${svc("tcp-6500", "tcp", "6500")}</service></shared>
  <devices>${ent("localhost.localdomain", `<deviceconfig><system><hostname>pano-ha</hostname></system></deviceconfig><device-group>${dgs.join("")}</device-group><template>${tpls.join("")}</template><template-stack>${stacks.join("")}</template-stack>`)}</devices>
  <readonly><devices>${ent("localhost.localdomain", `<device-group>${ent("Global", "<id>31</id>")}${ent("Internet", "<id>32</id><parent-dg>Global</parent-dg>")}${ent("DMZ", "<id>33</id><parent-dg>Global</parent-dg>")}${ent("Hub", "<id>34</id><parent-dg>Global</parent-dg>")}${ent("Hub-A", "<id>35</id><parent-dg>Hub</parent-dg>")}${ent("SiteX", "<id>36</id><parent-dg>Global</parent-dg>")}${ent("Branch", "<id>37</id><parent-dg>Global</parent-dg>")}</device-group>`)}</devices></readonly>
</config>
`;
}
files["panorama-ha-edge.xml"] = haEdge();

/* Scale sample (generated on demand, not committed): a large synthetic Panorama.
 * 67 managed devices, 589 DGs (most unmapped), 344 templates, 322 stacks, ~480 VRs, ~20k rules, ~25k addresses.
 * Branches run BGP only to an MPLS PE (no static routes). DCs are multi-vsys without external zones. */
function bgpVr(name, ifs, routes, { localAs, rid, peers = [], redist = [], profiles = [], ospf = null, exportDeny = [] }) {
  const pg = {}; for (const p of peers) (pg[p.group] = pg[p.group] || []).push(p);
  const peerXml = Object.entries(pg).map(([g, list]) => ent(g, `<enable>yes</enable><type><${list[0].ibgp ? "ibgp" : "ebgp"}><export-nexthop>resolve</export-nexthop></${list[0].ibgp ? "ibgp" : "ebgp"}></type><peer>${list.map((p) => ent(p.name, `<enable>yes</enable><peer-as>${p.peerAs}</peer-as><local-address><interface>${p.localIf}</interface><ip>${p.localIp}</ip></local-address><peer-address><ip>${p.peerIp}</ip></peer-address>`)).join("")}</peer>`)).join("");
  const prof = profiles.map((x) => ent(x.name, `<priority>1</priority><filter><type>${m(x.types)}</type>${x.ifaces ? `<interface>${m(x.ifaces)}</interface>` : ""}${x.dests ? `<destination>${m(x.dests)}</destination>` : ""}</filter><action><redist/></action>`)).join("");
  const exp = exportDeny.length ? `<policy><export><rules>${ent("no-" + exportDeny[0].replace(/[./]/g, "_"), `<enable>yes</enable><match><address-prefix>${exportDeny.map((x) => ent(x, "<exact>no</exact>")).join("")}</address-prefix></match><action><deny/></action>`) + ent("allow-rest", "<enable>yes</enable><match/><action><allow><update/></allow></action>")}</rules></export></policy>` : "";
  const ospfXml = ospf ? `<ospf><enable>yes</enable><router-id>${rid}</router-id><area>${ent("0.0.0.0", `<type><normal/></type><interface>${ospf.ifaces.map((i) => ent(i.name, `<enable>yes</enable><passive>${i.passive ? "yes" : "no"}</passive>`)).join("")}</interface>`)}</area>${ospf.exportRules ? `<export-rules>${ospf.exportRules.map((r) => ent(r, "<new-path-type>ext-2</new-path-type>")).join("")}</export-rules>` : ""}</ospf>` : "<ospf><enable>no</enable></ospf>";
  const bgpXml = localAs ? `<bgp><enable>yes</enable><router-id>${rid}</router-id><local-as>${localAs}</local-as><peer-group>${peerXml}</peer-group><redist-rules>${redist.map((r) => ent(r, "<enable>yes</enable><address-family-identifier>ipv4</address-family-identifier>")).join("")}</redist-rules>${exp}</bgp>` : "<bgp><enable>no</enable></bgp>";
  return ent(name, `<protocol>${bgpXml}${ospfXml}<rip><enable>no</enable></rip><redist-profile>${prof}</redist-profile></protocol><interface>${m(ifs)}</interface><routing-table><ip><static-route>${routes.join("")}</static-route></ip></routing-table>`);
}
function scaleBgp() {
  const v = (n, val) => ent(n, `<type><ip-netmask>${val}</ip-netmask></type>`);
  const devVars = (serial, vars) => ent(serial, `<variable>${Object.entries(vars).map(([k, x]) => v(k, x)).join("")}</variable>`);
  const PE_AS = "65000";
  const conn = { name: "redist-connected", types: ["connect"] };
  // --- mapped templates
  const tBranch = ent("T-BR-BGP", `<variable>${v("$wan", "10.251.0.1/30")}${v("$pe", "10.251.0.2")}${v("$lan", "10.120.0.1/24")}${v("$rid", "10.251.0.1")}</variable><config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/1", "$wan"), eth("ethernet1/2", "$lan")] })}<virtual-router>${bgpVr("default", ["ethernet1/1", "ethernet1/2"], [], { localAs: "65100", rid: "$rid", peers: [{ group: "MPLS", name: "PE", peerAs: PE_AS, localIf: "ethernet1/1", localIp: "$wan", peerIp: "$pe" }], redist: ["redist-connected"], profiles: [conn] })}</virtual-router></network><vsys>${vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/2"], zones: [zone("mpls", "layer3", ["ethernet1/1"]), zone("lan", "layer3", ["ethernet1/2"])] })}</vsys>`)}</devices></config>`);
  const dc = (k, hairpinByNextVr) => ent("T-DC" + k, `<config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/1", `10.251.${200 + k}.1/30`), eth("ethernet1/4", `10.140.${k}.1/29`), eth("ethernet1/5", `10.140.${k}.2/29`), eth("ethernet1/6", `10.150.${k}.1/29`)], ae: [eth("ae1", null, [["ae1.100", `10.130.${k}.1/24`, 100], ["ae1.200", `10.131.${k}.1/24`, 200]])] })}<virtual-router>
    ${bgpVr("vr-corp", ["ethernet1/1", "ethernet1/4", "ethernet1/6", "ae1.100"], [hairpinByNextVr ? route("to-pci", `10.131.${k}.0/24`, { nextVr: "vr-pci" }) : route("to-pci", `10.131.${k}.0/24`, { ip: `10.140.${k}.2` })], { localAs: "65010", rid: `10.251.${200 + k}.1`,
      peers: [{ group: "MPLS", name: "PE", peerAs: PE_AS, localIf: "ethernet1/1", localIp: `10.251.${200 + k}.1/30`, peerIp: `10.251.${200 + k}.2` }], redist: ["dc-to-bgp"], profiles: [{ name: "dc-to-bgp", types: ["connect", "static", "ospf"], dests: ["10.0.0.0/8"] }], exportDeny: ["10.140.0.0/16"],
      ospf: { ifaces: [{ name: "ethernet1/6" }, { name: "ae1.100", passive: true }] } })}
    ${vr("vr-pci", ["ethernet1/5", "ae1.200"], [route("default", "0.0.0.0/0", { ip: `10.140.${k}.1` })])}</virtual-router></network><vsys>${
    vsys("vsys1", { display: "Corp", ifs: ["ethernet1/1", "ethernet1/4", "ethernet1/6", "ae1.100"], vrs: ["vr-corp"], zones: [zone("mpls", "layer3", ["ethernet1/1"]), zone("to-pci", "layer3", ["ethernet1/4"]), zone("ospf-core", "layer3", ["ethernet1/6"]), zone("corp", "layer3", ["ae1.100"])] }) +
    vsys("vsys2", { display: "PCI", ifs: ["ethernet1/5", "ae1.200"], vrs: ["vr-pci"], zones: [zone("from-corp", "layer3", ["ethernet1/5"]), zone("pci", "layer3", ["ae1.200"])] })}</vsys>`)}</devices></config>`);
  const tLab = ent("T-LABCORE", `<config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/1", "10.150.1.2/29"), eth("ethernet1/2", "10.151.0.1/24")] })}<virtual-router>${bgpVr("default", ["ethernet1/1", "ethernet1/2"], [], { ospf: { ifaces: [{ name: "ethernet1/1" }, { name: "ethernet1/2", passive: true }] }, rid: "10.150.1.2" })}</virtual-router></network><vsys>${vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/2"], zones: [zone("core", "layer3", ["ethernet1/1"]), zone("lab", "layer3", ["ethernet1/2"])] })}</vsys>`)}</devices></config>`);
  const tEdge = ent("T-EDGE-BGP", `<variable>${v("$wan", "10.251.250.1/30")}${v("$pe", "10.251.250.2")}${v("$dmz", "172.31.0.1/24")}${v("$isp", "203.0.113.1/30")}${v("$isp-gw", "203.0.113.2")}</variable><config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/1", "$isp"), eth("ethernet1/2", "$dmz"), eth("ethernet1/3", "$wan")] })}<virtual-router>${bgpVr("default", ["ethernet1/1", "ethernet1/2", "ethernet1/3"], [route("default", "0.0.0.0/0", { ip: "$isp-gw" })], { localAs: "65020", rid: "$pe", peers: [{ group: "MPLS", name: "PE", peerAs: PE_AS, localIf: "ethernet1/3", localIp: "$wan", peerIp: "$pe" }], redist: ["dmz-only"], profiles: [{ name: "dmz-only", types: ["connect"], ifaces: ["ethernet1/2"] }] })}</virtual-router></network><vsys>${vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/2", "ethernet1/3"], zones: [zone("internet", "layer3", ["ethernet1/1"]), zone("dmz", "layer3", ["ethernet1/2"]), zone("mpls", "layer3", ["ethernet1/3"])] })}</vsys>`)}</devices></config>`);
  const branches = []; for (let n = 1; n <= 55; n++) branches.push({ n, serial: "02100" + String(1000000 + n).slice(1) });
  const dcs = [{ k: 1, serial: "021100000001" }, { k: 2, serial: "021100000002" }];
  const edges = [1, 2, 3].map((e) => ({ e, serial: "02120000000" + e }));
  const lab = { serial: "021300000001" };
  const dgOnly = [1, 2, 3, 4, 5, 6].map((i) => ({ i, serial: "02140000000" + i }));
  const tpls = [tBranch, dc(1, false), dc(2, true), tLab, tEdge];
  const stacks = [
    ent("S-BR-BGP", `<templates>${m(["T-BR-BGP"])}</templates><devices>${branches.map((b) => devVars(b.serial, { "$wan": `10.251.${b.n}.1/30`, "$pe": `10.251.${b.n}.2`, "$lan": `10.120.${b.n}.1/24`, "$rid": `10.251.${b.n}.1` })).join("")}</devices>`),
    ...dcs.map((d) => ent("S-DC" + d.k, `<templates>${m(["T-DC" + d.k])}</templates><devices>${ent(d.serial, "")}</devices>`)),
    ent("S-LABCORE", `<templates>${m(["T-LABCORE"])}</templates><devices>${ent(lab.serial, "")}</devices>`),
    ent("S-EDGE-BGP", `<templates>${m(["T-EDGE-BGP"])}</templates><devices>${edges.map((x) => devVars(x.serial, { "$wan": `10.251.${246 + x.e}.1/30`, "$pe": `10.251.${246 + x.e}.2`, "$dmz": `172.31.${x.e}.1/24`, "$isp": `203.0.113.${x.e * 4 + 1}/30`, "$isp-gw": `203.0.113.${x.e * 4 + 2}` })).join("")}</devices>`),
  ];
  // --- unmapped legacy templates and stacks (no devices): VRs + static routes, never shown by default
  for (let t = 0; t < 339; t++) {
    const a = 16 + (t % 200), b = Math.floor(t / 200);
    const rts = []; for (let r = 0; r < 8; r++) rts.push(route("r" + r, `10.${a}.${b * 16 + r}.0/24`, { ip: `172.31.${t % 250}.254` }));
    const vrs = [vr("vr-" + t, ["ethernet1/1"], rts)]; if (t < 135) vrs.push(vr("vr-" + t + "-b", [], [route("d", "0.0.0.0/0", { nextVr: "vr-" + t })]));
    tpls.push(ent("T-OLD-" + t, `<config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/1", `172.31.${t % 250}.1/24`)] })}<virtual-router>${vrs.join("")}</virtual-router></network><vsys>${vsys("vsys1", { ifs: ["ethernet1/1"], zones: [zone("z" + t, "layer3", ["ethernet1/1"])] })}</vsys>`)}</devices></config>`));
  }
  for (let st = 0; st < 317; st++) stacks.push(ent("S-OLD-" + st, `<templates>${m(["T-OLD-" + (st % 339)])}</templates>`));
  // --- device groups: 12 mapped, 577 unmapped legacy with ~35 rules and ~40 addresses each
  const dgs = [], ro = [];
  const R = (dg, parent) => ro.push(ent(dg, `<id>${ro.length + 100}</id>${parent ? `<parent-dg>${parent}</parent-dg>` : ""}`));
  dgs.push(ent("Global", `<address>${addr("rfc1918-10", "ip-netmask", "10.0.0.0/8")}</address><pre-rulebase><security><rules>${sec("global-deny-bad", { from: ["any"], to: ["any"], dst: ["198.51.100.66"], svc: ["any"], action: "deny" })}</rules></security></pre-rulebase>`)); R("Global");
  dgs.push(ent("BR-BGP", `<devices>${branches.map((b) => ent(b.serial, "")).join("")}</devices><pre-rulebase><security><rules>${sec("lan-out", { from: ["lan"], to: ["mpls"] })}</rules></security></pre-rulebase>`)); R("BR-BGP", "Global");
  dgs.push(ent("DC-Corp", `<devices>${dcs.map((d) => ent(d.serial, `<vsys>${ent("vsys1", "")}</vsys>`)).join("")}</devices><address>${addr("corp-app", "ip-netmask", "10.130.1.20")}</address><pre-rulebase><security><rules>${sec("mpls-to-corp-web", { from: ["mpls"], to: ["corp"], svc: ["service-https"] })}</rules></security></pre-rulebase>`)); R("DC-Corp", "Global");
  dgs.push(ent("DC-PCI", `<devices>${dcs.map((d) => ent(d.serial, `<vsys>${ent("vsys2", "")}</vsys>`)).join("")}</devices>`)); R("DC-PCI", "Global");
  dgs.push(ent("DMZ-Edge", `<devices>${edges.map((x) => ent(x.serial, "")).join("")}</devices>`)); R("DMZ-Edge", "Global");
  dgs.push(ent("Lab", `<devices>${ent(lab.serial, "")}</devices>`)); R("Lab", "Global");
  dgs.push(ent("Policy-Only", `<devices>${dgOnly.map((x) => ent(x.serial, "")).join("")}</devices>`)); R("Policy-Only", "Global");
  for (let g = 0; g < 582; g++) {
    let ad = "", rl = "";
    for (let a = 0; a < 40; a++) ad += addr(`old${g}-h${a}`, "ip-netmask", `10.${16 + (g % 200)}.${a}.${(g % 250) + 1}`);
    for (let r = 0; r < 35; r++) rl += sec(`old${g}-r${r}`, { from: ["z" + (g % 339)], to: ["any"], src: [`old${g}-h${r % 40}`], dst: [`old${g}-h${(r + 7) % 40}`], svc: ["application-default"], app: ["ssl"] });
    dgs.push(ent("OLD-DG-" + g, `<devices>${ent("0999" + String(10000000 + g).slice(1), "")}${ent("0998" + String(10000000 + g).slice(1), "")}</devices><address>${ad}</address><pre-rulebase><security><rules>${rl}</rules></security></pre-rulebase>`));
    R("OLD-DG-" + g, g % 10 ? "OLD-DG-" + (g - (g % 10)) : null);
  }
  let shAddr = ""; for (let i = 0; i < 2300; i++) shAddr += addr("shared-h" + i, "ip-netmask", `172.20.${i >> 8}.${i & 255}`);
  const managed = [...branches.map((b) => [b.serial, "br-bgp-" + String(b.n).padStart(2, "0")]), ...dcs.map((d) => [d.serial, "dc-bgp-" + d.k]), ...edges.map((x) => [x.serial, "edge-bgp-" + x.e]), [lab.serial, "lab-core"], ...dgOnly.map((x) => [x.serial, "policy-only-" + x.i])];
  return `<?xml version="1.0"?>
<config version="11.1.0" detail-version="11.1.13">
  <mgt-config><users>${ent("admin", "<phash>$5$SYNTHETIC$scale</phash>")}</users><devices>${managed.map(([sn, hn]) => ent(sn, `<hostname>${hn}</hostname>`)).join("")}</devices></mgt-config>
  <shared><address>${shAddr}</address><service>${svc("tcp-1433", "tcp", "1433")}</service></shared>
  <devices>${ent("localhost.localdomain", `<deviceconfig><system><hostname>pano-scale</hostname></system></deviceconfig><device-group>${dgs.join("")}</device-group><template>${tpls.join("")}</template><template-stack>${stacks.join("")}</template-stack>`)}</devices>
  <readonly><devices>${ent("localhost.localdomain", `<device-group>${ro.join("")}</device-group>`)}</devices></readonly>
</config>
`;
}
if (process.argv.includes("--scale") || process.argv.includes("--all")) {
  fs.mkdirSync(path.join(OUT, "_gen"), { recursive: true });
  const x = scaleBgp(); fs.writeFileSync(path.join(OUT, "_gen", "panorama-scale-bgp.xml"), x); console.log("wrote _gen/panorama-scale-bgp.xml", x.length);
}

/* 10. Panorama: internet edge with inbound destination NAT in front of a DMZ firewall that sees only private addresses.
   Covers: NAT from parent/child device groups (pre and post), port translation, proxy-ARP public block, NAT on the
   interface address, to-interface, bi-directional static NAT, U-turn NAT, FQDN translated address. */
function inboundNat() {
  const S = { edge: "009905000001", dmz: "009905000002", partner: "009905000003", spare: "009905000009" };
  const tEdge = ent("T-INET", `<config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/1", "203.0.113.2/28"), eth("ethernet1/2", "10.60.0.1/30"), eth("ethernet1/3", "10.61.0.1/24")] })}<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2", "ethernet1/3"], [
    route("default", "0.0.0.0/0", { ip: "203.0.113.1" }), route("dmz-nets", "172.20.0.0/16", { ip: "10.60.0.2" })])}</virtual-router></network><vsys>${vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/2", "ethernet1/3"], zones: [zone("untrust", "layer3", ["ethernet1/1"]), zone("to-dmz", "layer3", ["ethernet1/2"]), zone("trust", "layer3", ["ethernet1/3"])] })}</vsys>`)}</devices></config>`);
  const tDmz = ent("T-DMZFW", `<config><devices>${ent("localhost.localdomain", `<network>${ifaces({ ethernet: [eth("ethernet1/1", "10.60.0.2/30"), eth("ethernet1/2", "172.20.1.1/24"), eth("ethernet1/3", "172.20.2.1/24")] })}<virtual-router>${vr("default", ["ethernet1/1", "ethernet1/2", "ethernet1/3"], [
    route("default", "0.0.0.0/0", { ip: "10.60.0.1" })])}</virtual-router></network><vsys>${vsys("vsys1", { ifs: ["ethernet1/1", "ethernet1/2", "ethernet1/3"], zones: [zone("outside", "layer3", ["ethernet1/1"]), zone("web", "layer3", ["ethernet1/2"]), zone("app", "layer3", ["ethernet1/3"])] })}</vsys>`)}</devices></config>`);
  const pub = [addr("pub-web", "ip-netmask", "203.0.113.10"), addr("pub-mail", "ip-netmask", "203.0.113.12"), addr("pub-toif", "ip-netmask", "203.0.113.13"), addr("pub-cdn", "ip-netmask", "203.0.113.14"), addr("fw-out-ip", "ip-netmask", "203.0.113.2"), addr("pub-sftp", "ip-netmask", "198.51.100.5"),
    addr("web01", "ip-netmask", "172.20.1.10"), addr("mail01", "ip-netmask", "172.20.1.25"), addr("app-ssh", "ip-netmask", "172.20.2.20"), addr("app-http", "ip-netmask", "172.20.2.30"), addr("app-toif", "ip-netmask", "172.20.2.40"), addr("cdn-origin", "fqdn", "origin.example.com"), addr("inside-users", "ip-netmask", "10.61.0.0/24")].join("");
  const dgs = [
    ent("DG-Inbound", `<address>${pub}</address><service>${svc("tcp-2222", "tcp", "2222")}${svc("tcp-22", "tcp", "22")}${svc("tcp-25", "tcp", "25")}${svc("tcp-8080", "tcp", "8080")}${svc("tcp-80", "tcp", "80")}</service>
      <pre-rulebase><nat><rules>${nat("nat-web", { from: ["untrust"], to: ["untrust"], dst: ["pub-web"], service: "service-https", dnat: "web01" })}</rules></nat></pre-rulebase>`),
    ent("DG-Edge", `<devices>${ent(S.edge, "")}</devices><pre-rulebase><nat><rules>${
      nat("uturn-web", { from: ["trust"], to: ["untrust"], src: ["inside-users"], dst: ["pub-web"], dnat: "web01", snatIf: "ethernet1/3" }) +
      nat("mail-bidir", { from: ["to-dmz"], to: ["untrust"], src: ["mail01"], staticIp: "pub-mail", bidir: true }) +
      nat("ifip-http", { from: ["untrust"], to: ["untrust"], dst: ["fw-out-ip"], service: "tcp-8080", dnat: "app-http", dport: 80 }) +
      nat("toif-app", { from: ["untrust"], to: ["untrust"], dst: ["pub-toif"], dnat: "app-toif", toIf: "ethernet1/1" }) +
      nat("cdn-fqdn", { from: ["untrust"], to: ["untrust"], dst: ["pub-cdn"], dnat: "cdn-origin" }) +
      nat("inside-out", { from: ["trust"], to: ["untrust"], src: ["inside-users"], snatIf: "ethernet1/1" })}</rules></nat><security><rules>${
      sec("in-web", { from: ["untrust"], to: ["to-dmz"], dst: ["pub-web"], svc: ["service-https"] }) +
      sec("in-sftp", { from: ["untrust"], to: ["to-dmz"], dst: ["pub-sftp"], svc: ["tcp-2222"] }) +
      sec("in-mail", { from: ["untrust"], to: ["to-dmz"], dst: ["pub-mail"], svc: ["tcp-25"] }) +
      sec("in-ifip", { from: ["untrust"], to: ["to-dmz"], dst: ["fw-out-ip"], svc: ["tcp-8080"] }) +
      sec("in-toif", { from: ["untrust"], to: ["to-dmz"], dst: ["pub-toif"], svc: ["service-https"] }) +
      sec("uturn-web-allow", { from: ["trust"], to: ["to-dmz"], src: ["inside-users"], dst: ["pub-web"], svc: ["service-https"] }) +
      sec("inside-out", { from: ["trust"], to: ["untrust"], src: ["inside-users"], svc: ["service-https"] })}</rules></security></pre-rulebase>
      <post-rulebase><nat><rules>${nat("sftp-proxyarp", { from: ["untrust"], to: ["untrust"], dst: ["pub-sftp"], service: "tcp-2222", dnat: "app-ssh", dport: 22 })}</rules></nat></post-rulebase>`),
    ent("DG-Partner", `<devices>${ent(S.partner, "")}${ent(S.spare, "")}</devices>`), // policy-only firewall (no template stack) and a serial Panorama does not manage
    ent("DG-Lab", ""),
    ent("DG-DMZFW", `<devices>${ent(S.dmz, "")}</devices><address>${addr("web01", "ip-netmask", "172.20.1.10")}${addr("mail01", "ip-netmask", "172.20.1.25")}${addr("app-ssh", "ip-netmask", "172.20.2.20")}${addr("app-http", "ip-netmask", "172.20.2.30")}${addr("app-toif", "ip-netmask", "172.20.2.40")}</address>
      <service>${svc("tcp-22", "tcp", "22")}${svc("tcp-25", "tcp", "25")}${svc("tcp-80", "tcp", "80")}</service><pre-rulebase><security><rules>${
      sec("dmz-web", { from: ["outside"], to: ["web"], dst: ["web01"], svc: ["service-https"] }) +
      sec("dmz-mail", { from: ["outside"], to: ["web"], dst: ["mail01"], svc: ["tcp-25"] }) +
      sec("dmz-ssh", { from: ["outside"], to: ["app"], dst: ["app-ssh"], svc: ["tcp-22"] }) +
      sec("dmz-http", { from: ["outside"], to: ["app"], dst: ["app-http", "app-toif"], svc: ["tcp-80", "service-https"] })}</rules></security></pre-rulebase>`),
  ];
  return `<?xml version="1.0"?>
<config version="11.1.0" detail-version="11.1.4">
  <mgt-config><users>${ent("admin", "<phash>$5$SYNTHETIC$inbound</phash>")}</users><devices>${ent(S.edge, "<hostname>fw-inet</hostname>")}${ent(S.dmz, "<hostname>fw-dmz</hostname>")}${ent(S.partner, "<hostname>fw-partner</hostname>")}</devices></mgt-config>
  <shared></shared>
  <devices>${ent("localhost.localdomain", `<deviceconfig><system><hostname>pano-inbound</hostname></system></deviceconfig><device-group>${dgs.join("")}</device-group><template>${tEdge}${tDmz}${ent("T-Lab-Unused", "<config><devices></devices></config>")}</template><template-stack>
    ${ent("S-INET", `<templates>${m(["T-INET"])}</templates><devices>${ent(S.edge, "")}</devices>`)}
    ${ent("S-DMZFW", `<templates>${m(["T-DMZFW"])}</templates><devices>${ent(S.dmz, "")}</devices>`)}
  </template-stack>`)}</devices>
  <readonly><devices>${ent("localhost.localdomain", `<device-group>${ent("DG-Inbound", "<id>21</id>")}${ent("DG-Edge", "<id>22</id><parent-dg>DG-Inbound</parent-dg>")}${ent("DG-DMZFW", "<id>23</id><parent-dg>DG-Inbound</parent-dg>")}${ent("DG-Partner", "<id>24</id><parent-dg>DG-Inbound</parent-dg>")}${ent("DG-Lab", "<id>25</id>")}</device-group>`)}</devices></readonly>
</config>
`;
}
files["panorama-inbound-nat.xml"] = inboundNat();
for (const [n, x] of Object.entries(files)) { fs.writeFileSync(path.join(OUT, n), x); console.log("wrote", n, x.length); }
