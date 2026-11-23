#!/usr/bin/env node
/* SPDX-License-Identifier: Apache-2.0 */
/* Synthetic sample for the site-role / scope feature: one Panorama export (two copies, as exported from each peer of a Panorama HA pair)
 * managing production, DR, lab and unclassified firewalls. All names, addresses and serials are made up. Run: node samples/generate_scope.mjs
 *
 *   dc1-prod-fw01 (P1) and dc2-dr-fw01 (D1): cloned builds. wan link 10.200.0.0/30, lan 10.10.1.0/24 (P1) / 10.20.1.0/24 (D1),
 *       both carry 10.250.0.2/29 toward hq-fw01 (a shared address on purpose).
 *   dc1-prod-fw02 (P2) and dc2-dr-fw02 (D2): both in the ONE device group DG-COMMON, so a rule pushed there reaches both.
 *   lab-fw01 (lab) and hq-fw01 (no role words at all: stays Other). */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const DIR = path.dirname(fileURLToPath(import.meta.url));
const W = (n, s) => { fs.writeFileSync(path.join(DIR, n), s); console.log("wrote samples/" + n, s.length, "bytes"); };
const m = (xs) => xs.map((x) => "<member>" + x + "</member>").join("");
const eth = (list) => "<ethernet>" + list.map(([n, ip]) => '<entry name="' + n + '"><layer3><ip><entry name="' + ip + '"/></ip></layer3></entry>').join("") + "</ethernet>";
const zones = (z) => "<zone>" + Object.entries(z).map(([n, ifs]) => '<entry name="' + n + '"><network><layer3>' + m(ifs) + "</layer3></network></entry>").join("") + "</zone>";
const rule = (name, from, to, src, dst, svc, action) => '<entry name="' + name + '"><from>' + m(from) + "</from><to>" + m(to) + "</to><source>" + m(src) + "</source><destination>" + m(dst) + "</destination><source-user>" + m(["any"]) + "</source-user><category>" + m(["any"]) + "</category><application>" + m(["any"]) + "</application><service>" + m([svc || "any"]) + "</service><action>" + (action || "allow") + "</action></entry>";
const vsys = (ifs, z, rules) => '<vsys><entry name="vsys1"><import><network><interface>' + m(ifs) + "</interface></network></import>" + zones(z) + "<rulebase><security><rules>" + rules.join("") + "</rules></security><nat><rules/></nat></rulebase></entry></vsys>";
const sr = (name, dst, nh) => '<entry name="' + name + '"><destination>' + dst + "</destination><nexthop><ip-address>" + nh + "</ip-address></nexthop><metric>10</metric></entry>";
const host = (h) => "<deviceconfig><system><hostname>" + h + "</hostname></system></deviceconfig>";
const tplH = (name, net, vs, h) => '<entry name="' + name + '"><config><devices><entry name="localhost.localdomain"><network>' + net + "</network>" + host(h) + vs + "</entry></devices></config></entry>";
const net = (ifs, statics) => "<interface>" + eth(ifs) + '</interface><virtual-router><entry name="default"><interface>' + m(ifs.map((x) => x[0])) + '</interface><routing-table><ip><static-route>' + statics + "</static-route></ip></routing-table></entry></virtual-router>";
const vs = (ifs, z, rules) => vsys(ifs.map((x) => x[0]), z, rules);
const dgE = (name, serials, rules) => '<entry name="' + name + '"><devices>' + serials.map((s) => '<entry name="' + s + '"/>').join("") + "</devices><pre-rulebase><security><rules>" + rules.join("") + "</rules></security></pre-rulebase></entry>";
const stackE = (name, tpls, serial) => '<entry name="' + name + '"><templates>' + m(tpls) + '</templates><devices><entry name="' + serial + '"/></devices></entry>';
const SER = { p1: "009970000001", p2: "009970000002", d1: "009970000003", d2: "009970000004", lab: "009970000005", hq: "009970000006" };

const p1If = [["ethernet1/1", "10.200.0.1/30"], ["ethernet1/2", "10.10.1.1/24"], ["ethernet1/3", "203.0.113.2/24"], ["ethernet1/4", "10.250.0.2/29"]];
const d1If = [["ethernet1/1", "10.200.0.2/30"], ["ethernet1/2", "10.20.1.1/24"], ["ethernet1/3", "192.0.2.10/24"], ["ethernet1/4", "10.250.0.2/29"]];
const z1 = { wan: ["ethernet1/1"], lan: ["ethernet1/2"], untrust: ["ethernet1/3"], core: ["ethernet1/4"] };
const p2If = [["ethernet1/1", "192.0.2.2/24"], ["ethernet1/2", "10.11.1.1/24"]];
const d2If = [["ethernet1/1", "198.18.0.2/24"], ["ethernet1/2", "10.21.1.1/24"]];
const z2 = { untrust: ["ethernet1/1"], lan: ["ethernet1/2"] };
const hqIf = [["ethernet1/1", "10.250.0.1/29"], ["ethernet1/2", "10.30.1.1/24"]];
const labIf = [["ethernet1/1", "10.60.0.1/24"]];

const tpls =
  tplH("T-DC1-PROD", net(p1If, sr("to-dr-lan", "10.20.0.0/16", "10.200.0.2") + sr("default", "0.0.0.0/0", "203.0.113.1")), vs(p1If, z1, []), "dc1-prod-fw01") +
  tplH("T-DC2-DR", net(d1If, sr("to-prod-lan", "10.10.0.0/16", "10.200.0.1") + sr("default", "0.0.0.0/0", "192.0.2.1")), vs(d1If, z1, []), "dc2-dr-fw01") +
  tplH("T-DC1-PROD-2", net(p2If, sr("default", "0.0.0.0/0", "192.0.2.1")), vs(p2If, z2, []), "dc1-prod-fw02") +
  tplH("T-DC2-DR-2", net(d2If, sr("default", "0.0.0.0/0", "198.18.0.1")), vs(d2If, z2, []), "dc2-dr-fw02") +
  tplH("T-HQ", net(hqIf, sr("to-dc", "10.10.0.0/16", "10.250.0.2")), vs(hqIf, { core: ["ethernet1/1"], lan: ["ethernet1/2"] }, []), "hq-fw01") +
  tplH("T-LAB", net(labIf, ""), vs(labIf, { lan: ["ethernet1/1"] }, []), "lab-fw01");
const stacks = stackE("ST-DC1-PROD", ["T-DC1-PROD"], SER.p1) + stackE("ST-DC2-DR", ["T-DC2-DR"], SER.d1) + stackE("ST-DC1-PROD-2", ["T-DC1-PROD-2"], SER.p2) +
  stackE("ST-DC2-DR-2", ["T-DC2-DR-2"], SER.d2) + stackE("ST-HQ", ["T-HQ"], SER.hq) + stackE("ST-LAB", ["T-LAB"], SER.lab);
const dgs =
  dgE("DG-DC1-PROD", [SER.p1], [rule("p-lan-wan", ["lan"], ["wan"], ["any"], ["any"], "any"), rule("p-core-lan", ["core"], ["lan"], ["10.30.1.0/24"], ["10.10.1.0/24"], "service-https")]) +
  dgE("DG-DC2-DR", [SER.d1], [rule("d-lan-wan", ["lan"], ["wan"], ["any"], ["any"], "any"), rule("d-wan-lan", ["wan"], ["lan"], ["any"], ["any"], "any"), rule("d-core-lan", ["core"], ["lan"], ["10.30.1.0/24"], ["10.20.1.0/24"], "service-https")]) +
  dgE("DG-COMMON", [SER.p2, SER.d2], [rule("c-lan-untrust", ["lan"], ["untrust"], ["any"], ["any"], "any")]) +
  dgE("DG-HQ", [SER.hq], [rule("hq-lan-core", ["lan"], ["core"], ["any"], ["any"], "any")]) +
  dgE("DG-LAB", [SER.lab], []);
/* One Panorama export per peer: identical firewalls, policy and templates; only the Panorama's own hostname and HA settings differ. */
const pano = (hostName, ownIp, peerIp, prio) => '<?xml version="1.0"?>\n<config version="11.1.0" detail-version="11.1.4">\n  <mgt-config><devices>' + Object.values(SER).map((s) => '<entry name="' + s + '"/>').join("") + "</devices></mgt-config>\n  <shared/>\n  <devices><entry name=\"localhost.localdomain\"><deviceconfig><system><hostname>" + hostName + "</hostname></system><high-availability><enabled>yes</enabled><interface><ha1><ip-address>" + ownIp + "/24</ip-address></ha1></interface><group><peer-ip>" + peerIp + "</peer-ip><election-option><priority>" + prio + "</priority><preemptive>yes</preemptive></election-option><mode><active-passive/></mode></group></high-availability></deviceconfig><device-group>" + dgs + "</device-group><template>" + tpls + "</template><template-stack>" + stacks + "</template-stack></entry></devices>\n</config>\n";
W("panorama-prod-dr-a.xml", pano("pano-dc1-prod-01", "10.1.250.1", "10.2.250.1", "primary"));
W("panorama-prod-dr-b.xml", pano("pano-dc2-dr-01", "10.2.250.1", "10.1.250.1", "secondary"));
