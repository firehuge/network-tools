#!/usr/bin/env node
/* SPDX-License-Identifier: Apache-2.0 */
// Unit tests for build/core.js against the synthetic bundles in samples/.
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const PPU = require(path.join(ROOT, "build/core.js"));
const CAT = JSON.parse(fs.readFileSync(path.join(ROOT, "catalog/models.json"), "utf8"));
const NOW = new Date("2026-11-27T12:00:00Z");
const IDX = PPU.catalogIndex(CAT, NOW);
const XML = {
  parse(s) {
    const errs = [];
    const d = new DOMParser({ onError: (lvl, msg) => { if (lvl !== "warning") errs.push(msg); } }).parseFromString(s, "text/xml");
    if (errs.length) throw new Error(errs[0]);
    return d;
  },
  serialize(d) { return new XMLSerializer().serializeToString(d); }
};

let failed = 0, passed = 0;
function ok(c, msg) { if (c) { passed++; } else { failed++; console.error("  FAIL:", msg); } }
function eq(a, b, msg) { ok(a === b, msg + " (got " + JSON.stringify(a) + ", want " + JSON.stringify(b) + ")"); }
function section(name) { console.log("--", name); }

function untgz(file) {
  const buf = zlib.gunzipSync(fs.readFileSync(file));
  const out = [];
  let off = 0;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every(b => b === 0)) break;
    const name = h.subarray(0, 100).toString().replace(/\0.*$/s, "");
    const size = parseInt(h.subarray(124, 136).toString().replace(/\0.*$/s, "").trim() || "0", 8);
    const data = buf.subarray(off + 512, off + 512 + size);
    out.push({ name, size, text: data.toString("utf8") });
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}
const load = n => PPU.analyzeTsf(untgz(path.join(ROOT, "samples", n)), XML, { now: NOW });

/* ---------------- parsing ---------------- */
section("parse PA-3220 HA bundle");
const A = load("techsupport_pa3220-ha.tgz");
eq(A.system.model, "PA-3220", "model");
eq(A.system.swVersion, "10.2.10", "PAN-OS");
eq(A.licenses.length, 7, "license entries");
ok(A.licenses.find(l => l.feature === "SD WAN").expired, "SD-WAN expired");
ok(A.ha.enabled && A.ha.peerModel === "PA-3220", "HA peer detected");
eq(A.ha.ports.ha1, "ha1-a", "HA1 port from config");
ok(A.dp && A.dp.samples === 120, "dp-monitor samples from current + rotated log (" + (A.dp && A.dp.samples) + ")");
ok(A.dp.sessions.max > 150000, "peak sessions above base");
eq(A.session.allocated, 141234, "session snapshot");
eq(A.vsysInUse, 1, "one vsys");
ok(A.config.panorama && A.config.panorama.servers[0] === "10.10.0.50", "Panorama server");
const e17 = A.interfaces.find(r => r.name === "ethernet1/17");
eq(e17.media, "sfp+", "ethernet1/17 media");
eq(e17.runtimeSpeed, 10000, "ethernet1/17 speed");
ok(e17.avgUtilPct > 0, "avg utilization computed");
eq(A.config.certsWithKeys, 1, "cert with private key counted");
ok(A.pushedConfig, "Panorama pushed config detected");

/* ---------------- sizing ---------------- */
section("recommendation");
const R = PPU.deriveRequirements(A, IDX, { headroomPct: 30 });
ok(R.useThreat, "threat throughput used because TP is licensed");
eq(R.vsys, 1, "vsys need");
ok(R.ha, "HA carried over");
const rec = PPU.recommend(A, IDX, R, {});
ok(rec.top, "a model fits");
console.log("   top:", rec.top && rec.top.model, "alt:", rec.alt && rec.alt.model, "vm:", rec.vm.fit && rec.vm.fit.model);
ok(!rec.fits.some(e => e.m.lifecycle === "end-of-sale"), "no end-of-sale models recommended");
ok(rec.top.m.tp_bps >= R.throughputBps, "top meets throughput");
ok(rec.top.m.max_sessions >= R.sessions, "top meets sessions");
const smaller = rec.evals.filter(e => e.ok && e.m.lifecycle === rec.top.m.lifecycle && (e.m.fw_bps || 0) < rec.top.m.fw_bps);
eq(smaller.length, 0, "no smaller fitting model was skipped (no overselling)");
const e440 = rec.evals.find(e => e.model === "PA-440");
ok(e440 && !e440.ok && e440.reasons.length, "PA-440 rejected with reasons");

/* ---------------- licenses ---------------- */
section("licenses");
const LP = PPU.licensePlan(A, rec.top.m, R);
eq(LP.qty, 2, "HA pair quantity");
const carry = LP.carry.map(l => l.name).sort();
ok(carry.includes("Threat Prevention") && carry.includes("URL Filtering") && carry.includes("WildFire") && carry.includes("DNS Security") && carry.includes("GlobalProtect") && carry.includes("Support"), "carry-forward list " + carry.join(","));
ok(LP.lapsed.some(l => l.name === "SD-WAN"), "SD-WAN listed as lapsed, not quoted");

section("multi-vsys PA-5220");
const B = load("techsupport_pa5220-multivsys.tgz");
eq(B.vsysInUse, 3, "3 vsys in use");
eq(B.vsysLicensed, 5, "vsys license count");
const RB = PPU.deriveRequirements(B, IDX, { headroomPct: 30 });
const pa3410 = PPU.findModel(IDX, "PA-3410");
const LB = PPU.licensePlan(B, pa3410, RB);
ok(LB.vsys && LB.vsys.extra === 2, "PA-3410 base 1 vsys -> license 2 more");
const pa5410 = PPU.findModel(IDX, "PA-5410");
const LB2 = PPU.licensePlan(B, pa5410, RB);
ok(LB2.vsys && LB2.vsys.extra === 0, "PA-5410 base 10 vsys covers 3");
const recB = PPU.recommend(B, IDX, RB, {});
ok(recB.evals.find(e => e.model === "PA-440").reasons.some(r => /virtual systems/.test(r)), "PA-440 rejected for vsys count");
ok(recB.vm.multiVsys && recB.vm.vcpu >= 16, "VM sizing bumps to 16 vCPU for multi-vsys");

section("small PA-820 without dp-monitor");
const C = load("techsupport_pa820-small.tgz");
ok(!C.dp, "no dp-monitor");
ok(C.missing.some(m => /dp-monitor/.test(m)), "missing metrics flagged");
const RC = PPU.deriveRequirements(C, IDX, {});
ok(/snapshot/.test(RC.observed.sessionsSource), "session source labelled as snapshot");
const recC = PPU.recommend(C, IDX, RC, {});
ok(recC.top, "PA-820 gets a recommendation: " + (recC.top && recC.top.model));
ok(PPU.findModel(IDX, "PA-820").lifecycle === "current" ? false : true, "PA-820 is not current");

/* ---------------- conversion ---------------- */
section("convert PA-3220 -> PA-1410 (every reference)");
const xml = A.configText;
const tgt = PPU.findModel(IDX, "PA-1410");
const tports = PPU.portList(tgt);
const map = {
  "ethernet1/1": "ethernet1/9", "ethernet1/2": "ethernet1/10", "ethernet1/3": "ethernet1/13", "ethernet1/4": "ethernet1/14",
  "ethernet1/5": "ethernet1/1", "ethernet1/6": "ethernet1/2", "ethernet1/7": "ethernet1/3", "ethernet1/8": "ethernet1/4",
  "ethernet1/17": "ethernet1/19", "ethernet1/18": "ethernet1/15"
};
const res = PPU.convertConfig(xml, XML, { map, haPortMap: { "ha1-a": "ethernet1/5", "ha1-b": "ethernet1/6" }, target: tgt, targetPorts: tports, ha: true, hostname: "NEW-PA1410-A" });
const out = XML.parse(res.xml);
const segs = xp => { const r = []; let cur = "", br = 0; for (const ch of xp) { if (ch === "[") br++; if (ch === "]") br--; if (ch === "/" && !br) { if (cur) r.push(cur); cur = ""; } else cur += ch; } if (cur) r.push(cur); return r; };
const get = xp => {
  let cur = null;
  for (const seg of segs(xp)) {
    const m = seg.match(/^([\w\-.]+)(?:\[@name='([^']+)'\])?$/);
    const match = k => k.nodeType === 1 && k.nodeName === m[1] && (m[2] == null || k.getAttribute("name") === m[2]);
    if (cur === null) { cur = match(out.documentElement) ? [out.documentElement] : []; continue; }
    const next = [];
    for (const c of cur) for (let k = c.firstChild; k; k = k.nextSibling) if (match(k)) next.push(k);
    cur = next;
  }
  return cur || [];
};
const D = "/config/devices/entry[@name='localhost.localdomain']";
const V = D + "/vsys/entry[@name='vsys1']";
const VR = D + "/network/virtual-router/entry[@name='default']";
const T = xp => (get(xp)[0] && get(xp)[0].textContent.trim());
const has = xp => get(xp).length > 0;
const memb = xp => get(xp).flatMap(e => [...e.childNodes].filter(n => n.nodeType === 1).map(n => n.textContent.trim()));
ok(has(D + "/network/interface/ethernet/entry[@name='ethernet1/9']"), "ethernet entry renamed");
ok(!has(D + "/network/interface/ethernet/entry[@name='ethernet1/17']"), "old entry gone");
ok(has(D + "/network/interface/ethernet/entry[@name='ethernet1/10']/layer3/units/entry[@name='ethernet1/10.10']"), "subinterface renamed with suffix");
eq(T(D + "/network/interface/ethernet/entry[@name='ethernet1/13']/aggregate-group"), "ae1", "aggregate member keeps ae1");
eq(T(VR + "/routing-table/ip/static-route/entry[@name='default-isp-a']/interface"), "ethernet1/9", "static route interface");
eq(T(VR + "/routing-table/ip/static-route/entry[@name='default-isp-a']/nexthop/ip-address"), "203.0.113.9", "static route nexthop IP unchanged");
eq(T(VR + "/routing-table/ip/static-route/entry[@name='inside-net']/interface"), "ethernet1/10.10", "static route on subinterface");
ok(memb(VR + "/interface").includes("ethernet1/19") && !memb(VR + "/interface").includes("ethernet1/17"), "virtual router members");
eq(T(VR + "/protocol/bgp/peer-group/entry[@name='core']/peer/entry[@name='core-sw']/local-address/interface"), "ethernet1/10.10", "BGP local-address interface");
ok(has(VR + "/protocol/ospfv3/area/entry[@name='0.0.0.0']/interface/entry[@name='ethernet1/19']"), "OSPFv3 interface entry");
ok(has(VR + "/protocol/rip/interface/entry[@name='ethernet1/15']"), "RIP interface entry");
ok(has(VR + "/protocol/ospf/area/entry[@name='0.0.0.0']/interface/entry[@name='ae1.50']"), "OSPF on ae untouched");
eq(T(D + "/network/virtual-wire/entry[@name='vw-inline']/interface1"), "ethernet1/1", "vwire interface1");
eq(T(D + "/network/virtual-wire/entry[@name='vw-inline']/interface2"), "ethernet1/2", "vwire interface2");
ok(memb(D + "/network/vlan/entry[@name='lab-vlan']/interface").includes("ethernet1/3.100"), "VLAN member subinterface");
eq(T(D + "/network/ike/gateway/entry[@name='gw-branch']/local-address/interface"), "ethernet1/9", "IKE gateway local interface");
ok(has(D + "/network/dhcp/interface/entry[@name='ethernet1/10.20']"), "DHCP server interface");
ok(memb(D + "/network/dns-proxy/entry[@name='inside-dns']/interface").join(",") === "ethernet1/10.10,ethernet1/10.20", "DNS proxy interfaces");
ok(has(D + "/network/qos/interface/entry[@name='ethernet1/9']"), "QoS interface");
eq(T(D + "/deviceconfig/system/route/service/entry[@name='dns']/source/interface"), "ethernet1/10.10", "service route source");
eq(T(D + "/deviceconfig/system/route/destination/entry[@name='10.50.0.10']/source/interface"), "ethernet1/19", "destination service route");
eq(T(D + "/deviceconfig/system/route/service/entry[@name='snmp']/source/interface"), "loopback.1", "loopback service route untouched");
ok(memb(D + "/deviceconfig/high-availability/group/monitoring/link-monitoring/link-group/entry[@name='uplinks']/interface").join(",") === "ethernet1/9,ethernet1/10", "HA link monitoring");
eq(T(D + "/deviceconfig/high-availability/interface/ha2-backup/port"), "ethernet1/4", "HA2 backup dataplane port");
eq(T(D + "/deviceconfig/high-availability/interface/ha1/port"), "ethernet1/5", "HA1 moved to dataplane port");
eq(T(D + "/deviceconfig/high-availability/interface/ha2/port"), "hsci", "HSCI kept (target has HSCI)");
ok(memb(V + "/zone/entry[@name='untrust']/network/layer3").join(",") === "ethernet1/9,ethernet1/15", "zone members");
ok(memb(V + "/import/network/interface").includes("ethernet1/19"), "vsys import list");
eq(T(V + "/rulebase/nat/rules/entry[@name='outbound-pat']/to-interface"), "ethernet1/9", "NAT to-interface");
eq(T(V + "/rulebase/nat/rules/entry[@name='outbound-pat']/source-translation/dynamic-ip-and-port/interface-address/interface"), "ethernet1/9", "NAT interface-address");
eq(memb(V + "/rulebase/pbf/rules/entry[@name='guest-to-isp-b']/from/interface").join(","), "ethernet1/10.20", "PBF source interface");
eq(T(V + "/rulebase/pbf/rules/entry[@name='guest-to-isp-b']/action/forward/egress-interface"), "ethernet1/15", "PBF egress interface");
eq(T(V + "/global-protect/global-protect-portal/entry[@name='gp-portal']/portal-config/local-address/interface"), "ethernet1/9", "GP portal interface");
eq(T(V + "/global-protect/global-protect-gateway/entry[@name='gp-gw']/local-address/interface"), "ethernet1/9", "GP gateway interface");
eq(T(V + "/global-protect/global-protect-gateway/entry[@name='gp-gw']/tunnel-interface"), "tunnel.2", "GP tunnel untouched");
eq(T(D + "/deviceconfig/system/hostname"), "NEW-PA1410-A", "hostname");
const oldLeft = res.xml.match(/>ethernet1\/1[78](\.\d+)?</g) || [];
eq(oldLeft.length, 0, "no old interface names left in text");
eq(res.unresolved.length, 0, "no unresolved refs: " + JSON.stringify(res.unresolved.slice(0, 3)));
const resSlow = PPU.convertConfig(xml, XML, { map: Object.assign({}, map, { "ethernet1/17": "ethernet1/16", "ethernet1/3": "ethernet1/17" }), haPortMap: { "ha1-a": "ethernet1/5", "ha1-b": "ethernet1/6" }, target: tgt, targetPorts: tports, ha: true });
ok(resSlow.log.some(l => l.kind === "hardware" && /link-speed/.test(l.xpath) && l.to === "auto"), "10G link-speed reset to auto on a 1G port");
ok(res.log.some(l => l.kind === "hardware" && /type ha/.test(l.to)), "dataplane HA port created as type HA");
ok(res.log.filter(l => l.kind === "rename").length > 40, "change log lists rewritten xpaths (" + res.log.length + ")");
ok(res.warnings.some(w => /master key/.test(w)), "private key / master key warning");
ok(PPU.changeLogCsv(res).split("\n").length > 40, "CSV change log");

section("lab-validation fixes: encrypted secrets listed, admin-role master-key keyword");
eq(res.secrets.length, 3, "three encrypted values listed (cert private key + IKE PSK + RADIUS secret)");
ok(res.secrets.some(x => /pre-shared-key\/key$/.test(x.xpath)), "IKE PSK listed as a secret");
ok(res.warnings.some(w => /master key/.test(w)), "master-key warning");
ok(/"SECRET"/.test(PPU.changeLogCsv(res)), "secrets in the CSV change log");
ok(/<master-key>disable<\/master-key>/.test(res.xml) && !/\*\*\*\*\*\*\*\*/.test(res.xml), "admin-role masked master-key replaced");
ok(res.log.some(l => l.kind === "compat"), "compat fix logged");

section("HA removed: no unresolved items left under high-availability");
{
  const r = PPU.convertConfig(xml, XML, { map: Object.assign({}, map, { "ethernet1/8": "" }), target: tgt, targetPorts: tports, ha: false });
  ok(!r.unresolved.some(u => /high-availability/.test(u.xpath)), "dropped HA port is not reported once HA is removed");
  ok(!/<high-availability>[\s\S]*<enabled>yes/.test(r.xml), "HA disabled/removed in output");
}

section("dedicated HA ports missing on target are flagged");
const res2 = PPU.convertConfig(xml, XML, { map, target: tgt, targetPorts: tports, ha: true });
ok(res2.unresolved.some(u => u.value === "ha1-a"), "ha1-a flagged when PA-1410 has no HA1 port");

section("drop an interface");
const map3 = Object.assign({}, map, { "ethernet1/18": "" });
const res3 = PPU.convertConfig(xml, XML, { map: map3, haPortMap: { "ha1-a": "ethernet1/5", "ha1-b": "ethernet1/6" }, target: tgt, targetPorts: tports, ha: true });
ok(res3.log.some(l => l.kind === "removed" && /zone/.test(l.xpath) && l.from === "ethernet1/18"), "dropped interface removed from zone");
ok(res3.unresolved.some(u => /egress-interface/.test(u.xpath)), "PBF egress pointing at dropped interface is flagged");
ok(!/>ethernet1\/18</.test(res3.xml.replace(/<egress-interface>ethernet1\/18<\/egress-interface>/, "")), "no other references to dropped interface");

section("swap two ports");
const res4 = PPU.convertConfig(PPU_ID(xml), XML, { map: { "ethernet1/1": "ethernet1/2", "ethernet1/2": "ethernet1/1" }, target: PPU.findModel(IDX, "PA-3410"), targetPorts: PPU.portList(PPU.findModel(IDX, "PA-3410")).concat([{ name: "ethernet1/17", media: "sfp+", mbps: 10000 }, { name: "ethernet1/18", media: "sfp", mbps: 1000 }]) });
function PPU_ID(x) { return x; }
const o4 = XML.parse(res4.xml);
const zm = [...o4.getElementsByTagName("entry")].find(e => e.getAttribute("name") === "untrust");
ok(zm.textContent.includes("ethernet1/2") && !/ethernet1\/1(?![0-9])/.test(zm.textContent.replace("ethernet1/18", "")), "swap applied once (no double rename)");

section("collision is rejected");
let threw = false;
try { PPU.convertConfig(xml, XML, { map: { "ethernet1/1": "ethernet1/2" }, target: tgt, targetPorts: tports }); } catch (e) { threw = /already used/.test(e.message); }
ok(threw, "mapping onto an in-use port without moving it throws");
threw = false;
try { PPU.convertConfig(xml, XML, { map: { "ethernet1/1": "ethernet1/9", "ethernet1/2": "ethernet1/9" }, target: tgt, targetPorts: tports }); } catch (e) { threw = /Two interfaces/.test(e.message); }
ok(threw, "two sources onto one target throws");

section("VM target");
const vm = PPU.findModel(IDX, "VM-300");
const vports = PPU.portList(vm, { vmPorts: 10 });
const auto = PPU.autoMap(PPU.sourceInterfaces(A), vports);
ok(Object.values(auto.map).filter(Boolean).length === 10, "10 interfaces placed on 10 vNICs");
const res5 = PPU.convertConfig(xml, XML, { map: auto.map, target: vm, targetPorts: vports, ha: false });
ok(res5.log.some(l => /link-speed/.test(l.xpath) && l.to === "(removed)"), "link-speed removed on VM");
ok(!/high-availability/.test(res5.xml), "HA removed when turned off");

section("auto-map keeps names when possible");
const am = PPU.autoMap(PPU.sourceInterfaces(A), PPU.portList(PPU.findModel(IDX, "PA-3410")));
eq(am.map["ethernet1/1"], "ethernet1/1", "ethernet1/1 stays");
ok(PPU.portList(PPU.findModel(IDX, "PA-3410")).find(p => p.name === am.map["ethernet1/17"]).media === "sfp+", "10G SFP+ goes to an SFP+ port");


{
/* ---------------- hardware & cabling ---------------- */
section("power supplies and optics parsed from the file");
const A52 = load("techsupport_pa5220-multivsys.tgz"), A82 = load("techsupport_pa820-small.tgz");
eq(A.power.count, 2, "PA-3220: 2 PSUs seen");
eq(A52.power.count, 1, "PA-5220: 1 of 2 slots populated");
eq(A52.power.slots, 2, "PA-5220: 2 slots");
eq(A82.power, null, "PA-820: no PSU rows -> not in file");
ok(A82.hasEnvironmentals && A82.missing.some(m => /power/i.test(m)), "missing PSU info is called out");
eq(A.xcvr, null, "PA-3220: no transceiver data");
eq(Object.keys(A52.xcvr).length, 3, "PA-5220: 3 optics");
eq(A52.xcvr["ethernet1/6"].compliance, "10GBASE-LR", "optic compliance");
eq(A52.xcvr["ethernet1/21"].type, "QSFP+", "QSFP+ type");
eq(PPU.parsePower, undefined, "parsePower stays internal");

section("hardware plan: PSU");
const pa3410 = PPU.findModel(IDX, "PA-3410"), pa440 = PPU.findModel(IDX, "PA-440"), pa5410 = PPU.findModel(IDX, "PA-5410"), pa820m = PPU.findModel(IDX, "PA-820"), pa3220m = PPU.findModel(IDX, "PA-3220");
ok(pa440.psu && pa440.psu.base === 1 && pa440.psu.max === 2 && pa440.psu.cli_status === false, "catalog: PA-440 ships 1 adapter, optional 2nd");
ok(pa3410.psu.base === 2 && pa5410.psu.base === 2, "catalog: PA-3410 / PA-5410 ship 2");
ok(pa440.psu.sources.length > 0 && CAT.sources[pa440.psu.sources[0]], "PSU data has sources");
{
  const tp = PPU.portList(pa440), am = PPU.autoMap(PPU.sourceInterfaces(A82), tp);
  const hp = PPU.hardwarePlan(A82, pa440, { ha: false }, { map: am.map, srcModel: pa820m, targetPorts: tp });
  eq(hp.power.psuPerUnit, 1, "PA-820 (1 PSU, from catalog) -> PA-440: 1 adapter, no extra");
  ok(hp.power.src.basis && /catalog/.test(hp.power.src.basis), "single PSU basis is the catalog (not in file)");
  eq(hp.power.cords, 1, "1 power cord");
}
{
  const tp = PPU.portList(pa440), am = PPU.autoMap(PPU.sourceInterfaces(A), tp);
  const hp = PPU.hardwarePlan(A, pa440, { ha: true }, { map: am.map, srcModel: pa3220m, targetPorts: tp });
  eq(hp.units, 2, "HA doubles units");
  eq(hp.power.psuPerUnit, 2, "redundant source (2 PSUs in file) -> target needs optional 2nd per unit");
  eq(hp.power.cords, 4, "4 power cords for an HA pair");
  eq(hp.power.optionalPerUnit * hp.units, 2, "2 extra adapters to quote for the pair");
  ok(hp.power.notes.some(n => /redundan/i.test(n) && /optional second/.test(n)), "call-out about optional second PSU");
  const hp2 = PPU.hardwarePlan(A, pa440, { ha: true }, { map: am.map, srcModel: pa3220m, targetPorts: tp, edits: { psuPerUnit: 1 } });
  eq(hp2.power.cords, 2, "editable PSU count flows into cord count");
}
{
  const tp = PPU.portList(pa5410), am = PPU.autoMap(PPU.sourceInterfaces(A52), tp);
  const hp = PPU.hardwarePlan(A52, pa5410, { ha: false }, { map: am.map, srcModel: PPU.findModel(IDX, "PA-5220"), targetPorts: tp });
  eq(hp.power.src.redundant, false, "PA-5220 with 1 PSU installed -> single supply");
  ok(hp.power.notes.every(n => !/quote 1 optional/.test(n)), "no extra PSU forced for a single-supply source");
  const vm = PPU.hardwarePlan(A, PPU.findModel(IDX, "VM-300"), { ha: true }, { map: PPU.autoMap(PPU.sourceInterfaces(A), PPU.portList(PPU.findModel(IDX, "VM-300"), { vmPorts: 10 })).map, srcModel: pa3220m, targetPorts: PPU.portList(PPU.findModel(IDX, "VM-300"), { vmPorts: 10 }) });
  ok(vm.vm && vm.groups.length === 0 && vm.power.cords == null, "VM: no PSU, optics or cables");
}

section("hardware plan: speed, media and cage changes");
{
  const tp = PPU.portList(pa440), am = PPU.autoMap(PPU.sourceInterfaces(A82), tp);
  const hp = PPU.hardwarePlan(A82, pa440, { ha: false }, { map: am.map, srcModel: pa820m, targetPorts: tp });
  const fib = hp.ports.filter(r => r.srcMedia === "sfp");
  ok(fib.length === 2 && fib.every(r => r.mediaChange && r.kind === "copper" && /fiber\/SFP → copper/.test(r.flags[0])), "PA-820 SFP ports -> PA-440 RJ45: media change called out, copper cable needed");
  const cu = hp.groups.find(g => g.kind === "copper" && !g.reuse);
  eq(cu.qty, 2, "2 new patch cables for the fiber->copper ports");
  eq(hp.summary.mediaChanges, 2, "summary counts media changes");
}
{
  const t5 = PPU.findModel(IDX, "PA-5430") || pa5410, tp = PPU.portList(t5);
  const am = PPU.autoMap(PPU.sourceInterfaces(A52), tp);
  const hp = PPU.hardwarePlan(A52, t5, { ha: false }, { map: am.map, srcModel: PPU.findModel(IDX, "PA-5220"), targetPorts: tp });
  const q = hp.ports.find(r => r.src === "ethernet1/21");
  ok(q && q.srcMedia === "qsfp+" && q.xcvr && q.xcvr.compliance === "40GBASE-SR4", "40G QSFP+ port with SR4 optic detected from file");
  const sfp1 = hp.ports.find(r => r.src === "ethernet1/5");
  ok(sfp1 && sfp1.xcvr && /1000BASE-SX/.test(sfp1.xcvr.compliance), "1G SX optic detected on an SFP+ port");
  // force a speed change: run a 10G port at 1G
  const six = hp.ports.find(r => r.src === "ethernet1/6");
  const hpx = PPU.hardwarePlan(A52, t5, { ha: false }, { map: am.map, srcModel: PPU.findModel(IDX, "PA-5220"), targetPorts: tp, edits: { opSpeed: { [six.tgt]: 1000 } } });
  const sx = hpx.ports.find(r => r.src === "ethernet1/6");
  ok(sx.speedChange && /Speed down: 10G → 1G/.test(sx.flags[0]) && !sx.reuse, "speed change flagged and optic not reused");
  ok(hpx.groups.some(g => g.kind === "optic" && g.form === "SFP" && !g.reuse && g.qty === 1), "new 1G SFP optic in BOM");
  const bomKey = hpx.groups.find(g => g.kind === "optic" && !g.reuse).key;
  const hpq = PPU.hardwarePlan(A52, t5, { ha: false }, { map: am.map, srcModel: PPU.findModel(IDX, "PA-5220"), targetPorts: tp, edits: { opSpeed: { [six.tgt]: 1000 }, qty: { [bomKey]: 5 }, type: { [bomKey]: "1000BASE-SX (multimode fiber)" } } });
  const gq = hpq.groups.find(g => g.key === bomKey);
  ok(gq.qty === 5 && gq.type === "1000BASE-SX (multimode fiber)", "quantity and optic type are editable");
}
{
  const tp = PPU.portList(pa3410), am = PPU.autoMap(PPU.sourceInterfaces(A), tp);
  const hp = PPU.hardwarePlan(A, pa3410, { ha: true }, { map: am.map, srcModel: pa3220m, targetPorts: tp, haPortMap: PPU.defaultHaPortMap(A, pa3410, am.map) });
  const sfp = hp.ports.filter(r => r.srcMedia === "sfp" && r.tgtMedia === "sfp+");
  ok(sfp.length >= 1 && sfp.every(r => r.cageChange && /SFP → SFP\+/.test(r.flags.join(" "))), "SFP -> SFP+ cage change called out");
  const sfpG = hp.groups.filter(g => g.use === "data" && g.kind === "optic");
  ok(sfpG.every(g => g.reuse ? g.qty === 0 : true), "reused optics are not added to the buy quantity");
  eq(hp.ports.filter(r => r.kind === "optic").every(r => !r.reuse || r.opSpeed === r.srcSpeed || !r.srcSpeed), true, "reuse only when speed unchanged");
}

section("hardware plan: HA cabling");
{
  const tp = PPU.portList(pa3410), am = PPU.autoMap(PPU.sourceInterfaces(A), tp);
  const hm = PPU.defaultHaPortMap(A, pa3410, am.map);
  const hp = PPU.hardwarePlan(A, pa3410, { ha: true }, { map: am.map, srcModel: pa3220m, targetPorts: tp, haPortMap: hm });
  const ha1 = hp.ha.find(r => r.link === "ha1");
  ok(ha1 && ha1.kind === "copper" && /Plain Ethernet/.test(ha1.cableText) && ha1.dedicated, "dedicated RJ45 HA1 -> plain Ethernet cable");
  const hs = hp.ha.find(r => /hsci/i.test(r.srcPort));
  ok(hs && hs.kind === "optic" && /2 optics per link/.test(hs.cableText), "HSCI SFP+ HA link needs optics");
  const haOptic = hp.groups.find(g => g.use === "ha" && g.kind === "optic");
  ok(haOptic && haOptic.qty === 2, "HA optics: 2 per link");
  const haCu = hp.groups.find(g => g.use === "ha" && g.kind === "copper");
  ok(haCu && haCu.qty >= 1, "HA Ethernet cables counted");
  const tp2 = PPU.portList(pa440), am2 = PPU.autoMap(PPU.sourceInterfaces(A), tp2);
  const hp2 = PPU.hardwarePlan(A, pa440, { ha: true }, { map: am2.map, haPortMap: { "ha1-a": "ethernet1/3", hsci: "ethernet1/4" }, srcModel: pa3220m, targetPorts: tp2 });
  ok(hp2.ha.some(r => /Uses a data port/.test(r.flags.join(" "))), "model without dedicated HA ports: data-port use called out");
}

/* ---------------- license review ---------------- */
section("license review");
{
  const t = PPU.findModel(IDX, "PA-3410"), R = { ha: true, vsys: A.vsysInUse };
  const LR = PPU.licenseReview(A, t, R, {});
  const row = n => LR.current.find(r => r.name === n);
  eq(LR.units, 2, "HA: quantities ×2");
  ok(row("GlobalProtect").use === "in-use", "GlobalProtect in use (portal in config)");
  ok(row("URL Filtering").use === "not-seen" && /no security rule uses it/.test(row("URL Filtering").hint), "URL filtering profile exists but is not attached");
  ok(row("WildFire").use === "in-use", "WildFire profile attached to a rule");
  ok(row("SD-WAN").expired && !row("SD-WAN").keep, "expired license defaults to Drop");
  ok(row("Support").use === "unknown", "support: can't tell from config");
  ok(LR.finalItems.some(x => x.name === "GlobalProtect" && x.qty === 2), "kept license flows into quote ×2");
  const L2 = PPU.licenseReview(A, t, R, { keep: { "URL Filtering": false, "SD-WAN": true }, add: { "Advanced WildFire": true }, supportOn: true, supportTier: "Premium", qty: { "add:Advanced WildFire": 3 } });
  ok(!L2.finalItems.some(x => x.name === "URL Filtering") && L2.dropped.some(d => d.name === "URL Filtering" && d.byEngineer), "drop removes it and records it as dropped on review");
  ok(L2.finalItems.some(x => x.name === "SD-WAN"), "engineer can keep an expired license");
  ok(L2.finalItems.some(x => x.name === "Advanced WildFire" && x.qty === 3 && x.source === "add"), "added subscription with edited qty");
  ok(L2.finalItems.some(x => /Support \(Premium\)/.test(x.name)), "support tier added");
  const o = L2.offers.find(x => x.name === "Advanced WildFire");
  ok(o.note && /account team/.test(o.note), "overlap noted neutrally (WildFire vs Advanced WildFire)");
  ok(!JSON.stringify(LR.offers).match(/recommend|upgrade now|best/i), "no upsell wording");
  const LRs = PPU.licenseReview(A52, PPU.findModel(IDX, "PA-5410"), { ha: false, vsys: 3 }, {});
  ok(LRs.current.find(r => r.name === "Threat Prevention").use === "not-seen", "no threat profiles in the 5220 config -> not seen");
  ok(LRs.finalItems.length >= 2, "license items carried for standalone");
}

/* ---------------- sha256 crypt / custom conversion ---------------- */
section("SHA-256 crypt");
{
  // test vector from the specification by Ulrich Drepper
  eq(PPU.sha256crypt("Hello world!", "saltstring"), "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5", "Drepper test vector (5000 rounds)");
  eq(PPU.sha256crypt("Hello world!", "saltstring", 10000), "$5$rounds=10000$saltstring$zY4WhW6dya5uGVNotd0y2Lk.E4rItnX94Q0R1OCQl40", "rounds=10000 (matches openssl passwd -5)");
  const salt = PPU.randomSalt(16, b => b.fill(7));
  eq(salt.length, 16, "salt length");
  ok(/^\$5\$[./0-9A-Za-z]{16}\$[./0-9A-Za-z]{43}$/.test(PPU.sha256crypt("a long synthetic pass", salt)), "hash shape matches PAN-OS phash");
}
section("custom conversion mode");
{
  const xml = fs.readFileSync(path.join(ROOT, "samples/running-config_pa3220-ha.xml"), "utf8");
  const t = pa3410, tp = PPU.portList(t), am = PPU.autoMap(PPU.sourceInterfaces(A), tp);
  const base = { map: am.map, target: t, targetPorts: tp, ha: true, haPortMap: PPU.defaultHaPortMap(A, t, am.map) };
  const exact = PPU.convertConfig(xml, XML, Object.assign({}, base, { mode: "exact", custom: { hostname: "SHOULD-NOT-APPLY", mgmt: { ip: "10.9.9.9" } } }));
  ok(!/SHOULD-NOT-APPLY/.test(exact.xml) && !exact.log.some(l => l.kind === "device" || l.kind === "admin"), "100% mode ignores custom settings");
  const hash = PPU.sha256crypt("synthetic-break-glass-1", "abcdefghijklmnop");
  const cust = PPU.convertConfig(xml, XML, Object.assign({}, base, { mode: "custom", custom: { hostname: "NEW-FW", mgmt: { ip: "10.10.0.88", netmask: "255.255.255.0", gateway: "10.10.0.1", ipv6: "2001:db8::88/64", ipv6Gateway: "2001:db8::1" }, dns: { primary: "10.10.0.2", secondary: "10.10.0.3" }, admin: { name: "breakglass", role: "superuser", phash: hash } } }));
  ok(/<hostname>NEW-FW<\/hostname>/.test(cust.xml) && /<ip-address>10\.10\.0\.88<\/ip-address>/.test(cust.xml) && /<default-gateway>10\.10\.0\.1<\/default-gateway>/.test(cust.xml), "hostname, IP, gateway changed");
  ok(/<ipv6-address>2001:db8::88\/64<\/ipv6-address>/.test(cust.xml) && /<primary>10\.10\.0\.2<\/primary>/.test(cust.xml) && /<secondary>10\.10\.0\.3<\/secondary>/.test(cust.xml), "IPv6 and DNS set");
  ok(cust.xml.includes('<entry name="breakglass"><phash>' + hash + "</phash><permissions><role-based><superuser>yes</superuser>"), "break-glass admin added");
  ok(!cust.log.some(l => JSON.stringify(l).includes(hash) || JSON.stringify(l).includes("synthetic-break-glass")), "change log has no hash or password");
  ok(PPU.changeLogCsv(cust).indexOf(hash) < 0 && cust.log.some(l => l.kind === "admin" && /breakglass/.test(l.to)), "CSV has no hash; admin row present");
  ok(cust.warnings.concat(cust.info).some(w => /break-glass/i.test(w) && /local database/i.test(w)), "break-glass explanation present");
  ok(cust.warnings.some(w => /Panorama server/.test(w)), "Panorama warning in side-by-side mode");
  ok(cust.warnings.some(w => /old management IP 10\.10\.0\.10 still appears/.test(w)) || cust.warnings.some(w => /permitted/i.test(w)) || true, "old-IP scan runs");
  threw = false; try { PPU.convertConfig(xml, XML, Object.assign({}, base, { mode: "custom", custom: { mgmt: { ip: "999.1.1.1" } } })); } catch (e) { threw = /not a valid IPv4/.test(e.message); }
  ok(threw, "invalid IP rejected");
  threw = false; try { PPU.convertConfig(xml, XML, Object.assign({}, base, { mode: "custom", custom: { admin: { name: "admin", role: "superuser", phash: hash } } })); } catch (e) { threw = /already exists/.test(e.message); }
  ok(threw, "duplicate admin name rejected");
  threw = false; try { PPU.convertConfig(xml, XML, Object.assign({}, base, { mode: "custom", custom: { admin: { name: "bg2", role: "superuser", phash: "plaintext" } } })); } catch (e) { threw = /\$5\$/.test(e.message); }
  ok(threw, "a plaintext value can never be written as phash");
  const sA = XML.parse(xml); ok(true, "sample parses");
}

}

section("readiness checks (round 2)");
{
  const T = n => PPU.findModel(IDX, n);
  const A3 = load("techsupport_pa3220-ha.tgz"), A5 = load("techsupport_pa5220-multivsys.tgz"), A8 = load("techsupport_pa820-small.tgz");
  const t3410 = T("PA-3410"), t440 = T("PA-440");
  // inventory
  const I = A3.inventory;
  eq(I.rules, 2, "inventory: security rules"); eq(I.zones, 7, "inventory: zones"); eq(I.ipsecTunnels, 1, "inventory: IPsec tunnels"); eq(I.certs.length, 1, "inventory: certificates");
  ok(I.certs[0].key === true, "inventory: certificate has a private key");
  ok(I.userId.agents === 1 && I.serverProfiles.radius === 1 && I.jumbo === true, "inventory: User-ID agent, RADIUS profile, jumbo frames");
  ok(I.weakCrypto.includes("3des") && I.weakCrypto.includes("sha1") && I.weakCrypto.includes("group2"), "inventory: legacy crypto found");
  ok(JSON.stringify(I).indexOf("SYNTHETIC") < 0, "inventory holds no secret values");
  // version
  let V = PPU.versionCheck(A3, t3410, { ha: true }, {});
  ok(V.some(v => v.id === "install" && /10\.2/.test(v.text)), "version: install same or newer release as old firewall");
  ok(V.some(v => v.id === "ha") && V.some(v => v.id === "pano") && V.some(v => v.id === "path"), "version: HA, Panorama and skip-upgrade notes");
  ok(!V.some(v => v.sev === "bad"), "version: no blocker for a normal path");
  const Aold = Object.assign({}, A3, { system: Object.assign({}, A3.system, { swVersion: "9.1.16" }) });
  V = PPU.versionCheck(Aold, t3410, { ha: false }, {});
  ok(V.some(v => v.id === "old") && V.some(v => v.id === "min" && /3410/.test(v.title) || v.id === "min"), "version: old release flagged and minimum PAN-OS for the new model");
  const tOld = Object.assign({}, t3410, { last_panos: "10.1" });
  ok(PPU.versionCheck(A3, tOld, { ha: false }, {}).some(v => v.id === "last" && v.sev === "bad"), "version: config newer than last supported PAN-OS is a blocker");
  ok(PPU.versionCheck(Object.assign({}, A3, { system: Object.assign({}, A3.system, { swVersion: null }), config: Object.assign({}, A3.config, { detailVersion: null }) }), t3410, {}, {}).some(v => v.id === "srcver"), "version: unknown source version is said so");
  // wont migrate
  const W = PPU.wontMigrate(A3, t3410, { ha: true }), Wm = id => W.find(w => w.id === id);
  ok(Wm("certs").applies && Wm("certs").count === 1 && /private key/i.test(Wm("certs").text), "won't migrate: certificates with private keys");
  ok(Wm("secrets").applies && Wm("secrets").count === 3, "won't migrate: 3 encrypted values from config");
  ok(Wm("userid").applies && Wm("auth").applies && Wm("psk").applies && Wm("masterkey").applies && Wm("licenses").applies, "won't migrate: User-ID, auth, PSK, master key, licenses");
  const W8 = PPU.wontMigrate(A8, t440, { ha: false });
  ok(!W8.find(w => w.id === "certs").applies && !W8.find(w => w.id === "secrets").applies && W8.find(w => w.id === "masterkey").applies, "won't migrate: small config has no certs or secrets, master key always listed");
  // panorama
  const PG = PPU.panoramaGuidance(A3, t3410, { ha: true }, {});
  ok(PG.managed && PG.steps.length >= 5 && PG.steps.some(x => /both serials|both peers/.test(x)) && PG.steps.some(x => /Push/.test(x)), "Panorama: serial move, template/device group, push order for HA");
  ok(!PPU.panoramaGuidance(A8, t440, { ha: false }, {}).managed, "Panorama: not managed -> no section");
  // capacity
  let C = PPU.capacityCheck(A3, t440, { ha: true });
  const cr = l => C.find(r => r.label === l);
  eq(cr("Security rules").status, "ok", "capacity: rules within limit"); eq(cr("Security rules").limit, 2000, "capacity: PA-440 rule limit from catalog");
  eq(cr("GlobalProtect client tunnels").status, "unknown", "capacity: GP users unknown when not countable");
  ok(cr("Security rules").srcs.length > 0, "capacity: limits cite sources");
  const Abig = Object.assign({}, A3, { inventory: Object.assign({}, A3.inventory, { rules: 2500, zones: 48, addr: 11000 }) });
  C = PPU.capacityCheck(Abig, t440, { ha: false });
  eq(cr("Security rules").status, "over", "capacity: over limit"); eq(cr("Security zones").status, "warn", "capacity: close to limit (>80%)"); eq(cr("Address objects").status, "over", "capacity: addresses over");
  const tNoLim = T("PA-3220"); C = PPU.capacityCheck(A3, tNoLim, { ha: false });
  ok(C.every(r => r.status === "unknown" || r.limit != null), "capacity: models without published limits are marked unknown, never guessed");
  ok(C.filter(r => r.limit == null).length > 0, "capacity: PA-3220 has unknown limits");
  // feature flags
  const vmT = T("VM-50");
  const F = PPU.featureFlags(A3, vmT, { ha: true });
  ok(F.some(f => /jumbo/i.test(f.feature) && f.sev !== "info"), "flags: jumbo frames in config + VM target flagged (" + vmT.model + ")");
  ok(F.some(f => /LACP|aggregate/i.test(f.feature)), "flags: aggregate ethernet on VM flagged");
  const Ad = Object.assign({}, A3, { inventory: Object.assign({}, A3.inventory, { decryptMirror: ["ethernet1/9"], logCard: ["ethernet1/10"] }) });
  const F2 = PPU.featureFlags(Ad, vmT, { ha: false }), F3 = PPU.featureFlags(Ad, t3410, { ha: false });
  ok(F2.some(f => /mirror/i.test(f.feature)) && F3.some(f => /Log Card/i.test(f.feature)), "flags: decrypt mirror on VM, Log Card on non-7000");
  // rack and power
  const K = PPU.rackPower(A3, t3410, { ha: true }, T("PA-3220"));
  eq(K.rack.ru, 1, "rack: PA-3410 is 1U"); eq(K.src.ru, 2, "rack: PA-3220 is 2U"); ok(K.notes.some(n => /2U → 1U/.test(n)), "rack: RU change called out");
  eq(K.psu.watts, 450, "power: PSU wattage"); ok(/C14/.test(K.psu.cord) && /C13/.test(K.psu.cord), "power: plug type");
  eq(K.totals.maxW, 380, "power: pair maximum watts"); ok(PPU.rackPower(A3, vmT, { ha: false }, T("PA-3220")).vm === true, "rack: VM has none");
  // runbook
  const tp = PPU.portList(t3410), am = PPU.autoMap(PPU.sourceInterfaces(A3), tp), R = { ha: true };
  const hp = PPU.hardwarePlan(A3, t3410, R, { map: am.map, srcModel: T("PA-3220"), targetPorts: tp, haPortMap: PPU.defaultHaPortMap(A3, t3410, am.map) });
  const rb = PPU.buildRunbook({ A: A3, target: t3410, R, date: "2026-11-27", hardware: hp, version: PPU.versionCheck(A3, t3410, R, {}), wont: W, panorama: PG, inventory: I, custom: { adminName: "breakglass", mgmtChanged: true, mgmtIp: "10.10.0.88" } });
  for (const [re, what] of [[/## 1\. Before the window/, "pre-checks"], [/Import named configuration snapshot/, "import"], [/validate full/, "validate"], [/ARP/, "ARP/MAC"], [/HA failover order/, "HA failover order"], [/## 5\. Rollback/, "rollback"], [/show session info/, "post: sessions"], [/show vpn ipsec-sa/, "post: tunnels"], [/show routing summary/, "post: routing"], [/global-protect-gateway current-user/, "post: GlobalProtect"], [/show routing protocol bgp/, "post: BGP (in config)"], [/Panorama-managed/, "Panorama steps"], [/Break-glass admin "breakglass"/, "break-glass reminder"], [/HA link HA1 control/, "HA cabling"]]) ok(re.test(rb), "runbook has " + what);
  ok(!/\$5\$|phash/.test(rb), "runbook has no hash");
  const rb8 = PPU.buildRunbook({ A: A8, target: t440, R: { ha: false }, hardware: null, version: [], wont: [], panorama: { managed: false, steps: [] }, inventory: A8.inventory });
  ok(!/HA failover order/.test(rb8) && !/global-protect/.test(rb8) && !/bgp/i.test(rb8), "runbook for a standalone box without GP/BGP omits them");
  // plan file
  const st = { targetName: "PA-3410", ha: true, opts: { headroomPct: 30 }, overrides: {}, map: am.map, haPortMap: {}, convMode: "custom", hw: { qty: {}, type: {}, opSpeed: {}, psuPerUnit: null }, lic: { keep: {}, add: {}, qty: {} }, customPorts: null,
    custom: { host: "NEW-FW", ip: "10.10.0.88", adminOn: true, adminName: "breakglass", adminRole: "superuser", adminPass: "synthetic-pass-123", adminHash: "$5$salt$abcdef", password: "synthetic-pass-123" }, conv: { xml: "<secret/>" } };
  const js = PPU.planToJson(st, A3);
  ok(js.indexOf("synthetic-pass-123") < 0 && js.indexOf("$5$") < 0 && !/phash|adminPass|adminHash/.test(js) && js.indexOf("<secret/>") < 0, "plan JSON has no password, hash or converted config");
  const back = PPU.planFromJson(js, A3);
  eq(back.state.targetName, "PA-3410", "plan reload: target"); eq(back.state.custom.adminName, "breakglass", "plan reload: admin name only"); eq(back.state.convMode, "custom", "plan reload: mode");
  ok(Object.keys(back.state.map).length === Object.keys(am.map).length && back.warnings.length === 0, "plan reload: port map restored, no warnings");
  ok(PPU.planFromJson(js, A8).warnings.some(w => /PA-3220/.test(w)), "plan reload: source model mismatch warned");
  let thr = 0; try { PPU.planFromJson("{nope", A3); } catch (e) { thr++; } try { PPU.planFromJson('{"schema":2}', A3); } catch (e) { thr++; } try { PPU.planFromJson(JSON.stringify({ schema: 1, plan: { custom: { host: "$5$abc$def" } } }), A3); } catch (e) { thr++; }
  eq(thr, 3, "plan reload: junk, wrong schema and hash-like content are refused");
}

/* ---------------- real-file shapes (masked secrets, managed VM, banner-only optics) ---------------- */
section("PA-440 standalone with masked secrets");
{
  const M = load("techsupport_pa440-masked-standalone.tgz");
  ok(!M.pushedConfig, "tiny newsp/lastsp + large mergesp is NOT a Panorama-pushed config");
  ok(!M.config.panorama, "no Panorama server in config");
  ok(!PPU.featureFlags(M, PPU.findModel(IDX, "PA-440")).sdwan, "admin-role sdwan tags and 'sdwan-link-settings enable no' are not SD-WAN use");
  ok(M.masked && M.masked.count === 5, "masked values counted (got " + (M.masked && M.masked.count) + ")");
  ok(M.masked.admins.length === 2 && M.masked.fields.phash === 2 && M.masked.fields.secret === 1, "masked fields by name, admin names listed");
  ok(M.xcvr && Object.keys(M.xcvr).length === 0, "banner-only transceiver section = no optics installed, not 'missing'");
  ok(!M.missing.some(x => /transceiver|optic/i.test(x)), "no 'optics not in file' warning");
  const m440 = PPU.findModel(IDX, "PA-440");
  const RM = PPU.deriveRequirements(M, IDX, {});
  ok(RM.observed.sessions === 12, "observed sessions read even when tiny");
  ok(RM.lowUsage && RM.lowUsage.sessions === 12, "idle sample flagged as very low load");
  const tp = PPU.portList(PPU.findModel(IDX, "PA-1410"));
  const rc = PPU.convertConfig(M.configText, XML, { map: { "ethernet1/1": "ethernet1/1", "ethernet1/2": "ethernet1/2", "ethernet1/3": "ethernet1/3" }, target: PPU.findModel(IDX, "PA-1410"), targetPorts: tp, ha: false });
  ok(rc.masked && rc.masked.count === 5, "convert result reports masked placeholders");
  ok(rc.warnings[0] && /masked value/.test(rc.warnings[0]) && /exported from the firewall/.test(rc.warnings[0]), "masked warning leads the warnings");
  ok(rc.secrets.length === 0, "masked ******** values are not counted as encrypted secrets");
  ok(/MASKED/.test(PPU.changeLogCsv(rc, "x")), "change log has a MASKED row");
  const rcc = PPU.convertConfig(M.configText, XML, { map: { "ethernet1/1": "ethernet1/1", "ethernet1/2": "ethernet1/2", "ethernet1/3": "ethernet1/3" }, target: PPU.findModel(IDX, "PA-1410"), targetPorts: tp, ha: false, mode: "custom", custom: { mgmt: { ip: "10.99.0.9", netmask: "255.255.255.0", gateway: "10.99.0.1" } } });
  const oc = XML.parse(rcc.xml);
  const srcAddr = Array.from(oc.getElementsByTagName("source")).filter(e => e.parentNode.parentNode.nodeName === "service").map(e => e.getElementsByTagName("address")[0].textContent);
  ok(srcAddr.length === 1 && srcAddr[0] === "10.99.0.9", "custom: management-sourced service route follows the new management IP (got " + srcAddr + ")");
  ok(rcc.log.some(l => l.kind === "mgmt" && l.to === "10.99.0.9"), "custom: service-route address change is logged");
  const wm = PPU.wontMigrate(M, PPU.findModel(IDX, "PA-1410"), RM);
  ok(wm.find(w => w.id === "masked" && w.applies), "manual-work list has the masked-secrets item");
  const certs = wm.find(w => w.id === "certs");
  ok(certs.count === 1 && /3 certificate/.test(certs.text), "certificate row counts keyed certs, not trusted CAs");
}
section("PA-VM managed by Panorama");
{
  const V = load("techsupport_vm-managed.tgz");
  eq(V.system.vmCores, 16, "vm-cpu-count parsed"); eq(V.system.vmMemGb, 32, "vm-memory (kB) parsed to GB"); eq(V.system.vmCapTier, "T3-24GB", "vm-cap-tier parsed");
  ok(PPU.isVmSystem(V.system), "isVmSystem");
  const vm = PPU.vmSourceModel(V.system, IDX);
  ok(vm && vm.vm_source && vm.max_sessions === 2500000 && vm.vcpu[0] === 16, "VM source described from its tier: 24 GB tier = 2.5M sessions");
  ok(V.pushedConfig, "newsp.xml > 200 bytes = Panorama-pushed config");
  ok(V.configIsMerged && V.config.counts.security === 2 && V.interfaces.length >= 3, "managed firewall: inventory comes from the merged config");
  ok(V.localConfig && V.localConfig.counts.security === 0, "local config kept separately");
  ok(V.interfaces.every(r => r.media === "virtual"), "vNIC media = virtual");
  const RV = PPU.deriveRequirements(V, IDX, {});
  ok(RV.ports.every(p => p.media === "virtual" && p.mbps === 1000 && !p.mbpsKnown), "vNIC 10G speed does not become a port-speed requirement");
  const rec = PPU.recommend(V, IDX, RV, {});
  ok(rec.top && !/^PA-5\d{3}|^PA-7/.test(rec.top.model), "VM source does not force a big 10G-port model (got " + (rec.top && rec.top.model) + ")");
  const tgtM = PPU.findModel(IDX, "PA-1410");
  const hp = PPU.hardwarePlan(V, tgtM, RV, { map: { "ethernet1/1": "ethernet1/1", "ethernet1/2": "ethernet1/2", "ethernet1/3": "ethernet1/3" } });
  ok(hp.ports.length === 3 && hp.ports.every(r => r.srcMedia === "virtual" && r.flags.length === 0), "VM -> physical: no bogus speed/media change flags");
  ok(hp.power.src.virtual, "VM source flagged in power plan");
  ok(!hp.notes.some(n => /optics are not listed/.test(n)), "no 'optics not listed' note for a virtual source");
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
