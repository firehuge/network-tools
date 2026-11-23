#!/usr/bin/env node
/* SPDX-License-Identifier: Apache-2.0 */
/* Phase 3: BGP in path tracing (legacy + advanced routing), pasted route tables, shared / overlapping address space.
 * Synthetic configs only (samples/generate_phase3.mjs). */
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FM = require(path.join(ROOT, "build/core.js"));
let failed = 0, passed = 0;
function ok(c, msg) { if (c) { passed++; console.log("  ok  :", msg); } else { failed++; console.error("  FAIL:", msg); } }
const load = (...names) => { const out = []; for (const n of names) { const c = FM.loadConfig(fs.readFileSync(path.join(ROOT, "samples", n), "utf8"), n); if (c.kind === "firewall") out.push(...c.devices); else for (const x of c.panorama.contexts) out.push(FM.buildPanoramaDevice(c, x)); } return out; };
const T = (d, s, t, o, port) => FM.trace(d, { src: s, dst: t, proto: "tcp", port: port || 443 }, o);
const inf = (d, host) => { const x = d.find((y) => y.hostname === host || y.name === host); FM.prepare(d, []); return [...new Set(x.vrs.values())].flatMap((v) => v.routes.filter((r) => r.inferred)); };
const has = (rs, p) => rs.find((r) => FM.prefixStr(r.dest) === p);
const routes = (n) => fs.readFileSync(path.join(ROOT, "samples", "routes", n), "utf8");

console.log("\n== BGP on the advanced routing engine (logical routers, PAN-OS 11) ==");
for (const [label, d] of [["local backups", load("fw-are-bgp-dc1.xml", "fw-are-bgp-dc2.xml")], ["Panorama templates / stacks", load("panorama-are-bgp.xml")]]) {
  const dc1 = d.find((x) => x.hostname === "dc1-core-fw"), S = FM.bgpSummary(dc1)[0];
  ok(S && S.engine === "advanced" && S.localAs === "65010" && S.routerId === "10.200.0.1", label + ": logical router BGP parsed (engine, AS, router id)");
  ok(S.groups[0].name === "PG-DC2" && S.groups[0].type === "ebgp" && S.groups[0].filteringProfile === "FP-OUT" && S.peers[0].peerIp === "10.200.0.2" && S.peers[0].peerAs === "65020", label + ": peer group, peer, peer AS, filtering profile");
  ok(S.redistribution[0].name === "RP-CONN" && S.redistribution[0].types.join() === "connect", label + ": redistribution profile (connected) from routing-profile/bgp");
  ok(S.networks.join() === "10.10.50.0/24" && S.aggregates[0].prefix === "10.10.0.0/22" && S.aggregates[0].summaryOnly, label + ": network statement and summary-only aggregate");
  const S2 = FM.bgpSummary(d.find((x) => x.hostname === "dc2-core-fw"))[0];
  ok(S2.conditional.length === 1 && S2.conditional[0].mode === "non-exist" && S2.peers[0].filteringProfile === "FP-COND", label + ": per-peer filtering profile (inherit no) with conditional advertisement");
  const r2 = inf(d, "dc2-core-fw");
  ok(has(r2, "10.10.0.0/22") && !has(r2, "10.10.1.0/24") && !has(r2, "10.10.2.0/24"), label + ": summary-only aggregate: dc2 learns 10.10.0.0/22, not the /24s");
  ok(!has(r2, "10.10.9.0/24"), label + ": outbound prefix list PL-NO-MGMT keeps 10.10.9.0/24 from dc2");
  ok(has(r2, "10.10.50.0/24") && /network statement/.test(has(r2, "10.10.50.0/24").inferred.reason), label + ": network statement for a static prefix is advertised, and says so");
  const r1 = inf(d, "dc1-core-fw");
  ok(has(r1, "10.20.1.0/24") && !has(r1, "10.20.200.0/24"), label + ": conditional advertisement (non-exist): backup LAN withheld while the primary LAN exists");
  ok(r2.every((r) => r.inferred.reason && /learns it from peer/.test(r.inferred.reason)), label + ": every inferred route carries a plain reason");
  let r = T(d, "10.20.1.50", "10.10.1.20");
  ok(r.status === "delivered" && r.pathStatus.status === "suggested" && r.pathStatus.label === "Suggested (BGP-inferred)" && r.pathStatus.bgpInferred, label + ": trace over an inferred BGP route -> 'Suggested (BGP-inferred)'");
  const a = r.pathStatus.hops[0].assumptions.find((x) => x.kind === "bgp");
  ok(a && /BGP-inferred/.test(a.what) && /Why: dc1-core-fw aggregates/.test(a.what) && /show advanced-routing route/.test(a.confirm), label + ": the hop says why (aggregate) and how to confirm (advanced-routing command)");
  r = T(d, "10.10.1.20", "10.20.200.5");
  const ch = r.changes.find((c) => c.kind === "route");
  ok(ch && ch.bgp && /withholds 10\.20\.200\.0\/24: conditional advertisement/.test(ch.why), label + ": a missing route explains the BGP reason (conditional advertisement withheld)");
  r = T(d, "10.20.1.50", "10.10.9.5");
  ok(r.changes.some((c) => c.kind === "route" && /PL-NO-MGMT/.test(c.why)), label + ": a missing route names the prefix list that filtered it");
}

console.log("\n== BGP on legacy virtual routers (Panorama template stack) ==");
{
  const d = load("panorama-legacy-bgp.xml"), hub = d.find((x) => x.serial === "009930000001"), br = d.find((x) => x.serial === "009930000002");
  const S = FM.bgpSummary(hub)[0], Sb = FM.bgpSummary(br)[0];
  ok(S.engine === "legacy" && S.localAs === "65100" && S.aggregates[0].prefix === "10.30.0.0/16" && !S.aggregates[0].summaryOnly && S.exportRules === 2, "legacy: AS, aggregation (not summary-only), export policy parsed (deny rule + allow-rest)");
  ok(Sb.conditional.length === 1 && Sb.conditional[0].usedBy.join() === "HUB", "legacy: conditional advertisement policy parsed (used-by peer group)");
  const rb = inf(d, "009930000002");
  ok(has(rb, "10.30.1.0/24") && has(rb, "10.30.0.0/16") && !has(rb, "10.30.99.0/24"), "legacy: branch learns the hub LAN and the aggregate; the export rule keeps 10.30.99.0/24 out");
  const rh = inf(d, "009930000001");
  ok(has(rh, "10.40.1.0/24") && !has(rh, "10.40.200.0/24"), "legacy: conditional advertisement withholds the backup LAN");
  const r = T(d, "10.40.1.10", "10.30.99.5");
  ok(r.pathStatus.label === "Suggested (BGP-inferred)" && r.segments[0].basis.kind === "bgp" && /10\.30\.0\.0\/16/.test(r.segments[0].basis.text), "legacy: 10.30.99.5 still reachable over the aggregate -> Suggested (BGP-inferred)");
}

console.log("\n== legacy import/export rules: once a rule applies to a peer group, an unmatched route is denied (verified on a live PA-VM, PAN-OS 11.1) ==");
{
  const xmlText = fs.readFileSync(path.join(ROOT, "samples", "panorama-legacy-bgp.xml"), "utf8");
  const ALLOW = '<entry name="allow-rest"><enable>yes</enable><used-by><member>BRANCHES</member></used-by><match/><action><allow><update/></allow></action></entry>';
  const loadX = (text) => { const c = FM.loadConfig(text, "x.xml"); return c.panorama.contexts.filter((x) => x.mapped).map((x) => FM.buildPanoramaDevice(c, x)); };
  ok(xmlText.includes(ALLOW), "sample: the hub's export policy ends with an allow-everything rule");
  const denyOnly = loadX(xmlText.replace(ALLOW, ""));
  ok(inf(denyOnly, "009930000002").every((r) => !/^10\.30\./.test(FM.prefixStr(r.dest))), "export: a deny-only rule list lets nothing else through to the branch (implicit deny)");
  ok(has(inf(loadX(xmlText), "009930000002"), "10.30.1.0/24"), "export: deny rule + allow-rest -> the branch learns the hub LAN again");
  const tr = (d) => T(d, "10.40.1.10", "10.30.1.10");
  ok(tr(denyOnly).status !== "delivered" || tr(denyOnly).pathStatus.status !== "complete", "export: with the implicit deny, the traced flow to the hub LAN is not reported as routed over BGP");
  const impDeny = '<import><rules><entry name="imp-deny"><enable>yes</enable><used-by><member>HUB</member></used-by><match><address-prefix><entry name="10.99.0.0/16"><exact>no</exact></entry></address-prefix></match><action><deny/></action></entry></rules></import>';
  const withImp = loadX(xmlText.replace("<policy><conditional-advertisement>", "<policy>" + impDeny + "<conditional-advertisement>"));
  ok(inf(withImp, "009930000002").every((r) => !/^10\.30\./.test(FM.prefixStr(r.dest))), "import: a deny-only import rule list on the branch's peer group drops everything else (implicit deny)");
  const impAllow = loadX(xmlText.replace("<policy><conditional-advertisement>", "<policy>" + impDeny.replace("</rules>", '<entry name="allow-rest"><enable>yes</enable><used-by><member>HUB</member></used-by><match/><action><allow><update/></allow></action></entry></rules>') + "<conditional-advertisement>"));
  ok(has(inf(impAllow, "009930000002"), "10.30.1.0/24"), "import: deny rule + allow-rest -> routes are learned again");
  ok(has(inf(loadX(xmlText.replace("<policy><conditional-advertisement>", "<policy>" + impDeny.replace("HUB", "OTHER-GROUP") + "<conditional-advertisement>")), "009930000002"), "10.30.1.0/24"), "import: a rule used by a different peer group does not affect this one");
}

console.log("\n== route flags printed run together (A?B, AOi, A S) ==");
{
  const xml = (fl) => '<response status="success"><result><flags>x</flags><entry><virtual-router>default</virtual-router><destination>10.9.0.0/16</destination><nexthop>10.1.1.1</nexthop><flags>' + fl + '</flags></entry></result></response>';
  const one = (fl) => { const p = FM.parseRouteTable(xml(fl)); return { n: p.count, proto: p.count ? p.routers.get("default")[0].proto : null }; };
  ok(one("A?B   ").proto === "bgp" && one("A?B   ").n === 1, "XML: 'A?B' is an active BGP route");
  ok(one(" ?B   ").n === 0, "XML: ' ?B' (inactive, loses to a better route) is skipped");
  ok(one("A Oi").proto === "ospf" && one("AS").proto === "static" && one("A C").proto === "connected", "XML: OSPF, static and connected flags");
  const txt = "VIRTUAL ROUTER: default (id 1)\n  ==========\ndestination nexthop metric flags age interface next-AS\n10.9.0.0/16 10.1.1.1 10 A?B 00:01:00 ethernet1/1\n10.8.0.0/16 10.1.1.1 10 ?B 00:01:00 ethernet1/1\n10.7.0.0/16 10.1.1.1 1 A Oi 00:01:00 ethernet1/1\n";
  const p = FM.parseRouteTable(txt), rows = p.routers.get("default") || [];
  ok(p.count === 2 && p.skipped === 1 && rows[0].proto === "bgp" && rows[1].proto === "ospf", "legacy text: 'A?B' parsed as BGP, '?B' skipped as inactive, 'A Oi' as OSPF");
}

console.log("\n== pasted route tables (actual learned routes win over inference) ==");
{
  let p = FM.parseRouteTable(routes("hub-show-routing-route.txt"));
  ok(p.format === "legacy" && p.count === 4 && p.routers.get("default").filter((r) => r.proto === "bgp").length === 2, "'show routing route' (legacy) parsed: router, BGP flags");
  p = FM.parseRouteTable(routes("dc2-show-advanced-routing-route.txt"));
  ok(p.format === "advanced" && p.routers.get("LR-CORE").length === 6 && p.routers.get("LR-CORE")[0].proto === "bgp" && p.routers.get("LR-CORE")[0].ad === 20, "'show advanced-routing route' parsed: logical router, protocol, distance");
  p = FM.parseRouteTable(routes("hub-route-api.xml"));
  ok(p.format === "xml" && p.count === 2 && p.skipped === 1, "XML API response parsed; inactive route (no A flag) skipped");
  p = FM.parseRouteTable("router,destination,nexthop,interface,protocol\nLR-CORE,10.9.0.0/16,10.200.0.1,ethernet1/1,bgp,20,0\n");
  ok(p.format === "csv" && p.count === 1, "CSV (e.g. from a TSF) parsed");
  ok(FM.parseRouteTable("hello").warnings.length === 1, "nothing recognisable -> a plain warning saying what to paste");
  const d = load("fw-are-bgp-dc1.xml", "fw-are-bgp-dc2.xml");
  let r = T(d, "10.20.1.50", "10.10.9.5");
  ok(r.pathStatus.status !== "complete", "before pasting: mgmt LAN filtered by inference");
  const rep = FM.applyRouteTables(d, [{ device: "dc2-core-fw", text: routes("dc2-show-advanced-routing-route.txt"), label: "dc2 table" }, { device: "nope", text: "x" }]);
  ok(rep[0].matched && rep[0].routes === 3 && rep[0].routers[0].vr === "LR-CORE" && !rep[1].matched && /No loaded firewall/.test(rep[1].warnings.join()), "applied per firewall: 3 learned routes on dc2; unknown firewall reported");
  r = T(d, "10.20.1.50", "10.10.9.5");
  ok(r.status === "delivered" && r.pathStatus.status === "complete" && r.pathStatus.label === "Complete (pasted route table)" && r.segments[0].basis.kind === "observed", "after pasting: the real BGP route wins -> Complete (pasted route table)");
  const dc2 = d.find((x) => x.hostname === "dc2-core-fw");
  ok(dc2.vrs.get("LR-CORE").routes.every((x) => !x.inferred), "a router with a pasted table gets no inferred routes");
  FM.applyRouteTables(d, []);
  ok(dc2.vrs.get("LR-CORE").routes.every((x) => !x.observed) && T(d, "10.20.1.50", "10.10.9.5").pathStatus.status !== "complete", "clearing the tables restores inference");
  const hp = load("panorama-legacy-bgp.xml");
  const rr = FM.applyRouteTables(hp, [{ device: "009930000001", text: routes("hub-route-api.xml") }]);
  ok(rr[0].routes === 2 && T(hp, "10.30.1.10", "10.40.200.7").status === "delivered", "legacy hub: pasted XML table shows the backup LAN really is learned (overrides the withheld inference)");
}

console.log("\n== shared / overlapping address space (cloned builds) ==");
{
  const d = load("panorama-cloned-dc.xml"), dc1 = d.find((x) => x.hostname === "core-dc1-fw"), dc2 = d.find((x) => x.hostname === "core-dc2-fw");
  ok(!FM.haGroups(d).groups.length, "cloned builds in different stacks are not an HA pair");
  const O = FM.overlapReport(d);
  ok(O.sharedIps.some((x) => x.ip === "10.99.0.2" && x.owners.length === 2) && O.sharedIps.some((x) => x.ip === "10.50.1.1"), "overlap callout lists every address configured on more than one firewall");
  ok(O.overlaps.some((x) => x.prefix === "10.50.1.0/24") && !O.overlaps.some((x) => x.prefix === "10.99.0.0/29" && x.owners.length === 3 && x.owners.every((o) => o.prefix === "10.99.0.0/29") && false), "overlapping subnets listed");
  ok(O.cloned.length === 1 && /different template stacks/.test(O.cloned[0].notHa), "cloned pair listed with why it is not HA");
  let r = T(d, "10.1.1.10", "10.50.1.20");
  const P = r.pathStatus, c = P.choices.find((x) => x.kind === "next-hop");
  ok(P.status === "incomplete" && P.label === "Needs your choice" && P.stop.choice, "ambiguous next hop -> Needs your choice (never picked silently)");
  ok(c && c.candidates.length === 2 && c.candidates.every((x) => x.hostname && x.serial && x.stack && x.site && x.reason) && c.candidates.map((x) => x.hostname).sort().join() === "core-dc1-fw,core-dc2-fw", "picker candidates: hostname, serial, stack, site, reason");
  ok(r.notes.some((n) => /Needs your choice/.test(n.text)), "a warning note names the decision");
  r = T(d, "10.1.1.10", "10.50.1.20", { choices: { [c.key]: dc2.id } });
  ok(r.segments[r.segments.length - 1].devId === dc2.id && r.pathStatus.status === "complete" && r.sharedChoices.every((x) => x.pinned), "pin for this trace (choices) -> follows core-dc2-fw, complete");
  r = T(d, "10.1.1.10", "10.50.1.20", { links: [{ from: { device: c.from, iface: "ethernet1/1" }, to: { device: dc1.name }, label: "to DC1" }] });
  ok(r.segments[r.segments.length - 1].devId === dc1.id && r.pathStatus.status === "complete" && r.sharedChoices.find((x) => x.kind === "next-hop").pinBy === "a saved link", "saved custom next-hop link -> follows core-dc1-fw");
  r = T(d, "10.1.1.10", "10.50.1.20", { links: [{ from: { device: c.from, iface: "ethernet1/1", nexthop: "10.99.0.2" }, to: { device: dc2.name } }] });
  ok(r.segments[r.segments.length - 1].devId === dc2.id, "a link that names the shared next-hop IP still goes where it says");
  r = T(d, "10.1.1.10", "10.50.1.20", { dstDevice: dc1.id });
  ok(r.segments[r.segments.length - 1].devId === dc1.id && r.sharedChoices.every((x) => x.pinned) && r.pathStatus.status === "complete", "picking the destination firewall settles the next hop that leads to it");
}
{
  // same stack, identical addresses, different sites by hostname: not HA (cloned); same site: still HA
  const base = fs.readFileSync(path.join(ROOT, "samples", "panorama-cloned-dc.xml"), "utf8");
  const one = base.replace("<member>T-CORE-DC2</member>", "<member>T-CORE-DC1</member>").replace('<entry name="ST-DC2"><templates><member>T-CORE-DC1</member></templates><devices><entry name="009940000003"/></devices></entry>', "").replace('<devices><entry name="009940000002"/></devices>', '<devices><entry name="009940000002"/><entry name="009940000003"/></devices>');
  const mk = (xml) => { const c = FM.loadConfig(xml, "x.xml"); return c.panorama.contexts.map((x) => FM.buildPanoramaDevice(c, x)); };
  let d = mk(one);
  const cores = d.filter((x) => x.stack === "ST-DC1");
  cores[0].hostname = "core-dc1-fw"; cores[1].hostname = "core-dc2-fw";
  ok(cores.length === 2 && !FM.haGroups(d).groups.length, "same stack + identical addresses but different sites (dc1 vs dc2): not paired");
  d = mk(one); const c2 = d.filter((x) => x.stack === "ST-DC1"); c2[0].hostname = "core-dc1-fw01"; c2[1].hostname = "core-dc1-fw02";
  ok(FM.haGroups(d).groups.length === 1, "same stack + identical addresses at the same site (fw01/fw02): still an HA pair");
  // two sites: never paired, even with identical addresses on one stack
  d = mk(one); const c3 = d.filter((x) => x.stack === "ST-DC1"); c3[0].hostname = "SITEA-FW01"; c3[1].hostname = "SITEB-FW01";
  ok(!FM.haGroups(d).groups.length, "two sites with identical addresses: never paired");
}
{
  // BGP peer address configured on two firewalls: not guessed (ambiguousPeers), unless one is at the same site
  const d = load("fw-are-bgp-dc1.xml", "fw-are-bgp-dc2.xml", "fw-are-bgp-dc2.xml");
  d[2].hostname = d[2].name = "dc3-core-fw"; d[2].id = "dc3";
  FM.invalidateCaches(d);
  const G = FM.prepare(d, []);
  ok(G.inference.ambiguousPeers >= 1, "BGP peer IP owned by two firewalls -> not guessed (" + G.inference.ambiguousPeers + " ambiguous peer)");
}
console.log("\n" + passed + " passed, " + failed + " failed");
process.exit(failed ? 1 : 0);
