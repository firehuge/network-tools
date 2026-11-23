#!/usr/bin/env node
/* Node tests for the trace engine against synthetic configs in samples/. */
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FM = require(path.join(ROOT, "build/core.js"));

let failed = 0, passed = 0;
function ok(c, msg) { if (c) { passed++; console.log("  ok  :", msg); } else { failed++; console.error("  FAIL:", msg); } }
function load(...names) {
  const devs = [];
  for (const n of names) {
    const c = FM.loadConfig(fs.readFileSync(path.join(ROOT, "samples", n), "utf8"), n);
    if (c.kind === "firewall") devs.push(...c.devices);
    else for (const ctx of c.panorama.contexts) devs.push(FM.buildPanoramaDevice(c, ctx));
  }
  return devs;
}
const T = (devs, src, dst, proto, port, opts) => FM.trace(devs, { src, dst, proto, port }, opts);
const req = (r) => r.changes.filter((c) => !c.optional);
const sec = (r) => req(r).filter((c) => c.kind === "security");

console.log("\n== primitives ==");
ok(FM.prefixStr(FM.parsePrefix("10.1.2.3/24")) === "10.1.2.0/24", "prefix normalizes");
ok(FM.parsePrefix("10.0.0.1/255.255.255.0").len === 24, "netmask notation");
ok(FM.coverage([FM.parsePrefix("10.0.0.0/25"), FM.parsePrefix("10.0.0.128/25")], FM.parsePrefix("10.0.0.0/24")) === "full", "coverage of split ranges");
ok(FM.coverage([FM.parsePrefix("10.0.0.0/25")], FM.parsePrefix("10.0.0.0/24")) === "partial", "partial coverage");
ok(FM.evalTagFilter("'web' and ('prod' or 'dmz')", new Set(["web", "dmz"])) === true, "tag filter eval");
const x = FM.parseXml('<a><b name="x&amp;y">t&lt;1</b><!-- c --><c/><![CDATA[<raw>]]></a>');
ok(x.c[0].c[0].a.name === "x&y" && x.c[0].c[0].x === "t<1" && x.c[0].x === "<raw>", "xml parser entities/cdata/comments");
ok(!FM.maskSecrets("<phash>$5$abc</phash><key>SECRET</key>").includes("SECRET"), "secret masking");

console.log("\n== single vsys ==");
let d = load("fw-single-vsys.xml"), r;
r = T(d, "10.10.0.50", "172.16.10.20", "tcp", 3389);
ok(r.segments.length === 1 && r.segments[0].check.fromZone === "trust" && r.segments[0].check.toZone === "dmz", "trust -> dmz");
ok(r.segments[0].check.action === "deny" && r.segments[0].check.rule === "deny-dmz", "blocked by deny-dmz (disabled rule skipped)");
ok(sec(r).length === 1 && sec(r)[0].rule.placeBefore === "deny-dmz", "one rule needed, placed above deny-dmz");
ok(sec(r)[0].cli.some((l) => l === "set service tcp-3389 protocol tcp port 3389"), "creates service object");
ok(sec(r)[0].rule.destination === "h-web01", "reuses existing address object name");
r = T(d, "10.10.0.50", "172.16.10.20", "tcp", 8443);
ok(r.segments[0].check.action === "allow" && r.segments[0].check.rule === "users-to-dmz-web", "dynamic group + nested group + service group allow");
ok(req(r).length === 0 && r.status === "delivered", "no changes; delivered");
r = T(d, "10.10.0.50", "8.8.8.8", "tcp", 443);
ok(r.segments[0].check.verdict === "conditional" && r.segments[0].check.maybes.some((m) => m.rule === "users-web-out"), "app-dependent rule reported as conditional");
ok(r.segments[0].nat && r.segments[0].nat.snat.text === "203.0.113.2", "source NAT to interface IP");
ok(r.final.kind === "exit" && /203\.0\.113\.1/.test(r.final.text), "exits toward default gateway");
r = T(d, "10.10.0.50", "10.99.1.1", "tcp", 22);
ok(r.status === "dropped", "discard route drops");
r = T(d, "10.10.20.5", "172.31.200.10", "tcp", 22);
ok(r.segments[0].check.fromZone === "voice" && r.segments[0].egress.iface === "tunnel.1", "subinterface ingress, tunnel egress");
r = T(d, "10.10.0.50", "10.10.255.1", "icmp");
ok(r.status === "local" || r.final.kind === "local", "destination is firewall loopback");

console.log("\n== multi-device ==");
d = load("fw-single-vsys.xml", "fw-core-peer.xml");
r = T(d, "10.10.0.50", "10.50.10.7", "tcp", 443);
ok(r.segments.length === 2 && r.segments[1].device === "core-fw1", "crosses into core-fw1 via next hop");
ok(r.status === "delivered" && req(r).length === 0, "allowed end-to-end");
ok(r.returnPath.every((p) => p.ok), "return path symmetric on both");
{ const dd = load("fw-dnat-pbf.xml"), wr = dd[0].vsys.get("vsys1").security.find((x) => x.name === "web-inbound"); wr.to = ["untrust"];
  const tr = T(dd, "198.51.100.7", "203.0.113.10", "tcp", 443);
  ok(tr.segments[0].notes.some((n) => /pre-NAT zone\).*post-NAT zone \(dmz\)/.test(n.text)), "DNAT: a rule written with the pre-NAT to-zone is called out");
  const rc = FM.replayCases(dd, {}).cases.find((x) => x.rule === "web-inbound");
  ok(rc && FM.replayCase(dd, rc, {}).cat === "rule uses pre-NAT zone (DNAT)", "replay files it as 'rule uses pre-NAT zone (DNAT)'"); }
{ const m = T(load("fw-core-peer.xml"), "203.0.113.77", "10.50.10.128", "tcp", 8443).changes.find((c) => c.kind === "security" && c.modify);
  ok(m && m.modify.rule === "branch-to-apps" && m.modify.field === "service" && m.modify.cli.some((l) => /rules branch-to-apps service tcp-8443$/.test(l)), "missing rule: also offers adding the one missing member to a near-miss rule"); }
r = T(d, "10.10.0.50", "10.50.20.9", "tcp", 5432);
ok(sec(r).length === 2 && sec(r).map((c) => c.device).join() === "branch-fw1,core-fw1", "rules needed on both firewalls in path order");

console.log("\n== multi-vsys ==");
d = load("fw-multi-vsys.xml");
r = T(d, "10.1.1.10", "10.2.2.20", "tcp", 1433);
ok(r.segments.map((s) => s.vsys).join() === "vsys1,vsys2", "vsys1 -> vsys2");
ok(r.segments[0].check.toZone === "ext-to-pci" && r.segments[0].check.action === "allow", "vsys1 to external zone allowed");
ok(r.segments[1].check.fromZone === "ext-from-corp" && r.segments[1].check.toZone === "pci-db" && r.segments[1].check.action === "deny", "vsys2 from external zone denied");
ok(sec(r).length === 1 && sec(r)[0].vsys === "vsys2" && sec(r)[0].cli[0].startsWith("set vsys vsys2 rulebase security rules"), "exactly one rule needed, in vsys2");
r = T(d, "10.1.1.10", "10.2.2.21", "tcp", 8443);
ok(sec(r).map((c) => c.vsys).join() === "vsys1,vsys2", "rules needed in vsys1 AND vsys2");
r = T(d, "10.1.1.10", "10.3.0.50", "tcp", 22);
ok(r.segments.length === 3 && r.notes.some((n) => /more than two/.test(n.text)), "3-vsys path flagged as not permitted");
ok(sec(r).length === 3, "three security changes listed");
ok(req(r).some((c) => c.kind === "route" && c.vr === "vr-lab" && c.cli.some((l) => /next-vr vr-pci/.test(l))), "missing return route in vr-lab suggested via next-vr");
ok(r.notes.some((n) => /BGP/.test(n.text)) || d[0].warnings.some((w) => /BGP/.test(w.text)), "dynamic routing flagged");

console.log("\n== shared gateway ==");
d = load("fw-shared-gateway.xml");
r = T(d, "10.0.0.25", "8.8.8.8", "tcp", 443);
ok(r.segments.map((s) => s.vsys).join() === "vsys1,sg1", "vsys1 -> sg1");
ok(r.segments[0].check && r.segments[0].check.toZone === "A-to-SG", "policy in vsys1 to external zone");
ok(!r.segments[1].check && r.segments[1].nat && r.segments[1].nat.rule === "vsys1-out", "no policy in SG, SNAT in SG");
r = T(d, "192.0.2.50", "198.51.100.4", "tcp", 443);
ok(r.segments[0].vsys === "sg1" && r.segments[0].nat.dnat.text === "10.0.0.4", "inbound DNAT in shared gateway");
ok(r.segments[1].check.fromZone === "A-to-SG" && r.segments[1].check.dst === "10.0.0.4", "vsys1 sees post-SG-NAT destination");
r = T(d, "10.0.0.25", "10.1.0.9", "tcp", 22);
ok(req(r).some((c) => c.kind === "zone" && c.vsys === "vsys2"), "missing external zone in vsys2 suggested");
ok(r.returnPath.some((p) => p.asym) && req(r).some((c) => c.kind === "route" && /asymmetric/.test(c.summary)), "asymmetric return flagged with route fix");

console.log("\n== DNAT / PBF ==");
d = load("fw-dnat-pbf.xml");
r = T(d, "198.18.5.5", "203.0.113.10", "tcp", 443);
ok(r.segments[0].nat.dnat.text === "172.16.10.20" && r.segments[0].nat.dnat.port === 8443, "DNAT with port translation");
ok(r.segments[0].check.toZone === "dmz" && r.segments[0].check.dst === "203.0.113.10" && r.segments[0].check.action === "allow", "policy: pre-NAT IP, post-NAT zone");
r = T(d, "198.18.5.5", "203.0.113.11", "tcp", 22);
ok(r.segments[0].notes.some((n) => /pre-NAT destination/.test(n.text)), "warns about rule written with post-NAT IP");
ok(sec(r)[0].rule.destination === "pub-ssh" && sec(r)[0].rule.to === "dmz", "suggested rule uses pre-NAT address + post-NAT zone");
r = T(d, "198.18.5.5", "203.0.113.12", "tcp", 25);
ok(r.segments[0].nat && r.segments[0].nat.reverse && r.segments[0].dstPost === "172.16.10.25", "bi-directional static NAT reverse");
r = T(d, "10.20.0.99", "1.1.1.1", "tcp", 443);
ok(r.segments[0].pbf && r.segments[0].egress.iface === "ethernet1/4", "PBF forwards out ethernet1/4");

console.log("\n== missing route ==");
d = load("fw-dnat-pbf.xml");
const dev = d[0]; dev.vrs.get("default").routes = dev.vrs.get("default").routes.filter((x) => x.name !== "default");
r = T(d, "10.20.0.5", "8.8.8.8", "tcp", 443);
ok(r.status === "no-route" && req(r).some((c) => c.kind === "route" && c.cli[0].includes("virtual-router default routing-table ip static-route")), "no route -> static route suggestion with CLI");

console.log("\n== parallel site firewalls ==");
{
  const { parallelSites, fwXml } = await import("./fixture-parallel.mjs");
  const pd = parallelSites(FM), pr = FM.trace(pd, { src: "10.1.0.5", dst: "10.9.1.50", proto: "tcp", port: 443 });
  ok(pr.ambiguous && pr.ambiguous.devices.join("|") === "site-fw-a|site-fw-b" && pr.plan.paths[pr.ambiguous.pathIndex].label === "hq-fw -> site-fw-b", "parallel site firewalls with equal evidence -> ambiguous, alternative kept");
  const alt = FM.trace(pd, { src: "10.1.0.5", dst: "10.9.1.50", proto: "tcp", port: 443 }, { pathIndex: pr.ambiguous.pathIndex, forcePlan: true });
  ok(alt.segments.at(-1).device === "site-fw-b", "the alternative traces through the other firewall");
  const hq = pd.filter((x) => x.name === "hq-fw"), b = FM.loadConfig(fwXml("site-fw-b", [["ethernet1/1", "10.255.9.3/24", "wan"], ["ethernet1/2", "10.9.1.3/24", "inside"], ["ethernet1/3", "10.8.0.5/30", "mgmt"], ["ethernet1/4", "10.8.1.1/30", "lab"]], [["0.0.0.0/0", "10.255.9.254"]], [["hq-in", "wan", "inside", "10.1.0.0/24", "10.9.1.0/24"]]), "b.xml").devices;
  const br = FM.trace(hq.concat(pd.filter((x) => x.name === "site-fw-a"), b), { src: "10.1.0.5", dst: "10.9.1.50", proto: "tcp", port: 443 });
  ok(!br.ambiguous && br.segments.at(-1).device === "site-fw-b" && br.status === "delivered", "a rule on one of them settles it (no ambiguity)");
}

console.log("\n== zone findings (cleanup list) ==");
{
  const { fwXml } = await import("./fixture-parallel.mjs");
  const zx = fwXml("zf-fw", [["ethernet1/1", "203.0.113.1/29", "untrust"], ["ethernet1/2", "10.1.0.1/24", "trust"], ["ethernet1/3", "10.2.0.1/24", "dmz"]], [["0.0.0.0/0", "203.0.113.6"]],
    [["good", "trust", "dmz", "10.1.0.0/24", "10.2.0.0/24"], ["swapped", "trust", "dmz", "10.2.0.0/24", "10.1.0.0/24"]]);
  const zf = FM.zoneFindings(FM.loadConfig(zx, "zf.xml").devices);
  ok(zf.length === 2 && zf.every((x) => x.rule === "swapped") && zf.some((x) => x.field === "source" && x.actual[0].zones[0] === "dmz"), "rule whose addresses live in other zones is listed; the correct rule is not");
  const mv = FM.zoneFindings(load("fw-multi-vsys.xml"));
  ok(!mv.some((x) => x.range === "10.2.2.20/32"), "inter-vsys: a destination in another vsys maps to the external zone (not flagged)");
  ok(mv.some((x) => x.range === "10.2.10.0/24" && x.actual[0].zones[0] === "corp-untrust"), "inter-vsys: a subnet with no next-vr route really leaves by the default route (flagged)");
  ok(!FM.zoneFindings(load("fw-dnat-pbf.xml")).some((x) => x.field === "destination"), "DNAT: pre-NAT destination with post-NAT to-zone is not flagged");
}

console.log("\n== environment view ==");
{
  ok(FM.siteToken("nyc-fw1") === "nyc" && FM.siteToken("chi-pa-01b") === "chi" && FM.siteToken("br-east-01") === "br-east-01" && FM.siteToken("site-x-fw-a") === "site-x", "site token: firewall words and unit numbers removed, site numbers kept");
  const { fwXml } = await import("./fixture-parallel.mjs");
  const mk = (h, ifs) => FM.loadConfig(fwXml(h, ifs, [["0.0.0.0/0", "10.255.9.254"]], []), h + ".xml").devices[0];
  const ev = FM.environment([mk("alpha-1", [["ethernet1/1", "10.255.9.2/24", "wan"], ["ethernet1/2", "10.50.1.1/24", "lan"], ["ethernet1/3", "10.60.0.1/30", "p2p"]]),
    mk("bravo-7", [["ethernet1/1", "10.255.9.3/24", "wan"], ["ethernet1/2", "10.50.1.2/24", "lan"], ["ethernet1/4", "10.70.0.1/24", "x"]]),
    mk("charlie-3", [["ethernet1/1", "10.255.9.4/24", "wan"], ["ethernet1/3", "10.60.0.2/30", "p2p"]])], []);
  const siteOf = (n) => ev.units.find((u) => u.name === n).site;
  ok(siteOf("alpha-1") === siteOf("bravo-7") && siteOf("charlie-3") !== siteOf("alpha-1"), "sites: shared LAN subnet groups firewalls; a point-to-point /30 does not");
  const he = FM.environment(load("panorama-ha-edge.xml"), []);
  ok(he.units.some((u) => u.members.length === 2), "HA pair shown as one unit with both members");
  const L = FM.envLayout(he, { expanded: new Set(he.units.map((u) => u.id)) }), X = FM.drawioXml(L, "t");
  const doc = FM.parseXml(X), cells = []; (function w(n) { for (const c of n.c || []) { if (c.t === "mxCell") cells.push(c); w(c); } })(doc);
  ok(cells.filter((c) => c.a.vertex === "1").length === L.shapes.length && cells.filter((c) => c.a.edge === "1").every((c) => L.shapes.some((s) => s.id === c.a.source) && L.shapes.some((s) => s.id === c.a.target)), "draw.io export: one vertex per shape, edges reference existing shapes");
  ok(L.shapes.some((s) => s.kind === "zone" && s.lines.length) && L.shapes.some((s) => s.kind === "vsys"), "expanded units show vsys, zones and interfaces");
}

console.log("\n== Panorama small ==");
d = load("panorama-dg-stack.xml");
ok(d.length === 1 && d[0].interfaces.get("ethernet1/1").ips[0].text === "203.0.113.66/29", "template variable resolved");
ok(d[0].vsys.get("vsys1").zones.has("dc") && d[0].vsys.get("vsys1").zones.has("inside"), "template stack merge");
r = T(d, "10.60.1.20", "10.40.10.15", "tcp", 443);
ok(r.segments[0].check.rule === "east-to-dc-apps" && r.segments[0].check.ruleScope === "DG Branch-East post-rulebase", "DG post rule matches");
r = T(d, "10.60.1.20", "198.18.66.9", "tcp", 443);
ok(r.segments[0].check.rule === "shared-block-bad", "shared pre-rule evaluated first");
ok(sec(r)[0].cli[0].startsWith("set shared pre-rulebase"), "rule suggested in shared pre-rulebase to beat shared deny");
{ // DG-only firewall (no template stack) + its local backup
  let px = fs.readFileSync(path.join(ROOT, "samples", "panorama-dg-stack.xml"), "utf8");
  px = px.replace(/(<mgt-config>.*?<devices>)/s, '$1<entry name="013201008888"><hostname>branch-fw1</hostname></entry>').replace(/(<entry name="Branch-East">.*?<devices>)/s, '$1<entry name="013201008888"></entry>');
  const pc = FM.loadConfig(px, "pano.xml"), pd = pc.panorama.contexts.map((c) => FM.buildPanoramaDevice(pc, c));
  const nn = pd.find((x) => x.serial === "013201008888");
  ok(nn && nn.interfaces.size === 0 && pc.panorama.contexts.some((c) => c.noNetwork && c.hostname === "branch-fw1"), "DG-only firewall has policy but no network config");
  const nr = FM.trace(pd, { src: "10.60.1.20", dst: "10.40.10.15", proto: "tcp", port: 443 });
  ok(nr.noNetwork && nr.noNetwork[0] === "branch-fw1" && nr.notes.some((x) => x.text === FM.NO_NET_MSG("branch-fw1")), "trace notes the DG-only firewall whose rules cover the flow");
  const loc = FM.loadConfig(fs.readFileSync(path.join(ROOT, "samples", "fw-single-vsys.xml"), "utf8"), "fw.xml").devices;
  const m = FM.mergeLocalBackups(pd.concat(loc)), M = m.find((x) => x.mergedLocal);
  const names = M.vsys.get("vsys1").security.map((x) => x.name);
  ok(m.length === 2 && M.serial === "013201008888" && M.interfaces.size === loc[0].interfaces.size, "local backup merged by hostname: one device, network from local file");
  ok(names[0] === "shared-block-bad" && names.indexOf("block-bad") > names.indexOf("branches-dns") && names.indexOf("east-web-out") > names.indexOf("deny-dmz") && names.at(-1) === "shared-deny-log", "merged rule order: Panorama pre, local, Panorama post");
  const mr = FM.trace(m, { src: "10.20.0.5", dst: "198.18.66.9", proto: "tcp", port: 443 });
  ok(!FM.trace(m, { src: "10.60.1.20", dst: "10.40.10.15", proto: "tcp", port: 443 }).noNetwork, "no note once the local backup is merged");
  ok(mr.segments[0].check.rule === "shared-block-bad", "merged firewall routes from local config and enforces the Panorama shared pre-rule");
}
r = T(d, "10.60.1.20", "10.40.0.53", "udp", 53);
ok(r.segments[0].check.maybes.some((m) => m.rule === "branches-dns" && m.scope === "DG Branches pre-rulebase"), "parent DG rule inherited");


console.log("\n== Panorama: DMZ -> MPLS (routers not in config) -> core multi-vsys ==");
d = load("panorama-dmz-mpls-core.xml");
r = T(d, "172.18.10.50", "10.30.2.20", "tcp", 1433);
ok(r.ingress.device === "fw-dmz", "source firewall found automatically (fw-dmz)");
ok(r.dstFirewalls.length === 1 && r.dstFirewalls[0].device === "fw-core" && r.dstFirewalls[0].vsys === "vsys2", "destination firewall/vsys found (fw-core vsys2)");
ok(r.segments.map((x) => x.device + ":" + x.vsys).join() === "fw-dmz:vsys1,fw-core:vsys1,fw-core:vsys2", "chain fw-dmz -> MPLS -> fw-core vsys1 -> vsys2");
ok(r.stitches.length === 1 && r.stitches[0].via.kind === "transit" && /10\.250\.1\.2/.test(r.stitches[0].via.label), "transit cloud via router 10.250.1.2");
ok(!r.stitches[0].ambiguous && r.stitches[0].alternatives[0].device === "fw-core", "prefers firewall with destination connected");
ok(r.segments[1].ingress.iface === "ethernet1/5" && r.segments[1].ingress.zone === "wan", "core ingress by reverse route (ethernet1/5 / wan)");
ok(sec(r).map((c) => c.where).join("|") === "DG DG-DMZ pre-rulebase|DG DG-Core-Corp pre-rulebase|DG DG-Core-PCI pre-rulebase", "rules on DMZ FW and both core vsys (by device group)");
ok(sec(r)[0].rule.placeBefore === "dmz-deny-mpls", "DMZ rule placed above dmz-deny-mpls");
ok(req(r).some((c) => c.kind === "route" && c.device === "fw-core" && c.vr === "vr-pci" && c.cli.some((l) => /next-vr vr-corp/.test(l))), "missing return route in core vr-pci suggested");
ok(r.returnPath.length === 3 && r.returnPath[1].ok, "return path checked on every firewall/vsys");
r = T(d, "172.18.10.50", "10.60.5.20", "tcp", 22);
ok(r.stitches[0].ambiguous && r.stitches[0].alternatives.filter((a) => a.score === r.stitches[0].alternatives[0].score).length === 2, "duplicate subnet on two sites -> ambiguous with alternatives");
ok(r.notes.some((n) => /ambiguous/.test(n.text)), "ambiguity reported");
const key = r.stitches[0].key;
const site2 = d.find((x) => x.name === "fw-site2");
r = T(d, "172.18.10.50", "10.60.5.20", "tcp", 22, { choices: { [key]: site2.id } });
ok(r.segments[1].device === "fw-site2" && !r.stitches[0].ambiguous, "user branch choice re-routes to fw-site2");
r = T(d, "172.18.10.50", "10.60.5.20", "tcp", 22, { links: [{ from: { device: "fw-dmz", nexthop: "10.250.1.2" }, to: { device: "fw-site2", iface: "ethernet1/1" }, label: "MPLS-East" }] });
ok(r.segments[1].device === "fw-site2" && r.stitches[0].via.kind === "link" && r.stitches[0].via.label === "MPLS-East", "user-defined link resolves the hop");
r = T(d, "172.18.10.50", "8.8.8.8", "tcp", 443);
ok(r.segments.length === 1 && r.final.kind === "exit", "internet traffic does not stitch to internal firewalls");
r = T(d, "10.30.2.20", "172.18.10.50", "tcp", 443);
ok(r.segments.map((x) => x.device + ":" + x.vsys).join() === "fw-core:vsys2,fw-core:vsys1,fw-dmz:vsys1", "reverse direction stitches core -> DMZ (" + r.segments.map((x) => x.device + ":" + x.vsys).join() + ")");

console.log("\n== inferred network graph: MPLS + hub-and-spoke + B2B (panorama-mpls-hub.xml) ==");
d = load("panorama-mpls-hub.xml");
const chain = (r) => r.segments.map((x) => x.device + ":" + x.vsys).join(",");
r = T(d, "172.18.10.50", "10.41.5.20", "tcp", 443);
ok(chain(r) === "fw-dmz2:vsys1,fw-hub:vsys1,fw-hub:vsys2,fw-b2b:vsys1,fw-vendor:vsys1", "DMZ -> MPLS -> hub vsys1 -> hub vsys2 -> B2B -> vendor (" + chain(r) + ")");
ok(new Set(sec(r).map((c) => c.device)).size === 4 && sec(r).length === 5, "5 security rules across 4 firewalls");
ok(r.plan.srcOwners[0].device === "fw-dmz2" && r.plan.dstOwners[0].device === "fw-vendor", "source and destination owners located first");
ok(r.stitches[0].via.kind === "transit" && /10\.0\.0\.0\/8|router 10\.250\.9\.2/.test(r.stitches[0].via.label + r.stitches[0].evidence.join()), "summarized 10.0.0.0/8 route on DMZ leads into the MPLS core");
ok(r.stitches[1].via.kind === "direct" && r.stitches[2].via.kind === "direct", "hub -> B2B -> vendor by next-hop = firewall interface");
ok(r.stitches.every((s) => s.confidence === "high"), "route + reverse route evidence -> high confidence");
ok(r.returnPath[4].asym && req(r).some((c) => c.kind === "route" && c.device === "fw-vendor" && /10\.43\.0\.1 on ethernet1\/1/.test(c.summary)), "asymmetric return on vendor flagged with return-route fix");
r = T(d, "10.61.1.20", "10.30.1.20", "tcp", 443);
ok(chain(r) === "fw-br-east1:vsys1,fw-hub:vsys1" && r.stitches[0].confidence === "medium", "MPLS branch with only a default route reaches the core (medium confidence)");
ok(req(r).length === 0, "existing rules allow branch -> corp https");
r = T(d, "10.61.1.20", "10.62.1.20", "tcp", 22);
ok(chain(r) === "fw-br-east1:vsys1,fw-br-west1:vsys1", "default-route-only branch -> branch across MPLS (internal destination)");
r = T(d, "10.61.1.20", "10.62.1.20", "tcp", 22, { via: ["fw-hub"] });
ok(chain(r).startsWith("fw-br-east1:vsys1,fw-hub:vsys1") && chain(r).endsWith("fw-br-west1:vsys1"), "'must pass through' fw-hub forces the hub (" + chain(r) + ")");
r = T(d, "10.181.1.20", "10.182.1.20", "tcp", 3389);
ok(chain(r) === "fw-spoke1:vsys1,fw-hub:vsys1,fw-spoke2:vsys1", "hub-and-spoke: spoke -> hub (tunnels) -> spoke");
r = T(d, "10.30.1.20", "10.62.1.20", "tcp", 22);
ok(/router 10\.250\.0\.3/.test(r.stitches[0].via.label) && r.stitches[0].nexthop === "10.250.0.3", "two routers on the hub transit: uses the one the route points to (10.250.0.3)");
r = T(d, "10.30.1.20", "10.61.1.20", "tcp", 22);
ok(/router 10\.250\.0\.2/.test(r.stitches[0].via.label), "... and 10.250.0.2 for east branches");
r = T(d, "10.70.1.20", "10.30.1.20", "tcp", 443);
ok(chain(r) === "fw-lab:vsys1,fw-hub:vsys1", "lab firewall without an MPLS route still gets an end-to-end chain");
ok(req(r).some((c) => c.kind === "route" && c.device === "fw-lab" && /10\.30\.1\.0\/24 via 10\.250\.170\.2 on ethernet1\/2/.test(c.summary)), "missing route on fw-lab listed (via inferred /30 peer 10.250.170.2)");
ok(r.stitches[0].confidence === "low", "inferred segment marked low confidence");
r = T(d, "10.61.1.20", "10.62.1.20", "tcp", 22, { srcDevice: "fw-br-east1", dstDevice: "fw-br-west1" });
ok(chain(r) === "fw-br-east1:vsys1,fw-br-west1:vsys1", "pinned source/destination firewalls");
r = T(d, "172.18.10.50", "8.8.8.8", "tcp", 443);
ok(r.segments.length === 1 && r.status === "exits" && r.plan.dstOwners.some((o) => o.kind === "internet" && o.device === "fw-dmz2"), "public destination: the DMZ firewall is its own internet edge, traffic exits there");
{
  const topo = FM.topology(d, []);
  const core = topo.nodes.find((n) => n.type === "core");
  ok(topo.nodes.filter((n) => n.type === "fw").length === 9 && core.members >= 5, "topology: 9 firewalls, MPLS core with " + core.members + " routers");
  ok(topo.nodes.some((n) => n.type === "seg" && n.label === "10.250.0.0/29" && n.routers === 2), "topology: hub transit with 2 routers");
  const diag = FM.diagnostics(d, [{ from: { device: "fw-dmz2", nexthop: "10.250.9.2" }, to: { device: "fw-hub" }, label: "secret-label" }], "test-key");
  const js = JSON.stringify(diag);
  ok(!/fw-hub|fw-dmz2|vendor-api|corp-app01|10\.30\.1\.|172\.18\.10|secret-label|SYNTHETIC|DG-/.test(js), "diagnostics: no names, IPs, labels or secrets");
  const hub = diag.devices.find((x) => x.multiVsys), ip = (dv, n) => dv.interfaces.find((i) => i.name === n).ips[0];
  const b2b = diag.devices.find((x) => x.interfaces.some((i) => i.name === "ethernet1/2") && x.interfaces.length === 2);
  const net = (s) => { const [a, l] = s.split("/"); const n = a.split(".").reduce((x, y) => x * 256 + Number(y), 0); return Math.floor(n / Math.pow(2, 32 - l)); };
  ok(net(ip(hub, "ethernet1/7")) === net(ip(b2b, "ethernet1/1")) && ip(hub, "ethernet1/7") !== "10.40.0.1/30", "diagnostics: pseudonymized IPs keep shared subnets");
  ok(hub.vsys.length === 2 && hub.vsys[0].counts.security >= 0 && !("rules" in hub.vsys[0]), "diagnostics: counts only, no rule content");
}

console.log("\n== Panorama 67 devices ==");
let t0 = Date.now();
const big = FM.loadConfig(fs.readFileSync(path.join(ROOT, "samples/panorama-67-devices.xml"), "utf8"), "p67");
const tParse = Date.now() - t0; t0 = Date.now();
d = big.panorama.contexts.map((c) => FM.buildPanoramaDevice(big, c));
const tBuild = Date.now() - t0;
ok(d.length === 67, "67 managed devices (" + d.length + ")");
ok(d.filter((x) => x.multiVsys).length === 4, "4 multi-vsys devices");
ok(tParse + tBuild < 5000, "parse " + tParse + " ms + build " + tBuild + " ms under 5 s");
const dc4 = d.find((x) => x.name === "dc-mv-4");
ok(dc4 && dc4.vsys.get("vsys2").dg === "DC-PCI" && dc4.vsys.get("vsys1").dg === "DC-Corp", "per-vsys device-group mapping");
t0 = Date.now();
r = T(d, "10.100.7.50", "10.200.32.20", "tcp", 1433);
ok(Date.now() - t0 < 3000, "trace across 67 devices in " + (Date.now() - t0) + " ms");
ok(r.segments.map((s) => s.device + ":" + s.vsys).join() === "br-east-07:vsys1,dc-mv-4:vsys1,dc-mv-4:vsys2", "branch -> DC vsys1 -> DC vsys2");
ok(sec(r).map((c) => c.where).join("|") === "DG Branch-East pre-rulebase|DG DC-Corp pre-rulebase|DG DC-PCI pre-rulebase", "three rules in three device groups");
ok(sec(r)[2].cli.some((l) => /target devices 007902000003 vsys vsys2/.test(l)), "target device + vsys in CLI");
r = T(d, "10.100.45.9", "10.200.11.5", "tcp", 443);
ok(r.segments.length === 2 && r.segments[1].device === "dc-mv-2" && req(r).length === 0, "branch 45 reaches DC2 corp servers on https with existing rules");

r = T(d, "172.30.2.50", "10.200.12.20", "tcp", 1433);
ok(r.segments.map((x) => x.device + ":" + x.vsys).join() === "edge-2:vsys1,dc-mv-2:vsys1,dc-mv-2:vsys2", "67-device: DMZ edge -> MPLS -> DC multi-vsys chain");
ok(r.stitches[0].via.kind === "transit" && sec(r).length === 3, "67-device: transit stitch + 3 rules");
t0 = Date.now();
r = T(d, "10.100.7.50", "10.100.8.20", "tcp", 22);
ok(chain(r) === "br-east-07:vsys1,dc-mv-4:vsys1,br-east-08:vsys1", "67-device: branch -> DC -> branch across the core (" + chain(r) + ", " + (Date.now() - t0) + " ms)");
ok(sec(r).length === 2 && r.stitches.length === 2, "67-device: rules on both branches, DC intrazone allowed");
r = T(d, "10.100.21.5", "10.100.50.9", "tcp", 443);
ok(r.segments[0].device !== r.segments[r.segments.length - 1].device && r.final.kind === "delivered", "67-device: another branch pair delivered end to end (" + chain(r) + ")");

console.log("\n== scale: Panorama shaped like a large real export, BGP-only branches over MPLS ==");
{
  const gp = path.join(ROOT, "samples/_gen/panorama-scale-bgp.xml");
  if (!fs.existsSync(gp)) require("node:child_process").execFileSync(process.execPath, [path.join(ROOT, "samples/generate_samples.mjs"), "--scale"]);
  const text = fs.readFileSync(gp, "utf8");
  let t0 = Date.now();
  const c = FM.loadConfig(text, "scale");
  const tP = Date.now() - t0; t0 = Date.now();
  const mapped = c.panorama.contexts.filter((x) => x.mapped);
  const ds = mapped.map((x) => FM.buildPanoramaDevice(c, x));
  const tB = Date.now() - t0; t0 = Date.now();
  const G = FM.prepare(ds, []);
  const tG = Date.now() - t0;
  ok(c.panorama.dgs.size === 589 && c.panorama.templates.size === 344 && c.panorama.stacks.size === 322, "589 DGs, 344 templates, 322 stacks");
  ok(mapped.length === 67 && c.panorama.contexts.length > 300, "only the 67 managed firewalls are mapped (" + c.panorama.contexts.length + " contexts in total)");
  ok(c.panorama.mappedDgs.size === 7, "7 device groups used by managed firewalls (of 589)");
  ok(mapped.filter((x) => x.noNetwork).length === 6, "6 firewalls in a DG but no stack are kept (policy only)");
  ok(tP + tB + tG < 5000, (text.length / 1e6).toFixed(1) + " MB: parse " + tP + " ms, build " + tB + " ms, BGP/OSPF inference + graph " + tG + " ms");
  ok(G.inference.bgpSpeakers === 60 && G.inference.fabrics === 1 && G.inference.routes > 1000, "BGP: 60 speakers in 1 MPLS fabric, " + G.inference.routes + " inferred routes");
  const br1 = ds.find((x) => x.name === "br-bgp-01"), dc1 = ds.find((x) => x.name === "dc-bgp-1");
  const rt = (d, vr, ip) => FM.lookupRoute(d.vrs.get(vr), FM.parsePrefix(ip));
  ok(br1.vrs.get("default").routes.filter((r) => r.type === "static").length === 0, "branch has no static routes (BGP only)");
  const r1 = rt(br1, "default", "10.120.2.20");
  ok(r1 && r1.route.type === "inferred-bgp" && r1.route.nexthop.value === "10.251.1.2" && r1.route.inferred.origin === "br-bgp-02", "branch learns another branch's LAN via its PE (inferred-bgp)");
  ok(!rt(br1, "default", "10.140.1.3"), "export policy deny (10.140.0.0/16) is honoured");
  const r2 = rt(dc1, "vr-corp", "10.151.0.20");
  ok(r2 && r2.route.type === "inferred-ospf" && r2.route.nexthop.value === "10.150.1.2", "DC learns the LAN from its OSPF neighbour");
  const r3 = rt(br1, "default", "10.151.0.20");
  ok(r3 && r3.route.type === "inferred-bgp" && r3.route.inferred.origin === "dc-bgp-1", "OSPF route redistributed into BGP reaches the branches");
  const cs = (r) => r.segments.map((x) => x.device + ":" + x.vsys).join(",");
  let x = T(ds, "10.120.1.50", "10.120.2.20", "tcp", 22);
  ok(cs(x) === "br-bgp-01:vsys1,br-bgp-02:vsys1" && x.stitches[0].confidence === "medium", "BGP-only branch -> branch over MPLS (medium confidence)");
  ok(x.segments[0].notes.some((n) => /inferred from the BGP config/.test(n.text)), "hop notes the inferred BGP route");
  x = T(ds, "10.120.1.50", "10.131.1.20", "tcp", 1433);
  ok(cs(x) === "br-bgp-01:vsys1,dc-bgp-1:vsys1,dc-bgp-1:vsys2" && x.stitches[1].hairpin && x.stitches[1].confidence === "high", "vsys1 -> vsys2 without external zones: hairpin via next hop = own vsys2 interface");
  ok(sec(x).map((c) => c.where).join("|") === "DG DC-Corp pre-rulebase|DG DC-PCI pre-rulebase", "rules in both vsys (by device group)");
  ok(!req(x).some((c) => c.kind === "zone"), "no external zones suggested for a hairpin");
  x = T(ds, "10.120.1.50", "10.131.2.20", "tcp", 1433);
  ok(cs(x) === "br-bgp-01:vsys1,dc-bgp-2:vsys1,dc-bgp-2:vsys2" && x.stitches[1].hairpin && x.segments[1].notes.some((n) => /no visible-vsys or external zone/.test(n.text)), "next-vr to another vsys without visible-vsys: modelled as hairpin over shared transit");
  x = T(ds, "10.120.3.50", "10.151.0.20", "tcp", 443);
  ok(cs(x) === "br-bgp-03:vsys1,dc-bgp-1:vsys1,lab-core:vsys1" && sec(x).length === 2, "branch -> DC -> OSPF-only lab firewall (3 firewalls)");
  ok(x.changes.some((c) => c.kind === "route" && c.device === "lab-core" && c.optional && /OSPF neighbour/.test(c.why)), "lab has no return route: flagged, with redistribution hint");
  x = T(ds, "172.31.1.50", "10.120.5.20", "tcp", 443);
  ok(cs(x) === "edge-bgp-1:vsys1,br-bgp-05:vsys1", "DMZ edge (static default + BGP) -> branch via BGP-learned specific route");
  t0 = Date.now(); for (let i = 1; i <= 20; i++) T(ds, "10.120." + i + ".9", "10.120." + (i + 20) + ".9", "tcp", 22);
  ok(Date.now() - t0 < 3000, "20 branch-to-branch traces in " + (Date.now() - t0) + " ms");
}

console.log("\n== stress: Panorama inflated with 250k shared objects ==");
{
  let t = fs.readFileSync(path.join(ROOT, "samples/panorama-67-devices.xml"), "utf8");
  let filler = ""; for (let i = 0; i < 250000; i++) filler += '<entry name="big-' + i + '"><ip-netmask>172.20.' + ((i >> 8) & 255) + "." + (i & 255) + "</ip-netmask><description>synthetic filler " + i + "</description></entry>";
  t = t.replace("<shared><address>", "<shared><address>" + filler);
  const t1 = Date.now();
  const c = FM.loadConfig(t, "stress");
  const devs = c.panorama.contexts.map((x) => FM.buildPanoramaDevice(c, x));
  const r2 = T(devs, "10.100.7.50", "10.200.32.20", "tcp", 1433);
  const ms = Date.now() - t1;
  ok(r2.segments.length === 3 && ms < 6000, (t.length / 1e6).toFixed(1) + " MB Panorama: parse + build 67 devices + trace in " + ms + " ms");
}

console.log("\n== HA pairs, internet edges, rule evidence, rule replay (panorama-ha-edge.xml) ==");
{
  const H = load("panorama-ha-edge.xml");
  const names = (r) => r.segments.map((s) => s.device);
  const noPeers = (r) => { const d = names(r); return !d.some((n, i) => d.some((m, j) => j !== i && m !== n && (H.find((x) => x.name === n).haPeers || []).includes(m))); };
  let r = T(H, "203.0.113.50", "198.51.100.10", "tcp", 443);
  ok(names(r).join() === "fw-inet-a,fw-dmz-a" && r.status === "delivered", "internet -> internet edge -> DNAT -> DMZ web server: " + names(r).join(" > "));
  ok(r.segments[0].check && r.segments[0].check.rule === "web-in" && r.segments[1].check.rule === "web-allow", "edge and DMZ rules matched (web-in, web-allow)");
  ok(r.segments[0].nat && r.segments[0].nat.dnat, "destination NAT applied on the internet edge");
  ok((H.find((d) => d.name === "fw-inet-a").haPeers || []).includes("fw-inet-b") && (r.segments[0].haPeers || []).includes("fw-inet-b"), "HA pair detected (identical interface addresses); peer listed on the segment");
  ok(noPeers(r), "an HA pair is never chained back to back");
  r = T(H, "10.221.5.20", "198.51.100.140", "tcp", 443);
  ok(names(r).join() === "fw-branch-5,fw-mpls-hub,fw-inet-a", "branch -> MPLS hub -> internet edge (rule evidence on hub and edge): " + names(r).join(" > "));
  ok(r.segments.every((s) => s.check && s.check.action === "allow"), "each firewall on the internet path has an allow rule");
  ok(r.plan.evidence.some((e) => e.device === "fw-mpls-hub" && e.rule === "branch-out"), "plan lists rule evidence");
  r = T(H, "10.221.5.20", "198.51.100.140", "tcp", 443, { evidence: false });
  ok(!names(r).includes("fw-mpls-hub"), "without rule evidence the hub is not on the internet path (shows evidence is what pulls it in)");
  r = T(H, "10.240.5.140", "10.240.5.210", "tcp", 80);
  ok(names(r).join() === "fw-site-x-a" && r.segments[0].check.rule === "x-client-to-server", "source behind a router is placed by the rule that allows it (site-x)");
  r = T(H, "10.221.5.20", "10.240.3.110", "tcp", 22);
  ok(names(r).join() === "fw-branch-5,fw-mpls-hub,fw-dmz-a" && r.status === "delivered", "branch -> hub -> DMZ: " + names(r).join(" > "));
  const rc = FM.replayCases(H, {});
  ok(rc.cases.every((c) => c.src !== c.dst), "replay never builds a host-to-itself flow");
  ok(rc.cases.length === 9 && rc.cases.some((c) => c.kind === "internet"), "replay builds 9 cases incl. internet-sourced (" + JSON.stringify(rc.skipped) + ")");
  const res = rc.cases.map((c) => FM.replayCase(H, c, {}));
  const sum = FM.replaySummary(res);
  ok(sum.pass === 8 && sum.byCategory["routing disagrees with rule"] === 1, "replay: every current rule passes; the stale one is 'routing disagrees with rule' (" + JSON.stringify(sum.byCategory) + ")");
  ok(sum.conflicts >= 1, "replay counts routing/rules conflicts (" + sum.conflicts + ")");
  const loo = FM.replaySummary(rc.cases.map((c) => FM.replayCase(H, c, { leaveOneOut: true })));
  ok(loo.pass >= 7, "leave-one-out replay still passes " + loo.pass + "/" + loo.total);

  // routing is authoritative: a narrow, stale rule elsewhere does not move the path, it is reported
  r = T(H, "10.221.5.20", "10.240.3.110", "tcp", 443);
  ok(names(r).join() === "fw-branch-5,fw-mpls-hub,fw-dmz-a" && r.status === "delivered", "routing path kept despite a narrower rule on another firewall: " + names(r).join(" > "));
  ok(r.conflict && r.conflict.rules === "fw-branch-5 -> fw-site-x-a -> fw-dmz-a" && r.conflict.evidence.some((e) => e.rule === "old-branch-to-web" && e.device === "fw-site-x-a"), "conflict: routing says X, rules suggest Y, with the rule as evidence");
  ok(r.conflict.routes.some((v) => v.device === "fw-site-x-a" && /back out/.test(v.route)), "conflict names the routing reason (site-x would send it back out the interface it came in on)");
  const alt = T(H, "10.221.5.20", "10.240.3.110", "tcp", 443, { pathIndex: r.conflict.pathIndex });
  ok(names(alt).join() === "fw-branch-5,fw-site-x-a,fw-dmz-a" && alt.segments[1].check.rule === "old-branch-to-web", "trace alternative follows the rules' path on request");
  ok(!T(H, "10.221.5.20", "10.240.3.110", "tcp", 22).conflict, "no conflict when the stale rule does not match the service");
  // every hop states its basis
  ok(r.segments[0].basis.kind === "default" && /default route via 10\.240\.8\.1 out ethernet1\/1/.test(r.segments[0].basis.text) && r.segments[0].basis.confidence === "high", "basis: branch uses its default route (high)");
  ok(r.segments[2].basis.kind === "connected" && /connected 10\.240\.3\.96\/27/.test(r.segments[2].basis.text), "basis: DMZ has the server connected");
  ok(r.segments[0].next.basis && /WAN\/MPLS core/.test(r.segments[0].next.basis.text) && /rule evidence/.test(r.segments[0].next.basis.chosenBy), "basis: next firewall found via the inferred core, chosen by routing then rule evidence");
  r = T(H, "10.240.5.140", "10.240.5.210", "tcp", 80);
  ok(r.segments[0].basis.kind === "static" && /static route 10\.240\.5\.192\/26 via 10\.240\.4\.2/.test(r.segments[0].basis.text), "basis: static route with prefix, next hop and VR (" + r.segments[0].basis.text + ")");
  const one = FM.ruleCase(H, "web-allow", "DG DMZ pre-rulebase");
  ok(one.case && one.case.dst === "10.240.3.110" && one.case.port === 443, "ruleCase gives the representative flow for one rule (" + (one.case ? one.case.src + " -> " + one.case.dst + "/" + one.case.port : one.skip) + ")");
  ok(FM.ruleCase(H, "nope", "x").skip === "rule not found", "ruleCase reports unknown rules");
  const t0 = Date.now(); for (const c of rc.cases) FM.replayCase(H, c, {}); ok(Date.now() - t0 < 2000, "replay is fast (" + (Date.now() - t0) + " ms for 8)");
}
{
  const B = load("panorama-67-devices.xml");
  const t0 = Date.now(); const rc = FM.replayCases(B, {}); const sample = rc.cases.filter((_, i) => i % 20 === 0);
  for (const c of sample) FM.replayCase(B, c, {});
  const ms = (Date.now() - t0) / Math.max(1, sample.length);
  ok(ms < 150, "67-device replay: " + sample.length + " cases at " + ms.toFixed(1) + " ms/case");
}



console.log("\n== device hostnames: hostname, serial, template stack ==");
{
  const base = fs.readFileSync(path.join(ROOT, "samples", "panorama-inbound-nat.xml"), "utf8");
  const devsOf = (x) => { const c = FM.loadConfig(x, "h.xml"); return c.panorama.contexts.filter((k) => k.mapped).map((k) => FM.buildPanoramaDevice(c, k)); };
  const lab = (D, ser) => FM.devLabel(D.find((d) => d.serial === ser));
  let D = devsOf(base);
  ok(lab(D, "009905000001") === "fw-inet \u00b7 009905000001 \u00b7 S-INET", "managed-device hostname, then serial, then template stack: " + lab(D, "009905000001"));
  ok(lab(D, "009905000003") === "fw-partner \u00b7 009905000003", "no template stack: hostname and serial only");
  const noHn = base.replace(/<hostname>fw-(inet|dmz|partner)<\/hostname>/g, "");
  D = devsOf(noHn);
  ok(lab(D, "009905000001") === "009905000001 \u00b7 S-INET" && !/\u00b7 \u00b7|^ \u00b7/.test(lab(D, "009905000001")), "no hostname anywhere: today's serial + stack, no blank part");
  D = devsOf(noHn.replace('<entry name="DG-Edge"><devices><entry name="009905000001"></entry>', '<entry name="DG-Edge"><devices><entry name="009905000001"><hostname>edge-from-dg</hostname></entry>'));
  ok(lab(D, "009905000001") === "edge-from-dg \u00b7 009905000001 \u00b7 S-INET", "hostname under a device-group devices entry (with its serial)");
  D = devsOf(noHn.replace(/(<template-stack>\s*<entry name="S-INET">[\s\S]*?<devices><entry name="009905000001")>/, '$1><hostname>edge-from-stack</hostname>'));
  ok(lab(D, "009905000001") === "edge-from-stack \u00b7 009905000001 \u00b7 S-INET", "hostname under a template-stack devices entry");
  ok(FM.devLabel(load("fw-multi-circuit.xml")[0]) === "fw-edge-2isp", "local firewall backup: deviceconfig/system/hostname");
  const H = load("panorama-ha-edge.xml"), E = FM.environment(H, []), u = E.units.find((x) => x.members.length > 1 && x.members.includes("fw-inet-a"));
  const L = FM.envLayout(E, { expanded: new Set() }), card = L.shapes.find((s) => s.kind === "fw" && s.unit === u.id);
  ok(card && card.label === "fw-inet-a + fw-inet-b" && /013100000001 \u00b7 013100000002 \u00b7 S-INET/.test(card.sub), "HA pair card: both hostnames, then both serials and the stack: " + (card && card.label + " | " + card.sub));
}
console.log("\n== public-space / circuit map, provider statics, no rule in this export (fw-multi-circuit.xml) ==");
{
  const M = load("fw-multi-circuit.xml"), FW = "fw-edge-2isp", NET = "203.0.113.200";
  const s0 = (r) => r.segments[0] || { ingress: {} };
  const has = (r, re, lvl) => r.notes.some((n) => re.test(n.text) && (!lvl || n.level === lvl));
  let r = T(M, NET, "198.51.100.10", "tcp", 443, { noCircuit: true });
  ok(s0(r).ingress.iface === "ethernet1/1" && r.status !== "delivered", "without the map: the default route (ISP-A) decides the entry and the ISP-B NAT never matches");
  r = T(M, NET, "198.51.100.10", "tcp", 443);
  ok(s0(r).ingress.iface === "ethernet1/2" && s0(r).nat && s0(r).nat.rule === "dnat-web-b" && s0(r).check.rule === "in-web-b" && r.status === "delivered", "more-specific provider static for the public /27 (ISP-B next hop): inbound flow enters on the ISP-B interface");
  ok(r.circuit && r.circuit.source === "static" && has(r, /more-specific static route pub27-isp-b/) && !has(r, /Asymmetric/, "warn") && !r.changes.some((c) => !c.optional), "provider static is a valid ingress/return pattern: noted, no asymmetry warning or required change");
  const sug = FM.publicSpaceSuggestions(M, []);
  ok(sug.some((x) => x.source === "static" && x.prefix === "198.51.100.0/27" && x.iface === "ethernet1/2" && /192\.0\.2\.1/.test(x.circuit)) && sug.some((x) => x.source === "nat" && x.prefix === "198.51.100.70/32" && x.iface === "ethernet1/1"), "suggestions: provider static (circuit from next hop) and public NAT original addresses with their landing interface");
  const map = [{ prefix: "198.51.100.0/24", circuit: "ISP-A", device: FW, iface: "ethernet1/1" }, { prefix: "198.51.100.0/27", circuit: "ISP-B", device: FW, zone: "isp-b-untrust" }];
  ok(!FM.publicSpaceSuggestions(M, map).some((x) => /^198\.51\.100\./.test(x.prefix)), "mapped prefixes are no longer suggested");
  r = T(M, NET, "198.51.100.10", "tcp", 443, { circuits: map });
  ok(s0(r).ingress.iface === "ethernet1/2" && r.circuit.source === "map" && r.circuit.prefix === "198.51.100.0/27" && r.circuit.agreesWithStatic && !r.circuit.conflict && has(r, /provider static route agrees/), "longest match picks the /27 (ISP-B, by zone); the provider static confirms it");
  r = T(M, NET, "198.51.100.70", "tcp", 443, { circuits: map });
  ok(s0(r).ingress.iface === "ethernet1/1" && r.circuit.prefix === "198.51.100.0/24" && r.circuit.agreesWithRouting && r.status === "delivered", "the /24 (ISP-A) covers the rest; routing agrees");
  r = T(M, NET, "198.51.100.10", "tcp", 443, { circuits: [map[0]] });
  ok(s0(r).ingress.iface === "ethernet1/1" && r.circuit.conflict && has(r, /disagrees with the public-space map/, "warn"), "explicit map entry wins over the provider static, and the disagreement is flagged");
  r = T(M, NET, "198.51.100.70", "tcp", 443, { circuits: [{ prefix: "203.0.113.192/26", circuit: "Partner", device: FW, iface: "ethernet1/2" }] });
  ok(s0(r).ingress.iface === "ethernet1/2" && r.circuit.prefix === "203.0.113.192/26" && r.circuit.conflict, "mapped source space enters on its circuit (overrides the reverse route), flagged as differing from routing");
  r = T(M, "172.16.10.20", "10.20.0.50", "tcp", 22);
  ok(r.noRuleInExport && has(r, /no rule in this export allows 172\.16\.10\.20 to 10\.20\.0\.50/, "warn") && has(r, /local to a firewall/) && has(r, /public-space map/), "no allow rule anywhere: says denied on this path, no rule in this export, check local rules or another circuit");
  r = T(M, "10.20.0.50", "172.16.10.20", "tcp", 443);
  ok(!r.noRuleInExport, "a rule naming the addresses exists (other zones): no 'no rule in this export' message");
  const H = load("panorama-ha-edge.xml");
  const base = T(H, "203.0.113.50", "198.51.100.10", "tcp", 443), ifn = base.segments[0].ingress.iface;
  r = T(H, "203.0.113.50", "198.51.100.10", "tcp", 443, { circuits: [{ prefix: "198.51.100.0/24", circuit: "ISP", device: "fw-inet-b", iface: ifn }] });
  ok(r.segments[0].device === "fw-inet-a" && r.circuit.agreesWithRouting && r.status === base.status, "HA pair: a map entry on the secondary counts as the pair (traced on the primary, routing agrees)");
}
console.log("\n== inbound destination NAT: internet edge -> DMZ firewall (panorama-inbound-nat.xml) ==");
{
  const dd = load("panorama-inbound-nat.xml"), IN = "198.51.100.200";
  const seg = (r, dev) => r.segments.find((x) => x.device === dev) || {};
  const okFlow = (r) => r.status === "delivered" && !req(r).length && r.segments.map((x) => x.device).join() === "fw-inet,fw-dmz";
  let r = T(dd, IN, "203.0.113.10", "tcp", 443);
  ok(okFlow(r) && seg(r, "fw-inet").nat.rule === "nat-web" && seg(r, "fw-inet").check.rule === "in-web", "pre-NAT query: NAT from parent device group, edge rule on public IP, DMZ rule on private IP");
  ok(seg(r, "fw-inet").check.toZone === "to-dmz" && seg(r, "fw-inet").egressPre.zone === "untrust", "NAT matched on pre-NAT zone (untrust), security on post-NAT zone (to-dmz)");
  r = T(dd, IN, "172.20.1.10", "tcp", 443);
  ok(okFlow(r) && seg(r, "fw-inet").nat.inferred && seg(r, "fw-inet").check.dst === "203.0.113.10" && seg(r, "fw-inet").check.rule === "in-web", "post-NAT query (private server IP): matched back to its NAT rule, no rule needed");
  r = T(dd, IN, "198.51.100.5", "tcp", 2222);
  ok(okFlow(r) && seg(r, "fw-inet").nat.rule === "sftp-proxyarp" && seg(r, "fw-dmz").check.rule === "dmz-ssh" && seg(r, "fw-dmz").check.svc === "tcp/22", "proxy-ARP public IP + port translation (post-rulebase NAT); downstream firewall sees the translated port");
  ok(seg(r, "fw-inet").check.svc === "tcp/2222", "edge security rule matched on the pre-NAT port");
  r = T(dd, IN, "172.20.2.20", "tcp", 22);
  ok(okFlow(r) && seg(r, "fw-inet").nat.inferred && seg(r, "fw-inet").check.svc === "tcp/2222", "post-NAT query with translated port maps back to the public port");
  r = T(dd, "10.61.0.50", "203.0.113.10", "tcp", 443);
  ok(okFlow(r) && seg(r, "fw-inet").nat.rule === "uturn-web" && seg(r, "fw-inet").nat.snat && seg(r, "fw-inet").check.rule === "uturn-web-allow", "U-turn NAT from inside users to the public IP (DNAT + SNAT)");
  r = T(dd, IN, "203.0.113.12", "tcp", 25);
  ok(okFlow(r) && seg(r, "fw-inet").nat.reverse && seg(r, "fw-dmz").check.rule === "dmz-mail", "bi-directional static NAT, reverse direction");
  r = T(dd, IN, "172.20.1.25", "tcp", 25);
  ok(okFlow(r) && seg(r, "fw-inet").nat.inferred && seg(r, "fw-inet").check.dst === "203.0.113.12", "bi-directional static NAT traced by the private address");
  r = T(dd, IN, "203.0.113.2", "tcp", 8080);
  ok(okFlow(r) && seg(r, "fw-inet").nat.rule === "ifip-http" && seg(r, "fw-dmz").check.svc === "tcp/80", "destination NAT on the firewall's own interface address");
  r = T(dd, IN, "203.0.113.13", "tcp", 443);
  ok(okFlow(r) && seg(r, "fw-inet").nat.rule === "toif-app", "NAT rule with to-interface");
  r = T(dd, IN, "203.0.113.14", "tcp", 443);
  ok(r.status === "unresolved" && /cannot be resolved offline/.test(r.final.text), "NAT to an FQDN object: stops with a clear note instead of guessing");
  r = T(dd, "10.61.0.50", "172.20.1.10", "tcp", 443);
  ok(!r.segments.some((x) => x.nat && x.nat.inferred), "internal client to the private IP: no NAT assumed (NAT from-zone does not match)");
  {
    // DHCP internet interface (connected subnet learned at runtime) + VIP block owned on a loopback in untrust; a broad
    // 10/8 route points inside, so by config alone the VIP would route to trust and the untrust->untrust NAT never match
    let x = fs.readFileSync(path.join(ROOT, "samples", "fw-dnat-pbf.xml"), "utf8")
      .replace('<entry name="ethernet1/1"><layer3><ip><entry name="203.0.113.2/24"></entry></ip></layer3></entry>', '<entry name="ethernet1/1"><layer3><dhcp-client><enable>yes</enable></dhcp-client></layer3></entry>')
      .replace("<loopback></loopback>", '<loopback><units><entry name="loopback.10"><ip><entry name="10.99.5.1"/></ip></entry></units></loopback>')
      .replace("<member>ethernet1/4</member></interface><routing-table>", "<member>ethernet1/4</member><member>loopback.10</member></interface><routing-table>")
      .replace("<nexthop><ip-address>203.0.113.1</ip-address></nexthop>", "<nexthop><ip-address>203.0.113.1</ip-address></nexthop><interface>ethernet1/1</interface>")
      .replace("</static-route>", '<entry name="corp"><nexthop><ip-address>10.20.0.254</ip-address></nexthop><interface>ethernet1/3</interface><destination>10.0.0.0/8</destination></entry></static-route>')
      .replace("<member>ethernet1/4</member></interface></network></import>", "<member>ethernet1/4</member><member>loopback.10</member></interface></network></import>")
      .replace('<entry name="untrust"><network><layer3><member>ethernet1/1</member>', '<entry name="untrust"><network><layer3><member>ethernet1/1</member><member>loopback.10</member>')
      .replace('<entry name="pub-web"><ip-netmask>203.0.113.10</ip-netmask></entry>', '<entry name="pub-web"><ip-netmask>203.0.113.10</ip-netmask></entry><entry name="vip-cgw"><ip-netmask>10.99.5.20</ip-netmask></entry>')
      .replace('<rules><entry name="web-inbound">', '<rules><entry name="vip-in"><to><member>dmz</member></to><from><member>untrust</member></from><source><member>any</member></source><destination><member>vip-cgw</member></destination><source-user><member>any</member></source-user><category><member>any</member></category><application><member>any</member></application><service><member>service-https</member></service><action>allow</action></entry><entry name="web-inbound">')
      .replace('<nat><rules>', '<nat><rules><entry name="dnat-vip"><destination-translation><translated-address>dmz-web</translated-address></destination-translation><to><member>untrust</member></to><from><member>untrust</member></from><source><member>any</member></source><destination><member>vip-cgw</member></destination><service>any</service></entry>');
    const c = FM.loadConfig(x, "dhcp-vip.xml"), dv = c.devices;
    let q = T(dv, "198.51.100.200", "10.99.5.20", "tcp", 443), g = q.segments[0] || {};
    ok(g.nat && g.nat.rule === "dnat-vip" && g.check && g.check.toZone === "dmz" && g.check.rule === "vip-in" && /learned at runtime/.test(JSON.stringify(q)), "VIP on a DHCP interface's runtime subnet: untrust->untrust NAT matches although a 10/8 route points inside");
    q = T(dv, "198.51.100.200", "172.16.10.20", "tcp", 443); g = q.segments[0] || {};
    ok(g.nat && g.nat.inferred && g.check && g.check.dst === "10.99.5.20" && g.check.rule === "vip-in", "post-NAT query matched back to the VIP on the DHCP interface's runtime subnet");
    const y = x.replace('<entry name="10.99.5.1"/>', '<entry name="10.98.5.1"/>');
    q = T(FM.loadConfig(y, "dhcp-vip2.xml").devices, "198.51.100.200", "10.99.5.20", "tcp", 443); g = q.segments[0] || {};
    ok(!(g.nat && g.nat.rule === "dnat-vip"), "no owned address near the VIP in the to-zone: routing decides (NAT does not match)");
  }
  const pre = FM.inboundDnatCases(dd, {}), post = FM.inboundDnatCases(dd, { post: true });
  ok(pre.cases.length === 5 && post.cases.length === 4 && post.cases.every((c) => /^172\.20\./.test(c.dst)), "inbound-DNAT replay cases: pre- and post-NAT variants");
  ok(pre.cases.concat(post.cases).every((c) => /^pass/.test(FM.replayCase(dd, c, {}).cat)), "all inbound-DNAT replay cases pass");
  const d1 = load("fw-dnat-pbf.xml"); r = T(d1, IN, "172.16.10.20", "tcp", 8443);
  ok(r.status === "delivered" && !req(r).length && r.segments[0].check.rule === "web-inbound", "single firewall: private-IP query with translated port finds the pre-NAT rule");
}

console.log("\n== path status: complete / suggested / incomplete ==");
{
  let d = load("fw-multi-circuit.xml"), r = T(d, "203.0.113.200", "198.51.100.10", "tcp", 443);
  ok(r.pathStatus && r.pathStatus.status === "complete" && r.pathStatus.assumed === 0, "explicit routes -> complete path: " + (r.pathStatus && r.pathStatus.status));
  d = load("panorama-dmz-mpls-core.xml"); r = T(d, "172.18.10.50", "10.60.5.20", "tcp", 22);
  const P = r.pathStatus;
  ok(P.status === "incomplete" && P.label === "Needs your choice" && P.stop.choice && P.stop.choice.candidates.length === 2, "the destination LAN is identical on fw-site1 and fw-site2 (one site template) -> needs your choice, never picked silently: " + P.label);
  ok(P.choices[0].candidates.every((c) => c.serial && c.stack && c.site && c.reason) && /fw-site1/.test(P.choices[0].candidates[0].label), "each candidate shows hostname, serial, stack, site and a reason");
  r = T(d, "172.18.10.50", "10.60.5.20", "tcp", 22, { dstDevice: P.choices[0].candidates[0].devId });
  const P2 = r.pathStatus;
  ok(P2.status === "suggested" && P2.confidence !== "high", "pinned destination: WAN/MPLS core transit -> suggested path, not high: " + P2.status + "/" + P2.confidence);
  const a = P2.hops.flatMap((h) => h.assumptions);
  ok(a.some((x) => /routers that are not in the export/.test(x.what) && /Add a link/.test(x.confirm)), "transit hop carries a plain-language assumption and how to confirm it");
  ok(P2.hops.find((h) => h.device === "fw-dmz").assumptions.length > 0, "assumption sits on the hop that made it (fw-dmz)");
  ok(P2.alternates.length >= 1 && P2.alternates.length <= 5 && P2.alternates.every((x) => x.why && x.devices.length), "alternates listed (<=5) with a why: " + P2.alternates.map((x) => x.label).join(" | "));
  ok(P2.alternates.some((x) => x.kind === "path" && typeof x.index === "number"), "alternates point at a plan path index (clickable)");
  r = T(d, "172.18.10.50", "10.60.5.20", "tcp", 22, { links: [{ from: { device: "fw-dmz", iface: "ethernet1/3" }, to: { device: "fw-site1", iface: null }, label: "MPLS" }] });
  ok(r.pathStatus.status === "complete", "a user link replaces the guess -> complete path: " + r.pathStatus.status);
  d = load("panorama-inbound-nat.xml"); r = T(d, "198.51.100.200", "203.0.113.14", "tcp", 443);
  ok(r.pathStatus.status === "incomplete" && /fw-inet/.test(r.pathStatus.stop.where) && r.pathStatus.stop.fix, "FQDN NAT target -> incomplete, names the stop hop and a fix: " + r.pathStatus.stop.where);
  d = load("fw-dnat-pbf.xml"); d[0].vrs.get("default").routes = d[0].vrs.get("default").routes.filter((x) => x.name !== "default");
  r = T(d, "10.20.0.5", "8.8.8.8", "tcp", 443);
  ok(r.pathStatus.status === "incomplete" && /route/i.test(r.pathStatus.stop.fix) && /default/.test(r.pathStatus.stop.where), "no route -> incomplete at firewall/vsys/VR with an add-route fix: " + r.pathStatus.stop.where);
  d = load("fw-single-vsys.xml"); r = T(d, "10.10.0.50", "172.31.99.1", "tcp", 443);
  ok(r.pathStatus.status === "suggested" && r.pathStatus.hops[0].assumptions.some((x) => /default route/.test(x.what)), "private dst out a default route to an unknown next hop -> suggested");
}

console.log("\n== ignore intrazone-default (toggle) ==");
{
  const d = load("panorama-67-devices.xml"), q = ["10.100.7.50", "10.100.8.20", "tcp", 22];
  const off = T(d, ...q), on = T(d, ...q, { ignoreIntrazoneDefault: true });
  const dc = (r) => r.checks.find((c) => c.device === "dc-mv-4");
  ok(dc(off).rule === "intrazone-default" && dc(off).action === "allow" && !sec(off).some((c) => c.device === "dc-mv-4"), "toggle off: same-zone hop allowed by intrazone-default (unchanged)");
  ok(dc(on).action === "deny" && dc(on).ignoredDefault && sec(on).some((c) => c.device === "dc-mv-4" && /intrazone-default would allow/.test(c.why)), "toggle on: that hop needs an explicit rule, and says the default was ignored");
  ok(on.ignoredIntrazone && on.ignoredIntrazone.length === 1 && on.notes.some((n) => /Ignoring intrazone-default/.test(n.text)), "toggle on: result notes the ignored default");
  ok(chain(on) === chain(off) && on.stitches.length === off.stitches.length && on.pathStatus.status === off.pathStatus.status, "toggle on: same routing path and path status (" + chain(on) + ", " + on.pathStatus.status + ")");
  ok(!on.noRuleInExport === !off.noRuleInExport && (on.plan.paths || []).length === (off.plan.paths || []).length, "toggle on: no extra no-rule message or path options");
  const inter = (r) => JSON.stringify(r.checks.filter((c) => c.fromZone !== c.toZone).map((c) => [c.device, c.rule, c.action]));
  ok(inter(on) === inter(off), "toggle on: interzone decisions unchanged");
  const ctx = d.find((x) => x.name === "dc-mv-4").vsys.get("vsys1");
  const base = ctx.security.find((x) => !x.disabled) || ctx.security[0];
  const mine = Object.assign({}, base, { name: "explicit-intra", from: ["dc-transit"], to: ["dc-transit"], source: ["any"], destination: ["any"], negSrc: false, negDst: false, service: ["any"], application: ["any"], srcUser: [], hip: [], category: [], action: "allow", ruleType: "intrazone", disabled: false, scope: "DG test pre-rulebase" });
  ctx.security.unshift(mine);
  const ex = T(d, ...q, { ignoreIntrazoneDefault: true });
  ok(dc(ex).rule === "explicit-intra" && dc(ex).action === "allow" && !dc(ex).ignoredDefault, "toggle on: an explicit intrazone allow rule still allows");
  ctx.security.shift();
  const was = ctx.defaults.intrazone; ctx.defaults.intrazone = "deny";
  const dn = T(d, ...q, { ignoreIntrazoneDefault: true }), dn0 = T(d, ...q);
  ok(dc(dn).action === "deny" && !dc(dn).ignoredDefault && JSON.stringify(dn.checks) === JSON.stringify(dn0.checks), "intrazone default already deny: toggle is a no-op");
  ctx.defaults.intrazone = was;
  ok(dc(T(d, ...q)).action === "allow", "toggle does not stick after a trace with it on");
}

console.log("\n== HA pairing is strict (no false pairs across sites or repeated designs) ==");
{
  const txt = fs.readFileSync(path.join(ROOT, "samples", "panorama-ha-edge.xml"), "utf8");
  const build = (tag) => { const c = FM.loadConfig(txt, tag + ".xml"); return c.panorama.contexts.filter((x) => x.mapped).map((x) => FM.buildPanoramaDevice(c, x)); };
  const by = (ds, n) => ds.find((d) => d.name === n);
  const pairs = (ds) => FM.haGroups(ds).groups.map((g) => g.map((d) => d.name + "@" + d.file).join("+"));
  let ds = build("a");
  ok(pairs(ds).length === 3 && FM.haGroups(ds).groups.every((g) => g.length === 2), "HA-edge: the three true same-stack pairs still pair (" + pairs(ds).join(", ") + ")");
  ds = build("b"); by(ds, "fw-inet-a").stack = "stack-siteb-dmz"; by(ds, "fw-inet-b").stack = "stack-sitea-dmz";
  ok(!pairs(ds).some((p) => /fw-inet/.test(p)), "different template stacks (site B vs site A) with identical addresses: not a pair");
  const x = build("c"), y = build("d");
  ds = [by(x, "fw-inet-a"), by(x, "fw-inet-b"), by(y, "fw-inet-a")];
  ok(FM.haGroups(ds).groups.length === 0, "three firewalls with the same addresses: no group at all");
  ds = [...x, by(y, "fw-inet-a")];
  ok(!pairs(ds).some((p) => /fw-inet/.test(p)) && FM.haGroups(ds).groups.every((g) => g.length === 2), "a repeated address set is not HA, and no group is ever larger than 2");
  const small = by(build("e"), "fw-inet-a"), big = by(build("f"), "fw-inet-b");
  let k = 9; for (const t of ["10.9.1.1/24", "10.9.2.1/24", "10.9.3.1/24"]) { const p = FM.parsePrefix(t); const ip = FM.ip2n(t.split("/")[0]); big.interfaces.set("ethernet1/" + k++, { name: "ethernet1/" + (k - 1), ips: [{ ip, len: p.len, net: p, text: t, via: null }] }); }
  ok(FM.haGroups([small, big]).groups.length === 0, "a 2-address firewall sharing both addresses with a 5-address one is not a pair (max, not min)");
  const aa1 = by(build("g"), "fw-inet-a"), aa2 = by(build("h"), "fw-inet-a");
  for (const it of aa2.interfaces.values()) it.ips = it.ips.map((ip) => Object.assign({}, ip, { ip: ip.ip + 1 }));
  aa2.name = "fw-inet-a2";
  let G = FM.haGroups([aa1, aa2]);
  ok(G.groups.length === 1 && G.cluster.size === 2, "active/active: same stack, same device groups and subnets, different addresses: pairs as a cluster");
  aa2.stack = "stack-sitea-dmz";
  ok(FM.haGroups([aa1, aa2]).groups.length === 0, "same subnets but a different template stack: not a pair");
}

console.log("\n== HA from config (deviceconfig/high-availability) ==");
{
  const base = fs.readFileSync(path.join(ROOT, "samples", "panorama-ha-edge.xml"), "utf8");
  const HA = '<deviceconfig><high-availability><enabled>yes</enabled><group><group-id>1</group-id><peer-ip>$ha-peer</peer-ip><mode><active-passive/></mode></group><interface><ha1><ip-address>$ha1-ip</ip-address><netmask>255.255.255.252</netmask></ha1></interface></high-availability></deviceconfig>';
  const v = (own, peer) => '<variable><entry name="$ha1-ip"><type><ip-netmask>' + own + '</ip-netmask></type></entry>' + (peer ? '<entry name="$ha-peer"><type><ip-netmask>' + peer + "</ip-netmask></type></entry>" : "") + "</variable>";
  const split = (t, va, vb) => t.replace('<entry name="T-INET"><config><devices><entry name="localhost.localdomain">', '<entry name="T-INET"><config><devices><entry name="localhost.localdomain">' + HA)
    .replace('<entry name="S-INET"><templates><member>T-INET</member></templates><devices><entry name="013100000001"></entry><entry name="013100000002"></entry></devices></entry>',
      '<entry name="stack-siteb-inet"><templates><member>T-INET</member></templates><devices><entry name="013100000001">' + va + '</entry></devices></entry><entry name="stack-sitea-inet"><templates><member>T-INET</member></templates><devices><entry name="013100000002">' + vb + "</entry></devices></entry>");
  const build = (t, tag) => { const c = FM.loadConfig(t, tag + ".xml"); return c.panorama.contexts.filter((x) => x.mapped).map((x) => FM.buildPanoramaDevice(c, x)); };
  const inetPair = (ds) => FM.haGroups(ds).groups.some((g) => g.map((d) => d.name).sort().join() === "fw-inet-a,fw-inet-b");
  let ds = build(split(base, v("10.255.0.1", "10.255.0.2"), v("10.255.0.2", "10.255.0.1")), "ha1");
  const a = ds.find((d) => d.name === "fw-inet-a");
  ok(a.ha && a.ha.enabled === true && a.ha.peers[0] === "10.255.0.2" && a.ha.own[0] === "10.255.0.1", "HA settings read from the template with per-device variables resolved");
  let G = FM.haGroups(ds);
  ok(inetPair(ds) && G.fromConfig.size === 2, "explicit mutual peer-ip pairs two firewalls even on different stacks (stack-siteb vs stack-sitea)");
  ok(!inetPair(build(split(base, "", ""), "ha2")), "same addresses on different stacks, HA variables unset: still not a pair");
  ds = build(split(base, v("10.255.0.1", "10.255.0.2"), v("10.255.0.2")), "ha3");
  ok(inetPair(ds), "one-way peer-ip that uniquely names the other firewall pairs them");
  // explicit config pointing elsewhere / disabled blocks inference
  const sx = () => build(base, "ha4");
  ds = sx(); ok(FM.haGroups(ds).groups.some((g) => g[0].name === "fw-site-x-a"), "baseline: site-x pair by inference");
  const hub = (ds) => [...ds.find((d) => d.name === "fw-mpls-hub").interfaces.values()].find((i) => i.ips.length).ips[0];
  ds = sx(); ds.find((d) => d.name === "fw-site-x-a").ha = { enabled: true, peers: [FM.n2ip(hub(ds).ip)], own: [], unresolved: [], mode: "active-passive" };
  G = FM.haGroups(ds);
  ok(!G.groups.some((g) => g.some((d) => d.name === "fw-site-x-a")), "HA config naming another firewall: no inference pair, and no pair with a firewall that is not configured back");
  ds = sx(); ds.find((d) => d.name === "fw-site-x-b").ha = { enabled: false, peers: [], own: [], unresolved: [], mode: null };
  ok(!FM.haGroups(ds).groups.some((g) => g.some((d) => d.name === "fw-site-x-b")), "HA explicitly disabled: not paired by inference");
  ds = sx(); for (const d of ds) d.ha = { enabled: true, peers: ["10.9.9.2"], own: ["10.9.9.1"], unresolved: [], mode: "active-passive" };
  G = FM.haGroups(ds);
  ok(G.groups.length === 3 && G.fromConfig.size === 0, "one template literal peer-ip on every firewall: no mass pair, inference unchanged (" + G.groups.length + " pairs)");
  ds = sx(); for (const d of ds) d.ha = { enabled: true, peers: ["10.9.9.2"], own: [], unresolved: [], mode: null };
  ds[4].ha.own = ["10.9.9.2"];
  G = FM.haGroups(ds);
  ok(G.fromConfig.size === 0 && G.groups.every((g) => g.length === 2), "a peer-ip named by many firewalls is not a unique peer: no config pairs");
  ds = sx(); ds.find((d) => d.name === "fw-site-x-a").ha = { enabled: true, peers: ["10.77.0.2"], own: ["10.77.0.1"], unresolved: [], mode: null }; ds.find((d) => d.name === "fw-site-x-b").ha = { enabled: true, peers: ["10.66.0.1"], own: ["10.66.0.2"], unresolved: [], mode: null };
  ok(!FM.haGroups(ds).groups.some((g) => g[0].name === "fw-site-x-a"), "HA addresses that contradict each other block the inference pair");
}

console.log("\n== bulk-accept public-space suggestions ==");
{
  let d = load("fw-multi-circuit.xml"); FM.prepare(d, []);
  const sug = FM.publicSpaceSuggestions(d, []);
  let r = FM.bulkAcceptSuggestions(d, [], sug);
  ok(r.accepted.length === sug.length && r.skipped.length === 0, "all " + sug.length + " suggestions accepted into an empty map");
  const user = [{ prefix: "198.51.100.0/27", circuit: "my-ISP", device: "fw-edge-2isp", iface: "ethernet1/9", zone: null }];
  r = FM.bulkAcceptSuggestions(d, user, sug);
  ok(!r.accepted.some((x) => x.prefix === "198.51.100.0/27" || x.prefix === "198.51.100.10/32") && r.skipped.filter((x) => x.reason === "already in the map").length === 2 && user[0].iface === "ethernet1/9", "user entry wins: the same /27 and a NAT address inside it are skipped, user entry untouched");
  ok(r.accepted.every((x) => x.device && x.prefix && ("iface" in x)), "accepted suggestions are regular map entries");
  d = load("panorama-ha-edge.xml"); FM.prepare(d, []);
  r = FM.bulkAcceptSuggestions(d, [], FM.publicSpaceSuggestions(d, []));
  ok(r.accepted.length === 1 && r.skipped.length === 1 && r.skipped[0].merged, "same prefix on an HA pair: one entry for the pair");
  d = load("panorama-inbound-nat.xml"); FM.prepare(d, []);
  r = FM.bulkAcceptSuggestions(d, [], FM.publicSpaceSuggestions(d, []));
  ok(!r.accepted.some((x) => x.prefix === "203.0.113.10/32") && r.skipped.some((x) => /several firewalls/.test(x.reason)), "same prefix on unrelated firewalls: skipped as a conflict, not guessed");
  ok(FM.publicSpaceSuggestions(d, r.accepted).every((x) => x.prefix === "203.0.113.10/32"), "after accepting, only the conflicting prefix is still suggested");
}

console.log("\n== circuits on the By-site Environment view ==");
{
  const H = load("panorama-ha-edge.xml"), E = FM.environment(H, []);
  const circuits = [{ prefix: "198.51.100.0/24", circuit: "ISP-A", device: "fw-inet-b", iface: "ethernet1/1" }, { prefix: "203.0.113.0/28", circuit: "ISP-A", device: "fw-inet-a", iface: "ethernet1/1" },
    { prefix: "192.0.2.0/29", circuit: "ISP-X", device: "fw-inet-a", iface: "ethernet1/1" }, { prefix: "192.0.2.8/29", circuit: "ISP-X", device: "fw-branch-5", iface: "ethernet1/1" }];
  const L = FM.envLayout(E, { circuits }), base = FM.envLayout(E, {});
  const a = L.shapes.find((s) => s.id === "circ:ISP-A"), x = L.shapes.find((s) => s.id === "circ:ISP-X");
  const uA = E.units.find((u) => u.members.includes("fw-inet-a")), site = L.shapes.find((s) => s.kind === "site" && E.sites.find((S) => S.id === s.id).units.includes(uA.id));
  ok(a && a.kind === "cloud" && /2 prefixes/.test(a.label) && L.edges.filter((e) => e.t === "circ:ISP-A").length === 1, "one cloud per circuit; an entry on an HA peer lands on the pair (one edge)");
  ok(site && a.x >= site.x && a.x + a.w <= site.x + site.w && a.y >= site.y && a.y + a.h <= site.y + site.h, "a circuit whose firewalls are all in one site is drawn inside that site");
  const sx = (n) => E.sites.find((S) => S.units.includes(E.units.find((u) => u.members.includes(n)).id)).id;
  const firstSiteY = Math.min(...L.shapes.filter((s) => s.kind === "site").map((s) => s.y));
  ok(x && (sx("fw-inet-a") === sx("fw-branch-5") || x.y < firstSiteY) && L.edges.filter((e) => e.t === "circ:ISP-X").length === 2, "a circuit landing in several sites goes in the top band, linked to each firewall");
  ok(base.shapes.filter((s) => s.circuit).length === 0 && base.shapes.length === L.shapes.length - 2, "no map entries: layout unchanged");
  ok(/ISP-A/.test(FM.drawioXml(L, "Environment")), "draw.io export includes the circuits");
}

console.log("\n== path status errors are visible ==");
{
  const d = load("fw-multi-circuit.xml"), r = T(d, "203.0.113.200", "198.51.100.10", "tcp", 443, { __pathStatusThrow: true });
  ok(r.pathStatus && r.pathStatus.status === "error" && /could not be worked out/.test(r.pathStatus.text) && r.status === "delivered", "a pathStatus failure gives an 'error' status with a message; the trace itself is kept");
}

console.log("\n== replay path-status counts ==");
{
  const d = load("panorama-ha-edge.xml"), all = FM.replayCases(d, {});
  const res = all.cases.map((c) => FM.replayCase(d, c, {}));
  const S = FM.replaySummary(res), n = Object.values(S.byPath).reduce((a, b) => a + b, 0);
  ok(n > 0 && n <= S.total && Object.keys(S.byPath).every((k) => ["complete", "suggested", "incomplete", "error"].includes(k)), "replay summary counts path status per replayed trace: " + JSON.stringify(S.byPath));
}

console.log("\n== firewalls without network config: incomplete stop points at the backup ==");
{
  let px = fs.readFileSync(path.join(ROOT, "samples", "panorama-dg-stack.xml"), "utf8");
  px = px.replace(/(<mgt-config>.*?<devices>)/s, '$1<entry name="013201008888"><hostname>branch-fw1</hostname></entry>').replace(/(<entry name="Branch-East">.*?<devices>)/s, '$1<entry name="013201008888"></entry>');
  const c = FM.loadConfig(px, "dg-only.xml"), d = c.panorama.contexts.filter((x) => x.mapped).map((x) => FM.buildPanoramaDevice(c, x));
  const r = T(d, "10.60.1.20", "10.40.10.15", "tcp", 443);
  ok(r.pathStatus.status === "incomplete" && r.pathStatus.stop.noNetwork.includes("branch-fw1") && /local backup of branch-fw1/.test(r.pathStatus.stop.fix) && /HA settings/.test(r.pathStatus.stop.fix), "stop names the firewall without network config and the local-backup fix");
}

console.log("\n== alternate paths: why offered, how they differ, what completes them ==");
{
  let d = load("panorama-dmz-mpls-core.xml"), r = T(d, "172.18.10.50", "10.60.5.20", "tcp", 22);
  const a = r.pathStatus.alternates.find((x) => x.label === "fw-dmz -> fw-site2");
  ok(a && /equal-cost/.test(a.offered) && /routers outside the export/.test(a.offered), "equal-cost alternate says why it is offered (" + (a && a.offered.slice(0, 60)) + ")");
  ok(a && a.differs === "after fw-dmz it goes to fw-site2 instead of fw-site1", "alternate says how it differs from the path shown");
  ok(a && /add a link from fw-dmz ethernet1\/3 to fw-site2/.test(a.toComplete), "alternate says what would make it complete");
  d = load("panorama-ha-edge.xml"); r = T(d, "10.221.5.20", "10.240.3.110", "tcp", 443);
  const c = r.pathStatus.alternates.find((x) => /contradicts/.test(x.why));
  ok(c && /security rules point this way, but routing does not \(fw-site-x-a /.test(c.offered), "rules-suggested alternate explains the routing disagreement in words");
  ok(r.pathStatus.alternates.every((x) => x.offered && x.differs && x.toComplete), "every alternate has all three reasons");
}

console.log("\n== conflicting public-space suggestions: pick one landing ==");
{
  let d = load("panorama-inbound-nat.xml"); FM.prepare(d, []);
  let sug = FM.publicSpaceSuggestions(d, []), C = FM.suggestionConflicts(d, [], sug);
  ok(C.length === 1 && C[0].prefix === "203.0.113.10/32" && C[0].candidates.length === 3, "unrelated firewalls with the same prefix: one conflict, three candidates");
  ok(C[0].candidates.every((x) => x.device && x.serial && x.source === "nat" && (x.iface || x.zone)), "each candidate carries firewall, serial, source kind and interface/zone");
  const e = FM.conflictEntry(C[0].candidates[1]);
  ok(e.prefix === "203.0.113.10/32" && e.device === C[0].candidates[1].device && "iface" in e, "picked candidate becomes a normal map entry");
  ok(FM.suggestionConflicts(d, [e], FM.publicSpaceSuggestions(d, [e])).length === 0 && !FM.publicSpaceSuggestions(d, [e]).some((x) => x.prefix === "203.0.113.10/32"), "once picked the prefix leaves conflicts and suggestions");
  const user = [{ prefix: "203.0.113.0/24", circuit: "mine", device: "fw-partner", iface: null, zone: "untrust" }];
  ok(FM.suggestionConflicts(d, user, sug).length === 0 && user[0].device === "fw-partner", "a user entry covering the prefix wins: no conflict offered, entry untouched");
  d = load("panorama-ha-edge.xml"); FM.prepare(d, []);
  sug = FM.publicSpaceSuggestions(d, []);
  ok(FM.suggestionConflicts(d, [], sug).length === 0, "same prefix on an HA pair only: not a conflict");
  const extra = Object.assign({}, sug[0], { device: "fw-branch-5", iface: "ethernet1/1", why: "synthetic" });
  C = FM.suggestionConflicts(d, [], sug.concat([extra]));
  ok(C.length === 1 && C[0].candidates.length === 2 && C[0].candidates[0].peers.length === 1, "HA pair plus an unrelated firewall: the pair folds into one candidate (" + (C[0] && C[0].candidates.map((x) => x.device + "+" + x.peers.join()).join(" / ")) + ")");
}

console.log("\n== hostnames a template stack pushes (one firewall per stack only) ==");
{
  const base = fs.readFileSync(path.join(ROOT, "samples", "panorama-dmz-mpls-core.xml"), "utf8").replace(/<hostname>fw-[a-z0-9]+<\/hostname>/g, "");
  const tplIns = (x, t, inner) => x.replace('<entry name="' + t + '"><config><devices><entry name="localhost.localdomain">', '<entry name="' + t + '"><config><devices><entry name="localhost.localdomain"><deviceconfig>' + inner + "</deviceconfig>");
  const mk = (x) => { const c = FM.loadConfig(x, "h.xml"); return { c, ctx: c.panorama.contexts.filter((y) => y.mapped), ds: c.panorama.contexts.filter((y) => y.mapped).map((y) => FM.buildPanoramaDevice(c, y)) }; };
  let x = tplIns(base, "T-DMZ", "<system><hostname>fw-dmz-t</hostname></system>");
  x = tplIns(x, "T-SITE", "<system><hostname>fw-site-shared</hostname></system>");
  x = tplIns(x, "T-CORE", "<setting><management><initcfg><hostname>fw-core-i</hostname></initcfg></management></setting>");
  let M = mk(x); const by = (s) => M.ds.find((d) => d.serial === s);
  ok(by("009901000001").hostname === "fw-dmz-t" && FM.devLabel(by("009901000001")) === "fw-dmz-t \u00b7 009901000001 \u00b7 S-DMZ", "template system hostname names the one firewall of its stack (" + FM.devLabel(by("009901000001")) + ")");
  ok(by("009901000001").name === "009901000001", "the firewall keeps its serial as its id name, so saved links and map entries still match");
  ok(!by("009903000001").hostname && !by("009903000002").hostname && !/fw-site-shared/.test(FM.devLabel(by("009903000001"))), "a template hostname on a two-firewall stack names neither firewall");
  ok(!by("009902000001").hostname && by("009902000001").hostnameInit === "fw-core-i" && /^fw-core-i \u00b7 009902000001/.test(FM.devLabel(by("009902000001"))), "init-cfg hostname of a one-firewall template is shown");
  ok(FM.devLabel(by("009902000001"), { "009902000001": "core-pasted" }).startsWith("core-pasted"), "a pasted hostname wins over the init-cfg one");
  M = mk(tplIns(tplIns(base, "T-CORE", "<setting><management><initcfg><hostname>dup-i</hostname></initcfg></management></setting>"), "T-DMZ", "<setting><management><initcfg><hostname>dup-i</hostname></initcfg></management></setting>"));
  ok(M.ds.every((d) => !d.hostnameInit), "the same init-cfg hostname on two firewalls' templates names neither");
  M = mk(tplIns(base, "T-DMZ", "<system><hostname>fw-dmz-t</hostname></system>").replace('<hostname></hostname>', ""));
  const c0 = mk(fs.readFileSync(path.join(ROOT, "samples", "panorama-dmz-mpls-core.xml"), "utf8").replace('<entry name="T-DMZ"><config><devices><entry name="localhost.localdomain">', '<entry name="T-DMZ"><config><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>other</hostname></system></deviceconfig>'));
  ok(c0.ds.find((d) => d.serial === "009901000001").hostname === "fw-dmz", "a Panorama managed-device hostname still wins over the template one");
  M = mk(base); ok(M.ds.every((d) => !d.hostname && FM.devLabel(d) === d.serial + " \u00b7 " + d.stack), "no hostname anywhere: label is serial \u00b7 stack, no blank");
}

console.log("\n" + passed + " passed, " + failed + " failed");

// Optional: real configs under real/ (never committed). Only counts are printed.
const realDir = path.join(ROOT, "real");
if (fs.existsSync(realDir)) for (const f of fs.readdirSync(realDir).filter((n) => n.endsWith(".xml"))) {
  try {
    const t = Date.now(); const c = FM.loadConfig(fs.readFileSync(path.join(realDir, f), "utf8"), f);
    const devs = c.kind === "firewall" ? c.devices : c.panorama.contexts.map((x) => FM.buildPanoramaDevice(c, x));
    console.log("real/" + "*" + ": " + c.kind + " " + c.version + ", " + devs.length + " device(s), " + devs.reduce((a, x) => a + x.vsys.size, 0) + " vsys, loaded in " + (Date.now() - t) + " ms");
  } catch (e) { failed++; console.error("real config failed to load:", e.message); }
}
process.exit(failed ? 1 : 0);
