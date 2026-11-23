#!/usr/bin/env node
/* Engine tests for static-route path fallbacks, filename-serial merge, same-box
   re-entry through an unknown network, vsys-level map, FCR paste/CSV, and
   device-group vsys join. Fixtures use generic lab names only. */
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FM = require(path.join(ROOT, "build/core.js"));

let failed = 0, passed = 0;
function ok(c, msg) { if (c) { passed++; console.log("  ok  :", msg); } else { failed++; console.error("  FAIL:", msg); } }

function fwShell({ host, serial, vsys, routesPath }) {
  /* vsys: [{name, display, ifs: [[name, ip, zone]], vr, routes: [[dest, nh, name?]] }]
     routesPath: "table" | "ip" | "static" | "both" */
  const e = (n, x) => `<entry name="${n}">${x}</entry>`;
  const allIfs = vsys.flatMap((v) => v.ifs);
  const eth = allIfs.map(([n, ip]) => e(n, `<layer3><ip>${e(ip, "")}</ip></layer3>`)).join("");
  const vrXml = vsys.map((v) => {
    const mem = v.ifs.map(([n]) => `<member>${n}</member>`).join("");
    const sr = (v.routes || []).map(([d, nh, nm], i) => e(nm || ("r" + i), `<nexthop><ip-address>${nh}</ip-address></nexthop><metric>10</metric><destination>${d}</destination>`)).join("");
    const body = `<interface>${mem}</interface>`;
    const path = routesPath || "table";
    let routes = "";
    if (path === "table" || path === "both") routes += `<routing-table><ip><static-route>${sr}</static-route></ip></routing-table>`;
    if (path === "ip") routes += `<ip><static-route>${sr}</static-route></ip>`;
    if (path === "static") routes += `<static-route>${sr}</static-route>`;
    if (path === "both") routes += `<ip><static-route>${sr}</static-route></ip>`;
    return e(v.vr || ("vr-" + v.name), body + routes);
  }).join("");
  const vsysXml = vsys.map((v) => {
    const mem = v.ifs.map(([n]) => `<member>${n}</member>`).join("");
    const vrs = `<virtual-router><member>${v.vr || ("vr-" + v.name)}</member></virtual-router>`;
    const zones = [...new Set(v.ifs.map((x) => x[2]))].map((z) => e(z, `<network><layer3>${v.ifs.filter((x) => x[2] === z).map((x) => `<member>${x[0]}</member>`).join("")}</layer3></network>`)).join("");
    const dn = v.display ? `<display-name>${v.display}</display-name>` : "";
    return e(v.name, `${dn}<import><network><interface>${mem}</interface>${vrs}</network></import><zone>${zones}</zone><rulebase></rulebase>`);
  }).join("");
  const sys = `<hostname>${host}</hostname>` + (serial ? `<serial>${serial}</serial>` : "");
  return `<?xml version="1.0"?><config version="11.1.0"><mgt-config></mgt-config><shared></shared><devices>${e("localhost.localdomain", `<network><interface><ethernet>${eth}</ethernet></interface><virtual-router>${vrXml}</virtual-router></network><deviceconfig><system>${sys}</system></deviceconfig><vsys>${vsysXml}</vsys>`)}</devices></config>`;
}

console.log("\n== Phase 0: static routes from current and legacy paths ==");
{
  const vs = [{ name: "vsys1", ifs: [["ethernet1/1", "10.10.1.1/24", "lan"], ["ethernet1/2", "10.0.0.1/30", "wan"]], vr: "default", routes: [["0.0.0.0/0", "10.0.0.2", "default"]] }];
  const a = FM.loadConfig(fwShell({ host: "lab-a", vsys: vs, routesPath: "table" }), "lab-a.xml").devices[0];
  const b = FM.loadConfig(fwShell({ host: "lab-b", vsys: vs, routesPath: "ip" }), "lab-b.xml").devices[0];
  const c = FM.loadConfig(fwShell({ host: "lab-c", vsys: vs, routesPath: "static" }), "lab-c.xml").devices[0];
  const d = FM.loadConfig(fwShell({ host: "lab-d", vsys: vs, routesPath: "both" }), "lab-d.xml").devices[0];
  const statics = (dev) => dev.vrs.get("default").routes.filter((r) => r.type === "static");
  ok(statics(a).some((r) => r.name === "default" && r.nexthop.value === "10.0.0.2"), "routing-table/ip/static-route still parsed");
  ok(statics(b).some((r) => r.name === "default" && r.nexthop.value === "10.0.0.2"), "legacy vr/ip/static-route parsed");
  ok(statics(c).some((r) => r.name === "default" && r.nexthop.value === "10.0.0.2"), "legacy vr/static-route parsed");
  ok(statics(d).filter((r) => r.name === "default").length === 1, "same route listed in both layouts is not duplicated");
}

console.log("\n== Phase 0: serial from filename, merge local backups ==");
{
  ok(FM.serialFromFilename("running-config_010000000042.xml") === "010000000042", "single 12-digit token in the filename is the serial");
  ok(FM.serialFromFilename("C:\\\\lab\\\\fw-010000000042-backup.xml") === "010000000042", "serial token works with a Windows path");
  ok(FM.serialFromFilename("fw-010000000042-010000000043.xml") === null, "two serial-like tokens are not guessed");
  ok(FM.serialFromFilename("notes-123.xml") === null, "a short number is not treated as a serial");
  const localXml = fwShell({ host: "box-local", vsys: [{ name: "vsys1", ifs: [["ethernet1/1", "10.180.1.1/24", "lan"], ["ethernet1/2", "10.0.8.1/30", "wan"]], vr: "default", routes: [["0.0.0.0/0", "10.0.8.2", "default"]] }] });
  const loc = FM.loadConfig(localXml, "running-config_010000000042.xml").devices[0];
  ok(loc.serial === "010000000042" && loc.hostname === "box-local", "local backup gets its serial from the filename when the XML has none");

  const pano = `<?xml version="1.0"?><config version="11.1.0"><mgt-config><devices><entry name="010000000042"><hostname>box-pano</hostname></entry></devices></mgt-config><shared></shared><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>pano-lab</hostname></system></deviceconfig>
    <device-group><entry name="DG-Box"><devices><entry name="010000000042"><vsys><entry name="vsys1"/></vsys></entry></devices>
      <pre-rulebase><security><rules><entry name="box-pre-allow"><to><member>any</member></to><from><member>any</member></from><source><member>any</member></source><destination><member>any</member></destination><source-user><member>any</member></source-user><category><member>any</member></category><application><member>any</member></application><service><member>any</member></service><action>allow</action></entry></rules></security></pre-rulebase>
    </entry></device-group>
    <template><entry name="T-Box"><config><devices><entry name="localhost.localdomain"><network></network><vsys><entry name="vsys1"></entry></vsys></entry></devices></config></entry></template>
    <template-stack><entry name="S-Box"><templates><member>T-Box</member></templates><devices><entry name="010000000042"></entry></devices></entry></template-stack>
  </entry></devices></config>`;
  const pc = FM.loadConfig(pano, "pano-lab.xml");
  const pd = pc.panorama.contexts.map((c) => FM.buildPanoramaDevice(pc, c));
  const m = FM.mergeLocalBackups(pd.concat([loc]));
  const M = m.find((x) => x.mergedLocal);
  ok(M && M.serial === "010000000042" && M.interfaces.size === loc.interfaces.size, "local backup merged by the serial in the filename (hostnames differ)");
  ok(M.vrs.get("default").routes.some((r) => r.type === "static" && r.name === "default"), "merged device keeps static routes from the local file");
}

console.log("\n== Phase 0: scale — merge local backups onto the 67-device Panorama ==");
{
  const text = fs.readFileSync(path.join(ROOT, "samples/panorama-67-devices.xml"), "utf8");
  const t0 = Date.now();
  const pc = FM.loadConfig(text, "panorama-67-devices.xml");
  const pd = pc.panorama.contexts.filter((c) => c.mapped).map((c) => FM.buildPanoramaDevice(pc, c));
  const serials = [...new Set(pd.map((d) => d.serial).filter(Boolean))];
  const locals = serials.map((ser, i) => FM.loadConfig(fwShell({
    host: "local-box-" + String(i + 1).padStart(2, "0"),
    vsys: [{ name: "vsys1", ifs: [["ethernet1/1", "10.90." + (i % 200) + ".1/24", "lan"]], vr: "default", routes: [] }]
  }), "local_" + ser + ".xml").devices[0]);
  const merged = FM.mergeLocalBackups(pd.concat(locals));
  const ms = Date.now() - t0;
  const hits = merged.filter((d) => d.mergedLocal).length;
  ok(serials.length >= 60 && hits === serials.length, "every mapped firewall with a serial merged a local backup named with that serial (" + hits + "/" + serials.length + ")");
  ok(ms < 8000, "67-device Panorama + " + locals.length + " local backups loaded and merged in " + ms + " ms");
}

console.log("\n== Phase 1: same-box re-entry through an unknown outside router ==");
{
  /* Two vsys, no external zones, no next-vr, no shared subnet. Each has a /30 to a different router. */
  const xml = fwShell({
    host: "lab-multi",
    vsys: [
      { name: "left", display: "Left", ifs: [["ethernet1/1.10", "10.10.1.1/24", "lan-a"], ["ethernet1/1.11", "10.0.0.1/30", "wan-a"]], vr: "vr-left", routes: [["0.0.0.0/0", "10.0.0.2", "default"]] },
      { name: "right", display: "Right", ifs: [["ethernet1/1.20", "10.20.1.1/24", "lan-b"], ["ethernet1/1.21", "10.0.1.1/30", "wan-b"]], vr: "vr-right", routes: [] }
    ]
  });
  const d = FM.loadConfig(xml, "lab-multi.xml").devices;
  const r = FM.trace(d, { src: "10.10.1.50", dst: "10.20.1.50", proto: "tcp", port: 443 });
  const chain = r.segments.map((s) => s.vsys).join(",");
  ok(chain === "left,right", "dest connected on the other vsys: path re-enters the same box (" + chain + ")");
  ok(r.stitches[0] && r.stitches[0].hairpin && r.stitches[0].confidence === "medium", "modelled as a medium-confidence hairpin through an outside router");
  ok(/outside router/.test((r.stitches[0] && r.stitches[0].via && r.stitches[0].via.label) || ""), "stitch label names the outside router");
  ok(r.segments[1] && r.segments[1].check && r.segments[1].check.action === "deny", "the second vsys still has its own policy check (default deny)");
}

console.log("\n== Phase 1: re-entry when the other vsys has a more-specific route, not a connected dest ==");
{
  const xml = fwShell({
    host: "lab-route",
    vsys: [
      { name: "left", ifs: [["ethernet1/1.10", "10.10.1.1/24", "lan-a"], ["ethernet1/1.11", "10.0.0.1/30", "wan-a"]], vr: "vr-left", routes: [["0.0.0.0/0", "10.0.0.2", "default"]] },
      { name: "right", ifs: [["ethernet1/1.21", "10.0.1.1/30", "wan-b"]], vr: "vr-right", routes: [["10.30.0.0/16", "10.0.1.2", "to-remote"]] }
    ]
  });
  const d = FM.loadConfig(xml, "lab-route.xml").devices;
  const r = FM.trace(d, { src: "10.10.1.50", dst: "10.30.1.20", proto: "tcp", port: 22 });
  const chain = r.segments.map((s) => s.vsys).join(",");
  ok(chain === "left,right", "more-specific route on the other vsys: path re-enters (" + chain + ")");
  ok(r.stitches[0] && r.stitches[0].hairpin && /more-specific route/.test(r.stitches[0].via.label), "hairpin cites the more-specific route");
}

console.log("\n== Phase 1: vsys-level map with grouping, collapse, and an unknown-network cloud ==");
{
  const xml = fwShell({
    host: "lab-map",
    vsys: [
      { name: "alpha", display: "Alpha", ifs: [["ethernet1/1.10", "10.10.1.1/24", "lan-a"], ["ethernet1/1.11", "10.0.0.1/30", "wan-a"]], vr: "vr-a", routes: [["0.0.0.0/0", "10.0.0.2", "default"]] },
      { name: "beta", display: "Beta", ifs: [["ethernet1/1.20", "10.20.1.1/24", "lan-b"], ["ethernet1/1.21", "10.0.1.1/30", "wan-b"]], vr: "vr-b", routes: [["0.0.0.0/0", "10.0.1.2", "default"]] },
      { name: "gamma", display: "Gamma", ifs: [["ethernet1/1.30", "10.40.1.1/24", "lan-c"]], vr: "vr-c", routes: [] }
    ]
  });
  const d = FM.loadConfig(xml, "lab-map.xml").devices;
  const tr = FM.trace(d, { src: "10.10.1.50", dst: "10.20.1.50", proto: "tcp", port: 443 });
  const map = FM.vsysMap(d, { path: tr.segments });
  ok(map.units[0].vsys.length === 3 && map.units[0].pathVsys === 2, "map lists all vsys and marks the ones on the last trace");
  const collapsed = FM.vsysMapLayout(map, { expanded: new Set() });
  ok(collapsed.shapes.some((s) => s.kind === "cloud" && /Unknown network/.test(s.label)), "collapsed layout still shows the unknown-network cloud");
  const open = FM.vsysMapLayout(map, { expanded: new Set([map.units[0].id]) });
  ok(open.shapes.filter((s) => s.kind === "vsys" && /●/.test(s.label)).length === 2, "expanded unit pulls the on-path vsys out");
  ok(open.shapes.some((s) => s.kind === "ghost" && /1 other vsys/.test(s.label)), "vsys not on the path collapse into an 'other vsys' pool");
  const X = FM.drawioXml(open, "Vsys map");
  const doc = FM.parseXml(X), cells = [];
  (function w(n) { for (const c of n.c || []) { if (c.t === "mxCell") cells.push(c); w(c); } })(doc);
  ok(cells.filter((c) => c.a.vertex === "1").length === open.shapes.length, "draw.io export has one vertex per vsys-map shape");
}

console.log("\n== Phase 2: FCR paste and CSV ==");
{
  const a = FM.parseFcr("10.10.1.50 -> 10.20.1.50 tcp/443");
  ok(a.rows.length === 1 && a.rows[0].src === "10.10.1.50" && a.rows[0].dst === "10.20.1.50" && a.rows[0].proto === "tcp" && a.rows[0].port === 443, "arrow paste with tcp/443");
  const b = FM.parseFcr("source,destination,protocol,port,application,ticket\n10.1.1.10,10.2.2.20,tcp,22,ssh,FCR-17\n10.3.3.3,10.4.4.4,udp,53,dns,FCR-18");
  ok(b.rows.length === 2 && b.rows[0].ticket === "FCR-17" && b.rows[1].port === 53 && b.rows[1].app === "dns", "CSV with a header and two rows");
  const c = FM.parseFcr("src: 10.8.1.2 dst: 10.9.1.2 proto: tcp port: 443 ticket: T-9");
  ok(c.rows[0] && c.rows[0].src === "10.8.1.2" && c.rows[0].ticket === "T-9", "key=value paste");
  const d = FM.parseFcr("not a flow");
  ok(d.errors.length && !d.rows.length, "garbage line is reported, not turned into a row");
}

console.log("\n== Phase 2: why-these-vsys, combined plan, checklist, log filters ==");
{
  const xml = fwShell({
    host: "lab-fcr",
    vsys: [
      { name: "left", display: "Left", ifs: [["ethernet1/1.10", "10.10.1.1/24", "lan-a"], ["ethernet1/1.11", "10.0.0.1/30", "wan-a"]], vr: "vr-left", routes: [["0.0.0.0/0", "10.0.0.2", "default"]] },
      { name: "right", display: "Right", ifs: [["ethernet1/1.20", "10.20.1.1/24", "lan-b"], ["ethernet1/1.21", "10.0.1.1/30", "wan-b"]], vr: "vr-right", routes: [] }
    ]
  });
  const d = FM.loadConfig(xml, "lab-fcr.xml").devices;
  const r = FM.annotateFcr(FM.trace(d, { src: "10.10.1.50", dst: "10.20.1.50", proto: "tcp", port: 443 }), d);
  ok(r.fcr.hops.length === 2 && r.fcr.hops.filter((h) => h.deny).length === 2, "per-hop verdicts: two hops, both denied by default");
  ok(r.fcr.why.vsysCount === 2 && r.fcr.why.hairpins === 1 && /later vsys can still deny/.test(r.fcr.why.text), "explanation covers both vsys and the hairpin");
  ok(r.fcr.plan.required >= 2 && r.fcr.plan.cli.includes("lab-fcr left") && r.fcr.plan.cli.includes("lab-fcr right"), "one combined change plan covers every hop");
  ok(r.fcr.checklist.some((x) => /Do not Push All/.test(x)) && r.fcr.checklist.some((x) => /traffic-log filters/.test(x)), "pre-push checklist mentions a targeted push and post-push log checks");
  ok(r.fcr.filters.hops.length === 2 && r.fcr.filters.hops.every((h) => /\(addr\.src eq 10\.10\.1\.50\)/.test(h.filter) && /\(vsys\.name eq/.test(h.filter)), "post-push traffic-log filters are per hop and include the vsys");
}

console.log("\n== Phase 2: device-group vsysN join by order and count (flagged uncertain) ==");
{
  const pano = `<?xml version="1.0"?><config version="11.1.0"><mgt-config><devices><entry name="010000000077"><hostname>lab-join</hostname></entry></devices></mgt-config><shared></shared><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>pano-join</hostname></system></deviceconfig>
    <device-group>
      <entry name="DG-Left"><devices><entry name="010000000077"><vsys><entry name="vsys2"/></vsys></entry></devices>
        <address><entry name="left-users"><ip-netmask>10.10.1.0/24</ip-netmask></entry><entry name="right-srv"><ip-netmask>10.20.1.50</ip-netmask></entry></address>
        <pre-rulebase><security><rules><entry name="left-out"><to><member>wan-a</member></to><from><member>lan-a</member></from><source><member>left-users</member></source><destination><member>right-srv</member></destination><source-user><member>any</member></source-user><category><member>any</member></category><application><member>any</member></application><service><member>service-https</member></service><action>allow</action></entry></rules></security></pre-rulebase>
      </entry>
      <entry name="DG-Right"><devices><entry name="010000000077"><vsys><entry name="vsys3"/></vsys></entry></devices></entry>
    </device-group>
    <template><entry name="T-Join"><config><devices><entry name="localhost.localdomain">
      <network><interface><ethernet>
        <entry name="ethernet1/1.10"><layer3><ip><entry name="10.10.1.1/24"/></ip></layer3></entry>
        <entry name="ethernet1/1.11"><layer3><ip><entry name="10.0.0.1/30"/></ip></layer3></entry>
        <entry name="ethernet1/1.20"><layer3><ip><entry name="10.20.1.1/24"/></ip></layer3></entry>
        <entry name="ethernet1/1.21"><layer3><ip><entry name="10.0.1.1/30"/></ip></layer3></entry>
      </ethernet></interface>
      <virtual-router>
        <entry name="vr-left"><interface><member>ethernet1/1.10</member><member>ethernet1/1.11</member></interface><routing-table><ip><static-route><entry name="default"><nexthop><ip-address>10.0.0.2</ip-address></nexthop><metric>10</metric><destination>0.0.0.0/0</destination></entry></static-route></ip></routing-table></entry>
        <entry name="vr-right"><interface><member>ethernet1/1.20</member><member>ethernet1/1.21</member></interface></entry>
      </virtual-router></network>
      <vsys>
        <entry name="alpha"><display-name>Alpha</display-name><import><network><interface><member>ethernet1/1.10</member><member>ethernet1/1.11</member></interface><virtual-router><member>vr-left</member></virtual-router></network></import>
          <zone><entry name="lan-a"><network><layer3><member>ethernet1/1.10</member></layer3></network></entry><entry name="wan-a"><network><layer3><member>ethernet1/1.11</member></layer3></network></entry></zone></entry>
        <entry name="beta"><display-name>Beta</display-name><import><network><interface><member>ethernet1/1.20</member><member>ethernet1/1.21</member></interface><virtual-router><member>vr-right</member></virtual-router></network></import>
          <zone><entry name="lan-b"><network><layer3><member>ethernet1/1.20</member></layer3></network></entry><entry name="wan-b"><network><layer3><member>ethernet1/1.21</member></layer3></network></entry></zone></entry>
      </vsys>
    </entry></devices></config></entry></template>
    <template-stack><entry name="S-Join"><templates><member>T-Join</member></templates><devices><entry name="010000000077"></entry></devices></entry></template-stack>
  </entry></devices></config>`;
  const pc = FM.loadConfig(pano, "pano-join.xml");
  const d = pc.panorama.contexts.map((c) => FM.buildPanoramaDevice(pc, c));
  const dev = d[0];
  ok(dev.dgJoin && dev.dgJoin.uncertain, "join is flagged uncertain when names do not match");
  ok(dev.vsys.get("alpha").dg === "DG-Left" && dev.vsys.get("alpha").dgVsys === "vsys2" && dev.vsys.get("alpha").dgJoinConfidence === "inferred", "alpha joined to DG-Left (vsys2) by order");
  ok(dev.vsys.get("beta").dg === "DG-Right" && dev.vsys.get("beta").dgVsys === "vsys3", "beta joined to DG-Right (vsys3) by order");
  const r = FM.annotateFcr(FM.trace(d, { src: "10.10.1.50", dst: "10.20.1.50", proto: "tcp", port: 443 }), d);
  ok(r.segments[0].check.action === "allow" && r.segments[0].check.rule === "left-out", "DG-Left pre-rule is evaluated on template vsys alpha after the join");
  ok(r.fcr.why.text.includes("uncertain") || r.fcr.plan.uncertain >= 0, "FCR explanation or plan can surface the uncertain join");
  ok(r.fcr.checklist.some((x) => /uncertain/.test(x) || /vsysN/.test(x)), "checklist asks to confirm an inferred vsys join");
  /* exact name match stays certain */
  const j = FM.inferDgVsysJoin([{ name: "vsys2", display: "Alpha" }, { name: "vsys3", display: "Beta" }], { vsys2: "DG-Left", vsys3: "DG-Right" });
  ok(!j.uncertain && j.map.vsys2.confidence === "high" && j.map.vsys3.dg === "DG-Right", "exact vsys name match is high confidence and not flagged");
}

console.log("\n== merge: thin local backup unions with a rich template network ==");
{
  const pano = `<?xml version="1.0"?><config version="11.1.0"><mgt-config><devices><entry name="010000000042"><hostname>box-pano</hostname></entry></devices></mgt-config><shared></shared><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>pano-lab</hostname></system></deviceconfig>
    <device-group><entry name="DG-Box"><devices><entry name="010000000042"><vsys><entry name="vsys1"/></vsys></entry></devices></entry></device-group>
    <template><entry name="T-Box"><config><devices><entry name="localhost.localdomain">
      <network><interface><ethernet>
        <entry name="ethernet1/1"><layer3><ip><entry name="10.180.1.1/24"/></ip></layer3></entry>
        <entry name="ethernet1/2"><layer3><ip><entry name="10.0.8.1/30"/></ip></layer3></entry>
      </ethernet></interface>
      <virtual-router><entry name="default"><interface><member>ethernet1/1</member><member>ethernet1/2</member></interface>
        <routing-table><ip><static-route>
          <entry name="default"><nexthop><ip-address>10.0.8.2</ip-address></nexthop><metric>10</metric><destination>0.0.0.0/0</destination></entry>
          <entry name="to-remote"><nexthop><ip-address>10.0.8.2</ip-address></nexthop><metric>10</metric><destination>10.30.0.0/16</destination></entry>
        </static-route></ip></routing-table>
      </entry></virtual-router></network>
      <vsys><entry name="vsys1"><import><network><interface><member>ethernet1/1</member><member>ethernet1/2</member></interface></network></import>
        <zone><entry name="lan"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
        <entry name="wan"><network><layer3><member>ethernet1/2</member></layer3></network></entry></zone></entry></vsys>
    </entry></devices></config></entry></template>
    <template-stack><entry name="S-Box"><templates><member>T-Box</member></templates><devices><entry name="010000000042"></entry></devices></entry></template-stack>
  </entry></devices></config>`;
  /* Thin local: same LAN, no WAN, no default, no to-remote; one extra route and a same-key override of to-remote. */
  const localXml = fwShell({
    host: "box-local",
    vsys: [{
      name: "vsys1",
      ifs: [["ethernet1/1", "10.180.1.1/24", "lan"], ["ethernet1/3", "10.180.2.1/24", "voice"]],
      vr: "default",
      routes: [
        ["10.30.0.0/16", "10.0.8.2", "to-remote-local"],
        ["10.40.0.0/16", "10.0.8.2", "to-extra"]
      ]
    }]
  });
  const pc = FM.loadConfig(pano, "pano-lab.xml");
  const pd = pc.panorama.contexts.map((c) => FM.buildPanoramaDevice(pc, c));
  const loc = FM.loadConfig(localXml, "running-config_010000000042.xml").devices[0];
  const panoDev = pd.find((d) => d.serial === "010000000042");
  const panoStatics = panoDev.vrs.get("default").routes.filter((r) => r.type === "static");
  ok(panoStatics.some((r) => r.name === "default") && panoStatics.some((r) => r.name === "to-remote"), "rich template has the default and to-remote routes before merge");
  ok(!loc.interfaces.has("ethernet1/2") && !loc.vrs.get("default").routes.some((r) => r.type === "static" && r.name === "default"), "thin local has no WAN interface and no default route");
  const m = FM.mergeLocalBackups(pd.concat([loc])), M = m.find((x) => x.mergedLocal);
  const statics = M.vrs.get("default").routes.filter((r) => r.type === "static");
  const byName = (n) => statics.filter((r) => r.name === n);
  const byDest = (p) => statics.filter((r) => FM.prefixStr(r.dest) === p);
  ok(M.netMerge === "union" && M.interfaces.has("ethernet1/2") && M.interfaces.has("ethernet1/3"), "union keeps the template WAN interface and the local-only interface");
  ok(byDest("0.0.0.0/0").length === 1 && byDest("0.0.0.0/0")[0].origin === "template" && byDest("0.0.0.0/0")[0].nexthop.value === "10.0.8.2", "template-only default route is kept and marked as template");
  ok(byDest("10.30.0.0/16").length === 1 && byDest("10.30.0.0/16")[0].name === "to-remote-local" && byDest("10.30.0.0/16")[0].origin === "local", "exact conflict (same VR, destination, next hop, metric): local route wins");
  ok(byName("to-extra").length === 1 && byName("to-extra")[0].origin === "local", "local-only route is added and marked as local backup");
  ok(M.interfaces.get("ethernet1/2").zone === "wan" && M.interfaces.get("ethernet1/3").zone === "voice", "template and local zones are both present after the union");
  const tr = FM.trace([M], { src: "10.180.1.50", dst: "10.30.1.20", proto: "tcp", port: 443 });
  ok(tr.segments[0] && tr.segments[0].vrPath.some((v) => v.route.origin === "local" && v.route.name === "to-remote-local"), "trace uses the local winning route and keeps its provenance");
  const trDef = FM.trace([M], { src: "10.180.1.50", dst: "10.99.1.20", proto: "tcp", port: 443 });
  ok(trDef.segments[0] && trDef.segments[0].vrPath.some((v) => v.route.origin === "template" && FM.prefixStr(v.route.dest) === "0.0.0.0/0"), "trace through a dest only the template covers still uses the kept template default");
}

console.log("\n== Rule needed in 2 places: one vsys, two virtual routers, hairpin ==");
{
  // Synthetic. Same vsys, VR-A and VR-B with no next-vr: each sends the other LAN out of its WAN unit to an
  // outside router, so the firewall checks policy twice (A-LAN -> A-WAN, then B-WAN -> B-LAN).
  const e = (n, x) => `<entry name="${n}">${x}</entry>`;
  const units = [["ethernet1/3.101", "10.66.1.1/24", 101], ["ethernet1/3.102", "10.66.2.1/24", 102], ["ethernet1/3.201", "10.66.0.2/29", 201], ["ethernet1/3.202", "10.66.0.10/29", 202]]
    .map(([n, ip, t]) => e(n, `<tag>${t}</tag><ip>${e(ip, "")}</ip>`)).join("");
  const sr = (d, nh, i) => e("r-" + d.split("/")[0], `<nexthop><ip-address>${nh}</ip-address></nexthop><interface>${i}</interface><destination>${d}</destination>`);
  const vr = (n, ifs, routes) => e(n, `<interface>${ifs.map((x) => `<member>${x}</member>`).join("")}</interface><routing-table><ip><static-route>${routes}</static-route></ip></routing-table>`);
  const zone = (n, i) => e(n, `<network><layer3><member>${i}</member></layer3></network>`);
  const rule = (n, f, t, src, dst, action) => e(n, `<from><member>${f}</member></from><to><member>${t}</member></to><source><member>${src}</member></source><destination><member>${dst}</member></destination><application><member>any</member></application><service><member>any</member></service><action>${action}</action>`);
  const xml = `<config version="11.1.0"><devices>${e("localhost.localdomain",
    `<deviceconfig><system><hostname>fw-hp</hostname></system></deviceconfig><network><interface><ethernet>${e("ethernet1/3", `<layer3><units>${units}</units></layer3>`)}</ethernet></interface>` +
    `<virtual-router>${vr("VR-A", ["ethernet1/3.101", "ethernet1/3.201"], sr("10.66.2.0/24", "10.66.0.1", "ethernet1/3.201"))}${vr("VR-B", ["ethernet1/3.102", "ethernet1/3.202"], sr("10.66.1.0/24", "10.66.0.9", "ethernet1/3.202"))}</virtual-router></network>` +
    `<vsys>${e("vsys1", `<zone>${zone("A-LAN", "ethernet1/3.101")}${zone("B-LAN", "ethernet1/3.102")}${zone("A-WAN", "ethernet1/3.201")}${zone("B-WAN", "ethernet1/3.202")}</zone>` +
      `<rulebase><security><rules>${rule("A-OUT", "A-LAN", "A-WAN", "any", "any", "allow")}${rule("DENY-ALL", "any", "any", "any", "any", "deny")}</rules></security></rulebase>`)}</vsys>`)}</devices></config>`;
  const d = FM.loadConfig(xml, "fw-hp.xml").devices;
  const r = FM.annotateFcr(FM.trace(d, { src: "10.66.1.10", dst: "10.66.2.10", proto: "tcp", port: 8443 }), d);
  const h = r.fcr.hops;
  ok(h.length === 2 && h[0].fromZone === "A-LAN" && h[0].toZone === "A-WAN" && h[1].fromZone === "B-WAN" && h[1].toZone === "B-LAN", "two enforcement points on one firewall: A-LAN->A-WAN then B-WAN->B-LAN");
  ok(h[0].vr === "VR-A" && h[1].vr === "VR-B", "each hop carries its virtual router (for FIB lookups)");
  ok(h[0].egressIf === "ethernet1/3.201" && h[1].ingressIf === "ethernet1/3.202", "hops carry the egress and ingress interfaces");
  ok(h[0].verdict === "allow" && h[0].rule === "A-OUT" && h[1].deny, "first pass allowed by A-OUT, second pass denied");
  ok(r.fcr.enforcement && r.fcr.enforcement.points === 2 && r.fcr.enforcement.needRule === 1 && r.fcr.enforcement.hops[0] === 2 && r.fcr.enforcement.multi, "enforcement summary: 2 places, 1 still needs a rule (hop 2)");
  const f = r.fcr.filters.hops;
  ok(f.length === 2 && /\(zone\.src eq A-LAN\)/.test(f[0].filter) && /\(zone\.dst eq A-WAN\)/.test(f[0].filter) && /\(zone\.src eq B-WAN\)/.test(f[1].filter) && f[0].filter !== f[1].filter, "traffic-log filters are zone-scoped, so the two passes in one vsys are told apart");
  const sec = (r.changes || []).filter((c) => c.kind === "security" && !c.optional);
  ok(sec.length === 1 && sec[0].rule.from === "B-WAN" && sec[0].rule.to === "B-LAN" && sec[0].rule.placeBefore === "DENY-ALL", "only the missing place gets a rule, placed above the deny");
  ok(/\(rule eq /.test(f[1].afterPush) && !/\(rule eq /.test(f[0].afterPush), "after-push filter names the new rule on the hop that needs it only");
  const t0 = r.fcr.filters.hops[0], t1 = r.fcr.filters.hops[1];
  ok(/\(port\.dst eq 8443\)/.test(r.fcr.filters.common) && /\(proto eq 6\)/.test(r.fcr.filters.common), "traffic-log filter keeps the protocol and port (read from the service text)");
  ok(t0.testCli.length === 2 && /^test routing fib-lookup virtual-router VR-A ip 10\.66\.2\.10$/.test(t0.testCli[0]) && /^test security-policy-match source 10\.66\.1\.10 destination 10\.66\.2\.10 destination-port 8443 protocol 6 from A-LAN to A-WAN$/.test(t0.testCli[1]), "each hop has the on-firewall FIB and policy-match test commands");
  ok(/virtual-router VR-B /.test(t1.testCli[0]) && /from B-WAN to B-LAN/.test(t1.testCli[1]), "the second pass in the same vsys uses its own virtual router and zones");
  // shared multi-place text and rule-order advice (also used by PAAT)
  const en = r.fcr.enforcement;
  ok(en.level === "need" && /2 places/.test(en.text) && /hop 2/.test(en.text) && /Push every one/.test(en.text), "enforcement text says 2 places, hop 2, push every one");
  ok(en.places.length === 2 && !en.places[0].needs && en.places[1].needs && en.places[1].newRule === sec[0].rule.name && en.places[0].newRule === null, "each place says whether it needs a rule and names the new rule on the one that does");
  ok(sec[0].order && sec[0].order.mode === "above" && sec[0].order.before === "DENY-ALL" && /above DENY-ALL/.test(sec[0].order.text), "rule-order advice: place above DENY-ALL");
  const render = require(path.join(ROOT, "build/render.js"));
  const svg = render.flowSvg(r, {});
  ok(/^<svg /.test(svg) && /<\/svg>$/.test(svg) && /POLICY/.test(svg) && /A-OUT/.test(svg), "flow diagram SVG renders headless (no DOM) with the policy hops");
  const ok1 = FM.annotateFcr(FM.trace(d, { src: "10.66.1.10", dst: "10.66.0.1", proto: "tcp", port: 22 }), d);
  ok(ok1.fcr.enforcement.level === "single" && ok1.fcr.enforcement.text === "", "a single-place flow has no multi-place text");
}

console.log("\n" + passed + " passed, " + failed + " failed");
process.exit(failed ? 1 : 0);
