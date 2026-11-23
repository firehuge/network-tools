#!/usr/bin/env node
/* Synthetic samples for FlowMapper Phase 3 (BGP inference, pasted route tables, shared / overlapping address space).
 * All names, addresses and serials are made up (RFC 1918 / documentation ranges, 0099... serials). Run: node samples/generate_phase3.mjs */
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
const fw = (ver, host, network, vs) => '<?xml version="1.0"?>\n<config version="' + ver + '" detail-version="' + ver + '.2">\n  <shared/>\n  <devices><entry name="localhost.localdomain"><network>' + network + "</network><deviceconfig><system><hostname>" + host + "</hostname></system></deviceconfig>" + vs + "</entry></devices>\n</config>\n";
const sr = (name, dst, nh) => '<entry name="' + name + '"><destination>' + dst + "</destination><nexthop><ip-address>" + nh + "</ip-address></nexthop><metric>10</metric></entry>";

/* ---------- 1) Advanced Routing Engine (PAN-OS 11.1 logical routers), eBGP between two data-center core firewalls ----------
 dc1 (AS 65010)  ethernet1/1 10.200.0.1/30 ---- 10.200.0.2/30 ethernet1/1  dc2 (AS 65020)
   apps 10.10.1.0/24, db 10.10.2.0/24, mgmt 10.10.9.0/24          users 10.20.1.0/24, backup 10.20.200.0/24
 dc1: redistributes connected (RP-CONN); aggregate 10.10.0.0/22 summary-only; network statement 10.10.50.0/24 (static);
      outbound prefix list PL-NO-MGMT denies 10.10.9.0/24.
 dc2: redistributes connected; conditional advertisement: 10.20.200.0/24 only while 10.20.1.0/24 does NOT exist (backup LAN). */
const prof = (redist, filtering, filters) => "<routing-profile><bgp><redistribution-profile>" + redist + "</redistribution-profile><filtering-profile>" + filtering + "</filtering-profile></bgp><filters>" + filters + "</filters></routing-profile>";
const rpConn = '<entry name="RP-CONN"><ipv4><unicast><connected><enable>yes</enable></connected><static><enable>no</enable></static></unicast></ipv4></entry>';
const pl = (name, list) => '<entry name="' + name + '"><type><ipv4><ipv4-entry>' + list.map(([seq, action, net, ge, le]) => '<entry name="' + seq + '"><action>' + action + "</action><prefix>" + (net === "any" ? "<network>any</network>" : "<entry><network>" + net + "</network>" + (ge ? "<greater-than-or-equal>" + ge + "</greater-than-or-equal>" : "") + (le ? "<less-than-or-equal>" + le + "</less-than-or-equal>" : "") + "</entry>") + "</prefix></entry>").join("") + "</ipv4-entry></ipv4></type></entry>";
const rmap = (name, list) => '<entry name="' + name + '"><route-map>' + list.map(([seq, action, plist]) => '<entry name="' + seq + '"><action>' + action + "</action>" + (plist ? "<match><ipv4><address><prefix-list>" + plist + "</prefix-list></address></ipv4></match>" : "") + "</entry>").join("") + "</route-map></entry>";
const lr = (name, ifs, bgp, statics) => '<logical-router><entry name="' + name + '"><vrf><entry name="default"><interface>' + m(ifs) + "</interface>" + (statics ? "<routing-table><ip><static-route>" + statics + "</static-route></ip></routing-table>" : "") + "<bgp>" + bgp + "</bgp></entry></vrf></entry></logical-router>";
const dc1Net = "<interface>" + eth([["ethernet1/1", "10.200.0.1/30"], ["ethernet1/2", "10.10.1.1/24"], ["ethernet1/3", "10.10.2.1/24"], ["ethernet1/4", "10.10.9.1/24"]]) + "</interface>" +
  lr("LR-CORE", ["ethernet1/1", "ethernet1/2", "ethernet1/3", "ethernet1/4"],
    "<enable>yes</enable><router-id>10.200.0.1</router-id><local-as>65010</local-as><install-route>yes</install-route><redistribution-profile><ipv4><unicast>RP-CONN</unicast></ipv4></redistribution-profile>" +
    '<advertise-network><ipv4><network><entry name="10.10.50.0/24"><unicast>yes</unicast></entry></network></ipv4></advertise-network>' +
    '<aggregate-routes><entry name="AGG-DC1"><enable>yes</enable><summary-only>yes</summary-only><type><ipv4><summary-prefix>10.10.0.0/22</summary-prefix></ipv4></type></entry></aggregate-routes>' +
    '<peer-group><entry name="PG-DC2"><enable>yes</enable><type><ebgp/></type><filtering-profile><ipv4>FP-OUT</ipv4></filtering-profile><peer><entry name="dc2"><enable>yes</enable><peer-as>65020</peer-as><local-address><interface>ethernet1/1</interface><ip>10.200.0.1/30</ip></local-address><peer-address><ip>10.200.0.2</ip></peer-address></entry></peer></entry></peer-group>',
    sr("apps-50", "10.10.50.0/24", "10.10.2.254")) +
  prof(rpConn, '<entry name="FP-OUT"><ipv4><unicast><outbound-network-filters><prefix-list>PL-NO-MGMT</prefix-list></outbound-network-filters></unicast></ipv4></entry>',
    "<prefix-list>" + pl("PL-NO-MGMT", [[10, "deny", "10.10.9.0/24"], [20, "permit", "any"]]) + "</prefix-list>");
const dc2Net = "<interface>" + eth([["ethernet1/1", "10.200.0.2/30"], ["ethernet1/2", "10.20.1.1/24"], ["ethernet1/3", "10.20.200.1/24"]]) + "</interface>" +
  lr("LR-CORE", ["ethernet1/1", "ethernet1/2", "ethernet1/3"],
    "<enable>yes</enable><router-id>10.200.0.2</router-id><local-as>65020</local-as><redistribution-profile><ipv4><unicast>RP-CONN</unicast></ipv4></redistribution-profile>" +
    '<peer-group><entry name="PG-DC1"><enable>yes</enable><type><ebgp/></type><peer><entry name="dc1"><enable>yes</enable><peer-as>65010</peer-as><inherit><no><filtering-profile><ipv4>FP-COND</ipv4></filtering-profile></no></inherit><local-address><interface>ethernet1/1</interface></local-address><peer-address><ip>10.200.0.1</ip></peer-address></entry></peer></entry></peer-group>') +
  prof(rpConn, '<entry name="FP-COND"><ipv4><unicast><conditional-advertisement><non-exist><advertise-map>RM-BACKUP</advertise-map><non-exist-map>RM-PRIMARY</non-exist-map></non-exist></conditional-advertisement></unicast></ipv4></entry>',
    "<prefix-list>" + pl("PL-BACKUP", [[10, "permit", "10.20.200.0/24"]]) + pl("PL-PRIMARY", [[10, "permit", "10.20.1.0/24"]]) + "</prefix-list><route-maps><bgp><bgp-entry>" + rmap("RM-BACKUP", [[10, "permit", "PL-BACKUP"]]) + rmap("RM-PRIMARY", [[10, "permit", "PL-PRIMARY"]]) + "</bgp-entry></bgp></route-maps>");
const dc1Vs = vsys(["ethernet1/1", "ethernet1/2", "ethernet1/3", "ethernet1/4"], { transit: ["ethernet1/1"], apps: ["ethernet1/2"], db: ["ethernet1/3"], mgmt: ["ethernet1/4"] },
  [rule("dc2-to-dc1", ["transit"], ["apps", "db", "mgmt"], ["any"], ["any"], "any"), rule("dc1-out", ["apps", "db", "mgmt"], ["transit"], ["any"], ["any"], "any")]);
const dc2Vs = vsys(["ethernet1/1", "ethernet1/2", "ethernet1/3"], { transit: ["ethernet1/1"], users: ["ethernet1/2"], backup: ["ethernet1/3"] },
  [rule("users-to-dc1", ["users", "backup"], ["transit"], ["any"], ["any"], "any"), rule("dc1-to-dc2", ["transit"], ["users", "backup"], ["any"], ["any"], "any")]);
W("fw-are-bgp-dc1.xml", fw("11.1.0", "dc1-core-fw", dc1Net, dc1Vs));
W("fw-are-bgp-dc2.xml", fw("11.1.0", "dc2-core-fw", dc2Net, dc2Vs));
// the same two firewalls managed by Panorama: BGP, routing profiles and filters live in the templates (one per stack)
const tplA = (name, net, vs, h) => '<entry name="' + name + '"><config><devices><entry name="localhost.localdomain"><network>' + net + "</network><deviceconfig><system><hostname>" + h + "</hostname></system></deviceconfig>" + vs + "</entry></devices></config></entry>";
const panoA = '<?xml version="1.0"?>\n<config version="11.1.0" detail-version="11.1.4">\n  <mgt-config><devices><entry name="009920000001"/><entry name="009920000002"/></devices></mgt-config>\n  <shared/>\n  <devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>pano-are</hostname></system></deviceconfig><device-group><entry name="DG-DC"><devices><entry name="009920000001"/><entry name="009920000002"/></devices></entry></device-group><template>' +
  tplA("T-DC1", dc1Net, dc1Vs, "dc1-core-fw") + tplA("T-DC2", dc2Net, dc2Vs, "dc2-core-fw") + '</template><template-stack><entry name="ST-DC1"><templates><member>T-DC1</member></templates><devices><entry name="009920000001"/></devices></entry><entry name="ST-DC2"><templates><member>T-DC2</member></templates><devices><entry name="009920000002"/></devices></entry></template-stack></entry></devices>\n</config>\n';
W("panorama-are-bgp.xml", panoA);

/* ---------- 2) Legacy virtual router BGP through a Panorama template stack (PAN-OS 10.1 style) ----------
 hub (AS 65100) eth1/1 10.201.0.1/30 --- 10.201.0.2/30 branch (AS 65200)
 hub: redistributes connected via redist profile; aggregate 10.30.0.0/16 (summary); export rules: deny 10.30.99.0/24 to the branch group, then allow everything else (PAN-OS denies what no rule matches once any rule applies).
 branch: redistributes connected; conditional advertisement: 10.40.200.0/24 only while 10.40.1.0/24 is absent. */
const legVr = (ifs, bgp, redist) => '<virtual-router><entry name="default"><interface>' + m(ifs) + "</interface><protocol><redist-profile>" + redist + "</redist-profile><bgp>" + bgp + "</bgp></protocol></entry></virtual-router>";
const legRedist = '<entry name="CONN"><filter><type>' + m(["connect"]) + '</type></filter><priority>1</priority><action><redist/></action></entry>';
const hubNet = "<interface>" + eth([["ethernet1/1", "10.201.0.1/30"], ["ethernet1/2", "10.30.1.1/24"], ["ethernet1/3", "10.30.99.1/24"]]) + "</interface>" +
  legVr(["ethernet1/1", "ethernet1/2", "ethernet1/3"], "<enable>yes</enable><router-id>10.201.0.1</router-id><local-as>65100</local-as>" +
    '<peer-group><entry name="BRANCHES"><enable>yes</enable><type><ebgp/></type><peer><entry name="branch1"><enable>yes</enable><peer-as>65200</peer-as><local-address><interface>ethernet1/1</interface></local-address><peer-address><ip>10.201.0.2</ip></peer-address></entry></peer></entry></peer-group>' +
    '<redist-rules><entry name="CONN"><enable>yes</enable><address-family-identifier>ipv4</address-family-identifier></entry></redist-rules>' +
    '<policy><export><rules><entry name="no-lab"><enable>yes</enable><used-by>' + m(["BRANCHES"]) + '</used-by><match><address-prefix><entry name="10.30.99.0/24"><exact>yes</exact></entry></address-prefix></match><action><deny/></action></entry><entry name="allow-rest"><enable>yes</enable><used-by>' + m(["BRANCHES"]) + '</used-by><match/><action><allow><update/></allow></action></entry></rules></export>' +
    '<aggregation><address><entry name="AGG-HUB"><prefix>10.30.0.0/16</prefix><enable>yes</enable><summary>no</summary></entry></address></aggregation></policy>', legRedist);
const brNet = "<interface>" + eth([["ethernet1/1", "10.201.0.2/30"], ["ethernet1/2", "10.40.1.1/24"], ["ethernet1/3", "10.40.200.1/24"]]) + "</interface>" +
  legVr(["ethernet1/1", "ethernet1/2", "ethernet1/3"], "<enable>yes</enable><router-id>10.201.0.2</router-id><local-as>65200</local-as>" +
    '<peer-group><entry name="HUB"><enable>yes</enable><type><ebgp/></type><peer><entry name="hub"><enable>yes</enable><peer-as>65100</peer-as><local-address><interface>ethernet1/1</interface></local-address><peer-address><ip>10.201.0.1</ip></peer-address></entry></peer></entry></peer-group>' +
    '<redist-rules><entry name="CONN"><enable>yes</enable></entry></redist-rules>' +
    '<policy><conditional-advertisement><policy><entry name="BACKUP-LAN"><enable>yes</enable><used-by>' + m(["HUB"]) + '</used-by><non-exist-filters><entry name="primary"><enable>yes</enable><match><address-prefix><entry name="10.40.1.0/24"/></address-prefix></match></entry></non-exist-filters><advertise-filters><entry name="backup"><enable>yes</enable><match><address-prefix><entry name="10.40.200.0/24"/></address-prefix></match></entry></advertise-filters></entry></policy></conditional-advertisement></policy>', legRedist);
const tpl = (name, net, vs) => '<entry name="' + name + '"><config><devices><entry name="localhost.localdomain"><network>' + net + "</network>" + vs + "</entry></devices></config></entry>";
const hubVs = vsys(["ethernet1/1", "ethernet1/2", "ethernet1/3"], { wan: ["ethernet1/1"], lan: ["ethernet1/2", "ethernet1/3"] }, []);
const brVs = vsys(["ethernet1/1", "ethernet1/2", "ethernet1/3"], { wan: ["ethernet1/1"], lan: ["ethernet1/2", "ethernet1/3"] }, []);
const pano = (devs, dgs, tpls, stacks) => '<?xml version="1.0"?>\n<config version="10.1.0" detail-version="10.1.9">\n  <mgt-config><devices>' + devs.map((s) => '<entry name="' + s + '"/>').join("") + "</devices></mgt-config>\n  <shared/>\n  <devices><entry name=\"localhost.localdomain\"><deviceconfig><system><hostname>pano-phase3</hostname></system></deviceconfig><device-group>" + dgs + "</device-group><template>" + tpls + "</template><template-stack>" + stacks + "</template-stack></entry></devices>\n</config>\n";
const dg = (name, serials, rules) => '<entry name="' + name + '"><devices>' + serials.map((s) => '<entry name="' + s + '"/>').join("") + "</devices><pre-rulebase><security><rules>" + rules.join("") + "</rules></security></pre-rulebase></entry>";
const stack = (name, tpls, serial) => '<entry name="' + name + '"><templates>' + m(tpls) + '</templates><devices><entry name="' + serial + '"/></devices></entry>';
W("panorama-legacy-bgp.xml", pano(["009930000001", "009930000002"],
  dg("DG-ALL", ["009930000001", "009930000002"], [rule("lan-wan", ["lan"], ["wan"], ["any"], ["any"], "any"), rule("wan-lan", ["wan"], ["lan"], ["any"], ["any"], "any")]),
  tpl("T-HUB", hubNet, hubVs) + tpl("T-BRANCH", brNet, brVs), stack("ST-HUB", ["T-HUB"], "009930000001") + stack("ST-BRANCH", ["T-BRANCH"], "009930000002")));

/* ---------- 3) Shared / overlapping address space: cloned core builds in two data centers ----------
 edge-dal-fw (ST-DAL) routes 10.50.0.0/16 via 10.99.0.2. Both core-dc1-fw (ST-DC1) and core-dc2-fw (ST-DC2) were built from one
 template and carry 10.99.0.2/29 and 10.50.1.1/24. Not an HA pair (different stacks, different sites); the trace must ask. */
const coreNet = "<interface>" + eth([["ethernet1/1", "10.99.0.2/29"], ["ethernet1/2", "10.50.1.1/24"]]) + '</interface><virtual-router><entry name="default"><interface>' + m(["ethernet1/1", "ethernet1/2"]) + '</interface><routing-table><ip><static-route>' + sr("users", "10.1.0.0/16", "10.99.0.1") + "</static-route></ip></routing-table></entry></virtual-router>";
const edgeNet = "<interface>" + eth([["ethernet1/1", "10.99.0.1/29"], ["ethernet1/2", "10.1.1.1/24"]]) + '</interface><virtual-router><entry name="default"><interface>' + m(["ethernet1/1", "ethernet1/2"]) + '</interface><routing-table><ip><static-route>' + sr("apps", "10.50.0.0/16", "10.99.0.2") + "</static-route></ip></routing-table></entry></virtual-router>";
const zvs = (a, b) => vsys(["ethernet1/1", "ethernet1/2"], { [a]: ["ethernet1/1"], [b]: ["ethernet1/2"] }, []);
const host = (h) => "<deviceconfig><system><hostname>" + h + "</hostname></system></deviceconfig>";
const tplH = (name, net, vs, h) => '<entry name="' + name + '"><config><devices><entry name="localhost.localdomain"><network>' + net + "</network>" + host(h) + vs + "</entry></devices></config></entry>";
W("panorama-cloned-dc.xml", pano(["009940000001", "009940000002", "009940000003"],
  dg("DG-ALL", ["009940000001", "009940000002", "009940000003"], [rule("users-to-apps", ["users", "core"], ["core", "apps"], ["any"], ["any"], "service-https")]),
  tplH("T-EDGE", edgeNet, zvs("core", "users"), "edge-dal-fw") + tplH("T-CORE-DC1", coreNet, zvs("core", "apps"), "core-dc1-fw") + tplH("T-CORE-DC2", coreNet, zvs("core", "apps"), "core-dc2-fw"),
  stack("ST-DAL", ["T-EDGE"], "009940000001") + stack("ST-DC1", ["T-CORE-DC1"], "009940000002") + stack("ST-DC2", ["T-CORE-DC2"], "009940000003")));

/* ---------- 4) Route tables to paste (what the firewalls would really show) ---------- */
W("routes/dc2-show-advanced-routing-route.txt", `flags: A:active, E:ecmp, R:recursive, Oi:ospf intra-area, Oo:ospf inter-area, O1:ospf ext 1, O2:ospf ext 2

destination                protocol    nexthop          distance  metric  flag  tag   age        interface
-------------------------------------------------------------------------------------------------------------
Logical Router: LR-CORE
==========================
10.10.0.0/22               bgp         10.200.0.1       20        0       A           01:02:03   ethernet1/1
10.10.9.0/24               bgp         10.200.0.1       20        0       A           01:02:03   ethernet1/1
10.10.50.0/24              bgp         10.200.0.1       20        0       A           01:02:03   ethernet1/1
10.20.1.0/24               connected   0.0.0.0          0         0       A           5d:01:02   ethernet1/2
10.20.200.0/24             connected   0.0.0.0          0         0       A           5d:01:02   ethernet1/3
10.200.0.0/30              connected   0.0.0.0          0         0       A           5d:01:02   ethernet1/1
total routes shown: 6
`);
W("routes/hub-show-routing-route.txt", `flags: A:active, ?:loose, C:connect, H:host, S:static, ~:internal, R:rip, O:ospf, B:bgp,
       Oi:ospf intra-area, Oo:ospf inter-area, O1:ospf ext-type-1, O2:ospf ext-type-2, E:ecmp, M:multicast


VIRTUAL ROUTER: default (id 1)
  ==========
destination                                 nexthop                                 metric flags      age   interface          next-AS
10.30.1.0/24                                10.30.1.1                               0      A C              ethernet1/2
10.40.1.0/24                                10.201.0.2                              0      A B        3600  ethernet1/1        65200
10.40.200.0/24                              10.201.0.2                              0      A B        60    ethernet1/1        65200
10.201.0.0/30                               10.201.0.1                              0      A C              ethernet1/1
total routes shown: 4
`);
W("routes/hub-route-api.xml", `<response status="success"><result><flags>flags: A:active, C:connect, B:bgp</flags>
<entry><virtual-router>default</virtual-router><destination>10.40.1.0/24</destination><nexthop>10.201.0.2</nexthop><metric>0</metric><flags>A B</flags><age>3600</age><interface>ethernet1/1</interface><route-table>unicast</route-table></entry>
<entry><virtual-router>default</virtual-router><destination>10.40.200.0/24</destination><nexthop>10.201.0.2</nexthop><metric>0</metric><flags>A B</flags><age>60</age><interface>ethernet1/1</interface><route-table>unicast</route-table></entry>
<entry><virtual-router>default</virtual-router><destination>10.40.77.0/24</destination><nexthop>10.201.0.2</nexthop><metric>0</metric><flags>B</flags><age>60</age><interface>ethernet1/1</interface><route-table>unicast</route-table></entry>
</result></response>
`);
