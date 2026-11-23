// Synthetic, deliberately messy Panorama export for the decommission engine.
// Invented names, RFC 1918/5737 addresses and example.test hostnames only. Run: node samples/generate_decom.mjs
import { writeFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
const here = dirname(fileURLToPath(import.meta.url));
const m = (xs) => xs.map((x) => `<member>${x}</member>`).join("");
const addr = (n, v, o = {}) => `<entry name="${n}"><${o.type || "ip-netmask"}>${v}</${o.type || "ip-netmask"}>${o.desc ? `<description>${o.desc}</description>` : ""}${o.tags ? `<tag>${m(o.tags)}</tag>` : ""}</entry>`;
const grp = (n, mem, desc) => `<entry name="${n}"><static>${m(mem)}</static>${desc ? `<description>${desc}</description>` : ""}</entry>`;
const dag = (n, filter) => `<entry name="${n}"><dynamic><filter>${filter}</filter></dynamic></entry>`;
const sec = (n, o) => `<entry name="${n}"><from>${m(o.from || ["any"])}</from><to>${m(o.to || ["any"])}</to><source>${m(o.src || ["any"])}</source><destination>${m(o.dst || ["any"])}</destination>${o.negSrc ? "<negate-source>yes</negate-source>" : ""}${o.negDst ? "<negate-destination>yes</negate-destination>" : ""}<source-user><member>any</member></source-user><category><member>any</member></category><application>${m(o.app || ["any"])}</application><service>${m(o.svc || ["any"])}</service><action>${o.action || "allow"}</action>${o.desc ? `<description>${o.desc}</description>` : ""}${o.disabled ? "<disabled>yes</disabled>" : ""}</entry>`;
const tpl = (name, host, ifs, zones, routes) => `<entry name="${name}"><config><devices><entry name="localhost.localdomain"><network><interface><ethernet>${ifs.map(([i, ip]) => `<entry name="${i}"><layer3><ip><entry name="${ip}"/></ip></layer3></entry>`).join("")}</ethernet></interface><virtual-router><entry name="default"><interface>${m(ifs.map((x) => x[0]))}</interface><routing-table><ip><static-route>${routes.map(([n, d, nh]) => `<entry name="${n}"><destination>${d}</destination><nexthop><ip-address>${nh}</ip-address></nexthop><metric>10</metric></entry>`).join("")}</static-route></ip></routing-table></entry></virtual-router></network><deviceconfig><system><hostname>${host}</hostname></system></deviceconfig><vsys><entry name="vsys1"><import><network><interface>${m(ifs.map((x) => x[0]))}</interface></network></import><zone>${zones.map(([z, i]) => `<entry name="${z}"><network><layer3><member>${i}</member></layer3></network></entry>`).join("")}</zone></entry></vsys></entry></devices></config></entry>`;

const shared = `<shared><address>${[
  addr("H-10.50.1.25", "10.50.1.25/32", { desc: "app01 server" }),
  addr("NET-APPS-10.50.0.0_16", "10.50.0.0/16"),
  addr("SH-WIDE-10.0.0.0_8", "10.0.0.0/8"),
  addr("app01-fqdn", "app01.example.test", { type: "fqdn" }),
].join("")}</address></shared>`;

const corpAddr = [
  addr("app01", "10.50.1.25", { tags: ["web"] }),
  addr("app02", "10.50.1.26"),
  addr("app03", "10.50.1.27"),
  addr("P2P-app01", "10.50.1.24/30"),
  addr("NET-APP01-POOL", "10.50.1.16/28", { desc: "app01 pool" }),
  addr("NET-APPS-24", "10.50.1.0/24"),
  addr("VIP-app01", "203.0.113.25"),
  addr("OLD-ONLY-OBJ", "10.60.0.9"),
  addr("NET-USERS", "10.1.1.0/24"),
].join("");
const corpGroups = [
  grp("GRP-APP01", ["app01", "H-10.50.1.25"]),
  grp("GRP-WEB-SERVERS", ["app01", "app02"]),
  grp("GRP-NESTED-OUTER", ["GRP-APP01", "app03"]),
  grp("GRP-ONLY-NESTED", ["GRP-APP01"]),
  grp("GRP-BIG", ["NET-APPS-10.50.0.0_16", "app02"]),
  dag("DAG-WEB", "'web'"),
].join("");
const corpRules = [
  sec("R-ALLOW-APP01-ONLY", { dst: ["app01"], svc: ["service-https"] }),
  sec("R-WEB-SERVERS", { dst: ["GRP-WEB-SERVERS"], svc: ["service-https"] }),
  sec("R-MIXED", { dst: ["app01", "app02"], svc: ["service-https"] }),
  sec("R-LITERAL", { dst: ["10.50.1.25", "10.50.1.30"], svc: ["service-http"] }),
  sec("R-LITERAL-WIDE", { src: ["NET-USERS"], dst: ["10.50.0.0/16"], app: ["ssh"], svc: ["application-default"] }),
  sec("R-NEGATE", { src: ["app01", "app02"], negSrc: true, dst: ["SH-WIDE-10.0.0.0_8"], app: ["dns"], svc: ["application-default"] }),
  sec("R-GRP-ONLY", { dst: ["GRP-ONLY-NESTED"], svc: ["service-https"] }),
  sec("OLD-APP01-RULE", { dst: ["OLD-ONLY-OBJ"], svc: ["service-http"], desc: "legacy" }),
  sec("R-APPS-BROAD", { src: ["NET-USERS", "10.99.0.0/29"], dst: ["NET-APPS-10.50.0.0_16"] }),
].join("");
const corpNat = `<entry name="NAT-APP01-VIP"><from><member>untrust</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>VIP-app01</member></destination><service>any</service><destination-translation><translated-address>app01</translated-address></destination-translation></entry>`;
const dcAddr = addr("app01", "10.50.1.25", { desc: "local duplicate of app01" });
const dcRules = [sec("DC-APP01", { src: ["NET-USERS"], dst: ["app01"] }), sec("DC-ALLOW-APPS-24", { from: ["core"], to: ["apps"], dst: ["NET-APPS-24"] })].join("");

const xml = `<?xml version="1.0"?>
<!-- SYNTHETIC messy Panorama export for decommission tests. Invented names and documentation/RFC 1918 addresses only. -->
<config version="11.1.0" detail-version="11.1.13">
  <mgt-config><devices><entry name="009950000001"/><entry name="009950000002"/></devices></mgt-config>
  ${shared}
  <readonly><devices><entry name="localhost.localdomain"><device-group><entry name="DG-CORP"><id>11</id></entry><entry name="DG-BRANCH"><id>12</id><parent-dg>DG-CORP</parent-dg></entry><entry name="DG-DC"><id>13</id><parent-dg>DG-CORP</parent-dg></entry></device-group></entry></devices></readonly>
  <devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>pano-decom-demo</hostname></system></deviceconfig>
  <device-group>
    <entry name="DG-CORP"><address>${corpAddr}</address><address-group>${corpGroups}</address-group><pre-rulebase><security><rules>${corpRules}</rules></security><nat><rules>${corpNat}</rules></nat></pre-rulebase></entry>
    <entry name="DG-BRANCH"><devices><entry name="009950000001"/></devices></entry>
    <entry name="DG-DC"><devices><entry name="009950000002"/></devices><address>${dcAddr}</address><pre-rulebase><security><rules>${dcRules}</rules></security></pre-rulebase></entry>
  </device-group>
  <template>${tpl("T-BRANCH", "branch-fw", [["ethernet1/1", "10.99.0.1/29"], ["ethernet1/2", "10.1.1.1/24"]], [["core", "ethernet1/1"], ["users", "ethernet1/2"]], [["apps", "10.50.0.0/16", "10.99.0.2"]])}${tpl("T-DC", "dc-fw", [["ethernet1/1", "10.99.0.2/29"], ["ethernet1/2", "10.50.1.1/24"]], [["core", "ethernet1/1"], ["apps", "ethernet1/2"]], [["users", "10.1.0.0/16", "10.99.0.1"]])}</template>
  <template-stack><entry name="ST-BRANCH"><templates><member>T-BRANCH</member></templates><devices><entry name="009950000001"/></devices></entry><entry name="ST-DC"><templates><member>T-DC</member></templates><devices><entry name="009950000002"/></devices></entry></template-stack>
  </entry></devices>
</config>
`;
writeFileSync(join(here, "panorama-decom-messy.xml"), xml);
console.log("wrote panorama-decom-messy.xml", xml.length, "bytes");
