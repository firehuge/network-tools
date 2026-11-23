export function fwXml(host, ifs, routes, rules) {
  const e = (n, x) => `<entry name="${n}">${x}</entry>`;
  const eth = ifs.map(([n, ip]) => e(n, `<layer3><ip>${e(ip, "")}</ip></layer3>`)).join("");
  const mem = ifs.map(([n]) => `<member>${n}</member>`).join("");
  const sr = routes.map(([d, nh], i) => e("r" + i, `<nexthop><ip-address>${nh}</ip-address></nexthop><metric>10</metric><destination>${d}</destination>`)).join("");
  const zones = [...new Set(ifs.map((x) => x[2]))].map((z) => e(z, `<network><layer3>${ifs.filter((x) => x[2] === z).map((x) => `<member>${x[0]}</member>`).join("")}</layer3></network>`)).join("");
  const rl = rules.map(([n, f, t, s, d]) => e(n, `<from><member>${f}</member></from><to><member>${t}</member></to><source><member>${s}</member></source><destination><member>${d}</member></destination><source-user><member>any</member></source-user><category><member>any</member></category><application><member>any</member></application><service><member>service-https</member></service><action>allow</action>`)).join("");
  return `<?xml version="1.0"?><config version="11.1.0"><mgt-config></mgt-config><shared></shared><devices>${e("localhost.localdomain", `<network><interface><ethernet>${eth}</ethernet></interface><virtual-router>${e("default", `<interface>${mem}</interface><routing-table><ip><static-route>${sr}</static-route></ip></routing-table>`)}</virtual-router></network><deviceconfig><system><hostname>${host}</hostname></system></deviceconfig><vsys>${e("vsys1", `<import><network><interface>${mem}</interface></network></import><zone>${zones}</zone><rulebase><security><rules>${rl}</rules></security></rulebase>`)}</vsys>`)}</devices></config>`;
}
export function parallelXmls() {
  const hq = fwXml("hq-fw", [["ethernet1/1", "10.255.9.1/24", "wan"], ["ethernet1/2", "10.1.0.1/24", "trust"]], [["10.9.0.0/16", "10.255.9.254"]], [["hq-to-site", "trust", "wan", "10.1.0.0/24", "10.9.1.0/24"]]);
  const site = (h, n, extra) => fwXml(h, [["ethernet1/1", "10.255.9." + n + "/24", "wan"], ["ethernet1/2", "10.9.1." + n + "/24", "inside"]].concat(extra), [["0.0.0.0/0", "10.255.9.254"]], []);
  return [hq, site("site-fw-a", 2, [["ethernet1/3", "10.8.0.1/30", "mgmt"]]), site("site-fw-b", 3, [["ethernet1/3", "10.8.0.5/30", "mgmt"], ["ethernet1/4", "10.8.1.1/30", "lab"]])];
}
/* Synthetic: HQ firewall -> WAN core router (10.255.9.254) -> two non-HA site firewalls on the same site subnet. */
export function parallelSites(FM) {
  return parallelXmls().flatMap((x, i) => FM.loadConfig(x, "p" + i + ".xml").devices);
}
