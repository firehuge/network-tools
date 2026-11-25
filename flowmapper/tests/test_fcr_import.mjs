#!/usr/bin/env node
/* FCR import: header synonyms (underscores, brackets), prose rows above the header, merged/continued cells, list cells,
   IP/address headers over VLAN-name headers, PRJ-style tickets, non-App-ID values, requested rule names, and the .xlsx reader
   (instruction sheet skipped, merged cells filled). Synthetic data only (documentation IP ranges). */
import fs from "node:fs";
import zlib from "node:zlib";
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


/* ---- tiny xlsx writer (deflate) so the reader is tested on a real zip ---- */
function crc32(b) { let c, crc = ~0; for (let n = 0; n < b.length; n++) { c = (crc ^ b[n]) & 0xff; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crc = (crc >>> 8) ^ c; } return ~crc >>> 0; }
function zip(files) {
  const parts = [], cds = []; let off = 0;
  for (const [name, text] of Object.entries(files)) {
    const nb = Buffer.from(name), raw = Buffer.from(text), cmp = zlib.deflateRawSync(raw), crc = crc32(raw);
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(8, 8); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(cmp.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(nb.length, 26);
    const cd = Buffer.alloc(46); cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(8, 10); cd.writeUInt32LE(crc, 16); cd.writeUInt32LE(cmp.length, 20); cd.writeUInt32LE(raw.length, 24); cd.writeUInt16LE(nb.length, 28); cd.writeUInt32LE(off, 42);
    parts.push(lh, nb, cmp); cds.push(cd, nb); off += 30 + nb.length + cmp.length;
  }
  const cdb = Buffer.concat(cds), eo = Buffer.alloc(22); eo.writeUInt32LE(0x06054b50, 0); eo.writeUInt16LE(cds.length / 2, 8); eo.writeUInt16LE(cds.length / 2, 10); eo.writeUInt32LE(cdb.length, 12); eo.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, cdb, eo]);
}
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;");
function colName(i) { return String.fromCharCode(65 + i); }
function xlsx(sheets) {  /* sheets: [{name, rows: [[...]], merges: ["C3:C5"]}] */
  const files = {
    "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>',
    "xl/workbook.xml": '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' + sheets.map((s, i) => `<sheet name="${esc(s.name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join("") + "</sheets></workbook>",
    "xl/_rels/workbook.xml.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + sheets.map((s, i) => `<Relationship Id="rId${i + 1}" Type="x" Target="worksheets/sheet${i + 1}.xml"/>`).join("") + "</Relationships>",
  };
  const sst = [];
  const si = (v) => { let k = sst.indexOf(v); if (k < 0) { sst.push(v); k = sst.length - 1; } return k; };
  sheets.forEach((s, i) => {
    const rows = s.rows.map((r, ri) => `<row r="${ri + 1}">` + r.map((v, ci) => v == null || v === "" ? "" : typeof v === "number" ? `<c r="${colName(ci)}${ri + 1}"><v>${v}</v></c>` : `<c r="${colName(ci)}${ri + 1}" t="s"><v>${si(v)}</v></c>`).join("") + "</row>").join("");
    const mc = (s.merges || []).length ? `<mergeCells count="${s.merges.length}">` + s.merges.map((m) => `<mergeCell ref="${m}"/>`).join("") + "</mergeCells>" : "";
    files[`xl/worksheets/sheet${i + 1}.xml`] = `<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${rows}</sheetData>${mc}</worksheet>`;
  });
  files["xl/sharedStrings.xml"] = '<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' + sst.map((t) => `<si><t xml:space="preserve">${esc(t)}</t></si>`).join("") + "</sst>";
  return zip(files);
}

const HDR = ["Rule Name", "Usage - (Temporary/Permanent)", "Source_VLAN_VNET_Name", "Source DNS Name", "Source IP", "Ports", "Protocol(TCP/UDP)", "Destination_VLAN_VNET_Name", "Destination DNS Name", "Destination_IP", "Justification", "App"];

console.log("\n== FCR headers ==");
{
  const k = (h) => FM.fcrHeaderKey(h);
  ok(k("Destination_IP") === "dst" && k("Source IP") === "src" && k("source_ip") === "src" && k("Destination Address") === "dst", "underscore and space forms of IP/address headers");
  ok(k("Ports") === "port" && k("Destination port number(s)") === "port" && k("Protocol(TCP/UDP)") === "proto" && k("App") === "app", "ports, protocol with brackets, app");
  ok(k("Source_VLAN_VNET_Name") === "srcLabel" && k("Destination_VLAN_VNET_Name") === "dstLabel", "VLAN/VNET name headers are labels, not addresses");
  ok(k("Source DNS Name") === null && k("Destination DNS Name") === null && k("Source Port") === null, "DNS-name and source-port headers are ignored");
  ok(k("Rule Name") === "ruleName" && k("Usage - (Temporary/Permanent)") === "usage" && k("Justification") === "notes", "rule name, usage, justification");
  ok(k("source") === "src" && k("dest") === "dst" && k("protocol") === "proto" && k("ticket") === "ticket", "the old simple headers still work");
}

console.log("\n== FCR table: prose above the header, IP over name, merged rows, lists, tickets ==");
{
  const t = [
    ["Please fill out the sheet as follows:"], ["Project: PRJ0012345"],
    HDR,
    ["Allow_One", "Permanent", "NET_A", "host-a", "192.0.2.10", "8443, 9000-9002", "TCP", "NET_B", "", "198.51.100.5", "why", "Billing"],
    ["Allow_Two", "Temporary", "NET_A", "", "192.0.2.11", "445", "TCP", "", "", "198.51.100.6", "", "ssl"],
    ["", "", "", "", "", "", "", "", "", "198.51.100.7, 198.51.100.8", "", ""],
  ];
  const r = FM.parseFcrTable(t, { fileName: "Change_v1.xlsx" });
  ok(r && r.headerRow === 3, "header row found below the prose");
  ok(r.mapping.src === "Source IP" && r.mapping.dst === "Destination_IP", "IP headers win over the VLAN-name headers");
  // Allow_One: 2 port tokens -> 2 flows; Allow_Two 1 flow; the continuation row inherits Allow_Two and expands to 2 destinations
  ok(r.rows.length === 2 + 1 + 2, "list cells expand to one flow each (5 flows)");
  const one = r.rows.filter((x) => x.ruleName === "Allow_One");
  ok(one.length === 2 && one[0].port === 8443 && one[1].port === 9000 && one[1].portRange === "9000-9002", "port list and range: 8443, then 9000 with the range kept");
  ok(one[0].ticket === "PRJ0012345", "PRJ number from the prose above the header is the ticket");
  ok(one[0].app === null && one[0].appLabel === "Billing", "non-App-ID value: no app, original name kept as a label");
  const two = r.rows.filter((x) => x.ruleName === "Allow_Two");
  ok(two.length === 3 && two[0].app === "ssl" && two[0].appLabel === undefined, "a real App-ID is kept");
  ok(two[1].src === "192.0.2.11" && two[1].dst === "198.51.100.7" && two[1].port === 445 && two[2].dst === "198.51.100.8", "a blank-source row continues the request above");
  ok(one[0].usage === "Permanent" && one[0].srcLabel === "NET_A" && one[0].dstLabel === "NET_B", "usage and network names are carried");
}

console.log("\n== FCR tickets and apps ==");
{
  ok(FM.parseFcr("src,dst,port\n192.0.2.1,198.51.100.1,443", { fileName: "VENDOR_PRJ0098765_form.xlsx" }).rows[0].ticket === "PRJ0098765", "PRJ number in the file name");
  ok(FM.parseFcr("src,dst,port,notes\n192.0.2.1,198.51.100.1,443,host WEB00123").rows[0].ticket === null, "a host name like WEB00123 is not a ticket");
  ok(FM.parseFcr("src,dst,port\n192.0.2.1,198.51.100.1,443", { fileName: "WO1234567.csv", projectPattern: "WO\\d{7}" }).rows[0].ticket === "WO1234567", "the ticket pattern is configurable");
  const a = FM.fcrClassifyApp("SSL, Jenkins, web-browsing");
  ok(a.ids.join() === "ssl,web-browsing" && a.labels.join() === "Jenkins", "classify: App-IDs vs labels");
  ok(FM.fcrClassifyApp("Billing", ["billing"]).ids.join() === "billing", "extra known apps are honoured");
  const old = FM.parseFcr("source,destination,protocol,port,application,ticket\n10.1.1.10,10.2.2.20,tcp,22,ssh,FCR-17");
  ok(old.rows[0].app === "ssh" && old.rows[0].ticket === "FCR-17", "old CSV form unchanged");
}

console.log("\n== applyFcrExtras on a real trace ==");
{
  const xml = fwShell({ host: "lab-x", vsys: [{ name: "vsys1", ifs: [["ethernet1/1", "10.10.1.1/24", "lan"], ["ethernet1/2", "10.20.1.1/24", "dmz"]], vr: "vr1", routes: [] }] });
  const d = FM.loadConfig(xml, "lab-x.xml").devices;
  const row = { src: "10.10.1.50", dst: "10.20.1.50", proto: "tcp", port: 8443, app: "ssl", ticket: "PRJ0012345", ruleName: "Allow/From:LAN*to DMZ (TCP)", usage: "Temporary", appLabel: "Billing" };
  const res = FM.annotateFcr(FM.trace(d, { src: row.src, dst: row.dst, proto: row.proto, port: row.port }), d);
  FM.applyFcrExtras(res, row);
  const ch = res.changes.find((c) => c.kind === "security");
  ok(ch && ch.rule.name === "Allow-From-LAN-to DMZ -TCP", "requested rule name, sanitized");
  ok(ch.rule.application === "ssl" && ch.cli.some((l) => / application ssl /.test(l)), "App-ID goes into the rule CLI");
  ok(ch.cli.every((l) => !/FM-lan-to-dmz/.test(l)) && ch.cli.some((l) => /"Allow-From-LAN-to DMZ -TCP"/.test(l)), "every CLI line uses the new name");
  ok(ch.cli.some((l) => / description .*FCR app: Billing/.test(l) && /PRJ0012345/.test(l) && /usage: Temporary/.test(l)), "description line carries ticket, app label and usage");
  ok(res.fcrNote && /FCR rule: /.test(res.fcrNote), "result keeps the note for the exports");
  const res2 = FM.annotateFcr(FM.trace(d, { src: row.src, dst: row.dst, proto: "tcp", port: 8443 }), d);
  FM.applyFcrExtras(res2, { src: row.src, dst: row.dst, proto: "tcp", port: 8443, app: null, appLabel: "Billing" });
  const c2 = res2.changes.find((c) => c.kind === "security");
  ok(c2.rule.application === "any" && c2.cli.some((l) => / application any /.test(l) && /FM-/.test(l)), "label-only app: application stays any, generated name kept");
}

console.log("\n== .xlsx reader ==");
(async () => {
  const instr = [["Please fill out the Firewall Rules worksheet"], [], ["Firewall (Optional)", "Source DNS Name", "Source IP Address", "Destination DNS Name", "Destination Address", "Destination Protocol", "Destination Port", "Application", "Notes"], ["", "", "This field is mandatory", "", "This field is mandatory", "", "Port Number"], ["", "", "192.0.2.99", "", "198.51.100.99", "TCP", "80"]];
  const rules = [HDR,
    ["Allow_A", "Temporary", "NET_A", "", "192.0.2.10", "445, 5985", "TCP", "", "", "198.51.100.10", "", "ADO"],
    [null, null, null, null, null, null, null, null, null, "198.51.100.11"],
    [null, null, null, null, null, null, null, null, null, "198.51.100.12"],
    ["Allow_B", "Temporary", "NET_A", "", "192.0.2.11", 1433, "TCP", "", "", "198.51.100.20", "", "Tableau"]];
  const buf = xlsx([{ name: "Instructions", rows: instr }, { name: "Firewall Rules", rows: rules, merges: ["A2:A4", "B2:B4", "C2:C4", "E2:E4", "F2:F4", "G2:G4", "L2:L4"] }, { name: "Site to Site VPN Modification", rows: [["Existing tunnel changes"]], merges: ["A1:H1"] }]);
  const x = await FM.readFcrXlsx(buf, {});
  ok(!x.error && x.sheet === "Firewall Rules" && x.skipped.includes("Instructions"), "the rules sheet is picked, the instruction sheet skipped");
  const r = FM.parseFcr(x.csv, { fileName: "Change_PRJ0012345_v1.xlsx" });
  ok(r.rows.length === 2 * 3 + 1, "merged cells are filled down: 3 destinations x 2 ports + 1 (7 flows)");
  ok(r.rows.filter((z) => z.src === "192.0.2.10").length === 6 && r.rows.every((z) => z.ticket === "PRJ0012345"), "merged source and ports apply to every destination row; ticket from the file name");
  ok(r.rows.filter((z) => z.ruleName === "Allow_A").length === 6 && r.rows.filter((z) => z.appLabel === "ADO").length === 6, "rule name and app label fill down too");
  const bad = await FM.readFcrXlsx(zip({ "x.txt": "hello" }), {}).catch((e) => ({ error: String(e.message) }));
  ok(bad.error, "a zip that is not a workbook is reported");
  console.log("\n" + passed + " passed, " + failed + " failed");
  process.exit(failed ? 1 : 0);
})();
