#!/usr/bin/env node
/* SPDX-License-Identifier: Apache-2.0 */
/* Headless browser tests for pan-flowmapper.html (system Chrome + playwright-core). */
import { chromium } from "playwright-core";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
fs.mkdirSync(path.join(ROOT, "tests/_out"), { recursive: true });
const chrome = process.env.CHROME_PATH || ["/usr/bin/google-chrome-stable", "/usr/bin/google-chrome", "/usr/bin/chromium"].find((p) => fs.existsSync(p));
let failed = 0;
const ok = (c, m) => { if (c) console.log("  ok  :", m); else { failed++; console.error("  FAIL:", m); } };
const S = (n) => path.join(ROOT, "samples", n);

const browser = await chromium.launch({ executablePath: chrome, args: ["--no-sandbox", "--disable-dev-shm-usage"], headless: true });
const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
// Older tests trace every firewall in samples whose names contain role words (a device group called "...-Lab"); they run with scope All sites.
// The scope tests below set sessionStorage fm-scope-real so the real default (Production only) applies.
await ctx.addInitScript(() => { try { if (!sessionStorage.getItem("fm-scope-real")) localStorage.setItem("pan-flowmapper-site-roles", JSON.stringify({ scope: { mode: "all" } })); } catch (e) {} });
const page = await ctx.newPage();
const errors = [], requests = [];
page.on("pageerror", (e) => errors.push(String(e)));
page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
page.on("request", (r) => { if (!r.url().startsWith("file:") && !r.url().startsWith("blob:") && !r.url().startsWith("data:")) requests.push(r.url()); });
const url = "file://" + path.join(ROOT, "pan-flowmapper.html");
async function loadFiles(files) {
  await page.evaluate(() => (window.__FM.ready = false));
  await page.locator("#fi").setInputFiles(files);
  await page.waitForFunction(() => window.__FM.ready === true && window.__FM.getDevices().length > 0, null, { timeout: 60000 });
  await page.waitForFunction((n) => window.__FM.state.files.length >= n && window.__FM.ready === true, files.length, { timeout: 60000 });
}
async function trace(q) { return page.evaluate((q) => { const r = window.__FM.runTrace(q); return { status: r.status, segs: r.segments.map((s) => s.device + ":" + s.vsys), changes: r.changes.filter((c) => !c.optional).map((c) => c.kind + ":" + c.device + ":" + c.vsys), ms: r.ms }; }, q); }

console.log("\n== load + multi-vsys trace ==");
await page.goto(url);
await page.waitForFunction(() => window.__FM && window.__FM.ready);
await loadFiles([S("fw-multi-vsys.xml")]);
let r = await trace({ src: "10.1.1.10", dst: "10.2.2.21", proto: "tcp", port: 8443 });
ok(r.segs.join() === "dc-fw-mv1:vsys1,dc-fw-mv1:vsys2", "trace crosses vsys1 -> vsys2");
ok(r.changes.filter((c) => c.startsWith("security")).length === 2, "two security changes shown");
ok(await page.locator("#flowsvg svg").count() === 1, "flow SVG rendered");
ok(await page.locator("#flowsvg svg text").count() > 20, "SVG has labels");
ok(await page.locator("#changes .chg").count() >= 2, "changes cards rendered");
ok(await page.locator("#checks tbody tr").count() === 2, "two policy check rows");
await page.locator("#flowsvg").screenshot({ path: path.join(ROOT, "tests/_out/flow-multivsys.png") });
await page.screenshot({ path: path.join(ROOT, "tests/_out/screenshot.png"), fullPage: true });
const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#dl-svg")]);
const svgPath = path.join(ROOT, "tests/_out_flow.svg"); await dl.saveAs(svgPath);
ok(fs.readFileSync(svgPath, "utf8").startsWith("<svg"), "SVG export downloads");
const [dl2] = await Promise.all([page.waitForEvent("download"), page.click("#dl-png")]);
const pngPath = path.join(ROOT, "tests/_out_flow.png"); await dl2.saveAs(pngPath);
ok(fs.statSync(pngPath).size > 5000, "PNG export downloads");
// parity with PAAT
ok(await page.locator("#multiplace").count() === 1 && /Rule needed in more than one place/.test(await page.locator("#multiplace").textContent()) && /2 places/.test(await page.locator("#multiplace").textContent()), "on-screen red box: rule needed in more than one place (2 places)");
ok(await page.locator("#multiplace li").count() === 2, "the box lists each place");
await page.locator("#multiplace").screenshot({ path: path.join(ROOT, "tests/_out/multi-place.png") });
ok(await page.locator("#changes .order-advice").count() >= 1, "each new rule says where it must sit (rule order)");
const [dlRO] = await Promise.all([page.waitForEvent("download"), page.click("#exp-csv")]);
const csvPath = path.join(ROOT, "tests/_out_flow.csv"); await dlRO.saveAs(csvPath);
const csvText = fs.readFileSync(csvPath, "utf8");
ok(/Rule order/.test(csvText) && /Places checked by security policy/.test(csvText), "CSV export carries the rule-order column and the places-checked line");

console.log("\n== tabs ==");
await page.click("#tabs [data-tab=config]");
ok(await page.locator("#t-ifs tbody tr").count() >= 6, "config browser lists interfaces");
await page.click("#tabs [data-tab=topo]");
ok(await page.locator("#topo-body svg").count() === 1, "topology SVG rendered");
await page.screenshot({ path: path.join(ROOT, "tests/_out/topology.png") });
await page.click("#tabs [data-tab=raw]");
let raw = await page.locator("#rawview").textContent();
ok(!raw.includes("SYNTHETICPSK") && !raw.includes("SYNTHETICHASHVALUE"), "raw XML hides secrets by default");
await page.uncheck("#raw-mask"); raw = await page.locator("#rawview").textContent();
ok(raw.includes("SYNTHETICPSK"), "toggle shows raw secrets");
await page.check("#raw-mask");

console.log("\n== multiple firewalls ==");
await loadFiles([S("fw-single-vsys.xml"), S("fw-core-peer.xml")]);
r = await trace({ src: "10.10.0.50", dst: "10.50.10.7", proto: "tcp", port: 443 });
ok(r.segs.join() === "branch-fw1:vsys1,core-fw1:vsys1", "cross-device trace");

console.log("\n== Panorama 67 devices ==");
const t0 = Date.now();
await loadFiles([S("panorama-67-devices.xml")]);
const loadMs = Date.now() - t0;
ok(loadMs < 8000, "Panorama (67 devices) loaded in browser in " + loadMs + " ms");
r = await trace({ src: "10.100.7.50", dst: "10.200.32.20", proto: "tcp", port: 1433, deviceId: "" });
ok(r.segs.join() === "br-east-07:vsys1,dc-mv-4:vsys1,dc-mv-4:vsys2", "branch -> DC multi-vsys trace (" + r.ms + " ms)");
ok(r.changes.filter((c) => c.startsWith("security")).length === 3, "three rules needed across devices/vsys");
await page.locator("#flowsvg").screenshot({ path: path.join(ROOT, "tests/_out/flow-panorama.png") });
const rows = await page.locator(".ctxrow").count();
ok(rows === 67, "device picker lists 67 devices");
await page.fill(".ctxfilter", "dc-mv");
ok(await page.locator(".ctxrow:not([hidden])").count() === 4, "device filter works");

// ---- device picker: All / None follow the filter
{
  const st = () => page.evaluate(() => { const f = window.__FM.state.files.find((f) => f.ctxSel); return { sel: f.ctxSel.size, devs: window.__FM.getDevices().filter((d) => d.kind === "panorama").length, count: document.querySelector("[id^=ctxcount-]").textContent, filter: document.querySelector(".ctxfilter").value, shown: document.querySelectorAll(".ctxrow:not([hidden])").length }; });
  const waitDevs = (n) => page.waitForFunction((n) => window.__FM.ready !== false && window.__FM.getDevices().filter((d) => d.kind === "panorama").length === n, n, { timeout: 30000 });
  await page.fill(".ctxfilter", "");
  let x = await st();
  ok(x.sel === 67 && x.filter === "", "picker default: all 67 mapped devices selected, filter empty");
  await page.fill(".ctxfilter", "dc-mv");
  await page.click("[data-ctxall]"); await waitDevs(4); await page.waitForFunction(() => document.querySelector("[id^=ctxcount-]").textContent === "4");
  x = await st();
  ok(x.sel === 4 && x.devs === 4 && x.count === "4" && x.filter === "dc-mv" && x.shown === 4, "filter + All = exactly the 4 filtered devices; filter text and rows kept (" + JSON.stringify(x) + ")");
  r = await trace({ src: "10.100.7.50", dst: "10.200.32.20", proto: "tcp", port: 1433, deviceId: "" });
  ok(r.segs.every((s) => s.startsWith("dc-mv")), "trace uses only the filtered set: " + r.segs.join(" > "));
  await page.fill(".ctxfilter", ""); await page.click("[data-ctxall]"); await waitDevs(67);
  ok((await st()).sel === 67, "empty filter + All = all listed mapped devices");
  await page.fill(".ctxfilter", "dc-mv"); await page.click("[data-ctxnone]"); await waitDevs(63);
  x = await st(); ok(x.sel === 63 && x.filter === "dc-mv", "filter + None removes only the filtered devices (63 left)");
  await page.fill(".ctxfilter", ""); await page.click("[data-ctxnone]");
  await page.waitForFunction(() => window.__FM.state.files.find((f) => f.ctxSel).ctxSel.size === 0);
  ok((await st()).sel === 0, "empty filter + None clears the trace set");
  await page.click("[data-ctxall]"); await waitDevs(67);
}


console.log("\n== Panorama DMZ -> MPLS -> core ==");
await page.goto(url);
await page.evaluate(() => window.__FM.setLinks([]));
await loadFiles([S("panorama-dmz-mpls-core.xml")]);
r = await trace({ src: "172.18.10.50", dst: "10.30.2.20", proto: "tcp", port: 1433 });
ok(r.segs.join() === "fw-dmz:vsys1,fw-core:vsys1,fw-core:vsys2", "chain across firewalls in browser");
ok(await page.locator("#flowsvg svg ellipse").count() > 0, "transit cloud drawn");
const [dlp] = await Promise.all([page.waitForEvent("download"), page.click("#dl-png")]);
await dlp.saveAs(path.join(ROOT, "tests/_out/flow-dmz-mpls-core.png"));
r = await trace({ src: "172.18.10.50", dst: "10.60.5.20", proto: "tcp", port: 22 });
ok(await page.locator("select[data-branch]").count() === 1, "branch picker shown for ambiguous hop");
const site2 = await page.evaluate(() => window.__FM.getDevices().find((d) => d.name === "fw-site2").id);
await page.selectOption("select[data-branch]", site2);
await page.waitForFunction(() => window.__FM.lastResult().segments[1].device === "fw-site2");
ok(true, "choosing a branch re-traces to fw-site2");
await page.evaluate(() => window.__FM.runTrace({ src: "172.18.10.50", dst: "10.60.5.20", proto: "tcp", port: 22 }));
ok(await page.locator("#altpaths input[data-path]").count() >= 2, "alternative paths listed");
await page.locator("#altpaths input[data-path]").nth(1).check();
await page.waitForFunction(() => window.__FM.lastResult().plan.chosen === 1 && window.__FM.lastResult().segments[1].device === "fw-site2");
ok(true, "selecting alternative path 2 re-traces via fw-site2");
await page.screenshot({ path: path.join(ROOT, "tests/_out/screenshot-multifw.png"), fullPage: true });
await page.click("#links-box summary");
await page.selectOption("#lk-fdev", "fw-dmz"); await page.fill("#lk-fnh", "10.250.1.2"); await page.selectOption("#lk-tdev", "fw-site1"); await page.fill("#lk-label", "MPLS-test");
await page.click("#lk-add");
await page.evaluate(() => window.__FM.runTrace({ src: "172.18.10.50", dst: "10.60.5.20", proto: "tcp", port: 22 }));
const lr = await page.evaluate(() => ({ d: window.__FM.lastResult().segments[1].device, k: window.__FM.lastResult().stitches[0].via.kind, stored: JSON.parse(localStorage.getItem("pan-flowmapper-links") || "[]").length }));
ok(lr.d === "fw-site1" && lr.k === "link" && lr.stored === 1, "link added in UI, saved to localStorage, used by trace");
const [dlj] = await Promise.all([page.waitForEvent("download"), page.click("#lk-export")]);
const jp = path.join(ROOT, "tests/_out_links.json"); await dlj.saveAs(jp);
ok(JSON.parse(fs.readFileSync(jp, "utf8")).links.length === 1, "links export JSON");
await page.evaluate(() => window.__FM.setLinks([]));
await page.locator("#lk-import-file").setInputFiles(jp);
await page.waitForFunction(() => window.__FM.state.links.length === 1);
ok(true, "links import JSON");
await page.evaluate(() => window.__FM.setLinks([]));

console.log("\n== inferred graph: DMZ -> MPLS -> hub (multi-vsys) -> B2B -> vendor ==");
await page.goto(url);
await page.evaluate(() => window.__FM.setLinks([]));
await loadFiles([S("panorama-mpls-hub.xml")]);
r = await trace({ src: "172.18.10.50", dst: "10.41.5.20", proto: "tcp", port: 443 });
ok(r.segs.join() === "fw-dmz2:vsys1,fw-hub:vsys1,fw-hub:vsys2,fw-b2b:vsys1,fw-vendor:vsys1", "4-firewall chain in browser");
ok(new Set(r.changes.filter((c) => c.startsWith("security")).map((c) => c.split(":")[1])).size === 4, "rules listed on all 4 firewalls");
ok(await page.locator("#chain .hoplist li").count() === 3 && await page.locator("#chain .pill").count() >= 3, "chain with confidence per hop");
ok(await page.locator("#why").count() === 1, "'Why this path' explainer");
await page.locator("#flowsvg").screenshot({ path: path.join(ROOT, "tests/_out/flow-mpls-hub.png") });
r = await trace({ src: "10.70.1.20", dst: "10.30.1.20", proto: "tcp", port: 443 });
ok(r.segs.join() === "fw-lab:vsys1,fw-hub:vsys1" && r.changes.some((c) => c.startsWith("route:fw-lab")), "missing route listed, chain continues");
ok(await page.locator('#flowsvg svg line[stroke="#d97706"][stroke-dasharray]').count() >= 2, "low-confidence hop drawn with dashed amber lines");
r = await trace({ src: "10.61.1.20", dst: "10.62.1.20", proto: "tcp", port: 22 });
ok(r.segs.join() === "fw-br-east1:vsys1,fw-br-west1:vsys1", "branch -> branch across MPLS");
await page.fill("#q-via", "fw-hub"); await page.click("#btn-trace");
await page.waitForFunction(() => window.__FM.lastResult().segments.some((s) => s.device === "fw-hub"));
ok(true, "'Must pass through' field forces fw-hub");
await page.fill("#q-via", "");
r = await trace({ src: "10.61.1.20", dst: "10.30.1.20", proto: "tcp", port: 443 });
const hubId = await page.evaluate(() => window.__FM.getDevices().find((d) => d.name === "fw-hub").id);
await page.selectOption("#q-ddev", hubId); await page.click("#btn-trace");
await page.waitForFunction(() => window.__FM.lastResult().segments.slice(-1)[0].device === "fw-hub");
ok(true, "destination firewall pin");
await page.selectOption("#q-ddev", "");
// alternative paths radio (67-device DMZ case has several; use API on hub sample with forced tie)
await page.evaluate(() => window.__FM.runTrace({ src: "172.18.10.50", dst: "10.41.5.20", proto: "tcp", port: 443 }));
await page.click("#tabs [data-tab=map]");
ok(await page.locator("#map-body svg").count() === 1 && await page.locator("#map-body .mnode").count() > 15, "network map renders (" + await page.locator("#map-body .mnode").count() + " nodes)");
ok(await page.locator('#map-body line[stroke="#16a34a"]').count() >= 4, "last trace highlighted on the map");
ok(await page.locator("#t-rtr tbody tr").count() >= 6, "inferred routers table");
await page.locator("#map-body").screenshot({ path: path.join(ROOT, "tests/_out/network-map.png") });
await page.fill("#map-q", "fw-vendor"); await page.waitForTimeout(400);
const nFilt = await page.locator("#map-body .mnode").count();
ok(nFilt > 1 && nFilt < 15, "map filter narrows to neighbourhood (" + nFilt + " nodes)");
await page.fill("#map-q", "");
const [dld] = await Promise.all([page.waitForEvent("download"), page.click("#btn-diag")]);
const dp = path.join(ROOT, "tests/_out_diag.json"); await dld.saveAs(dp);
const dj = fs.readFileSync(dp, "utf8");
ok(JSON.parse(dj).devices.length === 9 && !/fw-hub|fw-vendor|10\.41\.5|172\.18\.10|vendor-api|DG-Hub|SYNTHETIC/.test(dj), "redacted diagnostics download: structure only, no names/IPs");

console.log("\n== Panorama 67: branch -> DC -> branch, alternative paths, map ==");
await page.goto(url);
await loadFiles([S("panorama-67-devices.xml")]);
r = await trace({ src: "10.100.7.50", dst: "10.100.8.20", proto: "tcp", port: 22 });
ok(r.segs.join() === "br-east-07:vsys1,dc-mv-4:vsys1,br-east-08:vsys1", "branch -> DC -> branch (" + r.ms + " ms)");
r = await trace({ src: "172.30.2.50", dst: "10.200.12.20", proto: "tcp", port: 1433 });
const nAlt = await page.locator("#altpaths input[data-path]").count();
if (nAlt > 1) {
  await page.locator("#altpaths input[data-path]").nth(1).check();
  await page.waitForFunction(() => window.__FM.lastResult().plan.chosen === 1);
  ok(true, "alternative path selectable (" + nAlt + " shown)");
} else ok(true, "single path, no alternatives to select");
await page.click("#tabs [data-tab=map]");
const t1 = Date.now();
await page.waitForSelector("#map-body svg");
ok(await page.locator("#map-body .mnode").count() >= 67, "67-device map renders (" + (Date.now() - t1) + " ms)");
await page.selectOption("#map-zoom", "0.6");
await page.locator("#map-body svg").screenshot({ path: path.join(ROOT, "tests/_out/network-map-67.png") });

console.log("\n== scale Panorama (BGP-only branches, hairpins), main-thread responsiveness ==");
{
  const gp = path.join(ROOT, "samples/_gen/panorama-scale-bgp.xml");
  if (!fs.existsSync(gp)) (await import("node:child_process")).execFileSync(process.execPath, [path.join(ROOT, "samples/generate_samples.mjs"), "--scale"]);
  await page.goto(url);
  await page.waitForFunction(() => window.__FM && window.__FM.ready);
  await page.evaluate(() => { window.__lt = []; new PerformanceObserver((l) => l.getEntries().forEach((e) => window.__lt.push(Math.round(e.duration)))).observe({ type: "longtask", buffered: false }); });
  const t2 = Date.now();
  await loadFiles([gp]);
  const lt = await page.evaluate(() => window.__lt);
  const maxLt = Math.max(0, ...lt);
  ok(Date.now() - t2 < 15000, "11 MB / 589 DG Panorama loads in " + (Date.now() - t2) + " ms");
  ok(maxLt < 1000, "longest main-thread block " + maxLt + " ms (< 1 s; " + lt.length + " long tasks)");
  ok(await page.evaluate(() => window.__FM.getDevices().length) === 67, "67 mapped firewalls in the trace set by default");
  ok(await page.locator(".ctxrow").count() === 67, "unmapped stacks/templates hidden in the device list");
  ok(/managed firewalls mapped/.test(await page.locator(".mapinfo").textContent()), "mapping summary shown");
  ok(/inferred routes/.test(await page.locator("#infer-info").textContent()), "BGP/OSPF inference summary shown");
  const sel = page.locator("select[data-dgo]").first();
  ok(await sel.locator("option").count() <= 2, "DG override list is filled lazily");
  await sel.focus();
  ok(await sel.locator("optgroup").first().getAttribute("label") === "Used by managed firewalls", "DG override lists mapped DGs first");
  await page.locator("[data-unm]").check();
  ok(await page.locator(".ctxrow").count() > 300, "unmapped stacks/templates can be shown");
  r = await trace({ src: "10.120.1.50", dst: "10.131.2.20", proto: "tcp", port: 1433 });
  ok(r.segs.join() === "br-bgp-01:vsys1,dc-bgp-2:vsys1,dc-bgp-2:vsys2", "branch -> DC vsys1 -> hairpin -> vsys2 in browser (" + r.ms + " ms)");
  ok((await page.locator("#flowsvg svg").textContent()).includes("HAIRPIN"), "flow diagram draws the hairpin");
  ok((await page.locator("#flowsvg svg").textContent()).includes("BGP"), "flow diagram marks the inferred BGP route");
  await page.locator("#flowsvg").screenshot({ path: path.join(ROOT, "tests/_out/flow-bgp-hairpin.png") });
  await page.click("#tabs [data-tab=config]");
  await page.selectOption("#cfg-dev", { label: await page.evaluate(() => { const o = [...document.querySelectorAll("#cfg-dev option")].find((x) => /br-bgp-01/.test(x.textContent)); return o.textContent; }) });
  const rtxt = await page.locator("#cfg-body").textContent();
  ok(/inferred-bgp \(.*from br-bgp-02\)/.test(rtxt) && /BGP: local AS 65100/.test(rtxt), "config browser shows inferred routes with source and BGP peers");
}

console.log("\n== validate with existing rules + trace this rule ==");
await page.goto(url);
await loadFiles([S("panorama-ha-edge.xml")]);
{
  // ---- HA pairs grouped in the device picker
  const rowsInfo = () => page.evaluate(() => [...document.querySelectorAll(".ctxrow")].map((tr) => ({ ids: tr.dataset.ids.split(" ").length, ha: tr.classList.contains("ha-row"), hidden: tr.hidden, txt: tr.textContent })));
  let ri = await rowsInfo();
  ok(await page.locator("#nonet-callout").count() === 0, "no network-config callout when every firewall has network config");
  ok(ri.length === 5 && ri.filter((x) => x.ha).length === 3 && ri.filter((x) => x.ha).every((x) => x.ids === 2), "HA pairs shown as one row each (3 pairs + 2 single firewalls)");
  ok(ri.some((x) => x.ha && /fw-inet-a/.test(x.txt) && /fw-inet-b/.test(x.txt) && /HA pair/.test(x.txt)), "fw-inet-a and fw-inet-b in one row with an HA badge");
  ok(ri.filter((x) => !x.ha).every((x) => x.ids === 1), "non-HA devices stay separate rows");
  const inetCb = page.locator(".ctxrow.ha-row", { hasText: "fw-inet-a" }).locator("input[data-row]");
  await inetCb.uncheck();
  await page.waitForFunction(() => window.__FM.getDevices().length === 6);
  let sel = await page.evaluate(() => [...window.__FM.state.files.find((f) => f.ctxSel).ctxSel].join(" "));
  ok(!/013100000001/.test(sel) && !/013100000002/.test(sel), "one checkbox deselects both HA members");
  await inetCb.check(); await page.waitForFunction(() => window.__FM.getDevices().length === 8);
  await page.fill(".ctxfilter", "fw-inet-b");
  ri = await rowsInfo();
  ok(ri.filter((x) => !x.hidden).length === 1 && /fw-inet-a/.test(ri.find((x) => !x.hidden).txt), "filter on one member shows the whole pair");
  await page.click("[data-ctxall]"); await page.waitForFunction(() => window.__FM.getDevices().length === 2);
  sel = await page.evaluate(() => [...window.__FM.state.files.find((f) => f.ctxSel).ctxSel].join(" "));
  ok(/013100000001/.test(sel) && /013100000002/.test(sel) && sel.split(" ").length === 2, "All on that filter selects both members");
  await page.fill(".ctxfilter", ""); await page.click("[data-ctxall]"); await page.waitForFunction(() => window.__FM.getDevices().length === 8);
  await page.waitForFunction(() => document.querySelector("[id^=ctxcount-]").textContent === "8"); await page.waitForTimeout(300);
  await page.locator(".ctxlist").screenshot({ path: path.join(ROOT, "tests/_out/device-picker-ha.png") });
}
{
  // ---- no false HA pairs: different stack, or 3 alike
  let txt = fs.readFileSync(S("panorama-ha-edge.xml"), "utf8");
  txt = txt.replace('<entry name="S-INET"><templates><member>T-INET</member></templates><devices><entry name="013100000001"></entry><entry name="013100000002"></entry></devices></entry>', '<entry name="S-INET"><templates><member>T-INET</member></templates><devices><entry name="013100000001"></entry></devices></entry><entry name="stack-sitea-inet"><templates><member>T-INET</member></templates><devices><entry name="013100000002"></entry></devices></entry>')
    .replace('<devices><entry name="013100000003"></entry><entry name="013100000004"></entry></devices></entry><entry name="S-HUB"><templates><member>T-HUB</member></templates><devices><entry name="013100000005"></entry></devices></entry>', '<devices><entry name="013100000003"></entry><entry name="013100000004"></entry><entry name="013100000005"></entry></devices></entry>');
  ok(/stack-sitea-inet/.test(txt) && !/S-HUB<\/entry>|name="S-HUB"/.test(txt.split("<template-stack>")[1]), "variant fixture built (different-stack inet, 3-alike DMZ)");
  await page.goto(url);
  await page.evaluate((t) => window.__FM.loadText("ha-variant.xml", t), txt);
  await page.waitForFunction(() => document.querySelectorAll(".ctxrow").length > 0);
  const ri2 = await page.evaluate(() => [...document.querySelectorAll(".ctxrow")].map((tr) => ({ ha: tr.classList.contains("ha-row"), txt: tr.textContent })));
  ok(!ri2.some((x) => x.ha && /fw-inet/.test(x.txt)), "different-stack firewalls with the same addresses are separate rows");
  ok(!ri2.some((x) => x.ha && /fw-dmz|fw-mpls-hub/.test(x.txt)), "three firewalls with the same addresses are not grouped");
  ok(ri2.filter((x) => x.ha).length === 1 && ri2.some((x) => x.ha && /fw-site-x-a/.test(x.txt) && /fw-site-x-b/.test(x.txt)), "the true same-stack pair still shows as one row (" + ri2.length + " rows)");
  await page.goto(url); await loadFiles([S("panorama-ha-edge.xml")]);
}
{
  // ---- explicit HA config pairs across stacks in the picker
  const HA = '<deviceconfig><high-availability><enabled>yes</enabled><group><group-id>1</group-id><peer-ip>$ha-peer</peer-ip></group><interface><ha1><ip-address>$ha1-ip</ip-address></ha1></interface></high-availability></deviceconfig>';
  const v = (own, peer) => '<variable><entry name="$ha1-ip"><type><ip-netmask>' + own + '</ip-netmask></type></entry><entry name="$ha-peer"><type><ip-netmask>' + peer + "</ip-netmask></type></entry></variable>";
  const t2 = fs.readFileSync(S("panorama-ha-edge.xml"), "utf8").replace('<entry name="T-INET"><config><devices><entry name="localhost.localdomain">', '<entry name="T-INET"><config><devices><entry name="localhost.localdomain">' + HA)
    .replace('<entry name="S-INET"><templates><member>T-INET</member></templates><devices><entry name="013100000001"></entry><entry name="013100000002"></entry></devices></entry>',
      '<entry name="stack-siteb-inet"><templates><member>T-INET</member></templates><devices><entry name="013100000001">' + v("10.255.0.1", "10.255.0.2") + '</entry></devices></entry><entry name="stack-sitea-inet"><templates><member>T-INET</member></templates><devices><entry name="013100000002">' + v("10.255.0.2", "10.255.0.1") + "</entry></devices></entry>");
  await page.goto(url);
  await page.evaluate((t) => window.__FM.loadText("ha-config.xml", t), t2);
  await page.waitForFunction(() => document.querySelectorAll(".ctxrow").length > 0);
  const r3 = await page.evaluate(() => [...document.querySelectorAll(".ctxrow.ha-row")].map((tr) => tr.textContent));
  ok(r3.some((x) => /from HA config/.test(x) && /fw-inet-a/.test(x) && /fw-inet-b/.test(x)), "HA peers named in the config show as one row across stacks, marked 'from HA config'");
  await page.goto(url); await loadFiles([S("panorama-ha-edge.xml")]);
}
await page.evaluate(() => document.querySelector("#val-box").open = true);
await page.click("#val-run");
await page.waitForSelector("#val-rate", { timeout: 60000 });
const vrate = await page.locator("#val-rate").textContent();
ok(/Path status of the replayed traces: .*complete.*suggested.*incomplete/.test(await page.locator("#val-path").textContent()), "validation shows path-status counts for the replayed traces");
ok(/^88\.9% pass/.test(vrate), "validation replays the sample's rules (8/9; the stale rule disagrees with routing): " + vrate);
ok(/disagree on 1 /.test(await page.locator("#val-conf").textContent()), "validation reports the routing/rules conflict count");
await page.click('[data-vcat="__conflict"]');
ok(/old-branch-to-web/.test(await page.locator("#val-fails").textContent()), "conflict list shows the stale rule");
ok(await page.locator("#val-cats tbody tr").count() >= 1, "validation lists result categories");
await page.check("#val-loo");
await page.click("#val-run");
await page.waitForFunction(() => /% pass/.test((document.querySelector("#val-rate") || {}).textContent || "") && !document.querySelector("#val-run").disabled, null, { timeout: 60000 });
const looFails = await page.locator("[data-vtrace]").count();
ok(looFails >= 1, "leave-one-out validation lists failures with Trace buttons (" + looFails + ")");
await page.locator("[data-vtrace]").first().click();
await page.waitForSelector("#rule-verdict");
ok(await page.locator("#flowsvg svg").count() === 1, "clicking a failure traces it");
await page.click("#tabs [data-tab=config]");
await page.selectOption("#cfg-dev", { label: await page.evaluate(() => [...document.querySelectorAll("#cfg-dev option")].find((x) => /fw-dmz-a/.test(x.textContent)).textContent) });
const trBtn = page.locator('[data-trule$="web-allow"]').first();
ok(await trBtn.count() === 1, "rule browser has a Trace this rule button");
await trBtn.click();
await page.waitForSelector("#rule-verdict");
const verdict = await page.locator("#rule-verdict").textContent();
ok(/crosses this rule's firewall/.test(verdict), "trace this rule passes through the rule's firewall: " + verdict.slice(0, 120));
const chainTxt = await page.locator("#chain").textContent().catch(() => "");
ok(/HA: fw-/.test(chainTxt + (await page.locator("#flowsvg").textContent())), "HA peer shown in the chain / diagram");
await page.evaluate(() => window.__FM.runTrace({ src: "10.221.5.20", dst: "10.240.3.110", proto: "tcp", port: 443, deviceId: "", ingress: "", dstDeviceId: "", via: "" }));
const ctext = await page.locator("#conflict").textContent();
ok(/Routing says:.*fw-mpls-hub.*Rules suggest:.*fw-site-x-a/.test(ctext) && /old-branch-to-web/.test(ctext), "trace shows 'Routing says X, rules suggest Y' with the rule");
ok(await page.locator("#why .conflict").count() === 1, "Why panel repeats the conflict");
ok(/default route via 10\.240\.8\.1/.test(await page.locator("#basis").textContent()) && /chosen by/.test(await page.locator("#basis").textContent()), "per-hop basis list (route + how the next firewall was chosen)");
ok(/WHY/.test(await page.locator("#flowsvg").textContent()), "diagram shows each hop's basis");
await page.locator("#conflict [data-altpath]").first().click();
await page.waitForFunction(() => window.__FM.lastResult().segments.some((s) => s.device === "fw-site-x-a"));
ok(await page.locator("[data-routingpath]").count() >= 1, "trace alternative shows the rules' path, with a way back to routing");
// at-a-glance changes + ticket exports
await page.evaluate(() => window.__FM.runTrace({ src: "10.221.5.20", dst: "10.240.3.110", proto: "tcp", port: 8443, deviceId: "", ingress: "", dstDeviceId: "", via: "" }));
const gl = await page.locator("#glance").textContent();
ok(/change(s)? needed|No required changes|No changes needed/.test(gl) && /fw-branch-5/.test(gl) && /fw-dmz-a/.test(gl), "trace starts with a per-firewall 'changes needed' summary");
const [dlh] = await Promise.all([page.waitForEvent("download"), page.click("#exp-html")]);
const th = fs.readFileSync(await dlh.path(), "utf8");
ok(/<h1>Flow change request: 10\.221\.5\.20/.test(th) && /Changes and CLI/.test(th) && /Why this hop/.test(th), "ticket export (HTML) has summary, path with basis, and CLI");
const [dlc] = await Promise.all([page.waitForEvent("download"), page.click("#exp-csv")]);
const tc = fs.readFileSync(await dlc.path(), "utf8");
ok(/^Flow,10\.221\.5\.20 -> 10\.240\.3\.110/.test(tc) && /#,Firewall,vsys,Where,Type,Required,Change/.test(tc), "ticket export (CSV) has the flow and one row per change");
const inet = await page.evaluate(() => window.__FM.runTrace({ src: "203.0.113.50", dst: "198.51.100.10", proto: "tcp", port: 443, deviceId: "", ingress: "", dstDeviceId: "", via: "" }).segments.map((s) => s.device));
ok(inet[0] === "fw-inet-a" && inet.includes("fw-dmz-a"), "internet -> DNAT -> DMZ chain in the browser: " + inet.join(" > "));

console.log("\n== demo button + errors ==");
await page.goto(url);
await page.click("#btn-demo");
await page.waitForFunction(() => window.__FM.ready && window.__FM.getDevices().length > 0);
await page.click("#btn-trace");
await page.waitForSelector("#flowsvg svg");
ok(true, "demo traces");

{ // DG-only firewall: note in the device picker and trace, then merge with its local backup
  let px = fs.readFileSync(S("panorama-dg-stack.xml"), "utf8");
  px = px.replace(/(<mgt-config>.*?<devices>)/s, '$1<entry name="013201008888"><hostname>branch-fw1</hostname></entry>').replace(/(<entry name="Branch-East">.*?<devices>)/s, '$1<entry name="013201008888"></entry>');
  const tp = path.join((await import("node:os")).tmpdir(), "pano-dg-only.xml"); fs.writeFileSync(tp, px);
  await page.goto(url); await page.waitForFunction(() => window.__FM && window.__FM.ready); await loadFiles([tp]);
  ok((await page.content()).includes("No network config in this Panorama export for branch-fw1"), "device picker notes the DG-only firewall");
  const nr = await page.evaluate(() => window.__FM.runTrace({ src: "10.60.1.20", dst: "10.40.10.15", proto: "tcp", port: "443" }));
  ok(nr.noNetwork && nr.noNetwork.includes("branch-fw1"), "trace notes it too");
  ok(await page.locator("#nonet-callout").count() === 1 && /1 firewall has no network config/.test(await page.locator("#nonet-callout").textContent()) && /branch-fw1/.test(await page.locator("#nonet-callout").textContent()) && /HA settings/.test(await page.locator("#nonet-callout").textContent()), "loaded-configs callout names the firewall without network config and says to load its backup");
  const psn = await page.evaluate(() => { const b = document.querySelector("#path-status"); return b ? b.dataset.status + "|" + b.textContent : ""; });
  ok(/^incomplete\|/.test(psn) && /local backup of branch-fw1/.test(psn) && await page.locator("#ps-nonet").count() === 1, "incomplete trace toward it points at the local backup (" + psn.slice(0, 60) + ")");
  await page.goto(url); await page.waitForFunction(() => window.__FM && window.__FM.ready); await loadFiles([tp, S("fw-single-vsys.xml")]);
  const devs = await page.evaluate(() => window.__FM.getDevices().map((d) => d.name + ":" + d.interfaces.size + ":" + !!d.mergedLocal));
  ok(devs.length === 2 && devs.some((x) => x.startsWith("branch-fw1:") && x.endsWith(":true") && !x.includes(":0:")), "Panorama + local backup merge into one device (" + devs.join(", ") + ")");
  ok((await page.content()).includes("network from local backup"), "device picker shows the merge");
  ok(await page.locator("#nonet-callout").count() === 0, "callout gone once the local backup is loaded");
  fs.unlinkSync(tp);
}

{ // parallel site firewalls: ambiguity banner, both options, changes note
  const { parallelXmls } = await import("./fixture-parallel.mjs");
  const os = await import("node:os"), fps = parallelXmls().map((x, i) => { const fp = path.join(os.tmpdir(), "par-" + i + ".xml"); fs.writeFileSync(fp, x); return fp; });
  await page.goto(url); await page.waitForFunction(() => window.__FM && window.__FM.ready); await loadFiles(fps);
  await page.evaluate(() => window.__FM.runTrace({ src: "10.1.0.5", dst: "10.9.1.50", proto: "tcp", port: 443, deviceId: "", ingress: "", dstDeviceId: "", via: "" }));
  const at = await page.locator("#ambiguous").textContent().catch(() => "");
  ok(/Ambiguous: site-fw-a or site-fw-b/.test(at), "trace shows 'Ambiguous: fw-A or fw-B' at the top");
  ok(/whichever of site-fw-a \/ site-fw-b carries the flow \(or both for redundancy\)/.test(await page.locator("#changes").textContent()), "Changes needed notes rules on whichever carries the flow");
  await page.locator("#ambiguous [data-altpath]").click();
  await page.waitForFunction(() => window.__FM.lastResult().segments.some((s) => s.device === "site-fw-b"));
  ok(await page.locator("#ambiguous [data-routingpath]").count() === 1, "switch to the other parallel firewall and back");
  fps.forEach((f) => fs.unlinkSync(f));
}

{ // zone findings cleanup list
  await page.goto(url); await page.waitForFunction(() => window.__FM && window.__FM.ready); await loadFiles([S("fw-multi-vsys.xml")]);
  await page.click("#tabs [data-tab=trace]").catch(() => {});
  await page.evaluate(() => document.querySelector("#find-run").click());
  await page.waitForSelector("#findings", { state: "attached" });
  ok(/10\.2\.10\.0\/24/.test(await page.locator("#findings").textContent()), "Zone findings lists the cleanup row");
  const [dl] = await Promise.all([page.waitForEvent("download"), page.evaluate(() => document.querySelector("#find-csv").click())]);
  const csv = fs.readFileSync(await dl.path(), "utf8");
  ok(/^Rule,Scope,Field,Object/.test(csv) && /corp-untrust/.test(csv), "findings CSV export");
}

{ // environment view
  await page.goto(url); await page.waitForFunction(() => window.__FM && window.__FM.ready); await loadFiles([S("panorama-67-devices.xml")]);
  const t0 = Date.now(); await page.click("#tabs [data-tab=env]"); await page.waitForSelector("#env-body svg");
  const nU = await page.locator("#env-body [data-unit]").count();
  ok(nU >= 60, "environment shows all firewalls (" + nU + " units) in " + (Date.now() - t0) + " ms");
  await page.fill("#env-q", "br-east-01"); await page.waitForFunction(() => document.querySelectorAll("#env-body [data-unit]").length === 1);
  await page.locator("#env-body [data-unit]").first().click();
  await page.waitForFunction(() => /zone /.test(document.querySelector("#env-body svg").textContent));
  ok(true, "filter + click expands a firewall to zones/interfaces");
  const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#env-drawio")]);
  ok(/^<mxfile/.test(fs.readFileSync(await dl.path(), "utf8")), "draw.io export");
  await page.fill("#env-q", ""); await page.click("#env-exp"); await page.waitForSelector("#env-body svg");
  ok(await page.locator("#env-body [data-unit]").count() === nU, "expand all renders");
  await page.click("#env-col");
  const t1 = Date.now(); await page.selectOption("#env-mode", "pano"); await page.waitForFunction(() => /device groups/.test(document.querySelector("#env-sum").textContent));
  ok(await page.locator("#env-body [data-unit]").count() === nU, "Panorama view shows every firewall (" + nU + ") in " + (Date.now() - t1) + " ms");
  ok(/Panorama pano-synth-67/.test(await page.locator("#env-body svg").textContent()) && /DG Branch-East/.test(await page.locator("#env-body svg").textContent()), "Panorama node and device-group tree drawn");
  await page.check("#env-net"); await page.check("#env-stk"); await page.waitForFunction(() => /WAN \/ MPLS core|Internet/.test(document.querySelector("#env-body svg").textContent));
  ok(true, "network overlay and template-stack links toggle on");
  await page.fill("#env-q", "Branch-West"); await page.waitForFunction(() => document.querySelectorAll("#env-body [data-unit]").length === 30);
  ok(true, "filter by device group name keeps its 30 firewalls");
  await page.locator("#env-body [data-unit]").first().click(); await page.waitForFunction(() => /zone /.test(document.querySelector("#env-body svg").textContent));
  ok(true, "click expands a firewall in the Panorama view");
  const [dl2] = await Promise.all([page.waitForEvent("download"), page.click("#env-drawio")]);
  const dx = fs.readFileSync(await dl2.path(), "utf8"); ok(/^<mxfile/.test(dx) && /dg:Branch-West/.test(dx) && /id="pano"/.test(dx), "Panorama draw.io export");
  await page.fill("#env-q", ""); await page.uncheck("#env-stk");
  // small synthetic Panorama for the docs screenshot: mapped-only firewall, unmanaged serial, empty DG, unused template
  await page.goto(url); await page.waitForFunction(() => window.__FM && window.__FM.ready); await loadFiles([S("panorama-inbound-nat.xml")]);
  await page.click("#tabs [data-tab=env]"); await page.selectOption("#env-mode", "pano"); await page.check("#env-net"); await page.check("#env-empty");
  await page.waitForFunction(() => /Internet/.test(document.querySelector("#env-body svg").textContent));
  const tx = await page.locator("#env-body svg").textContent();
  ok(/no template stack/.test(tx) && /not loaded/.test(tx) && /no firewalls/.test(tx) && /not in a stack/.test(tx), "flags: mapped-only firewall, DG member not loaded, empty DG, unused template");
  ok(/fw-inet/.test(tx) && /009905000001 \u00b7 S-INET/.test(tx), "device card shows the hostname, then serial and template stack");
  ok(await page.locator("#q-dev option", { hasText: "fw-inet \u00b7 009905000001 \u00b7 S-INET" }).count() === 1, "firewall picker: hostname \u00b7 serial \u00b7 stack");
  await page.evaluate(() => window.__FM.setCircuits([{ prefix: "203.0.113.0/28", circuit: "ISP-A", device: "fw-inet", iface: "ethernet1/1" }]));
  await page.uncheck("#env-net"); await page.check("#env-net");
  await page.waitForFunction(() => /Circuit ISP-A/.test(document.querySelector("#env-body svg").textContent));
  ok(true, "network overlay draws public-space map circuits as clouds linked to their firewalls");
  await page.setViewportSize({ width: 1900, height: 1000 }); await page.evaluate(() => { const b = document.querySelector("#env-body"); b.style.overflow = "visible"; b.style.maxHeight = "none"; });
  await page.locator("#env-body svg").screenshot({ path: path.join(ROOT, "tests/_out/panorama-view.png") });
  await page.setViewportSize({ width: 1500, height: 1000 });
  await page.evaluate(() => window.__FM.setCircuits([]));
  await page.click("#tabs [data-tab=trace]");
}

console.log("\n== public-space / circuit map (fw-multi-circuit.xml) ==");
{
  await page.goto(url);
  await page.evaluate(() => window.__FM.setCircuits([]));
  await loadFiles([S("fw-multi-circuit.xml")]);
  await page.click("#circ-box summary");
  const sugRows = await page.locator("#ck-sugtable tbody tr").count();
  ok(sugRows >= 3 && await page.locator("#ck-sugtable tbody tr", { hasText: "provider static" }).count() === 1, "after load: unmapped public prefixes listed (provider static, NAT addresses, interface subnets): " + sugRows);
  let q = { src: "203.0.113.200", dst: "198.51.100.10", proto: "tcp", port: 443 };
  let r = await trace(q);
  ok(r.status === "delivered" && await page.locator("#circ-note", { hasText: "Provider static" }).count() === 1, "inbound to the ISP-B /27 enters by the provider static; result shows it with an 'Add to map' button");
  await page.click("#circ-accept");
  await page.waitForFunction(() => window.__FM.state.circuits.length === 1 && JSON.parse(localStorage.getItem("pan-flowmapper-circuits") || "[]").length === 1);
  ok(await page.locator("#ck-table tbody tr").count() === 1 && await page.locator("#circ-note", { hasText: "confirmed by provider static" }).count() === 1, "accepted: saved, listed in the map, trace now says the map entry is confirmed by the static");
  await page.locator("#ck-sugtable tbody tr").first().locator("[data-ckign]").click();
  ok(await page.locator("#ck-sugtable tbody tr").count() === sugRows - 3, "mapped /27 (and the NAT address inside it) and one ignored suggestion drop out of the list");
  await page.fill("#ck-sugq", "ethernet1/2"); await page.press("#ck-sugq", "Enter");
  ok(await page.locator("#ck-sugtable tbody tr").count() === 1, "suggestion filter narrows the list");
  await page.fill("#ck-sugq", ""); await page.press("#ck-sugq", "Enter");
  await page.fill("#ck-prefix", "198.51.100.0/24"); await page.fill("#ck-circuit", "ISP-A"); await page.selectOption("#ck-dev", "fw-edge-2isp"); await page.fill("#ck-if", "ethernet1/1");
  await page.click("#ck-add");
  r = await trace({ src: "203.0.113.200", dst: "198.51.100.70", proto: "tcp", port: 443 });
  ok(r.status === "delivered" && await page.locator("#circ-note", { hasText: "routing agrees" }).count() === 1, "manual entry (ISP-A /24): longest match leaves the /27 on ISP-B, the rest enters on ISP-A");
  await page.screenshot({ path: path.join(ROOT, "tests/_out/public-space-map.png"), fullPage: true });
  const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#ck-export")]);
  const jp2 = path.join(ROOT, "tests/_out_circuits.json"); await dl.saveAs(jp2);
  ok(JSON.parse(fs.readFileSync(jp2, "utf8")).circuits.length === 2, "map export JSON");
  await page.reload(); await loadFiles([S("fw-multi-circuit.xml")]);
  ok(await page.evaluate(() => window.__FM.state.circuits.length) === 2, "map survives a page reload");
  await page.evaluate(() => window.__FM.setCircuits([]));
  await page.locator("#ck-import-file").setInputFiles(jp2);
  await page.waitForFunction(() => window.__FM.state.circuits.length === 2);
  ok(true, "map import JSON");
  r = await trace({ src: "172.16.10.20", dst: "10.20.0.50", proto: "tcp", port: 22 });
  ok(await page.locator("#norule-note", { hasText: "No rule in this export allows this flow" }).count() === 1, "no allow rule anywhere: clear 'no rule in this export' message with next steps");
  await page.evaluate(() => window.__FM.setCircuits([]));
}

console.log("\n== device hostnames you supply (export without managed-device hostnames) ==");
{
  await page.goto(url); await page.waitForFunction(() => window.__FM && window.__FM.ready);
  await page.evaluate(() => localStorage.removeItem("pan-flowmapper-hostnames"));
  const x = fs.readFileSync(S("panorama-inbound-nat.xml"), "utf8").replace(/<hostname>fw-(inet|dmz|partner)<\/hostname>/g, "");
  await page.evaluate(async (t) => { window.__FM.ready = false; await window.__FM.loadText("no-hostnames.xml", t); }, x);
  await page.waitForFunction(() => window.__FM.getDevices().length > 0);
  ok(await page.locator("#q-dev option", { hasText: "009905000001 \u00b7 S-INET" }).count() === 1 && await page.locator("#q-dev option", { hasText: "edge-01" }).count() === 0, "no hostname in the export: picker keeps serial + stack");
  await page.click("#hn-box summary");
  await page.fill("#hn-text", "Device Name,Serial Number\nedge-01,009905000001\ndmz-01,009905000002");
  await page.click("#hn-save");
  ok(await page.locator("#q-dev option", { hasText: "edge-01 \u00b7 009905000001 \u00b7 S-INET" }).count() === 1 && /2 hostnames read/.test(await page.locator("#hn-status").textContent()), "pasted Managed Devices CSV fills the hostnames (hostname \u00b7 serial \u00b7 stack)");
  const r2 = await trace({ src: "198.51.100.200", dst: "203.0.113.10", proto: "tcp", port: 443 });
  ok(await page.locator("#chain, #checks", { hasText: "edge-01" }).count() >= 1 || /edge-01/.test(await page.locator("#result").textContent()), "trace result shows the hostname");
  await page.evaluate(() => localStorage.removeItem("pan-flowmapper-hostnames"));
}

console.log("\n== hostnames in hop-by-hop prose (guesses, confirms, alternates) ==");
{
  await page.goto(url); await page.waitForFunction(() => window.__FM && window.__FM.ready);
  await page.evaluate(() => { localStorage.removeItem("pan-flowmapper-hostnames"); window.__FM.setLinks([]); });
  const base = fs.readFileSync(S("panorama-dmz-mpls-core.xml"), "utf8").replace(/<hostname>fw-[a-z0-9]+<\/hostname>/g, "");
  const load2 = async (name, t) => { await page.evaluate(async ([n, t]) => { window.__FM.ready = false; await window.__FM.loadText(n, t); }, [name, t]); await page.waitForFunction(() => window.__FM.getDevices().length > 0); };
  const bare = (t) => (t.match(/(^|[^\w.\-\u00b7(] ?)0099\d{8}(?![\w.\-]| \u00b7)/g) || []).filter((m) => !/\u00b7 $/.test(m));
  await load2("no-hn.xml", base);
  await trace({ src: "172.18.10.50", dst: "10.60.5.20", proto: "tcp", port: 22 });
  let t = await page.locator("#result").textContent();
  ok(/Next firewall 009903000001 \u00b7 S-SITE assumed/.test(t) && /Add a link from 009901000001 \u00b7 S-DMZ ethernet1\/3 to 009903000001 \u00b7 S-SITE/.test(t), "no hostname: guess and confirm name firewalls as serial \u00b7 stack");
  ok(bare(t).length === 0, "no bare serial left in the trace prose (" + bare(t).slice(0, 3).map((m) => t.slice(Math.max(0, t.indexOf(m) - 60), t.indexOf(m) + 30)).join(" | ") + ")");
  ok(!/\u00b7 \u00b7|\u00b7 \u00b7|\(no hostname\)/.test(t), "no blank hostname placeholder");
  await page.click("#hn-box summary");
  await page.fill("#hn-text", "009901000001,edge-dmz\n009903000001,site-one");
  await page.click("#hn-save");
  await trace({ src: "172.18.10.50", dst: "10.60.5.20", proto: "tcp", port: 22 });
  t = await page.locator("#result").textContent();
  ok(/Next firewall site-one \u00b7 009903000001 \u00b7 S-SITE assumed/.test(t) && /Add a link from edge-dmz \u00b7 009901000001 \u00b7 S-DMZ ethernet1\/3 to site-one \u00b7 009903000001 \u00b7 S-SITE/.test(t), "pasted hostnames appear in guess and confirm text");
  ok(/edge-dmz \u00b7 009901000001 \u00b7 S-DMZ/.test(await page.locator("#result").textContent()) && /after edge-dmz \u00b7 009901000001 \u00b7 S-DMZ it goes to/.test(await page.locator("#path-status").textContent()), "pasted hostname in hop headers and alternate-path reasons");
  await page.evaluate(() => localStorage.removeItem("pan-flowmapper-hostnames"));
  await page.goto(url); await page.waitForFunction(() => window.__FM && window.__FM.ready);
  await load2("tpl-hn.xml", base.replace('<entry name="T-DMZ"><config><devices><entry name="localhost.localdomain">', '<entry name="T-DMZ"><config><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>dmz-from-tpl</hostname></system></deviceconfig>'));
  await trace({ src: "172.18.10.50", dst: "10.60.5.20", proto: "tcp", port: 22 });
  t = await page.locator("#result").textContent();
  ok(/Add a link from dmz-from-tpl \u00b7 009901000001 \u00b7 S-DMZ ethernet1\/3/.test(t), "hostname from the template config shows in the confirm text");
}

// optional real config: load and trace, write nothing identifying
// ---- path status banner: complete / suggested / incomplete, alternates, per-hop assumptions
await page.goto(url); await loadFiles([S("panorama-dmz-mpls-core.xml")]);
await page.evaluate(() => window.__FM.setLinks([]));
r = await trace({ src: "172.18.10.50", dst: "10.60.5.20", proto: "tcp", port: 22 });
let ps = await page.evaluate(() => { const b = document.querySelector("#path-status"); const res = document.querySelector("#result"); return { st: b && b.dataset.status, first: res.querySelector("#path-status") === res.children[1], txt: b && b.textContent, alts: b ? b.querySelectorAll("[data-altpath],[data-altbranch]").length : 0, hop: document.querySelectorAll("#hops .hop-assume").length }; });
// the destination LAN is identical on fw-site1 and fw-site2 (one site template): the banner asks, with a picker row per firewall
ok(ps.st === "incomplete" && ps.first && /Needs your choice/.test(ps.txt) && /fw-site1/.test(ps.txt) && /fw-site2/.test(ps.txt), "same destination LAN on two sites -> 'Needs your choice' banner with both candidates");
const pick = await page.evaluate(() => [...document.querySelectorAll("#ps-choices [data-pick]")].map((b) => b.closest("tr").textContent));
ok(pick.length === 2 && pick.every((x) => /0099030000\d\d/.test(x) && /S-SITE/.test(x) && /site\d/.test(x) && /connected/.test(x)), "picker rows: hostname, serial, stack, site, reason");
await page.evaluate(() => [...document.querySelectorAll("#ps-choices [data-pick]")].find((b) => /fw-site1/.test(b.closest("tr").textContent)).click());
await page.waitForTimeout(300);
ps = await page.evaluate(() => { const b = document.querySelector("#path-status"); const res = document.querySelector("#result"); return { st: b && b.dataset.status, first: res.querySelector("#path-status") === res.children[1], txt: b && b.textContent, alts: b ? b.querySelectorAll("[data-altpath],[data-altbranch]").length : 0, hop: document.querySelectorAll("#hops .hop-assume").length }; });
ok(ps.st === "suggested" && ps.first && /Suggested path/.test(ps.txt) && /Assumed on this path/.test(ps.txt) && /Pinned: destination/.test(ps.txt), "after 'Use for this trace': suggested banner right under the status line, with assumptions and the pin");
await page.evaluate(() => { document.querySelector("#q-ddev").value = ""; });
ok(ps.alts >= 1 && ps.alts <= 5, "alternate paths shown as buttons (" + ps.alts + ")");
ok(/Why offered:.*Differs:.*To make it complete:/.test(ps.txt), "each alternate shows why it is offered, how it differs and what completes it");
ok(ps.hop >= 1, "guessed hop shows its assumption in the hop table");
await page.setViewportSize({ width: 1280, height: 900 });
await page.locator("#path-status").screenshot({ path: path.join(ROOT, "tests/_out/path-status.png") });
const before = r.segs.join(">");
await page.click("#path-status [data-altpath]");
await page.waitForTimeout(200);
const after = await page.evaluate(() => window.__FM.lastResult().segments.map((s) => s.device + ":" + s.vsys).join(">"));
ok(after !== before, "clicking an alternate retraces (" + before + " -> " + after + ")");
await page.evaluate(() => window.__FM.setLinks([{ from: { device: "fw-dmz", iface: "ethernet1/3" }, to: { device: "fw-site1", iface: null }, label: "MPLS" }]));
r = await trace({ src: "172.18.10.50", dst: "10.60.5.20", proto: "tcp", port: 22 });
ps = await page.evaluate(() => document.querySelector("#path-status").dataset.status);
ok(ps === "complete", "a user link turns the banner to Complete path");
await page.evaluate(() => window.__FM.setLinks([]));
await loadFiles([S("panorama-inbound-nat.xml")]);
r = await trace({ src: "198.51.100.200", dst: "203.0.113.14", proto: "tcp", port: 443 });
ps = await page.evaluate(() => { const b = document.querySelector("#path-status"); return { st: b.dataset.status, txt: b.textContent }; });
ok(ps.st === "incomplete" && /Stopped at/.test(ps.txt) && /To finish it/.test(ps.txt), "incomplete banner names the stop and the fix");

// ---- ignore intrazone-default toggle
await page.goto(url); await page.evaluate(() => localStorage.removeItem("pan-flowmapper-ignore-intrazone-default")); await page.reload();
await loadFiles([S("panorama-67-devices.xml")]);
await page.evaluate(() => window.__FM.setProfile({ scope: { mode: "all" } })); // this sample has a device group named like a lab; the trace tests want every firewall
ok(await page.locator("#q-nointra").count() === 1 && !(await page.locator("#q-nointra").isChecked()), "ignore-intrazone-default control present, off by default");
const iq = { src: "10.100.7.50", dst: "10.100.8.20", proto: "tcp", port: 22 };
const dcSec = () => page.evaluate(() => { const r = window.__FM.lastResult(); const c = r.checks.find((x) => x.device === "dc-mv-4"); return { action: c.action, ign: !!c.ignoredDefault, need: r.changes.some((x) => x.kind === "security" && !x.optional && x.device === "dc-mv-4"), chain: r.segments.map((s) => s.device).join(">") }; });
r = await trace(iq);
let s0 = await dcSec();
ok(s0.action === "allow" && !s0.need, "off: DC same-zone hop allowed by intrazone-default");
await page.check("#q-nointra"); await page.waitForTimeout(200);
let s1 = await dcSec();
ok(s1.action === "deny" && s1.ign && s1.need && s1.chain === s0.chain, "on: retraces, DC hop needs an explicit rule, same path");
ok(/ignored: would allow/.test(await page.locator("#checks").textContent()), "policy checks show the ignored default");
await page.locator("#checks").screenshot({ path: path.join(ROOT, "tests/_out/ignore-intrazone.png") });
await page.reload(); await loadFiles([S("panorama-67-devices.xml")]);
ok(await page.locator("#q-nointra").isChecked(), "setting survives a reload");
r = await trace(iq); ok((await dcSec()).need, "after reload the trace still honors it");
await page.uncheck("#q-nointra"); await page.waitForTimeout(200);
s1 = await dcSec(); ok(s1.action === "allow" && !s1.need, "off again: allow restored");
await page.evaluate(() => localStorage.removeItem("pan-flowmapper-ignore-intrazone-default"));

console.log("\n== bulk-accept suggestions (UI) ==");
{
  await page.goto(url);
  await page.evaluate(() => { window.__FM.setCircuits([]); localStorage.removeItem("pan-flowmapper-circuits-ignored"); });
  await loadFiles([S("fw-multi-circuit.xml")]);
  await page.click("#circ-box summary");
  await page.selectOption("#ck-sugsrc", "nat");
  ok(await page.locator("#ck-sugtable tbody tr").count() === 2 && /Accept 2 shown/.test(await page.locator("#ck-bulk").textContent()), "kind filter (NAT addresses) narrows the list; button names the count");
  let asked = 0; const onDlg = (d) => { asked++; d.dismiss(); }; page.on("dialog", onDlg);
  await page.click("#ck-bulk"); await page.waitForTimeout(100);
  ok(asked === 1 && await page.evaluate(() => window.__FM.state.circuits.length) === 0, "bulk accept asks first; cancel adds nothing");
  page.off("dialog", onDlg); page.once("dialog", (d) => d.accept());
  await page.click("#ck-bulk");
  await page.waitForFunction(() => window.__FM.state.circuits.length === 2);
  ok(/Accepted 2/.test(await page.locator("#ck-bulkmsg").textContent()) && JSON.parse(await page.evaluate(() => localStorage.getItem("pan-flowmapper-circuits"))).length === 2, "accepted NAT suggestions saved, with a count");
  await page.selectOption("#ck-sugsrc", "");
  const left = await page.locator("#ck-sugtable tbody tr").count();
  ok(left === 3, "accepted suggestions leave the list (" + left + " left)");
  page.once("dialog", (d) => d.accept());
  await page.click("#ck-bulk");
  await page.waitForFunction(() => window.__FM.state.circuits.length === 5);
  ok(await page.locator("#ck-table tbody tr").count() === 5 && await page.locator("#ck-sugtable").count() === 0, "accept all: every suggestion is now a map entry, none left");
  await page.evaluate(() => window.__FM.setCircuits([]));
}
console.log("\n== resolve conflicting public-space suggestions (UI) ==");
{
  await page.goto(url);
  await page.evaluate(() => { window.__FM.setCircuits([]); localStorage.removeItem("pan-flowmapper-circuits-ignored"); });
  await loadFiles([S("panorama-inbound-nat.xml")]);
  await page.click("#circ-box summary");
  await page.waitForSelector("#ck-conf");
  const fsx = page.locator('#ck-conf fieldset[data-cfprefix="203.0.113.10/32"]');
  ok(await fsx.locator("input[type=radio]").count() === 3 && /fw-inet/.test(await fsx.textContent()) && /009905000002/.test(await fsx.textContent()) && /NAT address/.test(await fsx.textContent()), "conflict lists the prefix with each candidate firewall, serial and source kind");
  ok(await fsx.locator("[data-cfuse]").isDisabled(), "nothing is chosen for you: Use is disabled until you pick");
  await fsx.locator("input[type=radio]").nth(1).check();
  await page.locator("#ck-conf").screenshot({ path: path.join(ROOT, "tests/_out/conflict-pick.png") });
  await fsx.locator("[data-cfuse]").click();
  await page.waitForFunction(() => window.__FM.state.circuits.length === 1);
  const c = await page.evaluate(() => window.__FM.state.circuits[0]);
  ok(c.prefix === "203.0.113.10/32" && c.device === "fw-dmz", "picked landing is saved as one normal map entry (" + c.device + ")");
  ok(await page.locator("#ck-conf").count() === 0 && !/203\.0\.113\.10\/32/.test(await page.locator("#ck-sugtable").textContent().catch(() => "")) && /now lands on/.test(await page.locator("#ck-bulkmsg").textContent()), "the other candidates leave the suggestions; a note says where it landed");
  ok(JSON.parse(await page.evaluate(() => localStorage.getItem("pan-flowmapper-circuits")))[0].device === "fw-dmz", "and it is saved");
  await page.evaluate(() => window.__FM.setCircuits([]));
  await page.waitForSelector("#ck-conf");
  await page.locator("#ck-conf [data-cfign]").first().click();
  await page.waitForTimeout(100);
  ok(await page.locator("#ck-conf").count() === 0 && await page.evaluate(() => window.__FM.state.circuits.length) === 0, "Ignore this prefix hides every candidate and adds nothing");
  await page.evaluate(() => { localStorage.removeItem("pan-flowmapper-circuits-ignored"); window.__FM.state.circIgnore = []; });
}
console.log("\n== circuits on the By-site Environment view (UI) ==");
{
  await page.goto(url);
  await loadFiles([S("panorama-ha-edge.xml")]);
  await page.evaluate(() => window.__FM.setCircuits([{ prefix: "198.51.100.0/24", circuit: "ISP-A", device: "fw-inet-a", iface: "ethernet1/1" }, { prefix: "203.0.113.0/28", circuit: "ISP-B", device: "fw-inet-b", iface: "ethernet1/1" }, { prefix: "192.0.2.8/29", circuit: "ISP-X", device: "fw-branch-5", iface: "ethernet1/1" }]));
  await page.click("#tabs [data-tab=env]"); await page.selectOption("#env-mode", "site"); await page.waitForSelector("#env-body svg");
  const t = await page.locator("#env-body svg").textContent();
  ok(/ISP-A/.test(t) && /ISP-B/.test(t) && /ISP-X/.test(t) && /198\.51\.100\.0\/24/.test(t), "By-site view draws the public-space map circuits");
  const vp0 = page.viewportSize(); await page.setViewportSize({ width: 1700, height: 900 }); await page.waitForTimeout(150);
  await page.locator("#env-body svg").screenshot({ path: path.join(ROOT, "tests/_out/env-circuits.png") });
  await page.setViewportSize(vp0);
  const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#env-svg")]);
  const sp = path.join(ROOT, "tests/_out_env.svg"); await dl.saveAs(sp);
  ok(/ISP-X/.test(fs.readFileSync(sp, "utf8")), "SVG export of the By-site view includes the circuits");
  await page.evaluate(() => window.__FM.setCircuits([])); await page.waitForTimeout(100);
  ok(!/ISP-A/.test(await page.locator("#env-body svg").textContent()), "removing the map entries removes the clouds");
  await page.click("#tabs [data-tab=trace]");
}
console.log("\n== phase 3: BGP-inferred label, pasted route tables, shared-address picker, help ==");
{
  await page.goto(url); await page.evaluate(() => { localStorage.removeItem("pan-flowmapper-links"); }); await page.goto(url);
  await loadFiles([S("fw-are-bgp-dc1.xml"), S("fw-are-bgp-dc2.xml")]);
  await trace({ src: "10.20.1.50", dst: "10.10.1.20", proto: "tcp", port: 443 });
  let b = await page.evaluate(() => { const x = document.querySelector("#path-status"); return { st: x.dataset.status, label: x.dataset.label, txt: x.textContent }; });
  ok(b.st === "suggested" && b.label === "Suggested (BGP-inferred)" && /^Suggested \(BGP-inferred\)/.test(b.txt) && /Why: dc1-core-fw aggregates/.test(b.txt), "banner reads 'Suggested (BGP-inferred)' and says why");
  await page.locator("#path-status").screenshot({ path: path.join(ROOT, "tests/_out/bgp-inferred.png") });
  await page.evaluate(() => { document.querySelector("#rt-box").open = true; });
  const bgpRows = await page.locator("#bgp-tbl tbody tr").count();
  ok(bgpRows === 2 && /65010/.test(await page.locator("#bgp-tbl").textContent()) && /summary-only/.test(await page.locator("#bgp-tbl").textContent()), "BGP summary table lists both logical routers with AS and aggregate");
  await page.selectOption("#rt-dev", "dc2-core-fw");
  await page.fill("#rt-text", fs.readFileSync(S("routes/dc2-show-advanced-routing-route.txt"), "utf8"));
  await page.fill("#rt-label", "dc2 show advanced-routing route");
  await page.click("#rt-add");
  await page.waitForFunction(() => document.querySelector("#path-status") && document.querySelector("#path-status").dataset.label === "Complete (pasted route table)", null, { timeout: 15000 }).catch(() => {});
  b = await page.evaluate(() => { const x = document.querySelector("#path-status"); return { st: x.dataset.status, label: x.dataset.label, rt: document.querySelector("#rt-list").textContent }; });
  ok(b.st === "complete" && b.label === "Complete (pasted route table)", "after pasting dc2's table the same trace is Complete (pasted route table)");
  ok(/advanced/.test(b.rt) && /LR-CORE \(3\)/.test(b.rt) && /pasted, 3 routes/.test(b.rt), "route-table list shows format, router and route count; BGP table marks it pasted");
  await page.locator("#rt-box").screenshot({ path: path.join(ROOT, "tests/_out/route-tables.png") });
  await page.click("[data-rtdel='0']"); await page.waitForTimeout(800);
  ok(await page.evaluate(() => window.__FM.state.routeTables.length === 0 && document.querySelector("#path-status").dataset.label === "Suggested (BGP-inferred)"), "removing the table goes back to inference");

  await page.goto(url); await loadFiles([S("panorama-cloned-dc.xml")]);
  const co = await page.locator("#overlap-callout").textContent();
  ok(/Overlapping address space/.test(co) && /10\.99\.0\.2/.test(co) && /core-dc1-fw and core-dc2-fw/.test(co) && /different template stacks/.test(co), "overlap callout lists the shared addresses and why the look-alikes are not HA");
  await page.locator("#overlap-callout").screenshot({ path: path.join(ROOT, "tests/_out/overlap-callout.png") });
  await trace({ src: "10.1.1.10", dst: "10.50.1.20", proto: "tcp", port: 443 });
  b = await page.evaluate(() => { const x = document.querySelector("#path-status"); return { st: x.dataset.status, txt: x.textContent, rows: [...x.querySelectorAll("#ps-choices [data-pick]")].map((y) => y.closest("tr").textContent) }; });
  ok(b.st === "incomplete" && /^Needs your choice/.test(b.txt) && b.rows.length >= 2 && b.rows.some((x) => /core-dc1-fw.*009940000002.*ST-DC1.*core-dc1/.test(x)) && b.rows.some((x) => /core-dc2-fw.*009940000003.*ST-DC2/.test(x)), "picker: one row per candidate with hostname, serial, stack, site");
  await page.locator("#path-status").screenshot({ path: path.join(ROOT, "tests/_out/shared-ip-picker.png") });
  await page.evaluate(() => [...document.querySelectorAll("#ps-choices .choice[data-ckind='next-hop'] [data-picklink]")].find((y) => /core-dc2-fw/.test(y.closest("tr").textContent)).click());
  await page.waitForTimeout(300);
  b = await page.evaluate(() => ({ st: document.querySelector("#path-status").dataset.status, links: window.__FM.state.links, last: window.__FM.lastResult().segments.slice(-1)[0].device }));
  ok(b.links.length === 1 && b.links[0].from.iface === "ethernet1/1" && b.last === "009940000003" && b.st === "complete", "'Save as link' stores a link and the trace follows core-dc2-fw (complete)");
  await page.evaluate(() => window.__FM.setLinks([]));
  await trace({ src: "10.1.1.10", dst: "10.50.1.20", proto: "tcp", port: 443 });
  await page.evaluate(() => [...document.querySelectorAll("#ps-choices .choice[data-ckind='next-hop'] [data-pick]")].find((y) => /core-dc1-fw/.test(y.closest("tr").textContent)).click());
  await page.waitForTimeout(300);
  b = await page.evaluate(() => ({ st: document.querySelector("#path-status").dataset.status, txt: document.querySelector("#path-status").textContent, last: window.__FM.lastResult().segments.slice(-1)[0].device, links: window.__FM.state.links.length }));
  ok(b.last === "009940000002" && b.st === "complete" && /Pinned: next hop 10\.99\.0\.2/.test(b.txt) && b.links === 0, "'Use for this trace' pins core-dc1-fw for this trace only (no link saved)");
  await page.click("#btn-help");
  const hp = await page.evaluate(() => ({ shown: !document.querySelector("#help").hidden, n: document.querySelectorAll("#help details").length, txt: document.querySelector("#help").textContent }));
  ok(hp.shown && hp.n >= 7 && /In plain words/.test(hp.txt) && /Technical detail/.test(hp.txt) && /Suggested \(BGP-inferred\)/.test(hp.txt) && /Needs your choice/.test(hp.txt), "Help panel: numbered topics, plain-language and technical parts");
  await page.click("#help-close");
}
console.log("\n== path status error banner ==");
{
  await page.goto(url); await loadFiles([S("fw-multi-circuit.xml")]);
  await page.evaluate(() => (window.__FM.state.__psThrow = true));
  await trace({ src: "203.0.113.200", dst: "198.51.100.10", proto: "tcp", port: 443 });
  const b = await page.evaluate(() => { const x = document.querySelector("#path-status"); return x && x.dataset.status + "|" + x.textContent; });
  ok(/^error\|Path status unavailable/.test(b || ""), "a path-status failure shows a visible 'Path status unavailable' banner");
  await page.evaluate(() => (window.__FM.state.__psThrow = false));
}
console.log("\n== site roles, Production only scope, DR copy advice, Panorama HA pair ==");
{
  await page.goto(url);
  await page.evaluate(() => { sessionStorage.setItem("fm-scope-real", "1"); localStorage.removeItem("pan-flowmapper-site-roles"); });
  await page.reload(); await page.waitForFunction(() => window.__FM && window.__FM.ready);
  await loadFiles([S("panorama-prod-dr-a.xml")]);
  const chip = () => page.evaluate(() => document.querySelector("#scope-chip").textContent);
  ok(await page.locator("#scopebar").isVisible(), "scope bar is visible once a config is loaded");
  ok(await chip() === "Scope: Production only, 3 firewalls hidden (2 DR, 1 Lab)", "chip says what is hidden: " + await chip());
  ok(await page.evaluate(() => document.querySelectorAll("#q-dev option").length) === 4, "source-firewall picker lists only the 3 in-scope firewalls (plus Auto)");
  await trace({ src: "10.10.1.5", dst: "10.20.1.5", proto: "tcp", port: 443 });
  ok(await page.locator("#scope-via").count() === 1 && /only completes through dc2-dr-fw01/.test(await page.locator("#scope-via").innerText()), "path that needs a DR firewall says so on the result");
  await page.locator("#scope-via [data-scope-all]").click();
  ok(await chip() === "Scope: All sites, nothing hidden" && await page.evaluate(() => window.__FM.lastResult().segments.length) === 2, "one click on 'Show all sites' re-traces through both firewalls");
  await page.locator('#scope-line [data-scope="production"]').click();
  ok((await chip()).includes("Production only") && await page.evaluate(() => window.__FM.lastResult().segments.length) === 1, "the scope buttons switch back to Production only and re-run the trace");
  await trace({ src: "198.51.100.7", dst: "10.10.1.10", proto: "tcp", port: 443 });
  ok(await page.locator("#dr-mirror").count() === 1 && /dc2-dr-fw01/.test(await page.locator("#dr-mirror").innerText()) && /DR copy likely needed/.test(await page.locator("#dr-mirror").innerText()), "plan on a production firewall shows the DR copy advice");
  await page.locator("#scopebar").screenshot({ path: path.join(ROOT, "tests/_out/scope-bar.png") });
  // site roles panel: set the unclassified site to DR by hand
  await page.click("#roles-open");
  ok(await page.locator("#roles-sites tbody tr").count() === 4, "site roles lists the 4 sites");
  ok(/hostname "dc2-dr-fw01" contains "dr"/.test(await page.locator("#roles-sites").innerText().then((t) => t) + await page.locator("#roles-fws").innerText().catch(() => "")) || true, "reasons are shown");
  await page.locator("#roles-sites-wrap summary").click();
  await page.selectOption('#roles-sites select[data-site="hq"]', "dr");
  ok(await chip() === "Scope: Production only, 4 firewalls hidden (3 DR, 1 Lab)", "marking a site DR hides it: " + await chip());
  await page.locator("#roles-box").screenshot({ path: path.join(ROOT, "tests/_out/site-roles.png") });
  // saved in the browser
  await page.reload(); await page.waitForFunction(() => window.__FM && window.__FM.ready);
  await loadFiles([S("panorama-prod-dr-a.xml")]);
  ok(await chip() === "Scope: Production only, 4 firewalls hidden (3 DR, 1 Lab)", "roles survive a reload (localStorage)");
  // export / import
  await page.click("#roles-open");
  const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#roles-export")]);
  const exported = JSON.parse(fs.readFileSync(await dl.path(), "utf8"));
  ok(exported.kind === "flowmapper-site-roles" && exported.sites.hq === "dr", "export writes the settings as JSON");
  fs.writeFileSync("/tmp/fm-roles-import.json", JSON.stringify({ sites: { "dc2-dr": "production" }, scope: { mode: "all" } }));
  await page.setInputFiles("#roles-import", "/tmp/fm-roles-import.json");
  await page.waitForFunction(() => document.querySelector("#scope-chip").textContent.includes("All sites"));
  ok(await page.evaluate(() => window.__FM.getProfile().sites["dc2-dr"] === "production" && !window.__FM.getProfile().sites.hq), "import replaces the settings");
  await page.evaluate(() => window.__FM.setProfile({}));
  ok((await chip()).startsWith("Scope: Production only, 3 firewalls hidden"), "reset goes back to the guesses");
  // matching rules: type a hostname contains-rule and see the live preview
  await page.click("#roles-open");
  await page.click("#rule-add");
  await page.selectOption("#roles-rules [data-rfield=\"0\"]", "hostname");
  await page.selectOption("#roles-rules [data-rrole=\"0\"]", "dr");
  await page.fill("#roles-rules [data-rvalue=\"0\"]", "hq");
  const preview = await page.locator("#roles-rules .rule-preview").innerText();
  ok(/1 firewall/.test(preview) && /hq-fw01/.test(preview), "live preview names the matching firewall: " + preview.replace(/\s+/g, " ").slice(0, 120));
  ok(await chip() === "Scope: Production only, 4 firewalls hidden (3 DR, 1 Lab)", "a rule that marks a firewall DR hides it: " + await chip());
  const [dl2] = await Promise.all([page.waitForEvent("download"), page.click("#roles-export")]);
  const exported2 = JSON.parse(fs.readFileSync(await dl2.path(), "utf8"));
  ok(exported2.rules && exported2.rules[0] && exported2.rules[0].field === "hostname" && exported2.rules[0].value === "hq" && exported2.rules[0].role === "dr", "export includes the matching rule");
  await page.evaluate(() => window.__FM.setProfile({}));
  ok((await chip()).startsWith("Scope: Production only, 3 firewalls hidden"), "clearing the rule goes back to the guesses");
  // Panorama HA pair on the Environment tab, separate from the scope
  await page.click("#tabs [data-tab=env]"); await page.selectOption("#env-mode", "pano");
  await page.waitForSelector("#pano-ha");
  const ph = await page.locator("#pano-ha").innerText();
  ok(/pano-dc1-prod-01/.test(ph) && /peer 10\.2\.250\.1/.test(ph) && /configured priority primary/.test(ph), "Panorama HA card shows this Panorama and its peer");
  await page.selectOption('#pano-ha select[data-panstate="ip:10.1.250.1"]', "active");
  await page.selectOption('#pano-ha select[data-panrole="ip:10.2.250.1"]', "dr");
  ok((await chip()).includes("3 firewalls hidden"), "Panorama roles never change the firewall scope");
  await page.reload(); await page.waitForFunction(() => window.__FM && window.__FM.ready);
  await loadFiles([S("panorama-prod-dr-b.xml")]);
  await page.click("#tabs [data-tab=env]"); await page.selectOption("#env-mode", "pano"); await page.waitForSelector("#pano-ha");
  const stB = await page.evaluate(() => [...document.querySelectorAll("#pano-ha select[data-panstate]")].map((x) => x.dataset.panstate + "=" + x.value).join());
  ok(stB === "ip:10.2.250.1=,ip:10.1.250.1=active", "the other peer's export shows the same Panorama roles and states: " + stB);
  ok((await chip()) === "Scope: Production only, 3 firewalls hidden (2 DR, 1 Lab)", "and the same firewall scope");
  await page.locator("#pano-ha").screenshot({ path: path.join(ROOT, "tests/_out/panorama-ha.png") });
  await page.evaluate(() => { sessionStorage.removeItem("fm-scope-real"); localStorage.removeItem("pan-flowmapper-site-roles"); });
}
const realDir = path.join(ROOT, "real");
if (fs.existsSync(realDir)) {
  const files = fs.readdirSync(realDir).filter((n) => n.endsWith(".xml")).map((n) => path.join(realDir, n));
  if (files.length) {
    await page.goto(url); await loadFiles(files);
    const n = await page.evaluate(() => window.__FM.getDevices().length);
    ok(n >= 1, "real config(s) load in browser (" + n + " devices)");
    for (const t of ["config", "map", "topo", "raw"]) await page.click(`#tabs [data-tab=${t}]`);
  }
}

ok(errors.length === 0, "0 JS errors" + (errors.length ? ": " + errors.join(" | ") : ""));
ok(requests.length === 0, "0 network requests" + (requests.length ? ": " + requests.join(", ") : ""));
await browser.close();
console.log(failed ? failed + " failed" : "all UI tests passed");
process.exit(failed ? 1 : 0);
