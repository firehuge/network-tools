#!/usr/bin/env node
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * Headless UI tests for pan-physical-upgrade.html (system Chrome + playwright-core).
 * Uses only the synthetic samples in samples/. Screenshots go to tests/_out/screenshots/ (git-ignored).
 */
import { chromium } from "playwright-core";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const PORT = 8766;
const SHOTS = path.join(ROOT, "tests", "_out", "screenshots"); // git-ignored (**/tests/_out*)
fs.mkdirSync(SHOTS, { recursive: true });

const server = http.createServer((req, res) => {
  const rel = decodeURIComponent((req.url || "/").split("?")[0]);
  const fp = path.join(ROOT, rel === "/" ? "pan-physical-upgrade.html" : rel);
  if (!fp.startsWith(ROOT) || !fs.existsSync(fp) || fs.statSync(fp).isDirectory()) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { "Content-Type": fp.endsWith(".html") ? "text/html; charset=utf-8" : "application/octet-stream" });
  fs.createReadStream(fp).pipe(res);
});
await new Promise(r => server.listen(PORT, "127.0.0.1", r));
const URL0 = `http://127.0.0.1:${PORT}/`;
const chrome = process.env.CHROME_PATH || ["/usr/bin/google-chrome-stable", "/usr/bin/google-chrome", "/usr/bin/chromium"].find(p => fs.existsSync(p));
if (!chrome) { console.log("No Chrome found; skipping UI tests."); server.close(); process.exit(0); }

let failed = 0;
const ok = (c, m) => { if (c) console.log("  ok  :", m); else { failed++; console.error("  FAIL:", m); } };
const browser = await chromium.launch({ executablePath: chrome, args: ["--no-sandbox"] });
const errors = [];
async function newPage(scheme) {
  const ctx = await browser.newContext({ colorScheme: scheme, viewport: { width: 1360, height: 1000 }, acceptDownloads: true });
  await ctx.addInitScript(() => { window.__PPU_NOW = "2026-11-27T12:00:00Z"; });
  const page = await ctx.newPage();
  page.on("pageerror", e => errors.push(String(e)));
  page.on("console", m => { if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(m.text()); });
  await page.goto(URL0);
  return page;
}
async function load(page, sample) {
  await page.setInputFiles("#fi", path.join(ROOT, "samples", sample));
  await page.waitForSelector("#out:not([hidden])", { timeout: 60000 });
}
const tab = (page, t) => page.click(`.tabs button[data-tab="${t}"]`);
const setVal = (page, sel, v) => page.$eval(sel, (e, v) => { e.value = v; e.dispatchEvent(new Event("change")); }, v);
process.on("unhandledRejection", e => { console.error(e); process.exit(1); });
const text = (page, sel) => page.$eval(sel, e => e.innerText);

console.log("-- theme");
{
  const page = await newPage("dark");
  ok(await page.evaluate(() => document.body.classList.contains("dark")), "follows OS dark preference");
  await page.click("#btn-dark");
  ok(!(await page.evaluate(() => document.body.classList.contains("dark"))), "toggle switches to light");
  await page.reload();
  ok(!(await page.evaluate(() => document.body.classList.contains("dark"))), "choice is remembered after reload");
  await page.context().close();
  const p2 = await newPage("light");
  ok(!(await p2.evaluate(() => document.body.classList.contains("dark"))), "follows OS light preference");
  await p2.context().close();
}

console.log("-- PA-3220 HA bundle (dark mode)");
{
  const page = await newPage("dark");
  await load(page, "techsupport_pa3220-ha.tgz");
  const cur = await text(page, "#tab-current");
  ok(/PA-3220/.test(cur) && /End of sale 2023-08-31/.test(cur), "current device + lifecycle shown");
  ok(/Concurrent sessions/.test(cur) && /283,993/.test(cur), "peak sessions from dp-monitor");
  ok(/ethernet1\/17/.test(cur), "interface table");
  ok(/Panorama-managed/.test(cur), "Panorama-managed flag");
  await page.screenshot({ path: path.join(SHOTS, "1-current-dark.png"), fullPage: true });
  await page.check("#hideser");
  ok(!/000000000001/.test(await text(page, "#tab-current")), "serial can be hidden");
  await page.uncheck("#hideser");

  await tab(page, "target");
  let tg = await text(page, "#tab-target");
  ok(/Smallest model that fits/.test(tg) && /PA-550/.test(tg), "suggests PA-550");
  ok(/VM-300/.test(tg), "VM sizing card");
  ok(/Why not smaller\?/.test(tg), "explains rejected smaller models");
  ok(/Panorama rule/.test(tg), "Panorama version rule shown");
  ok(await page.isChecked("#o-ha"), "HA defaults on for HA source");
  await page.screenshot({ path: path.join(SHOTS, "2-target-dark.png"), fullPage: true });
  await setVal(page, "#o-head", "100");
  tg = await text(page, "#tab-target");
  ok(!/Smallest model that fits\s*\n\s*PA-550/.test(tg), "more headroom picks a bigger model");
  await setVal(page, "#o-head", "30");

  await tab(page, "hardware");
  const hw = await text(page, "#tab-hardware");
  ok(/Power supplies and power cords/.test(hw) && /2 power supply\(ies\) seen in the tech-support file/.test(hw), "PSU count read from the tech-support file");
  ok(/Optics and cables to quote/.test(hw) && /HA cabling/.test(hw), "optics/cables and HA cabling sections");
  ok(/copper\/fiber change|port type change/.test(hw), "speed/media/port-type change summary");
  await page.screenshot({ path: path.join(SHOTS, "6-hardware-dark.png"), fullPage: true });
  await page.click("#btn-dark");
  await page.screenshot({ path: path.join(SHOTS, "6-hardware-light.png"), fullPage: true });
  await page.click("#btn-dark");
  const qty0 = await page.$$eval(".hw-qty", e => e.map(x => x.value));
  ok(qty0.length > 0, "BOM has editable quantities");

  await tab(page, "lic");
  let lic = await text(page, "#tab-lic");
  ok(/Review what you have today/.test(lic) && /Threat Prevention/.test(lic) && /HA pair/.test(lic), "license review page with HA ×2");
  ok(/Config uses it/.test(lic) && /Not seen in config/.test(lic), "usage hints from the config");
  ok(/Not included:/.test(lic) && /SD WAN|SD-WAN/i.test(lic), "expired subscription not carried by default");
  ok(/Add or change/.test(lic) && /Advanced WildFire/.test(lic), "neutral add section");
  await page.selectOption('.lic-keep[data-n="URL Filtering"]', "0");
  ok(/dropped by you/.test(await text(page, "#tab-lic")), "dropping a license is recorded");
  await page.check('.lic-add[data-n="Advanced WildFire"]');
  ok(/Advanced WildFire/.test(await text(page, "#tab-lic").then(t => t.split("3. List for the quote")[1])), "added subscription lands in the list");
  await page.screenshot({ path: path.join(SHOTS, "7-licenses-dark.png"), fullPage: true });

  await tab(page, "convert");
  ok(await page.$$eval(".mapsel", s => s.length) >= 10, "mapping rows");
  ok(await page.isChecked('input[name="cmode"][value="exact"]') && !(await page.$("#c-host")), "100% mode is the default and has no device-setting fields");
  await page.click("#b-conv");
  await page.waitForSelector("#b-dlxml");
  { const [dlx] = await Promise.all([page.waitForEvent("download"), page.click("#b-dlxml")]); const x0 = fs.readFileSync(await dlx.path(), "utf8"); ok(!/SYN-NEW-FW/.test(x0) && /<hostname>SYN-PA3220-A<\/hostname>/.test(x0), "100% conversion keeps hostname"); }
  await page.check('input[name="cmode"][value="custom"]');
  await page.fill("#c-host", "SYN-NEW-FW");
  await page.fill("#c-ip", "10.10.0.77"); await page.fill("#c-mask", "255.255.255.0"); await page.fill("#c-gw", "10.10.0.1");
  await page.fill("#c-dns1", "10.10.0.2"); await page.fill("#c-dns2", "10.10.0.3");
  await page.check("#c-adm"); await page.fill("#c-an", "breakglass");
  await page.fill("#c-ap", "Synthetic-Pass-123"); await page.fill("#c-ap2", "Different-Pass-123");
  await page.click("#b-conv");
  ok(/do not match/.test(await text(page, "#convout")), "mismatched admin passwords are rejected");
  await page.fill("#c-ap", "Synthetic-Pass-123"); await page.fill("#c-ap2", "Synthetic-Pass-123");
  await page.click("#b-conv");
  await page.waitForSelector("#b-dlxml");
  const conv = await text(page, "#convout");
  ok(/Converted/.test(conv), "conversion ran");
  ok(/No unresolved references/.test(conv), "HA links auto-suggested onto free ports, nothing unresolved");
  ok(/break-glass/i.test(conv) || /Break-glass/.test(conv), "break-glass note shown");
  ok(!/Synthetic-Pass-123/.test(await page.content()) && (await page.$eval("#c-ap", e => e.value)) === "", "password is cleared from the page");
  const [dl] = await Promise.all([page.waitForEvent("download"), page.click("#b-dlxml")]);
  const xml = fs.readFileSync(await dl.path(), "utf8");
  ok(/<hostname>SYN-NEW-FW<\/hostname>/.test(xml), "downloaded XML has new hostname");
  ok(/<ip-address>10\.10\.0\.77<\/ip-address>/.test(xml) && /<primary>10\.10\.0\.2<\/primary>/.test(xml), "custom mgmt IP and DNS applied");
  ok(/<entry name="breakglass"><phash>\$5\$[^<]+<\/phash><permissions><role-based><superuser>yes<\/superuser>/.test(xml) && !/Synthetic-Pass-123/.test(xml), "local admin added with $5$ hash, no plaintext");
  ok(/^<\?xml/.test(xml) && /<config/.test(xml), "downloaded XML is a config");
  const [dl2] = await Promise.all([page.waitForEvent("download"), page.click("#b-dlcsv")]);
  const csv = fs.readFileSync(await dl2.path(), "utf8");
  ok(/^"kind","xpath","from","to","note"/m.test(csv), "change log CSV");
  ok(/new local admin breakglass/.test(csv) && !/\$5\$/.test(csv) && !/Synthetic-Pass/.test(csv), "change log lists the admin but no hash or password");
  await page.screenshot({ path: path.join(SHOTS, "4-convert-dark.png"), fullPage: true });

  await tab(page, "report");
  await page.waitForTimeout(300);
  const fr = page.frame({ url: /about:srcdoc/ });
  const rtxt = await fr.evaluate(() => document.body.innerText);
  const bg = await fr.evaluate(() => getComputedStyle(document.body).backgroundColor);
  ok(/Firewall refresh summary/.test(rtxt) && /PA-550/.test(rtxt), "report shows target");
  ok(!/\$\s?\d/.test(rtxt), "report has no prices");
  ok(/Hardware, power and cabling to quote/.test(rtxt) && /Power cords/.test(rtxt), "report has hardware & cabling section");
  ok(/Added at the customer's request:.*Advanced WildFire/.test(rtxt) && /dropped on review/.test(rtxt), "report reflects license review");
  ok(bg === "rgb(255, 255, 255)", "report is light even in dark mode (" + bg + ")");
  await page.screenshot({ path: path.join(SHOTS, "5-report-from-dark.png"), fullPage: true });
  const [dl3] = await Promise.all([page.waitForEvent("download"), page.click("#b-rhtml")]);
  ok(/color-scheme content=light/.test(fs.readFileSync(await dl3.path(), "utf8")), "exported report forces light");
  ok(/Readiness checks/.test(rtxt) && /Capacity against/.test(rtxt) && /Does not move with the config/.test(rtxt) && /Rack and power/.test(rtxt), "report has readiness section");
  // readiness tab
  await tab(page, "readiness");
  const rd = await text(page, "#tab-readiness");
  ok(/PAN-OS version and upgrade path/.test(rd) && /Install this PAN-OS on the new firewall/.test(rd), "readiness: version check");
  ok(/Certificates and private keys/.test(rd) && /Master key/.test(rd) && /User-ID agents/.test(rd), "readiness: won't-migrate list");
  ok(/Panorama-managed firewall/.test(rd) && /Push to Devices/.test(rd), "readiness: Panorama guidance");
  ok(/Capacity: your config against PA-550/.test(rd) && /Within limit|Unknown/.test(rd) && /Security rules/.test(rd), "readiness: capacity table");
  ok(/Rack and power/i.test(rd) && /Power inlet/i.test(rd) && /not in sources/i.test(rd), "readiness: rack and power (PA-550 rack data unknown, said so)");
  ok(await page.$$eval("#tab-readiness a[href^='http']", a => a.length) > 0, "readiness: sources are linked");
  await page.screenshot({ path: path.join(SHOTS, "8-readiness-dark.png"), fullPage: true });
  // runbook and plan file
  await tab(page, "report");
  { const [dr] = await Promise.all([page.waitForEvent("download"), page.click("#b-runbook")]); const md = fs.readFileSync(await dr.path(), "utf8");
    ok(/^# Cutover runbook/.test(md) && /ARP/.test(md) && /Rollback/.test(md) && /show session info/.test(md), "runbook downloads with key sections");
    ok(!/\$5\$/.test(md), "runbook has no hash"); }
  let planTxt;
  { const [dp] = await Promise.all([page.waitForEvent("download"), page.click("#b-psave")]); planTxt = fs.readFileSync(await dp.path(), "utf8");
    ok(/"schema": 1/.test(planTxt) && !/\$5\$|phash|synthetic-break-glass|password/i.test(planTxt), "plan JSON has no password or hash"); }
  ok(JSON.parse(planTxt).plan.custom.adminName === "breakglass" && !("adminPass" in JSON.parse(planTxt).plan.custom), "plan keeps admin name only");
  { const planPath = path.join(ROOT, "tests", "_out", "plan.json"); fs.mkdirSync(path.dirname(planPath), { recursive: true }); fs.writeFileSync(planPath, planTxt.replace('"hideSerial"', '"x"'));
    await tab(page, "target"); await page.selectOption("#o-model", "PA-3410");
    await tab(page, "report"); await page.setInputFiles("#b-pload", planPath); await page.waitForTimeout(500);
    ok(/Plan loaded/.test(await text(page, "#plan-msg")), "plan loads");
    await tab(page, "target"); ok((await page.$eval("#o-model", e => e.value)) === "PA-550", "plan reload restores the target");
    fs.rmSync(planPath, { force: true }); }

  // manual VM pick
  await tab(page, "target");
  await page.selectOption("#o-model", "VM-300");
  ok(/Current vs\. proposed/.test(await text(page, "#tab-target")) && /VM-300/.test(await text(page, "#tab-target")), "manual VM pick shows comparison");
  await tab(page, "convert");
  await page.check('input[name="cmode"][value="exact"]');
  await page.click("#b-conv");
  await page.waitForSelector("#b-dlxml");
  ok(/Converted/.test(await text(page, "#convout")), "converts to VM-300");
  await tab(page, "hardware");
  ok(/no power supplies or cords/.test(await text(page, "#tab-hardware")) && /No physical optics or cables/.test(await text(page, "#tab-hardware")), "VM target: no PSU/cables");
  await page.context().close();
}

console.log("-- PA-5220 multi-vsys (light mode)");
{
  const page = await newPage("light");
  await load(page, "techsupport_pa5220-multivsys.tgz");
  await page.screenshot({ path: path.join(SHOTS, "1-current-light.png"), fullPage: true });
  await tab(page, "target");
  await page.screenshot({ path: path.join(SHOTS, "2-target-light.png"), fullPage: true });
  await tab(page, "lic");
  const lic = await text(page, "#tab-lic");
  ok(/vsys/i.test(lic), "vsys callout on licenses");
  await page.screenshot({ path: path.join(SHOTS, "3-licenses-light.png"), fullPage: true });
  await tab(page, "target");
  await page.selectOption("#o-model", "PA-3410");
  await tab(page, "lic");
  ok(/Virtual Systems license \(\+2\)/.test(await text(page, "#tab-lic")), "PA-3410 needs +2 vsys license");
  await page.context().close();
}

console.log("-- PA-820 without dp-monitor; plain XML");
{
  const page = await newPage("light");
  await load(page, "techsupport_pa820-small.tgz");
  ok(/Not in this file/.test(await text(page, "#tab-current")), "missing metrics called out");
  await page.setInputFiles("#fi", path.join(ROOT, "samples", "running-config_pa3220-ha.xml"));
  await page.waitForFunction(() => /PAN-OS/.test(document.querySelector("#tab-current").innerText));
  await tab(page, "convert");
  ok(await page.$$eval(".mapsel", s => s.length) > 0, "plain running-config can be converted");
  await page.context().close();
}

console.log("-- PA-440 with masked secrets: warnings and real-config override");
{
  const page = await newPage("light");
  await load(page, "techsupport_pa440-masked-standalone.tgz");
  const cur = await text(page, "#tab-current");
  await page.screenshot({ path: path.join(SHOTS, "7-current-masked-standalone-light.png"), fullPage: true });
  ok(/Secrets are masked in this file/.test(cur), "Current tab warns about masked secrets");
  ok(!/Panorama-managed|gets config from Panorama/.test(cur), "standalone PA-440 is not shown as Panorama-managed");
  ok(!/power supply status/i.test(cur), "no PSU 'not in file' warning for a model that never reports it");
  ok(/Very low measured load/.test(await (async () => { await tab(page, "target"); return text(page, "#tab-target"); })()), "Target tab flags the idle sample");
  await tab(page, "convert");
  ok(/masked secrets/.test(await text(page, "#tab-convert")), "Convert tab warns and offers real-config input");
  await page.screenshot({ path: path.join(SHOTS, "8-convert-masked-light.png"), fullPage: true });
  await page.setInputFiles("#c-real", path.join(ROOT, "samples", "running-config_pa440-exported.xml"));
  await page.waitForFunction(() => /instead of the tech-support copy/.test(document.querySelector("#tab-convert").innerText));
  await page.click("#b-conv"); await page.waitForSelector("#convout .status, #convout .note", { timeout: 60000 });
  const co = await text(page, "#convout");
  ok(/Converted/.test(co) && !/masked value/.test(co), "conversion from the real export has no masked warning");
  await page.screenshot({ path: path.join(SHOTS, "9-convert-real-export-light.png"), fullPage: true });
  ok(/encrypted value/.test(co), "real export: encrypted values are listed");
  await page.setInputFiles("#c-real", path.join(ROOT, "samples", "running-config_pa3220-ha.xml"));
  await page.waitForTimeout(300);
  await page.context().close();
}
console.log("-- PA-VM managed by Panorama");
{
  const page = await newPage("light");
  await load(page, "techsupport_vm-managed.tgz");
  const cur = await text(page, "#tab-current");
  await page.screenshot({ path: path.join(SHOTS, "10-current-vm-managed-light.png"), fullPage: true });
  ok(/VM-Series/.test(cur) && /16 vCPU/.test(cur) && /2,500,000/.test(cur), "Current tab describes the VM and its session capacity");
  ok(/merged config/.test(cur), "Current tab says counts come from the merged config");
  ok(!/model not in catalog/i.test(cur), "no 'model not in catalog' for PA-VM");
  await tab(page, "hardware");
  ok(/Virtual machine: no power supplies/.test(await text(page, "#tab-hardware")), "hardware tab: VM source has no power supplies");
  await page.context().close();
}

if (process.env.PPU_REAL_TSF && fs.existsSync(process.env.PPU_REAL_TSF)) {
  // Optional local check against a real bundle. Prints pass/fail only; no screenshots, nothing written.
  console.log("-- real bundle (local only)");
  const page = await newPage("light");
  await page.setInputFiles("#fi", process.env.PPU_REAL_TSF);
  await page.waitForSelector("#out:not([hidden]), #err:not([hidden])", { timeout: 300000 });
  ok(await page.isVisible("#out"), "real bundle loads");
  await tab(page, "target"); await tab(page, "lic"); await tab(page, "convert");
  if (await page.$("#b-conv")) { await page.click("#b-conv"); await page.waitForSelector("#convout .status, #convout .note", { timeout: 60000 }); ok(/Converted/.test(await text(page, "#convout")), "real config converts"); }
  await tab(page, "report");
  await page.context().close();
}

console.log("-- offline by default, opt-in catalog check, Help, header buttons");
{
  const RAW = "https://raw.githubusercontent.com/**/pan-physical-upgrade/catalog/models.json"; // route glob; the page itself uses its built-in URL
  const RAW_PROBE = "https://raw.githubusercontent.com/example/example/main/probe.json";
  const cat = JSON.parse(fs.readFileSync(path.join(ROOT, "catalog", "models.json"), "utf8"));
  const newer = { ...cat, data_as_of: "2099-01-01" };
  const mk = async (url, route) => {
    const ctx = await browser.newContext({ viewport: { width: 1360, height: 1000 } });
    const page = await ctx.newPage();
    const net = [], viol = [];
    page.on("request", r => { if (!/^(http:\/\/127\.0\.0\.1|blob:|data:)/.test(r.url())) net.push(r.url()); });
    page.on("console", m => { if (/Content Security Policy/i.test(m.text())) viol.push(m.text()); });
    // Always intercept the catalog URL before the page loads, so tests never reach the real network.
    await page.route(RAW, route === "fail" ? (r => r.abort()) : (r => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(newer) })));
    await page.goto(url);
    return { ctx, page, net, viol };
  };
  const base = `http://127.0.0.1:${PORT}/`;
  // 1) default load: offline, nothing fetched, CSP has no connect-src allowance
  let s = await mk(base, true);
  await s.page.waitForTimeout(800);
  const csp0 = await s.page.evaluate(() => document.querySelector('meta[http-equiv="Content-Security-Policy"]').content);
  ok(/connect-src 'none'/.test(csp0) && /default-src 'none'/.test(csp0) && !/githubusercontent/.test(csp0), "default CSP: connect-src 'none'");
  ok(s.net.length === 0, "default load makes no network request");
  ok(/Offline by default/.test(await text(s.page, "#nettip")) && /bundled/.test(await text(s.page, "#catbadge")), "header says offline by default; catalog is bundled");
  const hdr = await s.page.evaluate(() => [...document.querySelectorAll("header > button")].map(b => b.id));
  ok(hdr.slice(-2).join() === "btn-help,btn-dark", "Help then Dark are the last two header buttons (" + hdr.join() + ")");
  ok(await s.page.evaluate(() => document.querySelector("#help").hidden), "help panel starts closed");
  await s.page.click("#btn-help");
  ok(await s.page.evaluate(() => !document.querySelector("#help").hidden && document.querySelectorAll("#help details").length >= 4), "Help button opens the usage guide");
  await s.page.click("#help-close");
  ok(await s.page.evaluate(() => document.querySelector("#help").hidden), "Close help hides it");
  const blocked = await s.page.evaluate(async RAW_PROBE => { try { await fetch(RAW_PROBE); return "allowed"; } catch (e) { return "blocked"; } }, RAW_PROBE);
  ok(blocked === "blocked", "a fetch attempt in offline mode is blocked by the CSP");
  // 2) clicking the button switches to online mode and the check works
  await s.page.click("#btn-catcheck");
  await s.page.waitForURL(/\?online/);
  s.viol.length = 0; // the deliberate offline fetch above logged one violation
  await s.page.waitForFunction(() => /Catalog: online/.test(document.querySelector("#catbadge").textContent), null, { timeout: 15000 });
  const cspOn = await s.page.evaluate(() => document.querySelector('meta[http-equiv="Content-Security-Policy"]').content);
  ok(/connect-src https:\/\/raw\.githubusercontent\.com;/.test(cspOn), "online CSP allows raw.githubusercontent.com only");
  ok(/Catalog: online \(data as of 2099-01-01\)/.test(await text(s.page, "#catbadge")), "online catalog check works and is applied");
  ok(s.viol.length === 0, "no CSP violations in online mode: " + s.viol.slice(0, 1).join("|"));
  const other = await s.page.evaluate(async () => { try { await fetch("https://example.com/"); return "allowed"; } catch (e) { return "blocked"; } });
  ok(other === "blocked", "online mode still blocks every other host");
  await s.ctx.close();
  // 3) ?offline wins even if ?online is present; a failed check keeps the bundled catalog
  s = await mk(base + "?online&offline", true);
  await s.page.waitForTimeout(500);
  ok(s.net.length === 0 && /connect-src 'none'/.test(await s.page.evaluate(() => document.querySelector('meta[http-equiv="Content-Security-Policy"]').content)), "?offline overrides ?online");
  await s.ctx.close();
  s = await mk(base + "?online", "fail");
  await s.page.waitForFunction(() => /check failed/.test(document.querySelector("#catbadge").textContent), null, { timeout: 15000 });
  ok(true, "a failed online check reports it and keeps the bundled catalog");
  await s.ctx.close();
}

ok(errors.length === 0, "no page errors" + (errors.length ? ": " + errors.slice(0, 3).join(" | ") : ""));
await browser.close();
server.close();
console.log(failed ? `${failed} UI check(s) failed` : "All UI checks passed");
process.exit(failed ? 1 : 0);
