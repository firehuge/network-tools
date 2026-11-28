/* SPDX-License-Identifier: Apache-2.0 */
/* Browser checks for gp-log-viewer.html: CSP, Help, button placement, real file load. Synthetic samples only. */
import { chromium } from "playwright-core";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, "..");
const chrome = process.env.CHROME_PATH || ["/usr/bin/google-chrome-stable", "/usr/bin/google-chrome", "/usr/bin/chromium"].find((p) => fs.existsSync(p));
let failed = 0;
const ok = (c, m) => { if (!c) { failed++; console.error("  FAIL:", m); } else console.log("  ok  :", m); };

const browser = await chromium.launch({ executablePath: chrome, args: ["--no-sandbox"] });
const page = await browser.newPage();
const viol = [], errors = [], external = [];
page.on("console", (m) => { if (m.type() === "error") (/Content Security Policy/i.test(m.text()) ? viol : errors).push(m.text()); });
page.on("pageerror", (e) => errors.push(String(e)));
page.on("request", (r) => { if (!/^(file:|blob:|data:)/.test(r.url())) external.push(r.url()); });
await page.goto("file://" + path.join(root, "gp-log-viewer.html"));

console.log("\n== offline hygiene ==");
const csp = await page.evaluate(() => (document.querySelector('meta[http-equiv="Content-Security-Policy"]') || {}).content || "");
ok(/default-src 'none'/.test(csp) && /connect-src 'none'/.test(csp), "strict CSP meta (no network access)");
const hdr = await page.evaluate(() => [...document.querySelectorAll("header > button")].map((b) => b.id));
ok(hdr.slice(-2).join() === "btn-help,btn-dark", "Help then Dark are the last two header buttons (" + hdr.join() + ")");
ok(await page.evaluate(() => document.querySelector("#help").hidden), "help panel starts closed");
await page.click("#btn-help");
ok(await page.evaluate(() => !document.querySelector("#help").hidden && document.querySelectorAll("#help details").length >= 4), "Help button opens the usage guide");
await page.click("#help-close");
ok(await page.evaluate(() => document.querySelector("#help").hidden), "Close help hides it");
await page.click("#btn-dark");
ok(await page.evaluate(() => document.body.classList.contains("dark")), "Dark toggle works");

console.log("\n== real file load under the CSP ==");
for (const f of ["GlobalProtectLogs.zip", "GlobalProtectLogs.tgz"]) {
  await page.goto("file://" + path.join(root, "gp-log-viewer.html"));
  await page.setInputFiles("#fi", path.join(root, "samples", f));
  await page.waitForFunction(() => !document.querySelector("#out").hidden && document.querySelector("#sum").children.length > 0, null, { timeout: 30000 });
  ok(await page.evaluate(() => document.querySelectorAll("#issues > *").length > 0), f + " loads and shows problem cards");
}
ok(viol.length === 0, "no CSP violations: " + viol.slice(0, 1).join("|"));
ok(errors.length === 0, "no page errors: " + errors.slice(0, 1).join("|"));
ok(external.length === 0, "no network requests: " + external.slice(0, 1).join("|"));
await browser.close();
console.log(failed ? `\n${failed} test(s) failed` : "\nall passed");
process.exit(failed ? 1 : 0);
