/* SPDX-License-Identifier: Apache-2.0 */
// Minimal tests: load the viewer's script in a stubbed DOM and feed it the synthetic samples.
import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(here, "..", "gp-log-viewer.html"), "utf8");
const script = html.match(/<script>([\s\S]*)<\/script>/)[1];

class El {
  constructor(sel) { this.sel = sel; this.kids = {}; this.children = []; this.textContent = ""; this.value = ""; this.className = ""; this.style = {}; this.length = 1; this.hidden = false; this.classList = { add() {}, remove() {}, toggle() {} }; }
  set innerHTML(v) {
    this._html = v; this.children = []; this.kids = {};
    for (const m of String(v).matchAll(/<(span|b|h3|div)\b/g)) { const c = new El(m[1]); this.children.push(c); }
  }
  get innerHTML() { return this._html || ""; }
  querySelector(s) {
    const tag = /^(span|b|h3)$/.test(s) ? s : (/^\.(what|tip|cnt|ex)$/.test(s) ? null : undefined);
    if (tag) { const c = this.children.find((x) => x.sel === tag); if (c) return c; } return (this.kids[s] ||= new El(s)); }
  appendChild(c) { this.children.push(c); return c; }
  append(...c) { c.forEach((x) => typeof x !== "string" && this.children.push(x)); }
  replaceChildren(f) { this.children = f && f.children ? f.children : []; }
  add() {}
  click() {}
  scrollIntoView() {}
}
const root = new El("root");
const document = {
  querySelector: (s) => root.querySelector(s),
  createElement: () => new El("el"),
  createDocumentFragment: () => new El("frag"),
};
const ctx = vm.createContext({ document, Option: class {}, window: {}, console, TextDecoder, Blob, Response, TextEncoder, DecompressionStream, Uint8Array, DataView, Date, setTimeout });
vm.runInContext(script, ctx);

let failed = 0;
function ok(cond, msg) { if (!cond) { failed++; console.log("FAIL:", msg); } else console.log("ok:", msg); }

async function loadSample(name) {
  const buf = fs.readFileSync(path.join(here, "..", "samples", name));
  ctx.__f = [{ name, arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) }];
  await vm.runInContext("load(__f)", ctx);
}

for (const sample of ["GlobalProtectLogs.tgz", "GlobalProtectLogs.zip"]) {
  await loadSample(sample);
  const lines = vm.runInContext("LINES.length", ctx);
  ok(lines >= 20, `${sample}: reads the log lines (${lines})`);
  const files = vm.runInContext("FILES.join(',')", ctx);
  ok(/PanGPS\.log/.test(files) && /pan_gp_event\.log/.test(files), `${sample}: lists the files it read`);
  const titles = root.querySelector("#issues").children.map((c) => c.querySelector("h3").textContent).join("|");
  for (const want of ["Wrong username or password", "Single sign-on", "Cannot reach the VPN portal", "Security certificate problem", "HIP", "MFA", "fallback to SSL"]) {
    ok(titles.includes(want), `${sample}: problem card "${want}"`);
  }
  const summary = root.querySelector("#sum").children.map((c) => c.querySelector("b").textContent + "=" + c.querySelector("span").textContent).join(";");
  ok(/Portal=vpn\.example\.com/.test(summary), `${sample}: portal is detected`);
  ok(/Gateway=gw1\.example\.com/.test(summary), `${sample}: gateway is detected`);
}

await vm.runInContext("load([{name:'x.log',arrayBuffer:async()=>new TextEncoder().encode('(T1) 11/02/26 08:00:00:000 Debug( 1): hello\\n').buffer}])", ctx);
ok(root.querySelector("#issues").innerHTML.includes("No known problems"), "clean log shows no problems");

console.log(failed ? `${failed} FAILED` : "all passed");
process.exit(failed ? 1 : 0);
