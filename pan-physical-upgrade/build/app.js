/* SPDX-License-Identifier: Apache-2.0 */
/* PAN Physical Upgrade Planner: UI. Logic lives in core.js (window.PPU). */
"use strict";
const WORKER_JS = "@@WORKER_JS@@";
const BUNDLED_CATALOG = "@@CATALOG_JSON@@";
const ONLINE = window.__PPU_ONLINE === true;
const ONLINE_CATALOG_URL = "https://raw.githubusercontent.com/firehuge/network-tools/main/pan-physical-upgrade/catalog/models.json";
const U = PPU.util;
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const XML = {
  parse(s) {
    const d = new DOMParser().parseFromString(s, "application/xml");
    const pe = d.getElementsByTagName("parsererror")[0];
    if (pe) throw new Error("XML parse error: " + pe.textContent.slice(0, 200));
    return d;
  },
  serialize(d) {
    let s = new XMLSerializer().serializeToString(d);
    if (!/^<\?xml/.test(s)) s = '<?xml version="1.0"?>\n' + s;
    return s;
  }
};

/* ---------------- state ---------------- */
const ST = {
  catalog: BUNDLED_CATALOG, catalogSource: "bundled", idx: null,
  A: null, fileName: "", R: null, rec: null, opts: { headroomPct: 30, includeRugged: false, includeCellular: false, showEos: false, vmPorts: 8 },
  overrides: {}, targetName: null, ha: null, map: {}, mapNotes: {}, haPortMap: {}, conv: null, hideSerial: false,
  convMode: "exact",
  custom: { host: "", ip: "", mask: "", gw: "", dns1: "", dns2: "", ipv6: "", ipv6gw: "", removePanorama: false, adminOn: false, adminName: "", adminRole: "superuser" },
  hw: { qty: {}, type: {}, opSpeed: {}, psuPerUnit: null },
  lic: { keep: {}, add: {}, qty: {}, supportOn: false, supportTier: "", vsysExtra: null },
  customPorts: null
};
const NEWCUSTOM = () => ({ host: "", ip: "", mask: "", gw: "", dns1: "", dns2: "", ipv6: "", ipv6gw: "", removePanorama: false, adminOn: false, adminName: "", adminRole: "superuser" });
function now() { return window.__PPU_NOW ? new Date(window.__PPU_NOW) : new Date(); }
function rebuildIndex() { ST.idx = PPU.catalogIndex(ST.catalog, now()); }
rebuildIndex();

/* ---------------- theme ---------------- */
const THEME_KEY = "ppu-theme";
function storedTheme() { try { return localStorage.getItem(THEME_KEY); } catch (e) { return null; } }
function applyTheme(t) {
  const dark = t === "dark" || (!t && window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches);
  document.body.classList.toggle("dark", dark);
  const b = $("#btn-dark"); if (b) b.textContent = dark ? "Light" : "Dark";
}
applyTheme(storedTheme());
if (window.matchMedia) { try { matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { if (!storedTheme()) applyTheme(null); }); } catch (e) {} }
$("#btn-dark").onclick = () => {
  const next = document.body.classList.contains("dark") ? "light" : "dark";
  try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
  applyTheme(next);
};

/* ---------------- catalog (bundled, online, or file) ---------------- */
function setCatalog(cat, source) {
  if (!cat || cat.schema !== 1 || !Array.isArray(cat.hardware)) throw new Error("Not a catalog file (schema 1)");
  ST.catalog = cat; ST.catalogSource = source; rebuildIndex();
  $("#catbadge").textContent = "Catalog: " + source + " (data as of " + (cat.data_as_of || "?") + ")";
  if (ST.A) refreshAll();
}
$("#catbadge").textContent = "Catalog: bundled (data as of " + (BUNDLED_CATALOG.data_as_of || "?") + ")";
/* Online catalog check is opt-in. The page starts offline (CSP: no network). The button reloads it with ?online, where the CSP
   allows raw.githubusercontent.com only, and the check then runs once automatically. */
$("#nettip").textContent = ONLINE
  ? "Online mode: the only network request is the catalog check to raw.githubusercontent.com. Files stay on this computer. Nothing is uploaded."
  : $("#nettip").textContent;
async function checkCatalog() {
  const badge = $("#catbadge"), bundled = String(BUNDLED_CATALOG.data_as_of || "");
  badge.textContent = "Catalog: checking online...";
  try {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 5000);
    const r = await fetch(ONLINE_CATALOG_URL, { signal: ctl.signal, cache: "no-store" }); clearTimeout(t);
    if (!r.ok) throw new Error("HTTP " + r.status);
    const cat = await r.json();
    if (cat.schema === 1 && String(cat.data_as_of || "") >= bundled) setCatalog(cat, "online");
    else badge.textContent = "Catalog: bundled is current (data as of " + (bundled || "?") + ")";
  } catch (e) { badge.textContent = "Catalog check failed (offline or blocked); using bundled (data as of " + (bundled || "?") + ")"; }
}
$("#btn-catcheck").onclick = () => {
  if (ONLINE) { checkCatalog(); return; }
  if (ST.A && !confirm("Checking for a newer catalog reloads the page in online mode, which clears the loaded file. Continue?")) return;
  location.href = location.pathname + "?online";
};
if (ONLINE) checkCatalog();
$("#catfile").onchange = async e => {
  const f = e.target.files[0]; if (!f) return;
  try { setCatalog(JSON.parse(await f.text()), "file " + f.name); } catch (err) { showErr("Catalog file: " + err.message); }
};

/* ---------------- loading ---------------- */
let worker = null, workerUrl = null;
function showErr(m) { const e = $("#err"); e.hidden = !m; e.textContent = m || ""; }
function progress(m) {
  const p = $("#prow"); p.hidden = false;
  const pct = m.fileSize ? Math.min(100, 100 * m.inBytes / m.fileSize) : 0;
  $("#pbar>div").style.width = pct.toFixed(0) + "%";
  $("#ptext").textContent = (m.stage || "reading") + " · " + (m.filesIndexed || 0) + " files · " + (m.currentFile || "").split("/").pop();
}
function unpack(file) {
  return new Promise((resolve, reject) => {
    const files = [];
    workerUrl = URL.createObjectURL(new Blob([WORKER_JS], { type: "text/javascript" }));
    worker = new Worker(workerUrl);
    const dec = new TextDecoder();
    const done = (fn, v) => { try { worker.terminate(); } catch (e) {} URL.revokeObjectURL(workerUrl); worker = null; fn(v); };
    worker.onmessage = ev => {
      const m = ev.data || {};
      if (m.type === "progress") progress(m);
      else if (m.type === "batch") for (const f of m.files) { if (f.textBuf) { f.text = dec.decode(new Uint8Array(f.textBuf)); delete f.textBuf; } files.push(f); }
      else if (m.type === "done") done(resolve, files);
      else if (m.type === "error") done(reject, new Error(m.message));
      else if (m.type === "cancelled") done(reject, new Error("Cancelled"));
    };
    worker.onerror = ev => done(reject, new Error(ev.message || "Worker failed"));
    worker.postMessage({ type: "start", file, budget: 512 * 1024 * 1024 });
  });
}
$("#btn-help").onclick = () => { const h = $("#help"); h.hidden = !h.hidden; if (!h.hidden) h.scrollIntoView({ behavior: "smooth", block: "start" }); };
$("#help-close").onclick = () => { $("#help").hidden = true; };
$("#btn-cancel").onclick = () => { if (worker) worker.postMessage({ type: "cancel" }); };
async function loadFile(file) {
  showErr(""); ST.fileName = file.name;
  $("#drop").classList.add("small");
  try {
    let files;
    if (/\.xml$/i.test(file.name)) files = [{ name: "running-config.xml", text: await file.text(), size: file.size }];
    else files = await unpack(file);
    $("#prow").hidden = true;
    ST.A = PPU.analyzeTsf(files, XML, { now: now() });
    if (!ST.A.system && !ST.A.config) throw new Error("No tech-support CLI output or running config found in this file.");
    ST.overrides = {}; ST.targetName = null; ST.ha = ST.A.ha.enabled; ST.map = {}; ST.haPortMap = {}; ST.conv = null; ST.customPorts = null;
    window.__planMsg = ""; ST.convMode = "exact"; ST.custom = NEWCUSTOM(); ST.hw = { qty: {}, type: {}, opSpeed: {}, psuPerUnit: null }; ST.lic = { keep: {}, add: {}, qty: {}, supportOn: false, supportTier: "", vsysExtra: null };
    $("#out").hidden = false;
    refreshAll();
    showTab("current");
  } catch (e) {
    $("#prow").hidden = true;
    showErr("Could not read " + file.name + ": " + e.message);
  }
}
const drop = $("#drop");
drop.onclick = () => $("#fi").click();
$("#fi").onchange = e => { if (e.target.files[0]) loadFile(e.target.files[0]); e.target.value = ""; };
drop.ondragover = e => { e.preventDefault(); drop.classList.add("over"); };
drop.ondragleave = () => drop.classList.remove("over");
drop.ondrop = e => { e.preventDefault(); drop.classList.remove("over"); if (e.dataTransfer.files[0]) loadFile(e.dataTransfer.files[0]); };
window.__ppuLoad = loadFile;

/* ---------------- tabs ---------------- */
function showTab(t) {
  for (const b of $$(".tabs button")) b.classList.toggle("on", b.dataset.tab === t);
  for (const p of $$(".tabpanel")) p.hidden = p.id !== "tab-" + t;
  if (t === "report") renderReport();
  if (t === "readiness") renderReadiness();
}
for (const b of $$(".tabs button")) b.onclick = () => showTab(b.dataset.tab);

/* ---------------- shared bits ---------------- */
function srcModel() { if (!ST.A || !ST.A.system) return null; return PPU.findModel(ST.idx, ST.A.system.model) || PPU.vmSourceModel(ST.A.system, ST.idx); }
function target() { return ST.targetName ? PPU.findModel(ST.idx, ST.targetName) : (ST.rec && ST.rec.top ? ST.rec.top.m : null); }
function targetPorts() {
  const t = target(); if (!t) return [];
  if (ST.customPorts && ST.customPorts.model === t.model) return ST.customPorts.ports;
  return PPU.portList(t, { vmPorts: ST.opts.vmPorts });
}
function maskSerial(s) { if (!s) return "—"; return ST.hideSerial ? "••••" + String(s).slice(-4) : s; }
function lifecyclePill(m) {
  if (m && m.vm_source) return '<span class="pill i">VM-Series' + (m.vcpu && m.vcpu[0] ? " · " + esc(m.vcpu[0]) + " vCPU" : "") + "</span>";
  if (!m) return '<span class="pill">model not in catalog</span>';
  const map = { "current": ["g", "Currently sold"], "end-of-sale-announced": ["y", "End-of-sale " + m.eos_date], "end-of-sale": ["r", "End of sale " + m.eos_date], "end-of-life": ["r", "End of life " + m.eol_date] };
  const [c, t] = map[m.lifecycle] || ["", m.lifecycle];
  return '<span class="pill ' + c + '">' + esc(t) + "</span>";
}
function f(label, value, src) { return '<div class="f"><b>' + esc(label) + "</b><span>" + (value == null || value === "" ? '<span class="nf">not in file</span>' : value) + "</span>" + (src ? '<div class="src">' + esc(src) + "</div>" : "") + "</div>"; }
function bar(p) { if (p == null || isNaN(p)) return ""; const c = p > 90 ? "r" : p > 70 ? "y" : ""; return '<div class="bar ' + c + '"><div style="width:' + Math.min(100, p).toFixed(0) + '%"></div></div>'; }
function srcRef(m) { return (m && m.sources || []).map(k => ST.idx.sources[k]).filter(Boolean).map(s => '<a href="' + esc(s.url) + '" target="_blank" rel="noopener">' + esc(s.title) + "</a>").join(" · "); }

function refreshAll() {
  ST.R = PPU.deriveRequirements(ST.A, ST.idx, Object.assign({}, ST.opts, ST.overrides, { ha: ST.ha }));
  ST.rec = PPU.recommend(ST.A, ST.idx, ST.R, ST.opts);
  if (ST.targetName && !PPU.findModel(ST.idx, ST.targetName)) ST.targetName = null;
  ensureMap();
  renderCurrent(); renderTarget(); renderHardware(); renderLic(); renderConvert(); renderReadiness();
  if (!$("#tab-report").hidden) renderReport();
}

/* ---------------- 1. current device ---------------- */
function catMedia(m, name) {
  if (!m || m.vm_source || !m.ports) return null;
  try { const p = PPU.portList(m).find(x => x.name === name); return p ? p.media + " (per catalog)" : null; } catch (e) { return null; }
}
function renderCurrent() {
  const A = ST.A, s = A.system || {}, m = srcModel(), c = A.config;
  const R = ST.R;
  let h = '<div class="card"><div class="status ' + (m && m.lifecycle !== "current" ? "s-y" : "s-g") + '">' + esc(s.model || "Unknown model") + " · PAN-OS " + esc(s.swVersion || (c && c.detailVersion) || "?") +
    '<span class="pills">' + lifecyclePill(m) + (A.ha.enabled ? '<span class="pill i">HA ' + esc(A.ha.mode || "") + "</span>" : '<span class="pill">Standalone</span>') +
    (c && c.panorama ? '<span class="pill i">Panorama-managed</span>' : "") + (A.vsysInUse > 1 ? '<span class="pill i">' + A.vsysInUse + " vsys</span>" : "") + "</span></div>";
  h += '<div class="grid">' + f("Hostname", esc(s.hostname || (c && c.mgmt.hostname))) + f("Serial", '<span id="serialv">' + esc(maskSerial(s.serial)) + "</span>") +
    f("Model", esc(s.model) + (m && m.vm_source ? " (" + esc(m.note.replace(/\.$/, "")) + ")" : "")) + f("PAN-OS", esc(s.swVersion)) + f("Uptime", esc(s.uptime)) +
    f("End of sale / end of life", m && m.vm_source ? "VM-Series has no hardware end-of-sale" : m && (m.eos_date || m.eol_date) ? esc((m.eos_date || "—") + " / " + (m.eol_date || "—")) : (m ? "Not announced" : null), m && m.replacement ? "Vendor replacement: " + m.replacement : "") +
    f("Last PAN-OS for this model", m && m.vm_source ? "See the PAN-OS release notes for your hypervisor" : m && m.last_panos ? esc(m.last_panos) : (m ? "Not announced" : null)) +
    f("HA", A.ha.enabled ? esc((A.ha.mode || "enabled") + (A.ha.peerModel ? " · peer " + A.ha.peerModel : "") + (A.ha.localState ? " · this unit " + A.ha.localState : "")) : "Not enabled") +
    f("Virtual systems", esc(A.vsysInUse) + (s.multiVsys ? " (multi-vsys on)" : ""), A.vsysLicensed ? "Licensed: " + A.vsysLicensed : "") +
    f("Panorama", c && c.panorama ? esc(c.panorama.servers.join(", ")) + (A.panoramaStatus ? (A.panoramaStatus.some(p => p.connected) ? " (connected)" : " (not connected)") : "") : "Not configured") + "</div>";
  h += '<label class="btn noprint" style="margin-top:10px;display:inline-block"><input type="checkbox" id="hideser"' + (ST.hideSerial ? " checked" : "") + "> Hide serial numbers (screen and report)</label>";
  const miss = A.missing.filter(x => !(m && m.psu && m.psu.cli_status === false && /^power supply status/.test(x)));
  if (miss.length) h += '<div class="note y"><b>Not in this file:</b> ' + miss.map(esc).join("; ") + ". Those numbers show as “not in file” and sizing falls back to what is available. You can type your own numbers on step 2.</div>";
  if (A.masked && A.masked.count) h += '<div class="note r"><b>Secrets are masked in this file.</b> ' + esc(A.masked.count) + ' value(s) show as ******** (private keys, pre-shared keys, server secrets' + (A.masked.admins.length ? ", local admin password hashes" : "") + '). Use this file for planning, but convert a config exported from the firewall (Device &gt; Setup &gt; Operations &gt; Export named configuration snapshot): load it on the Convert tab.</div>';
  if (A.configIsMerged) h += '<div class="note">Counts and interfaces below come from the <b>merged</b> config (Panorama template + device group + local), because that is what the firewall enforces. The local config alone has only ' + esc(A.localConfig.interfaces.length) + " interface(s) and " + esc(A.localConfig.counts.security) + ' security rule(s).</div>';
  if (A.pushedConfig || (c && c.panorama)) h += '<div class="note">This firewall gets config from Panorama. Only the <b>local</b> config is converted. Template and device-group settings stay in Panorama: update the template\'s interface names to match your new mapping, and add the new serial to the same template stack and device group.</div>';
  h += "</div>";

  // Usage matrix
  const cap = m || {};
  const row = (label, cur, peak, capv, fmt, srcTxt, note) => {
    const u = peak != null && capv ? 100 * peak / capv : null;
    return "<tr><td>" + esc(label) + '</td><td class="num">' + (cur == null ? '<span class="nf">not in file</span>' : fmt(cur)) + '</td><td class="num">' + (peak == null ? '<span class="nf">not in file</span>' : fmt(peak)) +
      '</td><td class="num">' + (capv == null ? '<span class="nf">not published</span>' : fmt(capv)) + "</td><td>" + (u == null ? "" : bar(u) + '<span class="muted">' + u.toFixed(0) + "%</span>") + '</td><td class="muted">' + esc(srcTxt || "") + (note ? "<br>" + esc(note) : "") + "</td></tr>";
  };
  const dp = A.dp, se = A.session || {};
  const tLabel = R.useThreat ? "Threat Prevention" : "firewall";
  h += '<div class="card"><h2>Usage vs. this model\'s capacity</h2><table class="data"><thead><tr><th>Metric</th><th class="num">Now</th><th class="num">Peak seen</th><th class="num">' + esc(s.model || "Model") + ' datasheet</th><th>Peak use</th><th>Where it came from</th></tr></thead><tbody>';
  h += row("Concurrent sessions", se.allocated, dp && dp.sessions ? dp.sessions.max : null, se.supported || cap.max_sessions, U.fmtNum, dp ? "dp-monitor " + dp.from.slice(0, 16).replace("T", " ") + " → " + dp.to.slice(0, 16).replace("T", " ") + " UTC" : "show session info", se.supported ? "capacity = sessions supported on this box" : "");
  h += row("Throughput (" + tLabel + ")", se.kbps != null ? se.kbps * 1000 : null, dp && dp.kbps ? dp.kbps.max * 1000 : null, R.useThreat ? cap.tp_bps : cap.fw_bps, U.fmtBps, dp ? "dp-monitor (sampled every ~10 min)" : "show session info", "");
  h += row("New sessions / sec", se.cps, dp && dp.cps ? dp.cps.max : null, cap.cps, U.fmtNum, dp ? "dp-monitor" : "show session info", "");
  h += row("Packets / sec", se.pps, dp && dp.pps ? dp.pps.max : null, null, U.fmtNum, "", "no datasheet figure");
  h += "</tbody></table>";
  if (dp) h += '<p class="muted">Peaks come from ' + dp.samples + " dp-monitor snapshots. Short bursts between snapshots are not captured, so keep some headroom.</p>";
  h += "</div>";

  // Interfaces
  const ifs = A.interfaces || [];
  h += '<div class="card"><h2>Interfaces</h2>';
  if (!ifs.length) h += '<p class="nf">No physical interface data.</p>';
  else {
    const pc = PPU.portCounts(ifs.filter(r => r.configured || r.up).map(r => ({ media: r.media || "unknown" })));
    h += '<p class="muted">' + ifs.filter(r => r.configured || r.up).length + " ports in use · " + (pc.virtual ? pc.virtual + " virtual · " : "") + pc.copper + " copper · " + (pc.fiber1g) + " 1G fiber · " + pc.fiber10g + " 10G fiber · " + (pc.fiber25g + pc.fiber40g + pc.fiber100g) + " 25G+ fiber" + (ifs.some(r => !r.media) ? " · some media unknown (not in file)" : "") + "</p>";
    h += '<div class="scroll"><table class="data"><thead><tr><th>Interface</th><th>Mode</th><th>Zone(s)</th><th>Subinterfaces</th><th>Media</th><th>Link</th><th class="num">Avg in</th><th class="num">Avg out</th><th>Avg use</th><th>Comment</th></tr></thead><tbody>';
    for (const r of ifs) {
      h += "<tr" + (!r.configured && !r.up ? ' class="muted"' : "") + "><td class=mono>" + esc(r.name) + "</td><td>" + esc(r.mode === "aggregate-group" ? "member of " + r.aggregateGroup : (r.mode || "—")) + "</td><td>" + esc((r.zones || []).join(", ")) + "</td><td>" + esc((r.units || []).length ? r.units.length + " (" + r.units.slice(0, 3).join(", ") + (r.units.length > 3 ? "…" : "") + ")" : "") +
        "</td><td>" + esc(r.portType || r.media || catMedia(m, r.name) || "—") + "</td><td>" + (r.up ? "up " + U.fmtSpeed(r.runtimeSpeed) : (r.state ? "down" : "—")) + '</td><td class="num">' + (r.avgRxBps != null ? U.fmtBps(r.avgRxBps) : '<span class="nf">—</span>') + '</td><td class="num">' + (r.avgTxBps != null ? U.fmtBps(r.avgTxBps) : '<span class="nf">—</span>') + "</td><td>" + (r.avgUtilPct != null ? bar(r.avgUtilPct) + '<span class="muted">' + r.avgUtilPct.toFixed(1) + "%</span>" : "") + "</td><td>" + esc(r.comment || "") + "</td></tr>";
    }
    h += "</tbody></table></div><p class=muted>Average use = byte counters ÷ uptime. It shows how busy a port is on average, not its peak. The tech-support file has no per-port peak.</p>";
  }
  if (c) {
    h += '<h3>Config at a glance</h3><div class="grid">' + f("Zones", c.counts.zones) + f("Security rules", c.counts.security) + f("NAT rules", c.counts.nat) + f("PBF rules", c.counts.pbf) + f("Decryption rules", c.counts.decryption) + f("Address objects", c.counts.addresses) + f("IPsec tunnels", c.counts.ipsecTunnels) + f("GlobalProtect", c.features.globalProtect ? c.counts.gpPortals + " portal(s), " + c.counts.gpGateways + " gateway(s)" : "none") + f("Routing", (c.lrs.length ? "Advanced routing (" + c.lrs.length + " logical router)" : c.vrs.length + " virtual router(s)")) + f("Aggregate groups", c.ae.length) + "</div>";
  }
  h += "</div>";
  $("#tab-current").innerHTML = h;
  const hs = $("#hideser"); if (hs) hs.onchange = () => { ST.hideSerial = hs.checked; renderCurrent(); };
}

/* ---------------- 2. target ---------------- */
function fitCell(fit, fmt) {
  if (!fit) return "<td></td>";
  if (fit.status === "unknown") return '<td class="unk">no data</td>';
  if (fit.status === "unpublished") return '<td class="unk">not published</td>';
  return '<td class="num ' + fit.status + '">' + fmt(fit.have) + (fit.util != null ? ' <span class="muted">(' + fit.util.toFixed(0) + "% used)</span>" : "") + "</td>";
}
function recCard(e, label, cls) {
  if (!e) return "";
  const m = e.m;
  const sel = target() && target().model === m.model;
  let h = '<div class="rec ' + (cls || "") + (sel ? " sel" : "") + '"><div class="muted">' + esc(label) + "</div><h3>" + esc(m.model) + (ST.R.ha ? " ×2 (HA)" : "") + "</h3>" + lifecyclePill(m);
  h += "<ul>";
  h += "<li>" + esc(ST.R.useThreat ? "Threat Prevention " : "Firewall ") + U.fmtBps(ST.R.useThreat ? m.tp_bps : m.fw_bps) + " · " + U.fmtNum(m.max_sessions) + " sessions · " + U.fmtNum(m.cps) + " CPS</li>";
  if (m.form === "hardware") h += "<li>Ports: " + esc(m.ports_text || "card based") + "</li>";
  if (e.maxUtil != null) h += "<li>Your peak + headroom uses " + e.maxUtil.toFixed(0) + "% of it</li>";
  if (e.vsysLicense) h += "<li>Needs a vsys license for " + e.vsysLicense + " more</li>";
  for (const w of e.warnings.slice(0, 4)) h += '<li class="why">⚠️ ' + esc(w) + "</li>";
  h += '</ul><div class="actions"><button type="button" class="primary pick" data-m="' + esc(m.model) + '">' + (sel ? "✓ Selected" : "Use this") + "</button></div></div>";
  return h;
}
function renderTarget() {
  const R = ST.R, rec = ST.rec, A = ST.A, o = ST.opts, ov = ST.overrides;
  let h = '<div class="card"><h2>What the new firewall must handle</h2><div class="form">';
  h += '<label>Growth headroom (%)<input type="number" id="o-head" min="0" max="300" step="5" value="' + esc(o.headroomPct) + '"></label>';
  h += '<label>Sessions needed<input type="number" id="o-sess" placeholder="' + esc(R.sessions == null ? "unknown" : R.sessions) + '" value="' + esc(ov.sessions ?? "") + '"></label>';
  h += '<label>Throughput needed (Gbps)<input type="number" id="o-thr" step="0.1" placeholder="' + esc(R.throughputBps == null ? "unknown" : (R.throughputBps / 1e9).toFixed(2)) + '" value="' + esc(ov.throughputBps != null ? ov.throughputBps / 1e9 : "") + '"></label>';
  h += '<label>New sessions/sec needed<input type="number" id="o-cps" placeholder="' + esc(R.cps == null ? "unknown" : R.cps) + '" value="' + esc(ov.cps ?? "") + '"></label>';
  h += '<label>Virtual systems needed<input type="number" id="o-vsys" min="1" placeholder="' + esc(R.vsys) + '" value="' + esc(ov.vsys ?? "") + '"></label>';
  h += '<label class="chk"><input type="checkbox" id="o-tp"' + (R.useThreat ? " checked" : "") + "> Size on Threat Prevention throughput" + (R.threatLicensed ? " (licensed today)" : "") + "</label>";
  h += '<label class="chk"><input type="checkbox" id="o-ha"' + (ST.ha ? " checked" : "") + "> HA pair on the new firewall" + (A.ha.enabled ? " (HA today)" : "") + "</label>";
  h += '<label class="chk"><input type="checkbox" id="o-rug"' + (o.includeRugged ? " checked" : "") + "> Include ruggedized models</label>";
  h += '<label class="chk"><input type="checkbox" id="o-cell"' + (o.includeCellular ? " checked" : "") + "> Include 5G models</label>";
  h += "</div>";
  h += '<p class="muted">Leave a box empty to use the measured value + headroom. Measured: ' + esc(R.observed.sessions != null ? U.fmtNum(R.observed.sessions) + " sessions (" + R.observed.sessionsSource + ")" : "sessions not in file") + " · " + esc(R.observed.kbps != null ? U.fmtBps(R.observed.kbps * 1000) + " (" + R.observed.kbpsSource + ")" : "throughput not in file") + " · " + esc(R.observed.cps != null ? U.fmtNum(R.observed.cps) + " CPS" : "CPS not in file") + ". Ports needed: " + R.ports.length + (R.ha ? " + HA links" : "") + ".</p></div>";
  if (R.lowUsage) h += '<div class="note y"><b>Very low measured load</b> (peak ' + esc(U.fmtNum(R.lowUsage.sessions)) + " sessions" + (R.lowUsage.bps != null ? ", " + esc(U.fmtBps(R.lowUsage.bps)) : "") + (R.lowUsage.days != null ? " over about " + esc(R.lowUsage.days) + " day(s) of samples" : "") + "). The suggestion below is the smallest model that fits the ports, virtual systems and features, not a throughput sizing. A lab, a quiet period or a short sample can look like this. Type the sessions, throughput and connections per second you expect in the boxes above, and keep the vendor's replacement series in mind.</div>";

  h += '<div class="card"><h2>Suggested</h2>';
  if (!rec.top) h += '<div class="note r">No currently sold model fits every requirement. Check the list below for what fell short, adjust the numbers, or pick one manually.</div>';
  h += '<div class="cards3">' + recCard(rec.top, "Smallest model that fits", "best") + recCard(rec.alt, "Next step (different series)", "") + vmCard() + "</div>";
  if (rec.top && rec.smallerRejected.length) {
    h += '<h3>Why not smaller?</h3><ul>' + rec.smallerRejected.map(e => "<li><b>" + esc(e.model) + "</b>: " + esc(e.reasons.join("; ")) + "</li>").join("") + "</ul>";
  }
  h += '<h3>Pick any model</h3><div class="form"><label>Model<select id="o-model"><option value="">— suggested (' + esc(rec.top ? rec.top.model : "none") + ") —</option>";
  const groups = {};
  for (const m of ST.idx.all) {
    if (m.form === "hardware" && !o.showEos && !(m.lifecycle === "current" || m.lifecycle === "end-of-sale-announced")) continue;
    (groups[m.family] = groups[m.family] || []).push(m);
  }
  for (const [fam, ms] of Object.entries(groups)) {
    h += '<optgroup label="' + esc(fam) + '">' + ms.map(m => { const e = rec.evals.concat(rec.vm.evals).find(x => x.model === m.model); return '<option value="' + esc(m.model) + '"' + (ST.targetName === m.model ? " selected" : "") + ">" + esc(m.model + (e ? (e.ok ? " ✓ fits" : " ✗ " + (e.reasons[0] || "")) : (m.lifecycle !== "current" ? " (" + m.lifecycle + ")" : ""))) + "</option>"; }).join("") + "</optgroup>";
  }
  h += '</select></label><label class="chk"><input type="checkbox" id="o-eos"' + (o.showEos ? " checked" : "") + "> Show end-of-sale models</label>";
  if (target() && target().form === "vm") h += '<label>VM data interfaces (vNICs)<input type="number" id="o-vmports" min="1" max="24" value="' + esc(o.vmPorts) + '"></label>';
  h += "</div></div>";

  // comparison matrix
  const t = target(), s = srcModel();
  if (t) {
    const e = rec.evals.concat(rec.vm.evals).find(x => x.model === t.model) || PPU.evaluateModel(t, R, A, o);
    const cell = (v, fmt) => v == null ? '<td class="unk">not published</td>' : '<td class="num">' + fmt(v) + "</td>";
    const need = (v, fmt) => v == null ? '<td class="num muted">—</td>' : '<td class="num">' + fmt(v) + "</td>";
    const pcs = m => { if (!m) return "—"; if (m.form === "vm") return "vNICs (hypervisor)"; if (!m.ports) return "card based"; const c = PPU.portCounts(PPU.portList(m)); return [c.copper && c.copper + " copper", c.combo && c.combo + " combo", c.fiber1g && c.fiber1g + "×1G SFP", c.fiber10g && c.fiber10g + "×10G SFP+", c.fiber25g && c.fiber25g + "×25G", c.fiber40g && c.fiber40g + "×40G", c.fiber100g && c.fiber100g + "×100G+"].filter(Boolean).join(", "); };
    h += '<div class="card"><h2>Current vs. proposed</h2><table class="data"><thead><tr><th></th><th class="num">Needed (peak + ' + esc(o.headroomPct) + '%)</th><th class="num">Today: ' + esc(A.system && A.system.model || "?") + '</th><th class="num">Proposed: ' + esc(t.model) + (R.ha ? " ×2" : "") + "</th></tr></thead><tbody>";
    h += "<tr><td>Firewall throughput</td>" + need(!R.useThreat ? R.throughputBps : null, U.fmtBps) + cell(s && s.fw_bps, U.fmtBps) + (R.useThreat ? cell(t.fw_bps, U.fmtBps) : fitCell(e.fits.throughput, U.fmtBps)) + "</tr>";
    h += "<tr><td>Threat Prevention throughput</td>" + need(R.useThreat ? R.throughputBps : null, U.fmtBps) + cell(s && s.tp_bps, U.fmtBps) + (R.useThreat ? fitCell(e.fits.throughput, U.fmtBps) : cell(t.tp_bps, U.fmtBps)) + "</tr>";
    h += "<tr><td>Max sessions</td>" + need(R.sessions, U.fmtNum) + cell(s && s.max_sessions, U.fmtNum) + fitCell(e.fits.sessions, U.fmtNum) + "</tr>";
    h += "<tr><td>New sessions/sec</td>" + need(R.cps, U.fmtNum) + cell(s && s.cps, U.fmtNum) + fitCell(e.fits.cps, U.fmtNum) + "</tr>";
    h += "<tr><td>IPsec VPN throughput</td><td></td>" + cell(s && s.ipsec_bps, U.fmtBps) + cell(t.ipsec_bps, U.fmtBps) + "</tr>";
    h += "<tr><td>Virtual systems (base / max)</td><td class=num>" + R.vsys + "</td><td class=num>" + esc(s ? (s.vsys_base ?? "?") + " / " + (s.vsys_max ?? "?") : "—") + '</td><td class="num ' + (e.reasons.some(r => /virtual systems/.test(r)) ? "short" : "ok") + '">' + esc((t.vsys_base ?? "?") + " / " + (t.vsys_max ?? "?")) + (e.vsysLicense ? " (+" + e.vsysLicense + " license)" : "") + "</td></tr>";
    h += "<tr><td>Data ports</td><td class=num>" + (e.fits.ports ? e.fits.ports.need : R.ports.length) + "</td><td>" + esc(pcs(s)) + '</td><td class="' + (e.fits.ports && e.fits.ports.status === "short" ? "short" : "") + '">' + esc(pcs(t)) + "</td></tr>";
    h += "<tr><td>Dedicated HA ports</td><td>" + (R.ha ? "HA needed" : "—") + "</td><td>" + esc(s ? (s.dedicated_ha || []).join(", ") || "none" : "—") + "</td><td>" + esc((t.dedicated_ha || []).join(", ") || (t.form === "vm" ? "none (use data vNICs)" : "none (uses 2 data ports)")) + "</td></tr>";
    h += "<tr><td>PAN-OS</td><td></td><td>" + esc(A.system && A.system.swVersion || "") + (s && s.last_panos ? " (last: " + s.last_panos + ")" : "") + "</td><td>" + esc(t.min_panos ? t.min_panos + " or later" : "not published") + "</td></tr>";
    h += "<tr><td>End of sale / life</td><td></td><td>" + esc(s ? (s.eos_date || "—") + " / " + (s.eol_date || "—") : "—") + "</td><td>" + esc((t.eos_date || "not announced") + (t.eol_date ? " / " + t.eol_date : "")) + "</td></tr>";
    h += "</tbody></table>";
    if (!e.ok) h += '<div class="note r"><b>' + esc(t.model) + " falls short:</b> " + esc(e.reasons.join("; ")) + "</div>";
    for (const w of e.warnings) h += '<div class="note y">' + esc(w) + "</div>";
    if (A.config && A.config.panorama) h += '<div class="note"><b>Panorama rule:</b> Panorama must run the same or a higher PAN-OS version than the new firewall' + (t.min_panos ? " (at least " + esc(U.majorMinor(t.min_panos)) + " for " + esc(t.model) + ")" : "") + ". Upgrade Panorama first.</div>";
    if (t.vsys_note) h += '<div class="note">' + esc(t.vsys_note) + "</div>";
    if (t.note) h += '<div class="note">' + esc(t.note) + "</div>";
    if (t.form === "hardware" && !t.ports_verified) h += '<p class="muted">Port numbering for ' + esc(t.model) + " is assumed in datasheet order (ethernet1/1 = first group listed). Check the hardware reference guide; you can edit the port list on step 4.</p>";
    h += '<p class="src">Sources: ' + srcRef(t) + "</p></div>";
  }
  $("#tab-target").innerHTML = h;
  const num = (id, key, scale) => { const el = $(id); if (!el) return; el.onchange = () => { const v = el.value.trim(); if (v === "") delete ST.overrides[key]; else ST.overrides[key] = parseFloat(v) * (scale || 1); refreshAll(); }; };
  $("#o-head").onchange = e => { ST.opts.headroomPct = Math.max(0, parseFloat(e.target.value) || 0); refreshAll(); };
  num("#o-sess", "sessions"); num("#o-thr", "throughputBps", 1e9); num("#o-cps", "cps"); num("#o-vsys", "vsys");
  $("#o-tp").onchange = e => { ST.overrides.useThreat = e.target.checked; refreshAll(); };
  $("#o-ha").onchange = e => { ST.ha = e.target.checked; refreshAll(); };
  $("#o-rug").onchange = e => { ST.opts.includeRugged = e.target.checked; refreshAll(); };
  $("#o-cell").onchange = e => { ST.opts.includeCellular = e.target.checked; refreshAll(); };
  $("#o-eos").onchange = e => { ST.opts.showEos = e.target.checked; renderTarget(); };
  $("#o-model").onchange = e => { pickTarget(e.target.value || null); };
  const vp = $("#o-vmports"); if (vp) vp.onchange = e => { ST.opts.vmPorts = Math.max(1, Math.min(24, parseInt(e.target.value) || 8)); ST.map = {}; refreshAll(); };
  for (const b of $$("#tab-target .pick")) b.onclick = () => pickTarget(b.dataset.m);
}
function vmCard() {
  const v = ST.rec.vm;
  let h = '<div class="rec"><div class="muted">Go virtual</div>';
  if (!v.fit) return h + "<h3>VM-Series</h3><p>No fixed VM size meets the measured load. Use a flexible vCPU license sized with Palo Alto.</p></div>";
  const m = v.fit.m;
  const sel = target() && target().model === m.model;
  h += "<h3>" + esc(m.model) + (ST.R.ha ? " ×2 (HA)" : "") + "</h3><ul>";
  h += "<li>" + esc(v.vcpu) + " vCPU · " + esc(m.mem_gb) + " GB RAM minimum" + (v.multiVsys ? " (16 vCPU for multi-vsys)" : "") + "</li>";
  h += "<li>" + U.fmtNum(m.max_sessions) + " sessions · App-ID up to " + U.fmtBps(m.fw_bps) + " (legacy datasheet)</li>";
  if (v.flex) h += "<li>Flexible license: " + esc(v.flex.memGb) + " GB memory tier covers " + U.fmtNum(v.flex.maxSessions) + " sessions (PAN-OS 11.2+)</li>";
  h += '<li class="why">Throughput depends on the host. Validate on your hardware.</li>';
  h += '</ul><div class="actions"><button type="button" class="primary pick" data-m="' + esc(m.model) + '">' + (sel ? "✓ Selected" : "Use this") + "</button></div></div>";
  return h;
}
function pickTarget(name) {
  ST.targetName = name; ST.map = {}; ST.haPortMap = {}; ST.conv = null; ST.customPorts = null; ST.hw = { qty: {}, type: {}, opSpeed: {}, psuPerUnit: null };
  refreshAll();
}

/* ---------------- 3. hardware & cabling ---------------- */
function hwPlan() {
  const t = target(); if (!t) return null;
  return PPU.hardwarePlan(ST.A, t, ST.R, { map: ST.map, haPortMap: ST.haPortMap, srcModel: srcModel(), targetPorts: targetPorts(), edits: ST.hw });
}
const USE_LABEL = { data: "Data ports", ha: "HA links" };
function renderHardware() {
  const A = ST.A, t = target(), el = $("#tab-hardware");
  if (!t) { el.innerHTML = '<div class="card"><p class="nf">Pick a target on step 2 first.</p></div>'; return; }
  const hp = hwPlan(), P = hp.power, U2 = hp.units;
  let h = '<div class="card"><h2>Power supplies and power cords</h2>';
  if (hp.vm) h += '<p>VM-Series has no power supplies or cords.</p>';
  else {
    const src = P.src;
    const srcTxt = src.virtual ? "Virtual machine: no power supplies" : A.power ? A.power.count + " power supply(ies) seen in the tech-support file" + (A.power.failed ? " (" + A.power.failed + " with an alarm)" : "") + " <span class='pill g'>from file</span>"
      : src.redundant != null ? (src.redundant ? "2 or more (redundant)" : "1") + " <span class='pill y'>from catalog</span> <span class='src'>" + esc(src.basis) + "</span>"
      : '<span class="nf">not in file</span> ' + esc(src.note || "");
    h += '<table class="data"><tbody><tr><th>Old firewall</th><td>' + srcTxt + "</td></tr>";
    h += "<tr><th>" + esc(t.model) + " includes</th><td>" + (P.included != null ? P.included : "?") + " " + (P.tgt && P.tgt.kind === "adapter" ? "power adapter(s)" : "power supply(ies)") + (P.tgt ? " · " + esc(P.tgt.feed || "") + (P.tgt.watts ? " · " + P.tgt.watts + " W" : "") + " · can hold up to " + (P.tgt.max || "?") : ' <span class="nf">not in catalog</span>') + "</td></tr>";
    h += '<tr><th>Needed per firewall</th><td><select id="hw-psu">' + [1, 2, 3, 4].filter(n => !P.tgt || !P.tgt.max || n <= P.tgt.max || n === P.psuPerUnit).map(n => '<option value="' + n + '"' + (n === P.psuPerUnit ? " selected" : "") + ">" + n + "</option>").join("") + "</select> " + (P.optionalPerUnit ? "(" + P.optionalPerUnit + " optional extra per firewall to order)" : "") + "</td></tr>";
    h += "<tr><th>Firewalls</th><td>" + U2 + (U2 === 2 ? " (HA pair)" : "") + "</td></tr>";
    h += "<tr><th>Power cords / feeds to quote</th><td><b>" + (P.cords != null ? P.cords : "?") + "</b> · " + esc(P.cordKind) + "</td></tr>";
    h += "<tr><th>Extra supplies to quote</th><td><b>" + (P.optionalPerUnit != null ? P.optionalPerUnit * U2 : "?") + "</b></td></tr></tbody></table>";
    for (const n of P.notes) h += '<div class="note y">' + esc(n) + "</div>";
    if (P.src.fromTsf == null && P.src.note) h += '<div class="note">' + esc(P.src.note) + "</div>";
    if (P.tgt && P.tgt.sources) h += '<p class="src">Sources: ' + srcRef(P.tgt) + "</p>";
  }
  h += "</div>";

  h += '<div class="card"><h2>Interface speed, port type and media changes</h2>';
  if (!A.config) h += '<p class="nf">This file has no running config, so the list of used ports is not known. Add ports by hand in the BOM below or load a tech-support file.</p>';
  else if (!hp.ports.length) h += '<p class="nf">No ports are mapped yet. Map interfaces on step 5.</p>';
  else {
    const sm = hp.summary;
    h += '<p><span class="pill ' + (sm.speedChanges ? "y" : "g") + '">' + sm.speedChanges + " speed change(s)</span> <span class=\"pill " + (sm.mediaChanges ? "y" : "g") + '">' + sm.mediaChanges + " copper/fiber change(s)</span> <span class=\"pill " + (sm.cageChanges ? "y" : "g") + '">' + sm.cageChanges + " port type change(s)</span> <span class=\"pill\">" + sm.reused + " of " + sm.ports + " can reuse the existing optic/cable</span>" + (PPU.isVmSystem(A.system) ? ' <span class="pill">old ports are virtual: no optics</span>' : sm.srcOpticsDetected != null ? ' <span class="pill g">' + sm.srcOpticsDetected + " optics seen in file</span>" : ' <span class="pill y">optics not listed in file</span>') + "</p>";
    h += '<div class="scroll"><table class="data"><thead><tr><th>Old port</th><th>Old media / speed</th><th>Optic in old firewall</th><th>New port</th><th>Run at</th><th>Needs</th><th>Call-outs</th></tr></thead><tbody>';
    const tpm = new Map(targetPorts().map(p => [p.name, p]));
    for (const r of hp.ports) {
      const choices = PPU.speedChoices(tpm.get(r.tgt) || { media: r.tgtMedia, mbps: r.tgtMax });
      const flagged = r.flags.length;
      h += "<tr" + (flagged ? ' class="unmapped"' : "") + "><td class=mono>" + esc(r.src) + "</td><td>" + esc(r.srcMedia === "unknown" ? "?" : r.srcMedia) + " " + (r.srcMedia === "virtual" ? "NIC" : r.srcSpeed ? esc(U.fmtSpeed(r.srcSpeed)) + (r.srcUp ? "" : "") : '<span class="nf">' + (r.srcUp ? "speed not in file" : "link down") + "</span>") + "</td><td>" + (r.xcvr ? esc(r.xcvr.label + (r.xcvr.wavelength ? ", " + r.xcvr.wavelength : "")) : '<span class="nf">' + (r.srcMedia === "virtual" ? "n/a (virtual)" : hp.vm || !A.xcvr ? "not in file" : "none listed") + "</span>") + "</td><td class=mono>" + esc(r.tgt) + " <span class=muted>(" + esc(r.tgtMedia) + ")</span></td>";
      h += "<td>" + (choices.length > 1 ? '<select class="hw-speed" data-p="' + esc(r.tgt) + '">' + choices.map(c => '<option value="' + c + '"' + (c === r.opSpeed ? " selected" : "") + ">" + esc(U.fmtSpeed(c)) + "</option>").join("") + "</select>" : esc(U.fmtSpeed(r.opSpeed))) + "</td>";
      const need = r.kind === "virtual" ? "vNIC" : r.kind === "optic" ? r.form + " optic" + (r.reuse ? " (reuse existing)" : "") : r.kind === "copper" ? (r.reuse ? "existing cable" : r.form) : "?";
      h += "<td>" + esc(need) + "</td><td>" + (r.flags.concat(r.note).map(x => "<div>" + esc(x) + "</div>").join("") || "✓ no change") + "</td></tr>";
    }
    h += "</tbody></table></div>";
  }
  h += "</div>";

  h += '<div class="card"><h2>Optics and cables to quote</h2>';
  if (hp.vm) h += "<p>No physical optics or cables for VM-Series.</p>";
  else if (!hp.groups.length) h += '<p class="nf">Nothing to buy from the mapped ports.</p>';
  else {
    h += '<p class="muted">Counts include both firewalls of an HA pair. Change the type and quantity to match what the customer will buy; the report uses these numbers. Pick the type (for example SR or LR) once you know the fiber and the other end.</p>';
    h += '<table class="data"><thead><tr><th>Used for</th><th>Item</th><th>Type</th><th class="num">Ports</th><th class="num">Quantity to quote</th></tr></thead><tbody>';
    for (const g of hp.groups) {
      const item = g.kind === "optic" ? (g.reuse ? g.form + " optics already installed" : g.form + " optic" + (g.use === "ha" ? " (2 per HA link)" : "")) : (g.use === "ha" ? "Ethernet cable for HA link" : g.form);
      const typeCell = g.kind === "optic" ? '<select class="hw-type" data-k="' + esc(g.key) + '">' + (g.typeOptions.length ? "" : '<option selected>' + esc(g.type) + "</option>") + (g.reuse ? "" : '<option value="' + esc("Type to be chosen") + '"' + (g.type === "Type to be chosen" ? " selected" : "") + ">Type to be chosen</option>") + g.typeOptions.map(o => '<option value="' + esc(o) + '"' + (o === g.type ? " selected" : "") + ">" + esc(o) + "</option>").join("") + "</select>" : esc(g.type);
      h += "<tr><td>" + USE_LABEL[g.use] + "</td><td>" + esc(item) + "</td><td>" + typeCell + '</td><td class="num">' + g.ports + '</td><td class="num"><input type="number" min="0" class="hw-qty" data-k="' + esc(g.key) + '" value="' + g.qty + '" style="width:80px"></td></tr>';
    }
    h += "</tbody></table>";
  }
  for (const n of hp.notes) h += '<div class="note">' + esc(n) + "</div>";
  h += "</div>";

  h += '<div class="card"><h2>HA cabling</h2>';
  if (!R_HA()) h += "<p>Not an HA pair on the new firewall. Turn on HA in step 2 to see the cables.</p>";
  else if (hp.vm) h += "<p>VM-Series HA: put the HA vNICs of both VMs on the same virtual network. No cables.</p>";
  else if (!hp.ha.length) h += '<p class="nf">No HA ports were found in the old config' + ((t.dedicated_ha || []).length ? ". " + esc(t.model) + " has dedicated ports: " + esc(t.dedicated_ha.join(", ")) + "." : ". " + esc(t.model) + " has no dedicated HA ports, so HA uses data ports.") + "</p>";
  else {
    h += '<table class="data"><thead><tr><th>Link</th><th>Old port</th><th>New port</th><th>What to connect</th><th>Call-outs</th></tr></thead><tbody>';
    for (const r of hp.ha) h += "<tr><td>" + esc(r.label) + "</td><td>" + esc(r.srcDesc) + "</td><td>" + esc(r.tgtDesc || "not chosen") + "</td><td>" + esc(r.cableText || "") + "</td><td>" + (r.flags.map(x => "<div>" + esc(x) + "</div>").join("") || "✓ no change") + "</td></tr>";
    h += "</tbody></table>";
  }
  h += '<p class="muted">Plain Ethernet is fine when the dedicated HA port is RJ45 (HA1 on most models). SFP+/QSFP HSCI and HA ports need optics or a DAC cable on both firewalls. Models without dedicated HA ports use two data ports.</p></div>';
  el.innerHTML = h;
  const re = () => { renderHardware(); if (!$("#tab-report").hidden) renderReport(); };
  const psu = $("#hw-psu"); if (psu) psu.onchange = e => { ST.hw.psuPerUnit = +e.target.value; re(); };
  for (const x of $$(".hw-speed")) x.onchange = () => { ST.hw.opSpeed[x.dataset.p] = +x.value; re(); };
  for (const x of $$(".hw-type")) x.onchange = () => { ST.hw.type[x.dataset.k] = x.value; };
  for (const x of $$(".hw-qty")) x.oninput = () => { ST.hw.qty[x.dataset.k] = Math.max(0, parseInt(x.value) || 0); };
}
function R_HA() { return !!(ST.R && ST.R.ha); }

/* ---------------- 4. licenses (review) ---------------- */
const USE_PILL = { "in-use": ["g", "Config uses it"], "not-seen": ["y", "Not seen in config"], unknown: ["", "Can't tell from config"] };
function licReview() { const t = target(); return t ? PPU.licenseReview(ST.A, t, ST.R, ST.lic) : null; }
function renderLic() {
  const A = ST.A, t = target(), el = $("#tab-lic");
  if (!t) { el.innerHTML = '<div class="card"><p class="nf">Pick a target on step 2 first.</p></div>'; return; }
  const LR = licReview(), LP = LR.plan;
  let h = '<div class="card"><h2>1. Review what you have today</h2><p class="muted">Each license found in the tech-support file. Keep or drop each one for the new firewall. The note in the last column comes from the config and is only a hint: a service can be used in ways the config does not show.</p>';
  if (!LR.current.length) h += '<p class="nf">No license output in this file (request license info).</p>';
  else {
    h += '<table class="data"><thead><tr><th>License</th><th>Expires</th><th>Status</th><th>What the config shows</th><th>New firewall</th><th class="num">Qty</th></tr></thead><tbody>';
    for (const r of LR.current) {
      const up = USE_PILL[r.use];
      const ctl = r.special === "vsys" ? '<span class="muted">see Virtual Systems below</span>' : '<select class="lic-keep" data-n="' + esc(r.name) + '"><option value="1"' + (r.keep ? " selected" : "") + ">Keep</option><option value=\"0\"" + (!r.keep ? " selected" : "") + ">Drop</option></select>";
      h += "<tr" + (r.expired ? ' class="warn"' : "") + "><td><b>" + esc(r.name) + '</b><div class="src">' + esc(r.feature) + "</div></td><td>" + esc(r.expires) + "</td><td>" + (r.expired ? "Expired" : "Active") + '</td><td><span class="pill ' + up[0] + '">' + up[1] + '</span><div class="src">' + esc(r.hint) + "</div></td><td>" + ctl + '</td><td class="num">' + (r.special ? "" : '<input type="number" min="0" class="lic-qty" data-k="cur:' + esc(r.name) + '" value="' + r.qty + '" style="width:70px">') + "</td></tr>";
    }
    h += "</tbody></table><p class=muted>Auth codes and license serials are not shown or exported.</p>";
  }
  h += "</div>";
  h += '<div class="card"><h2>2. Add or change</h2><p class="muted">Subscriptions currently sold for ' + esc(t.model) + ". Tick any the customer wants. Nothing here is recommended or added by default.</p>";
  h += '<table class="data"><thead><tr><th>Add</th><th>Subscription</th><th>Note</th><th class="num">Qty</th></tr></thead><tbody>';
  for (const o of LR.offers) {
    h += "<tr><td>" + (o.held ? "<span class=muted>have it</span>" : '<input type="checkbox" class="lic-add" data-n="' + esc(o.name) + '"' + (o.on ? " checked" : "") + ">") + "</td><td>" + esc(o.name) + "</td><td>" + esc(o.held ? "Already licensed and active today" : o.note || "") + '</td><td class="num">' + (o.held ? "" : '<input type="number" min="0" class="lic-qty" data-k="add:' + esc(o.name) + '" value="' + o.qty + '" style="width:70px">') + "</td></tr>";
  }
  h += '<tr><td><input type="checkbox" id="lic-sup"' + (LR.support.on ? " checked" : "") + '></td><td>Support (change or add tier)</td><td><select id="lic-tier"><option value="">Tier to be chosen</option>' + LR.support.options.map(x => '<option' + (x === LR.support.tier ? " selected" : "") + ">" + esc(x) + "</option>").join("") + '</select></td><td class="num"><input type="number" min="0" class="lic-qty" data-k="add:Support" value="' + LR.support.qty + '" style="width:70px"></td></tr>';
  h += '<tr><td></td><td>Additional Virtual Systems</td><td>' + esc(LR.vsys.note || (LP.vsys ? LP.vsys.note : "")) + '</td><td class="num"><input type="number" min="0" id="lic-vsys" value="' + LR.vsys.extra + '" style="width:70px"></td></tr>';
  h += "</tbody></table></div>";
  h += '<div class="card"><h2>3. List for the quote</h2><table class="data"><thead><tr><th>Item</th><th class="num">Qty</th><th>Source</th></tr></thead><tbody>';
  h += "<tr><td><b>" + esc(t.form === "vm" ? t.model + " (Software NGFW credits: " + (ST.rec.vm.vcpu || "?") + " vCPU)" : t.model + " hardware") + '</b></td><td class="num">' + LR.units + "</td><td>" + (ST.R.ha ? "HA pair" : "Standalone") + "</td></tr>";
  for (const f2 of LR.finalItems) h += "<tr><td>" + esc(f2.name) + '</td><td class="num">' + f2.qty + "</td><td>" + esc(f2.source === "carry" ? "kept (" + f2.note + ")" : f2.source === "required" ? "required: " + f2.note : f2.note) + "</td></tr>";
  h += "</tbody></table>";
  if (LR.dropped.length) h += '<div class="note y"><b>Not included:</b> ' + LR.dropped.map(d => esc(d.name) + (d.expired ? " (expired)" : " (dropped by you)")).join(", ") + ".</div>";
  for (const n of LP.notes) h += '<div class="note">' + esc(n) + "</div>";
  h += '<p class="muted">No prices are shown; get them from your reseller or Palo Alto. This page only records the choices you make.</p></div>';
  el.innerHTML = h;
  const re = () => { renderLic(); if (!$("#tab-report").hidden) renderReport(); };
  for (const x of $$(".lic-keep")) x.onchange = () => { ST.lic.keep[x.dataset.n] = x.value === "1"; re(); };
  for (const x of $$(".lic-add")) x.onchange = () => { ST.lic.add[x.dataset.n] = x.checked; re(); };
  for (const x of $$(".lic-qty")) x.onchange = () => { ST.lic.qty[x.dataset.k] = Math.max(0, parseInt(x.value) || 0); re(); };
  $("#lic-sup").onchange = e => { ST.lic.supportOn = e.target.checked; re(); };
  $("#lic-tier").onchange = e => { ST.lic.supportTier = e.target.value; if (e.target.value) ST.lic.supportOn = true; re(); };
  $("#lic-vsys").onchange = e => { ST.lic.vsysExtra = Math.max(0, parseInt(e.target.value) || 0); re(); };
}

/* ---------------- 4. convert ---------------- */
function ensureMap() {
  const A = ST.A, t = target();
  if (!A.config || !t) return;
  const srcIfs = PPU.sourceInterfaces(A);
  const missing = srcIfs.some(s => !(s.name in ST.map));
  if (missing) {
    const am = PPU.autoMap(srcIfs, targetPorts());
    for (const s of srcIfs) if (!(s.name in ST.map)) { ST.map[s.name] = am.map[s.name] || ""; ST.mapNotes[s.name] = am.notes[s.name] || ""; }
  }
  // HA dedicated ports
  const ded = new Set(t.dedicated_ha || []);
  for (const [link, port] of Object.entries(A.ha.ports || {})) {
    if (!port || /^ethernet/.test(port)) continue;
    if (!(port in ST.haPortMap)) {
      if (ded.has(port)) ST.haPortMap[port] = port;
      else {
        // suggest a free copper data port (set to type HA on conversion)
        const taken = new Set(Object.values(ST.map).concat(Object.values(ST.haPortMap)).filter(Boolean));
        const free = targetPorts().filter(p => !taken.has(p.name));
        const pick = free.find(p => /rj45|mgig|virtual/.test(p.media)) || free[0];
        ST.haPortMap[port] = pick ? pick.name : "";
      }
    }
  }
}
function renderConvert() {
  const A = ST.A, t = target();
  let h = "";
  if (!A.config) { $("#tab-convert").innerHTML = '<div class="card"><p class="nf">No running-config.xml in this file, so there is nothing to convert.</p></div>'; return; }
  if (!t) { $("#tab-convert").innerHTML = '<div class="card"><p class="nf">Pick a target on step 2 first.</p></div>'; return; }
  const ports = targetPorts();
  const srcIfs = PPU.sourceInterfaces(A);
  const used = {};
  for (const [s, v] of Object.entries(ST.map)) if (v) (used[v] = used[v] || []).push(s);
  h += '<div class="card"><h2>Map interfaces: ' + esc(A.system && A.system.model || "source") + " → " + esc(t.model) + "</h2>";
  h += '<p class="muted">Each configured interface on the old firewall needs a port on the new one. Subinterfaces, zones, routes, NAT, PBF, VPN, GlobalProtect, DHCP, DNS proxy, QoS, HA and service routes follow automatically. Choose “don\'t migrate” to leave an interface out (references to it are removed or flagged).</p>';
  h += '<div class="actions"><button type="button" id="b-auto">↻ Auto-map again</button><button type="button" id="b-ident">Keep the same names</button>' + (t.form === "hardware" && !t.ports_verified ? '<span class="muted">Port numbering is assumed from the datasheet. Edit it below if your hardware differs.</span>' : "") + "</div>";
  h += '<div class="scroll"><table class="data"><thead><tr><th>Old interface</th><th>Mode / zones</th><th>Subinterfaces</th><th>Old media</th><th>New port</th><th>Check</th></tr></thead><tbody>';
  for (const s of srcIfs) {
    const v = ST.map[s.name] || "";
    const tp = ports.find(p => p.name === v);
    const fit = tp ? PPU.portFit(s, tp) : null;
    const dup = v && used[v] && used[v].length > 1;
    const msg = !v ? "not migrated" : dup ? "⚠ used twice" : fit && !fit.ok ? "⚠ " + fit.warn : fit && fit.warn ? "⚠ " + fit.warn : "✓";
    h += "<tr" + (!v || dup || (fit && !fit.ok) ? ' class="unmapped"' : "") + "><td class=mono>" + esc(s.name) + "</td><td>" + esc((s.mode === "aggregate-group" ? "member of " + s.aggregateGroup : s.mode) + (s.zones.length ? " · " + s.zones.join(", ") : "")) + "</td><td class=mono>" + esc(s.units.join(", ")) + "</td><td>" + esc(s.media === "unknown" ? "?" : s.media) + " " + esc(U.fmtSpeed(s.mbps)) + '</td><td><select class="mapsel" data-s="' + esc(s.name) + '"><option value="">— don\'t migrate —</option>' +
      ports.map(p => '<option value="' + esc(p.name) + '"' + (p.name === v ? " selected" : "") + ">" + esc(p.name + " · " + (p.media === "virtual" ? "vNIC" : p.media + " " + U.fmtSpeed(p.mbps)) + (p.poe ? " PoE" : "") + (used[p.name] && p.name !== v ? " (used)" : "")) + "</option>").join("") + "</select></td><td>" + esc(msg) + "</td></tr>";
  }
  h += "</tbody></table></div>";
  // HA links
  const haPorts = Object.entries(A.ha.ports || {}).filter(([k, v]) => v);
  if (haPorts.length && ST.ha) {
    h += '<h3>HA links</h3><table class="data"><thead><tr><th>Link</th><th>Old port</th><th>New port</th></tr></thead><tbody>';
    for (const [link, port] of haPorts) {
      if (/^ethernet/.test(port)) { h += "<tr><td>" + esc(link) + "</td><td class=mono>" + esc(port) + "</td><td class=muted>follows the interface map (" + esc(ST.map[port] || "not migrated") + ")</td></tr>"; continue; }
      const opts = (t.dedicated_ha || []).map(p => ({ name: p, label: p + " (dedicated)" })).concat(ports.map(p => ({ name: p.name, label: p.name + " (data port, set to type HA)" + (Object.values(ST.map).includes(p.name) ? " (used)" : "") })));
      h += "<tr><td>" + esc(link) + "</td><td class=mono>" + esc(port) + '</td><td><select class="hasel" data-p="' + esc(port) + '"><option value="">— pick a port —</option>' + opts.map(o => '<option value="' + esc(o.name) + '"' + (ST.haPortMap[port] === o.name ? " selected" : "") + ">" + esc(o.label) + "</option>").join("") + "</select></td></tr>";
    }
    h += "</tbody></table>";
  }
  h += '<details class="box"><summary>Edit the target port list (advanced)</summary><p class="muted">One port per line: <span class="mono">name media speedMbps</span>, e.g. <span class="mono">ethernet1/9 sfp+ 10000</span>. Media: rj45, mgig, combo, sfp, sfp+, sfp28, qsfp+, qsfp28, qsfp-dd, virtual.</p><textarea id="portsedit" rows="8" style="width:100%" class="mono">' + esc(ports.map(p => p.name + " " + p.media + " " + (p.mbps || "")).join("\n")) + '</textarea><div class="actions"><button type="button" id="b-ports">Apply port list</button><button type="button" id="b-ports-reset">Reset to catalog</button></div></details>';
  h += "</div>";

  // options
  const c = A.config, co = ST.custom, cm = ST.convMode;
  h += '<div class="card"><h2>How should the config be converted?</h2>';
  const rc = ST.realConfig && ST.realConfig.A === A ? ST.realConfig : null;
  if (A.masked && A.masked.count && !rc) h += '<div class="note r"><b>The config in this tech-support file has masked secrets</b> (' + esc(A.masked.count) + " × ********: " + esc(Object.keys(A.masked.fields).join(", ")) + "). PAN-OS itself refuses to validate or commit such a file (lab-confirmed on 11.1: “This config has been sanitized of password data … Please use a non-sanitized config”), and private keys, pre-shared keys, server secrets" + (A.masked.admins.length ? " and the local admin passwords (" + esc(A.masked.admins.join(", ")) + ")" : "") + " are placeholders. Load a config exported from the firewall below to convert that instead.</div>";
  if (A.configIsMerged) h += '<div class="note">This firewall is managed by Panorama. The interface list above comes from the merged config; the conversion below changes only the <b>local</b> config in the file. Apply the same mapping to the Panorama template.</div>';
  h += '<div class="form"><label>Real exported config (optional) <input type="file" id="c-real" accept=".xml,text/xml"></label></div>';
  h += rc ? '<div class="note g">Converting <b>' + esc(rc.name) + "</b> (" + esc(U.fmtNum(rc.size)) + " bytes) instead of the tech-support copy. It stays in this browser tab and is never saved in the plan file. " + (rc.extraIfs.length ? "It has interface(s) the tech-support file did not show: " + esc(rc.extraIfs.join(", ")) + " (map them above after re-analysis, or they are removed)." : "Its interfaces match the mapping above.") + ' <button type="button" id="c-real-x">Use the tech-support copy again</button></div>' : '<p class="muted">Export from the firewall: Device &gt; Setup &gt; Operations &gt; Export named configuration snapshot (running-config.xml). Nothing is uploaded.</p>';
  h += '<div class="modes"><label class="mode' + (cm === "exact" ? " on" : "") + '"><input type="radio" name="cmode" value="exact"' + (cm === "exact" ? " checked" : "") + '> <b>100% conversion</b><span>Exact copy. The only change is the interface mapping above (and what the new hardware requires). Management IP, hostname, admins and everything else stay as they are.</span></label>';
  h += '<label class="mode' + (cm === "custom" ? " on" : "") + '"><input type="radio" name="cmode" value="custom"' + (cm === "custom" ? " checked" : "") + '> <b>Customized</b><span>Change the management address, DNS and hostname so the new firewall can run next to production, and add a break-glass admin.</span></label></div>';
  h += '<div class="form"><label class="chk"><input type="checkbox" id="c-ha"' + (ST.ha ? " checked" : "") + "> Keep HA settings (HA pair)</label></div>";
  if (cm === "custom") {
    h += '<h3>Management and device settings</h3><div class="form">';
    h += '<label>Hostname<input type="text" id="c-host" placeholder="' + esc(c.mgmt.hostname) + '" value="' + esc(co.host) + '" autocomplete="off"></label>';
    h += '<label>Management IP<input type="text" id="c-ip" placeholder="' + esc(c.mgmt.ip || "unchanged") + '" value="' + esc(co.ip) + '" autocomplete="off"></label>';
    h += '<label>Netmask<input type="text" id="c-mask" placeholder="' + esc(c.mgmt.netmask || "unchanged") + '" value="' + esc(co.mask) + '" autocomplete="off"></label>';
    h += '<label>Default gateway<input type="text" id="c-gw" placeholder="' + esc(c.mgmt.gateway || "unchanged") + '" value="' + esc(co.gw) + '" autocomplete="off"></label>';
    h += '<label>Primary DNS<input type="text" id="c-dns1" placeholder="' + esc(c.mgmt.dns && c.mgmt.dns.primary || "unchanged") + '" value="' + esc(co.dns1) + '" autocomplete="off"></label>';
    h += '<label>Secondary DNS<input type="text" id="c-dns2" placeholder="' + esc(c.mgmt.dns && c.mgmt.dns.secondary || "unchanged") + '" value="' + esc(co.dns2) + '" autocomplete="off"></label>';
    if (c.mgmt.ipv6 || co.ipv6) {
      h += '<label>Management IPv6 (address/prefix)<input type="text" id="c-ip6" placeholder="' + esc(c.mgmt.ipv6 || "unchanged") + '" value="' + esc(co.ipv6) + '" autocomplete="off"></label>';
      h += '<label>IPv6 default gateway<input type="text" id="c-ip6gw" placeholder="' + esc(c.mgmt.ipv6Gateway || "unchanged") + '" value="' + esc(co.ipv6gw) + '" autocomplete="off"></label>';
    }
    if (c.panorama) h += '<label class="chk"><input type="checkbox" id="c-pano"' + (co.removePanorama ? " checked" : "") + "> Standalone (remove Panorama settings)</label>";
    h += '</div><p class="muted">Leave a field empty to keep the old value. Changing the management IP lets the new firewall sit on the network next to production. You will see warnings if the old address is used elsewhere in the config.</p>';
    h += '<h3>Break-glass local admin</h3><div class="note">A local account with its own password stored on the firewall. If TACACS+, LDAP or RADIUS login stops working after the commit (wrong server address, unreachable from the new IP, expired secret), this is the way back in. It uses no authentication profile, so external servers are not involved.</div>';
    h += '<div class="form"><label class="chk"><input type="checkbox" id="c-adm"' + (co.adminOn ? " checked" : "") + "> Add a local admin</label></div>";
    if (co.adminOn) {
      h += '<div class="form"><label>User name<input type="text" id="c-an" value="' + esc(co.adminName) + '" autocomplete="off" placeholder="e.g. breakglass"></label>';
      h += '<label>Role<select id="c-ar"><option value="superuser"' + (co.adminRole === "superuser" ? " selected" : "") + '>Superuser (full access)</option><option value="superreader"' + (co.adminRole === "superreader" ? " selected" : "") + '>Superuser (read only)</option></select></label>';
      h += '<label>Password<input type="password" id="c-ap" autocomplete="new-password" placeholder="at least 12 characters"></label>';
      h += '<label>Repeat password<input type="password" id="c-ap2" autocomplete="new-password"></label></div>';
      h += '<p class="muted">The password is turned into a salted SHA-256 hash in this browser tab (nothing is uploaded). Only the hash goes into the downloaded config. The password and the hash are never saved by this tool, never shown in the change log, and cleared from the page after you convert. Write the password down in your password manager first.</p>';
      const auth = c.auth;
      if (auth && (auth.deviceProfile || auth.profiles.some(p => p.method && p.method !== "local-database") || auth.sequences.length)) {
        h += '<div class="note y"><b>This config uses external admin login' + (auth.deviceProfile ? ' (device authentication profile "' + esc(auth.deviceProfile) + '")' : "") + ".</b> Profiles: " + esc(auth.profiles.map(p => p.name + " (" + (p.method || "?") + ")").join(", ") || "none") + (auth.sequences.length ? ". Sequences: " + esc(auth.sequences.map(q => q.name).join(", ")) : "") + ". The break-glass account is local, so it is not blocked by these. After the commit, test the external login <i>and</i> the break-glass login.</div>";
      }
    }
  }
  h += '<div class="actions"><button type="button" class="primary" id="b-conv">⚙️ Convert config</button></div><div id="convout"></div></div>';
  $("#tab-convert").innerHTML = h;

  for (const sel of $$(".mapsel")) sel.onchange = () => { ST.map[sel.dataset.s] = sel.value; ST.conv = null; renderConvert(); };
  for (const sel of $$(".hasel")) sel.onchange = () => { ST.haPortMap[sel.dataset.p] = sel.value; ST.conv = null; };
  $("#b-auto").onclick = () => { ST.map = {}; ensureMap(); renderConvert(); };
  $("#b-ident").onclick = () => { const names = new Set(ports.map(p => p.name)); for (const s of srcIfs) ST.map[s.name] = names.has(s.name) ? s.name : ""; renderConvert(); };
  $("#b-ports").onclick = () => {
    const list = $("#portsedit").value.split("\n").map(l => l.trim().split(/\s+/)).filter(a => a[0]).map(a => ({ name: a[0], media: a[1] || "rj45", mbps: parseInt(a[2]) || null }));
    ST.customPorts = { model: t.model, ports: list }; ST.map = {}; ensureMap(); renderConvert();
  };
  $("#b-ports-reset").onclick = () => { ST.customPorts = null; ST.map = {}; ensureMap(); renderConvert(); };
  for (const r of $$('input[name="cmode"]')) r.onchange = () => { ST.convMode = r.value; ST.conv = null; renderConvert(); };
  const bind = (id, key) => { const el = $(id); if (el) el.oninput = () => { ST.custom[key] = el.value.trim(); }; };
  bind("#c-host", "host"); bind("#c-ip", "ip"); bind("#c-mask", "mask"); bind("#c-gw", "gw"); bind("#c-dns1", "dns1"); bind("#c-dns2", "dns2"); bind("#c-ip6", "ipv6"); bind("#c-ip6gw", "ipv6gw"); bind("#c-an", "adminName");
  $("#c-ha").onchange = e => { ST.ha = e.target.checked; refreshAll(); };
  const pn = $("#c-pano"); if (pn) pn.onchange = e => { ST.custom.removePanorama = e.target.checked; };
  const ad = $("#c-adm"); if (ad) ad.onchange = e => { ST.custom.adminOn = e.target.checked; renderConvert(); };
  const ar = $("#c-ar"); if (ar) ar.onchange = e => { ST.custom.adminRole = e.target.value; };
  $("#b-conv").onclick = doConvert;
  $("#c-real").onchange = async e => {
    const f = e.target.files[0]; if (!f) return;
    try {
      const text = await f.text();
      const doc = XML.parse(text);
      if (!doc.documentElement || doc.documentElement.nodeName !== "config") throw new Error("This is not a PAN-OS config (the root element is not <config>).");
      const sum = PPU.summarizeConfig(doc);
      const mk = PPU.maskedSummary(doc);
      if (mk.count) throw new Error("This file also has " + mk.count + " masked (********) value(s). It came from a tech-support file, or from an export taken by an account that cannot see secrets (an API export by a limited admin role is masked the same way). Export it as a full superuser.");
      const have = new Set(PPU.sourceInterfaces(A).map(x => x.name));
      const extra = sum.interfaces.map(x => x.name).filter(n => /^(ethernet|ae)/.test(n) && !have.has(n));
      ST.realConfig = { A, text, name: f.name, size: text.length, extraIfs: extra }; ST.conv = null; renderConvert();
    } catch (err) { ST.conv = { error: "Could not use that file: " + err.message }; renderConvOut(); }
  };
  const rx = $("#c-real-x"); if (rx) rx.onclick = () => { ST.realConfig = null; ST.conv = null; renderConvert(); };
  if (ST.conv) renderConvOut();
}
function doConvert() {
  const t = target(), co = ST.custom, custom = ST.convMode === "custom";
  try {
    const plan = { map: ST.map, haPortMap: ST.ha ? ST.haPortMap : {}, target: t, targetPorts: targetPorts(), ha: !!ST.ha, mode: ST.convMode };
    if (custom) {
      plan.custom = { hostname: co.host || null, mgmt: { ip: co.ip, netmask: co.mask, gateway: co.gw, ipv6: co.ipv6, ipv6Gateway: co.ipv6gw }, dns: { primary: co.dns1, secondary: co.dns2 } };
      plan.removePanorama = !!co.removePanorama;
      if (co.adminOn) {
        const pw = $("#c-ap") ? $("#c-ap").value : "", pw2 = $("#c-ap2") ? $("#c-ap2").value : "";
        if (!co.adminName) throw new Error("Enter a user name for the break-glass admin, or untick it.");
        if (pw.length < 12) throw new Error("The break-glass password must be at least 12 characters.");
        if (pw !== pw2) throw new Error("The two passwords do not match.");
        plan.custom.admin = { name: co.adminName, role: co.adminRole, phash: PPU.sha256crypt(pw, PPU.randomSalt(16)) };
        if ($("#c-ap")) $("#c-ap").value = ""; if ($("#c-ap2")) $("#c-ap2").value = "";
      }
    }
    ST.conv = PPU.convertConfig(ST.realConfig && ST.realConfig.A === ST.A ? ST.realConfig.text : ST.A.configText, XML, plan);
    ST.conv.error = null;
  } catch (e) { ST.conv = { error: e.message }; }
  renderConvOut();
}
function download(name, text, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: type || "text/plain" }));
  a.download = name; document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}
function outName(ext) {
  const t = target();
  const host = ((ST.convMode === "custom" && ST.custom.host) || (ST.A.config && ST.A.config.mgmt.hostname) || "firewall").replace(/[^\w.-]+/g, "_");
  return host + "_" + (t ? t.model : "target") + ext;
}
function renderConvOut() {
  const r = ST.conv, el = $("#convout"); if (!el || !r) return;
  if (r.error) { el.innerHTML = '<div class="note r"><b>Cannot convert:</b> ' + esc(r.error) + "</div>"; return; }
  const kinds = {}; for (const l of r.log) kinds[l.kind] = (kinds[l.kind] || 0) + 1;
  let h = '<div class="status ' + (r.unresolved.length ? "s-y" : "s-g") + '">' + (r.unresolved.length ? "⚠️ Converted with " + r.unresolved.length + " item(s) to fix" : "✓ Converted. No unresolved references") +
    '<span class="pills">' + Object.entries(kinds).map(([k, n]) => '<span class="pill">' + esc(n + " " + k) + "</span>").join("") + "</span></div>";
  h += '<div class="actions"><button type="button" class="primary" id="b-dlxml">⬇️ Download config XML</button><button type="button" id="b-dlcsv">⬇️ Download change log (CSV)</button></div>';
  if (r.unresolved.length) h += '<h3>Fix before you commit</h3><table class="data"><thead><tr><th>Where</th><th>Value</th><th>What to do</th></tr></thead><tbody>' + r.unresolved.map(u => '<tr class="drop"><td class=mono>' + esc(u.xpath) + "</td><td class=mono>" + esc(u.value) + "</td><td>" + esc(u.why) + "</td></tr>").join("") + "</tbody></table>";
  for (const w of r.warnings) h += '<div class="note y">' + esc(w) + "</div>";
  if (r.secrets && r.secrets.length) h += '<details class="box"><summary>Encrypted values to check (' + r.secrets.length + ")</summary><ul>" + r.secrets.map(x => "<li class=mono>" + esc(x.xpath) + "</li>").join("") + "</ul></details>";
  for (const i of r.info) h += '<div class="note">' + esc(i) + "</div>";
  h += '<details class="box"><summary>How to load this on the new firewall</summary><ol><li>Install the target PAN-OS version first (same as or newer than the old firewall; see step 2).</li><li>Device &gt; Setup &gt; Operations &gt; <b>Import named configuration snapshot</b>: pick the downloaded XML.</li><li><b>Load named configuration snapshot</b>: choose the file. This only changes the candidate config.</li><li>Commit &gt; <b>Validate commit</b> (or CLI <span class="mono">validate full</span>). Fix anything it reports.</li><li>Check licenses, certificates and the HA peer, then commit. Panorama-managed: add the serial in Panorama and push the template stack and device group.</li></ol></details>';
  h += '<details class="box" open><summary>Change log (' + r.log.length + " changes)</summary>" + '<input type="search" id="logq" placeholder="Filter…" style="margin:8px 0;width:100%"><div class="scroll"><table class="data" id="logtbl"><thead><tr><th>Kind</th><th>XPath</th><th>From</th><th>To</th><th>Note</th></tr></thead><tbody>' +
    r.log.map(l => "<tr><td>" + esc(l.kind) + "</td><td class=mono>" + esc(l.xpath) + "</td><td class=mono>" + esc(l.from) + "</td><td class=mono>" + esc(l.to) + "</td><td>" + esc(l.note) + "</td></tr>").join("") + "</tbody></table></div></details>";
  el.innerHTML = h;
  $("#b-dlxml").onclick = () => download(outName(".xml"), r.xml, "application/xml");
  $("#b-dlcsv").onclick = () => download(outName("_changes.csv"), PPU.changeLogCsv(r), "text/csv");
  $("#logq").oninput = e => { const q = e.target.value.toLowerCase(); for (const tr of $$("#logtbl tbody tr")) tr.hidden = q && !tr.textContent.toLowerCase().includes(q); };
}


/* ---------------- 6. readiness checks ---------------- */
function readiness() {
  const t = target(); if (!t) return null;
  const A = ST.A, R = ST.R, ctx = { map: ST.map };
  const version = PPU.versionCheck(A, t, R, ctx);
  return { version, wont: PPU.wontMigrate(A, t, R), pano: PPU.panoramaGuidance(A, t, R, ctx), flags: PPU.featureFlags(A, t, R), cap: PPU.capacityCheck(A, t, R), rack: PPU.rackPower(A, t, R, srcModel()) };
}
function refLinks(keys) {
  const a = (keys || []).map(k => ST.idx.sources[k]).filter(Boolean).map(x => '<a href="' + esc(x.url) + '" target="_blank" rel="noopener">' + esc(x.title) + "</a>");
  return a.length ? '<div class="src">Source: ' + a.join(" · ") + "</div>" : "";
}
const SEVPILL = { bad: ["r", "Blocker"], warn: ["y", "Check"], info: ["i", "Note"] };
function capPill(st) { return { ok: ["g", "Within limit"], warn: ["y", "Close to limit"], over: ["r", "Over limit"], unknown: ["", "Unknown"] }[st] || ["", st]; }
function renderReadiness() {
  const el = $("#tab-readiness"), A = ST.A, t = target();
  if (!t) { el.innerHTML = '<div class="card"><p class="nf">Pick a target on step 2 first.</p></div>'; return; }
  const Z = readiness();
  let h = '<div class="card"><h2>PAN-OS version and upgrade path</h2>';
  for (const v of Z.version) { const [c, l] = SEVPILL[v.sev] || ["", v.sev]; h += '<div class="ci"><span class="pill ' + c + '">' + l + "</span> <b>" + esc(v.title) + "</b><p>" + esc(v.text) + "</p>" + refLinks(v.refs) + "</div>"; }
  h += "</div>";
  h += '<div class="card"><h2>What will not move with the config</h2><p class="muted">Items marked with a count were found in the file. Others are always true for a config move.</p><div class="scroll"><table class="data"><thead><tr><th>Item</th><th>In your config</th><th>What to do</th></tr></thead><tbody>';
  for (const w of Z.wont) h += "<tr><td><b>" + esc(w.title) + "</b><div class=\"muted\">" + esc(w.text) + "</div></td><td>" + (w.applies ? '<span class="pill y">' + (w.count != null ? esc(w.count) + " found" : "Yes") + "</span>" : '<span class="pill g">None seen</span>') + "</td><td>" + esc(w.action || "") + "</td></tr>";
  h += "</tbody></table></div></div>";
  if (Z.pano.managed) {
    h += '<div class="card"><h2>Panorama-managed firewall</h2><p>This config points at Panorama. Order of work:</p><ol>' + Z.pano.steps.map(x => "<li>" + esc(x) + "</li>").join("") + "</ol>";
    if (Z.pano.notes.length) h += "<ul>" + Z.pano.notes.map(x => "<li>" + esc(x) + "</li>").join("") + "</ul>";
    h += "</div>";
  }
  h += '<div class="card"><h2>Features and platform differences for ' + esc(t.model) + "</h2>";
  for (const f2 of Z.flags) { const [c, l] = SEVPILL[f2.sev] || ["", f2.sev]; h += '<div class="ci"><span class="pill ' + c + '">' + l + "</span> <b>" + esc(f2.feature) + "</b><p>" + esc(f2.text) + "</p>" + refLinks(f2.refs) + "</div>"; }
  h += "</div>";
  h += '<div class="card"><h2>Capacity: your config against ' + esc(t.model) + " published limits</h2>";
  h += '<div class="scroll"><table class="data"><thead><tr><th>Item</th><th>In your config</th><th>' + esc(t.model) + ' limit</th><th>Result</th><th>Note / source</th></tr></thead><tbody>';
  for (const r of Z.cap) { const [c, l] = capPill(r.status); h += "<tr><td>" + esc(r.label) + "</td><td>" + (r.used == null ? '<span class="nf">not counted</span>' : U.fmtNum(r.used)) + "</td><td>" + (r.limit == null ? '<span class="nf">unknown</span>' : U.fmtNum(r.limit)) + '</td><td><span class="pill ' + c + '">' + l + "</span></td><td>" + esc(r.note || "") + refLinks(r.srcs) + "</td></tr>"; }
  h += "</tbody></table></div><p class=\"muted\">Counts come from the running config in the file (all virtual systems together). A limit shown as unknown is not in the sources this tool uses; check the Palo Alto product comparison tool for it. Always confirm limits for the PAN-OS version you will run.</p></div>";
  const K = Z.rack;
  h += '<div class="card"><h2>Rack and power</h2>';
  if (K.vm) h += "<p>VM-Series: no rack space or power. Size the hypervisor host instead.</p>";
  else {
    h += '<div class="scroll"><table class="data"><thead><tr><th></th><th>Old firewall</th><th>New firewall</th></tr></thead><tbody>';
    const row = (l, a, b) => "<tr><th>" + l + "</th><td>" + (a == null || a === "" ? '<span class="nf">not in sources</span>' : esc(a)) + "</td><td>" + (b == null || b === "" ? '<span class="nf">not in sources</span>' : esc(b)) + "</td></tr>";
    const o = K.src || {}, n = K.rack || {};
    h += row("Rack units", o.ru != null ? o.ru + "U" : (o.mount || null), n.ru != null ? n.ru + "U" : (n.mount || null));
    h += row("Size (H × D × W)", o.dims, n.dims) + row("Weight (lbs)", o.lbs, n.lbs) + row("Airflow", o.airflow, n.airflow);
    h += row("Max power (W)", o.max_w, n.max_w) + row("Heat (BTU/hr)", o.btu_hr, n.btu_hr);
    h += row("Power supplies", (ST.A.power ? ST.A.power.count + " present of " + ST.A.power.slots + " slots (from the file)" : null), K.psu ? K.psu.base + " fitted, up to " + K.psu.max + " (" + (K.psu.watts ? K.psu.watts + " W each" : "wattage not in sources") + ")" : null);
    h += row("Power inlet", null, K.psu ? K.psu.cord : null);
    h += "</tbody></table></div><ul>" + K.notes.map(x => "<li>" + esc(x) + "</li>").join("") + "</ul>";
    if (K.totals && K.units > 1) h += '<p class="muted">Pair totals for the new firewalls: ' + (K.totals.ru != null ? K.totals.ru + "U together, " : "") + (K.totals.maxW != null ? "up to " + U.fmtNum(K.totals.maxW) + " W together (nameplate maximum, not typical draw)" : "") + ".</p>";
    h += refLinks((n.sources || []).concat(K.psu && K.psu.sources || []));
  }
  h += "</div>";
  el.innerHTML = h;
}
function readinessReportHtml() {
  const t = target(); if (!t) return "";
  const Z = readiness(); let h = "<h2>Readiness checks</h2>";
  const vs = Z.version.filter(v => v.sev !== "info");
  h += "<h3>PAN-OS version</h3><ul>" + (Z.version.filter(v => v.id === "install").concat(vs).map(v => "<li><b>" + esc(v.title) + ".</b> " + esc(v.text) + "</li>").join("")) + "</ul>";
  h += "<h3>Capacity against " + esc(t.model) + " published limits</h3><table><tr><th>Item</th><th>Config</th><th>Limit</th><th>Result</th></tr>";
  for (const r of Z.cap) h += "<tr><td>" + esc(r.label) + "</td><td>" + (r.used == null ? "not counted" : U.fmtNum(r.used)) + "</td><td>" + (r.limit == null ? "unknown" : U.fmtNum(r.limit)) + "</td><td>" + esc(capPill(r.status)[1]) + "</td></tr>";
  h += "</table>";
  const fl = Z.flags.filter(f2 => f2.feature !== "Features not listed here");
  if (fl.length) h += "<h3>Feature and platform call-outs</h3><ul>" + fl.map(f2 => "<li><b>" + esc(f2.feature) + ".</b> " + esc(f2.text) + "</li>").join("") + "</ul>";
  const wm = Z.wont.filter(w => w.applies);
  h += "<h3>Does not move with the config</h3><ul>" + wm.map(w => "<li><b>" + esc(w.title) + (w.count != null ? " (" + esc(w.count) + ")" : "") + ".</b> " + esc(w.action || w.text) + "</li>").join("") + "</ul>";
  if (Z.pano.managed) h += "<h3>Panorama</h3><ol>" + Z.pano.steps.map(x => "<li>" + esc(x) + "</li>").join("") + "</ol>";
  if (!Z.rack.vm) h += "<h3>Rack and power</h3><ul>" + Z.rack.notes.map(x => "<li>" + esc(x) + "</li>").join("") + "</ul>";
  return h;
}
function runbookText() {
  const t = target(), R = ST.R;
  const Z = readiness(); const cu = ST.custom;
  const d = new Date(), ds = d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
  return PPU.buildRunbook({ A: ST.A, target: t, R, date: ds, hardware: hwPlan(), version: Z.version, wont: Z.wont, panorama: Z.pano, inventory: ST.A.inventory,
    custom: ST.convMode === "custom" ? { adminName: cu.adminOn ? cu.adminName : "", mgmtChanged: !!cu.ip, mgmtIp: cu.ip } : null });
}
function savePlan() {
  const t = target(); download(outName("_plan.json"), PPU.planToJson(Object.assign({}, ST, { targetName: t ? t.model : ST.targetName }), ST.A), "application/json");
}
async function loadPlan(file) {
  try {
    const r = PPU.planFromJson(await file.text(), ST.A);
    const p = r.state;
    for (const k of ["targetName", "ha", "opts", "overrides", "map", "haPortMap", "convMode", "hw", "lic", "customPorts"]) if (p[k] !== undefined) ST[k] = p[k];
    if (p.custom) ST.custom = Object.assign(NEWCUSTOM(), p.custom);
    ST.conv = null;
    refreshAll();
    window.__planMsg = "Plan loaded" + (r.savedOn ? " (saved " + r.savedOn + ")" : "") + "." + (r.warnings.length ? " " + r.warnings.join(" ") : "");
  } catch (e) { window.__planMsg = "Could not load plan: " + e.message; }
  renderReport();
}

/* ---------------- 5. report ---------------- */
function reportHtml() {
  const A = ST.A, s = A.system || {}, m = srcModel(), t = target(), R = ST.R, rec = ST.rec;
  const LP = PPU.licensePlan(A, t, R);
  const e = t ? (rec.evals.concat(rec.vm.evals).find(x => x.model === t.model) || PPU.evaluateModel(t, R, A, ST.opts)) : null;
  const nd = new Date(); const d = nd.getFullYear() + "-" + String(nd.getMonth() + 1).padStart(2, "0") + "-" + String(nd.getDate()).padStart(2, "0");
  let h = '<h1>Firewall refresh summary</h1><p class="meta">' + esc(s.hostname || "") + " · prepared " + d + " · generated offline by PAN Physical Upgrade Planner</p>";
  h += "<h2>What we have today</h2><table><tr><th>Model</th><td>" + esc(s.model || "?") + (R.ha ? " (HA pair, 2 units)" : "") + "</td></tr><tr><th>Serial</th><td>" + esc(maskSerial(s.serial)) + (A.ha.enabled && A.ha.peerModel ? " + HA peer" : "") + "</td></tr><tr><th>PAN-OS</th><td>" + esc(s.swVersion || "?") + "</td></tr>";
  h += "<tr><th>End of sale / end of life</th><td>" + esc(m ? (m.eos_date || "not announced") + " / " + (m.eol_date || "not announced") : "model not in catalog") + "</td></tr>";
  h += "<tr><th>Peak load seen</th><td>" + esc(R.observed.sessions != null ? U.fmtNum(R.observed.sessions) + " sessions" : "sessions not in file") + " · " + esc(R.observed.kbps != null ? U.fmtBps(R.observed.kbps * 1000) : "throughput not in file") + " · " + esc(R.observed.cps != null ? U.fmtNum(R.observed.cps) + " new sessions/s" : "CPS not in file") + "</td></tr>";
  h += "<tr><th>Ports in use</th><td>" + R.ports.length + "</td></tr><tr><th>Virtual systems</th><td>" + R.vsys + "</td></tr></table>";
  if (t) {
    h += "<h2>What we are moving to</h2><table><tr><th>Model</th><td><b>" + esc(t.model) + "</b>" + (t.form === "vm" ? " (VM-Series, " + esc(rec.vm.vcpu) + " vCPU, " + esc(t.mem_gb) + " GB RAM minimum)" : "") + "</td></tr><tr><th>Quantity</th><td>" + LP.qty + (R.ha ? " (HA pair)" : "") + "</td></tr>";
    h += "<tr><th>Sold until</th><td>" + esc(t.eos_date ? "end-of-sale " + t.eos_date + " (announced)" : "currently sold, no end-of-sale announced") + "</td></tr><tr><th>Minimum PAN-OS</th><td>" + esc(t.min_panos || "not published") + "</td></tr></table>";
    h += "<h3>Why this model</h3><ul><li>Sized for peak load plus " + esc(ST.opts.headroomPct) + "% growth" + (R.useThreat ? ", using Threat Prevention throughput because threat services are licensed" : "") + ".</li>";
    if (e && e.maxUtil != null) h += "<li>At that load it runs at about " + e.maxUtil.toFixed(0) + "% of its rated capacity.</li>";
    if (rec.top && rec.top.model === t.model) h += "<li>It is the smallest currently sold model that meets every requirement.</li>";
    for (const x of rec.smallerRejected.slice(0, 2)) if (rec.top && rec.top.model === t.model) h += "<li>Smaller option " + esc(x.model) + " ruled out: " + esc(x.reasons[0]) + ".</li>";
    if (e && !e.ok) h += "<li><b>Note:</b> selected manually. It falls short on: " + esc(e.reasons.join("; ")) + ".</li>";
    h += "</ul>";
    const hp = hwPlan();
    h += "<h2>Hardware, power and cabling to quote</h2>";
    h += "<table><tr><th>Item</th><th>Qty</th><th>Note</th></tr><tr><td>" + esc(t.form === "vm" ? t.model + " capacity (Software NGFW credits)" : t.model + " appliance") + "</td><td>" + LP.qty + "</td><td>" + (R.ha ? "HA pair" : "Standalone") + "</td></tr>";
    if (!hp.vm) {
      const P = hp.power;
      if (P.optionalPerUnit) h += "<tr><td>" + esc(t.model) + " extra " + (P.tgt && P.tgt.kind === "adapter" ? "power adapter" : "power supply") + "</td><td>" + P.optionalPerUnit * hp.units + "</td><td>second supply for redundancy" + (hp.units === 2 ? ", 1 per firewall" : "") + "</td></tr>";
      h += "<tr><td>Power cords / feeds (" + esc(P.cordKind) + ")</td><td>" + (P.cords != null ? P.cords : "to be confirmed") + "</td><td>" + (P.psuPerUnit != null ? P.psuPerUnit + " per firewall" : "") + "</td></tr>";
      for (const g of hp.groups) {
        if (g.reuse && !g.qty) continue;
        const item = g.kind === "optic" ? g.form + " optic" + (g.reuse ? " (existing, reuse)" : "") : (g.use === "ha" ? "Ethernet cable, HA link" : g.form);
        h += "<tr><td>" + esc(item) + (g.kind === "optic" ? " — " + esc(g.type) : "") + "</td><td>" + g.qty + "</td><td>" + (g.use === "ha" ? "HA links" : "data ports") + (g.kind === "optic" && g.type === "Type to be chosen" ? " (confirm SR/LR or DAC before ordering)" : "") + "</td></tr>";
      }
    }
    h += "</table>";
    if (!hp.vm) {
      const P = hp.power;
      h += "<h3>Power</h3><ul><li>Old firewall: " + esc(P.src.fromTsf ? P.src.fromTsf.count + " power supply(ies) in the tech-support file" : P.src.redundant != null ? (P.src.redundant ? "redundant power" : "single power supply") + " (" + P.src.basis + ")" : "not in the file") + ".</li>" + P.notes.map(n => "<li>" + esc(n) + "</li>").join("") + "</ul>";
      const flagged = hp.ports.filter(r => r.flags.length);
      if (flagged.length) h += "<h3>Ports where speed or media changes</h3><table><tr><th>Old → new port</th><th>Call-out</th></tr>" + flagged.map(r => "<tr><td>" + esc(r.src + " → " + r.tgt) + "</td><td>" + r.flags.map(x => esc(x)).join("<br>") + "</td></tr>").join("") + "</table>";
      else if (hp.ports.length) h += "<p>No port changes speed or media. Existing optics and cables can be reused where the cage size allows.</p>";
      if (hp.ha.length) h += "<h3>HA cabling</h3><table><tr><th>Link</th><th>Old</th><th>New</th><th>Connect</th></tr>" + hp.ha.map(r => "<tr><td>" + esc(r.label) + "</td><td>" + esc(r.srcDesc) + "</td><td>" + esc(r.tgtDesc || "not chosen") + "</td><td>" + esc(r.cableText || "") + (r.flags.length ? "<br>" + r.flags.map(x => esc(x)).join("<br>") : "") + "</td></tr>").join("") + "</table>";
      h += "<ul>" + hp.notes.map(n => "<li>" + esc(n) + "</li>").join("") + "</ul>";
    }
    const LR = licReview();
    h += "<h2>Licenses to quote</h2><table><tr><th>Item</th><th>Qty</th><th>Note</th></tr>";
    for (const f2 of LR.finalItems) h += "<tr><td>" + esc(f2.name) + "</td><td>" + f2.qty + "</td><td>" + esc(f2.source === "carry" ? "kept; " + f2.note : f2.source === "required" ? "required; " + f2.note : f2.note) + "</td></tr>";
    h += "</table>";
    const added = LR.finalItems.filter(x => x.source === "add").map(x => x.name);
    if (added.length) h += "<p><b>Added at the customer's request:</b> " + added.map(esc).join(", ") + ".</p>";
    if (LR.dropped.length) h += "<p><b>Not included:</b> " + LR.dropped.map(d => esc(d.name) + (d.expired ? " (expired today)" : " (dropped on review)")).join(", ") + ".</p>";
    h += "<ul>" + LP.notes.map(n => "<li>" + esc(n) + "</li>").join("") + "</ul>";
  } else h += "<p>No target selected.</p>";
  h += readinessReportHtml();
  h += '<p class="meta">No prices are included. Specifications come from Palo Alto Networks datasheets and the end-of-life page (catalog data as of ' + esc(ST.catalog.data_as_of || "?") + ").</p>";
  return h;
}
const REPORT_CSS = "body{font:15px/1.45 system-ui,Segoe UI,Arial;color:#111;background:#fff;max-width:900px;margin:24px auto;padding:0 20px}h1{font-size:24px;margin:0}h2{font-size:19px;margin:22px 0 8px;border-bottom:2px solid #2f6fd6;padding-bottom:4px}h3{font-size:16px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}th{background:#f2f4f7;width:32%}.meta{color:#555;font-size:13px}@media print{body{margin:0}}";
function renderReport() {
  const html = reportHtml();
  $("#tab-report").innerHTML = '<div class="card"><div class="actions"><button type="button" class="primary" id="b-rhtml">⬇️ Export report (HTML)</button><button type="button" id="b-rprint">🖨️ Print / save as PDF</button><button type="button" id="b-runbook">📋 Export cutover runbook (Markdown)</button><button type="button" id="b-psave">💾 Save plan (JSON)</button><label class="btn">📂 Load plan<input type="file" id="b-pload" accept=".json,application/json" hidden></label><label class="btn"><input type="checkbox" id="r-hide"' + (ST.hideSerial ? " checked" : "") + '> Hide serial numbers</label></div><div id="rpt" class="rptbox"><p class="muted" id="plan-msg">The plan file has your choices only (target, ports, hardware, licenses, convert options). It never contains the admin password or hash. It has hostnames and IP addresses from your choices, so keep it with your project files, not in a public place.</p><iframe id="rframe" title="Report preview" style="width:100%;height:900px;border:1px solid var(--bd);border-radius:8px;background:#fff"></iframe></div></div>';
  const doc = "<!DOCTYPE html><html><head><meta charset=utf-8><meta name=color-scheme content=light><title>Firewall refresh summary</title><style>" + REPORT_CSS + "</style></head><body>" + html + "</body></html>";
  const fr = $("#rframe"); fr.srcdoc = doc;
  $("#b-rhtml").onclick = () => download(outName("_refresh-summary.html"), doc, "text/html");
  $("#b-runbook").onclick = () => download(outName("_cutover-runbook.md"), runbookText(), "text/markdown");
  $("#b-psave").onclick = savePlan;
  $("#b-pload").onchange = e => { const f2 = e.target.files[0]; if (f2) loadPlan(f2); };
  if (window.__planMsg) $("#plan-msg").textContent = window.__planMsg;
  $("#b-rprint").onclick = () => { try { fr.contentWindow.focus(); fr.contentWindow.print(); } catch (e) { window.print(); } };
  $("#r-hide").onchange = e => { ST.hideSerial = e.target.checked; renderReport(); renderCurrent(); };
  window.__ppuReportHtml = doc;
}
