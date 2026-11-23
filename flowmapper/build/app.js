/* SPDX-License-Identifier: Apache-2.0 */
/* PAN-OS FlowMapper UI. Depends on window.FM (core.js). No network access. */
(function () {
"use strict";
const FM = window.FM;
const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const DEMO = "@@DEMO_XML@@";
/* The firewalls that take part in traces, pickers, diagrams, batch runs and plans: everything loaded, minus what the scope hides. */
const V = () => (state.view ? state.view.devices : state.devices);

const LINKS_KEY = "pan-flowmapper-links", CIRC_KEY = "pan-flowmapper-circuits", CIRC_IGN_KEY = "pan-flowmapper-circuits-ignored";
const HN_KEY = "pan-flowmapper-hostnames";
function loadJson(k) { try { const v = JSON.parse(localStorage.getItem(k) || "[]"); return Array.isArray(v) ? v : []; } catch (e) { return []; } }
const ROLES_KEY = "pan-flowmapper-site-roles";
function loadProfile() { try { return FM.normalizeProfile(JSON.parse(localStorage.getItem(ROLES_KEY) || "{}")); } catch (e) { return FM.defaultProfile(); } }
const state = { files: [], devices: [], view: null, profile: loadProfile(), last: null, lastSvg: null, choices: {}, pathIndex: 0, links: loadLinks(), hostnames: loadHostnames(), circuits: loadJson(CIRC_KEY), circIgnore: loadJson(CIRC_IGN_KEY), routeTables: [], rtReports: [] };
function loadLinks() { try { const v = JSON.parse(localStorage.getItem("pan-flowmapper-links") || "[]"); return Array.isArray(v) ? v : []; } catch (e) { return []; } }
function saveLinks() { try { localStorage.setItem(LINKS_KEY, JSON.stringify(state.links)); } catch (e) {} renderLinks(); }
window.__FM = { ready: false, state, loadText, runTrace, addRouteTable: (d, t, l) => addRouteTable(d, t, l), runValidation: () => runValidation(), traceRule: (scope, name) => traceRule(scope, name), getDevices: () => state.devices, getView: () => state.view, setProfile: (p) => { state.profile = FM.normalizeProfile(p); saveProfile(); }, getProfile: () => state.profile, lastResult: () => state.last, showTab, setLinks: (l) => { state.links = l; saveLinks(); }, setCircuits: (l) => { state.circuits = l; state.circIgnore = []; saveCircuits(); }, choose: (key, devId) => { state.choices[key] = devId; state.pathIndex = 0; return runTrace(null, true); }, choosePath: (i) => { state.pathIndex = i; state.choices = {}; return runTrace(null, true); }, diagnostics: () => FM.diagnostics(state.devices, state.links) };

$("#ver").textContent = "v" + FM.version;

/* ---------------- loading ---------------- */
$("#fi").addEventListener("change", (e) => loadFiles(e.target.files));
const drop = $("#drop");
drop.addEventListener("click", () => $("#fi").click());
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); loadFiles(e.dataTransfer.files); });
$("#btn-demo").addEventListener("click", () => loadText("demo-multi-vsys.xml (synthetic)", DEMO).then(() => {
  if (!$("#q-src").value) { $("#q-src").value = "10.1.1.10"; $("#q-dst").value = "10.2.2.20"; $("#q-proto").value = "tcp"; $("#q-port").value = "1433"; }
}));
$("#btn-dark").addEventListener("click", () => document.body.classList.toggle("dark"));
$("#btn-diag").addEventListener("click", () => {
  if (!state.devices.length) { flash("Load a config first."); return; }
  const d = FM.diagnostics(state.devices, state.links);
  download("flowmapper-diagnostics-redacted-" + stamp() + ".json", new Blob([JSON.stringify(d, null, 1)], { type: "application/json" }));
});

async function loadFiles(list) {
  window.__FM.ready = false;
  for (const f of Array.from(list || [])) {
    try { await loadText(f.name, await f.text()); }
    catch (e) { flash("Could not load " + f.name + ": " + e.message); }
  }
  window.__FM.ready = true;
}
function flash(msg) { const r = $("#result"); r.insertAdjacentHTML("afterbegin", '<div class="note error">' + esc(msg) + "</div>"); showTab("trace"); }
async function loadText(name, text) {
  window.__FM.ready = false;
  drop.innerHTML = "Reading " + esc(name) + " (" + Math.round(text.length / 1024) + " KB)...";
  await new Promise((r) => setTimeout(r, 20));
  const t0 = performance.now();
  let loaded;
  try { loaded = await FM.loadConfigAsync(text, name, (f) => { drop.innerHTML = "Reading " + esc(name) + "... " + Math.round(f * 100) + "%"; }); }
  catch (e) { resetDrop(); flash(name + ": " + e.message); window.__FM.ready = true; throw e; }
  const entry = { name, loaded, enabled: true, ctxSel: null, dgOverride: {}, ms: 0, showUnmapped: false };
  if (loaded.kind === "panorama") { const cs = loaded.panorama.contexts, mapped = cs.filter((c) => c.mapped); entry.ctxSel = new Set((mapped.length ? mapped : cs).map((c) => c.id)); }
  state.files = state.files.filter((f) => f.name !== name).concat([entry]);
  await rebuildDevices();
  entry.ms = Math.round(performance.now() - t0);
  resetDrop(); renderFiles(); refreshSelectors();
  $("#tabs").hidden = false; if ($$(".tab").every((t) => t.hidden)) showTab("trace");
  window.__FM.ready = true;
  return loaded;
}
function resetDrop() { drop.classList.add("small"); drop.innerHTML = "Drop more config XML files here to trace across firewalls, or click to browse. <span class='muted'>Nothing is uploaded.</span>"; }
/* A local firewall backup loaded alongside Panorama for this DG-only firewall (matched by serial or hostname). */
function localFwFor(c) {
  const k = (x) => String(x || "").toLowerCase();
  for (const f of state.files) if (f.enabled && f.loaded.kind === "firewall") for (const d of f.loaded.devices) if ((c.serial && d.serial === c.serial) || (c.hostname && k(d.name) === k(c.hostname))) return f.name;
  return null;
}
function noNetCell(c) {
  const lf = localFwFor(c);
  return lf ? '<span class="ok">network from local backup ' + esc(lf) + "</span>" : '<span class="nonet">' + esc(FM.NO_NET_MSG(c.hostname || c.serial)) + "</span>";
}
async function rebuildDevices() {
  const devs = [];
  for (const f of state.files) {
    if (!f.enabled) continue;
    if (f.loaded.kind === "firewall") devs.push(...f.loaded.devices);
    else {
      f.built = f.built || new Map();
      let i = 0;
      for (const c of f.loaded.panorama.contexts) {
        if (!f.ctxSel.has(c.id)) continue;
        const dg = f.dgOverride[c.id] || "";
        const key = c.id + "|" + dg;
        if (!f.built.has(key)) {
          const spec = Object.assign({}, c, dg ? { dgMap: {}, dg } : {});
          f.built.set(key, FM.buildPanoramaDevice(f.loaded, spec));
          if (++i % 10 === 0) { drop.innerHTML = "Building device models from Panorama... " + i; await new Promise((r) => setTimeout(r, 0)); }
        }
        devs.push(f.built.get(key));
      }
    }
  }
  state.devices = FM.mergeLocalBackups(devs);
  applyHostnames();
  // pasted route tables (memory only): actual learned routes win over inference
  state.rtReports = FM.applyRouteTables(state.devices, state.routeTables); // also clears tables removed since last time
  drop.innerHTML = "Inferring BGP/OSPF routes and the network graph...";
  await new Promise((r) => setTimeout(r, 0));
  const t0 = performance.now();
  state.view = FM.scopeDevices(state.devices, state.profile);
  const g = FM.prepare(state.view.devices, state.links);
  state.inference = Object.assign({ ms: Math.round(performance.now() - t0) }, g.inference || {});
}

/* ---------------- files panel ---------------- */
/* Device-picker rows: HA pairs (detected by the engine from interface addresses) are one row; others one row each. */
function ctxRows(f, ctxs) {
  const byId = new Map(ctxs.map((c) => [c.id, c])), grpOf = new Map();
  for (const g of fileHaGroups(f)) { const cs = g.filter((id) => byId.has(id)); if (cs.length > 1) for (const id of cs) grpOf.set(id, cs); }
  const seen = new Set(), rows = [];
  for (const c of ctxs) {
    if (seen.has(c.id)) continue;
    const ids = grpOf.get(c.id) || [c.id]; ids.forEach((id) => seen.add(id));
    const cs = ids.map((id) => byId.get(id));
    const text = cs.map((x) => [x.label, x.hostname, x.serial && state.hostnames[x.serial], x.serial, x.stack, x.template, ...Object.values(x.dgMap || {})].filter(Boolean).join(" ")).join(" ").toLowerCase();
    rows.push({ ids, ctxs: cs, text });
  }
  return rows;
}
function fileHaGroups(f) {
  if (f.haGroupIds) return f.haGroupIds;
  const P = f.loaded.panorama; f.built = f.built || new Map();
  const devs = [], idOf = new Map();
  for (const c of P.contexts) {
    if (!c.mapped && !f.ctxSel.has(c.id)) continue;
    const key = c.id + "|";
    if (!f.built.has(key)) f.built.set(key, FM.buildPanoramaDevice(f.loaded, Object.assign({}, c)));
    const d = f.built.get(key); devs.push(d); idOf.set(d, c.id);
  }
  try { const G = FM.haGroups(devs); f.haGroupIds = G.groups.map((g) => g.map((d) => idOf.get(d))); f.haCfgIds = new Set([...(G.fromConfig || [])].map((d) => idOf.get(d))); } catch (e) { f.haGroupIds = []; f.haCfgIds = new Set(); }
  return f.haGroupIds;
}
/* Shared / overlapping address space between firewalls that are not HA pairs (cloned builds, overlapping RFC1918). */
function overlapCalloutHtml() {
  if (!state.devices.length) return "";
  let O; try { O = FM.overlapReport(V()); } catch (e) { return ""; }
  if (!O.total) return "";
  const own = (list) => list.map((o) => esc(o.label) + ' <span class="muted">' + esc(o.iface + (o.zone ? " zone " + o.zone : "") + " " + o.prefix) + "</span>").join("<br>");
  const rows = O.sharedIps.slice(0, 200).map((x) => "<tr><td>" + esc(x.ip) + "</td><td>same address</td><td>" + own(x.owners) + "</td></tr>").concat(O.overlaps.slice(0, 200).map((x) => "<tr><td>" + esc(x.prefix) + "</td><td>" + (x.identical ? "same subnet" : "overlapping subnets") + "</td><td>" + own(x.owners) + "</td></tr>"));
  return '<div class="note warn" id="overlap-callout"><b>Overlapping address space: ' + esc(O.text) + "</b> " +
    (O.cloned.length ? "<br>Look-alike firewalls kept apart (not HA): " + O.cloned.slice(0, 6).map((c) => esc(c.a.hostname || c.a.device) + " and " + esc(c.b.hostname || c.b.device) + ' <span class="muted">(' + esc(c.notHa) + ")</span>").join("; ") + (O.cloned.length > 6 ? " and " + (O.cloned.length - 6) + " more" : "") + "." : "") +
    '<details id="overlap-list"' + (O.total <= 4 ? " open" : "") + '><summary>Show the ' + O.total + ' shared addresses / subnets</summary><div class="tblwrap" style="max-height:260px"><table class="data"><thead><tr><th>Address / subnet</th><th>Kind</th><th>Configured on</th></tr></thead><tbody>' + rows.join("") + "</tbody></table></div></details></div>";
}
/* Firewalls in the trace set that have no network config in the Panorama export (and no local backup merged). */
function noNetDevices() { return V().filter((d) => d.kind === "panorama" && !d.interfaces.size && !d.mergedLocal); }
function noNetCalloutHtml() {
  const nn = noNetDevices(); if (!nn.length) return "";
  return '<div class="note warn" id="nonet-callout"><b>' + nn.length + " firewall" + (nn.length === 1 ? " has" : "s have") + " no network config in this export.</b> Traces that reach " + (nn.length === 1 ? "it" : "them") + " stop there (Incomplete path). Load each firewall's own local backup (drop it here with the Panorama file) to trace through it; the local backup also carries its HA settings (peer-ip, HA1), so HA pairs can be confirmed." +
    '<details id="nonet-list"' + (nn.length <= 6 ? " open" : "") + "><summary>" + (nn.length <= 6 ? "Firewalls" : "Show the " + nn.length + " firewalls") + '</summary><ul class="nonet-ul">' + nn.map((d) => "<li>" + esc(DL(d.name)) + "</li>").join("") + "</ul></details></div>";
}
function renderFiles() {
  const box = $("#files"); box.hidden = !state.files.length;
  let h = "<h2>Loaded configs</h2>";
  for (const f of state.files) {
    const L = f.loaded;
    h += '<div class="filerow"><label><input type="checkbox" data-file="' + esc(f.name) + '" ' + (f.enabled ? "checked" : "") + "> <b>" + esc(f.name) + "</b></label>" +
      '<span class="pill ' + (L.kind === "panorama" ? "b" : "g") + '">' + (L.kind === "panorama" ? "Panorama" : "Firewall") + "</span>" +
      '<span class="muted">PAN-OS ' + esc(L.version || "?") + " &middot; " + (L.kind === "firewall" ? esc(L.devices[0].vsys.size + " vsys/shared-gw, " + L.devices[0].interfaces.size + " interfaces, " + new Set(L.devices[0].vrs.values()).size + " routers") : esc(L.panorama.contexts.length + " managed devices, " + L.panorama.dgs.size + " device groups, " + L.panorama.stacks.size + " template stacks")) + " &middot; " + f.ms + " ms</span>" +
      '<button class="sm" data-remove="' + esc(f.name) + '">Remove</button></div>';
    if (L.kind === "panorama") {
      const allCtx = L.panorama.contexts;
      const unm = allCtx.filter((c) => !c.mapped).length;
      const ctxs = f.showUnmapped ? allCtx : allCtx.filter((c) => c.mapped || f.ctxSel.has(c.id));
      const mdg = L.panorama.mappedDgs ? L.panorama.mappedDgs.size : L.panorama.dgs.size, mst = new Set(allCtx.filter((c) => c.mapped && c.stack).map((c) => c.stack)).size;
      h += '<p class="muted mapinfo">' + esc(allCtx.filter((c) => c.mapped).length + " managed firewalls mapped by template-stack / device-group device lists. " + mdg + " of " + L.panorama.dgs.size + " device groups and " + mst + " of " + L.panorama.stacks.size + " template stacks are used by them" + (unm ? "; " + unm + " unmapped stacks/templates are hidden" : "") + ".") + (unm ? ' <label><input type="checkbox" data-unm="' + esc(f.name) + '"' + (f.showUnmapped ? " checked" : "") + "> show unmapped</label>" : "") + "</p>";
      h += '<div class="ctxlist"><div class="ctl"><b>Devices in trace set: <span id="ctxcount-' + esc(f.name) + '">' + f.ctxSel.size + "</span> / " + ctxs.length + "</b>" +
        '<button class="sm" data-ctxall="' + esc(f.name) + '">All</button><button class="sm" data-ctxnone="' + esc(f.name) + '">None</button>' +
        '<input type="search" class="ctxfilter" data-f="' + esc(f.name) + '" placeholder="Filter devices (hostname, serial, stack, DG)"></div>' +
        '<div class="tblwrap" style="max-height:260px"><table class="data"><thead><tr><th></th><th>Device</th><th>Template stack</th><th>Device group (by vsys)</th><th>Override DG</th></tr></thead><tbody>';
      const rows = ctxRows(f, ctxs); f._rows = rows;
      const hnOf = (c) => c.hostname || c.hostnameTpl || (c.serial && state.hostnames[c.serial]) || c.hostnameInit || null;
      const ctxRowHtml = (c) => esc(hnOf(c) || c.serial || "-") + (hnOf(c) && c.serial ? ' <span class="muted">' + esc(c.serial) + "</span>" : "");
      const dgOf = (c) => Object.keys(c.dgMap).length ? esc(Object.entries(c.dgMap).map(([v, d]) => (v === "*" ? "" : v + ": ") + d).join(", ")) : '<span class="muted">none</span>';
      const dgoSel = (c, lab) => '<div>' + (lab ? '<span class="muted">' + esc(lab) + "</span> " : "") + '<select class="sm" data-dgo="' + esc(c.id) + '" data-f="' + esc(f.name) + '"><option value="">' + (Object.keys(c.dgMap).length ? "(by serial)" : "(none)") + "</option>" + (f.dgOverride[c.id] ? "<option selected>" + esc(f.dgOverride[c.id]) + "</option>" : "") + "</select></div>";
      rows.forEach((row, ri) => {
        const on = row.ids.every((id) => f.ctxSel.has(id)), some = !on && row.ids.some((id) => f.ctxSel.has(id));
        const c0 = row.ctxs[0], ha = row.ctxs.length > 1;
        const stacks = [...new Set(row.ctxs.map((c) => c.noNetwork ? null : c.stack || c.template))];
        h += '<tr class="ctxrow' + (ha ? " ha-row" : "") + '" data-text="' + esc(row.text) + '" data-ids="' + esc(row.ids.join(" ")) + '"><td><input type="checkbox" data-row="' + ri + '" data-f="' + esc(f.name) + '"' + (ha ? "" : ' data-ctx="' + esc(c0.id) + '"') + (on ? " checked" : "") + (some ? ' data-some="1"' : "") + "></td><td>" +
          (ha ? (f.haCfgIds && f.haCfgIds.has(c0.id) ? '<span class="pill b" title="HA peers named in the HA settings (peer-ip); both members are selected together">HA pair &middot; from HA config</span><br>' : '<span class="pill b" title="HA pair inferred from matching interface addresses on the same template stack; both members are selected together">HA pair</span><br>') + row.ctxs.map(ctxRowHtml).join("<br>") : ctxRowHtml(c0)) + "</td><td>" +
          (c0.noNetwork ? noNetCell(c0) : stacks.map((x) => esc(x || "")).join("<br>")) + "</td><td>" + [...new Set(row.ctxs.map(dgOf))].join("<br>") + "</td><td>" + (ha ? row.ctxs.map((c) => dgoSel(c, hnOf(c) || c.serial)).join("") : dgoSel(c0)) + "</td></tr>";
      });
      h += "</tbody></table></div></div>";
    }
  }
  h += noNetCalloutHtml();
  h += overlapCalloutHtml();
  if (state.inference && state.inference.bgpSpeakers + state.inference.ospfSpeakers > 0) h += '<p class="muted" id="infer-info">Dynamic routing inferred from config: ' + esc(state.inference.bgpSpeakers + " BGP speakers, " + state.inference.ospfSpeakers + " OSPF speakers, " + state.inference.fabrics + " provider fabric(s), " + state.inference.routes + " inferred routes" + (state.inference.unresolvedPeers ? ", " + state.inference.unresolvedPeers + " peers without a resolvable address" : "") + " (" + state.inference.ms + " ms). Inferred routes are medium confidence; see the route tables in the Config browser.") + "</p>";
  box.innerHTML = h;
  $$("[data-unm]", box).forEach((cb) => cb.addEventListener("change", () => { fileOf(cb.dataset.unm).showUnmapped = cb.checked; renderFiles(); }));
  $$("select[data-dgo]", box).forEach((sel) => sel.addEventListener("focus", () => {
    if (sel.dataset.filled) return; sel.dataset.filled = "1";
    const f = fileOf(sel.dataset.f), P = f.loaded.panorama, cur = sel.value;
    const mapped = [...P.dgs.keys()].filter((d) => !P.mappedDgs || P.mappedDgs.has(d)), other = [...P.dgs.keys()].filter((d) => P.mappedDgs && !P.mappedDgs.has(d));
    sel.innerHTML = sel.options[0].outerHTML + '<optgroup label="Used by managed firewalls">' + mapped.map((d) => "<option>" + esc(d) + "</option>").join("") + "</optgroup>" + (other.length ? '<optgroup label="Unmapped device groups">' + other.map((d) => "<option>" + esc(d) + "</option>").join("") + "</optgroup>" : "");
    sel.value = cur;
  }));
  $$("[data-file]", box).forEach((cb) => cb.addEventListener("change", async () => { state.files.find((f) => f.name === cb.dataset.file).enabled = cb.checked; await rebuildDevices(); resetDrop(); refreshSelectors(); }));
  $$("[data-remove]", box).forEach((b) => b.addEventListener("click", async () => { state.files = state.files.filter((f) => f.name !== b.dataset.remove); await rebuildDevices(); resetDrop(); renderFiles(); refreshSelectors(); }));
  const fileOf = (n) => state.files.find((f) => f.name === n);
  $$("input[data-row]", box).forEach((cb) => { if (cb.dataset.some) cb.indeterminate = true; cb.addEventListener("change", async () => { const f = fileOf(cb.dataset.f), row = f._rows[Number(cb.dataset.row)]; for (const id of row.ids) cb.checked ? f.ctxSel.add(id) : f.ctxSel.delete(id); $("#ctxcount-" + CSS.escape(f.name)).textContent = f.ctxSel.size; await rebuildDevices(); resetDrop(); refreshSelectors(); }); });
  // All / None act on the rows the filter shows: with a filter, All makes the trace set exactly those devices and None removes only them
  const shownRows = (f) => { const q = (f.ctxFilter || "").trim().toLowerCase(); return (f._rows || []).filter((r) => !q || r.text.includes(q)); };
  $$("[data-ctxall]", box).forEach((b) => b.addEventListener("click", async () => { const f = fileOf(b.dataset.ctxall); f.ctxSel = new Set(shownRows(f).flatMap((r) => r.ids)); await rebuildDevices(); resetDrop(); renderFiles(); refreshSelectors(); }));
  $$("[data-ctxnone]", box).forEach((b) => b.addEventListener("click", async () => { const f = fileOf(b.dataset.ctxnone); if ((f.ctxFilter || "").trim()) shownRows(f).forEach((r) => r.ids.forEach((id) => f.ctxSel.delete(id))); else f.ctxSel.clear(); await rebuildDevices(); resetDrop(); renderFiles(); refreshSelectors(); }));
  $$("[data-dgo]", box).forEach((s) => s.addEventListener("change", async () => { const f = fileOf(s.dataset.f); f.dgOverride[s.dataset.dgo] = s.value; await rebuildDevices(); resetDrop(); refreshSelectors(); }));
  const applyFilter = (inp) => { const q = inp.value.trim().toLowerCase(); $$(".ctxrow", inp.closest(".ctxlist")).forEach((tr) => { tr.hidden = !!q && !tr.dataset.text.includes(q); }); };
  $$(".ctxfilter", box).forEach((inp) => { inp.value = fileOf(inp.dataset.f).ctxFilter || ""; applyFilter(inp); inp.addEventListener("input", () => { fileOf(inp.dataset.f).ctxFilter = inp.value; applyFilter(inp); }); });
}
function devLabel(d) { return FM.devLabel(d) + (d.multiVsys ? " (multi-vsys)" : ""); }
/* Display label for a firewall referenced by name (hostname, serial, stack); unknown names are shown as they are. */
function DL(name) { if (!name) return name; const d = state.devices.find((x) => x.name === name || x.id === name); return d ? FM.devLabel(d) : name; }
const DLs = (list) => (list || []).map(DL).join(", ");
/* Free text from the engine names a firewall without a hostname by its serial. Show the full label (hostname · serial ·
   stack) wherever a bare serial appears in prose; a serial already inside a label, or in "(serial)", is left alone. */
let SER_RE = null, SER_MAP = null, SER_SIG = "";
function serialLabels() {
  const sig = state.devices.length + "|" + state.devices.map((d) => (d.serial || "") + ":" + FM.devLabel(d)).join(",");
  if (sig === SER_SIG) return SER_RE;
  SER_SIG = sig; SER_MAP = new Map();
  for (const d of state.devices) { const ser = d.serial || (d.panorama && d.panorama.serial); const lab = ser && FM.devLabel(d); if (ser && lab && lab !== ser && !SER_MAP.has(ser)) SER_MAP.set(ser, lab); }
  SER_RE = SER_MAP.size ? new RegExp("(?<![\\w.\\-]|\u00b7 )(" + [...SER_MAP.keys()].map((x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).sort((a, b) => b.length - a.length).join("|") + ")(?![\\w.\\-]| \u00b7)", "g") : null;
  return SER_RE;
}
function labelSerials(text) { const re = serialLabels(); if (!re || !text || typeof text !== "string") return text; re.lastIndex = 0; return text.replace(re, (m, g, i, all) => all[i - 1] === "(" && all[i + m.length] === ")" ? m : SER_MAP.get(m) || m); }
const SKIP_LABEL = "svg, textarea, script, style, input, #tab-config, #files, [data-nolabel]";
function labelSerialsIn(root) {
  if (!serialLabels() || !root) return;
  if (root.nodeType === 3) { const p = root.parentElement; if (p && !p.closest(SKIP_LABEL)) { const v = labelSerials(root.nodeValue); if (v !== root.nodeValue) root.nodeValue = v; } return; }
  if (root.nodeType !== 1 || root.closest(SKIP_LABEL)) return;
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, { acceptNode: (n) => n.parentElement && n.parentElement.closest(SKIP_LABEL) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT });
  const xs = []; while (w.nextNode()) xs.push(w.currentNode);
  for (const n of xs) { const v = labelSerials(n.nodeValue); if (v !== n.nodeValue) n.nodeValue = v; }
}
if (typeof MutationObserver !== "undefined") new MutationObserver((ms) => { for (const m of ms) for (const n of m.addedNodes) labelSerialsIn(n); }).observe(document.body, { childList: true, subtree: true });
function refreshSelectors() {
  const devOpts = V().map((d, i) => '<option value="' + esc(d.id) + '">' + esc(devLabel(d)) + "</option>").join("");
  for (const id of ["#q-dev", "#q-ddev"]) {
    const qd = $(id), cur = qd.value;
    qd.innerHTML = '<option value="">Auto (search all ' + V().length + " devices)</option>" + devOpts; qd.value = cur;
    if (qd.value !== cur) qd.value = "";
  }
  fillIngress();
  for (const id of ["#cfg-dev", "#topo-dev"]) { const s = $(id), c = s.value; s.innerHTML = id === "#cfg-dev" ? state.devices.map((d) => '<option value="' + esc(d.id) + '">' + esc(devLabel(d)) + "</option>").join("") : devOpts; if (c) s.value = c; if (!s.value && state.devices[0]) s.value = state.devices[0].id; }
  $("#raw-file").innerHTML = state.files.map((f) => "<option>" + esc(f.name) + "</option>").join("");
  // datalist of object names (capped for very large configs)
  const names = FM.addressNames(V()); let h = "", n = 0;
  for (const [k, v] of names) { if (n++ > 5000) break; h += '<option value="' + esc(k) + '">' + esc(v) + "</option>"; }
  $("#addrlist").innerHTML = h;
  const devNames = [...new Set(state.devices.map((d) => d.name))].sort();
  const nameOpts = devNames.map((n) => '<option value="' + esc(n) + '">' + esc(DL(n)) + "</option>").join("");
  $("#lk-fdev").innerHTML = '<option value="">(any)</option>' + nameOpts;
  $("#lk-tdev").innerHTML = nameOpts;
  { const rd = $("#rt-dev"), cur = rd.value; rd.innerHTML = '<option value="">(pick the firewall)</option>' + nameOpts; rd.value = cur; }
  renderRouteTables();
  $("#devlist").innerHTML = nameOpts;
  renderLinks();
  $("#ck-dev").innerHTML = nameOpts; ckDevChanged();
  renderCircuits();
  renderConfig(); renderTopo(); renderMap(); renderEnv(); renderRaw();
  renderScopeBar(); renderRolesPanel();
}
function fillIngress() {
  const devId = $("#q-dev").value;
  const devs = devId ? V().filter((d) => d.id === devId) : (V().length <= 3 ? V() : []);
  let h = '<option value="">Auto (by route lookup)</option>';
  for (const d of devs) for (const it of d.interfaces.values()) if (it.vr) h += '<option value="' + esc(d.id + "|" + it.name) + '">' + esc((devs.length > 1 ? FM.devLabel(d) + " " : "") + it.name + (it.zone ? " (" + it.zone + ")" : "") + (it.ips[0] ? " " + it.ips[0].text : "") + (d.multiVsys ? " " + it.vsys : "")) + "</option>";
  $("#q-ing").innerHTML = h;
}
$("#q-dev").addEventListener("change", fillIngress);

/* ---------------- site roles and scope ---------------- */
function saveProfile(opts) { try { localStorage.setItem(ROLES_KEY, JSON.stringify(state.profile)); } catch (e) {} refreshView(!(opts && opts.silent)); }
/* Recompute which firewalls are in scope, then redraw everything that depends on it. */
function refreshView(rerun) {
  if (!state.devices.length) { state.view = null; renderScopeBar(); return; }
  state.view = FM.scopeDevices(state.devices, state.profile);
  FM.prepare(state.view.devices, state.links);
  ENV.key = null; ENV.pkey = null; mapCache.key = null;
  renderScopeBar(); renderFiles(); refreshSelectors();
  if ($("#roles-box") && !$("#roles-box").hidden && !refreshView._inRoles) renderRolesPanel();
  if (rerun && state.last && state.last.query && state.last.query.src) runTrace(null, true);
}
const roleLabel = (id) => { const r = FM.roleModel(state.devices, state.profile).defs.byId.get(id); return r ? r.label : id; };
function roleSelect(attr, val, autoLabel, extra) {
  const defs = FM.roleModel(state.devices, state.profile).defs.list;
  return '<select class="sm" ' + attr + ">" + '<option value="">' + esc(autoLabel) + "</option>" + defs.map((r) => '<option value="' + esc(r.id) + '"' + (val === r.id ? " selected" : "") + ">" + esc(r.label) + "</option>").join("") + "</select>";
}
function renderScopeBar() {
  const bar = $("#scopebar"), V0 = state.view;
  if (!V0 || !state.devices.length) { bar.hidden = true; return; }
  bar.hidden = false;
  const mode = state.profile.scope.mode, M = V0.model;
  const unk = M.sites.filter((s) => s.source === "default" && s.role === "other").length;
  const seg = (m, t, tip) => '<button type="button" class="sm' + (mode === m ? " on" : "") + '" data-scope="' + m + '" title="' + esc(tip) + '">' + t + "</button>";
  $("#scope-line").innerHTML = '<span class="chip scope-chip' + (V0.hiddenCount ? " hid" : "") + '" id="scope-chip" title="' + esc(V0.text) + '">' + esc(V0.chip) + "</span>" +
    '<span class="seg" role="group" aria-label="Change scope">' + seg("all", "All sites", "Trace through every loaded firewall") + seg("production", "Production only", "Leave out DR, Lab and Test firewalls") + seg("custom", "Custom sites…", "Pick exactly which sites to include") + "</span>" +
    '<button type="button" class="sm" id="roles-open">Site roles…</button>' +
    (unk && mode === "production" ? ' <span class="muted">' + unk + " site" + (unk === 1 ? " has" : "s have") + " no production / DR words in its names, so " + (unk === 1 ? "it is" : "they are") + " kept. Set roles to hide DR.</span>" : "");
  $$("#scope-line [data-scope]").forEach((b) => b.addEventListener("click", () => { state.profile.scope.mode = b.dataset.scope; if (b.dataset.scope === "custom" && !state.profile.scope.sites.length) state.profile.scope.sites = M.sites.filter((s) => (V0.model.defs.byId.get(s.role) || {}).focus).map((s) => s.id); saveProfile(); if (b.dataset.scope === "custom") openRoles(); }));
  $("#roles-open").addEventListener("click", () => openRoles());
}
function openRoles() { const d = $("#roles-box"); d.hidden = false; d.open = true; renderRolesPanel(); d.scrollIntoView({ behavior: "smooth", block: "nearest" }); }
function renderRolesPanel() {
  const box = $("#roles-box"); if (box.hidden || !state.view) return;
  refreshView._inRoles = true;
  const M = state.view.model, P = state.profile, body = $("#roles-body");
  if (!Array.isArray(P.rules)) P.rules = [];
  const q = ($("#roles-q") && $("#roles-q").value || "").trim().toLowerCase();
  const keepQ = $("#roles-q") ? $("#roles-q").value : "";
  const roleF = ($("#roles-rolef") && $("#roles-rolef").value) || "";
  const sitesOpen = $("#roles-sites-wrap") ? $("#roles-sites-wrap").open : false;
  const extraOpen = $("#roles-extra") ? $("#roles-extra").open : false;
  const focusId = document.activeElement && body.contains(document.activeElement) ? document.activeElement.id : "";
  const focusPos = (document.activeElement && document.activeElement.selectionStart) || 0;
  const preview = FM.rulePreview(state.devices, P);
  const defs = M.defs.list;
  const fieldSel = (i, val) => "<select class=\"sm\" id=\"rfield-" + i + "\" data-rfield=\"" + i + "\">" + FM.RULE_FIELDS.map((f) => "<option value=\"" + esc(f.id) + "\"" + (val === f.id ? " selected" : "") + ">" + esc(f.label) + "</option>").join("") + "</select>";
  const matchSel = (i, val) => "<select class=\"sm\" id=\"rmatch-" + i + "\" data-rmatch=\"" + i + "\">" + [["contains", "contains"], ["word", "whole word"], ["regex", "regex"]].map((x) => "<option value=\"" + x[0] + "\"" + (val === x[0] ? " selected" : "") + ">" + x[1] + "</option>").join("") + "</select>";
  const roleSelReq = (attr, val) => { const v = val || "production"; return "<select class=\"sm\" " + attr + ">" + defs.map((r) => "<option value=\"" + esc(r.id) + "\"" + (v === r.id ? " selected" : "") + ">" + esc(r.label) + "</option>").join("") + "</select>"; };
  let h = '<p class="muted"><b>Matching rules</b> come first and are usually enough: for example, <i>template stack contains</i> a word you type, set to DR. First match wins. A setting on one firewall or one site still beats a rule, and a rule beats the built-in guess. <b>Production only</b> leaves DR, Lab and Test out of traces.</p>';
  h += "<h3>Matching rules</h3>";
  h += '<div class="tblwrap" id="roles-rules"><table class="data"><thead><tr><th>#</th><th>Look in</th><th>Match</th><th>Text</th><th>Role</th><th></th></tr></thead><tbody>';
  P.rules.forEach((rule, i) => {
    const pr = preview.rules[i] || { count: 0, devices: [], warning: null, overlapCount: 0 };
    const names = pr.devices.slice(0, 8).map((d) => d.label).join(", ") + (pr.devices.length > 8 ? " +" + (pr.devices.length - 8) + " more" : "");
    let note = pr.warning ? '<div class="note warn" style="margin:4px 0 0">' + esc(pr.warning) + "</div>" : (pr.count ? '<div class="muted">' + pr.count + " firewall" + (pr.count === 1 ? "" : "s") + (names ? ": " + esc(names) : "") + "</div>" : "");
    if (pr.overlapCount) note += '<div class="note warn" style="margin:4px 0 0">' + pr.overlapCount + " of these already match rule " + (pr.overlap[0] && pr.overlap[0].earlier) + ", so this rule will not apply to them.</div>";
    h += "<tr><td>" + (i + 1) + "</td><td>" + fieldSel(i, rule.field) + "</td><td>" + matchSel(i, rule.match) + "</td>" +
      '<td><input class="sm" id="rvalue-' + i + '" data-rvalue="' + i + '" value="' + esc(rule.value) + '" placeholder="e.g. backup" style="min-width:8em"></td>' +
      "<td>" + roleSelReq('id="rrole-' + i + '" data-rrole="' + i + '"', rule.role) + "</td>" +
      '<td><button type="button" class="sm" data-rup="' + i + '" title="Move up"' + (i === 0 ? " disabled" : "") + ">Up</button> " +
      '<button type="button" class="sm" data-rdown="' + i + '" title="Move down"' + (i === P.rules.length - 1 ? " disabled" : "") + ">Down</button> " +
      '<button type="button" class="sm" data-rremove="' + i + '">Remove</button></td></tr>' +
      '<tr class="rule-preview"><td></td><td colspan="5">' + note + "</td></tr>";
  });
  h += "</tbody></table></div>";
  h += '<div class="ctl"><button type="button" class="sm" id="rule-add">Add rule</button> <span class="muted">Leave the text box empty while you think — the preview updates as you type. Saved in this browser; export the same JSON PAAT uses.</span></div>';

  const fws = state.devices.filter((d) => {
    const m = M.byDev.get(d);
    if (roleF && m && m.role !== roleF) return false;
    if (!q) return true;
    return [d.hostname, d.name, d.serial, d.stack, m && m.site, m && m.role, m && m.source, m && m.why].filter(Boolean).join(" ").toLowerCase().includes(q);
  });
  const counts = {};
  state.devices.forEach((d) => { const r = (M.byDev.get(d) || {}).role || "other"; counts[r] = (counts[r] || 0) + 1; });
  const countLine = defs.map((r) => (counts[r.id] || 0) ? (roleLabel(r.id) + " " + counts[r.id]) : "").filter(Boolean).join(" · ");
  h += "<h3>Firewalls <span class=\"muted\">(" + state.devices.length + (countLine ? " — " + countLine : "") + ")</span></h3>";
  h += '<div class="ctl"><input type="search" id="roles-q" placeholder="Filter by hostname, serial, stack, site, role or reason" value="' + esc(keepQ) + '"> ';
  h += '<select class="sm" id="roles-rolef"><option value="">All roles</option>' + defs.map((r) => "<option value=\"" + esc(r.id) + "\"" + (roleF === r.id ? " selected" : "") + ">" + esc(r.label) + " (" + (counts[r.id] || 0) + ")</option>").join("") + "</select> ";
  h += 'Bulk set ' + roleSelect('id="roles-bulk-role"', "", "Choose a role") + ' <button type="button" class="sm" id="roles-bulk-set">Set role on ' + fws.length + " shown</button> ";
  h += '<button type="button" class="sm" id="roles-bulk-clear">Clear overrides on ' + fws.length + " shown</button></div>";
  h += '<div class="tblwrap" style="max-height:360px"><table class="data" id="roles-fws"><thead><tr><th>Firewall</th><th>Site</th><th>Stack</th><th>Role</th><th>Source</th></tr></thead><tbody>';
  h += fws.slice(0, 400).map((d) => {
    const m = M.byDev.get(d);
    const src = m.source === "rule" ? m.why : m.source === "firewall setting" ? "You set this firewall" : m.source === "site setting" ? "You set this site" : m.source === "guess" ? "Guess" : m.source === "ha" ? "HA peer" : "Other (no rule or guess)";
    return "<tr><td>" + esc(FM.devLabel(d)) + "</td><td>" + esc(m.site) + "</td><td class=\"muted\">" + esc(d.stack || "") + "</td><td>" + roleSelect('data-fw="' + esc(m.key) + '"', P.devices[m.key] || "", "Auto: " + roleLabel(m.role)) + "</td><td class=\"muted\" title=\"" + esc(m.why) + "\">" + esc(src) + "</td></tr>";
  }).join("");
  h += "</tbody></table></div>" + (fws.length > 400 ? '<p class="muted">Showing the first 400 of ' + fws.length + ". Use the filter.</p>" : "");

  h += '<details id="roles-sites-wrap"' + (sitesOpen || P.scope.mode === "custom" ? " open" : "") + "><summary><b>Sites</b> (" + M.sites.length + ") — set every firewall at a site, or pick a custom set</summary>";
  h += '<div class="tblwrap" style="max-height:240px"><table class="data" id="roles-sites"><thead><tr><th>Site</th><th>Firewalls</th><th>Role</th><th>Why</th>' + (P.scope.mode === "custom" ? "<th>Include</th>" : "") + "</tr></thead><tbody>";
  h += M.sites.map((s) => '<tr><td><b>' + esc(s.id) + "</b></td><td>" + s.count + (s.mixed ? ' <span class="pill y" title="Firewalls in this site have different roles">mixed</span>' : "") + "</td><td>" + roleSelect('data-site="' + esc(s.id) + '"', P.sites[s.id] || "", "Auto: " + roleLabel(s.role)) + "</td><td class=\"muted\">" + esc(s.why) + "</td>" +
    (P.scope.mode === "custom" ? '<td><input type="checkbox" data-incl="' + esc(s.id) + '"' + (P.scope.sites.includes(s.id) ? " checked" : "") + "></td>" : "") + "</tr>").join("") + "</tbody></table></div></details>";

  h += '<details id="roles-extra"' + (extraOpen ? " open" : "") + "><summary><b>Roles, extra words, DR copy advice</b></summary>";
  h += "<p class=\"muted\">Add your own roles (for example Staging), say whether <i>Production only</i> keeps them and whether they count as a DR copy, and add your own guess words. Built-in words only: prod, prd, production, dr, drc, cob, bcp, backup, bkp, failover, recovery, disaster, lab, test, tst, qa, uat, dev, stage, stg, preprod (plus <i>primary</i> / <i>secondary</i> in stack and device-group names).</p>";
  h += '<table class="data" id="roles-defs"><thead><tr><th>Role</th><th>Kept by Production only</th><th>DR copy target</th><th>Extra words (comma separated)</th><th></th></tr></thead><tbody>' + defs.map((r) => { const custom = P.roles.some((x) => x.id === r.id); return "<tr><td><b>" + esc(r.label) + "</b></td><td>" + (custom ? '<input type="checkbox" data-rfocus="' + esc(r.id) + '"' + (r.focus ? " checked" : "") + ">" : r.focus ? "yes" : "no") + "</td><td>" + (custom ? '<input type="checkbox" data-rmirror="' + esc(r.id) + '"' + (r.mirror ? " checked" : "") + ">" : r.mirror ? "yes" : "no") + '</td><td><input class="sm" data-rwords="' + esc(r.id) + '" value="' + esc((P.tokens[r.id] || []).join(", ")) + '" placeholder="none"></td><td>' + (custom ? '<button type="button" class="sm" data-rdel="' + esc(r.id) + '">Remove</button>' : "") + "</td></tr>"; }).join("") + "</tbody></table>";
  h += '<div class="ctl"><input id="role-new" placeholder="New role name, e.g. Staging"><label><input type="checkbox" id="role-new-focus"> keep in Production only</label><label><input type="checkbox" id="role-new-mirror"> is a DR copy</label><button type="button" class="sm" id="role-add">Add role</button></div>';
  h += '<h4>DR copy advice</h4><label><input type="checkbox" id="mirror-on"' + (P.mirror.enabled ? " checked" : "") + '> When a plan adds rules on production firewalls, list the DR firewalls that probably need the same change (advice only; DR firewalls are never traced).</label></details>';
  h += '<div class="ctl" style="margin-top:12px"><button type="button" class="sm" id="roles-export">Export roles JSON</button><label class="btn sm" for="roles-import">Import roles JSON</label><input type="file" id="roles-import" accept=".json,application/json" hidden><button type="button" class="sm" id="roles-reset">Reset to guesses</button><span class="muted">Saved in this browser. The same file works with PAAT\'s <code>--roles</code> option.</span></div>';
  h += '<p class="muted" id="roles-msg"></p>';
  body.innerHTML = h;
  const set = (obj, k, v) => { if (v) obj[k] = v; else delete obj[k]; };
  const syncRule = (i) => {
    const field = body.querySelector("[data-rfield=\"" + i + "\"]");
    const match = body.querySelector("[data-rmatch=\"" + i + "\"]");
    const value = body.querySelector("[data-rvalue=\"" + i + "\"]");
    const role = body.querySelector("[data-rrole=\"" + i + "\"]");
    if (!field) return;
    P.rules[i] = { field: field.value, match: match.value, value: value.value, role: role.value };
  };
  $$("[data-rfield], [data-rmatch], [data-rrole]", body).forEach((s) => s.addEventListener("change", () => { syncRule(Number(s.dataset.rfield || s.dataset.rmatch || s.dataset.rrole)); saveProfile(); }));
  $$("[data-rvalue]", body).forEach((i) => i.addEventListener("input", () => { syncRule(Number(i.dataset.rvalue)); saveProfile({ silent: true }); }));
  $$("[data-rup]", body).forEach((b) => b.addEventListener("click", () => { const i = Number(b.dataset.rup); if (i < 1) return; const x = P.rules[i - 1]; P.rules[i - 1] = P.rules[i]; P.rules[i] = x; saveProfile(); }));
  $$("[data-rdown]", body).forEach((b) => b.addEventListener("click", () => { const i = Number(b.dataset.rdown); if (i >= P.rules.length - 1) return; const x = P.rules[i + 1]; P.rules[i + 1] = P.rules[i]; P.rules[i] = x; saveProfile(); }));
  $$("[data-rremove]", body).forEach((b) => b.addEventListener("click", () => { P.rules.splice(Number(b.dataset.rremove), 1); saveProfile(); }));
  $("#rule-add").addEventListener("click", () => { P.rules.push({ field: "stack", match: "contains", value: "", role: "dr" }); saveProfile({ silent: true }); const last = $("#rvalue-" + (P.rules.length - 1)); if (last) last.focus(); });
  $$("[data-site]", body).forEach((s) => s.addEventListener("change", () => { set(P.sites, s.dataset.site, s.value); saveProfile(); }));
  $$("[data-fw]", body).forEach((s) => s.addEventListener("change", () => { set(P.devices, s.dataset.fw, s.value); saveProfile(); }));
  $$("[data-incl]", body).forEach((c) => c.addEventListener("change", () => { const a = new Set(P.scope.sites); c.checked ? a.add(c.dataset.incl) : a.delete(c.dataset.incl); P.scope.sites = [...a]; saveProfile(); }));
  $$("[data-rfocus]", body).forEach((c) => c.addEventListener("change", () => { P.roles.find((r) => r.id === c.dataset.rfocus).focus = c.checked; saveProfile(); }));
  $$("[data-rmirror]", body).forEach((c) => c.addEventListener("change", () => { P.roles.find((r) => r.id === c.dataset.rmirror).mirror = c.checked; saveProfile(); }));
  $$("[data-rwords]", body).forEach((i) => i.addEventListener("change", () => { const ws = i.value.split(/[,\s]+/).map((w) => w.toLowerCase().trim()).filter((w) => /^[a-z0-9]{1,24}$/.test(w)); if (ws.length) P.tokens[i.dataset.rwords] = ws; else delete P.tokens[i.dataset.rwords]; saveProfile(); }));
  $$("[data-rdel]", body).forEach((b) => b.addEventListener("click", () => { const id = b.dataset.rdel; P.roles = P.roles.filter((r) => r.id !== id); for (const m of [P.sites, P.devices]) for (const k of Object.keys(m)) if (m[k] === id) delete m[k]; delete P.tokens[id]; state.profile = FM.normalizeProfile(P); saveProfile(); }));
  $("#role-add").addEventListener("click", () => { const name = $("#role-new").value.trim(); if (!name) return; const id = name.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, ""); if (!id || FM.ROLE_DEFS.some((r) => r.id === id) || P.roles.some((r) => r.id === id)) { $("#roles-msg").textContent = "That role name is taken."; return; } P.roles.push({ id, label: name, focus: $("#role-new-focus").checked, mirror: $("#role-new-mirror").checked }); saveProfile(); });
  $("#mirror-on").addEventListener("change", (e) => { P.mirror.enabled = e.target.checked; saveProfile(); });
  const restore = (el) => { if (!el) return; el.focus(); if (el.setSelectionRange && el.value != null) try { el.setSelectionRange(focusPos, focusPos); } catch (err) {} };
  $("#roles-q").addEventListener("input", () => { renderRolesPanel(); restore($("#roles-q")); });
  $("#roles-rolef").addEventListener("change", () => renderRolesPanel());
  $("#roles-bulk-set").addEventListener("click", () => {
    const role = $("#roles-bulk-role").value; if (!role) { $("#roles-msg").textContent = "Choose a role to apply to the shown firewalls."; return; }
    fws.forEach((d) => { const m = M.byDev.get(d); if (m && m.key) P.devices[m.key] = role; });
    $("#roles-msg").textContent = "Set " + fws.length + " firewall" + (fws.length === 1 ? "" : "s") + " to " + roleLabel(role) + ".";
    saveProfile();
  });
  $("#roles-bulk-clear").addEventListener("click", () => {
    fws.forEach((d) => { const m = M.byDev.get(d); if (m && m.key) delete P.devices[m.key]; });
    $("#roles-msg").textContent = "Cleared per-firewall overrides on " + fws.length + " shown firewall" + (fws.length === 1 ? "" : "s") + ".";
    saveProfile();
  });
  $("#roles-export").addEventListener("click", () => download("flowmapper-site-roles-" + stamp() + ".json", new Blob([JSON.stringify(state.profile, null, 2)], { type: "application/json" })));
  $("#roles-reset").addEventListener("click", () => { state.profile = FM.defaultProfile(); saveProfile(); });
  $("#roles-import").addEventListener("change", (e) => { const f = e.target.files && e.target.files[0]; e.target.value = ""; if (!f) return; f.text().then((t) => { try { state.profile = FM.normalizeProfile(JSON.parse(t)); saveProfile(); $("#roles-msg").textContent = "Imported " + f.name + "."; } catch (er) { $("#roles-msg").textContent = "Could not read " + f.name + ": " + er.message; } }); });
  if (focusId) restore(document.getElementById(focusId));
  refreshView._inRoles = false;
}

/* Result-page callouts: a hidden firewall the path needs, and the DR copy advice. */
function scopeNoteHtml(r) {
  const v = r.scope && r.scope.viaHidden; if (!v) return "";
  return '<div class="note warn" id="scope-via"><b>Needs a firewall outside the scope.</b> ' + esc(v.text) + ' <button type="button" class="sm" data-scope-all="1">Show all sites</button></div>';
}
function mirrorHtml(r, forTicket) {
  const m = r && r.drMirror; if (!m || !m.enabled || !m.items.length) return "";
  const rows = m.items.map((it) => "<li><b>" + esc(it.display) + "</b>: " + esc(it.changes.join("; ")) + (it.candidates.length ? "<ul>" + it.candidates.map((c) => "<li><b>" + esc(c.display) + "</b> (" + esc(roleLabel(c.role)) + ") &mdash; " + (c.level === "automatic" ? "<b>reached automatically</b>: shares a device group, so a rule pushed to that group already applies" : c.level === "likely" ? "<b>DR copy likely needed</b>" : "DR copy possibly needed") + ' <span class="muted">(' + esc(c.reasons.join("; ")) + ")</span>" + (c.addrNote ? ' <span class="muted">' + esc(c.addrNote) + "</span>" : "") + "</li>").join("") + "</ul>" : ' <span class="muted">' + esc(it.note || "") + "</span>") + "</li>").join("");
  return '<div class="warnbox' + (forTicket ? "" : " card") + '" id="dr-mirror" role="note" style="border-left:6px solid #b7791f;padding:6px 10px;margin:8px 0;background:#fff6dc;color:#1b2430"><b>DR copy likely needed?</b> ' + esc(m.text) + '<ul style="margin:6px 0 0 18px">' + rows + "</ul></div>";
}
function panoPairHtml() {
  const pf = panoFile(); if (!pf) return "";
  const pr = FM.panoramaPair(pf.loaded.panorama, state.profile), P = state.profile;
  const row = (e, title) => "<tr><td><b>" + esc(title) + "</b><br><span class=\"muted\">" + esc(e.name) + "</span></td><td>" + roleSelect('data-panrole="' + esc(e.key) + '"', (P.panoramas[e.key] || {}).role || "", e.role ? "Auto: " + roleLabel(e.role) : "(not set)") + '</td><td><select class="sm" data-panstate="' + esc(e.key) + '"><option value="">(unknown)</option><option value="active"' + (e.state === "active" ? " selected" : "") + '>Active</option><option value="passive"' + (e.state === "passive" ? " selected" : "") + '>Passive</option></select></td><td class="muted">' + esc(e.roleWhy) + "</td></tr>";
  const ha = pr.ha;
  return '<div class="card" id="pano-ha"><h2 style="margin:0 0 6px">Panorama HA pair</h2><p class="muted">' + esc(pr.note) + "</p>" +
    (ha ? '<p class="muted">This export: <b>' + esc(pr.hostname) + "</b>, HA " + (ha.enabled === false ? "disabled" : "enabled") + (ha.priority ? ", configured priority <b>" + esc(ha.priority) + "</b>" : "") + (ha.ownIp ? ", HA1 " + esc(ha.ownIp) : "") + (ha.peerIp ? ", peer " + esc(ha.peerIp) : "") + ".</p>" : '<p class="muted">This export has no Panorama HA settings (a single Panorama, or HA is not in the export).</p>') +
    '<table class="data"><thead><tr><th>Panorama</th><th>Role</th><th>State now</th><th>Why</th></tr></thead><tbody>' + row(pr.this, "This export") + (pr.peer ? row(pr.peer, "HA peer") : "") + "</tbody></table></div>";
}
function bindPanoPair(box) {
  const P = state.profile;
  $$("[data-panrole]", box).forEach((s) => s.addEventListener("change", () => { const k = s.dataset.panrole; P.panoramas[k] = Object.assign({}, P.panoramas[k], { role: s.value || undefined }); if (!s.value) delete P.panoramas[k].role; try { localStorage.setItem(ROLES_KEY, JSON.stringify(P)); } catch (e) {} ENV.pkey = null; renderEnv(); }));
  $$("[data-panstate]", box).forEach((s) => s.addEventListener("change", () => { const k = s.dataset.panstate; P.panoramas[k] = Object.assign({}, P.panoramas[k], { state: s.value || undefined }); if (!s.value) delete P.panoramas[k].state; try { localStorage.setItem(ROLES_KEY, JSON.stringify(P)); } catch (e) {} renderEnv(); }));
}

/* ---------------- tabs ---------------- */
function showTab(name) {
  $$(".tab").forEach((t) => (t.hidden = t.id !== "tab-" + name));
  $$("#tabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === name));
  if (name === "topo") renderTopo();
  if (name === "map") renderMap();
  if (name === "env") renderEnv();
  if (name === "raw") renderRaw();
}
$$("#tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));

/* ---------------- trace ---------------- */
const NOINTRA_KEY = "pan-flowmapper-ignore-intrazone-default";
try { $("#q-nointra").checked = localStorage.getItem(NOINTRA_KEY) === "1"; } catch (e) {}
$("#q-nointra").addEventListener("change", () => { try { localStorage.setItem(NOINTRA_KEY, $("#q-nointra").checked ? "1" : "0"); } catch (e) {} if (state.last && state.last.query && state.last.query.src) runTrace(null, true); });
$("#qform").addEventListener("submit", (e) => { e.preventDefault(); state.choices = {}; state.pathIndex = 0; runTrace(); });
function applyFcrRow(row) {
  state.fcrTicket = row.ticket || null;
  $("#q-src").value = row.src || "";
  $("#q-dst").value = row.dst || "";
  $("#q-proto").value = ["tcp", "udp", "icmp", "any"].includes(row.proto) ? row.proto : "tcp";
  $("#q-port").value = row.port == null ? "" : row.port;
}
function renderFcrBatch(parsed, results) {
  const box = $("#fcr-batch");
  if (!parsed) { box.innerHTML = ""; $("#fcr-count").textContent = ""; return; }
  const n = parsed.rows.length, err = parsed.errors.length;
  $("#fcr-count").textContent = n ? "(" + n + " flow" + (n === 1 ? "" : "s") + (err ? ", " + err + " unparsed" : "") + ")" : (err ? "(" + err + " unparsed)" : "");
  let h = state.view ? '<p class="muted" id="fcr-scope">' + esc(state.view.chip) + ". Every flow below is traced inside this scope.</p>" : "";
  if (err) h += parsed.errors.map((e) => '<div class="note warn">' + esc(e.error) + "</div>").join("");
  if (results && results.length) {
    h += '<div class="tblwrap"><table class="data glance"><thead><tr><th>#</th><th>Flow</th><th>Ticket</th><th>Hops</th><th>Denies</th><th>Places</th><th>Status</th><th></th></tr></thead><tbody>' + results.map((x, i) => {
      const r = x.res, hops = r && r.fcr ? r.fcr.hops.length : (r && r.segments ? r.segments.length : 0);
      const den = r && r.fcr ? r.fcr.hops.filter((z) => z.deny).length : 0, en = r && r.fcr && r.fcr.enforcement;
      return "<tr><td>" + (i + 1) + "</td><td>" + esc(x.row.src + " → " + x.row.dst + " " + (x.row.proto || "tcp") + (x.row.port != null ? "/" + x.row.port : "")) + "</td><td>" + esc(x.row.ticket || "") + "</td><td>" + hops + "</td><td" + (den ? ' class="bad"' : "") + ">" + den + "</td>" + (en && en.multi ? "<td" + (en.needRule ? ' class="bad"' : "") + ' title="' + esc(en.text) + '">' + en.points + " places" + (en.needRule ? ", " + en.needRule + " need a rule" : ", all allowed") + "</td>" : "<td>1</td>") + "<td>" + esc(r ? r.status : "error") + (r && r.scope && r.scope.viaHidden ? ' <span class="pill y" title="' + esc(r.scope.viaHidden.text) + '">needs hidden firewall</span>' : "") + (r && r.drMirror && r.drMirror.items.length ? ' <span class="pill y" title="' + esc(r.drMirror.text) + '">DR copy?</span>' : "") + '</td><td><button type="button" class="sm" data-fcrrow="' + i + '">Show</button></td></tr>';
    }).join("") + "</tbody></table></div>";
  }
  box.innerHTML = h;
  $$("[data-fcrrow]", box).forEach((b) => b.addEventListener("click", () => {
    const x = results[Number(b.dataset.fcrrow)]; if (!x) return;
    applyFcrRow(x.row); state.choices = {}; state.pathIndex = 0; runTrace();
  }));
}
function runFcr() {
  const parsed = FM.parseFcr($("#fcr-text").value);
  $("#fcr-status").textContent = parsed.rows.length ? parsed.rows.length + " flow" + (parsed.rows.length === 1 ? "" : "s") + " parsed" : "nothing parsed";
  if (!parsed.rows.length) { renderFcrBatch(parsed, []); return; }
  if (!state.devices.length) { flash("Load a config first."); renderFcrBatch(parsed, []); return; }
  const rows = parsed.rows.slice(0, 50);
  if (parsed.rows.length > 50) parsed.errors = parsed.errors.concat([{ error: "Only the first 50 rows were traced (" + parsed.rows.length + " in the paste)." }]);
  if (rows.length === 1) {
    applyFcrRow(rows[0]); state.choices = {}; state.pathIndex = 0;
    const res = runTrace();
    renderFcrBatch(parsed, res ? [{ row: rows[0], res }] : []);
    return;
  }
  const results = [];
  for (const row of rows) {
    applyFcrRow(row); state.choices = {}; state.pathIndex = 0;
    results.push({ row, res: runTrace() });
  }
  renderFcrBatch(parsed, results);
  const last = results[results.length - 1];
  if (last && last.res) { applyFcrRow(last.row); renderResult(last.res); }
  showTab("trace");
}
$("#fcr-run").addEventListener("click", runFcr);
$("#fcr-file").addEventListener("change", (e) => {
  const f = e.target.files && e.target.files[0]; e.target.value = "";
  if (!f) return;
  f.text().then((t) => { $("#fcr-text").value = t; $("#fcr-box").open = true; runFcr(); });
});
$("#btn-swap").addEventListener("click", () => { const a = $("#q-src").value; $("#q-src").value = $("#q-dst").value; $("#q-dst").value = a; $("#q-ing").value = ""; });
function runTrace(q, keepChoices) {
  if (q && !keepChoices) { state.choices = {}; state.pathIndex = 0; }
  if (q) { $("#q-src").value = q.src || ""; $("#q-dst").value = q.dst || ""; $("#q-proto").value = q.proto || "tcp"; $("#q-port").value = q.port == null ? "" : q.port; if (q.deviceId != null) { $("#q-dev").value = q.deviceId; fillIngress(); } if (q.ingress != null) $("#q-ing").value = q.ingress; if (q.dstDeviceId != null) $("#q-ddev").value = q.dstDeviceId; if (q.via != null) $("#q-via").value = q.via; }
  if (!state.devices.length) { flash("Load a config first."); return null; }
  const t0 = performance.now();
  const tq = { src: $("#q-src").value, dst: $("#q-dst").value, proto: $("#q-proto").value, port: $("#q-port").value };
  const topts = { srcDevice: $("#q-dev").value || null, ingress: $("#q-ing").value || null, dstDevice: $("#q-ddev").value || null,
    via: $("#q-via").value.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean), pathIndex: state.pathIndex, choices: state.choices, links: state.links, circuits: state.circuits, ignoreIntrazoneDefault: $("#q-nointra").checked, __pathStatusThrow: !!state.__psThrow };
  const res = FM.trace(V(), tq, topts);
  FM.attachScope(res, state.view, tq, topts, true);
  res.ms = Math.round(performance.now() - t0);
  FM.annotateFcr(res, V());
  res.drMirror = FM.drMirror(res, state.devices, state.profile);
  if (state.fcrTicket) res.fcrTicket = state.fcrTicket;
  state.last = res;
  renderResult(res);
  if (ENV && ENV.mode === "vsys") { ENV.key = null; renderEnv(); }
  showTab("trace");
  return res;
}
const STATUS = {
  delivered: ["s-g", "Reaches the destination"], exits: ["s-g", "Leaves the firewall toward the destination"], local: ["s-g", "Terminates on the firewall"],
  "needs-changes": ["s-r", "Changes needed"], "no-route": ["s-r", "No route"], dropped: ["s-r", "Dropped"], loop: ["s-r", "Routing loop"], unresolved: ["s-y", "Cannot resolve"], error: ["s-r", "Trace failed"],
};
function pathStatusHtml(r) {
  const P = r.pathStatus; if (!P) return "";
  if (P.status === "error") return '<div id="path-status" class="ps-incomplete" data-status="error"><h3>Path status unavailable <span class="pill r">check</span></h3><div>' + esc(P.text) + "</div></div>";
  const head = { complete: ["Complete path", "g", "every hop is an explicit route, link or map entry"], suggested: ["Suggested path", "y", "some hops are guesses about routers or routes outside the loaded configs"], incomplete: ["Incomplete path", "r", "the trace stopped before the destination"] }[P.status];
  const choice = P.stop && P.stop.choice;
  if (choice) { head[0] = "Needs your choice"; head[2] = "the same address is configured on several firewalls; pick the right one"; }
  else if (P.label) head[0] = P.label.replace(/^Complete/, "Complete path").replace(/^Suggested(?! \()/, "Suggested path").replace(/^Incomplete/, "Incomplete path");
  let h = '<div id="path-status" class="ps-' + P.status + (choice ? " ps-choice" : "") + '" data-status="' + P.status + '" data-label="' + esc(P.label || "") + '"><h3>' + esc(head[0]) + ' <span class="pill ' + head[1] + '">' + esc(P.confidence) + " confidence</span></h3><div>" + esc(P.text) + ' <span class="muted">(' + esc(head[2]) + ")</span></div>";
  h += choicesHtml(P.choices || []);
  if (P.stop && !choice) h += '<div class="ps-stop"><b>Stopped at:</b> ' + esc(P.stop.where ? DL(P.stop.where.split(" ")[0]) + P.stop.where.slice(P.stop.where.split(" ")[0].length) : "the source") + "<br><b>Why:</b> " + esc(P.stop.why) + "<br><b>To finish it:</b> " + esc(P.stop.fix) + (P.stop.noNetwork && P.stop.noNetwork.length ? ' <button type="button" class="sm" id="ps-nonet">Show firewalls without network config</button>' : "") + "</div>";
  const as = P.hops.flatMap((x) => x.assumptions.map((a) => ({ dev: x.device, vsys: x.vsys, a })));
  if (as.length) h += '<div><b>Assumed on this path:</b><ul class="ps-assume">' + as.map((x) => "<li><b>" + esc(DL(x.dev)) + " " + esc(x.vsys) + ":</b> " + esc(x.a.what) + ' <span class="muted">Confirm: ' + esc(x.a.confirm) + "</span></li>").join("") + "</ul></div>";
  if (P.weak && P.stronger) h += '<div class="note warn" id="ps-weak">This path is weak (' + esc((r.plan.paths[r.plan.chosen] || {}).routing === "contradicts" ? "it contradicts routing" : "low confidence") + "). A stronger option exists: " + esc(DLs(P.stronger.devices)) + " (" + esc(P.stronger.confidence) + ").</div>";
  if (P.alternates.length) h += '<div><b>Other possible paths</b> <span class="muted">(click one to trace it; the path above stays the routing choice until you do)</span><ul class="ps-alts">' + P.alternates.map((a) => '<li><button type="button" class="sm"' + (a.kind === "path" ? ' data-altpath="' + a.index + '"' : ' data-altbranch="' + esc(a.key + "|" + a.devId) + '"') + ' title="' + esc(a.why) + '">' + esc(a.devices.join(" \u2192 ")) + (a.confidence ? " \u00b7 " + esc(a.confidence) : "") + '</button> <span class="muted">' + esc(a.why) + "</span>" +
    (a.offered ? '<div class="ps-alt-why"><b>Why offered:</b> ' + esc(a.offered) + "</div>" : "") + (a.differs ? '<div class="ps-alt-why"><b>Differs:</b> ' + esc(a.differs) + "</div>" : "") + (a.toComplete ? '<div class="ps-alt-why"><b>To make it complete:</b> ' + esc(a.toComplete) + "</div>" : "") + "</li>").join("") + "</ul>" + (P.moreAlternates ? '<div class="muted">+' + P.moreAlternates + " more in the path list below</div>" : "") + "</div>";
  return h + "</div>";
}
/* Shared-address picker: every candidate with hostname, serial, stack, site and why it fits. Never chosen silently. */
function choicesHtml(list) {
  if (!list.length) return "";
  return '<div id="ps-choices">' + list.map((c, ci) => '<div class="choice' + (c.pinned ? " pinned" : "") + '" data-ckind="' + esc(c.kind) + '"><b>' + (c.pinned ? "Pinned" : "Pick one") + ": " + esc(c.what) + "</b> at " + esc(c.at) + '<div class="muted">' + esc(c.reason) + (c.pinned ? " Using " + esc(DL(c.chosen)) + " (" + esc(c.pinBy) + ")." : " The path below goes to " + esc(DL(c.chosen)) + " only as a placeholder.") + '</div><table class="data choice-tbl"><thead><tr><th>Firewall</th><th>Serial</th><th>Template stack</th><th>Site</th><th>Why it fits</th><th></th></tr></thead><tbody>' +
    c.candidates.map((x) => "<tr" + (x.device === c.chosen ? ' class="cur"' : "") + "><td><b>" + esc(x.hostname || x.device) + "</b></td><td data-nolabel>" + esc(x.serial || "") + "</td><td>" + esc(x.stack || "") + "</td><td>" + esc(x.site || "") + "</td><td>" + esc(x.reason || "") + '</td><td class="nowrap"><button type="button" class="sm primary" data-pick="' + ci + "|" + esc(x.devId) + '" title="Use this firewall for this trace only">Use for this trace</button>' +
      (c.kind === "next-hop" ? ' <button type="button" class="sm" data-picklink="' + ci + "|" + esc(x.devId) + '" title="Save a link so every trace from ' + esc(c.at) + ' goes to this firewall">Save as link</button>' : "") + "</td></tr>").join("") + "</tbody></table></div>").join("") + "</div>";
}
function bindChoices(box, r) {
  const list = (r.pathStatus && r.pathStatus.choices) || [];
  const get = (v) => { const [i, id] = v.split("|"); return { c: list[Number(i)], id: v.slice(i.length + 1) }; };
  $$("[data-pick]", box).forEach((b) => b.addEventListener("click", () => {
    const { c, id } = get(b.dataset.pick); if (!c) return;
    if (c.kind === "next-hop") state.choices[c.key] = id;
    else if (c.kind === "destination") $("#q-ddev").value = id;
    else { $("#q-dev").value = id; fillIngress(); }
    state.pathIndex = 0; runTrace(null, true);
  }));
  $$("[data-picklink]", box).forEach((b) => b.addEventListener("click", () => {
    const { c, id } = get(b.dataset.picklink); if (!c) return;
    const to = c.candidates.find((x) => x.devId === id);
    const eg = c.link && c.link.from && c.link.from.iface;
    state.links = state.links.filter((l) => !(l.from && l.from.device === c.from && l.from.iface === eg));
    state.links.push({ from: { device: c.from, iface: eg || null, nexthop: eg ? null : (c.link.from.nexthop || null) }, to: { device: to ? to.device : id, iface: to ? to.iface : null }, label: "shared " + c.what });
    saveLinks(); state.pathIndex = 0; runTrace(null, true);
  }));
}
function renderResult(r) {
  const box = $("#result");
  let [cls, title] = STATUS[r.status] || ["s-y", r.status];
  if (cls === "s-g" && r.conditional) { cls = "s-y"; title += " (only under conditions)"; }
  if (cls === "s-g" && r.blocked) { cls = "s-r"; title = "Blocked by policy"; }
  let h = '<div class="status ' + cls + '" id="status">' + esc(title) + (r.query.src ? ": " + esc(r.query.src) + " &rarr; " + esc(r.query.dst) + " " + esc(r.query.svc) : "") + "<small>" + esc(r.summary || "") + (r.ms != null ? " &middot; " + r.ms + " ms" : "") + "</small></div>";
  h += scopeNoteHtml(r);
  h += pathStatusHtml(r);
  h += ambHtml(r);
  h += multiPlaceHtml(r);
  h += mirrorHtml(r);
  h += glanceHtml(r);
  h += fcrHtml(r);
  h += conflictHtml(r, "conflict");
  if (r.circuit) { const c = r.circuit; h += '<div class="note ' + (c.conflict ? "warn" : "info") + '" id="circ-note"><b>' + (c.source === "map" ? "Public-space map" : "Provider static") + ":</b> " + esc(c.prefix + (c.circuit ? " via " + c.circuit : "") + " enters at " + c.device + " " + c.iface + (c.zone ? " (zone " + c.zone + ")" : "")) + " " + (c.conflict ? '<span class="pill r">disagrees with routing</span>' : c.source === "map" ? '<span class="pill g">' + (c.agreesWithRouting ? "routing agrees" : "confirmed by provider static") + "</span>" : '<span class="pill b">from a more-specific static</span> <button class="sm" id="circ-accept">Add to map</button>') + "</div>"; }
  if (r.noRuleInExport) h += '<div class="note warn" id="norule-note"><b>No rule in this export allows this flow.</b> It is denied on the path found (at ' + esc(DLs(r.noRuleInExport.devices)) + '). If it works in production, the allow is probably in rules local to a firewall (load that firewall\'s own backup alongside the Panorama export) or the traffic enters through a different circuit (add its prefix to the <a href="#circ-box" id="norule-map">public-space map</a>).</div>';
  const topNotes = r.notes.filter((n) => (n.level !== "info" || !r.segments.length) && !(r.noRuleInExport && /^Denied on the path found/.test(n.text)));
  if (topNotes.length) h += topNotes.map((n) => '<div class="note ' + n.level + '">' + esc(n.text) + "</div>").join("");
  if (r.segments.length) {
    h += '<div class="card"><div class="ctl"><h2 style="margin:0;flex:1">Flow diagram</h2><button id="dl-svg">Export SVG</button><button id="dl-png">Export PNG</button></div><div class="svgwrap" id="flowsvg">' + flowSvg(r) + "</div>" +
      (r.ingress ? '<p class="muted">Source firewall: <b>' + esc(DL(r.ingress.device)) + "</b> " + esc(r.ingress.iface + " - " + r.ingress.how) + (r.dstFirewalls && r.dstFirewalls.length ? " &middot; Destination is connected behind: <b>" + esc(r.dstFirewalls.map((f) => DL(f.device) + " " + f.iface + (f.vsys && f.vsys !== "vsys1" ? " (" + f.vsys + ")" : "")).join(", ")) + "</b>" : "") + "</p>" : "") +
      chainHtml(r) + basisHtml(r) + "</div>";
    h += changesHtml(r);
    h += checksHtml(r);
    h += hopsHtml(r);
    const info = r.notes.filter((n) => n.level === "info");
    if (info.length && r.segments.length) h += '<div class="card"><h2>Notes</h2>' + info.map((n) => '<div class="note info">' + esc(n.text) + "</div>").join("") + "</div>";
  }
  box.innerHTML = h;
  const ca = $("#circ-accept", box); if (ca) ca.addEventListener("click", () => { const c = r.circuit; state.circuits.push({ prefix: c.prefix, circuit: c.circuit || "", device: c.device, iface: c.iface, zone: null }); saveCircuits(); runTrace(null, true); });
  const nm = $("#norule-map", box); if (nm) nm.addEventListener("click", () => { $("#circ-box").open = true; });
  $$("select[data-branch]", box).forEach((sel) => sel.addEventListener("change", () => { const o = sel.selectedOptions[0]; if (o && o.dataset.path) { state.pathIndex = Number(o.dataset.path); state.choices = {}; } else { state.choices[sel.dataset.branch] = sel.value; state.pathIndex = 0; } runTrace(null, true); }));
  $$("input[data-path]", box).forEach((rb) => rb.addEventListener("change", () => { state.pathIndex = Number(rb.dataset.path); state.choices = {}; runTrace(null, true); }));
  $$("[data-altpath]", box).forEach((b) => b.addEventListener("click", () => { state.choices = {}; state.pathIndex = Number(b.dataset.altpath); runTrace(null, true); }));
  const pn = $("#ps-nonet", box); if (pn) pn.addEventListener("click", () => { const l = $("#nonet-list"); if (l) { l.open = true; $("#nonet-callout").scrollIntoView({ behavior: "smooth", block: "center" }); } });
  bindChoices(box, r);
  $$("[data-scope-all]", box).forEach((b) => b.addEventListener("click", () => { state.profile.scope.mode = "all"; saveProfile(); }));
  $$("[data-altbranch]", box).forEach((b) => b.addEventListener("click", () => { const [k, id] = b.dataset.altbranch.split("|"); state.choices[k] = id; state.pathIndex = 0; runTrace(null, true); }));
  $$("[data-routingpath]", box).forEach((b) => b.addEventListener("click", () => { state.choices = {}; state.pathIndex = 0; runTrace(null, true); }));
  $$("[data-pin]", box).forEach((b) => b.addEventListener("click", () => { const [k, id] = b.dataset.pin.split("|"); $(k === "src" ? "#q-dev" : "#q-ddev").value = id; if (k === "src") fillIngress(); state.pathIndex = 0; runTrace(null, true); }));
  if (r.segments.length) {
    $("#dl-svg").addEventListener("click", () => exportSvg($("#flowsvg svg"), "flow"));
    $("#dl-png").addEventListener("click", () => exportPng($("#flowsvg svg"), "flow"));
  }
  if ($("#exp-html", box)) $("#exp-html", box).addEventListener("click", () => download("flow-change-" + stamp() + ".html", new Blob([labelSerials(ticketHtml(withSelectedChanges(r, box)))], { type: "text/html" })));
  if ($("#exp-csv", box)) $("#exp-csv", box).addEventListener("click", () => download("flow-change-" + stamp() + ".csv", new Blob([labelSerials(ticketCsv(withSelectedChanges(r, box)))], { type: "text/csv" })));
  $$("[data-copy]", box).forEach((b) => b.addEventListener("click", () => {
    const all = b.dataset.copy === "all" || b.dataset.copy === "selected";
    const rows = (all ? selectedChanges(r, box) : [r.changes[Number(b.dataset.copy)]]).filter(Boolean);
    if (!rows.length) { flash("Tick at least one change to copy."); return; }
    copyText(rows.map((c) => (all ? "# " + c.device + " - " + c.summary + "\n" : "") + c.cli.join("\n")).join("\n\n"), b);
  }));
  const syncChg = () => { const n = selectedChanges(r, box).length; const b = $("[data-copy=\"all\"]", box) || $("[data-copy=selected]", box); if (b && b.dataset.copy) b.textContent = n === r.changes.length ? "Copy all CLI" : "Copy selected CLI (" + n + ")"; };
  $$("input[data-chg]", box).forEach((el) => el.addEventListener("change", syncChg));
  const sa = $("#chg-all", box), sn = $("#chg-none", box);
  if (sa) sa.addEventListener("click", () => { $$("input[data-chg]", box).forEach((el) => { el.checked = true; }); syncChg(); });
  if (sn) sn.addEventListener("click", () => { $$("input[data-chg]", box).forEach((el) => { el.checked = false; }); syncChg(); });
  $$("[data-copyfilter]", box).forEach((b) => b.addEventListener("click", () => { const f = r.fcr && r.fcr.filters.hops[Number(b.dataset.copyfilter)]; if (f) copyText(f.afterPush || f.filter, b); }));
}
function copyText(t, btn) {
  const done = () => { const o = btn.textContent; btn.textContent = "Copied"; setTimeout(() => (btn.textContent = o), 1200); };
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(t).then(done, () => fallbackCopy(t, done)); else fallbackCopy(t, done);
}
function fallbackCopy(t, done) { const ta = document.createElement("textarea"); ta.value = t; document.body.appendChild(ta); ta.select(); try { document.execCommand("copy"); } catch (e) {} ta.remove(); done(); }
/* Planned changes the user has ticked in the change plan (all ticked by default). */
function selectedChanges(r, box) {
  const root = box || document;
  const boxes = $$("input[data-chg]", root);
  if (!boxes.length) return r.changes.slice();
  return [...boxes].filter((el) => el.checked).map((el) => r.changes[Number(el.dataset.chg)]).filter(Boolean);
}
function withSelectedChanges(r, box) {
  const sel = selectedChanges(r, box);
  const copy = Object.assign({}, r, { changes: sel });
  if (sel.length !== r.changes.length) copy.exportNote = "Exported " + sel.length + " of " + r.changes.length + " planned changes (the rest were left unticked).";
  return copy;
}
/* One line per firewall/vsys on the path: does an existing rule allow it, and what has to change there. */
function glanceRows(r) {
  const rows = [], seen = new Set();
  for (const sg of r.segments) {
    const k = sg.device + "|" + sg.vsys; if (seen.has(k)) continue; seen.add(k);
    const ch = r.changes.filter((c) => c.device === sg.device && (c.vsys === sg.vsys || !c.vsys));
    const c = sg.check;
    const policy = !c ? "no policy check" : c.action === "allow" && c.verdict !== "conditional" ? "allowed by " + c.rule : c.verdict === "conditional" ? "conditional (" + c.rule + ")" : "blocked (" + c.rule + ")";
    rows.push({ device: sg.device, vsys: sg.vsys, display: sg.display, inZone: sg.ingress && sg.ingress.zone, outZone: sg.egress && sg.egress.zone, policy, ok: !!c && c.action === "allow" && c.verdict !== "conditional", basis: sg.basis ? sg.basis.text : "", changes: ch });
  }
  // changes on firewalls not in the path (return routes, other vsys)
  for (const c of r.changes) if (!rows.some((x) => x.device === c.device && (x.vsys === c.vsys || !c.vsys))) { let x = rows.find((y) => y.device === c.device && y.vsys === c.vsys && y.extra); if (!x) { x = { device: c.device, vsys: c.vsys, extra: true, policy: "", changes: [] }; rows.push(x); } x.changes.push(c); }
  return rows;
}
function changeShort(c) {
  if (c.kind === "security" && c.rule) return (c.optional ? "Verify/add rule " : "Add rule ") + c.rule.from + " \u2192 " + c.rule.to + ", " + c.rule.source + " \u2192 " + c.rule.destination + " " + c.rule.service + (c.modify ? " (or add " + c.modify.field + " to " + c.modify.rule + ")" : "");
  return c.summary;
}
function glanceHtml(r) {
  if (!r.segments.length && !r.changes.length) return "";
  const rows = glanceRows(r), req = r.changes.filter((c) => !c.optional).length;
  let h = '<div class="card" id="glance"><div class="ctl"><h2 style="margin:0;flex:1">' + (req ? req + " change" + (req > 1 ? "s" : "") + " needed" : r.changes.length ? "No required changes (" + r.changes.length + " to verify)" : "No changes needed") + '</h2><button id="exp-html" title="Printable page with path, changes and CLI for a change ticket">Export for ticket (HTML)</button><button id="exp-csv">Export CSV</button></div>';
  if (r.ambiguous) h += '<div class="note warn amb-rules">' + esc(ambText(r.ambiguous) + ". " + ambRules(r.ambiguous)) + "</div>";
  h += '<table class="glance"><thead><tr><th>Firewall / vsys</th><th>Zones</th><th>Policy now</th><th>Change needed</th></tr></thead><tbody>' + rows.map((x) =>
    "<tr><td><b>" + esc(DL(x.device)) + "</b> " + esc(x.vsys || "") + (x.extra ? ' <span class="muted">(not on the forward path)</span>' : "") + "</td><td>" + esc(x.inZone ? x.inZone + " \u2192 " + (x.outZone || "?") : "") + '</td><td class="' + (x.ok ? "ok" : x.policy ? "bad" : "") + '">' + esc(x.policy) + "</td><td>" +
    (x.changes.length ? x.changes.map((c) => '<div><span class="pill ' + (c.optional ? "y" : c.kind === "security" ? "r" : "b") + '">' + esc(c.kind) + "</span> " + esc(changeShort(c)) + "</div>").join("") : '<span class="muted">none</span>') + "</td></tr>").join("") + "</tbody></table></div>";
  return h;
}
function multiPlaceHtml(r, forTicket) {
  const en = r && r.fcr && r.fcr.enforcement;
  if (!en || !(en.multi || en.assumesOutsideHop)) return "";
  const need = en.level === "need" || (en.needRule && !en.multi);
  const rows = (en.places || []).map((x) => "<li" + (x.needs ? ' class="bad"' : "") + "><b>Place " + x.n + ":</b> " + esc(DL(x.device) + " " + (x.display && x.display !== x.vsys ? x.display + " (" + x.vsys + ")" : x.vsys)) + (x.fromZone ? " (" + esc(x.fromZone + " \u2192 " + (x.toZone || "?")) + ")" : "") + (x.hairpin ? " [hairpin]" : "") + " &mdash; " + (x.needs ? "<b>needs an allow</b>" + (x.newRule ? " (new rule " + esc(x.newRule) + ")" : "") : "already allowed" + (x.rule ? " by " + esc(x.rule) : "")) + "</li>").join("");
  return '<div class="warnbox' + (forTicket ? "" : " card") + '" id="multiplace" role="alert" style="border-left:6px solid ' + (need ? "#b00020" : "#1b7f3b") + ";padding:6px 10px;margin:8px 0;background:" + (need ? "#fff1f1" : "#eefaf1") + '"><b>' + (en.multi ? ("Rule needed in more than one place" + (need ? "!" : "?")) : "Rules this flow needs") + "</b> " + esc(en.text) + (rows ? '<ol style="margin:6px 0 0 18px">' + rows + "</ol>" : "") + "</div>";
}
function csvCell(v) { v = v == null ? "" : String(v); return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
function ticketCsv(r) {
  const head = ["#", "Firewall", "vsys", "Where", "Type", "Required", "Change", "Why", "Rule name", "From zone", "To zone", "Source", "Destination", "Application", "Service", "Place before", "Rule order", "Alternative (modify existing rule)", "CLI", "Alternative CLI"];
  const lines = [head];
  r.changes.forEach((c, i) => lines.push([i + 1, DL(c.device), c.vsys || "", c.where || c.vr || "", c.kind, c.optional ? "verify" : "yes", c.summary, c.why || "", c.rule && c.rule.name, c.rule && c.rule.from, c.rule && c.rule.to, c.rule && c.rule.source, c.rule && c.rule.destination, c.rule && c.rule.application, c.rule && c.rule.service, c.rule && c.rule.placeBefore, c.order ? c.order.text : "", c.modify ? c.modify.summary.replace(/^or /, "") : "", c.cli.join("\n"), c.modify ? c.modify.cli.join("\n") : ""]));
  const meta = [["Flow", r.query.src + " -> " + r.query.dst + " " + r.query.svc], ["Result", (STATUS[r.status] || [0, r.status])[1]], ["Path", r.segments.map((x) => DL(x.device) + ":" + x.vsys).join(" > ")], ...(r.ambiguous ? [["Ambiguous", ambText(r.ambiguous) + ". " + ambRules(r.ambiguous)]] : []), ...(r.fcr && r.fcr.enforcement && r.fcr.enforcement.multi ? [["Places checked by security policy", r.fcr.enforcement.text]] : []), ["Generated", new Date().toISOString()], ...(r.exportNote ? [["Note", r.exportNote]] : []), []];
  return meta.concat(lines).map((l) => l.map(csvCell).join(",")).join("\r\n") + "\r\n";
}
function ticketHtml(r) {
  const e = esc, rows = glanceRows(r);
  const css = "body{font:13px/1.45 system-ui,Segoe UI,Arial,sans-serif;margin:24px;color:#111}h1{font-size:18px;margin:0 0 4px}h2{font-size:15px;margin:18px 0 6px;border-bottom:1px solid #ccc}table{border-collapse:collapse;width:100%;margin:6px 0}td,th{border:1px solid #bbb;padding:4px 6px;vertical-align:top;text-align:left}th{background:#eee}pre{background:#f6f6f6;border:1px solid #ddd;padding:6px;white-space:pre-wrap;font:12px Consolas,monospace;margin:4px 0}.muted{color:#666}.ok{color:#176b2c}.bad{color:#a01818}.note{border-left:3px solid #c80;padding:2px 8px;margin:4px 0}@media print{button{display:none}h2{page-break-after:avoid}.chg{page-break-inside:avoid}}";
  let h = '<!doctype html><html><head><meta charset="utf-8"><title>Flow change: ' + e(r.query.src + " -> " + r.query.dst + " " + r.query.svc) + "</title><style>" + css + "</style></head><body>";
  h += "<h1>Flow change request: " + e(r.query.src) + " \u2192 " + e(r.query.dst) + " " + e(r.query.svc) + '</h1><div class="muted">Generated ' + e(new Date().toLocaleString()) + " by PAN-OS FlowMapper " + e(FM.version) + " from the loaded configuration. Confirm on the firewalls with test security-policy-match and test routing fib-lookup before committing.</div>" + (r.exportNote ? '<div class="note">' + e(r.exportNote) + "</div>" : "");
  h += "<p><b>Result:</b> " + e((STATUS[r.status] || [0, r.status])[1]) + (r.summary ? " - " + e(r.summary) : "") + "</p>";
  if (r.ambiguous) h += '<div class="note"><b>' + e(ambText(r.ambiguous)) + ".</b> " + e(ambRules(r.ambiguous)) + "</div>";
  if (r.conflict) h += '<div class="note"><b>Routing says:</b> ' + e(r.conflict.routing) + " &nbsp; <b>Rules suggest:</b> " + e(r.conflict.rules) + ". The path below follows routing."
    + (r.conflict.scopeText ? " " + e(r.conflict.scopeText) : "") + "</div>";
  h += "<h2>Summary</h2><table><tr><th>Firewall / vsys</th><th>Zones</th><th>Policy now</th><th>Change needed</th></tr>" + rows.map((x) => "<tr><td><b>" + e(DL(x.device)) + "</b> " + e(x.vsys || "") + "</td><td>" + e(x.inZone ? x.inZone + " \u2192 " + (x.outZone || "?") : "") + '</td><td class="' + (x.ok ? "ok" : "bad") + '">' + e(x.policy || "") + "</td><td>" + (x.changes.length ? x.changes.map((c) => "<div>" + e(changeShort(c)) + "</div>").join("") : "none") + "</td></tr>").join("") + "</table>";
  if (r.segments.length) h += "<h2>Path</h2><table><tr><th>#</th><th>Firewall / vsys</th><th>In</th><th>Out</th><th>Why this hop (basis)</th></tr>" + r.segments.map((sg, i) => "<tr><td>" + (i + 1) + "</td><td>" + e(sg.device + " " + sg.vsys) + "</td><td>" + e(((sg.ingress && sg.ingress.iface) || "") + " " + ((sg.ingress && sg.ingress.zone) || "")) + "</td><td>" + e(((sg.egress && sg.egress.iface) || "") + " " + ((sg.egress && sg.egress.zone) || "")) + "</td><td>" + e(sg.basis ? sg.basis.text + " (" + sg.basis.confidence + ")" : "") + "</td></tr>").join("") + "</table>";
  h += "<h2>Changes and CLI</h2>" + (r.changes.length ? r.changes.map((c, i) => '<div class="chg"><p><b>' + (i + 1) + ". " + e(DL(c.device) + (c.vsys ? " " + c.vsys : "")) + ":</b> " + e(c.summary) + (c.optional ? " <i>(verify)</i>" : "") + (c.why ? '<br><span class="muted">' + e(c.why) + "</span>" : "") + (c.order && c.order.text ? '<br><span class="muted"><b>Rule order:</b> ' + e(c.order.text) + "</span>" : "") + "</p><pre>" + e(c.cli.join("\n")) + "</pre>" + (c.modify ? "<p>Alternative: " + e(c.modify.summary.replace(/^or /, "")) + "</p><pre>" + e(c.modify.cli.join("\n")) + "</pre>" : "") + "</div>").join("") : "<p>None. Existing routes and rules already allow this flow.</p>");
  const notes = (r.notes || []).concat(...r.segments.map((sg) => sg.notes)).filter((n) => n.level !== "info");
  if (notes.length) h += "<h2>Notes</h2>" + notes.map((n) => '<div class="note">' + e(n.text) + "</div>").join("");
  if (r.fcr) {
    if (r.fcrTicket) h += "<p><b>FCR / ticket:</b> " + e(r.fcrTicket) + "</p>";
    h += "<h2>Why these vsys</h2>" + (r.fcr.why.lines || [r.fcr.why.text]).map((l) => "<p>" + e(l) + "</p>").join("");
    h += multiPlaceHtml(r, true);
    h += "<h2>Per-hop verdicts</h2><table><tr><th>#</th><th>Firewall / vsys</th><th>Verdict</th><th>Rule</th><th>Zones</th></tr>" + r.fcr.hops.map((x) => "<tr><td>" + x.n + "</td><td>" + e(DL(x.device) + " " + (x.display && x.display !== x.vsys ? x.display + " (" + x.vsys + ")" : x.vsys)) + "</td><td>" + e(x.verdict) + "</td><td>" + e(x.rule || "") + "</td><td>" + e((x.fromZone || "") + " → " + (x.toZone || "")) + "</td></tr>").join("") + "</table>";
    h += "<h2>Pre-push checklist</h2><ol>" + (r.fcr.checklist || []).map((c) => "<li>" + e(c) + "</li>").join("") + "</ol>";
    h += "<h2>Post-push traffic-log filters</h2><p class='muted'>Use these in the traffic log on each vsys after the push.</p>" + (r.fcr.filters.hops || []).map((f) => "<p><b>" + e(DL(f.device) + " " + f.vsys) + ":</b><pre>" + e(f.afterPush || f.filter) + "</pre>" + (f.testCli && f.testCli.length ? "<pre>" + e(f.testCli.join("\n")) + "</pre>" : "") + "<span class='muted'>" + e(f.expected) + "</span></p>").join("");
    if (r.fcr.plan && r.fcr.plan.uncertain) h += '<div class="note"><b>Device-group placement is uncertain on ' + r.fcr.plan.uncertain + " change(s).</b> Confirm the vsys on the target device before you commit.</div>";
  }
  return h + "</body></html>";
}
function fcrHtml(r) {
  if (!r.fcr) return "";
  const F = r.fcr;
  let h = '<div class="card" id="fcr-out">';
  h += "<h2>Why these vsys</h2><p>" + esc(F.why.text) + "</p>";
  h += '<div class="tblwrap"><table class="data glance"><thead><tr><th>#</th><th>Firewall / vsys</th><th>Verdict</th><th>Rule</th><th>Zones</th></tr></thead><tbody>' + F.hops.map((x) => {
    const cls = x.verdict === "allow" ? "ok" : x.verdict === "deny" ? "bad" : "";
    return "<tr><td>" + x.n + "</td><td><b>" + esc(DL(x.device)) + "</b> " + esc(x.display && x.display !== x.vsys ? x.display + " (" + x.vsys + ")" : x.vsys) + (x.dg ? ' <span class="muted">DG ' + esc(x.dg) + "</span>" : "") + (x.hairpin ? ' <span class="pill y">hairpin</span>' : "") + (x.transit ? ' <span class="pill y">unknown network</span>' : "") + '</td><td class="' + cls + '">' + esc(x.verdict) + "</td><td>" + esc(x.rule || "") + "</td><td>" + esc((x.fromZone || "") + (x.toZone ? " → " + x.toZone : "")) + "</td></tr>";
  }).join("") + "</tbody></table></div>";
  if (F.plan && F.plan.uncertain) h += '<div class="note warn">Device-group placement is uncertain on ' + F.plan.uncertain + " change(s). The plan marks those CLI blocks. Confirm the vsys on the target device before you commit.</div>";
  h += "<h2>Pre-push checklist</h2><ol class='fcr-check'>" + (F.checklist || []).map((c) => "<li>" + esc(c) + "</li>").join("") + "</ol>";
  h += "<h2>Post-push traffic-log filters</h2><p class='muted'>Paste into Monitor → Logs → Traffic on each vsys (or the Panorama traffic log with the vsys name). After the push, confirm the new allow or a later deny.</p>";
  h += (F.filters.hops || []).map((f, i) => '<div class="fcr-filter"><div class="ctl"><b>' + esc(DL(f.device) + " " + f.vsys) + '</b> <span class="muted">' + esc(f.expected) + '</span><button type="button" class="sm" data-copyfilter="' + i + '">Copy filter</button></div><pre class="cli">' + esc(f.afterPush || f.filter) + "</pre>" + (f.testCli && f.testCli.length ? '<div class="muted">Or check on the firewall itself' + (f.testVsys ? " (first <code>set system setting target-vsys " + esc(f.testVsys) + "</code>)" : "") + ':</div><pre class="cli fcr-testcli">' + esc(f.testCli.join("\n")) + "</pre>" : "") + "</div>").join("");
  return h + "</div>";
}
function changesHtml(r) {
  if (!r.changes.length) return '<div class="card" id="changes"><h2>Changes needed</h2><p>None. Existing routes and rules already allow this flow (based on the config).</p></div>';
  const req = r.changes.filter((c) => !c.optional), opt = r.changes.filter((c) => c.optional);
  const byDev = new Map();
  r.changes.forEach((c, i) => { if (!byDev.has(c.device)) byDev.set(c.device, []); byDev.get(c.device).push([c, i]); });
  let h = '<div class="card" id="changes"><div class="ctl"><h2 style="margin:0;flex:1">Changes needed (' + req.length + " required" + (opt.length ? ", " + opt.length + " to verify" : "") + ')</h2><label class="muted"><input type="checkbox" id="incl-opt"> include "verify" items</label><button type="button" class="sm" id="chg-all">Select all</button><button type="button" class="sm" id="chg-none">Select none</button><button data-copy="all">Copy all CLI</button></div>';
  if (r.ambiguous) h += '<div class="note warn amb-rules">' + esc(ambText(r.ambiguous) + ". " + ambRules(r.ambiguous)) + "</div>";
  h += '<p class="muted">Every place this flow needs a rule, route or zone, in path order. Tick the changes to include, then export or copy only those. CLI is a starting point: review names, objects and placement before committing.</p>';
  for (const [dev, list] of byDev) {
    h += "<h3>" + esc(DL(dev)) + "</h3>";
    for (const [c, i] of list) {
      const kindTxt = { security: "Security rule", route: "Route", zone: "Zone" }[c.kind] || c.kind;
      h += '<div class="chg ' + (c.optional ? "opt " : "") + esc(c.kind) + '" data-kind="' + esc(c.kind) + '" data-idx="' + i + '"><label class="chg-pick"><input type="checkbox" data-chg="' + i + '" checked> Include in export / copy</label><h4><span class="pill ' + (c.optional ? "y" : c.kind === "security" ? "r" : "b") + '">' + esc(kindTxt) + (c.optional ? " - verify" : "") + "</span> " + esc(c.summary) + "</h4>" +
        (c.why ? '<div class="muted">' + esc(c.why) + "</div>" : "") +
        (c.rule ? '<div class="muted">From <b>' + esc(c.rule.from) + "</b> to <b>" + esc(c.rule.to) + "</b> &middot; source " + esc(c.rule.source) + " &middot; destination " + esc(c.rule.destination) + " &middot; service " + esc(c.rule.service) + " &middot; app " + esc(c.rule.application) + (c.rule.placeBefore ? " &middot; place above <b>" + esc(c.rule.placeBefore) + "</b>" : "") + "</div>" : "") +
        (c.order && c.order.text ? '<div class="muted order-advice" data-order="' + esc(c.order.mode) + '"><b>Rule order:</b> ' + esc(c.order.text) + "</div>" : "") +
        '<pre class="cli">' + esc(c.cli.join("\n")) + '</pre><button class="sm" data-copy="' + i + '">Copy</button>' +
        (c.modify ? '<div class="modalt"><b>Alternative:</b> ' + esc(c.modify.summary.replace(/^or /, "")) + '<pre class="cli">' + esc(c.modify.cli.join("\n")) + "</pre></div>" : "") + "</div>";
    }
  }
  return h + "</div>";
}
const CONF = { high: ["g", "high"], medium: ["y", "medium"], low: ["r", "low"] };
function confPill(c) { const x = CONF[c] || ["y", c || "?"]; return '<span class="pill ' + x[0] + '">' + esc(x[1]) + " confidence</span>"; }
/* Routing is authoritative. When the rulebase points elsewhere, say so plainly and offer the other path. */
function conflictHtml(r, id) {
  const k = r.conflict, P = r.plan || {};
  let h = "";
  if (k) {
    const showingRules = P.forced && P.chosen === k.pathIndex;
    h += '<div class="note warn conflict"' + (id ? ' id="' + id + '"' : "") + "><b>Routing says:</b> " + esc(k.routing) + " &nbsp; <b>Rules suggest:</b> " + esc(k.rules) +
      (showingRules ? ' <span class="pill y">showing the rules\' path (against routing)</span>' : "") + "<ul>" +
      k.evidence.map((e) => "<li>rule <b>" + esc(e.rule) + "</b> on " + esc(DL(e.device) + (e.vsys !== "vsys1" ? " " + e.vsys : "")) + " (" + esc(e.from.join(",") + " \u2192 " + e.to.join(",")) + ") allows this flow, but routing does not send it there</li>").join("") +
      k.routes.map((v) => "<li>" + esc(v.device + " routes it out " + v.routeIface + " (" + v.route + "); the rules' path needs " + v.pathIface) + "</li>").join("") +
      (k.ownerOnlyByRules ? "<li>destination placed only by a rule: " + esc(k.ownerOnlyByRules) + "</li>" : "") +
      '</ul><span class="muted">' + (k.scopeCause === "hidden-routed-hop" || k.scopeCause === "hidden-owner" ? esc(k.scopeText) : k.scopeCause === "preexisting" ? "Routing and rules also disagree when every loaded firewall is included. This is worth reviewing (a stale rule or a routing problem). The trace follows routing." : "Likely a stale rule, or a routing problem worth reviewing. The trace follows routing.") + "</span> "
      + ((k.scopeCause === "hidden-routed-hop" || k.scopeCause === "hidden-owner") ? '<button type="button" class="sm" data-scope-all="1">Show all sites</button> ' : "") +
      (showingRules ? '<button type="button" class="sm" data-routingpath="1">Back to the routing path</button>' : '<button type="button" class="sm" data-altpath="' + k.pathIndex + '">Trace alternative (rules\' path)</button>') + "</div>";
  }
  if (r.dnatElsewhere && r.dnatElsewhere.length) h += '<div class="note warn">Destination NAT for ' + esc(r.query.dst) + " exists on " + esc(r.dnatElsewhere.join(", ")) + ", which the routing path does not cross.</div>";
  return h;
}
/* Parallel firewalls the evidence cannot separate: say so at the top and offer both. */
const ambText = (a) => "Ambiguous: " + a.devices.join(" or ");
const ambRules = (a) => "Rules needed on whichever of " + a.devices.join(" / ") + " carries the flow (or both for redundancy).";
function ambHtml(r) {
  const a = r.ambiguous; if (!a) return "";
  const P = r.plan || {}, on = P.forced && P.chosen === a.pathIndex ? 1 : 0;
  return '<div class="note warn ambiguous" id="ambiguous"><b>' + esc(ambText(a)) + "</b>: routing and rules fit both parallel firewalls equally (paths " + esc(a.paths.join("  |  ")) + "). The trace below goes through <b>" + esc(a.devices[on]) + "</b>; confirm which one carries this flow (e.g. test routing fib-lookup on the upstream router). " +
    '<button type="button" class="sm"' + (on ? ' data-routingpath="1"' : " disabled") + ">Trace via " + esc(a.devices[0]) + '</button> <button type="button" class="sm"' + (on ? " disabled" : ' data-altpath="' + a.pathIndex + '"') + ">Trace via " + esc(a.devices[1]) + "</button></div>";
}
function basisHtml(r) {
  if (!r.segments.length) return "";
  const pill = (c) => '<span class="pill ' + (c === "high" ? "g" : c === "medium" ? "y" : "r") + '">' + esc(c) + "</span>";
  let h = '<div id="basis"><p><b>Why each hop</b> <span class="muted">(routing decides; rules only break ties, place addresses no route covers, and pick internet edges)</span></p><ol class="hoplist">';
  r.segments.forEach((s) => {
    h += "<li><b>" + esc(DL(s.device) + " " + s.vsys) + "</b>: " + (s.basis ? esc(s.basis.text) + " " + pill(s.basis.confidence) : '<span class="muted">-</span>');
    if (s.next && s.next.basis) h += "<br><span class=\"muted\">next firewall " + esc(s.next.to) + ":</span> " + esc(s.next.basis.text) + " " + pill(s.next.basis.confidence) + ' <span class="muted">chosen by ' + esc(s.next.basis.chosenBy) + "</span>";
    h += "</li>";
  });
  return h + "</ol></div>";
}
function chainHtml(r) {
  const P = r.plan;
  let h = "";
  const devs = []; for (const s of r.segments) { const n = DL(s.device) + (s.haPeers && s.haPeers.length ? " (HA: " + DLs(s.haPeers) + ")" : ""); if (devs[devs.length - 1] !== n) devs.push(n); }
  if (r.stitches && r.stitches.length) {
    h += '<div id="chain"><p><b>Firewall chain:</b> ' + devs.map(esc).join(" &rarr; ") + "</p><ol class=\"hoplist\">";
    for (const st of r.stitches) {
      h += "<li>" + esc(DL(st.from) + " " + (st.egress || "")) + " &rarr; <i>" + esc(st.via.label) + "</i> &rarr; " + esc(DL(st.to) + " " + st.ingress) + " " + confPill(st.confidence) + (st.needsRoute ? ' <span class="pill b">route change needed</span>' : "") + "</li>";
    }
    h += "</ol></div>";
    for (const st of r.stitches) {
      const alts = st.alternatives || [];
      if (alts.length < 2) continue;
      h += '<div class="branch"><b>' + (st.ambiguous ? "Ambiguous next firewall" : "Next firewall") + "</b> after " + esc(DL(st.from) + " " + (st.egress || "") + (st.nexthop ? " (next hop " + st.nexthop + ")" : "")) + ': <select data-branch="' + esc(st.key) + '">' +
        alts.slice(0, 25).map((a) => '<option value="' + esc(a.devId) + '"' + (a.pathIndex != null ? ' data-path="' + a.pathIndex + '"' : "") + (a.chosen ? " selected" : "") + ">" + esc(DL(a.device) + " " + (a.iface || "") + " - " + (a.via || a.why) + " [cost " + a.score + (a.confidence ? ", " + a.confidence : "") + "]") + "</option>").join("") + "</select>" +
        ' <span class="muted">Pick a branch to re-trace, or add a link below the form to make it permanent.</span></div>';
    }
  }
  if (P) {
    if (P.paths && P.paths.length > 1) {
      h += '<div id="altpaths"><b>Alternative paths</b> <span class="muted">(top ' + P.paths.length + ", lower cost = stronger evidence)</span>" + P.paths.map((p, i) => '<label class="altp"><input type="radio" name="altp" data-path="' + i + '"' + (i === P.chosen ? " checked" : "") + "> " + esc(p.label) + ' <span class="muted">cost ' + p.cost + "</span> " + (p.routing === "contradicts" ? '<span class="pill r">contradicts routing</span> ' : p.routing === "extends" ? '<span class="pill y" title="Routing places the address behind a firewall on this path; rules show where it actually enters or leaves. Every hop follows routing.">extends routing via rules</span> ' : i === 0 ? '<span class="pill g">follows routing</span> ' : "") + (p.rules ? '<span class="pill y">rules\' path</span> ' : "") + confPill(p.confidence) + "</label>").join("") + "</div>";
    }
    const pins = [];
    for (const o of (P.srcOwners || []).slice(0, 4)) pins.push('<button type="button" class="sm" data-pin="src|' + esc(o.devId) + '">source: ' + esc(DL(o.device)) + "</button>");
    for (const o of (P.dstOwners || []).slice(0, 4)) pins.push('<button type="button" class="sm" data-pin="dst|' + esc(o.devId) + '">destination: ' + esc(DL(o.device)) + "</button>");
    h += '<details id="why"' + (r.plan.paths.length ? "" : " open") + "><summary><b>Why this path" + (r.plan.reached < r.plan.total || !r.plan.paths.length ? " / why it stopped" : "") + "</b></summary>" +
      "<ul>" + (P.explain || []).map((t) => "<li>" + esc(t) + "</li>").join("") + "</ul>" +
      (r.conflict || r.dnatElsewhere ? "<p><b>Routing vs rules</b></p>" + conflictHtml(r) : "") +
      ((P.srcOwners || []).length ? "<p><b>Source owner candidates:</b> " + P.srcOwners.slice(0, 5).map((o) => esc(DL(o.device) + " (" + o.how + ")")).join("; ") + "</p>" : "") +
      ((P.dstOwners || []).length ? "<p><b>Destination owner candidates:</b> " + P.dstOwners.slice(0, 5).map((o) => esc(DL(o.device) + " (" + o.how + ")")).join("; ") + "</p>" : "") +
      ((P.evidence || []).length ? "<p><b>Rules that already allow this flow</b> (used as path evidence):</p><ul>" + P.evidence.slice(0, 8).map((e) => "<li>" + esc(DL(e.device) + (e.vsys !== "vsys1" ? " " + e.vsys : "") + ": rule " + e.rule + " (" + e.from.join(",") + " \u2192 " + e.to.join(",") + ", weight " + e.weight + ")") + "</li>").join("") + "</ul>" : "") +
      ((P.considered || []).length ? "<p><b>Other firewalls considered:</b></p><ul>" + P.considered.map((c) => "<li>" + esc(DL(c.device) + " (next to " + DL(c.near) + "): " + c.why) + "</li>").join("") + "</ul>" : "") +
      (P.replanned && P.replanned.length ? "<p>" + P.replanned.map((x) => esc("Re-planned at " + x.at + " after destination NAT to " + x.dst + ": " + x.label)).join("<br>") + "</p>" : "") +
      (pins.length ? '<p class="ctl"><span class="muted">Pin a firewall:</span> ' + pins.join(" ") + "</p>" : "") +
      '<p class="muted">Order of authority: connected, static and next-vr routes, PBF, user links and HA pairs decide each hop; inferred BGP/OSPF routes come next. Rule and NAT evidence only break ties between equally valid routing options, place addresses no specific route covers (default or /8-style summaries only), and pick internet edges. Evidence weights for the inferred connections: user link &gt; next hop is a firewall interface &gt; shared subnet &gt; specific route + reverse route &gt; specific route &gt; default route &gt; zone/interface naming hint. Routers and the WAN/MPLS core are inferred from next hops. Allow rules that match the flow on a firewall (through the zones the path uses) pull the path through that firewall; public addresses enter and leave at internet edges (default route to the ISP, internet-named zone, or a rule allowing the address through the zone that carries the default route).</p></details>';
  }
  return h;
}
function renderLinks() {
  const box = $("#lk-list"); if (!box) return;
  $("#links-count").textContent = state.links.length ? "(" + state.links.length + ")" : "";
  if (!state.links.length) { box.innerHTML = '<p class="muted">No links. Links are only needed when the tool cannot tell which firewall sits behind a router/MPLS hop.</p>'; return; }
  box.innerHTML = '<table class="data"><thead><tr><th>From firewall</th><th>Egress interface</th><th>Next hop</th><th>To firewall</th><th>Ingress interface</th><th>Label</th><th></th></tr></thead><tbody>' +
    state.links.map((l, i) => "<tr><td>" + esc(DL(l.from.device) || "(any)") + "</td><td>" + esc(l.from.iface || "") + "</td><td>" + esc(l.from.nexthop || "") + "</td><td>" + esc(DL(l.to.device)) + "</td><td>" + esc(l.to.iface || "auto") + "</td><td>" + esc(l.label || "") + '</td><td><button class="sm" data-lkdel="' + i + '">Remove</button></td></tr>').join("") + "</tbody></table>";
  $$("[data-lkdel]", box).forEach((b) => b.addEventListener("click", () => { state.links.splice(Number(b.dataset.lkdel), 1); saveLinks(); }));
}
function ifOptions(devName) { const d = state.devices.find((x) => x.name === devName); return d ? [...d.interfaces.values()].filter((i) => i.vr).map((i) => '<option value="' + esc(i.name) + '">' + esc((i.zone || "") + " " + (i.ips[0] ? i.ips[0].text : "")) + "</option>").join("") : ""; }
$("#lk-fdev").addEventListener("change", () => { $("#lk-iflist").innerHTML = ifOptions($("#lk-fdev").value); });
$("#lk-tdev").addEventListener("change", () => { $("#lk-iflist2").innerHTML = ifOptions($("#lk-tdev").value); });
$("#lk-add").addEventListener("click", () => {
  const l = { from: { device: $("#lk-fdev").value || null, iface: $("#lk-fif").value.trim() || null, nexthop: $("#lk-fnh").value.trim() || null }, to: { device: $("#lk-tdev").value, iface: $("#lk-tif").value.trim() || null }, label: $("#lk-label").value.trim() || null };
  if (!l.to.device || (!l.from.iface && !l.from.nexthop)) { alert("A link needs a target firewall and an egress interface or next hop."); return; }
  state.links.push(l); saveLinks(); ["#lk-fif", "#lk-fnh", "#lk-tif", "#lk-label"].forEach((x) => ($(x).value = ""));
  if (state.last) runTrace(null, true);
});
$("#lk-export").addEventListener("click", () => download("flowmapper-links-" + stamp() + ".json", new Blob([JSON.stringify({ type: "pan-flowmapper-links", version: 1, links: state.links }, null, 2)], { type: "application/json" })));
$("#lk-import-file").addEventListener("change", async (e) => {
  const f = e.target.files[0]; if (!f) return;
  try { const j = JSON.parse(await f.text()); const list = Array.isArray(j) ? j : j.links; if (!Array.isArray(list)) throw new Error("no links array"); state.links = list.filter((l) => l && l.to && l.to.device && l.from); saveLinks(); if (state.last) runTrace(null, true); }
  catch (err) { alert("Could not import links: " + err.message); }
  e.target.value = "";
});
/* ---------- pasted route tables + BGP summary ---------- */
function renderRouteTables() {
  const box = $("#rt-list"); if (!box) return;
  $("#rt-count").textContent = state.routeTables.length ? "(" + state.routeTables.length + ")" : "";
  let h = "";
  if (state.routeTables.length) h += '<table class="data"><thead><tr><th>Firewall</th><th>Source</th><th>Format</th><th>Routes used</th><th>Routers</th><th>Notes</th><th></th></tr></thead><tbody>' + state.routeTables.map((t, i) => { const r = state.rtReports[i] || {}; return "<tr><td>" + esc(DL(t.device)) + "</td><td>" + esc(t.label) + "</td><td>" + esc(r.format || "?") + "</td><td>" + (r.routes || 0) + "</td><td>" + esc((r.routers || []).map((x) => x.vr + " (" + x.routes + ")").join(", ")) + "</td><td>" + esc((r.warnings || []).concat((r.unmatchedRouters || []).length ? ["no router named " + r.unmatchedRouters.join(", ")] : []).join("; ")) + '</td><td><button class="sm" data-rtdel="' + i + '">Remove</button></td></tr>'; }).join("") + "</tbody></table>";
  else h += '<p class="muted">No route tables pasted. Traces use the config routes plus BGP/OSPF routes inferred from it.</p>';
  const B = state.devices.flatMap((d) => FM.bgpSummary(d));
  if (B.length) h += '<h4>BGP in the loaded configs</h4><div class="tblwrap" style="max-height:300px"><table class="data" id="bgp-tbl"><thead><tr><th>Firewall</th><th>Router</th><th>Engine</th><th>Local AS</th><th>Peers (group, AS)</th><th>Advertises</th><th>Filters / conditions</th><th>Route table</th></tr></thead><tbody>' +
    B.map((b) => "<tr><td>" + esc(DL(b.device)) + "</td><td>" + esc(b.vr) + "</td><td>" + esc(b.engine === "advanced" ? "advanced routing" : "legacy") + "</td><td>" + esc(b.localAs || "") + "</td><td>" + esc(b.peers.map((p) => (p.peerIp || "?") + " (" + p.group + ", AS " + (p.peerAs || "?") + ")").join("; ")) + "</td><td>" +
      esc([b.redistribution.length ? "redistributes " + b.redistribution.map((r) => r.name + (r.types.length ? " [" + r.types.join("/") + "]" : "") + (r.missing ? " (profile missing)" : "")).join(", ") : "", b.networks.length ? "networks " + b.networks.join(", ") : "", b.aggregates.length ? "aggregates " + b.aggregates.map((a) => a.prefix + (a.summaryOnly ? " summary-only" : "")).join(", ") : ""].filter(Boolean).join("; ")) + "</td><td>" +
      esc([b.importRules ? b.importRules + " import rule(s)" : "", b.exportRules ? b.exportRules + " export rule(s)" : "", ...b.peers.filter((p) => p.filteringProfile).map((p) => "filtering profile " + p.filteringProfile), ...b.conditional.map((c) => "conditional " + c.name)].filter(Boolean).join("; ")) + "</td><td>" + (b.observed ? '<span class="pill g">pasted, ' + b.observed.routes + " routes</span>" : '<span class="pill y">inferred</span>') + "</td></tr>").join("") + "</tbody></table></div>";
  box.innerHTML = h;
  $$("[data-rtdel]", box).forEach((b) => b.addEventListener("click", async () => { state.routeTables.splice(Number(b.dataset.rtdel), 1); await rebuildDevices(); resetDrop(); refreshSelectors(); if (state.last) runTrace(null, true); }));
}
async function addRouteTable(device, text, label) {
  if (!device) { alert("Pick the firewall this route table belongs to."); return; }
  const P = FM.parseRouteTable(text);
  if (!P.count) { alert(P.warnings.join(" ") || "No routes found."); return; }
  state.routeTables = state.routeTables.filter((t) => !(t.device === device && t.label === label));
  state.routeTables.push({ device, text, label: label || "pasted route table" });
  await rebuildDevices(); resetDrop(); refreshSelectors();
  if (state.last) runTrace(null, true);
}
$("#rt-add").addEventListener("click", () => addRouteTable($("#rt-dev").value, $("#rt-text").value, $("#rt-label").value.trim() || "pasted " + new Date().toLocaleString()).then(() => { $("#rt-text").value = ""; }));
$("#rt-file").addEventListener("change", async (e) => { const f = e.target.files[0]; if (!f) return; await addRouteTable($("#rt-dev").value, await f.text(), f.name); e.target.value = ""; });
$("#btn-help").addEventListener("click", () => { const h = $("#help"); h.hidden = !h.hidden; if (!h.hidden) h.scrollIntoView({ behavior: "smooth", block: "start" }); });
$("#help-close").addEventListener("click", () => { $("#help").hidden = true; });
/* ---------- public-space / circuit map ---------- */
function saveCircuits() { try { localStorage.setItem(CIRC_KEY, JSON.stringify(state.circuits)); localStorage.setItem(CIRC_IGN_KEY, JSON.stringify(state.circIgnore)); } catch (e) {} renderCircuits(); if (typeof renderEnv === "function") renderEnv(); }
function ckDevChanged() {
  const d = state.devices.find((x) => x.name === $("#ck-dev").value);
  $("#ck-iflist").innerHTML = d ? [...d.interfaces.values()].filter((i) => i.vr).map((i) => '<option value="' + esc(i.name) + '">' + esc((i.zone || "") + " " + (i.ips[0] ? i.ips[0].text : "")) + "</option>").join("") : "";
  $("#ck-zlist").innerHTML = d ? [...new Set([...d.interfaces.values()].map((i) => i.zone).filter(Boolean))].map((z) => '<option value="' + esc(z) + '">').join("") : "";
}
$("#ck-dev").addEventListener("change", ckDevChanged);
const sugKey = (x) => x.prefix + "|" + x.device;
function fillCircuitForm(x) { $("#ck-prefix").value = x.prefix || ""; $("#ck-circuit").value = x.circuit || ""; if (x.device) { $("#ck-dev").value = x.device; ckDevChanged(); } $("#ck-if").value = x.iface || ""; $("#ck-zone").value = x.iface ? "" : x.zone || ""; $("#circ-box").open = true; $("#ck-prefix").focus(); }
function renderCircuits() {
  const box = $("#ck-list"); if (!box) return;
  $("#circ-count").textContent = state.circuits.length ? "(" + state.circuits.length + ")" : "";
  box.innerHTML = !state.circuits.length ? '<p class="muted">No entries yet. Add one above, or accept a suggestion below.</p>' :
    '<table class="data" id="ck-table"><thead><tr><th>Public prefix</th><th>Circuit</th><th>Firewall</th><th>Interface / zone</th><th></th></tr></thead><tbody>' +
    state.circuits.map((c, i) => "<tr><td>" + esc(c.prefix) + "</td><td>" + esc(c.circuit || "") + "</td><td>" + esc(DL(c.device)) + (state.devices.length && !state.devices.some((d) => d.name === c.device) ? ' <span class="pill r">not loaded</span>' : "") + "</td><td>" + esc(c.iface || (c.zone ? "zone " + c.zone : "auto")) + '</td><td><button class="sm" data-ckedit="' + i + '">Edit</button> <button class="sm" data-ckdel="' + i + '">Remove</button></td></tr>').join("") + "</tbody></table>";
  $$("[data-ckdel]", box).forEach((b) => b.addEventListener("click", () => { state.circuits.splice(Number(b.dataset.ckdel), 1); saveCircuits(); if (state.last) runTrace(null, true); }));
  $$("[data-ckedit]", box).forEach((b) => b.addEventListener("click", () => { const c = state.circuits.splice(Number(b.dataset.ckedit), 1)[0]; saveCircuits(); fillCircuitForm(c); }));
  const sb = $("#ck-sug"); if (!sb) return;
  if (!state.devices.length) { sb.innerHTML = ""; return; }
  const ign = new Set(state.circIgnore), all = FM.publicSpaceSuggestions(V(), state.circuits), fq = (state.circSugQ || "").toLowerCase();
  const fs_ = state.circSugSrc || "";
  const list = all.filter((x) => !ign.has(sugKey(x)) && (!fs_ || x.source === fs_) && (!fq || [x.prefix, x.device, x.iface, x.zone, x.circuit, x.source, x.why].join(" ").toLowerCase().includes(fq)));
  state.circSug = list;
  sb.innerHTML = '<p><b>Not in the map yet</b> <span class="muted">(' + list.length + (all.length > list.length ? ", " + (all.length - list.length) + ' ignored <button class="sm" id="ck-unign">Show again</button>' : "") + "): provider static routes for public prefixes (more-specific than the default), public NAT addresses and public interface subnets</span> " + '<input type="search" id="ck-sugq" placeholder="Filter: prefix, firewall, zone, static/nat" value="' + esc(state.circSugQ || "") + '"> <select id="ck-sugsrc" class="sm" title="Only this kind of suggestion">' + [["", "All kinds"], ["static", "Provider statics"], ["nat", "NAT addresses"], ["interface", "Interface subnets"]].map(([v, l]) => '<option value="' + v + '"' + (fs_ === v ? " selected" : "") + ">" + l + " (" + (v ? all.filter((x) => !ign.has(sugKey(x)) && x.source === v).length : all.filter((x) => !ign.has(sugKey(x))).length) + ")</option>").join("") + "</select>" +
    (list.length ? ' <button class="sm primary" id="ck-bulk">Accept ' + list.length + " shown suggestion" + (list.length === 1 ? "" : "s") + "</button>" : "") + "</p>" + (state.circBulkMsg ? '<div class="note info" id="ck-bulkmsg">' + esc(state.circBulkMsg) + "</div>" : "") +
    (list.length ? '<table class="data" id="ck-sugtable"><thead><tr><th>Public prefix</th><th>Found as</th><th>Firewall</th><th>Interface / zone</th><th>Suggested circuit</th><th></th></tr></thead><tbody>' +
      list.slice(0, 60).map((x, i) => "<tr><td>" + esc(x.prefix) + '</td><td><span class="pill ' + (x.source === "static" ? "b" : "y") + '">' + esc(x.source === "static" ? "provider static" : x.source === "nat" ? "NAT address" : "interface") + "</span> " + esc(x.why) + "</td><td>" + esc(DL(x.device)) + "</td><td>" + esc((x.iface || "") + (x.zone ? " (" + x.zone + ")" : "")) + "</td><td>" + esc(x.circuit || "") + '</td><td><button class="sm" data-ckacc="' + i + '">Add</button> <button class="sm" data-ckfill="' + i + '">Edit</button> <button class="sm" data-ckign="' + i + '">Ignore</button></td></tr>').join("") + "</tbody></table>" + (list.length > 60 ? '<p class="muted">' + (list.length - 60) + " more not shown; add or ignore some to see them.</p>" : "") : "");
  const conf = FM.suggestionConflicts(V(), state.circuits, list); state.circConf = conf;
  if (conf.length) {
    const kind = (k) => k === "static" ? "provider static" : k === "nat" ? "NAT address" : "interface";
    const ch = state.circConfPick || (state.circConfPick = {});
    sb.insertAdjacentHTML("afterbegin", '<div id="ck-conf" class="note warn"><p><b>Same prefix on several firewalls (' + conf.length + ")</b>: the map holds one landing per prefix, so bulk accept skips these. Pick where each prefix lands; the other candidates then leave the list. HA peers count as one candidate.</p>" +
      conf.slice(0, 20).map((c, i) => '<fieldset class="ck-conf1" data-cfprefix="' + esc(c.prefix) + '"><legend><b>' + esc(c.prefix) + "</b> " + c.candidates.length + " candidates</legend>" +
        c.candidates.map((x, j) => '<label class="ck-cand"><input type="radio" name="cf' + i + '" value="' + j + '"' + (ch[c.prefix] === j ? " checked" : "") + "> " + esc(DL(x.device)) + (x.peers.length ? ' <span class="muted">(+ HA peer ' + esc(x.peers.map(DL).join(", ")) + ")</span>" : "") +
          ' <span class="pill ' + (x.source === "static" ? "b" : "y") + '">' + esc(x.sources.map(kind).join(" + ")) + "</span> " + esc((x.iface || "") + (x.zone ? " (zone " + x.zone + ")" : "")) + ' <span class="muted">' + esc(x.why) + "</span></label>").join("") +
        '<div><button class="sm primary" data-cfuse="' + i + '"' + (ch[c.prefix] == null ? " disabled" : "") + '>Use this landing</button> <button class="sm" data-cfign="' + i + '">Ignore this prefix</button></div></fieldset>').join("") +
      (conf.length > 20 ? '<p class="muted">' + (conf.length - 20) + " more; resolve or ignore some to see them.</p>" : "") + "</div>");
    $$("#ck-conf input[type=radio]", sb).forEach((r) => r.addEventListener("change", () => { const fsx = r.closest("fieldset"); ch[fsx.dataset.cfprefix] = Number(r.value); const b = fsx.querySelector("[data-cfuse]"); if (b) b.disabled = false; }));
    $$("[data-cfuse]", sb).forEach((b) => b.addEventListener("click", () => { const c = state.circConf[Number(b.dataset.cfuse)], j = ch[c.prefix]; if (j == null) return; state.circuits.push(FM.conflictEntry(c.candidates[j])); delete ch[c.prefix]; state.circBulkMsg = c.prefix + " now lands on " + DL(c.candidates[j].device) + "."; saveCircuits(); if (state.last) runTrace(null, true); }));
    $$("[data-cfign]", sb).forEach((b) => b.addEventListener("click", () => { const c = state.circConf[Number(b.dataset.cfign)]; for (const x of c.candidates) for (const y of x.items) state.circIgnore.push(sugKey(y)); saveCircuits(); }));
  }
  const pick = (b, k) => state.circSug[Number(b.dataset[k])];
  $$("[data-ckacc]", sb).forEach((b) => b.addEventListener("click", () => { const x = pick(b, "ckacc"); state.circuits.push({ prefix: x.prefix, circuit: x.circuit || "", device: x.device, iface: x.iface || null, zone: x.iface ? null : x.zone || null }); saveCircuits(); if (state.last) runTrace(null, true); }));
  $$("[data-ckfill]", sb).forEach((b) => b.addEventListener("click", () => fillCircuitForm(pick(b, "ckfill"))));
  $$("[data-ckign]", sb).forEach((b) => b.addEventListener("click", () => { state.circIgnore.push(sugKey(pick(b, "ckign"))); saveCircuits(); }));
  const sq = $("#ck-sugq"); if (sq) sq.addEventListener("change", () => { state.circSugQ = sq.value.trim(); renderCircuits(); const n = $("#ck-sugq"); if (n) n.focus(); });
  const un = $("#ck-unign"); if (un) un.addEventListener("click", () => { state.circIgnore = []; saveCircuits(); });
  const ss = $("#ck-sugsrc"); if (ss) ss.addEventListener("change", () => { state.circSugSrc = ss.value; state.circBulkMsg = ""; renderCircuits(); });
  const bk = $("#ck-bulk"); if (bk) bk.addEventListener("click", () => {
    const shown = state.circSug.slice();
    if (!window.confirm("Add " + shown.length + " suggestions to the public-space map? Entries you already have are kept; a prefix already in the map, or found on two unrelated firewalls, is skipped.")) return;
    const r = FM.bulkAcceptSuggestions(V(), state.circuits, shown);
    state.circuits.push(...r.accepted);
    const why = {}; for (const x of r.skipped.filter((y) => !y.merged)) { const k = x.reason.replace(/ \(.*$/, ""); why[k] = (why[k] || 0) + 1; }
    const merged = r.skipped.filter((y) => y.merged).length;
    state.circBulkMsg = "Accepted " + r.accepted.length + " suggestion" + (r.accepted.length === 1 ? "" : "s") + (merged ? " (" + merged + " HA-peer duplicates folded into their pair)" : "") + "; skipped " + (r.skipped.length - merged) + (Object.keys(why).length ? ": " + Object.entries(why).map(([k, n]) => n + " " + k).join(", ") : "") + "." + (r.skipped.some((y) => /several firewalls/.test(y.reason)) ? " Pick one landing for each prefix under Same prefix on several firewalls." : "");
    state.lastBulk = r;
    saveCircuits(); if (state.last) runTrace(null, true);
  });
}
$("#ck-add").addEventListener("click", () => {
  const prefix = $("#ck-prefix").value.trim(), p = FM.parsePrefix(prefix);
  const c = { prefix: p ? FM.prefixStr(p) : prefix, circuit: $("#ck-circuit").value.trim(), device: $("#ck-dev").value, iface: $("#ck-if").value.trim() || null, zone: $("#ck-zone").value.trim() || null };
  if (!p || !c.device) { alert("A map entry needs a valid prefix (CIDR) and the firewall it lands on."); return; }
  const dup = state.circuits.findIndex((x) => x.prefix === c.prefix && x.device === c.device);
  if (dup >= 0 && !confirm("Replace the existing entry for " + c.prefix + " on " + c.device + "?")) return;
  if (dup >= 0) state.circuits.splice(dup, 1);
  state.circuits.push(c); saveCircuits(); ["#ck-prefix", "#ck-circuit", "#ck-if", "#ck-zone"].forEach((x) => ($(x).value = ""));
  if (state.last) runTrace(null, true);
});
$("#ck-export").addEventListener("click", () => download("flowmapper-public-space-" + stamp() + ".json", new Blob([JSON.stringify({ type: "pan-flowmapper-public-space", version: 1, circuits: state.circuits }, null, 2)], { type: "application/json" })));
$("#ck-import-file").addEventListener("change", async (e) => {
  const f = e.target.files[0]; if (!f) return;
  try { const j = JSON.parse(await f.text()); const list = Array.isArray(j) ? j : j.circuits; if (!Array.isArray(list)) throw new Error("no circuits array"); state.circuits = list.filter((c) => c && c.prefix && c.device && FM.parsePrefix(String(c.prefix))); saveCircuits(); if (state.last) runTrace(null, true); }
  catch (err) { alert("Could not import the public-space map: " + err.message); }
  e.target.value = "";
});
/* ---------- hostnames for serials you supply (Panorama exports often carry no managed-device hostnames) ---------- */
function loadHostnames() { try { const v = JSON.parse(localStorage.getItem(HN_KEY) || "{}"); return v && typeof v === "object" && !Array.isArray(v) ? v : {}; } catch (e) { return {}; } }
/* Accepts "serial,hostname" or "hostname,serial" lines, or a CSV with a header naming the serial and device-name columns
   (e.g. Panorama > Managed Devices export). Returns {serial: hostname}. */
function parseHostnames(text) {
  const out = {}, rows = String(text || "").split(/\r?\n/).map((l) => l.split(/[,;\t]/).map((x) => x.trim().replace(/^"|"$/g, ""))).filter((r) => r.some(Boolean));
  if (!rows.length) return out;
  const h = rows[0].map((x) => x.toLowerCase());
  let si = h.findIndex((x) => /serial/.test(x)), ni = h.findIndex((x) => /^(device ?name|hostname|host ?name|name)$/.test(x));
  const body = si >= 0 && ni >= 0 ? rows.slice(1) : rows;
  const known = new Set(state.devices.map((d) => d.serial || (d.panorama && d.panorama.serial)).filter(Boolean));
  for (const r of body) {
    let ser, hn;
    if (si >= 0 && ni >= 0) { ser = r[si]; hn = r[ni]; }
    else if (r.length >= 2) { const a = r[0], b = r[1]; const isSer = (x) => known.has(x) || /^\d{9,15}$/.test(x); if (isSer(a) && !isSer(b)) { ser = a; hn = b; } else if (isSer(b) && !isSer(a)) { ser = b; hn = a; } else { ser = a; hn = b; } }
    if (ser && hn) out[ser] = hn;
  }
  return out;
}
function applyHostnames() {
  for (const d of state.devices) {
    const ser = d.serial || (d.panorama && d.panorama.serial);
    if (d.hostnameFrom === "list") { d.hostname = null; d.hostnameFrom = null; }
    if (!d.hostname && ser && state.hostnames[ser]) { d.hostname = state.hostnames[ser]; d.hostnameFrom = "list"; }
  }
  const c = $("#hn-count"); if (c) { const n = Object.keys(state.hostnames).length; c.textContent = n ? "(" + n + ")" : ""; }
}
$("#hn-save").addEventListener("click", () => {
  const add = parseHostnames($("#hn-text").value);
  state.hostnames = $("#hn-replace").checked ? add : Object.assign({}, state.hostnames, add);
  try { localStorage.setItem(HN_KEY, JSON.stringify(state.hostnames)); } catch (e) {}
  applyHostnames(); refreshSelectors(); renderLinks(); renderCircuits(); renderFiles();
  $("#hn-status").textContent = Object.keys(add).length + " hostnames read; " + state.devices.filter((d) => d.hostnameFrom === "list").length + " loaded firewalls use one.";
  if (ENV && ENV.layout) { ENV.key = null; renderEnv(); }
  if (state.last) runTrace(null, true);
});
function pillFor(c) {
  if (c && c.ignoredDefault) return '<span class="pill y" title="Only intrazone-default would allow this; you chose to ignore it">NEEDS RULE</span>';
  if (!c) return "";
  if (c.verdict === "conditional") return '<span class="pill y">CONDITIONAL</span>';
  return c.action === "allow" ? '<span class="pill g">ALLOW</span>' : '<span class="pill r">DENY</span>';
}
function checksHtml(r) {
  const segs = r.segments.filter((s) => s.check || s.isSG);
  if (!segs.length) return "";
  let h = '<div class="card" id="checks"><h2>Policy checks</h2><div class="tblwrap"><table class="data"><thead><tr><th>#</th><th>Device</th><th>Vsys</th><th>From zone</th><th>To zone</th><th>Source</th><th>Destination (pre-NAT)</th><th>Service</th><th>Result</th><th>Matching rule</th></tr></thead><tbody>';
  segs.forEach((s, i) => {
    if (!s.check) { h += "<tr><td>" + (i + 1) + "</td><td>" + esc(DL(s.device)) + "</td><td>" + esc(s.display) + '</td><td colspan="7" class="muted">Shared gateway: no security policy here (NAT ' + esc(s.nat ? s.nat.rule : "none") + ")</td></tr>"; return; }
    const c = s.check;
    h += "<tr class=\"" + (c.action !== "allow" ? "deny" : "") + "\"><td>" + (i + 1) + "</td><td>" + esc(DL(c.device)) + "</td><td>" + esc(c.vsys + (c.display !== c.vsys ? " (" + c.display + ")" : "")) + (c.dg ? '<br><span class="muted">DG ' + esc(c.dg) + "</span>" : "") + "</td><td>" + esc(c.fromZone) + "</td><td>" + esc(c.toZone) + "</td><td>" + esc(c.src) + "</td><td>" + esc(c.dst) + (c.dstPost !== c.dst ? '<br><span class="muted">post-NAT ' + esc(c.dstPost) + "</span>" : "") + "</td><td>" + esc(c.svc) + "</td><td>" + pillFor(c) + "</td><td>" + esc(c.rule) + (c.ignoredDefault ? ' <span class="pill y" title="Your setting: ignore the intrazone-default allow">ignored: would allow</span>' : "") + ' <span class="muted">' + esc(c.ruleScope || "") + "</span>" +
      (c.maybes.length ? '<div class="muted">Earlier rules that may match: ' + c.maybes.slice(0, 4).map((m) => esc(m.rule + " (" + m.action + ": " + m.reasons.join("; ") + ")")).join("<br>") + "</div>" : "") + "</td></tr>";
  });
  return h + "</tbody></table></div></div>";
}
function hopAssumeHtml(r, i) {
  const x = r.pathStatus && r.pathStatus.hops[i]; if (!x || !x.assumptions.length) return "";
  return x.assumptions.map((a) => '<div class="hop-assume"><span class="pill y">guess</span> ' + esc(a.what) + "<br><i>Confirm: " + esc(a.confirm) + "</i></div>").join("");
}
function hopsHtml(r) {
  let h = '<div class="card" id="hops"><h2>Hop by hop</h2><div class="tblwrap"><table class="data"><thead><tr><th>Device / vsys</th><th>Ingress</th><th>Routing</th><th>NAT</th><th>Egress</th><th>Return path</th><th>Notes</th></tr></thead><tbody>';
  r.segments.forEach((s, i) => {
    const rp = r.returnPath[i];
    const ing = s.ingress.iface ? s.ingress.iface + " / " + s.ingress.zone : "from " + s.ingress.fromCtx + " / " + s.ingress.zone;
    const routing = s.vrPath.map((x) => x.vr + ": " + x.route.name + " " + FM.prefixStr(x.route.dest) + (x.route.nexthop && x.route.nexthop.value ? " -> " + x.route.nexthop.value : "") + (x.route.origin === "template" ? " [template]" : x.route.origin === "local" ? " [local backup]" : "")).join("<br>");
    const nat = s.nat ? esc(s.nat.rule) + ": " + (s.nat.snat ? "src -> " + esc(s.nat.snat.text) + " " : "") + (s.nat.dnat ? "dst -> " + esc(s.nat.dnat.text) + (s.nat.dnat.port ? ":" + s.nat.dnat.port : "") : "") + (s.nat.reverse ? " (bi-directional)" : "") + (s.nat.inferred ? '<br><span class="pill y">you traced the translated address; clients use ' + esc(s.nat.pre) + "</span>" : "") : '<span class="muted">none</span>';
    const eg = s.egress ? (s.egress.iface ? s.egress.iface : "to " + (s.egress.toCtx || "?")) + " / " + (s.egress.zone || "?") : "-";
    h += "<tr><td>" + esc(DL(s.device)) + "<br><b>" + esc(s.display) + "</b>" + (s.hypothetical ? '<br><span class="pill y">assumes suggested route</span>' : "") + hopAssumeHtml(r, i) + "</td><td>" + esc(ing) + "</td><td>" + routing.split("<br>").map(esc).join("<br>") + "</td><td>" + nat + "</td><td>" + esc(eg) + (s.final ? '<br><span class="muted">' + esc(s.final.text) + "</span>" : "") + "</td><td>" + (rp ? '<span class="pill ' + (rp.ok ? "g" : rp.asym ? "y" : "r") + '">' + (rp.ok ? "OK" : rp.asym ? "ASYMMETRIC" : "MISSING") + "</span> " + esc(rp.text) : "") + "</td><td>" + s.notes.map((n) => '<div class="note ' + n.level + '">' + esc(n.text) + "</div>").join("") + "</td></tr>";
  });
  return h + "</tbody></table></div></div>";
}

/* ---------------- SVG helpers ---------------- */
/* diagram renderers live in build/render.js (shared with PAAT) */
const { C, DEVCOL, DEFS, trunc, T, R, arrow, cloud, subLines, envSvg } = FM.render;
const flowSvg = (r) => FM.render.flowSvg(r, { DL });

/* ---------------- export ---------------- */
function download(name, blob) { const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500); }
function exportSvg(svg, base) { if (!svg) return; download(base + "-" + stamp() + ".svg", new Blob([new XMLSerializer().serializeToString(svg)], { type: "image/svg+xml" })); }
function exportPng(svg, base) {
  if (!svg) return;
  const xml = new XMLSerializer().serializeToString(svg);
  const url = URL.createObjectURL(new Blob([xml], { type: "image/svg+xml" }));
  const img = new Image();
  img.onload = () => {
    const sc = 2, c = document.createElement("canvas"); c.width = svg.width.baseVal.value * sc; c.height = svg.height.baseVal.value * sc;
    const g = c.getContext("2d"); g.fillStyle = "#fff"; g.fillRect(0, 0, c.width, c.height); g.scale(sc, sc); g.drawImage(img, 0, 0);
    URL.revokeObjectURL(url); c.toBlob((b) => download(base + "-" + stamp() + ".png", b), "image/png");
  };
  img.src = url;
}
function stamp() { const d = new Date(); const p = (n) => String(n).padStart(2, "0"); return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + "-" + p(d.getHours()) + p(d.getMinutes()); }

/* ---------------- config browser ---------------- */
$("#cfg-dev").addEventListener("change", renderConfig);
$("#cfg-inf").addEventListener("change", renderConfig);
$("#cfg-q").addEventListener("input", () => { const q = $("#cfg-q").value.toLowerCase(); $$("#cfg-body tbody tr").forEach((tr) => (tr.hidden = q && !tr.textContent.toLowerCase().includes(q))); });
function table(id, head, rows) { return '<div class="tblwrap"><table class="data" id="' + id + '"><thead><tr>' + head.map((x) => "<th>" + esc(x) + "</th>").join("") + "</tr></thead><tbody>" + rows.map((r) => "<tr>" + r.map((c) => "<td>" + (c && c.html != null ? c.html : esc(c)) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>"; }
function renderConfig() {
  const d = state.devices.find((x) => x.id === $("#cfg-dev").value) || state.devices[0];
  const body = $("#cfg-body"); if (!d) { body.innerHTML = ""; return; }
  const S = FM.deviceSummary(d);
  let h = '<div class="grid">' + [["Virtual systems", S.vsys.filter((v) => !v.isSG).length], ["Shared gateways", S.vsys.filter((v) => v.isSG).length], ["Interfaces", S.interfaces.length], ["Zones", S.vsys.reduce((a, v) => a + v.zones.length, 0)], ["Routers", S.vrs.length], ["Security rules", S.vsys.reduce((a, v) => a + v.security, 0)], ["NAT rules", S.vsys.reduce((a, v) => a + v.nat, 0)]].map(([k, v]) => '<div class="f"><b>' + k + "</b><span>" + v + "</span></div>").join("") + "</div>";
  if (d.panorama) h += '<p class="muted">Panorama context: template ' + (d.panorama.stack ? "stack " + esc(d.panorama.stack) : esc(d.panorama.template)) + (d.serial ? ", serial " + esc(d.serial) : "") + ". Policies combine shared + device-group hierarchy pre/post rules." + (d.mergedLocal && d.netMerge === "union" ? " Network is the union of the template and local backup " + esc(d.mergedLocal) + " (local wins on exact conflicts)." : d.mergedLocal ? " Network from local backup " + esc(d.mergedLocal) + "." : "") + "</p>";
  if (S.warnings.length) h += S.warnings.slice(0, 30).map((w) => '<div class="note ' + w.level + '">' + esc(w.text) + "</div>").join("");
  h += "<h3>Virtual systems</h3>" + table("t-vsys", ["Name", "Display", "Type", "Device group", "Routers", "Zones", "Security", "NAT", "PBF", "Visible vsys"], S.vsys.map((v) => [v.name, v.display, v.isSG ? "shared gateway" : "vsys", v.dg || "", v.vrs.join(", "), v.zones.length, v.security, v.nat, v.pbf, v.visible.join(", ")]));
  h += "<h3>Zones</h3>" + table("t-zones", ["Vsys", "Zone", "Type", "Members"], S.vsys.flatMap((v) => v.zones.map((z) => [v.name, z.name, z.type, z.members.join(", ")])));
  h += "<h3>Interfaces</h3>" + table("t-ifs", ["Interface", "Type", "Mode", "IP", "Zone", "Vsys", "Router", "Tag", "Comment"], S.interfaces.map((i) => [i.name, i.type, i.mode, i.ips.map((x) => x.text + (x.via ? " (" + x.via + ")" : "")).join(", ") + (i.dhcp ? "DHCP" : ""), i.zone || "", i.vsys || "", i.vr || "", i.tag || "", i.comment || ""]));
  for (const vr of S.vrs) {
    h += "<h3>Router " + esc(vr.name) + ' <span class="muted">' + esc(vr.engine === "advanced" ? "advanced routing (logical router)" : "virtual router") + (vr.owner ? " &middot; vsys " + esc(vr.owner) : "") + (vr.dynamic.length ? " &middot; dynamic: " + esc(vr.dynamic.join(", ")) + " (not resolvable offline)" : "") + "</span></h3>";
    const P = vr.proto || {};
    if (P.bgp) h += '<p class="muted">BGP: local AS ' + esc(P.bgp.localAs || "?") + ", router-id " + esc(P.bgp.routerId || "?") + ", " + P.bgp.peers.length + " peer(s): " + esc(P.bgp.peers.map((x) => x.group + "/" + x.name + " " + (x.peerIp || x.fqdn || "?") + " AS " + (x.peerAs || "?") + (x.localIf ? " via " + x.localIf : "")).join("; ")) + (P.bgp.redistRules.length ? " &middot; redistributes: " + esc(P.bgp.redistRules.join(", ")) : "") + "</p>";
    if (P.ospf) h += '<p class="muted">OSPF: router-id ' + esc(P.ospf.routerId || "?") + ", areas " + esc(P.ospf.areas.map((a) => a.id + " [" + a.ifaces.map((i) => i.name + (i.passive ? " passive" : "")).join(", ") + "]").join("; ")) + (P.ospf.exportRules.length ? " &middot; export: " + esc(P.ospf.exportRules.join(", ")) : "") + "</p>";
    const showInf = $("#cfg-inf").checked;
    h += table("t-vr-" + vr.name, ["Name", "Source", "Destination", "Next hop", "Interface", "Metric", "Admin dist"], vr.routes.filter((r) => r.type !== "local" && (showInf || !r.inferred)).map((r) => [r.name, r.inferred ? r.type + " (" + r.inferred.via + ", from " + r.inferred.origin + ")" : r.type + (r.origin === "template" ? " (Panorama template)" : r.origin === "local" ? " (local backup)" : ""), FM.prefixStr(r.dest), r.nexthop.type === "ip" ? r.nexthop.value : r.nexthop.type === "next-vr" ? "next-vr " + r.nexthop.value : r.nexthop.type, r.iface || "", r.metric, r.ad]));
  }
  for (const v of d.vsys.values()) {
    if (v.security.length) h += "<h3>Security rules - " + esc(v.name) + "</h3>" + table("t-sec-" + v.name, ["#", "Name", "Scope", "From", "To", "Source", "Destination", "Application", "Service", "Action", ""], v.security.slice(0, 3000).map((r, i) => [i + 1, r.name + (r.disabled ? " (disabled)" : ""), r.scope, r.from.join(", "), r.to.join(", "), (r.negSrc ? "NOT " : "") + r.source.join(", "), (r.negDst ? "NOT " : "") + r.destination.join(", "), r.application.join(", "), r.service.join(", "), r.action,
      { html: '<button type="button" class="sm" data-trule="' + esc(r.scope) + '\u0001' + esc(r.name) + '" title="Trace a representative flow allowed by this rule (first host of its source and destination, first service port)">Trace this rule</button>' }]));
    if (v.nat.length) h += "<h3>NAT rules - " + esc(v.name) + "</h3>" + table("t-nat-" + v.name, ["#", "Name", "Scope", "From", "To", "Source", "Destination", "Service", "Source translation", "Destination translation"], v.nat.slice(0, 3000).map((r, i) => [i + 1, r.name + (r.disabled ? " (disabled)" : ""), r.scope, r.from.join(", "), r.to.join(", "), r.source.join(", "), r.destination.join(", "), r.service, r.snat ? r.snat.type + " " + (r.snat.iface || (r.snat.addrs || []).join(",")) + (r.snat.bidir ? " bi-dir" : "") : "", r.dnat ? r.dnat.addr + (r.dnat.port ? ":" + r.dnat.port : "") : ""]));
  }
  body.innerHTML = h;
  $$("[data-trule]", body).forEach((b) => b.addEventListener("click", () => { const [scope, name] = b.dataset.trule.split("\u0001"); traceRule(scope, name); }));
}
function ruleQuery(c) { return { src: c.src, dst: c.dst, proto: c.proto === "any" ? "any" : c.proto, port: c.port == null ? "" : c.port, deviceId: "", ingress: "", dstDeviceId: "", via: "" }; }
function traceRule(scope, name) {
  const x = FM.ruleCase(V(), name, scope, state.links);
  if (!x.case) { flash("Cannot trace rule " + name + ": " + x.skip + " (needs concrete source/destination addresses or source any from an internet-facing zone)."); return null; }
  const c = x.case, res = runTrace(ruleQuery(c));
  if (res) showReplayVerdict(c);
  return res;
}
function showReplayVerdict(c) {
  const v = FM.replayCase(V(), c, { links: state.links, scope: state.view });
  const ok = /^pass/.test(v.cat);
  $("#result").insertAdjacentHTML("afterbegin", '<div class="note ' + (ok ? "info" : "warn") + '" id="rule-verdict"><b>Rule ' + esc(c.rule) + "</b> (" + esc(c.scope) + ", " + esc(c.from.join(",") + " \u2192 " + c.to.join(",")) + ", on " + esc(c.instances.map((i) => i.device + (i.vsys !== "vsys1" ? ":" + i.vsys : "")).slice(0, 6).join(", ") + (c.instances.length > 6 ? " +" + (c.instances.length - 6) : "")) + "): " +
    (ok ? "the traced path crosses this rule's firewall and zones (" + esc(v.cat + (v.how === "conditional" ? ", conditional" : "")) + ")." : "the traced path does not match it - " + esc(v.cat + (v.detail ? ": " + v.detail : "")) + ". Pin the rule's firewall (Must pass through) or add a link if you know the real path.") +
    (c.kind === "internet" ? ' <span class="muted">Source is "any" from an internet-facing zone, so a public probe address is used.</span>' : "") + "</div>");
}

/* ---------------- validate with existing rules ---------------- */
const VAL = { run: 0 };
$("#val-run").addEventListener("click", () => runValidation());
$("#val-stop").addEventListener("click", () => { VAL.run++; $("#val-stop").hidden = true; $("#val-run").disabled = false; $("#val-prog").textContent = "stopped"; });
function runValidation() {
  if (!state.devices.length) { flash("Load a config first."); return Promise.resolve(null); }
  const my = ++VAL.run, loo = $("#val-loo").checked, cap = Number($("#val-cap").value);
  const all = FM.replayCases(V(), { links: state.links });
  let cases = all.cases;
  if (cap && cases.length > cap) { const step = cases.length / cap; cases = Array.from({ length: cap }, (_, i) => cases[Math.floor(i * step)]); } // even sample across the rulebase
  const results = []; let i = 0; const t0 = performance.now();
  $("#val-run").disabled = true; $("#val-stop").hidden = false; $("#val-out").innerHTML = "";
  return new Promise((done) => {
    const tick = () => {
      if (my !== VAL.run) return done(null);
      const until = performance.now() + 40;
      while (i < cases.length && performance.now() < until) { const c = cases[i++]; const r = FM.replayCase(V(), c, { links: state.links, leaveOneOut: loo, scope: state.view }); results.push({ c, cat: r.cat, detail: r.detail, how: r.how, conflict: !!r.conflict, scopeCause: r.scopeCause || null, pathStatus: r.res && r.res.pathStatus ? r.res.pathStatus.status : null }); }
      $("#val-prog").textContent = i + " / " + cases.length + " rules";
      if (i < cases.length) return setTimeout(tick, 0);
      $("#val-run").disabled = false; $("#val-stop").hidden = true;
      const S = FM.replaySummary(results);
      state.validation = { results, summary: S, skipped: all.skipped, units: all.units, total: all.cases.length, loo, ms: Math.round(performance.now() - t0) };
      renderValidation();
      done(state.validation);
    };
    setTimeout(tick, 0);
  });
}
function renderValidation(filter) {
  const V = state.validation; if (!V) return;
  const S = V.summary, cats = Object.entries(S.byCategory).sort((a, b) => b[1] - a[1]);
  $("#val-sum").textContent = "- " + S.rate + "% of " + S.total + " replayed rules pass";
  $("#val-prog").textContent = V.ms + " ms";
  let h = '<p><b class="' + (S.rate >= 90 ? "ok" : "") + '" id="val-rate">' + S.rate + "% pass</b> (" + S.pass + " of " + S.total + (V.total > S.total ? ", evenly sampled from " + V.total : "") + " replayable rules, " + V.units + " rules in total" + (V.loo ? ", replayed rule left out of the evidence" : "") + ').</p><p class="muted">Each enabled allow rule with concrete addresses is turned into one flow (first host of its source and destination, first port of its service). It passes when the traced path crosses one of the rule\'s firewalls through the rule\'s zones. Skipped: ' +
    esc(Object.entries(V.skipped).map(([k, v]) => k + " " + v).join(", ") || "none") + ".</p>";
  h += table("val-cats", ["Result", "Rules", "Share"], cats.map(([k, v]) => [{ html: /^pass/.test(k) ? esc(k) : '<a href="#" data-vcat="' + esc(k) + '">' + esc(k) + "</a>" }, v, Math.round(1000 * v / S.total) / 10 + "%"]));
  const bp = S.byPath || {}, bpn = (bp.complete || 0) + (bp.suggested || 0) + (bp.incomplete || 0) + (bp.error || 0);
  if (bpn) h += '<p id="val-path">Path status of the replayed traces: <b>' + (bp.complete || 0) + "</b> complete, <b>" + (bp.suggested || 0) + "</b> suggested (some hop assumed), <b>" + (bp.incomplete || 0) + "</b> incomplete" + (bp.error ? ", " + bp.error + " unavailable" : "") + ". Add links or public-space map entries to turn suggested paths into complete ones.</p>";
  let confLine = "Routing and rules disagree on <b>" + S.conflicts + "</b> of " + S.total + " flows";
  const hopN = S.conflictsHiddenHop || 0, ownN = S.conflictsHiddenOwner || 0, genu = S.conflictsGenuine, hidN = hopN + ownN;
  if (S.conflicts && hidN) {
    const bits = [];
    if (hopN) bits.push("<b>" + hopN + "</b> only appear because the scope hid the firewall routing would use");
    if (ownN) bits.push("<b>" + ownN + "</b> only appear because the scope hid the address's owner");
    confLine += ": " + bits.join("; ");
    confLine += genu ? "; <b>" + genu + "</b> also disagree when every site is included and are worth reviewing" : ". Those are not, by themselves, stale rules — switch the scope to All sites to see the routed path";
  } else if (S.conflicts) {
    confLine += (S.byCategory["routing disagrees with rule"] ? " (" + S.byCategory["routing disagrees with rule"] + " of them only pass against routing)" : "") + " — likely stale rules or routing problems worth reviewing";
  }
  h += '<p id="val-conf">' + confLine + '. <a href="#" data-vcat="__conflict">Show them</a></p>';
  const fails = V.results.filter((r) => filter === "__conflict" ? r.conflict || r.cat === "routing disagrees with rule" : !/^pass/.test(r.cat) && (!filter || r.cat === filter));
  if (fails.length) h += "<h3>" + (filter === "__conflict" ? "Routing / rules conflicts" : "Failures") + (filter && filter !== "__conflict" ? " - " + esc(filter) : "") + (filter ? ' <a href="#" data-vcat="">(show all failures)</a>' : "") + ' <span class="muted">(' + fails.length + (fails.length > 300 ? ", first 300" : "") + "; click Trace to see the path the tool picked)</span></h3>" +
    table("val-fails", ["Rule", "Firewalls", "Zones", "Flow", "Result", ""], fails.slice(0, 300).map((r) => [r.c.rule, r.c.instances.map((x) => DL(x.device)).slice(0, 3).join(", ") + (r.c.instances.length > 3 ? " +" + (r.c.instances.length - 3) : ""), r.c.from.join(",") + " \u2192 " + r.c.to.join(","), r.c.src + " \u2192 " + r.c.dst + " " + r.c.proto + (r.c.port != null ? "/" + r.c.port : ""), r.cat + (r.detail ? ": " + trunc(r.detail, 90) : ""),
      { html: '<button type="button" class="sm" data-vtrace="' + V.results.indexOf(r) + '">Trace</button>' }]));
  const out = $("#val-out"); out.innerHTML = h;
  $$("[data-vcat]", out).forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); renderValidation(a.dataset.vcat || null); }));
  $$("[data-vtrace]", out).forEach((b) => b.addEventListener("click", () => { const r = V.results[Number(b.dataset.vtrace)]; if (runTrace(ruleQuery(r.c))) { showReplayVerdict(r.c); $("#result").scrollIntoView({ block: "start" }); } }));
}

/* ---------------- zone findings: cleanup list ---------------- */
const FIND = { rows: null };
$("#find-run").addEventListener("click", () => {
  const t = performance.now(); FIND.rows = FM.zoneFindings(V()); FIND.ms = Math.round(performance.now() - t); renderFindings();
});
const findCols = ["Rule", "Scope", "Field", "Object", "Range", "Rule zones", "Where it routes (firewall: zones)", "Finding"];
const findRow = (f) => [f.rule, f.scope, f.field, f.object, f.range, f.ruleZones.join(", "), f.actual.map((a) => DL(a.firewall) + ": " + a.zones.join("/")).join("; "), f.text];
function renderFindings() {
  const F = FIND.rows || [], rules = new Set(F.map((f) => f.scope + "|" + f.rule)).size;
  let h = '<div class="card" id="findings"><div class="ctl"><h2 style="margin:0;flex:1">Zone findings: ' + F.length + " object" + (F.length === 1 ? "" : "s") + " in " + rules + " rule" + (rules === 1 ? "" : "s") + ' <small class="muted">(' + FIND.ms + ' ms)</small></h2><button id="find-csv">Export CSV</button><button id="find-html">Export HTML</button></div>' +
    '<p class="muted">Allow rules whose source or destination object never routes to the rule\'s from/to-zone on any firewall that carries the rule. PAN-OS picks zones from the ingress/egress interface, so that part of the rule never matches there: a stale object, a wrong zone, or a missing route. Destinations behind destination NAT are skipped (the post-NAT zone decides).</p>';
  if (F.length) h += '<div class="tblwrap" style="max-height:420px"><table class="data"><thead><tr>' + findCols.map((c) => "<th>" + esc(c) + "</th>").join("") + "</tr></thead><tbody>" + F.slice(0, 500).map((f) => "<tr>" + findRow(f).map((v) => "<td>" + esc(v) + "</td>").join("") + "</tr>").join("") + "</tbody></table></div>" + (F.length > 500 ? '<p class="muted">First 500 shown; the exports have all ' + F.length + ".</p>" : "");
  $("#find-out").innerHTML = h + "</div>";
  $("#find-csv").addEventListener("click", () => download("zone-findings-" + stamp() + ".csv", new Blob([[findCols].concat(F.map(findRow)).map((l) => l.map(csvCell).join(",")).join("\r\n") + "\r\n"], { type: "text/csv" })));
  $("#find-html").addEventListener("click", () => download("zone-findings-" + stamp() + ".html", new Blob(['<!doctype html><html><head><meta charset="utf-8"><title>Zone findings</title><style>body{font:13px system-ui,Arial;margin:24px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}th{background:#eee}</style></head><body><h1>Zone findings (rule cleanup list)</h1><p>' + F.length + " objects in " + rules + " rules. Generated " + esc(new Date().toLocaleString()) + " by PAN-OS FlowMapper " + esc(FM.version) + ". Each row: the object never routes to the rule's zone on the firewalls carrying the rule.</p><table><tr>" + findCols.map((c) => "<th>" + esc(c) + "</th>").join("") + "</tr>" + F.map((f) => "<tr>" + findRow(f).map((v) => "<td>" + esc(v) + "</td>").join("") + "</tr>").join("") + "</table></body></html>"], { type: "text/html" })));
}

/* ---------------- topology ---------------- */
$("#topo-dev").addEventListener("change", renderTopo);
$("#topo-svg").addEventListener("click", () => exportSvg($("#topo-body svg"), "topology"));
$("#topo-png").addEventListener("click", () => exportPng($("#topo-body svg"), "topology"));
function renderTopo() {
  const tab = $("#tab-topo"); if (tab.hidden) return;
  const d = V().find((x) => x.id === $("#topo-dev").value) || V()[0];
  $("#topo-body").innerHTML = d ? topoSvg(d) : "";
}
function topoSvg(d) {
  const ctxs = [...d.vsys.values()];
  const W = 280, GAP = 60, PAD = 20, TOP = 76;
  const ifsOf = (zone) => [...d.interfaces.values()].filter((i) => i.zone === zone.name && i.vsys === zone.vsys);
  const layout = ctxs.map((c) => { let h = 36; const zs = [...c.zones.values()].map((z) => { const ifs = z.type === "external" ? [] : ifsOf(z); const zh = 24 + Math.max(1, ifs.length) * 16 + 6; h += zh + 6; return { z, ifs, zh }; }); return { c, zs, h: h + 6 }; });
  const vrs = [...new Set(d.vrs.values())];
  const H = Math.max(...layout.map((l) => l.h), 80);
  const vrY = TOP + H + 50, vrW = 200, vrH = 58;
  const width = Math.max(PAD * 2 + layout.length * (W + GAP), PAD * 2 + vrs.length * (vrW + 30)) ;
  const height = vrY + vrH + 70;
  let o = '<svg xmlns="http://www.w3.org/2000/svg" width="' + width + '" height="' + height + '" viewBox="0 0 ' + width + " " + height + '" style="background:#fff">' + DEFS + '<rect width="100%" height="100%" fill="#fff"/>';
  o += T(PAD, 26, "Topology: " + d.name + (d.multiVsys ? " (multi-vsys)" : ""), { size: 15, bold: true, max: 100 });
  const pos = new Map(), zpos = new Map(), ifpos = new Map();
  layout.forEach((l, i) => {
    const x = PAD + i * (W + GAP), y = TOP, col = l.c.isSG ? C.sg : DEVCOL[i % DEVCOL.length];
    pos.set(l.c.name, { x, y, w: W, h: l.h });
    o += R(x, y, W, l.h, { fill: l.c.isSG ? C.sgb : C.card, stroke: col, sw: 1.5 }) + '<rect x="' + x + '" y="' + y + '" width="' + W + '" height="28" rx="8" fill="' + col + '"/>' + T(x + 10, y + 19, (l.c.isSG ? "Shared gateway " : "") + l.c.name + (l.c.display !== l.c.name ? " - " + l.c.display : "") + (l.c.dg ? " [DG " + l.c.dg + "]" : ""), { size: 13, bold: true, fill: "#fff", max: 38 });
    let yy = y + 36;
    for (const { z, ifs, zh } of l.zs) {
      const ext = z.type === "external";
      o += R(x + 8, yy, W - 16, zh, { fill: ext ? C.yb : C.bg, stroke: ext ? C.y : C.bd, rx: 6 }) + T(x + 14, yy + 16, "zone " + z.name + "  (" + z.type + ")", { size: 12, bold: true, max: 36 });
      zpos.set(l.c.name + "|" + z.name, { x: x + W - 8, y: yy + 12, ext: ext ? z.members : null });
      if (ext) o += T(x + 14, yy + 32, "\u2192 " + z.members.join(", "), { size: 11, fill: C.mu });
      ifs.forEach((it, k) => { o += T(x + 20, yy + 32 + k * 16, it.name + "  " + it.ips.map((a) => a.text).join(", "), { size: 11, fill: C.tx, max: 40 }); ifpos.set(it.name, { x: x + 20, y: yy + 32 + k * 16 }); });
      if (!ext && !ifs.length) o += T(x + 20, yy + 32, "(no layer3 interfaces)", { size: 11, fill: C.mu });
      yy += zh + 6;
    }
  });
  // external zone links: route through the gap, then over the top of the cards
  let li = 0;
  for (const [k, p] of zpos) {
    if (!p.ext) continue;
    for (const tgt of p.ext) {
      const t = pos.get(tgt); if (!t) continue;
      const lane = TOP - 8 - (li % 5) * 6, gx = p.x + 10 + (li % 4) * 6, tx = t.x + t.w / 2 + ((li % 3) - 1) * 14;
      o += '<path d="M' + p.x + "," + p.y + " L" + gx + "," + p.y + " L" + gx + "," + lane + " L" + tx + "," + lane + " L" + tx + "," + (t.y - 2) + '" fill="none" stroke="' + C.y + '" stroke-width="1.8" marker-end="url(#ah)"/>';
      li++;
    }
  }
  // VRs
  const vrpos = new Map();
  vrs.forEach((vr, i) => {
    const x = PAD + i * (vrW + 30);
    vrpos.set(vr.name, { x, y: vrY });
    o += R(x, vrY, vrW, vrH, { fill: C.bb, stroke: C.b, sw: 1.5 }) + T(x + 10, vrY + 18, (vr.engine === "advanced" ? "LR " : "VR ") + vr.name, { size: 13, bold: true, max: 26 }) +
      T(x + 10, vrY + 34, vr.routes.filter((r) => r.type === "static").length + " static, " + vr.interfaces.length + " interfaces", { size: 11, fill: C.mu }) + T(x + 10, vrY + 49, vr.dynamic.length ? "dynamic: " + vr.dynamic.join(", ") : (vr.owner ? "vsys " + vr.owner : ""), { size: 11, fill: vr.dynamic.length ? C.y : C.mu, max: 30 });
    // link VR to owning vsys card
    const own = pos.get(vr.owner);
    if (own) o += '<line x1="' + (x + vrW / 2) + '" y1="' + vrY + '" x2="' + (own.x + own.w / 2) + '" y2="' + (own.y + own.h) + '" stroke="' + C.b + '" stroke-width="1.2" stroke-dasharray="3 3"/>';
  });
  // next-vr links
  let nvk = 0;
  for (const vr of vrs) {
    const a = vrpos.get(vr.name);
    const targets = new Set(vr.routes.filter((r) => r.nexthop.type === "next-vr").map((r) => r.nexthop.value));
    for (const t of targets) { const b = vrpos.get(t); if (!b) continue; const dir = b.x > a.x ? 1 : -1, depth = 14 + (nvk++ % 6) * 7; const ax = a.x + vrW / 2 + dir * 20, bx = b.x + vrW / 2 - dir * 20;
      o += '<path d="M' + ax + "," + (vrY + vrH) + " L" + ax + "," + (vrY + vrH + depth) + " L" + bx + "," + (vrY + vrH + depth) + " L" + bx + "," + (vrY + vrH + 2) + '" fill="none" stroke="' + C.b + '" stroke-width="1.4" marker-end="url(#ah)"/>'; }
  }
  o += T(PAD, height - 8, "Orange arrows: external zone -> target vsys. Blue curves: next-vr static routes. Dashed: router used by vsys.", { size: 11, fill: C.mu, max: 140 });
  return o + "</svg>";
}

/* ---------------- environment: all firewalls by site ---------------- */
const ENV = { key: null, env: null, expanded: new Set(), layout: null, envAll() { const k = state.devices.map((d) => d.id).join(",") + "|" + JSON.stringify(state.links); if (this.fullKey !== k || !this.full) { this.fullKey = k; this.full = state.view && state.view.devices === state.devices && this.env ? this.env : FM.environment(state.devices, state.links); } return this.full; } };
let envT = null;
$("#env-q").addEventListener("input", () => { clearTimeout(envT); envT = setTimeout(renderEnv, 250); });
$("#env-exp").addEventListener("click", () => { const units = (ENV.mode === "vsys" && ENV.vsys) ? ENV.vsys.units : (ENV.env && ENV.env.units); if (units) units.forEach((u) => { ENV.expanded.add(u.id); ENV.expanded.add(u.id + ":all"); }); renderEnv(); });
$("#env-col").addEventListener("click", () => { ENV.expanded.clear(); renderEnv(); });
function envExportName() { return ENV.mode === "pano" ? "panorama" : ENV.mode === "vsys" ? "vsys-map" : "environment"; }
$("#env-svg").addEventListener("click", () => exportSvg($("#env-body svg"), envExportName()));
$("#env-png").addEventListener("click", () => exportPng($("#env-body svg"), envExportName()));
$("#env-drawio").addEventListener("click", () => { if (ENV.layout) download(envExportName() + "-" + stamp() + ".drawio", new Blob([FM.drawioXml(ENV.layout, ENV.mode === "pano" ? "Panorama" : ENV.mode === "vsys" ? "Vsys map" : "Environment")], { type: "application/xml" })); });
["#env-mode", "#env-net", "#env-stk", "#env-empty"].forEach((id) => $(id).addEventListener("change", renderEnv));
function panoFile() { return state.files.find((f) => f.enabled && f.loaded.kind === "panorama"); }
function envMatcher(q) {
  if (!q) return { match: () => true, auto: new Set() };
  const ipq = /^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(q) ? FM.parsePrefix(q) : null, auto = new Set();
  const inNet = (txt) => { if (!ipq) return false; const p = FM.parsePrefix(txt); if (!p) return false; const lo = p.lo - (p.lo % Math.pow(2, 32 - p.len)), hi = lo + Math.pow(2, 32 - p.len) - 1; return ipq.lo <= hi && ipq.hi >= lo; };
  const siteLab = new Map(ENV.env.sites.map((s) => [s.id, s.label.toLowerCase()]));
  return { auto, match: (u) => {
    if (u.members.some((m) => m.toLowerCase().includes(q)) || (siteLab.get(u.site) || "").includes(q)) return true;
    const hit = u.vsys.some((v) => v.name.toLowerCase().includes(q) || v.zones.some((z) => z.name.toLowerCase().includes(q) || z.ifaces.some((i) => i.ips.some((x) => x.includes(q) || inNet(x)))));
    if (hit) auto.add(u.id); return hit;
  } };
}
function renderEnv() {
  if ($("#tab-env").hidden || !state.devices.length) return;
  const key = V().map((d) => d.id).join(",") + "|" + JSON.stringify(state.links);
  if (ENV.key !== key) { ENV.key = key; ENV.env = FM.environment(V(), state.links); if (ENV.env.units.length <= 6) ENV.env.units.forEach((u) => ENV.expanded.add(u.id)); }
  const E = ENV.env, q = $("#env-q").value.trim().toLowerCase(), M = envMatcher(q);
  const vis = E.units.filter(M.match);
  const expanded = new Set([...ENV.expanded, ...M.auto]);
  const pf = panoFile();
  $("#env-mode").querySelector('[value="pano"]').disabled = !pf;
  if (!pf && $("#env-mode").value === "pano") $("#env-mode").value = "site";
  ENV.mode = $("#env-mode").value; $$(".env-pano-only").forEach((x) => (x.hidden = ENV.mode !== "pano"));
  if (ENV.mode === "pano") {
    const pk = ENV.key + "|" + pf.name;
    if (ENV.pkey !== pk) { ENV.pkey = pk; ENV.pano = FM.panoramaView(pf.loaded.panorama, ENV.envAll(), state.devices); }
    const P = ENV.pano, c = P.counts;
    ENV.layout = FM.panoLayout(P, ENV.envAll(), { expanded, match: M.match, q, network: $("#env-net").checked, circuits: state.circuits, stackLinks: $("#env-stk").checked, showEmpty: $("#env-empty").checked });
    $("#env-sum").textContent = P.name + ": " + c.firewalls + " firewalls (" + c.ha + " HA groups merged), " + c.dgs + " device groups, " + c.stacks + " template stacks, " + c.templates + " templates." + [c.noStack ? " " + c.noStack + " without a template stack" : "", c.noNetwork ? " " + c.noNetwork + " with no network config" : "", c.noDg ? " " + c.noDg + " in no device group" : "", c.notLoaded ? " " + c.notLoaded + " device-group members not loaded" : "", c.emptyDgs ? " " + c.emptyDgs + " empty device groups" + ($("#env-empty").checked ? "" : " (hidden)") : ""].filter(Boolean).join(";") + (q ? " Showing " + vis.length + " matching '" + q + "'." : "") + " Click a firewall to expand it.";
  } else if (ENV.mode === "vsys") {
    ENV.vsys = FM.vsysMap(V(), { links: state.links, path: (state.last && state.last.segments) || [] });
    const units = ENV.vsys.units.filter((u) => { const eu = E.units.find((x) => x.id === u.id); return !eu || M.match(eu); });
    ENV.layout = FM.vsysMapLayout({ env: ENV.vsys.env, units, pathCount: ENV.vsys.pathCount }, { expanded });
    const nV = units.reduce((a, u) => a + u.vsys.length, 0), nP = units.reduce((a, u) => a + u.pathVsys, 0);
    $("#env-sum").textContent = units.length + " firewalls, " + nV + " vsys" + (nP ? " (" + nP + " on the last trace, pulled out when you expand a firewall)" : "") + ". Next hops no loaded firewall owns go to the unknown-network cloud. Click a firewall to expand it; Expand all lists every vsys." + (q ? " Showing matches for '" + q + "'." : "");
  } else ENV.layout = FM.envLayout(E, { expanded, match: M.match, circuits: state.circuits });
  if (ENV.mode === "site") $("#env-sum").textContent = E.units.length + " firewalls (" + E.units.filter((u) => u.members.length > 1).length + " HA groups merged) in " + E.sites.length + " inferred sites; " + E.units.filter((u) => u.wan).length + " on the inferred WAN core, " + E.units.filter((u) => u.internet.length).length + " with an internet edge, " + E.fabrics.length + " external BGP fabrics" + (q ? ". Showing " + vis.length + " matching '" + q + "'" : "") + ".";
  $("#pano-box").innerHTML = ENV.mode === "pano" ? panoPairHtml() : ""; bindPanoPair($("#pano-box"));
  $("#env-body").innerHTML = envSvg(ENV.layout);
  $$("#env-body [data-unit]").forEach((g) => {
    g.addEventListener("click", () => { const id = g.dataset.unit; if (ENV.expanded.has(id)) ENV.expanded.delete(id); else ENV.expanded.add(id); renderEnv(); });
    g.addEventListener("dblclick", () => { $("#topo-dev").value = g.dataset.unit; showTab("topo"); });
  });
}
/* ---------------- network map (inferred topology across all firewalls) ---------------- */
const mapCache = { key: null, topo: null, pos: null };
let mapT = null;
$("#map-q").addEventListener("input", () => { clearTimeout(mapT); mapT = setTimeout(renderMap, 250); });
["#map-stub", "#map-inet", "#map-hl", "#map-zoom"].forEach((id) => $(id).addEventListener("change", renderMap));
$("#map-svg").addEventListener("click", () => exportSvg($("#map-body svg"), "network-map"));
$("#map-png").addEventListener("click", () => exportPng($("#map-body svg"), "network-map"));
function renderMap() {
  const tab = $("#tab-map"); if (tab.hidden || !state.devices.length) return;
  const key = V().map((d) => d.id).join(",") + "|" + JSON.stringify(state.links);
  if (mapCache.key !== key) { mapCache.key = key; mapCache.topo = FM.topology(V(), state.links); mapCache.pos = null; }
  const topo = mapCache.topo;
  const q = $("#map-q").value.trim().toLowerCase(), showStub = $("#map-stub").checked;
  const adj = new Map(); topo.nodes.forEach((n) => adj.set(n.id, []));
  topo.edges.forEach((e) => { adj.get(e.a).push(e.b); adj.get(e.b).push(e.a); });
  const showInet = $("#map-inet").checked;
  const inetR = new Set(showInet ? [] : topo.nodes.filter((n) => n.type === "rtr" && !n.core && !n.private).map((n) => n.id));
  const inetS = new Set(showInet ? [] : topo.nodes.filter((n) => n.type === "seg" && n.fws === 1 && n.routers > 0 && adj.get(n.id).filter((t) => t.startsWith("rtr:")).every((t) => inetR.has(t))).map((n) => n.id));
  let vis = new Set(topo.nodes.filter((n) => (showStub || n.type !== "seg" || !n.stub) && !inetR.has(n.id) && !inetS.has(n.id)).map((n) => n.id));
  if (q) {
    const seeds = topo.nodes.filter((n) => n.label.toLowerCase().includes(q)).map((n) => n.id);
    const keep = new Set(seeds); let fr = seeds;
    for (let d = 0; d < 2; d++) { const nx = []; for (const id of fr) for (const t of adj.get(id)) if (!keep.has(t) && (t !== "core" || d === 0)) { keep.add(t); nx.push(t); } fr = nx; }
    vis = new Set([...keep].filter((id) => vis.has(id) || seeds.includes(id)));
  }
  const nodes = topo.nodes.filter((n) => vis.has(n.id) && (n.type !== "core" || n.members > 0));
  const ids = new Set(nodes.map((n) => n.id));
  const edges = topo.edges.filter((e) => ids.has(e.a) && ids.has(e.b));
  const fwN = topo.nodes.filter((n) => n.type === "fw").length, segN = topo.nodes.filter((n) => n.type === "seg"), rN = topo.nodes.filter((n) => n.type === "rtr");
  $("#map-sum").textContent = fwN + " firewalls, " + segN.length + " subnets (" + segN.filter((x) => x.fws > 1).length + " shared by 2+ firewalls), " + rN.length + " inferred routers (" + rN.filter((x) => x.core).length + " joined into the inferred WAN/MPLS core)" + (q ? " - showing " + nodes.length + " nodes around '" + q + "'" : "") + ".";
  // highlight
  const hlN = new Set(), hlE = new Set();
  if ($("#map-hl").checked && state.last && state.last.plan && state.last.plan.paths && state.last.plan.paths[state.last.plan.chosen]) {
    for (const h of state.last.plan.paths[state.last.plan.chosen].hops) { (h.nodeIds || []).forEach((id, i, a) => { hlN.add(id); if (i) hlE.add(a[i - 1] + ">" + id); }); }
  }
  $("#map-body").innerHTML = mapSvg(nodes, edges, hlN, hlE, Number($("#map-zoom").value));
  // details tables
  const visR = rN.filter((x) => !q || ids.has(x.id));
  const visS = segN.filter((x) => x.fws > 1 || x.routers > 0).filter((x) => !q || ids.has(x.id));
  const neigh = (id, type) => adj.get(id).map((t) => topo.nodes.find((n) => n.id === t)).filter((n) => n && n.type === type).map((n) => n.label);
  $("#map-detail").innerHTML = "<h3>Inferred routers</h3>" + table("t-rtr", ["Router (next hop)", "On subnet", "Used by", "In WAN/MPLS core", "Why"], visR.slice(0, 2000).map((x) => [x.label, neigh(x.id, "seg").join(", "), x.usedBy + " route(s)", x.core ? "yes" : "no", x.why])) +
    "<h3>Subnets with routers or several firewalls</h3>" + table("t-seg", ["Subnet", "Firewalls", "Routers", "Naming hints"], visS.slice(0, 2000).map((x) => [x.label, neigh(x.id, "fw").join(", "), neigh(x.id, "rtr").join(", "), x.hints.join(", ")]));
}
function mapLayout(nodes, edges) {
  // deterministic force-directed layout
  const N = nodes.length, idx = new Map(nodes.map((n, i) => [n.id, i]));
  const fws = nodes.filter((n) => n.type === "fw");
  const P = nodes.map((n, i) => { const a = (i * 2.399963) % (Math.PI * 2), r = n.type === "core" ? 0 : n.type === "fw" ? 420 : n.type === "rtr" ? 180 : 300; return { x: Math.cos(a) * r, y: Math.sin(a) * r }; });
  fws.forEach((n, k) => { const a = (k / Math.max(1, fws.length)) * Math.PI * 2, i = idx.get(n.id); P[i].x = Math.cos(a) * 460; P[i].y = Math.sin(a) * 460; });
  const E = edges.map((e) => [idx.get(e.a), idx.get(e.b), e.kind]);
  const it = N > 400 ? 120 : 260;
  for (let s = 0; s < it; s++) {
    const t = 1 - s / it, F = P.map(() => ({ x: 0, y: 0 }));
    for (let i = 0; i < N; i++) for (let j = i + 1; j < N; j++) {
      let dx = P[i].x - P[j].x, dy = P[i].y - P[j].y, d2 = dx * dx + dy * dy + 0.01;
      if (d2 > 250000) continue;
      const f = 2600 / d2, d = Math.sqrt(d2); dx /= d; dy /= d;
      F[i].x += dx * f * 40; F[i].y += dy * f * 40; F[j].x -= dx * f * 40; F[j].y -= dy * f * 40;
    }
    for (const [a, b, k] of E) {
      const L = k === "core" ? 170 : k === "attach" ? 50 : k === "if" ? 85 : 130;
      const dx = P[b].x - P[a].x, dy = P[b].y - P[a].y, d = Math.sqrt(dx * dx + dy * dy) + 0.01, f = (d - L) * 0.06;
      F[a].x += dx / d * f; F[a].y += dy / d * f; F[b].x -= dx / d * f; F[b].y -= dy / d * f;
    }
    for (let i = 0; i < N; i++) {
      if (nodes[i].type === "core") { P[i].x = 0; P[i].y = 0; continue; }
      F[i].x -= P[i].x * 0.004; F[i].y -= P[i].y * 0.004;
      const m = Math.sqrt(F[i].x * F[i].x + F[i].y * F[i].y), cap = 30 * t + 1;
      if (m > cap) { F[i].x *= cap / m; F[i].y *= cap / m; }
      P[i].x += F[i].x; P[i].y += F[i].y;
    }
  }
  return P;
}
function mapSvg(nodes, edges, hlN, hlE, zoom) {
  if (!nodes.length) return '<p class="muted">Nothing matches.</p>';
  const P = mapLayout(nodes, edges);
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  P.forEach((p) => { minX = Math.min(minX, p.x); minY = Math.min(minY, p.y); maxX = Math.max(maxX, p.x); maxY = Math.max(maxY, p.y); });
  const pad = 110, W = Math.max(600, maxX - minX + pad * 2), H = Math.max(400, maxY - minY + pad * 2 + 30);
  const X = (p) => p.x - minX + pad, Y = (p) => p.y - minY + pad + 30;
  const idx = new Map(nodes.map((n, i) => [n.id, i]));
  let o = '<svg xmlns="http://www.w3.org/2000/svg" width="' + Math.round(W * zoom) + '" height="' + Math.round(H * zoom) + '" viewBox="0 0 ' + Math.round(W) + " " + Math.round(H) + '" style="background:#fff">' + '<rect width="100%" height="100%" fill="#fff"/>';
  o += T(16, 22, "Inferred network map: firewalls, subnets, inferred routers and WAN/MPLS core", { size: 15, bold: true, max: 120 });
  const ES = { if: [C.bd, 1.3, null], attach: ["#94a3b8", 1.2, "3 3"], core: ["#d97706", 1.4, "6 4"], nh: [C.b, 2, null], link: ["#7c3aed", 3, null], hint: ["#d97706", 1.4, "2 4"] };
  for (const e of edges) {
    const a = P[idx.get(e.a)], b = P[idx.get(e.b)];
    const hl = hlE.has(e.a + ">" + e.b) || hlE.has(e.b + ">" + e.a);
    const st = ES[e.kind] || [C.mu, 1, null];
    o += '<line x1="' + X(a).toFixed(1) + '" y1="' + Y(a).toFixed(1) + '" x2="' + X(b).toFixed(1) + '" y2="' + Y(b).toFixed(1) + '" stroke="' + (hl ? "#16a34a" : st[0]) + '" stroke-width="' + (hl ? 4 : st[1]) + '"' + (st[2] && !hl ? ' stroke-dasharray="' + st[2] + '"' : "") + "><title>" + esc(e.kind + (e.label ? ": " + e.label : "")) + "</title></line>";
  }
  nodes.forEach((n, i) => {
    const x = X(P[i]), y = Y(P[i]), hl = hlN.has(n.id);
    if (n.type === "core") { o += '<g class="mnode" data-id="core">' + cloud(x, y, 180, 90, "#d97706") + T(x, y - 2, "WAN / MPLS core", { size: 12, bold: true, anchor: "middle" }) + T(x, y + 14, "(inferred, " + n.members + " routers)", { size: 10, anchor: "middle", fill: C.mu }) + "</g>"; return; }
    if (n.type === "fw") { const w = Math.max(90, Math.min(170, n.label.length * 7.4 + 20)); o += '<g class="mnode" data-id="' + esc(n.id) + '">' + R(x - w / 2, y - 15, w, 30, { fill: hl ? "#dcfce7" : C.bb, stroke: hl ? "#16a34a" : n.multiVsys ? C.sg : C.b, sw: hl ? 3 : 1.6, rx: 6 }) + T(x, y + 4, n.label, { size: 11.5, bold: true, anchor: "middle", max: 22 }) + (n.multiVsys ? T(x, y + 26, n.vsys + " vsys", { size: 9.5, anchor: "middle", fill: C.sg }) : "") + "<title>" + esc(n.label + (n.multiVsys ? " (multi-vsys, " + n.vsys + ")" : "")) + "</title></g>"; return; }
    if (n.type === "rtr") { o += '<g class="mnode" data-id="' + esc(n.id) + '"><circle cx="' + x.toFixed(1) + '" cy="' + y.toFixed(1) + '" r="9" fill="' + (hl ? "#dcfce7" : n.core ? "#fff7ed" : "#f1f5f9") + '" stroke="' + (hl ? "#16a34a" : n.core ? "#d97706" : "#64748b") + '" stroke-width="' + (hl ? 3 : 1.5) + '"' + (n.inferred ? ' stroke-dasharray="3 2"' : "") + "/>" + T(x, y + 21, n.label, { size: 9.5, anchor: "middle", fill: C.mu }) + "<title>" + esc("router " + n.label + " - " + n.why) + "</title></g>"; return; }
    const w = n.label.length * 5.9 + 12;
    o += '<g class="mnode" data-id="' + esc(n.id) + '">' + R(x - w / 2, y - 9, w, 18, { fill: hl ? "#dcfce7" : n.fws > 1 ? "#ecfeff" : "#f8fafc", stroke: hl ? "#16a34a" : n.fws > 1 ? "#0f8a8a" : "#cbd5e1", rx: 9, sw: hl ? 2.5 : 1 }) + T(x, y + 4, n.label, { size: 9.5, anchor: "middle", max: 24 }) + "<title>" + esc("subnet " + n.label + " - " + n.fws + " firewall(s), " + n.routers + " router(s)" + (n.hints.length ? ", named " + n.hints.join("/") : "")) + "</title></g>";
  });
  const ly = H - 12;
  o += T(16, ly, "Blue box: firewall (purple border = multi-vsys). Pill: subnet (teal = shared). Circle: inferred router (orange = in WAN/MPLS core, dashed = far end of a /30 guessed). Orange dashed: inferred core links. Green: last traced path.", { size: 10.5, fill: C.mu, max: 220 });
  return o + "</svg>";
}

/* ---------------- raw XML ---------------- */
$("#raw-file").addEventListener("change", renderRaw);
$("#raw-mask").addEventListener("change", renderRaw);
let rawT = null; $("#raw-q").addEventListener("input", () => { clearTimeout(rawT); rawT = setTimeout(renderRaw, 250); });
function renderRaw() {
  if ($("#tab-raw").hidden) return;
  const f = state.files.find((x) => x.name === $("#raw-file").value) || state.files[0];
  const pre = $("#rawview"); if (!f) { pre.textContent = ""; return; }
  let t = f.loaded.text;
  if ($("#raw-mask").checked) t = FM.maskSecrets(t);
  const LIM = 3 * 1024 * 1024, q = $("#raw-q").value;
  let start = 0;
  if (q) { const i = t.toLowerCase().indexOf(q.toLowerCase()); if (i >= 0) start = Math.max(0, i - 2000); }
  const part = t.slice(start, start + LIM);
  let h = esc(part);
  if (q) { const re = new RegExp(esc(q).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"); h = h.replace(re, (m) => "<mark>" + m + "</mark>"); }
  pre.innerHTML = (start > 0 ? "... (" + start + " characters above)\n" : "") + h + (t.length > start + LIM ? "\n... (truncated; use Find to jump)" : "");
  const mk = pre.querySelector("mark"); if (mk) mk.scrollIntoView({ block: "center" });
}

window.__FM.ready = true;
})();
