#!/usr/bin/env node
/**
 * Headless runner for the vendored FlowMapper engine (core.js, render.js, decom.js).
 * Reads a job JSON (file paths + FCR text) and writes a plain JSON result.
 * Never logs configuration XML or FCR addresses; only counts go to stderr.
 */
"use strict";

const fs = require("fs");
const path = require("path");

function arg(flag, fallback) {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

function loadFM(corePath) {
  const resolved = path.resolve(corePath);
  if (!fs.existsSync(resolved)) throw new Error("FlowMapper core.js not found at " + resolved);
  const FM = require(resolved);
  if (!FM || typeof FM.loadConfig !== "function" || typeof FM.trace !== "function") {
    throw new Error("core.js did not export the FlowMapper FM object");
  }
  return FM;
}

function loadRender(FM, corePath) {
  // Shared renderers (flow diagram, environment diagram): vendored next to core.js. Optional so an older engine still runs.
  const rp = path.join(path.dirname(path.resolve(corePath)), "render.js");
  if (!fs.existsSync(rp)) return null;
  const R = require(rp);
  return R && typeof R.flowSvg === "function" ? R : null;
}

function loadDevices(FM, files) {
  const devices = [];
  const loaded = [];
  const cfgs = [];
  for (const f of files || []) {
    const p = f.path;
    const name = f.name || path.basename(p);
    const text = fs.readFileSync(p, "utf8");
    const cfg = FM.loadConfig(text, name);
    cfgs.push(cfg);
    const kind = cfg.panorama ? "panorama" : "firewall";
    let built = [];
    if (cfg.panorama && cfg.panorama.contexts && cfg.panorama.contexts.length) {
      // Same rule as the FlowMapper page: trace through the firewalls Panorama maps (template stack or device
      // group device lists). An unattached stack or template carries the same network as a real firewall and would
      // otherwise become a phantom device that a hairpin flow can "re-enter" (no pushed rules, so a false deny).
      const all = cfg.panorama.contexts, mapped = all.filter((c) => c.mapped);
      built = (mapped.length ? mapped : all).map((c) => FM.buildPanoramaDevice(cfg, c));
    } else if (cfg.devices && cfg.devices.length) {
      built = cfg.devices.slice();
    }
    devices.push(...built);
    loaded.push({ name, kind, devices: built.length, bytes: text.length });
  }
  const merged = typeof FM.mergeLocalBackups === "function" ? FM.mergeLocalBackups(devices) : devices;
  return { devices: merged, loaded, cfgs };
}

function summarize(devices, loaded) {
  let routes = 0, mergedLocal = 0, vsys = 0;
  for (const d of devices || []) {
    if (d.mergedLocal) mergedLocal++;
    vsys += d.vsys && typeof d.vsys.size === "number" ? d.vsys.size : (d.vsys ? d.vsys.length : 0);
    if (d.vrs && typeof d.vrs.values === "function") {
      for (const vr of d.vrs.values()) routes += (vr.routes || []).length;
    }
  }
  return {
    files: (loaded || []).length,
    devices: (devices || []).length,
    mergedLocal,
    vsys,
    staticRoutes: routes,
    fileKinds: (loaded || []).map((x) => x.kind)
  };
}

function plainHop(h) {
  return {
    n: h.n, device: h.device, hostname: (LABELS && LABELS.get(h.device)) || null, vsys: h.vsys, display: h.display || null,
    dg: h.dg || null, vr: h.vr || null, ingressIf: h.ingressIf || null, egressIf: h.egressIf || null,
    fromZone: h.fromZone || null, toZone: h.toZone || null,
    verdict: h.verdict, rule: h.rule || null, deny: !!h.deny,
    hairpin: !!h.hairpin, transit: !!h.transit
  };
}

function plainPlan(plan) {
  if (!plan) return { items: [], cli: "", required: 0, verify: 0, uncertain: 0 };
  const items = (plan.items || []).map((c) => ({
    kind: c.kind || null,
    device: c.device || null,
    vsys: c.vsys || null,
    display: c.display || null,
    dg: c.dg || null,
    dgVsys: c.dgVsys || null,
    optional: !!c.optional,
    uncertain: !!c.uncertain,
    summary: c.summary || "",
    order: c.order ? { mode: c.order.mode, before: c.order.before || null, scope: c.order.scope || null, text: c.order.text } : null,
    joinNote: c.joinNote || null,
    where: c.where || null,
    cli: Array.isArray(c.cli) ? c.cli.slice() : [],
    rule: c.rule && typeof c.rule === "object" ? { name: c.rule.name || null, from: c.rule.from, to: c.rule.to, placeBefore: c.rule.placeBefore || null } : (c.rule || null)
  }));
  return { items, cli: plan.cli || "", required: plan.required || 0, verify: plan.verify || 0, uncertain: plan.uncertain || 0 };
}

let LABELS = null; // device name (often a serial on Panorama) -> hostname, so text reads like the page
function relabel(t) {
  if (!t || !LABELS || !LABELS.size) return t;
  return String(t).replace(/\b\d{9,15}\b/g, (m) => (LABELS.has(m) ? LABELS.get(m) + " (" + m + ")" : m));
}
function setLabels(devices) {
  LABELS = new Map();
  for (const d of devices || []) { const hn = d.hostname || (d.panorama && d.panorama.hostname); if (hn && hn !== d.name) LABELS.set(d.name, hn); }
}

function plainChoice(c) {
  return {
    kind: c.kind, key: c.key || null, at: relabel(c.at) || null, what: c.what || null, reason: relabel(c.reason) || null,
    chosen: c.chosen || null, pinned: !!c.pinned, pinBy: c.pinBy || null,
    from: typeof c.from === "string" ? c.from : null,
    link: c.link && c.link.from ? { device: (LABELS && LABELS.get(c.link.from.device)) || c.link.from.device || null, iface: c.link.from.iface || null, nexthop: c.link.from.nexthop || null } : null,
    candidates: (c.candidates || []).map((x) => ({ devId: x.devId, device: x.device, hostname: x.hostname || null, serial: x.serial || null, stack: x.stack || null, site: x.site || null, iface: x.iface || null, reason: x.reason || null, label: x.label || null }))
  };
}

function plainPathStatus(ps) {
  return {
    status: ps.status || null, label: ps.label || null, confidence: ps.confidence || null, text: relabel(ps.text) || null,
    assumed: ps.assumed || 0, bgpInferred: !!ps.bgpInferred,
    assumptions: (ps.hops || []).flatMap((h) => (h.assumptions || []).map((a) => ({ hop: relabel(h.device) + (h.vsys ? " " + h.vsys : ""), what: relabel(a.what), confirm: relabel(a.confirm) || null, kind: a.kind || null }))),
    stop: ps.stop ? { where: relabel(ps.stop.where) || null, why: relabel(ps.stop.why) || null, fix: relabel(ps.stop.fix) || null, choice: !!ps.stop.choice } : null,
    choices: (ps.choices || []).map(plainChoice)
  };
}

function plainRow(rec, tr, R, dl) {
  const fcr = (tr && tr.fcr) || {};
  const ps = (tr && tr.pathStatus) || {};
  return {
    query: { src: rec.src, dst: rec.dst, proto: rec.proto || "tcp", port: rec.port == null ? null : rec.port, app: rec.app || null, ticket: rec.ticket || null, raw: rec.raw || null },
    status: (tr && tr.status) || "error",
    pathStatus: plainPathStatus(ps),
    summary: (tr && tr.summary) || "",
    notes: ((tr && tr.notes) || []).map((n) => ({ level: n.level || "info", text: relabel(n.text || String(n)), choice: /^Needs your choice/.test(n.text || "") })),
    hops: (fcr.hops || []).map(plainHop),
    why: fcr.why ? { text: relabel(fcr.why.text || ""), lines: (fcr.why.lines || []).map((l) => (typeof l === "string" ? relabel(l) : l)), vsysCount: fcr.why.vsysCount || 0, firewallCount: fcr.why.firewallCount || 0, hairpins: fcr.why.hairpins || 0, transits: fcr.why.transits || 0 } : null,
    plan: plainPlan(fcr.plan),
    enforcement: fcr.enforcement ? Object.assign({}, fcr.enforcement, { places: (fcr.enforcement.places || []).map((x) => Object.assign({}, x, { hostname: (LABELS && LABELS.get(x.device)) || null })) }) : null,
    scope: tr && tr.scope ? { mode: tr.scope.mode, chip: tr.scope.chip, hidden: tr.scope.hidden, viaHidden: tr.scope.viaHidden ? { text: relabel(tr.scope.viaHidden.text), devices: tr.scope.viaHidden.names || [], fullStatus: tr.scope.viaHidden.fullStatus || null } : null, scopeConflict: tr.scope.scopeConflict ? { cause: tr.scope.scopeConflict.cause, text: relabel(tr.scope.scopeConflict.text), devices: tr.scope.scopeConflict.names || [] } : null } : null,
    conflict: tr && tr.conflict ? { routing: relabel(tr.conflict.routing) || null, rules: relabel(tr.conflict.rules) || null, scopeCause: tr.conflict.scopeCause || null, scopeText: tr.conflict.scopeText ? relabel(tr.conflict.scopeText) : null, scopeDevices: tr.conflict.scopeDevices || [] } : null,
    drMirror: tr && tr.drMirror && tr.drMirror.enabled && tr.drMirror.items.length ? plainMirror(tr.drMirror) : null,
    diagram: R && tr && tr.segments && tr.segments.length ? safeSvg(() => R.flowSvg(tr, { DL: dl })) : null,
    checklist: fcr.checklist || [],
    filters: fcr.filters || { common: "", hops: [] }
  };
}

function safeSvg(fn) { try { return fn(); } catch (_) { return null; } }

function plainScope(sc) {
  return { mode: sc.mode, chip: sc.chip, text: sc.text, hidden: sc.hiddenCount, visible: sc.visibleCount, byRole: sc.byRole, hiddenDevices: sc.hidden.map((d) => d.hostname || (d.panorama && d.panorama.hostname) || d.name) };
}
function plainMirror(m) {
  return { text: m.text, devices: m.devices, viaDg: m.viaDg, items: m.items.map((it) => ({ device: it.display, changes: it.changes, note: it.note || null, candidates: it.candidates.map((c) => ({ device: c.display, role: c.role, level: c.level, score: c.score, reasons: c.reasons, addrNote: c.addrNote || null })) })) };
}
// The role of every site and firewall, with the reason, so the web page can show and edit them.
function plainRoles(FM, sc, devices, cfgs, profile) {
  const M = sc.model, defs = M.defs.list.map((r) => ({ id: r.id, label: r.label, focus: !!r.focus, mirror: !!r.mirror, custom: !!(profile.roles || []).some((x) => x.id === r.id) }));
  const pano = (cfgs || []).find((c) => c && c.panorama);
  return {
    defs,
    sites: M.sites.map((s) => ({ id: s.id, role: s.role, source: s.source, why: s.why, count: s.count, mixed: !!s.mixed, setBy: profile.sites[s.id] || null, included: sc.mode === "custom" ? (profile.scope.sites || []).includes(s.id) : null })),
    firewalls: devices.slice(0, 2000).map((d) => { const m = M.byDev.get(d); return { key: m.key, name: (d.hostname || (d.panorama && d.panorama.hostname) || d.name), hostname: d.hostname || (d.panorama && d.panorama.hostname) || d.hostnameInit || null, serial: d.serial || (d.panorama && d.panorama.serial) || null, stack: d.stack || null, dg: typeof FM.ruleFieldText === "function" ? FM.ruleFieldText(d, "dg") : null, site: m.site, role: m.role, source: m.source, why: m.why, setBy: profile.devices[m.key] || null, hidden: sc.hidden.includes(d) }; }),
    firewallCount: devices.length,
    panorama: pano && typeof FM.panoramaPair === "function" ? FM.panoramaPair(pano.panorama, profile) : null,
    profile
  };
}
function plainMap(FM, devices, pathSegs, R) {
  if (typeof FM.vsysMap !== "function") return null;
  const map = FM.vsysMap(devices, { path: pathSegs });
  const expand = new Set((map.units || []).filter((u) => u.pathVsys).map((u) => u.id));
  const layout = FM.vsysMapLayout(map, { expanded: expand });
  const units = (map.units || []).map((u) => ({
    id: u.id, name: u.name, members: u.members || [], site: u.site || null,
    multiVsys: !!u.multiVsys, pathVsys: u.pathVsys || 0,
    vsys: (u.vsys || []).map((v) => ({
      name: v.name, display: v.display || v.name, dg: v.dg || null, onPath: !!v.onPath,
      ifaces: v.ifaces || 0, zones: v.zones || [], unknownNhs: v.unknownNhs || 0,
      joinUncertain: !!v.joinUncertain
    }))
  }));
  return {
    units, pathCount: map.pathCount || 0, layout,
    svg: R && typeof R.envSvg === "function" ? safeSvg(() => R.envSvg(layout)) : null,
    drawio: typeof FM.drawioXml === "function" ? safeSvg(() => FM.drawioXml(layout, "Vsys map")) : null
  };
}

function readTables(job) {
  // [{device, path | text, label}] -> [{device, text, label}]; the text never goes to stderr
  return (job.routeTables || []).map((t) => ({ device: t.device, label: t.label || (t.path ? path.basename(t.path) : "pasted route table"), text: t.text != null ? String(t.text) : fs.readFileSync(t.path, "utf8") }));
}

function plainOverlap(FM, devices) {
  if (typeof FM.overlapReport !== "function") return null;
  const O = FM.overlapReport(devices);
  const card = (c) => ({ devId: c.devId, device: c.device, hostname: c.hostname || null, serial: c.serial || null, stack: c.stack || null, site: c.site || null, label: c.label || null });
  return {
    total: O.total || 0, text: O.text || "",
    sharedIps: (O.sharedIps || []).slice(0, 200).map((x) => ({ ip: x.ip, owners: (x.owners || []).map((o) => Object.assign(card(o), { iface: o.iface || null })) })),
    overlaps: (O.overlaps || []).slice(0, 200).map((x) => ({ prefix: x.prefix, owners: (x.owners || []).map((o) => Object.assign(card(o), { iface: o.iface || null, prefix: o.prefix || null })) })),
    cloned: (O.cloned || []).slice(0, 100).map((x) => ({ a: card(x.a), b: card(x.b), shared: x.sharedAddresses || 0, notHa: x.notHa || null }))
  };
}

function deviceLabel(FM, devices) {
  return (name) => { if (!name) return name; const d = devices.find((x) => x.name === name || x.id === name); return d && typeof FM.devLabel === "function" ? FM.devLabel(d) : name; };
}

// Environment (by site) and Panorama diagrams, rendered on demand for a saved trace's configuration files.
function runDiagram(job, FM, R) {
  const kind = (job.diagram && job.diagram.kind) || "site";
  if (!R || typeof R.envSvg !== "function") throw new Error("this engine copy has no diagram renderer; re-run tools/sync-flowmapper.py");
  const { devices: allDevices, cfgs } = loadDevices(FM, job.files || []);
  // the site diagram follows the scope; the Panorama diagram always shows everything Panorama manages
  const sc = kind !== "pano" && typeof FM.scopeDevices === "function" ? FM.scopeDevices(allDevices, FM.normalizeProfile(Object.assign({}, job.roles || {}, job.scope ? { scope: job.scope } : {}))) : null;
  const devices = sc ? sc.devices : allDevices;
  const E = FM.environment(devices, []);
  const expanded = new Set(E.units.length <= 6 ? E.units.map((u) => u.id) : []);
  let layout, title, summary;
  if (kind === "pano") {
    const cfg = cfgs.find((c) => c && c.panorama);
    if (!cfg) throw new Error("none of the loaded files is a Panorama export");
    const P = FM.panoramaView(cfg.panorama, E, devices);
    const c = P.counts;
    layout = FM.panoLayout(P, E, { expanded, match: () => true, q: "", network: false, circuits: [], stackLinks: true, showEmpty: false });
    title = "Panorama";
    summary = P.name + ": " + c.firewalls + " firewalls (" + c.ha + " HA groups merged), " + c.dgs + " device groups, " + c.stacks + " template stacks, " + c.templates + " templates.";
  } else {
    layout = FM.envLayout(E, { expanded, match: () => true, circuits: [] });
    title = "Environment";
    summary = E.units.length + " firewalls (" + E.units.filter((u) => u.members.length > 1).length + " HA groups merged) in " + E.sites.length + " inferred sites." + (sc && sc.hiddenCount ? " " + sc.chip + "." : "");
  }
  return { ok: true, kind, summary, svg: R.envSvg(layout), drawio: FM.drawioXml(layout, title), shapes: layout.shapes.length };
}

function run(job, FM, R) {
  const { devices: allDevices, loaded, cfgs } = loadDevices(FM, job.files || []);
  setLabels(allDevices);
  const DL = deviceLabel(FM, allDevices);
  const tables = readTables(job);
  const rtReports = tables.length && typeof FM.applyRouteTables === "function" ? FM.applyRouteTables(allDevices, tables) : [];
  // Scope: which firewalls take part (Production only leaves DR / Lab / Test out). Roles are for firewalls only; Panorama's own HA is never used.
  const hasScope = typeof FM.scopeDevices === "function" && typeof FM.normalizeProfile === "function";
  const profile = hasScope ? FM.normalizeProfile(Object.assign({}, job.roles || {}, job.scope ? { scope: job.scope } : {})) : null;
  const sc = hasScope ? FM.scopeDevices(allDevices, profile) : null;
  const devices = sc ? sc.devices : allDevices;
  const parsed = FM.parseFcr(job.fcr || "");
  const rows = [];
  const pathSegs = [];
  const opts = job.options || {};
  const traceOpts = {};
  if (opts.ignoreIntrazoneDefault) traceOpts.ignoreIntrazoneDefault = true;
  // custom next-hop links (Save as link) apply to every row; pins (Use for this trace) are per row
  // links may name firewalls by hostname, serial or id; the engine wants the device name
  const findDev = (k) => { const x = String(k || "").toLowerCase(); const d = devices.find((y) => [y.name, y.id, y.serial, y.hostname, y.panorama && y.panorama.hostname].some((v) => v && String(v).toLowerCase() === x)); return d ? d.name : k; };
  const links = (Array.isArray(job.links) ? job.links : []).map((l) => Object.assign({}, l, { from: Object.assign({}, l.from, { device: findDev(l.from && l.from.device) }), to: Object.assign({}, l.to, { device: findDev(l.to && l.to.device) }) }));
  if (links.length) traceOpts.links = links;
  const pinsFor = (i) => Object.assign({}, job.pins && job.pins["*"], job.pins && job.pins[String(i + 1)]);
  (parsed.rows || []).forEach((rec, i) => {
    const pin = pinsFor(i), o = Object.assign({}, traceOpts);
    if (pin.choices && typeof pin.choices === "object") o.choices = Object.assign({}, pin.choices);
    if (pin.dstDevice) o.dstDevice = pin.dstDevice;
    if (pin.srcDevice) o.srcDevice = pin.srcDevice;
    const tq = { src: rec.src, dst: rec.dst, proto: rec.proto || "tcp", port: rec.port, app: rec.app || undefined };
    const tr0 = FM.trace(devices, tq, o);
    if (sc) FM.attachScope(tr0, sc, tq, o, true);
    const tr = FM.annotateFcr(tr0, devices);
    if (sc && typeof FM.drMirror === "function") tr.drMirror = FM.drMirror(tr, allDevices, profile);
    if (tr.segments) pathSegs.push(...tr.segments);
    const row = plainRow(rec, tr, job.diagrams === false ? null : R, DL);
    row.pins = { choices: o.choices || {}, dstDevice: o.dstDevice || null, srcDevice: o.srcDevice || null };
    rows.push(row);
  });
  const result = {
    ok: true,
    engine: { version: FM.version || null },
    summary: Object.assign(summarize(devices, loaded), { devicesLoaded: allDevices.length }),
    scope: sc ? plainScope(sc) : null,
    roles: sc ? plainRoles(FM, sc, allDevices, cfgs, profile) : null,
    parseErrors: parsed.errors || [],
    rows,
    vsysMap: plainMap(FM, devices, pathSegs, job.diagrams === false ? null : R),
    routeTables: rtReports.map((r, i) => ({ device: r.device, label: tables[i] && tables[i].label, matched: !!r.matched, format: r.format, routes: r.routes || 0, routers: r.routers || [], unmatchedRouters: r.unmatchedRouters || [], skipped: r.skipped || 0, warnings: r.warnings || [] })),
    overlap: plainOverlap(FM, devices),
    bgp: typeof FM.bgpSummary === "function" ? devices.flatMap((d) => FM.bgpSummary(d)).map((b) => Object.assign(b, { hostname: (LABELS && LABELS.get(b.device)) || null })) : [],
    noNetwork: (devices || []).filter((d) => d.kind === "panorama" && d.interfaces && !d.interfaces.size && !d.mergedLocal).slice(0, 500).map((d) => ({ device: d.name, hostname: (LABELS && LABELS.get(d.name)) || null, serial: d.serial || null })),
    links: links.length
  };
  return result;
}

function loadDecom(FM, corePath) {
  // Decommission engine (decom.js), vendored next to core.js and hash-checked like it. It registers itself as FM.decom.
  const dp = path.join(path.dirname(path.resolve(corePath)), "decom.js");
  if (!fs.existsSync(dp)) throw new Error("the vendored engine has no decommission module; re-run tools/sync-flowmapper.py");
  const D = require(dp);
  if (!D || typeof D.analyze !== "function") throw new Error("decom.js did not export analyze()");
  return D;
}

/* Decommission: every config (Panorama and local backups), every firewall (no production scope: a reference or a permit
 * on a DR or lab firewall still counts). Returns the engine result plus the exports, as plain JSON. */
function runDecom(job, FM, D) {
  const { devices, loaded, cfgs } = loadDevices(FM, job.files || []);
  const d = job.decom || {};
  const flows = Array.isArray(d.flows) && d.flows.length ? d.flows : (d.flowsText ? (FM.parseFcr(d.flowsText).rows || []).map((r) => ({ src: r.src, dst: r.dst, proto: r.proto || "tcp", port: r.port })) : []);
  const opts = { devices };
  if (Array.isArray(d.select)) opts.select = d.select;
  const r = D.analyze(cfgs, { targets: d.targets || [], mode: d.mode === "block" ? "block" : "remove", flows }, opts);
  r.ok = true;
  r.engine = { version: FM.version || null, decom: D.version };
  r.summary = summarize(devices, loaded);
  r.exports = { csv: D.toCsv(r), markdown: D.toMarkdown(r), cli: D.cliText(r, "apply"), rollback: D.cliText(r, "rollback") };
  return r;
}

function main() {
  const core = arg("--core", path.join(__dirname, "core.js"));
  const jobPath = arg("--job");
  const outPath = arg("--out");
  if (!jobPath || !outPath) {
    process.stderr.write("usage: node cli.js --core core.js --job job.json --out out.json\n");
    process.exit(2);
  }
  const FM = loadFM(core);
  const job = JSON.parse(fs.readFileSync(jobPath, "utf8"));
  const fileCount = (job.files || []).length;
  const R = loadRender(FM, core);
  if (job.mode === "decom") {
    const r = runDecom(job, FM, loadDecom(FM, core));
    fs.writeFileSync(outPath, JSON.stringify(r));
    const c = r.counts || {};
    process.stderr.write("decom files=" + fileCount + " exact=" + (c.exact || 0) + " likely=" + (c.likely || 0) + " possible=" + (c.possible || 0) + " actions=" + (c.actions || 0) + "\n");
    return;
  }
  if (job.mode === "diagram") {
    const d = runDiagram(job, FM, R);
    fs.writeFileSync(outPath, JSON.stringify(d));
    process.stderr.write("flowtrace diagram kind=" + d.kind + " files=" + fileCount + " shapes=" + d.shapes + "\n");
    return;
  }
  const result = run(job, FM, R);
  fs.writeFileSync(outPath, JSON.stringify(result));
  const req = (result.rows || []).reduce((n, r) => n + ((r.plan && r.plan.required) || 0), 0);
  process.stderr.write("flowtrace files=" + fileCount + " rows=" + (result.rows || []).length + " required=" + req + " devices=" + (result.summary && result.summary.devices) + "\n");
}

try { main(); }
catch (err) {
  const msg = (err && err.stack) ? String(err.stack) : String(err);
  process.stderr.write("flowtrace error\n");
  const outPath = arg("--out");
  const payload = JSON.stringify({ ok: false, error: String(err && err.message || err) });
  if (outPath) {
    try { fs.writeFileSync(outPath, payload); } catch (_) { /* ignore */ }
  } else {
    process.stdout.write(payload);
  }
  process.exit(1);
}
