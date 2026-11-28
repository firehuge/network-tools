/* SPDX-License-Identifier: Apache-2.0 */
/* PAN Physical Upgrade planner: pure logic (no DOM rendering).
   Runs in the browser and in Node tests. XML parsing goes through an adapter so Node
   can use @xmldom/xmldom and the browser uses the native DOMParser. */
(function (root) {
"use strict";
const PPU = {};

/* ============================ small helpers ============================ */
const NBSP = /\u00a0/g;
function clean(s) { return String(s == null ? "" : s).replace(NBSP, " ").replace(/\r/g, ""); }
function toInt(s) { if (s == null) return null; const m = String(s).replace(/,/g, "").match(/-?\d+(?:\.\d+)?/); return m ? Math.round(parseFloat(m[0])) : null; }
function pct(a, b) { return (a != null && b) ? (100 * a / b) : null; }
function fmtNum(n) { if (n == null || isNaN(n)) return "—"; return Math.round(n).toLocaleString("en-US"); }
function fmtBps(bps) {
  if (bps == null || isNaN(bps)) return "—";
  if (bps >= 1e12) return (bps / 1e12).toFixed(2).replace(/\.?0+$/, "") + " Tbps";
  if (bps >= 1e9) return (bps / 1e9).toFixed(2).replace(/\.?0+$/, "") + " Gbps";
  if (bps >= 1e6) return (bps / 1e6).toFixed(1).replace(/\.0$/, "") + " Mbps";
  if (bps >= 1e3) return (bps / 1e3).toFixed(1).replace(/\.0$/, "") + " kbps";
  return Math.round(bps) + " bps";
}
function fmtSpeed(mbps) { if (!mbps) return "—"; return mbps >= 1000 ? (mbps / 1000) + "G" : mbps + "M"; }
function cmpVer(a, b) {
  const pa = String(a || "").match(/\d+/g) || [], pb = String(b || "").match(/\d+/g) || [];
  for (let i = 0; i < Math.max(pa.length, pb.length, 3); i++) {
    const x = +(pa[i] || 0), y = +(pb[i] || 0);
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
function majorMinor(v) { const m = String(v || "").match(/^(\d+)\.(\d+)/); return m ? m[1] + "." + m[2] : null; }
function parseDate(s) {
  if (!s) return null;
  const t = clean(s).trim();
  if (/^never$/i.test(t)) return null;
  const iso = t.match(/^(\d{4})-(\d\d)-(\d\d)/);
  if (iso) return new Date(Date.UTC(+iso[1], +iso[2] - 1, +iso[3]));
  const d = new Date(t + " UTC");
  return isNaN(+d) ? null : d;
}
function isoDate(d) { return d ? d.toISOString().slice(0, 10) : null; }
function sortIfNames(a, b) {
  const ka = ifKey(a), kb = ifKey(b);
  for (let i = 0; i < Math.max(ka.length, kb.length); i++) {
    const x = ka[i], y = kb[i];
    if (x === y) continue;
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (typeof x === "number" && typeof y === "number") return x - y;
    return String(x) < String(y) ? -1 : 1;
  }
  return 0;
}
function ifKey(n) { return String(n).split(/(\d+)/).filter(Boolean).map(p => /^\d+$/.test(p) ? +p : p); }
PPU.util = { clean, toInt, fmtNum, fmtBps, fmtSpeed, cmpVer, majorMinor, parseDate, isoDate, sortIfNames, pct };

/* ============================ interface names ============================ */
const RE_ETH = /^ethernet(\d+)\/(\d+)(?:\.(\d+))?$/;
const RE_AE = /^ae(\d+)(?:\.(\d+))?$/;
const RE_LOGICAL = /^(?:vlan|loopback|tunnel)(?:\.(\d+))?$/;
const RE_HA_DED = /^(?:ha1-a|ha1-b|ha1|ha2|hsci|ha2-a|ha2-b|dedicated-ha\d|management)$/;
function isIfToken(s) { return RE_ETH.test(s) || RE_AE.test(s) || RE_LOGICAL.test(s); }
function parentOf(name) { const i = name.indexOf("."); return i < 0 ? name : name.slice(0, i); }
function suffixOf(name) { const i = name.indexOf("."); return i < 0 ? "" : name.slice(i); }
PPU.ifnames = { RE_ETH, RE_AE, RE_LOGICAL, isIfToken, parentOf, suffixOf };

/* ============================ CLI sections ============================ */
function splitCli(text) {
  const out = new Map();
  if (!text) return out;
  const lines = clean(text).split("\n");
  let cmd = null, buf = [];
  const flush = () => {
    if (cmd == null) return;
    if (!out.has(cmd)) out.set(cmd, []);
    out.get(cmd).push(buf.join("\n"));
  };
  for (const ln of lines) {
    const m = ln.match(/^> (\S.*?)\s*$/);
    if (m) { flush(); cmd = m[1].replace(/\s+/g, " ").trim(); buf = []; continue; }
    if (cmd != null) buf.push(ln);
  }
  flush();
  return out;
}
function section(map, cmd, which) {
  const key = cmd.replace(/\s+/g, " ").trim();
  const arr = map.get(key);
  if (!arr || !arr.length) return null;
  const nonEmpty = arr.filter(s => s.trim());
  if (!nonEmpty.length) return null;
  return which === "first" ? nonEmpty[0] : nonEmpty[nonEmpty.length - 1];
}
function kv(text) {
  const o = {};
  for (const ln of clean(text || "").split("\n")) {
    const m = ln.match(/^\s*([A-Za-z0-9][\w .\-\/()?]*?)\s*:\s*(.*?)\s*$/);
    if (m && !(m[1] in o)) o[m[1].trim().toLowerCase()] = m[2];
  }
  return o;
}
PPU.cli = { splitCli, section, kv };

function parseSystemInfo(text) {
  const o = kv(text);
  if (!o.model && !o.hostname) return null;
  return {
    hostname: o.hostname || null, model: o.model || null, serial: o.serial || null,
    family: o.family || null, swVersion: o["sw-version"] || null, uptime: o.uptime || null,
    uptimeSec: parseUptime(o.uptime), multiVsys: /^on$/i.test(o["multi-vsys"] || ""),
    advancedRouting: /^on$/i.test(o["advanced-routing"] || ""),
    mgmtIp: o["ip-address"] || null, vmMode: o["vm-mode"] || null, vmCores: toInt(o["vm-cpu-count"] || o["vm-cores"]),
    vmMemGb: o["vm-memory"] && toInt(o["vm-memory"]) ? Math.round(toInt(o["vm-memory"]) / 1048576 * 10) / 10 : null, vmMem: o["vm-memory"] || o["vm-mem"] || null,
    vmLicense: o["vm-license"] || null, vmCapTier: o["vm-cap-tier"] || null, operationalMode: o["operational-mode"] || null,
    appVersion: o["app-version"] || null, threatVersion: o["threat-version"] || null,
    cloudMode: o["cloud-mode"] || null,
    time: o.time || null
  };
}
function isVmSystem(sys) { return !!sys && (/^vm$/i.test(sys.family || "") || /^(PA-)?VM(-\d+)?$/i.test(sys.model || "") || !!sys.vmMode); }
PPU.isVmSystem = isVmSystem;
// A VM-Series source has no catalog row of its own ("PA-VM"). Describe it from the license, vCPU and memory tier.
function vmSourceModel(sys, idx) {
  if (!isVmSystem(sys)) return null;
  const tierGb = sys.vmCapTier && (sys.vmCapTier.match(/(\d+(?:\.\d+)?)\s*GB/i) || [])[1];
  const memGb = tierGb ? +tierGb : sys.vmMemGb || null;
  let sessions = null;
  const rows = idx && idx.cat && idx.cat.vm_memory_tiers && idx.cat.vm_memory_tiers.rows;
  if (rows && memGb) { const r = rows.filter(x => x[0] <= memGb).pop(); if (r) sessions = r[1]; }
  return { model: sys.model || "PA-VM", form: "vm", family: "VM-Series", lifecycle: "current", vm_source: true, vcpu: sys.vmCores ? [sys.vmCores] : [], mem_gb: memGb, max_sessions: sessions,
    license: sys.vmLicense || null, hypervisor: sys.vmMode || null, note: "VM-Series source" + (sys.vmCores ? ", " + sys.vmCores + " vCPU" : "") + (memGb ? ", " + memGb + " GB memory tier" : "") + (sys.vmMode ? " on " + sys.vmMode : "") + ".", sources: [] };
}
PPU.vmSourceModel = vmSourceModel;
function parseUptime(s) {
  if (!s) return null;
  const m = String(s).match(/(?:(\d+)\s+days?,\s*)?(\d+):(\d+):(\d+)/);
  if (!m) return null;
  return (+(m[1] || 0)) * 86400 + (+m[2]) * 3600 + (+m[3]) * 60 + (+m[4]);
}
function parseLicenses(text, now) {
  const out = [];
  if (!text) return out;
  const blocks = clean(text).split(/License entry:/).slice(1);
  for (const b of blocks) {
    const o = kv(b);
    if (!o.feature) continue;
    const expires = o.expires || "";
    const expD = parseDate(expires);
    let expired = /^yes/i.test(o["expired?"] || "");
    if (!o["expired?"] && expD && now) expired = expD < now;
    out.push({ feature: o.feature, description: o.description || "", issued: o.issued || "", expires,
      expiresIso: isoDate(expD), never: /never/i.test(expires), expired });
  }
  return out;
}
function vsysLicenseCount(lics) {
  let n = null;
  for (const l of lics || []) {
    if (/virtual\s*sys/i.test(l.feature + " " + l.description) && !l.expired) {
      const m = (l.feature + " " + l.description).match(/(\d+)/);
      if (m) n = Math.max(n || 0, +m[1]);
      else n = n || 0;
    }
  }
  return n;
}
function parseSessionInfo(text) {
  if (!text) return null;
  const o = kv(text);
  const r = {
    supported: toInt(o["number of sessions supported"]),
    allocated: toInt(o["number of allocated sessions"]),
    utilizationPct: toInt(o["session table utilization"]),
    createdSinceBoot: toInt(o["number of sessions created since bootup"]),
    pps: toInt(o["packet rate"]),
    kbps: toInt(o.throughput),
    cps: toInt(o["new connection establish rate"])
  };
  return (r.supported != null || r.allocated != null) ? r : null;
}
function parseInterfaceAll(text) {
  const res = { hardware: [], logical: [], aggregateGroups: null };
  if (!text) return res;
  const lines = clean(text).split("\n");
  let mode = null;
  for (const ln of lines) {
    if (/total configured hardware interfaces/i.test(ln)) { mode = "hw"; continue; }
    if (/total configured logical interfaces/i.test(ln)) { mode = "lg"; continue; }
    const ag = ln.match(/aggregation groups:\s*(\d+)/i);
    if (ag) { res.aggregateGroups = +ag[1]; mode = null; continue; }
    if (/^\s*(name\s+id|---)/.test(ln) || !ln.trim()) continue;
    if (mode === "hw") {
      const m = ln.match(/^(\S+)\s+(\d+)\s+(\S+)/);
      if (m) {
        const [sp, dup, st] = m[3].split("/");
        res.hardware.push({ name: m[1], id: +m[2], speed: sp, duplex: dup, state: (st || "").replace(/\(.*$/, ""), up: /^up/i.test(st || "") });
      }
    } else if (mode === "lg") {
      const m = ln.match(/^(\S+)\s+(\d+)\s+(\d+)\s+(.*)$/);
      if (m) {
        const rest = m[4];
        const cols = rest.trim().split(/\s{2,}/);
        let zone = "", fwd = "", tag = "", addr = "";
        const fm = rest.match(/(vr:\S+|lr:\S+|vlan:\S+|vw:\S+|N\/A|ha|tap)/);
        if (fm) {
          fwd = fm[1];
          zone = rest.slice(0, fm.index).trim();
          const after = rest.slice(fm.index + fm[1].length).trim().split(/\s+/);
          tag = after[0] || ""; addr = after.slice(1).join(" ");
        } else { zone = cols[0] || ""; }
        res.logical.push({ name: m[1], id: +m[2], vsys: +m[3], zone, forwarding: fwd, tag, address: addr });
      }
    }
  }
  return res;
}
function parseInterfaceDetail(text) {
  if (!text) return null;
  const o = {};
  const t = clean(text);
  let m;
  if ((m = t.match(/Runtime link speed\/duplex\/state:\s*(\S+)/))) {
    const [sp, du, st] = m[1].split("/");
    o.runtimeSpeed = toInt(sp); o.runtimeDuplex = du; o.runtimeUp = /up/i.test(st || "");
  }
  if ((m = t.match(/Configured link speed\/duplex\/state:\s*(\S+)/))) o.configured = m[1];
  if ((m = t.match(/Port Type\s*:?\s*(\S[^\n]*)/))) o.portType = m[1].trim();
  if ((m = t.match(/Capability\s*:\s*([^\n]*)/))) {
    o.capability = m[1].trim();
    let best = 0;
    const re = /(\d+)\s*(G|M)b\/s/gi; let c;
    while ((c = re.exec(o.capability))) best = Math.max(best, (+c[1]) * (c[2].toUpperCase() === "G" ? 1000 : 1));
    if (best) o.maxMbps = best;
  }
  if ((m = t.match(/Operation mode:\s*(\S+)/))) o.mode = m[1];
  return o;
}
function parseCounterInterface(text) {
  const res = {};
  if (!text) return res;
  const parts = clean(text).split(/\n\s*Interface:\s*/).slice(1);
  for (const p of parts) {
    const name = p.split("\n")[0].trim();
    const g = re => { const m = p.match(re); return m ? toInt(m[1]) : null; };
    res[name] = {
      rxBytes: g(/rx-bytes\s+(\d+)/) ?? g(/bytes received\s+(\d+)/),
      txBytes: g(/tx-bytes\s+(\d+)/) ?? g(/bytes transmitted\s+(\d+)/)
    };
  }
  return res;
}
function parseHaOp(text) {
  if (!text) return null;
  const t = clean(text);
  if (/HA not enabled/i.test(t)) return { enabled: false };
  const o = { enabled: true };
  let m;
  if ((m = t.match(/Mode:\s*(Active-\w+)/i))) o.mode = m[1];
  const local = t.split(/Peer Information/i)[0];
  const peer = t.split(/Peer Information/i)[1] || "";
  if ((m = local.match(/State:\s*(\w+)/))) o.localState = m[1];
  if ((m = peer.match(/State:\s*(\w+)/))) o.peerState = m[1];
  if ((m = peer.match(/Model:\s*(\S+)/))) o.peerModel = m[1];
  if ((m = peer.match(/Build Release:\s*(\S+)/))) o.peerVersion = m[1];
  if ((m = peer.match(/Serial Number:\s*(\S+)/i))) o.peerSerial = m[1];
  if ((m = local.match(/Group\s+(\d+)/i))) o.group = +m[1];
  return o;
}
function parsePower(cli) {
  const rows = new Map();
  let from = null;
  // 1) show chassis inventory (PA-5450 / PA-7000): "PS1  Not Present" or "PS3  PAN-PWR-2200W-AC  serial ..."
  const inv = section(cli, "show chassis inventory");
  if (inv) {
    for (const ln of clean(inv).split("\n")) {
      const m = ln.match(/^\s*PS(\d+)\s+(.*)$/i);
      if (!m) continue;
      const rest = m[2].trim();
      const present = !/not present|empty|absent/i.test(rest);
      const part = present ? (rest.split(/\s+/)[0] || null) : null;
      rows.set(+m[1], { id: +m[1], present, alarm: false, part });
      from = "show chassis inventory";
    }
  }
  // 2) show system environmentals (power rows): "S1  Power Supply #1 (left)  False  ..."
  if (!rows.size) {
    const keys = [...cli.keys()].filter(k => /^show system environmentals/.test(k));
    for (const k of keys) for (const text of cli.get(k)) {
      let hdr = null;
      for (const ln of clean(text).split("\n")) {
        if (/^\s*Slot\s+Description/i.test(ln)) { hdr = ln.trim().split(/\s{2,}/).map(x => x.toLowerCase()); continue; }
        const m = ln.match(/power\s*suppl(?:y|ies)\s*#?\s*(\d+)/i);
        if (!m) continue;
        const id = +m[1];
        const f = ln.trim().split(/\s{2,}/);
        const col = n => { if (!hdr) return null; const i = hdr.findIndex(h => h === n); return i >= 0 && f[i] != null ? f[i] : null; };
        let alarm = col("alarm"); let ins = col("inserted");
        if (alarm == null) { const t = ln.match(/\b(True|False)\b/); alarm = t ? t[1] : null; }
        if (ins == null) { const t = ln.match(/inserted\W+(True|False)/i); ins = t ? t[1] : null; }
        const r = rows.get(id) || { id, present: true, alarm: false, part: null };
        if (/^true$/i.test(alarm || "")) r.alarm = true;
        if (/^false$/i.test(ins || "") || /not present|absent|empty/i.test(ln)) r.present = false;
        rows.set(id, r);
        from = "show system environmentals";
      }
    }
  }
  if (!rows.size) return null;
  const list = [...rows.values()].sort((a, b) => a.id - b.id);
  const present = list.filter(r => r.present);
  return { from, rows: list, count: present.length, failed: present.filter(r => r.alarm).length, slots: list.length };
}
function parseTransceivers(cli) {
  const out = {};
  const det = section(cli, "show transceiver-detail all");
  if (det) {
    let cur = null;
    for (const ln of clean(det).split("\n")) {
      const pm = ln.match(/^\s*(?:(?:Port|Interface)\s*:?\s*)?(ethernet\d+\/\d+)\s*:?\s*$/i);
      if (pm) { cur = pm[1].toLowerCase(); out[cur] = out[cur] || { present: true, raw: {} }; continue; }
      if (!cur) continue;
      const m = ln.match(/^\s*([A-Za-z][\w .\/()-]*?)\s*:\s*(.+?)\s*$/);
      if (m) out[cur].raw[m[1].toLowerCase()] = m[2];
    }
    for (const x of Object.values(out)) {
      const r = x.raw;
      const pick = (...ks) => { for (const k of ks) for (const rk of Object.keys(r)) if (rk.includes(k)) return r[rk]; return null; };
      x.type = pick("transceiver type", "identifier", "module type");
      x.vendor = pick("vendor name");
      x.pn = pick("vendor pn", "part number", "vendor part");
      x.compliance = pick("compliance", "media", "ethernet");
      x.wavelength = pick("wavelength");
      x.label = [x.compliance || null, x.pn || null, x.type || null].filter(Boolean)[0] || "optic present";
      delete x.raw;
    }
  }
  const tbl = section(cli, "show transceiver all");
  const bad = t => !t || /Server error|Invalid|not found|Unknown command|Unsupported/i.test(t);
  const sectionSeen = !bad(det) || !bad(tbl);
  if (tbl) for (const ln of clean(tbl).split("\n")) { const m = ln.match(/^\s*(ethernet\d+\/\d+)\s+\S/i); if (m && !out[m[1].toLowerCase()]) out[m[1].toLowerCase()] = { present: true, label: "optic present" }; }
  // an empty list in a file that has the section means 'no optics installed'; a missing section means 'not in file'
  return Object.keys(out).length ? out : (sectionSeen ? {} : null);
}
function parsePanoramaStatus(text) {
  if (!text) return null;
  const servers = [];
  const re = /Panorama Server\s*(\d)\s*:\s*(\S+)[\s\S]*?Connected\s*:\s*(\w+)/gi;
  let m;
  while ((m = re.exec(clean(text)))) servers.push({ idx: +m[1], host: m[2], connected: /yes/i.test(m[3]) });
  return servers.length ? servers : null;
}
function parseDpMonitor(files) {
  const series = [];
  for (const f of files) {
    let cur = null;
    for (const ln of clean(f.text || "").split("\n")) {
      const ts = ln.match(/^(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d)/);
      if (ts) { cur = { t: ts[1] + "T" + ts[2] + "Z" }; continue; }
      if (!cur) continue;
      let m;
      if ((m = ln.match(/Number of allocated sessions:\s*(\d+)/))) { cur.sessions = +m[1]; }
      else if ((m = ln.match(/Number of sessions supported:\s*(\d+)/))) { cur.supported = +m[1]; }
      else if ((m = ln.match(/Throughput:\s*(\d+)\s*kbps/))) { cur.kbps = +m[1]; }
      else if ((m = ln.match(/Packet rate:\s*(\d+)/))) { cur.pps = +m[1]; }
      else if ((m = ln.match(/New connection establish rate:\s*(\d+)/))) {
        cur.cps = +m[1];
        if (cur.sessions != null || cur.kbps != null) series.push(cur);
        cur = { t: cur.t };
      }
    }
  }
  const seen = new Set();
  const uniq = series.filter(s => { const k = s.t + "|" + s.sessions + "|" + s.kbps; if (seen.has(k)) return false; seen.add(k); return true; });
  uniq.sort((a, b) => a.t < b.t ? -1 : a.t > b.t ? 1 : 0);
  if (!uniq.length) return null;
  const stat = key => {
    const v = uniq.map(s => s[key]).filter(x => x != null).sort((a, b) => a - b);
    if (!v.length) return null;
    const p95 = v[Math.min(v.length - 1, Math.floor(v.length * 0.95))];
    const maxRow = uniq.reduce((best, s) => (s[key] != null && (best == null || s[key] > best[key])) ? s : best, null);
    return { max: v[v.length - 1], p95, avg: v.reduce((a, b) => a + b, 0) / v.length, at: maxRow && maxRow.t, n: v.length };
  };
  return { samples: uniq.length, from: uniq[0].t, to: uniq[uniq.length - 1].t,
    sessions: stat("sessions"), kbps: stat("kbps"), cps: stat("cps"), pps: stat("pps"), series: uniq };
}

/* ============================ config (XML) ============================ */
function kids(el, tag) { const r = []; if (!el) return r; for (let c = el.firstChild; c; c = c.nextSibling) if (c.nodeType === 1 && (!tag || c.nodeName === tag)) r.push(c); return r; }
function kid(el, tag) { if (!el) return null; for (let c = el.firstChild; c; c = c.nextSibling) if (c.nodeType === 1 && c.nodeName === tag) return c; return null; }
function path(el, ...tags) { let e = el; for (const t of tags) { e = kid(e, t); if (!e) return null; } return e; }
function txt(el) { return el ? clean(el.textContent).trim() : ""; }
function entries(el) { return kids(el, "entry"); }
function members(el) { return kids(el, "member").map(txt); }
function attr(el, n) { return el && el.getAttribute ? el.getAttribute(n) : null; }
function isLeaf(el) { for (let c = el.firstChild; c; c = c.nextSibling) if (c.nodeType === 1) return false; return true; }
PPU.xml = { kids, kid, path, txt, entries, members, attr, isLeaf };

function deviceRoot(doc) {
  const cfg = doc && doc.documentElement;
  if (!cfg || cfg.nodeName !== "config") return null;
  const devs = path(cfg, "devices");
  return devs ? (entries(devs).find(e => attr(e, "name") === "localhost.localdomain") || entries(devs)[0] || null) : null;
}
PPU.deviceRoot = deviceRoot;

function authSummary(doc, dev, sys) {
  const out = { deviceProfile: sys ? txt(kid(sys, "authentication-profile")) || null : null, profiles: [], sequences: [], users: [] };
  for (const tag of ["authentication-profile", "authentication-sequence"]) {
    for (const el of Array.from(doc.getElementsByTagName(tag))) {
      if (!el.parentNode || el.parentNode.nodeName === "system") continue;
      for (const e of entries(el)) {
        if (tag === "authentication-profile") {
          const m = kid(e, "method"); const method = m ? (kids(m)[0] ? kids(m)[0].nodeName : null) : null;
          out.profiles.push({ name: attr(e, "name"), method, allowList: members(path(e, "allow-list")).slice(0, 5) });
        } else out.sequences.push({ name: attr(e, "name"), profiles: members(path(e, "auth-profile")) });
      }
    }
  }
  const users = path(doc.documentElement, "mgt-config", "users");
  for (const u of entries(users)) {
    const perm = path(u, "permissions", "role-based");
    const role = perm ? (kids(perm)[0] ? kids(perm)[0].nodeName : null) : null;
    out.users.push({ name: attr(u, "name"), role, authProfile: txt(kid(u, "authentication-profile")) || null, local: !!kid(u, "phash") });
  }
  return out;
}
// SD-WAN counts as used only when something is actually set up. The tag names also appear as admin-role permissions
// (<sdwan-rulebase>enable</...>) and as disabled link settings (<sdwan-link-settings><enable>no</enable>), which are not use.
function sdwanInUse(doc) {
  const has = tag => Array.from(doc.getElementsByTagName(tag));
  if (has("sdwan-interface-profile").some(el => entries(el).length > 0)) return true;
  if (has("sdwan-rules").some(el => entries(el).length > 0)) return true;
  if (has("sdwan-interfaces").some(el => entries(el).length > 0)) return true;
  if (has("sdwan-link-settings").some(el => txt(kid(el, "enable")) === "yes")) return true;
  return false;
}
function summarizeConfig(doc) {
  const cfg = doc.documentElement;
  const dev = deviceRoot(doc);
  const S = { version: attr(cfg, "version"), detailVersion: attr(cfg, "detail-version"), interfaces: [], ae: [], logical: [],
    vsys: [], zones: [], vrs: [], lrs: [], ha: null, mgmt: {}, panorama: null, counts: {}, features: {}, certsWithKeys: 0 };
  if (!dev) return S;
  const net = path(dev, "network");
  const ifs = path(net, "interface");
  const unitRows = (parent, unitsEl, kind) => entries(unitsEl).map(u => ({
    name: attr(u, "name"), parent, kind, tag: txt(kid(u, "tag")) || null,
    ips: entries(path(u, "ip")).map(e => attr(e, "name")), comment: txt(kid(u, "comment")) }));
  for (const e of entries(path(ifs, "ethernet"))) {
    const name = attr(e, "name");
    let mode = "none", units = [];
    for (const m of ["layer3", "layer2", "virtual-wire", "tap", "ha", "aggregate-group", "decrypt-mirror", "log-card", "lldp"]) {
      const c = kid(e, m);
      if (c) {
        mode = m;
        if (m === "layer3" || m === "layer2" || m === "virtual-wire") units = unitRows(name, path(c, "units"), m);
        break;
      }
    }
    const l3 = kid(e, "layer3");
    S.interfaces.push({ name, mode, aggregateGroup: mode === "aggregate-group" ? txt(kid(e, "aggregate-group")) : null,
      linkSpeed: txt(kid(e, "link-speed")) || null, ips: l3 ? entries(path(l3, "ip")).map(x => attr(x, "name")) : [],
      dhcp: !!(l3 && kid(l3, "dhcp-client")), poe: !!kid(e, "poe"), comment: txt(kid(e, "comment")), units });
  }
  for (const e of entries(path(ifs, "aggregate-ethernet"))) {
    const name = attr(e, "name");
    let units = [];
    for (const m of ["layer3", "layer2", "virtual-wire"]) { const c = kid(e, m); if (c) units = unitRows(name, path(c, "units"), m); }
    S.ae.push({ name, mode: ["layer3", "layer2", "virtual-wire", "ha"].find(m => kid(e, m)) || "none", units,
      members: S.interfaces.filter(i => i.aggregateGroup === name).map(i => i.name) });
  }
  for (const k of ["vlan", "loopback", "tunnel"]) {
    const el = path(ifs, k);
    if (!el) continue;
    S.logical.push({ name: k, units: entries(path(el, "units")).map(u => attr(u, "name")) });
  }
  for (const v of entries(path(dev, "vsys"))) {
    const vname = attr(v, "name");
    const zones = entries(path(v, "zone")).map(z => {
      const n = path(z, "network");
      let type = "", ifl = [];
      for (const t of ["layer3", "layer2", "virtual-wire", "tap", "tunnel", "external"]) { const c = kid(n, t); if (c) { type = t; ifl = members(c); break; } }
      return { vsys: vname, name: attr(z, "name"), type, interfaces: ifl, zpp: txt(kid(n, "zone-protection-profile")) || null };
    });
    S.zones.push(...zones);
    const rb = path(v, "rulebase");
    const cnt = t => entries(path(rb, t, "rules")).length;
    S.vsys.push({ name: vname, display: txt(kid(v, "display-name")) || vname, zones: zones.length,
      imported: members(path(v, "import", "network", "interface")),
      security: cnt("security"), nat: cnt("nat"), pbf: cnt("pbf"), decryption: cnt("decryption"), qos: cnt("qos"),
      addresses: entries(path(v, "address")).length, gpPortals: entries(path(v, "global-protect", "global-protect-portal")).length,
      gpGateways: entries(path(v, "global-protect", "global-protect-gateway")).length });
  }
  S.vrs = entries(path(net, "virtual-router")).map(v => ({ name: attr(v, "name"), interfaces: members(kid(v, "interface")),
    staticRoutes: entries(path(v, "routing-table", "ip", "static-route")).length + entries(path(v, "routing-table", "ipv6", "static-route")).length,
    bgp: txt(path(v, "protocol", "bgp", "enable")) === "yes", ospf: txt(path(v, "protocol", "ospf", "enable")) === "yes" }));
  S.lrs = entries(path(net, "logical-router")).map(v => ({ name: attr(v, "name") }));
  const sh = path(cfg, "shared");
  const sum = k => S.vsys.reduce((a, v) => a + v[k], 0);
  S.counts = { security: sum("security"), nat: sum("nat"), pbf: sum("pbf"), decryption: sum("decryption"), zones: S.zones.length,
    addresses: sum("addresses") + entries(path(sh, "address")).length, vsys: S.vsys.length,
    ikeGateways: entries(path(net, "ike", "gateway")).length, ipsecTunnels: entries(path(net, "tunnel", "ipsec")).length,
    gpPortals: sum("gpPortals"), gpGateways: sum("gpGateways") };
  S.features = {
    globalProtect: S.counts.gpPortals + S.counts.gpGateways > 0,
    ipsec: S.counts.ipsecTunnels > 0,
    dhcpServer: entries(path(net, "dhcp", "interface")).some(e => kid(e, "server")),
    dhcpRelay: entries(path(net, "dhcp", "interface")).some(e => kid(e, "relay")),
    qos: entries(path(net, "qos", "interface")).length > 0,
    lldp: txt(path(net, "lldp", "enable")) === "yes",
    sdwan: sdwanInUse(doc),
    decryption: S.counts.decryption > 0,
    zoneProtection: S.zones.some(z => z.zpp),
    advancedRouting: S.lrs.length > 0,
    vwire: entries(path(net, "virtual-wire")).length > 0
  };
  const sys = path(dev, "deviceconfig", "system");
  S.mgmt = { hostname: txt(kid(sys, "hostname")), ip: txt(kid(sys, "ip-address")), netmask: txt(kid(sys, "netmask")), gateway: txt(kid(sys, "default-gateway")) };
  S.auth = authSummary(doc, dev, sys);
  S.mgmt.ipv6 = txt(kid(sys, "ipv6-address")) || null; S.mgmt.ipv6Gateway = txt(kid(sys, "ipv6-default-gateway")) || null;
  S.mgmt.dns = { primary: txt(path(sys, "dns-setting", "servers", "primary")) || null, secondary: txt(path(sys, "dns-setting", "servers", "secondary")) || null, proxy: !!path(sys, "dns-setting", "dns-proxy-object") };
  const pano = path(sys, "panorama", "local-panorama");
  const ps = [];
  if (pano) { for (const k of ["panorama-server", "panorama-server-2"]) if (txt(kid(pano, k))) ps.push(txt(kid(pano, k))); }
  for (const k of ["panorama-server", "panorama-server-2"]) if (txt(kid(sys, k))) ps.push(txt(kid(sys, k)));
  S.panorama = ps.length ? { servers: ps } : null;
  const ha = path(dev, "deviceconfig", "high-availability");
  if (ha) {
    const ifc = path(ha, "interface");
    const port = k => txt(path(ifc, k, "port")) || null;
    S.ha = { enabled: txt(kid(ha, "enabled")) === "yes", groupId: txt(path(ha, "group", "group-id")) || entries(path(ha, "group")).map(e => attr(e, "name"))[0] || null,
      peerIp: txt(path(ha, "group", "peer-ip")) || null,
      mode: path(ha, "group", "mode", "active-active") ? "active-active" : "active-passive",
      ports: { ha1: port("ha1"), "ha1-backup": port("ha1-backup"), ha2: port("ha2"), "ha2-backup": port("ha2-backup"), ha3: port("ha3"), ha4: port("ha4"), "ha4-backup": port("ha4-backup") } };
  }
  const certs = [...(doc.getElementsByTagName("certificate") || [])];
  let withKey = 0;
  for (const c of certs) for (const e of entries(c)) if (kid(e, "private-key")) withKey++;
  S.certsWithKeys = withKey;
  S.usage = configUsage(doc);
  return S;
}
PPU.summarizeConfig = summarizeConfig;

// Which security-profile types exist and which are attached to a rule (hints for the license review).
function configUsage(doc) {
  const U = { profiles: {}, attached: {}, rules: 0, dns: false, dlp: false };
  const TYPES = ["virus", "spyware", "vulnerability", "url-filtering", "wildfire-analysis", "file-blocking", "data-filtering"];
  const names = {};
  for (const pr of Array.from(doc.getElementsByTagName("profiles"))) {
    for (const t of TYPES) { const el = kid(pr, t); if (el) { const n = entries(el).length; if (n) { U.profiles[t] = (U.profiles[t] || 0) + n; (names[t] = names[t] || new Set()); entries(el).forEach(e => names[t].add(attr(e, "name"))); } } }
  }
  const groups = {};
  for (const g of Array.from(doc.getElementsByTagName("profile-group"))) for (const e of entries(g)) {
    groups[attr(e, "name")] = TYPES.filter(t => kid(e, t) && members(kid(e, t)).length);
  }
  for (const ps of Array.from(doc.getElementsByTagName("profile-setting"))) {
    const parent = ps.parentNode && ps.parentNode.parentNode ? ps.parentNode : null;
    U.rules++;
    const prof = kid(ps, "profiles");
    if (prof) for (const t of TYPES) if (kid(prof, t) && members(kid(prof, t)).length) U.attached[t] = (U.attached[t] || 0) + 1;
    const grp = kid(ps, "group");
    if (grp) for (const gname of members(grp)) for (const t of groups[gname] || []) U.attached[t] = (U.attached[t] || 0) + 1;
  }
  U.dns = Array.from(doc.getElementsByTagName("botnet-domains")).some(b => kid(b, "lists") && entries(kid(b, "lists")).length);
  U.dlp = (U.profiles["data-filtering"] || 0) > 0 || doc.getElementsByTagName("data-objects").length > 0;
  return U;
}

/* ============================ TSF bundle ============================ */
function pickConfig(files) {
  const cand = files.filter(f => f.text && /<config[\s>]/.test(f.text.slice(0, 4000)));
  const rank = f => {
    const n = f.name.toLowerCase();
    if (/saved-configs\/running-config\.xml$/.test(n)) return 0;
    if (/running-config\.xml$/.test(n) && !/merged/.test(n)) return 1;
    if (/techsupport-saved-currcfg\.xml$/.test(n)) return 2;
    if (/merged-running-config/.test(n)) return 3;
    return 5;
  };
  cand.sort((a, b) => rank(a) - rank(b));
  return cand[0] || null;
}
function pickCli(files) {
  const c = files.filter(f => f.text && /(?:^|\/)techsupport[^/]*\.txt$/i.test(f.name) && !/\/logs\//.test(f.name));
  c.sort((a, b) => (b.text.length - a.text.length));
  return c[0] || null;
}

function analyzeTsf(files, xmlAdapter, opts) {
  const now = (opts && opts.now) || new Date();
  const A = { files: files.length, notes: [], missing: [] };
  const cliF = pickCli(files);
  const cfgF = pickConfig(files);
  A.cliFile = cliF && cliF.name; A.configFile = cfgF && cfgF.name;
  const cli = splitCli(cliF ? cliF.text : "");
  A.system = parseSystemInfo(section(cli, "show system info", "first"));
  A.licenses = parseLicenses(section(cli, "request license info"), now);
  A.session = parseSessionInfo(section(cli, "show session info"));
  A.ifAll = parseInterfaceAll(section(cli, "show interface all"));
  A.ifDetail = {};
  for (const [k, arr] of cli) {
    const m = k.match(/^show interface (ethernet\d+\/\d+|ae\d+)$/);
    if (m) { const d = parseInterfaceDetail(arr.join("\n")); if (d) A.ifDetail[m[1]] = d; }
  }
  A.counters = parseCounterInterface(section(cli, "show counter interface all"));
  A.power = parsePower(cli);
  A.xcvr = parseTransceivers(cli);
  A.hasEnvironmentals = [...cli.keys()].some(k => /^show system environmentals/.test(k));
  A.haOp = parseHaOp(section(cli, "show high-availability all"));
  A.panoramaStatus = parsePanoramaStatus(section(cli, "show panorama-status"));
  A.dp = parseDpMonitor(files.filter(f => /dp\d*-?monitor\.log/i.test(f.name) && f.text));
  // Pushed (Panorama) config: newsp.xml / lastsp.xml hold what Panorama pushed. On a standalone firewall they are ~55-byte stubs;
  // mergesp.xml is always large (local config plus predefined objects), so it says nothing about Panorama.
  A.pushedConfig = files.some(f => /panorama_pushed\/(newsp|lastsp)\.xml$/i.test(f.name) && (f.size || 0) > 200);
  if (cfgF) {
    try {
      const doc = xmlAdapter.parse(cfgF.text);
      A.configText = cfgF.text;
      A.config = summarizeConfig(doc);
      A.inventory = configInventory(doc, A.config);
      A.masked = maskedSummary(doc);
      A.configFromFile = cfgF.name;
      // Panorama-managed: the device enforces limits on the merged config (template + device group + local), so use it for analysis.
      const mf = files.find(f => /saved-configs\/\.merged-running-config\.xml$/i.test(f.name) && f.text && f !== cfgF);
      if (mf && (A.pushedConfig || (A.config.panorama && A.config.panorama.servers.length))) {
        try {
          const mdoc = xmlAdapter.parse(mf.text);
          const ms = summarizeConfig(mdoc);
          if (ms.interfaces.length > A.config.interfaces.length || ms.counts.security + ms.counts.nat + ms.zones.length > A.config.counts.security + A.config.counts.nat + A.config.zones.length) {
            A.localConfig = A.config; A.config = ms; A.inventory = configInventory(mdoc, ms); A.masked = maskedSummary(mdoc);
            A.configIsMerged = true;
          }
        } catch (e) { A.notes.push("Could not parse the merged config: " + e.message); }
      }
    } catch (e) { A.notes.push("Could not parse " + cfgF.name + ": " + e.message); }
  }
  if (!A.system && A.config) A.system = { hostname: A.config.mgmt.hostname, model: null, swVersion: A.config.detailVersion };
  if (!cliF) A.missing.push("techsupport CLI output (model, licenses, sessions, interface speeds)");
  if (!cfgF) A.missing.push("running-config.xml (needed to convert)");
  if (!A.dp) A.missing.push("dp-monitor logs (peak sessions / throughput over time)");
  if (!A.session) A.missing.push("show session info");
  if (cliF && !A.power && !isVmSystem(A.system)) A.missing.push("power supply status (show system environmentals / show chassis inventory)");
  if (cliF && !A.xcvr && !isVmSystem(A.system)) A.missing.push("installed transceiver details (show transceiver-detail all)");
  A.interfaces = buildInterfaceTable(A);
  A.vsysLicensed = vsysLicenseCount(A.licenses);
  A.vsysInUse = A.config ? Math.max(1, A.config.vsys.length) : (A.system && A.system.multiVsys ? null : 1);
  A.ha = mergeHa(A);
  return A;
}
PPU.analyzeTsf = analyzeTsf;

function mediaFromPortType(pt, maxMbps) {
  const p = String(pt || "").toLowerCase();
  if (!p) return null;
  if (/qsfp-?dd/.test(p)) return "qsfp-dd";
  if (/qsfp28|100g/.test(p)) return "qsfp28";
  if (/qsfp/.test(p)) return "qsfp+";
  if (/sfp28|25g/.test(p)) return "sfp28";
  if (/sfp\+|sfp-plus|10g/.test(p)) return "sfp+";
  if (/sfp|fiber|optic/.test(p)) return (maxMbps && maxMbps >= 10000) ? "sfp+" : "sfp";
  if (/rj-?45|copper|base-?t/.test(p)) return (maxMbps && maxMbps > 1000) ? "mgig" : "rj45";
  if (/virtual|vmxnet|virtio|netvsc/.test(p)) return "virtual";
  return null;
}
PPU.mediaFromPortType = mediaFromPortType;

function buildInterfaceTable(A) {
  const rows = new Map();
  const get = n => { if (!rows.has(n)) rows.set(n, { name: n }); return rows.get(n); };
  const cfg = A.config;
  if (cfg) {
    for (const i of cfg.interfaces) { const r = get(i.name); Object.assign(r, { mode: i.mode, aggregateGroup: i.aggregateGroup, linkSpeed: i.linkSpeed, configured: i.mode !== "none" || i.units.length > 0, units: i.units.map(u => u.name), ips: i.ips, poe: i.poe, comment: i.comment }); }
    for (const z of cfg.zones) for (const m of z.interfaces) { const p = parentOf(m); if (rows.has(p)) { const r = rows.get(p); r.zones = r.zones || []; if (!r.zones.includes(z.name)) r.zones.push(z.name); } }
  }
  for (const h of (A.ifAll.hardware || [])) {
    if (!RE_ETH.test(h.name)) continue;
    const r = get(h.name); r.state = h.state; r.up = h.up; r.speedStr = h.speed; r.runtimeSpeed = toInt(h.speed) || r.runtimeSpeed || null;
  }
  for (const [n, d] of Object.entries(A.ifDetail || {})) {
    if (!RE_ETH.test(n)) continue;
    const r = get(n); r.portType = d.portType; r.maxMbps = d.maxMbps; if (d.runtimeSpeed) r.runtimeSpeed = d.runtimeSpeed; if (d.runtimeUp != null) r.up = d.runtimeUp;
  }
  const up = A.system && A.system.uptimeSec;
  for (const [n, c] of Object.entries(A.counters || {})) {
    if (!rows.has(n)) continue;
    const r = rows.get(n);
    r.rxBytes = c.rxBytes; r.txBytes = c.txBytes;
    if (up && (c.rxBytes != null || c.txBytes != null)) {
      r.avgRxBps = (c.rxBytes || 0) * 8 / up; r.avgTxBps = (c.txBytes || 0) * 8 / up;
      const sp = r.runtimeSpeed;
      if (sp) r.avgUtilPct = 100 * Math.max(r.avgRxBps, r.avgTxBps) / (sp * 1e6);
    }
  }
  for (const r of rows.values()) {
    r.media = mediaFromPortType(r.portType, r.maxMbps);
    if (isVmSystem(A.system)) { r.media = "virtual"; r.virtual = true; }
    if (r.configured == null) r.configured = false;
  }
  return [...rows.values()].filter(r => RE_ETH.test(r.name)).sort((a, b) => sortIfNames(a.name, b.name));
}

function mergeHa(A) {
  const c = A.config && A.config.ha;
  const o = A.haOp;
  const enabled = !!((c && c.enabled) || (o && o.enabled));
  return { enabled, mode: (o && o.mode) || (c && c.mode) || null, peerIp: c && c.peerIp, peerModel: o && o.peerModel, peerVersion: o && o.peerVersion,
    localState: o && o.localState, peerState: o && o.peerState, ports: (c && c.ports) || {}, fromConfig: !!c, fromOp: !!o };
}

/* ============================ catalog ============================ */
function catalogIndex(cat, now) {
  const today = now || new Date();
  const all = [];
  for (const h of cat.hardware || []) {
    const m = Object.assign({}, h);
    const eos = parseDate(m.eos_date), eol = parseDate(m.eol_date);
    if (eol && eol <= today) m.lifecycle = "end-of-life";
    else if (eos && eos <= today) m.lifecycle = "end-of-sale";
    else if (eos) m.lifecycle = "end-of-sale-announced";
    else m.lifecycle = "current";
    all.push(m);
  }
  for (const v of cat.vm || []) all.push(Object.assign({ lifecycle: "current" }, v));
  const byModel = new Map(all.map(m => [m.model.toUpperCase(), m]));
  return { all, byModel, cat, sources: cat.sources || {} };
}
PPU.catalogIndex = catalogIndex;
function findModel(idx, name) {
  if (!name) return null;
  const n = String(name).toUpperCase().replace(/\s+/g, "").replace(/^PA(\d)/, "PA-$1");
  return idx.byModel.get(n) || idx.byModel.get(n.replace(/-ZTP$/, "")) || null;
}
PPU.findModel = findModel;

function portList(model, opts) {
  const o = opts || {};
  if (!model) return [];
  if (model.form === "vm") {
    const n = o.vmPorts || 8;
    const r = [];
    for (let i = 1; i <= n; i++) r.push({ name: "ethernet1/" + i, media: "virtual", mbps: null });
    return r;
  }
  if (!model.ports) return [];
  const r = []; let i = 1;
  for (const g of model.ports) for (let k = 0; k < g.n; k++) r.push({ name: "ethernet1/" + (i++), media: g.media, mbps: g.mbps, poe: !!g.poe, bypass: !!g.bypass });
  return r;
}
PPU.portList = portList;
function portCounts(ports) {
  const c = { copper: 0, fiber1g: 0, fiber10g: 0, fiber25g: 0, fiber40g: 0, fiber100g: 0, combo: 0, virtual: 0, total: 0 };
  for (const p of ports) {
    c.total++;
    switch (p.media) {
      case "rj45": case "mgig": c.copper++; break;
      case "combo": c.combo++; break;
      case "sfp": c.fiber1g++; break;
      case "sfp+": c.fiber10g++; break;
      case "sfp28": c.fiber25g++; break;
      case "qsfp+": c.fiber40g++; break;
      case "qsfp28": case "qsfp-dd": c.fiber100g++; break;
      case "virtual": c.virtual++; break;
    }
  }
  return c;
}
PPU.portCounts = portCounts;

/* ============================ requirements & sizing ============================ */
const FIBER = ["sfp", "sfp+", "sfp28", "qsfp+", "qsfp28", "qsfp-dd"];
const COPPER = ["rj45", "mgig"];
const MEDIA_MAX = { rj45: 1000, mgig: 10000, combo: 1000, sfp: 1000, "sfp+": 10000, sfp28: 25000, "qsfp+": 40000, qsfp28: 100000, "qsfp-dd": 400000 };
function srcPortNeed(r, srcModel) {
  if (r.media === "virtual") return { media: "virtual", mbps: 1000, mbpsKnown: false };
  let media = r.media;
  let mbps = r.runtimeSpeed && r.up ? r.runtimeSpeed : null;
  if (!media && srcModel && srcModel.ports) {
    const p = portList(srcModel).find(x => x.name === r.name);
    if (p) { media = p.media; if (!mbps) mbps = null; }
  }
  if (!mbps) { const ls = toInt(r.linkSpeed); if (ls) mbps = ls; }
  return { media: media || "unknown", mbps: mbps || 1000, mbpsKnown: !!(r.runtimeSpeed && r.up) || !!toInt(r.linkSpeed) };
}
function family(media) { return COPPER.includes(media) ? "copper" : FIBER.includes(media) ? "fiber" : media === "combo" ? "combo" : media === "virtual" ? "virtual" : "unknown"; }
function portFit(need, tgt) {
  // Returns {ok, score, warn}
  if (tgt.media === "virtual") return { ok: true, score: 50, warn: null };
  const nf = family(need.media), tf = family(tgt.media);
  const tmax = tgt.mbps || MEDIA_MAX[tgt.media] || 1000;
  if (tmax < need.mbps) return { ok: false, score: 0, warn: "target port is slower (" + fmtSpeed(tmax) + " < " + fmtSpeed(need.mbps) + ")" };
  let score = 100, warn = null;
  if (nf === "unknown" || nf === "virtual") score -= 5;
  else if (tf === "combo" || nf === "combo") { score -= 5; }
  else if (nf !== tf) { score -= 60; warn = (nf === "copper" ? "copper → fiber: needs a copper SFP or new cabling" : "fiber → copper: needs new cabling"); }
  if (tgt.media === need.media) score += 10;
  if (tmax > need.mbps) score -= Math.min(30, Math.log10(tmax / need.mbps) * 15);
  if (need.media === "sfp" && tgt.media === "sfp+") warn = warn || "1G optic in a 10G SFP+ port: confirm the port supports 1G";
  if (tgt.poe) score -= 2;
  return { ok: true, score, warn };
}
PPU.portFit = portFit;

function usedPorts(A) {
  return (A.interfaces || []).filter(r => r.configured || r.up);
}
function deriveRequirements(A, idx, opts) {
  const o = Object.assign({ headroomPct: 30 }, opts || {});
  const h = 1 + (o.headroomPct || 0) / 100;
  const srcModel = A.system ? findModel(idx, A.system.model) : null;
  const R = { headroomPct: o.headroomPct, basis: {}, srcModel };
  const peakSess = A.dp && A.dp.sessions ? A.dp.sessions.max : null;
  const nowSess = A.session ? A.session.allocated : null;
  const sess = peakSess != null || nowSess != null ? Math.max(peakSess || 0, nowSess || 0) : null;
  R.observed = {
    sessions: sess, sessionsSource: peakSess != null ? "peak in dp-monitor logs (" + A.dp.samples + " samples)" : nowSess != null ? "show session info (one snapshot)" : null,
    kbps: A.dp && A.dp.kbps ? A.dp.kbps.max : (A.session ? A.session.kbps : null),
    kbpsSource: A.dp && A.dp.kbps ? "peak in dp-monitor logs" : A.session && A.session.kbps != null ? "show session info (one snapshot)" : null,
    cps: A.dp && A.dp.cps ? A.dp.cps.max : (A.session ? A.session.cps : null),
    cpsSource: A.dp && A.dp.cps ? "peak in dp-monitor logs" : A.session && A.session.cps != null ? "show session info (one snapshot)" : null
  };
  const ifaceBps = (A.interfaces || []).reduce((s, r) => s + Math.max(r.avgRxBps || 0, r.avgTxBps || 0), 0);
  R.observed.avgIfaceBps = ifaceBps || null;
  R.sessions = o.sessions != null ? o.sessions : sess != null ? Math.ceil(sess * h) : null;
  const bps = R.observed.kbps != null ? R.observed.kbps * 1000 : null;
  // A near-idle sample (lab box, quiet weekend, short window) says nothing about real load: say so instead of presenting a tiny model as a sized answer.
  if (sess != null && sess <= 1000 && (bps == null || bps <= 50e6) && (R.observed.cps == null || R.observed.cps <= 10)) {
    let days = null;
    if (A.dp && A.dp.from && A.dp.to) days = Math.round((Date.parse(A.dp.to) - Date.parse(A.dp.from)) / 864e5 * 10) / 10;
    R.lowUsage = { sessions: sess, bps, days };
  }
  R.throughputBps = o.throughputBps != null ? o.throughputBps : bps ? Math.ceil(bps * h) : null;
  R.cps = o.cps != null ? o.cps : R.observed.cps ? Math.ceil(R.observed.cps * h) : null;
  R.vsys = o.vsys != null ? o.vsys : (A.vsysInUse || 1);
  R.threatLicensed = (A.licenses || []).some(l => /threat/i.test(l.feature) && !l.expired);
  R.useThreat = o.useThreat != null ? o.useThreat : R.threatLicensed;
  R.ports = usedPorts(A).filter(r => r.mode !== "ha" || true).map(r => Object.assign({ name: r.name, mode: r.mode }, srcPortNeed(r, srcModel)));
  R.ha = o.ha != null ? o.ha : !!(A.ha && A.ha.enabled);
  R.zones = A.config ? A.config.counts.zones : null;
  R.rules = A.config ? A.config.counts.security : null;
  R.ipsecTunnels = A.config ? A.config.counts.ipsecTunnels : null;
  R.cellular = (A.ifAll.hardware || []).some(h => /^cellular/.test(h.name));
  return R;
}
PPU.deriveRequirements = deriveRequirements;

function assignPorts(needs, ports) {
  // greedy: highest-speed needs first, best score
  const free = ports.map(p => Object.assign({}, p));
  const used = new Set();
  const out = [];
  const order = needs.slice().sort((a, b) => b.mbps - a.mbps);
  for (const n of order) {
    let best = null, bestFit = null;
    for (const p of free) {
      if (used.has(p.name)) continue;
      const f = portFit(n, p);
      if (f.ok && (!bestFit || f.score > bestFit.score)) { best = p; bestFit = f; }
    }
    if (best) { used.add(best.name); out.push({ need: n, port: best, fit: bestFit }); }
    else out.push({ need: n, port: null, fit: null });
  }
  return out;
}
PPU.assignPorts = assignPorts;

function evaluateModel(m, R, A, opts) {
  const o = opts || {};
  const E = { model: m.model, m, ok: true, reasons: [], warnings: [], fits: {} };
  const thr = R.useThreat ? m.tp_bps : m.fw_bps;
  const label = R.useThreat ? "Threat Prevention throughput" : "firewall throughput";
  const chk = (key, need, have, what, fmt) => {
    if (need == null) { E.fits[key] = { need, have, status: "unknown" }; return; }
    if (have == null) { E.fits[key] = { need, have, status: "unpublished" }; E.warnings.push(what + " not published for " + m.model); return; }
    const ok = have >= need;
    E.fits[key] = { need, have, status: ok ? "ok" : "short", util: 100 * need / have };
    if (!ok) { E.ok = false; E.reasons.push(what + ": needs " + fmt(need) + ", " + m.model + " has " + fmt(have)); }
  };
  chk("sessions", R.sessions, m.max_sessions, "Max sessions", fmtNum);
  chk("throughput", R.throughputBps, thr, label, fmtBps);
  chk("cps", R.cps, m.cps, "New sessions/sec", fmtNum);
  const vmax = m.vsys_max;
  if (R.vsys > 1) {
    if (m.form === "vm") {
      E.vmVsys = true;
      E.warnings.push("Needs " + R.vsys + " vsys: VM-Series multi-vsys needs a flexible license, PAN-OS 11.1.3+, Tier 3/4 and 16+ vCPUs");
    } else if (vmax == null || vmax < R.vsys) { E.ok = false; E.reasons.push("Needs " + R.vsys + " virtual systems; " + m.model + " supports " + (vmax == null ? "an unknown number" : vmax)); }
    else if (m.vsys_base < R.vsys) E.vsysLicense = R.vsys - m.vsys_base;
  }
  if (m.form === "vm") {
    if (R.zones != null && m.zones != null && R.zones > m.zones) { E.ok = false; E.reasons.push(R.zones + " zones in use; " + m.model + " allows " + m.zones); }
    if (R.rules != null && m.rules != null && R.rules > m.rules) { E.ok = false; E.reasons.push(R.rules + " security rules; " + m.model + " allows " + m.rules); }
    if (R.ipsecTunnels != null && m.ipsec_tunnels != null && R.ipsecTunnels > m.ipsec_tunnels) { E.ok = false; E.reasons.push(R.ipsecTunnels + " IPsec tunnels; " + m.model + " allows " + m.ipsec_tunnels); }
  }
  let needs = R.ports.filter(p => p.mode !== "ha");
  const haNeeds = [];
  if (R.ha && m.form !== "vm" && !(m.dedicated_ha || []).length) {
    haNeeds.push({ name: "HA1 (control)", media: "rj45", mbps: 1000, synthetic: true }, { name: "HA2 (data sync)", media: "rj45", mbps: 1000, synthetic: true });
  }
  needs = needs.concat(R.ports.filter(p => p.mode === "ha" && !haNeeds.length && !(m.dedicated_ha || []).length));
  needs = needs.concat(haNeeds);
  if (m.form === "vm") {
    E.portPlan = null;
    E.fits.ports = { need: needs.length, have: o.vmPorts || 8, status: needs.length <= (o.vmPorts || 8) ? "ok" : "short" };
    if (needs.length > (o.vmPorts || 8)) E.warnings.push(needs.length + " data interfaces needed; check how many vNICs your hypervisor allows (the tool assumes " + (o.vmPorts || 8) + ")");
  } else if (!m.ports) {
    E.fits.ports = { need: needs.length, have: null, status: "unpublished" };
    E.warnings.push("Port layout depends on installed cards");
  } else {
    const plan = assignPorts(needs, portList(m));
    E.portPlan = plan;
    const miss = plan.filter(p => !p.port);
    E.fits.ports = { need: needs.length, have: portList(m).length, status: miss.length ? "short" : "ok" };
    if (miss.length) { E.ok = false; E.reasons.push("Not enough matching ports for " + miss.map(x => x.need.name + " (" + (x.need.media === "unknown" ? "" : x.need.media + " ") + fmtSpeed(x.need.mbps) + ")").join(", ")); }
    const cross = plan.filter(p => p.fit && p.fit.warn);
    if (cross.length) E.warnings.push(cross.length + " port(s) change media or speed (see mapping)");
  }
  if (R.cellular && !m.cellular && m.form !== "vm") E.warnings.push("Source has a cellular interface; " + m.model + " has no built-in 5G");
  if (m.lifecycle === "end-of-sale-announced") E.warnings.push("End-of-sale announced: last order " + m.eos_date + ", end of life " + m.eol_date);
  if (m.lifecycle === "end-of-sale" || m.lifecycle === "end-of-life") { E.ok = false; E.reasons.push("No longer sold (" + m.lifecycle.replace(/-/g, " ") + ")"); }
  const src = A.system && A.system.swVersion;
  if (m.min_panos && src && cmpVer(majorMinor(m.min_panos) || m.min_panos, majorMinor(src)) > 0) E.warnings.push("Needs PAN-OS " + m.min_panos + " or later (source runs " + src + ")");
  if (m.last_panos && src && cmpVer(majorMinor(src), m.last_panos) > 0) { E.ok = false; E.reasons.push(m.model + " stops at PAN-OS " + m.last_panos + " (source runs " + src + ")"); }
  const utils = ["sessions", "throughput", "cps"].map(k => E.fits[k] && E.fits[k].util).filter(x => x != null);
  E.maxUtil = utils.length ? Math.max(...utils) : null;
  E.sizeRank = (m.fw_bps || 0);
  return E;
}
PPU.evaluateModel = evaluateModel;

function recommend(A, idx, R, opts) {
  const o = opts || {};
  const hwModels = idx.all.filter(m => m.form === "hardware" && (m.lifecycle === "current" || m.lifecycle === "end-of-sale-announced") && !m.chassis);
  const include = m => (o.includeRugged || !m.rugged) && (o.includeCellular || !m.cellular || R.cellular);
  const evals = hwModels.filter(include).map(m => evaluateModel(m, R, A, o));
  const fits = evals.filter(e => e.ok);
  // Prefer currently-sold over EoS-announced, then the smallest that fits (by firewall throughput, then sessions)
  const rank = e => [e.m.lifecycle === "current" ? 0 : 1, e.m.fw_bps || 0, e.m.max_sessions || 0];
  fits.sort((a, b) => { const x = rank(a), y = rank(b); for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] - y[i]; return 0; });
  const top = fits[0] || null;
  // "Step-up" option: next one in a different family or bigger
  const alt = fits.find(e => top && e.m.family !== top.m.family && e.m.lifecycle === "current") || null;
  const notChosen = evals.filter(e => !e.ok).sort((a, b) => (b.m.fw_bps || 0) - (a.m.fw_bps || 0));
  const smallestRejected = evals.filter(e => !e.ok && top && (e.m.fw_bps || 0) < (top.m.fw_bps || 0)).sort((a, b) => (b.m.fw_bps || 0) - (a.m.fw_bps || 0)).slice(0, 3);
  return { evals, fits, top, alt, notChosen, smallerRejected: smallestRejected, vm: sizeVm(A, idx, R, o) };
}
PPU.recommend = recommend;

function sizeVm(A, idx, R, opts) {
  const vms = idx.all.filter(m => m.form === "vm");
  const evals = vms.map(m => evaluateModel(m, R, A, opts));
  const fit = evals.find(e => e.ok) || null;
  const tiers = (idx.cat.vm_memory_tiers && idx.cat.vm_memory_tiers.rows) || [];
  let flex = null;
  if (R.sessions != null) {
    const row = tiers.find(t => t[1] >= R.sessions);
    if (row) flex = { memGb: row[0], maxSessions: row[1], dpVcpu: row[2] };
  }
  let vcpu = fit ? Math.max(...fit.m.vcpu) : null;
  const multi = R.vsys > 1;
  if (multi) vcpu = Math.max(vcpu || 0, 16);
  return { evals, fit, flex, vcpu, multiVsys: multi,
    notes: ["VM-Series throughput depends on the host CPU, NIC type (SR-IOV/DPDK), and hypervisor. Validate on the real host before you commit to a size.",
      "Fixed models (VM-50 to VM-700) are now sold as Software NGFW credits (flexible vCPU). Buy vCPUs + memory to match the size below."] };
}

/* ============================ licenses ============================ */
const SUB_MAP = [
  [/advanced threat/i, "Advanced Threat Prevention"], [/threat prevention/i, "Threat Prevention"],
  [/advanced url/i, "Advanced URL Filtering"], [/url/i, "URL Filtering"],
  [/advanced wildfire/i, "Advanced WildFire"], [/wildfire/i, "WildFire"],
  [/advanced dns/i, "Advanced DNS Security"], [/dns security/i, "DNS Security"],
  [/globalprotect|global protect|portal/i, "GlobalProtect"], [/sd[- ]?wan/i, "SD-WAN"],
  [/iot/i, "IoT Security"], [/dlp/i, "Enterprise DLP"], [/saas/i, "SaaS Security"],
  [/premium|platinum|standard|support|partner enabled|focus/i, "Support"], [/virtual sys/i, "Virtual Systems"],
  [/logging service|cortex data lake|strata logging/i, "Strata Logging Service"], [/aiops/i, "AIOps"],
  [/vm-?series|capacity|vm-?\d+/i, "VM-Series capacity"]
];
function normalizeSub(feature) { for (const [re, n] of SUB_MAP) if (re.test(feature)) return n; return feature; }
function licensePlan(A, target, R) {
  const qty = R.ha ? 2 : 1;
  const today = [];
  const seen = new Map();
  for (const l of A.licenses || []) {
    const n = normalizeSub(l.feature);
    const prev = seen.get(n);
    if (!prev || (prev.expired && !l.expired)) seen.set(n, Object.assign({ name: n }, l));
    today.push(Object.assign({ name: n }, l));
  }
  const carry = [], lapsed = [];
  for (const [n, l] of seen) {
    if (n === "Virtual Systems" || n === "VM-Series capacity") continue;
    (l.expired ? lapsed : carry).push(l);
  }
  // Collapse base+advanced duplicates: if Advanced X active, drop X
  const adv = new Set(carry.filter(l => /^Advanced /.test(l.name)).map(l => l.name.replace(/^Advanced /, "")));
  const carryF = carry.filter(l => !adv.has(l.name));
  const lapsedF = lapsed.filter(l => !carryF.some(c => c.name === l.name || c.name === "Advanced " + l.name));
  const vsysNeed = R.vsys || 1;
  let vsysLine = null;
  if (target) {
    const base = target.vsys_base || 1;
    if (target.form === "vm") {
      if (vsysNeed > 1) vsysLine = { needed: vsysNeed, base: 1, extra: vsysNeed - 1, note: "VM-Series: add " + (vsysNeed - 1) + " virtual system(s) to the flexible license (Tier 3 ≤ 25, Tier 4 ≤ 100; 16+ vCPUs)." };
    } else if (vsysNeed > base) {
      vsysLine = { needed: vsysNeed, base, extra: vsysNeed - base, note: target.model + " includes " + base + " vsys; quote a Virtual Systems license for " + (vsysNeed - base) + " more (max " + target.vsys_max + ")." };
    } else if (vsysNeed > 1) {
      vsysLine = { needed: vsysNeed, base, extra: 0, note: target.model + " includes " + base + " vsys, enough for the " + vsysNeed + " in use. No vsys license needed." };
    }
  }
  const todayVsys = A.vsysLicensed;
  const notes = [];
  if (A.system && A.system.multiVsys && vsysNeed === 1) notes.push("Multi-vsys mode is on but only one vsys is configured.");
  if (todayVsys && vsysLine && vsysLine.extra === 0) notes.push("A vsys license exists today (" + todayVsys + "), but the target's base count covers it. Don't re-buy it.");
  if (todayVsys && vsysLine && vsysLine.extra > 0) notes.push("Today's vsys license does not transfer to new hardware; quote it for the new serial(s).");
  if (R.ha) notes.push("HA pair: each firewall needs its own subscriptions and support. Quantities below are per pair (×2).");
  if (target && target.form === "vm") notes.push("VM-Series is licensed with Software NGFW credits: size vCPUs/memory, then pick the same security services.");
  notes.push("Subscriptions and support are tied to a serial number. Ask your account team about a hardware refresh / trade-in so remaining term can move to the new serials.");
  return { qty, today, carry: carryF, lapsed: lapsedF, vsys: vsysLine, notes };
}
PPU.licensePlan = licensePlan;

/* ============================ auto interface mapping ============================ */
function sourceInterfaces(A) {
  // Interfaces that exist in config and must be placed on the target
  const cfg = A.config;
  if (!cfg) return [];
  const r = [];
  for (const i of cfg.interfaces) {
    const row = (A.interfaces || []).find(x => x.name === i.name) || {};
    const need = srcPortNeed(Object.assign({}, row, { linkSpeed: i.linkSpeed, name: i.name }), A.system ? null : null);
    r.push({ name: i.name, mode: i.mode, aggregateGroup: i.aggregateGroup, units: i.units.map(u => u.name), zones: row.zones || [], up: row.up, media: need.media, mbps: need.mbps, mbpsKnown: need.mbpsKnown, ips: i.ips, comment: i.comment });
  }
  return r.sort((a, b) => sortIfNames(a.name, b.name));
}
PPU.sourceInterfaces = sourceInterfaces;

function autoMap(srcIfs, targetPorts, opts) {
  const o = opts || {};
  const map = {};
  const taken = new Set();
  const tByName = new Map(targetPorts.map(p => [p.name, p]));
  const notes = {};
  // pass 1: keep the same name when it fits (fewest changes)
  for (const s of srcIfs) {
    const t = tByName.get(s.name);
    if (t && !taken.has(t.name)) {
      const f = portFit(s, t);
      if (f.ok && f.score >= 60) { map[s.name] = t.name; taken.add(t.name); if (f.warn) notes[s.name] = f.warn; }
    }
  }
  // pass 2: fastest/most important first
  const rest = srcIfs.filter(s => !(s.name in map)).sort((a, b) => (b.mbps - a.mbps) || sortIfNames(a.name, b.name));
  for (const s of rest) {
    let best = null, bf = null;
    for (const t of targetPorts) {
      if (taken.has(t.name)) continue;
      const f = portFit(s, t);
      if (f.ok && (!bf || f.score > bf.score)) { best = t; bf = f; }
    }
    if (best) { map[s.name] = best.name; taken.add(best.name); if (bf.warn) notes[s.name] = bf.warn; }
    else { map[s.name] = ""; notes[s.name] = "no free matching port on the target"; }
  }
  return { map, notes };
}
PPU.autoMap = autoMap;

/* ============================ conversion ============================ */
function xpathOf(el) {
  const parts = [];
  for (let e = el; e && e.nodeType === 1; e = e.parentNode) {
    const n = attr(e, "name");
    parts.unshift(e.nodeName + (n != null ? "[@name='" + n + "']" : ""));
  }
  return "/" + parts.join("/");
}
PPU.xpathOf = xpathOf;

function expandRenames(baseMap, doc) {
  // Expand parent renames (ethernet1/5 -> ethernet1/13) to every subinterface (ethernet1/5.3 -> ethernet1/13.3)
  const full = new Map();
  const drop = new Set();
  for (const [s, t] of Object.entries(baseMap)) {
    if (t === s) continue;
    if (!t) drop.add(s); else full.set(s, t);
  }
  const all = new Set();
  const walk = el => {
    for (let c = el.firstChild; c; c = c.nextSibling) {
      if (c.nodeType !== 1) continue;
      const n = attr(c, "name"); if (n && isIfToken(n)) all.add(n);
      if (isLeaf(c)) { const t = txt(c); if (t && isIfToken(t)) all.add(t); }
      walk(c);
    }
  };
  walk(doc.documentElement);
  for (const n of all) {
    if (!n.includes(".")) continue;
    const p = parentOf(n), suf = suffixOf(n);
    if (full.has(p) && !full.has(n)) full.set(n, full.get(p) + suf);
    if (drop.has(p)) drop.add(n);
  }
  return { full, drop, all };
}

function S_panoramaServers(sys) {
  const r = [];
  for (const k of ["panorama-server", "panorama-server-2"]) { const v = txt(kid(sys, k)) || txt(path(sys, "panorama", "local-panorama", k)); if (v) r.push(v); }
  return r;
}
function convertConfig(xmlText, xmlAdapter, plan) {
  const P = Object.assign({ map: {}, haPortMap: {}, hostname: null, mgmt: null, ha: null, removePanorama: false, target: null, targetPorts: [] }, plan || {});
  const doc = xmlAdapter.parse(xmlText);
  const log = [], warnings = [], unresolved = [], info = [];
  const dev = deviceRoot(doc);
  if (!dev) throw new Error("This file is not a PAN-OS firewall config (no /config/devices/entry).");
  const add = (kind, el, from, to, note) => log.push({ kind, xpath: xpathOf(el), from: from == null ? "" : from, to: to == null ? "" : to, note: note || "" });

  // ---- 1. renames (generic walk) ----
  const merged = Object.assign({}, P.map);
  const { full, drop } = expandRenames(merged, doc);
  for (const [s, t] of Object.entries(P.haPortMap || {})) if (t && t !== s) full.set(s, t);
  // collision check: two sources -> same target
  const tgtSeen = new Map();
  for (const [s, t] of full) { if (tgtSeen.has(t)) throw new Error("Two interfaces map to " + t + ": " + tgtSeen.get(t) + " and " + s); tgtSeen.set(t, s); }
  const leaving = new Set([...full.keys(), ...drop]);
  const { all: allNames } = expandRenames({}, doc);
  for (const [s, t] of full) {
    if (!t.includes(".") && allNames.has(t) && !leaving.has(t)) throw new Error(s + " is mapped to " + t + ", but " + t + " is already used in the config and is not being moved. Map or drop " + t + " first.");
  }
  const removals = [];
  const walk = el => {
    for (let c = el.firstChild; c; c = c.nextSibling) {
      if (c.nodeType !== 1) continue;
      const n = attr(c, "name");
      if (n != null && full.has(n)) { c.setAttribute("name", full.get(n)); add("rename", c, n, full.get(n)); }
      else if (n != null && drop.has(n)) { removals.push({ el: c, val: n, how: "entry" }); }
      if (isLeaf(c)) {
        const t = txt(c);
        if (t && full.has(t)) {
          const old = t; while (c.firstChild) c.removeChild(c.firstChild);
          c.appendChild(doc.createTextNode(full.get(old))); add("rename", c, old, full.get(old));
        } else if (t && drop.has(t)) removals.push({ el: c, val: t, how: "leaf" });
      }
      walk(c);
    }
  };
  walk(doc.documentElement);
  for (const r of removals) {
    if (!r.el.parentNode) continue;
    if (r.how === "entry" || r.el.nodeName === "member") {
      const xp = xpathOf(r.el);
      r.el.parentNode.removeChild(r.el);
      log.push({ kind: "removed", xpath: xp, from: r.val, to: "", note: r.how === "entry" ? "interface not migrated" : "reference to an interface that is not migrated" });
    } else {
      unresolved.push({ xpath: xpathOf(r.el), value: r.val, why: "points at " + r.val + ", which is not migrated. Pick a new interface or delete this setting." });
    }
  }

  // ---- 2. hardware fit of physical ports ----
  const tPorts = new Map((P.targetPorts || []).map(p => [p.name, p]));
  const ifs = path(dev, "network", "interface");
  for (const e of entries(path(ifs, "ethernet"))) {
    const n = attr(e, "name");
    const tp = tPorts.get(n);
    if (!tp) { unresolved.push({ xpath: xpathOf(e), value: n, why: n + " does not exist on " + (P.target ? P.target.model : "the target") + ". Map it to a target port or drop it." }); continue; }
    const ls = kid(e, "link-speed");
    if (ls) {
      const v = txt(ls); const sp = toInt(v);
      if (tp.media === "virtual") { const x = xpathOf(ls); e.removeChild(ls); log.push({ kind: "hardware", xpath: x, from: v, to: "(removed)", note: "VM-Series uses the vNIC speed" }); }
      else if (sp && tp.mbps && sp > tp.mbps) { while (ls.firstChild) ls.removeChild(ls.firstChild); ls.appendChild(doc.createTextNode("auto")); add("hardware", ls, v, "auto", "target port max is " + fmtSpeed(tp.mbps)); }
    }
    for (const k of ["link-duplex", "link-state"]) {
      const el = kid(e, k);
      if (el && tp.media === "virtual" && txt(el) !== "auto") { const x = xpathOf(el), v = txt(el); e.removeChild(el); log.push({ kind: "hardware", xpath: x, from: v, to: "(removed)", note: "not applicable on VM-Series" }); }
    }
    const poe = kid(e, "poe");
    if (poe && !tp.poe) { const x = xpathOf(poe); e.removeChild(poe); log.push({ kind: "hardware", xpath: x, from: "poe", to: "(removed)", note: "target port has no PoE" }); }
    for (const bad of ["decrypt-mirror", "log-card"]) if (kid(e, bad)) warnings.push(n + " is a " + bad + " interface; check the target supports it.");
  }

  // ---- 3. device settings ----
  const sys = path(dev, "deviceconfig", "system");
  const setLeaf = (parent, tag, val, note) => {
    if (!parent) return;
    let el = kid(parent, tag);
    const old = el ? txt(el) : "";
    if (old === val) return;
    if (!el) { el = doc.createElement(tag); parent.appendChild(el); }
    while (el.firstChild) el.removeChild(el.firstChild);
    el.appendChild(doc.createTextNode(val));
    add("device", el, old, val, note);
  };
  const C = P.mode === "custom" && P.custom ? P.custom : null;
  const old = { host: sys ? txt(kid(sys, "hostname")) : "", ip: sys ? txt(kid(sys, "ip-address")) : "", mask: sys ? txt(kid(sys, "netmask")) : "", gw: sys ? txt(kid(sys, "default-gateway")) : "", ip6: sys ? txt(kid(sys, "ipv6-address")) : "" };
  if (C) {
    const v4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
    const chk = (v, what) => { if (v && !v4.test(v)) throw new Error(what + " \"" + v + "\" is not a valid IPv4 address."); };
    const m = C.mgmt || {};
    chk(m.ip, "Management IP"); chk(m.netmask, "Netmask"); chk(m.gateway, "Default gateway");
    if (C.dns) { chk(C.dns.primary, "Primary DNS"); chk(C.dns.secondary, "Secondary DNS"); }
    if (m.ipv6 && !/^[0-9a-fA-F:]+(\/\d{1,3})?$/.test(m.ipv6)) throw new Error("IPv6 address \"" + m.ipv6 + "\" is not valid (use address/prefix).");
    if (m.ipv6Gateway && !/^[0-9a-fA-F:]+$/.test(m.ipv6Gateway)) throw new Error("IPv6 gateway \"" + m.ipv6Gateway + "\" is not valid.");
    if (C.hostname && !/^[A-Za-z0-9]([A-Za-z0-9._-]{0,62})$/.test(C.hostname)) throw new Error("Hostname \"" + C.hostname + "\" is not valid (letters, digits, dot, dash, underscore).");
    P.hostname = C.hostname || P.hostname; P.mgmt = Object.assign({}, P.mgmt || {}, { ip: m.ip, netmask: m.netmask, gateway: m.gateway });
  }
  if (P.hostname && sys) setLeaf(sys, "hostname", P.hostname, "new hostname");
  if (C && sys) {
    const m = C.mgmt || {};
    if (m.ipv6) setLeaf(sys, "ipv6-address", m.ipv6, "management IPv6 address");
    if (m.ipv6Gateway) setLeaf(sys, "ipv6-default-gateway", m.ipv6Gateway, "management IPv6 gateway");
    const d = C.dns || {};
    if (d.primary || d.secondary) {
      if (path(sys, "dns-setting", "dns-proxy-object")) warnings.push("DNS: this firewall uses a DNS proxy object for management DNS, so the primary/secondary servers you entered were not applied. Change the proxy object on the firewall instead.");
      else {
        let ds = kid(sys, "dns-setting"); if (!ds) { ds = doc.createElement("dns-setting"); sys.appendChild(ds); }
        let sv = kid(ds, "servers"); if (!sv) { sv = doc.createElement("servers"); ds.appendChild(sv); }
        if (d.primary) setLeaf(sv, "primary", d.primary, "primary DNS server");
        if (d.secondary) setLeaf(sv, "secondary", d.secondary, "secondary DNS server");
      }
    }
  }
  if (P.mgmt && sys) {
    if (P.mgmt.ip) setLeaf(sys, "ip-address", P.mgmt.ip, "management IP");
    if (P.mgmt.netmask) setLeaf(sys, "netmask", P.mgmt.netmask, "management netmask");
    if (P.mgmt.gateway) setLeaf(sys, "default-gateway", P.mgmt.gateway, "management gateway");
  }
  const haEl = path(dev, "deviceconfig", "high-availability");
  if (P.ha === false && haEl) {
    const x = xpathOf(haEl); haEl.parentNode.removeChild(haEl);
    log.push({ kind: "device", xpath: x, from: "high-availability", to: "(removed)", note: "HA turned off for the target" });
  } else if (P.ha === true && !haEl) {
    info.push("The source is not in HA. Configure HA on the target pair after import (Device > High Availability).");
  } else if (P.ha === true && haEl) {
    info.push("HA settings were kept. Set the peer HA1 IP and the device priority on each unit before you commit; the second unit needs its own management IP and hostname.");
  }
  if (P.removePanorama && sys) {
    const pano = kid(sys, "panorama");
    for (const el of [pano, kid(sys, "panorama-server"), kid(sys, "panorama-server-2")]) {
      if (el) { const x = xpathOf(el); const v = txt(el).slice(0, 60); sys.removeChild(el); log.push({ kind: "device", xpath: x, from: v, to: "(removed)", note: "standalone target (no Panorama)" }); }
    }
  }

  // ---- 3b. custom mode: break-glass local admin + warnings about the old management address ----
  if (C) {
    const m = C.mgmt || {};
    if (C.admin && C.admin.name) {
      const a = C.admin;
      if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,30}$/.test(a.name)) throw new Error("Admin user name must be 1-31 characters: letters, digits, dot, dash or underscore.");
      if (!/^\$5\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}$/.test(a.phash || "")) throw new Error("The password hash is missing or not in $5$ (SHA-256 crypt) format. Enter the password again.");
      const role = a.role === "superreader" ? "superreader" : "superuser";
      let mc = kid(doc.documentElement, "mgt-config"); if (!mc) { mc = doc.createElement("mgt-config"); doc.documentElement.insertBefore(mc, doc.documentElement.firstChild); }
      let us = kid(mc, "users"); if (!us) { us = doc.createElement("users"); mc.appendChild(us); }
      if (entries(us).some(e => attr(e, "name").toLowerCase() === a.name.toLowerCase())) throw new Error("A local admin named \"" + a.name + "\" already exists in this config. Pick another name.");
      const ent = doc.createElement("entry"); ent.setAttribute("name", a.name);
      const ph = doc.createElement("phash"); ph.appendChild(doc.createTextNode(a.phash)); ent.appendChild(ph);
      const pm = doc.createElement("permissions"), rb = doc.createElement("role-based"), rl = doc.createElement(role); rl.appendChild(doc.createTextNode("yes"));
      rb.appendChild(rl); pm.appendChild(rb); ent.appendChild(pm); us.appendChild(ent);
      log.push({ kind: "admin", xpath: xpathOf(ent), from: "", to: "new local admin " + a.name + " (" + role + ")", note: "break-glass account; password hash set, not shown here" });
      info.push("Break-glass admin \"" + a.name + "\" was added with its own local password and no authentication profile, so it signs in against the firewall's local database even when TACACS+/LDAP/RADIUS is unreachable. Test the login on the new firewall before you rely on it.");
    }
    const A2 = authSummary(doc, dev, sys);
    const ext = A2.profiles.filter(p => p.method && p.method !== "local-database");
    if (A2.deviceProfile || ext.length || A2.sequences.length) {
      const prof = A2.deviceProfile ? "The device uses authentication profile \"" + A2.deviceProfile + "\" for admin logins" : "This config has external authentication profiles/sequences (" + [...new Set(ext.map(p => p.method))].join(", ") + ")";
      warnings.push(prof + ". After commit, if that server can't be reached from the new management IP, only local accounts can sign in. " + (C.admin && C.admin.name ? "The break-glass admin \"" + C.admin.name + "\" is local, so it still works." : "No break-glass admin was added: consider adding one."));
      const wl = A2.profiles.filter(p => p.allowList.length && !p.allowList.includes("all"));
      if (wl.length) warnings.push("Authentication profile(s) " + wl.map(p => p.name).join(", ") + " have an allow list. Local accounts with no profile are not affected, but check the allow list includes your normal admins.");
      const seqLocal = A2.sequences.filter(q => q.profiles.some(n => (A2.profiles.find(p => p.name === n) || {}).method === "local-database"));
      if (A2.sequences.length && !seqLocal.length) warnings.push("No authentication sequence includes a local-database profile. That is fine for the break-glass admin (it uses no sequence), but regular local admins given a sequence would not fall back to local.");
    }
    // references to the old management address
    const oldIp = old.ip, newIp = m.ip;
    if (oldIp && newIp && oldIp !== newIp) {
      // A service route that sources from the management interface carries the management address too. PAN-OS validate full
      // rejects it ("address is not a valid reference") once that address is no longer the management IP, so move it with the IP.
      for (const rt of Array.from(doc.getElementsByTagName("source"))) {
        if (!rt.parentNode || rt.parentNode.nodeName !== "entry" || !rt.parentNode.parentNode || rt.parentNode.parentNode.nodeName !== "service") continue;
        if (txt(kid(rt, "interface")) !== "management") continue;
        const ad = kid(rt, "address"); if (!ad) continue;
        const v = txt(ad), cidr = v.indexOf("/");
        if ((cidr < 0 ? v : v.slice(0, cidr)) !== oldIp) continue;
        const nv = newIp + (cidr < 0 ? "" : v.slice(cidr));
        while (ad.firstChild) ad.removeChild(ad.firstChild); ad.appendChild(doc.createTextNode(nv));
        log.push({ kind: "mgmt", xpath: xpathOf(ad), from: v, to: nv, note: "service route " + attr(rt.parentNode, "name") + " sources from the management interface, so its address follows the new management IP" });
      }
      const hits = [];
      const scan = el => {
        for (let c = el.firstChild; c; c = c.nextSibling) {
          if (c.nodeType !== 1) continue;
          const nm = attr(c, "name");
          const hit = v => v && (v === oldIp || v.startsWith(oldIp + "/") || v === oldIp + "/32");
          if (isLeaf(c)) { if (hit(txt(c)) && !(c.nodeName === "ip-address" && c.parentNode === sys)) hits.push(xpathOf(c)); }
          else if (nm && hit(nm)) hits.push(xpathOf(c));
          scan(c);
        }
      };
      scan(doc.documentElement);
      if (hits.length) warnings.push("The old management IP " + oldIp + " still appears in " + hits.length + " place(s) in the config (for example permitted IP lists, service routes, address objects or syslog/SNMP sources): " + hits.slice(0, 4).join("; ") + (hits.length > 4 ? "; and more" : "") + ". Review them if the new firewall should use " + newIp + ".");
      const pip = members(path(sys, "permitted-ip")).concat(entries(path(sys, "permitted-ip")).map(e => attr(e, "name")));
      if (pip.length) warnings.push("Management access is limited to " + pip.length + " permitted IP entr" + (pip.length === 1 ? "y" : "ies") + " (Device > Setup > Interfaces > Management). Those are the computers allowed to connect; make sure the admin PC that will reach " + newIp + " is on the list.");
      const sr = Array.from(doc.getElementsByTagName("service-route")).length || Array.from(doc.getElementsByTagName("route")).some(r => kid(r, "service"));
      if (sr) warnings.push("Service routes are set. Services that use the management interface (DNS, NTP, updates, Panorama, syslog) will now source from " + newIp + "; check upstream firewall rules allow it.");
    }
    if (S_panoramaServers(sys).length) warnings.push("Panorama server " + S_panoramaServers(sys).join(", ") + " is configured. A second firewall running side by side will try to reach Panorama from " + (newIp || "its management IP") + ". Allow it on the network, or tick \"Standalone (no Panorama)\" so this test unit does not register.");
    if (old.host && (!C.hostname || C.hostname === old.host)) warnings.push("The hostname is unchanged (" + old.host + "). Two firewalls with the same hostname are easy to confuse in logs and Panorama; consider a new hostname.");
  }

  // ensure HA dataplane ports are type ha
  if (P.ha !== false) {
    const hp = path(dev, "deviceconfig", "high-availability", "interface");
    for (const link of kids(hp)) {
      const pv = txt(kid(link, "port"));
      if (pv && RE_ETH.test(pv)) {
        const e = entries(path(ifs, "ethernet")).find(x => attr(x, "name") === pv);
        if (e && !kid(e, "ha")) warnings.push("HA link " + link.nodeName + " uses " + pv + ", but that interface is not type HA in the config. Set it to HA on the target.");
        if (!e) {
          const eth = path(ifs, "ethernet");
          if (eth) {
            const ne = doc.createElement("entry"); ne.setAttribute("name", pv); ne.appendChild(doc.createElement("ha"));
            eth.appendChild(ne); add("hardware", ne, "", "type ha", "HA link " + link.nodeName + " moved to a dataplane port");
          }
        }
      }
    }
  }

  // ---- 4. unresolved references sweep ----
  const defined = new Set();
  for (const k of ["ethernet", "aggregate-ethernet"]) for (const e of entries(path(ifs, k))) {
    defined.add(attr(e, "name"));
    for (const m of ["layer3", "layer2", "virtual-wire"]) for (const u of entries(path(e, m, "units"))) defined.add(attr(u, "name"));
  }
  for (const k of ["vlan", "loopback", "tunnel"]) { const el = path(ifs, k); if (el) { defined.add(k); for (const u of entries(path(el, "units"))) defined.add(attr(u, "name")); } }
  const haDed = new Set(((P.target && P.target.dedicated_ha) || []).concat(["management"]));
  const sweep = (el, inIfDefs) => {
    for (let c = el.firstChild; c; c = c.nextSibling) {
      if (c.nodeType !== 1) continue;
      const here = inIfDefs || (c.nodeName === "interface" && c.parentNode && c.parentNode.nodeName === "network");
      if (isLeaf(c)) {
        const t = txt(c);
        if (t && isIfToken(t) && !defined.has(t)) {
          unresolved.push({ xpath: xpathOf(c), value: t, why: t + " is referenced but not defined in the converted config" });
        }
        if (t && RE_HA_DED.test(t) && c.nodeName === "port" && !haDed.has(t) && P.target && P.target.form !== undefined) {
          unresolved.push({ xpath: xpathOf(c), value: t, why: "HA port " + t + " does not exist on " + P.target.model + ". Map it to a dataplane port set to type HA." });
        }
      }
      sweep(c, here);
    }
  };
  sweep(doc.documentElement, false);
  // ---- 4b. cross-version fixes found in lab validation ----
  // admin-role .../webui/device/master-key holds a masked value on some 11.1 builds; newer schemas reject it.
  for (const el of Array.from(doc.getElementsByTagName("master-key"))) {
    if (!isLeaf(el)) continue;
    const t = txt(el), anc = xpathOf(el);
    if (/admin-role/.test(anc) && t && !/^(enable|disable|read-only)$/.test(t)) {
      el.textContent = "disable";
      add("compat", el, t, "disable", "admin-role master-key permission had an invalid keyword; set to disable. Review the role.");
    }
  }
  // ---- 4c. encrypted secrets (only decrypt if the target has the same master key) ----
  const secrets = [];
  const walkSecrets = el => {
    for (let c = el.firstChild; c; c = c.nextSibling) {
      if (c.nodeType !== 1) continue;
      if (isLeaf(c)) { const t = txt(c); if (!MASK_RE.test(t) && (/^-AQ==/.test(t) || c.nodeName === "private-key")) secrets.push({ xpath: xpathOf(c), field: c.nodeName }); }
      else walkSecrets(c);
    }
  };
  walkSecrets(doc.documentElement);
  const masked = maskedSummary(doc);
  // ---- 5. warnings about things that don't move by themselves ----
  const S = summarizeConfig(doc);
  if (masked.count) warnings.unshift("This config has " + masked.count + " masked value(s) (" + Object.entries(masked.fields).map(([k, v]) => k + " ×" + v).join(", ") + "). Tech-support files replace secrets with ********, so these are placeholders, not real values. " + (masked.admins.length ? "Local admin account(s) " + masked.admins.join(", ") + " would have no usable password. " : "") + "PAN-OS rejects such a file in validate full (lab-confirmed on 11.1: \"This config has been sanitized of password data ... Please use a non-sanitized config\"), and it would carry broken private keys, VPN pre-shared keys and server secrets. For the real cutover, use a config exported from the firewall (Device > Setup > Operations > Export named configuration snapshot) and load it here on the Convert tab.");
  if (secrets.length) warnings.push(secrets.length + " encrypted value(s) (certificate private keys, pre-shared keys, RADIUS/TACACS/LDAP secrets and similar) are encrypted with the old firewall's master key. If the new firewall's master key is different, load fails validation with \"bad encryption or wrong masterkey\": set the same master key on the target first, or re-enter these after loading. They are listed in the change log as SECRET rows.");
  else if (S.certsWithKeys) warnings.push(S.certsWithKeys + " certificate(s) with private keys. Keys are encrypted with the master key: set the same master key on the target before loading, or re-import the certificates.");
  if (S.panorama && !P.removePanorama) info.push("Panorama server settings were kept (" + S.panorama.servers.length + " server(s)). Panorama must run a PAN-OS version equal to or higher than the new firewall. Add the new serial to Panorama, and point the device at the right template stack and device group (update template interface names to match this mapping).");
  if (P.target && P.target.form === "vm") {
    info.push("VM-Series: interfaces map in vNIC order (first data vNIC = ethernet1/1). Check the hypervisor port groups match the zones.");
  }
  const seenU = new Set();
  const uniqU = unresolved.filter(u => {
    if (P.ha === false && /\/high-availability(\/|$)/.test(u.xpath)) return false; // HA settings were removed
    const k = u.xpath + "|" + u.value; if (seenU.has(k)) return false; seenU.add(k); return true;
  });
  const out = xmlAdapter.serialize(doc);
  return { xml: out, log, warnings, unresolved: uniqU, info, summary: S, secrets, masked };
}
PPU.convertConfig = convertConfig;

function changeLogCsv(res) {
  const q = v => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
  const rows = [["kind", "xpath", "from", "to", "note"].map(q).join(",")];
  for (const r of res.log) rows.push([r.kind, r.xpath, r.from, r.to, r.note].map(q).join(","));
  for (const u of res.unresolved) rows.push(["UNRESOLVED", u.xpath, u.value, "", u.why].map(q).join(","));
  if (res.masked && res.masked.count) rows.push(["MASKED", "(" + Object.keys(res.masked.fields).join(" ") + ")", "********", "", res.masked.count + " placeholder value(s) from a tech-support file; use an exported config for the real cutover"].map(q).join(","));
  for (const x of res.secrets || []) rows.push(["SECRET", x.xpath, "(encrypted)", "", "re-enter on the target unless the master key matches"].map(q).join(","));
  for (const w of res.warnings) rows.push(["warning", "", "", "", w].map(q).join(","));
  return rows.join("\n") + "\n";
}
PPU.changeLogCsv = changeLogCsv;



/* ============================ SHA-256 crypt ($5$) ============================ */
/* PAN-OS stores local admin passwords in <phash> as a Unix crypt string. $5$ (SHA-256 crypt) is what current PAN-OS exports contain.
   Implemented here in plain JS so the password is hashed in the browser and never leaves it. */
const SHA = (function () {
  const K = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  function hash(parts) {
    let len = 0; for (const p of parts) len += p.length;
    const total = (len + 9 + 63) & ~63, buf = new Uint8Array(total); let o = 0;
    for (const p of parts) { buf.set(p, o); o += p.length; }
    buf[len] = 0x80;
    const dv = new DataView(buf.buffer); dv.setUint32(total - 8, Math.floor(len / 0x20000000), false); dv.setUint32(total - 4, (len << 3) >>> 0, false);
    const h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]), w = new Uint32Array(64);
    const rr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let i = 0; i < total; i += 64) {
      for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4, false);
      for (let t = 16; t < 64; t++) { const s0 = rr(w[t-15],7) ^ rr(w[t-15],18) ^ (w[t-15] >>> 3), s1 = rr(w[t-2],17) ^ rr(w[t-2],19) ^ (w[t-2] >>> 10); w[t] = (w[t-16] + s0 + w[t-7] + s1) | 0; }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let t = 0; t < 64; t++) {
        const S1 = rr(e,6) ^ rr(e,11) ^ rr(e,25), ch = (e & f) ^ (~e & g), t1 = (hh + S1 + ch + K[t] + w[t]) | 0;
        const S0 = rr(a,2) ^ rr(a,13) ^ rr(a,22), mj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + mj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    const out = new Uint8Array(32), ov = new DataView(out.buffer); for (let i = 0; i < 8; i++) ov.setUint32(i * 4, h[i], false);
    return out;
  }
  return { hash };
})();
const CRYPT64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
function sha256crypt(password, salt, rounds) {
  const enc = new TextEncoder(); const key = enc.encode(password);
  salt = String(salt).slice(0, 16); const sb = enc.encode(salt);
  const R = rounds || 5000;
  const B = SHA.hash([key, sb, key]);
  const ctxA = [key, sb];
  let cnt; for (cnt = key.length; cnt > 32; cnt -= 32) ctxA.push(B);
  ctxA.push(B.subarray(0, cnt));
  for (cnt = key.length; cnt > 0; cnt >>= 1) ctxA.push(cnt & 1 ? B : key);
  let A = SHA.hash(ctxA);
  const dpParts = []; for (let i = 0; i < key.length; i++) dpParts.push(key);
  const DP = SHA.hash(dpParts); const P = new Uint8Array(key.length); for (let i = 0; i < key.length; i++) P[i] = DP[i % 32];
  const dsParts = []; for (let i = 0; i < 16 + A[0]; i++) dsParts.push(sb);
  const DS = SHA.hash(dsParts); const S = new Uint8Array(sb.length); for (let i = 0; i < sb.length; i++) S[i] = DS[i % 32];
  let C = A;
  for (let i = 0; i < R; i++) {
    const parts = [i & 1 ? P : C];
    if (i % 3) parts.push(S);
    if (i % 7) parts.push(P);
    parts.push(i & 1 ? C : P);
    C = SHA.hash(parts);
  }
  const b64 = (b2, b1, b0, n) => { let w = (b2 << 16) | (b1 << 8) | b0, r = ""; for (let i = 0; i < n; i++) { r += CRYPT64[w & 63]; w >>>= 6; } return r; };
  const o = [[0,10,20],[21,1,11],[12,22,2],[3,13,23],[24,4,14],[15,25,5],[6,16,26],[27,7,17],[18,28,8],[9,19,29]];
  let out = ""; for (const t of o) out += b64(C[t[0]], C[t[1]], C[t[2]], 4);
  out += b64(0, C[31], C[30], 3);
  return "$5$" + (rounds && rounds !== 5000 ? "rounds=" + rounds + "$" : "") + salt + "$" + out;
}
function randomSalt(len, rnd) {
  let s = ""; const n = len || 16;
  const bytes = new Uint8Array(n);
  (rnd || ((b) => (typeof crypto !== "undefined" ? crypto.getRandomValues(b) : (() => { throw new Error("No secure random source available."); })())))(bytes);
  for (let i = 0; i < n; i++) s += CRYPT64[bytes[i] & 63];
  return s;
}
PPU.sha256crypt = sha256crypt; PPU.randomSalt = randomSalt;

/* ============================ hardware & cabling ============================ */
const CAGE_GROUP = { sfp: ["sfp", 1], "sfp+": ["sfp", 2], sfp28: ["sfp", 3], "qsfp+": ["qsfp", 1], qsfp28: ["qsfp", 2], "qsfp-dd": ["qsfp", 3] };
const OPTIC_TYPES = {
  "SFP": ["1000BASE-SX (multimode fiber)", "1000BASE-LX (single-mode fiber)", "1000BASE-T (copper SFP)"],
  "SFP+": ["10GBASE-SR (multimode)", "10GBASE-LR (single-mode)", "DAC / AOC cable", "10GBASE-T (copper SFP+)"],
  "SFP28": ["25GBASE-SR (multimode)", "25GBASE-LR (single-mode)", "DAC / AOC cable"],
  "QSFP+": ["40GBASE-SR4 (multimode)", "40GBASE-LR4 (single-mode)", "DAC / AOC cable"],
  "QSFP28": ["100GBASE-SR4 (multimode)", "100GBASE-LR4 (single-mode)", "DAC / AOC cable"],
  "QSFP-DD": ["400GBASE-SR8 (multimode)", "400GBASE-DR4 (single-mode)", "DAC / AOC cable"]
};
const TBD = "Type to be chosen";
function formForSpeed(mbps) { return mbps <= 1000 ? "SFP" : mbps <= 10000 ? "SFP+" : mbps <= 25000 ? "SFP28" : mbps <= 40000 ? "QSFP+" : mbps <= 100000 ? "QSFP28" : "QSFP-DD"; }
function copperCable(mbps) { return mbps >= 10000 ? "Cat6a patch cable (10G)" : mbps >= 2500 ? "Cat5e/Cat6 patch cable (2.5G/5G)" : "Cat5e/Cat6 patch cable"; }
function speedChoices(tp) { const mx = tp.mbps || MEDIA_MAX[tp.media] || 1000; return [1000, 2500, 5000, 10000, 25000, 40000, 100000, 400000].filter(x => x <= mx && (tp.media === "rj45" || tp.media === "combo" ? x === 1000 : tp.media === "mgig" ? x <= 10000 : FIBER.includes(tp.media) ? ({ sfp: [1000], "sfp+": [1000, 10000], sfp28: [10000, 25000], "qsfp+": [40000], qsfp28: [40000, 100000], "qsfp-dd": [100000, 400000] }[tp.media] || []).includes(x) : true)); }
function haSpecFor(model, port) {
  // dedicated HA port name -> catalog spec (or null when the type is not in the catalog)
  if (!model || !model.ha_ports) return null;
  const id = /^ha1/.test(port) ? "ha1" : /^hsci/.test(port) ? "hsci" : /^ha2/.test(port) ? "ha2" : null;
  const sp = model.ha_ports.find(h => h.id === id);
  return sp || null;
}
const HA_LABEL = { ha1: "HA1 control", "ha1-backup": "HA1 control (backup)", ha2: "HA2 data", "ha2-backup": "HA2 data (backup)", ha3: "HA3 packet forwarding", ha4: "HA4 session sync", "ha4-backup": "HA4 session sync (backup)" };

function xcvrSpeed(x) {
  const t = [x.compliance, x.pn, x.label].filter(Boolean).join(" ");
  let m = t.match(/(\d+)\s*G(?:BASE|E)?/i); if (m) return +m[1] * 1000;
  if (/1000\s*BASE/i.test(t)) return 1000;
  return null;
}
function defaultHaPortMap(A, target, map) {
  const out = {}; const ded = target && target.dedicated_ha || [];
  const used = new Set(Object.values(map || {}).filter(Boolean));
  for (const port of Object.values((A.ha && A.ha.ports) || {})) {
    if (!port || RE_ETH.test(port) || port in out) continue;
    if (ded.includes(port)) { out[port] = port; continue; }
    const fam = /^ha1/.test(port) ? "ha1" : /^ha2/.test(port) ? "ha2" : /^hsci/.test(port) ? "hsci" : port;
    const pick = ded.find(d => d.startsWith(fam) && !Object.values(out).includes(d)) || ded.find(d => d.startsWith("ha") && !Object.values(out).includes(d) && fam !== "hsci") || null;
    out[port] = pick || "";
  }
  return out;
}
PPU.defaultHaPortMap = defaultHaPortMap;
function hardwarePlan(A, target, R, opts) {
  const o = opts || {};
  const ed = o.edits || {};
  const units = R && R.ha ? 2 : 1;
  const out = { units, vm: !!(target && target.form === "vm"), power: null, ports: [], ha: [], groups: [], summary: {}, notes: [] };
  if (!target) return out;
  const srcModel = o.srcModel || null;
  // ---- power ----
  const tp = target.psu || null;
  const sp = srcModel && srcModel.psu || null;
  const P = { units, tgt: tp, vm: out.vm, src: { virtual: isVmSystem(A.system), fromTsf: A.power || null, catalog: sp, note: null, redundant: null, basis: null } };
  if (A.power) { P.src.redundant = A.power.count >= 2; P.src.basis = "tech-support file (" + A.power.from + ")"; }
  else if (sp && sp.base != null && sp.cli_status !== false) { P.src.redundant = sp.base >= 2; P.src.basis = "catalog: " + srcModel.model + " ships with " + sp.base; }
  else if (sp && sp.cli_status === false) { P.src.note = srcModel.model + " does not report power adapter status in the CLI, so the file cannot say whether a second adapter is installed. Check the old firewall (PWR 2)."; }
  else if (!A.hasEnvironmentals) P.src.note = "No power information in this file.";
  let extra = 0; const pn = [];
  if (out.vm) { pn.push("VM-Series: no power supplies or power cords. Plan host resources and hypervisor networking instead."); }
  else if (!tp) pn.push(target.model + ": power supply details are not in the catalog sources. Confirm PSU count and power cords on the quote.");
  else {
    if (tp.base == null) pn.push(target.model + ": supply count depends on configuration (" + (tp.text || "see datasheet") + "). Confirm on the quote.");
    if (P.src.redundant === true && tp.base != null && tp.base < 2) {
      if ((tp.max || 1) >= 2) { extra = 1; pn.push("The old firewall had redundant power" + (A.power ? " (" + A.power.count + " supplies seen in the file)" : "") + ". " + target.model + " ships with " + tp.base + " " + (tp.kind === "adapter" ? "power adapter" : "supply") + "; quote " + (units === 2 ? "1 optional second per firewall (" + units + " total)" : "1 optional second") + " to keep redundancy."); }
      else pn.push("The old firewall had redundant power, but " + target.model + " cannot take a second power supply. Redundancy is lost; plan for it (UPS or a different model).");
    } else if (P.src.redundant === false && tp.base === 1 && (tp.max || 1) >= 2) pn.push("The old firewall ran on a single supply. A second one for " + target.model + " is available if you want redundancy; it is not added here.");
    else if (P.src.virtual && tp.base === 1 && (tp.max || 1) >= 2) pn.push("The old firewall is a virtual machine, so there is nothing to copy. " + target.model + " ships with one supply; add a second only if you want power redundancy.");
    else if (P.src.redundant == null && tp.base === 1 && (tp.max || 1) >= 2) pn.push("It is not known whether the old firewall had a second supply. " + target.model + " ships with one; add a second if the old setup was redundant.");
    if (tp.feed === "AC or DC") pn.push("AC and DC supplies can't be mixed in one firewall. Confirm AC or DC with the customer.");
    if (tp.note) pn.push(tp.note);
  }
  P.extraDefault = extra;
  P.psuPerUnit = ed.psuPerUnit != null ? ed.psuPerUnit : (tp && tp.base != null ? tp.base + extra : null);
  P.included = tp && tp.base != null ? tp.base : null;
  P.optionalPerUnit = P.psuPerUnit != null && P.included != null ? Math.max(0, P.psuPerUnit - P.included) : null;
  P.cords = P.psuPerUnit != null ? P.psuPerUnit * units : null;
  P.cordKind = tp ? (tp.feed === "DC" ? "DC power cables" : tp.kind === "adapter" ? "AC cord for each adapter (cord comes with the adapter)" : "AC power cords" + (tp.cord ? " (" + tp.cord + ")" : "")) : "power cords";
  P.notes = pn;
  out.power = P;

  // ---- data ports ----
  const tports = o.targetPorts || portList(target, { vmPorts: o.vmPorts });
  const tmap = new Map(tports.map(p => [p.name, p]));
  const map = o.map || {};
  const rows = [];
  for (const [srcName, tgtName] of Object.entries(map)) {
    if (!tgtName) continue;
    const sr = (A.interfaces || []).find(r => r.name === srcName);
    if (!sr || !RE_ETH.test(srcName)) continue;
    const tpt = tmap.get(tgtName); if (!tpt) continue;
    let media = sr.media || "unknown";
    if (media === "unknown" && srcModel && srcModel.ports) { const q = portList(srcModel).find(x => x.name === srcName); if (q) media = q.media; }
    const need = srcPortNeed(sr, srcModel);
    const srcVirtual = media === "virtual";
    const srcSpeedKnown = !srcVirtual && !!(sr.up && sr.runtimeSpeed);
    const srcSpeed = srcSpeedKnown ? sr.runtimeSpeed : null;
    const tmax = tpt.mbps || MEDIA_MAX[tpt.media] || 1000;
    const edSp = ed.opSpeed && ed.opSpeed[tgtName];
    const baseSpeed = srcSpeed || need.mbps || 1000;
    const op = edSp || Math.min(baseSpeed, tmax);
    const x = sr.up ? (A.xcvr && A.xcvr[srcName]) || null : null;
    const row = { src: srcName, tgt: tgtName, srcMedia: media, srcSpeed, srcSpeedKnown, srcUp: !!sr.up, tgtMedia: tpt.media, tgtMax: tmax, opSpeed: op, xcvr: x, flags: [], speedChange: false, mediaChange: false, cageChange: false, reuse: false, kind: null, form: null, note: [] };
    if (out.vm) { row.kind = "virtual"; rows.push(row); continue; }
    const sf = family(media), tf = family(tpt.media);
    if (srcSpeed && op < srcSpeed) { row.speedChange = true; row.flags.push("Speed down: " + fmtSpeed(srcSpeed) + " → " + fmtSpeed(op) + ". The device at the other end must also run " + fmtSpeed(op) + "."); }
    else if (srcSpeed && op > srcSpeed) { row.speedChange = true; row.flags.push("Speed up: " + fmtSpeed(srcSpeed) + " → " + fmtSpeed(op) + ". New optic or cable, and the other end must support " + fmtSpeed(op) + "."); }
    else if (srcVirtual) row.note.push("The old port is a virtual NIC, so there is no speed or media to carry over. Choose the speed and cable for the switch this port plugs into (shown here at " + fmtSpeed(op) + ").");
    else if (!srcSpeed) row.note.push(sr.up ? "Link speed not in file; assumed " + fmtSpeed(op) + "." : "Link was down when the file was taken; confirm this port is cabled.");
    const toCopper = tpt.media === "rj45" || tpt.media === "mgig" || (tpt.media === "combo" && sf !== "fiber");
    if (sf !== "unknown" && sf !== "combo" && sf !== "virtual" && ((sf === "copper") !== toCopper)) { row.mediaChange = true; row.flags.push(sf === "copper" ? "Media change: copper → fiber/SFP port. Needs an optic (or a copper SFP) and may need re-cabling." : "Media change: fiber/SFP → copper port. Needs a copper patch cable and the other end must be copper."); }
    if (!toCopper) {
      const form = tpt.media === "combo" ? "SFP" : formForSpeed(op);
      row.kind = "optic"; row.form = form;
      const sg = CAGE_GROUP[media], tg = CAGE_GROUP[tpt.media === "combo" ? "sfp" : tpt.media];
      if (sf === "fiber" && sg && tg && sg[0] === tg[0] && sg[1] !== tg[1]) { row.cageChange = true; row.flags.push("Port type change: " + media.toUpperCase() + " → " + tpt.media.toUpperCase() + (sg[1] < tg[1] ? ". The existing optic fits the larger cage and runs at its own speed." : ". The smaller cage will not take the old optic.")); }
      else if (sf === "fiber" && sg && tg && sg[0] !== tg[0]) { row.cageChange = true; row.flags.push("Port type change: " + media.toUpperCase() + " → " + tpt.media.toUpperCase() + ". The old optic will not fit."); }
      const fits = sf === "fiber" && sg && tg && sg[0] === tg[0] && sg[1] <= tg[1];
      const xs = x ? xcvrSpeed(x) : null;
      const spOk = srcSpeed ? op === srcSpeed && form === formForSpeed(srcSpeed) : (!sr.up && form === formForSpeed(need.mbps || op));
      row.reuse = !!(fits && spOk && (!xs || xs === op) && !ed.buyNew);
      if (x && xs && xs !== op) row.note.push("The optic in the old firewall is " + fmtSpeed(xs) + "; this link runs at " + fmtSpeed(op) + ", so a new optic is needed.");
      if (tpt.media === "sfp28" && op <= 1000) row.note.push("25G SFP28 ports may not support 1G. Check the hardware reference.");
    } else {
      row.kind = "copper"; row.form = copperCable(op);
      row.reuse = sf === "copper" && (srcSpeed ? op === srcSpeed : !sr.up);
      if (op >= 10000 && !(sf === "copper" && srcSpeed >= 10000)) row.note.push("10G over copper needs Cat6a or better.");
    }
    row.flags.forEach(f => 0);
    rows.push(row);
  }
  out.ports = rows.sort((a, b) => sortIfNames(a.tgt, b.tgt));

  // ---- HA links ----
  const hrows = [];
  if (R && R.ha && A.ha && A.ha.ports) {
    const tpsList = tports;
    for (const [link, srcPort] of Object.entries(A.ha.ports)) {
      if (!srcPort) continue;
      const row = { link, label: HA_LABEL[link] || link, srcPort, srcDesc: null, tgtPort: null, tgtDesc: null, dedicated: false, kind: null, form: null, mediaChange: false, speedChange: false, flags: [], cableText: null };
      // source description
      if (RE_ETH.test(srcPort)) { const sr = (A.interfaces || []).find(r => r.name === srcPort); row.srcMedia = sr && sr.media || null; row.srcSpeed = sr && sr.runtimeSpeed || null; row.srcDesc = srcPort + " (data port" + (row.srcMedia ? ", " + row.srcMedia.toUpperCase() : "") + ")"; }
      else { const sc = haSpecFor(srcModel, srcPort); row.srcMedia = sc && sc.media; row.srcSpeed = sc && sc.mbps; row.srcDesc = srcPort.toUpperCase() + (sc ? " (" + sc.media.toUpperCase() + " " + fmtSpeed(sc.mbps) + ")" : " (type not in catalog)"); }
      // target port
      const isTargetDed = n => (target.dedicated_ha || []).includes(n);
      let tgt = RE_ETH.test(srcPort) ? (map[srcPort] || null) : ((o.haPortMap || {})[srcPort] || null);
      row.tgtPort = tgt;
      if (!tgt) { row.flags.push("No target port chosen for this HA link."); row.kind = null; hrows.push(row); continue; }
      if (out.vm) { row.kind = "virtual"; row.tgtDesc = tgt + " (vNIC)"; row.cableText = "No cable: put both VMs' HA vNICs on the same virtual network."; hrows.push(row); continue; }
      let media = null, mbps = null;
      if (isTargetDed(tgt)) {
        row.dedicated = true;
        const sc = haSpecFor(target, tgt);
        if (sc) { media = sc.media; mbps = sc.mbps; row.tgtDesc = tgt.toUpperCase() + " (dedicated " + sc.media.toUpperCase() + " " + fmtSpeed(sc.mbps) + ")"; }
        else row.tgtDesc = tgt.toUpperCase() + " (dedicated; port type not in catalog)";
      } else { const tpt = tpsList.find(p => p.name === tgt); if (tpt) { media = tpt.media; mbps = tpt.mbps; } row.tgtDesc = tgt + " (data port" + (media ? ", " + media.toUpperCase() : "") + "; set to type HA)"; }
      row.tgtMedia = media; row.tgtMbps = mbps;
      if (!media) { row.kind = "unknown"; row.cableText = "Port type for " + tgt + " is not in the catalog. Check the hardware reference to choose a cable or optics."; hrows.push(row); continue; }
      const cu = media === "rj45" || media === "mgig" || media === "combo";
      const speed = Math.min(mbps || 1000, row.srcSpeed || mbps || 1000);
      row.opSpeed = speed;
      if (cu) { row.kind = "copper"; row.form = "Ethernet cable"; row.cableText = "Plain Ethernet cable (Cat5e or better) between the two firewalls. 1 per link."; }
      else { row.kind = "optic"; row.form = formForSpeed(speed); row.cableText = row.form + " optic at each end + fiber (or one DAC/AOC cable) between the firewalls. 2 optics per link."; }
      if (row.srcMedia && row.tgtMedia && family(row.srcMedia) !== family(media)) { row.mediaChange = true; row.flags.push("Cable type changes: " + (family(row.srcMedia) === "copper" ? "copper → fiber, so the old Ethernet HA cable will not work" : "fiber → copper, so optics are no longer needed and a plain Ethernet cable is used")); }
      if (row.srcSpeed && speed !== row.srcSpeed) { row.speedChange = true; row.flags.push("HA link speed " + fmtSpeed(row.srcSpeed) + " → " + fmtSpeed(speed)); }
      if (!row.dedicated && !isTargetDed(tgt) && !RE_ETH.test(srcPort)) row.flags.push("Uses a data port: " + target.model + " has no dedicated port for this link.");
      hrows.push(row);
    }
    // a second HA link of the same kind cannot reuse the same physical port
  }
  out.ha = hrows;

  // ---- groups (BOM) ----
  const G = new Map();
  const add = (use, kind, form, speed, reuse, count, optics, label) => {
    const key = [use, kind, form, reuse ? "reuse" : "new"].join("|");
    if (!G.has(key)) G.set(key, { key, use, kind, form, speedMbps: speed, reuse, ports: 0, defaultQty: 0, label });
    const g = G.get(key); g.ports += count; if (!reuse) g.defaultQty += optics;
  };
  if (!out.vm) {
    for (const r of rows) if (r.kind === "optic" || r.kind === "copper") add("data", r.kind, r.form, r.opSpeed, r.reuse, units, r.reuse ? 0 : units);
    for (const h of hrows) if (h.kind === "optic") add("ha", "optic", h.form, h.opSpeed, false, 1, 2); else if (h.kind === "copper") add("ha", "copper", h.form, h.opSpeed, false, 1, 1);
  }
  out.groups = [...G.values()].map(g => {
    const q = ed.qty && ed.qty[g.key]; const ty = ed.type && ed.type[g.key];
    return Object.assign(g, { qty: q != null ? q : g.defaultQty, type: g.kind === "optic" ? (ty || (g.reuse ? "Reuse existing optic" : TBD)) : g.form, typeOptions: g.kind === "optic" ? (g.reuse ? ["Reuse existing optic"] : []).concat(OPTIC_TYPES[g.form] || []) : [] });
  }).sort((a, b) => (a.use === b.use ? 0 : a.use === "data" ? -1 : 1) || a.kind.localeCompare(b.kind) || a.speedMbps - b.speedMbps);
  const cnt = f => rows.filter(f).length;
  out.summary = { ports: rows.length, speedChanges: cnt(r => r.speedChange), mediaChanges: cnt(r => r.mediaChange), cageChanges: cnt(r => r.cageChange), reused: cnt(r => r.reuse), srcOpticsDetected: A.xcvr ? Object.keys(A.xcvr).length : null, haLinks: hrows.length };
  if (!A.xcvr && !out.vm && !isVmSystem(A.system)) out.notes.push("Installed optics are not listed in this file (show transceiver-detail all). Check the old firewall's optics before ordering.");
  if (!out.vm) out.notes.push("Counts cover the firewall side only. Where a link's speed or media changes, the switch or router at the other end needs a matching optic or port.");
  return out;
}
PPU.hardwarePlan = hardwarePlan;
PPU.OPTIC_TYPES = OPTIC_TYPES; PPU.speedChoices = speedChoices;


/* ============================ readiness checks ============================ */
// Tech-support files hide secrets: private keys, PSKs, auth-server secrets and admin password hashes show up as ********.
// A config taken from such a file cannot be loaded as-is: the placeholders are not real values.
const MASK_RE = /^\*{4,}$/;
function maskedSummary(doc) {
  const fields = {}, admins = [];
  let count = 0;
  for (const el of Array.from(doc.getElementsByTagName("*"))) {
    if (!isLeaf(el) || !MASK_RE.test((el.textContent || "").trim())) continue;
    const n = el.nodeName === "key" && el.parentNode ? el.parentNode.nodeName : el.nodeName;
    fields[n] = (fields[n] || 0) + 1; count++;
    if (el.nodeName === "phash" && el.parentNode && el.parentNode.nodeName === "entry") { const u = attr(el.parentNode, "name"); if (u) admins.push(u); }
  }
  return { count, fields, admins };
}
PPU.maskedSummary = maskedSummary;
function configInventory(doc, S) {
  const dev = deviceRoot(doc);
  const I = { rules: 0, nat: 0, decrypt: 0, pbf: 0, zones: S.zones.length, addr: 0, addrgrp: 0, svc: 0, svcgrp: 0, ipsecTunnels: 0, ikeGateways: 0, staticRoutes: 0,
    bgp: false, ospf: false, rip: false, vsys: S.vsys.length, certs: [], secrets: {}, userId: { agents: 0, tsAgents: 0, groupMapping: 0, serverMonitor: 0 },
    serverProfiles: { radius: 0, tacplus: 0, ldap: 0, kerberos: 0, saml: 0 }, syslog: 0, snmpV3: false, dynamicUpdates: false, jumbo: false, decryptMirror: [], logCard: [], ae: S.ae.length,
    psk: 0, gpPortals: 0, gpGateways: 0, edl: 0, weakCrypto: [], panoramaServers: [] };
  if (!dev) return I;
  const cfg = doc.documentElement, net = path(dev, "network"), sh = path(cfg, "shared");
  const all = tag => Array.from(doc.getElementsByTagName(tag));
  const nEntries = (el) => entries(el).length;
  // rules: vsys rulebases plus shared pre/post rulebases
  for (const v of S.vsys) { I.rules += v.security; I.nat += v.nat; I.decrypt += v.decryption; I.pbf += v.pbf; }
  for (const t of ["pre-rulebase", "post-rulebase"]) { const rb = path(sh, t); I.rules += nEntries(path(rb, "security", "rules")); I.nat += nEntries(path(rb, "nat", "rules")); I.decrypt += nEntries(path(rb, "decryption", "rules")); }
  const vsysEls = entries(path(dev, "vsys"));
  const countKid = tag => { let n = nEntries(path(sh, tag)); for (const v of vsysEls) n += nEntries(path(v, tag)); return n; };
  I.addr = countKid("address"); I.addrgrp = countKid("address-group"); I.svc = countKid("service"); I.svcgrp = countKid("service-group"); I.edl = countKid("external-list");
  I.ikeGateways = nEntries(path(net, "ike", "gateway")); I.ipsecTunnels = nEntries(path(net, "tunnel", "ipsec"));
  I.gpPortals = S.counts.gpPortals; I.gpGateways = S.counts.gpGateways;
  // routing: virtual routers and logical routers
  for (const vr of entries(path(net, "virtual-router"))) {
    I.staticRoutes += nEntries(path(vr, "routing-table", "ip", "static-route")) + nEntries(path(vr, "routing-table", "ipv6", "static-route"));
    if (txt(path(vr, "protocol", "bgp", "enable")) === "yes") I.bgp = true;
    if (txt(path(vr, "protocol", "ospf", "enable")) === "yes") I.ospf = true;
    if (txt(path(vr, "protocol", "rip", "enable")) === "yes") I.rip = true;
  }
  for (const lr of entries(path(net, "logical-router"))) for (const vrf of entries(path(lr, "vrf"))) {
    I.staticRoutes += nEntries(path(vrf, "routing-table", "ip", "static-route")) + nEntries(path(vrf, "routing-table", "ipv6", "static-route"));
    if (path(vrf, "bgp") && txt(path(vrf, "bgp", "enable")) !== "no") I.bgp = true;
    if (path(vrf, "ospf") && txt(path(vrf, "ospf", "enable")) !== "no") I.ospf = true;
    if (path(vrf, "ospfv3") && txt(path(vrf, "ospfv3", "enable")) !== "no") I.ospf = true;
    if (path(vrf, "rip") && txt(path(vrf, "rip", "enable")) !== "no") I.rip = true;
  }
  // certificates and encrypted values (names and counts only; values are never copied)
  for (const c of all("certificate")) for (const e of entries(c)) I.certs.push({ name: attr(e, "name"), key: !!kid(e, "private-key"), cn: txt(kid(e, "common-name")) || null });
  for (const el of Array.from(doc.getElementsByTagName("*"))) {
    if (!isLeaf(el)) continue;
    const v = el.textContent || "";
    if (v.indexOf("-AQ==") === 0) {
      const n = el.nodeName === "key" && el.parentNode ? el.parentNode.nodeName : el.nodeName;
      I.secrets[n] = (I.secrets[n] || 0) + 1;
    }
  }
  I.psk = all("pre-shared-key").length;
  // User-ID, authentication servers, logging, SNMP, updates
  for (const t of all("user-id-agent")) I.userId.agents += nEntries(t);
  for (const t of all("ts-agent")) I.userId.tsAgents += nEntries(t);
  for (const t of all("group-mapping")) I.userId.groupMapping += nEntries(t);
  for (const t of all("server-monitor")) I.userId.serverMonitor += nEntries(t);
  for (const sp of all("server-profile")) {
    for (const k of kids(sp)) {
      const n = nEntries(k);
      if (k.nodeName === "radius") I.serverProfiles.radius += n; else if (k.nodeName === "tacplus") I.serverProfiles.tacplus += n;
      else if (k.nodeName === "ldap") I.serverProfiles.ldap += n; else if (k.nodeName === "kerberos") I.serverProfiles.kerberos += n;
      else if (k.nodeName === "saml-idp") I.serverProfiles.saml += n; else if (k.nodeName === "syslog") I.syslog += n;
    }
  }
  I.snmpV3 = all("v3").some(el => el.parentNode && /^(access-setting|snmp-setting)$/.test(el.parentNode.nodeName));
  I.dynamicUpdates = all("update-schedule").some(el => kids(el).length > 0);
  I.jumbo = all("jumbo-frame").some(el => txt(el) === "yes");
  for (const i of S.interfaces) { if (i.mode === "decrypt-mirror") I.decryptMirror.push(i.name); if (i.mode === "log-card") I.logCard.push(i.name); }
  // legacy crypto algorithms
  const weak = new Set();
  const WEAK = { encryption: /^(3des|des|null)$/, authentication: /^(md5|sha1)$/, hash: /^(md5|sha1)$/, "dh-group": /^(group1|group2|group5)$/ };
  for (const tag of ["ike-crypto-profiles", "ipsec-crypto-profiles"]) for (const p of all(tag)) for (const e of entries(p)) {
    for (const [k, re] of [["encryption", WEAK.encryption], ["authentication", WEAK.authentication], ["hash", WEAK.hash], ["dh-group", WEAK["dh-group"]]]) {
      const holders = [e, kid(e, "esp"), kid(e, "ah")].filter(Boolean);
      for (const h of holders) { const el = kid(h, k); if (!el) continue; const vals = kids(el, "member").length ? members(el) : [txt(el)]; for (const x of vals) if (re.test(x)) weak.add(x); }
    }
  }
  I.weakCrypto = Array.from(weak);
  I.panoramaServers = S.panorama ? S.panorama.servers.slice() : [];
  return I;
}
PPU.configInventory = configInventory;

function parseVer(v) {
  const m = String(v || "").match(/^(\d+)\.(\d+)(?:\.(\d+))?(?:-h(\d+))?/);
  return m ? { major: +m[1], minor: +m[2], maint: +(m[3] || 0), hf: +(m[4] || 0), fr: m[1] + "." + m[2], full: String(v) } : null;
}
function sourceVersion(A) { return (A.system && A.system.swVersion) || (A.config && A.config.detailVersion) || null; }
const UP = ["upgrade_path", "upgrade_notes"];
function versionCheck(A, target, R, ctx) {
  const items = [], c = ctx || {};
  const sv = parseVer(sourceVersion(A));
  const src = (id, t) => items.push(Object.assign({ sev: "info", refs: [] }, t, { id }));
  if (!sv) { src("srcver", { sev: "warn", title: "Source PAN-OS version not found", text: "The file does not show the PAN-OS version, so version checks are skipped. Check it on the old firewall (Device > Software)." }); return items; }
  const tmin = target && target.min_panos ? target.min_panos : null, tlast = target && target.last_panos ? target.last_panos : null;
  const install = tmin && cmpVer(majorMinor(tmin), sv.fr) > 0 ? tmin : sv.fr;
  src("install", { sev: "info", title: "Install this PAN-OS on the new firewall before importing", text: "Old firewall: PAN-OS " + sv.full + ". The new firewall must run the same feature release or newer (a newer config cannot be loaded on an older release). Install PAN-OS " + install + (install === sv.fr ? " (the same feature release, at the latest maintenance release you have approved)" : "") + " first, then import the config. " + (target && target.model ? target.model + " ships with the release it was built for; check Device > Software and upgrade before the import." : ""), refs: UP });
  if (tmin && cmpVer(majorMinor(tmin), sv.fr) > 0) src("min", { sev: "warn", title: target.model + " needs PAN-OS " + tmin + " or later", text: "The old firewall runs " + sv.fr + ", which is older than the minimum for the new model. Plan the version change together with the hardware change: the config is upgraded when it is loaded on the newer release, and the new feature release may change or deprecate settings. Review the release notes for every release between " + sv.fr + " and " + tmin + ".", refs: UP.concat(["compat"]) });
  if (tlast && cmpVer(majorMinor(tlast), sv.fr) < 0) src("last", { sev: "bad", title: "Old config is newer than the last PAN-OS " + target.model + " supports", text: "The old firewall runs " + sv.fr + "; " + target.model + " supports up to " + tlast + ". The config cannot be loaded on an older release. Pick a different model or stay on the old release until the model can be replaced.", refs: ["compat"] });
  if (sv.major < 10 || (sv.major === 10 && sv.minor === 0)) src("old", { sev: "warn", title: "PAN-OS " + sv.fr + " is old: check support status", text: "From 9.1 and earlier the upgrade path installs the latest maintenance release of every feature release on the way (no skipping), and each step can change or remove settings. Check the Palo Alto support status for " + sv.fr + " and read the release notes of each release you pass.", refs: UP });
  else src("path", { sev: "info", title: "Upgrade path after the migration", text: "From PAN-OS 10.1 or later you can use Skip Software Version Upgrade to skip up to three feature releases (for example 10.2 straight to 11.2, 11.0 or 11.1 straight to 12.1). Do not install the base image of a release you are not moving to. Keep both HA peers and Panorama in step (see below).", refs: UP });
  if (R && R.ha) src("ha", { sev: "info", title: "HA peers must be within one feature release", text: "When upgrading an HA pair across feature releases, upgrade both peers to the same feature release before you go on. Peers two or more feature releases apart will not form HA (\"Peer version too old\"). Match the PAN-OS version on both new firewalls before you enable HA.", refs: UP });
  if (A.config && A.config.panorama) src("pano", { sev: "info", title: "Panorama must run the same or a later PAN-OS than the firewall", text: "Panorama can manage a firewall on a higher version only within the same release train from 10.2.7 onwards; otherwise upgrade Panorama first. Check the Panorama version before you change the firewall's release.", refs: ["upgrade_panorama"] });
  if (target && target.model === "PA-5450" && cmpVer(sv.fr, "10.2") < 0) src("5450", { sev: "warn", title: "PA-5450 cannot be upgraded straight from 10.1", text: "Per Palo Alto's upgrade notes, a PA-5450 coming from PAN-OS 10.1.x must first go to the latest 10.2.x or 11.x release before moving on. Plan the version of the first boot accordingly.", refs: ["upgrade_notes"] });
  if (A.config && A.config.features.advancedRouting && sv.major >= 11) src("are", { sev: "info", title: "Advanced Routing Engine is in use", text: "The old firewall uses the logical-router (advanced routing) config, which is available from PAN-OS 11.0. The new firewall must run 11.0 or later when the config is loaded, or the routing config is rejected.", refs: [] });
  if (A.config && A.vsysInUse > 1 && A.config.panorama) src("vsys", { sev: "info", title: "Multi-vsys firewall managed by Panorama", text: "After upgrading a managed multi-vsys firewall to 10.2 with Skip Software Version Upgrade, the firewall shows out of sync in Panorama until you do a full commit and push. Plan a full commit and push after the upgrade.", refs: ["upgrade_notes"] });
  if (A.inventory && A.inventory.weakCrypto.length) src("crypto", { sev: "info", title: "Legacy algorithms in IKE/IPsec crypto profiles", text: "Found: " + A.inventory.weakCrypto.join(", ") + ". They convert as they are. Review them against the release notes of the PAN-OS you will run: newer releases can drop or warn on weak algorithms, and the VPN peers must still agree.", refs: [] });
  return items;
}
PPU.versionCheck = versionCheck;

function wontMigrate(A, target, R) {
  const I = A.inventory, rows = [];
  const add = (r) => rows.push(Object.assign({ applies: true, sev: "warn" }, r));
  if (!I) { return [{ id: "noconfig", title: "No config in this file", text: "Without a running config the tool cannot list what will not move.", sev: "info", applies: true }]; }
  const keyCerts = I.certs.filter(c => c.key);
  const mk = A.masked;
  if (mk && mk.count) add({ id: "masked", sev: "bad", title: "Secrets are masked in this file", count: mk.count, applies: true, text: mk.count + " value(s) are shown as ******** (" + Object.entries(mk.fields).map(([k, v]) => k + " ×" + v).join(", ") + "). Tech-support files hide secrets, so the config in this file cannot carry them." + (mk.admins.length ? " Local admins with a masked password hash: " + mk.admins.join(", ") + "." : ""), action: "Do the real conversion from a config exported from the firewall (Device > Setup > Operations > Export named configuration snapshot), not from the tech-support file. This planner can load that file on the Convert tab and keep your port mapping." });
  add({ id: "certs", title: "Certificates and private keys", count: keyCerts.length || I.certs.length, applies: I.certs.length > 0, text: I.certs.length + " certificate(s) in the config" + (keyCerts.length ? ", " + keyCerts.length + " with a private key (the rest are certificates without a key, such as trusted CAs)" : " (none with a private key)") + (I.certs.length ? " (" + I.certs.slice(0, 6).map(c => c.name).join(", ") + (I.certs.length > 6 ? ", …" : "") + ")" : "") + ". Private keys are encrypted with the master key and some (device certificates, hardware-bound or HSM keys) cannot be exported.", action: "Export each certificate with its private key from the old firewall (Device > Certificate Management > Certificates) and import it on the new one. Check expiry and the portal, SSL decryption and management certificates." });
  add({ id: "masterkey", title: "Master key", applies: true, text: "The master key is not part of the exported config. Encrypted values (keys, passwords, shared secrets) only load if the new firewall uses the same master key.", action: "On the old firewall check Device > Master Key and Diagnostics. Set the same master key on the new firewall before importing the config, or re-enter the secrets afterwards." });
  const sec = Object.entries(I.secrets); const nSec = sec.reduce((n, [, v]) => n + v, 0);
  add({ id: "secrets", title: "Encrypted secrets (PSKs, RADIUS/TACACS+/LDAP secrets, SNMPv3, passwords)", count: nSec, applies: nSec > 0, text: nSec + " encrypted value(s)" + (nSec ? ": " + sec.map(([k, v]) => k + " ×" + v).join(", ") : "") + "." + (A.masked && A.masked.count ? " Another " + A.masked.count + " value(s) are masked (********) in this file; see the masked-secrets item above." : ""), action: "They move only with a matching master key. Without it, re-enter each secret and test the service. The tool never reads or shows their values." });
  const sp = I.serverProfiles, nsp = sp.radius + sp.tacplus + sp.ldap + sp.kerberos + sp.saml;
  add({ id: "auth", title: "Authentication servers", count: nsp, applies: nsp > 0, text: "Server profiles in the config: RADIUS " + sp.radius + ", TACACS+ " + sp.tacplus + ", LDAP " + sp.ldap + ", Kerberos " + sp.kerberos + ", SAML " + sp.saml + ". The servers see a new source IP and may only allow the old firewall's address.", action: "Allow the new firewall's management/service-route IPs on the servers, then test an admin login. Keep the break-glass local admin until the test works." });
  add({ id: "psk", title: "VPN peers (IKE pre-shared keys)", count: I.psk, applies: I.ipsecTunnels > 0 || I.ikeGateways > 0, text: I.ikeGateways + " IKE gateway(s), " + I.ipsecTunnels + " IPsec tunnel(s). The tunnels come up from the new firewall's interface IPs; the remote peers may be locked to the old serial's or old public IP's identity.", action: "Tell each remote party if the public IP or peer ID changes, and check the pre-shared keys loaded (master key). Existing SAs do not carry over; expect a short outage while tunnels renegotiate." });
  const ua = I.userId.agents + I.userId.tsAgents;
  add({ id: "userid", title: "User-ID agents and mappings", count: ua, applies: ua > 0 || I.userId.serverMonitor > 0 || I.userId.groupMapping > 0, text: "User-ID agents " + I.userId.agents + ", Terminal Server agents " + I.userId.tsAgents + ", server monitors " + I.userId.serverMonitor + ", group mappings " + I.userId.groupMapping + ". Agents pair with a firewall serial or IP; the live IP-to-user mappings do not move.", action: "Add the new firewall (or its IP) to each User-ID agent and Terminal Server agent, open the firewall rules on the domain controllers, and check the mappings after cutover." });
  add({ id: "content", title: "Content and software versions", applies: true, text: "App/threat" + (A.system && A.system.appVersion ? " (" + A.system.appVersion + ")" : "") + ", antivirus, WildFire, URL/DNS databases, GlobalProtect client packages and plugins are not in the config.", action: "Install the same or newer content versions, plugins and GlobalProtect packages on the new firewall before commit. Without a valid license the dynamic updates fail." });
  add({ id: "licenses", title: "Licenses", applies: true, text: "License keys are tied to the serial number and are not in the config.", action: "Activate licenses on the new serial (Device > Licenses) before commit, so subscription-based features validate." });
  add({ id: "sessions", title: "Sessions, ARP/MAC, routing adjacencies", applies: true, text: "Live sessions, ARP/MAC tables, DHCP leases, IPsec SAs and routing neighbors do not move. Interface MAC addresses change, so upstream devices hold stale ARP entries.", action: "Plan a short outage. Clear ARP/MAC on the neighbors after cutover (see the runbook)." });
  add({ id: "logs", title: "Logs, reports and ACC data", applies: true, text: "Local traffic, threat and system logs, and report history stay on the old firewall" + (I.syslog ? "; " + I.syslog + " syslog server profile(s) are in the config and will keep forwarding from the new one" : "") + ".", action: "Export or keep the old firewall's logs if you need them. Check log forwarding to the collector or Panorama after cutover." });
  add({ id: "edl", title: "External dynamic lists and caches", count: I.edl, applies: I.edl > 0, text: I.edl + " external dynamic list(s). Cached entries are fetched again after commit.", action: "Make sure the new firewall can reach the list servers (service route, proxy, DNS) or the lists stay empty and rules that use them stop matching." });
  add({ id: "snmp", title: "SNMP engine ID and monitoring", applies: I.snmpV3, text: "SNMPv3 is configured. The engine ID differs on new hardware, so monitoring systems must re-learn it.", action: "Update the SNMPv3 user/engine in the monitoring tool." });
  add({ id: "api", title: "API keys and automation", applies: true, sev: "info", text: "API keys are per firewall and are not in the config.", action: "Generate new keys and update scripts, Panorama-independent automation and monitoring." });
  add({ id: "pano", title: "Panorama registration", applies: !!(A.config && A.config.panorama), text: "Panorama knows the firewall by serial number. The new serial is a new device to Panorama.", action: "See Panorama guidance below: add the serial, assign the device group and template stack, then push." });
  return rows;
}
PPU.wontMigrate = wontMigrate;

function panoramaGuidance(A, target, R, ctx) {
  const c = A.config; const managed = !!(c && c.panorama) || !!(A.panoramaStatus && A.panoramaStatus.servers && A.panoramaStatus.servers.length);
  const out = { managed, steps: [], notes: [] };
  if (!managed) return out;
  const map = (ctx && ctx.map) || {};
  const renames = Object.entries(map).filter(([s2, t2]) => t2 && t2 !== s2);
  out.steps = [
    "Add the new serial number in Panorama (Panorama > Managed Devices > Summary > Add) or let the firewall register with its Panorama server entry. For an HA pair add both serials.",
    "Assign the new firewall to the same device group and template stack as the old one" + (R && R.ha ? " (both peers)" : "") + ". For a pair, keep the HA pair setting in the template or on the device.",
    "Check the template and device group for anything tied to the old model: interface names, HA ports, port speeds, VM-specific settings." + (renames.length ? " " + renames.length + " interface(s) get a new name in this plan (" + renames.slice(0, 5).map(([s2, t2]) => s2 + " → " + t2).join(", ") + (renames.length > 5 ? ", …" : "") + "); fix them in the template too." : ""),
    "Import or load the local config on the new firewall (this tool's XML covers the local config only), then register it to Panorama.",
    "Commit on Panorama, then Push to Devices: push the Templates first, then the Device Group (or use Commit and Push All Changes). Use Validate before pushing.",
    "Confirm the firewall shows Connected and In Sync, then move it to production. Remove the old serial from Panorama after the retention period."];
  out.notes.push("Local vs pushed config: this tool converts the firewall's own saved config. Objects, rules and network settings pushed from Panorama (templates, device groups, shared) live on Panorama and are not changed. " + (A.pushedConfig ? "This file contains the pushed (merged) config; it is not converted." : "This file does not include the pushed config."));
  out.notes.push("Panorama must run the same or a later PAN-OS version than the firewall (see the version check). A Panorama-managed firewall validates the merged config, so ports used by the template can clash with local interfaces (\"already in use\").");
  out.notes.push("Do not make local config changes on a Panorama-managed firewall that Panorama also manages; they are overwritten or flagged at the next push.");
  if (c && c.panorama && c.panorama.servers.length) out.notes.push("Panorama server(s) in the config: " + c.panorama.servers.join(", ") + ". The new firewall must reach them on TCP 3978 (management) from its management or service-route IP.");
  return out;
}
PPU.panoramaGuidance = panoramaGuidance;

function featureFlags(A, target, R) {
  const I = A.inventory, out = [];
  if (!target) return out;
  const add = (sev, feature, text, refs) => out.push({ sev, feature, text, refs: refs || [] });
  const vm = target.form === "vm";
  if (I && I.ae && vm) add("warn", "Aggregate Ethernet / LACP (" + I.ae + " group(s))", "VM-Series documents LACP with aggregate groups for ESXi and KVM. For other hypervisors and clouds, check the VM-Series docs for your platform. Plan vNIC-to-port-group mapping and the virtual switch settings (LACP passthrough).", ["vm_lacp"]);
  if (I && I.jumbo) add(vm ? "warn" : "info", "Jumbo frames", vm ? "Jumbo frames are enabled in the config. On VM-Series it is a global setting that needs a reboot, and multi-NUMA instances fall back to packet MMAP mode (not DPDK) while it is on. Check the hypervisor vSwitch and physical MTU." : "Jumbo frames are enabled in the config; it is a global setting that needs a reboot after the change. Check MTU on the switches.", ["vm_jumbo"]);
  if (I && I.decryptMirror.length) add(vm ? "bad" : "info", "Decryption port mirror (" + I.decryptMirror.join(", ") + ")", vm ? "Decrypt Mirror is not available on VM-Series for GCP, VMware NSX and Citrix SDX, and on AWS/Azure only from 11.2.12 / 12.1.8. The interface type must be changed or removed." : "Decrypt Mirror interfaces need a decrypt-mirror license and a port on the new model that can be used for it.", ["decrypt_mirror"]);
  if (I && I.logCard.length && target.family !== "PA-7000") add("bad", "Log card interface (" + I.logCard.join(", ") + ")", "The Log Card interface type exists only on PA-7000 Series. It must be changed to another interface type.", []);
  if (A.config) { const poe = A.config.interfaces.filter(i => i.poe).length; if (poe) { const has = target.ports && Array.isArray(target.ports) && target.ports.some(p => p.poe); add(has ? "info" : "warn", "PoE on " + poe + " interface(s)", has ? "The new model has PoE ports. Check the PoE budget and which ports supply power." : "The config enables PoE on " + poe + " interface(s). The catalog does not show PoE ports on " + target.model + "; check the datasheet.", []); } }
  if (vm && R && R.ha) add("info", "High availability on VM-Series", "VM-Series has no dedicated HA ports: HA1, HA2 and HA3 use data vNICs. Both VMs need the same virtual-network layout; some clouds limit HA options.", []);
  if (target.vsys_note && A.vsysInUse > 1) add("warn", "Virtual systems", target.vsys_note, []);
  if (I && A.config && A.config.features.advancedRouting && target.min_panos && cmpVer(majorMinor(target.min_panos), "11.0") < 0) add("warn", "Advanced routing", "The config uses the Advanced Routing Engine (PAN-OS 11.0+). Run 11.0 or later on the new firewall.", []);
  else if (A.config && A.config.features.advancedRouting) add("warn", "Advanced routing", "The config uses the Advanced Routing Engine (PAN-OS 11.0+). Run 11.0 or later on the new firewall.", []);
  if (A.config && A.config.features.sdwan) add("info", "SD-WAN", "SD-WAN needs the SD-WAN license on the new firewall and a supported PAN-OS release.", []);
  out.push({ sev: "info", feature: "Features not listed here", text: "Hardware offload, per-model feature limits and platform-specific features are not published in the sources the catalog uses. Check the product comparison tool for your target model.", refs: ["pc_tool"] });
  return out;
}
PPU.featureFlags = featureFlags;

function capacityCheck(A, target, R) {
  const I = A.inventory, rows = [];
  if (!target) return rows;
  const L = target.limits || {};
  const vmL = target.form === "vm" ? { rules: target.rules, zones: target.zones, s2s: target.ipsec_tunnels, gp: target.ssl_tunnels } : {};
  const lim = k => (L[k] != null ? L[k] : vmL[k] != null ? vmL[k] : null);
  const srcs = target.limits_src || (target.form === "vm" ? ["vm_models"] : []);
  const add = (label, used, k, note) => {
    const limit = lim(k);
    let st = "unknown";
    if (used == null) st = "unknown"; else if (limit == null) st = "unknown"; else if (used > limit) st = "over"; else if (used > limit * 0.8) st = "warn"; else st = "ok";
    rows.push({ key: k, label, used, limit, status: st, note: note || (limit == null ? "Limit not in the sources used. Check the product comparison tool." : null), srcs });
  };
  if (!I) return rows;
  add("Security rules", I.rules, "rules"); add("NAT rules", I.nat, "nat"); add("Decryption rules", I.decrypt, "decrypt"); add("Security zones", I.zones, "zones");
  add("Address objects", I.addr, "addr"); add("Address groups", I.addrgrp, "addrgrp"); add("Service objects", I.svc, "svc");
  add("IPsec tunnels (configured)", I.ipsecTunnels, "s2s", "Counts tunnel interfaces in the config. Tunnels with several proxy IDs count more.");
  add("IKE gateways (peers)", I.ikeGateways, "ike");
  add("GlobalProtect client tunnels", null, "gp", "Users are not in the config. Compare the limit with the peak GlobalProtect user count on the old firewall (" + I.gpPortals + " portal(s), " + I.gpGateways + " gateway(s) configured).");
  add("IPv4 routes (static only)", I.staticRoutes, "fib4", I.bgp || I.ospf || I.rip ? "Dynamic routing is on (" + [I.bgp && "BGP", I.ospf && "OSPF", I.rip && "RIP"].filter(Boolean).join(", ") + "): the routes learned are not in the config. Check show routing summary on the old firewall for the real count." : null);
  const vu = A.vsysInUse || 1;
  rows.push({ key: "vsys", label: "Virtual systems", used: vu, limit: target.vsys_max || null, status: target.vsys_max == null ? "unknown" : vu > target.vsys_max ? "over" : "ok", note: target.vsys_base != null ? "Base " + target.vsys_base + (target.vsys_max ? ", up to " + target.vsys_max + " with licenses" : "") + (vu > target.vsys_base ? "; extra virtual systems need a license." : ".") : null, srcs: target.sources ? ["summary"] : [] });
  return rows;
}
PPU.capacityCheck = capacityCheck;

function rackPower(A, target, R, srcModel) {
  if (!target) return null;
  const units = R && R.ha ? 2 : 1;
  if (target.form === "vm") return { vm: true };
  const r = target.rack || null, p = target.psu || null, s0 = srcModel && srcModel.rack || null;
  const out = { vm: false, units, rack: r, psu: p, src: s0, notes: [], totals: {} };
  if (!r) { out.notes.push("Rack facts for " + target.model + " are not in the catalog sources. Check the datasheet."); return out; }
  out.totals = { ru: r.ru ? r.ru * units : null, maxW: r.max_w ? r.max_w * units : null, btu: r.btu_hr ? r.btu_hr * units : null };
  if (!r.ru) out.notes.push(r.mount || "Not a standard 19-inch rack unit.");
  if (s0 && r.ru && s0.ru && r.ru !== s0.ru) out.notes.push("Rack height changes: " + s0.ru + "U → " + r.ru + "U. Check the rack space and the rails.");
  if (s0 && r.airflow && s0.airflow && r.airflow !== s0.airflow) out.notes.push("Airflow direction differs: " + s0.airflow + " → " + r.airflow + ". Check hot/cold aisle orientation.");
  if (r.ru && r.dims) out.notes.push("Rail kit and mounting hardware are not in the sources; confirm on the quote. Check rack depth against " + r.dims.split(" x ")[1] + ".");
  if (p && p.cord) out.notes.push("Power inlet: " + p.cord + (p.watts ? "; " + p.watts + " W per " + (p.kind === "adapter" ? "adapter" : "supply") : "") + ".");
  if (p && p.feed && /DC/.test(p.feed)) out.notes.push("DC power supplies need DC feed and cabling; AC and DC supplies cannot be mixed.");
  if (!p) out.notes.push("Power supply details are not in the catalog.");
  return out;
}
PPU.rackPower = rackPower;

/* ============================ cutover runbook, plan file ============================ */
function buildRunbook(c) {
  const A = c.A, t = c.target, R = c.R || {}, ha = !!R.ha, hp = c.hardware, L = [];
  const sv = sourceVersion(A), srcM = A.system && A.system.model, host = (A.system && A.system.hostname) || "the old firewall";
  const h = (n, x) => L.push("\n" + "#".repeat(n) + " " + x + "\n");
  const li = x => L.push("- " + x);
  const ck = x => L.push("- [ ] " + x);
  L.push("# Cutover runbook: " + (srcM || "old firewall") + " → " + (t ? t.model : "new firewall"));
  L.push("\nPrepared " + (c.date || "") + " by PAN Physical Upgrade Planner. Old firewall: " + host + (sv ? ", PAN-OS " + sv : "") + (ha ? ", HA pair" : ", standalone") + ". New: " + (t ? t.model : "?") + (ha ? " ×2 (HA pair)" : "") + ". Edit this list for your change process.");
  h(2, "1. Before the window");
  ck("Change approved; window agreed; users and the service desk told. Cutover causes a short outage: sessions, VPNs and routing adjacencies restart.");
  ck("Export the old firewall's config and a tech-support file now (Device > Setup > Operations > Export named configuration snapshot).");
  ck("Write down the old firewall's counters: `show session info`, `show vpn ipsec-sa`, `show routing summary`, `show high-availability state`, GlobalProtect users. You will compare after cutover.");
  if (c.version) for (const v of c.version.filter(v => v.id === "install" || v.id === "min" || v.id === "ha" || v.id === "pano")) ck(v.title + ". " + v.text);
  if (hp && !hp.vm) {
    ck("New hardware racked and powered: " + (hp.power && hp.power.cords != null ? hp.power.cords + " power cord(s)" : "power cords") + (hp.power && hp.power.optionalPerUnit ? ", " + hp.power.optionalPerUnit * hp.units + " extra power supply(ies) installed" : "") + ".");
    for (const g of hp.groups) if (g.qty) ck(g.qty + " × " + (g.kind === "optic" ? g.form + " optic (" + g.type + ")" : g.type) + " on hand (" + (g.use === "ha" ? "HA links" : "data ports") + ").");
    const ch = hp.ports.filter(r => r.flags.length);
    for (const r of ch) ck("Port " + r.src + " → " + r.tgt + ": " + r.flags.join(" "));
    for (const r of hp.ha) ck("HA link " + r.label + " (" + r.srcPort + " → " + r.tgtPort + "): " + (r.cableText || "") + ((r.flags || []).length ? " " + r.flags.join(" ") : ""));
  }
  const wm = (c.wont || []).filter(w => w.applies);
  ck("Master key on the new firewall set to match the old one (so encrypted secrets and certificate keys load).");
  for (const w of wm.filter(w => ["masked", "auth", "userid", "psk"].includes(w.id))) ck(w.title + ": " + w.action);
  ck("Licenses activated on the new serial(s); content, plugins and PAN-OS installed to the versions above.");
  if (c.custom && c.custom.adminName) ck("Break-glass admin \"" + c.custom.adminName + "\" password stored in the password manager. Test it on the new firewall before cutover.");
  h(2, "2. Import and validate (new firewall, off the production network)");
  li("Install the target PAN-OS. Device > Setup > Operations > Import named configuration snapshot, then Load named configuration snapshot (this only changes the candidate).");
  li("Commit > Validate Commit (CLI `validate full`). Fix everything it lists; nothing is committed yet.");
  li("Fix the items under \"Fix before you commit\" in the tool. Check the SECRET rows of the change log.");
  if (c.custom && c.custom.mgmtChanged) li("The management IP was changed so the new firewall can sit next to production: " + c.custom.mgmtIp + ". Review the old-IP warnings in the tool.");
  li("Commit. Check Dashboard, `show system info`, interface status, license state.");
  if (ha) li("Form HA: set peer IPs, device priority, preemption and link/path monitoring on both new firewalls. Wait for `show high-availability state` to show active/passive and config synced.");
  const pg = c.panorama;
  if (pg && pg.managed) { h(3, "Panorama-managed"); pg.steps.forEach((x, i) => L.push((i + 1) + ". " + x)); }
  h(2, "3. Cutover");
  li("Hold the old firewall" + (ha ? "s" : "") + " powered on and unchanged. Label every cable first.");
  if (ha) {
    li("HA failover order: make the OLD passive unit suspend first (`request high-availability state suspend`), so the old active carries traffic alone. Then move cables for one side: disconnect the old active's data ports last.");
    li("Connect the NEW active firewall's data cables first, then confirm it is active and passing traffic. Then connect the NEW passive firewall's data cables and check path/link monitors are green. Do one planned failover to prove the passive takes over, then set it back.");
  } else li("Move the data cables from the old firewall to the new one, one interface at a time, in the order you agreed (internet last if you want to test inside first).");
  li("Upstream and downstream devices still hold the old ARP/MAC entries (the interface MAC addresses changed). Clear ARP and MAC tables on the adjacent switches and routers for the firewall's IPs. The firewall sends gratuitous ARP when interfaces come up; clear the tables if neighbors still point at the old box.");
  li("If a link changed speed or media (see the hardware list), set the other end to match and confirm link up.");
  li("Watch: `show interface all`, `show session info`, `show counter global filter delta yes severity drop`.");
  h(2, "4. Post-checks (compare with the numbers you wrote down)");
  ck("Sessions: `show session info` count and new-session rate in the expected range after 15 to 30 minutes.");
  ck("Routing: `show routing summary`, `show routing route`" + (c.inventory && c.inventory.bgp ? ", `show routing protocol bgp summary`" : "") + (c.inventory && c.inventory.ospf ? ", `show routing protocol ospf neighbor`" : "") + ". Default route and key routes present.");
  ck("VPN tunnels: `show vpn ike-sa`, `show vpn ipsec-sa`. Every tunnel from the old list is up" + (c.inventory ? " (" + c.inventory.ipsecTunnels + " configured)" : "") + ".");
  if (c.inventory && (c.inventory.gpPortals || c.inventory.gpGateways)) ck("GlobalProtect: `show global-protect-gateway current-user`; test a client login and the portal certificate.");
  ck("HA: `show high-availability state` on both units; failover test done; config in sync.");
  ck("Management: Panorama connected (`show panorama-status`), NTP and DNS working, log forwarding reaching the collector, SNMP polled, external admin login and break-glass login tested.");
  ck("Users: spot-check key applications; User-ID mappings repopulating (`show user ip-user-mapping all | match <ip>`).");
  ck("Licenses and content: `request license info`; latest content installed.");
  h(2, "5. Rollback");
  li("Keep the old firewall" + (ha ? "s" : "") + " powered, cabled-label ready and not decommissioned for at least a week. Do not wipe them.");
  li("To roll back: disconnect the new firewall's data cables, reconnect the old ones (reverse order), clear ARP/MAC on neighbors again, and confirm sessions and VPNs on the old firewall.");
  li("If only the config is wrong on the new firewall, load the previous saved config (Device > Setup > Operations > Load config version) and commit.");
  li("Decide the rollback point (time limit and failure criteria) with the owner before the window starts.");
  if (c.wont && c.wont.length) { h(2, "6. Things that did not move"); for (const w of wm) li("**" + w.title + "**: " + w.text + " Action: " + w.action); }
  return L.join("\n") + "\n";
}
PPU.buildRunbook = buildRunbook;

const PLAN_KEYS = { targetName: "string", ha: "boolean", opts: "object", overrides: "object", map: "object", haPortMap: "object", convMode: "string", hw: "object", lic: "object", customPorts: "object" };
function planToJson(st, A) {
  const cu = st.custom || {};
  const plan = { schema: 1, tool: "PAN Physical Upgrade Planner", saved: new Date().toISOString().slice(0, 10),
    source: { model: A && A.system ? A.system.model : null, interfaces: A && A.config && A.config.interfaces ? A.config.interfaces.length : null },
    plan: {} };
  for (const k of Object.keys(PLAN_KEYS)) if (st[k] !== undefined) plan.plan[k] = JSON.parse(JSON.stringify(st[k]));
  // custom conversion settings, never any secret: only whether an admin is wanted, its name and role
  plan.plan.custom = { host: cu.host || "", ip: cu.ip || "", mask: cu.mask || "", gw: cu.gw || "", dns1: cu.dns1 || "", dns2: cu.dns2 || "", ipv6: cu.ipv6 || "", ipv6gw: cu.ipv6gw || "", removePanorama: !!cu.removePanorama, adminOn: !!cu.adminOn, adminName: cu.adminName || "", adminRole: cu.adminRole === "superreader" ? "superreader" : "superuser" };
  return JSON.stringify(plan, null, 1) + "\n";
}
function planFromJson(text, A) {
  let o; try { o = JSON.parse(text); } catch (e) { throw new Error("This is not a plan file (not valid JSON)."); }
  if (!o || o.schema !== 1 || !o.plan || typeof o.plan !== "object") throw new Error("This is not a plan file from this tool (schema 1).");
  if (/\$[156]\$|phash|password/i.test(JSON.stringify(o))) throw new Error("Refusing to load: the plan file contains something that looks like a password or hash.");
  const warnings = [];
  if (o.source && o.source.model && A && A.system && A.system.model && o.source.model !== A.system.model) warnings.push("The plan was saved for a " + o.source.model + " but the loaded file is a " + A.system.model + ". Interface mappings may not fit.");
  const out = {};
  for (const [k, ty] of Object.entries(PLAN_KEYS)) if (o.plan[k] !== undefined && (ty === "object" ? (o.plan[k] === null || typeof o.plan[k] === "object") : typeof o.plan[k] === ty)) out[k] = o.plan[k];
  if (o.plan.custom && typeof o.plan.custom === "object") { const c = o.plan.custom; out.custom = { host: String(c.host || ""), ip: String(c.ip || ""), mask: String(c.mask || ""), gw: String(c.gw || ""), dns1: String(c.dns1 || ""), dns2: String(c.dns2 || ""), ipv6: String(c.ipv6 || ""), ipv6gw: String(c.ipv6gw || ""), removePanorama: !!c.removePanorama, adminOn: !!c.adminOn, adminName: String(c.adminName || ""), adminRole: c.adminRole === "superreader" ? "superreader" : "superuser" }; }
  return { state: out, warnings, savedOn: o.saved || null };
}
PPU.planToJson = planToJson; PPU.planFromJson = planFromJson;

/* ============================ license review ============================ */
const SUB_OFFERS = ["Advanced Threat Prevention", "Advanced URL Filtering", "Advanced WildFire", "Advanced DNS Security", "SD-WAN", "GlobalProtect", "IoT Security", "Enterprise DLP", "SaaS Security"];
const SUPPORT_TIERS = ["Standard", "Premium", "Platinum"];
function licenseUse(name, A) {
  const c = A.config, U = c && c.usage;
  const unk = (h) => ({ use: "unknown", hint: h });
  if (!c) return unk("No config in this file, so use can't be checked.");
  const att = t => (U.attached[t] || 0) > 0, have = t => (U.profiles[t] || 0) > 0;
  const prof = (t, label) => att(t) ? { use: "in-use", hint: label + " profile is attached to " + U.attached[t] + " rule(s)." } : have(t) ? { use: "not-seen", hint: label + " profile exists but no security rule uses it." } : { use: "not-seen", hint: "No " + label + " profile in the config." };
  switch (name) {
    case "GlobalProtect": return c.features.globalProtect ? { use: "in-use", hint: c.counts.gpPortals + " portal(s), " + c.counts.gpGateways + " gateway(s) configured." } : { use: "not-seen", hint: "No GlobalProtect portal or gateway in the config." };
    case "URL Filtering": case "Advanced URL Filtering": return prof("url-filtering", "URL filtering");
    case "WildFire": case "Advanced WildFire": return prof("wildfire-analysis", "WildFire analysis");
    case "Threat Prevention": case "Advanced Threat Prevention": {
      const t = ["virus", "spyware", "vulnerability"].filter(att);
      return t.length ? { use: "in-use", hint: "Attached to rules: " + t.join(", ") + "." } : ["virus", "spyware", "vulnerability"].some(have) ? { use: "not-seen", hint: "Threat profiles exist but no security rule uses them." } : { use: "not-seen", hint: "No antivirus, anti-spyware or vulnerability profiles in the config." };
    }
    case "DNS Security": case "Advanced DNS Security": return U.dns ? { use: "in-use", hint: "An anti-spyware profile has DNS Security lists." } : { use: "not-seen", hint: "No DNS Security lists in any anti-spyware profile." };
    case "SD-WAN": return c.features.sdwan ? { use: "in-use", hint: "SD-WAN interface profiles are configured." } : { use: "not-seen", hint: "No SD-WAN configuration." };
    case "Enterprise DLP": return U.dlp ? { use: "in-use", hint: "Data filtering profiles or data objects are configured." } : { use: "not-seen", hint: "No data filtering profile or data object." };
    case "Virtual Systems": return (A.vsysInUse || 1) > 1 ? { use: "in-use", hint: A.vsysInUse + " virtual systems configured." } : { use: "not-seen", hint: "Only one virtual system configured." };
    default: return unk("Use can't be seen from the config.");
  }
}
function licenseReview(A, target, R, state) {
  const st = state || {};
  const LP = licensePlan(A, target, R);
  const units = LP.qty;
  const seen = new Map();
  for (const l of LP.today) { const p = seen.get(l.name); if (!p || (p.expired && !l.expired)) seen.set(l.name, l); }
  const current = [];
  for (const [name, l] of seen) {
    if (name === "VM-Series capacity") continue;
    const u = licenseUse(name, A);
    const row = { name, feature: l.feature, expires: l.expires, expired: l.expired, status: l.expired ? "expired" : "active", use: u.use, hint: u.hint, special: name === "Virtual Systems" ? "vsys" : null };
    row.defaultKeep = !l.expired && name !== "Virtual Systems";
    row.keep = row.special ? false : (st.keep && name in st.keep ? !!st.keep[name] : row.defaultKeep);
    row.qty = st.qty && st.qty["cur:" + name] != null ? st.qty["cur:" + name] : units;
    current.push(row);
  }
  const heldActive = new Set(current.filter(r => !r.expired).map(r => r.name));
  const offers = [];
  for (const name of SUB_OFFERS) {
    const held = heldActive.has(name);
    const oRow = { name, held, on: !!(st.add && st.add[name]), qty: st.qty && st.qty["add:" + name] != null ? st.qty["add:" + name] : units, note: null };
    if (name.startsWith("Advanced ")) { const base = name.replace("Advanced ", ""); if (heldActive.has(base)) oRow.note = "You have " + base + " today. Ask your account team whether you need both."; }
    if (name === "GlobalProtect" && target && target.form === "vm") oRow.note = "VM-Series uses Software NGFW credits for subscriptions; the same service names apply.";
    offers.push(oRow);
  }
  const needVsys = LP.vsys && LP.vsys.extra > 0 ? LP.vsys : null;
  const support = { options: SUPPORT_TIERS, tier: st.supportTier || "", on: !!st.supportOn, qty: st.qty && st.qty["add:Support"] != null ? st.qty["add:Support"] : units };
  const vsysAdd = { extra: st.vsysExtra != null ? st.vsysExtra : (needVsys ? needVsys.extra : 0), required: needVsys ? needVsys.extra : 0, note: needVsys ? needVsys.note : null };
  const finalItems = [];
  for (const r of current) if (r.keep) finalItems.push({ name: r.name, qty: r.qty, source: "carry", note: (r.expired ? "expired " : "renews ") + r.expires });
  for (const r of offers) if (r.on) finalItems.push({ name: r.name, qty: r.qty, source: "add", note: "added by engineer" });
  if (support.on) finalItems.push({ name: "Support" + (support.tier ? " (" + support.tier + ")" : " (tier to be chosen)"), qty: support.qty, source: "add", note: "added by engineer" });
  if (vsysAdd.extra > 0) finalItems.push({ name: "Virtual Systems license (+" + vsysAdd.extra + ")", qty: units, source: vsysAdd.required ? "required" : "add", note: vsysAdd.note || "added by engineer" });
  const dropped = current.filter(r => !r.keep && r.special !== "vsys").map(r => ({ name: r.name, expired: r.expired, use: r.use, byEngineer: !r.expired && r.defaultKeep }));
  return { plan: LP, units, current, offers, support, vsys: vsysAdd, finalItems, dropped };
}
PPU.licenseReview = licenseReview;

if (typeof module !== "undefined" && module.exports) module.exports = PPU;
else root.PPU = PPU;
})(typeof self !== "undefined" ? self : this);
