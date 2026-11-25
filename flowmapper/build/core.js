/* PAN-OS FlowMapper core: XML parsing, config model, route/NAT/policy trace.
 * Pure JS, no DOM, no network. Runs in the browser and in Node (tests). */
(function (root) {
"use strict";

/* ------------------------------------------------------------------ XML */
const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
function decodeEnt(s) {
  if (s.indexOf("&") < 0) return s;
  return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (m, e) => {
    if (e[0] === "#") {
      const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return isFinite(n) ? String.fromCodePoint(n) : m;
    }
    return ENT[e] != null ? ENT[e] : m;
  });
}
function parseXml(s) { const P = xmlParser(s); P.run(Infinity); return P.doc; }
/* Time-sliced parse so the page never freezes on large exports. */
async function parseXmlAsync(s, onProgress, sliceMs) {
  const P = xmlParser(s);
  while (!P.run(sliceMs || 40)) { if (onProgress) onProgress(P.pos() / s.length); await new Promise((r) => setTimeout(r, 0)); }
  return P.doc;
}
function xmlParser(s) {
  const doc = { t: "#doc", a: {}, c: [], x: "", p: null };
  const stack = [doc];
  const n = s.length;
  let i = 0;
  const attrRe = /([^\s=\/]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  const now = typeof performance !== "undefined" ? () => performance.now() : () => Date.now();
  function run(budget) {
  const t0 = budget === Infinity ? 0 : now();
  let k = 0;
  while (i < n) {
    if (budget !== Infinity && (++k & 4095) === 0 && now() - t0 > budget) return false;
    const lt = s.indexOf("<", i);
    const cur = stack[stack.length - 1];
    if (lt < 0) break;
    if (lt > i) {
      const txt = s.slice(i, lt);
      if (/\S/.test(txt)) cur.x += decodeEnt(txt);
    }
    if (s.startsWith("<!--", lt)) { const e = s.indexOf("-->", lt + 4); i = e < 0 ? n : e + 3; continue; }
    if (s.startsWith("<![CDATA[", lt)) { const e = s.indexOf("]]>", lt + 9); cur.x += s.slice(lt + 9, e < 0 ? n : e); i = e < 0 ? n : e + 3; continue; }
    const c1 = s.charCodeAt(lt + 1);
    if (c1 === 63 /*?*/ || c1 === 33 /*!*/) { const e = s.indexOf(">", lt); i = e < 0 ? n : e + 1; continue; }
    if (c1 === 47 /*/*/) {
      const e = s.indexOf(">", lt);
      const tag = s.slice(lt + 2, e).trim();
      // pop to matching tag (tolerant)
      for (let k = stack.length - 1; k > 0; k--) { if (stack[k].t === tag) { stack.length = k; break; } }
      i = e < 0 ? n : e + 1; continue;
    }
    let j = lt + 1, q = 0;
    while (j < n) {
      const ch = s.charCodeAt(j);
      if (q) { if (ch === q) q = 0; } else if (ch === 34 || ch === 39) q = ch; else if (ch === 62) break;
      j++;
    }
    let body = s.slice(lt + 1, j);
    let self = false;
    if (body.endsWith("/")) { self = true; body = body.slice(0, -1); }
    const sp = body.search(/\s/);
    const tag = sp < 0 ? body : body.slice(0, sp);
    const node = { t: tag, a: {}, c: [], x: "", p: cur };
    if (sp >= 0) {
      attrRe.lastIndex = 0; let m;
      const rest = body.slice(sp);
      while ((m = attrRe.exec(rest))) node.a[m[1]] = decodeEnt(m[2] != null ? m[2] : m[3]);
    }
    cur.c.push(node);
    if (!self) stack.push(node);
    i = j + 1;
  }
  i = n; return true;
  }
  return { doc, run, pos: () => i };
}
function ch(n, tag) { if (!n) return null; for (const c of n.c) if (c.t === tag) return c; return null; }
function chs(n, tag) { return n ? n.c.filter((c) => c.t === tag) : []; }
function at(n, path) { let cur = n; for (const p of path.split("/")) { if (!p) continue; cur = ch(cur, p); if (!cur) return null; } return cur; }
function entries(n) { return chs(n, "entry"); }
function entryMap(n) { const m = new Map(); for (const e of entries(n)) if (e.a.name != null) m.set(e.a.name, e); return m; }
function txt(n) { return n ? n.x.trim() : ""; }
function members(n) { if (!n) return []; const ms = chs(n, "member").map(txt).filter(Boolean); if (ms.length) return ms; const t = txt(n); return t ? [t] : []; }
function findEntry(n, name) { for (const e of entries(n)) if (e.a.name === name) return e; return null; }

/* Deep merge of template config nodes: hi wins, entries merged by name. */
function mergeNodes(hi, lo) {
  if (!hi) return lo; if (!lo) return hi;
  const out = { t: hi.t, a: Object.assign({}, lo.a, hi.a), c: [], x: hi.x || lo.x, p: null };
  if (hi.c.some((c) => c.t === "member")) { out.c = hi.c.slice(); return out; }
  const key = (c) => c.t + (c.a.name != null ? "\u0000" + c.a.name : "");
  const loMap = new Map(); for (const c of lo.c) loMap.set(key(c), c);
  const seen = new Set();
  for (const c of hi.c) { const k = key(c); seen.add(k); out.c.push(loMap.has(k) ? mergeNodes(c, loMap.get(k)) : c); }
  for (const c of lo.c) if (!seen.has(key(c))) out.c.push(c);
  return out;
}

/* ------------------------------------------------------------------ IPv4 */
function ip2n(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s).trim());
  if (!m) return null;
  const p = m.slice(1).map(Number); if (p.some((x) => x > 255)) return null;
  return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3];
}
function n2ip(n) { return [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256].join("."); }
function isV6(s) { return /:/.test(String(s)); }
/* Parse "a.b.c.d", "a.b.c.d/len", "a-b" -> {lo,hi,len,ip,text} */
function parsePrefix(s) {
  s = String(s || "").trim();
  if (!s) return null;
  let m = /^([\d.]+)\s*-\s*([\d.]+)$/.exec(s);
  if (m) { const lo = ip2n(m[1]), hi = ip2n(m[2]); if (lo == null || hi == null || hi < lo) return null; return { lo, hi, len: null, ip: lo, text: s }; }
  m = /^([\d.]+)(?:\/(\d{1,2}))?$/.exec(s);
  if (m) {
    const ip = ip2n(m[1]); if (ip == null) return null;
    let len = m[2] == null ? 32 : Number(m[2]); if (len > 32) return null;
    const size = Math.pow(2, 32 - len);
    const lo = Math.floor(ip / size) * size;
    return { lo, hi: lo + size - 1, len, ip, text: s };
  }
  m = /^([\d.]+)\/([\d.]+)$/.exec(s); // ip/netmask or wildcard
  if (m) {
    const ip = ip2n(m[1]), mk = ip2n(m[2]); if (ip == null || mk == null) return null;
    const bits = mk.toString(2).padStart(32, "0");
    if (/^1*0*$/.test(bits)) { const z = bits.indexOf("0"); return parsePrefix(m[1] + "/" + (z < 0 ? 32 : z)); }
  }
  return null;
}
function prefixStr(p) { if (!p) return "?"; if (p.len == null) return n2ip(p.lo) + "-" + n2ip(p.hi); return n2ip(p.lo) + "/" + p.len; }
function hostOrPrefix(p) { if (p.len === 32 || p.lo === p.hi) return n2ip(p.lo); return prefixStr(p); }
function rngContains(r, q) { return r.lo <= q.lo && r.hi >= q.hi; }
function rngOverlap(r, q) { return r.lo <= q.hi && q.lo <= r.hi; }
/* coverage of query q by list of ranges: 'full' | 'partial' | 'none' */
function coverage(ranges, q) {
  const ov = ranges.filter((r) => rngOverlap(r, q)).map((r) => [Math.max(r.lo, q.lo), Math.min(r.hi, q.hi)]).sort((a, b) => a[0] - b[0]);
  if (!ov.length) return "none";
  let pos = q.lo;
  for (const [lo, hi] of ov) { if (lo > pos) return "partial"; if (hi + 1 > pos) pos = hi + 1; if (pos > q.hi) return "full"; }
  return pos > q.hi ? "full" : "partial";
}

/* ------------------------------------------------------------------ ports/services */
function parsePorts(s) {
  const out = [];
  for (const part of String(s || "").split(",")) {
    const t = part.trim(); if (!t) continue;
    const m = /^(\d+)(?:\s*-\s*(\d+))?$/.exec(t); if (!m) continue;
    out.push([Number(m[1]), Number(m[2] || m[1])]);
  }
  return out;
}
const PREDEF_SERVICES = {
  "service-http": [{ proto: "tcp", ports: [[80, 80], [8080, 8080]] }],
  "service-https": [{ proto: "tcp", ports: [[443, 443]] }],
};
/* Default ports of common applications (subset of App-ID content). */
const APP_DEFAULTS = {
  "web-browsing": ["tcp/80"], "ssl": ["tcp/443"], "ssh": ["tcp/22"], "telnet": ["tcp/23"], "ftp": ["tcp/21"],
  "dns": ["tcp/53", "udp/53"], "dns-base": ["tcp/53", "udp/53"], "ntp": ["udp/123"], "ntp-base": ["udp/123"], "snmp": ["udp/161", "udp/162"],
  "snmpv3": ["udp/161", "udp/162"], "snmp-base": ["udp/161", "udp/162"], "syslog": ["udp/514", "tcp/514"],
  "smtp": ["tcp/25", "tcp/587"], "smtp-base": ["tcp/25", "tcp/587"], "pop3": ["tcp/110"], "imap": ["tcp/143"], "ldap": ["tcp/389", "udp/389"],
  "ms-rdp": ["tcp/3389", "udp/3389"], "msrpc": ["tcp/135"], "msrpc-base": ["tcp/135"], "ms-ds-smb": ["tcp/445", "tcp/139"], "ms-ds-smb-base": ["tcp/445", "tcp/139"],
  "mssql-db": ["tcp/1433"], "mssql-db-base": ["tcp/1433"], "mssql-mon": ["udp/1434"], "mysql": ["tcp/3306"], "oracle": ["tcp/1521"], "postgres": ["tcp/5432"],
  "kerberos": ["tcp/88", "udp/88"], "radius": ["udp/1812", "udp/1813", "udp/1645", "udp/1646"], "tacacs-plus": ["tcp/49"],
  "ike": ["udp/500", "udp/4500"], "ipsec-esp-udp": ["udp/4500"], "ping": ["icmp"], "icmp": ["icmp"], "traceroute": ["udp/33434-33534", "icmp"],
  "dhcp": ["udp/67", "udp/68"], "tftp": ["udp/69"], "netbios-ns": ["udp/137"], "netbios-dg": ["udp/138"], "netbios-ss": ["tcp/139"],
  "http-proxy": ["tcp/8080", "tcp/3128"], "panorama": ["tcp/3978", "tcp/28443"], "paloalto-updates": ["tcp/443"], "paloalto-wildfire-cloud": ["tcp/443"],
  "vnc": ["tcp/5900-5901"], "citrix": ["tcp/1494", "tcp/2598"], "sip": ["tcp/5060", "udp/5060"], "rtsp": ["tcp/554"], "nfs": ["tcp/2049", "udp/2049"],
  "ms-update": ["tcp/80", "tcp/443"], "windows-azure-base": ["tcp/443"], "ms-office365-base": ["tcp/443"], "google-base": ["tcp/443", "tcp/80"],
  "git": ["tcp/9418"], "bgp": ["tcp/179"], "ospf": ["ip/89"], "ssl-vpn": ["tcp/443"], "globalprotect": ["tcp/443", "udp/4501"], "winrm": ["tcp/5985", "tcp/5986"],
  "vmware": ["tcp/902", "tcp/443"], "ms-sms": ["tcp/2701"], "sccm": ["tcp/2701", "tcp/10123"], "ms-exchange": ["tcp/135", "tcp/443"],
};
function parseAppPorts(list) {
  const out = [];
  for (const s of list) {
    const m = /^(tcp|udp|sctp|icmp|ip)(?:\/(.+))?$/.exec(String(s).trim()); if (!m) continue;
    out.push({ proto: m[1], ports: m[2] && m[1] !== "ip" ? parsePorts(m[2]) : null });
  }
  return out;
}
function svcMatchesQuery(defs, q) {
  // defs: [{proto, ports:[[a,b]] | null}]; q: {proto, port}
  for (const d of defs) {
    if (q.proto === "any") return true;
    if (d.proto !== q.proto) continue;
    if (q.proto === "icmp" || !d.ports || q.port == null) return true;
    if (d.ports.some(([a, b]) => q.port >= a && q.port <= b)) return true;
  }
  return false;
}

/* ------------------------------------------------------------------ object scopes */
function readObjects(node, label) {
  // node: vsys entry, device-group entry, shared, or shared-gateway entry
  const o = { label, address: new Map(), addressGroup: new Map(), service: new Map(), serviceGroup: new Map(),
    appGroup: new Map(), appFilter: new Map(), app: new Map(), edl: new Set(), region: new Set() };
  if (!node) return o;
  for (const e of entries(ch(node, "address"))) {
    let type = null, val = null;
    for (const t of ["ip-netmask", "ip-range", "ip-wildcard", "fqdn"]) { const c = ch(e, t); if (c) { type = t; val = txt(c); break; } }
    o.address.set(e.a.name, { name: e.a.name, type, value: val, tags: members(ch(e, "tag")), desc: txt(ch(e, "description")) });
  }
  for (const e of entries(ch(node, "address-group"))) {
    const st = ch(e, "static"), dy = ch(e, "dynamic");
    o.addressGroup.set(e.a.name, { name: e.a.name, static: st ? members(st) : null, dynamic: dy ? txt(ch(dy, "filter")) : null, tags: members(ch(e, "tag")) });
  }
  for (const e of entries(ch(node, "service"))) {
    const p = ch(e, "protocol"); const defs = [];
    if (p) for (const pr of ["tcp", "udp", "sctp"]) { const c = ch(p, pr); if (c) defs.push({ proto: pr, ports: parsePorts(txt(ch(c, "port"))), srcPorts: txt(ch(c, "source-port")) || null }); }
    o.service.set(e.a.name, { name: e.a.name, defs });
  }
  for (const e of entries(ch(node, "service-group"))) o.serviceGroup.set(e.a.name, { name: e.a.name, members: members(ch(e, "members")) });
  for (const e of entries(ch(node, "application-group"))) o.appGroup.set(e.a.name, { name: e.a.name, members: members(ch(e, "members")).concat(members(e).length && !ch(e, "members") ? [] : []) });
  for (const e of entries(ch(node, "application-filter"))) o.appFilter.set(e.a.name, { name: e.a.name });
  for (const e of entries(ch(node, "application"))) {
    const d = at(e, "default/port"); o.app.set(e.a.name, { name: e.a.name, ports: d ? members(d) : [] });
  }
  for (const e of entries(ch(node, "external-list"))) o.edl.add(e.a.name);
  for (const e of entries(ch(node, "region"))) o.region.add(e.a.name);
  return o;
}
function lookupObj(scopes, kind, name) { for (const s of scopes) { const v = s[kind].get(name); if (v) return { v, scope: s.label }; } return null; }

/* Evaluate dynamic address-group filter like "'web' and ('prod' or 'dmz')" over a tag set. */
function evalTagFilter(filter, tags) {
  const toks = String(filter || "").match(/'[^']*'|"[^"]*"|\(|\)|\band\b|\bor\b|\bnot\b|[^\s()]+/gi) || [];
  let i = 0;
  function prim() {
    const t = toks[i++]; if (t == null) return false;
    if (t === "(") { const v = expr(); i++; return v; }
    if (/^not$/i.test(t)) return !prim();
    return tags.has(t.replace(/^['"]|['"]$/g, ""));
  }
  function andE() { let v = prim(); while (toks[i] && /^and$/i.test(toks[i])) { i++; const r = prim(); v = v && r; } return v; }
  function expr() { let v = andE(); while (toks[i] && /^or$/i.test(toks[i])) { i++; const r = andE(); v = v || r; } return v; }
  try { return expr(); } catch (e) { return false; }
}

/* Resolve address member list -> {any, ranges[], unresolved[], names[]} */
function resolveAddrs(list, scopes) {
  const res = { any: false, ranges: [], unresolved: [], v6: false };
  const seen = new Set();
  function add(name, depth) {
    if (name === "any") { res.any = true; return; }
    if (depth > 20 || seen.has(name)) return; seen.add(name);
    const a = lookupObj(scopes, "address", name);
    if (a) {
      const o = a.v;
      if (o.type === "fqdn") { res.unresolved.push({ name, why: "FQDN " + o.value + " (resolved by DNS at runtime)" }); return; }
      if (o.value && isV6(o.value)) { res.v6 = true; return; }
      if (o.type === "ip-wildcard") { res.unresolved.push({ name, why: "wildcard mask " + o.value + " (not evaluated)" }); return; }
      const p = parsePrefix(o.value);
      if (p) res.ranges.push(p); else res.unresolved.push({ name, why: "could not parse " + o.value });
      return;
    }
    const g = lookupObj(scopes, "addressGroup", name);
    if (g) {
      if (g.v.static) for (const m of g.v.static) add(m, depth + 1);
      if (g.v.dynamic != null) {
        res.unresolved.push({ name, why: "dynamic group (filter " + g.v.dynamic + "); members registered at runtime are not known", soft: true });
        for (const s of scopes) for (const [n, o] of s.address) if (evalTagFilter(g.v.dynamic, new Set(o.tags))) add(n, depth + 1);
      }
      return;
    }
    if (scopes.some((s) => s.edl.has(name))) { res.unresolved.push({ name, why: "external dynamic list (contents not in config)" }); return; }
    if (isV6(name)) { res.v6 = true; return; }
    const p = parsePrefix(name);
    if (p) { res.ranges.push(p); return; }
    if (/^[A-Z]{2}$/.test(name) || scopes.some((s) => s.region.has(name))) { res.unresolved.push({ name, why: "region/country (GeoIP at runtime)" }); return; }
    res.unresolved.push({ name, why: "object not found in config" });
  }
  for (const n of list) add(n, 0);
  return res;
}
function addrMatch(set, q, negate) {
  // returns {m:'yes'|'maybe'|'no', why}
  let cov = set.any ? "full" : coverage(set.ranges, q);
  const unk = set.unresolved.length > 0;
  if (negate) {
    if (set.any) return { m: "no" };
    if (cov === "none") return unk ? { m: "maybe", why: "negated set has unresolved members" } : { m: "yes" };
    if (cov === "full") return { m: "no" };
    return { m: "maybe", why: "query only partly excluded by negated set" };
  }
  if (cov === "full") return { m: "yes" };
  if (cov === "partial") return { m: "maybe", why: "only part of " + prefixStr(q) + " is covered" };
  if (unk) return { m: "maybe", why: "rule uses " + set.unresolved.map((u) => u.name + " [" + u.why + "]").join(", ") };
  return { m: "no" };
}

/* Resolve service member list -> {any, appDefault, defs[], unresolved[]} */
function resolveServices(list, scopes) {
  const res = { any: false, appDefault: false, defs: [], unresolved: [], srcPort: false };
  const seen = new Set();
  function add(name, d) {
    if (name === "any") { res.any = true; return; }
    if (name === "application-default") { res.appDefault = true; return; }
    if (d > 20 || seen.has(name)) return; seen.add(name);
    const s = lookupObj(scopes, "service", name);
    if (s) { for (const x of s.v.defs) { res.defs.push(x); if (x.srcPorts) res.srcPort = true; } return; }
    const g = lookupObj(scopes, "serviceGroup", name);
    if (g) { for (const m of g.v.members) add(m, d + 1); return; }
    if (PREDEF_SERVICES[name]) { res.defs.push(...PREDEF_SERVICES[name]); return; }
    res.unresolved.push(name);
  }
  for (const n of list) add(n, 0);
  return res;
}
function expandApps(list, scopes) {
  const out = []; const seen = new Set(); const unknownGroups = [];
  function add(n, d) {
    if (seen.has(n) || d > 20) return; seen.add(n);
    const g = lookupObj(scopes, "appGroup", n);
    if (g) { for (const m of g.v.members) add(m, d + 1); return; }
    if (lookupObj(scopes, "appFilter", n)) { unknownGroups.push(n); return; }
    out.push(n);
  }
  for (const n of list) add(n, 0);
  return { apps: out, filters: unknownGroups };
}
function appDefaultDefs(app, scopes) {
  const c = lookupObj(scopes, "app", app);
  if (c && c.v.ports.length) return parseAppPorts(c.v.ports);
  if (APP_DEFAULTS[app]) return parseAppPorts(APP_DEFAULTS[app]);
  return null;
}

/* ------------------------------------------------------------------ device model */
const IF_KINDS = ["ethernet", "aggregate-ethernet"];
function readInterfaces(netNode, vars, scopes, warn) {
  const ifs = new Map();
  const ifRoot = ch(netNode, "interface");
  if (!ifRoot) return ifs;
  function ipsOf(node) {
    const out = [];
    for (const e of entries(ch(node, "ip"))) {
      let name = e.a.name, src = null;
      if (name && name[0] === "$" && vars[name]) { src = name; name = vars[name]; }
      let p = parsePrefix(name);
      if (!p && scopes) { const o = lookupObj(scopes, "address", name); if (o && o.v.value) { src = name; p = parsePrefix(o.v.value); } }
      if (p && !/\//.test(name) && p.lo === p.hi) warn.push({ level: "info", text: "Interface IP " + (src || name) + " has no mask; treated as /32 (no connected subnet)." });
      if (p) out.push({ ip: p.ip, len: p.len == null ? 32 : p.len, net: p, text: n2ip(p.ip) + "/" + (p.len == null ? 32 : p.len), via: src });
      else if (isV6(name)) { /* ignore v6 */ }
      else warn.push({ level: "warn", text: "Interface IP '" + name + "' could not be resolved (variable or object missing)." });
    }
    return out;
  }
  function addL3(name, type, l3, parent) {
    if (!l3) return;
    const it = { name, type, parent: parent || null, ips: ipsOf(l3), dhcp: !!ch(l3, "dhcp-client"), tag: txt(ch(l3, "tag")) || null,
      comment: txt(ch(l3, "comment")), mode: "layer3", zone: null, vsys: null, vr: null };
    ifs.set(name, it);
    for (const u of entries(ch(l3, "units"))) addL3(u.a.name, type + "-sub", u, name);
  }
  for (const k of IF_KINDS) {
    for (const e of entries(ch(ifRoot, k))) {
      const l3 = ch(e, "layer3");
      if (l3) addL3(e.a.name, k, l3);
      else {
        const mode = ["layer2", "virtual-wire", "tap", "ha", "decrypt-mirror", "aggregate-group"].find((m) => ch(e, m)) || "none";
        ifs.set(e.a.name, { name: e.a.name, type: k, ips: [], mode, zone: null, vsys: null, vr: null, comment: txt(ch(e, "comment")) });
        const l2 = ch(e, mode);
        if (l2) for (const u of entries(ch(l2, "units"))) ifs.set(u.a.name, { name: u.a.name, type: k + "-sub", parent: e.a.name, ips: [], mode, zone: null, vsys: null, vr: null, tag: txt(ch(u, "tag")) });
      }
    }
  }
  for (const k of ["vlan", "loopback", "tunnel"]) {
    const n = ch(ifRoot, k); if (!n) continue;
    if (ch(n, "ip")) addL3(k, k, n);
    for (const u of entries(ch(n, "units"))) {
      const it = { name: u.a.name, type: k, parent: k, ips: ipsOf(u), dhcp: !!ch(u, "dhcp-client"), mode: "layer3", zone: null, vsys: null, vr: null, comment: txt(ch(u, "comment")) };
      ifs.set(u.a.name, it);
    }
  }
  return ifs;
}

function serialFromFilename(fileName) {
  if (!fileName) return null;
  const base = String(fileName).split(/[/\\]/).pop().replace(/\.(xml|conf)$/i, "");
  const toks = base.split(/[^0-9]+/).filter((t) => /^[0-9]{12,16}$/.test(t));
  return toks.length === 1 ? toks[0] : null;
}
/* Collect static routes from routing-table/ip/static-route (current PAN-OS) and the older
   vr/ip/static-route and vr/static-route layouts. Callers may pass the VR/VRF node or the
   routing-table node; both work. Duplicate entries (same name, dest, next hop, interface) are skipped. */
function staticRouteRoots(node) {
  const roots = [], seen = new Set();
  const add = (n) => { if (n && !seen.has(n)) { seen.add(n); roots.push(n); } };
  if (!node) return roots;
  add(at(node, "routing-table/ip/static-route"));
  add(at(node, "ip/static-route"));
  add(ch(node, "static-route"));
  return roots;
}
function readStaticRoutes(node, vars, scopes) {
  const out = [], seen = new Set();
  for (const root of staticRouteRoots(node)) {
  for (const e of entries(root)) {
    let dst = txt(ch(e, "destination"));
    if (dst[0] === "$" && vars[dst]) dst = vars[dst];
    let p = parsePrefix(dst);
    if (!p && scopes) { const o = lookupObj(scopes, "address", dst); if (o) p = parsePrefix(o.v.value); }
    if (!p) continue;
    const nh = ch(e, "nexthop"); let nexthop = { type: "none" };
    if (nh) {
      for (const t of ["ip-address", "next-vr", "next-lr", "next-vrf", "fqdn", "discard", "ipv6-address"]) {
        const c = ch(nh, t);
        if (c) {
          let v = txt(c);
          if (t === "ip-address") {
            if (v[0] === "$" && vars[v]) v = vars[v];
            if (ip2n(v) == null && scopes) { const o = lookupObj(scopes, "address", v); if (o) v = (o.v.value || "").split("/")[0]; }
            nexthop = { type: "ip", value: v.split("/")[0] };
          } else if (/^next-/.test(t)) nexthop = { type: "next-vr", value: v };
          else nexthop = { type: t, value: v };
          break;
        }
      }
    }
    const rtt = ch(e, "route-table");
    if (rtt && (ch(rtt, "multicast") || ch(rtt, "no-install"))) continue;
    const iface = txt(ch(e, "interface")) || null;
    const key = (e.a.name || "") + "|" + prefixStr(p) + "|" + (nexthop.type || "") + "|" + (nexthop.value || "") + "|" + (iface || "");
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ name: e.a.name, dest: p, nexthop, iface, metric: Number(txt(ch(e, "metric")) || 10),
      ad: Number(txt(ch(e, "admin-dist")) || 10), type: "static" });
  }
  }
  return out;
}
/* BGP / OSPF configuration (legacy virtual router). Used to infer learned routes. */
function readDynamicConfig(protoNode, vrNode, vars, scopes) {
  const out = { bgp: null, ospf: null, redist: new Map() };
  if (!protoNode) return out;
  const val = (v) => { v = String(v || "").trim(); if (v[0] === "$" && vars[v]) v = vars[v]; if (ip2n(v.split("/")[0]) == null && scopes) { const o = lookupObj(scopes, "address", v); if (o && o.v.value) v = o.v.value; } return v; };
  for (const e of entries(ch(protoNode, "redist-profile")).concat(entries(ch(vrNode, "redist-profile")))) {
    const f = ch(e, "filter");
    out.redist.set(e.a.name, { name: e.a.name, types: members(at(f, "type")), ifaces: members(at(f, "interface")), dests: members(at(f, "destination")).map((x) => parsePrefix(val(x))).filter(Boolean), redist: !ch(ch(e, "action"), "no-redist") });
  }
  const policyRules = (n) => entries(at(n, "rules")).filter((r) => txt(ch(r, "enable")) !== "no").map((r) => ({ name: r.a.name, usedBy: members(ch(r, "used-by")), prefixes: entries(at(r, "match/address-prefix")).map((x) => ({ p: parsePrefix(val(x.a.name)), exact: txt(ch(x, "exact")) === "yes" })).filter((x) => x.p), deny: !!at(r, "action/deny") }));
  const b = ch(protoNode, "bgp");
  if (b && txt(ch(b, "enable")) === "yes") {
    const bgp = { localAs: txt(ch(b, "local-as")) || null, routerId: val(txt(ch(b, "router-id"))) || null, peers: [], redistRules: [], exportRules: policyRules(at(b, "policy/export")), importRules: policyRules(at(b, "policy/import")) };
    for (const g of entries(ch(b, "peer-group"))) {
      if (txt(ch(g, "enable")) === "no") continue;
      const gtype = at(g, "type/ibgp") ? "ibgp" : at(g, "type/ebgp") ? "ebgp" : at(g, "type/ebgp-confed") || at(g, "type/ibgp-confed") ? "confed" : "ebgp";
      for (const pe of entries(ch(g, "peer"))) {
        if (txt(ch(pe, "enable")) === "no") continue;
        const pip = val(txt(at(pe, "peer-address/ip")) || txt(ch(pe, "peer-address"))).split("/")[0];
        const lip = val(txt(at(pe, "local-address/ip"))).split("/")[0];
        bgp.peers.push({ group: g.a.name, name: pe.a.name, type: gtype, peerAs: txt(ch(pe, "peer-as")) || null, peerIp: ip2n(pip) != null ? pip : null, fqdn: ip2n(pip) == null ? txt(at(pe, "peer-address/fqdn")) || null : null,
          localIf: txt(at(pe, "local-address/interface")) || null, localIp: ip2n(lip) != null ? lip : null });
      }
    }
    for (const r of entries(ch(b, "redist-rules"))) if (txt(ch(r, "enable")) !== "no") bgp.redistRules.push(r.a.name);
    bgp.engine = "legacy";
    bgp.groups = entries(ch(b, "peer-group")).map((g) => ({ name: g.a.name, enabled: txt(ch(g, "enable")) !== "no", type: at(g, "type/ibgp") ? "ibgp" : "ebgp", peers: entries(ch(g, "peer")).length }));
    // aggregation: policy/aggregation/address/entry {prefix, summary}
    bgp.aggregates = entries(at(b, "policy/aggregation/address")).filter((e) => txt(ch(e, "enable")) !== "no").map((e) => ({ name: e.a.name, prefix: parsePrefix(val(txt(ch(e, "prefix")))), summaryOnly: txt(ch(e, "summary")) === "yes" })).filter((x) => x.prefix);
    // conditional advertisement (legacy supports non-exist only): advertise-filters are sent only while non-exist-filters are absent
    const pfx = (n) => entries(n).flatMap((f) => txt(ch(f, "enable")) === "no" ? [] : entries(at(f, "match/address-prefix")).map((x) => parsePrefix(val(x.a.name))).filter(Boolean));
    bgp.condAdv = entries(at(b, "policy/conditional-advertisement/policy")).filter((e) => txt(ch(e, "enable")) !== "no").map((e) => ({ name: e.a.name, usedBy: members(ch(e, "used-by")), mode: "non-exist", cond: pfx(ch(e, "non-exist-filters")), advertise: pfx(ch(e, "advertise-filters")) })).filter((x) => x.advertise.length);
    bgp.networks = [];
    out.bgp = bgp;
  }
  const o = ch(protoNode, "ospf");
  if (o && txt(ch(o, "enable")) === "yes") {
    const ospf = { routerId: val(txt(ch(o, "router-id"))) || null, areas: [], exportRules: entries(ch(o, "export-rules")).map((x) => x.a.name) };
    for (const a of entries(ch(o, "area"))) ospf.areas.push({ id: a.a.name, ifaces: entries(ch(a, "interface")).filter((x) => txt(ch(x, "enable")) !== "no").map((x) => ({ name: x.a.name, passive: txt(ch(x, "passive")) === "yes" })) });
    out.ospf = ospf;
  }
  return out;
}
/* BGP on the Advanced Routing Engine (PAN-OS 10.2+ logical routers): network/logical-router/entry/vrf/entry/bgp plus the
   shared profiles under network/routing-profile (bgp redistribution/filtering profiles, filters prefix-list / access-list / route-maps).
   Returns the same shape as readDynamicConfig so the inference treats both engines alike; filters are kept as data
   (prefix lists and route maps) and evaluated by bgpFilterAllows. */
function readAdvancedBgp(vrf, net, vars, scopes) {
  const out = { bgp: null, ospf: null, redist: new Map() };
  const b = ch(vrf, "bgp");
  if (!b || txt(ch(b, "enable")) !== "yes") return out;
  const val = (v) => { v = String(v || "").trim(); if (v[0] === "$" && vars[v]) v = vars[v]; if (ip2n(v.split("/")[0]) == null && scopes) { const o = lookupObj(scopes, "address", v); if (o && o.v.value) v = o.v.value; } return v; };
  const rp = at(net, "routing-profile");
  const pl = new Map(), acl = new Map(), rmBgp = new Map(), rmRedist = new Map();
  for (const e of entries(at(rp, "filters/prefix-list"))) {
    const list = entries(at(e, "type/ipv4/ipv4-entry")).map((x) => {
      const pe = at(x, "prefix/entry"), any = !pe || txt(at(x, "prefix/network")) === "any";
      return { seq: Number(x.a.name) || 0, permit: txt(ch(x, "action")) !== "deny", any, p: any ? null : parsePrefix(val(txt(ch(pe, "network")))), ge: Number(txt(ch(pe, "greater-than-or-equal"))) || null, le: Number(txt(ch(pe, "less-than-or-equal"))) || null };
    }).filter((x) => x.any || x.p).sort((a, b2) => a.seq - b2.seq);
    pl.set(e.a.name, list);
  }
  for (const e of entries(at(rp, "filters/access-list"))) {
    const list = entries(at(e, "type/ipv4/ipv4-entry")).map((x) => {
      const sa = at(x, "source-address"), any = !sa || txt(ch(sa, "entry")) === "any" || txt(sa) === "any";
      let p = null;
      if (!any) { const a = val(txt(ch(sa, "address"))), w = ip2n(txt(ch(sa, "wildcard")) || "0.0.0.0"); const inv = w == null ? null : 32 - Math.round(Math.log2(w + 1)); p = parsePrefix(a.split("/")[0] + (inv != null && Number.isFinite(inv) ? "/" + inv : "")); }
      return { seq: Number(x.a.name) || 0, permit: txt(ch(x, "action")) !== "deny", any, p, ge: null, le: 32 };
    }).filter((x) => x.any || x.p).sort((a, b2) => a.seq - b2.seq);
    acl.set(e.a.name, list);
  }
  const rmEntries = (n) => entries(at(n, "route-map")).map((x) => ({ seq: Number(x.a.name) || 0, permit: txt(ch(x, "action")) !== "deny", prefixList: txt(at(x, "match/ipv4/address/prefix-list")) || null, accessList: txt(at(x, "match/ipv4/address/access-list")) || null })).sort((a, b2) => a.seq - b2.seq);
  for (const e of entries(at(rp, "filters/route-maps/bgp/bgp-entry"))) rmBgp.set(e.a.name, rmEntries(e));
  for (const e of entries(at(rp, "filters/route-maps/redistribution/redist-entry"))) { const all = []; for (const src of e.c) for (const dst of src.c || []) if (dst.t === "bgp") all.push(...rmEntries(dst)); rmRedist.set(e.a.name, all.sort((a, b2) => a.seq - b2.seq)); }
  const filt = { prefixLists: pl, accessLists: acl, routeMaps: rmBgp, redistMaps: rmRedist };
  // redistribution profile -> the redist entry format used by the legacy path (types + optional route map per type)
  const redistName = txt(at(b, "redistribution-profile/ipv4/unicast"));
  const redistRules = [];
  if (redistName) {
    const prof = findEntry(at(rp, "bgp/redistribution-profile"), redistName), u = at(prof, "ipv4/unicast"), types = [], maps = {};
    for (const [tag, kind] of [["static", "static"], ["connected", "connect"], ["ospf", "ospf"], ["rip", "rip"]]) { const n = ch(u, tag); if (n && txt(ch(n, "enable")) === "yes") { types.push(kind); const rm = txt(ch(n, "route-map")); if (rm) maps[kind] = rm; } }
    out.redist.set(redistName, { name: redistName, types, ifaces: [], dests: [], redist: !!prof && types.length > 0, maps, missing: !prof });
    redistRules.push(redistName);
  }
  const fprof = (name) => {
    if (!name) return null;
    const e = findEntry(at(rp, "bgp/filtering-profile"), name); if (!e) return { name, missing: true };
    const u = at(e, "ipv4/unicast"); if (!u) return { name };
    const one = (dir) => ({ prefixList: txt(at(u, dir + "-network-filters/prefix-list")) || null, distList: txt(at(u, dir + "-network-filters/distribute-list")) || null, routeMap: txt(at(u, "route-maps/" + dir.replace("bound", "bound"))) || null });
    const ca = [];
    for (const mode of ["exist", "non-exist"]) { const c = at(u, "conditional-advertisement/" + mode); if (c) ca.push({ mode, advertiseMap: txt(ch(c, "advertise-map")) || null, condMap: txt(ch(c, mode + "-map")) || null }); }
    return { name, in: one("inbound"), out: one("outbound"), condAdv: ca };
  };
  const bgp = { engine: "advanced", localAs: txt(ch(b, "local-as")) || null, routerId: val(txt(ch(b, "router-id"))) || null, peers: [], groups: [], redistRules, exportRules: [], importRules: [], filters: filt,
    installRoute: txt(ch(b, "install-route")) !== "no", alwaysAdvertiseNetwork: txt(ch(b, "always-advertise-network-route")) === "yes",
    networks: entries(at(b, "advertise-network/ipv4/network")).filter((e) => txt(ch(e, "unicast")) !== "no").map((e) => parsePrefix(val(e.a.name))).filter(Boolean),
    aggregates: entries(ch(b, "aggregate-routes")).filter((e) => txt(ch(e, "enable")) !== "no").map((e) => ({ name: e.a.name, prefix: parsePrefix(val(txt(at(e, "type/ipv4/summary-prefix")))), summaryOnly: txt(ch(e, "summary-only")) === "yes" })).filter((x) => x.prefix), condAdv: [] };
  for (const g of entries(ch(b, "peer-group"))) {
    const genabled = txt(ch(g, "enable")) !== "no", gtype = at(g, "type/ibgp") ? "ibgp" : "ebgp";
    const gf = txt(at(g, "filtering-profile/ipv4")) || null;
    bgp.groups.push({ name: g.a.name, enabled: genabled, type: gtype, peers: entries(ch(g, "peer")).length, filteringProfile: gf });
    if (!genabled) continue;
    for (const pe of entries(ch(g, "peer"))) {
      if (txt(ch(pe, "enable")) === "no") continue;
      const pip = val(txt(at(pe, "peer-address/ip"))).split("/")[0], lip = val(txt(at(pe, "local-address/ip"))).split("/")[0];
      const own = at(pe, "inherit/no") ? txt(at(pe, "inherit/no/filtering-profile/ipv4")) || null : null;
      const fp = fprof(own || gf);
      bgp.peers.push({ group: g.a.name, name: pe.a.name, type: gtype, peerAs: txt(ch(pe, "peer-as")) || (gtype === "ibgp" ? txt(ch(b, "local-as")) : null) || null, peerIp: ip2n(pip) != null ? pip : null, fqdn: ip2n(pip) == null ? txt(at(pe, "peer-address/fqdn")) || null : null,
        localIf: txt(at(pe, "local-address/interface")) || null, localIp: ip2n(lip) != null ? lip : null, passive: txt(ch(pe, "passive")) === "yes", filtering: fp });
      if (fp && fp.condAdv) for (const c of fp.condAdv) bgp.condAdv.push({ name: fp.name + " (" + c.mode + ")", usedBy: [g.a.name], peer: pe.a.name, mode: c.mode, advertiseMap: c.advertiseMap, condMap: c.condMap });
    }
  }
  out.bgp = bgp;
  return out;
}
/* Does a prefix list / access list / route map permit dest? Lists end in an implicit deny; a missing list permits (PAN-OS ignores a
   reference it cannot resolve at commit time, so the export is taken as-is). */
function prefixListPermits(list, dest) {
  if (!list) return true;
  for (const e of list) {
    let m = e.any;
    if (!m && e.p && dest.lo >= e.p.lo && dest.hi <= e.p.hi) { const L = dest.len == null ? 32 : dest.len, ge = e.ge || (e.le ? e.p.len : null), le = e.le || (e.ge ? 32 : null); m = ge == null && le == null ? L === e.p.len : L >= (ge || e.p.len) && L <= (le || 32); }
    if (m) return e.permit;
  }
  return false;
}
function routeMapPermits(filters, rm, dest) {
  if (!rm) return true;
  for (const e of rm) {
    let m = true;
    if (e.prefixList) m = prefixListPermits(filters.prefixLists.get(e.prefixList), dest);
    else if (e.accessList) m = prefixListPermits(filters.accessLists.get(e.accessList), dest);
    if (m) return e.permit;
  }
  return false;
}
/* Peer-level filter check for one direction ("in" | "out"). Legacy: import/export policy rules (used-by peer group; first match wins, no match = deny once any rule applies). Advanced: the
   peer's (or its group's) BGP filtering profile: network filter (prefix or distribute list) AND route map must permit. */
function bgpFilterAllows(bgp, pe, dir, dest) {
  if (!bgp) return { ok: true };
  if (bgp.engine !== "advanced") {
    const rules = dir === "in" ? bgp.importRules : bgp.exportRules;
    let applicable = 0;
    for (const r of rules || []) {
      if (r.usedBy.length && !r.usedBy.includes(pe ? pe.group : null)) continue;
      applicable++;
      const m = !r.prefixes.length || r.prefixes.some((x) => (x.exact ? x.p.lo === dest.lo && x.p.hi === dest.hi : dest.lo >= x.p.lo && dest.hi <= x.p.hi));
      if (m) return r.deny ? { ok: false, why: (dir === "in" ? "import" : "export") + " rule " + r.name + " denies it" } : { ok: true, why: (dir === "in" ? "import" : "export") + " rule " + r.name };
    }
    /* Verified live on PAN-OS 11.1: once any rule applies to a peer group, a route that matches none of them is NOT
       exchanged (implicit deny). Only a peer group with no rules at all passes everything. */
    return applicable ? { ok: false, why: (dir === "in" ? "import" : "export") + " rules exist for this peer group and none matches it (implicit deny)" } : { ok: true };
  }
  const fp = pe && pe.filtering; if (!fp || fp.missing || !fp[dir]) return { ok: true };
  const f = fp[dir], F = bgp.filters, label = "filtering profile " + fp.name + " " + (dir === "in" ? "inbound" : "outbound");
  if (f.prefixList && !prefixListPermits(F.prefixLists.get(f.prefixList), dest)) return { ok: false, why: label + " prefix list " + f.prefixList + " does not permit it" };
  if (f.distList && !prefixListPermits(F.accessLists.get(f.distList), dest)) return { ok: false, why: label + " distribute list " + f.distList + " does not permit it" };
  if (f.routeMap && F.routeMaps.has(f.routeMap) && !routeMapPermits(F, F.routeMaps.get(f.routeMap), dest)) return { ok: false, why: label + " route map " + f.routeMap + " does not permit it" };
  return { ok: true, why: f.prefixList || f.routeMap || f.distList ? label + " permits it" : null };
}
/* Plain summary of a VR's BGP config, for the config browser and the BGP panel. */
function bgpSummary(dev) {
  const out = [];
  for (const vr of new Set(dev.vrs.values())) {
    const b = vr.proto && vr.proto.bgp; if (!b) continue;
    out.push({ device: dev.name, vr: vr.name, engine: b.engine, localAs: b.localAs, routerId: b.routerId,
      groups: (b.groups || []).map((g) => ({ name: g.name, type: g.type, enabled: g.enabled, peers: g.peers, filteringProfile: g.filteringProfile || null })),
      peers: b.peers.map((p) => ({ group: p.group, name: p.name, peerAs: p.peerAs, peerIp: p.peerIp || p.fqdn, localIf: p.localIf, filteringProfile: p.filtering ? p.filtering.name : null })),
      redistribution: b.redistRules.map((n) => { const r = vr.proto.redist.get(n); return { name: n, types: r ? r.types : [], missing: !r || !!r.missing }; }),
      networks: (b.networks || []).map(prefixStr), aggregates: (b.aggregates || []).map((a) => ({ prefix: prefixStr(a.prefix), summaryOnly: a.summaryOnly })),
      conditional: (b.condAdv || []).map((c) => ({ name: c.name, mode: c.mode, usedBy: c.usedBy })),
      importRules: (b.importRules || []).length, exportRules: (b.exportRules || []).length,
      observed: vr.observedTable ? { source: vr.observedTable.source, routes: vr.observedTable.count } : null });
  }
  return out;
}
function dynProtocols(protoNode) {
  const out = [];
  if (!protoNode) return out;
  for (const p of ["bgp", "ospf", "ospfv3", "rip", "eigrp"]) {
    const n = ch(protoNode, p);
    if (n && (txt(ch(n, "enable")) === "yes")) out.push(p);
  }
  return out;
}

/* Build a device model.
 * spec: {id, name, kind, deviceNode (devices/entry), sharedNode, vars,
 *        vsysPolicy: function(vsysName) -> {scopes:[...extra scopes], rules:{security:[], nat:[], pbf:[]}, label} } */
/* deviceconfig/high-availability, after template merge and $variable resolution.
   enabled: true | false | null (absent); peers: resolved peer-ip / peer-ip-backup; own: this device's HA1 / HA1-backup addresses. */
function readHa(dn, vars) {
  const ha = at(dn, "deviceconfig/high-availability");
  if (!ha) return null;
  const val = (node) => { let v = txt(node); if (!v) return null; v = v.trim(); if (v[0] === "$") { const r = vars && vars[v]; if (!r) return { unresolved: v }; v = String(r).trim(); } const p = parsePrefix(v.split("/")[0]); return p && p.lo === p.hi ? n2ip(p.lo) : null; };
  const en = txt(ch(ha, "enabled")); const enabled = en === "yes" ? true : en === "no" ? false : null;
  let grp = ch(ha, "group"); if (grp && entries(grp).length) grp = entries(grp)[0];
  const peers = [], own = [], unresolved = [];
  const add = (list, v) => { if (!v) return; if (v.unresolved) unresolved.push(v.unresolved); else if (!list.includes(v)) list.push(v); };
  if (grp) { add(peers, val(ch(grp, "peer-ip"))); add(peers, val(ch(grp, "peer-ip-backup"))); }
  const ifn = ch(ha, "interface");
  if (ifn) for (const k of ["ha1", "ha1-backup"]) add(own, val(at(ifn, k + "/ip-address")));
  const mode = grp && at(grp, "mode/active-active") ? "active-active" : grp && at(grp, "mode/active-passive") ? "active-passive" : null;
  return { enabled, peers, own, unresolved, mode, groupId: grp ? txt(ch(grp, "group-id")) || (grp.a && grp.a.name) || null : null };
}
function buildDevice(spec) {
  const warn = [];
  const dn = spec.deviceNode;
  const net = ch(dn, "network");
  const vars = spec.vars || {};
  const sharedScope = readObjects(spec.sharedNode, "shared");
  const dev = { id: spec.id, name: spec.name, kind: spec.kind, file: spec.file || null, serial: spec.serial || null, panorama: spec.panorama || null,
    interfaces: new Map(), vsys: new Map(), vrs: new Map(), warnings: warn, multiVsys: false, sharedGateways: [] };
  dev.ha = readHa(dn, vars);
  const vsysNodes = entries(ch(dn, "vsys"));
  const sgNodes = entries(at(dn, "network/shared-gateway"));
  dev.multiVsys = vsysNodes.length > 1 || sgNodes.length > 0;
  const firstScopes = [readObjects(vsysNodes[0], vsysNodes[0] ? vsysNodes[0].a.name : "vsys1"), sharedScope];
  dev.interfaces = readInterfaces(net, vars, firstScopes, warn);

  function buildCtx(node, isSG) {
    const name = node.a.name;
    const local = readObjects(node, name);
    const pol = spec.vsysPolicy ? spec.vsysPolicy(name, isSG) : null;
    const scopes = [local].concat(pol && pol.scopes ? pol.scopes : [], [sharedScope]);
    const v = { uid: (spec.id || "") + "/" + name, name, display: txt(ch(node, "display-name")) || name, isSG, zones: new Map(), importIfs: members(at(node, "import/network/interface")),
      importVrs: members(at(node, "import/network/virtual-router")).concat(members(at(node, "import/network/logical-router"))),
      visible: members(at(node, "import/visible-vsys")), scopes, security: [], nat: [], pbf: [], defaults: { intrazone: "allow", interzone: "deny" }, policyLabel: pol && pol.label };
    for (const z of entries(ch(node, "zone"))) {
      const nw = ch(z, "network"); let type = "unknown", mem = [];
      if (nw) for (const t of ["layer3", "layer2", "virtual-wire", "tap", "external", "tunnel"]) { const c = ch(nw, t); if (c) { type = t; mem = members(c); break; } }
      v.zones.set(z.a.name, { name: z.a.name, type, members: mem, vsys: name });
    }
    const rb = ch(node, "rulebase");
    const localRules = { security: parseSecRules(at(rb, "security/rules"), name), nat: parseNatRules(at(rb, "nat/rules"), name), pbf: parsePbfRules(at(rb, "pbf/rules"), name) };
    const dsr = at(rb, "default-security-rules/rules");
    for (const e of entries(dsr)) { const a = txt(ch(e, "action")); if (a && /intrazone/.test(e.a.name)) v.defaults.intrazone = a; if (a && /interzone/.test(e.a.name)) v.defaults.interzone = a; }
    if (pol && pol.rules) {
      v.security = pol.rules.pre.security.concat(localRules.security, pol.rules.post.security);
      v.nat = pol.rules.pre.nat.concat(localRules.nat, pol.rules.post.nat);
      v.pbf = pol.rules.pre.pbf.concat(localRules.pbf, pol.rules.post.pbf);
      if (pol.defaults) Object.assign(v.defaults, pol.defaults);
    } else { v.security = localRules.security; v.nat = localRules.nat; v.pbf = localRules.pbf; }
    if (spec.serial) for (const k of ["security", "nat", "pbf"]) v[k] = v[k].filter((r) => targetAllows(r, spec.serial, name));
    return v;
  }
  for (const n of vsysNodes) dev.vsys.set(n.a.name, buildCtx(n, false));
  for (const n of sgNodes) { const c = buildCtx(n, true); dev.vsys.set(n.a.name, c); dev.sharedGateways.push(n.a.name); }
  if (!dev.vsys.size) { const fake = { t: "entry", a: { name: "vsys1" }, c: [], x: "" }; dev.vsys.set("vsys1", buildCtx(fake, false)); }

  // interface ownership
  const ctxs = [...dev.vsys.values()];
  const anyImports = ctxs.some((c) => c.importIfs.length);
  for (const it of dev.interfaces.values()) {
    let owner = ctxs.find((c) => c.importIfs.includes(it.name));
    if (!owner && it.parent) owner = ctxs.find((c) => c.importIfs.includes(it.parent) && !it.type.startsWith("ethernet") ) || null;
    if (!owner && (!anyImports || !dev.multiVsys)) owner = ctxs.find((c) => !c.isSG) || ctxs[0];
    it.vsys = owner ? owner.name : null;
    for (const c of ctxs) for (const z of c.zones.values()) if (z.type !== "external" && z.members.includes(it.name)) { it.zone = z.name; if (!it.vsys) it.vsys = c.name; }
  }
  // virtual routers (legacy) + logical routers (advanced routing)
  for (const e of entries(at(net, "virtual-router"))) {
    const vr = { name: e.a.name, engine: "legacy", interfaces: members(ch(e, "interface")), routes: readStaticRoutes(e, vars, firstScopes), dynamic: dynProtocols(ch(e, "protocol")), owner: null };
    vr.proto = readDynamicConfig(ch(e, "protocol"), e, vars, firstScopes);
    dev.vrs.set(vr.name, vr);
  }
  for (const lr of entries(at(net, "logical-router"))) {
    for (const vrf of entries(ch(lr, "vrf"))) {
      const nm = vrf.a.name === "default" ? lr.a.name : lr.a.name + ":" + vrf.a.name;
      const vr = { name: nm, lr: lr.a.name, vrf: vrf.a.name, engine: "advanced", interfaces: members(ch(vrf, "interface")), routes: readStaticRoutes(vrf, vars, firstScopes),
        dynamic: ["bgp", "ospf", "ospfv3", "rip"].filter((p) => { const n = ch(vrf, p); return n && txt(ch(n, "enable")) === "yes"; }), owner: null };
      vr.proto = readAdvancedBgp(vrf, net, vars, firstScopes);
      dev.vrs.set(nm, vr);
      if (!dev.vrs.has(lr.a.name)) dev.vrs.set(lr.a.name, vr);
    }
  }
  // resolve next-vr names for ARE (lr name -> default vrf)
  for (const vr of new Set(dev.vrs.values())) {
    for (const it of vr.interfaces) { const i = dev.interfaces.get(it); if (i) i.vr = vr.name; }
    // connected routes
    for (const iname of vr.interfaces) {
      const i = dev.interfaces.get(iname); if (!i) continue;
      for (const ip of i.ips) {
        const size = Math.pow(2, 32 - ip.len), lo = Math.floor(ip.ip / size) * size;
        vr.routes.push({ name: "connected " + iname, dest: { lo, hi: lo + size - 1, len: ip.len }, nexthop: { type: "connected" }, iface: iname, metric: 0, ad: 0, type: "connected" });
        if (ip.len < 32) vr.routes.push({ name: "local " + iname, dest: { lo: ip.ip, hi: ip.ip, len: 32 }, nexthop: { type: "local" }, iface: iname, metric: 0, ad: 0, type: "local" });
        else vr.routes[vr.routes.length - 1].type = "local", vr.routes[vr.routes.length - 1].nexthop = { type: "local" };
      }
      if (i.dhcp) warn.push({ level: "warn", text: "Interface " + iname + " uses DHCP; its IP and default route are learned at runtime and not in the config." });
    }
    // owner
    const imp = ctxs.find((c) => c.importVrs.includes(vr.name) || (vr.lr && c.importVrs.includes(vr.lr)));
    if (imp) vr.owner = imp.name;
    else {
      const owners = new Set(vr.interfaces.map((n) => dev.interfaces.get(n)).filter(Boolean).map((i) => i.vsys).filter(Boolean));
      vr.owner = owners.size === 1 ? [...owners][0] : (owners.size === 0 && !dev.multiVsys ? (ctxs[0] && ctxs[0].name) : null);
      vr.sharedOwners = [...owners];
    }
    if (vr.dynamic.length) warn.push({ level: "info", text: "Router " + vr.name + " runs " + vr.dynamic.join("/").toUpperCase() + "; routes learned dynamically are not in the config, so traces use static and connected routes only." });
  }
  return dev;
}
function targetAllows(rule, serial, vsys) {
  if (!rule.target || !rule.target.devices.length) return true;
  const hit = rule.target.devices.some((d) => d.serial === serial && (!d.vsys.length || d.vsys.includes(vsys)));
  return rule.target.negate ? !hit : hit;
}

/* ------------------------------------------------------------------ rules */
function parseTarget(e) {
  const t = ch(e, "target"); if (!t) return null;
  const devs = entries(ch(t, "devices")).map((d) => ({ serial: d.a.name, vsys: entries(ch(d, "vsys")).map((v) => v.a.name) }));
  return { devices: devs, negate: txt(ch(t, "negate")) === "yes" };
}
function parseSecRules(n, scope) {
  return entries(n).map((e, idx) => ({ name: e.a.name, scope, idx, uuid: e.a.uuid || null,
    from: members(ch(e, "from")), to: members(ch(e, "to")), source: members(ch(e, "source")), destination: members(ch(e, "destination")),
    negSrc: txt(ch(e, "negate-source")) === "yes", negDst: txt(ch(e, "negate-destination")) === "yes",
    srcUser: members(ch(e, "source-user")), application: members(ch(e, "application")), service: members(ch(e, "service")),
    category: members(ch(e, "category")), hip: members(ch(e, "source-hip")).concat(members(ch(e, "hip-profiles"))),
    action: txt(ch(e, "action")) || "allow", disabled: txt(ch(e, "disabled")) === "yes", ruleType: txt(ch(e, "rule-type")) || "universal",
    desc: txt(ch(e, "description")), target: parseTarget(e), tags: members(ch(e, "tag")) }));
}
function parseNatRules(n, scope) {
  return entries(n).map((e, idx) => {
    const st = ch(e, "source-translation"); let snat = null;
    if (st) {
      const dip = ch(st, "dynamic-ip-and-port"), sip = ch(st, "static-ip"), dyn = ch(st, "dynamic-ip");
      if (dip) { const ia = ch(dip, "interface-address"); snat = ia ? { type: "dynamic-ip-and-port", iface: txt(ch(ia, "interface")), ip: txt(ch(ia, "ip")) || null } : { type: "dynamic-ip-and-port", addrs: members(ch(dip, "translated-address")) }; }
      else if (sip) snat = { type: "static-ip", addrs: [txt(ch(sip, "translated-address"))], bidir: txt(ch(sip, "bi-directional")) === "yes" };
      else if (dyn) snat = { type: "dynamic-ip", addrs: members(ch(dyn, "translated-address")) };
    }
    const dt = ch(e, "destination-translation") || ch(e, "dynamic-destination-translation"); let dnat = null;
    if (dt) dnat = { addr: txt(ch(dt, "translated-address")), port: txt(ch(dt, "translated-port")) ? Number(txt(ch(dt, "translated-port"))) : null, dynamic: dt.t === "dynamic-destination-translation" };
    return { name: e.a.name, scope, idx, from: members(ch(e, "from")), to: members(ch(e, "to")), toIf: txt(ch(e, "to-interface")) || "any",
      source: members(ch(e, "source")), destination: members(ch(e, "destination")), service: txt(ch(e, "service")) || "any",
      snat, dnat, disabled: txt(ch(e, "disabled")) === "yes", natType: txt(ch(e, "nat-type")) || "ipv4", target: parseTarget(e) };
  });
}
function parsePbfRules(n, scope) {
  return entries(n).map((e, idx) => {
    const fr = ch(e, "from"); const zones = members(at(fr, "zone")), ifs = members(at(fr, "interface"));
    const a = ch(e, "action"); let action = { type: "none" };
    if (a) {
      const fw = ch(a, "forward"), fv = ch(a, "forward-to-vsys");
      if (fw) action = { type: "forward", iface: txt(ch(fw, "egress-interface")), nexthop: txt(at(fw, "nexthop/ip-address")) || null };
      else if (fv) action = { type: "forward-to-vsys", vsys: txt(fv) };
      else if (ch(a, "discard")) action = { type: "discard" };
      else if (ch(a, "no-pbf")) action = { type: "no-pbf" };
    }
    return { name: e.a.name, scope, idx, fromZones: zones, fromIfs: ifs, source: members(ch(e, "source")), destination: members(ch(e, "destination")),
      service: members(ch(e, "service")), application: members(ch(e, "application")), action, disabled: txt(ch(e, "disabled")) === "yes", target: parseTarget(e) };
  });
}

/* ------------------------------------------------------------------ config loading */
function loadConfig(text, fileName) { return loadConfigDoc(parseXml(text), text, fileName); }
async function loadConfigAsync(text, fileName, onProgress) { return loadConfigDoc(await parseXmlAsync(text, onProgress), text, fileName); }
function loadConfigDoc(doc, text, fileName) {
  let cfg = ch(doc, "config");
  if (!cfg) { // maybe wrapped in <response><result><config>
    const find = (n) => { if (n.t === "config") return n; for (const c of n.c) { const r = find(c); if (r) return r; } return null; };
    cfg = find(doc);
  }
  if (!cfg) throw new Error("No <config> element found. Is this a PAN-OS configuration XML?");
  const devEntry = findEntry(ch(cfg, "devices"), "localhost.localdomain") || entries(ch(cfg, "devices"))[0];
  if (!devEntry) throw new Error("No <devices><entry> in config.");
  const isPanorama = !!(ch(devEntry, "device-group") || ch(devEntry, "template") || ch(devEntry, "template-stack"));
  const version = cfg.a["detail-version"] || cfg.a.version || "";
  const hostname = txt(at(devEntry, "deviceconfig/system/hostname")) || fileName || "firewall";
  const serial = txt(at(devEntry, "deviceconfig/system/serial")) || serialFromFilename(fileName);
  const out = { fileName, kind: isPanorama ? "panorama" : "firewall", version, hostname, doc, cfg, devices: [], panorama: null, text };
  if (!isPanorama) {
    out.devices.push(buildDevice({ id: (fileName || hostname) + "", name: hostname, kind: "firewall", file: fileName, serial, deviceNode: devEntry, sharedNode: ch(cfg, "shared") }));
    if (txt(at(devEntry, "deviceconfig/system/hostname"))) out.devices[out.devices.length - 1].hostname = hostname;
    if (serial && !out.devices[out.devices.length - 1].serial) out.devices[out.devices.length - 1].serial = serial;
  } else {
    out.panorama = readPanorama(cfg, devEntry, fileName);
  }
  return out;
}

function readPanorama(cfg, devEntry, fileName) {
  const pano = { fileName, dgs: new Map(), templates: new Map(), stacks: new Map(), shared: ch(cfg, "shared") };
  const ro = ch(cfg, "readonly");
  const parentOf = {};
  for (const e of entries(at(ro, "devices/entry/device-group")) .concat(entries(at(ro, "dg-meta-data/dg-info")))) { const p = txt(ch(e, "parent-dg")); if (p) parentOf[e.a.name] = p; }
  for (const e of entries(ch(devEntry, "device-group"))) {
    const devs = entries(ch(e, "devices")).map((d) => ({ serial: d.a.name, hostname: txt(ch(d, "hostname")) || null, vsys: entries(ch(d, "vsys")).map((v) => v.a.name) }));
    pano.dgs.set(e.a.name, { name: e.a.name, node: e, parent: parentOf[e.a.name] || null, devices: devs });
  }
  for (const e of entries(ch(devEntry, "template"))) {
    pano.templates.set(e.a.name, { name: e.a.name, node: e, config: ch(e, "config"), vars: readVars(ch(e, "variable")) });
  }
  for (const e of entries(ch(devEntry, "template-stack"))) {
    const devs = entries(ch(e, "devices")).map((d) => ({ serial: d.a.name, hostname: txt(ch(d, "hostname")) || null, vars: readVars(ch(d, "variable")) }));
    pano.stacks.set(e.a.name, { name: e.a.name, node: e, templates: members(ch(e, "templates")), config: ch(e, "config"), vars: readVars(ch(e, "variable")), devices: devs });
  }
  pano.hostname = txt(at(devEntry, "deviceconfig/system/hostname")) || "panorama";
  pano.ha = readPanoramaHa(devEntry); // Panorama's own HA pair: shown on the ecosystem view only, never used for firewalls
  pano.managed = new Map();
  for (const e of entries(at(cfg, "mgt-config/devices"))) pano.managed.set(e.a.name, { serial: e.a.name, hostname: txt(ch(e, "hostname")) || null, vsys: entries(ch(e, "vsys")).map((v) => v.a.name) });
  // device hostname by serial, from the managed-device list first, then hostname children of device-group / template-stack
  // device entries, then a per-device $hostname template variable (a template's own deviceconfig hostname is not per device)
  pano.hostBySerial = new Map();
  const setHn = (serial, hn) => { if (serial && hn && !pano.hostBySerial.has(serial)) pano.hostBySerial.set(serial, hn); };
  for (const m of pano.managed.values()) setHn(m.serial, m.hostname);
  for (const g of pano.dgs.values()) for (const d of g.devices || []) setHn(d.serial, d.hostname);
  for (const st of pano.stacks.values()) for (const d of st.devices) setHn(d.serial, d.hostname || d.vars["$hostname"] || null);
  for (const m of pano.managed.values()) if (!m.hostname) m.hostname = pano.hostBySerial.get(m.serial) || null;
  pano.policyCache = new Map();
  pano.scopeCache = new Map();
  pano.contexts = listPanoramaContexts(pano);
  return pano;
}
function readVars(n) {
  const v = {};
  for (const e of entries(n)) { const t = ch(e, "type"); if (t && t.c[0]) v[e.a.name] = txt(t.c[0]); }
  return v;
}
function dgChain(pano, name) {
  const chain = []; let cur = name; const seen = new Set();
  while (cur && pano.dgs.has(cur) && !seen.has(cur)) { seen.add(cur); chain.unshift(pano.dgs.get(cur)); cur = pano.dgs.get(cur).parent; }
  return chain; // root -> leaf
}
/* Suggested contexts: each stack (or standalone template) x each serial, paired with DG by serial. */
function listPanoramaContexts(pano) {
  const ctx = [];
  const inStack = new Set(); for (const s of pano.stacks.values()) s.templates.forEach((t) => inStack.add(t));
  const dgForSerial = (serial) => { const m = {}; for (const dg of pano.dgs.values()) for (const d of dg.devices) if (d.serial === serial) { if (!d.vsys.length) m["*"] = dg.name; for (const v of d.vsys) m[v] = dg.name; } return m; };
  const dgIdx = new Map();
  for (const dg of pano.dgs.values()) for (const d of dg.devices) { if (!dgIdx.has(d.serial)) dgIdx.set(d.serial, {}); const m = dgIdx.get(d.serial); if (!d.vsys.length) m["*"] = dg.name; for (const v of d.vsys) m[v] = dg.name; }
  const dgMapOf = (serial) => Object.assign({}, dgIdx.get(serial) || {});
  const inStackSerial = new Set();
  // Hostnames a template stack pushes: deviceconfig/system/hostname (the configured name) and the init-cfg hostname that an
  // imported device config leaves behind. Used only when the stack serves exactly one firewall, so a template-wide value
  // never names several firewalls. A $variable resolves per device, else it is ignored.
  const cfgsOf = (s) => [s.config].concat(s.templates.map((t) => (pano.templates.get(t) || {}).config)).filter(Boolean);
  const devEntryOf = (cfg) => findEntry(ch(cfg, "devices"), "localhost.localdomain") || entries(ch(cfg, "devices"))[0];
  const tplVal = (s, d, xp) => {
    for (const cfg of cfgsOf(s)) { const v = txt(at(devEntryOf(cfg), xp)); if (!v) continue;
      if (v[0] !== "$") return v;
      const vars = {}; for (const t of s.templates.slice().reverse()) Object.assign(vars, (pano.templates.get(t) || {}).vars || {}); Object.assign(vars, s.vars, d.vars);
      const r = vars[v]; return r && r[0] !== "$" ? r : null; }
    return null;
  };
  const initCount = new Map();
  for (const s of pano.stacks.values()) for (const d of s.devices) { const v = tplVal(s, d, "deviceconfig/setting/management/initcfg/hostname"); if (v) initCount.set(v, (initCount.get(v) || 0) + 1); }
  for (const s of pano.stacks.values()) {
    if (s.devices.length) for (const d of s.devices) {
      inStackSerial.add(d.serial);
      const mg = pano.managed && pano.managed.get(d.serial);
      const hn = (mg && mg.hostname) || (pano.hostBySerial && pano.hostBySerial.get(d.serial)) || d.vars["$hostname"] || null;
      const one = s.devices.length === 1, tplHn = !hn && one ? tplVal(s, d, "deviceconfig/system/hostname") : null;
      const ini = !hn && !tplHn && one ? tplVal(s, d, "deviceconfig/setting/management/initcfg/hostname") : null;
      const initHn = ini && initCount.get(ini) === 1 ? ini : null;
      const shown = hn || tplHn || initHn;
      ctx.push({ id: "stack:" + s.name + ":" + d.serial, stack: s.name, template: null, serial: d.serial, hostname: hn, hostnameTpl: tplHn, hostnameInit: initHn, dgMap: dgMapOf(d.serial), mapped: true, label: (shown ? shown + " (" + d.serial + ")" : d.serial) + " - " + s.name });
    }
    else ctx.push({ id: "stack:" + s.name, stack: s.name, template: null, serial: null, dgMap: {}, mapped: false, label: s.name + " (no devices)" });
  }
  // managed firewalls that are in a device group but no template stack: policy only, no network config
  if (pano.managed) for (const mg of pano.managed.values()) if (!inStackSerial.has(mg.serial)) ctx.push({ id: "dev:" + mg.serial, stack: null, template: null, serial: mg.serial, hostname: mg.hostname, dgMap: dgMapOf(mg.serial), mapped: true, noNetwork: true, label: (mg.hostname ? mg.hostname + " (" + mg.serial + ")" : mg.serial) + " - no template stack" });
  for (const t of pano.templates.values()) if (!inStack.has(t.name)) ctx.push({ id: "tpl:" + t.name, stack: null, template: t.name, serial: null, dgMap: {}, mapped: false, label: "template " + t.name });
  pano.mappedDgs = new Set();
  for (const c of ctx) if (c.mapped) for (const d of Object.values(c.dgMap)) for (const x of dgChain(pano, d)) pano.mappedDgs.add(x.name);
  return ctx;
}
function buildPanoramaDevice(loaded, ctxSpec) {
  const pano = loaded.panorama;
  let cfgNode = null, vars = {};
  if (ctxSpec.stack) {
    const s = pano.stacks.get(ctxSpec.stack);
    if (!s.merged) {
      const parts = [s.config].concat(s.templates.map((t) => pano.templates.get(t)).filter(Boolean).map((t) => t.config));
      for (const p of parts.slice().reverse()) s.merged = s.merged ? mergeNodes(p, s.merged) : p;
    }
    cfgNode = s.merged;
    // vars: template < stack < per-device
    for (const t of s.templates.slice().reverse()) Object.assign(vars, (pano.templates.get(t) || {}).vars || {});
    Object.assign(vars, s.vars);
    const d = s.devices.find((x) => x.serial === ctxSpec.serial); if (d) Object.assign(vars, d.vars);
  } else if (ctxSpec.template) { const t = pano.templates.get(ctxSpec.template); cfgNode = t.config; vars = Object.assign({}, t.vars); }
  const devEntry = cfgNode ? (findEntry(ch(cfgNode, "devices"), "localhost.localdomain") || entries(ch(cfgNode, "devices"))[0]) : null;
  const deviceNode = devEntry || { t: "entry", a: { name: "localhost.localdomain" }, c: [], x: "" };
  const shared = cfgNode ? ch(cfgNode, "shared") : null; // template-level shared; Panorama shared objects come via policy scopes
  if (!pano.sharedObjs) pano.sharedObjs = readObjects(pano.shared, "shared");
  const sharedPano = pano.sharedObjs;
  const dgDefault = ctxSpec.dg || null;
  const vsysForJoin = entries(ch(deviceNode, "vsys")).map((n) => ({ name: n.a.name, display: txt(ch(n, "display-name")) || n.a.name, isSG: false }));
  const dgJoin = inferDgVsysJoin(vsysForJoin, ctxSpec.dgMap || {});
  const resolvedDgMap = Object.assign({}, ctxSpec.dgMap);
  for (const [name, j] of Object.entries(dgJoin.map || {})) if (j && j.dg && resolvedDgMap[name] == null) resolvedDgMap[name] = j.dg;
  function policyFor(vsysName, isSG) {
    const dgName = (resolvedDgMap && (resolvedDgMap[vsysName] || resolvedDgMap["*"])) || dgDefault;
    const ck = (dgName || "") + "|" + (isSG ? 1 : 0);
    if (pano.policyCache && pano.policyCache.has(ck)) return pano.policyCache.get(ck);
    const r = policyForUncached(dgName, isSG);
    if (pano.policyCache) pano.policyCache.set(ck, r);
    return r;
  }
  function policyForUncached(dgName, isSG) {
    const chain = dgName ? dgChain(pano, dgName) : [];
    const scopes = chain.slice().reverse().map((dg) => { if (!dg.objs) dg.objs = readObjects(dg.node, "DG " + dg.name); return dg.objs; }); // leaf first
    const pre = { security: [], nat: [], pbf: [] }, post = { security: [], nat: [], pbf: [] };
    const sh = pano.shared;
    const addRb = (node, label, into, prefix) => {
      into.security.push(...parseSecRules(at(node, prefix + "/security/rules"), label));
      into.nat.push(...parseNatRules(at(node, prefix + "/nat/rules"), label));
      into.pbf.push(...parsePbfRules(at(node, prefix + "/pbf/rules"), label));
    };
    addRb(sh, "shared pre-rulebase", pre, "pre-rulebase");
    for (const dg of chain) addRb(dg.node, "DG " + dg.name + " pre-rulebase", pre, "pre-rulebase");
    for (const dg of chain.slice().reverse()) addRb(dg.node, "DG " + dg.name + " post-rulebase", post, "post-rulebase");
    addRb(sh, "shared post-rulebase", post, "post-rulebase");
    let defaults = null;
    for (const node of [sh].concat(chain.map((d) => d.node))) for (const e of entries(at(node, "post-rulebase/default-security-rules/rules"))) {
      const a = txt(ch(e, "action")); if (!a) continue; defaults = defaults || {};
      if (/intrazone/.test(e.a.name)) defaults.intrazone = a; if (/interzone/.test(e.a.name)) defaults.interzone = a;
    }
    return { scopes: scopes.concat([sharedPano]), rules: isSG ? { pre: { security: [], nat: pre.nat, pbf: pre.pbf }, post: { security: [], nat: post.nat, pbf: post.pbf } } : { pre, post }, label: dgName ? "DG " + dgName : null, defaults, dg: dgName };
  }
  const name = ctxSpec.serial ? (ctxSpec.hostname || ctxSpec.serial) : (ctxSpec.stack || ctxSpec.template);
  if (ctxSpec.noNetwork) deviceNode.c = deviceNode.c.filter((x) => x.t !== "network");
  const dev = buildDevice({ id: loaded.fileName + "#" + ctxSpec.id + "#" + (dgDefault || ""), name, kind: "panorama", file: loaded.fileName, serial: ctxSpec.serial, deviceNode, sharedNode: shared, vars, vsysPolicy: policyFor,
    panorama: { stack: ctxSpec.stack, template: ctxSpec.template, serial: ctxSpec.serial, hostname: ctxSpec.hostname || null, dgMap: resolvedDgMap, dg: dgDefault, dgJoin } });
  dev.hostname = ctxSpec.hostname || ctxSpec.hostnameTpl || null; dev.stack = ctxSpec.stack || null;
  if (!ctxSpec.hostname && ctxSpec.hostnameTpl) dev.hostnameFrom = "template";
  if (ctxSpec.hostnameInit) dev.hostnameInit = ctxSpec.hostnameInit;
  dev.dgJoin = dgJoin;
  for (const v of dev.vsys.values()) {
    const j = dgJoin.map[v.name];
    v.dg = policyFor(v.name, v.isSG).dg;
    if (j) { v.dgVsys = j.dgVsys; v.dgJoinConfidence = j.confidence; v.dgJoinReason = j.reason; }
  }
  dev.stack = ctxSpec.stack || ctxSpec.template;
  return dev;
}
/* Join device-group vsys names (often vsys1..vsysN) to template vsys names (often descriptive).
   Prefer an exact name or display-name match. If those fail and the unmatched counts are equal,
   map by vsys number / template order and flag the result as inferred (uncertain). */
function inferDgVsysJoin(vsysList, dgMap) {
  const map = {}, notes = [];
  const used = new Set();
  const keys = Object.keys(dgMap || {}).filter((k) => k !== "*");
  const take = (tName, dgVsys, confidence, reason) => {
    if (!tName || map[tName] || !dgVsys || used.has(dgVsys) || dgMap[dgVsys] == null) return false;
    map[tName] = { dg: dgMap[dgVsys], dgVsys, confidence, reason };
    used.add(dgVsys);
    return true;
  };
  for (const v of vsysList || []) {
    if (v.isSG) continue;
    if (dgMap[v.name] != null) take(v.name, v.name, "high", "device-group vsys name matches the template vsys");
    else if (v.display && dgMap[v.display] != null) take(v.name, v.display, "high", "device-group vsys name matches the vsys display-name");
  }
  const leftoverT = (vsysList || []).filter((v) => !v.isSG && !map[v.name]);
  const leftoverK = keys.filter((k) => !used.has(k));
  const nums = leftoverK.map((k) => { const m = /^vsys(\d+)$/i.exec(k); return m ? { k, n: Number(m[1]) } : null; }).filter(Boolean);
  if (leftoverT.length && nums.length === leftoverK.length && nums.length === leftoverT.length) {
    nums.sort((a, b) => a.n - b.n);
    leftoverT.forEach((v, i) => take(v.name, nums[i].k, "inferred", "inferred by order and count: the device group lists " + leftoverK.length + " vsys (" + nums[0].k + "–" + nums[nums.length - 1].k + ") and the template has the same number of unmatched vsys"));
    notes.push({ level: "warn", text: "Device-group vsys names (vsysN) do not match template vsys names; joined by order and count. Confirm the placement before pushing." });
  } else if (leftoverT.length && leftoverK.length) {
    notes.push({ level: "warn", text: "Could not join template vsys " + leftoverT.map((v) => v.name).join(", ") + " to device-group vsys " + leftoverK.join(", ") + ". Device-group placement for a change on those vsys is uncertain." });
  }
  for (const v of vsysList || []) if (!v.isSG && !map[v.name] && dgMap && dgMap["*"] != null) map[v.name] = { dg: dgMap["*"], dgVsys: "*", confidence: "high", reason: "device group applies to all vsys of this firewall" };
  return { map, notes, uncertain: notes.length > 0 };
}

/* ------------------------------------------------------------------ routing */
function vrOwner(dev, vr, cur) {
  if (vr.owner) return vr.owner;
  if (vr.sharedOwners && vr.sharedOwners.includes(cur)) return cur;
  return (vr.sharedOwners && vr.sharedOwners[0]) || cur;
}
function lookupRoute(vr, q) {
  let best = null, ties = [];
  for (const r of vr.routes) {
    if (!(r.dest.lo <= q.lo && r.dest.hi >= q.lo)) continue;
    const len = r.dest.len == null ? 32 : r.dest.len;
    const key = [len, -r.ad, -r.metric];
    if (!best || key[0] > best.k[0] || (key[0] === best.k[0] && (key[1] > best.k[1] || (key[1] === best.k[1] && key[2] > best.k[2])))) { best = { r, k: key }; ties = [r]; }
    else if (key[0] === best.k[0] && key[1] === best.k[1] && key[2] === best.k[2]) ties.push(r);
  }
  if (!best) return null;
  return { route: best.r, ecmp: ties.length > 1 ? ties : null, partial: !(best.r.dest.hi >= q.hi) };
}
/* Follow routes (and next-vr hops inside the same vsys) until an egress interface or a vsys boundary. */
function resolveForward(dev, vrName, q, ctxName) {
  const vrPath = [];
  let vr = dev.vrs.get(vrName);
  for (let guard = 0; guard < 10; guard++) {
    if (!vr) return { kind: "none", vrPath, why: "router " + vrName + " not found", vr: vrName };
    const lr = lookupRoute(vr, q);
    if (!lr) return { kind: "none", vrPath, vr: vr.name, dynamic: vr.dynamic.length > 0, why: "no route to " + prefixStr(q) + " in " + vr.name };
    const r = lr.route; vrPath.push({ vr: vr.name, route: r, ecmp: lr.ecmp, partial: lr.partial });
    const nh = r.nexthop;
    if (nh.type === "next-vr") {
      const t = dev.vrs.get(nh.value);
      if (!t) return { kind: "none", vrPath, vr: vr.name, why: "route " + r.name + " points to unknown router " + nh.value };
      const own = vrOwner(dev, t, ctxName);
      if (own !== ctxName) return { kind: "vsys", targetCtx: own, targetVr: t.name, vrPath, route: r };
      vr = t; continue;
    }
    if (nh.type === "discard") return { kind: "discard", vrPath, route: r };
    if (nh.type === "fqdn") return { kind: "unresolved", vrPath, route: r, why: "route " + r.name + " uses FQDN next hop " + nh.value };
    if (nh.type === "local") return withOwner(dev, { kind: "local", iface: r.iface, vrPath, route: r }, ctxName);
    if (nh.type === "connected") return withOwner(dev, { kind: "iface", iface: r.iface, nexthop: null, direct: true, vrPath, route: r }, ctxName);
    let iface = r.iface, nhip = nh.type === "ip" ? nh.value : null;
    if (!iface && nhip) {
      const nq = parsePrefix(nhip);
      const c = nq && lookupRoute(vr, nq);
      if (c && (c.route.type === "connected" || c.route.type === "local")) iface = c.route.iface;
      else if (c && c.route.iface) iface = c.route.iface;
    }
    if (!iface) return { kind: "unresolved", vrPath, route: r, why: "next hop " + (nhip || "?") + " is not on a connected subnet of " + vr.name };
    return withOwner(dev, { kind: "iface", iface, nexthop: nhip, direct: false, vrPath, route: r }, ctxName);
  }
  return { kind: "loop", vrPath, why: "routing loop between virtual routers" };
}
function withOwner(dev, res, ctxName) {
  const it = dev.interfaces.get(res.iface);
  res.ifObj = it || null;
  if (it && it.vsys && it.vsys !== ctxName) { res.crossCtx = it.vsys; }
  return res;
}
function externalZone(dev, fromCtx, toCtx) {
  const c = dev.vsys.get(fromCtx); if (!c) return null;
  for (const z of c.zones.values()) if (z.type === "external" && z.members.includes(toCtx)) return z.name;
  return null;
}
function ifaceIpIn(it, q) { return it.ips.find((ip) => { const size = Math.pow(2, 32 - ip.len), lo = Math.floor(ip.ip / size) * size; return q.lo >= lo && q.hi <= lo + size - 1; }); }

/* ------------------------------------------------------------------ policy evaluation */
function cached(rule, key, fn) { if (!rule._c) Object.defineProperty(rule, "_c", { value: {}, enumerable: false }); if (!(key in rule._c)) rule._c[key] = fn(); return rule._c[key]; }
function zoneOk(list, z) { return list.includes("any") || list.includes(z); }
function svcMatch(rule, scopes, q, uid) {
  const svc = cached(rule, "svc" + uid, () => resolveServices(rule.service.length ? rule.service : ["any"], scopes));
  const anyApp = !rule.application || !rule.application.length || rule.application.includes("any");
  const reasons = [];
  let m = "yes";
  if (svc.any) m = "yes";
  else if (svc.appDefault) {
    if (anyApp) { m = "maybe"; reasons.push("service application-default with application any: allowed only on the identified app's default port"); }
    else {
      const ex = cached(rule, "apps" + uid, () => expandApps(rule.application, scopes));
      let hit = false, unknown = ex.filters.length > 0;
      for (const a of ex.apps) { const d = appDefaultDefs(a, scopes); if (!d) { unknown = true; continue; } if (svcMatchesQuery(d, q)) hit = true; }
      if (hit) m = "yes"; else if (unknown) { m = "maybe"; reasons.push("default ports of " + ex.apps.concat(ex.filters).join(", ") + " not known offline"); } else m = "no";
    }
  } else {
    if (svcMatchesQuery(svc.defs, q)) m = "yes";
    else if (svc.unresolved.length) { m = "maybe"; reasons.push("service " + svc.unresolved.join(", ") + " not found"); }
    else m = "no";
    if (m === "yes" && svc.srcPort) reasons.push("service restricts source port");
  }
  let appDep = false;
  if (m !== "no" && !anyApp) { appDep = true; reasons.push("only if App-ID identifies " + rule.application.join(", ")); }
  return { m, reasons, appDep };
}
let IGNORE_INTRA = false; // opts.ignoreIntrazoneDefault for the current trace(): the predefined intrazone allow counts as "no rule"
function evalSecurity(ctx, fromZ, toZ, srcQ, dstQ, svcQ) {
  const out = { decision: null, maybes: [], evaluated: 0 };
  for (const r of ctx.security) {
    if (r.disabled) continue;
    out.evaluated++;
    if (!zoneOk(r.from, fromZ) || !zoneOk(r.to, toZ)) continue;
    if (r.ruleType === "intrazone" && fromZ !== toZ) continue;
    if (r.ruleType === "interzone" && fromZ === toZ) continue;
    const sm = addrMatch(cached(r, "src" + ctx.uid, () => resolveAddrs(r.source, ctx.scopes)), srcQ, r.negSrc);
    if (sm.m === "no") continue;
    const dm = addrMatch(cached(r, "dst" + ctx.uid, () => resolveAddrs(r.destination, ctx.scopes)), dstQ, r.negDst);
    if (dm.m === "no") continue;
    const sv = svcMatch(r, ctx.scopes, svcQ, ctx.uid);
    if (sv.m === "no") continue;
    const reasons = [];
    if (sm.why) reasons.push("source: " + sm.why);
    if (dm.why) reasons.push("destination: " + dm.why);
    reasons.push(...sv.reasons.filter((x) => !/source port/.test(x) || true));
    if (r.srcUser.length && !r.srcUser.includes("any")) reasons.push("only for users " + r.srcUser.join(", "));
    if (r.hip.length && !r.hip.includes("any")) reasons.push("only for HIP " + r.hip.join(", "));
    if (r.category.length && !r.category.includes("any")) reasons.push("only for URL category " + r.category.join(", "));
    const definite = sm.m === "yes" && dm.m === "yes" && sv.m === "yes" && !sv.appDep && !reasons.some((x) => /^only for/.test(x)) && !(sv.reasons.length && /application-default/.test(sv.reasons[0]));
    const entry = { rule: r, reasons, appDep: sv.appDep, action: normAction(r.action) };
    if (definite) { out.decision = Object.assign({ kind: "rule" }, entry); break; }
    out.maybes.push(entry);
  }
  if (!out.decision) {
    const intra = fromZ === toZ;
    out.decision = { kind: "default", rule: { name: intra ? "intrazone-default" : "interzone-default", scope: "predefined" }, action: normAction(intra ? ctx.defaults.intrazone : ctx.defaults.interzone), reasons: [] };
    if (intra && IGNORE_INTRA && out.decision.action === "allow") { out.decision.action = "deny"; out.decision.ignoredDefault = true; }
  }
  const firstMaybe = out.maybes[0];
  out.verdict = out.decision.action;
  if (out.maybes.some((m) => m.action !== out.decision.action)) out.verdict = "conditional";
  out.conditionalRule = firstMaybe || null;
  return out;
}
function normAction(a) { return /allow/.test(a || "") ? "allow" : "deny"; }

function resolveSingleIp(name, scopes, notes, dev, ctx) {
  if (!name) return null;
  let p = parsePrefix(name);
  if (!p) {
    const o = lookupObj(scopes, "address", name);
    if (o && o.v.type === "fqdn") { notes.push({ level: "warn", text: "NAT translated address " + name + " is an FQDN (" + o.v.value + "); cannot resolve offline." }); return null; }
    if (o) p = parsePrefix(o.v.value);
    else {
      const g = resolveAddrs([name], scopes); if (g.ranges.length) p = g.ranges[0];
    }
  }
  return p;
}
/* A NAT rule's to-zone holds a DHCP/PPPoE interface whose connected subnet is learned at runtime (not in the config). When
   the original destination is not in any configured connected subnet, only matches a route broader than /24, and the
   firewall owns another address of that /24 in the to-zone (loopback/secondary/proxy-ARP block), PAN-OS most likely
   resolves it on the runtime connected subnet of the DHCP interface: return that zone (and interface), else null. */
function runtimeSubnetZone(dev, vsysName, ip, toZones) {
  if (!toZones || !toZones.length || toZones.includes("any")) return null;
  let dh = null, own = false;
  for (const it of dev.interfaces.values()) {
    if (it.vsys !== vsysName || !it.zone || !toZones.includes(it.zone)) continue;
    if (it.dhcp && !it.ips.length && !dh) dh = it;
    for (const a of it.ips) if (a.ip >>> 8 === ip >>> 8) own = true;
  }
  if (!dh || !own) return null;
  for (const it of dev.interfaces.values()) for (const a of it.ips) { const len = a.len == null ? 32 : a.len; if (len < 32 && ((ip ^ a.ip) >>> (32 - len)) === 0) return null; }
  const f = resolveForward(dev, dh.vr || dev.vrs.keys().next().value, { lo: ip, hi: ip, len: 32, ip }, vsysName);
  const last = f && f.vrPath && f.vrPath[f.vrPath.length - 1], len = last && last.route && last.route.dest ? (last.route.dest.len == null ? 32 : last.route.dest.len) : 0;
  if (len >= 24) return null;
  return { zone: dh.zone, iface: dh.name };
}
function evalNat(dev, ctx, fromZ, toZ, egIf, srcQ, dstQ, svcQ, notes) {
  const maybes = [];
  for (const r of ctx.nat) {
    if (r.disabled || r.natType !== "ipv4") continue;
    if (r.snat && r.snat.type === "static-ip" && r.snat.bidir && zoneOk(r.to, toZ)) {
      // bi-directional static NAT: implicit reverse rule (any -> original to-zone, dst = translated address)
      const tr = resolveSingleIp(r.snat.addrs[0], ctx.scopes, notes);
      if (tr && rngContains(tr, dstQ)) {
        const orig = resolveAddrs(r.source, ctx.scopes).ranges[0];
        if (orig) { const ip = orig.lo + (dstQ.lo - tr.lo); return { rule: r, reverse: true, dnat: { ip, port: null, text: n2ip(ip) }, snat: null, maybes }; }
      }
    }
    if (!zoneOk(r.from, fromZ)) continue;
    let rtz = null;
    if (!zoneOk(r.to, toZ)) { if (!r.dnat || !(rtz = runtimeSubnetZone(dev, ctx.name, dstQ.lo, r.to))) continue; }
    if (r.toIf && r.toIf !== "any" && (rtz ? rtz.iface : egIf) && r.toIf !== (rtz ? rtz.iface : egIf)) continue;
    const sm = addrMatch(cached(r, "src" + ctx.uid, () => resolveAddrs(r.source, ctx.scopes)), srcQ, false);
    const dm = addrMatch(cached(r, "dst" + ctx.uid, () => resolveAddrs(r.destination, ctx.scopes)), dstQ, false);
    if (sm.m === "no" || dm.m === "no") continue;
    if (r.service && r.service !== "any") {
      const sv = resolveServices([r.service], ctx.scopes);
      if (!sv.any && !svcMatchesQuery(sv.defs, svcQ)) continue;
    }
    if (sm.m === "maybe" || dm.m === "maybe") { maybes.push({ rule: r, why: [sm.why, dm.why].filter(Boolean).join("; ") }); continue; }
    const res = { rule: r, snat: null, dnat: null, maybes };
    if (rtz) notes.push({ level: "info", text: "NAT rule " + r.name + ": " + n2ip(dstQ.lo) + " routes to zone " + toZ + " by the config, but zone " + rtz.zone + " has DHCP interface " + rtz.iface + " (subnet learned at runtime) and the firewall owns an address in the same /24 there; assuming the address is on that runtime subnet." });
    if (r.snat) {
      let ip = null;
      if (r.snat.iface) {
        const it = dev.interfaces.get(r.snat.iface);
        const p = r.snat.ip ? parsePrefix(r.snat.ip) : null;
        ip = p ? p.ip : it && it.ips[0] ? it.ips[0].ip : null;
        if (ip == null) notes.push({ level: "warn", text: "Source NAT uses interface " + r.snat.iface + " address, which is not in the config (DHCP?)." });
      } else if (r.snat.addrs && r.snat.addrs.length) {
        const p = resolveSingleIp(r.snat.addrs[0], ctx.scopes, notes);
        if (p) ip = r.snat.type === "static-ip" && p.len != null && p.hi > p.lo ? p.lo + (srcQ.lo - (cached(r, "src" + ctx.uid, () => resolveAddrs(r.source, ctx.scopes)).ranges[0] || srcQ).lo) : p.lo;
        if (p && p.hi > p.lo && r.snat.type !== "static-ip") notes.push({ level: "info", text: "Source NAT pool " + r.snat.addrs.join(",") + " has several addresses; showing the first." });
      }
      res.snat = { type: r.snat.type, ip, text: ip != null ? n2ip(ip) : "(unknown)" };
    }
    if (r.dnat) {
      const p = resolveSingleIp(r.dnat.addr, ctx.scopes, notes);
      let ip = p ? p.lo : null;
      if (p && p.hi > p.lo && !r.dnat.dynamic) { // static translation of a range/subnet maps 1:1 when the original range has the same size
        const o = cached(r, "dst" + ctx.uid, () => resolveAddrs(r.destination, ctx.scopes)).ranges.find((x) => x.lo <= dstQ.lo && x.hi >= dstQ.lo);
        if (o && o.hi - o.lo === p.hi - p.lo) ip = p.lo + (dstQ.lo - o.lo);
      }
      res.dnat = { ip, port: r.dnat.port, text: ip != null ? n2ip(ip) : r.dnat.addr, dynamic: r.dnat.dynamic };
      if (r.dnat.dynamic) notes.push({ level: "info", text: "NAT rule " + r.name + " uses dynamic destination translation (FQDN/pool); showing the first address." });
    }
    return res;
  }
  return { rule: null, maybes };
}
/* The traced destination is the translated (post-NAT) address of a destination NAT rule (or the private side of a
   bi-directional static NAT) that applies to traffic arriving in inZone: clients really connect to the pre-NAT address.
   Returns {rule, pre: range, port, preZone} with the address/port PAN-OS matches NAT and security policy on, or null. */
function inboundDnatFor(dev, ctx, inZone, srcQ, dstQ, svcQ) {
  const zoneOfPre = (p) => { const f = resolveForward(dev, inVr(dev, ctx), p, ctx.name); const it = f && (f.ifObj || (f.iface && dev.interfaces.get(f.iface))); return { zone: it ? it.zone : null, iface: it ? it.name : null }; };
  for (const r of ctx.nat) {
    if (r.disabled || r.natType !== "ipv4") continue;
    if (r.dnat) {
      if (!zoneOk(r.from, inZone)) continue;
      const t = resolveSingleIp(r.dnat.addr, ctx.scopes, []); if (!t || !rngContains(t, dstQ)) continue;
      const typedPre = r.dnat.port && svcQ.port != null && svcQ.port !== r.dnat.port; // the query names the pre-NAT (public) port
      if (typedPre && (!r.service || r.service === "any")) continue;
      if (addrMatch(cached(r, "src" + ctx.uid, () => resolveAddrs(r.source, ctx.scopes)), srcQ, false).m === "no") continue;
      const O = cached(r, "dst" + ctx.uid, () => resolveAddrs(r.destination, ctx.scopes)); if (O.any || !O.ranges.length) continue;
      const o = O.ranges.find((x) => x.hi - x.lo === t.hi - t.lo) || O.ranges[0];
      // a private client naming a private server behind a public VIP (U-turn) most likely means the direct path: do not assume NAT
      if (isPrivateN(srcQ.lo) && !isPrivateN(o.lo)) continue;
      const ip = o.hi - o.lo === t.hi - t.lo ? o.lo + (dstQ.lo - t.lo) : o.lo;
      let port = svcQ.port;
      if (r.dnat.port && !typedPre && r.service && r.service !== "any") { const sv = resolveServices([r.service], ctx.scopes); const d0 = (sv.defs || []).find((d) => d.ports && d.ports.length); if (d0) port = d0.ports[0][0]; }
      if (r.service && r.service !== "any") { const sv = resolveServices([r.service], ctx.scopes); if (!sv.any && !svcMatchesQuery(sv.defs, Object.assign({}, svcQ, { port }))) continue; }
      const pre = { lo: ip, hi: ip, len: 32, ip }, z = zoneOfPre(pre);
      if (z.zone && !zoneOk(r.to, z.zone)) { const rz = runtimeSubnetZone(dev, ctx.name, ip, r.to); if (!rz) continue; z.zone = rz.zone; z.iface = rz.iface; }
      if (r.toIf && r.toIf !== "any" && z.iface && r.toIf !== z.iface) continue;
      return { rule: r, pre, port, preZone: z.zone, postPort: r.dnat.port || null };
    }
    if (r.snat && r.snat.type === "static-ip" && r.snat.bidir) {
      const S = cached(r, "src" + ctx.uid, () => resolveAddrs(r.source, ctx.scopes)); const o = S.ranges.find((x) => rngContains(x, dstQ)); if (!o) continue;
      const t = resolveSingleIp(r.snat.addrs[0], ctx.scopes, []); if (!t) continue;
      const ip = t.hi - t.lo === o.hi - o.lo ? t.lo + (dstQ.lo - o.lo) : t.lo, pre = { lo: ip, hi: ip, len: 32, ip }, z = zoneOfPre(pre);
      if (!z.zone || !zoneOk(r.to, z.zone) || z.zone !== inZone && !r.to.includes("any") && !looksInternet(inZone) && !r.to.includes(inZone)) continue;
      return { rule: r, pre, port: svcQ.port, preZone: z.zone, bidir: true };
    }
  }
  return null;
}
/* Internet source to a destination NAT'd server: the firewall whose NAT rule owns the address (pre- or post-NAT), entered on
   the interface its routing uses toward the source, when that interface is in the NAT rule's from-zone and the pre-NAT
   address routes into the NAT rule's to-zone there. */
function dnatEntries(devices, src, dst) {
  const out = [];
  for (const dev of devices) for (const ctx of dev.vsys.values()) {
    if (!ctx.nat || !ctx.nat.length) continue;
    for (const r of ctx.nat) {
      if (r.disabled || !r.dnat || r.natType !== "ipv4") continue;
      const O = cached(r, "dst" + ctx.uid, () => resolveAddrs(r.destination, ctx.scopes)); if (O.any || !O.ranges.length) continue;
      const t = resolveSingleIp(r.dnat.addr, ctx.scopes, []);
      const byPost = t && rngContains(t, dst), byPre = O.ranges.some((x) => rngContains(x, dst));
      if (!byPost && !byPre) continue;
      if (addrMatch(cached(r, "src" + ctx.uid, () => resolveAddrs(r.source, ctx.scopes)), src, false).m === "no") continue;
      const zs = zoneOfAddr(dev, ctx.name, src.lo), zd = zoneOfAddr(dev, ctx.name, byPre ? dst.lo : O.ranges[0].lo);
      if (!zs || !zoneOk(r.from, zs) || (zd && !zoneOk(r.to, zd) && !runtimeSubnetZone(dev, ctx.name, byPre ? dst.lo : O.ranges[0].lo, r.to))) continue;
      const vr = inVr(dev, ctx), f = resolveForward(dev, vr, src, ctx.name), it = f && f.kind === "iface" ? dev.interfaces.get(f.iface) : null;
      if (!it || it.zone !== zs) continue;
      if (!out.some((x) => x.dev === dev)) out.push({ dev, iface: it, rule: r, byPost });
      break;
    }
  }
  return out;
}
function inVr(dev, ctx) { for (const it of dev.interfaces.values()) if (it.vsys === ctx.name && it.vr) return it.vr; return dev.vrs.keys().next().value; }
function evalPbf(ctx, inZone, inIf, srcQ, dstQ, svcQ) {
  for (const r of ctx.pbf) {
    if (r.disabled) continue;
    if (r.fromZones.length && !r.fromZones.includes(inZone) && !r.fromZones.includes("any")) continue;
    if (r.fromIfs.length && !r.fromIfs.includes(inIf)) continue;
    const sm = addrMatch(resolveAddrs(r.source, ctx.scopes), srcQ, false), dm = addrMatch(resolveAddrs(r.destination, ctx.scopes), dstQ, false);
    if (sm.m !== "yes" || dm.m !== "yes") continue;
    const sv = resolveServices(r.service.length ? r.service : ["any"], ctx.scopes);
    if (!sv.any && !sv.appDefault && !svcMatchesQuery(sv.defs, svcQ)) continue;
    return { rule: r, appDep: r.application.length && !r.application.includes("any") };
  }
  return null;
}

/* ------------------------------------------------------------------ query */
function parseQuery(q, devices) {
  const err = [];
  const resolveSide = (v, label) => {
    v = String(v || "").trim();
    if (!v) { err.push(label + " is required"); return null; }
    let p = parsePrefix(v);
    if (p) return { p, text: hostOrPrefix(p) };
    // address object name
    for (const d of devices) for (const c of d.vsys.values()) {
      const r = resolveAddrs([v], c.scopes);
      if (r.ranges.length === 1 && !r.unresolved.length) return { p: r.ranges[0], text: v + " (" + hostOrPrefix(r.ranges[0]) + ")", obj: v };
      if (r.ranges.length > 1) { const lo = Math.min(...r.ranges.map((x) => x.lo)), hi = Math.max(...r.ranges.map((x) => x.hi)); err.push(label + " object " + v + " has " + r.ranges.length + " separate ranges; trace one at a time (" + r.ranges.slice(0, 4).map(prefixStr).join(", ") + ")"); return null; }
      if (r.unresolved.length && r.unresolved[0].why !== "object not found in config") { err.push(label + " " + v + ": " + r.unresolved[0].why); return null; }
    }
    err.push(label + " '" + v + "' is not an IPv4 address, subnet, range, or known address object" + (isV6(v) ? " (IPv6 is not supported yet)" : ""));
    return null;
  };
  const s = resolveSide(q.src, "Source"), d = resolveSide(q.dst, "Destination");
  const proto = (q.proto || "tcp").toLowerCase();
  let port = q.port === "" || q.port == null ? null : Number(q.port);
  if (port != null && !(port >= 0 && port <= 65535)) err.push("Port must be 0-65535");
  if (proto === "icmp" || proto === "any") port = null;
  return { err, src: s, dst: d, svc: { proto, port } };
}
function svcText(svc) { return svc.proto === "any" ? "any" : svc.proto + (svc.port != null ? "/" + svc.port : ""); }

/* Find where the source enters. */
function findIngress(devices, srcQ, opts) {
  const pool = opts.deviceId ? devices.filter((d) => d.id === opts.deviceId) : devices;
  if (opts.ingress) {
    const [devId, ifn] = opts.ingress.split("|");
    const d = devices.find((x) => x.id === devId); const it = d && d.interfaces.get(ifn);
    if (it) return { dev: d, iface: it, how: "chosen by you", alternatives: [] };
  }
  const cands = [];
  for (const d of pool) for (const it of d.interfaces.values()) {
    if (!it.vr) continue;
    for (const ip of it.ips) {
      const size = Math.pow(2, 32 - ip.len), lo = Math.floor(ip.ip / size) * size;
      if (srcQ.lo >= lo && srcQ.hi <= lo + size - 1) cands.push({ dev: d, iface: it, len: ip.len, how: "source is on connected subnet " + n2ip(lo) + "/" + ip.len + (ip.ip === srcQ.lo && srcQ.lo === srcQ.hi ? " (source is the firewall interface itself)" : "") });
    }
  }
  if (!cands.length) {
    for (const d of pool) for (const vr of new Set(d.vrs.values())) {
      const lr = lookupRoute(vr, srcQ); if (!lr) continue;
      const own = vrOwner(d, vr, vr.owner || (d.vsys.keys().next().value));
      const res = resolveForward(d, vr.name, srcQ, own);
      if (res.kind !== "iface" || !res.ifObj) continue;
      const isDefault = (lr.route.dest.len || 0) === 0;
      cands.push({ dev: d, iface: res.ifObj, len: lr.route.dest.len == null ? 32 : lr.route.dest.len, isDefault, how: "reverse route lookup in " + vr.name + " (" + prefixStr(lr.route.dest) + (res.nexthop ? " via " + res.nexthop : "") + ")" });
    }
  }
  if (!cands.length) return null;
  cands.sort((a, b) => b.len - a.len);
  const best = cands[0];
  const seen = new Set([best.dev.id + "|" + best.iface.name]);
  const alts = cands.filter((c) => c.len === best.len && !seen.has(c.dev.id + "|" + c.iface.name) && seen.add(c.dev.id + "|" + c.iface.name));
  return { dev: best.dev, iface: best.iface, how: best.how, alternatives: alts, isDefault: best.isDefault };
}
function findDeviceByIp(devices, ipn, exceptDev) {
  for (const d of devices) {
    if (d === exceptDev) continue;
    for (const it of d.interfaces.values()) for (const ip of it.ips) if (ip.ip === ipn) return { dev: d, iface: it };
  }
  return null;
}


/* ------------------------------------------------------------------ multi-firewall stitching */
function destFirewalls(devices, dst) {
  const out = [];
  for (const d of devices) for (const it of d.interfaces.values()) if (it.vr && ifaceIpIn(it, dst) && !(it.ips.some((ip) => ip.len === 32))) out.push({ devId: d.id, device: d.name, iface: it.name, vsys: it.vsys, zone: it.zone });
  return out;
}
function destInfo(B, dst) {
  let connected = null, len = -1;
  for (const it of B.interfaces.values()) if (it.vr && it.ips.some((ip) => ip.len < 32) && ifaceIpIn(it, dst)) { connected = it; break; }
  for (const vr of new Set(B.vrs.values())) { const lr = lookupRoute(vr, dst); if (lr && lr.route.nexthop.type !== "discard" && lr.route.type !== "local") len = Math.max(len, lr.route.dest.len == null ? 32 : lr.route.dest.len); }
  return { connected, len };
}
function subnetOf(ip) { const sz = Math.pow(2, 32 - ip.len); return { lo: Math.floor(ip.ip / sz) * sz, len: ip.len }; }
/* Decide which loaded firewall receives traffic leaving `dev` on `egIf` toward `nh`. */
function stitchNext(devices, dev, egIf, nh, src, dst, visited, opts, usedRoute) {
  const key = dev.name + "|" + (egIf ? egIf.name : "?") + "|" + (nh || "");
  const nhN = nh ? ip2n(nh) : null;
  const cands = [];
  let loopNote = null;
  const egSubnets = egIf ? egIf.ips.filter((x) => x.len < 32).map(subnetOf) : [];
  const egDefault = !usedRoute || (usedRoute.dest.len || 0) === 0;
  const transitLabel = egIf && /^tunnel/.test(egIf.name) ? "IPsec/GRE tunnel " + egIf.name : (egSubnets.length ? "transit " + n2ip(egSubnets[0].lo) + "/" + egSubnets[0].len : "transit network") + (nh ? " via router " + nh : "");
  const push = (c) => {
    if (!c.iface || !c.iface.vsys) return;
    if (visited.has(c.dev.id)) { loopNote = loopNote || ("Path would return to " + c.dev.name + " (already traversed); ignored to prevent a loop."); return; }
    const ex = cands.find((x) => x.dev === c.dev);
    if (ex) { if (c.score > ex.score) Object.assign(ex, c); return; }
    cands.push(c);
  };
  for (const L of opts.links || []) {
    const f = L.from || {}, t = L.to || {};
    if (f.device && f.device !== dev.name) continue;
    if (!f.iface && !f.nexthop) continue;
    if (f.iface && (!egIf || f.iface !== egIf.name)) continue;
    if (f.nexthop && f.nexthop !== nh) continue;
    const B = devices.find((d) => d.name === t.device || d.id === t.device); if (!B || B === dev) continue;
    let iface = t.iface ? B.interfaces.get(t.iface) : null;
    if (!iface) { const ri = findIngress([B], src, {}); iface = ri && ri.iface; }
    push({ dev: B, iface, score: 1000, why: "user-defined link" + (L.label ? " '" + L.label + "'" : ""), via: { kind: "link", label: L.label || "user link" } });
  }
  for (const B of devices) {
    if (B === dev) continue;
    let direct = null, adj = null;
    for (const it of B.interfaces.values()) {
      if (!it.vr) continue;
      for (const ip of it.ips) {
        if (nhN != null && ip.ip === nhN) direct = it;
        if (ip.len < 32) {
          const sb = subnetOf(ip);
          const shared = egSubnets.some((e) => e.len === sb.len && e.lo === sb.lo);
          if (shared && !adj) adj = { it, sb };
        }
      }
    }
    const di = destInfo(B, dst);
    if (direct) { push({ dev: B, iface: direct, score: 900, why: "next hop " + nh + " is " + B.name + " " + direct.name, via: { kind: "direct", label: "next hop " + nh } }); continue; }
    if (adj) {
      const nhOnB = nhN == null || (nhN >= adj.sb.lo && nhN < adj.sb.lo + Math.pow(2, 32 - adj.sb.len));
      if (!nhOnB) continue;
      if (!di.connected && di.len <= 0) continue; // shares the subnet but only has a default route: not where the next hop leads
      const usedLen = usedRoute && usedRoute.dest ? (usedRoute.dest.len == null ? 32 : usedRoute.dest.len) : 0;
      if (!di.connected && di.len <= usedLen && !egDefault) continue; // must know the destination better than the firewall sending to it
      const score = di.connected ? 800 : 700 + di.len;
      push({ dev: B, iface: adj.it, score, why: "shares subnet " + n2ip(adj.sb.lo) + "/" + adj.sb.len + " with " + dev.name + (di.connected ? " and has the destination connected" : di.len > 0 ? " and routes the destination (/" + di.len + ")" : " (default route only)"),
        via: { kind: "segment", label: "shared subnet " + n2ip(adj.sb.lo) + "/" + adj.sb.len + (nh ? " via " + nh : "") } });
      continue;
    }
    if (!di.connected) continue; // without a shared subnet or next hop, only a firewall that has the destination connected is a credible continuation
    const ri = findIngress([B], src, {});
    if (!ri) continue;
    const bDefault = !!ri.isDefault;
    if (egDefault && bDefault) continue; // both sides only know each other by default route: not evidence of a path
    if (ri.iface && di.connected && ri.iface.name === di.connected.name) continue; // source side == destination side: not a transit path
    const score = (di.connected ? 600 : 400 + di.len) + (bDefault ? 0 : 20);
    push({ dev: B, iface: ri.iface, score, why: (di.connected ? "destination is connected on " + B.name + " " + di.connected.name : B.name + " routes the destination (/" + di.len + ")") + "; " + B.name + " reaches the source via " + ri.iface.name,
      via: { kind: "transit", label: transitLabel } });
  }
  cands.sort((a, b) => b.score - a.score);
  if (!cands.length) return { key, cands, chosen: null, loopNote };
  let chosen = cands[0];
  const forced = opts.choices && opts.choices[key];
  if (forced) chosen = cands.find((c) => c.dev.id === forced || c.dev.name === forced) || chosen;
  const ambiguous = !forced && cands.length > 1 && cands[1].score === cands[0].score && cands[0].score < 1000;
  return { key, cands, chosen, ambiguous, loopNote };
}

/* ------------------------------------------------------------------ dynamic routing inference
 * Learned routes are not in the config, but the BGP/OSPF config says who peers with whom and what
 * each router redistributes. We synthesize the routes each VR would most likely learn:
 *  - BGP to a router (MPLS PE / provider): every firewall VR peering into the same provider fabric
 *    (same provider AS, or iBGP to a reflector in the same AS) learns the others' advertisements
 *    with the PE as next hop. BGP to another firewall's interface: learns that VR's table directly.
 *  - OSPF: VRs with OSPF interfaces on a shared subnet are neighbours; routes flow across the area.
 * Routes are marked type inferred-bgp / inferred-ospf and treated as medium confidence. */
const INFER_DONE = typeof WeakMap !== "undefined" ? new WeakMap() : null;
function inferDynamicRoutes(devices) {
  if (INFER_DONE && INFER_DONE.has(devices)) return INFER_DONE.get(devices);
  const nm = (d) => d.hostname || d.name;
  const stats = { bgpSpeakers: 0, ospfSpeakers: 0, fabrics: 0, routes: 0, unresolvedPeers: 0 };
  const vrs = [];
  for (const d of devices) for (const vr of new Set(d.vrs.values())) {
    vr.routes = vr.routes.filter((r) => !r.inferred); delete vr.bgpWithheld;
    if (vr.proto && (vr.proto.bgp || vr.proto.ospf)) vrs.push({ dev: d, vr, uid: d.id + "/" + vr.name, learned: new Map() });
  }
  if (!vrs.length) { if (INFER_DONE) INFER_DONE.set(devices, stats); return stats; }
  const ipOwner = new Map(), ipOwners = new Map();
  for (const d of devices) for (const it of d.interfaces.values()) if (it.vr) for (const ip of it.ips) { ipOwner.set(ip.ip, { dev: d, iface: it }); if (!ipOwners.has(ip.ip)) ipOwners.set(ip.ip, []); if (!ipOwners.get(ip.ip).some((o) => o.dev === d)) ipOwners.get(ip.ip).push({ dev: d, iface: it }); }
  stats.ambiguousPeers = 0; stats.observedVrs = 0; stats.aggregates = 0; stats.conditional = 0;
  const byUid = new Map(vrs.map((x) => [x.uid, x]));
  const within = (p, q) => q.lo >= p.lo && q.hi <= p.hi;
  const subnetIfaceFor = (S, ipn) => { for (const n of S.vr.interfaces) { const it = S.dev.interfaces.get(n); if (it && it.ips.some((x) => x.len < 32 && ipn >= subnetOf(x).lo && ipn < subnetOf(x).lo + Math.pow(2, 32 - x.len))) return it.name; } return null; };
  const redistSet = (S, names, proto) => {
    const out = [];
    for (const name of names || []) {
      if (/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(name)) { const p = parsePrefix(name); if (p) out.push({ dest: p, src: "prefix", how: "redistributes " + prefixStr(p) + " (redistribution rule)" }); continue; }
      const prof = S.vr.proto.redist.get(name); if (!prof || !prof.redist) continue;
      const types = prof.types.length ? prof.types : ["connect", "static"];
      const F = S.vr.proto.bgp && S.vr.proto.bgp.filters, maps = prof.maps || {};
      const pool = S.vr.routes.concat([...S.learned.values()].map((l) => ({ dest: l.dest, type: "learned-" + l.proto, iface: l.iface })));
      for (const r of pool) {
        const ok = (r.type === "connected" && r.dest.len < 32 && types.includes("connect")) || (r.type === "static" && types.includes("static")) ||
          (r.type === "learned-ospf" && types.includes("ospf") && proto !== "ospf") || (r.type === "learned-bgp" && types.includes("bgp") && proto !== "bgp");
        if (!ok) continue;
        if (prof.ifaces.length && !prof.ifaces.includes(r.iface)) continue;
        if (prof.dests.length && !prof.dests.some((p) => within(p, r.dest))) continue;
        const kind = r.type === "connected" ? "connect" : r.type === "static" ? "static" : r.type.replace(/^learned-/, "");
        if (F && maps[kind] && F.redistMaps.has(maps[kind]) && !routeMapPermits(F, F.redistMaps.get(maps[kind]), r.dest)) continue;
        out.push({ dest: r.dest, src: r.type, how: "redistributes " + (r.type === "connected" ? "connected" : r.type.replace(/^learned-/, "")) + " " + prefixStr(r.dest) + " into " + (proto === "bgp" ? "BGP" : "OSPF") + " (profile " + name + (maps[kind] ? ", route map " + maps[kind] : "") + ")" });
      }
    }
    return out;
  };
  const policyAllows = (rules, group, dest) => {
    for (const r of rules || []) {
      if (r.usedBy.length && !r.usedBy.includes(group)) continue;
      const m = !r.prefixes.length || r.prefixes.some((x) => (x.exact ? x.p.lo === dest.lo && x.p.hi === dest.hi : within(x.p, dest)));
      if (m) return !r.deny;
    }
    return true;
  };
  // peers
  const fabrics = new Map(); // key -> [{S, peer}]
  for (const S of vrs) {
    const b = S.vr.proto.bgp; if (!b) continue;
    stats.bgpSpeakers++;
    S.peers = [];
    for (const pe of b.peers) {
      if (!pe.peerIp) { stats.unresolvedPeers++; continue; }
      const n = ip2n(pe.peerIp); let o = ipOwner.get(n);
      const iface = pe.localIf || subnetIfaceFor(S, n);
      const os = (ipOwners.get(n) || []).filter((x) => !(x.dev === S.dev && x.iface.vr === S.vr.name));
      if (os.length > 1) { // the peer address is configured on several firewalls (cloned builds / overlapping space): prefer one at the same site, else do not guess
        const site = siteOfDev(S.dev), same = os.filter((x) => site && siteOfDev(x.dev) === site);
        if (same.length === 1) o = same[0];
        else { stats.ambiguousPeers++; (S.ambiguous = S.ambiguous || []).push({ peerIp: pe.peerIp, owners: os.map((x) => x.dev.name) }); continue; }
      }
      const ebgp = pe.type !== "ibgp" && pe.peerAs !== b.localAs;
      if (o && o.dev === S.dev && o.iface.vr === S.vr.name) continue;
      if (o) { const T = byUid.get(o.dev.id + "/" + o.iface.vr); S.peers.push({ pe, kind: "fw", T, iface, ebgp }); continue; }
      const key = (ebgp ? "ebgp-as:" + (pe.peerAs || "?") : "ibgp-as:" + (b.localAs || "?"));
      if (!fabrics.has(key)) fabrics.set(key, []);
      fabrics.get(key).push({ S, pe, iface, ebgp });
      S.peers.push({ pe, kind: "fabric", key, iface, ebgp });
    }
  }
  stats.fabrics = fabrics.size;
  Object.defineProperty(stats, "fabricList", { enumerable: false, value: [...fabrics].map(([key, list]) => ({ key, ebgp: list.some((m) => m.ebgp), devIds: [...new Set(list.map((m) => m.S.dev.id))] })) });
  // OSPF adjacencies
  const ospfSeg = new Map();
  for (const S of vrs) {
    const o = S.vr.proto.ospf; if (!o) continue;
    stats.ospfSpeakers++;
    S.ospfIfs = [];
    for (const a of o.areas) for (const x of a.ifaces) {
      const it = S.dev.interfaces.get(x.name); if (!it || it.vr !== S.vr.name) continue;
      S.ospfIfs.push({ it, passive: x.passive });
      if (x.passive) continue;
      for (const ip of it.ips) if (ip.len < 32) { const k = subnetOf(ip).lo + "/" + ip.len; if (!ospfSeg.has(k)) ospfSeg.set(k, []); ospfSeg.get(k).push({ S, it, ip: ip.ip }); }
    }
  }
  const nbrCache = new Map();
  const ospfNbrs = (S) => { if (nbrCache.has(S)) return nbrCache.get(S); const out = []; nbrCache.set(S, out); for (const [k, list] of ospfSeg) { const me = list.find((x) => x.S === S); if (!me) continue; for (const x of list) if (x.S !== S) out.push({ T: x.S, nh: n2ip(x.ip), iface: me.it.name }); } return out; };
  for (const S of vrs) { S.conn = new Set(S.vr.routes.filter((r) => r.type === "connected" || r.type === "local").map((r) => r.dest.lo + "-" + r.dest.hi)); S.obs = S.vr.observedTable ? S.vr.routes.filter((r) => r.observed) : null; if (S.obs) stats.observedVrs++; }
  const learn = (S, l) => {
    const k = l.dest.lo + "/" + l.dest.len;
    const prev = S.learned.get(k);
    if (prev && (prev.ad < l.ad || (prev.ad === l.ad && prev.path.length <= l.path.length))) return false;
    if (S.conn.has(l.dest.lo + "-" + l.dest.hi)) return false;
    if (l.path.includes(S.uid)) return false;
    S.learned.set(k, l); return true;
  };
  // the peer entry on T that points back at S (used for T's export filters toward S)
  const backPeer = (T, S) => { const b = T.vr.proto.bgp; if (!b) return null; for (const pe of b.peers) { const n = ip2n(pe.peerIp || ""); if (n == null) continue; for (const nm of S.vr.interfaces) { const it = S.dev.interfaces.get(nm); if (it && it.ips.some((x) => x.ip === n)) return pe; } } return null; };
  const ribHas = (S, test) => S.vr.routes.some((r) => r.type !== "local" && test(r.dest)) || [...S.learned.values()].some((l) => test(l.dest)) || (S.obs || []).some((r) => test(r.dest));
  const bgpOut = (S, pe, fabricKey, dropped) => { // routes learned from a provider fabric are not sent back into it (AS-path loop / split horizon)
    const b = S.vr.proto.bgp; if (!b) return [];
    const group = pe ? pe.group : null;
    const own = redistSet(S, b.redistRules, "bgp").map((x) => ({ dest: x.dest, origin: S, path: [S.uid], how: x.how }));
    for (const p of b.networks || []) if (b.alwaysAdvertiseNetwork || ribHas(S, (d) => d.lo === p.lo && d.hi === p.hi)) own.push({ dest: p, origin: S, path: [S.uid], how: "advertises network " + prefixStr(p) + (b.alwaysAdvertiseNetwork ? " (always-advertise)" : " (network statement; the prefix is in its table)") });
    const fwd = [...S.learned.values()].filter((l) => l.proto === "bgp" && !(fabricKey && l.fabric === fabricKey)).map((l) => ({ dest: l.dest, origin: l.origin, path: l.path.concat([S.uid]), how: l.how, cond: l.cond }))
      .concat((S.obs || []).filter((r) => r.observed.proto === "bgp").map((r) => ({ dest: r.dest, origin: S, path: [S.uid], how: "re-advertises BGP route " + prefixStr(r.dest) + " seen in its pasted route table" })));
    let list = own.concat(fwd);
    for (const ag of b.aggregates || []) {
      const contrib = list.filter((x) => within(ag.prefix, x.dest) && (x.dest.len || 0) > ag.prefix.len);
      if (!contrib.length) continue;
      stats.aggregates++;
      if (ag.summaryOnly) list = list.filter((x) => !contrib.includes(x));
      if (!list.some((x) => x.dest.lo === ag.prefix.lo && x.dest.len === ag.prefix.len)) list.push({ dest: ag.prefix, origin: S, path: [S.uid], how: "aggregates " + contrib.length + " route(s) into " + prefixStr(ag.prefix) + (ag.summaryOnly ? " (summary only: the more-specific routes are suppressed)" : "") });
    }
    for (const c of b.condAdv || []) {
      if (c.usedBy.length && !c.usedBy.includes(group)) continue;
      if (c.peer && pe && c.peer !== pe.name) continue;
      const F = b.filters;
      const advMatch = (d) => c.advertise ? c.advertise.some((p) => within(p, d)) : (F && c.advertiseMap && F.routeMaps.has(c.advertiseMap) ? routeMapPermits(F, F.routeMaps.get(c.advertiseMap), d) : false);
      const condMatch = (d) => c.cond ? c.cond.some((p) => within(p, d)) : (F && c.condMap && F.routeMaps.has(c.condMap) ? routeMapPermits(F, F.routeMaps.get(c.condMap), d) : false);
      const exists = ribHas(S, condMatch), send = c.mode === "exist" ? exists : !exists;
      list = list.flatMap((x) => {
        if (!advMatch(x.dest)) return [x];
        stats.conditional++;
        const note = "conditional advertisement " + c.name + ": sent only while the " + (c.mode === "exist" ? "exist" : "non-exist") + " condition holds; per the config it is " + (exists ? "in" : "not in") + " the table, so it is " + (send ? "advertised" : "withheld") + " (the runtime table may differ)";
        if (!send && dropped) dropped.push({ dest: x.dest, why: nm(S.dev) + " withholds " + prefixStr(x.dest) + ": " + note });
        return send ? [Object.assign({}, x, { cond: note })] : [];
      });
    }
    return list.filter((x) => { const f = bgpFilterAllows(b, pe, "out", x.dest); if (!f.ok && dropped) dropped.push({ dest: x.dest, why: nm(S.dev) + " does not advertise " + prefixStr(x.dest) + " to this peer: " + f.why }); return f.ok; });
  };
  const withheld = (S, list) => { const W = S.vr.bgpWithheld || (S.vr.bgpWithheld = []); for (const x of list) if (!W.some((y) => y.dest.lo === x.dest.lo && y.dest.len === x.dest.len && y.why === x.why)) W.push(x); };
  const ospfOut = (S) => {
    if (!S.ospfIfs) return [];
    const own = [];
    for (const { it } of S.ospfIfs) for (const ip of it.ips) if (ip.len < 32) { const sb = subnetOf(ip); own.push({ dest: { lo: sb.lo, hi: sb.lo + Math.pow(2, 32 - ip.len) - 1, len: ip.len }, ext: false }); }
    for (const x of redistSet(S, S.vr.proto.ospf.exportRules, "ospf")) own.push({ dest: x.dest, ext: true });
    const fwd = [...S.learned.values()].filter((l) => l.proto === "ospf").map((l) => ({ dest: l.dest, origin: l.origin, path: l.path.concat([S.uid]), ext: l.ext }));
    return own.map((x) => ({ dest: x.dest, origin: S, path: [S.uid], ext: x.ext })).concat(fwd);
  };
  for (let round = 0; round < 6; round++) {
    let changed = false;
    // fabric advertisement snapshot
    const fabAds = new Map();
    for (const [key, list] of fabrics) { const ads = []; for (const m of list) for (const a of bgpOut(m.S, m.pe, key)) ads.push(Object.assign({ via: m }, a)); fabAds.set(key, ads); }
    for (const S of vrs) {
      if (S.vr.observedTable) continue; // a pasted route table is the real answer for this router: nothing is inferred into it
      for (const P of S.peers || []) {
        const drops = [];
        const ads = P.kind === "fabric" ? (fabAds.get(P.key) || []).filter((a) => a.via.S !== S) : (P.T ? bgpOut(P.T, backPeer(P.T, S), null, drops) : []);
        if (drops.length) withheld(S, drops);
        for (const a of ads) {
          const fi = bgpFilterAllows(S.vr.proto.bgp, P.pe, "in", a.dest);
          if (!fi.ok) { withheld(S, [{ dest: a.dest, why: nm(S.dev) + " does not accept " + prefixStr(a.dest) + " from " + P.pe.peerIp + ": " + fi.why }]); continue; }
          const peerTxt = P.kind === "fabric" ? "peer " + P.pe.peerIp + " (" + (P.ebgp ? "eBGP AS " + (P.pe.peerAs || "?") : "iBGP") + ", group " + P.pe.group + ")" : "peer " + (P.T ? nm(P.T.dev) + " " + P.T.vr.name : "?") + " " + P.pe.peerIp + " (" + (P.ebgp ? "eBGP AS " + (P.pe.peerAs || "?") : "iBGP") + ", group " + P.pe.group + ")";
          const how = nm(a.origin.dev) + (a.origin.dev === S.dev ? " " + a.origin.vr.name : "") + " " + (a.how || "advertises " + prefixStr(a.dest)) + (a.path.length > 1 ? "; passed on by " + (a.path.length - 1) + " BGP speaker(s)" : "");
          if (learn(S, { dest: a.dest, proto: "bgp", fabric: P.kind === "fabric" ? P.key : null, origin: a.origin, path: a.path, nh: P.pe.peerIp, iface: P.iface, ad: P.ebgp ? 20 : 200, how: a.how, cond: a.cond,
            reason: how + "; " + nm(S.dev) + " " + S.vr.name + " learns it from " + peerTxt + (fi.why ? "; " + fi.why : "") + (a.cond ? "; " + a.cond : ""),
            via: P.kind === "fabric" ? "BGP peer " + P.pe.peerIp + " (" + (P.ebgp ? "AS " + (P.pe.peerAs || "?") : "iBGP") + ")" : "BGP peer " + (P.T ? P.T.dev.name : "?") + " " + P.pe.peerIp })) changed = true;
        }
      }
      if (S.ospfIfs && !S.vr.observedTable) for (const N of ospfNbrs(S)) for (const a of ospfOut(N.T)) {
        if (learn(S, { dest: a.dest, proto: "ospf", origin: a.origin, path: a.path, nh: N.nh, iface: N.iface, ad: a.ext ? 150 : 30, ext: a.ext, via: "OSPF neighbour " + N.T.dev.name + " " + N.nh })) changed = true;
      }
    }
    if (!changed) break;
  }
  for (const S of vrs) for (const l of S.learned.values()) {
    S.vr.routes.push({ name: (l.proto === "bgp" ? "BGP " : "OSPF ") + prefixStr(l.dest) + " from " + l.origin.dev.name + (l.origin.dev === S.dev ? " " + l.origin.vr.name : ""), dest: l.dest, nexthop: { type: "ip", value: l.nh }, iface: l.iface || null, metric: 10 + l.path.length, ad: l.ad,
      type: "inferred-" + l.proto, inferred: { proto: l.proto, origin: l.origin.dev.name, originVr: l.origin.vr.name, via: l.via, hops: l.path.length, confidence: l.cond ? "low" : "medium", reason: l.reason || null, conditional: l.cond || null } });
    stats.routes++;
  }
  if (INFER_DONE) INFER_DONE.set(devices, stats);
  return stats;
}


/* ------------------------------------------------------------------ pasted route tables
 * Offline we cannot see learned routes. The user may paste (or upload) the firewall's own table:
 *   legacy:   show routing route            (VIRTUAL ROUTER: <name> ... destination nexthop metric flags age interface)
 *   advanced: show advanced-routing route   (Logical Router: <name> ... destination protocol nexthop distance metric flag ... interface)
 *   XML API:  <show><routing><route/></routing></show> response (<entry><virtual-router>..<destination>..)
 *   CSV:      router,destination,nexthop,interface,protocol[,distance,metric]  (e.g. pulled from a TSF)
 * Only active IPv4 routes are kept. Pasted routes win over inference: a router with a pasted table gets no inferred routes. */
const RT_PROTO = { S: "static", C: "connected", H: "local", B: "bgp", O: "ospf", Oi: "ospf", Oo: "ospf", O1: "ospf", O2: "ospf", R: "rip", "~": "internal" };
const RT_AD = { static: 10, connected: 0, local: 0, bgp: 20, ibgp: 200, ebgp: 20, ospf: 30, "ospf-ext": 110, rip: 120 };
function parseRouteTable(text) {
  const out = { format: null, routers: new Map(), count: 0, skipped: 0, warnings: [] };
  const put = (vr, r) => { vr = vr || "default"; if (!out.routers.has(vr)) out.routers.set(vr, []); out.routers.get(vr).push(r); out.count++; };
  const t = String(text || "").replace(/\r/g, "");
  if (/<entry>[\s\S]*<destination>/.test(t)) {
    out.format = "xml";
    let doc; try { doc = parseXml(t); } catch (e) { out.warnings.push("XML could not be parsed: " + e.message); return out; }
    const walk = (n) => { if (!n || !n.c) return; for (const c of n.c) { if (c.t === "entry" && ch(c, "destination")) row(c); else walk(c); } };
    const row = (e) => {
      const dest = parsePrefix(txt(ch(e, "destination")));
      let flags = txt(ch(e, "flags")), vr = txt(ch(e, "virtual-router")) || txt(ch(e, "logical-router")) || txt(ch(e, "vr")) || "default";
      if (!dest || isV6(txt(ch(e, "destination")))) { out.skipped++; return; }
      if (flags) flags = splitFlags(flags).join(" ");
      if (flags && !/\bA\b/.test(flags)) { out.skipped++; return; }
      const proto = txt(ch(e, "protocol")) || protoFromFlags(flags);
      put(vr, { dest, nexthop: txt(ch(e, "nexthop")), iface: txt(ch(e, "interface")) || null, proto: normProto(proto), ad: Number(txt(ch(e, "distance")) || txt(ch(e, "admin-distance"))) || null, metric: Number(txt(ch(e, "metric"))) || 0, flags });
    };
    walk(doc);
    return out;
  }
  let vr = null, adv = false, cols = null;
  for (const raw of t.split("\n")) {
    const line = raw.trim(); if (!line) continue;
    let m = /^(?:VIRTUAL ROUTER|virtual-router)\s*:\s*(\S+)/i.exec(line) || /^Logical Router\s*:\s*(\S+)/i.exec(line) || /^(?:VRF|logical-router)\s*:\s*(\S+)/i.exec(line);
    if (m) { vr = m[1]; if (/logical/i.test(line)) adv = true; out.format = out.format || (adv ? "advanced" : "legacy"); continue; }
    if (/^destination\s/i.test(line)) { cols = line.toLowerCase().split(/\s+/); if (cols.includes("protocol")) adv = true; out.format = out.format || (adv ? "advanced" : "legacy"); continue; }
    if (/^[A-Za-z_-]+\s*,\s*\d+\.\d+\.\d+\.\d+\/\d+\s*,/.test(line) || /^\d+\.\d+\.\d+\.\d+\/\d+\s*,/.test(line)) { // CSV
      out.format = out.format || "csv";
      const f = splitCsvLine(line).map((x) => x.trim()); const hasVr = !/^\d/.test(f[0]);
      const [r, d, nh, ifn, pr, ad, met] = hasVr ? f : ["default"].concat(f);
      const dest = parsePrefix(d); if (!dest) { out.skipped++; continue; }
      put(r, { dest, nexthop: nh || "", iface: ifn || null, proto: normProto(pr || "static"), ad: Number(ad) || null, metric: Number(met) || 0 });
      continue;
    }
    const tok = line.split(/\s+/);
    if (!/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(tok[0])) { if (/^[0-9a-f:]+\/\d+$/i.test(tok[0])) out.skipped++; continue; }
    const dest = parsePrefix(tok[0]); if (!dest) { out.skipped++; continue; }
    const ifn = tok.slice(1).find((x) => /^(ethernet|ae|tunnel|vlan|loopback|eth)\d/i.test(x)) || null;
    let proto = null, nexthop = "", flags = "", ad = null, metric = 0;
    if (adv || (cols && cols.includes("protocol"))) {
      proto = tok[1]; nexthop = tok[2] || ""; ad = Number(tok[3]) || null; metric = Number(tok[4]) || 0; flags = tok.slice(5).filter((x) => /^[A-Z?~]{1,3}$/.test(x) && x !== "N/A").join(" ");
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(nexthop)) { const ip = tok.slice(1).find((x) => /^\d+\.\d+\.\d+\.\d+$/.test(x)); nexthop = ip || nexthop; }
    } else {
      nexthop = tok[1] || ""; metric = Number(tok[2]) || 0;
      const fl = []; for (const x of tok.slice(3)) { if (/^(?:O[io12]|[ASCHRBOEM~?])+$/.test(x)) fl.push(...splitFlags(x)); else if (fl.length) break; }
      flags = fl.join(" "); proto = protoFromFlags(flags);
    }
    if (flags && !/\bA\b/.test(flags)) { out.skipped++; continue; }
    put(vr, { dest, nexthop, iface: ifn, proto: normProto(proto), ad, metric, flags });
  }
  if (!out.format && out.count) out.format = "legacy";
  if (!out.count) out.warnings.push("No IPv4 routes found. Paste the output of 'show routing route' (legacy) or 'show advanced-routing route' (advanced routing), the XML API response, or a CSV of router,destination,nexthop,interface,protocol.");
  return out;
}
/* PAN-OS prints route flags run together ("A?B" = active, loose, BGP; "A Oi" = active, OSPF intra-area). */
const RT_FLAG_RE = /O[io12]|[ASCHRBOEM~?]/g;
function splitFlags(flags) { return String(flags || "").match(RT_FLAG_RE) || []; }
function protoFromFlags(flags) { const f = splitFlags(flags).find((x) => RT_PROTO[x]); return f ? RT_PROTO[f] : "unknown"; }
function normProto(p) { p = String(p || "").toLowerCase(); if (/^(b|bgp|ibgp|ebgp)$/.test(p)) return "bgp"; if (/^o|ospf/.test(p)) return "ospf"; if (/^(s|static)$/.test(p)) return "static"; if (/^(c|connect|connected)$/.test(p)) return "connected"; if (/^(h|host|local)$/.test(p)) return "local"; if (/rip/.test(p)) return "rip"; return p || "unknown"; }
/* Apply pasted tables: tables = [{ device: id | name | serial | hostname, text, label }]. Returns one report per table.
 * Connected/local entries are skipped (the config already has them); static entries are added only when the config lacks them
 * (e.g. set locally); learned (BGP/OSPF/RIP) entries become routes of type "learned-<proto>" with route.observed = { source, proto }. */
function applyRouteTables(devices, tables) {
  const reports = [];
  for (const d of devices) for (const vr of new Set(d.vrs.values())) { if (vr.observedTable) { vr.routes = vr.routes.filter((r) => !r.observed); delete vr.observedTable; } }
  for (const T of tables || []) {
    const key = String(T.device || "").toLowerCase();
    const d = devices.find((x) => [x.id, x.name, x.serial, x.hostname].some((v) => v && String(v).toLowerCase() === key));
    const P = parseRouteTable(T.text), label = T.label || "pasted route table";
    const rep = { device: T.device, matched: !!d, format: P.format, routes: 0, routers: [], unmatchedRouters: [], skipped: P.skipped, warnings: P.warnings.slice() };
    reports.push(rep);
    if (!d) { rep.warnings.push("No loaded firewall matches '" + T.device + "' (use its name, hostname or serial)."); continue; }
    for (const [vrName, rows] of P.routers) {
      let vr = d.vrs.get(vrName);
      if (!vr && d.vrs.size === 1) vr = d.vrs.values().next().value;
      if (!vr && vrName === "default") vr = [...d.vrs.values()].find((v) => v.lr && v.vrf === "default") || null;
      if (!vr) { rep.unmatchedRouters.push(vrName); continue; }
      const have = new Set(vr.routes.filter((r) => r.type === "static").map((r) => prefixStr(r.dest) + "|" + (r.nexthop.value || "")));
      let n = 0;
      for (const r of rows) {
        if (r.proto === "connected" || r.proto === "local") continue;
        if (r.proto === "static" && have.has(prefixStr(r.dest) + "|" + (r.nexthop || ""))) continue;
        const nh = /^\d+\.\d+\.\d+\.\d+$/.test(r.nexthop) && r.nexthop !== "0.0.0.0" ? { type: "ip", value: r.nexthop } : /^discard$/i.test(r.nexthop) ? { type: "discard" } : /^(vr|lr)\s|^next-/i.test(r.nexthop) ? { type: "next-vr", value: r.nexthop.split(/\s+/).pop() } : r.iface ? { type: "ip", value: null } : { type: "none" };
        if (nh.type === "ip" && !nh.value && !r.iface) continue;
        vr.routes.push({ name: r.proto.toUpperCase() + " " + prefixStr(r.dest) + " (" + label + ")", dest: r.dest, nexthop: nh.type === "ip" && !nh.value ? { type: "connected" } : nh, iface: r.iface, metric: r.metric || 0, ad: r.ad != null ? r.ad : (RT_AD[r.proto] != null ? RT_AD[r.proto] : 100),
          type: r.proto === "static" ? "static" : "learned-" + r.proto, observed: { source: label, proto: r.proto } });
        n++;
      }
      vr.observedTable = { source: label, count: n };
      rep.routers.push({ vr: vr.name, routes: n }); rep.routes += n;
    }
  }
  invalidateCaches(devices);
  return reports;
}
function invalidateCaches(devices) {
  const sc = typeof SCOPE_CACHE !== "undefined" && SCOPE_CACHE ? SCOPE_CACHE.get(devices) : null;
  const lists = [devices];
  if (sc && sc.scopes) for (const o of sc.scopes.values()) if (o.devices && o.devices !== devices) lists.push(o.devices);
  for (const l of lists) for (const c of [INFER_DONE, GRAPH_CACHE, HA_CACHE, PS_CACHE, INFER_SNAP]) if (c) c.delete(l);
  if (sc) SCOPE_CACHE.delete(devices);
}

/* ------------------------------------------------------------------ shared / overlapping address space
 * Cloned builds in different data centers and overlapping RFC1918 between sites put the same address on several firewalls.
 * HA pairs are merged first (haInfo), so whatever still shares an address is a different firewall. The trace never picks one
 * of them silently: sharedIpChoices lists each decision point with every candidate, and pathStatus reports "Needs your choice"
 * until you pin one (per trace via choices / srcDevice / dstDevice, or for good with a saved link). */
function devCard(d) {
  const serial = d.serial || (d.panorama && d.panorama.serial) || null, hn = d.hostname || (d.panorama && d.panorama.hostname) || d.hostnameInit || null;
  return { devId: d.id, device: d.name, hostname: hn, serial, stack: d.stack || (d.panorama && d.panorama.stack) || null, site: siteOfDev(d), label: devLabel(d) + (siteOfDev(d) ? " \u00b7 site " + siteOfDev(d) : "") };
}
const OVERLAP_CACHE = typeof WeakMap !== "undefined" ? new WeakMap() : null;
function overlapReport(devices) {
  const c = OVERLAP_CACHE && OVERLAP_CACHE.get(devices); if (c) return c;
  const ha = haInfo(devices), act = ha.active, groups = ha.groups;
  const ipMap = new Map(), nets = [];
  for (const d of act) for (const it of d.interfaces.values()) {
    if (!it.vr) continue;
    for (const ip of it.ips) {
      if (!ipMap.has(ip.ip)) ipMap.set(ip.ip, []);
      const L = ipMap.get(ip.ip); if (!L.some((x) => x.dev === d)) L.push({ dev: d, iface: it.name, zone: it.zone || null, len: ip.len });
      if (ip.len < 32) { const sb = subnetOf(ip); nets.push({ lo: sb.lo, hi: sb.lo + Math.pow(2, 32 - ip.len) - 1, len: ip.len, ip: ip.ip, dev: d, iface: it.name, zone: it.zone || null }); }
    }
  }
  const sharedIps = [];
  for (const [ip, L] of ipMap) if (L.length > 1) sharedIps.push({ ip: n2ip(ip), owners: L.map((x) => Object.assign(devCard(x.dev), { iface: x.iface, zone: x.zone, prefix: n2ip(ip) + "/" + x.len })) });
  // overlapping subnets between firewalls at different sites / stacks (same site, different addresses = a shared segment: normal)
  nets.sort((a, b) => a.lo - b.lo || a.len - b.len);
  const pairKey = new Map(), overl = new Map();
  const sameSeg = (x, y) => x.lo === y.lo && x.len === y.len && x.ip !== y.ip; // one segment (a LAN or transit both sit on): normal
  const open = [];
  for (const n of nets) {
    for (let i = open.length - 1; i >= 0; i--) if (open[i].hi < n.lo) open.splice(i, 1);
    for (const o of open) {
      if (o.dev === n.dev || !rngOverlap(o, n) || sameSeg(o, n)) continue;
      const outer = o.len <= n.len ? o : n, k = n2ip(outer.lo) + "/" + outer.len;
      if (!overl.has(k)) overl.set(k, { prefix: k, owners: [], identical: true });
      const E = overl.get(k);
      for (const x of [o, n]) if (!E.owners.some((y) => y.devId === x.dev.id && y.iface === x.iface)) E.owners.push(Object.assign(devCard(x.dev), { iface: x.iface, zone: x.zone, prefix: n2ip(x.lo) + "/" + x.len }));
      if (o.lo !== n.lo || o.len !== n.len) E.identical = false;
      const pk = [o.dev.id, n.dev.id].sort().join("\u0000"); pairKey.set(pk, (pairKey.get(pk) || 0) + (o.ip === n.ip ? 1 : 0));
    }
    open.push(n);
  }
  // firewalls that look alike (same addresses) but were not paired as HA, and why
  const inGroup = new Set(groups.flat().map((d) => d.id));
  const cloned = [];
  for (const [pk, sameIp] of pairKey) {
    if (sameIp < 2) continue;
    const [ai, bi] = pk.split("\u0000"), A = act.find((d) => d.id === ai), B = act.find((d) => d.id === bi); if (!A || !B) continue;
    const why = A.stack && B.stack && A.stack !== B.stack ? "different template stacks (" + A.stack + " vs " + B.stack + ")" : siteKey(A) && siteKey(B) && siteKey(A) !== siteKey(B) ? "different sites by hostname (" + siteOfDev(A) + " vs " + siteOfDev(B) + ")" : (A.ha && A.ha.enabled) || (B.ha && B.ha.enabled) ? "their HA config does not name each other" : inGroup.has(A.id) || inGroup.has(B.id) ? "one of them is already in another HA pair" : "more than two firewalls share these addresses, or the match is too loose to call it HA";
    cloned.push({ a: devCard(A), b: devCard(B), sharedAddresses: sameIp, notHa: why });
  }
  const out = { sharedIps: sharedIps.sort((a, b) => b.owners.length - a.owners.length), overlaps: [...overl.values()].sort((a, b) => b.owners.length - a.owners.length), cloned,
    total: sharedIps.length + overl.size, text: sharedIps.length || overl.size ? sharedIps.length + " address(es) configured on more than one firewall and " + overl.size + " overlapping subnet(s) between sites. Traces that need one of these ask you to pick the firewall." : "No overlapping address space between the loaded firewalls." };
  if (OVERLAP_CACHE) OVERLAP_CACHE.set(devices, out);
  return out;
}
function sharedIpChoices(res, devices, opts) {
  opts = opts || {};
  const out = [];
  if (!res || !res.segments || !res.segments.length) return out;
  const G = getGraph(devices, opts.links), act = G.ha && G.ha.groups.length ? G.ha.active : devices;
  const card = (id, extra) => { const d = act.find((x) => x.id === id || x.name === id); return d ? Object.assign(devCard(d), extra || {}) : null; };
  const pinnedLink = (st) => (opts.links || []).some((L) => (L.from || {}).device === st.from && (!(L.from || {}).iface || L.from.iface === st.egress) && (!(L.from || {}).nexthop || L.from.nexthop === st.nexthop));
  for (const st of res.stitches || []) {
    if (!st.nexthop || st.hairpin) continue;
    const n = ip2n(st.nexthop); const os = (G.ipOwners && G.ipOwners.get(n) || []).filter((o) => o.dev.name !== st.from);
    if (os.length < 2) continue;
    const toD = act.find((x) => x.name === st.to), byDst = !!opts.dstDevice && !!toD && (opts.dstDevice === toD.id || opts.dstDevice === toD.name);
    const pinned = !!(opts.choices && opts.choices[st.key]) || (st.via && st.via.kind === "link") || pinnedLink(st) || byDst;
    const fromD = act.find((x) => x.name === st.from), fromL = fromD ? devCard(fromD).hostname || st.from : st.from;
    out.push({ kind: "next-hop", key: st.key, from: st.from, at: fromL + (st.egress ? " " + st.egress : ""), what: "next hop " + st.nexthop, chosen: st.to, pinned, pinBy: pinned ? (opts.choices && opts.choices[st.key] ? "your choice" : byDst && !(st.via && st.via.kind === "link") && !pinnedLink(st) ? "your destination choice" : "a saved link") : null,
      reason: "Next hop " + st.nexthop + " is configured on " + os.length + " firewalls. The config cannot say which one " + fromL + " really reaches.",
      candidates: os.map((o) => card(o.dev.id, { iface: o.iface.name, zone: o.iface.zone || null, reason: "has " + st.nexthop + " on " + o.iface.name + (o.iface.zone ? " (zone " + o.iface.zone + ")" : "") })).filter(Boolean),
      link: { from: { device: st.from, iface: st.egress || null, nexthop: st.nexthop } } });
  }
  const pinnedTo = new Set(out.filter((c) => c.pinned).map((c) => c.chosen)); // a pinned next hop also settles the destination it leads to
  const ov = (side) => {
    const P = res.plan || {}, pinOpt = side === "dst" ? opts.dstDevice : (opts.srcDevice || opts.deviceId || (opts.ingress ? opts.ingress.split("|")[0] : null));
    let list = (side === "dst" ? P.dstOwners : P.srcOwners) || [];
    if (pinOpt) { const pq = parsePrefix(side === "dst" ? res.query.dst : res.query.src); if (pq) list = ownersOf(G, act, pq, null).map((o) => ({ devId: o.dev.id, device: o.dev.name, iface: o.iface || null, kind: o.kind, prefix: o.prefix || null, how: o.how, len: o.len })); }
    const conn = list.filter((o) => o.kind === "connected"); if (conn.length < 2) return;
    const best = conn[0].len, top = conn.filter((o) => o.len === best);
    if (top.length < 2) return;
    // only overlapping space (identical address on both, or different sites/stacks) needs a choice; one segment shared at a site does not
    const devs = top.map((o) => act.find((d) => d.id === o.devId)).filter(Boolean);
    const sites = new Set(devs.map((d) => siteKey(d) || "?")), stacks = new Set(devs.map((d) => d.stack || "?"));
    const ipsOn = devs.map((d) => { const it = d.interfaces.get(top.find((o) => o.devId === d.id).iface); return it ? it.ips.map((x) => x.ip).join(",") : ""; });
    const identical = new Set(ipsOn).size < ipsOn.length;
    if (!identical) return; // the same subnet with different gateway addresses is one shared segment: either firewall reaches it
    const q = side === "dst" ? res.query.dst : res.query.src, used = side === "dst" ? res.segments[res.segments.length - 1].device : res.segments[0].device;
    const byLink = side === "dst" && ((res.stitches || []).some((st) => st.to === used && st.via && st.via.kind === "link") || pinnedTo.has(used));
    const pinned = side === "dst" ? !!opts.dstDevice || byLink : !!(opts.srcDevice || opts.ingress || opts.deviceId);
    out.push({ kind: side === "dst" ? "destination" : "source", key: side === "dst" ? "dstDevice" : "srcDevice", at: side === "dst" ? "destination" : "source", what: (side === "dst" ? "destination " : "source ") + q, chosen: used, pinned, pinBy: pinned ? (byLink && !opts.dstDevice ? (pinnedTo.has(used) ? "your next-hop choice" : "a saved link") : "your choice") : null,
      reason: (side === "dst" ? "The destination " : "The source ") + q + " is inside a subnet connected on " + top.length + " firewalls (" + "same gateway address on each: cloned build or overlapping space" + ").",
      candidates: top.map((o) => card(o.devId, { iface: o.iface, prefix: o.prefix, reason: o.how })).filter(Boolean) });
  };
  ov("src"); ov("dst");
  return out;
}
/* ------------------------------------------------------------------ inferred network graph
 * Routers, switches and MPLS clouds are not in firewall configs. We infer them:
 *   fw:<id>    a loaded firewall (vsys/VR detail is handled by the per-firewall engine)
 *   seg:<pfx>  an L3 segment (every interface subnet; firewalls sharing a subnet join it)
 *   rtr:<ip>   an inferred router (each distinct static-route next hop that is not a firewall)
 *   core       an inferred WAN/MPLS core interconnecting routers
 * Edges carry evidence; costs are computed per query (they depend on src/dst routing). */
const HINT_RE = /(mpls|wan|transit|core|backbone|uplink|dmz|vpn|sd-?wan|carrier|isp|internet|outside|untrust)/gi;
const WAN_HINT = /^(mpls|wan|transit|core|backbone|uplink|sd-?wan|carrier)$/i;
function isPrivateN(n) { return (n >= 167772160 && n <= 184549375) || (n >= 2886729728 && n <= 2887778303) || (n >= 3232235520 && n <= 3232301055) || (n >= 1681915904 && n <= 1686110207); }
function ifaceHints(it) {
  const s = [it.zone, it.comment, /^tunnel/.test(it.name) ? "vpn" : ""].filter(Boolean).join(" ");
  const m = s.match(HINT_RE); return m ? [...new Set(m.map((x) => x.toLowerCase()))] : [];
}
const GRAPH_CACHE = typeof WeakMap !== "undefined" ? new WeakMap() : null;
/* HA pairs: Panorama lists both members of an active/passive pair; their interfaces carry the same
 * addresses. Treat each pair as one logical firewall (the first one loaded), and remember the peers. */
const HA_CACHE = typeof WeakMap !== "undefined" ? new WeakMap() : null;
function haInfo(devices) {
  const c = HA_CACHE && HA_CACHE.get(devices); if (c) return c;
  const { groups, primary, cluster } = haGroups(devices);
  for (const d of cluster) d.haKind = "cluster";
  for (const grp of groups) { for (const d of grp) d.haPeers = grp.filter((x) => x !== d).map((x) => x.name); grp[0].haPrimary = true; for (const d of grp.slice(1)) d.haSecondary = true; }
  const active = devices.filter((d) => !primary.has(d.id));
  const out = { active, groups, primaryOf: (d) => primary.get(typeof d === "string" ? d : d.id) || null, mapId: (id) => { const p = primary.get(id); return p ? p.id : id; } };
  if (HA_CACHE) HA_CACHE.set(devices, out);
  if (HA_CACHE && active !== devices) HA_CACHE.set(active, { active, groups, primaryOf: () => null, mapId: (id) => id });
  return out;
}
/* Pure HA grouping (no flags written): used by haInfo and by the device picker to group pairs.
 * Correctness over grouping: a missed pair shows as two firewalls, a false pair hides one. So a pair needs
 *  - both devices on the same template stack (when both have one; different stacks are different sites),
 *  - nearly the same interface addresses on both sides (shared >= 2 and >= 80% of the LARGER set), or for
 *    active/active: same stack, same device groups and the same interface subnets (tight overlap),
 *  - and exactly one such match each: an address/subnet set that 3+ devices share is a repeated design, not HA.
 * Names are never used. Groups are at most two devices. */
function haGroups(devices) {
  const sig = new Map(), net = new Map(), dgs = new Map(), stk = new Map();
  for (const d of devices) {
    const s = new Set(), n = new Set();
    for (const it of d.interfaces.values()) for (const ip of it.ips) if (ip.len < 32) { s.add(ip.ip + "/" + ip.len); const sb = subnetOf(ip); n.add(it.name + "|" + sb.lo + "/" + sb.len); }
    sig.set(d, s); net.set(d, n);
    dgs.set(d, [...d.vsys.values()].map((v) => v.dg || "").filter(Boolean).sort().join(","));
    stk.set(d, d.stack || (d.panorama && d.panorama.stack) || null);
  }
  const overlap = (a, b) => { let n = 0; for (const x of a) if (b.has(x)) n++; return n; };
  const sameIps = (A, B) => { const sa = sig.get(A), sb = sig.get(B); if (sa.size < 2 || sb.size < 2) return false; const n = overlap(sa, sb); return n >= 2 && n >= 0.8 * Math.max(sa.size, sb.size); };
  const sameNets = (A, B) => {
    const na = net.get(A), nb = net.get(B);
    if (!stk.get(A) || stk.get(A) !== stk.get(B) || na.size < 2 || nb.size < 2 || !dgs.get(A) || dgs.get(A) !== dgs.get(B)) return false;
    const n = overlap(na, nb); return (n >= 3 && n >= 0.8 * Math.max(na.size, nb.size)) || (n >= 2 && n === na.size && n === nb.size);
  };
  const stackOk = (A, B) => !(stk.get(A) && stk.get(B) && stk.get(A) !== stk.get(B));
  // cloned builds in different data centers carry the same addresses: different sites (by hostname) never pair without HA config
  const siteOk = (A, B) => { const a = siteKey(A), b = siteKey(B); return !(a && b && a !== b); };
  // 1) explicit HA config: a peer-ip that uniquely names one other firewall (its HA1 / HA1-backup or an interface address)
  const owners = new Map(), haOwners = new Map(), own = (m, ip, d) => { if (!m.has(ip)) m.set(ip, new Set()); m.get(ip).add(d); };
  for (const d of devices) { if (d.ha && d.ha.enabled !== false) for (const ip of d.ha.own) { own(haOwners, ip, d); own(owners, ip, d); } for (const it of d.interfaces.values()) for (const ip of it.ips) own(owners, n2ip(ip.ip), d); }
  const peerUse = new Map(); // literal peer-ip -> how many firewalls name it (a shared template literal is not a unique peer)
  for (const d of devices) if (d.ha && d.ha.enabled) for (const ip of d.ha.peers) peerUse.set(ip, (peerUse.get(ip) || 0) + 1);
  const pointsTo = new Map(), viaHa = new Set(); // d -> the one firewall its HA config names; viaHa: it names that firewall's own HA1 address
  for (const d of devices) {
    if (!d.ha || !d.ha.enabled || !d.ha.peers.length) continue;
    const t = new Set(); let ha1 = false;
    for (const ip of d.ha.peers) { if ((peerUse.get(ip) || 0) > 2) continue; const o = owners.get(ip); if (o && o.size === 1 && !o.has(d)) { t.add([...o][0]); const h = haOwners.get(ip); if (h && h.size === 1) ha1 = true; } }
    if (t.size === 1) { pointsTo.set(d, [...t][0]); if (ha1) viaHa.add(d); }
  }
  const pointedBy = new Map(); for (const [a, b] of pointsTo) { if (!pointedBy.has(b)) pointedBy.set(b, []); pointedBy.get(b).push(a); }
  const explicit = [], taken = new Set();
  for (const A of devices) {
    const B = pointsTo.get(A); if (!B || taken.has(A) || taken.has(B)) continue;
    const mutual = pointsTo.get(B) === A;
    const oneWay = viaHa.has(A) && !pointsTo.has(B) && !(B.ha && B.ha.enabled === false) && (pointedBy.get(B) || []).length === 1 && (pointedBy.get(A) || []).length === 0;
    if (!mutual && !oneWay) continue;
    const [P, Q] = devices.indexOf(A) < devices.indexOf(B) ? [A, B] : [B, A];
    explicit.push([P, Q]); taken.add(P); taken.add(Q);
  }
  // HA config on A names a peer address, B lists its own HA1 addresses, and they differ: not each other's peer
  const uniqPeers = (A) => (A.ha && A.ha.enabled ? A.ha.peers.filter((ip) => (peerUse.get(ip) || 0) <= 2) : []);
  const uniqOwn = (B) => (B.ha && B.ha.enabled !== false ? B.ha.own.filter((ip) => (haOwners.get(ip) || new Set()).size === 1) : []);
  const haContradicts = (A, B) => { const p = uniqPeers(A), o = uniqOwn(B); return p.length > 0 && o.length > 0 && !p.some((ip) => o.includes(ip)); };
  // 2) inference only for firewalls whose HA config is absent or does not resolve to a loaded firewall
  const inferable = (d) => !taken.has(d) && !(d.ha && d.ha.enabled === false) && !pointsTo.has(d);
  const pool = devices.filter(inferable);
  const match = new Map(pool.map((d) => [d, []])), how = new Map();
  for (let i = 0; i < pool.length; i++) for (let j = i + 1; j < pool.length; j++) {
    const A = pool[i], B = pool[j];
    if (!stackOk(A, B) || haContradicts(A, B) || haContradicts(B, A)) continue;
    const ip = sameIps(A, B), nets = !ip && sameNets(A, B);
    if (!ip && !nets) continue;
    match.get(A).push(B); match.get(B).push(A); if (nets) how.set(A.id + "\u0000" + B.id, "cluster");
  }
  const primary = new Map(), groups = [], cluster = new Set(), fromConfig = new Set();
  for (const [A, B] of explicit) { groups.push([A, B]); primary.set(B.id, A); fromConfig.add(A); fromConfig.add(B); if ((A.ha && A.ha.mode === "active-active") || (B.ha && B.ha.mode === "active-active")) { cluster.add(A); cluster.add(B); } }
  for (let i = 0; i < pool.length; i++) {
    const A = pool[i], mA = match.get(A);
    if (mA.length !== 1 || primary.has(A.id)) continue;
    const B = mA[0]; if (match.get(B).length !== 1 || pool.indexOf(B) < i || !siteOk(A, B)) continue; // 3+ alike = repeated design; different sites = cloned build
    groups.push([A, B]); primary.set(B.id, A);
    if (how.get(A.id + "\u0000" + B.id)) { cluster.add(A); cluster.add(B); }
  }
  groups.sort((a, b) => devices.indexOf(a[0]) - devices.indexOf(b[0]));
  return { groups, primary, cluster, fromConfig, haConfigured: devices.filter((d) => d.ha && d.ha.enabled).length, haResolved: pointsTo.size };
}
/* The inferred (BGP/OSPF) routes live on the shared router objects, so a scoped copy of the firewall list and the full list must not
 * overwrite each other's routes: every list that has been prepared keeps a snapshot, restored when that list is used again. */
const INFER_SNAP = typeof WeakMap !== "undefined" ? new WeakMap() : null;
let LAST_ACTIVE = null;
function snapshotInferred(devices) {
  const out = [];
  for (const d of devices) for (const vr of new Set(d.vrs.values())) out.push({ vr, routes: vr.routes.filter((r) => r.inferred), withheld: vr.bgpWithheld });
  return out;
}
function restoreInferred(snap) {
  for (const x of snap) { x.vr.routes = x.vr.routes.filter((r) => !r.inferred).concat(x.routes); if (x.withheld === undefined) delete x.vr.bgpWithheld; else x.vr.bgpWithheld = x.withheld; }
}
function getGraph(devices, links) {
  const k = JSON.stringify(links || []);
  const ha0 = haInfo(devices);
  const c = GRAPH_CACHE && GRAPH_CACHE.get(devices);
  if (c && c.k === k) {
    if (LAST_ACTIVE !== ha0.active && INFER_SNAP && INFER_SNAP.has(devices)) restoreInferred(INFER_SNAP.get(devices));
    LAST_ACTIVE = ha0.active;
    return c.g;
  }
  const ha = ha0;
  if (INFER_DONE && INFER_DONE.has(ha.active) && LAST_ACTIVE !== ha.active && INFER_SNAP && INFER_SNAP.has(devices)) restoreInferred(INFER_SNAP.get(devices));
  const inf = inferDynamicRoutes(ha.active);
  // HA secondaries mirror the primary's inferred routes (same config, shown in the config browser)
  for (const grp of ha.groups) for (const d of grp.slice(1)) for (const vr of new Set(d.vrs.values())) { const pv = grp[0].vrs.get(vr.name); if (pv) vr.routes = vr.routes.filter((r) => !r.inferred).concat(pv.routes.filter((r) => r.inferred)); }
  if (INFER_SNAP) INFER_SNAP.set(devices, snapshotInferred(devices));
  LAST_ACTIVE = ha.active;
  const g = buildGraph(ha.active, links);
  g.ha = ha;
  g.inference = inf;
  if (GRAPH_CACHE) GRAPH_CACHE.set(devices, { k, g });
  return g;
}
function buildGraph(devices, links) {
  const nodes = new Map(), adj = new Map(), edges = [];
  const node = (id, o) => { let n = nodes.get(id); if (!n) { n = Object.assign({ id }, o); nodes.set(id, n); adj.set(id, []); } return n; };
  const edge = (a, b, kind, meta) => { const e = { a, b, kind, meta: meta || {} }; edges.push(e); adj.get(a).push({ to: b, e }); adj.get(b).push({ to: a, e }); return e; };
  const ipOwner = new Map(), ipOwners = new Map(), owned = [];
  for (const d of devices) {
    node("fw:" + d.id, { type: "fw", dev: d, label: d.name, devId: d.id });
    for (const it of d.interfaces.values()) {
      if (!it.vr) continue;
      for (const ip of it.ips) {
        ipOwner.set(ip.ip, { dev: d, iface: it });
        if (!ipOwners.has(ip.ip)) ipOwners.set(ip.ip, []);
        if (!ipOwners.get(ip.ip).some((o) => o.dev === d)) ipOwners.get(ip.ip).push({ dev: d, iface: it });
        if (ip.len < 32) { const sb = subnetOf(ip); owned.push({ lo: sb.lo, hi: sb.lo + Math.pow(2, 32 - ip.len) - 1, len: ip.len, dev: d, iface: it }); }
      }
    }
  }
  const devSegs = new Map();
  for (const d of devices) {
    const mine = []; devSegs.set(d.id, mine);
    for (const it of d.interfaces.values()) {
      if (!it.vr) continue;
      for (const ip of it.ips) {
        if (ip.len >= 32) continue;
        const sb = subnetOf(ip), id = "seg:" + n2ip(sb.lo) + "/" + sb.len;
        const s = node(id, { type: "seg", lo: sb.lo, hi: sb.lo + Math.pow(2, 32 - sb.len) - 1, len: sb.len, label: n2ip(sb.lo) + "/" + sb.len, fws: [], hints: new Set(), routers: [] });
        if (s.fws.some((x) => x.dev === d && x.iface === it.name)) continue;
        s.fws.push({ dev: d, devId: d.id, iface: it.name, ip: ip.ip, zone: it.zone, vsys: it.vsys });
        for (const h of ifaceHints(it)) s.hints.add(h);
        mine.push(s);
        edge("fw:" + d.id, id, "if", { devId: d.id, iface: it.name, ip: ip.ip });
      }
    }
  }
  const segs = [...nodes.values()].filter((n) => n.type === "seg");
  const segIdx = new Map(); for (const s of segs) { if (!segIdx.has(s.len)) segIdx.set(s.len, new Map()); segIdx.get(s.len).set(s.lo, s); }
  const segLens = [...segIdx.keys()].sort((a, b) => b - a);
  const segContaining = (ipn, d) => {
    let best = null;
    for (const s of (d && devSegs.get(d.id)) || []) if (ipn >= s.lo && ipn <= s.hi && (!best || s.len > best.len)) best = s;
    if (best) return best;
    for (const len of segLens) { const sz = Math.pow(2, 32 - len); const s = segIdx.get(len).get(Math.floor(ipn / sz) * sz); if (s) return s; }
    return null;
  };
  const nhSeen = new Set();
  const attachRouter = (rid, ipn, s, o) => {
    const R = node(rid, Object.assign({ type: "rtr", ip: ipn, label: n2ip(ipn), usedBy: [], private: isPrivateN(ipn), seg: s ? s.id : null }, o || {}));
    if (s && !R.attached) { R.attached = true; s.routers.push(rid); edge(rid, s.id, "attach", {}); }
    return R;
  };
  for (const d of devices) for (const vr of new Set(d.vrs.values())) for (const r of vr.routes) {
    if (r.nexthop.type !== "ip") continue;
    const nh = ip2n(r.nexthop.value); if (nh == null) continue;
    const o = ipOwner.get(nh);
    const s = segContaining(nh, d);
    const fromIf = r.iface || (s && (s.fws.find((f) => f.dev === d) || {}).iface) || null;
    if (o && o.dev !== d) { // a next hop configured on several firewalls (cloned builds, overlapping space) links to each of them; the trace asks which
      const os = ipOwners.get(nh).filter((x) => x.dev !== d), shared = os.length > 1;
      for (const x of os) {
        const k = d.id + "|" + x.dev.id + "|" + fromIf + "|" + nh;
        if (!nhSeen.has(k)) { nhSeen.add(k); edge("fw:" + d.id, "fw:" + x.dev.id, "nh", { fromId: d.id, toId: x.dev.id, fromIf, toIf: x.iface.name, nh: n2ip(nh), shared }); }
      }
      continue;
    }
    if (o) continue;
    const R = attachRouter("rtr:" + n2ip(nh), nh, s);
    R.usedBy.push({ devId: d.id, dev: d.name, vr: vr.name, dest: r.dest, route: r.name, iface: fromIf });
    const k = "r|" + d.id + "|" + fromIf + "|" + nh;
    if (fromIf && !nhSeen.has(k)) { nhSeen.add(k); edge("fw:" + d.id, R.id, "rnh", { fromId: d.id, fromIf, nh: n2ip(nh), seg: s ? s.label : null }); }
  }
  // point-to-point /30 or /31 with a single firewall and no known router: the far end is a router
  for (const s of segs) {
    if (s.fws.length !== 1 || s.routers.length || s.len < 30) continue;
    const f = s.fws[0];
    const peer = s.len === 31 ? (f.ip === s.lo ? s.hi : s.lo) : (f.ip === s.lo + 1 ? s.lo + 2 : f.ip === s.lo + 2 ? s.lo + 1 : null);
    if (peer == null) continue;
    attachRouter("rtr:" + n2ip(peer), peer, s, { inferred: "far end of point-to-point " + s.label });
  }
  const core = node("core", { type: "core", label: "Inferred WAN / MPLS core", members: [] });
  const routers = [...nodes.values()].filter((n) => n.type === "rtr");
  for (const R of routers) {
    let ev = null, strong = false;
    for (const u of R.usedBy) {
      if ((u.dest.len || 0) === 0) continue;
      const hit = owned.find((o) => o.dev.id !== u.devId && o.lo >= u.dest.lo && o.hi <= u.dest.hi);
      if (hit) { ev = u.dev + " routes " + prefixStr(u.dest) + " via " + R.label + " (covers " + hit.dev.name + " networks)"; strong = true; break; }
    }
    const s = R.seg && nodes.get(R.seg);
    if (!ev && R.private) ev = "private next-hop address (typical MPLS/WAN router)";
    if (!ev && s && [...s.hints].some((h) => WAN_HINT.test(h))) ev = "segment " + s.label + " is named like WAN/MPLS (" + [...s.hints].join(", ") + ")";
    if (ev) { R.core = ev; R.coreStrong = strong; core.members.push(R.id); edge(R.id, "core", "core", { why: ev, strong }); }
  }
  for (const s of segs) if (s.fws.length === 1 && !s.routers.length && [...s.hints].some((h) => WAN_HINT.test(h))) edge(s.id, "core", "hint", { why: "zone/interface named " + [...s.hints].join(", ") });
  // user-defined links: highest weight
  for (const L of links || []) {
    const f = L.from || {}, t = L.to || {};
    const A = devices.find((d) => d.name === f.device || d.id === f.device);
    const B = devices.find((d) => d.name === t.device || d.id === t.device);
    if (!B) continue;
    let from = null;
    if (f.nexthop) { const n = ip2n(f.nexthop); if (n != null && !ipOwners.has(n)) { /* a next hop owned by a firewall: the link starts at that firewall itself */ const s = segContaining(n, A); from = nodes.has("rtr:" + f.nexthop) ? "rtr:" + f.nexthop : attachRouter("rtr:" + f.nexthop, n, s).id; } }
    if (!from && A) from = "fw:" + A.id;
    if (!from || from === "fw:" + B.id) continue;
    edge(from, "fw:" + B.id, "link", { label: L.label || "user link", fromId: A ? A.id : null, fromIf: f.iface || null, nh: f.nexthop || null, toId: B.id, toIf: t.iface || null });
  }
  return { nodes, adj, edges, owned, ipOwner, ipOwners, devices };
}

/* Which firewall owns a prefix: connected subnet (most specific), else closest gateway (most specific non-default route pointing inward). */
function ownersOf(G, devices, q, pinId) {
  const pool = pinId ? devices.filter((d) => d.id === pinId || d.name === pinId) : devices;
  const ids = new Set(pool.map((d) => d.id));
  let c = G.owned.filter((o) => ids.has(o.dev.id) && q.lo >= o.lo && q.hi <= o.hi).map((o) => ({ dev: o.dev, iface: o.iface.name, len: o.len, kind: "connected", prefix: n2ip(o.lo) + "/" + o.len, how: "connected " + n2ip(o.lo) + "/" + o.len + " on " + o.iface.name + (o.iface.zone ? " (zone " + o.iface.zone + ")" : "") }));
  if (!c.length) {
    for (const d of pool) {
      let best = null;
      for (const vr of new Set(d.vrs.values())) {
        const lr = lookupRoute(vr, q); if (!lr) continue;
        const r = lr.route, len = r.dest.len == null ? 32 : r.dest.len;
        if ((!pinId && len === 0) || r.nexthop.type === "discard" || r.type === "local") continue;
        let rif = r.iface || null, nhv = r.nexthop.type === "ip" ? r.nexthop.value : null;
        if (!rif || r.nexthop.type === "next-vr") {
          // follow next-vr / vsys hand-offs to the VR that actually sends it out: its next hop decides whether this route points inward
          let f = resolveForward(d, vr.name, q, vrOwner(d, vr, vr.owner || d.vsys.keys().next().value));
          for (let g = 0; g < 4 && f.kind === "vsys"; g++) f = resolveForward(d, f.targetVr || vr.name, q, f.targetCtx);
          if (f.kind === "iface") { rif = rif || f.iface; if (r.nexthop.type === "next-vr") nhv = f.nexthop || null; }
        }
        let inward = true;
        if (nhv) {
          const R = G.nodes.get("rtr:" + nhv); if (R && R.core && R.coreStrong) inward = false;
          const o = G.ipOwner.get(ip2n(nhv)); if (o && o.dev.id !== d.id) inward = false; // next hop is another firewall: that firewall is closer
        }
        if (!best || len > best.len) best = { dev: d, len, inward, kind: "route", prefix: prefixStr(r.dest), iface: rif, how: "closest gateway: " + vr.name + " routes " + prefixStr(r.dest) + (r.nexthop.value ? " via " + r.nexthop.value : "") + (inward ? "" : " (toward the WAN)") };
      }
      if (best) c.push(best);
    }
    const inw = c.filter((x) => x.inward);
    if (inw.length) c = inw;
  }
  if (pinId && !c.length && pool.length) c = [{ dev: pool[0], len: 0, kind: "pinned", how: "pinned by you" }];
  c.sort((a, b) => b.len - a.len);
  const seen = new Set();
  return c.filter((x) => !seen.has(x.dev.id) && seen.add(x.dev.id));
}

/* Per-device forwarding summary toward q: egress iface -> best route (follows next-vr across vsys). */
function fwdSummary(dev, q) {
  const out = new Map();
  for (const vr of new Set(dev.vrs.values())) {
    let f = resolveForward(dev, vr.name, q, vrOwner(dev, vr, vr.owner || dev.vsys.keys().next().value));
    for (let g = 0; g < 4 && f.kind === "vsys"; g++) f = resolveForward(dev, f.targetVr || vr.name, q, f.targetCtx);
    if (f.kind !== "iface") continue;
    const last = f.vrPath[f.vrPath.length - 1]; const len = last ? (last.route.dest.len == null ? 32 : last.route.dest.len) : 0;
    const prev = out.get(f.iface);
    if (!prev || len > prev.len) out.set(f.iface, { len, isDef: len === 0, nh: f.nexthop || null, direct: !!f.direct, route: last && last.route.name, vr: last && last.vr, inferred: f.vrPath.some((h) => h.route.inferred) ? f.vrPath.find((h) => h.route.inferred).route.inferred.proto : null });
  }
  return out;
}

/* Where this firewall's own routing sends q when it arrives on interface ifName (follows next-vr across vsys). */
/* True when the deciding entry is a default route (a hub with a specific route back out the same interface is a deliberate hairpin). */
/* Interface a on device A and interface b on device B share a subnet (B is a direct neighbour of A on that segment). */
function sameSubnet(A, a, B, b) {
  const I = A && a ? A.interfaces.get(a) : null, J = B && b ? B.interfaces.get(b) : null;
  if (!I || !J) return false;
  return I.ips.some((x) => J.ips.some((y) => { const m = x.len === 0 ? 0 : (~0 << (32 - x.len)) >>> 0; return x.len === y.len && ((x.ip & m) >>> 0) === ((y.ip & m) >>> 0); }));
}
function isDefaultFwd(f) { const vp = f.vrPath || [], last = vp[vp.length - 1]; return !!last && (last.route.dest.len || 0) === 0; }
function routeFrom(dev, ifName, q) {
  const I = ifName ? dev.interfaces.get(ifName) : null;
  if (!I || !I.vr) return null;
  let f = resolveForward(dev, I.vr, q, I.vsys);
  for (let g = 0; g < 4 && f.kind === "vsys"; g++) f = resolveForward(dev, f.targetVr || I.vr, q, f.targetCtx);
  return f;
}
/* Plain-language basis of a forwarding decision: which config entry decided it, and how sure we are. */
function routeBasis(f) {
  if (!f) return null;
  const vp = f.vrPath || [], last = vp[vp.length - 1];
  if (f.pbf) return { kind: "pbf", text: last ? last.route.name : "policy-based forwarding", confidence: "high" };
  if (f.planned) return { kind: "evidence", text: "follows the chosen inferred path; this firewall's routing does not (route change listed)", confidence: "low" };
  if (!last) return { kind: "none", text: f.why || "no route", confidence: "low" };
  const r = last.route, pre = vp.length > 1 ? "next-vr " + vp.map((h) => h.vr).join(" -> ") + ", then " : "";
  const out = f.iface ? " out " + f.iface : "";
  if (r.type === "suggested") return { kind: "suggested", text: pre + "no route - suggested route to " + prefixStr(r.dest) + out, confidence: "low" };
  if (r.inferred) return { kind: r.inferred.proto, text: pre + r.inferred.proto.toUpperCase() + " inferred " + prefixStr(r.dest) + (f.nexthop ? " via " + f.nexthop : "") + out + " (" + last.vr + ", originated by " + r.inferred.origin + ")", reason: r.inferred.reason || null, conditional: r.inferred.conditional || null, confidence: r.inferred.confidence || "medium" };
  if (r.observed) return { kind: "observed", proto: r.observed.proto, text: pre + r.observed.proto.toUpperCase() + " route " + prefixStr(r.dest) + (f.nexthop ? " via " + f.nexthop : "") + out + " (" + last.vr + ", from " + r.observed.source + ")", confidence: "high" };
  if (r.type === "connected" || r.nexthop.type === "connected") return { kind: "connected", text: pre + "connected " + prefixStr(r.dest) + " on " + r.iface + " (" + last.vr + ")", confidence: "high" };
  if (r.type === "local" || r.nexthop.type === "local") return { kind: "local", text: "address of this firewall (" + r.iface + ")", confidence: "high" };
  const def = (r.dest.len || 0) === 0;
  return { kind: def ? "default" : "static", text: pre + (def ? "default route" : "static route " + prefixStr(r.dest)) + (r.nexthop.type === "ip" ? " via " + r.nexthop.value : "") + out + " (" + last.vr + ")", confidence: "high" };
}
function makeCost(G, src, dst, targetIds) {
  const fs = new Map(), rs = new Map();
  const F = (d) => { if (!fs.has(d.id)) fs.set(d.id, fwdSummary(d, dst)); return fs.get(d.id); };
  const Rv = (d) => { if (!rs.has(d.id)) rs.set(d.id, fwdSummary(d, src)); return rs.get(d.id); };
  return function (fromId, toId, e) {
    const from = G.nodes.get(fromId), to = G.nodes.get(toId);
    if (e.kind === "link") return { c: 0.05, why: "user-defined link '" + e.meta.label + "'", link: true };
    if (e.kind === "attach") return { c: 0.3, why: (from.type === "rtr" ? from : to).label + " is on " + (from.type === "seg" ? from : to).label };
    if (e.kind === "core") return { c: 1.5, why: "WAN/MPLS core (" + e.meta.why + ")" };
    if (e.kind === "hint") return { c: 5, why: "weak hint: " + e.meta.why, low: true };
    if (e.kind === "nh") {
      if (fromId !== "fw:" + e.meta.fromId) return null;
      const ri = F(from.dev).get(e.meta.fromIf);
      if (ri && ri.nh === e.meta.nh) return { c: (ri.isDef ? 1.5 : 0.2) + (ri.inferred ? 0.8 : 0), why: from.label + " routes the destination (" + (ri.isDef ? "default route" : "/" + ri.len) + (ri.inferred ? ", inferred " + ri.inferred.toUpperCase() : "") + ") to " + e.meta.nh + " = " + to.label + " " + e.meta.toIf, inferred: !!ri.inferred };
      return { c: 7, why: from.label + " has routes to " + to.label + " (" + e.meta.nh + ") but not for this destination", needsRoute: true };
    }
    if (e.kind === "rnh") {
      if (from.type === "fw") {
        const ri = F(from.dev).get(e.meta.fromIf);
        if (!ri || ri.nh !== e.meta.nh) return null;
        return { c: (ri.isDef ? 2.5 : 1) + 0.3 + (ri.inferred ? 0.8 : 0), why: from.label + " routes the destination (" + (ri.isDef ? "default route" : "/" + ri.len) + (ri.inferred ? ", inferred " + ri.inferred.toUpperCase() : "") + ") to router " + e.meta.nh + " on " + e.meta.fromIf, def: ri.isDef, inferred: !!ri.inferred };
      }
      const B = to.dev, rv = Rv(B).get(e.meta.fromIf);
      if (!rv || rv.nh !== e.meta.nh) return null;
      return { c: (targetIds.has(B.id) ? 0.3 : 1) + (rv.isDef ? 1 : 0.2) + 0.3 + (rv.inferred ? 0.4 : 0), why: B.name + " " + e.meta.fromIf + " routes replies to the source via router " + e.meta.nh + " (" + (rv.isDef ? "default route" : "/" + rv.len) + (rv.inferred ? ", inferred " + rv.inferred.toUpperCase() : "") + ")", inferred: !!rv.inferred };
    }
    if (e.kind === "if") {
      if (from.type === "fw") {
        const ri = F(from.dev).get(e.meta.iface);
        if (ri) {
          let c = (ri.isDef ? 2.5 : 1) + (ri.inferred ? 0.8 : 0);
          if (ri.nh) { const o = G.ipOwner.get(ip2n(ri.nh)); if (o && o.dev !== from.dev) c += 4; }
          return { c, why: from.label + " routes the destination out " + e.meta.iface + " (" + (ri.isDef ? "default route" : ri.direct ? "connected" : "/" + ri.len + (ri.inferred ? " inferred " + ri.inferred.toUpperCase() : "") + " route") + (ri.nh ? " via " + ri.nh : "") + ")", def: ri.isDef, inferred: !!ri.inferred };
        }
        const hint = [...to.hints].some((h) => WAN_HINT.test(h));
        return { c: hint ? 6 : 8, why: from.label + " has no route for the destination out " + e.meta.iface + (hint ? " (interface looks like WAN/MPLS)" : ""), needsRoute: true };
      }
      const B = to.dev;
      let c = targetIds.has(B.id) ? 0.3 : 1;
      const rv = Rv(B).get(e.meta.iface);
      if (rv) c += (rv.isDef ? 1 : 0.2) + (rv.inferred ? 0.4 : 0); else c += 2.5;
      return { c, why: B.name + " " + e.meta.iface + (rv ? " is where it routes replies to the source (" + (rv.isDef ? "default route" : rv.direct ? "connected" : "/" + rv.len) + ")" : " - no reverse route to the source there (possible asymmetry)"), noReverse: !rv };
    }
    return null;
  };
}

function dijkstra(G, startId, goalId, cost, banned) {
  const dist = new Map([[startId, 0]]), prev = new Map(), done = new Set();
  // binary heap of [dist, id]
  const H = [[0, startId]];
  const push = (x) => { H.push(x); let i = H.length - 1; while (i > 0) { const p = (i - 1) >> 1; if (H[p][0] <= H[i][0]) break; [H[p], H[i]] = [H[i], H[p]]; i = p; } };
  const pop = () => { const top = H[0], last = H.pop(); if (H.length) { H[0] = last; let i = 0; for (;;) { const l = 2 * i + 1, r = l + 1; let m = i; if (l < H.length && H[l][0] < H[m][0]) m = l; if (r < H.length && H[r][0] < H[m][0]) m = r; if (m === i) break; [H[m], H[i]] = [H[i], H[m]]; i = m; } } return top; };
  const open = { push: (id) => push([dist.get(id), id]) };
  while (H.length) {
    const [du, u] = pop();
    if (done.has(u) || du > dist.get(u) + 1e-9) continue; done.add(u);
    if (u === goalId) break;
    const un = G.nodes.get(u);
    if (un.type === "fw" && u !== startId) { /* transit firewall: continue through it */ }
    for (const { to, e } of G.adj.get(u)) {
      if (done.has(to) || (banned && (banned.has(e) || (banned.has(to) && to !== goalId)))) continue;
      const tn = G.nodes.get(to);
      if (tn.type === "fw" && to !== goalId && un.type === "fw") { /* fw->fw via nh/link fine */ }
      const r = cost(u, to, e); if (!r) continue;
      const nd = dist.get(u) + r.c;
      if (!dist.has(to) || nd < dist.get(to) - 1e-9) { dist.set(to, nd); prev.set(to, { from: u, e, r }); open.push(to); }
    }
  }
  if (!dist.has(goalId) || !done.has(goalId)) return null;
  const steps = []; let cur = goalId;
  while (cur !== startId) { const p = prev.get(cur); steps.unshift({ from: p.from, to: cur, e: p.e, r: p.r }); cur = p.from; }
  return { cost: dist.get(goalId), steps };
}

function stepsToHops(G, steps) {
  const hops = []; let cur = null;
  for (const s of steps) {
    if (!cur) { const n = G.nodes.get(s.from); cur = { fromId: n.devId, from: n.label, steps: [], cost: 0 }; }
    cur.steps.push(s); cur.cost += s.r.c;
    const tn = G.nodes.get(s.to);
    if (tn.type === "fw") { cur.toId = tn.devId; cur.to = tn.label; hops.push(cur); cur = { fromId: tn.devId, from: tn.label, steps: [], cost: 0 }; }
  }
  for (const h of hops) {
    const a = h.steps[0], z = h.steps[h.steps.length - 1];
    h.egIf = a.e.kind === "if" ? a.e.meta.iface : a.e.kind === "nh" ? a.e.meta.fromIf : a.e.meta.fromIf || null;
    h.inIf = z.e.kind === "if" ? z.e.meta.iface : z.e.kind === "nh" ? z.e.meta.toIf : z.e.kind === "rnh" ? z.e.meta.fromIf : z.e.meta.toIf || null;
    const kinds = h.steps.map((s) => s.e.kind);
    const routers = h.steps.map((s) => G.nodes.get(s.to)).filter((n) => n.type === "rtr").map((n) => n.label);
    const segsOn = [];
    for (const s of h.steps) { const n = G.nodes.get(s.to); if (n.type === "seg") segsOn.push(n.label); else if (n.type === "rtr" && n.seg && !segsOn.includes(G.nodes.get(n.seg).label)) segsOn.push(G.nodes.get(n.seg).label); }
    const viaCore = kinds.includes("core") || kinds.includes("hint");
    if (a.e.kind === "nh") h.nexthop = a.e.meta.nh;
    else if (a.e.kind === "link") h.nexthop = a.e.meta.nh || null;
    else if (routers.length) h.nexthop = routers[0];
    else if (z.e.kind === "if") h.nexthop = n2ip(z.e.meta.ip);
    // the address the next firewall sees the traffic coming from (for return routes)
    if (z.e.kind === "rnh") h.peer = z.e.meta.nh;
    else if (z.e.kind === "if" && h.steps.length >= 2) {
      const before = G.nodes.get(z.from), prevStep = h.steps[h.steps.length - 2];
      const pn = G.nodes.get(prevStep.from);
      if (pn.type === "rtr") h.peer = pn.label;
      else if (pn.type === "fw" && a.e.kind === "if") h.peer = n2ip(a.e.meta.ip);
      else if (before.type === "seg") h.peer = null;
    } else if (z.e.kind === "nh") { const A = G.devices.find((d) => d.id === h.fromId); const it = A && A.interfaces.get(h.egIf); const ip = it && it.ips.find((x) => x.len < 32); h.peer = ip ? n2ip(ip.ip) : null; }
    if (kinds.includes("link")) h.via = { kind: "link", label: (h.steps.find((s) => s.e.kind === "link").e.meta.label) };
    else if (a.e.kind === "nh") h.via = { kind: "direct", label: "next hop " + a.e.meta.nh };
    else if (!routers.length && !viaCore && segsOn.length === 1) h.via = { kind: "segment", label: "shared subnet " + segsOn[0] };
    else {
      const parts = []; let coreDone = false;
      const segL = (n) => { const x = n.seg && G.nodes.get(n.seg); return x ? x.label : null; };
      for (const s of h.steps) { const n = G.nodes.get(s.to); if (n.type === "seg") parts.push(n.label); else if (n.type === "rtr") { if (s.e.kind === "rnh" && segL(n) && parts[parts.length - 1] !== segL(n)) parts.push(segL(n)); parts.push("router " + n.label + (n.inferred ? " (inferred)" : "")); } else if (n.type === "core" && !coreDone) { parts.push("WAN/MPLS core"); coreDone = true; } else if (n.type === "fw" && s.e.kind === "rnh" && segL(G.nodes.get(s.from))) parts.push(segL(G.nodes.get(s.from))); }
      h.via = { kind: "transit", label: (/^tunnel/.test(h.egIf || "") ? "tunnel " + h.egIf + ": " : "") + parts.join(" -> ") };
    }
    h.routers = routers; h.segments = segsOn; h.viaCore = viaCore;
    h.evidence = h.steps.map((s) => s.r.why);
    h.needsRoute = h.steps.some((s) => s.r.needsRoute);
    h.inferredRoute = h.steps.some((s) => s.r.inferred);
    h.noReverse = h.steps.some((s) => s.r.noReverse);
    const low = h.steps.some((s) => s.r.low);
    const weakCore = h.steps.some((s) => s.e.kind === "core" && !s.e.meta.strong);
    h.confidence = kinds.includes("link") ? "high" : (low || h.cost > 10) ? "low" : (h.needsRoute || weakCore || h.noReverse || h.inferredRoute || h.cost > 6) ? "medium" : "high";
    h.key = h.from + "|" + (h.egIf || "?") + "|" + (h.nexthop || "");
    h.nodeIds = [h.steps[0].from];
    for (const x of h.steps) { if (x.e.kind === "rnh") { const rn = G.nodes.get(x.from).type === "rtr" ? G.nodes.get(x.from) : G.nodes.get(x.to); if (rn.seg) h.nodeIds.push(rn.seg); } h.nodeIds.push(x.to); }
    delete h.steps;
  }
  return hops;
}

/* Find the top-k firewall chains from the source owner to the destination owner. */
function findPaths(G, devices, src, dst, opts) {
  opts = opts || {};
  const out = { srcOwners: [], dstOwners: [], paths: [], explain: [], considered: [] };
  let so = ownersOf(G, devices, src, opts.srcDevice), dO = ownersOf(G, devices, dst, opts.dstDevice);
  const pub = !isPrivateN(dst.lo) || !isPrivateN(dst.hi), pubS = !isPrivateN(src.lo) || !isPrivateN(src.hi);
  // evidence from existing allow rules
  const ev = opts.evidence === false ? [] : ruleEvidence(devices, src, dst, opts.svc || null, opts.excludeRule || null);
  const evW = new Map(); for (const e of ev) evW.set(e.dev.id, Math.max(evW.get(e.dev.id) || 0, e.weight));
  out.evidence = ev.slice().sort((a, b) => b.weight - a.weight).slice(0, 12).map((e) => ({ devId: e.dev.id, device: e.dev.name, vsys: e.vsys, rule: e.rule.name, scope: e.rule.scope, from: e.from, to: e.to, weight: Math.round(e.weight * 100) / 100 }));
  const merge = (list, add) => { for (const a of add) { const ex = list.find((x) => x.dev.id === a.dev.id); if (!ex) list.push(a); else if (a.len > ex.len && ex.kind !== "connected") Object.assign(ex, a); } list.sort((a, b) => b.len - a.len || (evW.get(b.dev.id) || 0) - (evW.get(a.dev.id) || 0)); return list; };
  const ruleOwners = (side) => {
    const add = [];
    for (const e of ev) {
      const spec = side === "src" ? e.sSpec : e.dSpec, zones = side === "src" ? e.from : e.to;
      if (!spec || zones.includes("any")) continue;
      const its = zoneIfaces(e.dev, e.vsys, zones); if (!its.length) continue;
      const q = side === "src" ? src : dst;
      // routing on that firewall must agree: the zone's interface is where it routes this address
      // (for the destination: by a specific route, not the default; a default only says "further away")
      const fs = fwdSummary(e.dev, q);
      let it = its.find((x) => ifaceIpIn(x, q));
      if (!it) { const ok = its.find((x) => { const f = fs.get(x.name); return f && (side === "src" || !f.isDef); }); if (!ok) continue; it = ok; }
      add.push({ dev: e.dev, iface: it.name, len: side === "src" ? e.lenS : e.lenD, kind: "rule", prefix: null, how: "rule '" + e.rule.name + "' on " + e.dev.name + " " + e.vsys + " allows it " + (side === "src" ? "from zone " + zones.join("/") : "to zone " + zones.join("/")) + " (" + it.name + ")" });
    }
    return add;
  };
  // routing owners (connected / specific route) decide; rules only place an address no route covers.
  // The rule-based view is kept separately to report where rules disagree with routing.
  const cp = (l) => l.map((x) => Object.assign({}, x));
  let soR = cp(so), dOR = cp(dO);
  if (!opts.srcDevice && !(so[0] && so[0].kind === "connected")) so = merge(cp(so), ruleOwners("src"));
  if (!opts.dstDevice && !(dO[0] && dO[0].kind === "connected")) dO = merge(cp(dO), ruleOwners("dst"));
  // a summary shorter than /16 (e.g. 10.0.0.0/8 toward the WAN) does not say which site: rules may place the address then
  // nor does a route that points into the WAN/MPLS core ("it is somewhere out there")
  const specific = (l) => l.some((o) => o.kind === "connected" || o.kind === "pinned" || ((o.len || 0) >= SPECIFIC_LEN && o.inward !== false));
  if (!specific(soR)) soR = cp(so);
  if (!specific(dOR)) dOR = cp(dO);
  // a default route toward another firewall or into the WAN/MPLS core is not an internet uplink
  const defIntoNetwork = (nh) => { if (!nh) return false; const n = ip2n(nh); if (n == null) return false; if (G.ipOwner.has(n)) return true; const rt = G.nodes.get("rtr:" + nh); return !!(rt && rt.core); };
  const edgeOwners = (side) => {
    const E = internetEdges(G).slice();
    // a rule allowing this public address through the zone that carries the default route marks an internet edge too
    const q = side === "src" ? src : dst;
    for (const e of ev) {
      const zones = side === "src" ? e.from : e.to, spec = side === "src" ? e.sSpec : e.dSpec;
      if (!spec || zones.includes("any")) continue;
      const fs = fwdSummary(e.dev, q);
      for (const it of zoneIfaces(e.dev, e.vsys, zones)) { const f = fs.get(it.name); if (f && f.isDef && !defIntoNetwork(f.nh) && !E.some((x) => x.dev === e.dev && x.iface === it)) E.push({ dev: e.dev, iface: it, vsys: it.vsys, zone: it.zone, vr: it.vr, nexthop: f.nh, why: "rule " + e.rule.name + " allows it via zone " + it.zone + ", which carries the default route" }); }
    }
    if (!E.length) return [];
    const dn = side === "src" ? dnatEdgesFor(G, dst) : new Set();
    const score = (x) => { let s = 0; for (const e of ev) if (e.dev === x.dev && (side === "src" ? e.from : e.to).some((z) => z === x.zone)) s = Math.max(s, 2 + e.weight); if (dn.has(x.dev.id)) s = Math.max(s, 1.5); return s; };
    const ranked = E.map((x) => ({ x, s: score(x) })).sort((a, b) => b.s - a.s);
    const pick = ranked[0].s > 0 ? ranked.filter((r) => r.s > 0).slice(0, 4) : ranked.slice(0, 8);
    return pick.map(({ x, s }) => ({ dev: x.dev, iface: x.iface.name, len: 0, kind: "internet", edgeScore: s, how: "internet edge " + x.dev.name + " " + x.iface.name + (x.zone ? " (zone " + x.zone + ")" : "") + ": " + x.why + (s >= 2 ? "; a rule there allows this traffic" : s > 0 ? "; destination NAT there matches" : "") }));
  };
  if (!opts.srcDevice && pubS) { const eo = (!so.length || !soR.length) ? edgeOwners("src") : []; if (!so.length) so = eo; if (!soR.length) soR = cp(eo); }
  if (!opts.dstDevice && pub) {
    const need = !dO.some((o) => o.kind === "connected" || o.kind === "rule"), needR = !dOR.some((o) => o.kind === "connected" || o.kind === "rule");
    const eo = need || needR ? edgeOwners("dst") : [];
    if (need) dO = dO.concat(eo.filter((e) => !dO.some((o) => o.dev.id === e.dev.id)));
    if (needR) dOR = dOR.concat(cp(eo).filter((e) => !dOR.some((o) => o.dev.id === e.dev.id)));
  }
  const fmtO = (o) => ({ devId: o.dev.id, device: o.dev.name, iface: o.iface || null, kind: o.kind, prefix: o.prefix || null, how: o.how, len: o.len });
  const uni = (a, b) => a.concat(b.filter((x) => !a.some((y) => y.dev.id === x.dev.id)));
  out.srcOwners = uni(soR, so).map(fmtO); out.dstOwners = uni(dOR, dO).map(fmtO);
  if (!so.length) { out.explain.push("No loaded firewall has the source on a connected subnet, a specific route, a matching rule, or an internet edge."); return out; }
  if (!dO.length) {
    out.explain.push(pub ? "Destination " + prefixStr(dst) + " is a public/unknown address and no internet edge was found: the path ends where it leaves the last firewall." : "No loaded firewall owns " + prefixStr(dst) + " (no connected subnet, specific route or matching rule).");
    out.noDstOwner = true; return out;
  }
  const topOf = (list, n) => {
    const nonI = list.filter((o) => o.kind !== "internet"), inet = list.filter((o) => o.kind === "internet");
    const t = nonI.length ? nonI.filter((o) => o.len === nonI[0].len || o.kind === "rule" && o.len >= nonI[0].len - 8).slice(0, n) : [];
    return t.concat(inet.slice(0, t.length ? 4 : 8));
  };
  const srcTopR = topOf(soR, 3), dstTopR = topOf(dOR, 4);
  const srcTop = uni(srcTopR, topOf(so, 3)), dstTop = uni(dstTopR, topOf(dO, 4));
  const srcIdsR = new Set(srcTopR.map((o) => o.dev.id)), dstIdsR = new Set(dstTopR.map((o) => o.dev.id));
  out.explain.push("Source " + prefixStr(src) + " is behind " + srcTopR.map((o) => o.dev.name + " (" + o.how + ")").join(" or ") + ".");
  out.explain.push("Destination " + prefixStr(dst) + " is behind " + dstTopR.map((o) => o.dev.name + " (" + o.how + ")").join(" or ") + ".");
  if (ev.length) out.explain.push("Existing allow rules for this traffic on: " + [...new Set(ev.sort((a, b) => b.weight - a.weight).map((e) => e.dev.name + " " + e.vsys + " (" + e.rule.name + ")"))].slice(0, 6).join(", ") + ". Routing decides each hop; these rules only break ties between equally valid routing options, place addresses no route covers, and pick internet edges.");
  const targetIds = new Set(dstTop.map((o) => o.dev.id));
  const cost = makeCost(G, src, dst, targetIds);
  const via = (opts.via || []).map((v) => devices.find((d) => d.id === v || d.name === v)).filter(Boolean);
  // the source firewall's ingress is known: leaving it anywhere but where its routing sends the destination costs a lot
  const egCache = new Map();
  const costFor = (sO) => {
    if (!sO) return cost;
    const ifn = typeof sO.iface === "string" ? sO.iface : sO.iface && sO.iface.name;
    const k = sO.dev.id + "|" + ifn;
    if (!egCache.has(k)) { const f = ifn ? routeFrom(sO.dev, ifn, dst) : null; egCache.set(k, f && f.kind === "iface" ? f.iface : null); }
    const eg = egCache.get(k); if (!eg) return cost;
    const sid = "fw:" + sO.dev.id;
    return (a, b, e) => { const r = cost(a, b, e); if (!r || a !== sid || e.kind === "link") return r; const fi = e.meta && (e.meta.iface || e.meta.fromIf); return fi && fi !== eg ? Object.assign({}, r, { c: r.c + 50 }) : r; };
  };
  const route = (sId, tId, banned, extraVia, sO) => {
    const way = [sId].concat(via.concat(extraVia || []).map((d) => d.id).filter((x) => x !== sId && x !== tId), [tId]);
    let total = 0, steps = []; const ban = new Set(banned || []);
    for (let i = 0; i + 1 < way.length; i++) {
      const p = dijkstra(G, "fw:" + way[i], "fw:" + way[i + 1], i === 0 ? costFor(sO) : cost, ban);
      if (!p) return null;
      total += p.cost; steps = steps.concat(p.steps);
      for (const s of p.steps) if (G.nodes.get(s.from).type === "fw") ban.add(s.from); // the WAN core may be crossed again (branch -> core -> hub -> core -> DMZ)
    }
    return { cost: total, steps };
  };
  const cands = [];
  const keyOf = (p) => p.steps.filter((s) => G.nodes.get(s.to).type === "fw").map((s) => s.to).join(">") + "|" + (p.srcId || "");
  const revisits = (p, sO) => { const ids = [sO.dev.id]; for (const st of p.steps) { const n = G.nodes.get(st.to); if (n.type === "fw") { if (ids.includes(n.devId)) return true; ids.push(n.devId); } } return false; };
  const add = (p, sO, dOw) => { if (p) p.srcId = sO.dev.id; if (p && !revisits(p, sO) && !cands.some((c) => keyOf(c) === keyOf(p))) cands.push(Object.assign(p, { srcOwner: sO, dstOwner: dOw })); };
  const many = srcTop.length * dstTop.length > 12;
  for (const s of srcTop) for (const t of dstTop) {
    if (s.dev.id === t.dev.id && !via.length) { add({ cost: 0, steps: [] }, s, t); continue; }
    const p = route(s.dev.id, t.dev.id, null, null, s); add(p, s, t);
    if (p && !many) for (const st of p.steps) {
      const n = G.nodes.get(st.to);
      if (st.to !== "fw:" + t.dev.id && n.type !== "seg") add(route(s.dev.id, t.dev.id, [st.to], null, s), s, t);
      if (st.e.kind !== "attach") add(route(s.dev.id, t.dev.id, [st.e], null, s), s, t);
    }
  }
  // paths through the firewalls whose rules already allow this traffic
  const evDevs = [...evW.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([id]) => devices.find((d) => d.id === id)).filter(Boolean);
  if (evDevs.length && srcTop.length && dstTop.length) for (const E of evDevs) for (const s of srcTop.slice(0, 2)) for (const t of dstTop.slice(0, 2)) {
    if (E.id === s.dev.id || E.id === t.dev.id || s.dev.id === t.dev.id) continue;
    add(route(s.dev.id, t.dev.id, null, [E], s), s, t);
  }
  // evidence counts in full only where the path crosses the firewall through the rule's zones
  const evBy = new Map(); for (const e of ev) { if (!evBy.has(e.dev.id)) evBy.set(e.dev.id, []); evBy.get(e.dev.id).push(e); }
  const zoneOf = (dev, it) => { if (!it) return null; const I = typeof it === "string" ? dev.interfaces.get(it) : it; return I && I.zone || null; };
  const crossings = (c) => {
    const hops = c.hops || (c.hops = stepsToHops(G, c.steps)), xs = [];
    const devOf = (id) => devices.find((d) => d.id === id);
    let cur = { dev: c.srcOwner.dev, inZ: zoneOf(c.srcOwner.dev, c.srcOwner.iface) };
    for (const h of hops) { cur.outZ = zoneOf(cur.dev, h.egIf); xs.push(cur); const D = devOf(h.toId); cur = { dev: D, inZ: D ? zoneOf(D, h.inIf) : null }; }
    cur.outZ = zoneOf(cur.dev, c.dstOwner.iface); xs.push(cur);
    return xs;
  };
  const zfit = (list, z) => !z || list.includes("any") || list.includes(z);
  const evOn = (c) => {
    let w = 0, pen = 0; const seen = new Set();
    const xs = crossings(c);
    xs.forEach((x, i) => {
      if (!x.dev) return;
      if (seen.has(x.dev.id)) return; seen.add(x.dev.id);
      let best = 0;
      for (const e of evBy.get(x.dev.id) || []) { const f = zfit(e.from, x.inZ), t = zfit(e.to, x.outZ); best = Math.max(best, e.weight * (f && t ? 1 : f || t ? 0.4 : 0.1)); }
      w += best;
    });
    return { w, pen };
  };
  for (const c of cands) { const r = evOn(c); c.ev = r.w; c.rank = c.cost - EVF * c.ev + r.pen - (c.srcOwner.edgeScore || 0) - (c.dstOwner.edgeScore || 0); }
  // routing is authoritative: a hop that leaves a firewall other than where its own route (from the ingress VR) sends the
  // destination contradicts the config. Explicit routes outrank inferred BGP/OSPF; evidence only orders what routing allows.
  const devById = new Map(devices.map((d) => [d.id, d]));
  const violations = (c) => {
    const hops = c.hops || (c.hops = stepsToHops(G, c.steps)), v = { ex: 0, inf: 0, list: [] };
    let dev = c.srcOwner.dev, inIf = typeof c.srcOwner.iface === "string" ? c.srcOwner.iface : (c.srcOwner.iface && c.srcOwner.iface.name) || null;
    for (const h of hops) {
      if (dev && h.egIf) {
        let bad = null;
        const f = inIf ? routeFrom(dev, inIf, dst) : null;
        if (f) { if (f.kind === "iface" && f.iface !== h.egIf) bad = { iface: f.iface, inferred: f.vrPath.some((x) => x.route.inferred), basis: routeBasis(f) }; }
        else {
          const fs = fwdSummary(dev, dst); let best = -1, bi = null;
          for (const [k, x] of fs) if (x.len > best) { best = x.len; bi = k; }
          const g = fs.get(h.egIf);
          if (best >= 0 && (!g || g.len < best)) { const x = fs.get(bi); bad = { iface: bi, inferred: !!x.inferred, basis: { kind: x.inferred || (x.isDef ? "default" : "static"), text: (x.isDef ? "default route" : "route " + (x.route || "") + " (/" + x.len + ")") + (x.nh ? " via " + x.nh : "") + " out " + bi + (x.vr ? " (" + x.vr + ")" : ""), confidence: x.inferred ? "medium" : "high" } }; }
        }
        if (bad) { if (bad.inferred) v.inf++; else v.ex++; v.list.push({ device: dev.name, devId: dev.id, pathIface: h.egIf, routeIface: bad.iface, route: bad.basis ? bad.basis.text : "", inferred: bad.inferred }); }
        else if (inIf && inIf === h.egIf && dev !== c.srcOwner.dev && (!f || isDefaultFwd(f)) && sameSubnet(dev, h.egIf, devById.get(h.toId), h.inIf)) { v.inf++; v.list.push({ device: dev.name, devId: dev.id, pathIface: h.egIf, routeIface: h.egIf, route: "would send it back out " + h.egIf + ", the interface it arrived on (the router before it would deliver directly)", inferred: true }); }
      }
      dev = devById.get(h.toId) || null; inIf = h.inIf || null;
    }
    return v;
  };
  // a rules' path that passes through the routed source/destination firewall (and obeys routing on every hop) only extends the routed path
  // upstream or downstream: a specific route says "behind me", not "directly attached", so that is consistent with routing.
  const fwSeq = (c) => [c.srcOwner.dev.id].concat((c.hops || (c.hops = stepsToHops(G, c.steps))).map((h) => h.toId));
  for (const c of cands) {
    c.viol = violations(c);
    const seq = fwSeq(c), sOk = srcIdsR.has(c.srcOwner.dev.id), dOk = dstIdsR.has(c.dstOwner.dev.id);
    c.inR = sOk && dOk ? 1 : 0;
    if (!c.inR && !c.viol.ex && !c.viol.inf && (sOk || seq.some((id) => srcIdsR.has(id))) && (dOk || seq.some((id) => dstIdsR.has(id)))) { c.inR = 1; c.extends = true; }
  }
  const evBest = cands.length ? cands.slice().sort((a, b) => a.rank - b.rank)[0] : null;
  cands.sort((a, b) => (b.inR - a.inR) || (a.viol.ex - b.viol.ex) || (a.viol.inf - b.viol.inf) || (a.rank - b.rank));
  // honor branch choices: key -> forced next device
  let list = cands;
  if (opts.choices && Object.keys(opts.choices).length) {
    for (const c of cands) c.hops = stepsToHops(G, c.steps);
    const fits = (c) => c.hops.every((h) => !opts.choices[h.key] || opts.choices[h.key] === h.toId || opts.choices[h.key] === h.to);
    const pref = cands.filter(fits);
    list = pref.concat(cands.filter((c) => !fits(c)));
  }
  let picked = list.slice(0, opts.k || 3);
  const rBest = list[0];
  // rules suggest a different path than routing: keep it as an alternative and report the disagreement
  const devsOf = (c) => [c.srcOwner.dev.name].concat((c.hops || (c.hops = stepsToHops(G, c.steps))).map((h) => h.to));
  // a real disagreement: the rules' path relies on rules that no firewall on the routing path carries
  const extraRules = (r, e) => { const rD = new Set(devsOf(r)), eD = devsOf(e); const onR = new Set(ev.filter((x) => rD.has(x.dev.name)).map((x) => x.rule.scope + "|" + x.rule.name)); return ev.some((x) => eD.includes(x.dev.name) && !rD.has(x.dev.name) && !onR.has(x.rule.scope + "|" + x.rule.name)); };
  const conflictWith = evBest && rBest && keyOf(evBest) !== keyOf(rBest) && evBest.ev > rBest.ev + 0.05 && !via.length && !(opts.choices && Object.keys(opts.choices).length) && extraRules(rBest, evBest) ? evBest : null;
  if (conflictWith && !picked.includes(conflictWith)) picked = picked.concat([conflictWith]);
  // parallel firewalls: the best two routing-compatible paths differ only by one firewall and the evidence is close
  let ambWith = null, ambPos = -1;
  if (rBest && !conflictWith && !via.length && !(opts.choices && Object.keys(opts.choices).length)) {
    const d0 = devsOf(rBest);
    for (const c of list.slice(1, 12)) {
      if (c.inR !== rBest.inR || c.viol.ex !== rBest.viol.ex || c.viol.inf !== rBest.viol.inf || !!c.extends !== !!rBest.extends) break;
      const d1 = devsOf(c);
      if (d1.length !== d0.length) continue;
      const diff = d0.map((n, i) => (n !== d1[i] ? i : -1)).filter((i) => i >= 0);
      if (diff.length !== 1 || Math.abs(c.rank - rBest.rank) > 2 || Math.abs((c.ev || 0) - (rBest.ev || 0)) > 0.1) continue;
      ambWith = c; ambPos = diff[0]; break;
    }
    if (ambWith && !picked.includes(ambWith)) picked = picked.concat([ambWith]);
  }
  out.paths = picked.map((c) => {
    const hops = c.hops || (c.hops = stepsToHops(G, c.steps));
    const devs = devsOf(c);
    const conf = hops.some((h) => h.confidence === "low") ? "low" : hops.some((h) => h.confidence === "medium") ? "medium" : "high";
    return { cost: Math.round(c.cost * 100) / 100, hops, devices: devs, confidence: c.viol && (c.viol.ex || c.viol.inf) ? "low" : conf, srcDevId: c.srcOwner.dev.id, dstDevId: c.dstOwner.dev.id, srcIface: c.srcOwner.iface || null, srcKind: c.srcOwner.kind, dstKind: c.dstOwner.kind, evidence: Math.round((c.ev || 0) * 100) / 100,
      routing: c.viol && !c.viol.ex && !c.viol.inf ? (c.extends ? "extends" : "agrees") : "contradicts", violations: c.viol ? c.viol.list : [], rules: c === conflictWith,
      label: devs.join(" -> ") + (hops.length ? "" : " (same firewall)") };
  });
  if (conflictWith && rBest) {
    const rDevs = new Set(devsOf(rBest)), eDevs = devsOf(conflictWith);
    const onRouting = new Set(ev.filter((e) => rDevs.has(e.dev.name)).map((e) => e.rule.scope + "|" + e.rule.name));
    const rules = ev.filter((e) => eDevs.includes(e.dev.name) && !rDevs.has(e.dev.name) && !onRouting.has(e.rule.scope + "|" + e.rule.name)).sort((a, b) => b.weight - a.weight);
    const seenR = new Set();
    out.conflict = {
      routing: out.paths[0].label, rules: out.paths[picked.indexOf(conflictWith)].label, pathIndex: picked.indexOf(conflictWith),
      evidence: rules.filter((e) => !seenR.has(e.dev.id + e.rule.name) && seenR.add(e.dev.id + e.rule.name)).slice(0, 6).map((e) => ({ device: e.dev.name, vsys: e.vsys, rule: e.rule.name, scope: e.rule.scope, from: e.from, to: e.to })),
      routes: conflictWith.viol.list.slice(0, 5),
      ownerOnlyByRules: !dstIdsR.has(conflictWith.dstOwner.dev.id) ? conflictWith.dstOwner.how : null,
    };
  }
  if (ambWith) {
    const i = picked.indexOf(ambWith), d0 = out.paths[0].devices, d1 = out.paths[i].devices;
    out.ambiguous = { devices: [d0[ambPos], d1[ambPos]], position: ambPos, pathIndex: i, paths: [out.paths[0].label, out.paths[i].label], evidence: [out.paths[0].evidence, out.paths[i].evidence] };
  }
  if (pub && rBest) { // destination NAT for this address on a firewall the routing path does not cross
    const dn = dnatEdgesFor(G, dst), rDevs = new Set(devsOf(rBest).map((n) => (devices.find((d) => d.name === n) || {}).id));
    const off = [...dn].filter((id) => !rDevs.has(id)).map((id) => devById.get(id)).filter(Boolean);
    if (off.length && ![...dn].some((id) => rDevs.has(id))) out.dnatElsewhere = off.map((d) => d.name);
  }
  if (!out.paths.length) {
    out.explain.push("No inferred connection between " + srcTop[0].dev.name + " and " + dstTop[0].dev.name + ": they share no subnet, next hop, WAN/MPLS router or user link. Add a link (Links between firewalls) to connect them.");
    return out;
  }
  const best = out.paths[0];
  for (const h of best.hops) out.explain.push(h.from + " -> " + h.to + " [" + h.confidence + "]: " + h.evidence.join("; ") + ".");
  if (out.paths.length > 1 && Math.abs(out.paths[1].cost - best.cost) < 1e-6) out.explain.push("Tie: alternative path " + out.paths[1].label + " scores the same; pick the right one or add a link.");
  // candidate firewalls considered (neighbours of the chosen chain that were not used)
  const onPath = new Set(best.devices);
  const seenC = new Set();
  for (const h of best.hops) {
    const A = devices.find((d) => d.id === h.fromId);
    for (const { to } of G.adj.get("fw:" + A.id)) {
      const n = G.nodes.get(to);
      const fws = n.type === "fw" ? [n] : n.type === "seg" ? n.fws.map((f) => G.nodes.get("fw:" + f.devId)) : [];
      if (n.type === "seg") for (const rid of n.routers) if (G.nodes.get(rid).core) fws.push({ label: "(any firewall behind the WAN/MPLS core)", devId: null });
      for (const f of fws) {
        if (!f || onPath.has(f.label) || seenC.has(f.label)) continue; seenC.add(f.label);
        if (!f.devId) continue;
        const B = devices.find((d) => d.id === f.devId);
        const owns = G.owned.some((o) => o.dev === B && dst.lo >= o.lo && dst.hi <= o.hi);
        const fsB = fwdSummary(B, dst);
        const why = owns ? "also owns the destination subnet but its path costs more" : fsB.size ? "routes the destination, but sending traffic through it is not shorter than the chosen chain" : "has no route toward the destination";
        out.considered.push({ device: B.name, near: h.from, why });
        if (out.considered.length >= 12) break;
      }
      if (out.considered.length >= 12) break;
    }
  }
  return out;
}

/* ------------------------------------------------------------------ evidence from the rulebase and the internet edge
 * Existing allow rules are the best map of how traffic flows today: a rule on firewall F that allows
 * zone A -> zone B for this source and destination says F is on the path, the source arrives from A
 * and the destination is reached through B. Rules applied to many firewalls (shared/parent device
 * groups) are weaker evidence than a rule on one firewall. */
const SPECIFIC_LEN = 16; // routes at least this specific locate an address on their own
const EVF = 40; // weight of rulebase evidence against path cost (tuned by rule replay: plateaus from ~30)
function ruleEvidence(devices, src, dst, svc, exclude) {
  const out = [];
  const lenIn = (ranges, q) => { let best = -1; for (const r of ranges) if (r.lo <= q.lo && r.hi >= q.hi) { const l = r.len == null ? 32 - Math.ceil(Math.log2(r.hi - r.lo + 1)) : r.len; if (l > best) best = l; } return best; };
  const byRule = new Map();
  for (const d of devices) for (const ctx of d.vsys.values()) {
    if (ctx.isSG) continue;
    for (const r of ctx.security) {
      if (r.disabled || r.negSrc || r.negDst || normAction(r.action) !== "allow") continue;
      if (exclude && r.scope + "\u0000" + r.name === exclude) continue;
      const S = cached(r, "src" + ctx.uid, () => resolveAddrs(r.source, ctx.scopes)); if (!S.any && !S.ranges.length) continue;
      const D = cached(r, "dst" + ctx.uid, () => resolveAddrs(r.destination, ctx.scopes)); if (!D.any && !D.ranges.length) continue;
      const ls = S.any ? 0 : lenIn(S.ranges, src); if (ls < 0) continue;
      const ld = D.any ? 0 : lenIn(D.ranges, dst); if (ld < 0) continue;
      const sSpec = ls >= 12, dSpec = ld >= 12;
      if (!sSpec && !dSpec) continue;
      if (svc && svcMatch(r, ctx.scopes, svc, ctx.uid).m === "no") continue;
      const e = { dev: d, vsys: ctx.name, rule: r, from: r.from, to: r.to, sSpec, dSpec, lenS: ls, lenD: ld };
      out.push(e);
      const k = r.scope + "|" + r.name; if (!byRule.has(k)) byRule.set(k, new Set()); byRule.get(k).add(d.id);
    }
  }
  // rules on fewer firewalls and with narrower addresses are stronger evidence
  for (const e of out) e.weight = (e.sSpec && e.dSpec ? 1 : 0.6) * (0.75 + (Math.min(e.lenS, 32) + Math.min(e.lenD, 32)) / 256) / Math.sqrt(Math.max(1, byRule.get(e.rule.scope + "|" + e.rule.name).size));
  return out;
}
function zoneIfaces(dev, vsys, zones) {
  const out = [];
  for (const it of dev.interfaces.values()) if (it.vr && it.zone && (!vsys || it.vsys === vsys) && zones.includes(it.zone) && it.ips.length) out.push(it);
  return out;
}
/* Internet edges: interfaces where a static default route leaves toward a public next hop, a public
 * interface address, or a zone named like the internet. */
function internetEdges(G) {
  if (G._inet) return G._inet;
  const out = [], probe = { lo: ip2n("203.0.113.77"), hi: ip2n("203.0.113.77"), len: 32 };
  for (const d of G.devices) {
    const seen = new Set();
    for (const vr of new Set(d.vrs.values())) {
      if (!vr.routes.some((r) => (r.dest.len || 0) === 0 && r.type === "static")) continue;
      const own = vrOwner(d, vr, vr.owner || d.vsys.keys().next().value);
      const f = resolveForward(d, vr.name, probe, own);
      if (f.kind !== "iface" || !f.ifObj || seen.has(f.ifObj.name)) continue;
      const it = f.ifObj, nh = f.nexthop ? ip2n(f.nexthop) : null;
      const why = [];
      if (nh != null && !isPrivateN(nh)) why.push("default route to public next hop " + f.nexthop);
      if (it.ips.some((x) => !isPrivateN(x.ip))) why.push("public interface address");
      if (looksInternet(it.zone) && !/mpls|wan/i.test(it.zone || "")) why.push("zone " + it.zone);
      if (nh != null && G.ipOwner.has(nh)) continue; // default points at another firewall: not an edge
      const rtr = nh != null && G.nodes.get("rtr:" + f.nexthop);
      if (rtr && rtr.core && rtr.coreStrong) continue; // default into the WAN/MPLS core
      if (!why.length) continue;
      seen.add(it.name);
      out.push({ dev: d, iface: it, vsys: it.vsys, zone: it.zone, vr: vr.name, nexthop: f.nexthop || null, why: why.join(", ") });
    }
  }
  G._inet = out;
  return out;
}
function dnatEdgesFor(G, dst) {
  // internet edges with a destination NAT rule whose original destination covers dst
  const out = new Set();
  for (const E of internetEdges(G)) {
    for (const ctx of E.dev.vsys.values()) for (const r of ctx.nat) {
      if (r.disabled || !r.dnat && !(r.snat && r.snat.bidir)) continue;
      const D = cached(r, "dst" + ctx.uid, () => resolveAddrs(r.destination, ctx.scopes));
      if (r.dnat && D.ranges.some((x) => x.lo <= dst.lo && x.hi >= dst.hi)) out.add(E.dev.id);
      if (r.dnat) { const t = resolveSingleIp(r.dnat.addr, ctx.scopes, []); if (t && t.lo <= dst.lo && t.hi >= dst.hi) out.add(E.dev.id); } // traced by its translated (private) address
      if (r.snat && r.snat.bidir) { const t = resolveSingleIp(r.snat.addrs[0], ctx.scopes, []); if (t && t.lo <= dst.lo && t.hi >= dst.hi) out.add(E.dev.id); }
    }
  }
  return out;
}

/* ------------------------------------------------------------------ topology for the Network map */
function topology(devices, links) {
  const G = getGraph(devices, links);
  const nodes = [], edges = [];
  for (const n of G.nodes.values()) {
    if (n.type === "fw") nodes.push({ id: n.id, type: "fw", label: n.label, multiVsys: n.dev.multiVsys, vsys: n.dev.vsys.size, kind: n.dev.kind });
    else if (n.type === "seg") nodes.push({ id: n.id, type: "seg", label: n.label, fws: n.fws.length, routers: n.routers.length, hints: [...n.hints], stub: n.fws.length === 1 && !n.routers.length });
    else if (n.type === "rtr") nodes.push({ id: n.id, type: "rtr", label: n.label, core: !!n.core, private: !!n.private, why: n.core || n.inferred || "next hop", inferred: !!n.inferred, usedBy: n.usedBy.length });
    else nodes.push({ id: n.id, type: "core", label: n.label, members: n.members.length });
  }
  for (const e of G.edges) if (e.kind !== "rnh")
    edges.push({ a: e.a, b: e.b, kind: e.kind, label: e.kind === "if" ? e.meta.iface : e.kind === "nh" ? e.meta.fromIf + " -> " + e.meta.nh : e.kind === "link" ? e.meta.label : "" });
  return { nodes, edges };
}

/* ------------------------------------------------------------------ environment view
 * All firewalls grouped by inferred site, HA pairs merged, with vsys/zones/interfaces, routers, WAN core, internet edges and BGP fabrics.
 * Site inference (each rule documented, no data-specific values): firewalls in one HA group; firewalls sharing a subnet that is not
 * on the WAN core; firewalls whose hostnames share the same site token once firewall words and unit numbers are removed;
 * firewalls in a device group used by no more than two firewalls. */
const FW_WORD = /^(fw|fwl|ngfw|firewall|pa|pan|palo|vm|ha|pri|sec|primary|secondary|active|passive|node|unit)$/;
/* Site token from a hostname: drop firewall words and the unit number that follows one (fw1, fw-02, pa-a), and a trailing a/b unit letter. Other numbers stay (site numbers). */
/* Site of a firewall from its hostname (or name); serial-only names have no site. */
function siteKey(d) { const t = siteOfDev(d); if (!t) return null; const parts = t.split("-"); while (parts.length > 1 && /^\d+[ab]?$/.test(parts[parts.length - 1])) parts.pop(); return parts.join("-"); }
function siteOfDev(d) { const t = siteToken((d && (d.hostname || d.name)) || ""); return t && !/^\d+$/.test(t) ? t : null; }
function siteToken(name) {
  const raw = String(name || "").toLowerCase().split(/[-_.\s]+/).filter(Boolean), out = [];
  for (let i = 0; i < raw.length; i++) {
    const m = /^([a-z]+)(\d+[ab]?|[ab])?$/.exec(raw[i]);
    if (m && FW_WORD.test(m[1])) { if (!m[2] && raw[i + 1] && /^(\d+[ab]?|[ab])$/.test(raw[i + 1])) i++; continue; }
    if (i === raw.length - 1 && /^[ab]$/.test(raw[i])) continue;
    out.push(i === raw.length - 1 ? raw[i].replace(/^(\d+)[ab]$/, "$1") : raw[i]);
  }
  return out.length ? out.join("-") : null;
}
function environment(devices, links) {
  const G = getGraph(devices, links), ha = G.ha;
  const primOf = (d) => (ha && ha.primaryOf(d)) || d;
  const units = new Map();
  for (const d of devices) { const P = primOf(d); if (!units.has(P.id)) units.set(P.id, { id: P.id, name: P.name, dev: P, members: [] }); units.get(P.id).members.push(d.name); }
  const coreR = new Set(G.edges.filter((e) => e.kind === "core").flatMap((e) => [e.a, e.b]).filter((x) => x.startsWith("rtr:")));
  const parent = new Map([...units.keys()].map((k) => [k, k])), why = new Map();
  const find = (x) => { while (parent.get(x) !== x) { parent.set(x, parent.get(parent.get(x))); x = parent.get(x); } return x; };
  const union = (a, b, w) => { a = find(a); b = find(b); if (a === b) return; parent.set(b, a); why.set(a, [...new Set([...(why.get(a) || []), ...(why.get(b) || []), w])]); };
  const uid = (devId) => { const d = devices.find((x) => x.id === devId); return d ? primOf(d).id : devId; };
  const wanUnits = new Set();
  for (const n of G.nodes.values()) {
    if (n.type !== "seg") continue;
    const us = [...new Set(n.fws.map((f) => uid(f.devId)))].filter((u) => units.has(u));
    const onCore = n.routers.some((r) => coreR.has(r));
    if (onCore) { us.forEach((u) => wanUnits.add(u)); continue; }
    // point-to-point, link-local and tunnel subnets join different sites; a shared LAN means the same site
    if (n.len >= 30 || (n.lo >= 2851995648 && n.lo <= 2852061183) || n.fws.some((f) => /^tunnel/.test(f.iface))) continue;
    for (let i = 1; i < us.length; i++) union(us[0], us[i], "shared subnet " + n.label);
  }
  const byTok = new Map(); for (const u of units.values()) { const t = siteToken(u.name); if (t) { if (!byTok.has(t)) byTok.set(t, []); byTok.get(t).push(u.id); } }
  for (const [t, l] of byTok) for (let i = 1; i < l.length; i++) union(l[0], l[i], "hostname '" + t + "'");
  const byDg = new Map(); for (const u of units.values()) { const dg = (u.dev.vsys.get("vsys1") || [...u.dev.vsys.values()][0] || {}).dg; if (dg) { if (!byDg.has(dg)) byDg.set(dg, []); byDg.get(dg).push(u.id); } }
  for (const [dg, l] of byDg) if (l.length === 2) union(l[0], l[1], "device group " + dg);
  const fab = (G.inference && G.inference.fabricList) || [];
  const out = { sites: [], units: [], fabrics: fab.map((f) => ({ key: f.key, ebgp: f.ebgp, units: [...new Set(f.devIds.map(uid))] })), wanRouters: coreR.size };
  const siteOf = new Map();
  for (const u of units.values()) {
    const d = u.dev, r = find(u.id);
    if (!siteOf.has(r)) { siteOf.set(r, { id: "site:" + r, units: [], why: why.get(r) || [] }); out.sites.push(siteOf.get(r)); }
    const vrs = [...new Set(d.vrs.values())];
    const inet = [];
    for (const vr of vrs) for (const rt of vr.routes) {
      if (rt.dest.len !== 0 || rt.type === "connected") continue;
      const nh = rt.nexthop && rt.nexthop.type === "ip" ? ip2n(rt.nexthop.value) : null;
      let ifn = rt.iface; if (!ifn && nh != null) for (const it of d.interfaces.values()) if (it.ips.some((p) => p.len < 32 && Math.floor(p.ip / Math.pow(2, 32 - p.len)) === Math.floor(nh / Math.pow(2, 32 - p.len)))) ifn = it.name;
      const it = ifn && d.interfaces.get(ifn);
      if (it && nh != null && !isPrivateN(nh) && !(it.ips[0] && isPrivateN(it.ips[0].ip))) inet.push({ iface: it.name, zone: it.zone, vr: vr.name });
    }
    const U = { id: u.id, name: u.name, members: u.members, memberParts: u.members.map((m) => devParts(devices.find((x) => x.name === m) || { name: m })), memberIds: u.members.map((m) => { const d = devices.find((x) => x.name === m) || {}; return { serial: d.serial || (d.panorama && d.panorama.serial) || null, stack: d.stack || (d.panorama && d.panorama.stack) || null }; }), site: siteOf.get(r).id, kind: d.kind, multiVsys: d.multiVsys, wan: wanUnits.has(u.id), internet: inet, noNetwork: !d.interfaces.size,
      dynamic: [...new Set(vrs.flatMap((v) => v.dynamic || []))],
      vrs: vrs.map((v) => ({ name: v.name, engine: v.engine, static: v.routes.filter((x) => x.type === "static").length, dynamic: v.dynamic || [] })),
      vsys: [...d.vsys.values()].map((v) => ({ name: v.name, display: v.display, isSG: v.isSG, dg: v.dg || null,
        zones: [...v.zones.values()].map((z) => ({ name: z.name, type: z.type, ext: z.type === "external" ? z.members : null,
          ifaces: [...d.interfaces.values()].filter((i) => i.zone === z.name && i.vsys === v.name).map((i) => ({ name: i.name, ips: i.ips.map((p) => p.text), vr: i.vr })) })) })) };
    out.units.push(U); siteOf.get(r).units.push(U.id);
  }
  for (const S of out.sites) {
    const us = S.units.map((id) => out.units.find((u) => u.id === id));
    const toks = [...new Set(us.map((u) => siteToken(u.name)).filter(Boolean))];
    const dgs = [...new Set(us.flatMap((u) => u.vsys.map((v) => v.dg)).filter(Boolean))];
    S.label = toks.length === 1 ? toks[0] : us.length === 1 ? us[0].name : dgs.length === 1 ? dgs[0] : us[0].name + " +" + (us.length - 1);
  }
  out.sites.sort((a, b) => b.units.length - a.units.length || a.label.localeCompare(b.label));
  return out;
}
/* Box layout shared by the SVG view and the draw.io export. opts: { expanded: Set(unitId), match: (unit) => bool, cols } */
function trunc2(s, n) { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n - 1) + "\u2026" : s; }
function envLayout(env, opts) {
  opts = opts || {};
  const exp = opts.expanded || new Set(), match = opts.match || (() => true);
  const shapes = [], edges = [], UW = 230, PAD = 14, GAP = 26;
  const unitH = (u) => { if (!exp.has(u.id)) return 54; let h = 50; for (const v of u.vsys) { h += 20; for (const z of v.zones) h += 16 + Math.max(0, z.ifaces.length) * 13; } return h + 8; };
  const sites = env.sites.map((S) => ({ S, us: S.units.map((id) => env.units.find((u) => u.id === id)).filter(match) })).filter((x) => x.us.length);
  const cols = opts.cols || Math.max(1, Math.min(5, Math.ceil(Math.sqrt(sites.length))));
  // public-space map circuits: one cloud per circuit name; inside the site when all its firewalls are in that site, else in the top band
  const unitOf = (dev) => env.units.find((x) => x.name === dev || (x.members || []).includes(dev));
  const visIds = new Set(sites.flatMap((x) => x.us.map((u) => u.id))), siteOf = new Map();
  for (const x of sites) for (const u of x.us) siteOf.set(u.id, x.S.id);
  const circs = new Map();
  for (const c of opts.circuits || []) { const u = unitOf(c.device); if (!u || !visIds.has(u.id)) continue; const k = c.circuit || "(unnamed circuit)"; if (!circs.has(k)) circs.set(k, { name: k, us: new Set(), pf: [] }); circs.get(k).us.add(u.id); circs.get(k).pf.push(c.prefix); }
  const siteCirc = new Map(), topCirc = [];
  for (const c of circs.values()) { const ss = new Set([...c.us].map((u) => siteOf.get(u))); if (ss.size === 1) { const k = [...ss][0]; if (!siteCirc.has(k)) siteCirc.set(k, []); siteCirc.get(k).push(c); } else topCirc.push(c); }
  const CW = 104, CH = 56, circLabel = (c) => trunc2(c.name, 18) + "\n" + (c.pf.length === 1 ? c.pf[0] : c.pf.length + " prefixes");
  const circEdges = (c, id) => { for (const u of c.us) edges.push({ id: "ec:" + c.name + ":" + u, s: "u:" + u, t: id, kind: "inet", label: c.pf.length > 1 ? c.pf.length + " prefixes" : c.pf[0] }); };
  const topPer = Math.max(1, Math.floor((cols * (UW * 2 + PAD * 3 + GAP)) / (CW + 14)));
  const topRows = Math.ceil(topCirc.length / topPer);
  topCirc.forEach((c, i) => { const id = "circ:" + c.name; shapes.push({ id, kind: "cloud", circuit: true, x: 20 + (i % topPer) * (CW + 14), y: 120 + Math.floor(i / topPer) * (CH + 12), w: CW, h: CH, label: circLabel(c), title: "Circuit " + c.name + ": " + c.pf.join(", ") }); circEdges(c, id); });
  const top = 150 + topRows * (CH + 12), colY = new Array(cols).fill(top);
  const anyWan = env.units.some((u) => u.wan), anyInet = env.units.some((u) => u.internet.length);
  const totalW = cols * (UW * 2 + PAD * 3 + GAP);
  if (anyWan) shapes.push({ id: "wan", kind: "cloud", x: totalW / 2 - 110, y: 20, w: 220, h: 80, label: "WAN / MPLS core (inferred)\n" + env.wanRouters + " routers" });
  if (anyInet) shapes.push({ id: "inet", kind: "cloud", x: 20, y: 20, w: 180, h: 80, label: "Internet" });
  const vis = new Set(sites.flatMap((x) => x.us.map((u) => u.id)));
  env.fabrics.filter((f) => f.units.some((u) => vis.has(u))).forEach((f, i) => {
    const fid = "fab:" + f.key;
    shapes.push({ id: fid, kind: "fabric", x: 240 + i * 170, y: 30, w: 150, h: 60, label: (f.ebgp ? "eBGP " : "iBGP ") + f.key.replace(/^[ei]bgp-as:/, "AS ") });
    for (const u of f.units) if (vis.has(u)) edges.push({ id: "ef:" + f.key + ":" + u, s: "u:" + u, t: fid, kind: "bgp" });
  });
  sites.forEach(({ S, us }) => {
    const c = colY.indexOf(Math.min(...colY)), per = us.length > 1 ? 2 : 1;
    const rows = []; for (let i = 0; i < us.length; i += per) rows.push(us.slice(i, i + per));
    const rh = rows.map((r) => Math.max(...r.map(unitH)));
    const w = per * UW + (per + 1) * PAD;
    const sc = siteCirc.get(S.id) || [], cper = Math.max(1, Math.floor((w - PAD) / (CW + 10))), cband = sc.length ? Math.ceil(sc.length / cper) * (CH + 10) : 0;
    const h = 34 + cband + rh.reduce((a, b) => a + b + PAD, 0);
    const x = 20 + c * (UW * 2 + PAD * 3 + GAP), y = colY[c];
    shapes.push({ id: S.id, kind: "site", x, y, w, h, label: "Site: " + S.label + " (" + us.length + ")", title: S.why.join("; ") });
    sc.forEach((ci, i) => { const id = "circ:" + ci.name; shapes.push({ id, kind: "cloud", circuit: true, x: x + PAD + (i % cper) * (CW + 10), y: y + 30 + Math.floor(i / cper) * (CH + 10), w: CW, h: CH, label: circLabel(ci), title: "Circuit " + ci.name + ": " + ci.pf.join(", ") }); circEdges(ci, id); });
    let yy = y + 34 + cband;
    rows.forEach((r, ri) => {
      r.forEach((u, k) => {
        const ux = x + PAD + k * (UW + PAD), uh = unitH(u);
        const badges = [u.members.length > 1 ? "HA " + u.members.length : "", u.multiVsys ? u.vsys.length + " vsys" : "", u.dynamic.length ? u.dynamic.join("/").toUpperCase() : "", u.internet.length ? "internet edge" : "", u.noNetwork ? "no network config" : ""].filter(Boolean).join(" | ");
        shapes.push({ id: "u:" + u.id, unit: u.id, kind: "fw", x: ux, y: yy, w: UW, h: uh, label: unitTitle(u), sub: [unitIds(u), badges].filter(Boolean).join(" | "), expanded: exp.has(u.id) });
        if (exp.has(u.id)) {
          let zy = yy + 50;
          for (const v of u.vsys) {
            shapes.push({ id: "v:" + u.id + ":" + v.name, kind: "vsys", x: ux + 6, y: zy, w: UW - 12, h: 18, label: (v.isSG ? "shared gateway " : "") + v.name + (v.display && v.display !== v.name ? " " + v.display : "") + (v.dg ? " [DG " + v.dg + "]" : "") }); zy += 20;
            for (const z of v.zones) {
              const zh = 14 + z.ifaces.length * 13;
              shapes.push({ id: "z:" + u.id + ":" + v.name + ":" + z.name, kind: z.ext ? "zext" : "zone", x: ux + 12, y: zy, w: UW - 24, h: zh, label: "zone " + z.name + (z.ext ? " -> " + z.ext.join(",") : ""), lines: z.ifaces.map((i) => i.name + " " + i.ips.join(", ") + (i.vr ? " [" + i.vr + "]" : "")) });
              zy += zh + 2;
            }
          }
        }
        if (u.wan && anyWan) edges.push({ id: "ew:" + u.id, s: "u:" + u.id, t: "wan", kind: "wan" });
        if (u.internet.length && anyInet) edges.push({ id: "ei:" + u.id, s: "u:" + u.id, t: "inet", kind: "inet", label: u.internet.map((i) => i.iface).join(",") });
      });
      yy += rh[ri] + PAD;
    });
    colY[c] = y + h + GAP;
  });
  return { shapes, edges, width: Math.max(totalW + 20, 600), height: Math.max(...colY) + 40 };
}
/* Panorama view: Panorama -> device-group tree -> managed firewalls (HA merged), plus template stacks/templates and,
   optionally, the inferred network (WAN core, internet, BGP fabrics). Works on the environment() units. */
function panoramaView(pano, env, devices) {
  const byName = new Map(devices.map((d) => [d.name, d]));
  const units = env.units.map((u) => {
    const devs = u.members.map((m) => byName.get(m)).filter(Boolean);
    const dgs = [...new Set(u.vsys.map((v) => v.dg).filter(Boolean))];
    const stacks = [...new Set(devs.map((d) => d.stack).filter(Boolean))];
    const serials = devs.map((d) => d.serial).filter(Boolean);
    const fromPano = devs.some((d) => d.kind === "panorama");
    const flags = [];
    if (fromPano && !dgs.length) flags.push("no device group");
    if (fromPano && devs.some((d) => !d.stack)) flags.push(devs.some((d) => d.mergedLocal) ? "no template stack (network from local backup)" : "no template stack (mapped only)");
    if (u.noNetwork) flags.push("no network config");
    return { id: u.id, name: u.name, members: u.members, serials, dgs, stacks, flags, fromPano, unit: u };
  });
  const loadedSerials = new Set(units.flatMap((u) => u.serials));
  const dgs = new Map();
  for (const g of pano.dgs.values()) dgs.set(g.name, { name: g.name, parent: g.parent && pano.dgs.has(g.parent) ? g.parent : null, children: [], units: [], extra: [], ghosts: [] });
  for (const g of dgs.values()) if (g.parent) dgs.get(g.parent).children.push(g.name);
  for (const u of units) { if (!u.dgs.length) continue; const home = dgs.get(u.dgs[0]); if (home) home.units.push(u.id); for (const x of u.dgs.slice(1)) if (dgs.get(x)) dgs.get(x).extra.push(u.id); }
  for (const g of pano.dgs.values()) for (const d of g.devices || []) if (!loadedSerials.has(d.serial)) { const mg = pano.managed && pano.managed.get(d.serial); dgs.get(g.name).ghosts.push({ serial: d.serial, hostname: (mg && mg.hostname) || (pano.hostBySerial && pano.hostBySerial.get(d.serial)) || null }); }
  const depthOf = (n) => { let k = 0, c = dgs.get(n); const seen = new Set(); while (c && c.parent && !seen.has(c.name)) { seen.add(c.name); k++; c = dgs.get(c.parent); } return k; };
  for (const g of dgs.values()) g.depth = depthOf(g.name);
  const inStack = new Set();
  const stacks = [...pano.stacks.values()].map((st) => { st.templates.forEach((t) => inStack.add(t)); return { name: st.name, templates: st.templates.slice(), serials: st.devices.map((d) => d.serial), units: units.filter((u) => u.stacks.includes(st.name)).map((u) => u.id) }; });
  const orphanTemplates = [...pano.templates.keys()].filter((t) => !inStack.has(t));
  const ghosts = [...dgs.values()].reduce((a, g) => a + g.ghosts.length, 0);
  return { name: pano.hostname || "Panorama", dgs: [...dgs.values()], stacks, orphanTemplates, units,
    counts: { firewalls: units.length, ha: units.filter((u) => u.members.length > 1).length, dgs: dgs.size, stacks: stacks.length, templates: pano.templates.size, noDg: units.filter((u) => u.fromPano && !u.dgs.length).length,
      noStack: units.filter((u) => u.flags.some((f) => /no template stack/.test(f))).length, noNetwork: units.filter((u) => u.unit.noNetwork).length, notLoaded: ghosts, emptyDgs: [...dgs.values()].filter((g) => !g.units.length && !g.ghosts.length && !g.children.length).length } };
}
/* Card title: hostname (or name) of each HA member; ids line: serials and template stack. */
function unitTitle(u) { return (u.memberParts || u.members.map((m) => [m])).map((p) => p[0]).join(" + "); }
function unitIds(u) { const xs = [], title = new Set((u.memberParts || []).map((p) => p[0])); for (const k of ["serial", "stack"]) for (const m of u.memberIds || []) if (m[k] && !xs.includes(m[k]) && !title.has(m[k])) xs.push(m[k]); return xs.join(" \u00b7 "); }
/* Shapes of one firewall card (collapsed or expanded), shared by both environment layouts. */
function envUnitH(u, exp) { if (!exp.has(u.id)) return 54; let h = 50; for (const v of u.vsys) { h += 20; for (const z of v.zones) h += 16 + Math.max(0, z.ifaces.length) * 13; } return h + 8; }
function envUnitShapes(u, ux, yy, UW, exp, shapes, extraSub) {
  const badges = [u.members.length > 1 ? "HA " + u.members.length : "", u.multiVsys ? u.vsys.length + " vsys" : "", u.dynamic.length ? u.dynamic.join("/").toUpperCase() : "", u.internet.length ? "internet edge" : "", u.noNetwork ? "no network config" : ""].concat(extraSub || []).filter(Boolean).join(" | ");
  const uh = envUnitH(u, exp);
  shapes.push({ id: "u:" + u.id, unit: u.id, kind: "fw", x: ux, y: yy, w: UW, h: uh, label: unitTitle(u), sub: [unitIds(u), badges].filter(Boolean).join(" | "), expanded: exp.has(u.id) });
  if (exp.has(u.id)) {
    let zy = yy + 50;
    for (const v of u.vsys) {
      shapes.push({ id: "v:" + u.id + ":" + v.name, kind: "vsys", x: ux + 6, y: zy, w: UW - 12, h: 18, label: (v.isSG ? "shared gateway " : "") + v.name + (v.display && v.display !== v.name ? " " + v.display : "") + (v.dg ? " [DG " + v.dg + "]" : "") }); zy += 20;
      for (const z of v.zones) {
        const zh = 14 + z.ifaces.length * 13;
        shapes.push({ id: "z:" + u.id + ":" + v.name + ":" + z.name, kind: z.ext ? "zext" : "zone", x: ux + 12, y: zy, w: UW - 24, h: zh, label: "zone " + z.name + (z.ext ? " -> " + z.ext.join(",") : ""), lines: z.ifaces.map((i) => i.name + " " + i.ips.join(", ") + (i.vr ? " [" + i.vr + "]" : "")) });
        zy += zh + 2;
      }
    }
  }
  return uh;
}
/* Left to right: templates -> template stacks -> Panorama -> device groups (tree) -> firewalls -> network (optional).
   opts: { expanded, match(unit), q (matches DG/stack names), network: bool, circuits: public-space map entries (drawn as circuit clouds when network is on), stackLinks: bool } */
function panoLayout(P, env, opts) {
  opts = opts || {};
  const exp = opts.expanded || new Set(), match = opts.match || (() => true), q = (opts.q || "").toLowerCase();
  const shapes = [], edges = [], UW = 230, GAP = 12, DGW = 180, DGX = 640, LV = 200;
  const U = new Map(P.units.map((u) => [u.id, u]));
  const dgBy = new Map(P.dgs.map((g) => [g.name, g]));
  // which DGs to show: those with a visible firewall in their subtree (or whose name matches the filter)
  const subtreeHas = new Map();
  const vis = (g) => { if (subtreeHas.has(g.name)) return subtreeHas.get(g.name); subtreeHas.set(g.name, false);
    const nameHit = q && g.name.toLowerCase().includes(q);
    const r = nameHit || g.units.some((id) => match(U.get(id).unit)) || g.extra.some((id) => match(U.get(id).unit)) || (!q && g.ghosts.length > 0) || g.children.some((c) => vis(dgBy.get(c))) || (!q && !!opts.showEmpty);
    subtreeHas.set(g.name, r); return r; };
  const nameHitDg = (g) => { for (let c = g; c; c = c.parent ? dgBy.get(c.parent) : null) if (q && c.name.toLowerCase().includes(q)) return true; return false; };
  const maxDepth = Math.max(0, ...P.dgs.filter(vis).map((g) => g.depth));
  const FX = DGX + (maxDepth + 1) * LV + 20;
  let y = 30, fwRight = FX + UW;
  const place = (g) => {
    if (!vis(g)) return null;
    const y0 = y, kids = g.children.map((c) => dgBy.get(c)).sort((a, b) => a.name.localeCompare(b.name)).map(place).filter(Boolean);
    const hit = nameHitDg(g);
    const mine = g.units.map((id) => U.get(id)).filter((u) => u && (hit || match(u.unit)));
    const cards = mine.length + (q ? 0 : g.ghosts.length);
    if (cards) {
      const cols = Math.max(1, Math.min(3, Math.ceil(cards / 8)));
      let row = [], rowH = 0, k = 0;
      const flush = () => { y += rowH + GAP; rowH = 0; k = 0; };
      for (const u of mine) {
        const ux = FX + k * (UW + GAP);
        const sub = u.flags.slice(); sub.warn = u.flags.length > 0;
        const h = envUnitShapes(u.unit, ux, y, UW, exp, shapes, sub.concat(u.stacks.filter((st) => !unitIds(u.unit).split(" \u00b7 ").includes(st)).map((st) => "stack " + st)));
        if (u.flags.length) shapes.find((s) => s.id === "u:" + u.id).warn = true;
        edges.push({ id: "td:" + g.name + ":" + u.id, s: "dg:" + g.name, t: "u:" + u.id, kind: "tree", dir: "h" });
        rowH = Math.max(rowH, h); fwRight = Math.max(fwRight, ux + UW); if (++k >= cols) flush();
      }
      if (!q) for (const gh of g.ghosts) {
        const ux = FX + k * (UW + GAP);
        shapes.push({ id: "gh:" + g.name + ":" + gh.serial, kind: "ghost", x: ux, y, w: UW, h: 44, label: gh.hostname ? gh.hostname + " \u00b7 " + gh.serial : gh.serial, sub: "in device group, not loaded (no template stack or local backup)" });
        edges.push({ id: "tg:" + g.name + ":" + gh.serial, s: "dg:" + g.name, t: "gh:" + g.name + ":" + gh.serial, kind: "tree", dir: "h" });
        rowH = Math.max(rowH, 44); fwRight = Math.max(fwRight, ux + UW); if (++k >= cols) flush();
      }
      if (k) flush();
    }
    if (!kids.length && !cards) y += 40;
    const y1 = y - GAP;
    const cy = kids.length && !cards ? (kids[0].cy + kids[kids.length - 1].cy) / 2 : (y0 + Math.max(y0 + 30, y1)) / 2;
    const empty = !g.units.length && !g.ghosts.length && !g.children.length;
    shapes.push({ id: "dg:" + g.name, kind: "dg", x: DGX + g.depth * LV, y: cy - 20, w: DGW, h: 40, label: "DG " + g.name, sub: (g.units.length ? g.units.length + " firewall" + (g.units.length > 1 ? "s" : "") : empty ? "no firewalls" : g.children.length + " child group" + (g.children.length > 1 ? "s" : "")) + (g.extra.length ? ", +" + g.extra.length + " via vsys" : ""), dim: empty });
    for (const k2 of kids) edges.push({ id: "dd:" + g.name + ":" + k2.name, s: "dg:" + g.name, t: "dg:" + k2.name, kind: "tree", dir: "h" });
    for (const id of g.extra) if (shapes.some((s) => s.id === "u:" + id)) edges.push({ id: "dx:" + g.name + ":" + id, s: "dg:" + g.name, t: "u:" + id, kind: "dgx", dir: "h" });
    return { name: g.name, cy };
  };
  const roots = P.dgs.filter((g) => !g.parent).sort((a, b) => a.name.localeCompare(b.name)).map(place).filter(Boolean);
  // firewalls with no device group
  const noDg = P.units.filter((u) => !u.dgs.length && match(u.unit));
  if (noDg.length) {
    const y0 = y; let k = 0, rowH = 0; const cols = Math.max(1, Math.min(3, Math.ceil(noDg.length / 8)));
    for (const u of noDg) { const ux = FX + k * (UW + GAP), sub = u.flags.slice(); const h = envUnitShapes(u.unit, ux, y, UW, exp, shapes, sub); const sh = shapes.find((s) => s.id === "u:" + u.id); if (u.fromPano) sh.warn = true; edges.push({ id: "tn:" + u.id, s: "dg:(none)", t: "u:" + u.id, kind: "tree", dir: "h" }); rowH = Math.max(rowH, h); fwRight = Math.max(fwRight, ux + UW); if (++k >= cols) { y += rowH + GAP; rowH = 0; k = 0; } }
    if (k) y += rowH + GAP;
    shapes.push({ id: "dg:(none)", kind: "dg", x: DGX, y: (y0 + y - GAP) / 2 - 20, w: DGW, h: 40, label: P.units.some((u) => u.fromPano) ? "No device group" : "Standalone firewalls", sub: noDg.length + " firewall" + (noDg.length > 1 ? "s" : ""), warn: P.units.some((u) => u.fromPano && !u.dgs.length) });
    roots.push({ name: "(none)", cy: (y0 + y - GAP) / 2 });
  }
  const H = Math.max(y + 20, 200);
  const pcy = roots.length ? (roots[0].cy + roots[roots.length - 1].cy) / 2 : H / 2;
  shapes.push({ id: "pano", kind: "pano", x: 420, y: pcy - 36, w: 180, h: 72, label: P.name, sub: P.counts.firewalls + " firewalls, " + P.counts.dgs + " DGs, " + P.counts.stacks + " stacks" });
  for (const r of roots) edges.push({ id: "pr:" + r.name, s: "pano", t: "dg:" + r.name, kind: "tree", dir: "h" });
  // template stacks (and their templates) to the left of Panorama
  const sts = P.stacks.filter((st) => (opts.showEmpty || st.units.length) && (!q || st.name.toLowerCase().includes(q) || st.units.some((id) => match(U.get(id).unit))));
  const tplH = (st) => Math.max(40, st.templates.length * 24);
  const totalS = sts.reduce((a, st) => a + tplH(st) + 14, 0) + (q || !opts.showEmpty ? 0 : P.orphanTemplates.length * 30);
  let sy = Math.max(20, pcy - totalS / 2);
  for (const st of sts) {
    const h = tplH(st);
    shapes.push({ id: "st:" + st.name, kind: "stack", x: 210, y: sy + h / 2 - 20, w: 170, h: 40, label: "Stack " + st.name, sub: st.units.length + " firewall" + (st.units.length === 1 ? "" : "s") + (st.serials.length > st.units.length ? " (" + st.serials.length + " serials)" : ""), dim: !st.serials.length });
    edges.push({ id: "sp:" + st.name, s: "st:" + st.name, t: "pano", kind: "stack", dir: "h" });
    st.templates.forEach((t, i) => { const id = "tp:" + st.name + ":" + t; shapes.push({ id, kind: "tpl", x: 20, y: sy + i * 24, w: 160, h: 20, label: t }); edges.push({ id: "ts:" + id, s: id, t: "st:" + st.name, kind: "stack", dir: "h" }); });
    if (opts.stackLinks) for (const id of st.units) if (shapes.some((s) => s.id === "u:" + id)) edges.push({ id: "sf:" + st.name + ":" + id, s: "st:" + st.name, t: "u:" + id, kind: "stackfw", dir: "h" });
    sy += h + 14;
  }
  if (!q && opts.showEmpty) for (const t of P.orphanTemplates) { shapes.push({ id: "tp:-:" + t, kind: "tpl", x: 20, y: sy, w: 160, h: 22, label: t + " (not in a stack)", dim: true }); sy += 30; }
  // network overlay
  let W = fwRight + 40;
  if (opts.network) {
    const NX = fwRight + 120, visU = new Set(shapes.filter((s) => s.kind === "fw").map((s) => s.unit));
    const nodes = [];
    if (env.units.some((u) => u.wan && visU.has(u.id))) nodes.push({ id: "wan", kind: "cloud", label: "WAN / MPLS core (inferred)\n" + env.wanRouters + " routers", us: env.units.filter((u) => u.wan && visU.has(u.id)).map((u) => u.id), ek: "wan" });
    if (env.units.some((u) => u.internet.length && visU.has(u.id))) nodes.push({ id: "inet", kind: "cloud", label: "Internet", us: env.units.filter((u) => u.internet.length && visU.has(u.id)).map((u) => u.id), ek: "inet" });
    for (const f of env.fabrics) { const us = f.units.filter((u) => visU.has(u)); if (us.length) nodes.push({ id: "fab:" + f.key, kind: "fabric", label: (f.ebgp ? "eBGP " : "iBGP ") + f.key.replace(/^[ei]bgp-as:/, "AS "), us, ek: "bgp" }); }
    // public-space map circuits (user entries): one cloud per circuit, edges to the firewalls its prefixes land on
    const byC = new Map();
    for (const c of opts.circuits || []) { const u = env.units.find((x) => x.name === c.device || (x.members || []).includes(c.device)); if (!u || !visU.has(u.id)) continue; const k = c.circuit || "(unnamed circuit)"; if (!byC.has(k)) byC.set(k, { us: new Set(), pf: [] }); byC.get(k).us.add(u.id); byC.get(k).pf.push(c.prefix); }
    for (const [k, v] of byC) nodes.push({ id: "circ:" + k, kind: "cloud", label: "Circuit " + k + "\n" + v.pf.slice(0, 2).join(", ") + (v.pf.length > 2 ? " +" + (v.pf.length - 2) : ""), us: [...v.us], ek: "inet" });
    const step = Math.max(110, (H - 40) / Math.max(1, nodes.length));
    nodes.forEach((n, i) => { shapes.push({ id: n.id, kind: n.kind, x: NX, y: 20 + i * step, w: n.kind === "fabric" ? 160 : 210, h: n.kind === "fabric" ? 60 : 80, label: n.label }); for (const u of n.us) edges.push({ id: "n:" + n.id + ":" + u, s: "u:" + u, t: n.id, kind: n.ek, dir: "h" }); });
    if (nodes.length) W = NX + 240;
  }
  return { shapes, edges, width: Math.max(W, 900), height: Math.max(H, sy + 20, pcy + 60) };
}
function xmlEsc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
/* draw.io / diagrams.net file (also opens in Visio via draw.io import). */
function drawioXml(L, title) {
  const ST = { cloud: "ellipse;shape=cloud;whiteSpace=wrap;html=1;fillColor=#fff7ed;strokeColor=#d97706;", site: "rounded=1;whiteSpace=wrap;html=1;fillColor=#f8fafc;strokeColor=#94a3b8;dashed=1;verticalAlign=top;align=left;spacingLeft=8;fontStyle=1;",
    fw: "rounded=1;whiteSpace=wrap;html=1;fillColor=#dbeafe;strokeColor=#2563eb;verticalAlign=top;fontStyle=1;", vsys: "rounded=0;whiteSpace=wrap;html=1;fillColor=#ede9fe;strokeColor=#7c3aed;fontSize=10;align=left;spacingLeft=4;",
    zone: "rounded=1;whiteSpace=wrap;html=1;fillColor=#ffffff;strokeColor=#64748b;fontSize=9;align=left;verticalAlign=top;spacingLeft=4;", zext: "rounded=1;whiteSpace=wrap;html=1;fillColor=#fef3c7;strokeColor=#d97706;fontSize=9;align=left;verticalAlign=top;spacingLeft=4;" };
  const ES = { wan: "endArrow=none;html=1;strokeColor=#d97706;dashed=1;", inet: "endArrow=none;html=1;strokeColor=#dc2626;", bgp: "endArrow=none;html=1;strokeColor=#16a34a;dashed=1;" };
  ST.fabric = "ellipse;shape=cloud;whiteSpace=wrap;html=1;fillColor=#dcfce7;strokeColor=#16a34a;";
  Object.assign(ST, { pano: "rounded=1;whiteSpace=wrap;html=1;fillColor=#1e3a8a;strokeColor=#1e3a8a;fontColor=#ffffff;fontStyle=1;", dg: "rounded=1;whiteSpace=wrap;html=1;fillColor=#f3e8ff;strokeColor=#7c3aed;fontStyle=1;",
    stack: "rounded=1;whiteSpace=wrap;html=1;fillColor=#ecfeff;strokeColor=#0891b2;fontStyle=1;", tpl: "rounded=0;whiteSpace=wrap;html=1;fillColor=#ffffff;strokeColor=#0891b2;fontSize=10;", ghost: "rounded=1;whiteSpace=wrap;html=1;fillColor=#f8fafc;strokeColor=#94a3b8;dashed=1;fontSize=10;" });
  Object.assign(ES, { tree: "endArrow=none;html=1;strokeColor=#7c3aed;edgeStyle=entityRelationEdgeStyle;", dgx: "endArrow=none;html=1;strokeColor=#7c3aed;dashed=1;", stack: "endArrow=none;html=1;strokeColor=#0891b2;", stackfw: "endArrow=none;html=1;strokeColor=#0891b2;dashed=1;opacity=50;" });
  let o = '<mxfile host="FlowMapper"><diagram name="' + xmlEsc(title || "Environment") + '"><mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" page="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>';
  for (const s of L.shapes) {
    const lab = [s.label, s.sub].concat(s.lines || []).filter(Boolean).map(xmlEsc).join("<br>");
    o += '<mxCell id="' + xmlEsc(s.id) + '" value="' + xmlEsc(lab) + '" style="' + (ST[s.kind] || ST.zone) + (s.warn ? "strokeColor=#d97706;strokeWidth=2;" : "") + (s.dim ? "opacity=50;" : "") + '" vertex="1" parent="1"><mxGeometry x="' + Math.round(s.x) + '" y="' + Math.round(s.y) + '" width="' + Math.round(s.w) + '" height="' + Math.round(s.h) + '" as="geometry"/></mxCell>';
  }
  for (const e of L.edges) o += '<mxCell id="' + xmlEsc(e.id) + '" value="' + xmlEsc(e.label || "") + '" style="' + (ES[e.kind] || "endArrow=none;html=1;") + '" edge="1" parent="1" source="' + xmlEsc(e.s) + '" target="' + xmlEsc(e.t) + '"><mxGeometry relative="1" as="geometry"/></mxCell>';
  return o + "</root></mxGraphModel></diagram></mxfile>";
}

/* ------------------------------------------------------------------ redacted diagnostics
 * Structure only: counts, interfaces, routes, subnets. IPs are pseudonymized with a
 * prefix-preserving keyed permutation (random key per export, never saved), names are replaced. */
function diagnostics(devices, links, seed) {
  const key = seed || (Math.random().toString(36).slice(2) + Date.now().toString(36));
  const hcache = new Map();
  const bit = (pfx) => { let h = hcache.get(pfx); if (h === undefined) { h = 2166136261; const s = key + "|" + pfx; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } h ^= h >>> 13; h = Math.imul(h, 0x5bd1e995); h ^= h >>> 15; h = h & 1; hcache.set(pfx, h); } return h; };
  const ipMap = (n) => { let bits = n.toString(2).padStart(32, "0"), out = ""; for (let i = 0; i < 32; i++) out += (Number(bits[i]) ^ bit(bits.slice(0, i))) ? "1" : "0"; return n2ip(parseInt(out, 2)); };
  const pfx = (p) => { if (!p) return null; if (p.len == null) return ipMap(p.lo) + "-" + ipMap(p.hi); const sz = Math.pow(2, 32 - p.len); const m = ip2n(ipMap(p.lo)); return n2ip(Math.floor(m / sz) * sz) + "/" + p.len; };
  const names = new Map(), cnt = {};
  const nm = (kind, v) => { if (v == null || v === "") return v; const k = kind + "|" + v; if (!names.has(k)) { cnt[kind] = (cnt[kind] || 0) + 1; names.set(k, kind + "-" + cnt[kind]); } return names.get(k); };
  const hintOf = (s) => { const m = String(s || "").match(HINT_RE); return m ? [...new Set(m.map((x) => x.toLowerCase()))] : []; };
  const out = { tool: "Palo Alto FlowMapper", format: "redacted-diagnostics/1", generated: new Date().toISOString(), note: "Structure only. Names and IP addresses are pseudonymized consistently within this file (prefix-preserving). No rules, objects, secrets or comments.", devices: [] };
  for (const d of devices) {
    const vrs = [...new Set(d.vrs.values())];
    out.devices.push({
      id: nm("fw", d.name), kind: d.kind, multiVsys: d.multiVsys,
      vsys: [...d.vsys.values()].map((v) => ({ id: nm("vsys", d.name + "/" + v.name), sharedGateway: v.isSG, zones: [...v.zones.values()].map((z) => ({ id: nm("zone", d.name + "/" + v.name + "/" + z.name), type: z.type, hints: hintOf(z.name), members: z.type === "external" ? z.members.map((m) => nm("vsys", d.name + "/" + m)) : z.members.length })),
        counts: { security: v.security.length, nat: v.nat.length, pbf: v.pbf.length }, importedRouters: v.importVrs.map((r) => nm("vr", d.name + "/" + r)), visibleVsys: v.visible.map((m) => nm("vsys", d.name + "/" + m)) })),
      interfaces: [...d.interfaces.values()].map((it) => ({ name: it.name, type: it.type, mode: it.mode, vsys: it.vsys ? nm("vsys", d.name + "/" + it.vsys) : null, zone: it.zone ? nm("zone", d.name + "/" + it.vsys + "/" + it.zone) : null, zoneHints: hintOf(it.zone), vr: it.vr ? nm("vr", d.name + "/" + it.vr) : null, ips: it.ips.map((ip) => ipMap(ip.ip) + "/" + ip.len), privateIps: it.ips.map((ip) => isPrivateN(ip.ip)), dhcp: !!it.dhcp })),
      routers: vrs.map((vr) => ({ id: nm("vr", d.name + "/" + vr.name), engine: vr.engine, dynamic: vr.dynamic, owner: vr.owner ? nm("vsys", d.name + "/" + vr.owner) : null,
        routes: vr.routes.filter((r) => r.type === "static").map((r) => ({ dest: pfx(r.dest), destPrivate: isPrivateN(r.dest.lo), nexthop: r.nexthop.type === "ip" ? { ip: ip2n(r.nexthop.value) != null ? ipMap(ip2n(r.nexthop.value)) : "unresolved" } : r.nexthop.type === "next-vr" ? { nextVr: nm("vr", d.name + "/" + r.nexthop.value) } : { type: r.nexthop.type }, iface: r.iface, metric: r.metric, ad: r.ad })) })),
      warnings: d.warnings.length
    });
  }
  out.links = (links || []).map((L) => ({ from: { device: nm("fw", (L.from || {}).device), iface: (L.from || {}).iface || null, nexthop: (L.from || {}).nexthop && ip2n(L.from.nexthop) != null ? ipMap(ip2n(L.from.nexthop)) : null }, to: { device: nm("fw", (L.to || {}).device), iface: (L.to || {}).iface || null } }));
  const G = getGraph(devices, links);
  const t = { fw: 0, seg: 0, rtr: 0, core: 0 }; for (const n of G.nodes.values()) t[n.type]++;
  out.graph = { firewalls: t.fw, segments: t.seg, sharedSegments: [...G.nodes.values()].filter((n) => n.type === "seg" && n.fws.length > 1).length, routers: t.rtr, coreRouters: G.nodes.get("core").members.length, edges: G.edges.length };
  return out;
}

/* ------------------------------------------------------------------ change suggestions */
function cliPrefixFor(dev, ctxName, what) {
  // what: 'policy' | 'network' | 'vsys'
  if (dev.kind === "panorama") {
    if (what === "policy") { const c = dev.vsys.get(ctxName); return "set device-group " + q(c && c.dg || "<device-group>") + " pre-rulebase "; }
    const t = dev.panorama.stack ? ("<template in stack " + dev.panorama.stack + ">") : dev.panorama.template;
    return "set template " + q(t) + " config " + (what === "vsys" ? "vsys " + ctxName + " " : "");
  }
  if (what === "network") return "set network ";
  if (!dev.multiVsys) return what === "policy" ? "set " : "set ";
  return (dev.vsys.get(ctxName) && dev.vsys.get(ctxName).isSG ? "set shared-gateway " : "set vsys ") + ctxName + " ";
}
function q(s) { s = String(s); return /[\s"<>]/.test(s) ? '"' + s.replace(/"/g, '\\"') + '"' : s; }
function findAddrName(scopes, p) {
  for (const s of scopes) {
    if (!s.pfxIndex) { s.pfxIndex = new Map(); for (const [n, o] of s.address) { const x = o.type !== "fqdn" && o.value && parsePrefix(o.value); if (x && !s.pfxIndex.has(x.lo + "-" + x.hi)) s.pfxIndex.set(x.lo + "-" + x.hi, n); } }
    const hit = s.pfxIndex.get(p.lo + "-" + p.hi); if (hit) return hit;
  }
  return null;
}
function findSvcName(scopes, svc) {
  if (svc.port == null) return null;
  for (const s of scopes) for (const [n, o] of s.service) if (o.defs.length === 1 && o.defs[0].proto === svc.proto && o.defs[0].ports.length === 1 && o.defs[0].ports[0][0] === svc.port && o.defs[0].ports[0][1] === svc.port && !o.defs[0].srcPorts) return n;
  if (svc.proto === "tcp" && svc.port === 443) return "service-https";
  return null;
}
function routeCli(dev, vrName, name, destText, nh) {
  const vr = dev.vrs.get(vrName);
  const pre = cliPrefixFor(dev, null, "network");
  const base = vr && vr.engine === "advanced" ? pre + (dev.kind === "panorama" ? "network " : "") + "logical-router " + q(vr.lr) + " vrf " + q(vr.vrf) + " routing-table ip static-route " + q(name) + " "
    : pre + (dev.kind === "panorama" ? "network " : "") + "virtual-router " + q(vrName) + " routing-table ip static-route " + q(name) + " ";
  const lines = [base + "destination " + destText];
  if (nh.nextVr) lines.push(base + "nexthop " + (vr && vr.engine === "advanced" ? "next-vr" : "next-vr") + " " + q(nh.nextVr));
  else { lines.push(base + "nexthop ip-address " + (nh.ip || "<next-hop-ip>")); lines.push(base + "interface " + (nh.iface || "<egress-interface>")); }
  return lines;
}

/* ------------------------------------------------------------------ inter-vsys and hairpins */
function interVsysAllowed(dev, fromCtx, toCtx) {
  const a = dev.vsys.get(fromCtx), b = dev.vsys.get(toCtx);
  if (!a || !b) return false;
  if (a.isSG || b.isSG) return true;
  return a.visible.includes(toCtx) || b.visible.includes(fromCtx) || !!externalZone(dev, fromCtx, toCtx) || !!externalZone(dev, toCtx, fromCtx);
}
const sameNet = (x, y) => x.len === y.len && x.len < 32 && subnetOf(x).lo === subnetOf(y).lo;
/* Interfaces of VR a and VR b on the same subnet (an outside switch/router joins them). */
function sharedTransit(dev, vrA, vrB) {
  const A = dev.vrs.get(vrA), B = dev.vrs.get(vrB); if (!A || !B) return null;
  for (const an of A.interfaces) { const ai = dev.interfaces.get(an); if (!ai) continue;
    for (const bn of B.interfaces) { const bi = dev.interfaces.get(bn); if (!bi || bi === ai) continue;
      for (const x of ai.ips) for (const y of bi.ips) if (sameNet(x, y)) return { out: ai, inn: bi, inIp: n2ip(y.ip), net: n2ip(subnetOf(x).lo) + "/" + x.len }; } }
  return null;
}
/* Traffic leaving `it` toward `nh` may come straight back into another VR/vsys of the same firewall. */
function hairpinAtExit(dev, it, nh, dst, src, curVr, links) {
  const nhN = nh ? ip2n(nh) : null;
  /* A user link from this firewall back to itself says what the outside router does: traffic out `it` (toward `nh`) re-enters at the named interface, usually in another vsys. It is pinned, so the trace does not flag it as an assumption. */
  for (const L of links || []) {
    const f = L.from || {}, t = L.to || {};
    if ((f.device || dev.name) !== dev.name && f.device !== dev.id) continue;
    if (!(t.device === dev.name || t.device === dev.id) || !t.iface) continue;
    if (!f.iface && !f.nexthop) continue;
    if (f.iface && f.iface !== it.name) continue;
    if (f.nexthop && f.nexthop !== nh) continue;
    const J = dev.interfaces.get(t.iface);
    if (!J || J === it || !J.vsys) continue;
    return { J, via: { kind: "hairpin", user: true, label: "user link" + (L.label ? " '" + L.label + "'" : "") + ": " + it.name + (nh ? " via " + nh : "") + " back into " + J.name + " (" + J.vsys + ")", confidence: "high" } };
  }
  if (nhN != null) for (const J of dev.interfaces.values()) if (J !== it && J.vr && J.vr !== curVr && J.ips.some((x) => x.ip === nhN)) return { J, via: { kind: "hairpin", label: "next hop " + nh + " is this firewall's " + J.name + " (" + J.vsys + ")", confidence: "high" } };
  let tgt = null;
  for (const J2 of dev.interfaces.values()) if (J2.vr && J2.vr !== curVr && J2.ips.some((x) => x.len < 32) && ifaceIpIn(J2, dst)) { tgt = J2; break; }
  if (!tgt) return hairpinBySpecificRoute(dev, it, nh, dst, curVr);
  for (const n of (dev.vrs.get(tgt.vr) || { interfaces: [] }).interfaces) { const J = dev.interfaces.get(n); if (J && J !== it && J.ips.some((x) => it.ips.some((y) => sameNet(x, y)))) return { J, via: { kind: "hairpin", label: "shared transit " + it.ips[0].text.replace(/\.\d+\//, ".x/") + " back into " + J.name + " (" + J.vsys + ")", confidence: "medium" } }; }
  const own = vrOwner(dev, dev.vrs.get(tgt.vr), tgt.vsys);
  const rv = resolveForward(dev, tgt.vr, src, own);
  if (rv.kind === "iface" && rv.ifObj && rv.ifObj !== it) return { J: rv.ifObj, via: { kind: "hairpin", label: "outside router" + (nh ? " " + nh : "") + " back into " + rv.ifObj.name + " (" + rv.ifObj.vsys + ", where " + tgt.vr + " routes replies)", confidence: "medium" } };
  /* Destination is connected on another vsys of this firewall. Traffic leaves toward an
     unknown outside router (no shared subnet; next hop is not this box) and is assumed to
     re-enter that vsys, even when that vsys has no route back for the source. Prefer a
     non-destination interface on that vsys (typically the WAN side) as the ingress, so
     policy is evaluated as inter-zone. */
  let inn = tgt;
  const tvr = dev.vrs.get(tgt.vr);
  if (tvr) {
    const nhN = nh ? ip2n(nh) : null;
    for (const n of tvr.interfaces) {
      const J = dev.interfaces.get(n);
      if (J && J !== it && J !== tgt && J.vsys === tgt.vsys && nhN != null && J.ips.some((x) => x.len < 32 && ((nhN ^ x.ip) >>> (32 - x.len)) === 0)) { inn = J; break; }
    }
    if (inn === tgt) for (const n of tvr.interfaces) {
      const J = dev.interfaces.get(n);
      if (J && J !== it && J !== tgt && J.vsys === tgt.vsys) { inn = J; break; }
    }
  }
  return { J: inn, via: { kind: "hairpin", label: "outside router" + (nh ? " " + nh : "") + " back into " + inn.name + " (" + inn.vsys + ", destination is connected there)", confidence: "medium" } };
}
function hairpinBySpecificRoute(dev, it, nh, dst, curVr) {
  if (!dst) return null;
  for (const vr of new Set(dev.vrs.values())) {
    if (!vr || vr.name === curVr) continue;
    if (vr.owner && it.vsys && vr.owner === it.vsys) continue;
    const lr = lookupRoute(vr, dst);
    if (!lr || !lr.route || !(lr.route.dest.len > 0)) continue;
    const own = vrOwner(dev, vr, vr.owner || it.vsys);
    const f = resolveForward(dev, vr.name, dst, own);
    if (f.kind === "iface" && f.ifObj && f.ifObj !== it && f.ifObj.vsys && f.ifObj.vsys !== it.vsys)
      return { J: f.ifObj, via: { kind: "hairpin", label: "outside router" + (nh ? " " + nh : "") + " back into " + f.ifObj.name + " (" + f.ifObj.vsys + ", more-specific route to the destination)", confidence: "medium" } };
  }
  return null;
}

/* ------------------------------------------------------------------ trace */
/* How the next firewall was found: user link, next hop = its interface, shared subnet, or inferred routers/WAN core. */
function stitchBasis(via, confidence, chosenBy) {
  const k = via && via.kind;
  const text = k === "link" ? "user link '" + via.label + "'" : k === "direct" ? via.label + " is that firewall's interface" : k === "segment" ? via.label : k === "hairpin" ? via.label : k === "transit" ? "inferred: " + via.label : (via && via.label) || "inferred";
  return { kind: k || "inferred", text, confidence: confidence || "medium", chosenBy: chosenBy || "routing" };
}
const NO_NET_MSG = (n) => "No network config in this Panorama export for " + n + ". Load this firewall's local backup alongside the Panorama export to trace through it.";
/* Firewalls in a device group without a template stack: rules that cover this flow, or a pin to one, get a note. */
function noNetworkFor(devices, query, opts) {
  const pq = parseQuery(query, devices), out = [];
  if (!pq.src || !pq.dst || pq.err.length) return out;
  const pins = new Set([opts.srcDevice, opts.dstDevice, opts.deviceId, ...(opts.via || [])].filter(Boolean));
  for (const d of devices) {
    if (d.interfaces.size || d.mergedLocal || d.kind !== "panorama") continue;
    let hit = pins.has(d.id) || pins.has(d.name);
    for (const v of d.vsys.values()) {
      if (hit) break;
      for (const r of v.security) {
        if (r.disabled || r.negSrc || r.negDst || r.action !== "allow") continue;
        const a = cached(r, "src" + v.uid, () => resolveAddrs(r.source, v.scopes)), b = cached(r, "dst" + v.uid, () => resolveAddrs(r.destination, v.scopes));
        if (a.any && b.any) continue;
        if (addrMatch(a, pq.src.p).m !== "no" && addrMatch(b, pq.dst.p).m !== "no") { hit = true; break; }
      }
    }
    if (hit) out.push(d.name);
  }
  return out;
}
/* ---------- Public-space / circuit map ----------
   Entries: { prefix: "198.51.100.0/24", circuit: "ISP-B", device: "fw-edge", iface: "ethernet1/4" | null, zone: "isp-b" | null }.
   Routing for public space often lives on provider/upstream routers that are not in the export; the map tells the tracer which
   firewall and interface traffic for a public prefix arrives on. Longest prefix wins; HA peers count as the same firewall. */
function circuitParse(list) {
  const out = [];
  for (const e of list || []) { const p = e && parsePrefix(String(e.prefix || "")); if (!p || !e.device) continue; out.push(Object.assign({}, e, { p })); }
  return out.sort((a, b) => b.p.len - a.p.len);
}
function circuitLookup(list, q) { for (const e of circuitParse(list)) if (rngContains(e.p, q)) return e; return null; }
function samePair(devices, a, b) { if (!a || !b) return false; if (a === b) return true; const da = devices.find((d) => d.name === a || d.id === a); return !!(da && da.haPeers && da.haPeers.includes(b)) || (devices.find((d) => d.name === b || d.id === b) || {}).haPeers?.includes(a) || false; }
function ifaceTowards(dev, q) {
  for (const vr of new Set(dev.vrs.values())) { const lr = lookupRoute(vr, q); if (!lr) continue; const own = vr.owner || [...dev.vsys.keys()][0]; const f = resolveForward(dev, vr.name, q, own); if (f.kind === "iface" && f.ifObj) return f.ifObj; }
  return null;
}
/* Resolve a map entry to {dev, iface} on the loaded devices (device by name or id; zone -> an interface of that zone). */
function circuitEntryIface(devices, e, srcQ) {
  const dev = devices.find((d) => d.name === e.device || d.id === e.device); if (!dev) return null;
  let it = e.iface ? dev.interfaces.get(e.iface) : null;
  if (!it && e.zone) { const inZ = [...dev.interfaces.values()].filter((i) => i.zone === e.zone && i.vr); const t = srcQ && ifaceTowards(dev, srcQ); it = (t && inZ.includes(t) ? t : null) || inZ.find((i) => i.ips.length) || inZ[0] || null; }
  if (!it && srcQ) it = ifaceTowards(dev, srcQ);
  return it ? { dev, iface: it } : null;
}
const providerFacing = (dev, it) => !!it && (looksInternet(it.zone) || [...new Set(dev.vrs.values())].some((vr) => vr.routes.some((r) => r.type === "static" && (r.dest.len || 0) === 0 && (r.iface === it.name || (r.nexthop && r.nexthop.type === "ip" && it.ips.some((a) => a.len < 32 && ((ip2n(r.nexthop.value) ^ a.ip) >>> (32 - a.len)) === 0))))));
/* More-specific static routes (not the default) for public prefixes that point at a provider/untrust/WAN/internet-facing
   interface: a valid way to steer the return path of provider-assigned space when a VR can only have one default route. */
function providerStatics(devices) {
  const out = [];
  for (const dev of devices) for (const vr of new Set(dev.vrs.values())) for (const r of vr.routes) {
    if (r.type !== "static" || !r.dest || !(r.dest.len > 0) || isPrivateN(r.dest.lo) || !r.nexthop || r.nexthop.type === "next-vr" || r.nexthop.type === "discard") continue;
    const own = vr.owner || [...dev.vsys.keys()][0], f = resolveForward(dev, vr.name, { lo: r.dest.lo, hi: r.dest.lo, len: 32 }, own);
    const it = f.kind === "iface" && f.ifObj ? f.ifObj : r.iface ? dev.interfaces.get(r.iface) : null;
    if (!it || !providerFacing(dev, it)) continue;
    const nh = r.nexthop.type === "ip" ? r.nexthop.value : null;
    out.push({ prefix: prefixStr(r.dest), p: r.dest, device: dev.name, devId: dev.id, iface: it.name, zone: it.zone || null, vr: vr.name, nexthop: nh, circuit: (it.zone || it.name) + (nh ? " via " + nh : ""), route: r.name, source: "static" });
  }
  return out;
}
/* Bulk accept: turn suggestions into map entries without touching user entries.
   - a prefix already in the map (exact or covered by an entry) is skipped: the user entry wins;
   - the same prefix suggested on an HA pair becomes one entry (the first member; an entry on a peer counts as the pair);
   - the same prefix suggested on two unrelated firewalls is skipped as a conflict for the user to decide. */
function bulkAcceptSuggestions(devices, circuits, list) {
  const map = circuitParse(circuits || []);
  const covered = (p) => map.some((e) => e.p.lo <= p.lo && e.p.hi >= p.hi);
  const byPrefix = new Map();
  for (const x of list || []) { if (!byPrefix.has(x.prefix)) byPrefix.set(x.prefix, []); byPrefix.get(x.prefix).push(x); }
  const accepted = [], skipped = [];
  for (const [prefix, xs] of byPrefix) {
    const p = parsePrefix(prefix);
    if (!p) { for (const x of xs) skipped.push({ s: x, reason: "not a prefix" }); continue; }
    if (covered(p)) { for (const x of xs) skipped.push({ s: x, reason: "already in the map" }); continue; }
    const devs = [...new Set(xs.map((x) => x.device))];
    const onePair = devs.length === 1 || devs.every((d) => samePair(devices, devs[0], d));
    if (!onePair) { for (const x of xs) skipped.push({ s: x, reason: "same prefix on several firewalls (" + devs.join(", ") + ")" }); continue; }
    const x = xs[0];
    accepted.push({ prefix: x.prefix, circuit: x.circuit || "", device: x.device, iface: x.iface || null, zone: x.iface ? null : x.zone || null });
    for (const y of xs.slice(1)) skipped.push({ s: y, reason: "HA peer of " + x.device + " (one entry covers the pair)", merged: true });
  }
  return { accepted, skipped };
}
/* Prefixes suggested on more than one unrelated firewall. The map holds one landing per prefix, so the user picks it.
   HA peers fold into one candidate; prefixes the map already covers (user entries) never appear. */
function suggestionConflicts(devices, circuits, list) {
  const map = circuitParse(circuits || []);
  const covered = (p) => map.some((e) => e.p.lo <= p.lo && e.p.hi >= p.hi);
  const byPrefix = new Map();
  for (const x of list || []) { if (!byPrefix.has(x.prefix)) byPrefix.set(x.prefix, []); byPrefix.get(x.prefix).push(x); }
  const out = [];
  for (const [prefix, xs] of byPrefix) {
    const p = parsePrefix(prefix); if (!p || covered(p)) continue;
    const cands = [];
    for (const x of xs) {
      const c = cands.find((y) => samePair(devices, y.device, x.device));
      if (c) { if (x.device !== c.device && !c.peers.includes(x.device)) c.peers.push(x.device); c.items.push(x); if (!c.sources.includes(x.source)) c.sources.push(x.source); continue; }
      const d = devices.find((z) => z.name === x.device || z.id === x.device) || {};
      cands.push({ device: x.device, hostname: d.hostname || null, serial: d.serial || null, stack: d.stack || null, source: x.source, sources: [x.source], iface: x.iface || null, zone: x.zone || null, circuit: x.circuit || "", why: x.why || "", peers: [], items: [x] });
    }
    if (cands.length > 1) out.push({ prefix, candidates: cands });
  }
  return out;
}
/* The map entry for one chosen candidate of a conflict (a normal entry: saved, exported, then gone from suggestions). */
function conflictEntry(c) { return { prefix: c.items[0].prefix, circuit: c.circuit || "", device: c.device, iface: c.iface || null, zone: c.iface ? null : c.zone || null }; }
/* Public prefixes the config owns or routes that the map does not cover yet: provider statics, public NAT original addresses
   (and bi-directional static NAT public sides), public interface subnets. Each is a ready-to-add map entry. */
function publicSpaceSuggestions(devices, circuits) {
  const map = circuitParse(circuits), out = [], seen = new Set();
  const covered = (p) => map.some((e) => e.p.lo <= p.lo && e.p.hi >= p.hi);
  const add = (s) => { const k = s.prefix + "|" + s.device; if (seen.has(k) || covered(s.p)) return; seen.add(k); out.push(s); };
  for (const s of providerStatics(devices)) add(Object.assign({ why: "static route " + s.route + " (" + s.vr + ") sends this public prefix to the provider side" + (s.nexthop ? " (" + s.nexthop + ")" : "") }, s));
  for (const dev of devices) {
    for (const ctx of dev.vsys.values()) for (const r of ctx.nat || []) {
      if (r.disabled) continue;
      let ranges = [];
      if (r.dnat) { const O = resolveAddrs(r.destination, ctx.scopes); if (!O.any) ranges = O.ranges; }
      else if (r.snat && r.snat.type === "static-ip" && r.snat.bidir) { const t = resolveSingleIp(r.snat.addrs[0], ctx.scopes, []); if (t) ranges = [t]; }
      for (const o of ranges) {
        if (isPrivateN(o.lo) || o.hi - o.lo > 65535) continue;
        const p = { lo: o.lo, hi: o.hi, len: o.len != null ? o.len : 32 - Math.round(Math.log2(o.hi - o.lo + 1)) };
        const zones = (r.dnat ? r.from : r.to || []).filter((z) => z !== "any");
        const it = [...dev.interfaces.values()].find((i) => i.vsys === ctx.name && zones.includes(i.zone) && i.vr) || null;
        add({ prefix: prefixStr(p), p, device: dev.name, devId: dev.id, iface: it ? it.name : null, zone: it ? it.zone : zones[0] || null, circuit: "", source: "nat", why: "public address of NAT rule " + r.name + (ctx.name !== "vsys1" ? " (" + ctx.name + ")" : "") });
      }
    }
    for (const it of dev.interfaces.values()) for (const a of it.ips) {
      if (isPrivateN(a.ip) || !it.vr || a.len >= 32 || a.len < 16) continue;
      const size = Math.pow(2, 32 - a.len), lo = Math.floor(a.ip / size) * size, p = { lo, hi: lo + size - 1, len: a.len };
      add({ prefix: prefixStr(p), p, device: dev.name, devId: dev.id, iface: it.name, zone: it.zone || null, circuit: it.zone || it.name, source: "interface", why: "public subnet on " + it.name });
    }
  }
  return out.map(({ p, ...s }) => s);
}
/* Which entry decides where traffic for this flow enters: the source's mapped space, else (public source) the destination's
   mapped space; then the same from provider statics. Returns null when nothing applies. */
function circuitDecision(devices, src, dst, circuits) {
  if (isPrivateN(src.lo)) return null;
  const user = circuitLookup(circuits, src) || (circuitLookup(circuits, dst) && !isPrivateN(dst.lo) ? circuitLookup(circuits, dst) : null);
  const st = providerStaticsCached(devices);
  const best = (q) => st.filter((s) => s.p.lo <= q.lo && s.p.hi >= q.hi).sort((a, b) => b.p.len - a.p.len)[0] || null;
  const stat = isPrivateN(dst.lo) ? null : best(dst);
  return user || stat ? { user, stat } : null;
}
const PS_CACHE = typeof WeakMap !== "undefined" ? new WeakMap() : null;
function providerStaticsCached(devices) { if (!PS_CACHE) return providerStatics(devices); let v = PS_CACHE.get(devices); if (!v) { v = providerStatics(devices); PS_CACHE.set(devices, v); } return v; }
/* No allow rule anywhere in the loaded export names this source and destination (any/any rules excluded). */
function noRuleInExport(devices, src, dst) {
  for (const d of devices) for (const v of d.vsys.values()) for (const r of v.security) {
    if (r.disabled || r.action !== "allow") continue;
    const a = cached(r, "src" + v.uid, () => resolveAddrs(r.source, v.scopes)), b = cached(r, "dst" + v.uid, () => resolveAddrs(r.destination, v.scopes));
    if (a.any && b.any) return false;
    if (addrMatch(a, src, r.negSrc).m !== "no" && addrMatch(b, dst, r.negDst).m !== "no") return false;
  }
  return true;
}
/* Entry chosen by the public-space map / a provider static: replies to the public source following the default route out
   another provider-facing interface is the expected pattern with provider-routed space (the provider side or symmetric
   return carries it), so it is reported, not required. */
/* ---------- Path status: complete / suggested / incomplete, with per-hop assumptions and alternates ----------
   complete:   every hop decided by connected/local/static routes, PBF, a user link, a direct next-hop firewall, a shared subnet,
               the public-space map or a provider static (routers and switches outside the export are not guessed).
   suggested:  some hop rests on an inferred router / WAN core, inferred BGP/OSPF, a suggested (missing) route, a hairpin over an
               unseen router, a default route toward a next hop nobody in the export owns, or a firewall picked by rules/NAT.
   incomplete: the trace stopped before the destination (no route, no next firewall, missing network config, FQDN, loop, error). */
function pathStatus(res, devices) {
  const hops = res.segments.map((s) => ({ device: s.device, vsys: s.vsys, vr: s.startVr || null, ingress: s.ingress && s.ingress.iface, egress: s.egress && s.egress.iface, assumptions: [] }));
  const assume = (i, what, confirm, kind) => { if (hops[i] && !hops[i].assumptions.some((a) => a.what === what)) hops[i].assumptions.push(kind ? { what, confirm, kind } : { what, confirm }); };
  const dstPublic = res.segments.length && res.segments[res.segments.length - 1].dstP ? !isPrivateN(res.segments[res.segments.length - 1].dstP.lo) : false;
  res.segments.forEach((s, i) => {
    const b = s.basis || {}, vr = s.startVr ? " (" + s.startVr + ")" : "";
    if (b.kind === "bgp" || b.kind === "ospf") { const dv = devices.find((d) => d.id === s.devId || d.name === s.device), v = dv && dv.vrs.get(s.startVr); s.engine = (v && v.engine) || null; }
    if (b.kind === "bgp" || b.kind === "ospf") assume(i, (b.kind === "bgp" ? "BGP-inferred: " : "OSPF-inferred: ") + "route learned by " + b.kind.toUpperCase() + " at runtime; the tool inferred it from the peers' configs: " + b.text + (b.reason ? ". Why: " + b.reason : ""), "Run '" + (s.engine === "advanced" ? "show advanced-routing route" : "show routing route") + " destination " + (s.dstPost || s.dst) + "' on " + s.device + vr + " and paste it under Route tables to confirm (pasted routes win over inference).", b.kind);
    if (b.kind === "suggested" || s.hypothetical) assume(i, s.device + " has no route for " + (s.dstPost || s.dst) + "; the path assumes the suggested route listed under changes.", "Add the route, or check 'show routing route' on " + s.device + vr + " (the route may be learned dynamically).");
    if (b.kind === "evidence") assume(i, "This hop follows the inferred path you chose; " + s.device + "'s own routing goes elsewhere.", "Pick the routing path, or add the listed route change.");
    if (b.kind === "default" && s.final && s.final.kind === "exit") {
      const it = devices.find((d) => d.id === s.devId), eg = s.egress && s.egress.zone;
      if (!(dstPublic && looksInternet(eg))) assume(i, s.device + " sends the traffic out " + (s.egress && s.egress.iface) + " by its default route" + (s.egress && s.egress.nexthop ? " to " + s.egress.nexthop : "") + "; what sits beyond that next hop is not in the export.", "Add a link to the firewall behind " + ((s.egress && s.egress.nexthop) || "that next hop") + ", or load its backup.");
    }
    if (s.final && s.final.kind === "exit" && !(dstPublic && looksInternet(s.egress && s.egress.zone)) && b.kind !== "default" && res.noNetwork && res.noNetwork.length) assume(i, "Traffic leaves toward a next hop outside the loaded configs, and firewalls with rules for this flow have no network config (" + res.noNetwork.slice(0, 3).join(", ") + ").", "Load those firewalls' local backups alongside the Panorama export.");
  });
  for (const st of res.stitches || []) {
    const i = res.segments.findIndex((s) => s.device === st.from && (!st.egress || (s.egress && s.egress.iface === st.egress)));
    const k = st.via && st.via.kind;
    if (k === "transit") assume(i < 0 ? 0 : i, "Next firewall " + st.to + " assumed through routers that are not in the export: " + st.via.label + ".", "Add a link from " + st.from + " " + (st.egress || "") + " to " + st.to + " if that is the real connection, or check the router's table.");
    else if (k === "hairpin" && !(st.via && st.via.user)) assume(i < 0 ? 0 : i, "Traffic assumed to hairpin over an outside router: " + st.via.label + ".", "Confirm the router's route back, or add a link.");
    else if (st.ambiguous) assume(i < 0 ? 0 : i, "Several firewalls fit the next hop after " + st.from + "; " + st.to + " was picked by score.", "Pick the right one in the branch list, or add a link.");
  }
  if (res.natEntry) assume(0, "Entered at " + res.natEntry.device + " " + res.natEntry.iface + " because its destination NAT owns the address; routing alone enters at " + (res.natEntry.routed ? res.natEntry.routed.device + " " + res.natEntry.routed.iface : "another firewall") + ".", "Add the public prefix to the public-space map to confirm the circuit.");
  if (res.ingress && /reverse route lookup/.test(res.ingress.how || "") && /\(0\.0\.0\.0\/0/.test(res.ingress.how) && res.segments[0] && isPrivateN(res.segments[0].srcP ? res.segments[0].srcP.lo : 0)) assume(0, "The source " + res.query.src + " is placed behind " + res.ingress.device + " only by its default route.", "Pick the source firewall or ingress interface, or add a link.");
  if (res.circuit && res.circuit.conflict) assume(0, "The public-space map and the firewall routing disagree about where " + res.circuit.prefix + " enters; the trace follows the map.", "Fix the map entry or the routing.");
  // stopped?
  const last = res.segments[res.segments.length - 1], fk = res.final && res.final.kind;
  let stop = null;
  if (!res.segments.length) stop = { where: "", why: res.summary || (res.notes[0] && res.notes[0].text) || "no firewall owns the source", fix: "Pick the source firewall and ingress interface, add the source's public prefix to the public-space map, or load the firewall that owns it." };
  else if (["no-route", "unresolved", "loop", "error"].includes(res.status) || ["no-route", "unresolved", "loop", "error"].includes(fk)) {
    const why = res.final ? res.final.text : res.status;
    stop = { where: last.device + " " + last.vsys + (last.startVr ? ", " + last.startVr : "") + (last.egress && last.egress.iface ? ", " + last.egress.iface : last.ingress && last.ingress.iface ? ", in on " + last.ingress.iface : ""), why,
      fix: fk === "unresolved" ? "The destination is an FQDN or dynamic object that cannot be resolved offline; trace the resolved IP." : fk === "loop" ? "Check the routes between these firewalls (they point at each other)." : "Add the missing route, add a link to the next firewall, or load that firewall's local backup." };
  } else if (res.plan && res.plan.total && res.plan.reached < res.plan.total && fk === "exit") {
    stop = { where: last.device + " " + last.vsys + (last.egress && last.egress.iface ? ", " + last.egress.iface : ""), why: "the next firewall on the planned path (" + ((res.plan.paths[res.plan.chosen] || {}).devices || []).slice(res.plan.reached + 1, res.plan.reached + 2).join("") + ") was not found from " + last.device + "'s routing", fix: "Add a link from " + last.device + " " + ((last.egress && last.egress.iface) || "") + " to the next firewall, or add a route." };
  } else if (fk === "exit" && res.noNetwork && res.noNetwork.length && !(dstPublic && looksInternet(last.egress && last.egress.zone))) {
    stop = { where: last.device + " " + last.vsys + (last.egress && last.egress.iface ? ", " + last.egress.iface : ""), why: "the traffic leaves the loaded firewalls, and " + res.noNetwork.length + " firewall(s) with rules for this flow have no network config", fix: "Load the local backup of " + res.noNetwork.slice(0, 3).join(", ") + (res.noNetwork.length > 3 ? " (+" + (res.noNetwork.length - 3) + " more)" : "") + " alongside the Panorama export. These firewalls have no network config in this export, so the trace cannot continue through them; their own backups also carry the HA settings (peer-ip, HA1) that are often set locally.", noNetwork: res.noNetwork.slice() };
  }
  const open = (res.sharedChoices || []).filter((c) => !c.pinned);
  if (!stop && open.length) {
    const c = open[0];
    stop = { where: c.at, why: c.reason.replace(/\.$/, ""), fix: "Pick the right firewall for " + c.what + " (" + c.candidates.length + " candidates). Pin it for this trace, or save it as a link so every trace uses it.", choice: c };
  }
  for (const c of (res.sharedChoices || []).filter((x) => x.pinned)) { const i = c.kind === "destination" ? res.segments.length - 1 : c.kind === "source" ? 0 : res.segments.findIndex((s) => c.at.startsWith(s.device)); assume(i < 0 ? 0 : i, c.what + " is shared by " + c.candidates.length + " firewalls; " + c.chosen + " was pinned by " + c.pinBy + ".", "Change the pin if " + c.chosen + " is not the right one.", "pinned"); }
  const assumed = hops.reduce((n, h) => n + h.assumptions.filter((a) => a.kind !== "pinned").length, 0);
  const status = stop ? "incomplete" : assumed ? "suggested" : "complete";
  const bgpInf = hops.some((h) => h.assumptions.some((a) => a.kind === "bgp")), observed = res.segments.some((s) => s.basis && s.basis.kind === "observed");
  const label = stop && stop.choice ? "Needs your choice" : status === "incomplete" ? "Incomplete" : status === "suggested" ? (bgpInf ? "Suggested (BGP-inferred)" : "Suggested") : observed ? "Complete (pasted route table)" : "Complete";
  const conf = status === "complete" ? "high" : status === "incomplete" ? "low" : hops.some((h) => h.assumptions.some((a) => /suggested route|inferred path you chose|disagree/.test(a.what))) ? "low" : "medium";
  // alternates (cap 5): other planned paths, then other next firewalls at ambiguous / multi-choice hops
  const P = res.plan || { paths: [], chosen: -1 };
  const alts = [];
  const cur0 = (P.paths || [])[P.chosen];
  const noNet = new Set(devices.filter((d) => d.kind === "panorama" && !d.interfaces.size && !d.mergedLocal).map((d) => d.name));
  const viaWhy = (h) => { const k = h && h.via && h.via.kind; return k === "link" ? "a link you added (" + h.from + " " + h.egIf + " to " + h.to + ")" : k === "direct" ? "the next hop " + (h.nexthop || "") + " is an interface of " + h.to : k === "segment" ? h.to + " shares the next-hop subnet " + ((h.segments && h.segments[0]) || "") + " with " + h.from : k === "transit" ? h.to + " is reached through routers outside the export (" + h.via.label + ")" : k === "hairpin" ? (h.via.user ? "a link you added (" + h.via.label + ")" : "an outside router sends it back (" + h.via.label + ")") : ""; };
  const toComplete = (hops, devs) => {
    const xs = [];
    for (const h of hops || []) {
      if (h.via && (h.via.kind === "transit" || h.via.kind === "hairpin") && !h.via.user) xs.push("add a link from " + h.from + " " + (h.egIf || "") + " to " + h.to);
      if (h.needsRoute) xs.push("add the route on " + h.from);
      if (h.inferredRoute) xs.push("confirm the dynamic route on " + h.from + " with 'show routing route'");
    }
    const nn = (devs || []).filter((d) => noNet.has(d)); if (nn.length) xs.push("load the local backup of " + nn.join(", "));
    return xs.length ? [...new Set(xs)].slice(0, 3).join("; ") : "nothing; every hop is already explicit";
  };
  const differs = (p) => {
    if (!cur0) return "";
    const a = cur0.devices || [], b = p.devices || [];
    let k = 0; while (k < a.length && k < b.length && a[k] === b[k]) k++;
    if (k < a.length || k < b.length) {
      const from = b[k - 1] || a[k - 1];
      if (!from) return "starts at " + (b[0] || "?") + " instead of " + (a[0] || "?");
      return "after " + from + " it goes to " + (b[k] || "(stops)") + " instead of " + (a[k] || "(stops)") + (b.length !== a.length ? "; " + b.length + " firewalls instead of " + a.length : "");
    }
    for (let h = 0; h < Math.min((cur0.hops || []).length, (p.hops || []).length); h++) { const x = cur0.hops[h], y = p.hops[h]; if (x.egIf !== y.egIf || x.nexthop !== y.nexthop) return "same firewalls, but " + y.from + " leaves on " + y.egIf + (y.nexthop ? " via " + y.nexthop : "") + " instead of " + x.egIf + (x.nexthop ? " via " + x.nexthop : ""); }
    return "same firewalls and exits, different route evidence";
  };
  (P.paths || []).forEach((p, i) => {
    if (i === P.chosen) return;
    const a = cur0 ? cur0.devices || [] : [], b = p.devices || []; let k = 0; while (k < a.length && k < b.length && a[k] === b[k]) k++;
    const dh = (p.hops || [])[Math.max(0, k - 1)] || (p.hops || [])[0];
    const offered = p.routing === "contradicts" ? "the security rules point this way, but routing does not" + (p.violations && p.violations[0] ? " (" + (typeof p.violations[0] === "string" ? p.violations[0] : p.violations[0].device + " " + (p.violations[0].route || "routes it elsewhere")) + ")" : "")
      : p.routing === "extends" ? "routing reaches it and the rules that allow this flow sit on it"
      : (cur0 && Math.abs((p.cost || 0) - (cur0.cost || 0)) < 0.01 ? "equal-cost option: routing fits it as well as the path shown" : "routing also fits it, at a higher cost") + (viaWhy(dh) ? "; " + viaWhy(dh) : "");
    alts.push({ kind: "path", index: i, devices: p.devices, label: p.label, confidence: p.confidence, why: p.routing === "contradicts" ? "rules' path (contradicts routing)" : p.routing === "extends" ? "rules' path (extends routing)" : "also fits routing", offered, differs: differs(p), toComplete: toComplete(p.hops, p.devices) });
  });
  for (const st of res.stitches || []) for (const a of (st.alternatives || []).filter((x) => !x.chosen && x.pathIndex == null).slice(0, 3)) if (!alts.some((y) => y.devices.join() === [st.from, a.device].join() || (y.kind === "path" && y.devices.indexOf(st.from) >= 0 && y.devices[y.devices.indexOf(st.from) + 1] === a.device))) {
    const v = String(a.via || "");
    alts.push({ kind: "branch", key: st.key, devId: a.devId, path: a.pathIndex != null ? a.pathIndex : null, devices: [st.from, a.device], label: st.from + " -> " + a.device + (a.iface ? " " + a.iface : ""), confidence: a.confidence || null,
      why: "other next firewall after " + st.from,
      offered: "another firewall also fits the next hop from " + st.from + (st.egress ? " " + st.egress : "") + (v ? " (" + v + ")" : "") + (a.score != null ? "; scored " + a.score + (st.alternatives.find((x) => x.chosen) ? " vs " + st.alternatives.find((x) => x.chosen).score + " for " + st.to : "") : ""),
      differs: "after " + st.from + " it goes to " + a.device + (a.iface ? " (" + a.iface + ")" : "") + " instead of " + st.to,
      toComplete: /router|core/.test(v) ? "add a link from " + st.from + " " + (st.egress || "") + " to the right firewall" + (noNet.has(a.device) ? "; load the local backup of " + a.device : "") : noNet.has(a.device) ? "load the local backup of " + a.device : "nothing; the hop is explicit" });
  }
  const cur = (P.paths || [])[P.chosen];
  const rank = { high: 3, medium: 2, low: 1 };
  const weak = !!cur && (cur.confidence === "low" || cur.routing === "contradicts");
  const stronger = weak ? alts.find((a) => a.kind === "path" && (rank[a.confidence] || 0) > (rank[cur.confidence] || 0) && !/contradicts/.test(a.why)) || null : null;
  return { status, label, bgpInferred: bgpInf, choices: res.sharedChoices || [], confidence: conf, hops, stop, assumed, alternates: alts.slice(0, 5), moreAlternates: Math.max(0, alts.length - 5), weak, stronger,
    text: status === "complete" ? "Every hop comes from explicit routes, links" + (observed ? ", pasted route tables" : "") + " or the public-space map." : status === "suggested" ? assumed + " assumption" + (assumed === 1 ? "" : "s") + " about routers or routes outside the export" + (bgpInf ? " (at least one hop rests on a BGP route inferred from the peers' configs; paste that firewall's route table to confirm it)" : "") + "." : stop.choice ? "Needs your choice at " + stop.where + ": " + String(stop.why).replace(/\.+$/, "") + "." : "Stopped at " + stop.where + ": " + String(stop.why).replace(/\.+$/, "") + "." };
}
function circuitReturnOk(res, devices) {
  const seg = res.segments[0], r = res.returnPath && res.returnPath.find((x) => x.device === (seg && seg.device) && x.asym);
  if (!seg || !r) return;
  const dev = devices.find((d) => d.id === seg.devId) || devices.find((d) => d.name === seg.device); if (!dev) return;
  const m = / replies route out (\S+)/.exec(r.text || ""), out = m && dev.interfaces.get(m[1]);
  if (!out || !providerFacing(dev, out)) return;
  r.asym = false; r.ok = true; r.circuitReturn = true;
  for (const c of res.changes) if (c.kind === "route" && c.device === seg.device && /^Add return route in /.test(c.summary || "") && c.summary.includes(" to " + seg.src + " ")) c.optional = true;
  res.notes = res.notes.filter((n) => !(n.level === "warn" && n.text.startsWith(seg.device + " " + seg.vsys + ": Asymmetric")));
  res.notes.push({ level: "info", text: seg.device + ": traffic enters " + seg.ingress.iface + " by the public-space map / provider static, and replies to " + seg.src + " follow the default route out " + out.name + " (another provider-facing interface). Expected with provider-routed public space; if the provider does not carry the return, add symmetric return (PBF) on " + seg.ingress.iface + "." });
  if (res.status === "needs-changes" && !res.changes.some((c) => !c.optional) && res.final && ["delivered", "exits"].includes(res.final.kind)) res.status = res.final.kind;
}
function trace(devices, query, opts) {
  opts = opts || {};
  const prevIgnore = IGNORE_INTRA;
  IGNORE_INTRA = !!opts.ignoreIntrazoneDefault;
  try {
    const res = traceOuter(devices, query, opts);
    const ig = (res.checks || []).filter((c) => c.ignoredDefault);
    if (ig.length) {
      res.ignoredIntrazone = ig.map((c) => ({ device: c.device, vsys: c.vsys, zone: c.fromZone }));
      res.notes.push({ level: "info", text: "Ignoring intrazone-default: " + ig.map((c) => c.device + " " + c.vsys + " zone " + c.fromZone).join(", ") + " would be allowed by the predefined intrazone-default rule; shown as needing an explicit rule instead." });
    }
    return res;
  } finally { IGNORE_INTRA = prevIgnore; }
}
function traceOuter(devices, query, opts) {
  let res = traceInner(devices, query, opts);
  let circ = null;
  // public-space / circuit map (and provider statics): decides where traffic for mapped public space enters
  if (!opts.ingress && !opts.srcDevice && !opts.deviceId && !(opts.via || []).length && !opts.noCircuit) {
    const pq = parseQuery(query, devices);
    const dec = pq.err.length ? null : circuitDecision(devices, pq.src.p, pq.dst.p, opts.circuits);
    const use = dec && (dec.user || dec.stat), ent = use && circuitEntryIface(devices, use, pq.src.p);
    if (ent) {
      const routed = res.ingress ? { device: res.ingress.device, iface: res.ingress.iface } : null;
      const agreeR = !!routed && samePair(devices, routed.device, ent.dev.name) && routed.iface === ent.iface.name;
      const where = ent.dev.name + " " + ent.iface.name + (ent.iface.zone ? " (zone " + ent.iface.zone + ")" : "");
      circ = { source: dec.user ? "map" : "static", prefix: use.prefix, circuit: use.circuit || "", device: ent.dev.name, iface: ent.iface.name, zone: ent.iface.zone || null, routed, agreesWithRouting: agreeR };
      if (dec.user && dec.stat) { circ.static = { prefix: dec.stat.prefix, device: dec.stat.device, iface: dec.stat.iface, nexthop: dec.stat.nexthop, route: dec.stat.route }; circ.agreesWithStatic = samePair(devices, dec.stat.device, ent.dev.name) && dec.stat.iface === ent.iface.name; }
      if (!agreeR) {
        const alt = traceInner(devices, query, Object.assign({}, opts, { ingress: ent.dev.id + "|" + ent.iface.name }));
        if (alt.segments.length) { res = alt; circuitReturnOk(res, devices); } else circ.unusable = true;
      }
      const notes = [];
      if (dec.user) {
        const okS = circ.agreesWithStatic === true;
        notes.push(agreeR || okS ? { level: "info", text: "Public-space map: " + use.prefix + (use.circuit ? " arrives on circuit " + use.circuit : "") + " at " + where + "; " + (agreeR ? "routing agrees." : "the provider static route agrees (the default route alone would enter at " + (routed ? routed.device + " " + routed.iface : "no firewall") + ").") }
          : { level: "warn", text: "Public-space map puts " + use.prefix + (use.circuit ? " (circuit " + use.circuit + ")" : "") + " on " + where + ", but the firewall routing enters at " + (routed ? routed.device + " " + routed.iface : "no firewall") + ". Traced from the map entry; check the map or the routing." });
        if (circ.static && (agreeR || !okS)) notes.push(circ.agreesWithStatic ? { level: "info", text: "Confirmed by static route " + circ.static.route + " on " + circ.static.device + " (" + circ.static.prefix + " to the provider side via " + circ.static.iface + ")." }
          : { level: "warn", text: "Static route " + circ.static.route + " on " + circ.static.device + " sends " + circ.static.prefix + " to the provider side via " + circ.static.iface + ", which disagrees with the public-space map entry." });
        circ.conflict = circ.agreesWithStatic === false || (!agreeR && !okS);
      } else if (!agreeR) {
        notes.push({ level: "info", text: "Entered at " + where + ": more-specific static route " + dec.stat.route + " sends " + dec.stat.prefix + " to the provider side" + (dec.stat.nexthop ? " (" + dec.stat.nexthop + ")" : "") + ". Provider-assigned space returns on that circuit, so inbound traffic for it arrives there too (not via the default route" + (routed ? " at " + routed.device + " " + routed.iface : "") + "). Add it to the public-space map to confirm." });
      }
      if (circ.unusable) notes.push({ level: "warn", text: "The public-space map entry for " + use.prefix + " could not be traced from " + where + "." });
      res.notes.unshift(...notes);
      res.circuit = circ;
    }
  }
  // internet -> destination-NAT'd server: when the routed entry does not reach an allowing NAT, try the firewall whose NAT owns the address
  if (!(circ && circ.source === "map" && !circ.unusable) && !opts.ingress && !opts.srcDevice && !opts.deviceId && !(opts.via || []).length && !opts.noNatEntry && res.segments.length && !res.segments.some((s) => s.nat && s.nat.dnat) && res.checks && res.checks.some((c) => c.action !== "allow")) {
    const pq = parseQuery(query, devices);
    if (!pq.err.length && !isPrivateN(pq.src.p.lo) && pq.dst.p.hi - pq.dst.p.lo < 256) {
      const G = getGraph(devices, opts.links), act = G.ha && G.ha.groups.length ? G.ha.active : devices;
      const E = dnatEntries(act, pq.src.p, pq.dst.p).filter((e) => !(e.dev.id === res.segments[0].devId && e.iface.name === (res.ingress && res.ingress.iface)));
      for (const e of E.slice(0, 3)) {
        const alt = traceInner(devices, query, Object.assign({}, opts, { ingress: e.dev.id + "|" + e.iface.name, noNatEntry: true }));
        // accept the NAT entry when it applies the DNAT and is strictly better: nothing denied there while the routed entry is denied
        const worst = (cs) => Math.max(0, ...(cs || []).map((c) => c.ignoredDefault ? 0 : c.verdict === "conditional" ? 1 : c.action === "allow" ? 0 : 2));
        if (!alt.segments.some((s) => s.nat && s.nat.dnat) || !alt.checks || !(worst(alt.checks) === 0 || worst(alt.checks) < worst(res.checks))) continue;
        alt.notes.unshift({ level: "info", text: "Entered at " + e.dev.name + " " + e.iface.name + " (zone " + e.iface.zone + "): its destination NAT rule " + e.rule.name + (e.byPost ? " translates to " : " owns ") + hostOrPrefix(pq.dst.p) + " for traffic from " + hostOrPrefix(pq.src.p) + ". The routed entry (" + (res.ingress ? res.ingress.device + " " + res.ingress.iface : "?") + ") was blocked; pick the ingress interface to compare." });
        alt.natEntry = { device: e.dev.name, iface: e.iface.name, rule: e.rule.name, routed: res.ingress };
        res = alt; break;
      }
    }
  }
  if (circ && res.circuit !== circ) { res.circuit = circ; }
  const nn = noNetworkFor(devices, query, opts || {});
  if ((res.changes || []).some((c) => c.kind === "security" && !c.optional)) {
    const pq = parseQuery(query, devices);
    if (!pq.err.length && (res.checks || []).some((c) => c.action !== "allow" && !c.ignoredDefault) && noRuleInExport(devices, pq.src.p, pq.dst.p)) {
      const at = [...new Set((res.changes || []).filter((c) => c.kind === "security" && !c.optional).map((c) => c.device))];
      res.noRuleInExport = { devices: at };
      res.notes.unshift({ level: "warn", text: "Denied on the path found (at " + at.join(", ") + "): no rule in this export allows " + hostOrPrefix(pq.src.p) + " to " + hostOrPrefix(pq.dst.p) + ". If this flow works in production, the allow is probably in rules local to a firewall (load that firewall's own backup alongside the Panorama export) or the traffic enters through a different circuit (add its public prefix to the public-space map). Otherwise, add the rule below." });
    }
  }
  if (nn.length) res.noNetwork = nn;
  for (const c of res.changes || []) { // a missing route on a BGP router: say what the config shows about why BGP does not supply it
    if (c.kind !== "route" || !c.vr) continue;
    const d = devices.find((x) => x.name === c.device), v = d && d.vrs.get(c.vr), seg = res.segments.find((s) => s.device === c.device), q = seg && (seg.dstP || null);
    const W = v && v.bgpWithheld && q ? v.bgpWithheld.filter((w) => q.lo >= w.dest.lo && q.hi <= w.dest.hi) : [];
    if (W.length) { c.bgp = W.map((w) => w.why); c.why += ". BGP: " + W.map((w) => w.why).join("; "); }
  }
  try { res.sharedChoices = sharedIpChoices(res, devices, opts); } catch (e) { res.sharedChoices = []; }
  for (const c of res.sharedChoices.filter((x) => !x.pinned)) res.notes.unshift({ level: "warn", text: "Needs your choice at " + c.at + ": " + c.reason + " Candidates: " + c.candidates.map((x) => x.label).join("; ") + ". The trace shows " + c.chosen + " only as a placeholder; pick the right firewall." });
  try { if (opts.__pathStatusThrow) throw new Error("test"); res.pathStatus = pathStatus(res, devices); }
  catch (e) { res.pathStatus = { status: "error", confidence: "unknown", hops: res.segments.map(() => ({ assumptions: [] })), stop: null, assumed: 0, alternates: [], moreAlternates: 0, weak: false, stronger: null, error: String((e && e.message) || e), text: "Path status could not be worked out (" + String((e && e.message) || e) + "). The trace below is still valid; treat the path as unverified." }; }
  if (nn.length) {
    res.noNetwork = nn;
    res.notes.unshift(...nn.slice(0, 5).map((n) => ({ level: "warn", text: NO_NET_MSG(n) })));
    if (nn.length > 5) res.notes.splice(5, 0, { level: "warn", text: nn.length - 5 + " more firewalls with rules for this flow have no network config in this export." });
  }
  return res;
}
function traceInner(devices, query, opts) {
  opts = opts || {};
  const pq = parseQuery(query, devices);
  const res = { query: { src: pq.src && pq.src.text, dst: pq.dst && pq.dst.text, svc: svcText(pq.svc) }, segments: [], changes: [], notes: [], status: "error", final: null, ingress: null, returnPath: [] };
  if (pq.err.length) { res.notes.push(...pq.err.map((t) => ({ level: "error", text: t }))); res.summary = pq.err.join("; "); return res; }
  const G = getGraph(devices, opts.links);
  { // HA pairs act as one firewall: trace on the primary, map pins on a secondary to it
    const ha = G.ha;
    if (ha && ha.groups.length) {
      const mapPin = (v) => { if (!v) return v; const d = devices.find((x) => x.id === v || x.name === v); return d && ha.primaryOf(d) ? ha.primaryOf(d).id : v; };
      opts = Object.assign({}, opts, { srcDevice: mapPin(opts.srcDevice), dstDevice: mapPin(opts.dstDevice), deviceId: mapPin(opts.deviceId), via: (opts.via || []).map(mapPin) });
      if (opts.ingress) { const [di, ifn] = opts.ingress.split("|"); opts.ingress = mapPin(di) + "|" + ifn; }
      devices = ha.active;
    }
  }
  let preIng = opts.ingress ? findIngress(devices, pq.src.p, { ingress: opts.ingress }) : null;
  const srcPin = preIng ? preIng.dev.id : (opts.srcDevice || opts.deviceId || null);
  const planOpts = { srcDevice: srcPin, dstDevice: opts.dstDevice || null, via: opts.via || [], choices: opts.choices || null, k: 3, svc: pq.svc, excludeRule: opts.excludeRule || null, evidence: opts.evidence };
  let pr = findPaths(G, devices, pq.src.p, pq.dst.p, planOpts);
  let plan = null, planIdx = 0;
  const pickPlan = (p, idx) => { const i = Math.max(0, Math.min(idx == null ? opts.pathIndex || 0 : idx, p.paths.length - 1)); return p.paths.length && p.paths[i].hops.length ? p.paths[i] : null; };
  // the plan may override a firewall's own routing only when you picked that path (or it has no route at all)
  const forcePlan = !!opts.forcePlan || (opts.pathIndex || 0) > 0;
  let replan = false;
  plan = pickPlan(pr);
  res.plan = { srcOwners: pr.srcOwners, dstOwners: pr.dstOwners, explain: pr.explain, considered: pr.considered, evidence: pr.evidence || [], forced: forcePlan, paths: pr.paths.map((x) => ({ label: x.label, cost: x.cost, confidence: x.confidence, devices: x.devices, hops: x.hops, evidence: x.evidence, routing: x.routing, violations: x.violations, rules: x.rules, extends: x.routing === "extends" })), chosen: pr.paths.length ? Math.max(0, Math.min(opts.pathIndex || 0, pr.paths.length - 1)) : -1, replanned: [] };
  if (pr.conflict) res.conflict = pr.conflict;
  if (pr.ambiguous) res.ambiguous = pr.ambiguous;
  if (pr.dnatElsewhere) res.dnatElsewhere = pr.dnatElsewhere;
  const evWt = new Map(); for (const e of pr.evidence || []) evWt.set(e.devId, Math.max(evWt.get(e.devId) || 0, e.weight));
  { // the chosen path may start at a rule zone or an internet edge: enter there
    const p0 = pr.paths.length ? pr.paths[Math.max(0, Math.min(opts.pathIndex || 0, pr.paths.length - 1))] : null;
    if (!preIng && p0 && (p0.srcKind === "rule" || p0.srcKind === "internet") && p0.srcIface) {
      const d = devices.find((x) => x.id === p0.srcDevId), it = d && d.interfaces.get(p0.srcIface);
      const o = pr.srcOwners.find((x) => x.devId === p0.srcDevId);
      if (it) preIng = { dev: d, iface: it, how: o ? o.how : p0.srcKind, alternatives: [], isDefault: false };
    }
  }
  const ing = preIng || findIngress(devices, pq.src.p, Object.assign({}, opts, { deviceId: plan ? plan.srcDevId : (srcPin || (pr.paths[0] && pr.paths[0].srcDevId) || null) })) || findIngress(devices, pq.src.p, Object.assign({}, opts, { deviceId: null }));
  if (!ing) { res.notes.push({ level: "error", text: "Could not find where " + pq.src.text + " enters any loaded firewall (no connected subnet or route). Pick the ingress interface manually." }); res.summary = "Source location unknown - pick the ingress interface"; return res; }
  res.ingress = { device: ing.dev.name, iface: ing.iface.name, how: ing.how, alternatives: ing.alternatives.map((a) => a.dev.name + " " + a.iface.name) };
  if (ing.alternatives.length) res.notes.push({ level: "warn", text: "Ingress is ambiguous: " + pq.src.text + " also matches " + res.ingress.alternatives.join(", ") + " equally well. Using " + ing.dev.name + " " + ing.iface.name + "; pick another ingress interface if that is wrong." });
  if (ing.isDefault) res.notes.push({ level: "info", text: "Source was placed by a default route (" + ing.how + "). If traffic really enters elsewhere, pick the ingress interface." });

  const svcQ0 = pq.svc;
  let st = { dev: ing.dev, ctx: ing.iface.vsys, vr: ing.iface.vr, inIf: ing.iface.name, inZone: ing.iface.zone, via: "interface", fromCtx: null, fromVr: null, peer: null,
    src: pq.src.p, dst: pq.dst.p, port: svcQ0.port, origSrc: pq.src.p, origDst: pq.dst.p, transit: null };
  const ctxCount = new Map();
  const seen = new Set();
  const visitedDevs = new Set([ing.dev.id]);
  res.stitches = [];
  res.dstFirewalls = destFirewalls(devices, pq.dst.p);
  const changes = res.changes;
  const addChange = (c) => { const key = c.kind + "|" + c.device + "|" + (c.vsys || c.vr) + "|" + c.summary; if (!changes.some((x) => x.key === key)) { c.key = key; changes.push(c); } };

  const planHop = (dev) => (plan && plan.hops[planIdx] && plan.hops[planIdx].fromId === dev.id) ? plan.hops[planIdx] : null;
  const destPrefixFor = (q) => { const o = G.owned.filter((x) => q.lo >= x.lo && q.hi <= x.hi).sort((a, b) => b.len - a.len)[0]; return o ? n2ip(o.lo) + "/" + o.len : prefixStr(q); };
  /* Make this firewall follow the inferred path; where its routing disagrees, list the route needed instead of stopping. */
  const applyPlan = (dev, ctx, seg, f, dstQ) => {
    const ph = planHop(dev);
    if (!ph || f.pbf || !ph.egIf) return f;
    const I = dev.interfaces.get(ph.egIf); if (!I) return f;
    if (f.kind === "iface" && f.ifObj && f.ifObj.ips.some((x) => x.len < 32) && ifaceIpIn(f.ifObj, dstQ)) return f;
    const ownerI = I.vsys || ctx.name;
    const progressing = (f.kind === "iface" && f.iface === I.name) || (f.kind === "vsys" && f.targetCtx === ownerI && ownerI !== ctx.name);
    if (progressing) return f;
    // a private destination that only matches a default route out an internet uplink has no usable route
    const lastR = f.vrPath && f.vrPath.length ? f.vrPath[f.vrPath.length - 1].route : null;
    const deadDefault = f.kind === "iface" && lastR && (lastR.dest.len || 0) === 0 && isPrivateN(dstQ.lo) && isPrivateN(dstQ.hi) && internetEdges(G).some((x) => x.dev === dev && x.iface.name === f.iface);
    if (deadDefault) seg.notes.push({ level: "warn", text: dev.name + " " + ctx.name + ": the only route to " + prefixStr(dstQ) + " is the default route out internet uplink " + f.iface + "; a private destination needs a specific route." });
    if (!forcePlan && !deadDefault && f.kind !== "none" && f.kind !== "unresolved") {
      // routing is authoritative: follow this firewall's own decision and re-plan from where it leads
      const b = routeBasis(f);
      seg.notes.push({ level: "info", text: dev.name + " " + ctx.name + ": routing (" + (b ? b.text : f.kind) + ") decides this hop, not the inferred path via " + I.name + " toward " + ph.to + ". Following routing." });
      plan = null; replan = true;
      return f;
    }
    const destText = destPrefixFor(dstQ);
    const destP = parsePrefix(destText);
    const cur = st.vr;
    const how = f.kind === "none" || f.kind === "unresolved" ? f.why : f.kind === "vsys" ? "routing sends it to " + f.targetCtx : "routing sends it out " + (f.iface || "?") + (f.nexthop ? " to " + f.nexthop : "");
    seg.notes.push({ level: "warn", text: dev.name + " " + ctx.name + ": " + how + ", but the inferred path to " + ph.to + " leaves via " + I.name + (ph.nexthop ? " (next hop " + ph.nexthop + ")" : "") + ". Listing the route needed for that path." });
    seg.planRoute = true;
    const nhIp = ph.nexthop || null;
    if (ownerI === ctx.name) {
      const path = [];
      if (I.vr && I.vr !== cur) {
        addChange({ kind: "route", device: dev.name, vr: cur, vsys: ctx.name, summary: "Add route in " + cur + " to " + destText + " via next-vr " + I.vr, why: "Inferred path to " + ph.to + " leaves through " + I.name + " in " + I.vr, cli: routeCli(dev, cur, "FM-to-" + destText.replace(/[\/.]/g, "_"), destText, { nextVr: I.vr }) });
        path.push({ vr: cur, route: { name: "(needed) to " + destText, dest: destP, nexthop: { type: "next-vr", value: I.vr }, type: "suggested" } });
      }
      const inner = I.vr && I.vr !== cur ? resolveForward(dev, I.vr, dstQ, ctx.name) : null;
      if (!inner || inner.iface !== I.name) {
        const vrn = I.vr || cur;
        addChange({ kind: "route", device: dev.name, vr: vrn, vsys: ctx.name, summary: "Add route in " + vrn + " to " + destText + " via " + (nhIp || "<next-hop-ip>") + " on " + I.name, why: (f.kind === "none" ? "No route to the destination" : "Routing does not send it toward " + ph.to) + " (inferred path: " + ph.via.label + ")", cli: routeCli(dev, vrn, "FM-to-" + destText.replace(/[\/.]/g, "_"), destText, { ip: nhIp, iface: I.name }) });
        path.push({ vr: vrn, route: { name: "(needed) to " + destText, dest: destP, nexthop: { type: "ip", value: nhIp || "?" }, type: "suggested" } });
      } else path.push(...inner.vrPath);
      return withOwner(dev, { kind: "iface", iface: I.name, nexthop: nhIp, direct: false, vrPath: path, route: null, planned: true }, ctx.name);
    }
    addChange({ kind: "route", device: dev.name, vr: cur, vsys: ctx.name, summary: "Add route in " + cur + " to " + destText + " via next-vr " + (I.vr || "<router of " + ownerI + ">"), why: "Inferred path to " + ph.to + " leaves through " + I.name + " in " + ownerI, cli: routeCli(dev, cur, "FM-to-" + destText.replace(/[\/.]/g, "_"), destText, { nextVr: I.vr || "<vr>" }) });
    return { kind: "vsys", targetCtx: ownerI, targetVr: I.vr, vrPath: [{ vr: cur, route: { name: "(needed) to " + destText, dest: destP, nexthop: { type: "next-vr", value: I.vr }, type: "suggested" } }], planned: true };
  };

  /* next-vr into another vsys needs visible-vsys + external zones. Without them, look for the real path: out a shared transit subnet and back in. */
  const interVsysCheck = (dev, ctx, seg, f) => {
    const target = f.kind === "vsys" ? f.targetCtx : f.kind === "iface" && f.crossCtx ? f.crossCtx : null;
    if (!target || !dev.multiVsys || interVsysAllowed(dev, ctx.name, target)) return f;
    const fromVr = f.vrPath && f.vrPath.length ? f.vrPath[f.vrPath.length - 1].vr : st.vr;
    const toVr = f.kind === "vsys" ? f.targetVr : (f.ifObj && f.ifObj.vr);
    const sh = toVr && sharedTransit(dev, fromVr, toVr);
    if (sh && sh.out.vsys === ctx.name) {
      seg.notes.push({ level: "warn", text: ctx.name + " -> " + target + ": no visible-vsys or external zone, so PAN-OS cannot pass this internally. Modelled as a hairpin out " + sh.out.name + " and back into " + sh.inn.name + " (" + target + ") over shared subnet " + sh.net + "." });
      seg.hairpin = { out: sh.out.name, inn: sh.inn.name, label: "shared transit " + sh.net + " (hairpin)", confidence: "medium" };
      return withOwner(dev, { kind: "iface", iface: sh.out.name, nexthop: sh.inIp, direct: false, vrPath: f.vrPath, route: f.route, hairpin: true }, ctx.name);
    }
    seg.notes.push({ level: "error", text: ctx.name + " routes to " + target + " (next-vr " + (toVr || "?") + ") but " + ctx.name + " and " + target + " are not visible to each other and have no external zones; PAN-OS drops this. Add visible-vsys and external zones (listed below), or route via an outside router." });
    return f;
  };
  let hairpins = 0;
  for (let step = 0; step < 40; step++) {
    const dev = st.dev;
    const ctx = dev.vsys.get(st.ctx);
    if (!ctx) { res.notes.push({ level: "error", text: "Interface " + st.inIf + " on " + dev.name + " is not assigned to any virtual system." }); res.status = "error"; break; }
    const key = dev.id + "|" + ctx.name + "|" + st.vr + "|" + st.dst.lo + "|" + st.inZone;
    if (seen.has(key)) { res.notes.push({ level: "error", text: "Loop detected at " + dev.name + " " + ctx.name + " " + st.vr + "." }); res.status = "loop"; break; }
    seen.add(key);
    const n = st.via === "vsys" ? (st.chainN || 1) + 1 : 1; st.chainN = n;
    const svcQ = st.port == null || st.port === svcQ0.port ? svcQ0 : Object.assign({}, svcQ0, { port: st.port });
    if (n === 3) res.notes.push({ level: "error", text: dev.name + ": this path crosses more than two virtual systems/shared gateways. PAN-OS does not allow a packet to traverse more than two (e.g. vsys1 -> vsys2 -> vsys3); the firewall will drop it. Route directly to the destination vsys instead." });
    const seg = { device: dev.name, devId: dev.id, devKind: dev.kind, haPeers: dev.haPeers || null, vsys: ctx.name, display: ctx.display, isSG: ctx.isSG, dg: ctx.dg || null,
      ingress: { iface: st.via === "interface" ? st.inIf : null, zone: st.inZone, via: st.via, fromCtx: st.fromCtx, peer: st.peer, transit: st.transit || null },
      src: hostOrPrefix(st.src), dst: hostOrPrefix(st.dst), port: st.port, startVr: st.vr, srcP: st.src, dstP: st.dst, notes: [] };
    res.segments.push(seg);
    if (!st.inZone) { seg.notes.push({ level: "error", text: "Ingress interface " + st.inIf + " has no zone; PAN-OS drops traffic on interfaces without a zone." }); addChange({ kind: "zone", device: dev.name, vsys: ctx.name, summary: "Assign interface " + st.inIf + " to a zone in " + ctx.name, cli: [cliPrefixFor(dev, ctx.name, "vsys") + "zone <zone-name> network layer3 " + st.inIf] }); }

    // PBF
    const pbf = evalPbf(ctx, st.inZone, st.inIf, st.src, st.dst, svcQ);
    let fwd = null;
    if (pbf && pbf.rule.action.type !== "no-pbf") {
      seg.pbf = { rule: pbf.rule.name, action: pbf.rule.action, appDep: pbf.appDep };
      const a = pbf.rule.action;
      if (a.type === "discard") { seg.final = { kind: "drop", text: "Discarded by PBF rule " + pbf.rule.name }; res.status = "dropped"; res.final = seg.final; break; }
      if (a.type === "forward" && a.iface) fwd = withOwner(dev, { kind: "iface", iface: a.iface, nexthop: a.nexthop, direct: !a.nexthop, vrPath: [{ vr: st.vr, route: { name: "PBF " + pbf.rule.name, dest: st.dst, nexthop: { type: "pbf" }, type: "pbf" } }], route: null, pbf: true }, ctx.name);
      if (a.type === "forward-to-vsys") fwd = { kind: "vsys", targetCtx: a.vsys, targetVr: null, vrPath: [], pbf: true };
      if (pbf.appDep) seg.notes.push({ level: "info", text: "PBF rule " + pbf.rule.name + " depends on application; applies to the first session only after App-ID cache." });
    }
    if (!fwd) fwd = resolveForward(dev, st.vr, st.dst, ctx.name);
    let hypothetical = false;
    { const f2 = applyPlan(dev, ctx, seg, fwd, st.dst); if (f2 !== fwd) { fwd = f2; hypothetical = true; } }
    fwd = interVsysCheck(dev, ctx, seg, fwd);
    // missing route -> suggest
    if (fwd.kind === "none" || fwd.kind === "unresolved") {
      const sug = suggestForwardRoute(dev, ctx, fwd.vr || st.vr, st.dst, devices);
      seg.notes.push({ level: fwd.kind === "none" && fwd.dynamic ? "warn" : "error", text: fwd.why + (fwd.dynamic ? " (the router runs dynamic routing; a learned route may exist at runtime)" : "") });
      if (fwd.kind === "none") {
        addChange({ kind: "route", device: dev.name, vr: fwd.vr || st.vr, vsys: ctx.name, summary: "Add route in " + (fwd.vr || st.vr) + " to " + sug.destText + " via " + (sug.nextVr ? "next-vr " + sug.nextVr : (sug.ip || "<next-hop-ip>") + " on " + (sug.iface || "<egress-interface>")), why: "No route to the destination" + (fwd.dynamic ? " in the static config (dynamic routing may supply one)" : "") + ". The path is incomplete; this is a suggested route only, not a hop the packet can take today.", optional: !!fwd.dynamic, cli: routeCli(dev, fwd.vr || st.vr, "FM-to-" + sug.destText.replace(/[\/.]/g, "_"), sug.destText, sug) });
        // Do not continue the trace on an invented route. Following a suggested next-vr (especially into
        // another vsys) used to invent hops and a multi-rule plan for a path that does not exist.
      }
      if (!hypothetical) { seg.final = { kind: "no-route", text: fwd.why }; res.status = "no-route"; res.final = seg.final; seg.vrPath = fwd.vrPath || []; break; }
    }
    seg.vrPath = fwd.vrPath || [];
    seg.hypothetical = hypothetical;
    for (const h of seg.vrPath) {
      if (h.route.inferred) seg.notes.push({ level: "info", text: h.vr + ": uses a route inferred from the " + h.route.inferred.proto.toUpperCase() + " config (" + prefixStr(h.route.dest) + " originated by " + h.route.inferred.origin + ", " + h.route.inferred.via + "). Medium confidence: verify with 'show routing route'." });
      if (h.ecmp) seg.notes.push({ level: "warn", text: h.vr + ": " + h.ecmp.length + " equal routes to " + prefixStr(h.route.dest) + " (ECMP); showing " + h.route.name + "." });
      if (h.partial) seg.notes.push({ level: "warn", text: h.vr + ": route " + h.route.name + " (" + prefixStr(h.route.dest) + ") covers only part of " + prefixStr(st.dst) + "; trace a smaller destination for exact results." });
    }
    if (fwd.kind === "discard") { seg.final = { kind: "drop", text: "Route " + fwd.route.name + " discards the traffic" }; res.status = "dropped"; res.final = seg.final; break; }
    if (fwd.kind === "loop") { seg.final = { kind: "loop", text: fwd.why }; res.status = "loop"; res.final = seg.final; break; }

    // egress zone (pre-NAT)
    const eg = egressInfo(dev, ctx, fwd, seg, addChange);
    seg.egressPre = eg;
    // NAT
    const nat = evalNat(dev, ctx, st.inZone, eg.zone, eg.iface, st.src, st.dst, svcQ, seg.notes);
    let postDst = st.dst, postPort = st.port, postSrc = st.src, egPost = eg, fwdPost = fwd;
    if (nat.rule) {
      seg.nat = { rule: nat.rule.name, scope: nat.rule.scope, reverse: !!nat.reverse, snat: nat.snat, dnat: nat.dnat ? { text: nat.dnat.text || n2ip(nat.dnat.ip), port: nat.dnat.port } : null };
      if (nat.dnat && nat.dnat.ip == null) {
        seg.final = { kind: "unresolved", text: "NAT rule " + nat.rule.name + " translates the destination to " + nat.dnat.text + ", which cannot be resolved offline (FQDN or missing object). Trace the server's own address instead; FlowMapper then matches it back to this NAT rule." };
        seg.egress = eg; seg.dstPost = hostOrPrefix(st.dst); seg.srcPost = hostOrPrefix(st.src); seg.portPost = st.port; res.status = "unresolved"; res.final = seg.final; break;
      }
      if (nat.dnat && nat.dnat.ip != null) {
        postDst = { lo: nat.dnat.ip, hi: nat.dnat.ip, len: 32, ip: nat.dnat.ip };
        if (nat.dnat.port) postPort = nat.dnat.port;
        fwdPost = resolveForward(dev, st.vr, postDst, ctx.name);
        { // destination NAT: re-plan the firewall chain from here to the translated destination
          const np = findPaths(G, devices, st.src, postDst, { srcDevice: dev.id, dstDevice: null, via: [], k: 3, svc: { proto: svcQ.proto, port: postPort }, excludeRule: opts.excludeRule || null, evidence: opts.evidence });
          const nplan = pickPlan(np);
          if (nplan || plan) { plan = nplan; planIdx = 0; res.plan.replanned.push({ at: dev.name, dst: n2ip(postDst.lo), label: nplan ? nplan.label : "(no further firewalls)", explain: np.explain }); if (nplan) { res.plan.paths = np.paths.map((x) => ({ label: x.label, cost: x.cost, confidence: x.confidence, devices: x.devices, hops: x.hops })); res.plan.chosen = 0; res.plan.explain = res.plan.explain.concat(["After destination NAT on " + dev.name + " to " + n2ip(postDst.lo) + ":"], np.explain); } }
          const f2 = applyPlan(dev, ctx, seg, fwdPost, postDst); if (f2 !== fwdPost) { fwdPost = f2; hypothetical = true; }
          fwdPost = interVsysCheck(dev, ctx, seg, fwdPost);
        }
        if (fwdPost.kind === "none") {
          const sug = suggestForwardRoute(dev, ctx, fwdPost.vr || st.vr, postDst, devices);
          addChange({ kind: "route", device: dev.name, vr: fwdPost.vr || st.vr, vsys: ctx.name, summary: "Add route in " + (fwdPost.vr || st.vr) + " to post-NAT " + sug.destText, why: "No route to the translated destination. The path is incomplete; this is a suggested route only, not a hop the packet can take today.", cli: routeCli(dev, fwdPost.vr || st.vr, "FM-to-" + sug.destText.replace(/[\/.]/g, "_"), sug.destText, sug) });
          seg.final = { kind: "no-route", text: "No route to post-NAT destination " + n2ip(postDst.lo) }; res.status = "no-route"; res.final = seg.final; break;
        }
        seg.vrPathPost = fwdPost.vrPath;
        egPost = egressInfo(dev, ctx, fwdPost, seg, addChange);
      }
      if (nat.snat && nat.snat.ip != null) postSrc = { lo: nat.snat.ip, hi: nat.snat.ip, len: 32, ip: nat.snat.ip };
    }
    const revNat = !nat.rule && !ctx.isSG ? inboundDnatFor(dev, ctx, st.inZone, st.src, st.dst, svcQ) : null;
    if (nat.maybes.length) seg.notes.push({ level: "warn", text: "NAT rule " + nat.maybes[0].rule.name + " may also apply (" + nat.maybes[0].why + ")." });
    seg.egress = egPost;
    seg.basis = routeBasis(fwdPost);
    if (seg.basis && hypothetical && !fwdPost.planned && seg.basis.kind !== "suggested") seg.basis = Object.assign({}, seg.basis, { text: seg.basis.text + " (assumes a suggested route)", confidence: "low" });
    seg.dstPost = hostOrPrefix(postDst); seg.portPost = postPort; seg.srcPost = hostOrPrefix(postSrc);

    // Security policy (not in shared gateway)
    if (!ctx.isSG && eg.zone) {
      const toZ = egPost.zone;
      let sec = evalSecurity(ctx, st.inZone, toZ, st.src, st.dst, svcQ), secDst = st.dst, secSvc = svcQ;
      if (revNat) {
        // the traced address is what destination NAT turns the real (pre-NAT) address into: PAN-OS matches the pre-NAT address
        const svcPre = revNat.port != null && revNat.port !== svcQ.port ? Object.assign({}, svcQ, { port: revNat.port }) : svcQ;
        const s2 = evalSecurity(ctx, st.inZone, toZ, st.src, revNat.pre, svcPre);
        const sure = (x) => x.decision.action === "allow" && x.decision.kind === "rule" && x.verdict !== "conditional", maybe = (x) => x.decision.action === "allow" || x.maybes.some((m) => m.action === "allow");
        const lit = !sure(s2) && (sure(sec) || (maybe(sec) && !maybe(s2)));
        const what = (revNat.bidir ? "bi-directional static NAT " : "NAT rule ") + revNat.rule.name;
        if (!lit) {
          sec = s2; secDst = revNat.pre; secSvc = svcPre;
          seg.nat = { rule: revNat.rule.name, scope: revNat.rule.scope, reverse: !!revNat.bidir, inferred: true, snat: null, pre: n2ip(revNat.pre.lo), dnat: { text: hostOrPrefix(st.dst), port: revNat.postPort || null } };
          seg.dstPre = n2ip(revNat.pre.lo); seg.egressPre = { zone: revNat.preZone };
          seg.notes.push({ level: "info", text: hostOrPrefix(st.dst) + " is the translated address of " + what + ": from zone " + st.inZone + " clients connect to " + n2ip(revNat.pre.lo) + (svcPre !== svcQ ? " port " + svcPre.port : "") + ", and PAN-OS matches security policy on that pre-NAT address with the post-NAT zone (" + toZ + "). Checked as " + n2ip(revNat.pre.lo) + " -> " + hostOrPrefix(st.dst) + "." });
        } else {
          const okPre = s2.decision.action === "allow" || s2.maybes.some((m) => m.action === "allow");
          const rn = sec.decision.kind === "rule" && sec.decision.action === "allow" ? sec.decision.rule.name : (sec.maybes.find((m) => m.action === "allow") || {}).rule.name;
          seg.notes.push(okPre ? { level: "info", text: "Also reachable from " + st.inZone + " at " + n2ip(revNat.pre.lo) + " through " + what + "." }
            : { level: "warn", text: "Rule " + rn + " allows the translated address " + hostOrPrefix(st.dst) + ", but clients behind " + what + " connect to " + n2ip(revNat.pre.lo) + " and PAN-OS matches security policy on that pre-NAT address (with post-NAT zone " + toZ + "). No rule allows " + n2ip(revNat.pre.lo) + "; use the pre-NAT address in the rule." });
        }
      }
      seg.check = { device: dev.name, vsys: ctx.name, display: ctx.display, dg: ctx.dg || null, fromZone: st.inZone, toZone: toZ, src: hostOrPrefix(st.src), dst: hostOrPrefix(secDst), dstPost: seg.dstPost, svc: svcText(secSvc),
        verdict: sec.verdict, action: sec.decision.action, rule: sec.decision.rule.name, ruleScope: sec.decision.rule.scope, kind: sec.decision.kind, ignoredDefault: !!sec.decision.ignoredDefault,
        maybes: sec.maybes.map((m) => ({ rule: m.rule.name, scope: m.rule.scope, action: m.action, reasons: m.reasons })), evaluated: sec.evaluated };
      if (sec.decision.action !== "allow" && nat.dnat && eg.zone && eg.zone !== toZ) {
        // common mistake: the rule names the pre-NAT zone; PAN-OS uses the post-NAT zone for the security match
        const pre = evalSecurity(ctx, st.inZone, eg.zone, st.src, st.dst, svcQ);
        if (pre.decision.kind === "rule" && pre.decision.action === "allow") seg.notes.push({ level: "warn", text: "Rule " + pre.decision.rule.name + " would allow this with to-zone " + eg.zone + " (the pre-NAT zone), but with destination NAT PAN-OS matches security rules on the post-NAT zone (" + toZ + ") and the pre-NAT address. Change its to-zone to " + toZ + "." });
      }
      if (sec.decision.action !== "allow" || sec.verdict === "conditional") {
        // hint: would a rule match with the post-NAT destination?
        if (nat.dnat && nat.dnat.ip != null) {
          const alt = evalSecurity(ctx, st.inZone, toZ, st.src, postDst, svcQ);
          const altR = alt.decision.kind === "rule" && alt.decision.action === "allow" ? alt.decision : alt.maybes.find((x) => x.action === "allow" && !sec.maybes.some((y) => y.rule === x.rule));
          if (altR && altR.rule !== sec.decision.rule) seg.notes.push({ level: "warn", text: "Rule " + altR.rule.name + " allows the post-NAT address " + seg.dstPost + ", but PAN-OS matches security rules on the pre-NAT destination (" + seg.dst + ") with the post-NAT zone. Change its destination to " + seg.dst + " (keep the post-NAT zone)." });
        }
        addChange(securityChange(dev, ctx, st.inZone, toZ, st.src, secDst, secSvc, sec));
      }
    } else if (ctx.isSG) seg.notes.push({ level: "info", text: "Shared gateway " + ctx.display + " does not evaluate security policy; the vsys on the other side enforces it. It does apply NAT and PBF." });

    // advance
    const nextSrc = postSrc, nextDst = postDst;
    const cross = fwdPost.kind === "vsys" ? fwdPost.targetCtx : (fwdPost.crossCtx || null);
    if (cross) {
      const tgt = dev.vsys.get(cross);
      if (!tgt) { seg.final = { kind: "error", text: "Target virtual system " + cross + " not found" }; res.status = "error"; res.final = seg.final; break; }
      let inZ = externalZone(dev, cross, ctx.name);
      if (!inZ) {
        inZ = "ext-from-" + ctx.name;
        addChange({ kind: "zone", device: dev.name, vsys: cross, summary: "Create external zone " + inZ + " in " + cross + " with member " + ctx.name + " (traffic from " + ctx.name + " arrives here)", cli: [cliPrefixFor(dev, cross, "vsys") + "zone " + q(inZ) + " network external " + ctx.name].concat(tgt.isSG ? [] : [cliPrefixFor(dev, cross, "vsys") + "import visible-vsys " + ctx.name]) });
      }
      const nextVr = fwdPost.kind === "vsys" ? (fwdPost.targetVr || (tgt.importVrs[0]) || st.vr) : st.vr;
      st = { chainN: n, dev, ctx: cross, vr: nextVr, inIf: null, inZone: inZ, via: "vsys", fromCtx: ctx.name, fromVr: (fwdPost.vrPath && fwdPost.vrPath.length ? fwdPost.vrPath[fwdPost.vrPath.length - 1].vr : st.vr), peer: null,
        src: nextSrc, dst: nextDst, port: postPort, origSrc: st.origSrc, origDst: st.origDst };
      seg.next = { kind: "vsys", to: cross };
      continue;
    }
    if (fwdPost.kind === "local") { seg.final = { kind: "local", text: "Destination " + seg.dstPost + " is an address of " + dev.name + " interface " + fwdPost.iface + " (traffic to the firewall itself)" }; res.status = "local"; res.final = seg.final; break; }
    if (fwdPost.kind === "iface") {
      const it = fwdPost.ifObj;
      if (it && ifaceIpIn(it, nextDst)) { seg.final = { kind: "delivered", text: "Destination " + seg.dstPost + " is directly connected on " + it.name + (it.zone ? " (zone " + it.zone + ")" : ""), iface: it.name }; res.status = hypothetical ? "needs-changes" : "delivered"; res.final = seg.final; break; }
      const usedRoute = fwdPost.vrPath && fwdPost.vrPath.length ? fwdPost.vrPath[fwdPost.vrPath.length - 1].route : null;
      const hp = hairpins < 3 && it ? (seg.hairpin && seg.hairpin.out === it.name ? { J: dev.interfaces.get(seg.hairpin.inn), via: { kind: "hairpin", label: seg.hairpin.label, confidence: seg.hairpin.confidence } } : (!planHop(dev) || dev.multiVsys ? hairpinAtExit(dev, it, fwdPost.nexthop, nextDst, nextSrc, (fwdPost.vrPath && fwdPost.vrPath.length ? fwdPost.vrPath[fwdPost.vrPath.length - 1].vr : st.vr), opts.links) : null)) : null;
      if (hp && hp.J && hp.J.vsys && !(planHop(dev) && planHop(dev).egIf === it.name && !seg.hairpin && hp.via.confidence !== "high")) {
        hairpins++;
        seg.final = { kind: "next-device", text: "Hairpins out " + it.name + " and back into " + dev.name + " " + hp.J.name + " (" + hp.via.label + ")", iface: it.name };
        seg.next = { kind: "hairpin", to: dev.name, via: hp.via, confidence: hp.via.confidence, alternatives: [] };
        res.stitches.push({ from: dev.name, egress: it.name, nexthop: fwdPost.nexthop || null, to: dev.name, ingress: hp.J.name, via: hp.via, confidence: hp.via.confidence, evidence: [hp.via.label], hairpin: true, alternatives: [], key: dev.name + "|" + it.name + "|hairpin", basis: stitchBasis(hp.via, hp.via.confidence, "routing") });
          if (seg.next) seg.next.basis = res.stitches[res.stitches.length - 1].basis;
        const myIp = it.ips.find((x) => hp.J.ips.some((y) => sameNet(x, y)));
        st = { dev, ctx: hp.J.vsys, vr: hp.J.vr, inIf: hp.J.name, inZone: hp.J.zone, via: "interface", fromCtx: null, fromVr: null, peer: myIp ? n2ip(myIp.ip) : fwdPost.nexthop, transit: hp.via,
          src: nextSrc, dst: nextDst, port: postPort, origSrc: st.origSrc, origDst: st.origDst };
        continue;
      }
      const ph = planHop(dev);
      if (ph && it && it.name === ph.egIf) {
        const B = devices.find((d) => d.id === ph.toId);
        let J = B && ph.inIf ? B.interfaces.get(ph.inIf) : null;
        if (B && !J) { const ri = findIngress([B], nextSrc, {}); J = ri && ri.iface; }
        if (B && J && J.vsys) {
          const alts = [];
          res.plan.paths.forEach((p, pi) => { const h = p.hops[planIdx]; if (!h || h.fromId !== dev.id) return; if (!alts.some((a) => a.devId === h.toId)) alts.push({ devId: h.toId, device: h.to, iface: h.inIf, score: p.cost, why: h.evidence.join("; "), via: h.via.label, confidence: h.confidence, pathIndex: pi, chosen: h.toId === ph.toId }); });
          alts.sort((a, b) => (b.chosen - a.chosen));
          const chosenCost = (alts.find((a) => a.chosen) || {}).score;
          const ambiguous = !(opts.choices && opts.choices[ph.key]) && ph.via.kind !== "link" && alts.some((a) => !a.chosen && Math.abs(a.score - chosenCost) < 1e-6);
          const via = Object.assign({}, ph.via, { confidence: ph.confidence });
          seg.final = { kind: "next-device", text: "Continues to " + B.name + " " + J.name + " (" + ph.via.label + ")", iface: it.name };
          seg.next = { kind: "device", to: B.name, via, key: ph.key, chosenId: B.id, ambiguous, confidence: ph.confidence, alternatives: alts };
          const planBy = opts.choices && opts.choices[ph.key] ? "your choice" : ph.via.kind === "link" ? "user link" : forcePlan && (opts.pathIndex || 0) > 0 ? "the path you picked" : alts.length > 1 ? (evWt.get(B.id) ? "routing, then rule evidence between equally valid options" : "routing, then lowest inferred cost") : "routing";
          res.stitches.push({ from: dev.name, egress: it.name, nexthop: fwdPost.nexthop || ph.nexthop || null, to: B.name, ingress: J.name, via, confidence: ph.confidence, evidence: ph.evidence, needsRoute: !!seg.planRoute, ambiguous, alternatives: alts, key: ph.key, basis: stitchBasis(ph.via, ph.confidence, planBy) });
          if (seg.next) seg.next.basis = res.stitches[res.stitches.length - 1].basis;
          if (ambiguous) res.notes.push({ level: "warn", text: "After " + dev.name + " " + it.name + " the next firewall is ambiguous: " + alts.filter((a) => Math.abs(a.score - chosenCost) < 1e-6).map((a) => a.device).join(", ") + " fit equally well. Using " + B.name + "; choose another branch or add a link." });
          if (ph.confidence !== "high") res.notes.push({ level: "info", text: dev.name + " -> " + B.name + " is inferred with " + ph.confidence + " confidence (" + ph.via.label + "). Add a link if you know the real connection." });
          visitedDevs.add(B.id); planIdx++;
          st = { dev: B, ctx: J.vsys, vr: J.vr, inIf: J.name, inZone: J.zone, via: "interface", fromCtx: null, fromVr: null, peer: ph.peer || (ph.via.kind === "transit" ? null : fwdPost.nexthop), transit: via,
            src: nextSrc, dst: nextDst, port: postPort, origSrc: st.origSrc, origDst: st.origDst };
          continue;
        }
      }
      if (plan && planIdx < plan.hops.length) res.notes.push({ level: "warn", text: "Trace left the inferred path at " + dev.name + " (" + (it ? it.name : fwdPost.iface) + "); falling back to next-hop matching." });
      const toIsp = usedRoute && (usedRoute.dest.len || 0) === 0 && isPrivateN(nextDst.lo) && isPrivateN(nextDst.hi) && it && internetEdges(G).some((x) => x.dev === dev && x.iface.name === it.name);
      if (toIsp) seg.notes.push({ level: "warn", text: dev.name + " sends private destination " + seg.dstPost + " out internet uplink " + it.name + " by its default route; it will not reach a site from there. Add a specific route toward the right firewall." });
      if (visitedDevs.size >= (opts.maxDevices || 16)) res.notes.push({ level: "warn", text: "Stopped stitching after " + visitedDevs.size + " firewalls (hop cap)." });
      else if (!toIsp) {
        const sn = stitchNext(devices, dev, it, fwdPost.nexthop, nextSrc, nextDst, visitedDevs, opts, usedRoute);
        if (sn.loopNote) seg.notes.push({ level: "warn", text: sn.loopNote });
        if (sn.chosen) {
          let c = sn.chosen, chosenBy = sn.cands.length > 1 && c.via.kind !== "link" ? "highest score" : "routing";
          if (c.via.kind === "link") chosenBy = "user link";
          else if (opts.choices && opts.choices[sn.key]) chosenBy = "your choice";
          else if (sn.ambiguous) { // equally valid by routing: let the rules that allow this traffic break the tie
            const tied = sn.cands.filter((x) => x.score === c.score);
            const best = tied.slice().sort((a, b) => (evWt.get(b.dev.id) || 0) - (evWt.get(a.dev.id) || 0))[0];
            if ((evWt.get(best.dev.id) || 0) > 0) { c = best; chosenBy = "rule evidence (tie between " + tied.map((x) => x.dev.name).join(", ") + ")"; } else chosenBy = "tie - first candidate";
          }
          seg.final = { kind: "next-device", text: "Continues to " + c.dev.name + " " + c.iface.name + " (" + c.via.label + ")", iface: it && it.name };
          seg.next = { kind: "device", to: c.dev.name, via: c.via, key: sn.key, chosenId: c.dev.id, ambiguous: sn.ambiguous,
            alternatives: sn.cands.map((x) => ({ devId: x.dev.id, device: x.dev.name, iface: x.iface.name, score: x.score, why: x.why, via: x.via.label, chosen: x === c })) };
          seg.next.chosenId = c.dev.id; seg.next.to = c.dev.name; seg.next.alternatives.forEach((a) => (a.chosen = a.devId === c.dev.id));
          seg.final.text = "Continues to " + c.dev.name + " " + c.iface.name + " (" + c.via.label + ")";
          res.stitches.push({ from: dev.name, egress: it && it.name, nexthop: fwdPost.nexthop || null, to: c.dev.name, ingress: c.iface.name, via: c.via, ambiguous: sn.ambiguous, alternatives: seg.next.alternatives, key: sn.key,
            basis: stitchBasis(c.via, c.via.kind === "link" ? "high" : c.via.kind === "direct" ? "high" : c.via.kind === "segment" ? "medium" : "low", chosenBy) });
          seg.next.basis = res.stitches[res.stitches.length - 1].basis;
          if (sn.ambiguous) res.notes.push({ level: "warn", text: "After " + dev.name + " " + (it ? it.name : "") + (fwdPost.nexthop ? " (next hop " + fwdPost.nexthop + ")" : "") + " the next firewall is ambiguous: " + sn.cands.filter((x) => x.score === c.score).map((x) => x.dev.name).join(", ") + ". Using " + c.dev.name + "; choose another branch or add a link." });
          const myIp = it && c.via.kind !== "transit" ? it.ips.find((x) => x.len < 32 && c.iface.ips.some((y) => { const sz = Math.pow(2, 32 - x.len); return Math.floor(x.ip / sz) === Math.floor(y.ip / sz); })) : null;
          visitedDevs.add(c.dev.id);
          if (replan) { // re-plan the rest of the chain from the firewall routing led to
            const np = findPaths(G, devices, nextSrc, nextDst, { srcDevice: c.dev.id, dstDevice: opts.dstDevice || null, via: [], k: 3, svc: { proto: svcQ.proto, port: postPort }, excludeRule: opts.excludeRule || null, evidence: opts.evidence });
            const nplan = pickPlan(np, 0); if (nplan) { plan = nplan; planIdx = 0; } replan = false;
          }
          st = { dev: c.dev, ctx: c.iface.vsys, vr: c.iface.vr, inIf: c.iface.name, inZone: c.iface.zone, via: "interface", fromCtx: null, fromVr: null, peer: myIp ? n2ip(myIp.ip) : (c.via.kind === "transit" ? null : fwdPost.nexthop), transit: c.via,
            src: nextSrc, dst: nextDst, port: postPort, origSrc: st.origSrc, origDst: st.origDst };
          continue;
        }
      }
      seg.final = { kind: "exit", text: "Leaves " + dev.name + " on " + (it ? it.name : fwdPost.iface) + (fwdPost.nexthop ? " toward next hop " + fwdPost.nexthop : ""), iface: fwdPost.iface };
      res.status = hypothetical ? "needs-changes" : "exits"; res.final = seg.final; break;
    }
    seg.final = { kind: "unresolved", text: fwdPost.why || "could not resolve forwarding" }; res.status = "unresolved"; res.final = seg.final; break;
  }
  if (plan && planIdx < plan.hops.length) {
    const rest = plan.hops.slice(planIdx);
    res.notes.push({ level: "warn", text: "The inferred path continues " + rest.map((h) => h.from + " -> " + h.to).join(", ") + " but the trace stopped at " + (res.final ? res.final.text : "?") + ". Those firewalls were not evaluated." });
  }
  if (res.plan) { res.plan.reached = planIdx; res.plan.total = plan ? plan.hops.length : 0; }
  checkReturnPath(res, devices, addChange);
  if (res.dstFirewalls.length && res.final && res.final.kind === "exit") {
    const reached = new Set(res.segments.map((x) => x.devId));
    const miss = res.dstFirewalls.filter((f) => !reached.has(f.devId));
    if (miss.length) res.notes.push({ level: "warn", text: "Destination " + res.query.dst + " is connected behind " + miss.map((f) => f.device + " " + f.iface).join(", ") + ", but the trace could not connect to it from " + res.final.text.replace(/^Leaves /, "") + ". Add a link (Links between firewalls) or check routing." });
  }
  // overall status
  const checks = res.segments.filter((s) => s.check).map((s) => s.check);
  res.checks = checks;
  res.blocked = checks.some((c) => c.action !== "allow");
  res.conditional = checks.some((c) => c.verdict === "conditional");
  if (["delivered", "exits", "local", "needs-changes"].includes(res.status)) {
    if (changes.some((c) => !c.optional)) res.status = "needs-changes";
    else if (res.conditional) res.status = res.status === "needs-changes" ? res.status : res.status;
  }
  res.summary = summarize(res);
  return res;
}
function egressInfo(dev, ctx, fwd, seg, addChange) {
  if (fwd.kind === "vsys") {
    const z = externalZone(dev, ctx.name, fwd.targetCtx);
    if (!z) {
      const nz = "ext-to-" + fwd.targetCtx;
      seg.notes.push({ level: "error", text: ctx.name + " has no external zone that includes " + fwd.targetCtx + "; inter-vsys traffic needs one." });
      addChange({ kind: "zone", device: dev.name, vsys: ctx.name, summary: "Create external zone " + nz + " in " + ctx.name + " with member " + fwd.targetCtx, cli: [cliPrefixFor(dev, ctx.name, "vsys") + "zone " + q(nz) + " network external " + fwd.targetCtx].concat(ctx.isSG ? [] : [cliPrefixFor(dev, ctx.name, "vsys") + "import visible-vsys " + fwd.targetCtx]) });
      return { zone: nz, iface: null, toCtx: fwd.targetCtx, missing: true };
    }
    return { zone: z, iface: null, toCtx: fwd.targetCtx };
  }
  if (fwd.kind === "iface" || fwd.kind === "local") {
    const it = fwd.ifObj;
    if (fwd.crossCtx) {
      const z = externalZone(dev, ctx.name, fwd.crossCtx);
      if (!z) {
        const nz = "ext-to-" + fwd.crossCtx;
        addChange({ kind: "zone", device: dev.name, vsys: ctx.name, summary: "Create external zone " + nz + " in " + ctx.name + " with member " + fwd.crossCtx, cli: [cliPrefixFor(dev, ctx.name, "vsys") + "zone " + q(nz) + " network external " + fwd.crossCtx] });
        return { zone: nz, iface: fwd.iface, toCtx: fwd.crossCtx, missing: true };
      }
      return { zone: z, iface: fwd.iface, toCtx: fwd.crossCtx };
    }
    if (it && !it.zone) seg.notes.push({ level: "error", text: "Egress interface " + fwd.iface + " has no zone." });
    return { zone: it ? it.zone : null, iface: fwd.iface, nexthop: fwd.nexthop || null };
  }
  return { zone: null, iface: null };
}
function suggestForwardRoute(dev, ctx, vrName, dst, devices) {
  // Look for another router on this device that reaches dst via a non-default route.
  // Prefer a router in the same vsys so a missing route is not "fixed" by inventing a walk through another vsys.
  let best = null;
  for (const vr of new Set(dev.vrs.values())) {
    if (vr.name === vrName) continue;
    const lr = lookupRoute(vr, dst); if (!lr || (lr.route.dest.len || 0) === 0) continue;
    const same = vrOwner(dev, vr, ctx.name) === ctx.name;
    if (!best || (same && !best.same) || (same === best.same && lr.route.dest.len > best.lr.route.dest.len)) best = { vr, lr, same };
  }
  if (best) {
    const destText = prefixStr(best.lr.route.dest.len >= 8 ? best.lr.route.dest : dst);
    const resolved = { kind: "vsys", targetCtx: vrOwner(dev, best.vr, ctx.name), targetVr: best.vr.name, vrPath: [{ vr: vrName, route: { name: "(suggested) to " + destText, dest: best.lr.route.dest, nexthop: { type: "next-vr", value: best.vr.name }, type: "suggested" } }] };
    if (resolved.targetCtx === ctx.name) { // same vsys: continue in that VR
      const inner = resolveForward(dev, best.vr.name, dst, ctx.name);
      inner.vrPath = resolved.vrPath.concat(inner.vrPath || []);
      return { destText, nextVr: best.vr.name, resolved: inner };
    }
    return { destText, nextVr: best.vr.name, resolved };
  }
  // A loaded peer device owns dst on a connected subnet? Find our interface on a shared subnet with that device.
  const vr = dev.vrs.get(vrName);
  for (const d of devices) {
    if (d === dev) continue;
    const ownsDst = [...d.interfaces.values()].some((it) => ifaceIpIn(it, dst));
    if (!ownsDst) continue;
    for (const myIfName of (vr ? vr.interfaces : [])) {
      const my = dev.interfaces.get(myIfName); if (!my) continue;
      for (const ip of my.ips) {
        const sz = Math.pow(2, 32 - ip.len);
        for (const it of d.interfaces.values()) for (const pip of it.ips) if (pip.ip !== ip.ip && Math.floor(pip.ip / sz) === Math.floor(ip.ip / sz) && ip.len < 32) {
          const destText = prefixStr(dst);
          return { destText, ip: n2ip(pip.ip), iface: my.name, resolved: withOwner(dev, { kind: "iface", iface: my.name, nexthop: n2ip(pip.ip), direct: false, vrPath: [{ vr: vrName, route: { name: "(suggested) to " + destText, dest: dst, nexthop: { type: "ip", value: n2ip(pip.ip) }, type: "suggested" } }] }, ctx.name) };
        }
      }
    }
  }
  return { destText: prefixStr(dst), ip: null, iface: null, resolved: null };
}
/* An existing allow rule in the same zones (evaluated before the blocking decision) that misses this flow on exactly one field:
   adding one member to it is often the smaller change. */
function nearMissRule(dev, ctx, fromZ, toZ, srcP, dstP, svc, sec, names) {
  const stop = sec.decision.kind === "rule" ? ctx.security.indexOf(sec.decision.rule) : ctx.security.length;
  for (let i = 0; i < Math.min(stop < 0 ? ctx.security.length : stop, ctx.security.length); i++) {
    const r = ctx.security[i];
    if (r.disabled || normAction(r.action) !== "allow" || !zoneOk(r.from, fromZ) || !zoneOk(r.to, toZ)) continue;
    if (r.ruleType === "intrazone" && fromZ !== toZ) continue;
    if (r.ruleType === "interzone" && fromZ === toZ) continue;
    if (r.negSrc || r.negDst) continue;
    const sm = addrMatch(resolveAddrs(r.source, ctx.scopes), srcP, false).m, dm = addrMatch(resolveAddrs(r.destination, ctx.scopes), dstP, false).m, vm = svcMatch(r, ctx.scopes, svc, ctx.uid).m;
    const miss = [sm === "no" ? "source" : null, dm === "no" ? "destination" : null, vm === "no" ? "service" : null].filter(Boolean);
    if (miss.length !== 1) continue;
    const field = miss[0], add = field === "source" ? names.src : field === "destination" ? names.dst : names.service;
    if (!add || add === "any" || (field === "service" && r.service.includes("application-default"))) continue;
    let pre;
    if (dev.kind === "panorama") {
      const m = /^DG (.+) (pre|post)-rulebase$/.exec(r.scope || ""), sh = /^shared (pre|post)-rulebase/.exec(r.scope || "");
      if (m) pre = "set device-group " + q(m[1]) + " " + m[2] + "-rulebase security rules "; else if (sh) pre = "set shared " + sh[1] + "-rulebase security rules "; else continue;
    } else pre = "set " + (dev.multiVsys ? "vsys " + ctx.name + " " : "") + "rulebase security rules ";
    return { rule: r.name, scope: r.scope, field, add, summary: "or add " + field + " " + add + " to existing rule " + r.name + " (" + r.scope + ")", cli: (field === "service" ? names.cli : []).concat([pre + q(r.name) + " " + field + " " + q(add)]) };
  }
  return null;
}
/* Where the new rule must sit. A rule added at the bottom of a rulebase is never reached when an earlier rule (often a
   catch-all deny) already matches, so say plainly which rule it has to go above, or that position does not matter. */
function ruleOrderAdvice(dr, blocking, optional) {
  if (optional) return { mode: "none", text: "An allow already matches this flow, so no new rule is needed here. Verify it still covers the ports you expect." };
  if (blocking && !/post-rulebase/.test(blocking.scope || ""))
    return { mode: "above", before: blocking.name, scope: blocking.scope || null, text: "Place the new rule above " + blocking.name + (blocking.scope ? " (" + blocking.scope + ")" : "") + ". That rule denies this flow today, so a rule left below it is never hit." };
  if (blocking)
    return { mode: "pre", before: null, scope: blocking.scope || null, text: blocking.name + " (" + blocking.scope + ") denies this flow, but it is evaluated last. Any rule in the pre-rulebase is checked first, so the position among pre-rules does not matter." };
  return { mode: "any", before: null, scope: null, text: "No explicit rule blocks this flow; only the default rule does, so the position does not matter. Keep it above any catch-all deny that is added later." };
}
function securityChange(dev, ctx, fromZ, toZ, srcP, dstP, svc, sec) {
  const srcName = findAddrName(ctx.scopes, srcP) || hostOrPrefix(srcP);
  const dstName = findAddrName(ctx.scopes, dstP) || hostOrPrefix(dstP);
  const dr = sec.decision;
  const blocking = dr.kind === "rule" && dr.action !== "allow" ? dr.rule : null;
  // Where the new rule must live so it is evaluated before the blocking rule.
  let objPre, rulePre, movePre, where;
  if (dev.kind === "panorama") {
    let scope = { type: "dg", dg: ctx.dg || "<device-group>" };
    if (blocking) {
      if (/^shared pre-rulebase/.test(blocking.scope)) scope = { type: "shared" };
      else { const m = /^DG (.+) pre-rulebase$/.exec(blocking.scope || ""); if (m) scope = { type: "dg", dg: m[1] }; }
    }
    const base = scope.type === "shared" ? "shared " : "device-group " + q(scope.dg) + " ";
    objPre = "set " + base; rulePre = "set " + base + "pre-rulebase security rules "; movePre = "move " + base + "pre-rulebase security rules ";
    where = scope.type === "shared" ? "Panorama shared pre-rulebase" : "DG " + scope.dg + " pre-rulebase";
  } else {
    const base = dev.multiVsys ? "vsys " + ctx.name + " " : "";
    objPre = "set " + base; rulePre = "set " + base + "rulebase security rules "; movePre = "move " + base + "rulebase security rules ";
    where = ctx.name + (ctx.display !== ctx.name ? " (" + ctx.display + ")" : "");
  }
  const cli = [];
  let service = "any", app = "any";
  if (svc.proto === "icmp") { app = "[ ping icmp ]"; service = "application-default"; }
  else if (svc.proto !== "any" && svc.port != null) {
    service = findSvcName(ctx.scopes, svc);
    if (!service) { service = svc.proto + "-" + svc.port; cli.push(objPre + "service " + service + " protocol " + svc.proto + " port " + svc.port); }
  }
  const name = ("FM-" + fromZ + "-to-" + toZ + "-" + (svc.port != null ? svc.proto + svc.port : svc.proto)).replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 63);
  cli.push(rulePre + q(name) + " from " + q(fromZ) + " to " + q(toZ) + " source " + q(srcName) + " destination " + q(dstName) + " application " + app + " service " + q(service) + " action allow");
  if (dev.kind === "panorama" && dev.serial) cli.push(rulePre + q(name) + " target devices " + dev.serial + (dev.multiVsys ? " vsys " + ctx.name : ""));
  if (blocking && !/post-rulebase/.test(blocking.scope || "")) cli.push(movePre + q(name) + " before " + q(blocking.name));
  let why;
  if (dr.kind === "default" && dr.ignoredDefault) why = "No explicit rule matches; intrazone-default would allow it, but you chose to ignore that default";
  else if (dr.kind === "default") why = "No rule matches; " + dr.rule.name + " " + (dr.action === "allow" ? "allows" : "denies") + " it";
  else why = "Rule " + dr.rule.name + " (" + dr.rule.scope + ") " + (dr.action === "allow" ? "allows" : "denies") + " it first";
  if (sec.verdict === "conditional" && sec.conditionalRule) why += "; rule " + sec.conditionalRule.rule.name + " might " + sec.conditionalRule.action + " it (" + sec.conditionalRule.reasons.join("; ") + ")";
  const optional = dr.action === "allow" || (sec.verdict === "conditional" && sec.conditionalRule && sec.conditionalRule.action === "allow");
  const modify = optional ? null : nearMissRule(dev, ctx, fromZ, toZ, srcP, dstP, svc, sec, { src: srcName, dst: dstName, service, cli: cli.filter((l) => / service /.test(l) && / protocol /.test(l)) });
  return { kind: "security", device: dev.name, vsys: ctx.name, display: ctx.display, dg: ctx.dg || null, where, modify,
    summary: (optional ? "Verify or add" : "Add") + " security rule in " + where + (dev.kind === "panorama" ? " for " + ctx.name : "") + ": " + fromZ + " -> " + toZ + ", " + srcName + " -> " + dstName + " " + svcText(svc),
    why, optional, order: ruleOrderAdvice(dr, blocking, optional), rule: { name, from: fromZ, to: toZ, source: srcName, destination: dstName, application: app, service, action: "allow", placeBefore: blocking && !/post-rulebase/.test(blocking.scope || "") ? blocking.name : null }, cli };
}
function checkReturnPath(res, devices, addChange) {
  for (const seg of res.segments) {
    const dev = devices.find((d) => d.id === seg.devId); if (!dev || !seg.startVr) continue;
    const ret = resolveForward(dev, seg.startVr, seg.srcP, seg.vsys);
    const r = { device: seg.device, vsys: seg.vsys, vr: seg.startVr, src: seg.src, ok: true, text: "" };
    const expectIf = seg.ingress.via === "interface" ? seg.ingress.iface : null;
    if (ret.kind === "none" || ret.kind === "unresolved") {
      r.ok = false; r.text = "No return route to " + seg.src + " in " + seg.startVr;
      let nh;
      if (seg.ingress.via === "vsys") {
        const fromSeg = res.segments[res.segments.indexOf(seg) - 1];
        nh = { nextVr: fromSeg ? fromSeg.startVr : "<source-vr>" };
      } else nh = { ip: seg.ingress.peer || (seg.ingress.transit ? "<router-ip>" : null), iface: expectIf };
      addChange({ kind: "route", device: dev.name, vr: seg.startVr, vsys: seg.vsys, summary: "Add return route in " + seg.startVr + " to " + seg.src + " via " + (nh.nextVr ? "next-vr " + nh.nextVr : (nh.ip || "<gateway>") + " on " + (nh.iface || "?")), why: "Reply traffic toward the source has no route" + (ret.dynamic ? " in the static config or in the routes inferred from BGP/OSPF" + ((dev.vrs.get(seg.startVr) || {}).proto && dev.vrs.get(seg.startVr).proto.ospf ? " (an OSPF neighbour would have to redistribute this prefix, e.g. BGP into OSPF via export-rules)" : "") : ""), optional: !!ret.dynamic, cli: routeCli(dev, seg.startVr, "FM-return-" + seg.src.replace(/[\/.]/g, "_"), prefixStr(seg.srcP), nh) });
    } else if (seg.ingress.via === "interface") {
      const outIf = ret.kind === "iface" || ret.kind === "local" ? ret.iface : null;
      if (ret.kind === "vsys" || ret.crossCtx || outIf !== expectIf) {
        r.ok = false; r.asym = true;
        r.text = "Asymmetric: traffic from " + seg.src + " enters " + expectIf + " but replies route out " + (outIf || ("to " + (ret.targetCtx || ret.crossCtx))) + " (" + seg.startVr + ")";
      } else r.text = "Replies route back out " + outIf;
    } else if (seg.ingress.via === "vsys") {
      const back = ret.kind === "vsys" ? ret.targetCtx : ret.crossCtx;
      if (back !== seg.ingress.fromCtx) { r.ok = false; r.asym = true; r.text = "Asymmetric: traffic arrives from " + seg.ingress.fromCtx + " but replies to " + seg.src + " route " + (back ? "to " + back : "out " + (ret.iface || "?")); }
      else r.text = "Replies route back to " + back;
    }
    if (r.asym) {
      let nh;
      if (seg.ingress.via === "vsys") { const fromSeg = res.segments[res.segments.indexOf(seg) - 1]; nh = { nextVr: fromSeg ? (fromSeg.vrPath.length ? fromSeg.vrPath[0].vr : fromSeg.startVr) : "<source-vr>" }; }
      else nh = { ip: seg.ingress.peer || null, iface: expectIf };
      addChange({ kind: "route", device: dev.name, vr: seg.startVr, vsys: seg.vsys, summary: "Add return route in " + seg.startVr + " to " + seg.src + " via " + (nh.nextVr ? "next-vr " + nh.nextVr : (nh.ip || "<gateway>") + " on " + (nh.iface || "?")) + " (fixes asymmetric return)", why: r.text, cli: routeCli(dev, seg.startVr, "FM-return-" + seg.src.replace(/[\/.]/g, "_"), prefixStr(seg.srcP), nh) });
    }
    if (r.asym) res.notes.push({ level: "warn", text: seg.device + " " + seg.vsys + ": " + r.text + ". PAN-OS drops asymmetric TCP (non-SYN TCP) unless asymmetric bypass is configured." });
    res.returnPath.push(r);
  }
}
function summarize(res) {
  if (res.status === "error") return "Trace failed";
  const need = res.changes.filter((c) => !c.optional);
  const bits = [];
  if (res.final) bits.push(res.final.text);
  if (need.length) bits.push(need.length + " change" + (need.length > 1 ? "s" : "") + " needed (" + need.filter((c) => c.kind === "security").length + " security rule, " + need.filter((c) => c.kind === "route").length + " route, " + need.filter((c) => c.kind === "zone").length + " zone)");
  else if (res.checks && res.checks.length) bits.push(res.conditional ? "Allowed only under conditions (see checks)" : "Allowed by existing rules");
  return bits.join(". ");
}

/* ------------------------------------------------------------------ secrets masking for raw view */
const SECRET_TAGS = ["phash", "password", "private-key", "secret", "bind-password", "key", "pre-shared-key", "auth-key", "passphrase", "community", "authpwd", "privpwd",
  "auth-password", "priv-password", "hash", "psk", "api-key", "access-key", "secret-key", "shared-secret", "client-secret", "otp", "token", "certificate-pem"];
function maskSecrets(text) {
  const re = new RegExp("<(" + SECRET_TAGS.join("|") + ")(\\s[^>]*)?>([\\s\\S]*?)</\\1>", "g");
  return text.replace(re, (m, t, a, body) => body.indexOf("<") >= 0 ? m.replace(/>([^<>]+)</g, (mm, v) => /\S/.test(v) ? ">********<" : mm) : "<" + t + (a || "") + ">********</" + t + ">");
}

/* ------------------------------------------------------------------ summaries */
function deviceSummary(dev) {
  const vsys = [...dev.vsys.values()].map((v) => ({ name: v.name, display: v.display, isSG: v.isSG, dg: v.dg || null, zones: [...v.zones.values()], security: v.security.length, nat: v.nat.length, pbf: v.pbf.length,
    addr: v.scopes[0].address.size, groups: v.scopes[0].addressGroup.size, vrs: [...new Set(dev.vrs.values())].filter((r) => r.owner === v.name).map((r) => r.name), visible: v.visible }));
  return { name: dev.name, kind: dev.kind, multiVsys: dev.multiVsys, vsys, interfaces: [...dev.interfaces.values()], vrs: [...new Set(dev.vrs.values())], warnings: dev.warnings };
}
function addressNames(devices) {
  const out = new Map();
  const seen = new Set();
  for (const d of devices) for (const v of d.vsys.values()) for (const s of v.scopes) {
    if (seen.has(s)) continue; seen.add(s);
    for (const [n, o] of s.address) if (!out.has(n)) out.set(n, o.value || "");
    for (const [n] of s.addressGroup) if (!out.has(n)) out.set(n, "group");
  }
  return out;
}

/* ------------------------------------------------------------------ rule replay: use existing allow rules as ground truth */
const PUBLIC_PROBES = ["203.0.113.77", "198.51.100.77", "192.0.2.77", "45.33.32.77", "151.101.1.77", "93.184.216.77"];
function pickHost(G, p) {
  if (p.hi === p.lo) return p.lo;
  const size = p.hi - p.lo + 1;
  // prefer an address inside a connected subnet that lies within the range
  const o = G.owned.filter((x) => x.lo >= p.lo && x.hi <= p.hi && x.hi - x.lo >= 2).sort((a, b) => b.len - a.len)[0];
  const base = o || p, bs = base.hi - base.lo + 1;
  let h = base.lo + (bs <= 2 ? 0 : bs <= 4 ? 1 : Math.max(1, Math.floor(bs / 2)));
  for (let i = 0; i < 8 && G.ipOwner.has(h) && h < base.hi; i++) h++;
  return Math.min(h, p.hi);
}
function repService(rule, scopes) {
  const sv = resolveServices(rule.service.length ? rule.service : ["any"], scopes);
  const pick = (defs) => { for (const d of defs || []) { if (d.proto === "icmp") return { proto: "icmp", port: null }; if (d.ports && d.ports.length) return { proto: d.proto, port: d.ports[0][0] }; if (d.proto === "tcp" || d.proto === "udp") return { proto: d.proto, port: d.proto === "tcp" ? 443 : 53 }; } return null; };
  if (sv.defs.length) return pick(sv.defs) || { proto: "tcp", port: 443 };
  if (sv.appDefault) {
    const ex = expandApps(rule.application || [], scopes);
    for (const a of ex.apps) { const d = appDefaultDefs(a, scopes); const p = d && pick(d); if (p) return p; }
  }
  return { proto: "tcp", port: 443 };
}
function looksInternet(zone) { return /untrust|outside|internet|inet|wan|isp|public|external|ext\b/i.test(zone || ""); }
/* Zones of a context whose interfaces carry the default route toward a public/unknown next hop: internet edges. */
function internetZones(dev, ctxName) {
  const out = new Set();
  for (const vr of new Set(dev.vrs.values())) for (const r of vr.routes) {
    if ((r.dest.len || 0) !== 0 || r.inferred) continue;
    const f = resolveForward(dev, vr.name, { lo: ip2n("203.0.113.77"), hi: ip2n("203.0.113.77"), len: 32 }, vrOwner(dev, vr, ctxName));
    if (f.kind === "iface" && f.ifObj && f.ifObj.zone && (!ctxName || f.ifObj.vsys === ctxName)) out.add(f.ifObj.zone);
  }
  return out;
}
/* Build the list of rule replay cases from the loaded devices. */
function ruleUnits(devices) {
  const units = new Map();
  for (const d of devices) for (const ctx of d.vsys.values()) {
    if (ctx.isSG) continue;
    for (const r of ctx.security) {
      const k = r.scope + "\u0000" + r.name;
      let u = units.get(k);
      if (!u) { u = { key: k, rule: r, name: r.name, scope: r.scope, instances: [] }; units.set(k, u); }
      u.instances.push({ devId: d.id, device: d.name, vsys: ctx.name });
    }
  }
  return units;
}
/* Zone an address is reached through on one firewall vsys (its route, following next-vr), or null. */
function zoneOfAddr(dev, vsysName, ip, cache) {
  const k = dev.id + "|" + vsysName + "|" + ip;
  if (cache && cache.has(k)) return cache.get(k);
  const q = { lo: ip, hi: ip, len: 32 }; let z = null, best = -1;
  const vrs = new Set(); for (const it of dev.interfaces.values()) if (it.vsys === vsysName && it.vr) vrs.add(it.vr);
  for (const vn of vrs) {
    let f = resolveForward(dev, vn, q, vsysName);
    // routed into another vsys / shared gateway: in this vsys the traffic uses the external zone that lists it (PAN-OS inter-vsys)
    if (f.kind === "vsys" && f.targetCtx && f.targetCtx !== vsysName) { const ez = externalZone(dev, vsysName, f.targetCtx); if (ez) { const len = f.route && f.route.dest ? f.route.dest.len || 0 : 0; if (len > best) { best = len; z = ez; } continue; } }
    for (let g = 0; g < 4 && f.kind === "vsys"; g++) f = resolveForward(dev, f.targetVr || vn, q, f.targetCtx);
    if (f.kind !== "iface") continue;
    const last = f.vrPath[f.vrPath.length - 1], len = last ? (last.route.dest.len == null ? 32 : last.route.dest.len) : 0;
    const it = dev.interfaces.get(f.iface);
    if (it && it.zone && len > best) { best = len; z = it.zone; }
  }
  if (cache) cache.set(k, z);
  return z;
}
/* Pick the source/destination addresses (one range each) that best fit the rule's zones on its own firewalls:
   rules pushed to several sites often name every site's networks, and only the local ones cross this firewall the rule's way. */
function pickCaseHosts(devices, G, u, r, sR, dR, internetSrc) {
  const insts = u.instances.slice(0, 4).map((i) => ({ dev: devices.find((d) => d.id === i.devId), vsys: i.vsys })).filter((x) => x.dev && x.dev.interfaces.size);
  const zOk = (list, z) => list.includes("any") || (z && list.includes(z));
  const cache = G._zoneCache || (G._zoneCache = new Map());
  // candidates: the usual host of each range, plus hosts in subnets the rule's own firewalls have connected or route inside the range
  const ids = new Set(insts.map((I) => I.dev.id));
  const local = [];
  for (const o of G.owned) if (ids.has(o.dev.id) && o.hi - o.lo >= 3) local.push({ lo: o.lo, hi: o.hi });
  for (const I of insts) for (const vr of new Set(I.dev.vrs.values())) for (const rt of vr.routes) if (rt.type === "static" && rt.dest.len >= 16 && rt.dest.len <= 30 && rt.nexthop.type === "ip") local.push({ lo: rt.dest.lo, hi: rt.dest.hi });
  // broader routes (default, /8, /12...) lead to other zones (core, WAN): sample hosts in their overlap with the range, away from connected subnets
  const wide = [];
  for (const I of insts) for (const vr of new Set(I.dev.vrs.values())) { if (![...I.dev.interfaces.values()].some((it) => it.vr === vr.name && it.vsys === I.vsys)) continue; for (const rt of vr.routes) if ((rt.type === "static" || rt.inferred) && rt.dest.len < 16 && rt.nexthop.type !== "discard") wide.push({ lo: rt.dest.lo, hi: rt.dest.hi }); }
  const notOwned = (h) => !G.ipOwner.has(h) && !G.owned.some((o) => ids.has(o.dev.id) && h >= o.lo && h <= o.hi);
  const cands = (ranges) => { const out = []; for (const x of ranges.slice(0, 6)) { out.push(pickHost(G, x));
    let k = 0; for (const w of wide) { const lo = Math.max(w.lo, x.lo), hi = Math.min(w.hi, x.hi); if (hi - lo < 4 || k >= 3) continue; for (const h of [lo + 1, lo + Math.floor((hi - lo) / 2), hi - 1]) if (notOwned(h) && !out.includes(h)) { out.push(h); k++; break; } } let n = 0; for (const l of local) if (l.lo >= x.lo && l.hi <= x.hi && (l.lo !== x.lo || l.hi !== x.hi) && n < 6) { const h = l.lo + Math.max(1, Math.floor((l.hi - l.lo) / 2)); if (!G.ipOwner.has(h) && !out.includes(h)) { out.push(h); n++; } } } return out.slice(0, 20); };
  const S = internetSrc != null ? [internetSrc] : cands(sR), D = cands(dR);
  let best = null;
  for (let di = 0; di < D.length; di++) for (let si = 0; si < S.length; si++) {
    if (S[si] === D[di]) continue;
    let sc = 0;
    for (const I of insts) { const v = (internetSrc != null || zOk(r.from, zoneOfAddr(I.dev, I.vsys, S[si], cache)) ? 1 : 0) + (zOk(r.to, zoneOfAddr(I.dev, I.vsys, D[di], cache)) ? 1 : 0); if (v > sc) sc = v; if (sc === 2) break; }
    if (!best || sc > best.sc) best = { sc, s: S[si], d: D[di] };
    if (sc === 2) return best;
  }
  return best;
}
/* Cleanup list: allow rules whose source/destination objects never route to the rule's zones on any firewall that carries the rule.
   PAN-OS picks the from-zone by the ingress interface (the route back to the source) and the to-zone by the egress interface
   (the route to the destination), so such an object never matches this rule there. */
function dnatCovers(ctx, h) {
  for (const n of ctx.nat || []) { if (n.disabled || !n.dnat) continue; const d = cached(n, "dst" + ctx.uid, () => resolveAddrs(n.destination, ctx.scopes)); if (d.any || d.ranges.some((p) => p.lo <= h && p.hi >= h)) return true; }
  return false;
}
function zoneFindings(devices, opts) {
  opts = opts || {};
  const units = new Map(), cache = new Map(), out = [];
  for (const d of devices) {
    if (!d.interfaces.size) continue;
    for (const ctx of d.vsys.values()) for (const r of ctx.security) {
      if (r.disabled || r.action !== "allow") continue;
      const k = r.scope + "|" + r.name; let u = units.get(k);
      if (!u) units.set(k, (u = { rule: r, insts: [] }));
      u.insts.push({ dev: d, ctx });
    }
  }
  for (const u of units.values()) {
    const r = u.rule;
    for (const [field, list, neg, zones] of [["source", r.source, r.negSrc, r.from], ["destination", r.destination, r.negDst, r.to]]) {
      if (neg || zones.includes("any") || list.includes("any")) continue;
      for (const name of list) {
        const ranges = resolveAddrs([name], u.insts[0].ctx.scopes).ranges.filter((p) => p.len == null || p.len >= 8);
        for (const p of ranges) {
          const hosts = new Set([p.hi - p.lo >= 2 ? p.lo + 1 : p.lo, p.hi - p.lo >= 2 ? p.hi - 1 : p.hi]);
          for (const I of u.insts) for (const it of I.dev.interfaces.values()) for (const ip of it.ips) { if (ip.len > 30) continue; const lo = ip.ip - (ip.ip % Math.pow(2, 32 - ip.len)), hh = ip.ip === lo + 1 ? lo + 2 : lo + 1; if (hh >= p.lo && hh <= p.hi && hosts.size < 34) hosts.add(hh); }
          let fits = false; const seen = new Map();
          for (const I of u.insts) {
            for (const h of hosts) {
              if (field === "destination" && dnatCovers(I.ctx, h)) { fits = true; break; } // post-NAT zone decides; not judged here
              const z = zoneOfAddr(I.dev, I.ctx.name, h, cache);
              if (!z) continue;
              if (zones.includes(z)) { fits = true; break; }
              const key = I.dev.name + (I.ctx.name !== "vsys1" ? " " + I.ctx.name : "");
              if (!seen.has(key)) seen.set(key, new Set()); seen.get(key).add(z);
            }
            if (fits) break;
          }
          if (fits || !seen.size) continue;
          out.push({ rule: r.name, scope: r.scope, field, object: name, range: prefixStr(p), ruleZones: zones.slice(), actual: [...seen].map(([fw, zs]) => ({ firewall: fw, zones: [...zs] })),
            text: field + " " + name + " (" + prefixStr(p) + ") routes to zone " + [...new Set([...seen.values()].flatMap((x) => [...x]))].join("/") + ", not the rule's " + (field === "source" ? "from" : "to") + "-zone " + zones.join("/") });
          if (opts.limit && out.length >= opts.limit) return out;
        }
      }
    }
  }
  return out;
}
/* A Panorama device (often one in a device group with no template stack) plus the firewall's own backup:
   network, routing and local rules from the local file; Panorama pre-rules before and post-rules after the local rules. */
/* How a firewall is shown: hostname, then serial, then template stack (each once, missing parts left out).
   names: optional serial -> hostname map you supplied (e.g. a Panorama Managed Devices export) for exports without hostnames. */
function devParts(d, names) {
  if (!d) return [];
  const serial = d.serial || (d.panorama && d.panorama.serial) || null;
  const hn = d.hostname || (d.panorama && d.panorama.hostname) || (serial && names && (names.get ? names.get(serial) : names[serial])) || d.hostnameInit || null;
  const stack = d.stack || (d.panorama && d.panorama.stack) || null;
  const out = [];
  for (const x of [hn, serial, stack]) if (x && !out.includes(x)) out.push(x);
  if (!out.length) out.push(d.name);
  else if (!out.includes(d.name) && d.name) out.unshift(d.name);
  return out;
}
function devLabel(d, names) { return devParts(d, names).join(" \u00b7 "); }
function staticRouteKey(vrName, r) {
  const nh = r.nexthop || {};
  return vrName + "|" + prefixStr(r.dest) + "|" + (nh.type || "") + "|" + (nh.value || "") + "|" + (r.metric == null ? "" : r.metric);
}
function addConnectedRoutes(vr, interfaces) {
  for (const iname of vr.interfaces) {
    const i = interfaces.get(iname); if (!i) continue;
    i.vr = vr.name;
    for (const ip of i.ips || []) {
      const size = Math.pow(2, 32 - ip.len), lo = Math.floor(ip.ip / size) * size;
      vr.routes.push({ name: "connected " + iname, dest: { lo, hi: lo + size - 1, len: ip.len }, nexthop: { type: "connected" }, iface: iname, metric: 0, ad: 0, type: "connected", origin: i.origin || null });
      if (ip.len < 32) vr.routes.push({ name: "local " + iname, dest: { lo: ip.ip, hi: ip.ip, len: 32 }, nexthop: { type: "local" }, iface: iname, metric: 0, ad: 0, type: "local", origin: i.origin || null });
      else vr.routes[vr.routes.length - 1].type = "local", vr.routes[vr.routes.length - 1].nexthop = { type: "local" };
    }
  }
}
function mergeZones(pz, lz) {
  const out = new Map();
  if (pz) for (const [n, z] of pz) out.set(n, Object.assign({}, z, { members: (z.members || []).slice(), origin: "template" }));
  if (lz) for (const [n, z] of lz) {
    const prev = out.get(n);
    if (!prev) { out.set(n, Object.assign({}, z, { members: (z.members || []).slice(), origin: "local" })); continue; }
    out.set(n, Object.assign({}, z, { members: [...new Set((prev.members || []).concat(z.members || []))], origin: "local" }));
  }
  return out;
}
function unionList(a, b) { return [...new Set((a || []).concat(b || []))]; }
/* Union a Panorama template network with a local backup. Local wins on an exact
   interface-name or static-route (VR + destination + nexthop + metric) conflict.
   Connected routes are rebuilt from the unioned interfaces. If either side has no
   interfaces, the other side is used as-is. */
function mergeNetworks(P, L) {
  if (!P.interfaces.size) return { interfaces: L.interfaces, vrs: L.vrs, from: "local" };
  if (!L.interfaces.size) return { interfaces: P.interfaces, vrs: P.vrs, from: "template" };
  const interfaces = new Map();
  for (const [n, it] of P.interfaces) interfaces.set(n, Object.assign({}, it, { ips: (it.ips || []).slice(), origin: "template" }));
  for (const [n, it] of L.interfaces) interfaces.set(n, Object.assign({}, it, { ips: (it.ips || []).slice(), origin: "local" }));
  const vrs = new Map();
  const names = new Set([...P.vrs.keys(), ...L.vrs.keys()]);
  const seenObj = new Set();
  for (const name of names) {
    const pv = P.vrs.get(name), lv = L.vrs.get(name);
    const canonical = (lv && lv.name) || (pv && pv.name) || name;
    if (vrs.has(canonical) && (lv === P.vrs.get(canonical) || pv === L.vrs.get(canonical))) { /* alias filled below */ }
    const key = canonical;
    if (vrs.has(key) && ((pv && seenObj.has(pv)) || (lv && seenObj.has(lv)))) {
      if (name !== key) vrs.set(name, vrs.get(key));
      continue;
    }
    if (pv) seenObj.add(pv); if (lv) seenObj.add(lv);
    const base = lv || pv;
    const vr = Object.assign({}, base, {
      name: key,
      interfaces: unionList(pv && pv.interfaces, lv && lv.interfaces),
      routes: [],
      dynamic: (lv && lv.dynamic && lv.dynamic.length ? lv.dynamic : (pv && pv.dynamic) || []).slice(),
      proto: (lv && lv.proto) || (pv && pv.proto) || null,
      owner: (lv && lv.owner) || (pv && pv.owner) || null
    });
    const byKey = new Map();
    const take = (r, origin) => {
      if (!r || r.type === "connected" || r.type === "local") return;
      const rec = Object.assign({}, r, { origin });
      if (r.type === "static") {
        const k = staticRouteKey(key, r);
        if (origin === "local" || !byKey.has(k)) byKey.set(k, rec);
        return;
      }
      const k = (r.type || "") + "|" + (r.name || "") + "|" + prefixStr(r.dest);
      if (origin === "local" || !byKey.has(k)) byKey.set(k, rec);
    };
    if (pv) for (const r of pv.routes) take(r, "template");
    if (lv) for (const r of lv.routes) take(r, "local");
    vr.routes = [...byKey.values()];
    addConnectedRoutes(vr, interfaces);
    vrs.set(key, vr);
    if (name !== key) vrs.set(name, vr);
  }
  return { interfaces, vrs, from: "union" };
}
function mergeLocalBackups(devices) {
  const locals = devices.filter((d) => d.kind !== "panorama"), out = [], used = new Set();
  const k = (x) => String(x || "").toLowerCase();
  for (const P of devices.filter((d) => d.kind === "panorama")) {
    const hn = P.panorama && P.panorama.hostname;
    const lser = (l) => l.serial || serialFromFilename(l.file);
    const L = locals.find((l) => !used.has(l) && ((P.serial && lser(l) && P.serial === lser(l)) || k(l.name) === k(P.name) || (hn && k(l.name) === k(hn))));
    if (!L) { out.push(P); continue; }
    used.add(L);
    const net = mergeNetworks(P, L);
    const warn = (L.warnings || []).concat(P.warnings || []);
    if (net.from === "union") warn.push({ level: "info", text: "Network merged from the Panorama template and the local backup. Local values win on an exact conflict (same interface name, or the same virtual router, destination, next hop and metric). The config browser marks each static route as template or local backup." });
    const M = Object.assign({}, P, { id: P.id, name: P.name, kind: "panorama", file: P.file, serial: P.serial, panorama: P.panorama, hostname: P.hostname || L.hostname || null, stack: P.stack || null, ha: L.ha || P.ha, mergedLocal: L.file || L.name, netMerge: net.from, interfaces: net.interfaces, vrs: net.vrs, warnings: warn, vsys: new Map(), sharedGateways: unionList(P.sharedGateways, L.sharedGateways), multiVsys: !!(P.multiVsys || L.multiVsys) });
    const pre = (list) => list.filter((r) => /pre-rulebase/.test(r.scope || "")), post = (list) => list.filter((r) => /post-rulebase/.test(r.scope || ""));
    for (const n of new Set([...L.vsys.keys(), ...P.vsys.keys()])) {
      const lc = L.vsys.get(n), pc = P.vsys.get(n);
      if (lc && pc) {
        const v = Object.assign({}, lc, { uid: lc.uid + "+" + pc.uid, dg: pc.dg, dgVsys: pc.dgVsys, dgJoinConfidence: pc.dgJoinConfidence, dgJoinReason: pc.dgJoinReason, display: lc.display && lc.display !== lc.name ? lc.display : (pc.display || lc.display), scopes: lc.scopes.concat(pc.scopes), policyLabel: pc.policyLabel || lc.policyLabel,
          importIfs: unionList(pc.importIfs, lc.importIfs), importVrs: unionList(pc.importVrs, lc.importVrs), visible: unionList(pc.visible, lc.visible), zones: net.from === "union" ? mergeZones(pc.zones, lc.zones) : lc.zones,
          security: pre(pc.security).concat(lc.security, post(pc.security)), nat: pre(pc.nat || []).concat(lc.nat || [], post(pc.nat || [])), pbf: pre(pc.pbf || []).concat(lc.pbf || [], post(pc.pbf || [])) });
        M.vsys.set(n, v);
      } else M.vsys.set(n, lc || pc);
    }
    if (!M.multiVsys) M.multiVsys = [...M.vsys.values()].filter((v) => !v.isSG).length > 1 || M.sharedGateways.length > 0;
    if (net.from === "union") {
      const ctxs = [...M.vsys.values()];
      for (const it of M.interfaces.values()) {
        for (const c of ctxs) for (const z of c.zones.values()) if (z.type !== "external" && (z.members || []).includes(it.name)) { it.zone = z.name; it.vsys = c.name; }
        if (!it.vsys) {
          const owner = ctxs.find((c) => (c.importIfs || []).includes(it.name)) || ((!ctxs.some((c) => (c.importIfs || []).length) || !M.multiVsys) && (ctxs.find((c) => !c.isSG) || ctxs[0]));
          if (owner) it.vsys = owner.name;
        }
      }
      for (const vr of new Set(M.vrs.values())) {
        const owners = new Set((vr.interfaces || []).map((n) => M.interfaces.get(n)).filter(Boolean).map((i) => i.vsys).filter(Boolean));
        const imp = ctxs.find((c) => (c.importVrs || []).includes(vr.name) || (vr.lr && (c.importVrs || []).includes(vr.lr)));
        vr.owner = imp ? imp.name : (owners.size === 1 ? [...owners][0] : (owners.size === 0 && !M.multiVsys ? (ctxs[0] && ctxs[0].name) : vr.owner));
        vr.sharedOwners = [...owners];
      }
    }
    M.dgJoin = P.dgJoin;
    out.push(M);
  }
  for (const l of locals) if (!used.has(l)) out.push(l);
  return out;
}
/* One representative flow for a rule unit (or {skip: reason}). */
function caseOfUnit(devices, G, u) {
    const r = u.rule;
    if (r.disabled) { return { skip: "disabled" }; }
    if (normAction(r.action) !== "allow") { return { skip: "not allow" }; }
    if (r.negSrc || r.negDst) { return { skip: "negated address" }; }
    const inst0 = devices.find((d) => d.id === u.instances[0].devId), ctx0 = inst0.vsys.get(u.instances[0].vsys);
    const S = resolveAddrs(r.source, ctx0.scopes), D = resolveAddrs(r.destination, ctx0.scopes);
    if (S.v6 && !S.ranges.length || D.v6 && !D.ranges.length) { return { skip: "IPv6 only" }; }
    if (D.any || !D.ranges.length) { return { skip: D.any ? "destination any" : "destination FQDN/EDL/unresolved" }; }
    if (r.from.includes("any") && r.to.includes("any") && u.instances.length > 1) { /* still fine */ }
    const dP = D.ranges.slice().sort((a, b) => (b.len == null ? 32 : b.len) - (a.len == null ? 32 : a.len))[0];
    let kind = "concrete", sIp;
    if (S.any || !S.ranges.length) {
      if (!S.any) { return { skip: "source FQDN/EDL/unresolved" }; }
      // source any: internet-sourced if the from-zone is an internet edge (or named like one)
      const inetZ = u.instances.some((i) => { const dv = devices.find((d) => d.id === i.devId); const z = internetZones(dv, i.vsys); return r.from.some((f) => z.has(f) || looksInternet(f)); });
      if (!inetZ) { return { skip: "source any (not internet-facing)" }; }
      kind = "internet";
      sIp = ip2n(PUBLIC_PROBES.find((x) => { const n = ip2n(x); return !G.owned.some((o) => n >= o.lo && n <= o.hi) && !S.ranges.length; }) || PUBLIC_PROBES[0]);
    } else sIp = pickHost(G, S.ranges[0]);
    let dIp = pickHost(G, dP);
    {
      const dR0 = D.ranges.slice().sort((a, b) => (b.len == null ? 32 : b.len) - (a.len == null ? 32 : a.len));
      const pk = pickCaseHosts(devices, G, u, r, S.ranges, dR0, kind === "internet" ? sIp : null);
      if (pk && pk.sc > 0) { sIp = pk.s; dIp = pk.d; }
    }
    if (sIp === dIp) {
      // a flow from a host to itself never crosses a firewall: pick another source/destination pair from the rule's objects
      const dR = D.ranges.slice().sort((a, b) => (b.len == null ? 32 : b.len) - (a.len == null ? 32 : a.len)), sR = kind === "internet" ? [] : S.ranges;
      let found = false;
      for (const d of dR) { for (const x of sR) { const si = pickHost(G, x), di = pickHost(G, d); if (si !== di) { sIp = si; dIp = di; found = true; break; } } if (found) break; }
      if (!found) for (const d of dR) { if (d.hi > d.lo) { dIp = dIp + 1 <= d.hi && dIp + 1 >= d.lo ? dIp + 1 : d.lo === sIp ? d.lo + 1 : d.lo; if (dIp !== sIp && dIp >= d.lo && dIp <= d.hi) { found = true; break; } } }
      if (!found && sR.length) for (const x of sR) { if (x.hi > x.lo) { const si = sIp + 1 <= x.hi && sIp + 1 >= x.lo ? sIp + 1 : x.lo; if (si !== dIp) { sIp = si; found = true; break; } } }
      if (!found) return { skip: "source equals destination" };
    }
    const svc = repService(r, ctx0.scopes);
    return { case: { key: u.key, rule: u.name, scope: u.scope, kind, from: r.from, to: r.to, src: n2ip(sIp), dst: n2ip(dIp), proto: svc.proto, port: svc.port, instances: u.instances, appDep: !!(r.application.length && !r.application.includes("any")) } };
}
/* Inbound destination-NAT cases: allow rules whose destination overlaps a destination NAT rule's original (pre-NAT)
   destination on the same firewall/vsys. The flow goes to the pre-NAT address on the NAT rule's pre-NAT port. */
function inboundDnatCases(devices, opts) {
  opts = opts || {};
  const G = getGraph(devices, opts.links), out = [], skipped = {};
  for (const u of ruleUnits(devices).values()) {
    const r = u.rule;
    if (r.disabled || normAction(r.action) !== "allow" || r.negSrc || r.negDst) continue;
    let hit = null;
    for (const i of u.instances) {
      const dv = devices.find((d) => d.id === i.devId), ctx = dv && dv.vsys.get(i.vsys); if (!ctx) continue;
      const D = resolveAddrs(r.destination, ctx.scopes); if (D.any || !D.ranges.length) break;
      for (const n of ctx.nat || []) {
        if (n.disabled || !n.dnat || n.natType !== "ipv4") continue;
        if (!r.from.includes("any") && !n.from.includes("any") && !n.from.some((z) => r.from.includes(z))) continue; // NAT never applies to this rule's traffic
        const N = cached(n, "dst" + ctx.uid, () => resolveAddrs(n.destination, ctx.scopes));
        for (const x of N.ranges) for (const y of D.ranges) { const lo = Math.max(x.lo, y.lo), hi = Math.min(x.hi, y.hi); if (lo <= hi && hi - lo < 65536) { hit = { ctx, n, lo, hi }; break; } }
        if (hit) break;
      }
      if (hit) break;
    }
    if (!hit) continue;
    const { ctx, n } = hit, S = resolveAddrs(r.source, ctx.scopes), NS = resolveAddrs(n.source, ctx.scopes);
    let sIp, kind = "concrete", srcR = null;
    if (!(S.any || !S.ranges.length) && !(NS.any || !NS.ranges.length)) { // both specific: a source both match
      for (const x of S.ranges) { for (const y of NS.ranges) { const lo = Math.max(x.lo, y.lo), hi = Math.min(x.hi, y.hi); if (lo <= hi) { srcR = { lo, hi, len: lo === hi ? 32 : null }; break; } } if (srcR) break; }
      if (!srcR) { skipped["source outside the NAT rule's source"] = (skipped["source outside the NAT rule's source"] || 0) + 1; continue; }
    } else srcR = S.any || !S.ranges.length ? (NS.any || !NS.ranges.length ? null : NS.ranges[0]) : S.ranges[0];
    if (!srcR) { if (!S.any) { skipped["source FQDN/EDL/unresolved"] = (skipped["source FQDN/EDL/unresolved"] || 0) + 1; continue; } kind = "internet"; sIp = ip2n(PUBLIC_PROBES.find((x) => { const v = ip2n(x); return !G.owned.some((o) => v >= o.lo && v <= o.hi); }) || PUBLIC_PROBES[0]); }
    else sIp = pickHost(G, srcR);
    const dIp = hit.hi > hit.lo ? hit.lo + Math.min(1, hit.hi - hit.lo) : hit.lo;
    let svc = repService(r, ctx.scopes);
    if (n.service && n.service !== "any") { const sv = resolveServices([n.service], ctx.scopes); const d0 = (sv.defs || []).find((d) => d.ports && d.ports.length); if (d0) svc = { proto: d0.proto, port: d0.ports[0][0] }; }
    const base = { key: u.key, rule: u.name, scope: u.scope, kind, inboundDnat: true, nat: n.name, from: r.from, to: r.to, src: n2ip(sIp), proto: svc.proto, instances: u.instances, appDep: !!(r.application.length && !r.application.includes("any")) };
    if (opts.post) { // the same flow traced by the translated (private) address, as people often do
      const t = resolveSingleIp(n.dnat.addr, ctx.scopes, []); if (!t) { skipped["translated address unresolved"] = (skipped["translated address unresolved"] || 0) + 1; continue; }
      if (isPrivateN(sIp) && !isPrivateN(hit.lo)) { skipped["U-turn: private client to public address (post-NAT variant)"] = (skipped["U-turn: private client to public address (post-NAT variant)"] || 0) + 1; continue; }
      out.push(Object.assign(base, { variant: "post", dst: n2ip(t.lo), port: n.dnat.port || svc.port })); continue;
    }
    out.push({ key: u.key, rule: u.name, scope: u.scope, kind, inboundDnat: true, nat: n.name, from: r.from, to: r.to, src: n2ip(sIp), dst: n2ip(dIp), proto: svc.proto, port: svc.port, instances: u.instances, appDep: !!(r.application.length && !r.application.includes("any")) });
  }
  return { cases: out, skipped };
}
function replayCases(devices, opts) {
  opts = opts || {};
  const G = getGraph(devices, opts.links);
  const units = ruleUnits(devices), skipped = {}, cases = [];
  for (const u of units.values()) { const x = caseOfUnit(devices, G, u); if (x.skip) skipped[x.skip] = (skipped[x.skip] || 0) + 1; else cases.push(x.case); }
  return { cases, skipped, units: units.size };
}
/* "Trace this rule": the representative flow for one rule (all devices that carry it). */
function ruleCase(devices, ruleName, scope, links) {
  const G = getGraph(devices, links);
  const u = ruleUnits(devices).get(scope + "\u0000" + ruleName);
  if (!u) return { skip: "rule not found" };
  return caseOfUnit(devices, G, u);
}
/* Run one case and classify. */
function replayCase(devices, c, opts) {
  opts = opts || {};
  const run = (extra) => trace(devices, { src: c.src, dst: c.dst, proto: c.proto, port: c.port }, Object.assign({ links: opts.links, excludeRule: opts.leaveOneOut ? c.key : null, evidence: opts.evidence }, extra || {}));
  let res;
  try { res = run(); }
  catch (e) { return { cat: "engine error", detail: String(e && e.message || e).slice(0, 200), res: null }; }
  const G = getGraph(devices, opts.links), mid = G.ha ? G.ha.mapId : (x) => x; // HA peers count as the same firewall
  const inst = new Set(c.instances.map((i) => mid(i.devId) + "|" + i.vsys)), instDev = new Set(c.instances.map((i) => mid(i.devId)));
  const instDevs = c.instances.map((i) => devices.find((d) => d.id === i.devId)).filter(Boolean);
  if (instDevs.length && instDevs.every((d) => !d.interfaces.size)) return { cat: "rule's firewall has no network config", detail: NO_NET_MSG(instDevs.map((d) => d.name).join(" / ")), res };
  const classify = (res) => {
  const segs = res.segments || [];
  const hit = segs.filter((s) => inst.has(s.devId + "|" + s.vsys));
  const zOk = (list, z) => list.includes("any") || list.includes(z);
  const matchedBy = (s) => s.check && (s.check.rule === c.rule && s.check.ruleScope === c.scope ? "rule" : s.check.maybes.some((m) => m.rule === c.rule && m.scope === c.scope) ? "conditional" : null);
  for (const s of hit) if (s.check) {
    const m = matchedBy(s);
    if (m) return { cat: "pass", how: m, res };
  }
  for (const s of hit) if (s.check && zOk(c.from, s.check.fromZone) && zOk(c.to, s.check.toZone)) {
    if (s.check.action === "allow") return { cat: "pass (earlier rule)", detail: s.check.rule, res };
    return { cat: "zones ok, rule not matched", detail: s.check.rule + " / " + s.check.verdict, res };
  }
  if (hit.length) {
    const s = hit.find((x) => x.check) || hit[0];
    if (!s.check) return { cat: "reached, no policy check", detail: (s.final && s.final.text) || "", res };
    const fz = zOk(c.from, s.check.fromZone), tz = zOk(c.to, s.check.toZone);
    if (fz && !tz && s.nat && s.nat.dnat && s.egressPre && zOk(c.to, s.egressPre.zone)) return { cat: "rule uses pre-NAT zone (DNAT)", detail: "NAT " + s.nat.rule + " translates to " + (s.dstPost || "?") + " in zone " + s.check.toZone + "; the rule's to-zone is the pre-NAT zone " + s.egressPre.zone, res };
    return { cat: !fz && !tz ? "wrong zones (both)" : !fz ? "wrong from-zone" : "wrong to-zone", detail: s.check.fromZone + " -> " + s.check.toZone + " (rule " + c.from.join(",") + " -> " + c.to.join(",") + ")", res };
  }
  if (segs.some((s) => instDev.has(s.devId))) return { cat: "wrong vsys", detail: segs.filter((s) => instDev.has(s.devId)).map((s) => s.vsys).join(","), res };
  if (!segs.length) return { cat: /Source location/.test(res.summary || "") ? "source not located" : "query error", detail: res.summary, res };
  const plan = res.plan || {};
  if (!(plan.dstOwners || []).length && !(res.dstFirewalls || []).length && !segs.some((s) => s.nat && s.nat.dnat)) return { cat: "destination not located", detail: res.final && res.final.text, res };
  if (res.status === "no-route" || res.status === "dropped" || res.status === "loop") return { cat: "routing gap", detail: res.status + ": " + (res.final && res.final.text), res };
  if (plan.dstOwners && plan.dstOwners.length && !plan.dstOwners.some((o) => instDev.has(o.devId)) && !(plan.srcOwners || []).some((o) => instDev.has(o.devId)) && !res.conflict) return { cat: "routing bypasses the rule's firewalls", detail: "src " + ((plan.srcOwners[0] || {}).device || "?") + ", dst " + plan.dstOwners.map((o) => o.device).slice(0, 3).join(","), res };
  if (plan.dstOwners && plan.dstOwners.length && !plan.dstOwners.some((o) => instDev.has(o.devId))) return { cat: "destination owned by another firewall", detail: plan.dstOwners.map((o) => o.device).slice(0, 3).join(","), res };
  if (!(plan.srcOwners || []).length || !instDev.has(res.segments[0].devId) && c.kind === "internet") return { cat: c.kind === "internet" ? "internet entry not found" : "chain does not reach rule's firewall", detail: (res.ingress ? res.ingress.device + " " + res.ingress.iface : "") + " => " + (res.final && res.final.text), res };
  return { cat: "chain does not reach rule's firewall", detail: (res.ingress ? res.ingress.device + " " + res.ingress.iface : "") + " => " + (res.final && res.final.text), res };
  };
  if (opts.scope) attachScope(res, opts.scope, { src: c.src, dst: c.dst, proto: c.proto, port: c.port }, opts, true);
  const r = classify(res);
  r.conflict = !!res.conflict;
  r.scopeCause = (res.conflict && res.conflict.scopeCause) || null;
  if (!/^pass/.test(r.cat)) { const o = G.ipOwner.get(ip2n(c.src)); if (o && instDev.has(mid(o.dev.id))) return Object.assign(r, { cat: "source is the firewall's own address", detail: c.src + " is " + o.dev.name + " " + o.iface.name + "; traffic the firewall originates is not matched by security rules", was: r.cat }); }
  if (/^pass/.test(r.cat)) return r;
  // does the rule's path only work against routing? Then the rule (or the routing) is worth reviewing, not an engine miss.
  const tries = [];
  if (res.conflict && res.conflict.pathIndex > 0) tries.push({ pathIndex: res.conflict.pathIndex, forcePlan: true });
  if (res.ambiguous && res.ambiguous.pathIndex > 0) tries.push({ pathIndex: res.ambiguous.pathIndex, forcePlan: true, amb: true });
  const pin = [...instDev][0]; if (pin) tries.push({ via: [pin], forcePlan: true });
  for (const t of tries) {
    let alt; try { const { amb, ...tt } = t; alt = run(tt); } catch (e) { continue; }
    const a = classify(alt);
    const cp = alt.plan && alt.plan.paths ? alt.plan.paths[alt.plan.chosen || 0] || alt.plan.paths[0] : null;
    const contra = (cp && cp.routing === "contradicts") || alt.segments.some((s) => s.notes.some((n) => /Listing the route needed/.test(n.text)));
    if (t.amb && /^pass/.test(a.cat) && !contra) return Object.assign(a, { cat: "pass (ambiguous parallel firewalls)", detail: "trace shows " + res.ambiguous.devices.join(" or ") + "; the rule is on the alternative", conflict: false });
    if (/^pass/.test(a.cat) && contra) {
      const v = (cp && cp.violations || [])[0];
      return { cat: "routing disagrees with rule", detail: "routing: " + ((res.plan.paths[0] || {}).label || res.segments.map((s) => s.device).join(" -> ")) + "; rule's path: " + (cp ? cp.label : alt.segments.map((s) => s.device).join(" -> ")) + (v ? " (" + v.device + " routes it out " + v.routeIface + ": " + v.route + ")" : ""), res, alt, conflict: true, was: r.cat, scopeCause: r.scopeCause };
    }
  }
  return r;
}
function replaySummary(results) {
  const by = {};
  for (const r of results) by[r.cat] = (by[r.cat] || 0) + 1;
  const pass = results.filter((r) => /^pass/.test(r.cat)).length;
  const isConf = (r) => r.conflict || r.cat === "routing disagrees with rule";
  const conflicts = results.filter(isConf).length;
  const conflictsHiddenHop = results.filter((r) => isConf(r) && r.scopeCause === "hidden-routed-hop").length;
  const conflictsHiddenOwner = results.filter((r) => isConf(r) && r.scopeCause === "hidden-owner").length;
  const conflictsGenuine = results.filter((r) => isConf(r) && (!r.scopeCause || r.scopeCause === "preexisting")).length;
  // path status of each replayed trace (complete / suggested / incomplete), when the results carry it
  const byPath = {};
  const byLabel = {};
  for (const r of results) {
    const ps = r.res && r.res.pathStatus, st = r.pathStatus || (ps && ps.status); if (st) byPath[st] = (byPath[st] || 0) + 1;
    if (ps && ps.label) byLabel[ps.label] = (byLabel[ps.label] || 0) + 1;
  }
  return { total: results.length, pass, rate: results.length ? Math.round(1000 * pass / results.length) / 10 : 0, byCategory: by, conflicts, conflictsHiddenHop, conflictsHiddenOwner, conflictsGenuine, byPath, byLabel };
}


/* ------------------------------------------------------------------ FCR (firewall change request) */
function splitCsvLine(line) {
  const out = []; let cur = "", q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === "," || c === "\t") { out.push(cur.trim()); cur = ""; }
    else cur += c;
  }
  out.push(cur.trim());
  return out;
}
/* ---- FCR header recognition: underscores, brackets and spaces are all word breaks ("Destination_IP", "Protocol(TCP/UDP)", "source ip") ---- */
function fcrHeaderWords(h) {
  return String(h || "").trim().toLowerCase().replace(/\(\s*s\s*\)/g, "s").replace(/[^a-z0-9]+/g, " ").trim().replace(/\s+/g, " ");
}
const FCR_ADDR_WORDS = /\b(ip|ips|address|addresses|addr|cidr)\b/;
const FCR_LABEL_WORDS = /\b(vlan|vnet|vpc|name|names|segment|site)\b/;
/* 0 = header says IP/address, 1 = plain "source", 2 = a network *name* label. Lower wins when two columns claim the same role. */
function fcrHeaderRank(h) {
  const x = fcrHeaderWords(h);
  return FCR_ADDR_WORDS.test(x) ? 0 : 1;
}
function fcrHeaderKey(h) {
  const x = fcrHeaderWords(h);
  if (!x) return null;
  if (/^(rule name|policy name|security rule name|proposed rule name|fcr rule name|rule)$/.test(x)) return "ruleName";
  if (/\busage\b/.test(x)) return "usage";
  if (/\b(dns|hostname|fqdn)\b/.test(x)) return null;
  if (/\b(source|src)\b/.test(x) && /\b(port|ports)\b/.test(x)) return null;
  if (/^(src|source|from)( (ip|ips|address|addresses|addr|host|network|cidr))*$/.test(x)) return "src";
  if (/^(dst|dest|destination|to|target)( (ip|ips|address|addresses|addr|host|network|cidr))*$/.test(x)) return "dst";
  if (/^(source|src) .*\b(vlan|vnet|vpc|name|names|segment|site)\b/.test(x) && !FCR_ADDR_WORDS.test(x)) return "srcLabel";
  if (/^(destination|dest|dst) .*\b(vlan|vnet|vpc|name|names|segment|site)\b/.test(x) && !FCR_ADDR_WORDS.test(x)) return "dstLabel";
  if (/^(proto|protocol|ip proto|ip protocol|destination protocol|dest protocol)( tcp udp)?$/.test(x)) return "proto";
  if (/^((dst|dest|destination) )?(tcp udp )?(port|ports|port number|port numbers|service|services)$/.test(x)) return "port";
  if (/^(app|apps|application|applications|app id)( if known)?$/.test(x)) return "app";
  if (/^(ticket|id|fcr|request|change request|ref|project|project number|project id|prj|prj number)$/.test(x)) return "ticket";
  if (/^(notes?|justification|comments?|reason|description)$/.test(x)) return "notes";
  return null;
}
/* PRJ-style project / request numbers count as the ticket when the sheet has no ticket column. Configurable. */
const FCR_PROJECT_RE = "(?:PRJ|PROJ|PRJT)[-_]?\\d{4,}";
function fcrFindTicket(texts, pattern) {
  let rx;
  try { rx = new RegExp("(?<![A-Za-z])(?:" + (pattern || FCR_PROJECT_RE) + ")(?!\\d)", "i"); } catch (e) { rx = new RegExp("(?<![A-Za-z])(?:" + FCR_PROJECT_RE + ")(?!\\d)", "i"); }
  for (const t of texts) { const m = rx.exec(String(t || "")); if (m) return m[0].toUpperCase(); }
  return null;
}
/* Application values the FCR may carry. Names that are not PAN-OS App-IDs (a system, project or team name) become
   application "any" in the proposed rule and are kept in the rule description instead. */
const FCR_APP_IDS = new Set(("ssl web-browsing ssh ms-rdp mssql-db mssql-mon mysql postgres oracle ldap ldaps dns dns-base ntp snmp snmp-base snmp-trap syslog smtp ftp sftp kerberos ms-ds-smb ms-ds-smb-base vnc vnc-base radius telnet imap pop3 tftp http-proxy http-video http2 quic msrpc netbios-ns netbios-dg netbios-ss ping icmp traceroute ms-netlogon ms-update ms-scheduler ms-spooler ms-exchange sharepoint-base sharepoint-online office365-base tacacs tacacs-plus dhcp ipsec ike ipsec-esp ipsec-esp-udp gre bgp ospf rip git github-base mongodb redis cassandra ibm-db2 nfs rsync rtsp sip rdp-base windows-push-notifications apt-get yum docker kubernetes prometheus grafana splunk elasticsearch kafka rabbitmq ms-teams zoom-base webex-base slack-base").split(" "));
function fcrClassifyApp(raw, extra) {
  const known = extra && extra.length ? new Set(extra.map((x) => String(x).toLowerCase())) : null;
  const ids = [], labels = [];
  for (const a of String(raw || "").split(/[,;\n\r]+/).map((x) => x.trim()).filter(Boolean)) {
    const l = a.toLowerCase();
    if (l === "any" || l === "application-default") continue;
    if (FCR_APP_IDS.has(l) || (known && known.has(l))) { if (!ids.includes(l)) ids.push(l); }
    else if (!labels.includes(a)) labels.push(a);
  }
  return { ids, labels };
}
function parseFcrService(s) {
  const t = String(s || "").trim();
  if (!t) return { proto: "tcp", port: null };
  const m = /^(tcp|udp|icmp|any)\s*[\/: ]\s*(\d{1,5})$/i.exec(t) || /^(tcp|udp|icmp|any)$/i.exec(t);
  if (m) return { proto: m[1].toLowerCase(), port: m[2] ? Number(m[2]) : null };
  if (/^\d{1,5}$/.test(t)) return { proto: "tcp", port: Number(t) };
  return { proto: "tcp", port: null, service: t };
}
function parseFcrLine(line) {
  const t = String(line || "").trim().replace(/^[#;].*/, "");
  if (!t) return null;
  const arrow = t.match(/^(\S+)\s*(?:->|→|>)\s*(\S+)(?:\s+(\S+))?(?:\s+(\S+))?/);
  if (arrow) {
    const svc = parseFcrService([arrow[3], arrow[4]].filter(Boolean).join(" "));
    return { src: arrow[1], dst: arrow[2], proto: svc.proto, port: svc.port, app: null, ticket: null, raw: t };
  }
  const kv = {};
  t.replace(/\b(src|source|dst|dest|destination|proto|protocol|port|app|application|ticket)\s*[:=]\s*(\S+)/gi, (_, k, v) => { kv[fcrHeaderKey(k) || k] = v; });
  if (kv.src && kv.dst) return { src: kv.src, dst: kv.dst, proto: (kv.proto || "tcp").toLowerCase(), port: kv.port ? Number(String(kv.port).replace(/^\D+/, "")) : null, app: kv.app || null, ticket: kv.ticket || null, raw: t };
  const parts = t.split(/[\s,;]+/).filter(Boolean);
  if (parts.length >= 2 && parsePrefix(parts[0]) && parsePrefix(parts[1])) {
    const svc = parseFcrService(parts.slice(2).join(" "));
    return { src: parts[0], dst: parts[1], proto: svc.proto, port: svc.port, app: null, ticket: null, raw: t };
  }
  return { error: "Could not parse FCR line: " + t, raw: t };
}
/* RFC-4180-style records (quoted cells may hold line breaks); comma or tab separates cells. */
function csvRecords(text) {
  const recs = []; let row = [], cur = "", q = false, any = false;
  const t = String(text || "").replace(/^\uFEFF/, "");
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) { if (c === '"') { if (t[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; continue; }
    if (c === '"') { q = true; any = true; }
    else if (c === "," || c === "\t") { row.push(cur.trim()); cur = ""; any = true; }
    else if (c === "\n" || c === "\r") { if (c === "\r" && t[i + 1] === "\n") i++; if (any || cur.trim() || row.length) { row.push(cur.trim()); recs.push(row); } row = []; cur = ""; any = false; }
    else { cur += c; any = true; }
  }
  if (any || cur.trim() || row.length) { row.push(cur.trim()); recs.push(row); }
  return recs;
}
function csvText(table) {
  const cell = (v) => { v = v == null ? "" : String(v); return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  return table.map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}
function fcrSplitList(v) { return String(v == null ? "" : v).split(/[,;\n\r]+/).map((x) => x.trim()).filter(Boolean); }
const FCR_MAX_EXPANSION = 500;
/* One header row in the first 30 rows, any prose above it is skipped; blank source cells under a merged/continued request
   inherit the request above; list cells (several destinations or ports) expand to one flow each. Returns null when no header row. */
function parseFcrTable(table, opts) {
  opts = opts || {};
  let hi = -1, keys = null;
  for (let i = 0; i < Math.min(table.length, 30); i++) {
    const ks = table[i].map(fcrHeaderKey);
    if (ks.includes("src") && ks.includes("dst") && ks.filter(Boolean).length >= 2) { hi = i; keys = ks; break; }
  }
  if (hi < 0) return null;
  const hdr = table[hi];
  const best = {};
  keys.forEach((k, i) => { if (!k) return; const r = fcrHeaderRank(hdr[i]); if (!(k in best) || r < best[k].rank) best[k] = { i, rank: r }; });
  const col = {}; for (const k in best) col[k] = best[k].i;
  const pre = table.slice(0, hi).map((r) => r.join(" "));
  const rows = [], errors = [];
  const INHERIT = ["src", "proto", "port", "app", "ticket", "ruleName", "usage", "srcLabel", "dstLabel", "notes"];
  let prev = null;
  for (const cells of table.slice(hi + 1)) {
    if (!cells.some((c) => c !== "" && c != null)) continue;
    if (/^#/.test(String(cells[0] || ""))) continue;
    const g = {}; for (const k in col) g[k] = cells[col[k]] == null ? "" : String(cells[col[k]]).trim();
    const raw = cells.join(",");
    if (!g.src && g.dst && prev) { for (const k of INHERIT) if (!g[k]) g[k] = prev[k] || ""; }
    if (!g.src || !g.dst) { errors.push({ error: "CSV row needs a source and destination: " + raw, raw }); continue; }
    prev = Object.assign({}, g);
    const srcs = fcrSplitList(g.src), dsts = fcrSplitList(g.dst);
    const protoCell = String(g.proto || "").toLowerCase();
    const ports = fcrSplitList(g.port);
    const protos = /\bboth\b/.test(protoCell) || (/tcp/.test(protoCell) && /udp/.test(protoCell)) ? ["tcp", "udp"] : [protoCell || null];
    const ticket = g.ticket || fcrFindTicket([opts.fileName, g.notes].concat(pre), opts.projectPattern) || null;
    const cls = fcrClassifyApp(g.app, opts.knownApps);
    const portToks = ports.length ? ports : [""];
    let n = 0;
    for (const sIp of srcs) for (const dIp of dsts) for (const pt of portToks) for (const pr of protos) {
      if (++n > FCR_MAX_EXPANSION) break;
      const rec = { src: sIp, dst: dIp, proto: "tcp", port: null, app: cls.ids.length ? cls.ids.join(" ") : null, ticket, raw };
      if (pt) {
        const rng = /^(\d{1,5})\s*[-:]\s*(\d{1,5})$/.exec(pt);
        if (rng) { rec.port = Number(rng[1]); rec.portRange = rng[1] + "-" + rng[2]; }
        else { const svc = parseFcrService(pt); rec.proto = svc.proto; rec.port = svc.port; if (svc.service && !rec.app && !cls.labels.length) cls.labels = [svc.service]; }
      }
      if (pr) { if (pr.includes("/")) { const svc = parseFcrService(pr); rec.proto = svc.proto; if (rec.port == null) rec.port = svc.port; } else rec.proto = pr; }
      if (g.ruleName) rec.ruleName = g.ruleName;
      if (g.usage) rec.usage = g.usage;
      if (g.srcLabel) rec.srcLabel = g.srcLabel;
      if (g.dstLabel) rec.dstLabel = g.dstLabel;
      if (g.notes) rec.notes = g.notes;
      if (cls.labels.length) rec.appLabel = cls.labels.join(", ");
      rows.push(rec);
    }
    if (n > FCR_MAX_EXPANSION) errors.push({ error: "A single request expanded to more than " + FCR_MAX_EXPANSION + " flows; only the first " + FCR_MAX_EXPANSION + " were kept: " + raw, raw });
  }
  return { rows, errors, headerRow: hi + 1, mapping: Object.fromEntries(Object.keys(col).map((k) => [k, String(hdr[col[k]])])) };
}
function parseFcr(text, opts) {
  opts = opts || {};
  const src = String(text || "").replace(/^\uFEFF/, "");
  if (!src.trim()) return { rows: [], errors: [{ error: "Nothing to parse." }] };
  const viaTable = parseFcrTable(csvRecords(src), opts);
  if (viaTable) return viaTable;
  const lines = src.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !/^#/.test(l));
  const rows = [], errors = [];
  if (!lines.length) return { rows, errors: [{ error: "Nothing to parse." }] };
  for (const line of lines) {
    const rec = parseFcrLine(line);
    if (!rec) continue;
    if (rec.error) errors.push(rec);
    else {
      if (rec.app) { const c = fcrClassifyApp(rec.app, opts.knownApps); rec.app = c.ids.join(" ") || null; if (c.labels.length) rec.appLabel = c.labels.join(", "); }
      if (!rec.ticket) rec.ticket = fcrFindTicket([opts.fileName, line], opts.projectPattern) || null;
      rows.push(rec);
    }
  }
  return { rows, errors };
}
function fcrRuleName(raw) {
  const s = String(raw || "").replace(/[^A-Za-z0-9_. -]+/g, "-").replace(/-{2,}/g, "-").replace(/^[ .-]+|[ .-]+$/g, "").slice(0, 63).replace(/[ .-]+$/, "");
  return s.replace(/[^A-Za-z0-9]/g, "").length >= 2 ? s : null;
}
function fcrDescription(row) {
  const bits = [];
  if (row.ticket) bits.push(row.ticket);
  if (row.appLabel) bits.push("FCR app: " + row.appLabel);
  if (row.usage) bits.push("usage: " + row.usage);
  if (row.srcLabel) bits.push("src net: " + row.srcLabel);
  if (row.dstLabel) bits.push("dst net: " + row.dstLabel);
  if (row.ruleName) bits.push("FCR rule: " + row.ruleName);
  return bits.join(" | ").slice(0, 1023);
}
/* Carry the FCR row's own details into the proposed security rules: the requested rule name (sanitized, kept unique),
   the application when it is a real App-ID (otherwise any, with the original name in the description), and a description. */
function applyFcrExtras(res, row) {
  if (!res || !row) return res;
  const desc = fcrDescription(row);
  res.fcrNote = desc || null;
  const want = fcrRuleName(row.ruleName);
  const appTok = row.app ? (row.app.includes(" ") ? "[ " + row.app + " ]" : row.app) : null;
  const used = new Set();
  for (const c of res.changes || []) {
    if (c.kind !== "security" || !c.rule || !c.cli) continue;
    const old = c.rule.name;
    const sep = "security rules ";
    const line = c.cli.find((l) => l.indexOf(sep + q(old) + " from ") > 0);
    const prefix = line ? line.slice(0, line.indexOf(sep) + sep.length) : null;
    if (want) {
      let nm = want, i = 2;
      while (used.has(nm)) { nm = (want.slice(0, 59) + "-" + i); i++; }
      used.add(nm);
      c.cli = c.cli.map((l) => l.split(q(old)).join(q(nm)));
      c.rule.name = nm;
    }
    if (appTok && !/^\[ ping/.test(c.rule.application || "")) {
      const nm = c.rule.name;
      c.cli = c.cli.map((l) => (l.indexOf(q(nm) + " from ") > 0 ? l.replace(" application " + c.rule.application + " ", " application " + appTok + " ") : l));
      c.rule.application = appTok;
    }
    if (desc && prefix) {
      const at = c.cli.findIndex((l) => l.indexOf(sep + q(c.rule.name) + " from ") > 0);
      c.cli.splice(at + 1, 0, prefix + q(c.rule.name) + " description " + q(desc));
      c.rule.description = desc;
    }
  }
  return res;
}
/* ---- .xlsx reader (offline, no libraries): zip central directory + DecompressionStream("deflate-raw") + the sheet XML ---- */
async function zipEntries(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  let e = -1;
  for (let i = u8.length - 22; i >= Math.max(0, u8.length - 65557); i--) if (dv.getUint32(i, true) === 0x06054b50) { e = i; break; }
  if (e < 0) throw new Error("not a zip/xlsx file");
  const n = dv.getUint16(e + 10, true); let p = dv.getUint32(e + 16, true);
  const out = new Map(), dec = new TextDecoder();
  for (let k = 0; k < n; k++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true), csize = dv.getUint32(p + 20, true), nl = dv.getUint16(p + 28, true), xl = dv.getUint16(p + 30, true), cl = dv.getUint16(p + 32, true), lo = dv.getUint32(p + 42, true);
    const name = dec.decode(u8.subarray(p + 46, p + 46 + nl));
    const ds = lo + 30 + dv.getUint16(lo + 26, true) + dv.getUint16(lo + 28, true);
    out.set(name, { method, data: u8.subarray(ds, ds + csize) });
    p += 46 + nl + xl + cl;
  }
  return { entries: out, async text(name) {
    const en = out.get(name); if (!en) return null;
    if (en.method === 0) return dec.decode(en.data);
    if (en.method !== 8) throw new Error("unsupported zip compression " + en.method);
    const ds = new DecompressionStream("deflate-raw");
    const w = ds.writable.getWriter(); w.write(en.data); w.close();
    return dec.decode(await new Response(ds.readable).arrayBuffer());
  } };
}
function xlLocal(t) { return String(t).replace(/^.*:/, ""); }
function xlKids(n, name) { return (n.c || []).filter((c) => xlLocal(c.t) === name); }
function xlText(n) { let s = ""; (function w(x) { if (xlLocal(x.t) === "t") s += x.x || ""; for (const c of x.c || []) w(c); })(n); return s; }
function xlColIndex(ref) { const m = /^([A-Z]+)(\d+)$/.exec(ref); if (!m) return null; let c = 0; for (const ch of m[1]) c = c * 26 + ch.charCodeAt(0) - 64; return { c: c - 1, r: Number(m[2]) - 1 }; }
async function xlsxSheets(buf) {
  const z = await zipEntries(buf);
  const wb = parseXml(await z.text("xl/workbook.xml") || ""), rels = parseXml(await z.text("xl/_rels/workbook.xml.rels") || "");
  const relMap = {}; (function w(n) { for (const c of n.c || []) { if (xlLocal(c.t) === "Relationship") relMap[c.a.Id] = c.a.Target; w(c); } })(rels);
  const sst = []; const sx = await z.text("xl/sharedStrings.xml");
  if (sx) (function w(n) { for (const c of n.c || []) { if (xlLocal(c.t) === "si") sst.push(xlText(c)); else w(c); } })(parseXml(sx));
  const sheets = [];
  const names = []; (function w(n) { for (const c of n.c || []) { if (xlLocal(c.t) === "sheet") names.push({ name: c.a.name, state: c.a.state || "visible", rid: c.a["r:id"] || c.a.id }); else w(c); } })(wb);
  for (const sh of names) {
    let target = relMap[sh.rid] || ""; target = target.replace(/^\//, "");
    const path = target.startsWith("xl/") ? target : "xl/" + target;
    const xml = await z.text(path); if (!xml) continue;
    const doc = parseXml(xml), rows = [], merges = [];
    (function w(n) {
      for (const c of n.c || []) {
        const t = xlLocal(c.t);
        if (t === "c") {
          const pos = xlColIndex(c.a.r || ""); if (!pos) continue;
          let v = "";
          const vn = xlKids(c, "v")[0], inl = xlKids(c, "is")[0];
          if (c.a.t === "s") v = sst[Number(vn && vn.x)] || "";
          else if (c.a.t === "inlineStr") v = inl ? xlText(inl) : "";
          else if (c.a.t === "b") v = vn && vn.x === "1" ? "TRUE" : "FALSE";
          else v = vn ? vn.x : "";
          while (rows.length <= pos.r) rows.push([]);
          const row = rows[pos.r]; while (row.length <= pos.c) row.push("");
          row[pos.c] = v;
        } else if (t === "mergeCell") merges.push(c.a.ref);
        else w(c);
      }
    })(doc);
    for (const ref of merges) {
      const m = /^([A-Z]+\d+):([A-Z]+\d+)$/.exec(ref || ""); if (!m) continue;
      const a = xlColIndex(m[1]), b = xlColIndex(m[2]); if (!a || !b || b.r <= a.r) continue;   // vertical merges only; titles stay put
      const val = rows[a.r] && rows[a.r][a.c]; if (val === "" || val == null) continue;
      for (let r = a.r + 1; r <= b.r; r++) { while (rows.length <= r) rows.push([]); for (let c = a.c; c <= b.c; c++) { while (rows[r].length <= c) rows[r].push(""); rows[r][c] = val; } }
    }
    sheets.push({ name: sh.name, hidden: sh.state !== "visible", table: rows.map((r) => r.map((x) => String(x == null ? "" : x).trim())) });
  }
  return sheets;
}
const FCR_SKIP_SHEET = /instruction|readme|read me|help|example|sample|legend|guide|how to/i;
/* Pick the sheet that holds the requests: a sheet named like the rule list first, instruction or example sheets last. */
async function readFcrXlsx(buf, opts) {
  const sheets = await xlsxSheets(buf);
  const cands = [];
  for (const sh of sheets) {
    const parsed = parseFcrTable(sh.table, opts);
    if (!parsed) continue;
    const nm = sh.name.toLowerCase();
    const rank = FCR_SKIP_SHEET.test(nm) ? -1 : /firewall/.test(nm) && /rule/.test(nm) ? 2 : /rule|firewall|acl|request|fcr/.test(nm) ? 1 : 0;
    cands.push({ sh, parsed, rank, score: Object.keys(parsed.mapping).length, n: parsed.rows.length });
  }
  if (!cands.length) return { error: "No sheet has a source and destination column (looked at: " + (sheets.map((s) => s.name).join(", ") || "none") + ")." };
  cands.sort((a, b) => b.rank - a.rank || b.score - a.score || b.n - a.n);
  const pick = cands[0];
  return { sheet: pick.sh.name, table: pick.sh.table, skipped: sheets.filter((s) => s !== pick.sh).map((s) => s.name), csv: csvText(pick.sh.table) };
}
function hopVerdict(s) {
  if (!s) return { verdict: "unknown", deny: false };
  if (s.isSG) return { verdict: "no-policy", deny: false };
  const c = s.check;
  if (!c) return { verdict: "unknown", deny: false };
  if (c.verdict === "conditional") return { verdict: "conditional", deny: false, rule: c.rule };
  if (c.action === "allow") return { verdict: "allow", deny: false, rule: c.rule };
  return { verdict: "deny", deny: true, rule: c.rule };
}
function explainVsysHops(res, devices) {
  const segs = (res && res.segments) || [];
  const lines = [];
  const vsys = [];
  const seen = new Set();
  for (const s of segs) { const k = s.device + "|" + s.vsys; if (seen.has(k)) continue; seen.add(k); vsys.push(s); }
  const fws = [...new Set(vsys.map((s) => s.device))];
  if (!vsys.length) {
    lines.push("No path was found in the loaded configuration, so there is no vsys list to explain.");
    return { text: lines.join(" "), lines, vsysCount: 0, firewallCount: 0, hairpins: 0, transits: 0 };
  }
  lines.push("This flow crosses " + vsys.length + " vsys on " + fws.length + " firewall" + (fws.length === 1 ? "" : "s") + " (" + vsys.map((s) => s.device + " " + (s.display && s.display !== s.vsys ? s.display + " (" + s.vsys + ")" : s.vsys)).join(" → ") + ").");
  const needRules = ((res.changes) || []).filter((c) => c.kind === "security" && !c.optional).length;
  const placeWord = vsys.length + " vsys" + (fws.length === 1 ? "/firewall" : " on " + fws.length + " firewalls");
  lines.push("It needs " + needRules + " security rule" + (needRules === 1 ? "" : "s") + " across " + placeWord + ".");
  if (vsys.length === 1) lines.push("It stays in one vsys, so a single security rule (plus any route or NAT on that vsys) may be enough.");
  else lines.push("A change on only the first vsys is not enough: each hop has its own rulebase, and a later vsys can still deny the session.");
  let hairpins = 0, transits = 0;
  for (const s of segs) {
    if (s.next && s.next.kind === "hairpin") {
      hairpins++;
      if (s.next.via && s.next.via.user) lines.push("After " + s.device + " " + s.vsys + " the packet leaves the vsys to a router outside the config and re-enters through the link you added (" + s.next.via.label + "). It is not an on-box hand-off, so each vsys needs its own rule.");
      else lines.push("After " + s.device + " " + s.vsys + " the packet leaves the vsys and is assumed to re-enter " + (s.next.to || s.device) + " through an outside router or unknown network (no on-box hand-off with an external zone, visible-vsys or shared gateway). Add a link (same firewall, egress interface to the re-entry interface) to pin it.");
    }
    if (s.next && s.next.via && s.next.via.kind === "transit") {
      transits++;
      lines.push("The hop after " + s.device + " " + s.vsys + " crosses a router or WAN/MPLS core that is not in the loaded configuration (" + (s.next.via.label || "inferred transit") + ").");
    }
  }
  const uncertain = [];
  for (const s of vsys) {
    const d = (devices || []).find((x) => x.name === s.device || x.id === s.devId);
    const v = d && d.vsys.get(s.vsys);
    if (v && v.dgJoinConfidence === "inferred") uncertain.push(s.device + " " + s.vsys + " → device group " + (v.dg || "?") + " (" + (v.dgJoinReason || "inferred") + ")");
    else if (d && d.dgJoin && d.dgJoin.uncertain && v && !v.dg) uncertain.push(s.device + " " + s.vsys + " has no confident device-group join");
  }
  if (uncertain.length) lines.push("Device-group placement is uncertain: " + uncertain.join("; ") + ".");
  const assumesOutside = hairpins > 0 || transits > 0;
  if (assumesOutside) lines.push("The rule count assumes the suggested outside hop.");
  return { text: lines.join(" "), lines, vsysCount: vsys.length, firewallCount: fws.length, hairpins, transits, needRules, assumesOutside };
}
function trafficLogFilters(res) {
  const q = (res && res.query) || {};
  // trace() reports the service as one string ("tcp/8443"); fall back to it so the port filter is never dropped.
  const sv = /^([a-z]+)(?:\/(\d+))?/i.exec(String(q.svc || ""));
  const src = q.src, dst = q.dst, port = q.port != null ? q.port : sv && sv[2] ? Number(sv[2]) : null, proto = (q.proto || (sv && sv[1]) || "tcp").toLowerCase();
  const protoN = proto === "tcp" ? 6 : proto === "udp" ? 17 : proto === "icmp" ? 1 : null;
  const base = [];
  if (src) base.push("(addr.src eq " + src.split("/")[0] + ")");
  if (dst) base.push("(addr.dst eq " + dst.split("/")[0] + ")");
  if (protoN) base.push("(proto eq " + protoN + ")");
  if (port) base.push("(port.dst eq " + port + ")");
  const common = base.join(" and ") || "(addr.src eq <src>) and (addr.dst eq <dst>)";
  const hops = ((res && res.segments) || []).map((s, i) => {
    const v = hopVerdict(s);
    const vsys = s.vsys || "vsys1";
    const fz = s.check && s.check.fromZone, tz = s.check && s.check.toZone;
    // Zone-scope each hop: a flow that leaves one virtual router and comes back in on another is checked twice in the
    // same vsys, and only the zones tell the two log lines (and the two proposed rules) apart.
    const bits = [common, "(vsys.name eq " + vsys + ")"].concat(fz ? ["(zone.src eq " + fz + ")"] : []).concat(tz ? ["(zone.dst eq " + tz + ")"] : []);
    const proposed = ((res.changes || []).find((c) => c.kind === "security" && !c.optional && c.device === s.device && c.vsys === s.vsys && (!c.rule || ((!fz || c.rule.from === fz) && (!tz || c.rule.to === tz)))) || {}).rule;
    // Commands to run on the firewall itself after the push: the same two checks PAAT's live check automates.
    const hostOf = (x) => String(x || "").split("/")[0];
    const pm = ["test security-policy-match source " + hostOf(s.src || src) + " destination " + hostOf(s.dst || dst)].concat(port ? ["destination-port " + port] : []).concat(protoN ? ["protocol " + protoN] : []).concat(fz ? ["from " + fz] : []).concat(tz ? ["to " + tz] : []).join(" ");
    const testCli = [].concat(s.startVr ? ["test routing fib-lookup virtual-router " + s.startVr + " ip " + hostOf(s.dst || dst)] : []).concat([pm]);
    return { hop: i + 1, device: s.device, vsys, display: s.display, testCli, testVsys: vsys !== "vsys1" || (s.display && s.display !== vsys) ? vsys : null, filter: bits.join(" and "), afterPush: proposed && proposed.name ? bits.concat(["(rule eq " + proposed.name + ")"]).join(" and ") : bits.join(" and "), expected: v.deny ? "look for the new allow (or a later deny)" : "confirm the existing allow still hits" };
  });
  return { common, hops };
}
function prePushChecklist(res, devices, plan) {
  const dgs = [...new Set((plan && plan.items || res.changes || []).map((c) => c.dg).filter(Boolean))];
  const items = [
    "Export or save a named configuration snapshot on Panorama (and on any firewall you will touch locally) before you edit.",
    "Make the changes in Panorama first; commit to Panorama and review the candidate config before any device push.",
    dgs.length ? "Push only the device group(s) in this plan (" + dgs.join(", ") + "). Do not Push All." : "Push only the device group or firewall that this plan names. Do not Push All.",
    "Confirm each new security rule is not shadowed: it must sit above the deny (or default) that currently matches, and an earlier allow must not already cover a broader set than you intend.",
    "Check NAT, PBF and the return path on every hop in the trace, not only the first vsys that denied.",
    "If any device-group vsys join was inferred (vsysN ↔ template vsys names), confirm the vsys on the target device before you commit.",
    "After the push, use the traffic-log filters below on each vsys in the path to confirm the new allow (or to see a later deny)."
  ];
  const uncertain = (res.fcr && res.fcr.why && /uncertain|joined by order/.test(res.fcr.why.text)) || (devices || []).some((d) => d.dgJoin && d.dgJoin.uncertain && (res.segments || []).some((s) => s.device === d.name));
  if (uncertain) items.push("Stop and confirm device-group placement where the plan is flagged uncertain, before pushing.");
  return items;
}
function combinedChangePlan(res, devices) {
  const items = [];
  const seenJoin = new Set();
  for (const c of (res.changes || [])) {
    const d = (devices || []).find((x) => x.name === c.device);
    const v = d && c.vsys ? d.vsys.get(c.vsys) : null;
    const join = v && (v.dgJoinConfidence || (d && d.dgJoin && d.dgJoin.map[c.vsys]));
    const j = v && v.dgJoinConfidence ? { confidence: v.dgJoinConfidence, reason: v.dgJoinReason, dg: v.dg, dgVsys: v.dgVsys } : (d && d.dgJoin && d.dgJoin.map[c.vsys]) || null;
    const item = Object.assign({}, c, { dg: c.dg || (v && v.dg) || null, dgVsys: v && v.dgVsys || null, dgJoin: j, uncertain: !!(j && j.confidence === "inferred") || !!(d && d.dgJoin && d.dgJoin.uncertain && v && !v.dg) });
    if (j && !seenJoin.has(c.device + "|" + c.vsys)) { seenJoin.add(c.device + "|" + c.vsys); item.joinNote = j.reason; }
    items.push(item);
  }
  const cli = items.filter((c) => !c.optional && c.cli && c.cli.length).map((c) => "# " + c.device + (c.vsys ? " " + c.vsys : "") + (c.dg ? " [DG " + c.dg + "]" : "") + (c.uncertain ? " [DG placement uncertain]" : "") + " — " + c.summary + "\n" + c.cli.join("\n")).join("\n\n");
  return { items, cli, required: items.filter((c) => !c.optional).length, verify: items.filter((c) => c.optional).length, uncertain: items.filter((c) => c.uncertain).length };
}
/* The "rule needed in more than one place" check, shared by the offline page and PAAT. A flow is checked by
   security policy at every firewall/vsys it crosses (and twice in one vsys when it hairpins out and back in), so one
   allow is not enough. Each place is listed with whether it still needs a rule. */
function multiPlace(hops, res) {
  const needRule = hops.filter((h) => h.verdict !== "allow");
  const changes = (res && res.changes) || [];
  const places = hops.map((h) => ({
    n: h.n, device: h.device, vsys: h.vsys, display: h.display || null, fromZone: h.fromZone || null, toZone: h.toZone || null,
    verdict: h.verdict, rule: h.rule || null, needs: h.verdict !== "allow", hairpin: !!h.hairpin,
    newRule: ((changes.find((c) => c.kind === "security" && !c.optional && c.device === h.device && c.vsys === h.vsys && (!c.rule || ((!h.fromZone || c.rule.from === h.fromZone) && (!h.toZone || c.rule.to === h.toZone)))) || {}).rule || {}).name || null
  }));
  const en = { points: hops.length, needRule: needRule.length, hops: needRule.map((h) => h.n), multi: hops.length > 1, places };
  en.level = !en.multi ? "single" : en.needRule ? "need" : "ok";
  const assumesOutside = places.some((p) => p.hairpin) || hops.some((h) => h.transit) || ((res && res.stitches) || []).some((st) => (st.via && (st.via.kind === "hairpin" || st.via.kind === "transit")) || st.hairpin);
  en.assumesOutsideHop = !!assumesOutside;
  const placeWord = en.points + " vsys/firewall" + (en.points === 1 ? "" : "s");
  en.needText = "This flow needs " + en.needRule + " rule" + (en.needRule === 1 ? "" : "s") + " across " + placeWord + ".";
  if (assumesOutside) en.needText += " The count assumes the suggested outside hop.";
  en.text = !en.multi ? "" : en.needText + " It is checked by security policy in " + en.points + " places. " +
    (en.needRule ? en.needRule + " of them still need an allow (hop" + (en.needRule > 1 ? "s " : " ") + en.hops.join(", ") + "). Push every one, or the traffic stays blocked at the one you missed." : "Every place already allows it.");
  return en;
}
function annotateFcr(res, devices) {
  if (!res) return res;
  const hops = ((res.segments) || []).map((s, i) => {
    const v = hopVerdict(s);
    return { n: i + 1, device: s.device, vsys: s.vsys, display: s.display, dg: (s.check && s.check.dg) || null, vr: s.startVr || null, ingressIf: (s.ingress && s.ingress.iface) || null, egressIf: (s.egress && s.egress.iface) || null, fromZone: s.check && s.check.fromZone, toZone: s.check && s.check.toZone, verdict: v.verdict, rule: v.rule || (s.check && s.check.rule) || null, deny: v.deny, hairpin: !!(s.next && s.next.kind === "hairpin"), transit: !!(s.next && s.next.via && s.next.via.kind === "transit") };
  });
  const why = explainVsysHops(res, devices);
  const plan = combinedChangePlan(res, devices);
  const needRule = hops.filter((h) => h.verdict !== "allow");
  // How many places on the path check security policy, and how many still need an allow.
  const enforcement = multiPlace(hops, res);
  res.fcr = { hops, why, plan, enforcement, checklist: [], filters: trafficLogFilters(res) };
  res.fcr.checklist = prePushChecklist(res, devices, plan);
  return res;
}

/* ------------------------------------------------------------------ vsys-level environment map */
function vsysMap(devices, opts) {
  opts = opts || {};
  const env = environment(devices, opts.links || []);
  const pathKeys = new Set((opts.path || []).map((h) => String(h.device || h.dev || "") + "|" + String(h.vsys || "")));
  const units = env.units.map((u) => {
    const devs = u.members.map((m) => devices.find((d) => d.name === m || d.id === m)).filter(Boolean);
    const vsys = [], seen = new Set();
    for (const d of devs) for (const v of d.vsys.values()) {
      if (v.isSG || seen.has(v.name)) continue;
      seen.add(v.name);
      const onPath = u.members.some((m) => pathKeys.has(m + "|" + v.name)) || pathKeys.has(d.name + "|" + v.name);
      let unknown = 0;
      for (const vr of new Set(d.vrs.values())) {
        if (vr.owner && vr.owner !== v.name && !(vr.sharedOwners || []).includes(v.name)) continue;
        for (const r of vr.routes) {
          if (r.type !== "static" || !r.nexthop || r.nexthop.type !== "ip") continue;
          const n = ip2n(r.nexthop.value);
          if (n == null) continue;
          const owned = devices.some((x) => [...x.interfaces.values()].some((i) => i.ips.some((p) => p.ip === n)));
          if (!owned) unknown++;
        }
      }
      vsys.push({ name: v.name, display: v.display, dg: v.dg || null, onPath, ifaces: [...d.interfaces.values()].filter((i) => i.vsys === v.name).length, zones: [...v.zones.keys()], unknownNhs: unknown, joinUncertain: v.dgJoinConfidence === "inferred" });
    }
    return { id: u.id, name: u.name, members: u.members, site: u.site, multiVsys: u.multiVsys, vsys, pathVsys: vsys.filter((v) => v.onPath).length };
  });
  return { env, units, pathCount: pathKeys.size };
}
function vsysMapLayout(map, opts) {
  opts = opts || {};
  const exp = opts.expanded || new Set();
  const shapes = [], edges = [];
  const UW = 260, PAD = 16, GAP = 28, COLS = Math.max(1, Math.min(4, Math.ceil(Math.sqrt((map.units || []).length || 1))));
  const cloudId = "unknown-net";
  let anyUnknown = false;
  const colY = new Array(COLS).fill(110);
  const colX = (c) => 20 + c * (UW + GAP);
  shapes.push({ id: cloudId, kind: "cloud", x: 20, y: 16, w: 220, h: 70, label: "Unknown network\n(routers / WAN not in the config)" });
  (map.units || []).forEach((u) => {
    const c = colY.indexOf(Math.min(...colY));
    const x = colX(c), y = colY[c];
    const open = exp.has(u.id);
    const path = u.vsys.filter((v) => v.onPath);
    const other = u.vsys.filter((v) => !v.onPath);
    const showAll = open && (path.length === 0 || exp.has(u.id + ":all"));
    const shown = !open ? [] : (showAll ? u.vsys : path);
    const pool = !open ? [] : (showAll ? [] : other);
    let h = 54;
    if (open) h = 50 + shown.length * 28 + (pool.length ? 28 : 0) + 8;
    shapes.push({ id: "u:" + u.id, kind: "fw", unit: u.id, x, y, w: UW, h, label: u.name, sub: u.vsys.length + " vsys" + (u.pathVsys ? " · " + u.pathVsys + " on the last trace" : "") + (u.members.length > 1 ? " · HA " + u.members.length : ""), expanded: open, warn: u.vsys.some((v) => v.joinUncertain) });
    let yy = y + 50;
    shown.forEach((v) => {
      const sid = "u:" + u.id + ":v:" + v.name;
      shapes.push({ id: sid, kind: "vsys", x: x + 8, y: yy, w: UW - 16, h: 24, label: (v.onPath ? "● " : "") + (v.display && v.display !== v.name ? v.display + " (" + v.name + ")" : v.name) + (v.dg ? "  [DG " + v.dg + "]" : "") + (v.unknownNhs ? " · outside NH" : ""), warn: v.onPath });
      if (v.unknownNhs) { edges.push({ id: "e:" + sid, s: sid, t: cloudId, kind: "wan", label: "" }); anyUnknown = true; }
      yy += 28;
    });
    if (pool.length) {
      const pid = "u:" + u.id + ":pool";
      shapes.push({ id: pid, kind: "ghost", x: x + 8, y: yy, w: UW - 16, h: 24, label: pool.length + " other vsys", sub: "click the firewall, then Expand all, to list them" });
      if (pool.some((v) => v.unknownNhs)) { edges.push({ id: "e:" + pid, s: pid, t: cloudId, kind: "wan", label: "" }); anyUnknown = true; }
    }
    if (!open && u.vsys.some((v) => v.unknownNhs)) { edges.push({ id: "e:u:" + u.id, s: "u:" + u.id, t: cloudId, kind: "wan", label: "" }); anyUnknown = true; }
    colY[c] += h + GAP;
  });
  if (!anyUnknown) shapes.splice(0, 1);
  const width = COLS * (UW + GAP) + 20, height = Math.max(...colY, 200) + 20;
  return { shapes, edges, width, height };
}

/* ------------------------------------------------------------------ site roles and scope (production-only view)
 * Every firewall gets a ROLE (Production, DR, Lab, Test, Other, or roles you add). Roles are about FIREWALLS only: Panorama
 * itself (and its own HA pair) is never used to place or pair a firewall. A scope (All sites / Production only / custom sites)
 * then decides which firewalls take part in tracing, next-hop candidates, shared-IP pickers, alternates, diagrams, batch runs and plans.
 *
 * How a role is guessed: only generic words found in the firewall's hostname, template stack and device-group names
 * (prod, prd, production, dr, cob, backup, failover, lab, test, qa ...). No site or customer name is built in. Each guess carries
 * its reason in plain words, and everything is overridable per site and per firewall, plus extra words and extra roles in a profile.
 * Nothing is hidden by a guess alone unless a word says DR / Lab / Test: firewalls with no clue stay "Other", which Production only keeps. */
/* SCOPE:BEGIN */
const ROLE_DEFS = [
  { id: "production", label: "Production", focus: true, mirror: false },
  { id: "dr", label: "DR", focus: false, mirror: true },
  { id: "lab", label: "Lab", focus: false, mirror: false },
  { id: "test", label: "Test", focus: false, mirror: false },
  { id: "other", label: "Other", focus: true, mirror: false }
];
const ROLE_TOKENS = {
  production: ["prod", "prd", "production"],
  dr: ["dr", "drc", "cob", "bcp", "backup", "bkp", "failover", "recovery", "disaster"],
  lab: ["lab", "labs", "sandbox", "poc"],
  test: ["test", "tst", "qa", "uat", "dev", "stage", "staging", "stg", "preprod"]
};
/* Weaker words: only trusted in template-stack and device-group names, where "primary" / "secondary" are not an HA unit label. */
const ROLE_WEAK_TOKENS = { production: ["primary"], dr: ["secondary", "standby"] };
const SCOPE_CACHE = typeof WeakMap !== "undefined" ? new WeakMap() : null;

/* User-defined role matching rules. First match wins. Never hard-code a site or customer name:
 * the words to look for come only from the saved profile (the user types them). */
const RULE_FIELDS = [
  { id: "hostname", label: "Hostname" },
  { id: "stack", label: "Template stack" },
  { id: "dg", label: "Device group" },
  { id: "serial", label: "Serial" },
  { id: "site", label: "Site id" },
  { id: "name", label: "Any name field" }
];
const RULE_FIELD_IDS = new Set(RULE_FIELDS.map((f) => f.id));
const RULE_FIELD_ALIAS = { "template-stack": "stack", "template_stack": "stack", templatestack: "stack", "device-group": "dg", "device_group": "dg", devicegroup: "dg", "site-id": "site", "site_id": "site", any: "name", "any-name": "name", "any_name": "name", anyname: "name" };
const RULE_MATCH_IDS = { contains: "contains", word: "word", "whole-word": "word", whole_word: "word", regex: "regex", regexp: "regex" };
function ruleFieldId(s) { const id = cleanId(s); return RULE_FIELD_IDS.has(id) ? id : (RULE_FIELD_ALIAS[id] || null); }
function ruleMatchId(s) { return RULE_MATCH_IDS[String(s == null ? "contains" : s).toLowerCase().trim()] || "contains"; }
function ruleFieldLabel(id) { const f = RULE_FIELDS.find((x) => x.id === id); return f ? f.label : id; }
function ruleMatchLabel(m) { return m === "word" ? "whole word" : m === "regex" ? "regex" : "contains"; }
function normalizeRules(raw, valid) {
  const out = [];
  if (!Array.isArray(raw)) return out;
  for (const r of raw) {
    if (!r || typeof r !== "object") continue;
    const field = ruleFieldId(r.field); if (!field) continue;
    const match = ruleMatchId(r.match != null ? r.match : r.op);
    const value = String(r.value == null ? "" : r.value).slice(0, 120);
    const role = cleanId(r.role); if (!valid || !valid.has(role)) continue;
    out.push({ field, match, value, role });
  }
  return out;
}
function ruleFieldText(d, field) {
  const hn = (d && (d.hostname || (d.panorama && d.panorama.hostname) || d.hostnameInit)) || "";
  const name = (d && d.name) || "";
  const stack = (d && d.stack) || "";
  const serial = (d && (d.serial || (d.panorama && d.panorama.serial))) || "";
  const site = typeof siteIdOf === "function" ? (siteIdOf(d) || "") : "";
  const dgs = (typeof devDgNames === "function" ? devDgNames(d) : []).join(" ");
  if (field === "hostname") return hn || (/^\d{9,}$/.test(name) ? "" : name);
  if (field === "stack") return stack;
  if (field === "dg") return dgs;
  if (field === "serial") return String(serial);
  if (field === "site") return site;
  return [hn, name, stack, dgs, site].filter(Boolean).join(" ");
}
function ruleRegex(value) {
  try { return { re: new RegExp(value, "i") }; } catch (err) { return { error: "invalid regular expression" }; }
}
function ruleApplies(d, rule) {
  const value = String((rule && rule.value) || "");
  if (!value) return { ok: false, error: "empty" };
  const text = ruleFieldText(d, rule.field);
  if (rule.match === "regex") {
    const c = ruleRegex(value);
    if (c.error) return { ok: false, error: c.error };
    return { ok: c.re.test(text) };
  }
  const t = String(text).toLowerCase(), v = value.toLowerCase();
  if (rule.match === "word") {
    const tw = rawWords(t), vw = rawWords(v);
    let ok = !!(vw.length && t === v);
    if (!ok && vw.length) for (let i = 0; i + vw.length <= tw.length; i++) if (vw.every((w, j) => tw[i + j] === w)) { ok = true; break; }
    return { ok };
  }
  return { ok: t.includes(v) };
}
function ruleDescribe(rule, index) {
  return "rule " + (index + 1) + ": " + ruleFieldLabel(rule.field).toLowerCase() + " " + ruleMatchLabel(rule.match) + ' "' + rule.value + '"';
}
function firstRoleRule(d, rules) {
  if (!rules || !rules.length) return null;
  for (let i = 0; i < rules.length; i++) {
    const a = ruleApplies(d, rules[i]);
    if (a.ok) return { index: i, rule: rules[i], role: rules[i].role, why: "Rule " + (i + 1) + ": " + ruleFieldLabel(rules[i].field).toLowerCase() + " " + ruleMatchLabel(rules[i].match) + ' "' + rules[i].value + '".' };
  }
  return null;
}
/* Live preview: how many firewalls each rule matches, which ones, overlaps (a later rule would also match), empty or invalid rules. */
function rulePreview(devices, profile) {
  profile = normalizeProfile(profile);
  const rules = profile.rules, first = new Map();
  const items = rules.map((rule, i) => {
    let error = null;
    if (!String(rule.value || "").trim()) error = "empty";
    else if (rule.match === "regex") { const c = ruleRegex(rule.value); if (c.error) error = c.error; }
    const hits = [], overlap = [];
    if (!error) for (const d of devices) {
      if (!ruleApplies(d, rule).ok) continue;
      const key = devKey(d), label = typeof devLabel === "function" ? devLabel(d) : (d.hostname || d.name || key);
      hits.push({ key, label, site: siteIdOf(d) });
      if (first.has(key)) overlap.push({ key, label, earlier: first.get(key) + 1 });
      else first.set(key, i);
    }
    let warning = null;
    if (error === "empty") warning = "This rule matches nothing (no text to look for).";
    else if (error) warning = "This rule has an " + error + ".";
    else if (!hits.length) warning = "This rule matches nothing.";
    return { index: i, rule, count: hits.length, devices: hits, overlap, overlapCount: overlap.length, warning };
  });
  return { rules: items, matched: first.size };
}

function defaultProfile() {

  return { kind: "flowmapper-site-roles", version: 1, roles: [], tokens: {}, sites: {}, devices: {}, rules: [], scope: { mode: "production", sites: [] }, mirror: { enabled: true }, panoramas: {} };
}
const cleanId = (s) => String(s == null ? "" : s).trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
/* Accepts anything (a saved profile, a partial override file, junk) and returns a complete, safe profile. */
function normalizeProfile(p) {
  const o = defaultProfile(); if (!p || typeof p !== "object" || Array.isArray(p)) return o;
  const builtin = new Set(ROLE_DEFS.map((r) => r.id));
  if (Array.isArray(p.roles)) for (const r of p.roles) { const id = cleanId(r && r.id || r && r.label); if (!id || builtin.has(id) || o.roles.some((x) => x.id === id)) continue; o.roles.push({ id, label: String(r.label || id).slice(0, 40), focus: !!r.focus, mirror: !!r.mirror }); }
  const valid = new Set([...builtin, ...o.roles.map((r) => r.id)]);
  const mapOf = (src, dst) => { if (src && typeof src === "object" && !Array.isArray(src)) for (const [k, v] of Object.entries(src)) { const id = cleanId(v); if (valid.has(id)) dst[k] = id; } };
  mapOf(p.sites, o.sites); mapOf(p.devices, o.devices);
  o.rules = normalizeRules(p.rules, valid);
  if (p.tokens && typeof p.tokens === "object") for (const [k, v] of Object.entries(p.tokens)) { const id = cleanId(k); if (valid.has(id) && Array.isArray(v)) o.tokens[id] = v.map((w) => String(w).toLowerCase().trim()).filter((w) => /^[a-z0-9]{1,24}$/.test(w)); }
  if (p.scope && typeof p.scope === "object") { const m = String(p.scope.mode || "").toLowerCase(); o.scope.mode = m === "all" || m === "custom" ? m : "production"; if (Array.isArray(p.scope.sites)) o.scope.sites = p.scope.sites.map(String); }
  if (p.mirror && typeof p.mirror === "object") o.mirror.enabled = p.mirror.enabled !== false;
  if (p.panoramas && typeof p.panoramas === "object" && !Array.isArray(p.panoramas)) for (const [k, v] of Object.entries(p.panoramas)) if (v && typeof v === "object") { const e = {}; const rid = cleanId(v.role); if (valid.has(rid)) e.role = rid; if (/^(active|passive)$/i.test(v.state || "")) e.state = String(v.state).toLowerCase(); if (v.label) e.label = String(v.label).slice(0, 60); o.panoramas[k] = e; }
  return o;
}
/* "--scope production | all | sites=a,b" (CLI and PAAT). Returns { mode, sites }. */
function parseScopeArg(s) {
  const t = String(s == null ? "" : s).trim();
  if (!t || /^production(-only)?$/i.test(t)) return { mode: "production", sites: [] };
  if (/^all(-sites)?$/i.test(t)) return { mode: "all", sites: [] };
  const m = /^sites?\s*=\s*(.+)$/i.exec(t);
  if (m) return { mode: "custom", sites: m[1].split(",").map((x) => x.trim()).filter(Boolean) };
  throw new Error("Unknown scope '" + t + "'. Use production, all, or sites=name1,name2.");
}
function roleDefs(profile) { const defs = ROLE_DEFS.concat(profile.roles); const m = new Map(defs.map((r) => [r.id, r])); return { list: defs, byId: m }; }
const wordMatches = (w, t) => w === t || (/^[a-z]+$/.test(t) && w.replace(/\d+[ab]?$/, "") === t && w.length > t.length);
function roleWords(profile, weak) {
  const out = []; // [role, word]
  const base = weak ? ROLE_WEAK_TOKENS : ROLE_TOKENS;
  for (const [r, ws] of Object.entries(base)) for (const w of ws) out.push([r, w]);
  if (!weak) for (const [r, ws] of Object.entries(profile.tokens || {})) for (const w of ws) out.push([r, w]);
  return out;
}
const rawWords = (s) => String(s || "").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
/* Evidence for a role in one text: [{ role, word, text }] */
function roleHits(text, profile, weak) {
  const hits = [], words = rawWords(text);
  for (const w of words) for (const [r, t] of roleWords(profile, weak)) if (wordMatches(w, t)) hits.push({ role: r, word: w, text });
  return hits;
}
function devKey(d) { return (d && (d.serial || (d.panorama && d.panorama.serial))) || (d && (d.hostname || d.name)) || ""; }
function devDgNames(d) { const s = new Set(); if (d.panorama && d.panorama.dgMap) for (const v of Object.values(d.panorama.dgMap)) if (v) s.add(v); for (const v of d.vsys ? d.vsys.values() : []) if (v.dg) s.add(v.dg); return [...s]; }
function siteIdOf(d) { return siteKey(d) || (d.stack ? "stack " + d.stack : "(no site)"); }
/* One firewall's own evidence: hostname counts 3, template stack 2, device group 2; weak words (primary, secondary) only from stack / DG, 1. */
function guessFromEvidence(d, profile) {
  const srcs = [];
  const hn = d.hostname || (d.panorama && d.panorama.hostname) || d.hostnameInit || null;
  if (hn) srcs.push({ src: "hostname", text: hn, w: 3, weak: false });
  if (d.name && d.name !== hn && !/^\d{9,}$/.test(d.name) && d.kind !== "panorama") srcs.push({ src: "name", text: d.name, w: 3, weak: false });
  if (d.stack) srcs.push({ src: "template stack", text: d.stack, w: 2, weak: false }, { src: "template stack", text: d.stack, w: 1, weak: true });
  for (const g of devDgNames(d)) srcs.push({ src: "device group", text: g, w: 2, weak: false }, { src: "device group", text: g, w: 1, weak: true });
  const score = {}, why = {};
  for (const s of srcs) for (const h of roleHits(s.text, profile, s.weak)) {
    const k = h.role + "|" + s.src + "|" + s.text; if (why[k]) continue; why[k] = true;
    score[h.role] = (score[h.role] || 0) + s.w; (score[h.role + "#why"] = score[h.role + "#why"] || []).push(s.src + ' "' + s.text + '" contains "' + h.word + '"');
  }
  const roles = Object.keys(score).filter((k) => !k.includes("#")).sort((a, b) => score[b] - score[a]);
  if (!roles.length) return { role: null, why: "no production / DR / lab / test words in its hostname, template stack or device group names" };
  if (roles.length > 1 && score[roles[0]] === score[roles[1]]) return { role: null, conflict: true, why: "mixed clues (" + roles.map((r) => r + ": " + score[r + "#why"].join("; ")).join(" | ") + ")" };
  return { role: roles[0], why: score[roles[0] + "#why"].join("; ") };
}
function roleKey(profile) { return JSON.stringify([profile.roles, profile.tokens, profile.sites, profile.devices, profile.rules]); }
/* Role of every firewall. Order of authority: your setting for the firewall, your setting for its site, a matching rule
 * (first match wins), its own clues, the site's majority clue, then Other. An HA secondary follows its primary unless you set it yourself. */
function roleModel(devices, profile) {
  profile = normalizeProfile(profile);
  const k = roleKey(profile), c = SCOPE_CACHE && SCOPE_CACHE.get(devices);
  if (c && c.roleKey === k && c.model) return c.model;
  const defs = roleDefs(profile), label = (id) => (defs.byId.get(id) || { label: id }).label;
  const ha = haInfo(devices);
  const sig = new Map(), siteDevs = new Map();
  for (const d of devices) { sig.set(d, guessFromEvidence(d, profile)); const sid = siteIdOf(d); if (!siteDevs.has(sid)) siteDevs.set(sid, []); siteDevs.get(sid).push(d); }
  const siteGuess = new Map();
  for (const [sid, ds] of siteDevs) {
    const cnt = {}; let n = 0; for (const d of ds) { const g = sig.get(d); if (g.role) { cnt[g.role] = (cnt[g.role] || 0) + 1; n++; } }
    const top = Object.keys(cnt).sort((a, b) => cnt[b] - cnt[a]);
    if (top.length && (top.length === 1 || cnt[top[0]] > cnt[top[1]])) siteGuess.set(sid, { role: top[0], why: cnt[top[0]] + " of " + ds.length + " firewall" + (ds.length === 1 ? "" : "s") + " at this site point to " + label(top[0]) + " by name" });
  }
  const byDev = new Map();
  for (const d of devices) {
    const sid = siteIdOf(d), key = devKey(d), g = sig.get(d);
    let r;
    if (profile.devices[key]) r = { role: profile.devices[key], source: "firewall setting", why: "You set this firewall to " + label(profile.devices[key]) + "." };
    else if (profile.sites[sid]) r = { role: profile.sites[sid], source: "site setting", why: "You set site " + sid + " to " + label(profile.sites[sid]) + "." };
    else { const ru = firstRoleRule(d, profile.rules);
      if (ru) r = { role: ru.role, source: "rule", why: ru.why };
      else if (g.role) r = { role: g.role, source: "guess", why: "Guessed " + label(g.role) + ": " + g.why + "." };
      else if (siteGuess.has(sid)) r = { role: siteGuess.get(sid).role, source: "guess", why: "Guessed " + label(siteGuess.get(sid).role) + " from its site: " + siteGuess.get(sid).why + "." };
      else r = { role: "other", source: "default", why: "Not guessed: " + g.why + ". Kept as Other, which Production only still shows. Set the role yourself if you know it." };
    }
    byDev.set(d, Object.assign(r, { site: sid, key }));
  }
  for (const grp of ha.groups) {
    const p = grp[0], pr = byDev.get(p);
    for (const d of grp.slice(1)) { const cur = byDev.get(d); if (cur.source !== "firewall setting") byDev.set(d, Object.assign({}, cur, { role: pr.role, source: pr.source === "firewall setting" ? "ha" : pr.source, why: "HA peer of " + (p.hostname || p.name) + ": same role (" + label(pr.role) + ")." })); }
  }
  const sites = [];
  for (const [sid, ds] of siteDevs) {
    const counts = {}; for (const d of ds) { const r = byDev.get(d).role; counts[r] = (counts[r] || 0) + 1; }
    const own = profile.sites[sid], gu = siteGuess.get(sid);
    const role = own || (gu && gu.role) || Object.keys(counts).sort((a, b) => counts[b] - counts[a])[0] || "other";
    sites.push({ id: sid, role, source: own ? "site setting" : gu ? "guess" : "default", why: own ? "You set this site to " + label(own) + "." : gu ? "Guessed " + label(gu.role) + ": " + gu.why + "." : "No clear words in the hostnames, stacks or device groups.", devices: ds.map((d) => d.id), count: ds.length, counts, mixed: Object.keys(counts).length > 1 });
  }
  sites.sort((a, b) => a.id.localeCompare(b.id));
  const model = { byDev, sites, defs, profile };
  const e = c || {}; e.roleKey = k; e.model = model; if (SCOPE_CACHE && !c) SCOPE_CACHE.set(devices, e);
  return model;
}
function roleOf(devices, profile, d) { const m = roleModel(devices, profile).byDev.get(d); return m ? m.role : "other"; }
function modeLabel(mode) { return mode === "all" ? "All sites" : mode === "custom" ? "Custom sites" : "Production only"; }
/* The firewalls that take part in a trace. Returns { devices, all, hidden, byRole, mode, chip, text, model }. When nothing is hidden,
 * devices === all (same array) so nothing is rebuilt. Hidden firewalls are left out of everything downstream (the list is the only input).
 * HA pairs are decided on the full list first, so hiding a firewall never makes two look-alike production firewalls pair up. */
function scopeDevices(devices, profile) {
  profile = normalizeProfile(profile);
  const model = roleModel(devices, profile), defs = model.defs, mode = profile.scope.mode;
  const sk = JSON.stringify([roleKey(profile), profile.scope]);
  let ent = SCOPE_CACHE && SCOPE_CACHE.get(devices);
  if (ent && ent.scopes && ent.scopes.has(sk)) return ent.scopes.get(sk);
  const focusOf = (d) => (defs.byId.get(model.byDev.get(d).role) || { focus: true }).focus;
  /* Production only that would leave nothing (for example a lab that only has lab firewalls) must not silently show an empty picture: show everything and say so. */
  const noneFocus = mode === "production" && devices.length > 0 && !devices.some(focusOf);
  const vis = (d) => { const r = model.byDev.get(d); if (mode === "all" || noneFocus) return true; if (mode === "custom") return profile.scope.sites.some((s) => s === r.site || s.toLowerCase() === String(r.site).toLowerCase()); return (defs.byId.get(r.role) || { focus: true }).focus; };
  const keep = devices.filter(vis), hidden = devices.filter((d) => !vis(d));
  const byRole = {}; for (const d of hidden) { const r = model.byDev.get(d).role; byRole[r] = (byRole[r] || 0) + 1; }
  const label = (id) => (defs.byId.get(id) || { label: id }).label;
  let scoped = devices;
  if (hidden.length) {
    const full = haInfo(devices), vset = new Set(keep);
    const groups = full.groups.filter((g) => g.every((d) => vset.has(d)));
    const primaryOf = (d) => { const p = full.primaryOf(d); return p && vset.has(p) ? p : null; };
    const active = keep.filter((d) => !primaryOf(d));
    scoped = keep;
    if (HA_CACHE) { HA_CACHE.set(keep, { active, groups, primaryOf: (d) => primaryOf(d), mapId: (id) => { const p = primaryOf(id); return p ? p.id : id; } }); if (active !== keep) HA_CACHE.set(active, { active, groups, primaryOf: () => null, mapId: (id) => id }); }
  }
  const parts = Object.keys(byRole).map((r) => byRole[r] + " " + label(r));
  const chip = noneFocus ? "Scope: Production only found no production firewalls, so all " + devices.length + " firewall" + (devices.length === 1 ? " is" : "s are") + " shown (mark which are production under Site roles)" : mode === "all" ? "Scope: All sites, nothing hidden" : "Scope: " + modeLabel(mode) + ", " + (hidden.length ? hidden.length + " firewall" + (hidden.length === 1 ? "" : "s") + " hidden (" + parts.join(", ") + ")" : "no firewalls hidden");
  const out = { devices: scoped, all: devices, hidden, byRole, mode, chip, noneFocus, hiddenCount: hidden.length, visibleCount: keep.length, model, profile,
    text: hidden.length ? "Traces, next hops, pickers, alternates, diagrams and plans use " + keep.length + " firewall" + (keep.length === 1 ? "" : "s") + ". " + hidden.length + " (" + parts.join(", ") + ") are left out. Change the scope to see them." : "Every loaded firewall takes part." };
  ent = (SCOPE_CACHE && SCOPE_CACHE.get(devices)) || ent || {}; if (!ent.scopes) ent.scopes = new Map();
  if (ent.scopes.size > 12) ent.scopes.delete(ent.scopes.keys().next().value);
  ent.scopes.set(sk, out); if (SCOPE_CACHE && !SCOPE_CACHE.has(devices)) SCOPE_CACHE.set(devices, ent);
  return out;
}
const scopeSummary = (sc) => ({ mode: sc.mode, chip: sc.chip, hidden: sc.hiddenCount, visible: sc.visibleCount, byRole: sc.byRole, hiddenDevices: sc.hidden.map((d) => d.hostname || d.name) });
/* Role label plus hostname, for hidden-firewall notices. */
function hiddenNames(sc, ids) {
  return ids.map((id) => sc.all.find((d) => d.id === id)).filter(Boolean).map((d) => {
    const r = sc.model && sc.model.byDev.get(d), lab = r && sc.model.defs.byId.get(r.role) ? sc.model.defs.byId.get(r.role).label : "";
    return (d.hostname || d.name) + (lab ? " (" + lab + ")" : "");
  });
}
function hiddenUsedIds(full, hid) {
  const used = [];
  const add = (id) => { if (id && hid.has(id) && !used.includes(id)) used.push(id); };
  if (!full) return used;
  for (const s of full.segments || []) add(s.devId);
  const p0 = full.plan && full.plan.paths && full.plan.paths[0];
  if (p0) { add(p0.srcDevId); add(p0.dstDevId); for (const h of p0.hops || []) { add(h.devId); add(h.toId); } }
  for (const o of (full.plan && full.plan.srcOwners) || []) add(o.devId);
  for (const o of (full.plan && full.plan.dstOwners) || []) add(o.devId);
  if (full.ingress && full.ingress.devId) add(full.ingress.devId);
  return used;
}
/* Did the path need a hidden firewall? Uses a full-scope trace when given, otherwise runs one. */
function hiddenPathCheck(sc, query, opts, res, full) {
  if (!sc.hidden.length) return null;
  const ps = res && res.pathStatus, done = res && res.status !== "error" && ps && ps.status === "complete" && res.final && res.final.kind === "delivered";
  if (done) return null;
  if (!full) { try { full = trace(sc.all, query, opts); } catch (e) { return null; } }
  const hid = new Set(sc.hidden.map((d) => d.id)), used = hiddenUsedIds(full, hid);
  if (!used.length) return null;
  const names = hiddenNames(sc, used);
  return { devices: used.map((id) => { const d = sc.all.find((x) => x.id === id); return d ? d.name : id; }), names, fullStatus: full.pathStatus ? full.pathStatus.status : null, fullFinal: full.final ? full.final.kind : null,
    text: "This path only completes through " + names.join(", ") + (used.length === 1 ? ", a firewall" : ", firewalls") + " hidden by the scope (" + modeLabel(sc.mode) + "). With the firewalls it needs left out, the trace stops at the edge of what is loaded. Switch the scope to All sites to see the whole path." };
}
/* When Production only (or a custom set) hides a firewall, a routing/rules disagreement can appear that is not present with every site included.
   Distinguish that from a genuine disagreement that exists either way, so the count is not mistaken for a wave of stale rules. */
function scopeConflictCheck(res, sc, full) {
  if (!res || !res.conflict || !sc || !sc.hidden.length || !full) return null;
  const hid = new Set(sc.hidden.map((d) => d.id));
  const hopIds = hiddenUsedIds(full, hid);
  const ownIds = [];
  for (const o of ((full.plan && full.plan.dstOwners) || []).concat((full.plan && full.plan.srcOwners) || [])) if (hid.has(o.devId) && !ownIds.includes(o.devId)) ownIds.push(o.devId);
  const used = hopIds.length ? hopIds : ownIds;
  const names = hiddenNames(sc, used);
  if (full.conflict) {
    return { cause: "preexisting", text: "Routing and rules also disagree when every loaded firewall is included. This is worth reviewing (a stale rule or a routing problem).", names, devices: used.map((id) => { const d = sc.all.find((x) => x.id === id); return d ? d.name : id; }) };
  }
  if (!used.length) {
    return { cause: "scope-other", text: "This disagreement appears only with the current scope, but the full path does not actually use a hidden firewall. Switch the scope to All sites to compare.", names: [], devices: [] };
  }
  const cause = hopIds.length ? "hidden-routed-hop" : "hidden-owner";
  const who = names.join(", ");
  const text = cause === "hidden-routed-hop"
    ? "This disagreement only appears because the scope (" + modeLabel(sc.mode) + ") hid " + who + ", the firewall" + (names.length === 1 ? "" : "s") + " routing would use. With All sites, routing takes that path and does not disagree with the rules. Switch the scope to All sites to see the routed path. This is not, by itself, a stale rule."
    : "This disagreement only appears because the address this flow uses is on " + who + ", hidden by the scope (" + modeLabel(sc.mode) + "). With that firewall left out, the tool picks another place and routing and rules now disagree. Switch the scope to All sites to see the real owner. This is not, by itself, a stale rule.";
  return { cause, text, names, devices: used.map((id) => { const d = sc.all.find((x) => x.id === id); return d ? d.name : id; }) };
}
/* Trace inside a scope. Result carries res.scope (chip, counts) and, when a hidden firewall is needed, res.scope.viaHidden. */
function traceScoped(devices, profile, query, opts) {
  const sc = scopeDevices(devices, profile);
  const res = trace(sc.devices, query, opts || {});
  attachScope(res, sc, query, opts || {}, true);
  return res;
}
function attachScope(res, sc, query, opts, check) {
  res.scope = scopeSummary(sc);
  if (!check || !sc.hidden.length) return res;
  const ps = res && res.pathStatus, done = res && res.status !== "error" && ps && ps.status === "complete" && res.final && res.final.kind === "delivered";
  if (done && !res.conflict) return res;
  let full; try { full = trace(sc.all, query, opts || {}); } catch (e) { return res; }
  const v = hiddenPathCheck(sc, query, opts, res, full);
  if (v) { res.scope.viaHidden = v; (res.notes = res.notes || []).unshift({ level: "warn", text: v.text }); }
  const cc = scopeConflictCheck(res, sc, full);
  if (cc) {
    res.scope.scopeConflict = cc;
    res.conflict.scopeCause = cc.cause;
    res.conflict.scopeText = cc.text;
    res.conflict.scopeDevices = cc.names;
    if (cc.cause !== "preexisting") (res.notes = res.notes || []).unshift({ level: "warn", text: cc.text });
  }
  return res;
}
/* ---- DR mirror: "a DR copy is likely needed". Advisory only; DR firewalls are never traced. ---- */
function normName(text, d, profile) {
  const drop = new Set(rawWords(siteKey(d) || ""));
  for (const [, w] of roleWords(profile, false).concat(roleWords(profile, true))) drop.add(w);
  return rawWords(text).filter((w) => !drop.has(w) && !roleWords(profile, false).concat(roleWords(profile, true)).some(([, t]) => wordMatches(w, t))).join("-");
}
function zoneSet(d) { const s = new Map(); for (const it of d.interfaces.values()) if (it.zone) { if (!s.has(it.zone)) s.set(it.zone, []); for (const ip of it.ips || []) s.get(it.zone).push(ip); } return s; }
function drMirror(res, devices, profile) {
  profile = normalizeProfile(profile);
  const out = { enabled: profile.mirror.enabled, items: [], devices: [], viaDg: [], text: "" };
  if (!out.enabled || !res || !(res.changes || []).length) return out;
  const model = roleModel(devices, profile), defs = model.defs;
  const touched = new Set((res.changes || []).filter((c) => !c.optional).map((c) => c.device));
  const mirrors = devices.filter((d) => (defs.byId.get(model.byDev.get(d).role) || {}).mirror && !touched.has(d.name));
  if (!mirrors.length) { out.text = ""; return out; }
  const prodOf = (d) => { const r = model.byDev.get(d); const df = defs.byId.get(r.role) || {}; return !df.mirror && df.focus; };
  const byDevChanges = new Map();
  for (const c of res.changes || []) { if (c.optional) continue; const d = devices.find((x) => x.name === c.device || x.id === c.device); if (!d || !prodOf(d)) continue; if (!byDevChanges.has(d)) byDevChanges.set(d, []); byDevChanges.get(d).push(c); }
  for (const [d, cs] of byDevChanges) {
    const zd = zoneSet(d), zonesNeeded = new Set();
    for (const c of cs) if (c.rule) { if (c.rule.from) zonesNeeded.add(c.rule.from); if (c.rule.to) zonesNeeded.add(c.rule.to); }
    const dgs = new Set(cs.map((c) => c.dg).filter(Boolean).concat(devDgNames(d)));
    const cands = [];
    for (const m of mirrors) {
      if (m === d) continue;
      const reasons = []; let score = 0, sameDg = false;
      const sd = d.stack && m.stack && normName(d.stack, d, profile) === normName(m.stack, m, profile);
      if (d.stack && m.stack && d.stack === m.stack) { score += 3; reasons.push("same template stack " + d.stack); } else if (sd) { score += 3; reasons.push("template stack " + m.stack + " follows the same pattern as " + d.stack); }
      const mdgs = devDgNames(m), shared = mdgs.filter((g) => dgs.has(g));
      if (shared.length) { score += 2; sameDg = true; reasons.push("same device group " + shared[0]); }
      else if (mdgs.some((g) => [...dgs].some((x) => normName(x, d, profile) && normName(x, d, profile) === normName(g, m, profile)))) { score += 2; reasons.push("device group follows the same pattern"); }
      const hd = normName(d.hostname || d.name, d, profile), hm = normName(m.hostname || m.name, m, profile);
      if (hd && hd === hm) { score += 2; reasons.push("hostnames match once site and role words are removed (" + hd + ")"); }
      const zm = zoneSet(m);
      if (zonesNeeded.size) { const have = [...zonesNeeded].filter((z) => zm.has(z)); if (have.length === zonesNeeded.size) { score += 2; reasons.push("has the same zones (" + [...zonesNeeded].join(", ") + ")"); } else if (have.length) score -= 1; else score -= 3; }
      let addrNote = null;
      for (const z of zonesNeeded) { const a = zd.get(z), b = zm.get(z); if (a && b && a.length && b.length) { const pa = a[0].len, pb = b[0].len; if (pa === pb) { score += 1; reasons.push("zone " + z + " has the same layout (/" + pa + ")"); } if (n2ip(a[0].ip) !== n2ip(b[0].ip) && Math.floor(a[0].ip / Math.pow(2, 32 - pa)) !== Math.floor(b[0].ip / Math.pow(2, 32 - pb))) addrNote = "Zone " + z + " uses different subnets on the DR side, so translate the addresses in the rule before copying it."; break; } }
      const named = reasons.some((x) => /stack|device group|hostnames/.test(x));
      if (named && (sameDg || score >= 3)) cands.push({ device: m.name, display: m.hostname || m.name, hostname: m.hostname || null, role: model.byDev.get(m).role, stack: m.stack || null, score, level: sameDg ? "automatic" : score >= 5 ? "likely" : "possible", sameDg, reasons, addrNote });
    }
    cands.sort((a, b) => b.score - a.score);
    if (!cands.length) { out.items.push({ device: d.name, display: d.hostname || d.name, hostname: d.hostname || null, changes: cs.map((c) => c.summary).slice(0, 6), candidates: [], note: "No DR counterpart found by stack, device group, hostname or zones. If this site has a DR copy, add the rule there by hand." }); continue; }
    out.items.push({ device: d.name, display: d.hostname || d.name, hostname: d.hostname || null, changes: cs.map((c) => c.summary).slice(0, 6), candidates: cands });
  }
  for (const it of out.items) for (const c of it.candidates) { if (!out.devices.includes(c.display)) out.devices.push(c.display); if (c.sameDg && !out.viaDg.includes(c.display)) out.viaDg.push(c.display); }
  const need = out.devices.filter((x) => !out.viaDg.includes(x));
  out.text = !out.items.length ? "" : (need.length ? "DR copy likely needed on " + need.join(", ") + ". " : "") + (out.viaDg.length ? out.viaDg.join(", ") + " share" + (out.viaDg.length === 1 ? "s" : "") + " a device group with the production firewall, so a rule pushed to that group reaches " + (out.viaDg.length === 1 ? "it" : "them") + " too (check the rule's target and zones). " : "") + (out.items.some((i) => !i.candidates.length) ? "Some production firewalls have no DR counterpart we can find. " : "") + "Advisory only: DR firewalls are not traced.";
  return out;
}
/* ---- Panorama's own HA pair: shown on the ecosystem view with its own roles; never used to place or pair a firewall. ---- */
function readPanoramaHa(devEntry) {
  const ha = at(devEntry, "deviceconfig/high-availability");
  if (!ha) return null;
  const ip = (n) => { const v = txt(n); const p = v && parsePrefix(v.split("/")[0]); return p && p.lo === p.hi ? n2ip(p.lo) : null; };
  const en = txt(ch(ha, "enabled"));
  let grp = ch(ha, "group"); if (grp && entries(grp).length && !ch(grp, "peer-ip")) grp = entries(grp)[0];
  return { enabled: en === "yes" ? true : en === "no" ? false : null, peerIp: grp ? ip(ch(grp, "peer-ip")) : null, peerIpBackup: grp ? ip(ch(grp, "peer-ip-backup")) : null,
    ownIp: ip(at(ha, "interface/ha1/ip-address")), priority: grp ? txt(at(grp, "election-option/priority")) || null : null, preemptive: grp ? txt(at(grp, "election-option/preemptive")) || null : null,
    mode: grp && at(grp, "mode/active-active") ? "active-active" : "active-passive" };
}
/* The Panorama pair as the user sees it. Roles are stored by HA1 address so the export from either peer shows the same two entries. */
function panoramaPair(pano, profile) {
  profile = normalizeProfile(profile);
  const ha = pano && pano.ha, host = (pano && pano.hostname) || "Panorama";
  const defs = roleDefs(profile), label = (id) => (defs.byId.get(id) || { label: id }).label;
  const guess = (t) => { const hs = roleHits(t, profile, false); if (!hs.length) return null; const by = {}; for (const h of hs) by[h.role] = (by[h.role] || 0) + 1; const top = Object.keys(by).sort((a, b) => by[b] - by[a]); return top.length > 1 && by[top[0]] === by[top[1]] ? null : { role: top[0], word: hs.find((h) => h.role === top[0]).word }; };
  const mk = (key, name, isThis) => { const sv = profile.panoramas[key] || {}, g = isThis ? guess(name) : null;
    return { key, name, isThisExport: !!isThis, role: sv.role || (g && g.role) || null, roleSource: sv.role ? "your setting" : g ? "guess" : null, roleWhy: sv.role ? "You set this Panorama to " + label(sv.role) + "." : g ? 'Guessed ' + label(g.role) + ': its hostname contains "' + g.word + '".' : "No clue; set it yourself.", state: sv.state || null }; };
  const ownKey = ha && ha.ownIp ? "ip:" + ha.ownIp : "host:" + host;
  const out = { hostname: host, ha: ha || null, haEnabled: !!(ha && ha.enabled), this: mk(ownKey, host, true), peer: null,
    note: "Panorama HA is separate from firewall scope. Its peer is not a firewall: it is never used to place or pair firewalls. The configured priority (primary / secondary) says who prefers to be active; which one is active right now is not in the export, so set it here if you know." };
  if (ha && (ha.peerIp || ha.peerIpBackup)) out.peer = mk("ip:" + (ha.peerIp || ha.peerIpBackup), "HA peer (" + (ha.peerIp || ha.peerIpBackup) + ")", false);
  return out;
}
/* SCOPE:END */
const FM = { ROLE_DEFS, ROLE_TOKENS, ROLE_WEAK_TOKENS, defaultProfile, normalizeProfile, parseScopeArg, roleModel, roleOf, roleHits, RULE_FIELDS, ruleFieldText, ruleApplies, firstRoleRule, rulePreview, ruleDescribe, scopeDevices, traceScoped, attachScope, hiddenPathCheck, scopeConflictCheck, drMirror, readPanoramaHa, panoramaPair, multiPlace, ruleOrderAdvice, bulkAcceptSuggestions, suggestionConflicts, conflictEntry, haGroups, pathStatus, devLabel, devParts, publicSpaceSuggestions, providerStatics, circuitLookup, noRuleInExport, inferDynamicRoutes, zoneOfAddr, zoneFindings, environment, envLayout, panoramaView, panoLayout, drawioXml, siteToken, vsysMap, vsysMapLayout, prepare: (devices, links) => getGraph(devices, links), parseRouteTable, applyRouteTables, invalidateCaches, overlapReport, sharedIpChoices, bgpSummary, bgpFilterAllows, prefixListPermits, siteOfDev, parseXml, parseXmlAsync, loadConfig, loadConfigAsync, buildPanoramaDevice, buildDevice, trace, parsePrefix, prefixStr, n2ip, ip2n, coverage, resolveAddrs, maskSecrets, deviceSummary, addressNames, listPanoramaContexts, dgChain, lookupRoute, mergeNodes, evalTagFilter, buildGraph, getGraph, findPaths, ownersOf, topology, diagnostics, replayCases, inboundDnatCases, dnatEntries, replayCase, replaySummary, ruleCase, internetZones, mergeLocalBackups, serialFromFilename, inferDgVsysJoin, parseFcr, parseFcrTable, csvRecords, csvText, fcrHeaderKey, fcrClassifyApp, fcrRuleName, applyFcrExtras, readFcrXlsx, explainVsysHops, annotateFcr, trafficLogFilters, prePushChecklist, combinedChangePlan, NO_NET_MSG, version: "1.9.3" };
/* Rule-matching helpers for the decommission engine (build/decom.js). */
Object.assign(FM, { addrMatch, svcMatch, zoneOk, normAction, resolveServices });
if (typeof module !== "undefined" && module.exports) module.exports = FM;
root.FM = FM;
})(typeof window !== "undefined" ? window : globalThis);
