/* PAN-OS FlowMapper decommission engine: find every reference to a retired host, subnet, FQDN, object or rule,
 * grade each one Exact / Highly likely / Possible, and build a safe removal plan (and, for "stop traffic", the
 * deny rules that close every place on the path that would still allow the flow).
 * Pure JS, no DOM, no network. Needs core.js (FM) loaded first. Used by the offline page and, vendored, by PAAT.
 *
 * Tier rules (also in the FlowMapper README and the PAAT manual):
 *   exact     the object or value IS the target: same host/prefix/range, same FQDN, same object/group/rule name,
 *             a literal in a rule equal to the target, or a group left with no members once exact members go.
 *             Pre-selected.
 *   likely    built for the target but not identical: a /30, /31 or range of at most 4 addresses holding it, a /28
 *             or smaller whose name or description names it, an object entirely inside a retired subnet, a group
 *             named for it whose members all point at it, a NAT rule translating to it, or an object only used by
 *             a rule that is being deleted. One click to select.
 *   possible  the target merely falls inside something broader (a /24, a /16, any), overlaps it, or only the name
 *             hints at it. Never selectable, never deleted: advice (leave it, carve it out, or deny above) with the
 *             blast radius (other addresses, rules and groups that use it).
 */
(function (root) {
"use strict";
const FM = (typeof module !== "undefined" && module.exports) ? require("./core.js") : root.FM;
const VERSION = "1.0.0";
const RANK = { exact: 0, likely: 1, possible: 2 };
const TIER_LABEL = { exact: "Exact (100%)", likely: "Highly likely", possible: "Possible" };
const RULE_TYPES = ["security", "nat", "pbf", "decryption", "qos", "authentication", "application-override", "dos", "tunnel-inspect", "sdwan", "network-packet-broker"];
const ADDR_FIELDS = ["source", "destination"];
const SMALL_RANGE = 4;   // a /30, /31 or a range of up to 4 addresses that holds the target
const NAMED_RANGE = 16;  // a /28 or smaller counts as likely when its name or description names the target
const SMALL_GROUP = 4;
const MAX_LIST = 200;

/* ------------------------------------------------------------------ small XML helpers (same node shape as core.js) */
function ch(n, tag) { if (!n) return null; for (const c of n.c) if (c.t === tag) return c; return null; }
function chs(n, tag) { return n ? n.c.filter((c) => c.t === tag) : []; }
function at(n, path) { let cur = n; for (const p of path.split("/")) { if (!p) continue; cur = ch(cur, p); if (!cur) return null; } return cur; }
function entries(n) { return chs(n, "entry"); }
function txt(n) { return n ? String(n.x || "").trim() : ""; }
function members(n) { if (!n) return []; const ms = chs(n, "member").map(txt).filter(Boolean); if (ms.length) return ms; const t = txt(n); return t ? [t] : []; }
function xmlEsc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
function serialize(n) {
  if (!n) return "";
  const a = Object.keys(n.a || {}).map((k) => " " + k + '="' + xmlEsc(n.a[k]) + '"').join("");
  const inner = xmlEsc(String(n.x || "").trim()) + (n.c || []).map(serialize).join("");
  return "<" + n.t + a + (inner ? ">" + inner + "</" + n.t + ">" : "/>");
}
function q(s) { s = String(s); return s === "" || /[\s"<>|;]/.test(s) ? '"' + s.replace(/"/g, '\\"') + '"' : s; }
function lst(a) { a = a && a.length ? a : ["any"]; return a.length === 1 ? q(a[0]) : "[ " + a.map(q).join(" ") + " ]"; }
function hostOrPrefix(p) { return p.lo === p.hi ? FM.n2ip(p.lo) : FM.prefixStr(p); }
function sizeOf(p) { return p.hi - p.lo + 1; }
function worst(tiers) { let t = "exact"; for (const x of tiers) if (RANK[x] > RANK[t]) t = x; return t; }
function plural(n, w) { return n + " " + w + (n === 1 ? "" : (/s$/.test(w) ? "es" : "s")); }
function safeName(s) { return String(s).replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^_+|_+$/g, ""); }

/* ------------------------------------------------------------------ targets */
const FQDN_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,62}\.?$/i;
function parseTarget(raw) {
  const s = String(raw == null ? "" : raw).trim();
  if (!s || s.startsWith("#")) return null;
  if (/:/.test(s) && /^[0-9a-f:\/.]+$/i.test(s)) return { raw: s, kind: "ip6", value: s.toLowerCase() };
  const p = FM.parsePrefix(s);
  if (p) return { raw: s, kind: "ip", p, host: p.lo === p.hi, size: sizeOf(p), text: hostOrPrefix(p) };
  if (/^\d[\d./-]*$/.test(s)) return { raw: s, kind: "invalid", error: "not a valid IPv4 address, subnet or range" };
  if (FQDN_RE.test(s) && /[a-z]/i.test(s.split(".").pop())) return { raw: s, kind: "fqdn", value: s.toLowerCase().replace(/\.$/, "") };
  return { raw: s, kind: "name", value: s };
}
function parseTargets(list) {
  const out = [], seen = new Set();
  const items = Array.isArray(list) ? list : String(list || "").split(/[\n,;]+/);
  for (const x of items) { const t = parseTarget(x); if (t && !seen.has(t.raw)) { seen.add(t.raw); out.push(t); } }
  return out;
}
function tokensOf(t) {
  if (t.kind === "ip") {
    const ip = FM.n2ip(t.p.lo);
    if (!t.host) return t.p.len != null ? [ip + "/" + t.p.len, ip + "_" + t.p.len, ip + "-" + t.p.len] : [t.raw];
    return [ip, ip.replace(/\./g, "_"), ip.replace(/\./g, "-")];
  }
  if (t.kind === "fqdn") { const label = t.value.split(".")[0]; return label.length >= 3 && label !== t.value ? [t.value, label] : [t.value]; }
  if (t.kind === "name") return t.value.length >= 3 ? [t.value] : [];
  return [];
}
function mentions(text, t) {
  const s = String(text || "").toLowerCase();
  if (!s) return null;
  for (const tok of tokensOf(t)) {
    const k = tok.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = t.kind === "ip" ? new RegExp("(^|[^0-9])" + k + "($|[^0-9])") : new RegExp("(^|[^a-z0-9])" + k + "($|[^a-z0-9])");
    if (re.test(s)) return tok;
  }
  for (const al of t.aliases || []) {
    const k = al.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp("(^|[^a-z0-9])" + k + "($|[^a-z0-9])").test(s)) return al;
  }
  return null;
}

/* ------------------------------------------------------------------ inventory: every scope, object, group and rule */
function scopeLabel(s) { return s.kind === "shared" ? (s.backend === "panorama" ? "shared" : (s.host || s.file) + " shared") : s.kind === "device-group" ? "device group " + s.name : (s.host || s.file) + "/" + s.name; }
function locOf(s) {
  const l = { file: s.file, backend: s.backend, kind: s.kind, name: s.name, location: s.kind === "shared" ? "shared" : s.kind };
  if (s.dg) l.device_group = s.dg;
  if (s.vsys) { l.vsys = s.vsys; l.multi_vsys = !!s.multiVsys; l.device = s.host || ""; }
  return l;
}
function readScope(s) {
  const n = s.node;
  s.addrs = new Map(); s.groups = new Map(); s.edls = new Set(); s.services = new Map(); s.rules = [];
  if (!n) return;
  for (const e of entries(ch(n, "address"))) {
    let type = null, value = "";
    for (const t of ["ip-netmask", "ip-range", "ip-wildcard", "fqdn"]) { const c = ch(e, t); if (c) { type = t; value = txt(c); break; } }
    const p = type === "ip-netmask" || type === "ip-range" ? FM.parsePrefix(value) : null;
    s.addrs.set(e.a.name, { name: e.a.name, type: type || "unknown", value, p, desc: txt(ch(e, "description")), tags: members(ch(e, "tag")), scope: s, node: e });
  }
  for (const e of entries(ch(n, "address-group"))) {
    const st = ch(e, "static"), dy = ch(e, "dynamic");
    s.groups.set(e.a.name, { name: e.a.name, static: st ? members(st) : null, dynamic: dy ? txt(ch(dy, "filter")) : null, desc: txt(ch(e, "description")), tags: members(ch(e, "tag")), scope: s, node: e });
  }
  for (const e of entries(ch(n, "external-list"))) s.edls.add(e.a.name);
  for (const e of entries(ch(n, "service"))) {
    const pr = ch(e, "protocol"); if (!pr) continue;
    for (const k of ["tcp", "udp"]) { const c = ch(pr, k); if (c) s.services.set(e.a.name, { name: e.a.name, proto: k, port: txt(ch(c, "port")), src: txt(ch(c, "source-port")) }); }
  }
  for (const rb of s.rulebases) for (const type of RULE_TYPES) {
    const list = entries(at(n, rb + "/" + type + "/rules"));
    list.forEach((e, idx) => {
      const fromN = ch(e, "from"), actN = ch(e, "action");
      const r = { scope: s, type, rulebase: rb, name: e.a.name, idx, node: e, next: list[idx + 1] ? list[idx + 1].a.name : null, prev: idx ? list[idx - 1].a.name : null,
        fields: { source: members(ch(e, "source")), destination: members(ch(e, "destination")) },
        neg: { source: txt(ch(e, "negate-source")) === "yes", destination: txt(ch(e, "negate-destination")) === "yes" },
        from: type === "pbf" ? members(at(fromN, "zone")) : members(fromN), to: members(ch(e, "to")),
        service: members(ch(e, "service")), application: members(ch(e, "application")), action: txt(actN) || (actN && actN.c[0] ? actN.c[0].t : ""),
        disabled: txt(ch(e, "disabled")) === "yes", desc: txt(ch(e, "description")), tags: members(ch(e, "tag")), translated: [] };
      r.id = s.id + "|" + type + "|" + rb + "|" + r.name;
      if (type === "nat") {
        const st = ch(e, "source-translation");
        if (st) for (const k of ["dynamic-ip-and-port", "dynamic-ip", "static-ip"]) { const c = ch(st, k); if (!c) continue; for (const v of members(ch(c, "translated-address"))) r.translated.push({ path: "source-translation " + k, value: v }); const ia = at(c, "interface-address/ip"); if (ia && txt(ia)) r.translated.push({ path: "source-translation interface-address ip", value: txt(ia) }); }
        for (const k of ["destination-translation", "dynamic-destination-translation"]) { const c = ch(e, k); if (c) for (const v of members(ch(c, "translated-address"))) r.translated.push({ path: k, value: v }); }
      }
      s.rules.push(r);
    });
  }
}
function inventory(cfgs) {
  const inv = { scopes: [], byId: new Map(), cfgs: [] };
  const add = (o) => { o.id = o.file + "#" + o.kind + ":" + o.name; inv.scopes.push(o); inv.byId.set(o.id, o); return o; };
  (cfgs || []).forEach((c, ci) => {
    const file = c.fileName || "config-" + (ci + 1);
    const devs = entries(ch(c.cfg, "devices"));
    const devEntry = devs.find((e) => e.a.name === "localhost.localdomain") || devs[0];
    const pano = c.kind === "panorama";
    const backend = pano ? "panorama" : "firewall";
    const shared = add({ file, backend, kind: "shared", name: "shared", node: ch(c.cfg, "shared"), parentId: null, rulebases: pano ? ["pre-rulebase", "post-rulebase"] : [], host: c.hostname });
    if (pano) {
      const dgs = (c.panorama && c.panorama.dgs) || new Map();
      const made = new Map();
      for (const [name, dg] of dgs) made.set(name, add({ file, backend, kind: "device-group", name, dg: name, node: dg.node, rulebases: ["pre-rulebase", "post-rulebase"], host: c.hostname, devices: dg.devices || [] }));
      for (const [name, dg] of dgs) made.get(name).parentId = dg.parent && made.get(dg.parent) ? made.get(dg.parent).id : shared.id;
    } else {
      const vs = entries(ch(devEntry, "vsys"));
      for (const v of vs) add({ file, backend, kind: "vsys", name: v.a.name, vsys: v.a.name, node: v, parentId: shared.id, rulebases: ["rulebase"], host: c.hostname, multiVsys: vs.length > 1 });
    }
    inv.cfgs.push({ file, kind: c.kind, hostname: c.hostname });
  });
  for (const s of inv.scopes) {
    let d = 0, cur = s; const seen = new Set();
    while (cur && cur.parentId && !seen.has(cur.id)) { seen.add(cur.id); d++; cur = inv.byId.get(cur.parentId); }
    s.depth = d;
    readScope(s);
  }
  return inv;
}
function chain(inv, s) { const out = [], seen = new Set(); let cur = s; while (cur && !seen.has(cur.id)) { seen.add(cur.id); out.push(cur); cur = cur.parentId ? inv.byId.get(cur.parentId) : null; } return out; }
function resolver(inv) {
  const memo = new Map();
  return function resolve(s, m) {
    const k = s.id + "\u0000" + m;
    if (memo.has(k)) return memo.get(k);
    let r = null;
    if (m === "any") r = { type: "any" };
    else {
      for (const sc of chain(inv, s)) {
        if (sc.addrs.has(m)) { r = { type: "address", obj: sc.addrs.get(m), key: sc.id + "|a|" + m }; break; }
        if (sc.groups.has(m)) { r = { type: "group", obj: sc.groups.get(m), key: sc.id + "|g|" + m }; break; }
        if (sc.edls.has(m)) { r = { type: "edl", name: m }; break; }
      }
      if (!r) { const p = FM.parsePrefix(m); r = p ? { type: "literal", p, value: m } : { type: "unknown", name: m }; }
    }
    memo.set(k, r);
    return r;
  };
}
/* Every place an address object or group is used, resolved the way PAN-OS resolves names (own scope, then parents, then shared). */
function referenceIndex(inv, resolve) {
  const refs = new Map();
  const push = (key, rec) => { if (!refs.has(key)) refs.set(key, []); refs.get(key).push(rec); };
  for (const s of inv.scopes) {
    for (const g of s.groups.values()) for (const m of g.static || []) { const r = resolve(s, m); if (r.key) push(r.key, { kind: "group", group: g, member: m }); }
    for (const rule of s.rules) {
      for (const f of ADDR_FIELDS) for (const m of rule.fields[f]) { const r = resolve(s, m); if (r.key) push(r.key, { kind: "rule", rule, field: f, member: m }); }
      for (const t of rule.translated) { const r = resolve(s, t.value); if (r.key) push(r.key, { kind: "nat-translated", rule, field: t.path, member: t.value }); }
    }
  }
  return refs;
}
function flatten(inv, resolve, g, seen) {
  seen = seen || new Set();
  const out = { leaves: [], dynamic: [], unknown: [] };
  if (seen.has(g.scope.id + "|" + g.name)) return out;
  seen.add(g.scope.id + "|" + g.name);
  if (g.dynamic != null) out.dynamic.push(g);
  for (const m of g.static || []) {
    const r = resolve(g.scope, m);
    if (r.type === "address") out.leaves.push(r.obj);
    else if (r.type === "group") { const f = flatten(inv, resolve, r.obj, seen); out.leaves.push(...f.leaves); out.dynamic.push(...f.dynamic); out.unknown.push(...f.unknown); }
    else out.unknown.push(m);
  }
  return out;
}

/* ------------------------------------------------------------------ relation of one address value to one target */
function relation(obj, t) {
  const nameHit = mentions(obj.name, t), descHit = mentions(obj.desc, t), hint = nameHit || descHit;
  const hintWhere = nameHit ? "name" : "description";
  if (t.kind === "name") return obj.name === t.value ? { rel: "named", tier: "exact", why: "the object is named " + t.value } : null;
  if (t.kind === "ip6") return String(obj.value || "").toLowerCase() === t.value ? { rel: "equal", tier: "exact", why: "same IPv6 value" } : null;
  if (t.kind === "fqdn") {
    if (obj.type === "fqdn" && String(obj.value || "").toLowerCase().replace(/\.$/, "") === t.value) return { rel: "equal", tier: "exact", why: "same FQDN " + t.value };
    if (obj.name && obj.name.toLowerCase() === t.value) return { rel: "named", tier: "exact", why: "the object is named " + t.value };
    if (hint) return { rel: "hint", tier: "possible", why: "the " + hintWhere + " mentions " + hint + ", but the value (" + (obj.value || obj.type) + ") cannot be compared offline" };
    return null;
  }
  if (t.kind !== "ip") return null;
  if (!obj.p) {
    if (obj.type === "fqdn" && hint) return { rel: "hint", tier: "possible", why: "FQDN object whose " + hintWhere + " mentions " + hint + "; DNS decides what it resolves to" };
    return null;
  }
  const a = obj.p, b = t.p;
  if (a.lo === b.lo && a.hi === b.hi) return { rel: "equal", tier: "exact", why: (t.host ? "host " : "same range ") + t.text + (obj.type === "literal" ? " typed directly in the rule" : "") };
  if (a.lo >= b.lo && a.hi <= b.hi) return { rel: "inside", tier: "likely", why: hostOrPrefix(a) + " is entirely inside the retired range " + t.text };
  if (a.lo <= b.lo && a.hi >= b.hi) {
    const others = sizeOf(a) - sizeOf(b);
    if (sizeOf(a) <= SMALL_RANGE) return { rel: "covers", tier: "likely", others, why: hostOrPrefix(a) + " is a small range (" + plural(sizeOf(a), "address") + ") holding " + t.text + "; only " + plural(others, "other address") + " in it" };
    if (hint && sizeOf(a) <= NAMED_RANGE) return { rel: "covers", tier: "likely", others, why: hostOrPrefix(a) + " holds " + t.text + " and its " + hintWhere + " mentions " + hint + " (" + plural(others, "other address") + " in it)" };
    return { rel: "covers", tier: "possible", others, why: t.text + " is inside the broader " + hostOrPrefix(a) + " (" + others.toLocaleString("en-US") + " other addresses). Broader objects are never deleted for one host" };
  }
  if (a.lo <= b.hi && b.lo <= a.hi) return { rel: "overlap", tier: "possible", others: sizeOf(a), why: hostOrPrefix(a) + " partly overlaps " + t.text };
  return null;
}

/* ------------------------------------------------------------------ analysis */
function analyze(cfgs, request, opts) {
  opts = opts || {};
  request = request || {};
  const mode = request.mode === "block" ? "block" : "remove";
  const targets = parseTargets(request.targets || []);
  const inv = inventory(cfgs);
  const resolve = resolver(inv);
  const refs = referenceIndex(inv, resolve);
  const cands = new Map();
  const notes = [];
  for (const t of targets.filter((x) => x.kind === "invalid")) notes.push({ level: "error", code: "invalid-target", text: t.raw + ": " + t.error });
  const goodTargets = targets.filter((t) => t.kind !== "invalid");
  const matched = new Map(goodTargets.map((t) => [t.raw, 0]));
  const addCand = (c) => {
    matched.set(c.target, (matched.get(c.target) || 0) + 1);
    const ex = cands.get(c.id);
    if (!ex) { c.targets = [c.target]; delete c.target; c.evidence = c.evidence || []; cands.set(c.id, c); return c; }
    if (!ex.targets.includes(c.target)) ex.targets.push(c.target);
    if (RANK[c.tier] < RANK[ex.tier]) { ex.tier = c.tier; ex.reason = c.reason; ex.rel = c.rel; ex.blast = c.blast || ex.blast; }
    for (const e of c.evidence || []) if (!ex.evidence.includes(e)) ex.evidence.push(e);
    return ex;
  };
  const usage = (key) => {
    const list = refs.get(key) || [];
    return { rules: new Set(list.filter((x) => x.kind !== "group").map((x) => x.rule)).size, groups: new Set(list.filter((x) => x.kind === "group").map((x) => x.group)).size,
      examples: [...new Set(list.map((x) => x.kind === "group" ? "group " + x.group.name : x.rule.type + " rule " + x.rule.name))].slice(0, 6) };
  };

  // names of objects that ARE an IP target (say app01 for 10.50.1.25) also count when a name or description mentions it
  for (const t of goodTargets) if (t.kind === "ip") {
    const al = new Set();
    for (const s of inv.scopes) for (const a of s.addrs.values()) { const r = relation(a, t); if (r && r.tier === "exact" && a.name.length >= 3 && !a.name.includes(t.text)) al.add(a.name); }
    t.aliases = [...al].slice(0, 20);
  }
  for (const t of goodTargets) {
    for (const s of inv.scopes) {
      for (const a of s.addrs.values()) {
        const r = relation(a, t);
        if (!r) continue;
        const key = s.id + "|a|" + a.name, u = usage(key);
        addCand({ id: "addr|" + key, kind: "address", tier: r.tier, rel: r.rel, target: t.raw, name: a.name, value: a.value, type: a.type, scope: s.id, scopeLabel: scopeLabel(s), location: locOf(s),
          reason: r.why, evidence: [a.type + " " + (a.value || "(empty)") + " in " + scopeLabel(s)].concat(a.desc ? ["description: " + a.desc] : []),
          blast: { otherAddresses: r.others || 0, rules: u.rules, groups: u.groups, examples: u.examples } });
      }
      if (t.kind === "name" || t.kind === "fqdn") {
        const nm = t.kind === "name" ? t.value : t.raw;
        const g = s.groups.get(nm);
        if (g) { const u = usage(s.id + "|g|" + g.name); addCand({ id: "grp|" + s.id + "|g|" + g.name, kind: "group", tier: "exact", target: t.raw, name: g.name, scope: s.id, scopeLabel: scopeLabel(s), location: locOf(s), reason: "address group named " + g.name + (g.dynamic != null ? " (dynamic: filter " + g.dynamic + ")" : ""), dynamic: g.dynamic != null, blast: { members: (g.static || []).length, rules: u.rules, groups: u.groups, examples: u.examples } }); }
        for (const rule of s.rules) if (rule.name === nm) addCand({ id: "rule|" + rule.id, kind: "rule", tier: "exact", target: t.raw, name: rule.name, ruleType: rule.type, rulebase: rule.rulebase, scope: s.id, scopeLabel: scopeLabel(s), location: locOf(s), reason: rule.type + " rule named " + rule.name + " (" + rule.rulebase + ")" });
      }
      if (t.kind === "ip") for (const rule of s.rules) for (const f of ADDR_FIELDS) for (const m of rule.fields[f]) {
        const res = resolve(s, m);
        if (res.type !== "literal") continue;
        const r = relation({ name: m, type: "literal", value: m, p: res.p }, t);
        if (!r) continue;
        addCand({ id: "lit|" + rule.id + "|" + f + "|" + m, kind: "literal", tier: r.tier, rel: r.rel, target: t.raw, name: m, value: m, field: f, rule: rule.name, ruleId: rule.id, ruleType: rule.type, rulebase: rule.rulebase, scope: s.id, scopeLabel: scopeLabel(s), location: locOf(s),
          reason: r.why + " (" + f + " of " + rule.type + " rule " + rule.name + ")", negated: rule.neg[f], blast: { otherAddresses: r.others || 0, rules: 1, groups: 0, examples: [rule.type + " rule " + rule.name] } });
      }
    }
  }
  // groups built for the target: the name or description points at it and every member (or a small group's member) is the target
  for (const s of inv.scopes) for (const g of s.groups.values()) {
    if (g.static == null || !g.static.length || cands.has("grp|" + s.id + "|g|" + g.name)) continue;
    for (const t of goodTargets) {
      const hint = mentions(g.name, t) || mentions(g.desc, t);
      if (!hint) continue;
      const f = flatten(inv, resolve, g);
      if (!f.leaves.length) continue;
      const tiers = f.leaves.map((a) => { const c = cands.get("addr|" + a.scope.id + "|a|" + a.name); return c ? c.tier : null; });
      const allPoint = tiers.every((x) => x === "exact" || x === "likely");
      const smallWithExact = g.static.length <= SMALL_GROUP && tiers.some((x) => x === "exact");
      if (!allPoint && !smallWithExact) continue;
      const u = usage(s.id + "|g|" + g.name);
      addCand({ id: "grp|" + s.id + "|g|" + g.name, kind: "group", tier: "likely", target: t.raw, name: g.name, scope: s.id, scopeLabel: scopeLabel(s), location: locOf(s),
        reason: "group " + (mentions(g.name, t) ? "name" : "description") + " mentions " + hint + " and " + (allPoint ? "every member points at the target" : "it is small (" + plural(g.static.length, "member") + ") with the target in it"),
        evidence: ["members: " + g.static.join(", ")], blast: { members: g.static.length, rules: u.rules, groups: u.groups, examples: u.examples } });
    }
  }
  // NAT rules that translate to an exact target
  for (const s of inv.scopes) for (const rule of s.rules) for (const tr of rule.translated) {
    const r = resolve(s, tr.value);
    let hitTarget = null;
    if (r.key && cands.get("addr|" + r.key) && cands.get("addr|" + r.key).tier === "exact") hitTarget = cands.get("addr|" + r.key).targets[0];
    if (r.type === "literal") for (const t of goodTargets) if (t.kind === "ip") { const rl = relation({ name: tr.value, type: "literal", p: r.p }, t); if (rl && rl.tier === "exact") hitTarget = t.raw; }
    if (!hitTarget || cands.has("rule|" + rule.id)) continue;
    addCand({ id: "rule|" + rule.id, kind: "rule", tier: "likely", target: hitTarget, name: rule.name, ruleType: rule.type, rulebase: rule.rulebase, scope: s.id, scopeLabel: scopeLabel(s), location: locOf(s), nat: true,
      reason: "NAT rule " + rule.name + " translates to the decommissioned address (" + tr.path + " " + tr.value + "). A NAT rule should not keep pointing at a retired host; delete it once you confirm", evidence: [tr.path + ": " + tr.value] });
  }
  // objects and groups used only by a rule that was named for deletion
  for (const c of [...cands.values()]) if (c.kind === "rule" && c.tier === "exact") {
    const s = inv.byId.get(c.scope);
    const rule = s.rules.find((r) => "rule|" + r.id === c.id);
    if (!rule) continue;
    for (const m of ADDR_FIELDS.flatMap((f) => rule.fields[f]).concat(rule.translated.map((x) => x.value))) {
      const r = resolve(s, m);
      if (!r.key) continue;
      const cid = (r.type === "address" ? "addr|" : "grp|") + r.key;
      if (cands.has(cid)) continue;
      const users = new Set((refs.get(r.key) || []).map((x) => x.kind === "group" ? "g:" + x.group.scope.id + x.group.name : "r:" + x.rule.id));
      if (users.size !== 1 || !users.has("r:" + rule.id)) continue;
      addCand({ id: cid, kind: r.type === "address" ? "address" : "group", tier: "likely", target: c.targets[0], name: r.obj.name, value: r.obj.value || "", type: r.obj.type, scope: r.obj.scope.id, scopeLabel: scopeLabel(r.obj.scope), location: locOf(r.obj.scope), exclusive: true,
        reason: "only used by rule " + rule.name + ", which is being deleted", blast: { rules: 1, groups: 0, examples: [rule.type + " rule " + rule.name] } });
    }
  }
  // dynamic groups and EDLs: evidence and notes only (their contents are decided at runtime)
  for (const s of inv.scopes) for (const g of s.groups.values()) if (g.dynamic != null) {
    const visible = new Set(chain(inv, s).map((x) => x.id));
    for (const c of cands.values()) if (c.kind === "address" && c.tier !== "possible" && visible.has(c.scope)) {
      const a = inv.byId.get(c.scope).addrs.get(c.name);
      if (a && a.tags.length && FM.evalTagFilter(g.dynamic, new Set(a.tags))) c.evidence.push("member of dynamic group " + g.name + " (" + scopeLabel(s) + ") by tag; deleting the object takes it out of that group");
    }
  }
  const dynUsed = [], edlUsed = new Set();
  for (const s of inv.scopes) for (const rule of s.rules) for (const f of ADDR_FIELDS) for (const m of rule.fields[f]) {
    const r = resolve(s, m);
    if (r.type === "edl") edlUsed.add(m);
    if (r.type === "group" && r.obj.dynamic != null && !dynUsed.includes(m)) dynUsed.push(m);
  }
  if (goodTargets.some((t) => t.kind === "ip") && dynUsed.length) notes.push({ level: "info", code: "dynamic-groups", text: plural(dynUsed.length, "dynamic address group") + " used in rules (" + dynUsed.slice(0, 5).join(", ") + (dynUsed.length > 5 ? ", ..." : "") + ") can hold IPs registered at runtime (User-ID, XML API, VM monitoring). The config cannot show those; run 'show object registered-ip ip <address>' on the firewall to check the target." });
  if (edlUsed.size) notes.push({ level: "info", code: "edl", text: plural(edlUsed.size, "external dynamic list") + " used in rules (" + [...edlUsed].slice(0, 5).join(", ") + "). EDL contents are not in the config; check the source list for the target." });

  // selection: Exact pre-selected; Highly likely only when picked; Possible never
  const picked = Array.isArray(opts.select) ? new Set(opts.select) : null;
  for (const c of cands.values()) {
    c.selectable = c.tier !== "possible" && !(c.kind === "group" && c.dynamic);
    c.selected = c.selectable && (picked ? picked.has(c.id) : c.tier === "exact");
    c.tierLabel = TIER_LABEL[c.tier];
    if (c.tier === "possible") c.advice = adviceFor(c, mode);
    if (c.kind === "group" && c.dynamic) c.advice = ["Dynamic groups are never edited or deleted automatically. Review the filter (and the tags on member objects) by hand."];
  }
  const plan = buildPlan(inv, resolve, refs, cands, notes, picked);
  const result = {
    engine: "flowmapper-decom", version: VERSION, mode,
    targets: targets.map((t) => ({ raw: t.raw, kind: t.kind, text: t.text || t.value || t.raw, matches: matched.get(t.raw) || 0, error: t.error || null })),
    configs: inv.cfgs, scopes: inv.scopes.length,
    candidates: [...cands.values()].sort((a, b) => RANK[a.tier] - RANK[b.tier] || a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name) || a.scopeLabel.localeCompare(b.scopeLabel)),
    plan, notes,
  };
  for (const t of result.targets) if (t.kind !== "invalid" && !t.matches) notes.push({ level: "warn", code: "unresolved", item: t.raw, text: t.raw + " was not found as an address value, object, group or rule in the loaded config" + (t.kind === "ip" ? " (no object or rule value equals, contains or sits inside it)" : "") + "." });
  if (mode === "block") result.block = blockAnalysis(inv, resolve, plan, goodTargets, request, opts);
  result.counts = counts(result);
  return result;
}
function adviceFor(c, mode) {
  const b = c.blast || {};
  if (c.rel === "hint") return ["Only the name or description points at the target. Check the value by hand; nothing is changed automatically."];
  const what = c.kind === "literal" ? "value" : "object";
  const out = [];
  if (mode === "remove") out.push("No change needed to retire the target: this " + what + " does not name it, and removing it would also cut " + (b.otherAddresses || 0).toLocaleString("en-US") + " other addresses" + (b.rules ? " used by " + plural(b.rules, "rule") : "") + ".");
  out.push("To stop traffic to the target only, use Stop traffic: it adds a narrow deny above the first rule that would still allow it, in every place on the path, and leaves this " + what + " alone.");
  if (c.rel === "covers" && (b.otherAddresses || 0) > 0) out.push("Carving the target out of " + (c.value || c.name) + " means splitting it into the ranges around the target and replacing it everywhere it is used" + (b.rules || b.groups ? " (" + [b.rules ? plural(b.rules, "rule") : "", b.groups ? plural(b.groups, "group") : ""].filter(Boolean).join(", ") + ")" : "") + "; review that as its own change.");
  return out;
}

/* ------------------------------------------------------------------ plan for the selected candidates */
function buildPlan(inv, resolve, refs, cands, notes, picked) {
  const sel = [...cands.values()].filter((c) => c.selected);
  const removedA = new Map(), removedG = new Map(), deletedRules = new Map(), litRemove = new Map();
  for (const c of sel) {
    if (c.kind === "address") removedA.set(c.id.slice(5), c);
    else if (c.kind === "group") removedG.set(c.id.slice(4), c);
    else if (c.kind === "rule") deletedRules.set(c.id.slice(5), { cand: c, reason: c.nat ? "nat-translates-to-target" : "named-rule", tier: c.tier });
    else if (c.kind === "literal") { if (!litRemove.has(c.ruleId)) litRemove.set(c.ruleId, {}); const m = litRemove.get(c.ruleId); (m[c.field] = m[c.field] || []).push({ value: c.name, cand: c }); }
  }
  const actions = [], dangers = [], kept = [];
  const groupEdits = new Map();
  // cascade: a static group with every member removed is removed too (nested groups, to a fixed point)
  let changed = true, guard = 0;
  while (changed && guard++ < 50) {
    changed = false;
    for (const s of inv.scopes) for (const g of s.groups.values()) {
      const gk = s.id + "|g|" + g.name;
      if (!g.static || (removedG.has(gk) && !removedG.get(gk).cascade)) continue;
      const rm = [], causes = [];
      for (const m of g.static) { const r = resolve(s, m); const c = r.key && (removedA.get(r.key) || removedG.get(r.key)); if (c) { rm.push(m); causes.push(c); } }
      if (!rm.length) continue;
      groupEdits.set(gk, { g, rm, causes });
      if (rm.length === g.static.length && !removedG.has(gk)) {
        removedG.set(gk, { id: "cascade|" + gk, tier: worst(causes.map((x) => x.tier)), cascade: true, name: g.name, causes: [...new Set(causes.map((x) => x.id))] });
        changed = true;
      }
    }
  }
  const remainingRule = new Map();
  const isRemoved = (s, m) => { const r = resolve(s, m); return r.key ? (removedA.get(r.key) || removedG.get(r.key)) : null; };
  for (const s of inv.scopes) for (const rule of s.rules) {
    if (deletedRules.has(rule.id)) continue;
    const remove = {}, remaining = {}, causes = [];
    for (const f of ADDR_FIELDS) {
      const lits = ((litRemove.get(rule.id) || {})[f]) || [];
      const rm = [];
      for (const m of rule.fields[f]) {
        const c = isRemoved(s, m) || (lits.find((x) => x.value === m) || {}).cand;
        if (c) { rm.push(m); causes.push(c); }
      }
      if (rm.length && rule.neg[f]) {
        // "everything except X": dropping X makes the rule start matching X, so this is never automatic
        const nid = "neg|" + rule.id + "|" + f;
        const nc = { id: nid, kind: "negated-field", tier: "likely", rel: "negated", target: causes[0] ? causes[0].target : "", name: rule.name, value: f + " negated: " + rm.join(", "), field: f, rule: rule.name, ruleId: rule.id, ruleType: rule.type, rulebase: rule.rulebase, scope: s.id, scopeLabel: scopeLabel(s), location: locOf(s),
          reason: rule.type + " rule " + rule.name + " negates its " + f + " and lists " + rm.join(", ") + ". Removing it makes the rule START matching the target, so it is only removed if you tick this.", evidence: ["negate-" + f + " yes"], blast: { rules: 1 },
          selectable: true, tierLabel: TIER_LABEL.likely };
        nc.selected = picked ? picked.has(nid) : false;
        cands.set(nid, nc);
        if (!nc.selected) { causes.length -= rm.length; kept.push({ kind: "negated-field", name: rule.name, scope: scopeLabel(s), text: rule.type + " rule " + rule.name + " (" + scopeLabel(s) + ") keeps " + rm.join(", ") + " in its negated " + f + ": removing it would make the rule start matching the target. Tick the Highly likely item to remove it anyway; the objects it uses are kept until then." }); continue; }
        causes.push(nc);
      }
      if (rm.length) { remove[f] = rm; remaining[f] = rule.fields[f].filter((m) => !rm.includes(m)); }
    }
    const transHits = rule.translated.filter((t) => isRemoved(s, t.value));
    if (transHits.length) kept.push({ kind: "nat-translated", name: rule.name, scope: scopeLabel(s), text: rule.type + " rule " + rule.name + " (" + scopeLabel(s) + ") translates to " + transHits.map((t) => t.value).join(", ") + ". The plan never edits a translation; select that NAT rule (Highly likely) to delete it, or re-point it by hand. Until then the object it uses stays." });
    if (!Object.keys(remove).length) continue;
    const tier = worst(causes.map((x) => x.tier));
    const emptied = Object.keys(remaining).filter((f) => !remaining[f].length);
    const base = { rule_kind: rule.type, name: rule.name, rulebase: rule.rulebase, location: locOf(s), scope: s.id, scopeLabel: scopeLabel(s), depth: s.depth, because: [...new Set(causes.map((x) => x.id))], snapshot: ruleSnapshot(rule) };
    if (emptied.length) {
      const negEmptied = emptied.filter((f) => rule.neg[f]);
      const head = "Removing " + emptied.map((f) => f + " " + remove[f].join(", ")).join(" and ") + " from " + rule.type + " rule " + rule.name + " (" + scopeLabel(s) + ") would leave " + (emptied.length > 1 ? "those fields" : "that field") + " empty. PAN-OS has no empty address field: it would become 'any' and the rule would match far more traffic. ";
      let op = "disable-rule", t = "likely", why = "empty-field-would-become-any", tail;
      if (negEmptied.length) { why = "negated-field-would-empty"; tail = "The field is negated ('everything except these'), so the rule is disabled instead of edited; review it by hand."; }
      else if (tier === "exact") { op = "delete-rule"; t = "exact"; tail = "Every member it held was an exact match for the target, so the rule existed only for it and is deleted instead (never left as 'any')."; }
      else tail = "Not every member was an exact match, so the rule is disabled (not deleted). Delete it by hand once you are sure.";
      dangers.push({ code: why, rule: rule.name, scope: scopeLabel(s), text: head + tail });
      actions.push(Object.assign({ op, tier: t, reason: why, fields: emptied, danger: true }, base));
      deletedRules.set(rule.id, { cascade: true });
      continue;
    }
    for (const f of Object.keys(remove)) if (rule.neg[f]) dangers.push({ code: "negated-field", rule: rule.name, scope: scopeLabel(s), text: rule.type + " rule " + rule.name + " (" + scopeLabel(s) + ") negates its " + f + ". Removing " + remove[f].join(", ") + " from a negated field makes the rule START matching it. Review before you push." });
    remainingRule.set(rule.id, remaining);
    actions.push(Object.assign({ op: "edit-rule", tier, remove, remaining, reason: "references the target", danger: ADDR_FIELDS.some((f) => remove[f] && rule.neg[f]) }, base));
  }
  for (const [rid, d] of deletedRules) {
    if (d.cascade) continue;
    const s = inv.byId.get(d.cand.scope);
    const rule = s && s.rules.find((r) => r.id === rid);
    if (!rule) continue;
    actions.push({ op: "delete-rule", tier: d.tier, reason: d.reason, rule_kind: rule.type, name: rule.name, rulebase: rule.rulebase, location: locOf(s), scope: s.id, scopeLabel: scopeLabel(s), depth: s.depth, because: [d.cand.id], snapshot: ruleSnapshot(rule) });
  }
  for (const [gk, ed] of groupEdits) {
    if (removedG.has(gk)) continue;
    const s = ed.g.scope;
    actions.push({ op: "edit-group", tier: worst(ed.causes.map((x) => x.tier)), name: ed.g.name, location: locOf(s), scope: s.id, scopeLabel: scopeLabel(s), depth: s.depth, remove: ed.rm, remaining: ed.g.static.filter((m) => !ed.rm.includes(m)), because: [...new Set(ed.causes.map((x) => x.id))], snapshot: { members: ed.g.static.slice(), description: ed.g.desc, tags: ed.g.tags } });
  }
  // anything still pointing at a removed object after the edits (PAN-OS refuses to delete a referenced object)
  const stillRefs = (key) => (refs.get(key) || []).filter((x) => {
    if (x.kind === "group") { const gk = x.group.scope.id + "|g|" + x.group.name; return !removedG.has(gk) && !(groupEdits.get(gk) || { rm: [] }).rm.includes(x.member); }
    if (deletedRules.has(x.rule.id)) return false;
    if (x.kind === "nat-translated") return true;
    const rem = remainingRule.get(x.rule.id);
    return rem && rem[x.field] ? rem[x.field].includes(x.member) : true;
  });
  const describe = (x) => x.kind === "group" ? "address group " + x.group.name + " (" + scopeLabel(x.group.scope) + ")" : x.rule.type + " rule " + x.rule.name + " " + x.field + " (" + scopeLabel(x.rule.scope) + ")";
  const sharedWarn = new Set();
  for (const [gk, c] of removedG) {
    const s = inv.byId.get(gk.split("|g|")[0]), g = s && s.groups.get(gk.split("|g|")[1]);
    if (!g || g.dynamic != null) continue;
    const left = stillRefs(gk);
    if (left.length) { kept.push({ kind: "group", name: g.name, scope: scopeLabel(s), text: "Address group " + g.name + " (" + scopeLabel(s) + ") is kept: still used by " + left.slice(0, 5).map(describe).join("; ") + (left.length > 5 ? " and " + (left.length - 5) + " more" : "") + "." }); continue; }
    if (s.kind === "shared" && s.backend === "panorama") sharedWarn.add(g.name);
    actions.push({ op: "delete-group", tier: c.tier, reason: c.cascade ? "empty-group" : c.tier === "exact" ? "named-group" : "built-for-target", name: g.name, location: locOf(s), scope: s.id, scopeLabel: scopeLabel(s), depth: s.depth, members: (g.static || []).slice(), because: c.causes || [c.id], snapshot: { members: (g.static || []).slice(), description: g.desc, tags: g.tags }, nest: nestLevel(inv, resolve, g, 0) });
  }
  for (const [ak, c] of removedA) {
    const s = inv.byId.get(ak.split("|a|")[0]), a = s && s.addrs.get(ak.split("|a|")[1]);
    if (!a) continue;
    const left = stillRefs(ak);
    if (left.length) { kept.push({ kind: "address", name: a.name, scope: scopeLabel(s), text: "Address object " + a.name + " (" + scopeLabel(s) + ") is kept: still used by " + left.slice(0, 5).map(describe).join("; ") + (left.length > 5 ? " and " + (left.length - 5) + " more" : "") + "." }); continue; }
    if (s.kind === "shared" && s.backend === "panorama") sharedWarn.add(a.name);
    actions.push({ op: "delete-address", tier: c.tier, reason: c.tier === "exact" ? "requested" : c.exclusive ? "exclusive" : "selected", name: a.name, type: a.type, value: a.value, description: a.desc, location: locOf(s), scope: s.id, scopeLabel: scopeLabel(s), depth: s.depth, because: [c.id], snapshot: { type: a.type, value: a.value, description: a.desc, tags: a.tags } });
  }
  if (sharedWarn.size) notes.push({ level: "warn", code: "shared-objects", text: "Panorama shared objects " + [...sharedWarn].slice(0, 6).join(", ") + " are deleted only because nothing in this export still uses them. Rules written locally on a firewall are not in a Panorama export; load the firewalls' local backups too if any could use them." });
  // order: edits before deletes; rules, then groups (outer first), then objects; deepest scope (child DG) first, shared last
  const PH = { "edit-rule": 0, "disable-rule": 1, "delete-rule": 2, "edit-group": 3, "delete-group": 4, "delete-address": 5 };
  actions.sort((x, y) => PH[x.op] - PH[y.op] || (x.op === "delete-group" ? (y.nest || 0) - (x.nest || 0) : 0) || y.depth - x.depth || x.scopeLabel.localeCompare(y.scopeLabel) || x.name.localeCompare(y.name));
  actions.forEach((a, i) => { a.seq = i + 1; a.tierLabel = TIER_LABEL[a.tier]; a.cli = actionCli(a); a.rollback = actionRollback(a); a.verify = actionVerify(a); });
  return { actions, dangers, kept };
}
function nestLevel(inv, resolve, g, d) {
  // outer groups (that contain this one) sort first: returns minus the number of containing levels
  if (d > 20) return 0;
  let n = 0;
  for (const s of inv.scopes) for (const o of s.groups.values()) if (o !== g && (o.static || []).some((m) => { const r = resolve(s, m); return r.type === "group" && r.obj === g; })) n = Math.min(n, nestLevel(inv, resolve, o, d + 1) - 1);
  return n;
}
function ruleSnapshot(rule) {
  return { name: rule.name, kind: rule.type, rulebase: rule.rulebase, from: rule.from, to: rule.to, source: rule.fields.source, destination: rule.fields.destination,
    negate_source: rule.neg.source, negate_destination: rule.neg.destination, application: rule.application, service: rule.service, action: rule.action, description: rule.desc,
    disabled: rule.disabled, tags: rule.tags, translated_addresses: rule.translated.map((t) => t.value), before: rule.next, after: rule.prev, xml: serialize(rule.node) };
}

/* ------------------------------------------------------------------ CLI text (set / delete / move), rollback and checks */
function cliPrefix(loc, verb) {
  if (loc.kind === "shared") return verb + " shared";
  if (loc.device_group) return verb + " device-group " + q(loc.device_group);
  if (loc.multi_vsys && loc.vsys) return verb + " vsys " + loc.vsys;
  return verb;
}
function rulePath(a) { return (a.rulebase || (a.location.device_group || a.location.kind === "shared" ? "pre-rulebase" : "rulebase")) + " " + (a.rule_kind || "security") + " rules " + q(a.name); }
function actionCli(a) {
  const L = a.location;
  switch (a.op) {
    case "edit-rule": return Object.keys(a.remove).flatMap((f) => a.remove[f].map((m) => cliPrefix(L, "delete") + " " + rulePath(a) + " " + f + " " + q(m)));
    case "disable-rule": return [cliPrefix(L, "set") + " " + rulePath(a) + " disabled yes"];
    case "delete-rule": return [cliPrefix(L, "delete") + " " + rulePath(a)];
    case "edit-group": return a.remove.map((m) => cliPrefix(L, "delete") + " address-group " + q(a.name) + " static " + q(m));
    case "delete-group": return [cliPrefix(L, "delete") + " address-group " + q(a.name)];
    case "delete-address": return [cliPrefix(L, "delete") + " address " + q(a.name)];
    case "add-service": return [cliPrefix(L, "set") + " service " + q(a.name) + " protocol " + a.protocol + " port " + a.port];
    case "add-deny-rule": {
      const r = a.rule, p = cliPrefix(L, "set") + " " + a.rulebase + " security rules " + q(r.name);
      const out = [p + " from " + lst(r.from) + " to " + lst(r.to) + " source " + lst(r.source) + " destination " + lst(r.destination) + " application " + lst(r.application) + " service " + lst(r.service) + " action deny log-end yes description " + q(r.description)];
      for (const t of r.targets || []) out.push(p + " target devices " + q(t.serial) + (t.vsys ? " vsys " + q(t.vsys) : ""));
      out.push(cliPrefix(L, "move") + " " + a.rulebase + " security rules " + q(r.name) + (a.place.where === "before" ? " before " + q(a.place.ref) : " bottom"));
      return out;
    }
  }
  return [];
}
function actionRollback(a) {
  const L = a.location, s = a.snapshot || {};
  switch (a.op) {
    case "edit-rule": return Object.keys(a.remove).flatMap((f) => a.remove[f].map((m) => cliPrefix(L, "set") + " " + rulePath(a) + " " + f + " " + q(m)));
    case "disable-rule": return [cliPrefix(L, "set") + " " + rulePath(a) + " disabled " + (s.disabled ? "yes" : "no")];
    case "delete-rule": {
      const out = [];
      if (a.rule_kind === "security") out.push(cliPrefix(L, "set") + " " + rulePath(a) + " from " + lst(s.from) + " to " + lst(s.to) + " source " + lst(s.source) + " destination " + lst(s.destination) + " application " + lst(s.application) + " service " + lst(s.service) + " action " + (s.action || "allow") + (s.negate_source ? " negate-source yes" : "") + (s.negate_destination ? " negate-destination yes" : "") + (s.description ? " description " + q(s.description) : "") + (s.tags && s.tags.length ? " tag " + lst(s.tags) : "") + (s.disabled ? " disabled yes" : ""));
      else out.push("# re-create " + a.rule_kind + " rule " + a.name + " from the XML snapshot in the plan (translation and options are not rebuilt from one set line)");
      out.push(cliPrefix(L, "move") + " " + rulePath(a) + (s.before ? " before " + q(s.before) : " bottom"));
      return out;
    }
    case "edit-group": return a.remove.map((m) => cliPrefix(L, "set") + " address-group " + q(a.name) + " static " + q(m));
    case "delete-group": return [cliPrefix(L, "set") + " address-group " + q(a.name) + " static " + lst(s.members || [])].concat(s.description ? [cliPrefix(L, "set") + " address-group " + q(a.name) + " description " + q(s.description)] : []);
    case "delete-address": return [cliPrefix(L, "set") + " address " + q(a.name) + " " + (s.type || "ip-netmask") + " " + q(s.value || "")]
      .concat(s.description ? [cliPrefix(L, "set") + " address " + q(a.name) + " description " + q(s.description)] : [])
      .concat(s.tags && s.tags.length ? [cliPrefix(L, "set") + " address " + q(a.name) + " tag " + lst(s.tags)] : []);
    case "add-service": return [cliPrefix(L, "delete") + " service " + q(a.name)];
    case "add-deny-rule": return [cliPrefix(L, "delete") + " " + a.rulebase + " security rules " + q(a.rule.name)];
  }
  return [];
}
function actionVerify(a) {
  const where = a.scopeLabel || "";
  switch (a.op) {
    case "edit-rule": return Object.keys(a.remove).map((f) => "Rule " + a.name + " (" + where + ") " + f + " no longer lists " + a.remove[f].join(", ") + "; it still lists " + a.remaining[f].join(", ") + ".");
    case "disable-rule": return ["Rule " + a.name + " (" + where + ") is disabled."];
    case "delete-rule": return ["Rule " + a.name + " (" + where + ") is gone."];
    case "edit-group": return ["Address group " + a.name + " (" + where + ") no longer lists " + a.remove.join(", ") + "."];
    case "delete-group": return ["Address group " + a.name + " (" + where + ") is gone."];
    case "delete-address": return ["Address object " + a.name + " (" + where + ") is gone."];
    case "add-deny-rule": return (a.tests || []).map((t) => "On " + (a.device || "the firewall") + ", '" + t + "' must return rule " + a.rule.name + " (deny).");
  }
  return [];
}

/* ------------------------------------------------------------------ stop traffic: who would still allow it, and the fix */
function ruleKey(s, rb, name) {
  if (s.backend === "panorama") return (s.kind === "shared" ? "shared " : "DG " + s.name + " ") + rb + "|" + name;
  return s.name + "|" + name;
}
function effectiveRuleMap(inv, plan) {
  const m = new Map();
  for (const a of plan.actions) {
    const s = inv.byId.get(a.scope);
    if (!s || !a.rule_kind) continue;
    const key = ruleKey(s, a.rulebase, a.name);
    if (a.op === "delete-rule" || a.op === "disable-rule") m.set(key, { deleted: true });
    else if (a.op === "edit-rule") m.set(key, { remaining: a.remaining });
  }
  return m;
}
/* The objects each scope would hold after the plan: edited groups lose members, deleted groups and objects are gone. */
function scopePatches(plan) {
  const out = new Map();
  const get = (id) => { if (!out.has(id)) out.set(id, { gEdit: new Map(), gDel: new Set(), aDel: new Set() }); return out.get(id); };
  for (const a of plan.actions) {
    if (a.op === "edit-group") get(a.scope).gEdit.set(a.name, a.remaining);
    else if (a.op === "delete-group") get(a.scope).gDel.add(a.name);
    else if (a.op === "delete-address") get(a.scope).aDel.add(a.name);
  }
  return out;
}
function patchedScopes(patches, dev, ctx, cache) {
  const key = dev.id + "|" + ctx.name;
  if (cache.has(key)) return cache.get(key);
  const list = ctx.scopes.map((sc) => {
    const lbl = String(sc.label || "");
    const id = dev.file + "#" + (/^DG /.test(lbl) ? "device-group:" + lbl.slice(3) : lbl === "shared" ? "shared:shared" : "vsys:" + lbl);
    const p = patches.get(id);
    if (!p) return sc;
    const copy = Object.assign({}, sc, { address: new Map(sc.address), addressGroup: new Map(sc.addressGroup) });
    for (const n of p.aDel) copy.address.delete(n);
    for (const n of p.gDel) copy.addressGroup.delete(n);
    for (const [n, rem] of p.gEdit) { const g = copy.addressGroup.get(n); if (g) copy.addressGroup.set(n, Object.assign({}, g, { static: rem })); }
    return copy;
  });
  cache.set(key, list);
  return list;
}
function gradeOne(ctx, r, eff, fromZ, toZ, srcQ, dstQ, svcQ, scopes) {
  scopes = scopes || ctx.scopes;
  if (r.disabled || (eff && eff.deleted)) return null;
  if (!FM.zoneOk(r.from, fromZ) || !FM.zoneOk(r.to, toZ)) return null;
  if (r.ruleType === "intrazone" && fromZ !== toZ) return null;
  if (r.ruleType === "interzone" && fromZ === toZ) return null;
  const src = eff && eff.remaining && eff.remaining.source ? eff.remaining.source : r.source;
  const dst = eff && eff.remaining && eff.remaining.destination ? eff.remaining.destination : r.destination;
  const sm = FM.addrMatch(FM.resolveAddrs(src, scopes), srcQ, r.negSrc); if (sm.m === "no") return null;
  const dm = FM.addrMatch(FM.resolveAddrs(dst, scopes), dstQ, r.negDst); if (dm.m === "no") return null;
  const sv = FM.svcMatch(Object.assign({}, r), scopes, svcQ, (ctx.uid || "") + "#decom"); if (sv.m === "no") return null;
  const reasons = [];
  if (sm.why) reasons.push("source: " + sm.why);
  if (dm.why) reasons.push("destination: " + dm.why);
  reasons.push(...sv.reasons);
  const users = r.srcUser && r.srcUser.length && !r.srcUser.includes("any"), cats = r.category && r.category.length && !r.category.includes("any"), hip = r.hip && r.hip.length && !r.hip.includes("any");
  if (users) reasons.push("only for users " + r.srcUser.join(", "));
  if (cats) reasons.push("only for URL category " + r.category.join(", "));
  if (hip) reasons.push("only for HIP " + r.hip.join(", "));
  const yes = sm.m === "yes" && dm.m === "yes";
  const grade = yes && sv.m === "yes" && !sv.appDep && !users && !cats && !hip && !(sv.reasons.length && /application-default/.test(sv.reasons[0])) ? "definite" : yes ? "likely" : "possible";
  return { rule: r.name, scope: r.scope, action: /allow/.test(r.action || "") ? "allow" : "deny", grade, reasons, edited: !!(eff && eff.remaining) };
}
function blockAnalysis(inv, resolve, plan, targets, request, opts) {
  const out = { flows: [], places: [], fixes: [], stillAllows: [], notes: [] };
  const eff = effectiveRuleMap(inv, plan);
  const patches = scopePatches(plan), scopeCache = new Map();
  const devices = opts.devices || [];
  const flows = (request.flows || []).slice(0, 50);
  const used = new Set(), fixKey = new Map();
  const unpicked = Array.isArray(opts.select) ? new Set(opts.select) : null;
  let n = 0;
  for (const fl of flows) {
    const flow = { src: String(fl.src || "").trim(), dst: String(fl.dst || "").trim(), proto: String(fl.proto || "tcp").toLowerCase(), port: fl.port == null || fl.port === "" ? null : Number(fl.port) };
    const fr = { flow, places: [], status: null, notes: [] };
    out.flows.push(fr);
    if (!devices.length) { fr.notes.push("No firewalls were built from the loaded files, so the path cannot be traced."); continue; }
    let res;
    try { res = FM.trace(devices, { src: flow.src, dst: flow.dst, proto: flow.proto, port: flow.port }, opts.traceOptions || {}); }
    catch (e) { fr.notes.push("Trace failed: " + ((e && e.message) || e)); continue; }
    fr.status = res.status || null;
    for (const nt of (res.notes || []).filter((x) => x.level === "error").slice(0, 3)) fr.notes.push(nt.text);
    (res.segments || []).forEach((seg, i) => {
      if (!seg.check) return;
      const dev = devices.find((d) => d.id === seg.devId) || devices.find((d) => d.name === seg.device);
      const ctx = dev && dev.vsys.get(seg.vsys);
      if (!ctx) return;
      const c = seg.check;
      const srcQ = FM.parsePrefix(c.src) || seg.srcP, dstQ = FM.parsePrefix(c.dst) || seg.dstP;
      const sq = { proto: flow.proto || "any", port: flow.port };
      const permits = [];
      let blockedBy = null;
      const scopes = patchedScopes(patches, dev, ctx, scopeCache);
      for (const r of ctx.security) {
        const g = gradeOne(ctx, r, eff.get(r.scope + "|" + r.name), c.fromZone, c.toZone, srcQ, dstQ, sq, scopes);
        if (!g) continue;
        if (g.action === "allow") { permits.push(g); continue; }
        if (g.grade === "definite") { blockedBy = g; break; }
      }
      if (!blockedBy) {
        const intra = c.fromZone === c.toZone;
        const act = /allow/.test((intra ? ctx.defaults.intrazone : ctx.defaults.interzone) || "") ? "allow" : "deny";
        const d = { rule: intra ? "intrazone-default" : "interzone-default", scope: "predefined", action: act, grade: "definite", reasons: [] };
        if (act === "allow") permits.push(d); else blockedBy = d;
      }
      const first = permits[0] || null;
      const after = permits.some((p) => p.grade === "definite") ? "allowed" : permits.length ? "maybe" : "denied";
      const place = { n: i + 1, device: dev.hostname || seg.device, serial: dev.serial || null, vsys: seg.vsys, dg: ctx.dg || null, fromZone: c.fromZone, toZone: c.toZone, src: c.src, dst: c.dst, svc: c.svc, permits, blockedBy: blockedBy ? { rule: blockedBy.rule, scope: blockedBy.scope } : null, after };
      for (const p of permits) out.stillAllows.push({ flow: flow.src + " -> " + flow.dst + " " + c.svc, device: place.device, vsys: seg.vsys, fromZone: c.fromZone, toZone: c.toZone, rule: p.rule, scope: p.scope, grade: p.grade, reasons: p.reasons, edited: p.edited });
      if (after !== "denied") {
        const fx = denyFix(inv, dev, ctx, place, first, flow, used, ++n);
        const k = JSON.stringify([fx.location, fx.rulebase, fx.rule.from, fx.rule.to, fx.rule.source, fx.rule.destination, fx.rule.service, fx.place]);
        if (fixKey.has(k)) place.fix = fixKey.get(k).id;
        else { if (unpicked) fx.selected = unpicked.has(fx.id); fixKey.set(k, fx); out.fixes.push(fx); place.fix = fx.id; }
      }
      fr.places.push(place);
      out.places.push(place);
    });
    if (!fr.places.length && !fr.notes.length) fr.notes.push("The trace found no place on the path that checks security policy (" + (res.status || "no path") + ").");
  }
  // anywhere in the config: allow rules that would still match traffic to or from a target after the plan, path or not
  const groupRem = new Map();
  for (const [sid, p] of patches) { for (const [n, rem] of p.gEdit) groupRem.set(sid + "|g|" + n, rem); for (const n of p.gDel) groupRem.set(sid + "|g|" + n, []); }
  for (const t of targets.filter((x) => x.kind === "ip")) {
    for (const s of inv.scopes) for (const rule of s.rules) {
      if (rule.type !== "security" || rule.disabled || !/allow/.test(rule.action)) continue;
      const e = eff.get(ruleKey(s, rule.rulebase, rule.name));
      if (e && e.deleted) continue;
      const fld = (f) => (e && e.remaining && e.remaining[f]) || rule.fields[f];
      const cov = { source: coverInv(resolve, s, fld("source"), t.p, rule.neg.source, groupRem), destination: coverInv(resolve, s, fld("destination"), t.p, rule.neg.destination, groupRem) };
      const svcAny = !rule.service.length || rule.service.includes("any"), appAny = !rule.application.length || rule.application.includes("any");
      let f = null, why = "";
      if (cov.destination === "full" || cov.destination === "partial") f = "destination";
      else if (cov.source === "full" || cov.source === "partial") f = "source";
      let grade;
      if (f) {
        const other = f === "source" ? "destination" : "source";
        const open = cov[other] === "any" && svcAny && appAny;
        grade = cov[f] === "full" ? (open ? "definite" : "likely") : "possible";
        why = cov[f] === "full" ? f + " covers " + t.text + " through a broader object or value" : f + " may cover " + t.text + " (partial, FQDN, EDL or runtime members)";
        if (!open) why += "; narrowed by " + [cov[other] === "any" ? "" : other, svcAny ? "" : "service", appAny ? "" : "application"].filter(Boolean).join(", ");
      } else if (cov.source === "any" && cov.destination === "any") {
        f = "source and destination"; grade = svcAny && appAny ? "definite" : "likely";
        why = "source and destination are both any" + (svcAny && appAny ? "" : "; narrowed by " + [svcAny ? "" : "service", appAny ? "" : "application"].filter(Boolean).join(", "));
      } else continue;
      out.stillAllows.push({ flow: null, target: t.raw, scopeLabel: scopeLabel(s), rule: rule.name, rulebase: rule.rulebase, field: f, coverage: cov[f] || "any", grade, reasons: [why], edited: !!(e && e.remaining) });
    }
  }
  const G = ["definite", "likely", "possible"];
  out.stillAllows.sort((a, b) => (a.flow ? 0 : 1) - (b.flow ? 0 : 1) || G.indexOf(a.grade) - G.indexOf(b.grade));
  out.stillAllowsTotal = out.stillAllows.length;
  if (out.stillAllows.length > MAX_LIST) { out.notes.push("Showing the first " + MAX_LIST + " of " + out.stillAllows.length + " rules that could still allow the traffic."); out.stillAllows = out.stillAllows.slice(0, MAX_LIST); }
  if (!flows.length) out.notes.push("No flow was given, so no path was traced. Add a flow (source, destination, port) to get a deny for every place on the path; the list below is every allow rule anywhere that could still match the target.");
  return out;
}
function coverInv(resolve, s, list, p, neg, groupRem) {
  if (!list.length || list.includes("any")) return neg ? "none" : "any";
  const ranges = [], unk = [], seen = new Set();
  const walk = (sc, m, d) => {
    if (d > 20 || seen.has(sc.id + "\u0000" + m)) return; seen.add(sc.id + "\u0000" + m);
    const r = resolve(sc, m);
    if (r.type === "address") { if (r.obj.p) ranges.push(r.obj.p); else unk.push(m); }
    else if (r.type === "group") { const st = groupRem && groupRem.has(r.key) ? groupRem.get(r.key) : r.obj.static || []; for (const x of st) walk(r.obj.scope, x, d + 1); if (r.obj.dynamic != null) unk.push(m); }
    else if (r.type === "literal") ranges.push(r.p);
    else unk.push(m);
  };
  for (const m of list) walk(s, m, 0);
  const cov = FM.coverage(ranges, p);
  if (neg) return cov === "none" ? (unk.length ? "partial" : "full") : cov === "full" ? "none" : "partial";
  if (cov === "full") return "full";
  if (cov === "partial" || unk.length) return "partial";
  return "none";
}
function denyFix(inv, dev, ctx, place, first, flow, used, n) {
  const pano = dev.kind === "panorama";
  const scopeFor = (kind, name) => inv.scopes.find((s) => s.file === dev.file && s.kind === kind && s.name === name);
  const locFor = (kind, name) => { const s = scopeFor(kind, name); return s ? locOf(s) : Object.assign({ kind, name, file: dev.file, backend: kind === "vsys" ? "firewall" : "panorama", location: kind === "shared" ? "shared" : kind }, kind === "device-group" ? { device_group: name } : kind === "vsys" ? { vsys: name, device: dev.name } : {}); };
  let location, rulebase, where = { where: "bottom", ref: null }, manual = null;
  if (pano) {
    const m = first && /^(shared|DG (.+)) (pre-rulebase|post-rulebase)$/.exec(first.scope || "");
    if (m && m[3] === "pre-rulebase") { location = m[2] ? locFor("device-group", m[2]) : locFor("shared", "shared"); rulebase = "pre-rulebase"; where = { where: "before", ref: first.rule }; }
    else if (ctx.dg) { location = locFor("device-group", ctx.dg); rulebase = "pre-rulebase"; }
    else { location = locFor("vsys", ctx.name); rulebase = "rulebase"; manual = "This firewall has no device group in the export; add the deny on the firewall itself."; }
  } else {
    location = locFor("vsys", ctx.name); rulebase = "rulebase";
    if (first && first.scope === ctx.name) where = { where: "before", ref: first.rule };
    else if (first && first.scope !== "predefined") manual = "The first rule that allows it (" + first.rule + ", " + first.scope + ") is pushed from Panorama, so a local rule cannot sit above it. Add this deny in Panorama above that rule.";
  }
  const base = "DECOM-DENY-" + safeName(FM.n2ip(FM.parsePrefix(place.dst).lo)).slice(0, 30);
  let name = base + "-" + n;
  while (used.has(name)) name = base + "-" + (++n);
  used.add(name);
  const svc = flow.proto === "any" || flow.proto === "icmp" || flow.port == null ? null : { proto: flow.proto, port: flow.port };
  let service = ["any"], svcObj = null;
  if (svc) {
    const s = scopeFor(location.kind, location.name);
    let found = null;
    if (s) for (const sc of chain(inv, s)) { for (const o of sc.services.values()) if (o.proto === svc.proto && String(o.port) === String(svc.port) && !o.src) { found = o.name; break; } if (found) break; }
    if (found) service = [found];
    else { const nm = "DECOM-" + svc.proto + "-" + svc.port; service = [nm]; svcObj = { op: "add-service", name: nm, protocol: svc.proto, port: String(svc.port), location, tier: "exact", scopeLabel: "" }; }
  }
  const proto = flow.proto === "udp" ? 17 : flow.proto === "icmp" ? 1 : 6;
  const rule = { name, from: [place.fromZone || "any"], to: [place.toZone || "any"], source: [place.src], destination: [place.dst], application: ["any"], service, action: "deny",
    description: "Decommission: stop " + place.src + " to " + place.dst + " " + (place.svc || "any") + " (FlowMapper plan)", targets: pano && dev.serial ? [{ serial: dev.serial, vsys: ctx.name }] : [] };
  const vsysCmd = dev.multiVsys || (ctx.name && ctx.name !== "vsys1") ? "set system setting target-vsys " + ctx.name + " ; " : "";
  const tests = [vsysCmd + "test security-policy-match from " + q(place.fromZone) + " to " + q(place.toZone) + " source " + FM.n2ip(FM.parsePrefix(place.src).lo) + " destination " + FM.n2ip(FM.parsePrefix(place.dst).lo) + " protocol " + proto + (svc ? " destination-port " + svc.port : "")];
  const fx = { id: "deny|" + dev.file + "|" + (location.device_group || location.name) + "|" + place.fromZone + ">" + place.toZone + "|" + place.src + ">" + place.dst + "|" + (place.svc || "any"),
    op: "add-deny-rule", tier: "exact", tierLabel: TIER_LABEL.exact, selected: true, location, rulebase, place: where, rule, service: svcObj, device: dev.name, serial: dev.serial || null, vsys: ctx.name, n: place.n,
    firstPermit: first ? { rule: first.rule, scope: first.scope, grade: first.grade } : null, manual, tests,
    why: first ? "Placed " + (where.where === "before" ? "directly above " + first.rule + " (" + first.scope + ")" : "at the bottom of the " + (location.device_group ? "device group " + location.device_group + " " : "") + rulebase + (rulebase === "pre-rulebase" ? " (pre-rules run before the firewall's local and post rules)" : "")) + ", the first rule that would still allow it here (" + first.grade + ")." : "" };
  fx.scopeLabel = location.device_group ? "device group " + location.device_group : location.kind === "shared" ? "shared" : dev.name + "/" + ctx.name;
  if (svcObj) svcObj.scopeLabel = fx.scopeLabel;
  fx.cli = (svcObj ? actionCli(svcObj) : []).concat(actionCli(fx));
  fx.rollback = actionRollback(fx).concat(svcObj ? actionRollback(svcObj) : []);
  fx.verify = actionVerify(fx);
  return fx;
}

/* ------------------------------------------------------------------ summaries and exports */
function counts(r) {
  const c = { exact: 0, likely: 0, possible: 0, selected: 0, actions: r.plan.actions.length, dangers: r.plan.dangers.length, kept: r.plan.kept.length, ops: {} };
  for (const x of r.candidates) { c[x.tier]++; if (x.selected) c.selected++; }
  for (const a of r.plan.actions) c.ops[a.op] = (c.ops[a.op] || 0) + 1;
  if (r.block) {
    c.fixes = r.block.fixes.length; c.fixesSelected = r.block.fixes.filter((f) => f.selected).length;
    const g = { definite: 0, likely: 0, possible: 0 }; for (const s of r.block.stillAllows) g[s.grade]++;
    c.stillAllows = g; c.stillAllowsTotal = r.block.stillAllowsTotal;
  }
  return c;
}
function csvCell(v) { v = v == null ? "" : String(v); return /^[=+\-@]/.test(v) ? "'" + v : /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
function toCsv(r) {
  const rows = [["section", "tier", "selected", "kind", "scope", "name", "value", "detail", "reason", "other_addresses", "rules_using", "groups_using"]];
  for (const c of r.candidates) { const b = c.blast || {}; rows.push(["finding", c.tierLabel, c.selected ? "yes" : c.selectable ? "no" : "advice only", c.kind, c.scopeLabel, c.name, c.value || "", c.kind === "literal" ? c.field + " of " + c.rule : c.kind === "rule" ? c.ruleType + " " + c.rulebase : "", c.reason, b.otherAddresses || "", b.rules || "", b.groups || ""]); }
  for (const a of r.plan.actions) rows.push(["action " + a.seq, a.tierLabel, "yes", a.op, a.scopeLabel, a.name, a.value || "", a.cli.join(" ; "), a.reason || "", "", "", ""]);
  for (const d of r.plan.dangers) rows.push(["danger", "", "", d.code, d.scope, d.rule, "", "", d.text, "", "", ""]);
  for (const k of r.plan.kept) rows.push(["kept", "", "", k.kind, k.scope, k.name || "", "", "", k.text, "", "", ""]);
  if (r.block) {
    for (const s of r.block.stillAllows) rows.push(["still allows", s.grade, "", "rule", s.scopeLabel || s.device + "/" + s.vsys, s.rule, s.flow || s.target, s.fromZone ? s.fromZone + " -> " + s.toZone : s.field, s.reasons.join("; "), "", "", ""]);
    for (const f of r.block.fixes) rows.push(["fix", f.tierLabel, f.selected ? "yes" : "no", "add-deny-rule", f.scopeLabel, f.rule.name, f.rule.source[0] + " -> " + f.rule.destination[0], f.cli.join(" ; "), f.why + (f.manual ? " " + f.manual : ""), "", "", ""]);
  }
  return rows.map((x) => x.map(csvCell).join(",")).join("\n") + "\n";
}
function toMarkdown(r) {
  const c = r.counts, o = [];
  const md = (s) => String(s == null ? "" : s).replace(/\|/g, "/");
  o.push("# Decommission plan (" + (r.mode === "block" ? "stop traffic" : "remove references") + ")", "");
  o.push("Targets: " + r.targets.map((t) => "`" + t.raw + "`" + (t.matches ? "" : " (not found)")).join(", "), "");
  o.push("Findings: " + c.exact + " exact, " + c.likely + " highly likely, " + c.possible + " possible. Selected: " + c.selected + ". Actions: " + c.actions + ". Dangers called out: " + c.dangers + ".", "");
  o.push("Exact items are pre-selected. Highly likely items need one click. Possible items are advice only: a broader object (like a /16) is never deleted because one host inside it is retired.", "");
  for (const tier of ["exact", "likely", "possible"]) {
    const list = r.candidates.filter((x) => x.tier === tier);
    if (!list.length) continue;
    o.push("## " + TIER_LABEL[tier] + " (" + list.length + ")", "", "| Pick | Kind | Name | Where | Why | Blast radius |", "|---|---|---|---|---|---|");
    for (const x of list) { const b = x.blast || {}; o.push("| " + (x.selected ? "[x]" : x.selectable ? "[ ]" : "advice") + " | " + x.kind + " | `" + md(x.name) + "`" + (x.value && x.value !== x.name ? " " + md(x.value) : "") + " | " + md(x.scopeLabel) + " | " + md(x.reason) + " | " + [b.otherAddresses ? b.otherAddresses.toLocaleString("en-US") + " other addresses" : "", b.rules ? plural(b.rules, "rule") : "", b.groups ? plural(b.groups, "group") : ""].filter(Boolean).join(", ") + " |"); }
    o.push("");
    if (tier === "possible") { for (const x of list) if (x.advice) o.push("- `" + x.name + "`: " + x.advice.join(" ")); o.push(""); }
  }
  if (r.plan.dangers.length) { o.push("## Dangers called out", ""); for (const d of r.plan.dangers) o.push("- " + d.text); o.push(""); }
  if (r.plan.kept.length) { o.push("## Kept (still in use)", ""); for (const k of r.plan.kept) o.push("- " + k.text); o.push(""); }
  if (r.plan.actions.length) { o.push("## Plan, in push order", ""); for (const a of r.plan.actions) { o.push(a.seq + ". **" + a.op + "** `" + a.name + "` (" + a.scopeLabel + ", " + a.tierLabel + ")"); for (const l of a.cli) o.push("    " + l); } o.push(""); }
  if (r.block) {
    o.push("## Stop traffic", "");
    for (const n of r.block.notes) o.push("- " + n);
    for (const f of r.block.flows) { o.push("", "Flow `" + f.flow.src + " -> " + f.flow.dst + " " + f.flow.proto + (f.flow.port != null ? "/" + f.flow.port : "") + "`: " + f.places.length + " place(s) check security policy."); for (const p of f.places) o.push("- Place " + p.n + ": " + p.device + " " + p.vsys + " " + p.fromZone + " -> " + p.toZone + ": after this plan the traffic is **" + p.after + "**" + (p.permits[0] ? " (first rule that allows it: " + p.permits[0].rule + ", " + p.permits[0].grade + ")" : "") + "."); for (const n of f.notes) o.push("- " + n); }
    if (r.block.stillAllows.length) { o.push("", "| Grade | Rule | Where | Why |", "|---|---|---|---|"); for (const s of r.block.stillAllows) o.push("| " + s.grade + " | `" + md(s.rule) + "` | " + md(s.scopeLabel || s.device + "/" + s.vsys + " " + s.fromZone + " -> " + s.toZone) + " | " + md(s.reasons.join("; ")) + " |"); }
    if (r.block.fixes.length) { o.push("", "Deny rules (one for each place that would still allow it):", ""); for (const f of r.block.fixes) { o.push("- " + (f.selected ? "[x] " : "[ ] ") + "`" + f.rule.name + "` in " + f.scopeLabel + " " + f.rulebase + ". " + f.why + (f.manual ? " " + f.manual : "")); for (const l of f.cli) o.push("    " + l); for (const t of f.tests) o.push("    " + t); } }
    o.push("");
  }
  if (r.notes.length) { o.push("## Notes", ""); for (const n of r.notes) o.push("- " + n.text); o.push(""); }
  return o.join("\n");
}
function cliText(r, which) {
  const out = [];
  const fixes = r.block ? r.block.fixes.filter((f) => f.selected) : [];
  if (which === "rollback") { for (const f of fixes) out.push(...f.rollback); for (const a of r.plan.actions.slice().reverse()) out.push(...a.rollback); }
  else { for (const a of r.plan.actions) out.push(...a.cli); for (const f of fixes) out.push(...f.cli); }
  return out.join("\n") + (out.length ? "\n" : "");
}

const decom = { version: VERSION, TIER_LABEL, parseTarget, parseTargets, inventory, relation, analyze, toCsv, toMarkdown, cliText };
FM.decom = decom;
if (typeof module !== "undefined" && module.exports) module.exports = decom;
})(typeof window !== "undefined" ? window : globalThis);
