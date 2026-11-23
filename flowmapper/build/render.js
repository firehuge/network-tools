/* PAN-OS FlowMapper shared renderers: the hop-by-hop flow diagram and the environment / vsys-map / Panorama diagrams as
 * plain SVG strings. Pure JS, no DOM, no network. Used by the offline page (build/app.js) and, vendored, by PAAT.
 * Needs core.js (FM) loaded first. */
(function (root) {
"use strict";
const FM = (typeof module !== "undefined" && module.exports) ? require("./core.js") : root.FM;
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const C = { g: "#1f9d55", gb: "#e7f6ee", r: "#d64545", rb: "#fdeaea", y: "#b7791f", yb: "#fff6dc", b: "#2f6fd6", bb: "#e8f0fe", tx: "#1b2430", mu: "#5c6b7a", bd: "#c9d1da", card: "#ffffff", bg: "#f7f9fb", sg: "#8250df", sgb: "#f3ecff" };
const DEVCOL = ["#2f6fd6", "#0f8a8a", "#8250df", "#c2410c", "#4d7c0f", "#b91c1c", "#0369a1"];
function trunc(s, n) { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n - 1) + "\u2026" : s; }
function T(x, y, s, o) { o = o || {}; const n = o.max || 40; return '<text x="' + x + '" y="' + y + '" font-family="Segoe UI,Arial,sans-serif" font-size="' + (o.size || 12) + '" fill="' + (o.fill || C.tx) + '"' + (o.bold ? ' font-weight="700"' : "") + (o.anchor ? ' text-anchor="' + o.anchor + '"' : "") + ">" + (String(s).length > n ? "<title>" + esc(s) + "</title>" : "") + esc(trunc(s, n)) + "</text>"; }
function R(x, y, w, h, o) { o = o || {}; return '<rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" rx="' + (o.rx == null ? 8 : o.rx) + '" fill="' + (o.fill || C.card) + '" stroke="' + (o.stroke || C.bd) + '" stroke-width="' + (o.sw || 1) + '"' + (o.dash ? ' stroke-dasharray="' + o.dash + '"' : "") + "/>"; }
function arrow(x1, y1, x2, y2, o) { o = o || {}; return '<line x1="' + x1 + '" y1="' + y1 + '" x2="' + x2 + '" y2="' + y2 + '" stroke="' + (o.stroke || C.mu) + '" stroke-width="' + (o.sw || 2) + '"' + (o.dash ? ' stroke-dasharray="' + o.dash + '"' : "") + ' marker-end="url(#ah)"/>'; }
const DEFS = '<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#5c6b7a"/></marker></defs>';

function cloud(cx, cy, w, h, col) {
  const bumps = [[-0.32, -0.18, 0.26], [-0.05, -0.32, 0.3], [0.25, -0.2, 0.26], [0.36, 0.08, 0.2], [-0.38, 0.1, 0.2], [0, 0.14, 0.42]];
  let o = "";
  for (const [dx, dy, r] of bumps) o += '<ellipse cx="' + (cx + dx * w) + '" cy="' + (cy + dy * h) + '" rx="' + r * w + '" ry="' + r * h * 1.25 + '" fill="#fff7ed" stroke="' + col + '" stroke-width="1.5"/>';
  for (const [dx, dy, r] of bumps) o += '<ellipse cx="' + (cx + dx * w) + '" cy="' + (cy + dy * h) + '" rx="' + (r * w - 1.5) + '" ry="' + (r * h * 1.25 - 1.5) + '" fill="#fff7ed"/>';
  return o;
}
function flowSvg(r, opts) {
  opts = opts || {};
  const DL = opts.DL || ((n) => n), DLs = (list) => (list || []).map(DL).join(", ");
  const segs = r.segments;
  const W = 280, GAP = 70, PADX = 20, TOP = 46;
  const rowsOf = (s) => {
    const rows = [];
    rows.push({ k: "IN", t: s.ingress.iface ? s.ingress.iface + (s.ingress.peer ? " (from " + s.ingress.peer + ")" : "") : "from " + s.ingress.fromCtx + " (inter-vsys)", z: s.ingress.zone });
    if (s.pbf) rows.push({ k: "PBF", t: s.pbf.rule + " -> " + (s.pbf.action.iface || s.pbf.action.vsys || s.pbf.action.type), c: "b" });
    for (const v of s.vrPath) rows.push({ k: v.route.inferred ? v.route.inferred.proto.toUpperCase() : "VR", t: v.vr + ": " + FM.prefixStr(v.route.dest) + (v.route.nexthop && v.route.nexthop.value ? " -> " + v.route.nexthop.value : v.route.type === "connected" ? " connected" : "") + (v.route.inferred ? " (inferred)" : v.route.origin === "template" ? " (template)" : v.route.origin === "local" ? " (local backup)" : ""), c: v.route.type === "suggested" || v.route.inferred ? "y" : null });
    if (s.nat) { if (s.nat.dnat) rows.push({ k: "DNAT", t: s.nat.rule + ": " + (s.nat.inferred ? s.nat.pre : s.dst) + " -> " + s.nat.dnat.text + (s.nat.dnat.port ? ":" + s.nat.dnat.port : ""), c: "b" }); if (s.nat.snat) rows.push({ k: "SNAT", t: s.nat.rule + ": " + s.src + " -> " + s.nat.snat.text, c: "b" }); }
    if (s.vrPathPost) for (const v of s.vrPathPost) rows.push({ k: "VR'", t: v.vr + ": " + FM.prefixStr(v.route.dest) + " (post-NAT)" });
    if (s.check) rows.push({ k: "POLICY", t: s.check.fromZone + " -> " + s.check.toZone, pol: s.check });
    else if (s.isSG) rows.push({ k: "POLICY", t: "none in shared gateway", c: "sg" });
    if (s.egress) rows.push({ k: "OUT", t: s.egress.iface ? s.egress.iface + (s.egress.toCtx ? " (to " + s.egress.toCtx + ")" : "") : "to " + (s.egress.toCtx || "?") + " (inter-vsys)", z: s.egress.zone });
    if (s.basis) rows.push({ k: "WHY", t: s.basis.text + " [" + s.basis.confidence + "]", c: s.basis.confidence === "high" ? "g" : s.basis.confidence === "medium" ? "y" : "r" });
    return rows;
  };
  const rowH = (row) => (row.pol ? 52 : row.z ? 36 : 24);
  const heights = segs.map((s) => 40 + rowsOf(s).reduce((a, x) => a + rowH(x) + 4, 0) + 6);
  const H = Math.max(...heights, 120);
  const n = segs.length + 2;
  const CLOUD = 190;
  const xs = [PADX];
  for (let i = 1; i < n; i++) {
    const prevW = i === 1 ? W - 60 : W;
    const crossDev = i >= 2 && i <= segs.length && (segs[i - 1].devId !== segs[i - 2].devId || (segs[i - 2].next && segs[i - 2].next.kind === "hairpin"));
    xs.push(xs[i - 1] + prevW + (crossDev ? CLOUD : GAP));
  }
  const width = xs[n - 1] + W - 60 + PADX;
  const totalH = TOP + H + 70;
  const devIdx = new Map(); segs.forEach((s) => { if (!devIdx.has(s.devId)) devIdx.set(s.devId, devIdx.size); });
  let out = '<svg xmlns="http://www.w3.org/2000/svg" width="' + width + '" height="' + totalH + '" viewBox="0 0 ' + width + " " + totalH + '" style="background:#fff">' + DEFS + '<rect width="100%" height="100%" fill="#fff"/>';
  out += T(PADX, 22, "Flow: " + r.query.src + " \u2192 " + r.query.dst + "  " + r.query.svc, { size: 15, bold: true, max: 120 });
  const colX = (i) => xs[i];
  // source box
  const sW = W - 60, midY = TOP + 20 + H / 2;
  out += R(colX(0), midY - 34, sW, 68, { fill: C.bb, stroke: C.b, sw: 2 }) + T(colX(0) + 12, midY - 12, "SOURCE", { size: 11, fill: C.mu, bold: true }) + T(colX(0) + 12, midY + 8, r.query.src, { size: 14, bold: true, max: 24 }) + T(colX(0) + 12, midY + 25, r.query.svc, { size: 12, fill: C.mu });
  // device group backgrounds
  let gStart = 0;
  for (let i = 1; i <= segs.length; i++) {
    if (i === segs.length || segs[i].devId !== segs[gStart].devId) {
      const x0 = colX(gStart + 1) - 12, x1 = colX(i) + W + 12, col = DEVCOL[devIdx.get(segs[gStart].devId) % DEVCOL.length];
      out += R(x0, TOP, x1 - x0, H + 40, { fill: "none", stroke: col, sw: 2, dash: "7 5", rx: 14 }) + T(x0 + 12, TOP + 17, "Firewall: " + DL(segs[gStart].device) + (segs[gStart].haPeers && segs[gStart].haPeers.length ? " (HA: " + DLs(segs[gStart].haPeers) + ")" : ""), { size: 13, bold: true, fill: col, max: 70 });
      gStart = i;
    }
  }
  segs.forEach((s, i) => {
    const x = colX(i + 1), y = TOP + 28, rows = rowsOf(s), h = heights[i] - 10;
    const col = s.isSG ? C.sg : DEVCOL[devIdx.get(s.devId) % DEVCOL.length];
    out += R(x, y, W, h, { fill: s.isSG ? C.sgb : C.card, stroke: col, sw: 1.5 });
    out += '<rect x="' + x + '" y="' + y + '" width="' + W + '" height="28" rx="8" fill="' + col + '"/>' + T(x + 10, y + 19, (s.isSG ? "Shared gateway " : "") + s.vsys + (s.display !== s.vsys ? " - " + s.display : "") + (s.dg ? "  [DG " + s.dg + "]" : ""), { size: 13, bold: true, fill: "#fff", max: 36 });
    let yy = y + 36;
    for (const row of rows) {
      const rh = rowH(row);
      let fill = C.bg, stroke = C.bd;
      if (row.pol) { const p = row.pol; if (p.verdict === "conditional") { fill = C.yb; stroke = C.y; } else if (p.action === "allow") { fill = C.gb; stroke = C.g; } else { fill = C.rb; stroke = C.r; } }
      else if (row.c === "b") { fill = C.bb; stroke = C.b; } else if (row.c === "y") { fill = C.yb; stroke = C.y; } else if (row.c === "g") { fill = C.gb; stroke = C.g; } else if (row.c === "r") { fill = C.rb; stroke = C.r; } else if (row.c === "sg") { fill = C.sgb; stroke = C.sg; }
      out += R(x + 8, yy, W - 16, rh, { fill, stroke, rx: 6 });
      out += T(x + 14, yy + 16, row.k, { size: 10, bold: true, fill: C.mu }) + T(x + 58, yy + 16, row.t, { size: 12, max: 31 });
      if (row.z) out += T(x + 58, yy + 30, "zone " + row.z, { size: 11, fill: C.mu, max: 28 });
      if (row.pol) {
        const p = row.pol, lab = p.verdict === "conditional" ? "CONDITIONAL" : p.action === "allow" ? "ALLOW" : "DENY", lc = p.verdict === "conditional" ? C.y : p.action === "allow" ? C.g : C.r;
        out += T(x + 14, yy + 33, lab, { size: 11, bold: true, fill: lc }) + T(x + 100, yy + 33, (p.kind === "default" ? "" : "rule ") + p.rule, { size: 11.5, max: 22 });
        out += T(x + 14, yy + 47, p.kind === "default" ? "no rule matches" : (p.ruleScope || ""), { size: 10, fill: C.mu, max: 40 });
      }
      yy += rh + 4;
    }
    if (s.hypothetical) out += T(x + 10, y + h + 14, "assumes suggested route", { size: 11, fill: C.y, bold: true });
  });
  // arrows between columns with on-the-wire labels
  for (let i = 0; i <= segs.length; i++) {
    const x1 = i === 0 ? colX(0) + sW : colX(i) + W, x2 = colX(i + 1) - 2;
    const prev = i > 0 ? segs[i - 1] : null;
    const label = prev ? (prev.srcPost !== prev.src || prev.dstPost !== prev.dst ? prev.srcPost + " \u2192 " + prev.dstPost : "") : "";
    const crossDev = prev && segs[i] && prev.devId !== segs[i].devId;
    if (prev && segs[i] && !crossDev && prev.next && prev.next.kind === "hairpin") {
      const v = prev.next.via, cx = (x1 + x2) / 2, cw = x2 - x1 - 50;
      out += arrow(x1 + 2, midY, cx - cw / 2 - 2, midY, { stroke: "#d97706", dash: "7 5" }) + arrow(cx + cw / 2, midY, x2, midY, { stroke: "#d97706", dash: "7 5" });
      const hpTitle = /outside router|unknown/.test((v && v.label) || "") ? "HAIRPIN via unknown network" : "HAIRPIN (outside)";
      out += R(cx - cw / 2, midY - 30, cw, 60, { fill: "#fff7ed", stroke: "#d97706", rx: 12, dash: "4 3" }) + T(cx, midY - 12, hpTitle, { size: 10, bold: true, anchor: "middle", fill: "#b45309", max: 32 }) + T(cx, midY + 4, v.label, { size: 10, anchor: "middle", max: 30 }) + T(cx, midY + 19, (v.confidence || "medium") + " confidence", { size: 10, anchor: "middle", fill: C.mu });
      if (label) out += T(cx, midY - 40, label, { size: 10, anchor: "middle", fill: C.b, max: 30 });
      continue;
    }
    if (crossDev) {
      const via = (prev.next && prev.next.via) || { kind: "direct", label: "next hop" };
      const cx = (x1 + x2) / 2, cw = x2 - x1 - 50;
      const conf = via.confidence || (prev.next && prev.next.confidence) || "high";
      const weak = conf !== "high";
      const lc = weak ? "#d97706" : "#c2410c", ld = weak ? "7 5" : null;
      out += arrow(x1 + 2, midY, cx - cw / 2 - 2, midY, { stroke: lc, dash: ld }) + arrow(cx + cw / 2, midY, x2, midY, { stroke: lc, dash: ld });
      out += T(cx, midY + 66, conf + " confidence" + (weak ? " (inferred)" : ""), { size: 10, anchor: "middle", bold: true, fill: conf === "low" ? C.r : weak ? "#d97706" : C.g });
      if (prev.next && prev.next.basis) out += T(cx, midY + 80, "chosen by: " + prev.next.basis.chosenBy, { size: 9, anchor: "middle", fill: C.mu, max: 34 });
      if (via.kind === "transit" || via.kind === "link" || via.kind === "segment") {
        out += cloud(cx, midY, cw, 74, via.kind === "link" ? "#7c3aed" : lc);
        out += T(cx, midY - 10, via.kind === "transit" ? "ROUTED TRANSIT" : via.kind === "link" ? "USER LINK" : "SHARED SUBNET", { size: 10, bold: true, anchor: "middle", fill: via.kind === "link" ? "#7c3aed" : "#c2410c" });
        const routers = (String(via.label).match(/router [\d.]+/g) || []);
        const first = String(via.label).replace(/^transit /, "").split(" -> ")[0];
        out += T(cx, midY + 5, routers.length ? routers.map((x) => x.replace("router ", "")).join(" \u2192 ") : first, { size: 10.5, anchor: "middle", max: 30 }) + (via.label.indexOf("WAN/MPLS core") >= 0 ? T(cx, midY + 19, "via inferred WAN/MPLS core", { size: 10, anchor: "middle", max: 30, fill: C.mu }) : routers.length ? T(cx, midY + 19, first, { size: 10, anchor: "middle", max: 30, fill: C.mu }) : "");
      } else {
        out += R(cx - cw / 2, midY - 18, cw, 36, { fill: "#fff7ed", stroke: "#c2410c", rx: 18 }) + T(cx, midY + 4, via.label, { size: 10.5, anchor: "middle", max: 26 });
      }
      if (prev.next && prev.next.alternatives && prev.next.alternatives.length > 1) out += T(cx, midY + 80, (prev.next.ambiguous ? "ambiguous: " : "") + prev.next.alternatives.length + " candidate firewalls", { size: 10, anchor: "middle", fill: prev.next.ambiguous ? C.r : C.mu, bold: !!prev.next.ambiguous });
      if (label) out += T(cx, midY - 46, label, { size: 10, anchor: "middle", fill: C.b, max: 30 });
      continue;
    }
    out += arrow(x1 + 2, midY, x2, midY, { stroke: C.mu, dash: prev && segs[i] ? "5 4" : null });
    if (label) out += T((x1 + x2) / 2, midY - 8, label, { size: 10, anchor: "middle", fill: C.b, max: 26 });
  }
  // destination
  const last = segs[segs.length - 1], fx = colX(segs.length + 1);
  const fin = r.final || { kind: "?", text: "" };
  const good = ["delivered", "exit", "local", "next-device"].includes(fin.kind);
  out += R(fx, midY - 40, sW, 80, { fill: good ? C.gb : C.rb, stroke: good ? C.g : C.r, sw: 2 }) + T(fx + 12, midY - 18, "DESTINATION", { size: 11, fill: C.mu, bold: true }) +
    T(fx + 12, midY + 2, last ? last.dstPost : r.query.dst, { size: 14, bold: true, max: 22 }) + T(fx + 12, midY + 20, { delivered: "directly connected", exit: "via next hop", local: "firewall itself", "no-route": "NO ROUTE", drop: "DROPPED" }[fin.kind] || fin.kind, { size: 12, fill: good ? C.g : C.r, bold: true });
  if (last && last.final && last.final.kind === "exit" && last.egress && last.egress.nexthop) out += T(fx + 12, midY + 34, "nh " + last.egress.nexthop, { size: 11, fill: C.mu });
  // legend
  const ly = totalH - 18;
  out += R(PADX, ly - 11, 14, 14, { fill: C.gb, stroke: C.g, rx: 3 }) + T(PADX + 20, ly, "allowed by rule", { size: 11 }) + R(PADX + 130, ly - 11, 14, 14, { fill: C.rb, stroke: C.r, rx: 3 }) + T(PADX + 150, ly, "denied / no rule (change needed)", { size: 11 }) +
    R(PADX + 360, ly - 11, 14, 14, { fill: C.yb, stroke: C.y, rx: 3 }) + T(PADX + 380, ly, "conditional / suggested / inferred route", { size: 11, max: 60 }) + R(PADX + 620, ly - 11, 14, 14, { fill: C.bb, stroke: C.b, rx: 3 }) + T(PADX + 640, ly, "NAT / PBF", { size: 11 });
  return out + "</svg>";
}

function subLines(t) { if (t.length <= 42) return [t]; const parts = t.split(" | "); let a = ""; const out = []; for (const p of parts) { if (a && (a + " | " + p).length > 42) { out.push(a); a = p; } else a = a ? a + " | " + p : p; } if (a) out.push(a); return out.slice(0, 2); }
function envSvg(L) {
  if (!L.shapes.length) return '<p class="muted">Nothing matches.</p>';
  const by = new Map(L.shapes.map((s) => [s.id, s]));
  let o = '<svg xmlns="http://www.w3.org/2000/svg" width="' + Math.round(L.width) + '" height="' + Math.round(L.height) + '" viewBox="0 0 ' + Math.round(L.width) + " " + Math.round(L.height) + '" style="background:#fff">' + DEFS + '<rect width="100%" height="100%" fill="#fff"/>';
  const ord = { site: 0, cloud: 1, fabric: 1, pano: 1, dg: 1, stack: 1, tpl: 1, ghost: 2, fw: 2, vsys: 3, zone: 4, zext: 4 };
  const ES = { wan: ["#d97706", "6 4"], inet: ["#dc2626", null], bgp: ["#16a34a", "3 3"] };
  for (const s of L.shapes.filter((x) => x.kind === "site")) o += '<g><title>' + esc(s.title || "") + "</title>" + R(s.x, s.y, s.w, s.h, { fill: "#f8fafc", stroke: "#94a3b8", dash: "5 4", rx: 10 }) + T(s.x + 10, s.y + 20, s.label, { size: 13, bold: true, max: 60 }) + "</g>";
  Object.assign(ES, { tree: ["#7c3aed", null], dgx: ["#7c3aed", "4 3"], stack: ["#0891b2", null], stackfw: ["#0891b2", "2 4"] });
  for (const e of L.edges.filter((x) => x.dir === "h")) { const a = by.get(e.s), b = by.get(e.t); if (!a || !b) continue; const st = ES[e.kind] || ["#64748b", null];
    const x1 = a.x + a.w, y1 = a.y + Math.min(a.h / 2, 27), x2 = b.x, y2 = b.y + Math.min(b.h / 2, 27), mx = (x1 + x2) / 2;
    o += '<path d="M' + x1 + " " + y1 + " C" + mx + " " + y1 + " " + mx + " " + y2 + " " + x2 + " " + y2 + '" fill="none" stroke="' + st[0] + '" stroke-width="1.2" opacity="' + (e.kind === "stackfw" ? 0.35 : 0.6) + '"' + (st[1] ? ' stroke-dasharray="' + st[1] + '"' : "") + "><title>" + esc(e.kind) + "</title></path>"; }
  for (const e of L.edges.filter((x) => x.dir !== "h")) { const a = by.get(e.s), b = by.get(e.t); if (!a || !b) continue; const st = ES[e.kind] || ["#64748b", null]; o += '<line x1="' + (a.x + a.w / 2) + '" y1="' + a.y + '" x2="' + (b.x + b.w / 2) + '" y2="' + (b.y + b.h) + '" stroke="' + st[0] + '" stroke-width="1.2" opacity="0.55"' + (st[1] ? ' stroke-dasharray="' + st[1] + '"' : "") + "><title>" + esc(e.kind + (e.label ? ": " + e.label : "")) + "</title></line>"; }
  for (const s of L.shapes.filter((x) => x.kind !== "site").sort((a, b) => ord[a.kind] - ord[b.kind])) {
    if (s.kind === "cloud" || s.kind === "fabric") { const col = s.kind === "fabric" ? "#16a34a" : s.id === "inet" || s.id.startsWith("circ:") ? "#dc2626" : "#d97706"; const ls = s.label.split("\n"); o += cloud(s.x + s.w / 2, s.y + s.h / 2, s.w, s.h, col) + ls.map((l, i) => T(s.x + s.w / 2, s.y + s.h / 2 + 4 + (i - (ls.length - 1) / 2) * 14, l, { size: i ? 10 : 12, bold: !i, anchor: "middle", max: 34 })).join(""); continue; }
    if (s.kind === "fw") { o += '<g class="mnode" data-unit="' + esc(s.unit) + '" style="cursor:pointer"><title>' + esc(s.label + (s.sub ? " - " + s.sub : "") + " (click: expand/collapse, double-click: detail diagram)") + "</title>" + R(s.x, s.y, s.w, s.h, { fill: s.warn ? C.yb : C.bb, stroke: s.warn ? C.y : C.b, sw: 1.6, rx: 7 }) + T(s.x + 8, s.y + 18, (s.expanded ? "\u25be " : "\u25b8 ") + s.label, { size: 12, bold: true, max: 34 }) + subLines(s.sub || "").map((l, i) => T(s.x + 8, s.y + 33 + i * 12, l, { size: 9.5, fill: s.warn && i ? C.y : C.mu, max: 44 })).join("") + "</g>"; continue; }
    if (s.kind === "pano") { o += R(s.x, s.y, s.w, s.h, { fill: "#1e3a8a", stroke: "#1e3a8a", rx: 10 }) + T(s.x + s.w / 2, s.y + 30, "Panorama " + s.label, { size: 13, bold: true, anchor: "middle", fill: "#fff", max: 26 }) + T(s.x + s.w / 2, s.y + 50, s.sub, { size: 10, anchor: "middle", fill: "#dbeafe", max: 34 }); continue; }
    if (s.kind === "dg" || s.kind === "stack") { const col = s.kind === "dg" ? ["#f3e8ff", "#7c3aed"] : ["#ecfeff", "#0891b2"]; o += '<g opacity="' + (s.dim ? 0.5 : 1) + '"><title>' + esc(s.label + " - " + (s.sub || "")) + "</title>" + R(s.x, s.y, s.w, s.h, { fill: col[0], stroke: s.warn ? C.y : col[1], sw: s.warn ? 2 : 1.3, rx: 6 }) + T(s.x + 8, s.y + 17, s.label, { size: 11, bold: true, max: 26 }) + T(s.x + 8, s.y + 32, s.sub || "", { size: 9.5, fill: C.mu, max: 30 }) + "</g>"; continue; }
    if (s.kind === "tpl") { o += '<g opacity="' + (s.dim ? 0.55 : 1) + '">' + R(s.x, s.y, s.w, s.h, { fill: "#fff", stroke: "#0891b2", rx: 3 }) + T(s.x + 6, s.y + 14, s.label, { size: 9.5, max: 28 }) + "</g>"; continue; }
    if (s.kind === "ghost") { o += "<g><title>" + esc(s.label + " - " + s.sub) + "</title>" + R(s.x, s.y, s.w, s.h, { fill: "#f8fafc", stroke: "#94a3b8", dash: "4 3", rx: 7 }) + T(s.x + 8, s.y + 18, s.label, { size: 11, bold: true, fill: C.mu, max: 34 }) + T(s.x + 8, s.y + 34, s.sub, { size: 9, fill: C.mu, max: 44 }) + "</g>"; continue; }
    if (s.kind === "vsys") { o += R(s.x, s.y, s.w, s.h, { fill: C.sgb, stroke: C.sg, rx: 3 }) + T(s.x + 5, s.y + 13, s.label, { size: 10, bold: true, max: 38 }); continue; }
    o += R(s.x, s.y, s.w, s.h, { fill: s.kind === "zext" ? C.yb : "#fff", stroke: s.kind === "zext" ? C.y : C.bd, rx: 4 }) + T(s.x + 5, s.y + 11, s.label, { size: 9.5, bold: true, max: 40 }) + (s.lines || []).map((l, i) => T(s.x + 9, s.y + 23 + i * 13, l, { size: 9, fill: C.tx, max: 42 })).join("");
  }
  return o + "</svg>";
}


const render = { C, DEVCOL, DEFS, trunc, T, R, arrow, cloud, subLines, flowSvg, envSvg };
FM.render = render;
if (typeof module !== "undefined" && module.exports) module.exports = render;
})(typeof window !== "undefined" ? window : globalThis);
