/* PAN-OS FlowMapper: Decommission tab (offline). Depends on window.FM, FM.decom (decom.js) and window.__FM (app.js). */
(function () {
"use strict";
const FM = window.FM, D = FM && FM.decom, APP = window.__FM;
if (!D || !APP) return;
const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const TIP = { exact: "The object or value IS the target. Pre-selected.", likely: "Built for the target but not identical. Tick it to include it.", possible: "The target only falls inside something broader. Advice only: never selected, never deleted." };

const tabs = $("#tabs");
const btn = document.createElement("button");
btn.dataset.tab = "decom"; btn.textContent = "Decommission";
const raw = tabs && tabs.querySelector('[data-tab="raw"]');
if (tabs) tabs.insertBefore(btn, raw || null);
const sec = document.createElement("section");
sec.id = "tab-decom"; sec.className = "tab"; sec.hidden = true;
sec.innerHTML = '<div class="card"><h2 style="margin-top:0">Decommission</h2>' +
  '<p class="muted">Find every reference to a retired server, subnet, FQDN, object or rule, and get a safe plan. Every finding is graded: ' +
  '<span class="dc-tier exact">Exact</span> (pre-selected), <span class="dc-tier likely">Highly likely</span> (one click) and <span class="dc-tier possible">Possible</span> (advice only). ' +
  'A broad object such as a /16 is never deleted because one host inside it is retired. Nothing leaves this browser.</p>' +
  '<form id="dc-form"><label for="dc-items"><b>What is being decommissioned?</b> One per line: IP, subnet, range, FQDN, object, group or rule name.</label>' +
  '<textarea id="dc-items" rows="4" style="width:100%;font-family:monospace" placeholder="10.50.1.25&#10;app01.example.test"></textarea>' +
  '<fieldset class="dc-intent"><legend><b>Intent</b></legend><label><input type="radio" name="dc-mode" value="remove" checked> <b>Remove references</b>: the server is retired; clean it out of rules, groups and objects.</label><br>' +
  '<label><input type="radio" name="dc-mode" value="block"> <b>Stop traffic</b>: make sure nothing still allows it; find every rule that would still let it through and add a narrow deny above the first one in each place.</label></fieldset>' +
  '<div id="dc-flows-wrap" hidden><label for="dc-flows"><b>Flows to stop</b> (one per line: <code>source destination tcp/443</code>, or paste an FCR CSV)</label>' +
  '<textarea id="dc-flows" rows="3" style="width:100%;font-family:monospace" placeholder="10.1.1.10 10.50.1.25 tcp/443"></textarea></div>' +
  '<div class="ctl"><button class="primary" type="submit">Analyze</button><span class="muted" id="dc-status"></span></div></form></div>' +
  '<div id="dc-out"></div>';
const main = $("main"), foot = main && main.querySelector(".foot");
if (main) main.insertBefore(sec, foot || null);
function show() {
  $$(".tab").forEach((t) => (t.hidden = t.id !== "tab-decom"));
  $$("#tabs button").forEach((b) => b.classList.toggle("on", b === btn));
}
btn.addEventListener("click", show);
$$('input[name="dc-mode"]').forEach((r) => r.addEventListener("change", () => { $("#dc-flows-wrap").hidden = mode() !== "block"; }));
function mode() { const r = $('input[name="dc-mode"]:checked'); return r ? r.value : "remove"; }

let last = null;
function cfgs() { return APP.state.files.filter((f) => f.enabled !== false).map((f) => f.loaded); }
function flows() {
  const t = $("#dc-flows").value.trim();
  if (!t) return [];
  const p = FM.parseFcr(t);
  return (p.rows || []).map((r) => ({ src: r.src, dst: r.dst, proto: r.proto || "tcp", port: r.port }));
}
function run(select) {
  const c = cfgs();
  if (!c.length) { $("#dc-status").textContent = "Load a config first."; return; }
  const items = $("#dc-items").value;
  if (!items.trim()) { $("#dc-status").textContent = "Type at least one item."; return; }
  const t0 = performance.now();
  try {
    last = D.analyze(c, { targets: items, mode: mode(), flows: flows() }, { devices: APP.state.devices, select });
  } catch (e) { $("#dc-status").textContent = "Failed: " + e.message; return; }
  $("#dc-status").textContent = "Done in " + Math.round(performance.now() - t0) + " ms.";
  render();
}
$("#dc-form").addEventListener("submit", (e) => { e.preventDefault(); run(); });
function picked() { return $$("#dc-out input[data-id]:checked").map((x) => x.dataset.id); }

function blast(b) {
  if (!b) return "";
  return [b.otherAddresses ? Number(b.otherAddresses).toLocaleString("en-US") + " other addresses" : "", b.rules ? b.rules + " rule" + (b.rules === 1 ? "" : "s") : "", b.groups ? b.groups + " group" + (b.groups === 1 ? "" : "s") : "", b.members ? b.members + " member" + (b.members === 1 ? "" : "s") : ""].filter(Boolean).join(", ");
}
function render() {
  const r = last, c = r.counts, o = [];
  o.push('<div class="card"><div class="dc-sum"><span class="dc-tier exact">' + c.exact + " exact</span> <span class=\"dc-tier likely\">" + c.likely + " highly likely</span> <span class=\"dc-tier possible\">" + c.possible + " possible</span> &middot; " + c.selected + " selected &middot; " + c.actions + " change" + (c.actions === 1 ? "" : "s") + " in the plan" + (r.block ? " &middot; " + c.fixesSelected + " deny rule" + (c.fixesSelected === 1 ? "" : "s") : "") + "</div>");
  o.push('<div class="ctl"><button id="dc-csv">Export CSV</button><button id="dc-md">Export Markdown</button><button id="dc-cli">Copy set commands</button><button id="dc-rb">Copy rollback</button></div>');
  for (const t of r.targets) if (!t.matches || t.error) o.push('<div class="note warn">' + esc(t.raw) + ": " + esc(t.error || "not found in the loaded config") + "</div>");
  o.push("</div>");
  for (const tier of ["exact", "likely", "possible"]) {
    const list = r.candidates.filter((x) => x.tier === tier);
    if (!list.length) continue;
    o.push('<div class="card"><h3><span class="dc-tier ' + tier + '">' + esc(D.TIER_LABEL[tier]) + "</span> " + list.length + ' <small class="muted">' + esc(TIP[tier]) + "</small></h3>");
    o.push('<table class="data"><thead><tr><th></th><th>Kind</th><th>Name</th><th>Where</th><th>Why</th><th>Blast radius</th></tr></thead><tbody>');
    for (const x of list) {
      const box = x.selectable ? '<input type="checkbox" data-id="' + esc(x.id) + '"' + (x.selected ? " checked" : "") + ' aria-label="Include ' + esc(x.name) + '">' : '<span class="muted" title="Advice only">advice</span>';
      o.push("<tr><td>" + box + "</td><td>" + esc(x.kind) + "</td><td><code>" + esc(x.name) + "</code>" + (x.value && x.value !== x.name ? "<br><span class=\"muted\">" + esc(x.value) + "</span>" : "") + "</td><td>" + esc(x.scopeLabel) + "</td><td>" + esc(x.reason) +
        (x.evidence && x.evidence.length ? '<details><summary class="muted">Evidence</summary><ul>' + x.evidence.map((e) => "<li>" + esc(e) + "</li>").join("") + "</ul></details>" : "") +
        (x.advice ? '<details><summary class="muted">What to do instead</summary><ul>' + x.advice.map((e) => "<li>" + esc(e) + "</li>").join("") + "</ul></details>" : "") + "</td><td>" + esc(blast(x.blast)) + "</td></tr>");
    }
    o.push("</tbody></table></div>");
  }
  if (r.plan.dangers.length) o.push('<div class="card dc-danger"><h3>Dangers called out</h3><ul>' + r.plan.dangers.map((d) => "<li>" + esc(d.text) + "</li>").join("") + "</ul></div>");
  if (r.plan.kept.length) o.push('<div class="card dc-kept"><h3>Kept (still in use)</h3><ul>' + r.plan.kept.map((d) => "<li>" + esc(d.text) + "</li>").join("") + "</ul></div>");
  o.push('<div class="card"><h3>Plan, in push order</h3>' + (r.plan.actions.length ? '<p class="muted">Edits come before deletes; child device groups before parents; shared objects last, and only when nothing uses them any more.</p><table class="data"><thead><tr><th>#</th><th>Change</th><th>Name</th><th>Where</th><th>Tier</th><th>CLI</th></tr></thead><tbody>' +
    r.plan.actions.map((a) => "<tr" + (a.danger ? ' class="dc-row-danger"' : "") + "><td>" + a.seq + "</td><td>" + esc(a.op) + "</td><td><code>" + esc(a.name) + "</code></td><td>" + esc(a.scopeLabel) + "</td><td>" + esc(a.tierLabel) + '</td><td><pre class="cli">' + esc(a.cli.join("\n")) + "</pre></td></tr>").join("") + "</tbody></table>" : '<p class="muted">Nothing selected yet.</p>') + "</div>");
  if (r.block) {
    const b = r.block;
    o.push('<div class="card"><h3>Stop traffic</h3>' + b.notes.map((n) => '<p class="muted">' + esc(n) + "</p>").join(""));
    for (const f of b.flows) {
      o.push("<p><b>" + esc(f.flow.src + " to " + f.flow.dst + " " + f.flow.proto + (f.flow.port != null ? "/" + f.flow.port : "")) + "</b>: " + f.places.length + " place" + (f.places.length === 1 ? "" : "s") + " on the path check security policy.</p>");
      if (f.places.length) o.push('<table class="data"><thead><tr><th>Place</th><th>Firewall</th><th>Zones</th><th>After this plan</th><th>First rule that still allows it</th></tr></thead><tbody>' + f.places.map((p) => "<tr><td>" + p.n + "</td><td>" + esc(p.device + " " + p.vsys) + "</td><td>" + esc(p.fromZone + " to " + p.toZone) + '</td><td><span class="dc-after ' + p.after + '">' + esc(p.after) + "</span></td><td>" + (p.permits[0] ? esc(p.permits[0].rule + " (" + p.permits[0].grade + ")") : "-") + "</td></tr>").join("") + "</tbody></table>");
      for (const n of f.notes) o.push('<p class="note warn">' + esc(n) + "</p>");
    }
    if (b.stillAllows.length) o.push('<details open><summary><b>Rules that would still allow it</b> (' + b.stillAllowsTotal + ')</summary><table class="data"><thead><tr><th>Grade</th><th>Rule</th><th>Where</th><th>Why</th></tr></thead><tbody>' + b.stillAllows.map((s) => '<tr><td><span class="dc-grade ' + s.grade + '">' + esc(s.grade) + "</span></td><td><code>" + esc(s.rule) + "</code></td><td>" + esc(s.scopeLabel || s.device + " " + s.vsys + " " + s.fromZone + " to " + s.toZone) + "</td><td>" + esc(s.reasons.join("; ")) + "</td></tr>").join("") + "</tbody></table></details>");
    if (b.fixes.length) o.push("<h4>Deny rules (one for each place that would still allow it)</h4>" + b.fixes.map((f) => '<div class="dc-fix"><label><input type="checkbox" data-id="' + esc(f.id) + '"' + (f.selected ? " checked" : "") + "> <code>" + esc(f.rule.name) + "</code> in " + esc(f.scopeLabel + " " + f.rulebase) + "</label><p class=\"muted\">" + esc(f.why + (f.manual ? " " + f.manual : "")) + '</p><pre class="cli">' + esc(f.cli.concat(["# check:"], f.tests).join("\n")) + "</pre></div>").join(""));
    o.push("</div>");
  }
  if (r.notes.length) o.push('<div class="card"><h3>Notes</h3><ul>' + r.notes.map((n) => "<li>" + esc(n.text) + "</li>").join("") + "</ul></div>");
  $("#dc-out").innerHTML = o.join("");
  $$("#dc-out input[data-id]").forEach((x) => x.addEventListener("change", () => run(picked())));
  const dl = (name, text, type) => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500); };
  const copy = (text) => { if (navigator.clipboard) navigator.clipboard.writeText(text).catch(() => {}); $("#dc-status").textContent = "Copied " + text.split("\n").filter(Boolean).length + " lines."; };
  $("#dc-csv").addEventListener("click", () => dl("decommission-plan.csv", D.toCsv(last), "text/csv"));
  $("#dc-md").addEventListener("click", () => dl("decommission-plan.md", D.toMarkdown(last), "text/markdown"));
  $("#dc-cli").addEventListener("click", () => copy(D.cliText(last, "apply")));
  $("#dc-rb").addEventListener("click", () => copy(D.cliText(last, "rollback")));
}

// help topic
const help = $("#help");
if (help) {
  const d = document.createElement("details");
  d.innerHTML = "<summary><b>Decommission: what Exact, Highly likely and Possible mean</b></summary>" +
    "<p><b>In plain words:</b> type the server's IP (or name), pick <i>Remove references</i> if it is gone for good or <i>Stop traffic</i> if you only need it blocked, and click Analyze. The tool lists every place the config mentions it and sorts them into three piles. Exact ones are already ticked. Highly likely ones need you to tick them. Possible ones are only advice: the tool will never delete a shared subnet like a /16 because one server inside it is retired.</p>" +
    "<p><b>Technical detail:</b></p><ul>" +
    "<li><b>Exact (100%)</b>: same host, prefix, range or FQDN; the object, group or rule with that exact name; a literal in a rule equal to the target; a group left empty once its exact members go.</li>" +
    "<li><b>Highly likely</b>: a /30, /31 or range of up to 4 addresses holding the target; a /28 or smaller whose name or description names it; an object entirely inside a retired subnet; a group named for it whose members all point at it; a NAT rule translating to it; an object only used by a rule being deleted.</li>" +
    "<li><b>Possible</b>: the target only falls inside something broader (a /24, a /16, any) or overlaps it. Shown with its blast radius (other addresses, rules and groups) and what to do instead: leave it, carve it out as its own change, or use Stop traffic.</li>" +
    "<li><b>Never 'any'</b>: if removing the target would empty a rule's source or destination, PAN-OS would treat the field as 'any'. The plan deletes the rule instead when every member was exact, otherwise disables it, and says so in red.</li>" +
    "<li><b>Order</b>: rule edits, then rule deletes, then group edits, then group deletes (outer first), then objects; child device groups before parents; shared objects last and only when nothing in the export still uses them.</li>" +
    "<li><b>Stop traffic</b>: traces each flow, checks every place on the path with the plan applied, grades each rule that would still allow it (definite, likely, possible), and adds a narrow deny directly above the first one in each place, with <code>test security-policy-match</code> to prove it.</li></ul>";
  help.appendChild(d);
}
})();
