#!/usr/bin/env node
/* Site roles, scope (Production only), DR mirror advisory, Panorama HA pair. Synthetic configs only (samples/generate_scope.mjs). */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FM = require(path.join(ROOT, "build/core.js"));
let failed = 0, passed = 0;
function ok(c, msg) { if (c) { passed++; console.log("  ok  :", msg); } else { failed++; console.error("  FAIL:", msg); } }
const load = (n) => { const L = FM.loadConfig(fs.readFileSync(path.join(ROOT, "samples", n), "utf8"), n); return { L, devs: L.panorama.contexts.map((c) => FM.buildPanoramaDevice(L, c)) }; };
const { L: LA, devs } = load("panorama-prod-dr-a.xml");
const { L: LB, devs: devsB } = load("panorama-prod-dr-b.xml");
const host = (d) => d.hostname || d.name;
const by = (ds, h) => ds.find((d) => host(d) === h);
const Q = (s, d, p) => ({ src: s, dst: d, proto: "tcp", port: p || 443 });
const roleBy = (ds, prof) => { const m = FM.roleModel(ds, prof); return Object.fromEntries(ds.map((d) => [host(d), m.byDev.get(d).role])); };

console.log("\n== role guess: generic words only, with a plain reason ==");
{
  const r = roleBy(devs, {});
  ok(r["dc1-prod-fw01"] === "production" && r["dc1-prod-fw02"] === "production", "prod in the hostname guesses Production");
  ok(r["dc2-dr-fw01"] === "dr" && r["dc2-dr-fw02"] === "dr", "dr in the hostname guesses DR");
  ok(r["lab-fw01"] === "lab", "lab guesses Lab");
  ok(r["hq-fw01"] === "other", "no words at all: Other (not hidden by a guess)");
  const m = FM.roleModel(devs, {});
  const why = m.byDev.get(by(devs, "dc2-dr-fw01")).why;
  ok(/hostname "dc2-dr-fw01" contains "dr"/.test(why) && /template stack/.test(why) && /device group/.test(why), "the reason names the hostname, stack and device group that matched: " + why.slice(0, 80) + "...");
  ok(/Not guessed/.test(m.byDev.get(by(devs, "hq-fw01")).why) && m.byDev.get(by(devs, "hq-fw01")).source === "default", "an unguessed firewall says so and how to fix it");
  ok(m.sites.map((s) => s.id + ":" + s.role).join() === "dc1-prod:production,dc2-dr:dr,hq:other,lab:lab", "sites: " + m.sites.map((s) => s.id + ":" + s.role).join(", "));
  // tokens from a stack alone; weak words only count from stack / device group, never a hostname
  const x = devs.map((d) => d); const t = by(x, "hq-fw01"); const keep = [t.hostname, t.stack];
  t.hostname = "hq-secondary-fw01"; ok(roleBy(x, {})["hq-secondary-fw01"] === "other", "'secondary' in a hostname is an HA unit label, not DR");
  t.hostname = keep[0]; t.stack = "ST-HQ-SECONDARY"; FM.invalidateCaches(x); ok(roleBy(x, {})[host(t)] === "dr", "'secondary' in a template stack name is a weak DR clue"); t.stack = keep[1]; FM.invalidateCaches(x);
}

console.log("\n== overrides: per site, per firewall, extra words, custom roles, saved profile ==");
{
  const p = { sites: { "dc2-dr": "test" }, devices: { "009970000004": "production" } };
  let r = roleBy(devs, p);
  ok(r["dc2-dr-fw01"] === "test" && r["dc2-dr-fw02"] === "production", "site setting applies to the site; a firewall setting beats it");
  const m = FM.roleModel(devs, p);
  ok(m.byDev.get(by(devs, "dc2-dr-fw01")).source === "site setting" && m.byDev.get(by(devs, "dc2-dr-fw02")).source === "firewall setting", "the source says whose decision it was");
  r = roleBy(devs, { sites: { hq: "dr" } }); ok(r["hq-fw01"] === "dr", "an unguessed site can be marked DR by hand");
  const cp = { roles: [{ id: "standby", label: "Standby", focus: false, mirror: true }], tokens: { standby: ["warm"] }, devices: { "009970000006": "standby" } };
  r = roleBy(devs, cp); ok(r["hq-fw01"] === "standby", "a custom role can be assigned");
  const ds2 = devs.slice(); const h = by(ds2, "hq-fw01"); const old = h.hostname; h.hostname = "warm-fw01";
  r = roleBy(ds2, { roles: cp.roles, tokens: cp.tokens }); ok(r["warm-fw01"] === "standby", "extra words you add are used by the guess"); h.hostname = old; FM.invalidateCaches(ds2);
  const sc = FM.scopeDevices(devs, { roles: cp.roles, devices: cp.devices, scope: { mode: "production" } });
  ok(sc.hidden.some((d) => host(d) === "hq-fw01") === true, "custom role with focus=false is hidden by Production only");
  const sc2 = FM.scopeDevices(devs, { roles: [{ id: "standby", label: "Standby", focus: true }], devices: cp.devices, scope: { mode: "production" } });
  ok(!sc2.hidden.some((d) => host(d) === "hq-fw01"), "custom role with focus=true stays in Production only");
  const withRules = FM.normalizeProfile({ roles: cp.roles, tokens: cp.tokens, sites: { x1: "dr" }, devices: { s1: "lab" }, scope: { mode: "custom", sites: ["x1"] }, rules: [{ field: "stack", match: "contains", value: "ST-LAB", role: "lab" }, { field: "nope", value: "x", role: "dr" }, { field: "hostname", op: "word", value: "hq", role: "production" }] });
  const rt = FM.normalizeProfile(JSON.parse(JSON.stringify(withRules)));
  ok(rt.sites.x1 === "dr" && rt.devices.s1 === "lab" && rt.scope.mode === "custom" && rt.roles[0].id === "standby" && rt.tokens.standby[0] === "warm" && rt.rules.length === 2 && rt.rules[0].field === "stack" && rt.rules[0].match === "contains" && rt.rules[1].match === "word" && Array.isArray(FM.normalizeProfile({}).rules) && FM.normalizeProfile({}).rules.length === 0, "export then import keeps everything, including matching rules; old files get an empty rules list");
  const junk = FM.normalizeProfile({ sites: { a: "nonsense" }, scope: { mode: "bogus" }, roles: "x", tokens: 5 });
  ok(junk.scope.mode === "production" && !junk.sites.a && Array.isArray(junk.roles), "junk in an imported file is ignored, not trusted");
  ok(FM.normalizeProfile(null).scope.mode === "production", "default scope is Production only");
  ok(JSON.stringify(FM.parseScopeArg("production")) === '{"mode":"production","sites":[]}' && FM.parseScopeArg("all").mode === "all" && FM.parseScopeArg("sites=a, b").sites.join() === "a,b", "--scope production | all | sites=a,b");
  let bad = false; try { FM.parseScopeArg("everything"); } catch (e) { bad = /Unknown scope/.test(e.message); } ok(bad, "an unknown --scope value is an error, not a silent default");
}

console.log("\n== scope: what Production only leaves out ==");
{
  const sc = FM.scopeDevices(devs, { scope: { mode: "production" } });
  ok(sc.hiddenCount === 3 && sc.visibleCount === 3 && sc.byRole.dr === 2 && sc.byRole.lab === 1, "3 hidden: 2 DR, 1 Lab");
  ok(sc.chip === "Scope: Production only, 3 firewalls hidden (2 DR, 1 Lab)", "chip: " + sc.chip);
  { const only = devs.filter((d) => ["dc2-dr-fw01", "dc2-dr-fw02", "lab-fw01"].includes(host(d)));
    const e = FM.scopeDevices(only, { scope: { mode: "production" } });
    ok(e.devices === only && e.hiddenCount === 0 && e.noneFocus && /found no production firewalls, so all 3 firewalls are shown/.test(e.chip), "Production only that would leave nothing shows everything and says so: " + e.chip);
    const e2 = FM.scopeDevices(only, { scope: { mode: "custom", sites: ["dc2-dr"] } }); ok(!e2.noneFocus && e2.visibleCount === 2, "the fallback never applies to a custom set"); }
  ok(FM.scopeDevices(devs, { scope: { mode: "all" } }).devices === devs && FM.scopeDevices(devs, { scope: { mode: "all" } }).chip.includes("nothing hidden"), "All sites: the same list, nothing hidden");
  ok(FM.scopeDevices(devs, { scope: { mode: "custom", sites: ["dc2-dr", "hq"] } }).devices.map(host).sort().join() === "dc2-dr-fw01,dc2-dr-fw02,hq-fw01", "custom set: exactly the sites you choose");
  ok(FM.scopeDevices(devs, { scope: { mode: "production" } }) === sc, "same scope returns the cached result (no rebuild)");
  // tracing
  const prodAll = FM.traceScoped(devs, { scope: { mode: "all" } }, Q("10.10.1.5", "10.20.1.5"), {});
  const prodOnly = FM.traceScoped(devs, { scope: { mode: "production" } }, Q("10.10.1.5", "10.20.1.5"), {});
  ok(prodAll.final.kind === "delivered" && prodAll.segments.length === 2, "All sites: the flow crosses a production and a DR firewall");
  ok(prodOnly.segments.length === 1 && prodOnly.final.kind === "exit", "Production only: the trace stops at the production firewall");
  const v = prodOnly.scope.viaHidden;
  ok(v && v.devices.length === 1 && /dc2-dr-fw01 \(DR\)/.test(v.text) && /only completes through/.test(v.text) && /All sites/.test(v.text), "says the path needs a hidden DR firewall instead of failing silently");
  ok(prodOnly.notes[0].level === "warn" && prodOnly.notes[0].text === v.text, "that message is also the first note on the result");
  ok(prodAll.scope.viaHidden === undefined, "no warning when nothing is hidden");
  // switching back and forth keeps each answer (inferred routes are restored per list)
  const again = FM.traceScoped(devs, { scope: { mode: "all" } }, Q("10.10.1.5", "10.20.1.5"), {});
  ok(again.segments.length === prodAll.segments.length && again.final.kind === "delivered", "going back to All sites gives the same trace as before");
  // shared addresses: the picker only offers production firewalls
  const hqAll = FM.traceScoped(devs, { scope: { mode: "all" } }, Q("10.30.1.5", "10.10.1.5"), {});
  const hqProd = FM.traceScoped(devs, { scope: { mode: "production" } }, Q("10.30.1.5", "10.10.1.5"), {});
  ok(hqAll.pathStatus.status === "incomplete" && hqAll.sharedChoices.length === 1 && hqAll.sharedChoices[0].candidates.length === 2, "All sites: the shared 10.250.0.2 address needs a choice between the production and the DR firewall");
  ok(hqProd.pathStatus.status === "complete" && !hqProd.sharedChoices.length && hqProd.segments.map((s) => s.device).join() === "009970000006,009970000001", "Production only: the picker is gone and the production firewall is the next hop");
  ok(!JSON.stringify(hqProd.pathStatus).includes("dc2-dr") && !JSON.stringify(hqProd.pathStatus).includes("009970000003"), "alternates and hops never mention the DR firewall");
  // HA inference
  ok(FM.haGroups(devs).groups.length === 0 && FM.haGroups(sc.devices).groups.length === 0, "look-alike production and DR firewalls are never paired as HA");
  const cl = load("panorama-cloned-dc.xml").devs, dc2 = cl.find((d) => host(d) === "core-dc2-fw");
  const scc = FM.scopeDevices(cl, { devices: { [dc2.serial]: "dr" }, scope: { mode: "production" } });
  ok(scc.hiddenCount === 1 && FM.getGraph(scc.devices, []).ha.groups.length === 0, "hiding one of three look-alikes never makes the other two an HA pair");
  // replay, maps
  const rp = FM.replayCases(sc.devices, {}), rpAll = FM.replayCases(devs, {});
  ok(rp.cases.length > 0 && rp.cases.length < rpAll.cases.length && rp.cases.every((c) => !JSON.stringify(c).includes("009970000003") && !JSON.stringify(c).includes("009970000004")), "replay: " + rp.cases.length + " of " + rpAll.cases.length + " cases, none on a DR firewall");
  const vm = FM.vsysMap(sc.devices, {}), vmAll = FM.vsysMap(devs, {});
  ok(JSON.stringify(vm).indexOf("009970000003") < 0 && JSON.stringify(vmAll).indexOf("009970000003") >= 0, "vsys map and diagrams leave DR out");
}

console.log("\n== DR mirror advisory ==");
{
  const prof = { scope: { mode: "production" } };
  const r1 = FM.traceScoped(devs, prof, Q("198.51.100.7", "10.10.1.10"), {});
  const m1 = FM.drMirror(r1, devs, prof);
  ok(m1.items.length === 1 && m1.items[0].candidates[0].display === "dc2-dr-fw01" && m1.items[0].candidates[0].level === "likely", "a rule on a production firewall: the DR counterpart is listed as likely");
  ok(m1.items[0].candidates[0].reasons.some((x) => /template stack/.test(x)) && m1.items[0].candidates[0].reasons.some((x) => /same zones/.test(x)) && m1.items[0].candidates[0].addrNote && /different subnets/.test(m1.items[0].candidates[0].addrNote), "reasons name the stack, zones, and warn that the DR subnets differ");
  ok(!m1.devices.includes("dc2-dr-fw02") && !m1.devices.includes("hq-fw01") && !m1.devices.includes("lab-fw01"), "unrelated DR, lab and unclassified firewalls are not suggested");
  ok(/DR copy likely needed on dc2-dr-fw01/.test(m1.text) && /not traced/.test(m1.text), "plain sentence: " + m1.text);
  const r2 = FM.traceScoped(devs, prof, Q("198.51.100.7", "10.11.1.10"), {});
  const m2 = FM.drMirror(r2, devs, prof);
  ok(m2.viaDg.join() === "dc2-dr-fw02" && m2.items[0].candidates[0].level === "automatic" && /share a device group|shares a device group/.test(m2.text) && !/DR copy likely needed/.test(m2.text), "a shared device group is called out: the rule reaches DR on its own");
  ok(FM.drMirror(r1, devs, { mirror: { enabled: false } }).items.length === 0, "optional: switched off gives nothing");
  ok(FM.drMirror(FM.traceScoped(devs, prof, Q("10.10.1.5", "10.20.1.5"), {}), devs, prof).items.length === 0, "no production change: no advisory");
  const mProd2 = FM.drMirror(r1, devs, { devices: { "009970000003": "production" } });
  ok(mProd2.items.length === 0 || !mProd2.devices.includes("dc2-dr-fw01"), "a firewall you marked Production is not a DR copy target");
}

console.log("\n== Panorama HA pair: separate from firewall scope ==");
{
  ok(LA.panorama.ha && LA.panorama.ha.peerIp === "10.2.250.1" && LA.panorama.ha.ownIp === "10.1.250.1" && LA.panorama.ha.priority === "primary", "this Panorama's own HA settings are read");
  ok(LB.panorama.ha.peerIp === "10.1.250.1" && LB.panorama.ha.priority === "secondary", "the other peer's export reads the mirror image");
  const ja = roleBy(devs, {}), jb = roleBy(devsB, {});
  ok(JSON.stringify(ja) === JSON.stringify(jb), "firewall roles are identical from either Panorama peer's export");
  const sa = FM.scopeDevices(devs, {}), sb = FM.scopeDevices(devsB, {});
  ok(sa.chip === sb.chip && sa.hidden.map(host).join() === sb.hidden.map(host).join(), "the scope result is identical from either export");
  const ta = FM.traceScoped(devs, {}, Q("198.51.100.7", "10.10.1.10"), {}), tb = FM.traceScoped(devsB, {}, Q("198.51.100.7", "10.10.1.10"), {});
  ok(JSON.stringify(ta.changes.map((c) => c.summary)) === JSON.stringify(tb.changes.map((c) => c.summary)), "plans are identical from either export");
  const pa = FM.panoramaPair(LA.panorama, {}), pb = FM.panoramaPair(LB.panorama, {});
  ok(pa.this.key === "ip:10.1.250.1" && pa.peer.key === "ip:10.2.250.1" && pb.this.key === pa.peer.key && pb.peer.key === pa.this.key, "the pair is keyed by HA address, so a role set from one export applies when the other is loaded");
  const saved = { panoramas: { "ip:10.1.250.1": { role: "production", state: "active" }, "ip:10.2.250.1": { role: "dr", state: "passive" } } };
  const qa = FM.panoramaPair(LA.panorama, saved), qb = FM.panoramaPair(LB.panorama, saved);
  ok(qa.this.role === "production" && qa.this.state === "active" && qa.peer.role === "dr" && qb.this.role === "dr" && qb.peer.role === "production" && qb.this.state === "passive", "roles and Active/Passive set once show on both exports");
  ok(pa.this.role === "production" && /hostname contains "prod"/.test(pa.this.roleWhy) && pb.this.role === "dr", "the Panorama's own role is guessed from its hostname, separately from firewalls");
  ok(FM.scopeDevices(devs, saved).hiddenCount === 3, "Panorama roles never change which firewalls are in scope");
  ok(devs.every((d) => !d.ha || !d.ha.peers.includes("10.2.250.1")), "the Panorama HA peer address is never read as a firewall HA peer");
}


console.log("\n== routing/rules conflict that only appears because the scope hid the routed next hop ==");
{
  const loadFw = (n) => FM.loadConfig(fs.readFileSync(path.join(ROOT, "samples/scope-conflict", n), "utf8"), n).devices;
  const all = ["core-prod-fw.xml", "site-dr-fw.xml", "alt-prod-fw.xml", "app-prod-fw.xml"].flatMap(loadFw);
  const q = Q("10.10.1.50", "10.30.1.10");
  const prof = { scope: { mode: "production" } };
  const sc = FM.scopeDevices(all, prof);
  ok(sc.hiddenCount === 1 && host(sc.hidden[0]) === "site-dr-fw", "Production only hides the one DR firewall");
  const allRes = FM.trace(all, q, {});
  ok((allRes.pathStatus && allRes.pathStatus.status) === "complete" && !allRes.conflict, "with every firewall, the path is complete and routing agrees with the rules");
  const prodRes = FM.traceScoped(all, prof, q, {});
  ok(!!prodRes.conflict, "with the DR firewall hidden, routing and rules now disagree");
  ok(prodRes.conflict.scopeCause === "hidden-routed-hop", "the cause is the hidden routed next hop, not a stale-rule count: " + prodRes.conflict.scopeCause);
  ok(/hid site-dr-fw \(DR\)/.test(prodRes.conflict.scopeText) && /not, by itself, a stale rule/.test(prodRes.conflict.scopeText), "the notice names the hidden firewall and says this is not, by itself, a stale rule");
  ok(prodRes.scope && prodRes.scope.scopeConflict && prodRes.scope.scopeConflict.cause === "hidden-routed-hop", "attachScope records the same cause on res.scope");
  // replay + summary split the count so a batch run is not mistaken for a wave of stale rules
  const cases = [{ key: "t", rule: "allow-lan-core", scope: "vsys1", kind: "concrete", src: q.src, dst: q.dst, proto: "tcp", port: 443, from: ["lan"], to: ["core"], instances: all.filter((d) => host(d) === "core-prod-fw").map((d) => ({ devId: d.id, device: d.name, vsys: "vsys1" })) }];
  const onAll = FM.replayCase(all, cases[0], {});
  const onProd = FM.replayCase(sc.devices, cases[0], { scope: sc });
  ok(!onAll.conflict, "the same flow is not a conflict when every firewall is included");
  ok(onProd.conflict && onProd.scopeCause === "hidden-routed-hop", "replayCase carries scopeCause when opts.scope is set");
  const sum = FM.replaySummary([onProd, onAll]);
  ok(sum.conflicts === 1 && sum.conflictsHiddenHop === 1 && sum.conflictsGenuine === 0, "summary: 1 conflict, all from a hidden routed hop, none genuine");
  const dropped = { cat: onProd.cat, conflict: onProd.conflict, res: onProd.res };
  ok(FM.replaySummary([dropped]).conflictsHiddenHop === 0 && FM.replaySummary([dropped]).conflictsGenuine === 1, "replaySummary reads r.scopeCause on the result object, not res.conflict.scopeCause");
  const kept = { cat: onProd.cat, conflict: onProd.conflict, res: onProd.res, scopeCause: onProd.scopeCause };
  ok(FM.replaySummary([kept]).conflictsHiddenHop === 1 && FM.replaySummary([kept]).conflictsGenuine === 0, "wrappers (Validate, scope-report) must pass scopeCause through");
}

console.log("\n== user-defined matching rules (first match wins; firewall > site > rule > guess) ==");
{
  const rules = [
    { field: "stack", match: "contains", value: "DC2-DR", role: "dr" },
    { field: "stack", match: "contains", value: "PROD", role: "production" },
    { field: "hostname", match: "word", value: "hq-fw01", role: "production" }
  ];
  const m = FM.roleModel(devs, { rules });
  const r = roleBy(devs, { rules });
  ok(r["dc2-dr-fw01"] === "dr" && r["dc2-dr-fw02"] === "dr" && m.byDev.get(by(devs, "dc2-dr-fw01")).source === "rule", "stack contains DC2-DR assigns DR and the source is rule");
  ok(/Rule 1: template stack contains "DC2-DR"/.test(m.byDev.get(by(devs, "dc2-dr-fw01")).why), "the reason is 'rule 1: template stack contains ...': " + m.byDev.get(by(devs, "dc2-dr-fw01")).why);
  ok(r["dc1-prod-fw01"] === "production" && r["dc1-prod-fw02"] === "production" && m.byDev.get(by(devs, "dc1-prod-fw01")).source === "rule", "stack contains PROD assigns Production");
  ok(r["hq-fw01"] === "production" && m.byDev.get(by(devs, "hq-fw01")).source === "rule", "whole-word hostname match assigns Production to the unclassified firewall");
  ok(r["lab-fw01"] === "lab" && m.byDev.get(by(devs, "lab-fw01")).source === "guess", "a firewall no rule matches still uses the generic guess");

  // first match wins: a later rule would also set hq to lab, but the earlier production rule already claimed it
  const order = FM.roleModel(devs, { rules: [{ field: "hostname", match: "contains", value: "hq", role: "production" }, { field: "stack", match: "contains", value: "HQ", role: "lab" }] });
  ok(order.byDev.get(by(devs, "hq-fw01")).role === "production" && /Rule 1:/.test(order.byDev.get(by(devs, "hq-fw01")).why), "first match wins over a later overlapping rule");

  // priority: firewall setting > site setting > rule > guess
  const pri = roleBy(devs, { rules, sites: { hq: "test" }, devices: { "009970000003": "lab" } });
  ok(pri["dc2-dr-fw01"] === "lab", "a per-firewall override beats a matching rule");
  ok(pri["hq-fw01"] === "test", "a per-site override beats a matching rule");
  ok(pri["dc1-prod-fw01"] === "production", "a rule still applies when neither override is set");

  // match kinds
  ok(roleBy(devs, { rules: [{ field: "hostname", match: "contains", value: "DC2-DR", role: "other" }] })["dc2-dr-fw01"] === "other", "contains is case-insensitive");
  ok(roleBy(devs, { rules: [{ field: "hostname", match: "word", value: "dc", role: "other" }] })["dc2-dr-fw01"] === "dr", "whole word does not match inside a longer token (dc vs dc2)");
  ok(roleBy(devs, { rules: [{ field: "hostname", match: "word", value: "dc2-dr-fw01", role: "other" }] })["dc2-dr-fw01"] === "other", "whole word matches the exact hostname token");
  ok(roleBy(devs, { rules: [{ field: "stack", match: "regex", value: "ST-DC2-DR(-2)?$", role: "test" }] })["dc2-dr-fw01"] === "test" && roleBy(devs, { rules: [{ field: "stack", match: "regex", value: "ST-DC2-DR(-2)?$", role: "test" }] })["dc2-dr-fw02"] === "test", "regex match");
  ok(roleBy(devs, { rules: [{ field: "stack", match: "regex", value: "[", role: "test" }] })["dc2-dr-fw01"] === "dr", "an invalid regex matches nothing and the guess remains");
  ok(roleBy(devs, { rules: [{ field: "serial", match: "contains", value: "009970000006", role: "test" }] })["hq-fw01"] === "test", "serial field");
  ok(roleBy(devs, { rules: [{ field: "site", match: "contains", value: "dc1-prod", role: "lab" }] })["dc1-prod-fw01"] === "lab", "site id field");
  ok(roleBy(devs, { rules: [{ field: "dg", match: "contains", value: "DG-HQ", role: "test" }] })["hq-fw01"] === "test", "device group field");
  ok(roleBy(devs, { rules: [{ field: "name", match: "contains", value: "ST-LAB", role: "test" }] })["lab-fw01"] === "test", "any name field sees the template stack");

  const prev = FM.rulePreview(devs, { rules: [
    { field: "stack", match: "contains", value: "DC2-DR", role: "dr" },
    { field: "hostname", match: "contains", value: "dc2-dr-fw01", role: "lab" },
    { field: "stack", match: "contains", value: "zzzz-no-such", role: "production" },
    { field: "stack", match: "contains", value: "", role: "production" },
    { field: "stack", match: "regex", value: "[", role: "production" }
  ] });
  ok(prev.rules[0].count === 2 && prev.rules[0].devices.every((x) => /dc2-dr-fw0[12]/.test(x.label)), "preview: first rule matches 2 firewalls and names them");
  ok(prev.rules[1].count === 1 && prev.rules[1].overlapCount === 1 && prev.rules[1].overlap[0].earlier === 1, "preview: later overlapping rule is flagged against the earlier one");
  ok(/matches nothing/.test(prev.rules[2].warning) && /no text/.test(prev.rules[3].warning) && /invalid regular expression/.test(prev.rules[4].warning), "preview warns when a rule matches nothing, is empty, or has a bad regex");

  const sc = FM.scopeDevices(devs, { rules: [{ field: "hostname", match: "contains", value: "hq", role: "dr" }], scope: { mode: "production" } });
  ok(sc.hidden.some((d) => host(d) === "hq-fw01") && sc.byRole.dr === 3, "Production only hides a firewall a rule marked DR");
}

console.log("\n== no site-specific names in the guess logic ==");
{
  const core = fs.readFileSync(path.join(ROOT, "build/core.js"), "utf8");
  const sec = core.slice(core.indexOf("/* SCOPE:BEGIN */"), core.indexOf("/* SCOPE:END */"));
  ok(sec.length > 5000, "found the scope section (" + sec.length + " chars)");
  const allowed = { production: "prod,prd,production", dr: "dr,drc,cob,bcp,backup,bkp,failover,recovery,disaster", lab: "lab,labs,sandbox,poc", test: "test,tst,qa,uat,dev,stage,staging,stg,preprod" };
  ok(Object.keys(allowed).every((k) => FM.ROLE_TOKENS[k].join() === allowed[k]) && Object.keys(FM.ROLE_TOKENS).length === 4, "the built-in word list is exactly the generic list (adding a word here must be a deliberate change)");
  ok(JSON.stringify(FM.ROLE_WEAK_TOKENS) === '{"production":["primary"],"dr":["secondary","standby"]}', "weak words are generic too");
  // invented site names must never be guessed as anything
  const fake = ["ab1", "xyz", "qq-site", "north", "east2", "hq", "branch7", "zed"].map((n) => FM.roleHits(n + "-fw01", {}, false).length + FM.roleHits(n, {}, true).length);
  ok(fake.every((x) => x === 0), "made-up site names produce no role clue");
  // no known city / customer names anywhere we ship (checked by hash so the names are not in this file)
  const bad = new Set(["6b9cd7872ae634539ea1a99e1c4c16b41c9314c99192560ecf9c4bb846647655", "037d390cd4ef796e5d75407fa72cc4708aa8a1ba3c36ed88db6fd3a441b68503"]);
  const hits = [];
  const walk = (dir) => { for (const f of fs.readdirSync(dir, { withFileTypes: true })) { if (f.name.startsWith(".") || f.name === "node_modules") continue; const p = path.join(dir, f.name); if (f.isDirectory()) walk(p); else if (/\.(js|mjs|cjs|html|md|css|json|py|xml|txt)$/.test(f.name)) { const t = fs.readFileSync(p, "utf8"); for (const w of new Set(t.toLowerCase().split(/[^a-z]+/))) if (w.length === 3 && bad.has(crypto.createHash("sha256").update(w).digest("hex"))) hits.push(path.relative(ROOT, p)); } } };
  walk(ROOT);
  ok(hits.length === 0, "no customer site names in code, tests, samples or docs" + (hits.length ? ": " + hits.join(", ") : ""));
}
console.log("\n" + passed + " passed, " + failed + " failed");
process.exit(failed ? 1 : 0);
