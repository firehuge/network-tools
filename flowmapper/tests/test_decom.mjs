#!/usr/bin/env node
/* SPDX-License-Identifier: Apache-2.0 */
/* Decommission engine (build/decom.js): tiers, plan safety, ordering and stop-traffic mode.
 * Synthetic configs only (samples/generate_decom.mjs and the small inline firewall below). */
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FM = require(path.join(ROOT, "build/core.js"));
const D = require(path.join(ROOT, "build/decom.js"));
let failed = 0, passed = 0;
function ok(c, msg) { if (c) { passed++; console.log("  ok  :", msg); } else { failed++; console.error("  FAIL:", msg); } }
const loadFile = (n) => FM.loadConfig(fs.readFileSync(path.join(ROOT, "samples", n), "utf8"), n);
const devicesOf = (cfg) => cfg.panorama ? cfg.panorama.contexts.filter((c) => c.mapped).map((c) => FM.buildPanoramaDevice(cfg, c)) : cfg.devices;
const run = (cfg, targets, extra, opts) => D.analyze([cfg], Object.assign({ targets, mode: "remove" }, extra || {}), Object.assign({ devices: devicesOf(cfg) }, opts || {}));
const cand = (r, kind, name, scopeHas) => r.candidates.find((c) => c.kind === kind && c.name === name && (!scopeHas || c.scopeLabel.includes(scopeHas)));
const act = (r, op, name, scopeHas) => r.plan.actions.find((a) => a.op === op && a.name === name && (!scopeHas || a.scopeLabel.includes(scopeHas)));

console.log("\n== targets ==");
{
  const t = D.parseTargets("10.50.1.25\n10.50.1.0/24, 10.1.1.1-10.1.1.9; app01.example.test\nGRP-APP01\n10.50.1.25");
  ok(t.map((x) => x.kind).join() === "ip,ip,ip,fqdn,name", "IP, subnet, range, FQDN and name are told apart; duplicates dropped");
  ok(D.parseTarget("10.0.0.300").kind === "invalid", "bad address is reported, not guessed");
}

console.log("\n== tiers on a messy Panorama export ==");
const pano = loadFile("panorama-decom-messy.xml");
let r = run(pano, ["10.50.1.25"]);
ok(cand(r, "address", "app01", "DG-CORP").tier === "exact" && cand(r, "address", "app01", "DG-DC").tier === "exact", "same host in two device groups: both exact (duplicates found)");
ok(cand(r, "address", "H-10.50.1.25", "shared").tier === "exact", "/32 object in shared is exact");
ok(cand(r, "literal", "10.50.1.25").tier === "exact", "host typed straight into a rule is exact");
ok(cand(r, "address", "P2P-app01").tier === "likely", "/30 holding the host is highly likely (4 addresses)");
ok(cand(r, "address", "NET-APP01-POOL").tier === "likely", "/28 whose name mentions the host's object is highly likely");
ok(cand(r, "address", "NET-APPS-24").tier === "possible" && cand(r, "address", "NET-APPS-10.50.0.0_16").tier === "possible" && cand(r, "address", "SH-WIDE-10.0.0.0_8").tier === "possible", "/24, /16 and /8 containing the host are possible only");
ok(cand(r, "literal", "10.50.0.0/16").tier === "possible", "/16 typed in a rule is possible only");
ok(r.candidates.filter((c) => c.tier === "possible").every((c) => !c.selectable && !c.selected && c.advice && c.advice.length), "possible items are never selectable and always carry advice");
ok(r.candidates.filter((c) => c.selected).every((c) => c.tier === "exact"), "only exact items are pre-selected");
ok(cand(r, "address", "NET-APPS-10.50.0.0_16").blast.otherAddresses === 65535, "blast radius counts the other addresses a broad object covers");
ok(cand(r, "rule", "NAT-APP01-VIP").tier === "likely", "NAT rule translating to the host is highly likely");
ok(cand(r, "negated-field", "R-NEGATE").tier === "likely" && !cand(r, "negated-field", "R-NEGATE").selected, "a negated field holding the host is highly likely, not pre-selected");

console.log("\n== the plan never deletes broad objects and never leaves 'any' ==");
const touched = new Set(r.plan.actions.map((a) => a.name));
for (const n of ["NET-APPS-24", "NET-APPS-10.50.0.0_16", "SH-WIDE-10.0.0.0_8", "NET-APP01-POOL", "P2P-app01", "R-LITERAL-WIDE", "R-APPS-BROAD"]) ok(!touched.has(n), n + " untouched");
ok(act(r, "delete-rule", "R-ALLOW-APP01-ONLY") && r.plan.dangers.some((d) => d.rule === "R-ALLOW-APP01-ONLY" && /any/.test(d.text)), "rule whose only destination was the host is deleted, with an 'any' danger callout");
ok(!r.plan.actions.some((a) => a.op === "edit-rule" && Object.values(a.remaining).some((x) => !x.length)), "no edit ever leaves an empty address field");
ok(act(r, "edit-rule", "R-MIXED").remaining.destination.includes("app02"), "mixed rule keeps its other members");
ok(act(r, "edit-group", "GRP-WEB-SERVERS").remaining.join() === "app02", "group with other members is edited, not deleted");
ok(act(r, "delete-group", "GRP-APP01") && act(r, "delete-group", "GRP-ONLY-NESTED") && act(r, "edit-group", "GRP-NESTED-OUTER"), "nested groups: emptied ones cascade, outer group keeps its other members");
ok(!act(r, "delete-address", "app01", "DG-CORP") && r.plan.kept.some((k) => /app01/.test(k.text) && /NAT-APP01-VIP/.test(k.text)), "object still used by NAT and a negated field is kept, with the reason");
ok(act(r, "delete-address", "app01", "DG-DC") && act(r, "delete-address", "H-10.50.1.25", "shared"), "unreferenced duplicates and shared object deleted");
ok(r.notes.some((n) => n.code === "shared-objects"), "shared deletes carry a note about firewall-local rules");
ok(!act(r, "edit-rule", "R-NEGATE"), "negated field is not edited unless picked");

console.log("\n== ordering ==");
const seq = (op, name, sc) => (act(r, op, name, sc) || {}).seq;
ok(r.plan.actions.every((a, i, l) => !i || ["edit-rule", "disable-rule", "delete-rule", "edit-group", "delete-group", "delete-address"].indexOf(l[i - 1].op) <= ["edit-rule", "disable-rule", "delete-rule", "edit-group", "delete-group", "delete-address"].indexOf(a.op)), "edits before deletes; rules, then groups, then objects");
ok(seq("delete-group", "GRP-ONLY-NESTED") < seq("delete-group", "GRP-APP01"), "outer group deleted before the group nested in it");
ok(seq("delete-address", "app01", "DG-DC") < seq("delete-address", "H-10.50.1.25", "shared"), "child device group before shared");
ok(r.plan.actions.every((a) => a.cli.length && a.rollback.length), "every action has CLI and rollback");

console.log("\n== selecting highly likely items ==");
const ids = r.candidates.filter((c) => c.selected).map((c) => c.id).concat([cand(r, "rule", "NAT-APP01-VIP").id, cand(r, "negated-field", "R-NEGATE").id]);
let r2 = run(pano, ["10.50.1.25"], null, { select: ids });
ok(act(r2, "delete-rule", "NAT-APP01-VIP") && act(r2, "edit-rule", "R-NEGATE"), "picking the NAT rule and the negated field adds them to the plan");
ok(act(r2, "delete-address", "app01", "DG-CORP"), "once nothing uses it, the DG-CORP object is deleted");
ok(r2.plan.dangers.some((d) => d.code === "negated-field"), "negated-field edit carries a danger callout");
let r3 = run(pano, ["10.50.1.25"], null, { select: [] });
ok(r3.plan.actions.length === 0, "empty selection: empty plan");

console.log("\n== names, FQDNs and rules as targets ==");
let rn = run(pano, ["app01.example.test", "OLD-APP01-RULE"]);
ok(cand(rn, "address", "app01-fqdn").tier === "exact", "FQDN object with the same FQDN is exact");
ok(cand(rn, "rule", "OLD-APP01-RULE").tier === "exact" && act(rn, "delete-rule", "OLD-APP01-RULE"), "rule named directly is exact and deleted");
ok(cand(rn, "address", "OLD-ONLY-OBJ") && cand(rn, "address", "OLD-ONLY-OBJ").tier === "likely", "object used only by that rule is highly likely");

console.log("\n== stop traffic ==");
let rb = run(pano, ["10.50.1.25"], { mode: "block", flows: [{ src: "10.1.1.10", dst: "10.50.1.25", proto: "tcp", port: 443 }] });
const f0 = rb.block.flows[0];
ok(f0.places.length === 2, "two places on the path check policy");
ok(f0.places.every((p) => p.after === "allowed" && p.permits[0].rule === "R-APPS-BROAD"), "after the plan, the /16 rule still allows it in both places (redundant permit found)");
ok(rb.block.stillAllows.some((s) => s.rule === "DC-ALLOW-APPS-24"), "every other rule that would still allow it is listed");
ok(rb.block.fixes.length === 2 && rb.block.fixes.every((f) => f.selected && /DG-CORP/.test(f.scopeLabel) && f.cli.some((c) => /before R-APPS-BROAD/.test(c))), "one deny per place, above the first permitting rule, in the right device group");
ok(rb.block.fixes.every((f) => f.tests.some((t) => /^test security-policy-match/.test(t)) && f.cli.some((c) => /target devices/.test(c))), "each deny is targeted to its firewall and comes with a policy-match test");
ok(rb.block.fixes.every((f) => f.rule.destination.join() === "10.50.1.25" && f.rule.source.join() === "10.1.1.10"), "deny is narrow: exact source and destination");
ok(!rb.plan.actions.some((a) => a.name === "R-APPS-BROAD"), "the broad permit itself is left alone");
let rbs = run(pano, ["10.50.1.25"], { mode: "block", flows: [{ src: "10.1.1.10", dst: "10.50.1.25", proto: "tcp", port: 443 }] }, { select: [] });
ok(rbs.block.fixes.every((f) => !f.selected), "deny rules can be un-picked like any item");

console.log("\n== firewall backup, dynamic group ==");
const fw = loadFile("fw-single-vsys.xml");
let rf = run(fw, ["172.16.10.20"], { mode: "block", flows: [{ src: "10.10.0.5", dst: "172.16.10.20", proto: "tcp", port: 443 }] });
ok(rf.notes.some((n) => n.code === "dynamic-groups"), "dynamic group use is called out (runtime IPs are not in the config)");
ok(rf.block.fixes.length === 1 && rf.block.fixes[0].cli.some((c) => /^set rulebase security rules DECOM-DENY/.test(c)), "local firewall deny uses the vsys rulebase");

console.log("\n== exports ==");
const csv = D.toCsv(r), md = D.toMarkdown(rb), cli = D.cliText(rb, "apply"), rbk = D.cliText(rb, "rollback");
ok(/^section,/.test(csv) && csv.split("\n").length > r.candidates.length, "CSV has a header and one line per finding and action");
ok(/## Exact/.test(md) && /## Stop traffic/.test(md), "Markdown has tier sections and the stop-traffic section");
ok(/DECOM-DENY/.test(cli) && /delete device-group DG-CORP pre-rulebase security rules DECOM-DENY/.test(rbk), "set commands and rollback cover the deny rules");
const evil = D.toCsv({ candidates: [{ tierLabel: "x", kind: "address", scopeLabel: "s", name: "=cmd()", reason: "r" }], plan: { actions: [], dangers: [], kept: [] }, notes: [] });
ok(!/,=cmd/.test(evil), "CSV neutralises formula injection");

console.log("\n" + passed + " passed, " + failed + " failed");
process.exit(failed ? 1 : 0);
