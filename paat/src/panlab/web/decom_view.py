# SPDX-License-Identifier: Apache-2.0
"""Decommission plan page: findings by tier with checkboxes, red callouts, the plan in push order, stop traffic.

Exact items are pre-ticked. Highly likely items need one click. Possible items are advice only (no checkbox):
a broader object such as a /16 is never changed because one host inside it is retired. Changing the
selection rebuilds the plan with the shared engine and resets any approval.
"""

from __future__ import annotations

import html

from panlab.decom import TIER_LABEL, iter_actions

e = html.escape
_TONE = {"exact": "success", "likely": "warning", "possible": "info"}
_TIP = {
    "exact": "The object or value IS the target. Pre-selected.",
    "likely": "Built for the target but not identical. Tick it to include it.",
    "possible": "The target only sits inside something broader. Advice only: never selected, never changed.",
}


def _blast(b: dict | None) -> str:
    b = b or {}
    parts = []
    if b.get("otherAddresses"):
        parts.append(f"{int(b['otherAddresses']):,} other addresses")
    if b.get("rules"):
        parts.append(f"{b['rules']} rule" + ("" if b["rules"] == 1 else "s"))
    if b.get("groups"):
        parts.append(f"{b['groups']} group" + ("" if b["groups"] == 1 else "s"))
    if b.get("members"):
        parts.append(f"{b['members']} member" + ("" if b["members"] == 1 else "s"))
    return ", ".join(parts)


def _details(summary: str, lines: list[str] | None) -> str:
    if not lines:
        return ""
    return f"<details><summary class='muted'>{e(summary)}</summary><ul>" + "".join(f"<li>{e(x)}</li>" for x in lines) + "</ul></details>"


def plan_html(cs: dict, customer: str, stem: str, can_edit: bool) -> str:
    d = cs.get("decom") or {}
    s = cs.get("summary") or {}
    t = s.get("tiers") or {}
    c, st = e(customer), e(stem)
    mode = d.get("mode") or "remove"
    out = [f"<h2>Decommission plan <span class='muted'>({'stop traffic' if mode == 'block' else 'remove references'})</span></h2>"]
    out.append("<div class='card'><p>" + theme_badge(f"{t.get('exact', 0)} exact", "success") + " "
               + theme_badge(f"{t.get('likely', 0)} highly likely", "warning") + " "
               + theme_badge(f"{t.get('possible', 0)} possible", "info")
               + f" &middot; {s.get('selected', 0)} selected &middot; {sum(1 for _ in iter_actions(cs))} changes in the plan"
               + (f" &middot; {s.get('deny_rules', 0)} deny rules" if mode == "block" else "") + "</p>"
               "<p class='muted'>Exact items are pre-selected. Highly likely items need one click. Possible items are advice only: "
               "a broader object (like a /16) is never changed because one host inside it is retired. "
               "Changing what is ticked rebuilds the plan and resets any approval.</p>"
               f"<p><a href='/changesets/{c}/{st}/decom.csv'>CSV</a> &middot; <a href='/changesets/{c}/{st}.md'>Markdown</a> &middot; "
               f"<a href='/changesets/{c}/{st}/decom.cli'>Set commands</a> &middot; <a href='/changesets/{c}/{st}/decom-rollback.cli'>Rollback</a></p></div>")
    for u in cs.get("unresolved") or []:
        out.append(f"<div class='note warn'><b>{e(u.get('item') or '')}</b>: {e(u.get('reason') or '')}</div>")

    form_open = f"<form method='post' action='/decom/{c}/{st}/select'>" if can_edit else "<div>"
    form_close = ("<div class='toolbar'><button class='btn' type='submit'>Rebuild plan with this selection</button>"
                  "<span class='muted'>Resets approval.</span></div></form>") if can_edit else "</div>"
    out.append(form_open)
    cands = d.get("candidates") or []
    for tier in ("exact", "likely", "possible"):
        lst = [x for x in cands if x.get("tier") == tier]
        if not lst:
            continue
        out.append(f"<div class='card'><h3>{theme_badge(TIER_LABEL[tier], _TONE[tier])} {len(lst)} "
                   f"<span class='muted' style='font-weight:normal'>{e(_TIP[tier])}</span></h3>")
        out.append("<div class='tablewrap'><table><tr><th>Pick</th><th>Kind</th><th>Name</th><th>Where</th><th>Why</th><th>Blast radius</th></tr>")
        for x in lst:
            if x.get("selectable"):
                box = (f"<input type='checkbox' name='pick' value='{e(x['id'])}'" + (" checked" if x.get("selected") else "")
                       + ("" if can_edit else " disabled") + f" aria-label='Include {e(x.get('name') or '')}'>")
            else:
                box = "<span class='muted' title='Advice only'>advice</span>"
            val = x.get("value")
            name = f"<code>{e(x.get('name') or '')}</code>" + (f"<br><span class='muted'>{e(str(val))}</span>" if val and val != x.get("name") else "")
            why = e(x.get("reason") or "") + _details("Evidence", x.get("evidence")) + _details("What to do instead", x.get("advice"))
            out.append(f"<tr><td>{box}</td><td>{e(x.get('kind') or '')}</td><td>{name}</td><td>{e(x.get('scopeLabel') or '')}</td>"
                       f"<td>{why}</td><td>{e(_blast(x.get('blast')))}</td></tr>")
        out.append("</table></div></div>")
    fixes = d.get("fixes") or []
    if fixes:
        out.append("<div class='card'><h3>Deny rules (one for each place that would still allow the traffic)</h3>")
        for f in fixes:
            out.append("<div class='card' style='margin:8px 0'><label><input type='checkbox' name='pick' value='" + e(f["id"]) + "'"
                       + (" checked" if f.get("selected") else "") + ("" if can_edit else " disabled") + "> "
                       f"<code>{e(f.get('name') or '')}</code> in {e(f.get('scopeLabel') or '')} {e(f.get('rulebase') or '')}"
                       + (f" for {e(f.get('device') or '')}" if f.get("device") else "") + "</label>"
                       f"<p class='muted'>{e((f.get('why') or '') + (' ' + f['manual'] if f.get('manual') else ''))}</p>"
                       "<pre>" + e("\n".join((f.get("cli") or []) + ["# check:"] + (f.get("tests") or []))) + "</pre></div>")
        out.append("</div>")
    out.append(form_close)

    reds = [f for f in cs.get("flags") or [] if f.get("level") == "red"]
    if reds:
        out.append("<div class='card' style='border-left:4px solid var(--danger)'><h3>Red flags and dangers</h3><ul>"
                   + "".join(f"<li>{e(f['message'])}</li>" for f in reds) + "</ul></div>")
    kept = [f for f in cs.get("flags") or [] if f.get("code") == "kept"]
    if kept:
        out.append("<div class='card' style='border-left:4px solid var(--warning)'><h3>Kept (still in use)</h3><ul>"
                   + "".join(f"<li>{e(f['message'])}</li>" for f in kept) + "</ul></div>")
    other = [f for f in cs.get("flags") or [] if f.get("level") == "yellow" and f.get("code") != "kept"]
    if other:
        out.append("<div class='card'><h3>Notes</h3><ul>" + "".join(f"<li>{e(f['message'])}</li>" for f in other) + "</ul></div>")

    rows = []
    for _, a in iter_actions(cs):
        loc = a.get("location") or {}
        where = "shared" if loc.get("kind") == "shared" else (f"device group {loc['device_group']}" if loc.get("device_group") else
                                                              f"{loc.get('device') or ''}/{loc.get('vsys') or ''}")
        cls = " class='red'" if a.get("flag") == "red" else ""
        rows.append(f"<tr{cls}><td>{a.get('seq')}</td><td>{e(a['op'])}</td><td><code>{e(a.get('name') or '')}</code></td><td>{e(where)}</td>"
                    f"<td>{e(a.get('tierLabel') or '')}</td><td><pre>{e(chr(10).join(a.get('cli') or []))}</pre></td></tr>")
    out.append("<div class='card'><h3>Plan, in push order</h3>"
               + ("<p class='muted'>Deny rules first, then rule edits, rule deletes, group edits, group deletes (outer first) and objects; "
                  "child device groups before parents; shared objects last, and only when nothing uses them any more.</p>"
                  "<div class='tablewrap'><table><tr><th>#</th><th>Change</th><th>Name</th><th>Where</th><th>Tier</th><th>CLI</th></tr>"
                  + "".join(rows) + "</table></div>" if rows else "<p class='muted'>Nothing selected yet.</p>") + "</div>")

    blk = d.get("block")
    if blk:
        out.append("<div class='card'><h3>Stop traffic</h3>")
        for f in blk.get("flows") or []:
            fl = f.get("flow") or {}
            out.append(f"<p><b>{e(str(fl.get('src')))} to {e(str(fl.get('dst')))} {e(str(fl.get('proto') or ''))}"
                       f"{'/' + e(str(fl.get('port'))) if fl.get('port') not in (None, '') else ''}</b>: "
                       f"{len(f.get('places') or [])} place(s) on the path check security policy.</p>")
            if f.get("places"):
                out.append("<div class='tablewrap'><table><tr><th>Place</th><th>Firewall</th><th>Zones</th><th>After this plan</th><th>First rule that still allows it</th></tr>")
                for p in f["places"]:
                    tone = {"allowed": "danger", "maybe": "warning", "denied": "success"}.get(p.get("after"), "neutral")
                    first = p["permits"][0] if p.get("permits") else None
                    out.append(f"<tr><td>{p.get('n')}</td><td>{e(str(p.get('device')))} {e(str(p.get('vsys') or ''))}</td>"
                               f"<td>{e(str(p.get('fromZone')))} to {e(str(p.get('toZone')))}</td><td>{theme_badge(p.get('after') or '', tone)}</td>"
                               f"<td>{e(first['rule'] + ' (' + first['grade'] + ')') if first else '-'}</td></tr>")
                out.append("</table></div>")
        sa = blk.get("stillAllows") or []
        if sa:
            out.append(f"<details open><summary><b>Rules that would still allow it</b> ({blk.get('stillAllowsTotal') or len(sa)})</summary>"
                       "<div class='tablewrap'><table><tr><th>Grade</th><th>Rule</th><th>Where</th><th>Why</th></tr>")
            for x in sa:
                tone = {"definite": "danger", "likely": "warning", "possible": "info"}.get(x.get("grade"), "neutral")
                where = x.get("scopeLabel") or f"{x.get('device')} {x.get('vsys')} {x.get('fromZone')} to {x.get('toZone')}"
                out.append(f"<tr><td>{theme_badge(x.get('grade') or '', tone)}</td><td><code>{e(x.get('rule') or '')}</code></td>"
                           f"<td>{e(str(where))}</td><td>{e('; '.join(x.get('reasons') or []))}</td></tr>")
            out.append("</table></div></details>")
        out.append("</div>")
    return "".join(out)


def theme_badge(text: str, tone: str) -> str:
    from panlab.web import theme
    return theme.badge(text, tone)
