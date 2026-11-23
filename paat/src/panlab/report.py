"""Human-readable change-set reports (Markdown and HTML) and dry-run set commands."""

from __future__ import annotations

import html
import re
import json
from pathlib import Path
from typing import Any

FLAG_ICON = {"red": "RED", "yellow": "YELLOW", "green": "GREEN", "info": "info"}

def _collapse_header(h: str) -> str:
    return re.sub(r"\s+", " ", str(h or "")).strip().replace("|", "/")


def _file_columns_text(f: dict[str, Any]) -> str:
    mapping = f.get("mapping") or {}
    parts = []
    for key in ("source", "destination", "ports", "protocol"):
        if mapping.get(key):
            parts.append(f"{key} ← {_collapse_header(mapping[key])}")
    return "; ".join(parts) or "-"


def _file_mapping_notes(f: dict[str, Any]) -> list[str]:
    notes = []
    if f.get("standard_template") is False:
        notes.append("non-standard format, check the mapping")
    for n in f.get("mapping_notes") or []:
        if n and n not in notes:
            notes.append(str(n))
    return notes



def _source_lines(cs: dict[str, Any]) -> list[str]:
    from panlab.uploads import source_label
    lab = source_label(cs)
    return [f"**{lab}.** This change set is plan only and cannot be pushed.", ""] if lab else []


def _source_html(cs: dict[str, Any]) -> str:
    from panlab.uploads import PLAN_ONLY, source_label
    lab = source_label(cs)
    if not lab:
        return ""
    e = html.escape
    return (f"<div class='yellow' style='padding:8px 12px;margin:8px 0;border-left:4px solid #8a6d00'>"
            f"<b>{e(lab)}</b>. {e(PLAN_ONLY).capitalize()}.</div>")


def group_title(g: dict[str, Any]) -> str:
    if g["backend"] == "panorama":
        return f"Panorama {g['target']} / device group {g['device_group']} / {g['rulebase']}"
    return f"Firewall {g['device']} / {g['vsys']}"


def _flags(fl: list[dict]) -> str:  # noqa: D401
    return "; ".join(f"{FLAG_ICON[f['level']]}: {f['message']}" for f in fl if f["level"] != "info") or ""


def callouts(g: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(rule, level, message) for every flag including info: routing, app/port, objects, management ports."""
    return [(r["name"], f["level"], f["message"]) for r in g["rules"] for f in r["flags"]]


def to_markdown(cs: dict[str, Any]) -> str:
    if cs.get("kind") == "decommission":
        return _decom_markdown(cs)
    s = cs["summary"]
    out = [f"# Change set for customer `{cs['customer']}`", "",
           f"Created {cs['created']} (America/Chicago). Nothing here has been pushed.", ""] + _source_lines(cs) + [
           "| Requests in | Unique | Placed | Unplaced | Rules | Intrazone (no rule) | New objects | Reused objects | Red flags | Needs a human |",
           "|---|---|---|---|---|---|---|---|---|---|",
           f"| {s['requests_in']} | {s['requests_unique']} | {s['placed']} | {s['unplaced']} | {s['rules']} | {s['skipped_intrazone']} | {s['new_objects']} | {s['reused_objects']} | {s['red_flags']} | {s['needs_human']} |",
           "", f"Confidence: high {s['confidence']['high']}, medium {s['confidence']['medium']}, low {s['confidence']['low']}", ""]
    if cs.get("file_errors"):
        out += ["**Some files could not be imported** and were skipped. The change set includes the files that parsed:", ""]
        out += [f"- {msg}" for msg in cs["file_errors"]]
        out += [""]
    if cs.get("fallback") or any((g.get("suggested_routes") or []) for g in cs.get("groups") or []):
        out += ["These networks are not fully on the firewall yet. The plan below proposes new address objects, "
                "a security rule, and any suggested routes. Confirm next hops and zones before you push. "
                "This is a proposed plan, not a failure.", ""]
    if cs["files"]:
        out += ["## Files", "",
                "| File | Project | Tickets | Rows | Sheet | Header row | Columns |",
                "|---|---|---|---|---|---|---|"]
        for f in cs["files"]:
            tix = f.get("tickets") or {}
            tickets = " / ".join((tix.get("ritm") or []) + (tix.get("sctask") or []) + (tix.get("cr") or [])) or "-"
            sheet = f.get("sheet") or "-"
            header_row = f.get("header_row") if f.get("header_row") is not None else "-"
            cols = _file_columns_text(f)
            notes = _file_mapping_notes(f)
            if notes:
                cols += " — " + "; ".join(f"**{n}**" for n in notes)
            out.append(
                f"| {f.get('file') or ''} | {f.get('project') or ''} | {tickets} | {f.get('rows', '')} "
                f"| {sheet} | {header_row} | {cols} |"
            )
        out.append("")
    for g in cs["groups"]:
        out += [f"## {group_title(g)}", ""]
        if g["rules"]:
            out += ["| Rule | From | To | Source | Destination | App | Service | Tags | Confidence | Flags |", "|---|---|---|---|---|---|---|---|---|---|"]
            for r in g["rules"]:
                src = ", ".join(r["source"] + [f"user:{u}" for u in r["source_user"]])
                kind = {"edit": " (edit existing)", "already-allowed": " (already allowed)"}.get(r.get("operation") or "add", "")
                out.append(f"| {r['name']}{kind} | {', '.join(r['from'])} | {', '.join(r['to'])} | {src} | {', '.join(r['destination'])} | "
                           f"{', '.join(r['application'])} | {', '.join(r['service'])} | {', '.join(r['tags'])} | "
                           f"{r['confidence']}{' (needs human)' if r['needs_human'] else ''} | {_flags(r['flags'])} |")
            out.append("")
            out += ["Why placed here:", ""]
            for r in g["rules"]:
                devs = ", ".join(f"{t['device']}/{t['vsys']}" for t in r["target_devices"])
                out.append(f"- **{r['name']}** on {devs}: " + " || ".join(r["reason"]))
            out.append("")
        if g["skipped"]:
            out += ["No rule needed (intrazone default allow):", ""]
            out += [f"- {x['request']} on {x['device']}/{x['vsys']}: {x['from']} -> {x['to']}" for x in g["skipped"]]
            out.append("")
        co = callouts(g)
        if co:
            out += ["", "**Callouts and advice** (routing, app/port, objects):", ""]
            out += [f"- {lv.upper()} `{rn}`: {m}" for rn, lv, m in co]
            out.append("")
        if g["objects"]["new"] or g["objects"]["reused"]:
            out += ["| Object | Kind | Value | New or reused | Where |", "|---|---|---|---|---|"]
            for o in g["objects"]["new"]:
                val = o.get("value") or (f"{o.get('protocol')}/{o.get('port')}" if o["kind"] == "service" else
                                         (", ".join(o.get("members") or []) if o["kind"] == "address-group" else ""))
                where = o.get("device_group") or o.get("vsys") or o.get("location")
                out.append(f"| {o['name']} | {o['kind']} | {val} | NEW: no existing object matches, will create | {where} |")
            for o in g["objects"]["reused"]:
                out.append(f"| {o['name']} | {o['kind']} | {o.get('value', '')} | EXISTING object matches, will reuse (nothing created) | {o['scope']} |")
            for m in g["objects"].get("near_matches", []):
                out.append(f"| {m['new']} | near-match | {m['existing']} = {m['existing_value']} | CHECK: same IP, different mask; use {m['existing']} if it is the same thing | {m['scope']} |")
            out.append("")
    if cs["unplaced"]:
        title = ("## Pick a target firewall to finish the plan" if cs.get("candidate_firewalls")
                 else "## Not placed yet")
        out += [title, ""]
        if cs.get("candidate_firewalls"):
            out.append("The networks in these requests are not on any firewall yet. Pick a target firewall "
                       f"({', '.join(cs['candidate_firewalls'])}) to build objects, the rule, and route suggestions.")
            out.append("")
        for rq in cs["requests"]:
            if rq["id"] in cs["unplaced"]:
                out.append(f"- {rq['id']} ({', '.join(rq['origins'])}): {_flags(rq['flags']) or 'no placement'}")
        out.append("")
    return "\n".join(out) + "\n"


def to_html(cs: dict[str, Any]) -> str:
    """Minimal standalone HTML rendering of the same report (for the future web GUI)."""
    if cs.get("kind") == "decommission":
        return _decom_html(cs)
    e = html.escape
    s = cs["summary"]
    parts = [f"<!doctype html><html><head><meta charset='utf-8'><title>PAAT change set {e(cs['customer'])}</title>",
             "<style>body{font-family:system-ui,sans-serif;margin:24px}table{border-collapse:collapse;margin:8px 0 20px}"
             "td,th{border:1px solid #ccc;padding:4px 8px;font-size:13px;vertical-align:top}th{background:#f3f3f3}"
             ".red{background:#fde2e2}.yellow{background:#fff6d6}.green{background:#e3f6e8}.new{color:#06c;font-weight:600}</style></head><body>",
             f"<h1>Change set: {e(cs['customer'])}</h1><p>Created {e(cs['created'])} (America/Chicago). Nothing has been pushed.</p>",
             _source_html(cs),
             f"<p>{s['requests_unique']} unique requests, {s['placed']} placed, {s['unplaced']} unplaced; {s['rules']} rules; "
             f"{s.get('skipped_intrazone') or 0} no-rule-needed (intrazone); "
             f"{s['new_objects']} new and {s['reused_objects']} reused objects; {s['red_flags']} red flags.</p>"]
    if cs.get("file_errors"):
        items = "".join(f"<li>{e(m)}</li>" for m in cs["file_errors"])
        parts.append(
            "<div class='yellow' style='padding:8px 12px;margin:8px 0;border-left:4px solid #8a6d00'>"
            "<b>Some files could not be imported</b> and were skipped. The change set includes the files that parsed."
            f"<ul style='margin:8px 0 0'>{items}</ul></div>"
        )
    if cs.get("fallback") or any((g.get("suggested_routes") or []) for g in cs.get("groups") or []):
        parts.append(
            "<div class='yellow' style='padding:8px 12px;margin:8px 0;border-left:4px solid #8a6d00'>"
            "These networks are not fully on the firewall yet. The plan below proposes new address objects, "
            "a security rule, and any suggested routes. Confirm next hops and zones before you push. "
            "This is a proposed plan, not a failure.</div>"
        )
    if cs.get("files"):
        parts.append(
            "<h2>Files</h2><table><tr><th>File</th><th>Project</th><th>Tickets</th>"
            "<th>Rows</th><th>Sheet</th><th>Header row</th><th>Columns</th></tr>"
        )
        for f in cs["files"]:
            tix = f.get("tickets") or {}
            tickets = " / ".join((tix.get("ritm") or []) + (tix.get("sctask") or []) + (tix.get("cr") or [])) or "-"
            sheet = f.get("sheet") or "-"
            header_row = f.get("header_row") if f.get("header_row") is not None else "-"
            cols = e(_file_columns_text(f))
            notes_html = ""
            for n in _file_mapping_notes(f):
                notes_html += (
                    "<div class='yellow' style='padding:6px 8px;margin:6px 0 0;"
                    "border-left:4px solid #8a6d00'>" + e(n) + "</div>"
                )
            parts.append(
                f"<tr><td>{e(f.get('file') or '')}</td><td>{e(str(f.get('project') or ''))}</td>"
                f"<td>{e(tickets)}</td><td>{e(str(f.get('rows', '')))}</td>"
                f"<td>{e(str(sheet))}</td><td>{e(str(header_row))}</td>"
                f"<td>{cols}{notes_html}</td></tr>"
            )
        parts.append("</table>")
    for g in cs["groups"]:
        parts.append(f"<h2>{e(group_title(g))}</h2>")
        if g.get("skipped"):
            parts.append(
                "<div class='yellow' style='padding:8px 12px;margin:8px 0;border-left:4px solid #8a6d00'>"
                "<b>No rule needed (intrazone default allow)</b>. "
                "Both sides resolved to the same zone on a connected or specific route, and the "
                "device-group or vsys intrazone-default action is allow. Confirm this is intended."
                "<ul style='margin:8px 0 0'>"
            )
            for x in g["skipped"]:
                why = e(x.get("why") or "")
                parts.append(
                    f"<li>{e(x['request'])} on {e(x['device'])}/{e(x['vsys'])}: "
                    f"{e(x.get('from') or '?')} -&gt; {e(x.get('to') or '?')}"
                    f"{(' — ' + why) if why else ''}</li>"
                )
            parts.append("</ul></div>")
        if g["rules"]:
            parts.append("<table><tr><th>Rule</th><th>From</th><th>To</th><th>Source</th><th>Destination</th>"
                         "<th>App</th><th>Service</th><th>Tags</th><th>Confidence</th><th>Flags</th></tr>")
            for r in g["rules"]:
                lv = "green" if r.get("operation") == "already-allowed" else "red" if any(f["level"] == "red" for f in r["flags"]) else "yellow" if (r["needs_human"] or any(f["level"] == "yellow" for f in r["flags"])) else ""
                src = r["source"] + [f"user:{u}" for u in r["source_user"]]
                parts.append(f"<tr class='{lv}'><td>{e(r['name'])}</td><td>{e(', '.join(r['from']))}</td><td>{e(', '.join(r['to']))}</td>"
                             f"<td>{e(', '.join(src))}</td><td>{e(', '.join(r['destination']))}</td><td>{e(', '.join(r['application']))}</td>"
                             f"<td>{e(', '.join(r['service']))}</td><td>{e(', '.join(r['tags']))}</td><td>{e(r['confidence'])}</td>"
                             f"<td>{e(_flags(r['flags']))}</td></tr>")
            parts.append("</table>")
        co = callouts(g)
        if co:
            colors = {"red": "#fde2e2", "yellow": "#fff6d6", "green": "#e3f6e8", "info": "#eef6ff"}
            parts.append("<h3>Callouts and advice (routing, app/port, objects)</h3><ul>" + "".join(
                f"<li style='background:{colors.get(lv, '#fff')};padding:2px 6px'><b>{e(lv.upper())}</b> {e(rn)}: {e(m)}</li>"
                for rn, lv, m in co) + "</ul>")
        if g["objects"]["new"] or g["objects"]["reused"]:
            parts.append("<table><tr><th>Object</th><th>Kind</th><th>Value</th><th>Status</th></tr>")
            for o in g["objects"]["new"]:
                val = o.get("value") or (f"{o.get('protocol')}/{o.get('port')}" if o["kind"] == "service" else "")
                parts.append(f"<tr><td>{e(o['name'])}</td><td>{e(o['kind'])}</td><td>{e(str(val))}</td><td class='new'>NEW: no existing object matches, will create</td></tr>")
            for o in g["objects"]["reused"]:
                parts.append(f"<tr style='background:#e7f6e7'><td>{e(o['name'])}</td><td>{e(o['kind'])}</td><td>{e(str(o.get('value', '')))}</td>"
                             f"<td><b>EXISTING object {e(o['name'])} matches, will reuse</b> ({e(o['scope'])}); nothing new is created</td></tr>")
            for m in g["objects"].get("near_matches", []):
                parts.append(f"<tr class='yellow'><td>{e(m['new'])}</td><td>near-match</td><td>{e(m['existing'])} = {e(m['existing_value'])}</td>"
                             f"<td>CHECK: existing {e(m['existing'])} has the same IP with a different mask; use it if it is the same host/network</td></tr>")
            parts.append("</table>")
    if cs["unplaced"]:
        if cs.get("candidate_firewalls"):
            parts.append("<h2>Pick a target firewall to finish the plan</h2>")
            parts.append(
                "<div class='yellow' style='padding:8px 12px;margin:8px 0;border-left:4px solid #8a6d00'>"
                "The networks in these requests are not on any firewall yet. Pick a target firewall "
                f"({e(', '.join(cs['candidate_firewalls']))}) to build objects, the rule, and route suggestions."
                "</div><ul>"
            )
        else:
            parts.append("<h2>Not placed yet</h2><ul>")
        for rq in cs["requests"]:
            if rq["id"] in cs["unplaced"]:
                parts.append(f"<li>{e(rq['id'])} ({e(', '.join(rq['origins']))}): {e(_flags(rq['flags']) or 'no placement')}</li>")
        parts.append("</ul>")
    parts.append("</body></html>")
    return "".join(parts)


def _q(v: str) -> str:
    return f'"{v}"' if any(c in v for c in ' "<>') else v


def _lst(vs: list[str]) -> str:
    vs = [_q(v) for v in vs]
    return vs[0] if len(vs) == 1 else "[ " + " ".join(vs) + " ]"


def set_commands(cs: dict[str, Any]) -> list[str]:
    """PAN-OS 'set' commands a reviewer can read. Dry run only; never sent anywhere by this function."""
    if cs.get("kind") == "decommission":
        from panlab.decom import delete_commands
        return delete_commands(cs)
    out: list[str] = []
    for g in cs["groups"]:
        out.append(f"# {group_title(g)}")
        for o in g["objects"]["new"]:
            if o["location"] == "shared":
                pre = "set shared"
            elif g["backend"] == "panorama":
                pre = f"set device-group {_q(o['device_group'])}"
            else:
                pre = f"set vsys {o['vsys']}" if o.get("multi_vsys") else "set"
            if o["kind"] == "address":
                out.append(f"{pre} address {_q(o['name'])} {o['type']} {o['value']}")
                out.append(f"{pre} address {_q(o['name'])} description {_q(o['description'])}")
            elif o["kind"] == "address-group":
                out.append(f"{pre} address-group {_q(o['name'])} static {_lst(o.get('members') or [])}")
                if o.get("description"):
                    out.append(f"{pre} address-group {_q(o['name'])} description {_q(o['description'])}")
            elif o["kind"] == "service":
                out.append(f"{pre} service {_q(o['name'])} protocol {o['protocol']} port {o['port']}")
            elif o["kind"] == "tag":
                out.append(f"{pre} tag {_q(o['name'])}")
        if g["backend"] == "panorama":
            rb = f"set device-group {_q(g['device_group'])} pre-rulebase security rules"
        else:
            rb = (f"set vsys {g['vsys']} rulebase security rules" if g.get("multi_vsys") else "set rulebase security rules")
        for r in g["rules"]:
            n = _q(r["name"])
            op = r.get("operation") or "add"
            if op == "already-allowed":
                out.append(f"# already allowed by existing rule {r['name']}: no set commands")
                continue
            if op == "edit":
                for ed in r.get("edits") or []:
                    field = ed.get("field")
                    if field in ("source", "destination", "tag") and ed.get("values"):
                        for v in ed["values"]:
                            out.append(f"{rb} {n} {field} {_q(v)}")
                    elif field == "description" and ed.get("value"):
                        out.append(f"{rb} {n} description {_q(ed['value'])}")
                if r.get("needs_human"):
                    out.append(f"# ^ {r['name']} needs a human: fix NEEDS-HUMAN zones or flags before any push")
                continue
            src_user = f" source-user {_lst(r['source_user'])}" if r["source_user"] else ""
            out.append(f"{rb} {n} from {_lst(r['from'])} to {_lst(r['to'])} source {_lst(r['source'] or ['any'])}{src_user} "
                       f"destination {_lst(r['destination'])} application {_lst(r['application'])} service {_lst(r['service'])} "
                       f"action {r['action']} log-end yes tag {_lst(r['tags'])} description {_q(r['description'])}")
            if g["backend"] == "panorama":
                for t in r["target_devices"]:
                    if t.get("serial"):
                        out.append(f"{rb} {n} target devices {t['serial']} vsys {t['vsys']}")
            if r.get("place_before"):
                out.append(f"{rb.replace('set ', 'move ', 1)} {n} before {_q(r['place_before'])}")
            if r["needs_human"]:
                out.append(f"# ^ {r['name']} needs a human: fix NEEDS-HUMAN zones or flags before any push")
        out.append("")
    return out


def write_outputs(cs: dict[str, Any], out_dir: Path, stem: str) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {"json": out_dir / f"{stem}.json", "md": out_dir / f"{stem}.md", "html": out_dir / f"{stem}.html"}
    paths["json"].write_text(json.dumps(cs, indent=2) + "\n", encoding="utf-8")
    paths["md"].write_text(to_markdown(cs), encoding="utf-8")
    paths["html"].write_text(to_html(cs), encoding="utf-8")
    return paths


def _decom_markdown(cs: dict[str, Any]) -> str:
    s = cs["summary"]
    out = [f"# Decommission change set for customer `{cs['customer']}`", "",
           f"Created {cs['created']} (America/Chicago). This is a proposed removal plan. Nothing here has been pushed.", ""] + _source_lines(cs) + [
           f"Items: {s['requests_unique']} unique, {s['placed']} matched, {s['unplaced']} unresolved. "
           f"{s.get('edited_rules', 0)} rules edited, {s.get('deleted_rules', 0)} rules deleted, "
           f"{s.get('edited_groups', 0)} groups edited, {s.get('deleted_groups', 0)} groups deleted, "
           f"{s.get('deleted_objects', 0)} address objects deleted"
           + (f", {s.get('deny_rules', 0)} deny rules added" if s.get("deny_rules") else "")
           + f". {s['red_flags']} red flags, {s.get('dangers', 0)} danger callouts, {s['needs_human']} need a human.", ""]
    t = s.get("tiers")
    if t:
        out += [f"Findings: {t.get('exact', 0)} Exact (100%, pre-selected), {t.get('likely', 0)} Highly likely (selected only when "
                f"ticked), {t.get('possible', 0)} Possible (advice only; a broader object is never changed because one host inside "
                f"it is retired). {s.get('selected', 0)} selected.", ""]
    if cs.get("files"):
        out += ["## Tickets and files", "", "| File | Tickets | Items |", "|---|---|---|"]
        for f in cs["files"]:
            tix = f.get("tickets") or {}
            out.append(f"| {f.get('file')} | {' / '.join((tix.get('ritm') or []) + (tix.get('sctask') or []) + (tix.get('cr') or [])) or '-'} | {f.get('rows', '')} |")
        out.append("")
    if cs.get("items"):
        out += ["## Requested items", "", ", ".join(f"`{i}`" for i in cs["items"]), ""]
    if cs.get("flags"):
        out += ["## Flags", ""]
        out += [f"- **{f['level'].upper()}**: {f['message']}" for f in cs["flags"]]
        out.append("")
    cands = (cs.get("decom") or {}).get("candidates") or []
    if cands:
        out += ["## Findings by tier", "", "| Pick | Tier | Kind | Name | Where | Why |", "|---|---|---|---|---|---|"]
        for c in cands:
            pick = "[x]" if c.get("selected") else ("[ ]" if c.get("selectable") else "advice")
            val = f" {c['value']}" if c.get("value") and c.get("value") != c.get("name") else ""
            out.append(f"| {pick} | {c.get('tierLabel') or c.get('tier')} | {c.get('kind')} | `{c.get('name')}`{val} | "
                       f"{c.get('scopeLabel') or ''} | {(c.get('reason') or '').replace('|', '/')} |")
        out.append("")
    elif cs.get("related"):
        out += ["## Related objects (not selected for removal)", ""]
        for rec in cs["related"]:
            out.append(f"- {rec.get('relation') or rec.get('tier')}: `{rec.get('name')}` = {rec.get('value')} ({rec.get('item') or rec.get('where')})")
        out.append("")
    if cs.get("unresolved"):
        out += ["## Unresolved", ""]
        for u in cs["unresolved"]:
            if isinstance(u, dict):
                out.append(f"- `{u.get('item')}`: {u.get('reason')}")
            else:
                out.append(f"- `{u}`")
        out.append("")
    for g in cs.get("groups") or []:
        out += [f"## {group_title(g)}", ""]
        acts = g.get("actions") or []
        if not acts:
            out.append("No actions in this scope.")
            out.append("")
            continue
        out += ["| Action | Name | Detail |", "|---|---|---|"]
        for a in acts:
            if a["op"] == "edit-rule":
                det = "; ".join(f"remove {f}: {', '.join(vs)}" for f, vs in (a.get("remove") or {}).items())
            elif a["op"] in {"delete-rule", "disable-rule"}:
                det = a.get("reason") or ""
            elif a["op"] == "edit-group":
                det = "remove " + ", ".join(a.get("remove") or [])
            elif a["op"] == "delete-address":
                det = a.get("value") or ""
            elif a["op"] == "add-deny-rule":
                r = a.get("rule") or {}
                det = (f"deny {', '.join(r.get('source') or [])} -> {', '.join(r.get('destination') or [])} "
                       f"{', '.join(r.get('service') or [])}; above {(a.get('place') or {}).get('ref') or '-'}")
            elif a["op"] == "add-service":
                det = f"{a.get('protocol')}/{a.get('port')}"
            else:
                det = a.get("reason") or ""
            out.append(f"| {a['op']} | {a.get('name')} | {det.replace('|', '/')} |")
        out.append("")
    return "\n".join(out) + "\n"


def _decom_html(cs: dict[str, Any]) -> str:
    e = html.escape
    s = cs["summary"]
    parts = [f"<!doctype html><html><head><meta charset='utf-8'><title>PAAT decommission {e(cs['customer'])}</title>",
             "<style>body{font-family:system-ui,sans-serif;margin:24px}table{border-collapse:collapse;margin:8px 0 20px}"
             "td,th{border:1px solid #ccc;padding:4px 8px;font-size:13px;vertical-align:top}th{background:#f3f3f3}"
             ".red{background:#fde2e2}.yellow{background:#fff6d6}</style></head><body>",
             f"<h1>Decommission change set: {e(cs['customer'])}</h1>",
             f"<p>Created {e(cs['created'])} (America/Chicago). This is a proposed removal plan. Nothing has been pushed.</p>",
             _source_html(cs),
             f"<p>{s['requests_unique']} items, {s['placed']} matched, {s['unplaced']} unresolved; "
             f"{s.get('edited_rules', 0)} rules edited, {s.get('deleted_rules', 0)} deleted; "
             f"{s.get('deleted_objects', 0)} address objects deleted; {s['red_flags']} red flags.</p>"]
    if cs.get("items"):
        parts.append("<p>Items: " + ", ".join(f"<code>{e(i)}</code>" for i in cs["items"]) + "</p>")
    if cs.get("flags"):
        colors = {"red": "#fde2e2", "yellow": "#fff6d6", "green": "#e3f6e8", "info": "#eef6ff"}
        parts.append("<h2>Flags</h2><ul>" + "".join(
            f"<li class='{e(f.get('level', ''))}' style='background:{colors.get(f.get('level'), '#fff')};padding:2px 6px'>"
            f"<b>{e(str(f.get('level', '')).upper())}</b> {e(f.get('message') or '')}</li>"
            for f in cs["flags"]) + "</ul>")
    for g in cs.get("groups") or []:
        parts.append(f"<h2>{e(group_title(g))}</h2>")
        parts.append("<table><tr><th>Action</th><th>Name</th><th>Detail</th></tr>")
        for a in g.get("actions") or []:
            if a["op"] == "edit-rule":
                det = "; ".join(f"remove {f}: {', '.join(vs)}" for f, vs in (a.get("remove") or {}).items())
            elif a["op"] in {"delete-rule", "disable-rule", "delete-group"}:
                det = a.get("reason") or ""
            elif a["op"] == "edit-group":
                det = "remove " + ", ".join(a.get("remove") or [])
            else:
                det = a.get("value") or a.get("reason") or ""
            cls = "red" if a.get("flag") == "red" or a.get("reason") in {"empty-field-would-become-any", "empty-group"} else ""
            parts.append(f"<tr class='{cls}'><td>{e(a['op'])}</td><td>{e(str(a.get('name') or ''))}</td><td>{e(det)}</td></tr>")
        parts.append("</table>")
    if cs.get("unresolved"):
        parts.append("<h2>Unresolved</h2><ul>" + "".join(
            f"<li>{e(u.get('item') if isinstance(u, dict) else str(u))}: "
            f"{e(u.get('reason') if isinstance(u, dict) else '')}</li>"
            for u in cs["unresolved"]) + "</ul>")
    parts.append("</body></html>")
    return "".join(parts)
