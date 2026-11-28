# SPDX-License-Identifier: Apache-2.0
"""Change-plan generator: CR-template GUI steps, set CLI, rollback, and verification.

Output is plain Markdown filled into a template so it can be pasted into a
change request. The template is ``customers/<name>/changeplan.md`` when it
exists, else ``templates/changeplan.md``. Placeholders use ``$name``
(string.Template). Customer-specific defaults (log forwarding, profile
group, comms boilerplate) come from the customer profile ``change_plan``
block, with a gitignored local override.
"""

from __future__ import annotations

import re

import xml.etree.ElementTree as ET
from pathlib import Path
from string import Template
from typing import Any

from panlab.customers import customers_dir
from panlab.paths import repo_root
from panlab.report import _lst, _q, group_title, set_commands

PROTO_NUM = {"tcp": 6, "udp": 17}


def _template(customer: str) -> Template:
    for p in (customers_dir() / customer / "changeplan.md", repo_root() / "templates" / "changeplan.md"):
        if p.is_file():
            return Template(p.read_text(encoding="utf-8"))
    return Template("# $heading\n\n**RITM:** $ritm\n\n**SCTask:** $sctask\n\n$gui_steps\n\n```\n$cli\n```\n\n$verify\n\n```\n$rollback\n```\n")


def _obj_prefix(g: dict, o: dict) -> str:
    if o["location"] == "shared":
        return "delete shared"
    if g["backend"] == "panorama":
        return f"delete device-group {_q(o['device_group'])}"
    return f"delete vsys {o['vsys']}" if o.get("multi_vsys") else "delete"


def referenced_elsewhere(root: ET.Element | None, cs: dict[str, Any], names: set[str]) -> dict[str, str]:
    """Names (objects/tags) that the config references outside this change set's own rules.

    Conservative: any ``member`` (or ``tag/member``) with that text anywhere in the
    config counts, except inside a security rule this change set created.
    """
    if root is None or not names:
        return {}
    own_rules = {r["name"] for g in cs["groups"] for r in g["rules"]
                 if (r.get("operation") or "add") == "add"}
    hits: dict[str, str] = {}

    def walk(el: ET.Element, ctx: str, in_own: bool) -> None:
        for ch in el:
            c, own = ctx, in_own
            if ch.tag == "entry":
                nm = ch.get("name") or ""
                if el.tag == "rules":
                    c, own = f"rule {nm}", nm in own_rules
                elif el.tag in ("address-group", "service-group", "address", "service", "application-group"):
                    c = f"{el.tag} {nm}"
            if ch.tag == "member" and not own and (ch.text or "").strip() in names:
                hits.setdefault(ch.text.strip(), c)
            walk(ch, c, own)

    walk(root, "config", False)
    return hits


def load_configs(paths: list) -> ET.Element | None:
    """Parse one or more config XML files into one root for reference checks."""
    if not paths:
        return None
    root = ET.Element("configs")
    for p in paths:
        root.append(ET.parse(str(p)).getroot())
    return root


def rollback_plan(cs: dict[str, Any], config_root: ET.Element | None = None) -> tuple[list[str], list[str]]:
    """(commands, notes). Rules first; then only objects this change set created that nothing else references."""
    created = {o["name"] for g in cs["groups"] for o in g["objects"]["new"]}
    refs = referenced_elsewhere(config_root, cs, created)
    out, notes = [], []
    for g in cs["groups"]:
        out.append(f"# {group_title(g)}")
        rb = (f"delete device-group {_q(g['device_group'])} pre-rulebase security rules" if g["backend"] == "panorama"
              else (f"delete vsys {g['vsys']} rulebase security rules" if g.get("multi_vsys") else "delete rulebase security rules"))
        for r in g["rules"]:
            op = r.get("operation") or "add"
            if op == "already-allowed":
                out.append(f"# already allowed by existing rule {r['name']}: no rollback")
                continue
            if op == "edit":
                for ed in r.get("edits") or []:
                    field = ed.get("field")
                    if field in ("source", "destination", "tag") and ed.get("values"):
                        for v in ed["values"]:
                            out.append(f"{rb} {_q(r['name'])} {field} {_q(v)}")
                    elif field == "description":
                        prev = ed.get("previous") or ""
                        if prev:
                            out.append(f"{rb.replace('delete', 'set', 1)} {_q(r['name'])} description {_q(prev)}")
                        else:
                            out.append(f"{rb} {_q(r['name'])} description")
                continue
            out.append(f"{rb} {_q(r['name'])}")
        for kind in ("address-group", "address", "service", "tag"):
            for o in g["objects"]["new"]:
                if o["kind"] != kind:
                    continue
                if o.get("rollback") == "keep" or (o.get("rollback") is None and kind == "tag" and o["name"] in cs.get("default_tags", [])):
                    out.append(f"# kept {kind} {o['name']}: {o.get('keep_reason', 'shared tag')}")
                    continue
                if o["name"] in refs:
                    out.append(f"# kept {kind} {o['name']}: still referenced by {refs[o['name']]}")
                    continue
                out.append(f"{_obj_prefix(g, o)} {kind} {_q(o['name'])}")
        out.append("")
    route_rb = route_rollback_commands(cs)
    for line in route_rb:
        out.append(line)
    if route_rb:
        out.append("")
        notes.append("Suggested static routes are listed for rollback only if an engineer added them by hand. "
                     "They are never pushed automatically (next hop REQUIRED-CONFIRM).")
    notes.append("Only rules and objects created by this change set are deleted. Objects that existed before "
                 "(reused) and shared tags are never deleted.")
    if config_root is None:
        notes.append("Objects are deleted only if nothing else references them. This list was NOT checked against a "
                     "current config: before running it, regenerate with `paat changeplan --config <current running "
                     "config>` (or the GUI after a fresh export) so objects other rules now use are dropped. PAN-OS also "
                     "refuses to commit a delete of an object that is still referenced.")
    else:
        notes.append(f"Checked against the supplied config: {len(refs)} created object(s) still referenced elsewhere and kept.")
    return out, notes


def rollback_commands(cs: dict[str, Any], config_root: ET.Element | None = None) -> list[str]:
    return rollback_plan(cs, config_root)[0]


def _values(g: dict) -> dict[str, str]:
    vals = {}
    for o in g["objects"]["new"] + g["objects"]["reused"]:
        v = o.get("value")
        if o["kind"] == "service" and o.get("protocol"):
            v = f"{o['protocol']}/{o['port']}"
        if v:
            vals[o["name"]] = v
    return vals


def _first_ip(v: str | None) -> str | None:
    if not v or v == "any":
        return None
    v = v.split("-")[0].split("/")[0]
    return v if v.replace(".", "").isdigit() else None


ADDR_TYPE = {"ip-netmask": "IP Netmask", "ip-range": "IP Range", "fqdn": "FQDN"}


def _dollar(s: str) -> str:
    """Escape $ so string.Template will not eat values from the change set."""
    return s.replace("$", "$$")


def _tickets(cs: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"ritm": [], "sctask": [], "cr": []}
    for f in cs.get("files") or []:
        tix = f.get("tickets") or {}
        for k in out:
            for t in tix.get(k) or []:
                if t not in out[k]:
                    out[k].append(t)
    return out


def _plan_cfg(cs: dict[str, Any]) -> dict[str, Any]:
    from panlab.customers import DEFAULT_CHANGE_PLAN, load_profile

    try:
        return dict(load_profile(cs["customer"]).change_plan)
    except Exception:  # profile missing in a unit test fixture
        return dict(DEFAULT_CHANGE_PLAN)


def _is_pano(cs: dict[str, Any]) -> bool:
    return any(g.get("backend") == "panorama" for g in cs.get("groups") or [])


def _join(xs: list[str] | None, default: str = "any") -> str:
    return ", ".join(xs) if xs else default


def _policy_nav(g: dict) -> str:
    if g["backend"] == "panorama":
        return f"Policies > Security > Pre Rules (Device Group: {g['device_group']})"
    return "Policies > Security"


def _obj_nav(g: dict, o: dict, path: str) -> str:
    if o.get("location") == "shared":
        loc = "Shared"
    elif g["backend"] == "panorama":
        loc = f"Device Group: {o.get('device_group') or g.get('device_group')}"
    elif (o.get("vsys") and o.get("multi_vsys")) or (g.get("multi_vsys") and o.get("vsys")):
        loc = f"vsys {o.get('vsys') or g.get('vsys')}"
    else:
        loc = f"firewall {g.get('device', '')}".strip()
    return f"{path} ({loc})" if loc else path


def _audit_comment(cs: dict[str, Any]) -> str:
    tix = _tickets(cs)
    return ", ".join(tix["cr"]) or ", ".join(tix["ritm"] + tix["sctask"]) or "see tickets above"


def _add_policy_block(g: dict, r: dict, cfg: dict, audit: str) -> list[str]:
    user = _join(r.get("source_user") or [], "any")
    targets = ", ".join(
        f"{t['device']}/{t['vsys']}" for t in (r.get("target_devices") or [])
    ) or "all devices in the device group"
    action = str(r.get("action") or "allow")
    lines = [
        "### Add Policy",
        "",
        f"Navigate to: {_policy_nav(g)}",
        "",
        "#### General",
        f"- Name: `{r['name']}`",
        f"- Description: {r.get('description') or ''}",
        f"- Tags: `{_join(r.get('tags'), '(none)')}`",
        f"- Audit Comment: {audit}",
        "",
        "#### Source",
        f"- Zone: `{_join(r.get('from'))}`",
        f"- Address: `{_join(r.get('source'))}`",
        f"- User: `{user}`",
        "",
        "#### Destination",
        f"- Zone: `{_join(r.get('to'))}`",
        f"- Address: `{_join(r.get('destination'))}`",
        "",
        "#### Application",
        f"- Application: `{_join(r.get('application'))}`",
        "",
        "#### Service/URL Category",
        f"- Service: `{_join(r.get('service'))}`",
        f"- URL Category: `{cfg.get('url_category', 'any')}`",
        "",
        "#### Actions",
        f"- Action: {action.capitalize()}",
        f"- Log at Session Start: {cfg.get('log_at_session_start', 'No')}",
        "- Log at Session End: Yes",
        f"- Log Forwarding: `{cfg.get('log_forwarding', 'LOG-FWD-DEFAULT')}`",
        f"- Profile Type: {cfg.get('profile_type', 'Group')}",
        f"- Group Profile: `{r.get('profile_group') or cfg.get('profile_group', 'PROFILE-GROUP-DEFAULT')}`",
        "",
    ]
    if g["backend"] == "panorama":
        lines += ["#### Target", f"- Devices: {targets}", ""]
    if r.get("place_before"):
        lines += ["#### Position", f"- Move this rule directly above `{r['place_before']}` (Move > Move Up, or drag). "
                  "That rule would otherwise deny this traffic first.", ""]
    return lines


def _edit_policy_block(g: dict, r: dict) -> list[str]:
    lines = [
        "### Edit Policy",
        "",
        f"Navigate to: {_policy_nav(g)}",
        "",
        f"- Rule: `{r['name']}`",
    ]
    for ed in r.get("edits") or []:
        label = ed.get("action") or f"{str(ed.get('op') or 'Add').title()} {ed.get('field') or ''}".strip()
        values = ed.get("values") or []
        if values:
            lines.append(f"- {label}:")
            lines.extend(f"  - `{v}`" for v in values)
        elif ed.get("value"):
            lines.append(f"- {label}: `{ed['value']}`")
        else:
            lines.append(f"- {label}")
    alt = r.get("proposed_name") or ""
    if alt and alt != r.get("name"):
        lines.append(f"- Alternative: create a new rule named `{alt}` instead of editing this one "
                     "(use the radio on the Change plan page to switch).")
    else:
        lines.append("- Alternative: create a new rule instead of editing this one "
                     "(use the radio on the Change plan page to switch).")
    lines.append("")
    return lines


def _already_allowed_block(g: dict, r: dict) -> list[str]:
    reqs = ", ".join(r.get("requests") or ([r["request"]] if r.get("request") else [])) or "this request"
    return [
        "### Already allowed",
        "",
        f"Navigate to: {_policy_nav(g)}",
        "",
        f"- Existing rule: `{r['name']}`",
        f"- {reqs} is already fully allowed by this rule. No new policy and no edit are required.",
    ] + ([
        f"- **Already permitted by {pb}** (GREEN): checked in policy order (pre-rules, device-group hierarchy, post-rules; "
        "disabled rules and other targets ignored; no deny above it).",
        "- Flow: " + ", ".join(r.get("source") or ["any"]) + " -> " + ", ".join(r.get("destination") or ["any"])
        + f" ({', '.join(r.get('from') or [])} -> {', '.join(r.get('to') or [])}), "
        + "; ".join(f"{e['service']} by {', '.join(x['rule'] for x in e['rules'])}" for e in r["permitted_by"]),
    ] if (pb := _permitted_label(r)) else []) + [""]


def _permitted_label(r: dict) -> str:
    if not r.get("permitted_by"):
        return ""
    from panlab.permitted import label
    return label(r["permitted_by"])


def suggested_routes(cs: dict[str, Any]) -> list[tuple[dict, dict]]:
    """(group, route) for each unique suggested static route in the change set."""
    out: list[tuple[dict, dict]] = []
    seen: set[tuple] = set()
    for g in cs.get("groups") or []:
        for sr in g.get("suggested_routes") or []:
            key = (g.get("target"), g.get("device") or g.get("device_group"), sr.get("vr"), sr.get("destination"))
            if key in seen:
                continue
            seen.add(key)
            out.append((g, sr))
    return out


def _add_route_block(g: dict, sr: dict) -> list[str]:
    if sr.get("overlap_192"):
        return [
            "### Static Route — not suggested",
            "",
            f"- {sr.get('reason') or 'Overlaps an existing 192.x route; no new route is proposed.'}",
            "",
        ]
    vr = sr.get("vr") or "default"
    hop = sr.get("nexthop") or "REQUIRED-CONFIRM"
    iface = sr.get("interface") or "<egress-interface>"
    return [
        "### Add Static Route",
        "",
        f"Navigate to: Network > Virtual Routers > {vr} > Static Routes",
        "",
        f"- Name: `{sr.get('name')}`",
        f"- Destination: `{sr.get('destination')}`",
        f"- Interface: `{iface}`",
        f"- Next Hop: `{hop}`",
        f"- Note: {sr.get('reason') or ''} Next hop is REQUIRED-CONFIRM. This route is not pushed "
        "automatically; confirm the next hop and interface before adding it.",
        "",
    ]


def route_commands(cs: dict[str, Any]) -> list[str]:
    """CLI for suggested VR routes. Not paste-ready until the next hop is confirmed."""
    rows = suggested_routes(cs)
    if not rows:
        return []
    out = [
        "# Suggested routes — do not paste until the next hop is confirmed (REQUIRED-CONFIRM).",
        "# These are not pushed automatically.",
    ]
    for _g, sr in rows:
        if sr.get("overlap_192"):
            out.append(f"# not suggested: {sr.get('reason')}")
            continue
        if sr.get("cli"):
            out.append(sr["cli"])
    return out


def route_rollback_commands(cs: dict[str, Any]) -> list[str]:
    out = []
    for _g, sr in suggested_routes(cs):
        if sr.get("overlap_192") or not sr.get("rollback"):
            continue
        out.append(f"# suggested route {sr.get('name')} (only if it was added by hand; next hop was REQUIRED-CONFIRM)")
        out.append(sr["rollback"])
    return out


def gui_steps(cs: dict[str, Any], cfg: dict[str, Any] | None = None) -> list[str]:
    """CR-template implementation plan: address objects first, then policies."""
    from panlab.decom import is_decom
    if is_decom(cs):
        return decom_gui_steps(cs)
    cfg = cfg or _plan_cfg(cs)
    audit = _audit_comment(cs)
    out: list[str] = []
    for g in cs["groups"]:
        if len(cs["groups"]) > 1:
            out += [f"### {group_title(g)}", ""]
        for o in g["objects"]["new"]:
            if o["kind"] == "address":
                typ = ADDR_TYPE.get(o.get("type") or "", o.get("type") or "")
                out += [
                    "### Add Address Object",
                    "",
                    f"Navigate to: {_obj_nav(g, o, 'Objects > Addresses')}",
                    "",
                    f"- Name: `{o['name']}`",
                    f"- Type: {typ}",
                    f"- Address: `{o.get('value', '')}`",
                    f"- Description: {o.get('description') or ''}",
                    "",
                ]
            elif o["kind"] == "address-group":
                members = o.get("members") or []
                out += [
                    "### Add Address Group",
                    "",
                    f"Navigate to: {_obj_nav(g, o, 'Objects > Address Groups')}",
                    "",
                    f"- Name: `{o['name']}`",
                    "- Type: Static",
                    "- Static Members:",
                    *[f"  - `{m}`" for m in members],
                    f"- Description: {o.get('description') or ''}",
                    "",
                ]
            elif o["kind"] == "service":
                out += [
                    "### Add Service",
                    "",
                    f"Navigate to: {_obj_nav(g, o, 'Objects > Services')}",
                    "",
                    f"- Name: `{o['name']}`",
                    f"- Protocol: {(o.get('protocol') or '').upper()}",
                    f"- Destination Port: `{o.get('port', '')}`",
                    "",
                ]
            else:
                out += [
                    "### Add Tag",
                    "",
                    f"Navigate to: {_obj_nav(g, o, 'Objects > Tags')}",
                    "",
                    f"- Name: `{o['name']}`",
                    "",
                ]
        for _g, sr in ((g, sr) for sr in g.get("suggested_routes") or []):
            out += _add_route_block(g, sr)
        for r in g["rules"]:
            op = r.get("operation") or "add"
            if op == "already-allowed":
                out += _already_allowed_block(g, r)
            elif r.get("edits") or op == "edit":
                out += _edit_policy_block(g, r)
            else:
                out += _add_policy_block(g, r, cfg, audit)
    has_change = any((g.get("objects") or {}).get("new") or
                     any((r.get("operation") or "add") in ("add", "edit") for r in g.get("rules") or [])
                     for g in cs.get("groups") or [])
    allowed_only = (not has_change) and any(r.get("operation") == "already-allowed"
                                           for g in cs.get("groups") or [] for r in g.get("rules") or [])
    if allowed_only:
        out += [
            "No new policy is required; the requested traffic is already allowed by existing rules.",
            "See the Already allowed section above.",
            "",
        ]
    elif not has_change:
        out += [
            "No policies or objects were placed in this change set, so there are no GUI steps to follow.",
            "See **Open items** above (unplaced requests or red flags). Fix those, rebuild the change set, and regenerate this plan.",
            "",
        ]
    out += ["### Add NAT Policy", "", "None for this change.", ""]
    return out


def default_backout(cs: dict[str, Any], cfg: dict[str, Any] | None = None) -> str:
    from panlab.decom import DECOM_BACKOUT, is_decom
    cfg = cfg or _plan_cfg(cs)
    if is_decom(cs):
        return (cfg.get("decom_backout_plan") or "").strip() or DECOM_BACKOUT
    if (cfg.get("backout_plan") or "").strip():
        return str(cfg["backout_plan"]).strip()
    if _is_pano(cs):
        return (
            "If the change must be reversed, use the Rollback CLI in this plan (rules first, then "
            "unreferenced objects created by this change). Commit to Panorama with the change number "
            "in the description, then Push to Devices for the same device group and targets. "
            "Alternatively, load a pre-change Panorama configuration version and commit and push it "
            "to the same targets."
        )
    return (
        "If the change must be reversed, go to Device > Setup > Operations > Load configuration "
        "version, select the pre-change configuration version taken before this change, review it, "
        "and Commit. The Rollback CLI in this plan may be used instead to delete only this change's "
        "rules and unreferenced new objects."
    )


def commit_section(cs: dict[str, Any], cfg: dict[str, Any] | None = None) -> list[str]:
    chg = _audit_comment(cs)
    if _is_pano(cs):
        lines = [
            "Navigate to: Commit > Commit to Panorama",
            "",
            f"- Description: {chg}",
            "- Commit Summary",
            "- Validate",
            "- Commit",
            "",
            "Then follow the Commit and push plan below.",
            "",
            "## Commit and push plan",
            "",
        ]
    else:
        lines = [
            "Navigate to: Commit",
            "",
            f"- Description: {chg}",
            "- Commit Summary",
            "- Validate",
            "- Commit",
            "",
            "## Commit and push plan",
            "",
        ]
    lines += commit_push_steps(cs)
    return lines


def verify_steps(cs: dict[str, Any]) -> list[str]:
    from panlab.decom import is_decom, verify_steps as decom_verify
    if is_decom(cs):
        return decom_verify(cs)
    out = []
    for g in cs["groups"]:
        vals = _values(g)
        for r in g["rules"]:
            op = r.get("operation") or "add"
            if op == "already-allowed":
                out.append(f"- [ ] Confirm existing rule `{r['name']}` still allows the requested traffic (no change was made).")
                continue
            devs = ", ".join(f"{t['device']}/{t['vsys']}" for t in r["target_devices"]) or g.get("device", "")
            src_names = r.get("source") or []
            dst_names = r.get("destination") or []
            if op == "edit":
                added_src = [v for ed in r.get("edits") or [] if ed.get("field") == "source" for v in ed.get("values") or []]
                added_dst = [v for ed in r.get("edits") or [] if ed.get("field") == "destination" for v in ed.get("values") or []]
                if added_src:
                    src_names = added_src
                if added_dst:
                    dst_names = added_dst
            src = _first_ip(vals.get(src_names[0])) if src_names else None
            dst = _first_ip(vals.get(dst_names[0])) if dst_names else None
            svc = vals.get(r["service"][0], "") if r["service"] else ""
            if r["service"] and r["service"][0] == "service-https":
                svc = "tcp/443"
            proto, _, port = svc.partition("/")
            if op == "edit":
                adds = []
                for ed in r.get("edits") or []:
                    if ed.get("values"):
                        adds.append((ed.get("action") or ed.get("field") or "") + ": " + ", ".join(f"`{v}`" for v in ed["values"]))
                out.append(f"- [ ] Existing rule `{r['name']}` on {devs} includes the added objects"
                           + (f" ({'; '.join(adds)})" if adds else "") + ".")
            else:
                tag = f" (Policies > Security, filter `tag eq {r['tags'][0]}`)" if r.get("tags") else " (Policies > Security)."
                out.append(f"- [ ] `{r['name']}` is present on {devs}{tag}")
            if src and dst and proto in PROTO_NUM and port:
                out.append(f"  On each firewall: `test security-policy-match from {r['from'][0]} to {r['to'][0]} source {src} "
                           f"destination {dst} protocol {PROTO_NUM[proto]} destination-port {port.split('-')[0]}` returns `{r['name']}`.")
            out.append("  Monitor > Traffic: filter `( rule eq '" + r["name"] + "' )` shows allowed sessions once the requester tests.")
    out.append("- [ ] Requester confirms the application works.")
    return out


def open_items(cs: dict[str, Any]) -> list[str]:
    from panlab.decom import is_decom
    if is_decom(cs):
        return decom_open_items(cs)
    out = []
    for g in cs["groups"]:
        for r in g["rules"]:
            reds = [f["message"] for f in r["flags"] if f["level"] == "red"]
            if r["needs_human"]:
                out.append(f"- `{r['name']}` needs a human: confirm zones ({', '.join(r['from'])} -> {', '.join(r['to'])}).")
            for m in reds:
                out.append(f"- `{r['name']}`: RED {m}")
    for rq in cs["requests"]:
        if rq["id"] in cs["unplaced"]:
            pick = cs.get("candidate_firewalls") or []
            extra = f" Pick a target firewall to build the plan: {', '.join(pick)}." if pick else ""
            out.append(f"- {rq['id']} ({', '.join(rq['origins'])}) could not be placed yet.{extra}")
    for _g, sr in suggested_routes(cs):
        if sr.get("overlap_192"):
            out.append(f"- {sr.get('reason')}")
        elif not sr.get("nexthop_confirmed"):
            out.append(
                f"- Confirm next hop and interface for static route `{sr.get('name')}` "
                f"({sr.get('destination')} on VR {sr.get('vr')}) before adding it. It is not pushed automatically."
            )
    return out or ["- None."]


def _push_scope(cs: dict[str, Any]) -> list[tuple[str, str, list[tuple[str, str]], set[str]]]:
    """Panorama groups -> (target, device group, [(device, serial)], template stacks hinted by route callouts)."""
    out = []
    for g in cs["groups"]:
        if g["backend"] != "panorama" or not (g.get("rules") or g.get("actions")):
            continue
        devs: list[tuple[str, str]] = []
        stacks: set[str] = set()
        for r in g["rules"]:
            for t in r["target_devices"]:
                if (t["device"], t.get("serial") or "") not in devs:
                    devs.append((t["device"], t.get("serial") or ""))
            for f in r["flags"]:
                for m in re.finditer(r"template stack (\S+?);", f["message"]):
                    stacks.add(m.group(1))
        out.append((g["target"], g["device_group"], devs, stacks))
    return out


def commit_push_steps(cs: dict[str, Any], rollback: bool = False) -> list[str]:
    """Commit-and-push plan. Panorama: commit to Panorama, then push the device group to only the target firewalls."""
    scope = _push_scope(cs)
    lines = []
    if any(g["backend"] != "panorama" for g in cs["groups"] if g.get("rules") or g.get("actions")):
        lines.append("- Standalone firewalls: `commit` on each firewall (GUI: Commit > Preview Changes, check only your "
                     "changes are listed, then Commit). Wait for the job to finish (`show jobs all`).")
    if not scope:
        return lines or ["- Nothing to commit."]
    what = "the rollback" if rollback else "the change"
    lines.append(f"- Panorama: two steps. Nothing reaches a firewall until step 2. Do step 1 for {what}, then step 2 per device group.")
    lines.append(f"  1. **Commit to Panorama** (GUI: Commit > Commit to Panorama, description = the CR number; CLI: `commit description \"<CR>\"`). "
                 "What: saves the change in Panorama only. Why: lets you review before any firewall changes.")
    for i, (target, dg, devs, stacks) in enumerate(scope, 2):
        names = ", ".join(f"{d} ({s})" if s else d for d, s in devs) or "the firewalls in this device group"
        lines.append(f"  {i}. **Push to Devices** for device group `{dg}` on Panorama `{target}`: GUI Commit > Push to Devices > Edit "
                     f"Selections > Device Groups tab: tick only `{dg}` and, under it, only {names}; leave Merge with Device "
                     "Candidate Config ticked; leave Include Device and Network Templates **unticked**. Push, then watch the job in "
                     "Tasks until every firewall shows Commit succeeded.")
        lines.append(f"     CLI (operational mode on Panorama): `commit-all shared-policy device-group {dg} include-template no` "
                     "pushes to every firewall directly in the group; use the GUI selection above to limit it to the targets. "
                     "Then `show jobs id <job>`.")
        if devs and all(s for _, s in devs):
            ents = "".join(f'<entry name="{s}"/>' for _, s in devs)
            lines.append(f"     XML API equivalent limited to the targets (type=commit&action=all): `<commit-all><shared-policy><device-group>"
                         f"<entry name=\"{dg}\"><devices>{ents}</devices></entry></device-group><include-template>no</include-template>"
                         "</shared-policy></commit-all>`")
        lines.append(f"     Why only these firewalls: rules in `{dg}` are inherited by its child device groups; pushing only the "
                     "targets keeps the blast radius to what the CR approved. (The CLI/API push of a parent group does not "
                     "reach firewalls in child groups; the GUI can include them when you tick them.)")
        for st in sorted(stacks):
            if rollback:
                lines.append(f"     The rollback does not touch template stack `{st}`; if a static route was added there for this change, "
                             f"remove it separately and push the stack (`commit-all template-stack {st}`).")
                continue
            lines.append(f"     If you added the suggested static route in template stack `{st}`, push that stack separately "
                         f"(Push to Devices > Templates tab: `{st}`; CLI `commit-all template-stack {st}`), after the network team agrees.")
    lines.append("  - Check: Panorama > Managed Devices > Summary shows the targets *In sync* for Shared Policy.")
    return lines


def callout_lines(cs: dict[str, Any]) -> list[str]:
    from panlab.decom import is_decom
    if is_decom(cs):
        return decom_callout_lines(cs)
    from panlab.report import callouts

    out = enforcement_lines(cs)
    out += [f"- **{lv.upper()}** `{rn}`: {m}" for g in cs["groups"] for rn, lv, m in callouts(g)]
    for g in cs["groups"]:
        for o in g["objects"]["reused"]:
            out.append(f"- EXISTING object `{o['name']}` ({o.get('value', '')}, {o['scope']}) matches and is reused; nothing new is created for it.")
    return out or ["- None."]


_EP_STATUS = {"new-rule": "new rule", "already-allowed": "already allowed by", "no-rule-needed": "no rule needed",
              "needs-human": "NEEDS A HUMAN"}



def assumes_outside_hop(cs: dict, rq: dict | None = None) -> bool:
    """True when a placement note records a hairpin or other unseen network hop."""
    rqs = [rq] if rq is not None else (cs.get("requests") or [])
    for item in rqs:
        notes = " ".join(item.get("placement_notes") or [])
        if "hairpin" in notes.lower() or "unknown network" in notes.lower():
            return True
        for pl in item.get("placements") or []:
            blob = " ".join(pl.get("notes") or [])
            if "hairpin" in blob.lower() or "unknown network" in blob.lower():
                return True
        for p in item.get("enforcement_points") or []:
            if p.get("hairpin") or p.get("transit"):
                return True
    return False


def enforcement_lines(cs: dict[str, Any]) -> list[str]:
    """One block per request whose flow is checked in more than one place."""
    out: list[str] = []
    for rq in cs.get("requests") or []:
        pts = rq.get("enforcement_points") or []
        if len(pts) < 2:
            continue
        need = sum(1 for p in pts if p.get("status") in ("new-rule", "needs-human"))
        assume = " The count assumes the suggested outside hop." if assumes_outside_hop(cs, rq) else ""
        out.append(f"- **RULE NEEDED IN {len(pts)} PLACES** {rq.get('id')} ({', '.join(rq.get('origins') or [])}): "
                   f"this flow needs {need} rule{'s' if need != 1 else ''} across {len(pts)} vsys/firewalls. "
                   f"The firewall checks this flow at every step below. Push and verify all of them.{assume}")
        for i, p in enumerate(pts, 1):
            st = _EP_STATUS.get(p.get("status") or "", p.get("status") or "?")
            rule = f" `{p['rule']}`" if p.get("rule") else ""
            pos = f", placed above `{p['place_before']}`" if p.get("place_before") else ""
            where = p.get("device_group") or p.get("vsys") or ""
            out.append(f"  {i}. {p.get('device')} ({where}): `{p.get('from')}` -> `{p.get('to')}`: {st}{rule}{pos}")
    return out


def _sub(tmpl: Template, **vals: str) -> str:
    return tmpl.safe_substitute({k: _dollar(v) for k, v in vals.items()})


def render_changeplan(cs: dict[str, Any], config_root: ET.Element | None = None, evidence: dict | None = None) -> str:
    from panlab.denylog import evidence_lines

    from panlab.decom import DECOM_IMPACT, DECOM_VALIDATION, delete_commands, is_decom
    from panlab.decom import rollback_commands as decom_rollback

    tix = _tickets(cs)
    tickets = tix["ritm"] + [t for t in tix["sctask"] + tix["cr"] if t not in tix["ritm"]]
    s = cs["summary"]
    cfg = _plan_cfg(cs)
    decom = is_decom(cs)
    if decom:
        rb, rb_notes = decom_rollback(cs), [
            "For a decommission, rollback re-creates deleted objects and groups first, then deleted rules, "
            "then puts removed members back on edited rules and groups. Commands are taken from the cached config at plan time.",
            "Review red flags in the callouts before you use this plan.",
        ]
    else:
        rb, rb_notes = rollback_plan(cs, config_root)
    scope = "; ".join(group_title(g) for g in cs["groups"]) or "none"
    heading = ("Panorama Change Request (Decommission)" if decom and _is_pano(cs)
               else "Firewall Change Request (Decommission)" if decom
               else "Panorama Change Request" if _is_pano(cs) else "Firewall Change Request")
    from panlab.uploads import source_note
    note = source_note(cs)
    text = _sub(
        _template(cs["customer"]),
        title=" / ".join(tickets) or cs["customer"],
        heading=heading,
        ritm=", ".join(tix["ritm"]) or "none",
        sctask=", ".join(tix["sctask"]) or "none",
        customer=cs["customer"], tickets=" / ".join(tickets) or "none",
        created=cs["created"], scope=scope,
        summary=(
            f"{s.get('edited_rules', 0)} edited rules, {s.get('deleted_rules', 0)} deleted rules, "
            f"{s.get('edited_groups', 0)} edited groups, {s.get('deleted_groups', 0)} deleted groups, "
            f"{s.get('deleted_objects', 0)} deleted objects, {s['red_flags']} red flags, {s['needs_human']} need a human"
            if decom else
            f"{s['rules']} rules, {s['new_objects']} new objects, {s['reused_objects']} reused, {s['red_flags']} red flags, {s['needs_human']} need a human"
        ),
        commit_push="\n".join(commit_push_steps(cs)),
        rollback_push="\n".join(commit_push_steps(cs, rollback=True)),
        commit_section="\n".join(commit_section(cs, cfg)),
        gui_steps="\n".join(gui_steps(cs, cfg)),
        cli=(
            "\n".join(delete_commands(cs)).strip() or "# No delete commands: nothing was matched for decommission."
            if decom else
            "\n".join(c for c in set_commands(cs) + ([""] if route_commands(cs) else []) + route_commands(cs)).strip() or "# No set commands: no rules or objects were placed in this change set."
        ),
        callouts="\n".join(callout_lines(cs)),
        evidence="\n".join(evidence_lines(evidence)),
        rollback="\n".join(rb).strip(),
        rollback_notes="\n".join(f"- {n}" for n in rb_notes),
        verify="\n".join(verify_steps(cs)),
        open_items="\n".join(open_items(cs)),
        impact_analysis=str((cfg.get("decom_impact_analysis") if decom else None) or (DECOM_IMPACT if decom else cfg.get("impact_analysis")) or ""),
        backout_plan=default_backout(cs, cfg),
        validation_plan=str((cfg.get("decom_validation_plan") if decom else None) or (DECOM_VALIDATION if decom else cfg.get("validation_plan")) or ""),
        communications_plan=str(cfg.get("communications_plan") or ""),
        config_source=(note + "\n") if note else "",
    )
    if note and "plan only - built from a backup file" not in text:
        lines = text.splitlines(True)
        for i, line in enumerate(lines):
            if line.startswith("# "):
                lines.insert(i + 1, "\n" + note + "\n")
                break
        text = "".join(lines)
    return text


_SECTION_MARKERS = (
    ("cli", "## Implementation (CLI)"),
    ("verify", "## Verification"),
    ("rollback", "## Rollback"),
)


def changeplan_sections(cs: dict[str, Any], config_root: ET.Element | None = None, evidence: dict | None = None) -> dict[str, str]:
    """Split the rendered plan into CR, CLI, verification, and rollback parts."""
    full = render_changeplan(cs, config_root, evidence)
    found = sorted(((full.find(h), name) for name, h in _SECTION_MARKERS if full.find(h) >= 0))
    parts: dict[str, str] = {"full": full, "cr": "", "cli": "", "verify": "", "rollback": ""}
    start_cr = 0
    if found:
        parts["cr"] = full[: found[0][0]].rstrip() + "\n"
        for i, (pos, name) in enumerate(found):
            end = found[i + 1][0] if i + 1 < len(found) else len(full)
            parts[name] = full[pos:end].rstrip() + "\n"
    else:
        parts["cr"] = full
    return parts


def _policy_nav_kind(g: dict, act: dict) -> str:
    kind = act.get("rule_kind") or "security"
    rb = act.get("rulebase") or g.get("rulebase") or ""
    if kind == "nat":
        path = "Policies > NAT"
    elif kind == "pbf":
        path = "Policies > Policy Based Forwarding"
    else:
        path = "Policies > Security"
    loc = act.get("location") or {}
    if loc.get("kind") == "shared" or loc.get("location") == "shared":
        return f"{path} (Shared)"
    if g.get("backend") == "panorama" or loc.get("device_group"):
        pre = " > Pre Rules" if kind == "security" and rb != "post-rulebase" else (" > Post Rules" if rb == "post-rulebase" and kind == "security" else "")
        return f"{path}{pre} (Device Group: {loc.get('device_group') or g.get('device_group')})"
    return path


def _obj_nav_loc(loc: dict, path: str) -> str:
    if loc.get("kind") == "shared" or loc.get("location") == "shared":
        place = "Shared"
    elif loc.get("device_group"):
        place = f"Device Group: {loc['device_group']}"
    elif loc.get("vsys") and loc.get("multi_vsys"):
        place = f"vsys {loc['vsys']}"
    else:
        place = f"firewall {loc.get('device') or loc.get('target') or ''}".strip()
    return f"{path} ({place})" if place else path


def _remove_field_label(field: str) -> str:
    return {
        "source": "Remove source address",
        "destination": "Remove destination address",
        "translated-address": "Remove translated address",
    }.get(field, f"Remove {field}")


def decom_gui_steps(cs: dict[str, Any]) -> list[str]:
    """CR-template decommission plan: edit/delete policies and groups first, objects last."""
    from panlab.decom import iter_actions

    out: list[str] = []
    last = None
    for g, act in iter_actions(cs):
        if len(cs["groups"]) > 1 and g is not last:
            out += [f"### {group_title(g)}", ""]
        last = g
        loc = act.get("location") or {}
        if act["op"] == "add-service":
            out += [
                "### Add Service",
                "",
                f"Navigate to: {_obj_nav_loc(loc, 'Objects > Services')}",
                "",
                f"- Name: `{act['name']}`",
                f"- Protocol: {(act.get('protocol') or '').upper()}",
                f"- Destination Port: `{act.get('port', '')}`",
                "",
            ]
        elif act["op"] == "add-deny-rule":
            r = act.get("rule") or {}
            place = act.get("place") or {}
            tgt = ", ".join(f"{t.get('serial')} ({t.get('vsys')})" if t.get("vsys") else str(t.get("serial")) for t in r.get("targets") or [])
            out += [
                "### Add Deny Policy (stop traffic)",
                "",
                f"Navigate to: {_policy_nav_kind(g, act)}",
                "",
                f"- Name: `{act['name']}`",
                f"- Source Zone: {', '.join(r.get('from') or ['any'])}",
                f"- Source Address: {', '.join(f'`{x}`' for x in r.get('source') or [])}",
                f"- Destination Zone: {', '.join(r.get('to') or ['any'])}",
                f"- Destination Address: {', '.join(f'`{x}`' for x in r.get('destination') or [])}",
                f"- Application: {', '.join(r.get('application') or ['any'])}",
                f"- Service: {', '.join(f'`{x}`' for x in r.get('service') or [])}",
                "- Action: Deny; Log at Session End: yes",
                f"- Description: {r.get('description') or ''}",
            ]
            if tgt:
                out.append(f"- Target: {tgt} only")
            if place.get("ref"):
                out.append(f"- Placement: directly above `{place['ref']}` (the first rule that would still allow this flow here)")
            for t in act.get("tests") or []:
                out.append(f"- Check after the push: `{t}` must return `{act['name']}`")
            out.append("")
        elif act["op"] == "edit-rule":
            out += [
                "### Edit Policy",
                "",
                f"Navigate to: {_policy_nav_kind(g, act)}",
                "",
                f"- Rule: `{act['name']}`",
            ]
            for field, vals in (act.get("remove") or {}).items():
                out.append(f"- {_remove_field_label(field)}:")
                out.extend(f"  - `{v}`" for v in vals)
            out.append("")
        elif act["op"] in {"delete-rule", "disable-rule"}:
            title = "### Delete Policy" if act["op"] == "delete-rule" else "### Disable Policy"
            out += [
                title,
                "",
                f"Navigate to: {_policy_nav_kind(g, act)}",
                "",
                f"- Rule: `{act['name']}`",
            ]
            if act.get("reason") == "empty-field-would-become-any":
                fields = ", ".join(act.get("fields") or [])
                instead = "deletion" if act["op"] == "delete-rule" else "disabling (not every member was an exact match)"
                out.append(
                    f"- Reason: removing the last address from {fields or 'an address field'} would leave that "
                    f"field empty, which PAN-OS treats as 'any' and would broaden the rule. The rule is proposed "
                    f"for {instead} instead. Never leave a rule with an empty address field."
                )
            elif act.get("reason") == "named-rule":
                out.append("- Reason: this rule was named in the decommission request.")
            elif act.get("reason") == "nat-translates-to-target":
                out.append("- Reason: this NAT rule translates to the decommissioned address (selected as Highly likely).")
            elif act.get("reason") == "negated-field-would-empty":
                out.append("- Reason: the field is negated and would be left empty; the rule is disabled for a person to review.")
            else:
                out.append(f"- Reason: {act.get('reason') or 'decommission'}.")
            out.append("")
        elif act["op"] == "edit-group":
            out += [
                "### Edit Address Group",
                "",
                f"Navigate to: {_obj_nav_loc(loc, 'Objects > Address Groups')}",
                "",
                f"- Group: `{act['name']}`",
                "- Remove members:",
            ]
            out.extend(f"  - `{v}`" for v in act.get("remove") or [])
            out.append("")
        elif act["op"] == "delete-group":
            out += [
                "### Delete Address Group",
                "",
                f"Navigate to: {_obj_nav_loc(loc, 'Objects > Address Groups')}",
                "",
                f"- Group: `{act['name']}`",
            ]
            if act.get("reason") == "empty-group":
                out.append("- Reason: removing the last member would leave the group empty. The group is proposed for deletion instead.")
            else:
                out.append("- Reason: this group was named in the decommission request.")
            out.append("")
        elif act["op"] == "delete-address":
            val = f" (`{act.get('value')}`)" if act.get("value") else ""
            typ = act.get("type") or (act.get("snapshot") or {}).get("type") or ""
            typ_s = f" — {typ}" if typ else ""
            out += [
                "### Delete Address Object",
                "",
                f"Navigate to: {_obj_nav_loc(loc, 'Objects > Addresses')}",
                "",
                f"- `{act['name']}`{val}{typ_s}",
                "",
            ]
    if not any((g.get("actions") or []) for g in cs.get("groups") or []):
        out += [
            "No objects or rules were matched for decommission, so there are no GUI steps to follow.",
            "See **Open items** and **Callouts** (unresolved names or red flags).",
            "",
        ]
    return out


def decom_callout_lines(cs: dict[str, Any]) -> list[str]:
    out = []
    for f in cs.get("flags") or []:
        out.append(f"- **{str(f.get('level', 'info')).upper()}** {f.get('message')}")
    for u in cs.get("unresolved") or []:
        msg = f"{u.get('item')}: {u.get('reason')}" if isinstance(u, dict) else str(u)
        # already in flags usually; skip exact duplicates
        if not any(msg in (f.get("message") or "") for f in cs.get("flags") or []):
            out.append(f"- **RED** {msg}")
    return out or ["- None."]


def decom_open_items(cs: dict[str, Any]) -> list[str]:
    out = []
    for f in cs.get("flags") or []:
        if f.get("level") == "red":
            out.append(f"- RED: {f.get('message')}")
    for u in cs.get("unresolved") or []:
        item = u.get("item") if isinstance(u, dict) else u
        reason = u.get("reason") if isinstance(u, dict) else ""
        if not any(str(item) in (f.get("message") or "") for f in cs.get("flags") or []):
            out.append(f"- `{item}` was not found in the cached config" + (f" ({reason})" if reason else "") + ".")
    return out or ["- None."]
