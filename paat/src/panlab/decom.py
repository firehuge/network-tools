"""Decommission: build a removal (or stop-traffic) change set from the shared FlowMapper engine.

The engine (vendor/flowmapper/decom.js) grades every reference Exact, Highly likely or Possible, and
plans edits and deletes in PAN-OS-safe order (references first, objects last; child device groups
before parents; shared last). A rule that would be left with an empty address field is deleted (all
members exact) or disabled, never left as 'any'. Broader objects are never changed. Nothing is pushed
from this module; the inventory below is used by the pusher to re-validate against a fresh export.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo
import xml.etree.ElementTree as ET

from panlab.addresses import parse_address_value
from panlab.configxml import load_config_root
from panlab.customers import Profile
from panlab.netmodel import Environment, _ch, _entries, _members, _txt
from panlab.report import _q as qname

TZ = ZoneInfo("America/Chicago")
SCHEMA = "panlab.changeset/v1"
KIND = "decommission"
ANY = {"any"}
SAFE_ITEM = re.compile(r"^[A-Za-z0-9._:/\-]+$")

# Fields on a rule that hold address-object (or group) members.
ADDR_FIELDS = ("source", "destination")
NAT_SINGLE = ("translated-address",)


# --------------------------------------------------------------------- items

def parse_item_text(text: str) -> list[str]:
    """Split a pasted list on newlines, commas, and semicolons. Skip blanks and # comments."""
    out: list[str] = []
    for raw in re.split(r"[\n,;]+", text or ""):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s not in out:
            out.append(s)
    return out


def parse_item_xlsx(path: Path) -> list[str]:
    """First column of the first sheet, one item per row. A header row is skipped."""
    from openpyxl import load_workbook

    wb = load_workbook(path, read_only=True, data_only=True)
    try:
        ws = wb.active
        values: list[str] = []
        for i, row in enumerate(ws.iter_rows(min_col=1, max_col=1, values_only=True)):
            cell = row[0]
            if cell is None:
                continue
            s = str(cell).strip()
            if not s:
                continue
            if i == 0 and s.lower() in {"item", "items", "name", "ip", "address", "object", "host", "hostname", "fqdn", "rule"}:
                continue
            if s not in values:
                values.append(s)
        return values
    finally:
        wb.close()


# --------------------------------------------------------------------- inventory

def _loc(**kw: Any) -> dict[str, Any]:
    return {k: v for k, v in kw.items() if v is not None}


@dataclass
class InvAddress:
    name: str
    typ: str
    value: str
    location: dict[str, Any]
    description: str = ""
    tags: list[str] = field(default_factory=list)
    parsed: Any = None


@dataclass
class InvGroup:
    name: str
    members: list[str]
    location: dict[str, Any]
    dynamic: bool = False
    filter: str = ""


@dataclass
class InvRule:
    name: str
    kind: str  # security | nat | pbf
    rulebase: str  # pre-rulebase | post-rulebase | rulebase
    location: dict[str, Any]
    from_zones: list[str] = field(default_factory=list)
    to_zones: list[str] = field(default_factory=list)
    source: list[str] = field(default_factory=list)
    destination: list[str] = field(default_factory=list)
    application: list[str] = field(default_factory=list)
    service: list[str] = field(default_factory=list)
    source_user: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    action: str = ""
    description: str = ""
    disabled: bool = False
    translated_addresses: list[str] = field(default_factory=list)
    xml: str = ""


@dataclass
class InvOther:
    name: str
    context: str
    location: dict[str, Any]


@dataclass
class Inventory:
    target: str
    kind: str  # firewall | panorama
    hostname: str = ""
    addresses: list[InvAddress] = field(default_factory=list)
    groups: list[InvGroup] = field(default_factory=list)
    rules: list[InvRule] = field(default_factory=list)
    others: list[InvOther] = field(default_factory=list)
    dg_parent: dict[str, str | None] = field(default_factory=dict)
    device: str = ""
    multi_vsys: bool = False


def _parse_addr_value(typ: str, value: str):
    if typ in {"ip-netmask", "ip-range", "fqdn"} and value:
        try:
            return parse_address_value(value, typ)
        except ValueError:
            return None
    return None


def _scope_addrs(node: ET.Element, loc: dict[str, Any], inv: Inventory) -> None:
    for e in _entries(_ch(node, "address")):
        typ = val = ""
        for t in ("ip-netmask", "ip-range", "ip-wildcard", "fqdn"):
            c = _ch(e, t)
            if c is not None and _txt(c):
                typ, val = t, _txt(c)
                break
        name = e.get("name") or ""
        if not name:
            continue
        inv.addresses.append(InvAddress(
            name=name, typ=typ or "unknown", value=val, location=dict(loc),
            description=_txt(_ch(e, "description")),
            tags=_members(_ch(e, "tag")),
            parsed=_parse_addr_value(typ, val),
        ))
    for e in _entries(_ch(node, "address-group")):
        name = e.get("name") or ""
        if not name:
            continue
        dyn = _ch(e, "dynamic")
        inv.groups.append(InvGroup(
            name=name,
            members=_members(_ch(e, "static")),
            location=dict(loc),
            dynamic=dyn is not None,
            filter=_txt(_ch(dyn, "filter")) if dyn is not None else "",
        ))


def _rule_from(entry: ET.Element, kind: str, rulebase: str, loc: dict[str, Any]) -> InvRule:
    svc = _members(_ch(entry, "service"))
    if not svc:
        st = _txt(_ch(entry, "service"))
        if st:
            svc = [st]
    translated: list[str] = []
    for path in (
        "source-translation/translated-address",
        "source-translation/dynamic-ip/translated-address",
        "source-translation/dynamic-ip-and-port/translated-address",
        "destination-translation/translated-address",
        "destination-translation/translated-address/entry",
    ):
        node = entry.find(path)
        if node is None:
            continue
        if node.tag == "entry" and node.get("name"):
            translated.append(node.get("name") or "")
        else:
            translated += _members(node) or ([_txt(node)] if _txt(node) else [])
    # also scan translated-address text anywhere in the rule
    for ta in entry.findall(".//translated-address"):
        vals = _members(ta) or ([_txt(ta)] if _txt(ta) else [])
        for v in vals:
            if v and v not in translated:
                translated.append(v)
    disabled = _txt(_ch(entry, "disabled")).lower() in {"yes", "true"}
    return InvRule(
        name=entry.get("name") or "",
        kind=kind,
        rulebase=rulebase,
        location=dict(loc),
        from_zones=_members(_ch(entry, "from")),
        to_zones=_members(_ch(entry, "to")),
        source=_members(_ch(entry, "source")),
        destination=_members(_ch(entry, "destination")),
        application=_members(_ch(entry, "application")),
        service=svc,
        source_user=_members(_ch(entry, "source-user")),
        tags=_members(_ch(entry, "tag")),
        action=_txt(_ch(entry, "action")) or _txt(entry.find("action/forward")) or "",
        description=_txt(_ch(entry, "description")),
        disabled=disabled,
        translated_addresses=[t for t in translated if t],
        xml=ET.tostring(entry, encoding="unicode"),
    )


_RULE_PATHS = (
    ("security", "pre-rulebase/security/rules", "pre-rulebase"),
    ("security", "post-rulebase/security/rules", "post-rulebase"),
    ("security", "rulebase/security/rules", "rulebase"),
    ("nat", "pre-rulebase/nat/rules", "pre-rulebase"),
    ("nat", "post-rulebase/nat/rules", "post-rulebase"),
    ("nat", "rulebase/nat/rules", "rulebase"),
    ("pbf", "pre-rulebase/pbf/rules", "pre-rulebase"),
    ("pbf", "post-rulebase/pbf/rules", "post-rulebase"),
    ("pbf", "rulebase/pbf/rules", "rulebase"),
)


def _scope_rules(node: ET.Element, loc: dict[str, Any], inv: Inventory) -> None:
    for kind, path, rb in _RULE_PATHS:
        parent = node.find(path)
        if parent is None:
            continue
        for e in _entries(parent):
            if e.get("name"):
                inv.rules.append(_rule_from(e, kind, rb, loc))


def _known_rule_group_names(inv: Inventory) -> set[tuple[str, str]]:
    names = {(r.kind + ":" + r.name, _scope_key(r.location)) for r in inv.rules}
    names |= {("group:" + g.name, _scope_key(g.location)) for g in inv.groups}
    return names


def _scope_key(loc: dict[str, Any]) -> str:
    return "|".join(str(loc.get(k) or "") for k in ("kind", "name", "device_group", "vsys", "device", "target"))


def _walk_other_refs(node: ET.Element, loc: dict[str, Any], inv: Inventory, known_objects: set[str]) -> None:
    """Flag member / translated-address hits that are not already a rule or group ref."""
    rule_names = {r.name for r in inv.rules}
    group_names = {g.name for g in inv.groups}

    def walk(el: ET.Element, ctx: str, skip: bool) -> None:
        for ch in el:
            c, sk = ctx, skip
            if ch.tag == "entry":
                nm = ch.get("name") or ""
                parent = el.tag
                if parent == "rules":
                    c, sk = f"rule {nm}", nm in rule_names
                elif parent == "address-group":
                    c, sk = f"address-group {nm}", nm in group_names
                elif parent in {"address", "service", "service-group", "application-group"}:
                    c = f"{parent} {nm}"
            text = (ch.text or "").strip()
            if not sk and ch.tag in {"member", "translated-address"} and text in known_objects:
                # skip static group members and rule source/dest (already inventoried)
                if ch.tag == "member" and el.tag in {"source", "destination", "from", "to", "application",
                                                      "service", "tag", "source-user", "static"}:
                    pass  # counted on the rule/group
                else:
                    inv.others.append(InvOther(name=text, context=c or ch.tag, location=dict(loc)))
            walk(ch, c, sk)

    walk(node, loc.get("kind") or "config", False)


def inventory_from_xml(source: Path | str | ET.Element, *, target: str, kind: str | None = None,
                       device: str = "", multi_vsys: bool = False) -> Inventory:
    root = load_config_root(source)
    is_pano = kind == "panorama" or any(root.find(p) is not None for p in
                                        (".//device-group", "./devices/entry/device-group"))
    kind = "panorama" if is_pano else (kind or "firewall")
    hostname = _txt(root.find(".//deviceconfig/system/hostname")) or device or target
    inv = Inventory(target=target, kind=kind, hostname=hostname, device=device or hostname, multi_vsys=multi_vsys)

    shared = root.find("shared")
    if shared is not None:
        loc = _loc(backend=kind, target=target, kind="shared", name="shared", location="shared")
        _scope_addrs(shared, loc, inv)
        _scope_rules(shared, loc, inv)

    if kind == "panorama":
        for e in root.findall("./devices/entry/device-group/entry") + root.findall(".//device-group/entry"):
            # Prefer the real devices/.../device-group tree; skip readonly duplicates by name later
            nm = e.get("name") or ""
            if not nm:
                continue
            parent = _txt(_ch(e, "parent-dg")) or None
            # readonly copies have almost no objects; record parent if new, objects if present
            if nm not in inv.dg_parent or parent:
                if nm not in inv.dg_parent:
                    inv.dg_parent[nm] = parent
                elif parent and not inv.dg_parent[nm]:
                    inv.dg_parent[nm] = parent
            loc = _loc(backend="panorama", target=target, kind="device-group", name=nm,
                       device_group=nm, location="device-group")
            # only load objects/rules from entries that actually have them (skip readonly stubs)
            if _ch(e, "address") is not None or _ch(e, "address-group") is not None or _ch(e, "pre-rulebase") is not None \
               or _ch(e, "post-rulebase") is not None or _ch(e, "rulebase") is not None:
                # Avoid double-adding if both devices/ and readonly/ were walked
                already = any(a.location.get("device_group") == nm for a in inv.addresses) or \
                          any(r.location.get("device_group") == nm for r in inv.rules)
                if not already:
                    _scope_addrs(e, loc, inv)
                    _scope_rules(e, loc, inv)
        # parent-dg from readonly metadata if still missing
        for e in root.findall(".//dg-info/entry") + root.findall(".//readonly//device-group/entry"):
            nm = e.get("name") or ""
            parent = _txt(_ch(e, "parent-dg")) or None
            if nm and nm not in inv.dg_parent:
                inv.dg_parent[nm] = parent
            elif nm and parent and not inv.dg_parent.get(nm):
                inv.dg_parent[nm] = parent
    else:
        for vs in root.findall("./devices/entry/vsys/entry") + root.findall(".//vsys/entry"):
            vn = vs.get("name") or "vsys1"
            loc = _loc(backend="firewall", target=target, kind="vsys", name=vn, vsys=vn,
                       device=inv.device, location="vsys", multi_vsys=multi_vsys)
            already = any(a.location.get("vsys") == vn for a in inv.addresses) or \
                      any(r.location.get("vsys") == vn and r.location.get("target") == target for r in inv.rules)
            if already:
                continue
            _scope_addrs(vs, loc, inv)
            _scope_rules(vs, loc, inv)

    known = {a.name for a in inv.addresses} | {g.name for g in inv.groups}
    if shared is not None:
        loc = _loc(backend=kind, target=target, kind="shared", name="shared", location="shared")
        _walk_other_refs(shared, loc, inv, known)
    return inv


def inventory_from_env(env: Environment) -> Inventory:
    src = env.source_path or env.source
    device = env.devices[0].name if env.devices else env.hostname or env.target
    multi = bool(env.devices and env.devices[0].multi_vsys)
    return inventory_from_xml(src, target=env.target, kind=env.kind, device=device, multi_vsys=multi)


# --------------------------------------------------------------------- plan (shared engine)
#
# The analysis runs in the FlowMapper decommission engine (vendor/flowmapper/decom.js, the same code as the
# offline page). This module turns its result into a change set: groups per target and scope, actions in
# push order, flags, and the tier list the GUI shows.
#
# Tiers (the engine's words):
#   exact     The object or value IS the target. Pre-selected.
#   likely    Built for the target but not identical (a /30 holding it, a /28 named for it, a NAT rule
#             translating to it, an object only a deleted rule used, a negated field). One click to include.
#   possible  The target only falls inside something broader (a /24, a /16, any) or a name hints at it.
#             Never selectable, never changed: advice and blast radius only.

TIER_LABEL = {"exact": "Exact (100%)", "likely": "Highly likely", "possible": "Possible"}
MODES = ("remove", "block")
_FLAG_LEVEL = {"error": "red", "warn": "yellow", "info": "yellow"}
# Red flags that stop a push: an item that matched nothing (remove mode) or could not be parsed, or a deny rule
# that has to be placed by hand. Other red flags are danger callouts (a rule deleted or disabled rather than left 'any').
BLOCKING_CODES = frozenset({"unresolved", "invalid-item", "deny-manual"})


def _scope_label(loc: dict[str, Any]) -> str:
    if loc.get("kind") == "shared" or loc.get("location") == "shared":
        return "shared"
    if loc.get("device_group"):
        return f"device group {loc['device_group']}"
    if loc.get("vsys"):
        dev = loc.get("device") or loc.get("target") or ""
        return f"{dev}/{loc['vsys']}" if dev else loc["vsys"]
    return loc.get("name") or "config"


def _flag(level: str, code: str, message: str, **extra: Any) -> dict[str, Any]:
    out = {"level": level, "code": code, "message": message}
    out.update({k: v for k, v in extra.items() if v is not None})
    return out


def running_only(envs: list[Environment]) -> list[Environment]:
    """Drop a snapshot's ``<x>-candidate.xml`` when ``<x>-running.xml`` is also loaded.

    The candidate file repeats the same device groups, so every finding and action would appear twice. A
    decommission is planned and revalidated against the running config; pending candidate edits are not planned.
    """
    names = {Path(e.source_path or e.source).name for e in envs}
    keep = []
    for e in envs:
        n = Path(e.source_path or e.source).name
        if n.endswith("-candidate.xml") and n[: -len("-candidate.xml")] + "-running.xml" in names:
            continue
        keep.append(e)
    return keep


def _env_files(envs: list[Environment]):
    from panlab.flowmapper import ConfigFile

    files, by_name = [], {}
    for env in envs:
        src = Path(env.source_path or env.source)
        name = src.name
        if name in by_name:
            name = f"{env.target}-{name}"
        by_name[name] = env
        files.append(ConfigFile(src, name))
    return files, by_name


def _lab_loc(eloc: dict[str, Any], by_name: dict[str, Environment]) -> dict[str, Any]:
    """Engine location {file, backend, kind, name} -> PAAT location (target, device_group / vsys / shared)."""
    env = by_name.get(eloc.get("file") or "")
    target = env.target if env else ""
    backend = (env.kind if env else None) or eloc.get("backend") or "firewall"
    kind = eloc.get("kind")
    if kind == "device-group":
        return _loc(backend="panorama", target=target, kind="device-group", name=eloc.get("name"),
                    device_group=eloc.get("name"), location="device-group")
    if kind == "vsys":
        dev = env.devices[0] if env and env.devices else None
        return _loc(backend=backend, target=target, kind="vsys", name=eloc.get("name"), vsys=eloc.get("name"),
                    device=(dev.name if dev else (env.hostname if env else None)) or target, location="vsys",
                    multi_vsys=bool(dev and dev.multi_vsys))
    return _loc(backend=backend, target=target, kind="shared", name="shared", location="shared")


def _panorama_dgs(envs: list[Environment]) -> dict[str, dict[str, Any]]:
    """Per Panorama target: device groups that have firewalls, and each group's descendants (for the push)."""
    out: dict[str, dict[str, Any]] = {}
    for env in envs:
        if env.kind != "panorama":
            continue
        with_devs = sorted(n for n, g in env.device_groups.items() if g.members)
        desc = {n: [d.name for d in env.dg_descendants(n)] for n in env.device_groups}
        out[env.target] = {"with_devices": with_devs, "descendants": desc}
    return out


def build_decom_changeset(profile: Profile, envs: list[Environment], items: list[str], *,
                          tickets: dict[str, list[str]] | None = None,
                          files: list[dict] | None = None,
                          created_by: str = "",
                          mode: str = "remove",
                          flows: list[dict[str, Any]] | None = None,
                          flows_text: str = "",
                          select: list[str] | None = None) -> dict[str, Any]:
    """Run the shared decommission engine on the cached configs and build a change set.

    mode: "remove" (retire: clean out references) or "block" (stop traffic: also flows / flows_text).
    select: candidate and deny ids to include. None = the default (Exact items and every deny rule).
    """
    from panlab.flowmapper import run_decom

    envs = running_only(envs)
    if not envs:
        raise ValueError("no cached configuration to analyse")
    mode = "block" if mode in ("block", "stop") else "remove"
    cfiles, by_name = _env_files(envs)
    r = run_decom(cfiles, list(items), mode=mode, flows=flows, flows_text=flows_text, select=select)
    cs = changeset_from_engine(profile, r, by_name, items, mode=mode, tickets=tickets, files=files,
                               created_by=created_by, select=select, flows=flows, flows_text=flows_text)
    cs["decom"]["panorama"] = _panorama_dgs(envs)
    return attach_configs(cs, envs)


def changeset_from_engine(profile: Profile, r: dict[str, Any], by_name: dict[str, Environment], items: list[str], *,
                          mode: str = "remove", tickets: dict[str, list[str]] | None = None,
                          files: list[dict] | None = None, created_by: str = "",
                          select: list[str] | None = None, flows: list[dict[str, Any]] | None = None,
                          flows_text: str = "") -> dict[str, Any]:
    tickets = tickets or {"ritm": [], "sctask": [], "cr": []}
    flags: list[dict] = []
    unresolved: list[dict] = []

    # Deny rules for stop-traffic go first: the traffic is blocked before anything it used is removed.
    actions: list[dict[str, Any]] = []
    seen_svc: set[tuple] = set()
    fixes = [f for f in ((r.get("block") or {}).get("fixes") or []) if f.get("selected")]
    for fx in fixes:
        if fx.get("manual"):
            flags.append(_flag("red", "deny-manual", f"Deny rule {fx['rule']['name']}: {fx['manual']}", rule=fx["rule"]["name"]))
            continue
        loc = _lab_loc(fx["location"], by_name)
        svc = fx.get("service")
        if svc:
            k = (loc.get("target"), _scope_label(loc), svc["name"])
            if k not in seen_svc:
                seen_svc.add(k)
                actions.append({"op": "add-service", "tier": "exact", "name": svc["name"], "protocol": svc["protocol"],
                                "port": str(svc["port"]), "location": loc, "reason": "deny-rule service",
                                "cli": [c for c in fx["cli"] if " service " in c and " rules " not in c][:1],
                                "rollback": [c for c in fx["rollback"] if " service " in c and " rules " not in c][:1],
                                "verify": [f"Service {svc['name']} ({svc['protocol']}/{svc['port']}, {_scope_label(loc)}) exists."]})
        rule = dict(fx["rule"])
        actions.append({"op": "add-deny-rule", "tier": fx.get("tier") or "exact", "name": rule["name"], "rule_kind": "security",
                        "rulebase": fx.get("rulebase") or ("pre-rulebase" if loc.get("device_group") else "rulebase"),
                        "location": loc, "rule": rule, "place": fx.get("place") or {}, "reason": fx.get("why") or "",
                        "fix_id": fx["id"], "tests": list(fx.get("tests") or []), "serial": fx.get("serial"),
                        "vsys": fx.get("vsys"), "device": fx.get("device"),
                        "cli": [c for c in fx["cli"] if " rules " in c],
                        "rollback": [c for c in fx["rollback"] if " rules " in c],
                        "verify": list(fx.get("verify") or [])})
    for a in (r.get("plan") or {}).get("actions") or []:
        act = {k: v for k, v in a.items() if k not in ("scope", "depth", "scopeLabel")}
        act["location"] = _lab_loc(a["location"], by_name)
        if a.get("danger"):
            act["flag"] = "red"
        if a["op"] == "delete-group":
            snap = dict(act.get("snapshot") or {})
            snap.setdefault("members", list(a.get("members") or []))
            act["snapshot"] = snap
        if a["op"] == "delete-address":
            snap = dict(act.get("snapshot") or {})
            for k in ("type", "value", "description"):
                if a.get(k) is not None:
                    snap.setdefault(k, a.get(k))
            act["snapshot"] = snap
        actions.append(act)
    for i, act in enumerate(actions, 1):
        act["seq"] = i
        act["tierLabel"] = TIER_LABEL.get(act.get("tier") or "exact", "Exact (100%)")

    plan = r.get("plan") or {}
    for d in plan.get("dangers") or []:
        flags.append(_flag("red", "would-broaden" if d.get("code") == "empty-field-would-become-any" else d.get("code") or "danger",
                           d["text"], rule=d.get("rule")))
    for k in plan.get("kept") or []:
        flags.append(_flag("yellow", "kept", k["text"], object=k.get("name")))
    for n in r.get("notes") or []:
        code = n.get("code") or "note"
        if code == "unresolved":
            item = n.get("item") or ""
            if mode == "remove":
                unresolved.append({"item": item, "reason": "not found in the cached config"})
                flags.append(_flag("red", "unresolved", n["text"], item=item))
            else:
                flags.append(_flag("yellow", "unresolved", n["text"] + " Stop traffic still adds deny rules for the flows.", item=item))
            continue
        if code == "invalid-target":
            unresolved.append({"item": n.get("item") or n["text"].split(":", 1)[0], "reason": "invalid"})
            flags.append(_flag("red", "invalid-item", n["text"]))
            continue
        flags.append(_flag(_FLAG_LEVEL.get(n.get("level") or "info", "yellow"), code, n["text"]))
    for c in r.get("candidates") or []:
        if c["kind"] == "group" and c.get("dynamic"):
            flags.append(_flag("yellow", "dynamic-group-named", f"{c['name']} ({c.get('scopeLabel')}) is a dynamic address group. "
                               "Dynamic groups are never edited or deleted automatically; review its filter and the tags on member objects.",
                               object=c["name"]))
        elif c.get("selected"):
            for ev in c.get("evidence") or []:
                if ev.startswith("member of dynamic group"):
                    flags.append(_flag("yellow", "dynamic-group", f"{c['name']}: {ev}.", object=c["name"]))
    block = r.get("block")
    if block:
        for f in block.get("flows") or []:
            for n in f.get("notes") or []:
                flags.append(_flag("yellow", "flow", n))
            if not f.get("places"):
                flags.append(_flag("red", "flow-no-path", f"Flow {f['flow'].get('src')} to {f['flow'].get('dst')}: no place on the "
                                   "traced path checks security policy. Nothing to deny automatically; check the path in Trace a flow."))
        for n in block.get("notes") or []:
            flags.append(_flag("yellow", "block-note", n))

    groups: dict[tuple, dict] = {}

    def group_for(loc: dict[str, Any]) -> dict:
        backend = loc.get("backend") or ("panorama" if loc.get("device_group") else "firewall")
        target = loc.get("target") or (profile.targets[0].name if profile.targets else "")
        dg = loc.get("device_group")
        vsys = loc.get("vsys") or ("vsys1" if backend == "firewall" else None)
        device = loc.get("device") or target
        key = (target, backend, dg or "", device or "", vsys or "", loc.get("kind") == "shared")
        if key not in groups:
            groups[key] = {
                "target": target, "backend": backend, "device": device, "vsys": vsys, "device_group": dg,
                "shared": loc.get("kind") == "shared",
                "rulebase": "pre-rulebase" if backend == "panorama" else "rulebase",
                "multi_vsys": bool(loc.get("multi_vsys")),
                "objects": {"new": [], "reused": []}, "rules": [], "skipped": [], "actions": [],
            }
        return groups[key]

    for act in actions:
        group_for(act["location"])["actions"].append(act)

    cands = r.get("candidates") or []
    related = [{"name": c["name"], "value": c.get("value"), "kind": c["kind"], "tier": c["tier"], "reason": c.get("reason"),
                "where": c.get("scopeLabel"), "advice": c.get("advice") or [], "blast": c.get("blast") or {}}
               for c in cands if c["tier"] == "possible"]
    # Blocking reds stop a push (see pusher._DECOM_PUSH_REFUSE); dangers are red callouts the reviewer must read.
    red = [f for f in flags if f["level"] == "red" and f["code"] in BLOCKING_CODES]
    dangers = [f for f in flags if f["level"] == "red" and f["code"] not in BLOCKING_CODES]
    unique_items = list(dict.fromkeys(items))
    counts = r.get("counts") or {}
    ops = {}
    for a in actions:
        ops[a["op"]] = ops.get(a["op"], 0) + 1
    file_rows = files or [{"file": "pasted-items", "project": "decommission", "tickets": tickets, "rows": len(unique_items)}]
    if file_rows and tickets and not any((f.get("tickets") or {}).get("ritm") or (f.get("tickets") or {}).get("cr") for f in file_rows):
        for f in file_rows:
            f.setdefault("tickets", tickets)
    summary = {
        "requests_in": len(items), "requests_unique": len(unique_items),
        "placed": len(unique_items) - len(unresolved), "unplaced": len(unresolved),
        "rules": ops.get("edit-rule", 0) + ops.get("delete-rule", 0) + ops.get("disable-rule", 0) + ops.get("add-deny-rule", 0),
        "skipped_intrazone": 0, "new_objects": ops.get("add-service", 0), "reused_objects": 0,
        "deleted_objects": ops.get("delete-address", 0), "edited_rules": ops.get("edit-rule", 0),
        "deleted_rules": ops.get("delete-rule", 0), "disabled_rules": ops.get("disable-rule", 0),
        "deleted_groups": ops.get("delete-group", 0), "edited_groups": ops.get("edit-group", 0),
        "deny_rules": ops.get("add-deny-rule", 0),
        "tiers": {"exact": counts.get("exact", 0), "likely": counts.get("likely", 0), "possible": counts.get("possible", 0)},
        "selected": counts.get("selected", 0),
        "red_flags": len(red), "dangers": len(dangers), "needs_human": len(red) + len(unresolved),
        "confidence": {"high": counts.get("exact", 0), "medium": counts.get("likely", 0), "low": counts.get("possible", 0)},
    }
    exports = r.get("exports") or {}
    decom = {
        "engine": dict(r.get("engine") or {}), "mode": mode,
        "request": {"items": unique_items, "flows": list(flows or []), "flows_text": flows_text or ""},
        "select": list(select) if select is not None else None,
        "candidates": [{k: c.get(k) for k in ("id", "kind", "tier", "tierLabel", "rel", "name", "value", "type", "field", "rule",
                                              "ruleType", "rulebase", "scopeLabel", "reason", "evidence", "advice", "blast",
                                              "selectable", "selected", "targets", "dynamic")} for c in cands],
        "fixes": [{k: f.get(k) for k in ("id", "selected", "scopeLabel", "rulebase", "why", "manual", "tests", "device", "serial",
                                         "vsys", "firstPermit", "cli")} | {"name": f["rule"]["name"]}
                  for f in ((block or {}).get("fixes") or [])],
        "block": {"flows": (block or {}).get("flows") or [], "stillAllows": (block or {}).get("stillAllows") or [],
                  "stillAllowsTotal": (block or {}).get("stillAllowsTotal") or 0} if block else None,
        "dangers": plan.get("dangers") or [], "kept": plan.get("kept") or [], "notes": r.get("notes") or [],
        "counts": counts,
        "exports": {"csv": exports.get("csv") or "", "markdown": exports.get("markdown") or ""},
    }
    return {
        "schema": SCHEMA, "kind": KIND, "customer": profile.name,
        "created": datetime.now(TZ).isoformat(timespec="seconds"), "created_by": created_by,
        "default_tags": list(profile.default_tags), "items": unique_items, "files": file_rows, "configs": [],
        "groups": list(groups.values()), "flags": flags, "related": related, "unresolved": unresolved,
        "unplaced": [u["item"] for u in unresolved], "requests": [], "summary": summary, "decom": decom,
    }


def selectable_ids(cs: dict[str, Any]) -> set[str]:
    """Ids the user may tick: Exact and Highly likely candidates, and deny rules. Possible items never."""
    d = cs.get("decom") or {}
    out = {c["id"] for c in d.get("candidates") or [] if c.get("selectable")}
    out |= {f["id"] for f in d.get("fixes") or []}
    return out


def current_selection(cs: dict[str, Any]) -> list[str]:
    d = cs.get("decom") or {}
    return [c["id"] for c in d.get("candidates") or [] if c.get("selected")] + \
           [f["id"] for f in d.get("fixes") or [] if f.get("selected")]


def rebuild_with_selection(profile: Profile, envs: list[Environment], cs: dict[str, Any], select: list[str]) -> dict[str, Any]:
    """Same request, new selection. Unknown or Possible ids are dropped (Possible is never selectable)."""
    allowed = selectable_ids(cs)
    picked = [x for x in dict.fromkeys(select) if x in allowed]
    req = (cs.get("decom") or {}).get("request") or {}
    new = build_decom_changeset(profile, envs, req.get("items") or cs.get("items") or [],
                                tickets=_first_tickets(cs), files=cs.get("files"), created_by=cs.get("created_by") or "",
                                mode=(cs.get("decom") or {}).get("mode") or "remove", flows=req.get("flows") or None,
                                flows_text=req.get("flows_text") or "", select=picked)
    for k in ("config_source", "plan_only"):
        if k in cs:
            new[k] = cs[k]
    return new


def _first_tickets(cs: dict[str, Any]) -> dict[str, list[str]]:
    for f in cs.get("files") or []:
        if f.get("tickets"):
            return f["tickets"]
    return {"ritm": [], "sctask": [], "cr": []}


def attach_configs(cs: dict[str, Any], envs: list[Environment]) -> dict[str, Any]:
    cs["configs"] = [{"target": e.target, "kind": e.kind, "source": e.source, "devices": len(e.devices)} for e in envs]
    return cs


# --------------------------------------------------------------------- CLI / GUI text

def _cli_pre(loc: dict[str, Any], verb: str) -> str:
    """'set'/'delete' prefix for a location, without a trailing space on the bare firewall case."""
    if loc.get("kind") == "shared" or loc.get("location") == "shared":
        return f"{verb} shared"
    if loc.get("device_group"):
        return f"{verb} device-group {qname(loc['device_group'])}"
    if loc.get("multi_vsys") and loc.get("vsys"):
        return f"{verb} vsys {loc['vsys']}"
    return verb


def _rule_cli_path(loc: dict[str, Any], rule_kind: str, rulebase: str) -> str:
    # "delete device-group DG pre-rulebase security rules"
    rb = rulebase if rulebase in {"pre-rulebase", "post-rulebase", "rulebase"} else (
        "pre-rulebase" if loc.get("device_group") else "rulebase"
    )
    noun = f"{rb} {rule_kind} rules"
    return noun


def _with_verb(loc: dict[str, Any], verb: str, rest: str) -> str:
    return f"{_cli_pre(loc, verb)} {rest}"


def action_delete_commands(act: dict[str, Any]) -> list[str]:
    if act.get("cli"):
        return list(act["cli"])
    loc = act["location"]
    op = act["op"]
    lines: list[str] = []
    if op == "edit-rule":
        noun = _rule_cli_path(loc, act["rule_kind"], act.get("rulebase") or "")
        for field_name, vals in (act.get("remove") or {}).items():
            if field_name == "translated-address":
                continue
            for v in vals:
                lines.append(_with_verb(loc, "delete", f"{noun} {qname(act['name'])} {field_name} {qname(v)}"))
        return lines
    if op == "disable-rule":
        noun = _rule_cli_path(loc, act["rule_kind"], act.get("rulebase") or "")
        lines.append(_with_verb(loc, "set", f"{noun} {qname(act['name'])} disabled yes"))
        return lines
    if op == "delete-rule":
        noun = _rule_cli_path(loc, act["rule_kind"], act.get("rulebase") or "")
        lines.append(_with_verb(loc, "delete", f"{noun} {qname(act['name'])}"))
        return lines
    if op == "edit-group":
        for v in act.get("remove") or []:
            lines.append(_with_verb(loc, "delete", f"address-group {qname(act['name'])} static {qname(v)}"))
        return lines
    if op == "delete-group":
        lines.append(_with_verb(loc, "delete", f"address-group {qname(act['name'])}"))
        return lines
    if op == "delete-address":
        lines.append(_with_verb(loc, "delete", f"address {qname(act['name'])}"))
        return lines
    return lines


def _rule_set_command(snap: dict[str, Any]) -> list[str]:
    loc = snap["location"]
    noun = _rule_cli_path(loc, snap.get("kind") or "security", snap.get("rulebase") or "")
    n = qname(snap["name"])
    from panlab.report import _lst

    def lst(key: str, default: list[str] | None = None) -> str:
        vals = snap.get(key) or default or []
        return _lst(vals) if vals else _lst(default or ["any"])

    if snap.get("kind") == "security" or not snap.get("kind"):
        src_user = f" source-user {_lst(snap['source_user'])}" if snap.get("source_user") else ""
        tags = f" tag {_lst(snap['tags'])}" if snap.get("tags") else ""
        desc = f" description {qname(snap['description'])}" if snap.get("description") else ""
        cmd = (_with_verb(loc, "set", f"{noun} {n} from {lst('from', ['any'])} to {lst('to', ['any'])} "
               f"source {lst('source', ['any'])}{src_user} destination {lst('destination', ['any'])} "
               f"application {lst('application', ['any'])} service {lst('service', ['any'])} "
               f"action {snap.get('action') or 'allow'}{tags}{desc}"))
        out = [cmd]
        if snap.get("disabled"):
            out.append(_with_verb(loc, "set", f"{noun} {n} disabled yes"))
        return out
    # NAT / PBF: best-effort set of zones and addresses; translation stays in a comment
    extra = ""
    if snap.get("translated_addresses"):
        extra = f"  # translated-address: {', '.join(snap['translated_addresses'])}; confirm against the cached config"
    cmd = _with_verb(loc, "set", f"{noun} {n} from {lst('from', ['any'])} "
                     + (f"to {lst('to', ['any'])} " if snap.get("to") or snap.get("kind") != "pbf" else "")
                     + f"source {lst('source', ['any'])} destination {lst('destination', ['any'])}")
    out = [cmd + extra]
    if snap.get("xml"):
        out.append(f"# original {snap.get('kind')} XML for {n} is in the change-set snapshot; restore translation settings from it if this set line is incomplete")
    return out


def action_rollback_commands(act: dict[str, Any]) -> list[str]:
    if act.get("rollback"):
        return list(act["rollback"])
    loc = act["location"]
    op = act["op"]
    lines: list[str] = []
    if op == "delete-address":
        snap = act.get("snapshot") or {}
        typ = snap.get("type") or act.get("type") or "ip-netmask"
        val = snap.get("value") or act.get("value") or ""
        lines.append(_with_verb(loc, "set", f"address {qname(act['name'])} {typ} {val}"))
        if snap.get("description"):
            lines.append(_with_verb(loc, "set", f"address {qname(act['name'])} description {qname(snap['description'])}"))
        return lines
    if op == "delete-group":
        snap = act.get("snapshot") or {}
        members = snap.get("members") or []
        if members:
            from panlab.report import _lst
            lines.append(_with_verb(loc, "set", f"address-group {qname(act['name'])} static {_lst(members)}"))
        else:
            lines.append(_with_verb(loc, "set", f"address-group {qname(act['name'])}"))
        return lines
    if op == "edit-group":
        for v in act.get("remove") or []:
            lines.append(_with_verb(loc, "set", f"address-group {qname(act['name'])} static {qname(v)}"))
        return lines
    if op == "delete-rule":
        return _rule_set_command(act.get("snapshot") or {"name": act["name"], "kind": act.get("rule_kind"),
                                                         "rulebase": act.get("rulebase"), "location": loc})
    if op == "disable-rule":
        noun = _rule_cli_path(loc, act["rule_kind"], act.get("rulebase") or "")
        lines.append(_with_verb(loc, "set", f"{noun} {qname(act['name'])} disabled no"))
        return lines
    if op == "edit-rule":
        noun = _rule_cli_path(loc, act["rule_kind"], act.get("rulebase") or "")
        for field_name, vals in (act.get("remove") or {}).items():
            if field_name == "translated-address":
                continue
            for v in vals:
                lines.append(_with_verb(loc, "set", f"{noun} {qname(act['name'])} {field_name} {qname(v)}"))
        return lines
    return lines


def iter_actions(cs: dict[str, Any]) -> Iterable[tuple[dict, dict]]:
    """(group, action) in push order (the engine's sequence; deny rules first, shared objects last)."""
    pairs = [(g, act) for g in cs.get("groups") or [] for act in g.get("actions") or []]
    pairs.sort(key=lambda p: p[1].get("seq") or 0)
    return pairs


def _header(g: dict[str, Any], act: dict[str, Any]) -> str:
    return f"# {g.get('target')} / {_scope_label(act['location'])}"


def delete_commands(cs: dict[str, Any]) -> list[str]:
    """Apply CLI in push order: deny rules, rule edits, rule deletes, group edits, group deletes, objects."""
    out: list[str] = []
    last = None
    for g, act in iter_actions(cs):
        h = _header(g, act)
        if h != last:
            if out:
                out.append("")
            out.append(h)
            last = h
        out.extend(action_delete_commands(act))
    if out:
        out.append("")
    return out


def rollback_commands(cs: dict[str, Any]) -> list[str]:
    """Undo in exact reverse order: objects and groups come back before the rules that use them."""
    out: list[str] = []
    last = None
    for g, act in reversed(iter_actions(cs)):
        h = _header(g, act)
        if h != last:
            if out:
                out.append("")
            out.append(h)
            last = h
        out.extend(action_rollback_commands(act))
    if out:
        out.append("")
    return out


def verify_steps(cs: dict[str, Any]) -> list[str]:
    lines = [
        "After commit, confirm each of the following. Stop and roll back if anything does not match.",
        "",
    ]
    for g, act in iter_actions(cs):
        loc = _scope_label(act["location"])
        if act["op"] == "edit-rule":
            for field_name, vals in (act.get("remove") or {}).items():
                lines.append(f"- Rule `{act['name']}` ({act.get('rule_kind')}, {loc}): `{field_name}` no longer lists "
                             + ", ".join(f"`{v}`" for v in vals)
                             + (f"; remaining: {', '.join(f'`{v}`' for v in act.get('remaining', {}).get(field_name) or [])}"
                                if field_name in (act.get("remaining") or {}) else "")
                             + ".")
        elif act["op"] == "delete-rule":
            lines.append(f"- Rule `{act['name']}` ({act.get('rule_kind')}, {loc}) is gone.")
        elif act["op"] == "disable-rule":
            lines.append(f"- Rule `{act['name']}` ({act.get('rule_kind')}, {loc}) is disabled.")
        elif act["op"] == "edit-group":
            lines.append(f"- Address group `{act['name']}` ({loc}) no longer lists "
                         + ", ".join(f"`{v}`" for v in act.get("remove") or []) + ".")
        elif act["op"] == "delete-group":
            lines.append(f"- Address group `{act['name']}` ({loc}) is gone.")
        elif act["op"] == "delete-address":
            val = f" ({act.get('value')})" if act.get("value") else ""
            lines.append(f"- Address object `{act['name']}`{val} ({loc}) is gone.")
        elif act["op"] == "add-service":
            lines.append(f"- Service `{act['name']}` ({act.get('protocol')}/{act.get('port')}, {loc}) exists.")
        elif act["op"] == "add-deny-rule":
            where = f" on {act.get('device')}" if act.get("device") else ""
            lines.append(f"- Deny rule `{act['name']}` ({loc}) is in place above `{(act.get('place') or {}).get('ref') or 'the first allow'}`.")
            for t in act.get("tests") or []:
                lines.append(f"  - Run{where}: `{t}`; it must return `{act['name']}` (deny).")
    if len(lines) == 2:
        lines.append("- Nothing was proposed for removal.")
    return lines


DECOM_IMPACT = (
    "This change removes decommissioned address objects, address groups, and/or security, NAT, or PBF "
    "policies, removes those objects from remaining policies, and (for Stop traffic) adds narrow deny rules "
    "above the first rule that would still allow the listed flows. Broader objects that only contain the "
    "decommissioned address (a /24, a /16) are not changed. Traffic that depended on the removed "
    "rules or objects will no longer match those rules and may be denied (or hit a lower rule). Existing "
    "unrelated policy is not intended to be changed. The commit is limited to the targets listed in this plan."
)
DECOM_VALIDATION = (
    "After commit, confirm each deleted object and rule is gone, confirm edited rules and groups no longer "
    "list the removed members, and have the requester confirm the decommissioned systems no longer need "
    "the access. See the Verification section."
)
DECOM_BACKOUT = (
    "Re-create the deleted address objects and groups first, then the deleted rules, then put the removed "
    "members back on the edited rules and groups, then delete any deny rules and services this plan added, using the Rollback CLI (taken from the cached config at "
    "plan time). Commit (and, on a standalone firewall, Device > Setup > Operations > Load configuration "
    "version if you prefer to restore the pre-change version)."
)


def is_decom(cs: dict[str, Any]) -> bool:
    return cs.get("kind") == KIND
