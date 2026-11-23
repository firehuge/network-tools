"""Merge FCR rule requests into one change set, placed and grouped by target.

- dedupe identical requests across files (tickets and origins are unioned)
- routing-first placement for every (source, destination) pair
- reuse existing address/service/tag objects by value, searching only the
  scopes a rule at that target can see (Panorama: device-group chain +
  shared; firewall: vsys + shared) and only inside this customer's configs
- new objects follow the customer's naming templates
- free-form rule names (default ``<Project>-<dst>-<port>``, overridable),
  description 'RITM... / SCTASK... / CR... | requester', one tag per ticket
- grouped by target: Panorama device group + pre-rulebase, or firewall/vsys
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, replace
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from panlab import permitted
from panlab.customers import Profile
from panlab.apps import app_flags
from panlab.fcr import Endpoint, Flag, PortSpec, RuleRequest, Tickets
from panlab.netmodel import Device, Environment, ObjectScope, parse_range
from panlab.placement import Placement, place

SCHEMA = "panlab.changeset/v1"
NEEDS_HUMAN_ZONE = "NEEDS-HUMAN"
PREDEFINED_SERVICES = {("tcp", "443"): "service-https"}
NAME_OK = re.compile(r"[^A-Za-z0-9_.\- ]+")
CHICAGO = ZoneInfo("America/Chicago")


def _sanitize(name: str, limit: int = 63) -> str:
    s = NAME_OK.sub("-", name).strip(" -.")
    s = re.sub(r"-{2,}", "-", s)
    return (s or "rule")[:limit].rstrip(" -.")


def dedupe(requests: list[RuleRequest]) -> list[RuleRequest]:
    merged: dict[tuple, RuleRequest] = {}
    for r in requests:
        k = r.key()
        if k not in merged:
            merged[k] = r
            continue
        m = merged[k]
        m.tickets.merge(r.tickets)
        m.origins += [o for o in r.origins if o not in m.origins]
        seen = {(f.code, f.message) for f in m.flags}
        m.flags += [f for f in r.flags if (f.code, f.message) not in seen]
        m.flags.append(Flag("info", "duplicate-merged", f"identical request also in {', '.join(r.origins)}"))
        if r.project and r.project not in m.project:
            m.project = m.project or r.project
    return list(merged.values())


def _range_of(ep: Endpoint) -> tuple[int, int] | None:
    return parse_range(ep.value) if ep.kind in ("ip", "range") else None


def _addr_value_key(typ: str | None, value: str | None) -> tuple | None:
    if not value:
        return None
    if typ == "fqdn":
        return ("fqdn", value.lower().rstrip("."))
    if typ in ("ip-netmask", "ip-range"):
        r = parse_range(value)
        return ("ip", r) if r else None
    return None


class _Ctx:
    """Object lookup + new-object bookkeeping for one target location."""

    def __init__(self, profile: Profile, scopes: list[ObjectScope], location: dict[str, Any]):
        self.profile, self.scopes, self.location = profile, scopes, location
        self.new_addresses: dict[str, dict] = {}
        self.new_services: dict[str, dict] = {}
        self.new_tags: dict[str, dict] = {}
        self.reused: dict[str, dict] = {}
        self.near: dict[str, list[dict]] = {}
        self.taken_below: set[str] = set()
        self.dg_chain: list[str] = []

    def _existing_names(self) -> set[str]:
        out = set()
        for s in self.scopes:
            out |= set(s.addresses) | set(s.address_groups) | set(s.services)
        return out | self.taken_below

    def address(self, ep: Endpoint) -> str:
        want = ("fqdn", ep.value) if ep.kind == "fqdn" else ("ip", _range_of(ep))
        for s in self.scopes:
            for a in s.addresses.values():
                if _addr_value_key(a.type, a.value) == want:
                    self.reused.setdefault(f"address:{a.name}", {"kind": "address", "name": a.name, "value": a.value, "scope": s.label})
                    return a.name
        for n, o in self.new_addresses.items():
            if o["key"] == want:
                return n
        nm = self.profile.naming
        if ep.kind == "fqdn":
            name, typ, val = nm["fqdn"].format(fqdn=ep.value), "fqdn", ep.value
        elif ep.kind == "range":
            a, b = ep.value.split("-")
            name, typ, val = nm["address_range"].format(start=a, end=b), "ip-range", ep.value
        else:
            net = ipaddress.IPv4Network(ep.value, strict=False)
            if net.prefixlen == 32:
                name, typ, val = nm["address_host"].format(ip=net.network_address, len=32), "ip-netmask", f"{net.network_address}/32"
            else:
                name, typ, val = nm["address_net"].format(ip=net.network_address, len=net.prefixlen), "ip-netmask", str(net)
        name = self._unique(_sanitize(name))
        if ep.kind in ("ip", "range") and want[1]:
            ip0 = want[1][0]
            for sc in self.scopes:
                for a in sc.addresses.values():
                    if a.type == "ip-netmask" and a.value:
                        try:
                            n2 = ipaddress.IPv4Network(a.value, strict=False)
                            same_ip = int(ipaddress.IPv4Interface(a.value).ip) == ip0
                        except ValueError:
                            continue
                        if same_ip and _addr_value_key(a.type, a.value) != want:
                            self.near.setdefault(name, []).append({"existing": a.name, "existing_value": a.value,
                                                                   "scope": sc.label, "mask": n2.prefixlen})
        self.new_addresses[name] = {"kind": "address", "name": name, "type": typ, "value": val, "key": want,
                                    "description": f"panlab: {ep.dns}" if ep.dns else "panlab", **self.location}
        return name

    def service(self, ps: PortSpec) -> str:
        if ps.proto == "icmp":
            return "application-default"
        if not ps.port:
            return "any"
        for s in self.scopes:
            for o in s.services.values():
                if o.proto == ps.proto and o.port == ps.port:
                    self.reused.setdefault(f"service:{o.name}", {"kind": "service", "name": o.name, "value": f"{o.proto}/{o.port}", "scope": s.label})
                    return o.name
        pre = PREDEFINED_SERVICES.get((ps.proto, ps.port))
        if pre:
            self.reused.setdefault(f"service:{pre}", {"kind": "service", "name": pre, "value": ps.text, "scope": "predefined"})
            return pre
        name = _sanitize(self.profile.naming["service"].format(proto=ps.proto, port=ps.port))
        if name not in self.new_services:
            name = self._unique(name) if name in self._existing_names() else name
            self.new_services[name] = {"kind": "service", "name": name, "protocol": ps.proto, "port": ps.port, **self.location}
        return name

    def tag(self, name: str) -> str:
        for s in self.scopes:
            if name in s.tags:
                self.reused.setdefault(f"tag:{name}", {"kind": "tag", "name": name, "scope": s.label})
                return name
        self.new_tags.setdefault(name, {"kind": "tag", "name": name, **self.location})
        return name

    def _unique(self, name: str) -> str:
        taken = self._existing_names() | set(self.new_addresses) | set(self.new_services)
        if name not in taken:
            return name
        i = 2
        while f"{name[:58]}-{i}" in taken:
            i += 1
        return f"{name[:58]}-{i}"


def _group_key(p: Placement) -> tuple:
    if p.backend == "panorama":
        return (p.target, "panorama", p.device_group or "?")
    return (p.target, "firewall", p.device, p.vsys)


def _location(p: Placement, profile: Profile, multi_vsys: bool) -> dict[str, Any]:
    shared = profile.object_scope == "shared"
    if p.backend == "panorama":
        return {"location": "shared" if shared else "device-group", "device_group": None if shared else p.device_group}
    return {"location": "shared" if shared else "vsys", "vsys": None if shared else p.vsys, "multi_vsys": multi_vsys}



def build_changeset(profile: Profile, envs: list[Environment], requests: list[RuleRequest], *,
                    files: list[dict] | None = None, name_overrides: dict[str, str] | None = None,
                    name_template: str | None = None, fallback_firewall: str | None = None,
                    combine: bool | None = None,
                    path_placements: dict | None = None,
                    require_profile_targets: bool = True,
                    use_engine_path: bool = False) -> dict[str, Any]:
    if require_profile_targets:
        for e in envs:
            if e.target not in {t.name for t in profile.targets}:
                raise ValueError(f"config for target {e.target!r} is not part of customer {profile.name!r}")
    reqs = dedupe(requests)
    if path_placements is None and use_engine_path:
        # Follow the same hops Trace a flow would. The older zone picker can
        # pick an on-box inter-vsys hand-off when a visible-vsys path exists,
        # even if the routing table leaves the first vsys through a WAN and
        # re-enters another vsys over a router the config cannot see. Single-vsys
        # estates keep the existing placer (fallback routes, combine, etc.).
        try:
            from panlab import flowmapper as fm
            tgt = profile.targets[0].name if profile.targets else (envs[0].target if envs else "default")
            path_placements = fm.placements_for_requests(envs, reqs, target=tgt, scope="all") or None
        except Exception:
            path_placements = None
    dev_by_key = {(d.target, d.name): (e, d) for e in envs for d in e.devices}
    groups: dict[tuple, dict[str, Any]] = {}
    ctxs: dict[tuple, _Ctx] = {}
    rules_by_slot: dict[tuple, dict] = {}
    req_out, unplaced = [], []
    used_names: dict[tuple, set[str]] = {}
    template = name_template or profile.naming["rule"]
    candidate_firewalls: list[str] = []
    used_fallback = False

    for i, r in enumerate(reqs, 1):
        rid = f"R{i:03d}"
        src_p = [e for e in r.sources if e.placeable] or [None]
        dst_p = [e for e in r.destinations if e.placeable] or [None]
        for side, eps in (("source", r.sources), ("destination", r.destinations)):
            for ep in eps:
                rg = _range_of(ep)
                if rg and (rg[1] - rg[0] + 1) >= 2 ** (32 - profile.broad_prefix_len):
                    r.flags.append(Flag("red", "broad", f"{side} {ep.value} is /{profile.broad_prefix_len} or bigger"))
        placements: list[tuple[Placement, Endpoint | None, Endpoint | None]] = []
        notes: list[str] = []
        traced = (path_placements or {}).get(r.key()) if path_placements else None
        if traced:
            s0 = src_p[0] if src_p and src_p[0] is not None else (r.sources[0] if r.sources else None)
            d0 = dst_p[0] if dst_p and dst_p[0] is not None else (r.destinations[0] if r.destinations else None)
            placements = [(p, s0, d0) for p in traced]
            notes.append("placement comes from a FlowMapper path trace, one hop per vsys")
            if any(p.needs_human for p in traced):
                notes.append("path trace flagged device-group or zone placement as needing a human")
        elif src_p == [None] and dst_p == [None]:
            notes.append("neither side has an IP; cannot place")
        else:
            for s in src_p:
                for d in dst_p:
                    res = place(envs, s.value if s else None, d.value if d else None,
                                firewall_hint=r.firewall, fallback_firewall=fallback_firewall)
                    notes += [n for n in res.notes if n not in notes]
                    placements += [(p, s, d) for p in res.placements]
                    if res.fallback:
                        used_fallback = True
                    for n in res.candidate_firewalls:
                        if n not in candidate_firewalls:
                            candidate_firewalls.append(n)
        mgmt = sorted({p for ps in r.services for p in profile.mgmt_ports if ps.proto in ("tcp", "any") and ps.covers(p)})
        if not placements:
            unplaced.append(rid)
            pick = ("; pick a target firewall to build the plan: " + ", ".join(candidate_firewalls)
                    if candidate_firewalls else "")
            r.flags.append(Flag("yellow", "needs-human",
                                "no placement found: " + "; ".join(notes or ["unknown"]) + pick))
            if mgmt:
                r.flags.append(Flag("red", "mgmt-port", f"management port(s) {mgmt} requested and placement unknown"))
        req_out.append({"id": rid, **_req_dict(r), "placements": [p.to_dict() for p, _, _ in placements], "placement_notes": notes})

        # already permitted by the existing policy? (per requested service, over every placed source x destination)
        slot_chk: dict[tuple, dict] = {}
        by_dev: dict[tuple, tuple] = {}
        for p, s, d in placements:
            if (p.rule_needed or p.already_permitted_by) and p.from_zone and p.to_zone:
                k = _group_key(p) + (rid, p.from_zone, p.to_zone, p.device, p.vsys)
                by_dev.setdefault(k, (p, []))[1].append((s, d))
        for k, (p, pairs) in by_dev.items():
            if p.already_permitted_by:
                # Path trace already named the allowing rule. Do not re-place with netmodel.
                chk = {"permitted": [{"service": ps.text, "rules": [{"rule": p.already_permitted_by, "port_based": False}]} for ps in r.services],
                       "missing": [], "blocked": [], "notes": [f"path trace: already permitted by {p.already_permitted_by}"]}
                slot = k[:-2]
                slot_chk[slot] = chk
                continue
            env, dev = dev_by_key[(p.target, p.device)]
            chk = permitted.check_request(env, dev, p, r, pairs)
            slot = k[:-2]
            if slot not in slot_chk:
                slot_chk[slot] = chk
            else:  # every firewall in the slot must already permit a service
                cur = slot_chk[slot]
                miss = [ps for ps in r.services if ps in cur["missing"] or ps in chk["missing"]]
                cur["permitted"] = [e for e in cur["permitted"] if e["service"] not in {m.text for m in miss}]
                cur["missing"] = miss
                cur["blocked"] += [b for b in chk["blocked"] if b not in cur["blocked"]]
                cur["notes"] += [n for n in chk["notes"] if n not in cur["notes"]]
        if slot_chk:
            req_out[-1]["policy_check"] = [
                {"from": sl[-2], "to": sl[-1], "group": list(sl[:-3]), "permitted": c["permitted"],
                 "missing": [m.text for m in c["missing"]], "blocked": c["blocked"], "notes": c["notes"],
                 "status": "permitted" if not c["missing"] else ("partial" if c["permitted"] else "not-permitted")}
                for sl, c in slot_chk.items()]

        for p, s, d in placements:
            env_dev = dev_by_key.get((p.target, p.device))
            if env_dev is None:
                # Path-traced hostname may not match a netmodel device (merge, or backup-only).
                env_dev = next(((e, d0) for (t, n), (e, d0) in dev_by_key.items() if n == p.device), None)
            if env_dev is None and envs:
                env_dev = (envs[0], envs[0].devices[0] if envs[0].devices else None)
            if env_dev is None or env_dev[1] is None:
                notes.append(f"no config model for {p.device}; skipped hop")
                continue
            env, dev = env_dev
            gk = _group_key(p)
            if gk not in groups:
                g = {"target": p.target, "backend": p.backend}
                g.update({"device_group": p.device_group, "rulebase": "pre-rulebase"} if p.backend == "panorama"
                         else {"device": p.device, "vsys": p.vsys, "multi_vsys": dev.multi_vsys, "rulebase": "rulebase"})
                g.update({"rules": [], "skipped": []})
                groups[gk] = g
                ctxs[gk] = _Ctx(profile, env.scopes_for(dev, p.vsys), _location(p, profile, dev.multi_vsys))
                if p.backend == "panorama" and p.device_group:
                    # names in descendant device groups would clash with (or shadow) a new object here
                    ctxs[gk].taken_below = {n for dg in env.dg_descendants(p.device_group) for n in
                                            set(dg.scope.addresses) | set(dg.scope.address_groups) | set(dg.scope.services)}
                    ctxs[gk].dg_chain = [dg.name for dg in env.dg_chain(p.device_group)]
                if p.backend == "panorama":
                    # rule names must be unique across the whole device-group hierarchy (and shared):
                    # one name set per Panorama, seeded with every existing rule name
                    pk = ("panorama-rule-names", p.target)
                    if pk not in used_names:
                        used_names[pk] = set(env.shared.rule_names) | {n for dg in env.device_groups.values() for n in dg.scope.rule_names}
                    used_names[gk] = used_names[pk]
                else:
                    used_names[gk] = {n for sc in env.scopes_for(dev, p.vsys) for n in sc.rule_names}
            g, ctx = groups[gk], ctxs[gk]
            if not p.rule_needed:
                g["skipped"].append({"request": rid, "device": p.device, "vsys": p.vsys, "from": p.from_zone, "to": p.to_zone, "why": "; ".join(p.notes)})
                continue
            fz, tz = p.from_zone or NEEDS_HUMAN_ZONE, p.to_zone or NEEDS_HUMAN_ZONE
            slot = gk + (rid, fz, tz)
            chk = slot_chk.get(slot)
            if chk is not None and not chk["missing"]:
                # fully permitted by existing rule(s): no new rule and no new objects, shown green in the plan
                rule = rules_by_slot.get(slot)
                if rule is None:
                    by = permitted.label(chk["permitted"])
                    first = chk["permitted"][0]["rules"][0]["rule"]
                    rule = {"name": first, "proposed_name": None, "request": rid, "requests": [rid],
                            "operation": "already-allowed", "from": [fz], "to": [tz], "source": [], "source_user": [],
                            "destination": [], "application": [a for a in r.applications if a] or ["any"],
                            "service": [ps.text for ps in r.services], "action": "allow", "description": "", "tags": [],
                            "target_devices": [], "confidence": p.confidence, "needs_human": False,
                            "flags": [{"level": "green", "code": "already-permitted", "message": f"Already permitted by {by}"}],
                            "reason": [], "origins": r.origins, "permitted_by": chk["permitted"],
                            "reuse": {"candidates": [], "selected": first, "verdict": "already-allowed"}}
                    pbr = sorted({x["rule"] for e in chk["permitted"] for x in e["rules"] if x.get("port_based")})
                    if pbr:
                        rule["flags"].append({"level": "info", "code": "permitted-port-based", "message":
                                              f"permitted by port-based rule(s) {', '.join(pbr)} (any application on these "
                                              "ports); run the App-ID advisor on them to tighten to the real applications"})
                    rules_by_slot[slot] = rule
                    g["rules"].append(rule)
                for ep in ([s] if s is not None else [e for e in r.sources if e.kind != "user"]):
                    if ep.value not in rule["source"]:
                        rule["source"].append(ep.value)
                for ep in ([d] if d is not None else list(r.destinations)):
                    if ep.value not in rule["destination"]:
                        rule["destination"].append(ep.value)
                td = {"device": p.device, "serial": p.serial, "vsys": p.vsys}
                if td not in rule["target_devices"]:
                    rule["target_devices"].append(td)
                if p.reason not in rule["reason"]:
                    rule["reason"].append(p.reason)
                continue
            rq = r if chk is None or not chk["permitted"] else replace(r, services=list(chk["missing"]))
            mgmt_rq = sorted({x for ps in rq.services for x in profile.mgmt_ports if ps.proto in ("tcp", "any") and ps.covers(x)})
            rule = rules_by_slot.get(slot)
            if rule is None:
                rule = {"name": None, "request": rid, "from": [fz], "to": [tz], "source": [], "source_user": [],
                        "destination": [], "application": [], "service": [], "action": "allow",
                        "description": "", "tags": [], "target_devices": [], "confidence": p.confidence,
                        "needs_human": p.needs_human, "flags": [], "reason": [], "origins": r.origins}
                rules_by_slot[slot] = rule
                g["rules"].append(rule)
                if p.backend == "panorama" and not p.device_group:
                    rule["flags"].append({"level": "red", "code": "no-device-group", "message":
                                          f"{p.device}/{p.vsys} is managed by Panorama but is in no device group: Panorama "
                                          "cannot push this rule. Add the firewall/vsys to a device group, or configure it "
                                          "locally on the firewall (and record that in the CR)."})
                tt = [profile.naming.get("ticket_tag", "{ticket}").format(ticket=t) for t in r.tickets.all()]
                for t in tt + profile.default_tags:
                    nm = ctx.tag(_sanitize(t, 127))
                    if nm not in rule["tags"]:
                        rule["tags"].append(nm)
                for ps in rq.services:
                    nm = ctx.service(ps)
                    if nm not in rule["service"]:
                        rule["service"].append(nm)
                apps = list(r.applications)
                if any(ps.proto == "icmp" for ps in rq.services):
                    apps += ["icmp", "ping"]
                rule["application"] = list(dict.fromkeys(apps)) or ["any"]
                if "application-default" in rule["service"] and len(rule["service"]) > 1:
                    rule["service"].remove("application-default")
                for ep in r.sources:
                    if ep.kind == "user":
                        rule["source_user"].append(ep.value)
                    elif ep.kind == "fqdn" and s is None:
                        rule["source"].append(ctx.address(ep))
                    elif ep.kind == "any" and "any" not in rule["source"]:
                        rule["source"].append("any")
                for ep in r.destinations:
                    if ep.kind == "fqdn" and d is None:
                        rule["destination"].append(ctx.address(ep))
                    elif ep.kind == "any" and "any" not in rule["destination"]:
                        rule["destination"].append("any")
                desc = [r.tickets.label() or "no ticket"]
                if r.requester:
                    desc.append(f"requester: {r.requester}")
                desc.append("from " + ", ".join(r.origins))
                rule["description"] = " | ".join(desc)[:1023]
                mg_flags = []
                if mgmt_rq:
                    if fz in profile.vpn_landing_zones:
                        mg_flags.append({"level": "info", "code": "mgmt-port", "message": f"management port(s) {mgmt_rq} from VPN landing zone {fz}"})
                    else:
                        mg_flags.append({"level": "red", "code": "mgmt-port", "message": f"management port(s) {mgmt_rq} from zone {fz}, not a VPN landing zone {profile.vpn_landing_zones}"})
                part = []
                if chk is not None and chk["permitted"]:
                    part.append({"level": "yellow", "code": "partly-permitted", "message":
                                 f"partly permitted already: {', '.join(e['service'] for e in chk['permitted'])} by "
                                 f"{permitted.label(chk['permitted'])}; this rule only adds "
                                 f"{', '.join(ps.text for ps in rq.services)}"})
                if chk is not None:
                    for n in chk["notes"]:
                        part.append({"level": "info", "code": "permitted-other-apps", "message":
                                     f"existing rule {n.replace(': ', ' allows this port, but ', 1)}; if the traffic is one of "
                                     "those apps, it is already permitted and no rule is needed"})
                    here = f"{p.device_group} pre-rulebase" if p.backend == "panorama" else p.vsys
                    for b in chk["blocked"]:
                        if "post-rulebase" in b["where"]:
                            continue  # a post-rule deny sits below the new pre-rule: expected, nothing to do
                        if b["where"] == here:
                            if not rule.get("place_before"):
                                rule["place_before"] = b["rule"]
                            part.append({"level": "yellow", "code": "blocked-above", "message":
                                         f"{b['service']}: {b['rule']} ({b['where']}) denies this traffic and sits above the "
                                         f"bottom of the rulebase. The push puts the new rule directly above "
                                         f"{rule['place_before']} so it is not shadowed. Check the deny is not intended."})
                        else:
                            part.append({"level": "red", "code": "blocked-above-elsewhere", "message":
                                         f"{b['service']}: {b['rule']} ({b['where']}) denies this traffic in a rulebase that "
                                         "is evaluated before this one (a parent device group or shared). A rule here "
                                         "cannot win; change or move that deny first."})
                rule["flags"] = rule["flags"] + part + [asdict(f) for f in r.flags] + mg_flags + app_flags(list(rq.services), list(rq.applications))
                sibling = next((x for x in g["rules"] if x is not rule and x["request"] == rid), None)
                suffix = None
                if sibling is not None:
                    suffix = (p.device if sibling["target_devices"] and sibling["target_devices"][0]["device"] != p.device
                              else f"hop{p.hop}" if p.hop else p.vsys)
                rule["name"] = _rule_name(template, rq, (name_overrides or {}).get(rid), used_names[gk], suffix)
            if s is not None:
                n = ctx.address(s)
                if n not in rule["source"]:
                    rule["source"].append(n)
            if d is not None:
                n = ctx.address(d)
                if n not in rule["destination"]:
                    rule["destination"].append(n)
            for fl in list(p.callouts) + [
                    {"level": "info", "code": "near-match",
                     "message": f"object: existing {m['existing']} ({m['existing_value']}, {m['scope']}) has the same IP as new {n} "
                                f"but a different mask. If it is the same host or network, use {m['existing']} instead of creating {n}."}
                    for n in rule["source"] + rule["destination"] for m in ctx.near.get(n, [])]:
                if fl not in rule["flags"]:
                    rule["flags"].append(fl)
            for td in [{"device": p.device, "serial": p.serial, "vsys": p.vsys}] + list(p.also_targets):
                if td not in rule["target_devices"]:
                    rule["target_devices"].append(td)
            if p.suggested_routes:
                rule.setdefault("suggested_routes", [])
                g.setdefault("suggested_routes", [])
                for sr in p.suggested_routes:
                    if sr not in rule["suggested_routes"]:
                        rule["suggested_routes"].append(sr)
                    if sr not in g["suggested_routes"]:
                        g["suggested_routes"].append(sr)
            if p.reason not in rule["reason"]:
                rule["reason"].append(p.reason)
            rank = {"high": 2, "medium": 1, "low": 0}
            if rank[p.confidence] < rank[rule["confidence"]]:
                rule["confidence"] = p.confidence
            rule["needs_human"] = rule["needs_human"] or p.needs_human
            if not rule["source"] and not rule["source_user"]:
                rule["source"] = ["any"]
            if not rule["destination"]:
                rule["destination"] = ["any"]

    out_groups = []
    for gk, g in groups.items():
        ctx = ctxs[gk]
        g["objects"] = {
            "new": [_with_rollback({k: v for k, v in o.items() if k != "key"}, profile)
                    for o in list(ctx.new_addresses.values()) + list(ctx.new_services.values()) + list(ctx.new_tags.values())],
            "reused": list(ctx.reused.values()),
            "near_matches": [{"new": n, **m} for n, ms in ctx.near.items() for m in ms],
        }
        out_groups.append(g)
    _dg_dedupe_callouts(groups, ctxs)
    conf = {"high": 0, "medium": 0, "low": 0}
    for g in out_groups:
        for rule in g["rules"]:
            conf[rule["confidence"]] += 1
    cs = {
        "schema": SCHEMA,
        "default_tags": list(profile.default_tags),
        "customer": profile.name,
        "created": datetime.now(CHICAGO).isoformat(timespec="seconds"),
        "files": files or [],
        "configs": [{"target": e.target, "kind": e.kind, "source": e.source, "devices": len(e.devices)} for e in envs],
        "requests": req_out,
        "groups": out_groups,
        "unplaced": unplaced,
        "candidate_firewalls": candidate_firewalls,
        "fallback": used_fallback,
        "summary": {
            "requests_in": len(requests), "requests_unique": len(reqs), "placed": len(reqs) - len(unplaced),
            "unplaced": len(unplaced), "rules": sum(len(g["rules"]) for g in out_groups),
            "fallback": used_fallback,
            "skipped_intrazone": sum(len(g["skipped"]) for g in out_groups),
            "new_objects": sum(len(g["objects"]["new"]) for g in out_groups),
            "reused_objects": sum(len(g["objects"]["reused"]) for g in out_groups),
            "confidence": conf,
            "red_flags": sum(1 for g in out_groups for r in g["rules"] for f in r["flags"] if f["level"] == "red")
                         + sum(1 for rq in req_out if rq["id"] in unplaced for f in rq["flags"] if f["level"] == "red"),
            "needs_human": sum(1 for g in out_groups for r in g["rules"] if r["needs_human"]) + len(unplaced),
        },
    }
    from panlab.combine import apply_combine, apply_reuse
    do_combine = profile.combine_rules if combine is None else bool(combine)
    apply_combine(cs, profile, envs, enabled=do_combine)
    apply_reuse(cs, profile, envs)
    annotate_enforcement_points(cs)
    return cs


def annotate_enforcement_points(cs: dict) -> None:
    """List every place a request's flow is checked by security policy, and what covers it there.

    A flow that crosses several firewalls, vsys, or the same firewall twice
    (leaves one virtual router and comes back in on another) needs an allow at
    every one of those points. The plan, the push page, and the change plan
    show this list so nobody pushes one rule and misses the other.
    """
    rules = []
    for g in cs.get("groups") or []:
        for r in g.get("rules") or []:
            rules.append((g, r))
        for sk in g.get("skipped") or []:
            rules.append((g, {"skipped": sk}))
    multi = 0
    for rq in cs.get("requests") or []:
        rid = rq.get("id")
        points: list[dict] = []
        seen: set[tuple] = set()
        for pl in rq.get("placements") or []:
            k = (pl.get("device"), pl.get("vsys"), pl.get("from_zone"), pl.get("to_zone"))
            if k in seen:
                continue
            seen.add(k)
            pt = {"device": pl.get("device"), "vsys": pl.get("vsys"), "device_group": pl.get("device_group"),
                  "from": pl.get("from_zone"), "to": pl.get("to_zone"), "hop": pl.get("hop"),
                  "status": "needs-human", "rule": None, "place_before": None}
            for g, r in rules:
                if "skipped" in r:
                    sk = r["skipped"]
                    if sk.get("request") == rid and sk.get("from") == pt["from"] and sk.get("to") == pt["to"] \
                            and sk.get("device") == pt["device"]:
                        pt["status"], pt["rule"] = "no-rule-needed", None
                        break
                    continue
                if rid not in (r.get("requests") or [r.get("request")]):
                    continue
                if pt["from"] not in (r.get("from") or []) or pt["to"] not in (r.get("to") or []):
                    continue
                if pl.get("device_group") and g.get("device_group") != pl.get("device_group"):
                    continue
                if r.get("operation") == "already-allowed":
                    pt["status"], pt["rule"] = "already-allowed", r.get("name")
                else:
                    pt["status"], pt["rule"] = "new-rule", r.get("name")
                    pt["place_before"] = r.get("place_before")
                break
            points.append(pt)
        rq["enforcement_points"] = points
        if len(points) > 1:
            multi += 1
            msg = (f"This flow is checked by security policy in {len(points)} places: "
                   + "; ".join(f"{i}) {p['device']} {p['from'] or '?'} -> {p['to'] or '?'}"
                               for i, p in enumerate(points, 1))
                   + ". Every place needs an allow, or the traffic is still blocked.")
            if all(p["status"] in ("already-allowed", "no-rule-needed") for p in points):
                msg = (f"This flow is checked in {len(points)} places and existing rules already allow it in every one: "
                       + "; ".join(f"{i}) {p['from']} -> {p['to']} by {p['rule'] or 'intrazone default'}"
                                   for i, p in enumerate(points, 1)) + ".")
                level = "info"
            else:
                level = "yellow"
            flags = rq.setdefault("flags", [])
            if not any(f.get("code") == "multi-place" for f in flags):
                flags.append({"level": level, "code": "multi-place", "message": msg})
    cs.setdefault("summary", {})["multi_place"] = multi


def _dg_dedupe_callouts(groups: dict, ctxs: dict) -> None:
    """Same new object value created in several device groups -> suggest one copy in their nearest common ancestor."""
    seen: dict[tuple, list[tuple]] = {}
    for gk, g in groups.items():
        if g["backend"] != "panorama" or not g.get("device_group"):
            continue
        for o in ctxs[gk].new_addresses.values():
            if o.get("location") == "device-group":
                seen.setdefault(("address", o["type"], o["value"]), []).append((gk, o["name"]))
        for o in ctxs[gk].new_services.values():
            if o.get("location") == "device-group":
                seen.setdefault(("service", o["protocol"], o["port"]), []).append((gk, o["name"]))
    for key, uses in seen.items():
        if len({gk for gk, _ in uses}) < 2:
            continue
        chains = [ctxs[gk].dg_chain for gk, _ in uses]
        common = next((d for d in chains[0] if all(d in c for c in chains[1:])), None)
        dgs = sorted({groups[gk]["device_group"] for gk, _ in uses})
        if common in dgs:
            rest = ", ".join(d for d in dgs if d != common)
            msg = (f"object: {key[0]} {key[2]} is created in {', '.join(dgs)}. {rest} inherit(s) from {common}, so create it "
                   f"only in {common} and drop the copies below (or create it in {common} first and re-run the import to reuse it).")
        else:
            where = f"device group {common}" if common else "shared"
            msg = (f"object: {key[0]} {key[2]} is created separately in {', '.join(dgs)}. Consider creating it once in {where} "
                   f"(their nearest common parent) so every child device group inherits it, then re-run the import to reuse it.")
        for gk, name in uses:
            for r in groups[gk]["rules"]:
                if name in r["source"] + r["destination"] + r["service"]:
                    fl = next((f for f in r["flags"] if f["code"] == "dg-common-parent"), None)
                    if fl is None:
                        r["flags"].append({"level": "info", "code": "dg-common-parent", "message": msg})
                    elif msg not in fl["message"]:
                        fl["message"] += " | " + msg


def _with_rollback(o: dict[str, Any], profile: Profile) -> dict[str, Any]:
    """Rollback policy per created object: shared/default tags are never deleted."""
    if o["kind"] == "tag" and o["name"] in profile.default_tags:
        o["rollback"], o["keep_reason"] = "keep", "shared default tag used by other panlab changes"
    else:
        o["rollback"] = "delete-if-unreferenced"
    return o


def _req_dict(r: RuleRequest) -> dict[str, Any]:
    d = r.to_dict()
    d["services"] = [p.text for p in r.services]
    return d


def _rule_name(template: str, r: RuleRequest, override: str | None, used: set[str], suffix: str | None = None) -> str:
    if override:
        base = _sanitize(override)
    else:
        dst = next((e for e in r.destinations if e.kind != "user"), None)
        dtxt = (dst.dns or dst.value) if dst else "any"
        dtxt = dtxt.replace("/", "_")
        ports = [ps.port or ps.proto for ps in r.services] or ["any"]
        port = "_".join(ports[:2]) + ("_etc" if len(ports) > 2 else "")
        tk = r.tickets
        base = _sanitize(template.format(project=r.project or "FCR", dst=dtxt, port=port,
                                         ritm=(tk.ritm or [""])[0], sctask=(tk.sctask or [""])[0], cr=(tk.cr or [""])[0],
                                         row=r.row, file=r.file.rsplit(".", 1)[0]))
    if suffix:
        base = _sanitize(f"{base[:62 - len(suffix)]}-{suffix}")
    name, i = base, 2
    while name in used:
        name = f"{base[:59]}-{i}"
        i += 1
    used.add(name)
    return name

_BUILD_FLAGS = {"needs-human", "broad", "mgmt-port"}


def requests_from_changeset(cs: dict[str, Any]) -> list[RuleRequest]:
    """Rebuild RuleRequest objects from a saved change set (for retargeting)."""
    out: list[RuleRequest] = []
    for rq in cs.get("requests") or []:
        src = [Endpoint(e["kind"], e["value"], e.get("dns")) for e in rq.get("sources") or []]
        dst = [Endpoint(e["kind"], e["value"], e.get("dns")) for e in rq.get("destinations") or []]
        services = []
        for p in rq.get("services") or []:
            if isinstance(p, dict):
                services.append(PortSpec(p["proto"], p.get("port")))
            else:
                proto, _, port = str(p).partition("/")
                services.append(PortSpec(proto, port or None))
        tix = rq.get("tickets") or {}
        tickets = Tickets(list(tix.get("ritm") or []), list(tix.get("sctask") or []), list(tix.get("cr") or []))
        flags = [Flag(f["level"], f["code"], f["message"]) for f in rq.get("flags") or []
                 if f.get("code") not in _BUILD_FLAGS]
        out.append(RuleRequest(
            file=rq.get("file") or "retarget",
            row=int(rq.get("row") or 0),
            project=rq.get("project") or "",
            sources=src,
            destinations=dst,
            services=services,
            applications=list(rq.get("applications") or []),
            firewall=rq.get("firewall"),
            notes=rq.get("notes") or "",
            tickets=tickets,
            requester=rq.get("requester") or "",
            flags=flags,
            origins=list(rq.get("origins") or []),
        ))
    return out
