"""Is a requested flow already permitted by the existing security policy? (read-only, plan time)

A flow is one source endpoint x one destination endpoint x one requested service (proto/port or range) x the requested
applications (none = any application), at one placement (device, vsys, from zone, to zone, Panorama device group).

The rulebase is walked in evaluation order and the first decisive rule wins:

- Panorama: shared pre-rules, device-group pre-rules from the top parent down to the device's group, then the device
  group's post-rules from the device's group up to the top parent, then shared post-rules.
- Firewall: the vsys rulebase.

Disabled rules and rules whose Target does not include the device/vsys are ignored. An allow rule that fully covers the
flow (zones, source and destination incl. groups / ranges / negate, application incl. groups, service incl.
application-default / groups / any) permits it. A deny / drop / reset rule *above* it that overlaps the flow at all makes
the flow "not permitted" (blocked by that rule). Allow rules that cover only part of the flow are skipped (the rest of the
flow still needs a rule). Unknowns (FQDN or dynamic groups, application filters, source users, custom apps on
application-default) never count as covering, so a "permitted" verdict is always safe to rely on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from panlab.apps import APP_PORTS, PREDEFINED_SERVICE_PORTS
from panlab.fcr import Endpoint, PortSpec
from panlab.netmodel import Environment, ExistingRule, ObjectScope, parse_range

DENY_ACTIONS = {"deny", "drop", "reset-client", "reset-server", "reset-both"}
ANY_RANGE = (0, 2**32 - 1)


@dataclass
class Verdict:
    status: str  # permitted | blocked | none
    rule: str = ""
    where: str = ""  # "DG-EXAMPLE pre-rulebase", "shared post-rulebase", "vsys1"
    note: str = ""
    partial_allow: list[str] = field(default_factory=list)  # allow rules that cover part of the flow (for the message)
    port_based: bool = False  # the permitting rule allows any application on explicit ports


# ----------------------------------------------------------------------------- object resolution

class Resolver:
    def __init__(self, scopes: list[ObjectScope]):
        self.scopes = scopes  # most specific first

    def _find(self, attr: str, name: str):
        for s in self.scopes:
            d = getattr(s, attr)
            if name in d:
                return d[name]
        return None

    def addresses(self, names: list[str], _seen: frozenset = frozenset()) -> tuple[bool, list[tuple[int, int]], set[str], bool]:
        """(is_any, ip ranges, fqdn/name tokens, has_unknown)."""
        any_, ranges, tokens, unknown = False, [], set(), False
        for n in names or []:
            if n.lower() == "any":
                any_ = True
                continue
            if n in _seen:
                continue
            grp = self._find("address_groups", n)
            if grp is not None:
                if any(n in s.dynamic_address_groups for s in self.scopes):
                    unknown = True
                    continue
                a, r, t, u = self.addresses(grp, _seen | {n})
                any_, unknown = any_ or a, unknown or u
                ranges += r
                tokens |= t
                continue
            obj = self._find("addresses", n)
            if obj is not None:
                if obj.type in ("ip-netmask", "ip-range") and obj.value and parse_range(obj.value):
                    ranges.append(parse_range(obj.value))
                elif obj.type == "fqdn" and obj.value:
                    tokens.add(obj.value.lower().rstrip("."))
                    tokens.add(n.lower())
                else:
                    unknown = True  # wildcard etc.
                continue
            r = parse_range(n)
            if r:
                ranges.append(r)
            else:
                tokens.add(n.lower())
                unknown = True
        return any_, ranges, tokens, unknown

    def apps(self, names: list[str], _seen: frozenset = frozenset()) -> tuple[bool, set[str], bool]:
        """(is_any, app names, has_unknown e.g. application filters)."""
        any_, out, unknown = False, set(), False
        for n in names or []:
            if n.lower() == "any":
                any_ = True
                continue
            if n in _seen:
                continue
            grp = self._find("app_groups", n)
            if grp is not None:
                a, o, u = self.apps(grp, _seen | {n})
                any_, unknown = any_ or a, unknown or u
                out |= o
                continue
            if any(n in s.app_filters for s in self.scopes):
                unknown = True
                continue
            out.add(n)
        return any_, out, unknown

    def services(self, names: list[str], _seen: frozenset = frozenset()) -> tuple[bool, bool, list[tuple[str, int, int]], bool]:
        """(is_any, application-default, [(proto, lo, hi)], has_unknown)."""
        any_, appdef, out, unknown = False, False, [], False
        for n in names or []:
            low = n.lower()
            if low == "any":
                any_ = True
                continue
            if low == "application-default":
                appdef = True
                continue
            if n in _seen:
                continue
            grp = self._find("service_groups", n)
            if grp is not None:
                a, d, o, u = self.services(grp, _seen | {n})
                any_, appdef, unknown = any_ or a, appdef or d, unknown or u
                out += o
                continue
            obj = self._find("services", n)
            if obj is not None:
                out += [(obj.proto, lo, hi) for lo, hi in port_ranges(obj.port)]
                continue
            if n in PREDEFINED_SERVICE_PORTS:
                out += [(p, lo, hi) for p, v in PREDEFINED_SERVICE_PORTS[n] for lo, hi in port_ranges(v)]
                continue
            unknown = True
        return any_, appdef, out, unknown


def port_ranges(spec: str | None) -> list[tuple[int, int]]:
    out = []
    for part in str(spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        a, _, b = part.partition("-")
        if a.isdigit() and (b.isdigit() or not b):
            out.append((int(a), int(b or a)))
    return out


def _covered(need: list[tuple[int, int]], have: list[tuple[int, int]]) -> bool:
    """Every range in ``need`` lies inside the union of ``have``."""
    merged: list[list[int]] = []
    for lo, hi in sorted(have):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return all(any(m[0] <= lo and hi <= m[1] for m in merged) for lo, hi in need)


def _overlaps(need: list[tuple[int, int]], have: list[tuple[int, int]]) -> bool:
    return any(lo <= h and l <= hi for lo, hi in need for l, h in have)


# ----------------------------------------------------------------------------- matching one rule

def _ep_range(ep: Endpoint) -> tuple[int, int] | None:
    if ep.kind == "any":
        return ANY_RANGE
    return parse_range(ep.value) if ep.kind in ("ip", "range") else None


def _addr_match(rule_names: list[str], negate: bool, ep: Endpoint, res: Resolver) -> tuple[bool, bool]:
    """(covers, overlaps) for one endpoint."""
    any_, ranges, tokens, unknown = res.addresses(rule_names)
    if ep.kind == "user":
        return False, True
    rg = _ep_range(ep)
    if rg is None:  # fqdn endpoint: only an object with the same name / fqdn covers it
        hit = ep.value.lower().rstrip(".") in tokens
        if negate:
            return False, True  # an FQDN against a negated list: cannot prove it
        return (any_ or hit), True
    if negate:
        if any_:
            return False, False
        inside = _overlaps([rg], ranges)
        return (not inside and not unknown and not tokens), not _covered([rg], ranges)
    if any_:
        return True, True
    return _covered([rg], ranges), _overlaps([rg], ranges) or bool(unknown or tokens)


def _app_default_ports(app: str) -> list[tuple[str, int, int]] | None:
    if app in ("ping", "icmp", "traceroute"):
        return [("icmp", 0, 0)]
    d = APP_PORTS.get(app)
    if d is None:
        return None
    return [(p, lo, hi) for p, v in d for lo, hi in port_ranges(v)]


def _svc_match(rule: ExistingRule, ps: PortSpec, apps: list[str], res: Resolver) -> tuple[bool, bool, str]:
    any_, appdef, ranges, unknown = res.services(rule.service or ["any"])
    if ps.proto == "icmp":
        return (any_ or appdef), True, ""
    need = port_ranges(ps.port) if ps.port else [(0, 65535)]
    protos = ["tcp", "udp"] if ps.proto == "any" else [ps.proto]
    if any_:
        return True, True, ""
    cover = True
    over = False
    note = ""
    if appdef:
        if not apps:
            cover = False  # unknown app: application-default cannot be checked
            note = "application-default"
            over = True
        for a in apps:
            d = _app_default_ports(a)
            if d is None:
                cover, over, note = False, True, f"default ports of {a} unknown"
                continue
            for pr in protos:
                have = [(lo, hi) for p, lo, hi in d if p == pr]
                cover = cover and _covered(need, have)
                over = over or _overlaps(need, have)
        if not ranges:
            return cover, over, note
    for pr in protos:
        have = [(lo, hi) for p, lo, hi in ranges if p == pr]
        if not appdef:
            cover = cover and _covered(need, have)
        over = over or _overlaps(need, have)
    if appdef and ranges:  # application-default mixed with ports is not valid on PAN-OS; be conservative
        cover = False
    if unknown:
        over = True
    return cover, over, note


def _app_match(rule: ExistingRule, apps: list[str], res: Resolver) -> tuple[bool, bool, str]:
    any_, have, unknown = res.apps(rule.application or ["any"])
    if any_:
        return True, True, ""
    if not apps:
        return False, True, f"only application(s) {', '.join(sorted(have)) or '?'}"
    cover = all(a in have for a in apps)
    over = any(a in have for a in apps) or unknown
    return cover, over, ""


def _zone_ok(members: list[str], zone: str | None) -> bool:
    return not members or any(m.lower() == "any" for m in members) or (zone in members)


def target_ok(er: ExistingRule, serial: str | None, vsys: str | None) -> bool:
    if not er.target_serials:
        return True
    hit = any(s == (serial or "") and (not v or (vsys in v)) for s, v in er.target_serials)
    return (not hit) if er.target_negate else hit


def match(er: ExistingRule, *, fz: str | None, tz: str | None, src: Endpoint, dst: Endpoint, ps: PortSpec,
          apps: list[str], res: Resolver) -> tuple[bool, bool, str]:
    """(covers, overlaps, note)."""
    if not (_zone_ok(er.from_zones, fz) and _zone_ok(er.to_zones, tz)):
        return False, False, ""
    # an intrazone rule only matches traffic that stays in one zone; an interzone rule never does
    rt = getattr(er, "rule_type", "universal")
    if fz and tz and ((rt == "intrazone" and fz != tz) or (rt == "interzone" and fz == tz)):
        return False, False, ""
    sc, so = _addr_match(er.source, er.negate_source, src, res)
    dc, do = _addr_match(er.destination, er.negate_destination, dst, res)
    ac, ao, anote = _app_match(er, apps, res)
    vc, vo, vnote = _svc_match(er, ps, apps, res)
    users_ok = not er.source_user or any(u.lower() == "any" for u in er.source_user)
    covers = sc and dc and ac and vc and users_ok
    overlaps = so and do and ao and vo
    return covers, overlaps, anote or vnote


# ----------------------------------------------------------------------------- evaluation order

def ordered_rules(env: Environment, *, device_group: str | None, vsys_scope: ObjectScope | None
                  ) -> list[tuple[ExistingRule, str]]:
    if env.kind == "panorama":
        chain = env.dg_chain(device_group)  # leaf -> root
        out = [(r, "shared pre-rulebase") for r in env.shared.security_rules if r.rulebase == "pre-rulebase"]
        for dg in reversed(chain):
            out += [(r, f"{dg.name} pre-rulebase") for r in dg.scope.security_rules if r.rulebase == "pre-rulebase"]
        for dg in chain:
            out += [(r, f"{dg.name} post-rulebase") for r in dg.scope.security_rules if r.rulebase == "post-rulebase"]
        out += [(r, "shared post-rulebase") for r in env.shared.security_rules if r.rulebase == "post-rulebase"]
        return out
    rules = vsys_scope.security_rules if vsys_scope else []
    return [(r, vsys_scope.name if vsys_scope else "vsys") for r in rules if r.rulebase == "rulebase"]


def evaluate(rules: list[tuple[ExistingRule, str]], res: Resolver, *, serial: str | None, vsys: str | None,
             fz: str | None, tz: str | None, src: Endpoint, dst: Endpoint, ps: PortSpec, apps: list[str]) -> Verdict:
    partial: list[str] = []
    notes: list[str] = []
    for er, where in rules:
        if er.disabled or not target_ok(er, serial, vsys):
            continue
        covers, overlaps, note = match(er, fz=fz, tz=tz, src=src, dst=dst, ps=ps, apps=apps, res=res)
        if er.action in DENY_ACTIONS:
            if overlaps:
                return Verdict("blocked", er.name, where, f"{er.action} rule {er.name} ({where}) above any allow", partial)
            continue
        if er.action != "allow":
            continue
        if covers:
            pb = (any(a.lower() == "any" for a in er.application or ["any"])
                  and not any(x.lower() in ("any", "application-default") for x in er.service or ["any"]))
            return Verdict("permitted", er.name, where, "", partial, port_based=pb)
        if overlaps:
            partial.append(f"{er.name} ({where})")
            if note:
                notes.append(f"{er.name}: {note}")
    return Verdict("none", note="; ".join(notes), partial_allow=partial)


# ----------------------------------------------------------------------------- one request at one placement

def check_request(env: Environment, dev: Any, p: Any, r: Any, pairs: list[tuple[Endpoint | None, Endpoint | None]]
                  ) -> dict[str, Any]:
    """Per requested service: permitted (by which rule) or not, over every source x destination pair at this placement.

    ``pairs`` holds the (source, destination) endpoints placed here; None means "the request's unplaced endpoints"
    (FQDN / any), which are expanded from the request itself.
    """
    vsys = dev.vsys.get(p.vsys)
    res = Resolver(env.scopes_for(dev, p.vsys))
    rules = ordered_rules(env, device_group=p.device_group, vsys_scope=vsys.scope if vsys else None)
    apps = [a for a in (r.applications or []) if a and a.lower() != "any"]
    if any(ps.proto == "icmp" for ps in r.services) and not apps:
        apps = ["ping"]
    users = [e for e in r.sources if e.kind == "user"]
    out = {"permitted": [], "missing": [], "blocked": [], "notes": []}
    for ps in r.services:
        verdicts = []
        for s, d in pairs:
            srcs = [s] if s is not None else ([e for e in r.sources if e.kind != "user"] or [Endpoint("any", "any")])
            dsts = [d] if d is not None else ([e for e in r.destinations if e.kind != "user"] or [Endpoint("any", "any")])
            for se in srcs:
                for de in dsts:
                    verdicts.append(evaluate(rules, res, serial=p.serial or dev.serial, vsys=p.vsys, fz=p.from_zone,
                                             tz=p.to_zone, src=se, dst=de, ps=ps, apps=apps))
        if users:
            verdicts.append(Verdict("none", note="source users are not checked"))
        rulesets = {(v.rule, v.where, v.port_based) for v in verdicts}
        if verdicts and all(v.status == "permitted" for v in verdicts):
            out["permitted"].append({"service": ps.text, "rules": [{"rule": a, "where": b, "port_based": c}
                                                                    for a, b, c in sorted(rulesets)]})
        else:
            out["missing"].append(ps)
            for v in verdicts:
                if v.status == "blocked":
                    b = {"service": ps.text, "rule": v.rule, "where": v.where}
                    if b not in out["blocked"]:
                        out["blocked"].append(b)
                if v.note and v.status == "none" and v.note not in out["notes"]:
                    out["notes"].append(v.note)
    return out


def label(entries: list[dict]) -> str:
    """'RULE-NAME (DG-EXAMPLE)' style list."""
    seen = []
    for e in entries:
        for r in e["rules"]:
            where = r["where"].replace(" pre-rulebase", "").replace(" post-rulebase", " post")
            t = f"{r['rule']} ({where})"
            if t not in seen:
                seen.append(t)
    return ", ".join(seen)
