# SPDX-License-Identifier: Apache-2.0
"""Combine similar proposed rules and suggest adding objects to existing rules.

Runs after placement and per-request rule construction:

- merge proposed rules that land on the same target, zones, action, and
  service/app (or the same addresses with a union of services)
- when many hosts share a side, put them in a new address group (or reuse
  an existing static group with exactly that membership)
- suggest, but never auto-apply, a subnet object when hosts sit in the same
  prefix
- for each remaining proposed rule, look for an existing enabled allow rule
  that could cover the request if we added the new addresses, or that already
  allows the traffic
"""

from __future__ import annotations

import ipaddress
from typing import Any

from panlab.changeset import _sanitize, _with_rollback
from panlab.customers import Profile
from panlab.netmodel import Environment, ExistingRule, ObjectScope, parse_range

ANY = {"any"}


# --------------------------------------------------------------------- helpers

def _is_any(vals: list[str] | None) -> bool:
    if not vals:
        return True
    return {v.lower() for v in vals} <= ANY


def _set(vals: list[str] | None) -> frozenset[str]:
    return frozenset(vals or [])


def _sorted(vals: list[str] | None) -> list[str]:
    return list(dict.fromkeys(vals or []))


def _flag(level: str, code: str, message: str) -> dict[str, str]:
    return {"level": level, "code": code, "message": message}


def _add_flag(rule: dict, fl: dict) -> None:
    if fl not in rule.setdefault("flags", []):
        rule["flags"].append(fl)


def _rule_ids(rule: dict) -> list[str]:
    ids = list(rule.get("requests") or [])
    if rule.get("request") and rule["request"] not in ids:
        ids.insert(0, rule["request"])
    return ids


def _targets_key(rule: dict) -> tuple:
    return tuple(sorted((t.get("device") or "", t.get("vsys") or "") for t in (rule.get("target_devices") or [])))


def _ticket_key(rule: dict, reqs: dict[str, dict]) -> tuple:
    tix: list[str] = []
    for rid in _rule_ids(rule):
        t = (reqs.get(rid) or {}).get("tickets") or {}
        for k in ("ritm", "sctask", "cr"):
            tix.extend(t.get(k) or [])
    return tuple(sorted(dict.fromkeys(tix))) or ("no-ticket",)


def _scopes_for_group(envs: list[Environment], g: dict) -> list[ObjectScope]:
    for env in envs:
        if env.target != g.get("target"):
            continue
        if g.get("backend") == "panorama":
            return [dg.scope for dg in env.dg_chain(g.get("device_group"))] + [env.shared]
        dev = next((d for d in env.devices if d.name == g.get("device")), None)
        if dev is None and env.devices:
            dev = env.devices[0]
        if dev is not None:
            return env.scopes_for(dev, g.get("vsys") or "vsys1")
        return [env.shared]
    return []


def _env_for(envs: list[Environment], target: str) -> Environment | None:
    return next((e for e in envs if e.target == target), None)


def _taken_names(g: dict, scopes: list[ObjectScope]) -> set[str]:
    names = {o["name"] for o in (g.get("objects") or {}).get("new") or []}
    names |= {o["name"] for o in (g.get("objects") or {}).get("reused") or []}
    for s in scopes:
        names |= set(s.addresses) | set(s.address_groups) | set(s.services)
    return names


def _unique_name(base: str, taken: set[str]) -> str:
    name = base or "GRP"
    if name not in taken:
        taken.add(name)
        return name
    i = 2
    while f"{name[:58]}-{i}" in taken:
        i += 1
    out = f"{name[:58]}-{i}"
    taken.add(out)
    return out


def _obj_lookup(g: dict, scopes: list[ObjectScope]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for s in scopes:
        for a in s.addresses.values():
            out[a.name] = {"kind": "address", "name": a.name, "type": a.type, "value": a.value, "scope": s.label}
        for gn, mems in s.address_groups.items():
            out[gn] = {"kind": "address-group", "name": gn, "members": list(mems),
                       "dynamic": gn in s.dynamic_address_groups, "scope": s.label}
        for sv in s.services.values():
            out[sv.name] = {"kind": "service", "name": sv.name, "protocol": sv.proto, "port": sv.port, "scope": s.label}
    for o in (g.get("objects") or {}).get("reused") or []:
        out.setdefault(o["name"], dict(o))
    for o in (g.get("objects") or {}).get("new") or []:
        out[o["name"]] = dict(o)
    return out


def _range_of_obj(o: dict | None) -> tuple[int, int] | None:
    if not o:
        return None
    if o.get("kind") == "address":
        typ, val = o.get("type"), o.get("value")
        if typ in ("ip-netmask", "ip-range") and val:
            return parse_range(val)
    return None


def _is_host(o: dict | None) -> bool:
    r = _range_of_obj(o)
    return bool(r and r[0] == r[1])


def _expand_ranges(names: list[str], lookup: dict[str, dict], seen: set[str] | None = None) -> tuple[bool, list[tuple[int, int]], set[str]]:
    """Return (is_any, ip ranges, unresolved names including FQDNs)."""
    seen = seen or set()
    any_side, ranges, other = False, [], set()
    for n in names or []:
        if n.lower() == "any":
            any_side = True
            continue
        if n in seen:
            continue
        seen.add(n)
        o = lookup.get(n)
        if o and o.get("kind") == "address-group" and not o.get("dynamic"):
            a, r, u = _expand_ranges(o.get("members") or [], lookup, seen)
            any_side = any_side or a
            ranges.extend(r)
            other |= u
            continue
        rg = _range_of_obj(o) if o else parse_range(n)
        if rg:
            ranges.append(rg)
        else:
            other.add((o or {}).get("value") or n)
    return any_side, ranges, other


def _covered_by(existing: list[str], proposed: list[str], lookup: dict[str, dict]) -> list[str]:
    """Proposed names not already covered by existing members (by name, group, or containing prefix)."""
    if _is_any(existing):
        return []
    exist_set = set(existing or [])
    ex_any, ex_ranges, ex_other = _expand_ranges(existing or [], lookup)
    if ex_any:
        return []
    missing = []
    for n in proposed or []:
        if n.lower() == "any":
            if not ex_any:
                missing.append(n)
            continue
        if n in exist_set:
            continue
        o = lookup.get(n)
        if o and o.get("kind") == "address-group":
            if n not in exist_set:
                missing.append(n)
            continue
        rg = _range_of_obj(o) if o else parse_range(n)
        if rg and any(e[0] <= rg[0] and rg[1] <= e[1] for e in ex_ranges):
            continue
        val = (o or {}).get("value") or n
        if val in ex_other or n in ex_other:
            continue
        missing.append(n)
    return missing


def _superset(existing: list[str], proposed: list[str]) -> bool:
    if _is_any(existing):
        return True
    if _is_any(proposed):
        return False
    return set(proposed or []) <= set(existing or [])


def _service_compatible(existing: list[str], proposed: list[str]) -> bool:
    """Same or existing is a superset. application-default is only compatible with itself (or any)."""
    if _is_any(existing):
        return True
    ex, pr = [x for x in (existing or [])], [x for x in (proposed or [])]
    if "application-default" in ex and set(pr) - {"application-default"}:
        return False
    return _superset(ex, pr)


# --------------------------------------------------------------------- combine

def _merge_rule(into: dict, other: dict) -> None:
    for field in ("source", "destination", "source_user", "application", "service", "tags", "reason", "origins"):
        for v in other.get(field) or []:
            if v not in (into.get(field) or []):
                into.setdefault(field, []).append(v)
    for td in other.get("target_devices") or []:
        if td not in into.setdefault("target_devices", []):
            into["target_devices"].append(td)
    for sr in other.get("suggested_routes") or []:
        if sr not in into.setdefault("suggested_routes", []):
            into["suggested_routes"].append(sr)
    for fl in other.get("flags") or []:
        _add_flag(into, fl)
    ids = _rule_ids(into)
    for rid in _rule_ids(other):
        if rid not in ids:
            ids.append(rid)
    into["requests"] = ids
    into["request"] = ids[0]
    parts = [p for p in (into.get("description") or "", other.get("description") or "") if p]
    # keep unique description segments (ticket lines often repeat after merge)
    seen, merged = set(), []
    for block in parts:
        for seg in [s.strip() for s in block.split(" | ")]:
            if seg and seg not in seen:
                seen.add(seg)
                merged.append(seg)
    into["description"] = " | ".join(merged)[:1023]
    rank = {"high": 2, "medium": 1, "low": 0}
    if rank.get(other.get("confidence") or "high", 2) < rank.get(into.get("confidence") or "high", 2):
        into["confidence"] = other["confidence"]
    into["needs_human"] = bool(into.get("needs_human") or other.get("needs_human"))
    _add_flag(into, _flag("info", "combined",
                          f"combined with {other.get('name')} (requests {', '.join(_rule_ids(other))})"))


def _combine_key(rule: dict, reqs: dict[str, dict], across_tickets: bool, kind: str) -> tuple:
    base = (
        _set(rule.get("from")),
        _set(rule.get("to")),
        (rule.get("action") or "allow"),
        _targets_key(rule),
    )
    tix = () if across_tickets else _ticket_key(rule, reqs)
    if kind == "svc":
        return base + (_set(rule.get("service")), _set(rule.get("application")), tix)
    # never fold an application-any rule into app-specific ones: [ssh, any] is invalid and would open every port to any app
    any_app = any(a.lower() == "any" for a in (rule.get("application") or ["any"]))
    return base + (_set(rule.get("source")), _set(rule.get("destination")),
                   _set(rule.get("source_user")), tix, any_app)


def _combine_group_rules(g: dict, reqs: dict[str, dict], across_tickets: bool) -> int:
    """In-place merge. Returns how many rules were absorbed."""
    absorbed = 0
    for kind in ("svc", "addr"):
        buckets: dict[tuple, dict] = {}
        keep: list[dict] = []
        for rule in g["rules"]:
            if (rule.get("operation") or "add") not in ("add", None, ""):
                keep.append(rule)
                continue
            key = _combine_key(rule, reqs, across_tickets, kind)
            if key in buckets:
                _merge_rule(buckets[key], rule)
                absorbed += 1
            else:
                buckets[key] = rule
                keep.append(rule)
        g["rules"] = keep
    return absorbed


def _host_names(names: list[str], lookup: dict[str, dict]) -> list[str]:
    return [n for n in names if n.lower() != "any" and _is_host(lookup.get(n))]


def _subnet_notes(hosts: list[str], lookup: dict[str, dict]) -> list[dict]:
    by24: dict[str, list[str]] = {}
    for n in hosts:
        rg = _range_of_obj(lookup.get(n))
        if not rg:
            continue
        net = ipaddress.IPv4Network((rg[0], "255.255.255.0"), strict=False)
        by24.setdefault(str(net), []).append(n)
    out = []
    for prefix, members in sorted(by24.items()):
        total = 256
        n = len(members)
        if n < 2:
            continue
        if n >= total:
            msg = f"hosts fully cover {prefix}; consider using the subnet object instead of individual hosts"
        else:
            msg = f"{n} of {total} hosts in {prefix}; consider using the subnet object"
        out.append(_flag("info", "subnet-suggest", msg))
    return out


def _dst_token(names: list[str], lookup: dict[str, dict]) -> str:
    hosts = _host_names(names, lookup)
    if hosts:
        nets = {}
        for n in hosts:
            rg = _range_of_obj(lookup.get(n))
            if rg:
                net = ipaddress.IPv4Network((rg[0], "255.255.255.0"), strict=False)
                nets.setdefault(str(net), 0)
                nets[str(net)] += 1
        if nets:
            best = max(nets, key=lambda k: nets[k])
            if nets[best] >= 2:
                return best.replace("/", "_")
    if names:
        o = lookup.get(names[0]) or {}
        return (o.get("value") or names[0]).replace("/", "_")
    return "multi"


def _group_name(profile: Profile, side: str, project: str, src_token: str, dst_token: str, taken: set[str]) -> str:
    tmpl = profile.naming.get("address_group_source" if side == "source" else "address_group")
    if not tmpl:
        tmpl = profile.naming.get("address_group") or "{project}-{dst}-SRV-GRP"
    try:
        raw = tmpl.format(project=project or "FCR", src=src_token, dst=dst_token)
    except (KeyError, IndexError):
        raw = f"{project or 'FCR'}-{dst_token if side == 'destination' else src_token}-GRP"
    return _unique_name(_sanitize(raw), taken)


def _find_existing_group(scopes: list[ObjectScope], members: list[str]) -> tuple[str, str] | None:
    want = set(members)
    for s in scopes:
        for gn, mems in s.address_groups.items():
            if gn in s.dynamic_address_groups:
                continue
            if set(mems) == want:
                return gn, s.label
    return None


def _find_new_group(g: dict, members: list[str]) -> str | None:
    want = set(members)
    for o in (g.get("objects") or {}).get("new") or []:
        if o.get("kind") == "address-group" and set(o.get("members") or []) == want:
            return o["name"]
    return None


def _location_of(g: dict) -> dict[str, Any]:
    if g.get("backend") == "panorama":
        loc = {"location": "shared" if not g.get("device_group") else "device-group"}
        if g.get("device_group"):
            loc["device_group"] = g["device_group"]
        return loc
    loc = {"location": "vsys", "vsys": g.get("vsys") or "vsys1", "multi_vsys": bool(g.get("multi_vsys"))}
    return loc


def _project_for(rule: dict, reqs: dict[str, dict]) -> str:
    for rid in _rule_ids(rule):
        if (reqs.get(rid) or {}).get("project"):
            return reqs[rid]["project"]
    return "FCR"


def _maybe_group_side(g: dict, rule: dict, side: str, profile: Profile, scopes: list[ObjectScope],
                      lookup: dict[str, dict], taken: set[str], reqs: dict[str, dict], threshold: int) -> None:
    names = [n for n in (rule.get(side) or []) if n.lower() != "any"]
    hosts = _host_names(names, lookup)
    # leave non-host members (nets, FQDNs, existing groups) on the rule
    if len(hosts) < threshold:
        for fl in _subnet_notes(hosts, lookup):
            _add_flag(rule, fl)
        return
    reused = _find_existing_group(scopes, hosts)
    if reused:
        gname, scope = reused
        (g.setdefault("objects", {}).setdefault("reused", []))
        key = f"address-group:{gname}"
        if not any(o.get("name") == gname and o.get("kind") == "address-group" for o in g["objects"]["reused"]):
            g["objects"]["reused"].append({"kind": "address-group", "name": gname, "members": list(hosts), "scope": scope})
        _add_flag(rule, _flag("info", "reused-group",
                              f"{side}: reused existing address group {gname} with the same {len(hosts)} members"))
    else:
        existing_new = _find_new_group(g, hosts)
        if existing_new:
            gname = existing_new
        else:
            src_token = _dst_token(rule.get("source") or [], lookup)
            dst_token = _dst_token(rule.get("destination") or [], lookup)
            gname = _group_name(profile, side, _project_for(rule, reqs), src_token, dst_token, taken)
            loc = _location_of(g)
            obj = _with_rollback({
                "kind": "address-group", "name": gname, "members": list(hosts),
                "description": f"panlab: {len(hosts)} hosts on {side}",
                **loc,
            }, profile)
            g.setdefault("objects", {}).setdefault("new", []).append(obj)
            lookup[gname] = obj
            _add_flag(rule, _flag("info", "new-group",
                                  f"{side}: {len(hosts)} hosts placed in new address group {gname}"))
    others = [n for n in names if n not in hosts]
    rule[side] = others + [gname]
    for fl in _subnet_notes(hosts, lookup):
        _add_flag(rule, fl)


def _rename_combined(rule: dict, profile: Profile, lookup: dict[str, dict], used: set[str], reqs: dict[str, dict]) -> None:
    """Give a merged rule a clearer name when several destinations were folded in."""
    if len(_rule_ids(rule)) <= 1:
        return
    if rule.get("name_locked"):
        return
    dsts = rule.get("destination") or ["any"]
    if len(dsts) == 1:
        o = lookup.get(dsts[0]) or {}
        dtxt = _dst_token(o.get("members") or dsts, lookup) if o.get("kind") == "address-group" else dsts[0]
    else:
        dtxt = _dst_token(dsts, lookup)
    ports: list[str] = []
    for rid in _rule_ids(rule):
        for s in (reqs.get(rid) or {}).get("services") or []:
            token = s.split("/")[-1] if "/" in str(s) else str(s)
            if token and token not in ports:
                ports.append(token)
    if not ports:
        ports = [s for s in (rule.get("service") or ["any"])]
    port = "_".join(ports[:2]) + ("_etc" if len(ports) > 2 else "")
    project = _project_for(rule, reqs)
    tmpl = profile.naming.get("rule") or "{project}-{dst}-{port}"
    try:
        base = _sanitize(tmpl.format(project=project, dst=str(dtxt).replace("/", "_"), port=port,
                                     ritm="", sctask="", cr="", row="", file=""))
    except (KeyError, IndexError):
        base = _sanitize(f"{project}-{dtxt}-{port}")
    name, i = base, 2
    reserved = used - {rule.get("name")}
    while name in reserved:
        name = f"{base[:59]}-{i}"
        i += 1
    if rule.get("name") in used:
        used.discard(rule["name"])
    rule["name"] = name
    used.add(name)


def apply_combine(cs: dict[str, Any], profile: Profile, envs: list[Environment], *,
                  enabled: bool = True, across_tickets: bool | None = None,
                  threshold: int | None = None) -> None:
    """Merge similar rules and optionally group hosts. Mutates the change set."""
    cs["combine"] = bool(enabled)
    cs["combine_across_tickets"] = profile.combine_across_tickets if across_tickets is None else bool(across_tickets)
    cs["address_group_threshold"] = int(profile.address_group_threshold if threshold is None else threshold)
    reqs = {r["id"]: r for r in cs.get("requests") or []}
    absorbed = 0
    for g in cs.get("groups") or []:
        if enabled:
            absorbed += _combine_group_rules(g, reqs, cs["combine_across_tickets"])
        used = {r["name"] for r in g["rules"]}
        scopes = _scopes_for_group(envs, g)
        lookup = _obj_lookup(g, scopes)
        taken = _taken_names(g, scopes)
        for rule in g["rules"]:
            if rule.get("operation") == "already-allowed":
                continue  # permitted by an existing rule: nothing to group or rename
            _maybe_group_side(g, rule, "source", profile, scopes, lookup, taken, reqs, cs["address_group_threshold"])
            _maybe_group_side(g, rule, "destination", profile, scopes, lookup, taken, reqs, cs["address_group_threshold"])
            if enabled:
                _rename_combined(rule, profile, lookup, used, reqs)
    cs.setdefault("summary", {})["combined_into"] = absorbed
    _refresh_summary(cs)


# --------------------------------------------------------------------- existing-rule reuse

def _wanted_rulebase(g: dict) -> set[str]:
    if g.get("backend") == "panorama":
        return {"pre-rulebase"}
    return {"rulebase"}


def _rule_targets_ok(er: ExistingRule, rule: dict) -> bool:
    if not er.target_serials:
        return True  # all devices in the DG / the vsys
    want = {(t.get("serial") or t.get("device") or "", t.get("vsys") or "") for t in (rule.get("target_devices") or [])}
    have: set[tuple[str, str]] = set()
    for serial, vsys in er.target_serials:
        if vsys:
            have.update((serial, v) for v in vsys)
        else:
            have.add((serial, ""))
    if not want:
        return not er.target_negate
    overlap = False
    for sn, vs in want:
        hit = (sn, vs) in have or (sn, "") in have
        if hit:
            overlap = True
    return (not overlap) if er.target_negate else overlap or not have


def _existing_rules(envs: list[Environment], g: dict) -> list[tuple[ExistingRule, ObjectScope]]:
    out: list[tuple[ExistingRule, ObjectScope]] = []
    want_rb = _wanted_rulebase(g)
    scopes = _scopes_for_group(envs, g)
    for s in scopes:
        for er in s.security_rules:
            if er.rulebase in want_rb:
                out.append((er, s))
    return out


def _is_broad(er: ExistingRule) -> bool:
    return any(_is_any(x) for x in (er.source, er.destination, er.application, er.service, er.from_zones, er.to_zones))


def _shadowed_by(er: ExistingRule, earlier: list[ExistingRule]) -> str | None:
    for prev in earlier:
        if prev.disabled or prev.name == er.name:
            continue
        if _set(prev.from_zones) != _set(er.from_zones) or _set(prev.to_zones) != _set(er.to_zones):
            continue
        if _superset(prev.source, er.source) and _superset(prev.destination, er.destination) \
           and _service_compatible(prev.service, er.service) and _superset(prev.application, er.application):
            return prev.name
    return None


def _profile_mismatch(er: ExistingRule, cfg: dict[str, Any]) -> str | None:
    want = (cfg or {}).get("profile_group") or ""
    if want and er.profile_group and er.profile_group != want:
        return f"existing rule uses profile group {er.profile_group}, plan default is {want}"
    if want and not er.profile_group:
        return f"existing rule has no profile group (plan default is {want})"
    log_fwd = (cfg or {}).get("log_forwarding") or ""
    if log_fwd and er.log_setting and er.log_setting != log_fwd:
        return f"existing rule log forwarding is {er.log_setting}, plan default is {log_fwd}"
    return None


def _score(er: ExistingRule, rule: dict, add_src: list[str], add_dst: list[str],
           project: str, flags: list[dict]) -> int:
    score = 100
    share_src = bool(set(er.source) & set(rule.get("source") or []))
    share_dst = bool(set(er.destination) & set(rule.get("destination") or []))
    if share_src or share_dst:
        score += 30
    if share_src and share_dst:
        score += 20
    blob = f"{er.name} {er.description}".lower()
    if project and project.lower() in blob:
        score += 25
    if set(er.service or []) == set(rule.get("service") or []):
        score += 10
    else:
        score -= 5
    if set(er.application or []) == set(rule.get("application") or []):
        score += 5
    score -= 3 * (len(add_src) + len(add_dst))
    if any(f["code"] == "reuse-broad" for f in flags):
        score -= 25
    if any(f["code"] == "reuse-shadowed" for f in flags):
        score -= 20
    if any(f["code"] == "reuse-profile" for f in flags):
        score -= 10
    # fewer other differences: extra members already on the existing rule
    extra = (len(er.source) - len(set(er.source) & set(rule.get("source") or []))) \
        + (len(er.destination) - len(set(er.destination) & set(rule.get("destination") or [])))
    score -= extra
    return score


def _edits_for(er: ExistingRule, add_src: list[str], add_dst: list[str],
               add_tags: list[str], new_description: str | None) -> list[dict]:
    edits = []
    if add_src:
        edits.append({"action": "Add source address", "field": "source", "values": list(add_src)})
    if add_dst:
        edits.append({"action": "Add destination address", "field": "destination", "values": list(add_dst)})
    if add_tags:
        edits.append({"action": "Add tag", "field": "tag", "values": list(add_tags)})
    if new_description is not None and new_description != (er.description or ""):
        edits.append({"action": "Set description", "field": "description", "value": new_description,
                      "previous": er.description or ""})
    return edits


def _candidate_dict(er: ExistingRule, score: int, add_src: list[str], add_dst: list[str],
                    add_tags: list[str], new_description: str | None, flags: list[dict],
                    reasons: list[str], already: bool) -> dict[str, Any]:
    return {
        "name": er.name,
        "score": score,
        "already_allowed": already,
        "add_source": list(add_src),
        "add_destination": list(add_dst),
        "add_tags": list(add_tags),
        "description": new_description,
        "previous_description": er.description or "",
        "existing": {
            "name": er.name, "from": list(er.from_zones), "to": list(er.to_zones),
            "source": list(er.source), "destination": list(er.destination),
            "application": list(er.application), "service": list(er.service),
            "tags": list(er.tags), "description": er.description or "",
            "action": er.action,
        },
        "edits": _edits_for(er, add_src, add_dst, add_tags, new_description),
        "flags": flags,
        "reasons": reasons,
    }


def _append_description(er: ExistingRule, rule: dict) -> str:
    extra = rule.get("description") or ""
    cur = er.description or ""
    if not extra:
        return cur
    if extra in cur:
        return cur
    return (f"{cur} | {extra}" if cur else extra)[:1023]


def _apply_candidate(rule: dict, cand: dict, mode: str) -> None:
    """mode is 'edit', 'already-allowed', or 'new'."""
    rule.setdefault("proposed_name", rule.get("name"))
    rule.setdefault("reuse", {})
    rule["reuse"]["selected"] = mode if mode == "new" else cand["name"]
    rule["reuse"]["verdict"] = mode
    if mode == "new":
        rule["operation"] = "add"
        rule["name"] = rule.get("proposed_name") or rule["name"]
        rule.pop("edits", None)
        return
    if mode == "already-allowed":
        rule["operation"] = "already-allowed"
        rule["name"] = cand["name"]
        rule["edits"] = []
        _add_flag(rule, _flag("info", "already-allowed",
                              f"traffic is already fully allowed by existing rule {cand['name']}"))
        for fl in cand.get("flags") or []:
            _add_flag(rule, fl)
        return
    rule["operation"] = "edit"
    rule["name"] = cand["name"]
    rule["edits"] = list(cand.get("edits") or [])
    # Keep the objects we are adding visible on the rule for CLI / plan, plus existing members.
    ex = cand.get("existing") or {}
    if cand.get("add_source"):
        rule["source"] = _sorted((ex.get("source") or []) + cand["add_source"])
    if cand.get("add_destination"):
        rule["destination"] = _sorted((ex.get("destination") or []) + cand["add_destination"])
    if cand.get("add_tags"):
        rule["tags"] = _sorted((ex.get("tags") or []) + (rule.get("tags") or []))
    if cand.get("description"):
        rule["description"] = cand["description"]
    for fl in cand.get("flags") or []:
        _add_flag(rule, fl)
    reasons = cand.get("reasons") or []
    if reasons:
        _add_flag(rule, _flag("info", "reuse-existing",
                              f"propose adding objects to existing rule {cand['name']}: " + "; ".join(reasons)))


def _find_candidates(rule: dict, g: dict, envs: list[Environment], cfg: dict[str, Any],
                     project: str) -> list[dict]:
    lookup = _obj_lookup(g, _scopes_for_group(envs, g))
    existing = _existing_rules(envs, g)
    earlier: list[ExistingRule] = []
    cands: list[dict] = []
    for er, _scope in existing:
        if er.disabled:
            earlier.append(er)
            continue
        if er.action != "allow":
            earlier.append(er)
            continue
        if _set(er.from_zones) != _set(rule.get("from")) or _set(er.to_zones) != _set(rule.get("to")):
            earlier.append(er)
            continue
        if not _rule_targets_ok(er, rule):
            earlier.append(er)
            continue
        if not _service_compatible(er.service, rule.get("service") or []):
            earlier.append(er)
            continue
        if not _superset(er.application, rule.get("application") or []):
            earlier.append(er)
            continue
        add_src = _covered_by(er.source, rule.get("source") or [], lookup)
        add_dst = _covered_by(er.destination, rule.get("destination") or [], lookup)
        if add_src and _is_any(er.source):
            earlier.append(er)
            continue
        if add_dst and _is_any(er.destination):
            earlier.append(er)
            continue
        already = not add_src and not add_dst
        flags: list[dict] = []
        reasons: list[str] = []
        if already:
            reasons.append("existing rule already covers these addresses, services, and applications")
        else:
            if add_src:
                reasons.append("add source " + ", ".join(add_src))
            if add_dst:
                reasons.append("add destination " + ", ".join(add_dst))
            if set(er.source) & set(rule.get("source") or []):
                reasons.append("already shares source objects")
            if set(er.destination) & set(rule.get("destination") or []):
                reasons.append("already shares destination objects")
        if project and project.lower() in f"{er.name} {er.description}".lower():
            reasons.append(f"name or description mentions project {project}")
        if _is_broad(er):
            flags.append(_flag("yellow", "reuse-broad",
                               f"existing rule {er.name} is broad (any on one or more fields)"))
        sh = _shadowed_by(er, earlier)
        if sh:
            flags.append(_flag("yellow", "reuse-shadowed",
                               f"existing rule {er.name} may be shadowed by {sh}"))
        mm = _profile_mismatch(er, cfg)
        if mm:
            flags.append(_flag("yellow", "reuse-profile", mm))
        add_tags = [t for t in (rule.get("tags") or []) if t not in (er.tags or [])]
        new_desc = None if already else _append_description(er, rule)
        score = _score(er, rule, add_src, add_dst, project, flags)
        if already:
            score += 40
        cands.append(_candidate_dict(er, score, add_src, add_dst, add_tags, new_desc, flags, reasons, already))
        earlier.append(er)
    cands.sort(key=lambda c: (-c["score"], c["name"]))
    return cands


def apply_reuse(cs: dict[str, Any], profile: Profile, envs: list[Environment]) -> None:
    """Attach existing-rule candidates and select a default (edit / already-allowed / new)."""
    from panlab.customers import DEFAULT_CHANGE_PLAN

    cfg = dict(profile.change_plan or DEFAULT_CHANGE_PLAN)
    reqs = {r["id"]: r for r in cs.get("requests") or []}
    edits = allowed = 0
    uid = 0
    for g in cs.get("groups") or []:
        for rule in g.get("rules") or []:
            uid += 1
            rule.setdefault("uid", f"U{uid:03d}")
            rule.setdefault("proposed_name", rule["name"])
            if (rule.get("operation") or "add") not in ("add", None, ""):
                continue
            project = _project_for(rule, reqs)
            rule.setdefault("original_source", list(rule.get("source") or []))
            rule.setdefault("original_destination", list(rule.get("destination") or []))
            rule.setdefault("original_tags", list(rule.get("tags") or []))
            rule.setdefault("original_description", rule.get("description") or "")
            cands = _find_candidates(rule, g, envs, cfg, project)
            rule["reuse"] = {"candidates": cands, "selected": "new", "verdict": "new"}
            if not cands:
                rule["operation"] = "add"
                continue
            best = cands[0]
            if best["already_allowed"]:
                _apply_candidate(rule, best, "already-allowed")
                allowed += 1
            else:
                _apply_candidate(rule, best, "edit")
                edits += 1
    cs.setdefault("summary", {})["edit_existing"] = edits
    cs["summary"]["already_allowed"] = allowed
    _refresh_summary(cs)


def apply_reuse_choice(cs: dict[str, Any], selections: dict[str, str]) -> None:
    """Apply GUI/CLI choices. selections maps rule uid (or name) to 'new' or an existing rule name."""
    by_uid = dict(selections or {})
    for g in cs.get("groups") or []:
        for rule in g.get("rules") or []:
            key = rule.get("uid") or rule.get("proposed_name") or rule["name"]
            choice = by_uid.get(key) or by_uid.get(rule.get("proposed_name") or "") or by_uid.get(rule["name"])
            if not choice:
                continue
            reuse = rule.get("reuse") or {}
            cands = reuse.get("candidates") or []
            if choice in ("new", "add"):
                if "original_source" in rule:
                    rule["source"] = list(rule["original_source"])
                if "original_destination" in rule:
                    rule["destination"] = list(rule["original_destination"])
                if "original_tags" in rule:
                    rule["tags"] = list(rule["original_tags"])
                if "original_description" in rule:
                    rule["description"] = rule["original_description"]
                rule["flags"] = [f for f in (rule.get("flags") or [])
                                 if f.get("code") not in {"already-allowed", "reuse-existing", "reuse-broad",
                                                          "reuse-shadowed", "reuse-profile"}]
                _apply_candidate(rule, {}, "new")
                rule["reuse"]["candidates"] = cands
                continue
            cand = next((c for c in cands if c["name"] == choice), None)
            if cand is None:
                continue
            mode = "already-allowed" if cand.get("already_allowed") else "edit"
            # reset flags that came from a previous candidate
            rule["flags"] = [f for f in (rule.get("flags") or [])
                             if f.get("code") not in {"already-allowed", "reuse-existing", "reuse-broad",
                                                      "reuse-shadowed", "reuse-profile"}]
            _apply_candidate(rule, cand, mode)
            rule["reuse"]["candidates"] = cands
    _refresh_summary(cs)


def _refresh_summary(cs: dict[str, Any]) -> None:
    s = cs.setdefault("summary", {})
    rules = [r for g in cs.get("groups") or [] for r in g.get("rules") or []]
    add = [r for r in rules if (r.get("operation") or "add") == "add"]
    edit = [r for r in rules if r.get("operation") == "edit"]
    allowed = [r for r in rules if r.get("operation") == "already-allowed"]
    s["rules"] = len(add) + len(edit)  # pushable policy actions (not already-allowed)
    s["edit_existing"] = len(edit)
    s["already_allowed"] = len(allowed)
    s["new_objects"] = sum(len((g.get("objects") or {}).get("new") or []) for g in cs.get("groups") or [])
    s["reused_objects"] = sum(len((g.get("objects") or {}).get("reused") or []) for g in cs.get("groups") or [])
    s["needs_human"] = sum(1 for r in add + edit if r.get("needs_human")) + len(cs.get("unplaced") or [])
    s["red_flags"] = (
        sum(1 for r in add + edit for f in r.get("flags") or [] if f.get("level") == "red")
        + sum(1 for rq in cs.get("requests") or []
              if rq.get("id") in (cs.get("unplaced") or [])
              for f in rq.get("flags") or [] if f.get("level") == "red")
    )


def is_add(rule: dict) -> bool:
    return (rule.get("operation") or "add") == "add"


def is_edit(rule: dict) -> bool:
    return rule.get("operation") == "edit"


def is_already_allowed(rule: dict) -> bool:
    return rule.get("operation") == "already-allowed"


def pushable_rules(g: dict) -> list[dict]:
    return [r for r in g.get("rules") or [] if is_add(r) or is_edit(r)]
