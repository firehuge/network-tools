# SPDX-License-Identifier: Apache-2.0
"""Routing-first rule placement.

For each requested source/destination (IP, CIDR or range) find which
firewall(s) and vsys see the flow and which zones it enters and leaves by:

1. connected interface subnet (an interface IP's subnet contains the address),
2. otherwise a route lookup (longest prefix, then admin distance, then metric)
   in the vsys' router, following next-vr / next-lr hops; when the hop lands
   on a router or interface owned by another vsys or a shared gateway, the
   zone is that vsys' *external* zone that points at the other side.

A device/vsys is a placement only as an *owner* when at least one side is
"local" to it (a connected subnet, or a specific static route of /16 or
longer) and that side's interface lives in that vsys. A side reached only
through a default route or a short summary/aggregate (shorter than /16)
lowers confidence and is never treated as ownership. Several placements
are allowed (source on one firewall, destination on another, multi-vsys).
When nothing owns either side, candidates that only matched a broad or
default route are kept as low-confidence, needs-human placements with a
proposed rule (the engineer can delete it), rather than auto-picking a
"best" firewall or concluding that no rule is needed. A fallback also
builds a plan if the customer has one firewall, the FCR Firewall column
names one, or the GUI target-firewall picker does: zones come from the
longest-prefix route (including the default route), RFC1918 addresses that
only hit the default (or have no route) get a "Route needed" suggestion
on that VR, and the result is a proposed rule plus objects rather than an
empty failure. HA secondaries are folded into their primary, and
devices on different template stacks never pair (no cross-site HA false
pairing). Same-zone flows are marked intrazone; ``rule_needed`` is False
only when both sides are connected or specific *and* the vsys
intrazone-default action is allow. A default or summary match in the same
zone still produces a proposed rule and a yellow callout.

Candidates are then pruned and ranked (``_prune``): firewalls that own a
side (connected or specific route) win; the path between them is stitched
firewall to firewall by next-hop IPs that belong to another firewall's
interface, and those transit hops are kept. Without any owner, every
broad-route candidate is kept as needs-human rather than a single "best"
tier being auto-selected.
Same-zone candidates in one Panorama device group collapse into one rule
with several targets. Everything else goes to ``alternatives``. When no
owner is found and some firewalls have no network config in the source,
the result lists them under ``needs_local_backup``.

Ported in spirit from FlowMapper's resolveForward/lookupRoute/externalZone
(see NOTICE).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field, replace

from panlab.netmodel import Device, Environment, Interface, Route, Router, Vsys

Net = ipaddress.IPv4Network
SUMMARY_MAX_LEN = 15  # a static shorter than /16 is a summary/aggregate, not a specific route
SPECIFIC_MIN_LEN = 16
BROAD_SAME_ZONE = (
    "both sides follow the same broad route via {iface}; "
    "the real path likely goes through another firewall or a transit - confirm"
)


def _prefixlen(s: "Side | None") -> int:
    if not s or not s.prefix or "/" not in s.prefix:
        return -1
    try:
        return int(s.prefix.split("/", 1)[1])
    except ValueError:
        return -1


def _is_broad(s: "Side | None") -> bool:
    """True when the match is a default or a summary/aggregate, not a connected or specific route."""
    if s is None:
        return False
    if s.kind in ("default", "summary"):
        return True
    return s.kind == "static" and 0 <= _prefixlen(s) < SPECIFIC_MIN_LEN



@dataclass
class Side:
    kind: str  # connected | local | static | summary | default | none | discard | unresolved
    iface: str | None = None
    zone: str | None = None
    vsys: str | None = None
    route: str | None = None
    prefix: str | None = None
    crossed: list[str] = field(default_factory=list)
    ecmp: bool = False
    partial: bool = False
    nexthop: str | None = None
    router: str | None = None  # virtual/logical router where the final route was found
    iface_router: str | None = None  # router the egress interface belongs to (if different)

    @property
    def local(self) -> bool:
        # Connected subnet, or a specific static route (not a default or a short summary).
        if self.kind in ("connected", "local"):
            return True
        if self.kind == "static":
            return _prefixlen(self) >= SPECIFIC_MIN_LEN
        return False

    def describe(self, label: str, addr: str) -> str:
        if self.kind in ("none", "unresolved", "discard"):
            return f"{label} {addr}: no usable route ({self.kind})"
        via = {"connected": "connected", "local": "firewall-owned", "static": "static route",
               "summary": "summary route", "default": "default route"}[self.kind]
        cross = f" via {' -> '.join(self.crossed)}" if self.crossed else ""
        return f"{label} {addr} {via} {self.prefix} on {self.iface} (zone {self.zone or '?'}, {self.vsys}){cross}"


@dataclass
class Placement:
    target: str
    backend: str  # firewall | panorama
    device: str
    serial: str | None
    vsys: str
    device_group: str | None
    stack: str | None
    from_zone: str | None
    to_zone: str | None
    reason: str
    confidence: str  # high | medium | low
    needs_human: bool = False
    rule_needed: bool = True
    intrazone: bool = False
    ha_peer: str | None = None
    notes: list[str] = field(default_factory=list)
    callouts: list[dict] = field(default_factory=list)  # routing callouts (suggestions only)
    suggested_routes: list[dict] = field(default_factory=list)  # VR static-route proposals; never auto-pushed
    role: str = "route-only"  # owner-both | source-owner | destination-owner | transit | route-only | fallback | path-hop
    also_targets: list[dict] = field(default_factory=list)  # other firewalls the same Panorama rule targets
    already_permitted_by: str | None = None  # existing rule name from a path trace (skip netmodel permitted check)
    hop: int | None = None  # 1-based enforcement point when one flow crosses this firewall more than once
    hops_total: int | None = None  # how many enforcement points the flow has on this path

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PlacementResult:
    placements: list[Placement]
    needs_human: bool
    notes: list[str] = field(default_factory=list)
    alternatives: list[Placement] = field(default_factory=list)  # pruned candidates, shown for troubleshooting only
    needs_local_backup: list[str] = field(default_factory=list)  # firewalls without network config in this source
    candidate_firewalls: list[str] = field(default_factory=list)  # multi-FW, no owner: user must pick one
    fallback: bool = False  # True when the plan was built without a connected/specific owner

    def to_dict(self) -> dict:
        return {"placements": [p.to_dict() for p in self.placements], "needs_human": self.needs_human, "notes": self.notes,
                "alternatives": [p.to_dict() for p in self.alternatives], "needs_local_backup": self.needs_local_backup,
                "candidate_firewalls": self.candidate_firewalls, "fallback": self.fallback}


def as_net(value: str | Net) -> Net | None:
    if isinstance(value, Net):
        return value
    s = str(value).strip()
    if "-" in s:  # range -> covering supernet of the first address (placement only)
        a, _, b = s.partition("-")
        try:
            lo, hi = ipaddress.IPv4Address(a.strip()), ipaddress.IPv4Address(b.strip())
        except ValueError:
            return None
        if hi < lo:
            return None
        nets = list(ipaddress.summarize_address_range(lo, hi))
        n = nets[0]
        while not (n.network_address <= hi <= n.broadcast_address) and n.prefixlen > 0:
            n = n.supernet()
        return n
    try:
        return ipaddress.IPv4Network(s, strict=False)
    except ValueError:
        return None


def lookup_route(router: Router, q: Net) -> tuple[Route | None, bool, bool]:
    best, key, ties = None, None, 0
    for r in router.routes:
        if r.nexthop_type == "none" and r.kind == "static" and not r.iface:
            continue
        if q.network_address not in r.dest:
            continue
        k = (r.dest.prefixlen, -r.ad, -r.metric)
        if key is None or k > key:
            best, key, ties = r, k, 1
        elif k == key:
            ties += 1
    if best is None:
        return None, False, False
    partial = not (q.broadcast_address in best.dest)
    return best, ties > 1, partial


def _routers_for_vsys(dev: Device, vsys: str) -> list[Router]:
    key = ("routers", vsys)
    if key not in dev.cache:
        dev.cache[key] = _routers_for_vsys_uncached(dev, vsys)
    return dev.cache[key]


def _connected(dev: Device) -> list[tuple[Net, Interface]]:
    if "connected" not in dev.cache:
        dev.cache["connected"] = sorted(((ip.network, it) for it in dev.interfaces.values() for ip in it.ips
                                         if ip.network.prefixlen < 32), key=lambda x: -x[0].prefixlen)
    return dev.cache["connected"]


def _routers_for_vsys_uncached(dev: Device, vsys: str) -> list[Router]:
    seen, out = set(), []
    for r in dev.routers.values():
        if id(r) in seen:
            continue
        seen.add(id(r))
        if r.owner == vsys or any(dev.interfaces.get(i) and dev.interfaces[i].vsys == vsys for i in r.interfaces):
            out.append(r)
    if not out and not dev.multi_vsys:
        out = [r for r in {id(x): x for x in dev.routers.values()}.values()]
    return out


def _iface_side(dev: Device, it: Interface, q: Net) -> Side | None:
    for ip in it.ips:
        if ip.network.prefixlen < 32 and q.network_address in ip.network:
            return Side("connected", it.name, it.zone, it.vsys, f"connected {it.name}", str(ip.network),
                        partial=q.broadcast_address not in ip.network)
    return None


_QCACHE: dict = {}  # per place() call: query-level memo (connected hit, route walk)
_DEV_OF: dict = {}  # per place() call: id(placement) -> device it was evaluated on


def _conn_hit(dev: Device, q: Net):
    k = ("conn", id(dev), q)
    if k not in _QCACHE:
        _QCACHE[k] = next(((net, it) for net, it in _connected(dev) if q.network_address in net), None)
    return _QCACHE[k]


def _follow_cached(dev: Device, router: Router, q: Net) -> Side:
    k = ("follow", id(dev), id(router), q)
    if k not in _QCACHE:
        _QCACHE[k] = _follow(dev, router, q)
    s = _QCACHE[k]
    return replace(s, crossed=list(s.crossed))


def resolve(dev: Device, vsys: str, q: Net) -> Side:
    """Where does *q* sit from the point of view of (dev, vsys)."""
    # 1) connected subnet anywhere on the device (owner vsys recorded)
    hit = _conn_hit(dev, q)
    for net, it in ([hit] if hit else []):
        if q.network_address in net:
            s = Side("connected", it.name, it.zone, it.vsys, f"connected {it.name}", str(net),
                     partial=q.broadcast_address not in net, router=it.router)
            r = dev.routers.get(it.router) if it.router else None
            if r is None or any(r is x for x in _routers_for_vsys(dev, vsys)) or it.vsys == vsys:
                return s
            # connected in another vsys' router: reached through inter-vsys
            s.crossed.append(f"vsys {it.vsys}")
            return s
    best: Side | None = None
    for start in _routers_for_vsys(dev, vsys):
        side = _follow_cached(dev, start, q)
        if best is None or _rank(side) > _rank(best):
            best = side
    return best or Side("none")


def _rank(s: Side) -> tuple:
    order = {"connected": 6, "local": 6, "static": 5, "summary": 3, "default": 2, "unresolved": 1, "discard": 0, "none": 0}
    plen = int(s.prefix.split("/")[1]) if s.prefix and "/" in s.prefix else -1
    return (order.get(s.kind, 0), plen)


def _follow(dev: Device, router: Router, q: Net) -> Side:
    crossed: list[str] = []
    cur = router
    visited: set[int] = set()
    for _ in range(8):
        if id(cur) in visited:
            return Side("unresolved", route="routing loop between virtual routers", crossed=crossed)
        visited.add(id(cur))
        r, ecmp, partial = lookup_route(cur, q)
        if r is None:
            return Side("none", crossed=crossed, router=cur.name)
        if r.nexthop_type == "discard":
            return Side("discard", route=r.name, prefix=str(r.dest), crossed=crossed)
        if r.nexthop_type == "next-vr":
            nxt = dev.routers.get(r.nexthop or "")
            if nxt is None:
                return Side("unresolved", route=r.name, prefix=str(r.dest), crossed=crossed)
            crossed.append(f"router {nxt.name}")
            cur = nxt
            continue
        iface = r.iface
        if not iface and r.nexthop_type == "ip" and r.nexthop:
            try:
                nq = ipaddress.IPv4Network(f"{r.nexthop}/32")
            except ValueError:
                return Side("unresolved", route=r.name, prefix=str(r.dest), crossed=crossed)
            c, _, _ = lookup_route(cur, nq)
            if c and c.iface:
                iface = c.iface
        it = dev.interfaces.get(iface or "")
        if it is None:
            return Side("unresolved", route=r.name, prefix=str(r.dest), crossed=crossed)
        if r.kind in ("connected", "local"):
            kind = r.kind
        elif r.dest.prefixlen == 0:
            kind = "default"
        elif r.dest.prefixlen <= SUMMARY_MAX_LEN:
            kind = "summary"
        else:
            kind = "static"
        nh = r.nexthop if r.nexthop_type == "ip" else None
        ir = it.router if it.router and it.router != cur.name else None
        return Side(kind, it.name, it.zone, it.vsys, r.name, str(r.dest), crossed, ecmp, partial, nh, cur.name, ir)
    return Side("unresolved", crossed=crossed)


def _zone_in(dev: Device, v: Vsys, side: Side) -> tuple[str | None, str | None]:
    """Zone in vsys *v* for a side; external zone if the side lives in another vsys/shared gateway."""
    if side.vsys == v.name or side.vsys is None:
        return side.zone, None
    for z in v.zones.values():
        if z.type == "external" and side.vsys in z.members:
            return z.name, f"inter-vsys: {v.name} reaches {side.vsys} through external zone {z.name}"
    return None, f"inter-vsys: no external zone in {v.name} pointing at {side.vsys}"


def place(envs: list[Environment], src: str | Net | None, dst: str | Net | None,
          firewall_hint: str | None = None, fallback_firewall: str | None = None) -> PlacementResult:
    """Place one (src, dst) pair. A None side (AD group / FQDN only) places by the other side."""
    _QCACHE.clear()
    _DEV_OF.clear()
    sq = as_net(src) if src is not None else None
    dq = as_net(dst) if dst is not None else None
    out: list[Placement] = []
    notes: list[str] = []
    devices = [d for e in envs for d in e.devices]
    env_of = {d.id: e for e in envs for d in e.devices}
    if firewall_hint:
        h = firewall_hint.strip().lower()
        hinted = [d for d in devices if h and (h in d.name.lower() or (d.serial and h == d.serial.lower()))]
        if hinted:
            devices = hinted
            notes.append(f"limited to firewall(s) matching hint '{firewall_hint}'")
        else:
            notes.append(f"firewall hint '{firewall_hint}' matched no device; used routing only")
    sides: dict[int, tuple[Side | None, Side | None]] = {}

    def evaluate(dev: Device, v: Vsys, relaxed: bool) -> tuple[Placement | None, set[str]]:
        s = resolve(dev, v.name, sq) if sq is not None else None
        d = resolve(dev, v.name, dq) if dq is not None else None
        s_routed = s is not None and s.kind in ("connected", "local", "static", "summary", "default")
        d_routed = d is not None and d.kind in ("connected", "local", "static", "summary", "default")
        s_here = s is not None and s.vsys in (v.name, None) and not s.crossed and (s.local or relaxed or s_routed)
        d_here = d is not None and d.vsys in (v.name, None) and not d.crossed and (d.local or relaxed or d_routed)
        if not (s_here or d_here):
            return None, set()
        if (s is not None and s.kind in ("none", "discard")) or (d is not None and d.kind in ("none", "discard")):
            for label, q, x in (("source", sq, s), ("destination", dq, d)):
                if x is not None and x.kind == "none" and q is not None:
                    vr = x.router or "?"
                    notes.append(f"routing: {dev.name}/{v.name}: {label} {q} has no route at all in virtual router {vr} (no default "
                                 f"route either), so traffic cannot be forwarded. If this firewall should carry it, add a route "
                                 f"(suggestion, not pushed): set network virtual-router {vr} routing-table ip static-route "
                                 f"to-{q.network_address}_{q.prefixlen} destination {q} interface <egress-interface> nexthop "
                                 f"ip-address <next-hop>")
                elif x is not None and x.kind == "discard":
                    notes.append(f"{dev.name}/{v.name}: {label} {q} hits a discard (blackhole) route; skipped")
            return None, set()
        pnotes: list[str] = []
        fz, n1 = _zone_in(dev, v, s) if s else (None, "source has no IP (AD group or FQDN); pick the source zone")
        tz, n2 = _zone_in(dev, v, d) if d else (None, "destination has no IP (FQDN); pick the destination zone")
        pnotes += [n for n in (n1, n2) if n]
        conf = "medium" if any(x is not None and x.kind in ("default", "summary") for x in (s, d)) else "high"
        if any(x is not None and (x.ecmp or x.partial) for x in (s, d)):
            conf = "low"
            pnotes.append("ECMP or partial route match")
        if relaxed:
            pnotes.append("on the path: traffic crosses into this vsys from another vsys on the same firewall")
        needs = fz is None or tz is None
        if needs:
            conf = "low"
        reason = "; ".join((
            s.describe("src", str(sq)) if s else "src: no IP",
            d.describe("dst", str(dq)) if d else "dst: no IP"))
        p = Placement(target=dev.target, backend=dev.backend, device=dev.name, serial=dev.serial, vsys=v.name,
                      device_group=v.device_group if dev.backend == "panorama" else None, stack=dev.stack,
                      from_zone=fz, to_zone=tz, reason=reason, confidence=conf, needs_human=needs,
                      ha_peer=dev.ha_peer, notes=pnotes)
        if dev.backend == "panorama" and not v.device_group:
            p.needs_human = True
            p.confidence = "low"
            p.notes.append("firewall/vsys is not in any device group")
        ztypes = {v.zones[z].type for z in (fz, tz) if z and z in v.zones}
        if {"layer3", "virtual-wire"} <= ztypes or ("virtual-wire" in ztypes and "external" in ztypes):
            p.needs_human = True
            p.confidence = "low"
            p.notes.append(f"zone type mismatch: {fz} and {tz} mix layer3/external and virtual-wire zones; PAN-OS rejects that")
        if fz and tz and fz == tz:
            p.intrazone = True
            broad = _is_broad(s) or _is_broad(d)
            if broad:
                ifaces: list[str] = []
                for side in (s, d):
                    if side and side.iface and side.iface not in ifaces:
                        ifaces.append(side.iface)
                msg = BROAD_SAME_ZONE.format(iface="/".join(ifaces) or "?")
                p.rule_needed = True
                p.needs_human = True
                p.confidence = "low"
                p.notes.append(msg)
            elif (v.intrazone_default or "allow") == "allow":
                p.rule_needed = False
                p.notes.append("intrazone: default intrazone allow already permits this; no rule needed unless the default is overridden")
            else:
                p.rule_needed = True
                p.notes.append("intrazone: default intrazone action is deny here, so a rule is needed")
        if dev.ha_peer:
            p.notes.append(f"HA pair with {dev.ha_peer}: one rule covers both")
        p.callouts, p.suggested_routes = suggest_routes(
            dev, v.name, (("source", sq, s), ("destination", dq, d)),
            _template_for(env_of.get(dev.id), dev))
        if p.intrazone and (_is_broad(s) or _is_broad(d)):
            iface_msg = next((n for n in p.notes if n.startswith("both sides follow the same broad route")), None)
            p.callouts.append({
                "level": "yellow",
                "code": "broad-same-zone",
                "message": iface_msg or BROAD_SAME_ZONE.format(iface="?"),
            })
            if not any(c.get("code") == "route-same-zone" for c in p.callouts):
                p.callouts.append({
                    "level": "yellow",
                    "code": "route-same-zone",
                    "message": (
                        f"both source and destination resolve to zone {fz}; this would be an intrazone rule. "
                        "Suggest a new zone or a more specific route instead of silently making a same-zone rule. "
                        "The rule is still in the plan so you can edit the zones."
                    ),
                })
        s_own = s is not None and s.local and s_here
        d_own = d is not None and d.local and d_here
        p.role = ("owner-both" if s_own and d_own else "source-owner" if s_own else "destination-owner" if d_own
                  else "transit" if relaxed else "route-only")
        sides[id(p)] = (s, d)
        _DEV_OF[id(p)] = dev
        other = {x.vsys for x in (s, d) if x is not None and x.vsys and x.vsys != v.name}
        return p, other

    for dev in devices:
        if dev.ha_secondary or dev.no_network:
            continue
        done: set[str] = set()
        follow: list[str] = []
        for v in dev.vsys.values():
            if v.shared_gateway:
                continue
            p, other = evaluate(dev, v, relaxed=False)
            if p:
                out.append(p)
                done.add(v.name)
                follow += sorted(other)
        for name in follow:  # continue the path into the vsys the flow crosses into
            v = dev.vsys.get(name)
            if v is None or v.shared_gateway:
                if v is not None and v.shared_gateway and name not in done:
                    notes.append(f"{dev.name}: flow uses shared gateway {name}; SG has no security policy, NAT only")
                    done.add(name)
                continue
            if name in done:
                # Already added in the first pass as route-only (a default or
                # summary was enough to count as "here"). This vsys is on the
                # path of an owner; promote it to transit so prune keeps it.
                for existing in out:
                    if existing.device == dev.name and existing.vsys == name and existing.role == "route-only":
                        existing.role = "transit"
                        existing.notes.append(
                            "on the path: traffic crosses into this vsys from another vsys on the same firewall"
                        )
                continue
            done.add(name)
            p, _ = evaluate(dev, v, relaxed=True)
            if p:
                out.append(p)
    out = _split_reentry(out, sides, sq, dq, notes)
    kept, alts = _prune(out, sides, devices, sq, dq, evaluate, notes)
    backup = []
    if not any(p.role != "route-only" for p in kept):
        backup = sorted({d.name for d in devices if d.no_network and not d.ha_secondary})
        if backup:
            more = f" (+{len(backup) - 5} more)" if len(backup) > 5 else ""
            notes.append(f"needs local backup: {len(backup)} firewall(s) have no network config in this source, so they "
                         f"could own the subnet: {', '.join(backup[:5])}{more}. Upload their device backups to place on them.")
    fallback = False
    candidates: list[str] = []
    owners_kept = any(p.role in ("owner-both", "source-owner", "destination-owner") for p in kept)
    if kept and not owners_kept:
        fallback = True
        for p in kept:
            if p.role == "route-only":
                p.role = "fallback"
    if kept and fallback_firewall and not owners_kept:
        chosen = [
            p for p in kept
            if fallback_firewall.strip().lower() in p.device.lower()
            or (p.serial and fallback_firewall.strip().lower() == p.serial.lower())
        ]
        if chosen:
            alts = [p for p in kept if p not in chosen] + alts
            kept = chosen
            fallback = True
            notes.append(
                f"target firewall '{fallback_firewall}' used because the networks are not on a connected subnet "
                "or specific route"
            )
    if not kept:
        targets = _fallback_targets(devices, fallback_firewall, notes)
        if not targets:
            candidates = sorted({d.name for d in devices if not d.ha_secondary and not d.no_network})
            notes.append("no firewall or vsys has the source or destination on a connected subnet or specific route")
            if len(candidates) > 1:
                notes.append(
                    "pick a target firewall to build address objects, the security rule, and route suggestions: "
                    + ", ".join(candidates)
                )
        else:
            for dev in targets:
                p = _fallback_placement(dev, sq, dq, env_of)
                if p:
                    kept.append(p)
                    fallback = True
            if kept:
                who = ", ".join(sorted({p.device for p in kept}))
                notes.append(
                    f"these networks are not on a connected subnet or specific route; proposing objects, a rule, "
                    f"and any needed routes on {who}"
                )
            else:
                notes.append("no firewall or vsys has the source or destination on a connected subnet or specific route")
    needs_human = not kept or all(p.needs_human for p in kept)
    return PlacementResult(kept, needs_human, notes, alts, backup, candidates, fallback)


_NO_PATH = ("none", "discard", "unresolved")


def reentry_hops(dev: Device, s: Side | None, d: Side | None, sq: Net | None, dq: Net | None) -> tuple[Side, Side] | None:
    """Same vsys, different virtual routers, no next-vr between them.

    The source's router sends the flow out of an interface toward something
    outside the config (a WAN router, a hairpin), and it comes back in on the
    destination router's interface. PAN-OS then sees two sessions and checks
    security policy twice: (source zone -> egress zone) on the way out and
    (ingress zone -> destination zone) on the way back in. Returns the two
    route walks (out, back), or None when one rule is enough.
    """
    if s is None or d is None or sq is None or dq is None:
        return None
    if not s.router or not d.router or s.router == d.router:
        return None
    if s.vsys != d.vsys or s.crossed or d.crossed:
        return None
    r_src, r_dst = dev.routers.get(s.router), dev.routers.get(d.router)
    if r_src is None or r_dst is None:
        return None
    out = _follow(dev, r_src, dq)
    if out.kind in _NO_PATH or not out.iface or out.iface == d.iface or f"router {d.router}" in out.crossed:
        return None  # next-vr into the destination router: one session, one rule
    back = _follow(dev, r_dst, sq)
    if back.kind in _NO_PATH or not back.iface or back.iface == s.iface or f"router {s.router}" in back.crossed:
        return None
    if not out.zone or not back.zone:
        return None
    return out, back


def _split_reentry(cands: list[Placement], sides: dict, sq: Net | None, dq: Net | None,
                   notes: list[str]) -> list[Placement]:
    """Turn one cross-router placement into one placement per enforcement point."""
    res: list[Placement] = []
    for p in cands:
        s, d = sides.get(id(p), (None, None))
        dev = _DEV_OF.get(id(p))
        hops = reentry_hops(dev, s, d, sq, dq) if dev is not None else None
        if not hops:
            res.append(p)
            continue
        out, back = hops
        why = (f"the flow leaves virtual router {s.router} on {out.iface} (zone {out.zone}) and comes back in on "
               f"{back.iface} (zone {back.zone}) of virtual router {d.router}; the firewall checks security policy "
               "on both passes, so a rule is needed in 2 places")
        first = replace(p, from_zone=s.zone, to_zone=out.zone, notes=list(p.notes), callouts=list(p.callouts),
                        also_targets=list(p.also_targets), suggested_routes=list(p.suggested_routes), hop=1, hops_total=2,
                        intrazone=s.zone == out.zone)
        second = replace(p, from_zone=back.zone, to_zone=d.zone, notes=list(p.notes), callouts=list(p.callouts),
                         also_targets=list(p.also_targets), suggested_routes=list(p.suggested_routes), hop=2, hops_total=2,
                         intrazone=back.zone == d.zone)
        for i, h in enumerate((first, second), 1):
            h.rule_needed = True
            h.notes.append(f"enforcement point {i} of 2: {why}")
            h.callouts.append({"level": "yellow", "code": "multi-place",
                               "message": f"Rule needed in 2 places on {p.device}: {s.zone} -> {out.zone}, then "
                                          f"{back.zone} -> {d.zone}. Push both or the flow stays blocked."})
            h.reason = f"{p.reason}; hop {i} of 2 ({h.from_zone} -> {h.to_zone})"
            sides[id(h)] = (s, d)
        if why not in notes:
            notes.append(why)
        res += [first, second]
    return res


def _template_for(env, dev: Device):
    """For a Panorama-managed firewall: router name -> (template, stack) that defines it."""
    if env is None or dev.backend != "panorama" or not dev.stack:
        return None
    return lambda vr: (env.vr_template.get((dev.stack, vr)), dev.stack)


RFC1918 = (ipaddress.IPv4Network("10.0.0.0/8"), ipaddress.IPv4Network("172.16.0.0/12"),
           ipaddress.IPv4Network("192.168.0.0/16"))
NET_192 = ipaddress.IPv4Network("192.0.0.0/8")


def is_rfc1918(q: Net) -> bool:
    return any(q.overlaps(n) for n in RFC1918)


def _primary_firewalls(devices: list[Device]) -> list[Device]:
    return [d for d in devices if not d.ha_secondary and not d.no_network]


def _match_firewall(devices: list[Device], name: str) -> list[Device]:
    h = name.strip().lower()
    if not h:
        return []
    return [d for d in devices if h in d.name.lower() or (d.serial and h == d.serial.lower())]


def _fallback_targets(devices: list[Device], fallback_firewall: str | None, notes: list[str]) -> list[Device]:
    """Firewalls to build a plan on when no connected/specific owner exists."""
    primaries = _primary_firewalls(devices)
    if fallback_firewall:
        matched = _match_firewall(primaries, fallback_firewall)
        if matched:
            notes.append(
                f"target firewall '{fallback_firewall}' used because the networks are not on a connected subnet "
                "or specific route"
            )
            return matched
        notes.append(f"target firewall '{fallback_firewall}' matched no device")
    names = sorted({d.name for d in primaries})
    if len(names) == 1:
        return [d for d in primaries if d.name == names[0]]
    return []


def _default_vr(dev: Device, vsys: str, side: Side | None) -> str:
    if side and side.router:
        return side.router
    routers = _routers_for_vsys(dev, vsys)
    return routers[0].name if routers else "default"


def _existing_192_overlaps(dev: Device, q: Net) -> list[str]:
    """Existing 192.x routes (not the default route) that overlap *q*."""
    hits: list[str] = []
    for router in dev.routers.values():
        for rt in router.routes:
            if rt.dest.prefixlen == 0:
                continue
            try:
                in_192 = rt.dest.subnet_of(NET_192)
            except ValueError:
                in_192 = False
            if in_192 and rt.dest.overlaps(q):
                rec = f"{rt.dest} in virtual router {router.name}"
                if rec not in hits:
                    hits.append(rec)
    return hits


def _route_name(q: Net) -> str:
    return f"to-{q.network_address}_{q.prefixlen}"


def _side_reason(addr: str, side: Side | None) -> str:
    if side is None:
        return f"{addr}: no IP"
    if side.kind in ("none", "unresolved", "discard"):
        vr = f" in virtual router {side.router}" if side.router else ""
        if side.kind == "discard":
            return f"{addr} hits a discard (blackhole) route{vr}"
        return f"{addr} is not on any connected subnet or route{vr}"
    if side.kind in ("default", "summary"):
        iface = side.iface or "unknown-interface"
        zone = side.zone or "?"
        return f"{addr} is not on this firewall; follows {side.kind} route via {iface} ({zone})"
    return side.describe("", addr).strip()


def _suggested_route(dev: Device, vsys: str, label: str, q: Net, side: Side | None) -> dict:
    vr = _default_vr(dev, vsys, side)
    overlap = _existing_192_overlaps(dev, q)
    rec: dict = {
        "vr": vr,
        "name": _route_name(q),
        "destination": str(q),
        "interface": "<egress-interface>",
        "nexthop": "REQUIRED-CONFIRM",
        "nexthop_confirmed": False,
        "label": label,
        "push": False,
    }
    if overlap:
        rec["overlap_192"] = True
        rec["existing"] = overlap
        rec["reason"] = (
            f"{q} overlaps existing 192.x route(s) {', '.join(overlap)} on this firewall. "
            "No new route is suggested, so those routes are not changed."
        )
        return rec
    rec["cli"] = (
        f"set network virtual-router {vr} routing-table ip static-route {rec['name']} "
        f"destination {q} interface <egress-interface> nexthop ip-address REQUIRED-CONFIRM"
    )
    rec["rollback"] = f"delete network virtual-router {vr} routing-table ip static-route {rec['name']}"
    if side is not None and side.kind in ("default", "summary"):
        rec["follows"] = {"iface": side.iface, "zone": side.zone, "kind": side.kind, "prefix": side.prefix}
        rec["reason"] = (
            f"{q} is not on any connected subnet; will use {side.kind} route via "
            f"{side.iface or 'unknown-interface'} ({side.zone or '?'}). Route suggested on VR {vr}."
        )
    else:
        rec["reason"] = (
            f"{q} is not on any connected subnet or route in virtual router {vr}. "
            f"Route suggested on VR {vr}."
        )
    return rec


def _pick_fallback_vsys(dev: Device, s: Side | None, d: Side | None) -> Vsys | None:
    for side in (s, d):
        if side and side.vsys and side.vsys in dev.vsys and not dev.vsys[side.vsys].shared_gateway:
            return dev.vsys[side.vsys]
    if "vsys1" in dev.vsys and not dev.vsys["vsys1"].shared_gateway:
        return dev.vsys["vsys1"]
    return next((v for v in dev.vsys.values() if not v.shared_gateway), None)


def _fallback_placement(dev: Device, sq: Net | None, dq: Net | None, env_of: dict) -> Placement | None:
    """Build a proposed placement on *dev* when neither side is locally owned."""
    vsys_guess = next((v for v in dev.vsys.values() if not v.shared_gateway), None)
    if vsys_guess is None:
        return None
    s = resolve(dev, vsys_guess.name, sq) if sq is not None else None
    d = resolve(dev, vsys_guess.name, dq) if dq is not None else None
    v = _pick_fallback_vsys(dev, s, d)
    if v is None:
        return None
    if s is not None and sq is not None and v.name != vsys_guess.name:
        s = resolve(dev, v.name, sq)
    if d is not None and dq is not None and v.name != vsys_guess.name:
        d = resolve(dev, v.name, dq)
    pnotes: list[str] = []
    if any(x is not None and x.kind == "discard" for x in (s, d)):
        pnotes.append("a side hits a discard (blackhole) route; confirm routing before using this plan")
    fz, n1 = _zone_in(dev, v, s) if s and s.kind not in ("none", "discard", "unresolved") else (None, None)
    tz, n2 = _zone_in(dev, v, d) if d and d.kind not in ("none", "discard", "unresolved") else (None, None)
    pnotes += [n for n in (n1, n2) if n]
    conf = "medium" if any(x is not None and x.kind in ("connected", "local", "static") for x in (s, d)) else "low"
    if any(x is not None and (x.ecmp or x.partial) for x in (s, d)):
        conf = "low"
        pnotes.append("ECMP or partial route match")
    reasons = []
    if s:
        reasons.append("src " + _side_reason(str(sq), s))
    else:
        reasons.append("src: no IP")
    if d:
        reasons.append("dst " + _side_reason(str(dq), d))
    else:
        reasons.append("dst: no IP")
    needs = fz is None or tz is None
    p = Placement(target=dev.target, backend=dev.backend, device=dev.name, serial=dev.serial, vsys=v.name,
                  device_group=v.device_group if dev.backend == "panorama" else None, stack=dev.stack,
                  from_zone=fz, to_zone=tz, reason="; ".join(reasons), confidence=conf, needs_human=needs,
                  ha_peer=dev.ha_peer, notes=pnotes, role="fallback")
    if dev.backend == "panorama" and not v.device_group:
        p.needs_human = True
        p.confidence = "low"
        p.notes.append("firewall/vsys is not in any device group")
    if fz and tz and fz == tz:
        p.intrazone = True
        p.rule_needed = True  # still propose a rule; do not treat as "no rule needed"
        p.needs_human = True
        p.notes.append(
            f"both sides resolve to zone {fz} (intrazone). Suggest adding a more specific route and/or a new zone "
            f"rather than an intrazone rule in {fz}."
        )
    if dev.ha_peer:
        p.notes.append(f"HA pair with {dev.ha_peer}: one rule covers both")
    p.callouts, p.suggested_routes = suggest_routes(
        dev, v.name, (("source", sq, s), ("destination", dq, d)),
        _template_for(env_of.get(dev.id), dev))
    if p.intrazone:
        p.callouts.append({
            "level": "yellow",
            "code": "route-same-zone",
            "message": (
                f"both source and destination resolve to zone {fz}; this would be an intrazone rule. "
                "Suggest a new zone or a more specific route instead of silently making a same-zone rule. "
                "The rule is still in the plan so you can edit the zones."
            ),
        })
    return p


def route_callouts(dev: str | Device, vsys: str, sides, tpl_for=None) -> list[dict]:
    """Routing callouts for a placement. Suggestions only; nothing is pushed.

    For Panorama-managed firewalls the suggested command goes into the template
    that defines the virtual router (``set template <T> config network ...``),
    followed by a commit and a push of the template stack.
    """
    out, _ = suggest_routes(dev, vsys, sides, tpl_for)
    return out


def suggest_routes(dev: str | Device, vsys: str, sides, tpl_for=None) -> tuple[list[dict], list[dict]]:
    """Callouts plus structured VR route suggestions (never auto-pushed)."""
    callouts, routes = _suggest_routes(dev, vsys, sides)
    if tpl_for is None:
        return callouts, routes
    def _rewrite(msg: str) -> str:
        m = re.search(r"set network virtual-router (\S+)", msg)
        if not m:
            return msg
        tpl, stack = tpl_for(m.group(1))
        if tpl and tpl.startswith("stack:"):
            msg = msg.replace("set network virtual-router", f"set template-stack {stack} config network virtual-router")
        elif tpl:
            msg = msg.replace("set network virtual-router", f"set template {tpl} config network virtual-router")
        return msg + (f" [Panorama: template stack {stack}; virtual router {m.group(1)} is defined in "
                      f"{'the stack itself' if tpl and tpl.startswith('stack:') else 'template ' + (tpl or '?')}. "
                      f"Commit on Panorama, then Push to Devices for template stack {stack}.]")
    for c in callouts:
        if "set network virtual-router" in c.get("message", ""):
            c["message"] = _rewrite(c["message"])
    for r in routes:
        if r.get("cli"):
            r["cli"] = _rewrite(r["cli"])
    return callouts, routes


def _suggest_routes(dev: str | Device, vsys: str, sides) -> tuple[list[dict], list[dict]]:
    out: list[dict] = []
    routes: list[dict] = []
    dev_obj = dev if isinstance(dev, Device) else None
    dev_name = dev.name if isinstance(dev, Device) else str(dev)
    for label, q, x in sides:
        if x is None or q is None:
            continue
        rname = f"to-{q.network_address}_{q.prefixlen}"
        need_route = is_rfc1918(q) and x.kind in ("default", "summary", "none", "unresolved")
        if need_route and dev_obj is not None:
            rec = _suggested_route(dev_obj, vsys, label, q, x)
            routes.append(rec)
            if rec.get("overlap_192"):
                out.append({"level": "yellow", "code": "route-192-overlap", "message": rec["reason"]})
            else:
                out.append({
                    "level": "yellow",
                    "code": "route-needed",
                    "message": (
                        f"{rec['reason']} Next hop REQUIRED-CONFIRM "
                        f"(suggestion, not pushed): {rec['cli']}"
                    ),
                })
        elif x.kind in ("default", "summary"):
            vr = x.router or "?"
            nh = x.nexthop or "<next-hop IP>"
            out.append({"level": "yellow", "code": "route-default",
                        "message": f"routing: {label} {q} has no specific route on {dev_name}/{vsys}; it only matches the {x.kind} route "
                                   f"{x.prefix} in virtual router {vr} (out {x.iface}, zone {x.zone}). If that is not the path you want, "
                                   f"add a static route (suggestion, not pushed): set network virtual-router {vr} routing-table ip "
                                   f"static-route {rname} destination {q} interface {x.iface} nexthop ip-address {nh}"})
        if x.iface_router:
            out.append({"level": "yellow", "code": "route-vr-mismatch",
                        "message": f"routing: {label} {q} is routed in virtual router {x.router} but egress interface {x.iface} "
                                   f"(zone {x.zone}) belongs to virtual router {x.iface_router}. Check that {x.iface_router} also has "
                                   f"a route for {q} (suggestion: set network virtual-router {x.iface_router} routing-table ip "
                                   f"static-route {rname} destination {q} interface {x.iface})."})
        hops = [c.split(" ", 1)[1] for c in x.crossed if c.startswith("router ")]
        if hops:
            out.append({"level": "info", "code": "route-next-vr",
                        "message": f"routing: {label} {q} is reached through next-vr hop(s) to {', '.join(hops)}; make sure the return "
                                   f"route exists in {x.router or hops[-1]} so replies come back the same way."})
    return out, routes


_ROLE_RANK = {"owner-both": 0, "source-owner": 1, "destination-owner": 1, "transit": 2, "route-only": 3}
_CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def _ip_index(devices: list[Device]) -> dict[str, Device]:
    idx: dict[str, Device] = {}
    for d in devices:
        if d.ha_secondary or d.no_network:
            continue
        for it in d.interfaces.values():
            for ip in it.ips:
                idx.setdefault(str(ip.ip), d)
    return idx


def _stitch(start: Device, vsys: str, q: Net, idx: dict[str, Device]) -> list[tuple[Device, str]]:
    """Walk firewall-to-firewall toward *q* by next-hop IPs that belong to another firewall's interface."""
    path: list[tuple[Device, str]] = []
    dev, vs, seen = start, vsys, {start.id}
    for _ in range(8):
        side = resolve(dev, vs, q)
        if side.kind in ("connected", "local") or not side.nexthop:
            break
        nxt = idx.get(side.nexthop)
        if nxt is None or nxt.id in seen:
            break
        seen.add(nxt.id)
        it = next((i for i in nxt.interfaces.values() if any(str(ip.ip) == side.nexthop for ip in i.ips)), None)
        dev, vs = nxt, (it.vsys if it and it.vsys else next(iter(nxt.vsys), "vsys1"))
        path.append((dev, vs))
    return path


def _prune(cands: list[Placement], sides: dict, devices: list[Device], sq: Net | None, dq: Net | None,
           evaluate, notes: list[str]) -> tuple[list[Placement], list[Placement]]:
    """Keep the firewalls that own a side (connected or specific route) plus the stitched path
    between them; if none own a side, keep every broad-route candidate as needs-human.
    Collapse same-zone Panorama candidates in one device group into one rule."""
    if len(cands) <= 1:
        return cands, []
    key = lambda p: (p.target, p.device, p.vsys)  # noqa: E731
    have = {key(p): p for p in cands}
    owners = [p for p in cands if p.role in ("owner-both", "source-owner", "destination-owner")]
    keep: list[Placement] = []
    if owners:
        keep = list(owners)
        idx = _ip_index(devices)
        devs = {(p.target, p.device): next((d for d in devices if d.target == p.target and d.name == p.device), None) for p in owners}
        for p in owners:
            dev = devs[(p.target, p.device)]
            if dev is None:
                continue
            walks = []
            if p.role == "source-owner" and dq is not None:
                walks.append(_stitch(dev, p.vsys, dq, idx))
            if p.role == "destination-owner" and sq is not None:
                walks.append(_stitch(dev, p.vsys, sq, idx))
            for walk in walks:
                for hop, vs in walk:
                    k = (hop.target, hop.name, vs)
                    hp = have.get(k)
                    if hp is None:
                        v = hop.vsys.get(vs)
                        hp, _ = evaluate(hop, v, True) if v is not None else (None, None)
                        if hp is None:
                            continue
                        have[k] = hp
                    if hp.role == "route-only":
                        hp.role = "transit"
                    if hp.role == "transit" or hp not in keep:
                        hp.notes.append(f"stitched path: {p.device} -> ... -> {hop.name} (next-hop IP owned by this firewall)")
                    if hp not in keep:
                        keep.append(hp)
        owner_devs = {(p.target, p.device) for p in keep}
        keep += [p for p in cands if p.role == "transit" and (p.target, p.device) in owner_devs and p not in keep]
    else:
        # Nothing owns either endpoint with a connected or specific route. Do not
        # auto-pick a "best" firewall that only matched a default or a short
        # summary: keep every candidate, mark them needs-human, and still propose
        # a rule so the plan is not a silent skip.
        for p in cands:
            p.needs_human = True
            p.confidence = "low"
            note = ("no firewall has a connected or specific route for these endpoints; "
                    "these candidates only match a broad or default route")
            if note not in p.notes:
                p.notes.append(note)
        keep = list(cands)
    keep_ids = {id(p) for p in keep}
    alts = [p for p in cands if id(p) not in keep_ids]
    # collapse: one Panorama rule (same DG + zones) can target several firewalls
    merged: dict[tuple, Placement] = {}
    final: list[Placement] = []
    for p in sorted(keep, key=lambda p: (_ROLE_RANK[p.role], _CONF_RANK[p.confidence], p.device, p.vsys)):
        if p.backend == "panorama" and p.device_group:
            mk = (p.target, p.device_group, p.from_zone, p.to_zone, p.rule_needed)
            if mk in merged:
                m = merged[mk]
                m.also_targets.append({"device": p.device, "serial": p.serial, "vsys": p.vsys})
                m.notes.append(f"same rule also targets {p.device}/{p.vsys}")
                if p.needs_human:
                    m.needs_human = True
                continue
            merged[mk] = p
        final.append(p)
    if alts:
        notes.append(f"{len(alts)} weaker candidate(s) pruned (transit or route-only matches on firewalls that do not own "
                     f"either subnet); see alternatives")
    return final, alts
