# SPDX-License-Identifier: Apache-2.0
"""Normalized network model for standalone firewalls and Panorama exports.

Loads a PAN-OS running-config export (firewall) or a Panorama export and
normalizes it to::

    Environment
      devices -> vsys (incl. shared gateways) -> zones
              -> interfaces (IP/subnet, zone, vsys, router)
              -> routers (legacy virtual routers + advanced logical-router VRFs)
      device groups (hierarchy, members by serial/vsys) and object scopes
      (shared, device group, vsys)

Panorama firewalls are built per (template stack x serial): the stack's
own config is merged over its templates in order (first template wins),
and variables resolve template < stack < per-device.

Ported from the FlowMapper project (the FlowMapper tool in this repository,
build/core.js: mergeNodes, readInterfaces, readStaticRoutes, buildDevice,
readPanorama, listPanoramaContexts, buildPanoramaDevice, readHa,
haGroups). Copied into this repo so there is no runtime dependency.
See NOTICE.
"""

from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

IF_KINDS = ("ethernet", "aggregate-ethernet")
Net = ipaddress.IPv4Network


# --------------------------------------------------------------------- xml
def _ch(node: ET.Element | None, tag: str) -> ET.Element | None:
    return node.find(tag) if node is not None else None


def _at(node: ET.Element | None, path: str) -> ET.Element | None:
    return node.find(path) if node is not None else None


def _entries(node: ET.Element | None) -> list[ET.Element]:
    return node.findall("entry") if node is not None else []


def _txt(node: ET.Element | None) -> str:
    return (node.text or "").strip() if node is not None else ""


def _members(node: ET.Element | None) -> list[str]:
    if node is None:
        return []
    ms = [(m.text or "").strip() for m in node.findall("member")]
    ms = [m for m in ms if m]
    if ms:
        return ms
    t = _txt(node)
    return [t] if t else []


def _find_entry(node: ET.Element | None, name: str) -> ET.Element | None:
    for e in _entries(node):
        if e.get("name") == name:
            return e
    return None


def _device_entry(devs: ET.Element | None) -> ET.Element | None:
    e = _find_entry(devs, "localhost.localdomain")
    if e is None:
        es = _entries(devs)
        e = es[0] if es else None
    return e


def merge_nodes(hi: ET.Element | None, lo: ET.Element | None) -> ET.Element | None:
    """Deep merge of template config nodes: *hi* wins, entries merged by name."""
    if hi is None:
        return lo
    if lo is None:
        return hi
    out = ET.Element(hi.tag, {**lo.attrib, **hi.attrib})
    out.text = hi.text if (hi.text or "").strip() else lo.text
    if any(c.tag == "member" for c in hi):
        out.extend(list(hi))
        return out

    def key(c: ET.Element) -> str:
        return c.tag + ("\0" + c.get("name") if c.get("name") is not None else "")

    lo_map = {key(c): c for c in lo}
    seen = set()
    for c in hi:
        k = key(c)
        seen.add(k)
        out.append(merge_nodes(c, lo_map[k]) if k in lo_map else c)
    for c in lo:
        if key(c) not in seen:
            out.append(c)
    return out


# --------------------------------------------------------------------- ip
def parse_net(value: str) -> Net | None:
    """Parse 'a.b.c.d', 'a.b.c.d/len' or 'a.b.c.d/mask' to a (non-strict) IPv4 network."""
    s = str(value or "").strip()
    if not s or ":" in s:
        return None
    try:
        return ipaddress.IPv4Network(s, strict=False)
    except ValueError:
        return None


def parse_range(value: str) -> tuple[int, int] | None:
    s = str(value or "").strip()
    if "-" not in s:
        n = parse_net(s)
        return (int(n.network_address), int(n.broadcast_address)) if n else None
    a, _, b = s.partition("-")
    try:
        lo, hi = int(ipaddress.IPv4Address(a.strip())), int(ipaddress.IPv4Address(b.strip()))
    except ValueError:
        return None
    return (lo, hi) if lo <= hi else None


# --------------------------------------------------------------------- model
@dataclass
class AddressObj:
    name: str
    type: str | None
    value: str | None


@dataclass
class ServiceObj:
    name: str
    proto: str
    port: str


@dataclass
class ExistingRule:
    """A security rule as it already exists in a config (for reuse / already-allowed)."""
    name: str
    rulebase: str  # pre-rulebase | post-rulebase | rulebase
    from_zones: list[str] = field(default_factory=list)
    to_zones: list[str] = field(default_factory=list)
    source: list[str] = field(default_factory=list)
    destination: list[str] = field(default_factory=list)
    application: list[str] = field(default_factory=list)
    service: list[str] = field(default_factory=list)
    action: str = "allow"
    disabled: bool = False
    description: str = ""
    tags: list[str] = field(default_factory=list)
    log_start: bool = False
    log_end: bool = True
    log_setting: str = ""
    profile_group: str = ""
    profile_type: str = ""  # group | profiles | ""
    target_serials: list[tuple[str, list[str]]] = field(default_factory=list)
    target_negate: bool = False
    negate_source: bool = False
    negate_destination: bool = False
    source_user: list[str] = field(default_factory=list)
    rule_type: str = "universal"  # universal | intrazone | interzone


@dataclass
class ObjectScope:
    label: str
    kind: str  # shared | device-group | vsys | template
    name: str
    addresses: dict[str, AddressObj] = field(default_factory=dict)
    address_groups: dict[str, list[str]] = field(default_factory=dict)
    dynamic_address_groups: set[str] = field(default_factory=set)
    services: dict[str, ServiceObj] = field(default_factory=dict)
    service_groups: dict[str, list[str]] = field(default_factory=dict)
    app_groups: dict[str, list[str]] = field(default_factory=dict)
    app_filters: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    rule_names: set[str] = field(default_factory=set)
    security_rules: list[ExistingRule] = field(default_factory=list)


@dataclass
class Interface:
    name: str
    ips: list[ipaddress.IPv4Interface] = field(default_factory=list)
    zone: str | None = None
    vsys: str | None = None
    router: str | None = None
    dhcp: bool = False
    mode: str = "layer3"


@dataclass
class Route:
    name: str
    dest: Net
    kind: str  # connected | local | static
    nexthop_type: str = "none"  # ip | next-vr | discard | connected | local | none | fqdn
    nexthop: str | None = None
    iface: str | None = None
    metric: int = 10
    ad: int = 10


@dataclass(eq=False)
class Router:
    name: str
    engine: str  # legacy | advanced
    interfaces: list[str] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    owner: str | None = None
    dynamic: list[str] = field(default_factory=list)


@dataclass
class Zone:
    name: str
    type: str
    members: list[str]


@dataclass
class Vsys:
    name: str
    display: str
    shared_gateway: bool = False
    zones: dict[str, Zone] = field(default_factory=dict)
    import_ifs: list[str] = field(default_factory=list)
    import_routers: list[str] = field(default_factory=list)
    device_group: str | None = None
    scope: ObjectScope | None = None
    intrazone_default: str = "allow"
    interzone_default: str = "deny"


@dataclass
class HaInfo:
    enabled: bool | None
    peers: list[str]
    own: list[str]
    mode: str | None


@dataclass
class Device:
    id: str
    name: str
    backend: str  # firewall | panorama
    target: str = ""
    serial: str | None = None
    stack: str | None = None
    interfaces: dict[str, Interface] = field(default_factory=dict)
    vsys: dict[str, Vsys] = field(default_factory=dict)
    routers: dict[str, Router] = field(default_factory=dict)
    multi_vsys: bool = False
    ha: HaInfo | None = None
    ha_peer: str | None = None
    ha_secondary: bool = False
    no_network: bool = False
    warnings: list[str] = field(default_factory=list)
    cache: dict = field(default_factory=dict, repr=False, compare=False)


@dataclass
class DeviceGroup:
    name: str
    parent: str | None
    members: list[tuple[str, list[str]]]  # (serial, vsys list)
    scope: ObjectScope


@dataclass
class Environment:
    kind: str  # firewall | panorama
    target: str
    source: str
    source_path: str = ""
    devices: list[Device] = field(default_factory=list)
    device_groups: dict[str, DeviceGroup] = field(default_factory=dict)
    shared: ObjectScope = field(default_factory=lambda: ObjectScope("shared", "shared", "shared"))
    hostname: str = ""
    version: str = ""
    stacks: dict[str, list[str]] = field(default_factory=dict)  # template stack -> templates (first wins)
    vr_template: dict[tuple[str, str], str] = field(default_factory=dict)  # (stack, router) -> defining template

    def dg_descendants(self, name: str | None) -> list[DeviceGroup]:
        out, todo = [], [name]
        while todo:
            cur = todo.pop()
            for g in self.device_groups.values():
                if g.parent == cur and g not in out:
                    out.append(g)
                    todo.append(g.name)
        return out

    def dg_chain(self, name: str | None) -> list[DeviceGroup]:
        """Leaf -> root."""
        chain, seen = [], set()
        while name and name in self.device_groups and name not in seen:
            seen.add(name)
            chain.append(self.device_groups[name])
            name = self.device_groups[name].parent
        return chain

    def scopes_for(self, device: Device, vsys: str) -> list[ObjectScope]:
        """Object scopes visible to a rule at (device, vsys), most specific first."""
        v = device.vsys.get(vsys)
        if self.kind == "panorama":
            dg = v.device_group if v else None
            return [g.scope for g in self.dg_chain(dg)] + [self.shared]
        out = [v.scope] if v and v.scope else []
        return out + [self.shared]


def unique_routers(dev: "Device") -> list["Router"]:
    seen: list[Router] = []
    for r in dev.routers.values():
        if not any(r is x for x in seen):
            seen.append(r)
    return seen


# --------------------------------------------------------------------- objects
def read_objects(node: ET.Element | None, label: str, kind: str, name: str) -> ObjectScope:
    o = ObjectScope(label=label, kind=kind, name=name)
    if node is None:
        return o
    for e in _entries(_ch(node, "address")):
        typ = val = None
        for t in ("ip-netmask", "ip-range", "ip-wildcard", "fqdn"):
            c = _ch(e, t)
            if c is not None:
                typ, val = t, _txt(c)
                break
        o.addresses[e.get("name")] = AddressObj(e.get("name"), typ, val)
    for e in _entries(_ch(node, "address-group")):
        nm = e.get("name")
        static = _ch(e, "static")
        if static is None and _ch(e, "dynamic") is not None:
            o.dynamic_address_groups.add(nm)
            o.address_groups[nm] = []
        else:
            o.address_groups[nm] = _members(static)
    for e in _entries(_ch(node, "service")):
        p = _ch(e, "protocol")
        for pr in ("tcp", "udp", "sctp"):
            c = _ch(p, pr)
            if c is not None:
                o.services[e.get("name")] = ServiceObj(e.get("name"), pr, _txt(_ch(c, "port")))
                break
    for e in _entries(_ch(node, "service-group")):
        o.service_groups[e.get("name")] = _members(_ch(e, "members"))
    for e in _entries(_ch(node, "application-group")):
        o.app_groups[e.get("name")] = _members(_ch(e, "members")) or _members(e)
    for e in _entries(_ch(node, "application-filter")):
        o.app_filters.add(e.get("name"))
    for e in _entries(_ch(node, "tag")):
        o.tags.add(e.get("name"))
    for path, rb in (
        ("rulebase/security/rules", "rulebase"),
        ("pre-rulebase/security/rules", "pre-rulebase"),
        ("post-rulebase/security/rules", "post-rulebase"),
    ):
        for e in _entries(_at(node, path)):
            o.rule_names.add(e.get("name"))
            o.security_rules.append(_security_rule_from_entry(e, rb))
    return o


def _security_rule_from_entry(e: ET.Element, rulebase: str) -> ExistingRule:
    grp = _members(_at(e, "profile-setting/group"))
    has_profiles = _at(e, "profile-setting/profiles") is not None
    targets: list[tuple[str, list[str]]] = []
    for dev in _entries(_at(e, "target/devices")):
        vsys = [v.get("name") for v in _entries(_ch(dev, "vsys")) if v.get("name")]
        targets.append((dev.get("name") or "", vsys))
    return ExistingRule(
        name=e.get("name") or "",
        rulebase=rulebase,
        from_zones=_members(_ch(e, "from")),
        to_zones=_members(_ch(e, "to")),
        source=_members(_ch(e, "source")),
        destination=_members(_ch(e, "destination")),
        application=_members(_ch(e, "application")),
        service=_members(_ch(e, "service")),
        action=(_txt(_ch(e, "action")) or "allow").lower(),
        disabled=_txt(_ch(e, "disabled")).lower() in {"yes", "true"},
        description=_txt(_ch(e, "description")),
        tags=_members(_ch(e, "tag")),
        log_start=_txt(_ch(e, "log-start")).lower() in {"yes", "true"},
        log_end=_txt(_ch(e, "log-end")).lower() not in {"no", "false"},
        log_setting=_txt(_ch(e, "log-setting")),
        profile_group=grp[0] if grp else "",
        profile_type="group" if grp else ("profiles" if has_profiles else ""),
        target_serials=targets,
        target_negate=_txt(_at(e, "target/negate")).lower() in {"yes", "true"},
        negate_source=_txt(_ch(e, "negate-source")).lower() in {"yes", "true"},
        negate_destination=_txt(_ch(e, "negate-destination")).lower() in {"yes", "true"},
        source_user=_members(_ch(e, "source-user")),
        rule_type=(_txt(_ch(e, "rule-type")) or "universal").lower(),
    )


# --------------------------------------------------------------------- network
def _lookup_addr(scopes: list[ObjectScope], name: str) -> str | None:
    for s in scopes:
        a = s.addresses.get(name)
        if a and a.value:
            return a.value
    return None


def _resolve(value: str, vars: dict[str, str], scopes: list[ObjectScope]) -> str:
    if value.startswith("$") and value in vars:
        value = vars[value]
    if parse_net(value) is None:
        v = _lookup_addr(scopes, value)
        if v:
            return v
    return value


def read_interfaces(net: ET.Element | None, vars: dict[str, str], scopes: list[ObjectScope], warn: list[str]) -> dict[str, Interface]:
    ifs: dict[str, Interface] = {}
    root = _ch(net, "interface")
    if root is None:
        return ifs

    def ips_of(node: ET.Element) -> list[ipaddress.IPv4Interface]:
        out = []
        for e in _entries(_ch(node, "ip")):
            raw = e.get("name") or ""
            val = _resolve(raw, vars, scopes)
            if ":" in val:
                continue
            try:
                out.append(ipaddress.IPv4Interface(val.strip()))
            except ValueError:
                warn.append(f"interface IP '{raw}' could not be resolved (variable or object missing)")
        return out

    def add_l3(name: str, l3: ET.Element) -> None:
        ifs[name] = Interface(name=name, ips=ips_of(l3), dhcp=_ch(l3, "dhcp-client") is not None)
        for u in _entries(_ch(l3, "units")):
            add_l3(u.get("name"), u)

    for k in IF_KINDS:
        for e in _entries(_ch(root, k)):
            l3 = _ch(e, "layer3")
            if l3 is not None:
                add_l3(e.get("name"), l3)
            else:
                mode = next((m for m in ("layer2", "virtual-wire", "tap", "ha", "decrypt-mirror", "aggregate-group") if _ch(e, m) is not None), "none")
                ifs[e.get("name")] = Interface(name=e.get("name"), mode=mode)
    for k in ("vlan", "loopback", "tunnel"):
        n = _ch(root, k)
        if n is None:
            continue
        if _ch(n, "ip") is not None:
            add_l3(k, n)
        for u in _entries(_ch(n, "units")):
            ifs[u.get("name")] = Interface(name=u.get("name"), ips=ips_of(u), dhcp=_ch(u, "dhcp-client") is not None)
    return ifs


def read_static_routes(rt: ET.Element | None, vars: dict[str, str], scopes: list[ObjectScope]) -> list[Route]:
    out: list[Route] = []
    node = _at(rt, "ip/static-route")
    if node is None:
        node = _ch(rt, "static-route")
    for e in _entries(node):
        dst = _resolve(_txt(_ch(e, "destination")), vars, scopes)
        p = parse_net(dst)
        if p is None:
            continue
        nh = _ch(e, "nexthop")
        nht, nhv = "none", None
        if nh is not None:
            for t in ("ip-address", "next-vr", "next-lr", "next-vrf", "fqdn", "discard"):
                c = _ch(nh, t)
                if c is not None:
                    nhv = _txt(c)
                    if t == "ip-address":
                        nht = "ip"
                        nhv = _resolve(nhv, vars, scopes).split("/")[0]
                    elif t in ("next-vr", "next-lr", "next-vrf"):
                        nht = "next-vr"
                    else:
                        nht = t
                    break
        metric = _txt(_ch(e, "metric"))
        ad = _txt(_ch(e, "admin-dist"))
        out.append(Route(name=e.get("name"), dest=p, kind="static", nexthop_type=nht, nexthop=nhv,
                         iface=_txt(_ch(e, "interface")) or None,
                         metric=int(metric) if metric.isdigit() else 10, ad=int(ad) if ad.isdigit() else 10))
    return out


def read_ha(dn: ET.Element, vars: dict[str, str]) -> HaInfo | None:
    ha = _at(dn, "deviceconfig/high-availability")
    if ha is None:
        return None

    def val(node):
        v = _txt(node)
        if not v:
            return None
        if v.startswith("$"):
            v = vars.get(v, "")
        n = parse_net(v.split("/")[0])
        return str(n.network_address) if n and n.prefixlen == 32 else None

    en = _txt(_ch(ha, "enabled"))
    grp = _ch(ha, "group")
    if grp is not None and _entries(grp):
        grp = _entries(grp)[0]
    peers, own = [], []
    for v in (val(_ch(grp, "peer-ip")), val(_ch(grp, "peer-ip-backup"))):
        if v and v not in peers:
            peers.append(v)
    for k in ("ha1", "ha1-backup"):
        v = val(_at(ha, f"interface/{k}/ip-address"))
        if v and v not in own:
            own.append(v)
    mode = None
    if grp is not None and _at(grp, "mode/active-active") is not None:
        mode = "active-active"
    elif grp is not None and _at(grp, "mode/active-passive") is not None:
        mode = "active-passive"
    return HaInfo(enabled=True if en == "yes" else False if en == "no" else None, peers=peers, own=own, mode=mode)


def build_device(*, id: str, name: str, backend: str, target: str, device_node: ET.Element,
                 shared_node: ET.Element | None, vars: dict[str, str] | None = None,
                 serial: str | None = None, stack: str | None = None,
                 dg_for_vsys=None, defaults_for_dg=None, shared_scope: ObjectScope | None = None) -> Device:
    vars = vars or {}
    warn: list[str] = []
    dev = Device(id=id, name=name, backend=backend, target=target, serial=serial, stack=stack, warnings=warn)
    net = _ch(device_node, "network")
    dev.ha = read_ha(device_node, vars)
    tpl_shared = read_objects(shared_node, "shared", "shared", "shared")
    vsys_nodes = _entries(_ch(device_node, "vsys"))
    sg_nodes = _entries(_at(device_node, "network/shared-gateway"))
    dev.multi_vsys = len(vsys_nodes) > 1 or bool(sg_nodes)
    first = read_objects(vsys_nodes[0], "vsys", "vsys", vsys_nodes[0].get("name")) if vsys_nodes else ObjectScope("vsys", "vsys", "vsys1")
    scopes = [first, tpl_shared] + ([shared_scope] if shared_scope else [])
    dev.interfaces = read_interfaces(net, vars, scopes, warn)

    def build_ctx(node: ET.Element, sg: bool) -> Vsys:
        nm = node.get("name")
        v = Vsys(name=nm, display=_txt(_ch(node, "display-name")) or nm, shared_gateway=sg,
                 import_ifs=_members(_at(node, "import/network/interface")),
                 import_routers=_members(_at(node, "import/network/virtual-router")) + _members(_at(node, "import/network/logical-router")),
                 scope=read_objects(node, f"vsys {nm}", "vsys", nm))
        for z in _entries(_ch(node, "zone")):
            nw = _ch(z, "network")
            typ, mem = "unknown", []
            for t in ("layer3", "layer2", "virtual-wire", "tap", "external", "tunnel"):
                c = _ch(nw, t)
                if c is not None:
                    typ, mem = t, _members(c)
                    break
            v.zones[z.get("name")] = Zone(z.get("name"), typ, mem)
        for e in _entries(_at(node, "rulebase/default-security-rules/rules")):
            a = _txt(_ch(e, "action"))
            if a and "intrazone" in e.get("name", ""):
                v.intrazone_default = a
            if a and "interzone" in e.get("name", ""):
                v.interzone_default = a
        if dg_for_vsys:
            v.device_group = dg_for_vsys(nm)
            if defaults_for_dg and v.device_group:
                for k, a in (defaults_for_dg(v.device_group) or {}).items():
                    setattr(v, f"{k}_default", a)
        return v

    for n in vsys_nodes:
        dev.vsys[n.get("name")] = build_ctx(n, False)
    for n in sg_nodes:
        dev.vsys[n.get("name")] = build_ctx(n, True)
    if not dev.vsys:
        dev.vsys["vsys1"] = build_ctx(ET.Element("entry", {"name": "vsys1"}), False)

    ctxs = list(dev.vsys.values())
    any_imports = any(c.import_ifs for c in ctxs)
    for it in dev.interfaces.values():
        owner = next((c for c in ctxs if it.name in c.import_ifs), None)
        if owner is None and "." in it.name:
            parent = it.name.split(".")[0]
            owner = next((c for c in ctxs if parent in c.import_ifs and not it.name.startswith("ethernet")), None)
        if owner is None and (not any_imports or not dev.multi_vsys):
            owner = next((c for c in ctxs if not c.shared_gateway), ctxs[0])
        it.vsys = owner.name if owner else None
        for c in ctxs:
            for z in c.zones.values():
                if z.type != "external" and it.name in z.members:
                    it.zone = z.name
                    it.vsys = it.vsys or c.name

    for e in _entries(_at(net, "virtual-router")):
        r = Router(name=e.get("name"), engine="legacy", interfaces=_members(_ch(e, "interface")),
                   routes=read_static_routes(_ch(e, "routing-table"), vars, scopes),
                   dynamic=[p for p in ("bgp", "ospf", "ospfv3", "rip") if _txt(_at(e, f"protocol/{p}/enable")) == "yes"])
        dev.routers[r.name] = r
    for lr in _entries(_at(net, "logical-router")):
        for vrf in _entries(_ch(lr, "vrf")):
            nm = lr.get("name") if vrf.get("name") == "default" else f"{lr.get('name')}:{vrf.get('name')}"
            r = Router(name=nm, engine="advanced", interfaces=_members(_ch(vrf, "interface")),
                       routes=read_static_routes(_ch(vrf, "routing-table"), vars, scopes),
                       dynamic=[p for p in ("bgp", "ospf", "ospfv3", "rip") if _txt(_at(vrf, f"{p}/enable")) == "yes"])
            dev.routers[nm] = r
            dev.routers.setdefault(lr.get("name"), r)

    for r in unique_routers(dev):
        for iname in r.interfaces:
            it = dev.interfaces.get(iname)
            if not it:
                continue
            it.router = it.router or r.name
            for ip in it.ips:
                if ip.network.prefixlen < 32:
                    r.routes.append(Route(f"connected {iname}", ip.network, "connected", "connected", iface=iname, metric=0, ad=0))
                r.routes.append(Route(f"local {iname}", ipaddress.IPv4Network(f"{ip.ip}/32"), "local", "local", iface=iname, metric=0, ad=0))
            if it.dhcp:
                warn.append(f"interface {iname} uses DHCP; its subnet and default route are learned at runtime")
        imp = next((c for c in ctxs if r.name in c.import_routers), None)
        if imp:
            r.owner = imp.name
        else:
            owners = {dev.interfaces[n].vsys for n in r.interfaces if n in dev.interfaces and dev.interfaces[n].vsys}
            r.owner = owners.pop() if len(owners) == 1 else (ctxs[0].name if not owners and not dev.multi_vsys else None)
        if r.dynamic:
            warn.append(f"router {r.name} runs {'/'.join(r.dynamic).upper()}; dynamic routes are not in the config")
    if not any(it.ips for it in dev.interfaces.values()):
        dev.no_network = True
    return dev


# --------------------------------------------------------------------- loaders
def _parse_root(source: str | Path | bytes | ET.Element) -> ET.Element:
    """Parse a PAN-OS config with defusedxml so external entities are refused."""
    from defusedxml.ElementTree import fromstring as safe_fromstring, parse as safe_parse
    from defusedxml.common import DefusedXmlException

    try:
        if isinstance(source, ET.Element):
            root = source
        elif isinstance(source, bytes):
            root = safe_fromstring(source)
        elif isinstance(source, str) and source.lstrip().startswith("<"):
            root = safe_fromstring(source)
        else:
            root = safe_parse(str(source)).getroot()
    except DefusedXmlException as exc:
        raise ValueError(f"refused to parse configuration XML ({exc.__class__.__name__})") from None
    except ET.ParseError as exc:
        raise ValueError("could not parse configuration XML") from exc
    if root.tag != "config":
        found = root.find(".//config")
        if found is None:
            raise ValueError("No <config> element found. Is this a PAN-OS configuration XML?")
        root = found
    return root


def _is_panorama_config(cfg: ET.Element, dev_entry: ET.Element) -> bool:
    """True when this running-config is a Panorama export, including a new empty one.

    Device-group / template / template-stack nodes are the usual signal. A
    brand-new Panorama often has none of those yet. A firewall running-config
    always has vsys (and usually network) under localhost.localdomain; a
    management-only deviceconfig tree without those is treated as Panorama.
    """
    if any(_ch(dev_entry, t) is not None for t in ("device-group", "template", "template-stack")):
        return True
    if _ch(cfg, "panorama") is not None:
        return True
    return (
        _ch(dev_entry, "vsys") is None
        and _ch(dev_entry, "network") is None
        and _ch(dev_entry, "deviceconfig") is not None
    )


def load_environment(source: str | Path | bytes | ET.Element, target: str = "default", label: str | None = None,
                     site_codes: list[str] | tuple[str, ...] | None = None) -> Environment:
    """Load a firewall running config or a Panorama export into an Environment.

    ``site_codes`` is the customer's list of site-name tokens (empty by default).
    When a vsys name and a device-group name both use one of those tokens, they
    must agree or the conservative name match is skipped. Nothing is hard-coded.
    """
    codes = normalize_site_codes(site_codes)
    cfg = _parse_root(source)
    devs = _ch(cfg, "devices")
    dev_entry = _device_entry(devs)
    if dev_entry is None:
        raise ValueError("No <devices><entry> in config.")
    is_pano = _is_panorama_config(cfg, dev_entry)
    is_path = isinstance(source, (str, Path)) and not str(source).lstrip().startswith("<")
    src_label = label or (Path(str(source)).name if is_path else "inline")
    hostname = _txt(_at(dev_entry, "deviceconfig/system/hostname"))
    env = Environment(kind="panorama" if is_pano else "firewall", target=target, source=src_label,
                      source_path=str(Path(source).resolve()) if is_path else "",
                      hostname=hostname, version=cfg.get("detail-version") or cfg.get("version") or "")
    env.shared = read_objects(_ch(cfg, "shared"), "shared", "shared", "shared")
    if not is_pano:
        d = build_device(id=f"{target}:{hostname or 'firewall'}", name=hostname or target, backend="firewall",
                         target=target, device_node=dev_entry, shared_node=_ch(cfg, "shared"))
        env.devices.append(d)
    else:
        _load_panorama(env, cfg, dev_entry, site_codes=codes)
    pair_ha(env.devices)
    return env


def _read_vars(n: ET.Element | None) -> dict[str, str]:
    out = {}
    for e in _entries(n):
        t = _ch(e, "type")
        if t is not None and len(t):
            out[e.get("name")] = _txt(t[0])
    return out



_VSYS_ID = re.compile(r"^vsys\d+$", re.I)
_SKIP_TOKENS = frozenset({"vsys", "dg", "fw", "tm"})


def _name_tokens(name: str) -> list[str]:
    return [t.lower() for t in re.split(r"[-_]+", name or "") if t and t.lower() not in _SKIP_TOKENS]


_SITE_CODE = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")


def normalize_site_codes(values: object) -> list[str]:
    """Lowercased, unique site-name tokens from a list or a comma-separated string. Junk is dropped."""
    if values is None:
        raw: list = []
    elif isinstance(values, str):
        raw = re.split(r"[,\s]+", values)
    elif isinstance(values, (list, tuple, set)):
        raw = list(values)
    else:
        raw = []
    out: list[str] = []
    seen: set[str] = set()
    for v in raw:
        t = str(v).strip().lower()
        if _SITE_CODE.match(t) and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def dg_for_vsys_name(vsys_name: str, dgmap: dict[str, str], site_codes: list[str] | tuple[str, ...] | None = None) -> str | None:
    """Resolve a vsys to a device group: exact map, wildcard, or a conservative name match.

    Device-group membership often lists ``vsys5`` while the template names the
    vsys ``VSYS_DC_APP``. The last significant token of the vsys name must appear
    in the DG name. When the customer has configured ``site_codes`` (for example
    ``dc1``, ``dc2``), a token from that list must agree on both names if it
    appears on either. Unique best overlap only; ties stay unmapped. The default
    site-code list is empty: no city or site name is built in.
    """
    if not vsys_name:
        return None
    if vsys_name in dgmap:
        return dgmap[vsys_name]
    if "*" in dgmap:
        return dgmap["*"]
    return _dg_match_named_vsys(vsys_name, dgmap, site_codes=site_codes)


def _dg_match_named_vsys(vsys_name: str, dgmap: dict[str, str], site_codes: list[str] | tuple[str, ...] | None = None) -> str | None:
    if not vsys_name or _VSYS_ID.match(vsys_name):
        return None
    vtoks = _name_tokens(vsys_name)
    if not vtoks:
        return None
    codes = set(normalize_site_codes(site_codes))
    last = vtoks[-1]
    scored: list[tuple[int, str]] = []
    for dg in sorted(set(dgmap.values())):
        dtoks = _name_tokens(dg)
        if last not in dtoks:
            continue
        sites = {t for t in set(vtoks) | set(dtoks) if t in codes}
        if any((s in vtoks) != (s in dtoks) for s in sites):
            continue
        scored.append((len(set(vtoks) & set(dtoks)), dg))
    if not scored:
        return None
    best = max(ov for ov, _ in scored)
    tops = [dg for ov, dg in scored if ov == best]
    return tops[0] if len(tops) == 1 else None


def _load_panorama(env: Environment, cfg: ET.Element, dev_entry: ET.Element, *, site_codes: list[str] | None = None) -> None:
    parent_of: dict[str, str] = {}
    ro = _ch(cfg, "readonly")
    for e in _entries(_at(ro, "devices/entry/device-group")) + _entries(_at(ro, "dg-meta-data/dg-info")):
        p = _txt(_ch(e, "parent-dg"))
        if p:
            parent_of[e.get("name")] = p
    dg_nodes: dict[str, ET.Element] = {}
    for e in _entries(_ch(dev_entry, "device-group")):
        nm = e.get("name")
        dg_nodes[nm] = e
        members = [(d.get("name"), [v.get("name") for v in _entries(_ch(d, "vsys"))]) for d in _entries(_ch(e, "devices"))]
        env.device_groups[nm] = DeviceGroup(nm, parent_of.get(nm), members, read_objects(e, f"DG {nm}", "device-group", nm))

    dg_index: dict[str, dict[str, str]] = {}
    for g in env.device_groups.values():
        for serial, vs in g.members:
            m = dg_index.setdefault(serial, {})
            if not vs:
                m["*"] = g.name
            for v in vs:
                m[v] = g.name

    def defaults_for(dg: str) -> dict[str, str]:
        out: dict[str, str] = {}
        nodes = [_ch(cfg, "shared")] + [dg_nodes.get(g.name) for g in reversed(env.dg_chain(dg))]
        for node in nodes:
            for e in _entries(_at(node, "post-rulebase/default-security-rules/rules")):
                a = _txt(_ch(e, "action"))
                if a and "intrazone" in e.get("name", ""):
                    out["intrazone"] = a
                if a and "interzone" in e.get("name", ""):
                    out["interzone"] = a
        return out

    templates = {e.get("name"): e for e in _entries(_ch(dev_entry, "template"))}
    managed = {e.get("name"): _txt(_ch(e, "hostname")) for e in _entries(_at(cfg, "mgt-config/devices"))}
    # vsys each firewall really has: managed-device list plus device-group membership.
    # A template shared by many firewalls can define vsys that a given firewall does not run.
    real_vsys: dict[str, set[str]] = {}
    for e in _entries(_at(cfg, "mgt-config/devices")):
        real_vsys.setdefault(e.get("name"), set()).update(v.get("name") for v in _entries(_ch(e, "vsys")))
    for g in env.device_groups.values():
        for serial, vs in g.members:
            real_vsys.setdefault(serial, set()).update(vs)
    in_stack: set[str] = set()
    for st in _entries(_ch(dev_entry, "template-stack")):
        sname = st.get("name")
        tnames = _members(_ch(st, "templates"))
        env.stacks[sname] = list(tnames)
        for tname, tnode in [(f"stack:{sname}", _ch(st, "config"))] + [(t, _ch(templates.get(t), "config")) for t in tnames]:
            if tnode is None:
                continue
            for kind in ("virtual-router", "logical-router"):
                for vr in tnode.iter(kind):
                    for e in _entries(vr):
                        env.vr_template.setdefault((sname, e.get("name")), tname)
        parts = [_ch(st, "config")] + [_ch(templates.get(t), "config") for t in tnames]
        merged = None
        for p in reversed([p for p in parts if p is not None]):
            merged = merge_nodes(p, merged) if merged is not None else p
        base_vars: dict[str, str] = {}
        for t in reversed(tnames):
            base_vars.update(_read_vars(_ch(templates.get(t), "variable")))
        base_vars.update(_read_vars(_ch(st, "variable")))
        devnode = None
        if merged is not None:
            d0 = _ch(merged, "devices")
            devnode = _device_entry(d0)
        tshared = _ch(merged, "shared") if merged is not None else None
        for d in _entries(_ch(st, "devices")):
            serial = d.get("name")
            in_stack.add(serial)
            vars = dict(base_vars)
            vars.update(_read_vars(_ch(d, "variable")))
            hn = managed.get(serial) or _txt(_ch(d, "hostname")) or vars.get("$hostname") or serial
            dgmap = dg_index.get(serial, {})
            node = devnode if devnode is not None else ET.Element("entry", {"name": "localhost.localdomain"})
            dev = build_device(id=f"{env.target}:{serial}", name=hn, backend="panorama", target=env.target,
                               device_node=node, shared_node=tshared, vars=vars, serial=serial, stack=sname,
                               dg_for_vsys=lambda v, m=dgmap: dg_for_vsys_name(v, m, site_codes=site_codes), defaults_for_dg=defaults_for,
                               shared_scope=env.shared)
            known = serial in real_vsys
            keep = set(real_vsys.get(serial) or ({"vsys1"} if known else set()))
            if keep:
                keep.update(n for n in dev.vsys if dg_for_vsys_name(n, dgmap, site_codes=site_codes))
            _restrict_vsys(dev, keep)
            env.devices.append(dev)
    for serial, hn in managed.items():
        if serial in in_stack:
            continue
        dgmap = dg_index.get(serial, {})
        dev = build_device(id=f"{env.target}:{serial}", name=hn or serial, backend="panorama", target=env.target,
                           device_node=ET.Element("entry", {"name": "localhost.localdomain"}), shared_node=None,
                           serial=serial, dg_for_vsys=lambda v, m=dgmap: dg_for_vsys_name(v, m, site_codes=site_codes), defaults_for_dg=defaults_for)
        dev.no_network = True
        dev.warnings.append("in a device group but no template stack: no network config in this export")
        env.devices.append(dev)


def _restrict_vsys(dev: Device, keep: set[str]) -> None:
    """Drop template vsys this firewall does not run (keeps shared gateways and the single-vsys case)."""
    if not keep or len(dev.vsys) <= 1:
        return
    drop = {n for n, v in dev.vsys.items() if n not in keep and not v.shared_gateway}
    if not drop or len(drop) == len(dev.vsys):
        return
    for n in drop:
        del dev.vsys[n]
    for name in [i for i, it in dev.interfaces.items() if it.vsys in drop]:
        del dev.interfaces[name]
    for name in [k for k, r in dev.routers.items() if r.owner in drop]:
        del dev.routers[name]
    for r in unique_routers(dev):
        r.routes = [x for x in r.routes if x.kind not in ("connected", "local") or x.iface in dev.interfaces]
    dev.multi_vsys = len(dev.vsys) > 1
    dev.warnings.append(f"template defines {len(drop)} vsys this firewall does not run; ignored")


# --------------------------------------------------------------------- HA
def pair_ha(devices: list[Device]) -> list[tuple[Device, Device]]:
    """Pair HA peers conservatively (FlowMapper rules).

    A missed pair shows as two firewalls; a false pair hides one, so:
    devices on different template stacks never pair (different sites); an
    explicit peer-ip must uniquely name one other firewall's HA1 or
    interface address; otherwise inference needs >=2 shared interface
    addresses and >=80% of the larger set, and exactly one match each.
    """
    def stack_ok(a: Device, b: Device) -> bool:
        return not (a.stack and b.stack and a.stack != b.stack)

    sig = {d.id: {str(ip) for it in d.interfaces.values() for ip in it.ips if ip.network.prefixlen < 32} for d in devices}
    owners: dict[str, set[str]] = {}
    for d in devices:
        ips = set(d.ha.own if d.ha and d.ha.enabled is not False else [])
        ips |= {str(ip.ip) for it in d.interfaces.values() for ip in it.ips}
        for ip in ips:
            owners.setdefault(ip, set()).add(d.id)
    by_id = {d.id: d for d in devices}
    pairs: list[tuple[Device, Device]] = []
    taken: set[str] = set()
    for d in devices:
        if d.id in taken or not d.ha or not d.ha.enabled:
            continue
        for ip in d.ha.peers:
            cand = owners.get(ip, set()) - {d.id}
            if len(cand) == 1:
                o = by_id[cand.pop()]
                if o.id not in taken and stack_ok(d, o):
                    pairs.append((d, o))
                    taken |= {d.id, o.id}
                    break
    pool = [d for d in devices if d.id not in taken and not (d.ha and d.ha.enabled is False)]
    match: dict[str, list[Device]] = {d.id: [] for d in pool}
    for i, a in enumerate(pool):
        for b in pool[i + 1:]:
            if not stack_ok(a, b):
                continue
            sa, sb = sig[a.id], sig[b.id]
            n = len(sa & sb)
            if len(sa) >= 2 and len(sb) >= 2 and n >= 2 and n >= 0.8 * max(len(sa), len(sb)):
                match[a.id].append(b)
                match[b.id].append(a)
    for a in pool:
        if len(match[a.id]) == 1 and a.id not in taken:
            b = match[a.id][0]
            if len(match[b.id]) == 1 and b.id not in taken:
                pairs.append((a, b))
                taken |= {a.id, b.id}
    for a, b in pairs:
        a.ha_peer, b.ha_peer = b.name, a.name
        b.ha_secondary = True
    return pairs


def merge_environments(envs: Iterable[Environment]) -> list[Device]:
    out: list[Device] = []
    for e in envs:
        out.extend(e.devices)
    return out
