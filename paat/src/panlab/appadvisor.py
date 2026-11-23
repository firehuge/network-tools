"""Port-to-App-ID advisor (read-only): turn port-based allow rules into App-ID rules, from the traffic logs.

For each port-based rule (application ``any`` with explicit service ports; or the rules you name):

1. Read the rule and its service objects/groups from the policy owner's running config
   (Panorama device group incl. parent groups and shared, or a standalone firewall's vsys).
2. Pull the rule's traffic logs over the XML API (``rule eq '<name>'`` over a time window)
   from the customer's firewall(s), and count sessions, bytes, first/last seen per port and app.
3. Look up each app's default ports on the firewall (``show predefined``; built-in table fallback).
4. Suggest a replacement:
   - apps seen on their default port -> one rule with those apps and ``service application-default``;
   - apps seen on a non-standard port (ssh on 2222) -> app + that explicit port;
   - ``insufficient-data`` / ``incomplete`` / ``unknown-*`` -> port stays on the original rule,
     marked "needs review / more data";
   - ports with no traffic in the window -> candidate for removal (more confident with a longer window).
5. Render a CR-template change plan (GUI + CLI + backout). Never writes to a device.
"""

from __future__ import annotations

import json
import re
import secrets
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Protocol

from panlab.apps import APP_PORTS
from panlab.customers import Profile
from panlab.pusher import PushError, now

REVIEW_APPS = {"insufficient-data", "incomplete", "unknown-tcp", "unknown-udp", "unknown-p2p", "not-applicable", "unknown"}
# building-block apps: seen when a session never got far enough to show the real app (or it was not that app at all)
BUILDING_BLOCKS = {"cotp": "ms-rdp", "t.120": "ms-rdp", "rpc": "msrpc", "ms-rpc": "msrpc"}
PREDEFINED_SERVICES = {"service-http": [("tcp", "80"), ("tcp", "8080")], "service-https": [("tcp", "443")]}
MAX_RULE_NAME = 63


# ---------------------------------------------------------------- config model

@dataclass
class Rule:
    name: str
    scope: str  # device group name, or "vsys1"
    rulebase: str  # pre-rulebase / post-rulebase / rulebase
    owner: str  # "panorama" or "firewall"
    from_: list[str]
    to: list[str]
    source: list[str]
    destination: list[str]
    application: list[str]
    service: list[str]
    action: str
    disabled: bool
    log_setting: str = ""
    profile_group: str = ""
    tags: list[str] = field(default_factory=list)
    log_end: bool = True

    @property
    def port_based(self) -> bool:
        return (self.action == "allow" and not self.disabled and self.application == ["any"]
                and self.service not in (["any"], ["application-default"], []))


def _m(e: ET.Element | None, p: str) -> list[str]:
    return [x.text or "" for x in e.findall(f"{p}/member")] if e is not None else []


class Config:
    """Rules + service objects from a Panorama or firewall running config (XML root)."""

    def __init__(self, root: ET.Element, parents: dict[str, str] | None = None):
        self.root = root
        dev = root.find("./devices/entry")
        self.panorama = dev is not None and dev.find("device-group") is not None
        self.services: dict[str, dict[str, ET.Element]] = defaultdict(dict)  # scope -> name -> entry
        self.groups: dict[str, dict[str, list[str]]] = defaultdict(dict)
        self.parent: dict[str, str] = {}
        self.rules: list[Rule] = []
        self._load_objects("shared", root.find("./shared"))
        if self.panorama:
            for dg in dev.findall("./device-group/entry"):
                self._load_objects(dg.get("name"), dg)
                for rb in ("pre-rulebase", "post-rulebase"):
                    for r in dg.findall(f"./{rb}/security/rules/entry"):
                        self.rules.append(self._rule(r, dg.get("name"), rb, "panorama"))
            for dg in root.findall("./readonly/devices/entry/device-group/entry"):
                p = dg.findtext("parent-dg")
                if p:
                    self.parent[dg.get("name")] = p
            self.parent.update(parents or {})
        else:
            for vs in (dev.findall("./vsys/entry") if dev is not None else []):
                self._load_objects(vs.get("name"), vs)
                for r in vs.findall("./rulebase/security/rules/entry"):
                    self.rules.append(self._rule(r, vs.get("name"), "rulebase", "firewall"))

    def _load_objects(self, scope: str, e: ET.Element | None) -> None:
        if e is None:
            return
        for s in e.findall("./service/entry"):
            self.services[scope][s.get("name")] = s
        for g in e.findall("./service-group/entry"):
            self.groups[scope][g.get("name")] = _m(g, "members")

    @staticmethod
    def _rule(r: ET.Element, scope: str, rb: str, owner: str) -> Rule:
        return Rule(name=r.get("name"), scope=scope, rulebase=rb, owner=owner, from_=_m(r, "from"), to=_m(r, "to"),
                    source=_m(r, "source"), destination=_m(r, "destination"), application=_m(r, "application"),
                    service=_m(r, "service"), action=(r.findtext("action") or "").strip(),
                    disabled=(r.findtext("disabled") or "no").strip() == "yes", log_setting=(r.findtext("log-setting") or "").strip(),
                    profile_group=(r.findtext("profile-setting/group/member") or "").strip(), tags=_m(r, "tag"),
                    log_end=(r.findtext("log-end") or "yes").strip() != "no")

    def chain(self, scope: str) -> list[str]:
        out, cur = [], scope
        while cur and cur not in out:
            out.append(cur)
            cur = self.parent.get(cur)
        return out + ["shared"]

    def resolve_service(self, name: str, scope: str, _seen: frozenset = frozenset()) -> list[tuple[str, str]]:
        """(proto, port-spec) list for a service object or group, looked up from ``scope`` upwards."""
        if name in PREDEFINED_SERVICES:
            return list(PREDEFINED_SERVICES[name])
        if name in _seen:
            return []
        for sc in self.chain(scope):
            if name in self.services.get(sc, {}):
                s = self.services[sc][name]
                out = []
                for proto in ("tcp", "udp"):
                    port = s.findtext(f"protocol/{proto}/port")
                    if port:
                        out += [(proto, p.strip()) for p in port.split(",") if p.strip()]
                return out
            if name in self.groups.get(sc, {}):
                return [x for m in self.groups[sc][name] for x in self.resolve_service(m, scope, _seen | {name})]
        # hierarchy unknown (older Panorama): any device group that defines the name
        for sc, objs in self.services.items():
            if name in objs and sc not in self.chain(scope):
                return self.resolve_service(name, sc, _seen)
        for sc, grps in self.groups.items():
            if name in grps and sc not in self.chain(scope):
                return [x for m in grps[name] for x in self.resolve_service(m, sc, _seen | {name})]
        return []

    def service_for(self, proto: str, port: str, scope: str) -> str | None:
        """An existing service object that is exactly proto/port, visible from ``scope``."""
        for sc in self.chain(scope):
            for n, s in sorted(self.services.get(sc, {}).items()):
                if self.resolve_service(n, scope) == [(proto, port)]:
                    return n
        return None


# ---------------------------------------------------------------- ports + app defaults

def parse_default_ports(members: list[str]) -> list[tuple[str, str]]:
    """``['tcp/25,587', 'udp/53']`` -> [(tcp,25),(tcp,587),(udp,53)]; ``dynamic`` kept as a port value."""
    out = []
    for m in members:
        if "/" not in m:
            continue
        proto, ports = m.split("/", 1)
        out += [(proto.strip().lower(), p.strip()) for p in ports.split(",") if p.strip()]
    return out


def port_in(proto: str, port: int, specs: list[tuple[str, str]]) -> bool:
    for p, spec in specs:
        if p != proto or spec == "dynamic":
            continue
        if "-" in spec:
            a, b = spec.split("-", 1)
            if a.isdigit() and b.isdigit() and int(a) <= port <= int(b):
                return True
        elif spec.isdigit() and int(spec) == port:
            return True
    return False


def fallback_defaults(app: str) -> list[tuple[str, str]] | None:
    if app in APP_PORTS:
        return list(APP_PORTS[app])
    return None


# ---------------------------------------------------------------- device access

class AdvisorAPI(Protocol):
    def config_root(self) -> ET.Element: ...
    def traffic_logs(self, query: str, nlogs: int) -> list[dict]: ...
    def app_default_ports(self, app: str) -> list[str] | None: ...  # raw members like 'tcp/25,587'; None = unknown


class LiveAPI:
    """Read-only: config from the policy owner (Panorama if the customer has one), logs + App-ID data from firewalls."""

    def __init__(self, profile: Profile, log_targets: list[str]):
        from panlab.pusher import connect_target

        owner = next((t for t in profile.targets if t.type == "panorama"), None) or profile.targets[0]
        self.owner = connect_target(profile, owner.name)
        self.owner_name = owner.name
        self.owner_type = owner.type
        self.log_targets = log_targets
        self.fws = {t: connect_target(profile, t) for t in log_targets}
        self._apps: dict[str, list[str] | None] = {}

    def config_root(self) -> ET.Element:
        from panlab.backup import export_running_config

        xml = export_running_config(self.owner.fw)
        return ET.fromstring(xml.split("?>", 1)[-1])

    def dg_parents(self) -> dict[str, str]:
        if self.owner_type != "panorama":
            return {}
        try:
            self.owner.fw.xapi.op("<show><dg-hierarchy></dg-hierarchy></show>")
        except Exception:  # noqa: BLE001 - older Panorama: fall back to the config's readonly section
            return {}
        out: dict[str, str] = {}

        def walk(e: ET.Element, parent: str | None) -> None:
            for dg in e.findall("./dg"):
                if parent:
                    out[dg.get("name")] = parent
                walk(dg, dg.get("name"))

        root = self.owner.fw.xapi.element_root
        hier = root.find(".//dg-hierarchy") if root is not None else None
        if hier is not None:
            walk(hier, None)
        return out

    def traffic_logs(self, query: str, nlogs: int) -> list[dict]:
        out = []
        for name, dev in self.fws.items():
            try:
                dev.fw.xapi.log(log_type="traffic", nlogs=nlogs, filter=query, interval=2, timeout=180)
            except Exception as exc:  # noqa: BLE001 - API message only, never credentials
                raise PushError(f"traffic log query on {name} failed: {exc}") from exc
            root = dev.fw.xapi.element_root
            for e in (root.findall(".//logs/entry") if root is not None else []):
                d = {c.tag: (c.text or "") for c in e}
                d["_target"] = name
                out.append(d)
        return out

    def app_default_ports(self, app: str) -> list[str] | None:
        if app in self._apps:
            return self._apps[app]
        if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,63}", app):
            return None
        val = None
        for dev in self.fws.values():
            try:
                dev.fw.xapi.op(f"<show><predefined><xpath>/predefined/application/entry[@name='{app}']</xpath></predefined></show>")
                root = dev.fw.xapi.element_root
                val = [m.text or "" for m in root.findall(".//default/port/member")]
                break
            except Exception:  # noqa: BLE001 - custom or unknown app: fall back
                continue
        self._apps[app] = val
        return val


def log_targets_for(profile: Profile, user=None) -> list[str]:
    """Firewall targets whose logs we read (in the user's device scope), else the Panorama (forwarded logs)."""
    from panlab import identity
    from panlab.web import auth

    fws = [t.name for t in profile.targets if t.type == "firewall"]
    if user is not None:
        pats = user.device_scope(profile.name)
        if pats is not None:
            fws = [t for t in fws if auth.device_in_scope(pats, target=t, hostname=(identity.cached(profile, t) or {}).get("hostname") or "",
                                                         serial=(identity.cached(profile, t) or {}).get("serial") or "")]
    if fws:
        return fws
    if user is not None and user.device_scope(profile.name) is not None:
        return []
    return [t.name for t in profile.targets if t.type == "panorama"]


api_factory: Callable[[Profile, list[str]], AdvisorAPI] = LiveAPI  # tests replace this


# ---------------------------------------------------------------- analysis

def build_query(rule: str, since: datetime) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.\- ]{1,63}", rule):
        raise PushError(f"bad rule name {rule!r}")
    return f"(rule eq '{rule}') and (receive_time geq '{since.strftime('%Y/%m/%d %H:%M:%S')}')"


def aggregate(entries: list[dict]) -> dict[tuple[str, int], dict[str, dict]]:
    """(proto, dport) -> app -> {sessions, bytes, first, last, devices}."""
    out: dict[tuple[str, int], dict[str, dict]] = defaultdict(dict)
    for e in entries:
        if (e.get("action") or "allow") != "allow":
            continue
        proto = (e.get("proto") or "").lower()
        try:
            port = int(e.get("dport") or "")
        except ValueError:
            continue
        app = e.get("app") or "unknown"
        n = int(e.get("repeatcnt") or 1)
        t = e.get("receive_time") or e.get("time_generated") or ""
        a = out[(proto, port)].setdefault(app, {"sessions": 0, "bytes": 0, "first": t, "last": t, "devices": {}})
        a["sessions"] += n
        a["bytes"] += int(e.get("bytes") or 0)
        a["first"] = min(a["first"], t) if a["first"] else t
        a["last"] = max(a["last"], t)
        dn, sn = e.get("device_name") or "", e.get("serial") or ""
        if dn or sn:
            a["devices"][sn or dn] = dn
    return out


def confidence(sessions: int, days: float) -> str:
    if sessions >= 20 and days >= 7:
        return "high"
    if sessions >= 3:
        return "medium"
    return "low"


def svc_name(naming: str, proto: str, port: int | str) -> str:
    try:
        name = naming.format(proto=proto, port=port)
    except (KeyError, IndexError, ValueError):
        name = f"{proto}-{port}"
    return re.sub(r"[^A-Za-z0-9_.\-]", "-", name)[:63]


def _rule_name(base: str, suffix: str) -> str:
    keep = MAX_RULE_NAME - len(suffix) - 1
    return f"{base[:keep]}-{suffix}"


def analyze_rule(cfg: Config, rule: Rule, entries: list[dict], *, days: float, capped: bool,
                 app_defaults: Callable[[str], list[tuple[str, str]] | None], naming: str = "{proto}-{port}") -> dict:
    specs = [(p, s) for svc in rule.service for p, s in cfg.resolve_service(svc, rule.scope)]
    agg = aggregate(entries)
    seen_ports = sorted(agg)
    ports: list[dict] = []
    # every configured port (single ports and ranges), plus any logged port not in the service (should not happen)
    singles: list[tuple[str, int]] = []
    for p, s in specs:
        if s.isdigit():
            singles.append((p, int(s)))
        elif "-" in s:
            singles += [k for k in seen_ports if k[0] == p and port_in(p, k[1], [(p, s)])] or []
    for k in seen_ports:
        if k not in singles:
            singles.append(k)
    singles = sorted(set(singles), key=lambda k: (k[0], k[1]))
    appid_apps: dict[str, int] = {}
    explicit: dict[tuple[str, int], dict[str, int]] = defaultdict(dict)
    keep_ports: list[tuple[str, int]] = []
    remove_ports: list[tuple[str, int]] = []
    for proto, port in singles:
        apps = agg.get((proto, port), {})
        rows = []
        real = {a: v for a, v in apps.items() if a not in REVIEW_APPS and a not in BUILDING_BLOCKS}
        review = {a: v for a, v in apps.items() if a in REVIEW_APPS or a in BUILDING_BLOCKS}
        for a, v in sorted(apps.items(), key=lambda kv: -kv[1]["sessions"]):
            if a in REVIEW_APPS:
                verdict, why = "review", "the firewall could not identify the application (too little data, or unknown traffic)"
            elif a in BUILDING_BLOCKS:
                real_app = BUILDING_BLOCKS[a]
                d = app_defaults(real_app) or []
                how = "with service application-default" if port_in(proto, port, d) else f"on {proto}/{port}"
                verdict, why = "review", (f"{a} is a building block of {real_app}; the sessions never showed {real_app} itself "
                                          f"(a test listener, failed logins, or not really {real_app}). If it is {real_app}, "
                                          f"allow {real_app} {how}; do not allow {a} on its own")
            else:
                d = app_defaults(a)
                if d is None:
                    verdict, why = "explicit", "default ports unknown (custom app?): keep the explicit port"
                elif port_in(proto, port, d):
                    verdict, why = "app-default", f"{proto}/{port} is a default port of {a} ({', '.join(f'{x}/{y}' for x, y in d) or 'none'})"
                else:
                    verdict, why = "explicit", (f"{a} on a non-standard port; its defaults are "
                                                f"{', '.join(f'{x}/{y}' for x, y in d) or 'none'}")
            rows.append({"app": a, **{k: v[k] for k in ("sessions", "bytes", "first", "last")}, "verdict": verdict, "why": why,
                         "confidence": confidence(v["sessions"], days)})
            if verdict == "app-default":
                appid_apps[a] = appid_apps.get(a, 0) + v["sessions"]
            elif verdict == "explicit":
                explicit[(proto, port)][a] = v["sessions"]
        if not apps:
            status = "unused"
            remove_ports.append((proto, port))
        elif review and real:
            status = "mixed"
            keep_ports.append((proto, port))
        elif review:
            status = "review"
            keep_ports.append((proto, port))
        else:
            status = "migrate"
        ports.append({"proto": proto, "port": port, "status": status, "apps": rows,
                      "sessions": sum(r["sessions"] for r in rows), "bytes": sum(r["bytes"] for r in rows),
                      "unused_confidence": ("medium" if days >= 30 else "low") if not apps else None})
    # proposed rules
    new_rules, new_services = [], []
    if appid_apps:
        new_rules.append({"name": _rule_name(rule.name, "APPID"), "application": sorted(appid_apps), "service": ["application-default"],
                          "why": "apps seen only on their default ports",
                          "confidence": confidence(min(appid_apps.values()), days)})
    for (proto, port), apps in sorted(explicit.items()):
        svc = cfg.service_for(proto, str(port), rule.scope)
        if not svc:
            svc = svc_name(naming, proto, port)
            if svc not in [s["name"] for s in new_services]:
                new_services.append({"name": svc, "proto": proto, "port": str(port)})
        new_rules.append({"name": _rule_name(rule.name, f"{proto.upper()}{port}"), "application": sorted(apps), "service": [svc],
                          "why": f"{', '.join(sorted(apps))} on {proto}/{port}, not the app's default port",
                          "confidence": confidence(min(apps.values()), days)})
    keep_services = []
    for proto, port in keep_ports:
        svc = cfg.service_for(proto, str(port), rule.scope)
        if not svc:
            svc = svc_name(naming, proto, port)
            if svc not in [s["name"] for s in new_services]:
                new_services.append({"name": svc, "proto": proto, "port": str(port)})
        keep_services.append(svc)
    if keep_services:
        original = {"action": "narrow", "service": keep_services,
                    "why": "these ports still carry traffic the firewall could not identify; keep them port-based until reviewed"}
    else:
        original = {"action": "disable", "service": rule.service,
                    "why": "every port is covered by the new App-ID rules or unused; disable now, delete after a quiet period"}
    total = sum(p["sessions"] for p in ports)
    return {"rule": asdict(rule) | {"port_based": rule.port_based}, "configured_ports": [f"{p}/{s}" for p, s in specs],
            "ports": ports, "sessions": total, "capped": capped, "new_rules": new_rules, "new_services": new_services,
            "original": original, "remove_ports": [f"{p}/{n}" for p, n in remove_ports],
            "review_ports": [f"{p}/{n}" for p, n in keep_ports],
            "overall_confidence": _lowest([n["confidence"] for n in new_rules]) if new_rules else "low"}


def _lowest(levels: list[str]) -> str:
    order = ["low", "medium", "high"]
    return min(levels, key=order.index)


def run(profile: Profile, *, rules: list[str] | None = None, days: int = 7, max_logs: int = 5000, actor: str = "",
        api: AdvisorAPI | None = None, log_targets: list[str] | None = None, save: bool = True) -> dict:
    """Analyze the named rules (or every port-based allow rule). Read-only."""
    targets = log_targets if log_targets is not None else log_targets_for(profile)
    if not targets:
        raise PushError("no firewall in your scope to read traffic logs from")
    api = api or api_factory(profile, targets)
    cfg = Config(api.config_root(), parents=getattr(api, "dg_parents", lambda: {})())
    wanted = [r for r in cfg.rules if (r.name in rules if rules else r.port_based)]
    if rules:
        missing = sorted(set(rules) - {r.name for r in wanted})
        if missing:
            raise PushError(f"rule(s) not found: {', '.join(missing)}")
    since = now() - timedelta(days=days)
    cache: dict[str, list[tuple[str, str]] | None] = {}

    def defaults(app: str):
        if app not in cache:
            raw = api.app_default_ports(app)
            cache[app] = parse_default_ports(raw) if raw is not None else fallback_defaults(app)
        return cache[app]

    naming = (profile.naming or {}).get("service") or "{proto}-{port}"
    results, devices = [], {}
    for r in wanted:
        q = build_query(r.name, since)
        entries = api.traffic_logs(q, max_logs)
        for e in entries:
            if e.get("serial") or e.get("device_name"):
                devices[e.get("serial") or e.get("device_name")] = e.get("device_name") or ""
        res = analyze_rule(cfg, r, entries, days=days, capped=len(entries) >= max_logs, app_defaults=defaults, naming=naming)
        res["query"] = q
        res["log_entries"] = len(entries)
        results.append(res)
    adv = {"schema": "panlab.app-advisor/v1", "id": f"adv-{now():%Y%m%d-%H%M%S}-{secrets.token_hex(3)}",
           "customer": profile.name, "created": now().isoformat(timespec="seconds"), "timezone": "America/Chicago", "by": actor,
           "window_days": days, "since": since.strftime("%Y/%m/%d %H:%M:%S"), "max_logs": max_logs,
           "log_targets": targets, "policy_owner": next((t.name for t in profile.targets if t.type == "panorama"), targets[0]),
           "log_devices": [{"serial": s, "hostname": h} for s, h in sorted(devices.items())],
           "results": results, "app_defaults": {k: [f"{p}/{x}" for p, x in v] if v is not None else None for k, v in cache.items()}}
    if save:
        p = advisor_dir(profile) / f"{adv['id']}.json"
        p.write_text(json.dumps(adv, indent=2), encoding="utf-8")
        p.chmod(0o600)
    return adv


def advisor_dir(profile: Profile) -> Path:
    return profile.data_dir("app-advisor")


def load(profile: Profile, aid: str) -> dict:
    if not re.fullmatch(r"adv-\d{8}-\d{6}-[0-9a-f]{6}", aid):
        raise ValueError("bad advisor id")
    return json.loads((advisor_dir(profile) / f"{aid}.json").read_text(encoding="utf-8"))


def list_runs(profile: Profile) -> list[str]:
    return sorted((p.stem for p in advisor_dir(profile).glob("adv-*.json")), reverse=True)


# ---------------------------------------------------------------- CR change plan

def _members(xs: list[str]) -> str:
    return "[ " + " ".join(xs) + " ]" if len(xs) != 1 else xs[0]


def _base(rule: dict) -> str:
    if rule["owner"] == "panorama":
        return f"device-group {rule['scope']} {rule['rulebase']} security rules"
    return "rulebase security rules"


def _obj_base(rule: dict) -> str:
    return f"device-group {rule['scope']} service" if rule["owner"] == "panorama" else "service"


def _gui_where(rule: dict) -> str:
    if rule["owner"] == "panorama":
        rb = "Pre Rules" if rule["rulebase"] == "pre-rulebase" else "Post Rules"
        return f"Panorama > Policies > Security > {rb}, Device Group **{rule['scope']}**"
    return "Policies > Security"


def render_cr(adv: dict, ident_line: str = "") -> str:
    L = [f"# App-ID migration: {', '.join(r['rule']['name'] for r in adv['results'])}", "",
         f"- Customer: {adv['customer']}",
         f"- Advisor run: {adv['id']} (created {adv['created']} America/Chicago, by {adv.get('by') or '?'})",
         f"- Log window: last {adv['window_days']} day(s), since {adv['since']} (firewall clock), up to {adv['max_logs']} log entries per rule",
         f"- Logs read from: {', '.join(adv['log_targets'])}" + (f" ({ident_line})" if ident_line else ""),
         "- This plan was generated from traffic logs and is advisory. Nothing was changed on any device.", "",
         "## Summary", ""]
    for r in adv["results"]:
        rule = r["rule"]
        L.append(f"### {rule['name']} ({rule['scope']} {rule['rulebase']})")
        L.append(f"Today: application **any** on {', '.join(r['configured_ports']) or '(no ports resolved)'} "
                 f"({', '.join(rule['service'])}). {r['sessions']} session(s) in {r['log_entries']} log entr(ies)"
                 + (" (result capped: widen the filter or shorten the window)" if r["capped"] else "") + ".")
        L += ["", "| Port | Status | Apps seen (sessions, bytes, first - last) |", "|---|---|---|"]
        for p in r["ports"]:
            apps = "; ".join(f"{a['app']} ({a['sessions']}, {a['bytes']} B, {a['first']} - {a['last']}) -> {a['verdict']}"
                             for a in p["apps"]) or f"none: candidate for removal ({p['unused_confidence']} confidence)"
            L.append(f"| {p['proto']}/{p['port']} | {p['status']} | {apps} |")
        L += ["", "Proposed:"]
        for n in r["new_rules"]:
            L.append(f"- New rule **{n['name']}**: application {', '.join(n['application'])}, service {', '.join(n['service'])} "
                     f"({n['why']}; confidence {n['confidence']}).")
        o = r["original"]
        if o["action"] == "narrow":
            L.append(f"- Keep **{rule['name']}** but only for {', '.join(r['review_ports'])} ({', '.join(o['service'])}): {o['why']}.")
        else:
            L.append(f"- Disable **{rule['name']}**: {o['why']}.")
        if r["remove_ports"]:
            L.append(f"- Remove unused port(s) {', '.join(r['remove_ports'])} (no sessions in the window; check a longer window "
                     "or a business cycle before you rely on this).")
        if r["review_ports"]:
            L.append(f"- **Needs review / more data:** {', '.join(r['review_ports'])}: the firewall saw "
                     "insufficient-data / incomplete / unknown traffic. Find out what really runs there before tightening.")
        L.append(f"- Overall confidence: **{r['overall_confidence']}**.")
        L.append("")
    L += ["## How to use this plan", "",
          "Add the new rules directly above the port-based rule, so traffic moves to them first; then narrow or disable the "
          "old rule. Watch the traffic log for denies after the change (the post-rule deny log, or `paat denylog`). If "
          "anything breaks, use the Backout Plan.", "", "## Implementation Plan", ""]
    n = 1
    for r in adv["results"]:
        rule = r["rule"]
        for s in r["new_services"]:
            L.append(f"{n}. Create service **{s['name']}**: {_gui_where(rule).split(',')[0].replace('Policies > Security', 'Objects > Services')}"
                     f"{', Device Group ' + rule['scope'] if rule['owner'] == 'panorama' else ''} > Add: Protocol {s['proto'].upper()}, "
                     f"Destination Port {s['port']}.")
            n += 1
        for nr in r["new_rules"]:
            L.append(f"{n}. {_gui_where(rule)} > select **{rule['name']}** > Clone (or Add) as **{nr['name']}**: same zones "
                     f"({', '.join(rule['from_'])} -> {', '.join(rule['to'])}), source {', '.join(rule['source'])}, destination "
                     f"{', '.join(rule['destination'])}; Application tab: {', '.join(nr['application'])}; Service/URL Category tab: "
                     f"{', '.join(nr['service'])}; Actions: Allow, same log forwarding ({rule['log_setting'] or 'none'}) and "
                     f"profile group ({rule['profile_group'] or 'none'}). Place it directly **above** {rule['name']}.")
            n += 1
        o = r["original"]
        if o["action"] == "narrow":
            L.append(f"{n}. Open **{rule['name']}** > Service/URL Category: replace {', '.join(rule['service'])} with "
                     f"{', '.join(o['service'])}. (Do not edit the shared group itself; other rules may use it.)")
        else:
            L.append(f"{n}. Select **{rule['name']}** > Disable.")
        n += 1
    owner_pano = any(r["rule"]["owner"] == "panorama" for r in adv["results"])
    dgs = sorted({r["rule"]["scope"] for r in adv["results"] if r["rule"]["owner"] == "panorama"})
    L.append(f"{n}. Commit" + (f" to Panorama, then Push to Devices for device group(s) {', '.join(dgs)}." if owner_pano else "."))
    L += ["", "## Implementation (CLI)", "", "```", "configure"]
    for r in adv["results"]:
        rule = r["rule"]
        for s in r["new_services"]:
            L.append(f"set {_obj_base(rule)} {s['name']} protocol {s['proto']} port {s['port']}")
        for nr in r["new_rules"]:
            parts = [f"set {_base(rule)} {nr['name']}", f"from {_members(rule['from_'])}", f"to {_members(rule['to'])}",
                     f"source {_members(rule['source'])}", f"destination {_members(rule['destination'])}",
                     f"application {_members(nr['application'])}", f"service {_members(nr['service'])}", "action allow",
                     f"log-end {'yes' if rule['log_end'] else 'no'}"]
            if rule["log_setting"]:
                parts.append(f"log-setting {rule['log_setting']}")
            if rule["profile_group"]:
                parts.append(f"profile-setting group {rule['profile_group']}")
            if rule["tags"]:
                parts.append(f"tag {_members(rule['tags'])}")
            parts.append(f'description "App-ID migration of {rule["name"]} ({adv["id"]})"')
            L.append(" ".join(parts))
            L.append(f"move {_base(rule)} {nr['name']} before {rule['name']}")
        o = r["original"]
        if o["action"] == "narrow":
            L.append(f"set {_base(rule)} {rule['name']} service {_members(o['service'])}")
        else:
            L.append(f"set {_base(rule)} {rule['name']} disabled yes")
    L.append("commit")
    if owner_pano:
        L += [f"commit-all shared-policy device-group {dg}" for dg in dgs]
    L += ["```", "", "## Impact Analysis Statement", "",
          "Traffic that matches the new App-ID rules keeps flowing. Traffic on the old ports that is NOT one of the listed "
          "applications will be denied once the old rule is narrowed or disabled; that is the point of the change, so check "
          "the deny log right after the push. Ports marked 'needs review' stay allowed for any application.", "",
          "## Backout Plan", "", "```", "configure"]
    for r in adv["results"]:
        rule = r["rule"]
        o = r["original"]
        if o["action"] == "narrow":
            L.append(f"set {_base(rule)} {rule['name']} service {_members(rule['service'])}")
        else:
            L.append(f"set {_base(rule)} {rule['name']} disabled no")
        for nr in r["new_rules"]:
            L.append(f"delete {_base(rule)} {nr['name']}")
        for s in r["new_services"]:
            L.append(f"delete {_obj_base(rule)} {s['name']}")
    L.append("commit")
    if owner_pano:
        L += [f"commit-all shared-policy device-group {dg}" for dg in dgs]
    L += ["```", "", "GUI: re-enable the old rule (or set its service back to the original), delete the new rules and any new "
          "service objects, Commit" + (" and Push to Devices." if owner_pano else "."), "",
          "## Validation Plan", "",
          "Monitor > Traffic, filter `( rule eq '<new rule>' )`: sessions now hit the new App-ID rules with the expected "
          "applications. Filter `( rule eq '<old rule>' )`: only the needs-review ports remain (or nothing, if disabled). "
          "Check the deny log for the old ports. Re-run the App-ID advisor after a few days.", "",
          "## Communications Plan", "",
          "Tell the application owners which ports move to App-ID and that unidentified traffic on those ports will be "
          "blocked, before the window and when complete.", ""]
    return "\n".join(L)
