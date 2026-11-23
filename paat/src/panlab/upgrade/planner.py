"""Customer-wide discovery snapshot and the ordered, checked upgrade plan.

Snapshot (read-only): every target in the customer profile, plus every
firewall a Panorama target reports under ``show devices connected`` (reached
through Panorama with ``target=<serial>``). Devices are keyed by an id:

* ``t:<target>``           a profile target (direct API)
* ``m:<panorama>:<serial>`` a firewall reached through that Panorama

Plan: the selected devices with their target versions, ordered Panorama
first, then standalone firewalls, then HA pairs (passive/secondary first,
active last), each with its download/install path, safety checks and the
exact step list the runner executes one step at a time.
"""

from __future__ import annotations

import json
import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from zoneinfo import ZoneInfo

from panlab import identity as ident
from panlab.customers import Profile
from panlab.upgrade import device as devmod
from panlab.upgrade import paths
from panlab.upgrade.discovery import CMD_SYSINFO, batch_available_for, discover, now_iso, parse_sysinfo
from panlab.upgrade.safety import GREEN, RED, YELLOW, Check, device_checks, load_reference, panorama_checks, worst
from panlab.upgrade.versions import Available, V, is_downgrade, recommend, upgrade_path

TZ = ZoneInfo("America/Chicago")
SNAP_RE = re.compile(r"^disc-\d{8}-\d{6}-[0-9a-f]{6}$")
PLAN_RE = re.compile(r"^upg-\d{8}-\d{6}-[0-9a-f]{6}$")


def _stamp() -> str:
    return datetime.now(TZ).strftime("%Y%m%d-%H%M%S")


def upgrade_dir(profile: Profile) -> Path:
    return profile.data_dir("upgrade")


def _write(p: Path, data: dict) -> None:
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    p.chmod(0o600)


# ---------------------------------------------------------------- snapshot

def discover_customer(profile: Profile, *, actor: str = "", include_managed: bool = True, refresh: bool = True,
                      factory: Callable | None = None, save: bool = True) -> dict[str, Any]:
    """Read-only snapshot. Panoramas first; then every firewall, through its Panorama when one manages it.

    A profile firewall target that a Panorama in this customer manages is read *through* that
    Panorama (``target=<serial>``); its own API is not needed. Its serial is matched from the
    identity cache (or Panorama's hostname list) without contacting it; only when the tool has
    never seen it does ``auto`` access make one ``show system info`` call to learn the serial.
    See :mod:`panlab.upgrade.paths`.
    """
    factory = factory or devmod.device_factory
    snap: dict[str, Any] = {"id": f"disc-{_stamp()}-{secrets.token_hex(3)}", "customer": profile.name, "created": now_iso(),
                            "by": actor, "devices": {}, "order": []}
    by_serial: dict[str, str] = {}

    def add(did: str, f: dict) -> None:
        snap["devices"][did] = f
        snap["order"].append(did)
        if f.get("serial"):
            by_serial[f["serial"]] = did

    # 1. Panoramas, on their own API.
    for t in [t for t in profile.targets if t.type == "panorama"]:
        did = f"t:{t.name}"
        try:
            f = discover(factory(profile, t.name), kind=t.type, refresh=refresh)
        except devmod.DeviceError as exc:
            f = {"kind": t.type, "reachable": False, "errors": [str(exc)], "warnings": []}
        f.update({"id": did, "name": t.name, "connect": {"target": t.name, "serial": None}, "managed_by": None,
                  "profile_target": t.name, "access_path": paths.direct(why="Panorama is reached on its own API")})
        f["identity"] = ident.from_facts(f) if f.get("reachable") else ident.make(source="device did not answer")
        ident.remember(profile, t.name, f["identity"])
        add(did, f)
    # serial -> (panorama target, Panorama's managed-device entry)
    managed: dict[str, tuple[str, dict]] = {}
    if include_managed:
        for t in [t for t in profile.targets if t.type == "panorama"]:
            pf = snap["devices"][f"t:{t.name}"]
            for m in (pf.get("managed") or []) if pf.get("reachable") else []:
                if m.get("serial"):
                    managed.setdefault(m["serial"], (t.name, m))

    def through_panorama(pano_t: str, m: dict, did: str, name: str, profile_target: str | None, why: str) -> dict:
        sn = m["serial"]
        pf = snap["devices"][f"t:{pano_t}"]
        if not m.get("connected"):
            f = {"kind": "firewall", "reachable": False, "errors": ["not connected to Panorama"], "warnings": [],
                 "hostname": m.get("hostname"), "sw_version": m.get("sw_version"), "serial": sn}
        else:
            try:  # the firewall's own update-server check is not used; Panorama's image list is (below)
                f = discover(factory(profile, pano_t, sn), kind="firewall", refresh=False)
            except devmod.DeviceError as exc:
                f = {"kind": "firewall", "reachable": False, "errors": [str(exc)], "warnings": []}
        f.update({"id": did, "name": name, "connect": {"target": pano_t, "serial": sn}, "managed_by": f"t:{pano_t}",
                  "device_groups": (pf.get("device_groups") or {}).get(sn, []), "profile_target": profile_target,
                  "panorama_entry": {k: m.get(k) for k in ("connected", "sw_version", "ha_state", "family", "sync")},
                  "access_path": paths.via_panorama(pf, why=why)})
        if f.get("reachable"):
            fam = m.get("family") or f.get("family") or ""
            av = batch_available_for(pf.get("device_software") or [], fam, f.get("sw_version"))
            if av:
                f["available"] = [a.__dict__ for a in av]
                f["software_source"] = "panorama"
            else:
                f.setdefault("warnings", []).append(
                    f"Panorama lists no PanOS_{fam or '?'} images for this firewall; showing the images already on the firewall. "
                    "Run discovery with the update-server refresh ticked, or check Panorama > Device Deployment > Software.")
            if pf.get("can_download") is False:
                f["can_download"] = False
        if f.get("reachable") and f.get("hostname"):
            f["identity"] = ident.from_facts(f, "show system info (through Panorama)")
        else:  # the device did not answer; Panorama's managed-device list still says what it is
            f["identity"] = ident.make(m.get("hostname"), sn, model=m.get("model"), source="Panorama managed-device list")
        if f["identity"]["serial"] != sn:
            f.setdefault("warnings", []).append(
                f"Panorama lists serial {sn} but the device reported {f['identity']['serial'] or 'no serial'}.")
        ident.remember(profile, f"{pano_t}/{sn}", f["identity"])
        if profile_target:
            ident.remember(profile, profile_target, f["identity"])
        return f

    def known_serial(t) -> str | None:
        """The serial this profile target had last time, if a Panorama here manages it (no device contact)."""
        c = ident.cached(profile, t.name) or {}
        if c.get("serial") in managed:
            return c["serial"]
        hosts = [sn for sn, (_, m) in managed.items() if m.get("hostname") and m["hostname"] in (c.get("hostname"), t.name)]
        return hosts[0] if len(hosts) == 1 else None

    claimed: set[str] = set()
    # 2. Firewall targets.
    for t in [t for t in profile.targets if t.type != "panorama"]:
        did = f"t:{t.name}"
        access = getattr(t, "access", "auto") or "auto"
        sn = known_serial(t) if access != "direct" else None
        direct_facts = None
        if sn is None and access == "auto" and managed:
            try:  # first sighting: one read to learn the serial, nothing else on its own API
                sn0 = parse_sysinfo(factory(profile, t.name).op(CMD_SYSINFO)).get("serial")
                sn = sn0 if sn0 in managed else None
            except devmod.DeviceError:
                sn = None
        if sn is not None and sn not in claimed:
            pano_t, m = managed[sn]
            claimed.add(sn)
            f = through_panorama(pano_t, m, did, t.name, t.name,
                                 why=f"managed by Panorama {pano_t}; access {access}")
            add(did, f)
            continue
        if access == "panorama":
            f = {"kind": "firewall", "reachable": False, "warnings": [], "id": did, "name": t.name,
                 "errors": ["access: panorama is set, but no Panorama in this customer lists this firewall "
                            "(show devices all). Its own API is not used."],
                 "connect": {"target": t.name, "serial": None}, "managed_by": None, "profile_target": t.name,
                 "access_path": paths.via_panorama({}, why="access: panorama, Panorama not found")}
            f["identity"] = ident.cached(profile, t.name) or ident.make(source="not read")
            add(did, f)
            continue
        try:
            direct_facts = discover(factory(profile, t.name), kind=t.type, refresh=refresh)
        except devmod.DeviceError as exc:
            direct_facts = {"kind": t.type, "reachable": False, "errors": [str(exc)], "warnings": []}
        f = direct_facts
        f.update({"id": did, "name": t.name, "connect": {"target": t.name, "serial": None}, "managed_by": None,
                  "profile_target": t.name, "access_path": paths.direct(why=f"standalone firewall; access {access}")})
        if not f.get("reachable") and managed:
            f["errors"].append("If a Panorama in this customer manages this firewall, it is listed under that Panorama "
                               "and is upgraded through it.")
        f["identity"] = ident.from_facts(f) if f.get("reachable") else ident.make(source="device did not answer")
        ident.remember(profile, t.name, f["identity"])
        if f.get("serial") in managed:  # access: direct on a Panorama-managed firewall (override case)
            pano_t, m = managed[f["serial"]]
            claimed.add(f["serial"])
            f["managed_by"] = f"t:{pano_t}"
            f["device_groups"] = (snap["devices"][f"t:{pano_t}"].get("device_groups") or {}).get(f["serial"], [])
            f["access_path"] = paths.direct(why=f"access: direct, although Panorama {pano_t} manages it", managed_override=True)
        add(did, f)
    # 3. Firewalls only Panorama knows about.
    for sn, (pano_t, m) in managed.items():
        if sn in claimed or sn in by_serial:
            continue
        add(f"m:{pano_t}:{sn}", through_panorama(pano_t, m, f"m:{pano_t}:{sn}", m.get("hostname") or sn, None,
                                                   why=f"managed by Panorama {pano_t}"))
    # A profile firewall whose panorama-status points at a Panorama we do not know about.
    for did in snap["order"]:
        f = snap["devices"][did]
        ps = f.get("panorama_status") or {}
        if f.get("kind") == "firewall" and not f.get("managed_by") and ps.get("managed"):
            f["external_panorama"] = [s["address"] for s in ps.get("servers") or []]
    # HA peer ids
    for did in snap["order"]:
        f = snap["devices"][did]
        ps = (f.get("ha") or {}).get("peer_serial")
        if not ps:
            for p in snap["devices"].values():
                for m in p.get("managed") or []:
                    if m.get("serial") == f.get("serial") and m.get("ha_peer_serial"):
                        ps = m["ha_peer_serial"]
        f["ha_peer_id"] = by_serial.get(ps) if ps else None
    ref = load_reference()
    for did in snap["order"]:
        f = snap["devices"][did]
        if f.get("reachable") and f.get("sw_version"):
            av = [Available(**a) for a in f.get("available") or []]
            pano = snap["devices"].get(f.get("managed_by") or "", {})
            r = recommend(f["sw_version"], av, (ref.get("preferred") or {}).get(V(f["sw_version"]).train, []),
                          ceiling=pano.get("sw_version") if pano.get("reachable") else None)
            f["recommended"] = r.__dict__
    if save:
        _write(upgrade_dir(profile) / f"{snap['id']}.json", snap)
    return snap


def load_snapshot(profile: Profile, sid: str) -> dict:
    if not SNAP_RE.match(sid or ""):
        raise ValueError("bad discovery id")
    return json.loads((upgrade_dir(profile) / f"{sid}.json").read_text(encoding="utf-8"))


def list_snapshots(profile: Profile) -> list[str]:
    return sorted((p.stem for p in upgrade_dir(profile).glob("disc-*.json")), reverse=True)


# ---------------------------------------------------------------- plan

def _order(snap: dict, ids: list[str]) -> list[str]:
    devs = snap["devices"]
    panos = [i for i in ids if devs[i].get("kind") == "panorama"]
    fws = [i for i in ids if i not in panos]
    single = [i for i in fws if not (devs[i].get("ha") or {}).get("enabled")]
    ha = [i for i in fws if i not in single]
    seen: set[str] = set()
    pairs: list[str] = []

    def rank(i: str) -> int:  # passive / secondary first, active / primary last
        st = ((devs[i].get("ha") or {}).get("local_state") or "").lower()
        return 0 if "passive" in st or "secondary" in st or st in ("suspended", "non-functional") else 1
    for i in ha:
        if i in seen:
            continue
        peer = devs[i].get("ha_peer_id")
        grp = [i] + ([peer] if peer in ha and peer not in seen else [])
        seen.update(grp)
        pairs.extend(sorted(grp, key=rank))
    return panos + single + pairs


def _ha_role(f: dict) -> str:
    return ((f.get("ha") or {}).get("local_state") or "").lower()


def device_identity(f: dict) -> dict:
    """What the device reported about itself (hostname, serial), from the snapshot."""
    return f.get("identity") or ident.make(f.get("hostname"), f.get("serial"), model=f.get("model"),
                                           source="show system info", read_at=f.get("discovered_at"))


def build_steps(f: dict, did: str, path: list, *, duplicate_hostnames: frozenset[str] = frozenset()) -> list[dict]:
    pname = f.get("name") or did
    idn = device_identity(f)
    name = ident.label(pname, idn)  # every step title says what the device really is
    confirm_with = ident.confirm_word(idn, pname, duplicate_hostnames=duplicate_hostnames)
    ha = (f.get("ha") or {}).get("enabled")
    steps: list[dict] = []

    def add(action: str, title: str, explain: str, **kw):
        steps.append({"device": did, "device_name": pname, "device_label": name, "hostname": idn["hostname"],
                      "serial": idn["serial"], "confirm_with": confirm_with, "action": action, "title": title,
                      "explain": explain, "status": "pending", "path_mode": mode, "path_text": ptxt, **kw})
    mode, ptxt = paths.mode_of(f), paths.describe(f)
    viap = mode == paths.PANORAMA
    add("precheck", f"Pre-check {name}", "Re-runs discovery and stops if anything is red (version, HA sync, pending changes, "
        "disk, Panorama-first).")
    add("backup", f"Back up {name}",
        ("Exports the firewall's running config through Panorama, plus Panorama's own running config."
         if viap else "Exports the running config and the device state."))
    installs = [s for s in path if s.action == "install"]
    via = " through Panorama (Device Deployment > Dynamic Updates)" if viap else ""
    add("content", f"Update Apps/Threats content on {name}", "Installs the latest application and threat content" + via +
        ". New PAN-OS versions refuse to install on old content, and the latest content always meets the minimum.")
    for s in path:
        if s.action == "download":
            why = s.why
            if viap:  # the Panorama path always runs Panorama's (idempotent) batch download; it is quick when Panorama has the image
                why = why.replace("(already downloaded; this step will be skipped)",
                                  "(Panorama already holds this image, so the download job finishes quickly)")
            add("download", f"Download {s.version} on {name}",
                why + (" Panorama downloads the image to its own repository (Panorama > Device Deployment > Software)."
                         if viap else ""), version=s.version)
        else:
            if ha:
                add("ha-suspend", f"Suspend HA on {name}", "Puts this unit into suspended state so traffic stays on (or fails over "
                    "to) the peer while this unit installs and reboots.")
            add("install", f"Downgrade {name} to {s.version}" if s.downgrade else f"Install {s.version} on {name}",
                s.why + (" Panorama uploads the image to the firewall and installs it (request batch software upload-install)."
                         if viap else ""), version=s.version)
            add("reboot", f"Reboot {name}", ("Panorama reboots the firewall (request batch reboot) " if viap else "Reboots ") +
                "so the new version loads. Traffic through this device stops until it is back "
                "(unless the HA peer carries it).", version=s.version)
            add("wait", f"Wait for {name} to come back on {s.version}",
                ("Polls Panorama's managed-device list until the firewall is connected again on the new version "
                 if viap else "Polls the API until the device answers on the new version ") +
                "(typically 10 to 25 minutes).", version=s.version)
            if ha:
                add("ha-functional", f"Make {name} HA-functional", "Returns the unit to normal HA operation, then checks the peers sync.")
            if s is not installs[-1]:
                add("precheck", f"Re-check {name} before the next hop", "Stepping through a feature release; re-check before continuing.")
    add("postcheck", f"Post-check {name}", "Confirms the version, HA state and sync, Panorama connection, interfaces up, sessions "
        "and last commit, and compares with the pre-check.")
    return steps


def path_checks(profile: Profile, snap: dict, f: dict) -> list[Check]:
    """Green when a Panorama-managed firewall goes through Panorama; red (or yellow with the override) when it would not."""
    if f.get("kind") != "firewall":
        return []
    mode = paths.mode_of(f)
    if mode == paths.PANORAMA:
        pano = snap["devices"].get((f.get("access_path") or {}).get("via") or f.get("managed_by") or "", {})
        return [Check("access-path", GREEN, f"Upgrade path: {paths.describe(f)}",
                      f"Every step (backup, content, download, install, reboot, checks) is sent to Panorama "
                      f"{ident.label(pano.get('name') or '', pano.get('identity'))}; it shows in Panorama's Task Manager and logs. "
                      "The firewall's own API is not used.")]
    if not paths.is_managed_direct(f):
        return [Check("access-path", GREEN, "Upgrade path: direct (standalone firewall)",
                      "No Panorama manages this firewall, so the tool uses the firewall's own API.")]
    who = (snap["devices"].get(f.get("managed_by") or "", {}).get("name") or ", ".join(f.get("external_panorama") or []) or "a Panorama")
    if getattr(profile, "allow_direct_managed", False):
        return [Check("access-path", YELLOW, "Direct upgrade of a Panorama-managed firewall (override)",
                      f"{who} manages this firewall, but this customer allows direct access (allow_direct_managed, test or "
                      "emergency only). Panorama will not show these steps in its Task Manager. Arming and every step are "
                      "audited as a direct override.")]
    fix = ("Remove 'access: direct' from the profile target so it goes through Panorama." if f.get("managed_by") else
           "Add that Panorama to the customer profile so the upgrade can go through it.")
    return [Check("access-path", RED, "Panorama-managed firewall: direct upgrade refused",
                  f"{who} manages this firewall, so the upgrade must go through Panorama for audit and control. {fix}")]


def build_plan(profile: Profile, snap: dict, selections: dict[str, str], *, actor: str = "", save: bool = True) -> dict[str, Any]:
    """selections: device id -> target version. Returns the plan (dry-run)."""
    devs = snap["devices"]
    unknown = [i for i in selections if i not in devs]
    if unknown:
        raise ValueError(f"unknown devices: {', '.join(unknown)}")
    ids = _order(snap, [i for i in snap["order"] if i in selections])
    hosts = [device_identity(devs[i])["hostname"] for i in ids]
    dup_hosts = frozenset(h for h in hosts if h and hosts.count(h) > 1)
    ref = load_reference()
    plan: dict[str, Any] = {"id": f"upg-{_stamp()}-{secrets.token_hex(3)}", "customer": profile.name, "snapshot": snap["id"],
                            "created": now_iso(), "created_by": actor, "mode": "dry-run", "status": "planned", "cr": "",
                            "devices": [], "checks": [], "steps": [], "log": [], "reference_source": ref.get("source")}
    for did in ids:
        f = devs[did]
        tgt = (selections.get(did) or "").strip()
        path, perr, dl = [], [], []
        if f.get("reachable") and tgt:
            try:
                V(tgt)
                path, perr = upgrade_path(f["sw_version"], tgt, [Available(**a) for a in f.get("available") or []],
                                          allow_downgrade=f.get("kind") == "firewall")
                if f.get("kind") == "panorama" and is_downgrade(f["sw_version"], tgt):
                    path, perr = [], [f"{tgt} is older than the running {f['sw_version']}. Panorama is never downgraded from this wizard: "
                            "its database and every managed firewall depend on it. Use the Palo Alto downgrade guide with a "
                            "VM snapshot or a device-state backup."]
            except ValueError:
                perr = [f"{tgt!r} is not a PAN-OS version"]
            have = {a["version"] for a in f.get("available") or [] if a.get("downloaded")}
            dl = [s.version for s in path if s.action == "download" and s.version not in have]
        checks = device_checks(f, tgt or None, perr, dl, ref)
        # HA peer must be in the same plan
        if (f.get("ha") or {}).get("enabled"):
            peer = f.get("ha_peer_id")
            if not peer or peer not in selections:
                checks.append(Check("ha-peer", RED, "HA peer is not in this plan",
                                    "Upgrade both HA peers in the same window (passive first). Select the peer too"
                                    + ("" if peer else "; it was not found in this customer's devices") + "."))
            else:
                checks.append(Check("ha-peer", GREEN, "HA peer is in the plan", f"Order: {'this unit first' if 'passive' in _ha_role(f) else 'peer first'}."))
        if f.get("external_panorama"):
            checks.append(Check("panorama-first", YELLOW, "Managed by a Panorama outside this customer profile",
                                f"panorama-status shows {', '.join(f['external_panorama'])}. Confirm that Panorama runs {tgt or 'the target'} "
                                "or newer before you start."))
        checks.extend(path_checks(profile, snap, f))
        idn = device_identity(f)
        note = ident.missing_note(f.get("name") or did, idn)
        if note:
            checks.append(Check("identity", YELLOW, "Hostname unknown" if not idn["hostname"] else "Serial number unknown", note))
        else:
            checks.append(Check("identity", GREEN, f"Device reports {ident.hs(idn)}",
                                f"Read with {idn.get('source') or 'show system info'} at {idn.get('read_at') or '?'}."))
        entry = {"id": did, "name": f.get("name"), "kind": f.get("kind"), "hostname": idn["hostname"], "model": f.get("model"),
                 "serial": idn["serial"], "identity": idn, "label": ident.label(f.get("name") or did, idn),
                 "confirm_with": ident.confirm_word(idn, f.get("name") or did, duplicate_hostnames=dup_hosts),
                 "current": f.get("sw_version"), "target": tgt, "managed_by": f.get("managed_by"),
                 "ha": {k: (f.get("ha") or {}).get(k) for k in ("enabled", "local_state", "peer_state", "running_sync")},
                 "path": [s.__dict__ for s in path], "checks": [c.as_dict() for c in checks], "connect": f.get("connect"),
                 "device_groups": f.get("device_groups") or [], "profile_target": f.get("profile_target"),
                 "access_path": dict(f.get("access_path") or {}, mode=paths.mode_of(f)), "path_text": paths.describe(f)}
        plan["devices"].append(entry)
    # Panorama-first across the plan.
    for pid in [i for i in snap["order"] if devs[i].get("kind") == "panorama" and devs[i].get("reachable")]:
        pf = devs[pid]
        planned = pid in selections and not any(c["level"] == RED for d in plan["devices"] if d["id"] == pid for c in d["checks"])
        pver = selections[pid] if planned else pf.get("sw_version", "")
        fws = []
        for i in snap["order"]:
            f = devs[i]
            if f.get("managed_by") != pid:
                continue
            in_plan = i in selections
            fws.append((f.get("name") or i, selections[i] if in_plan else f.get("sw_version", ""), in_plan))
        for c in panorama_checks(pf.get("name") or pid, pver, planned, fws):
            dev_name = c.title.split(" ", 1)[0]
            target_entry = next((d for d in plan["devices"] if d["name"] == dev_name), None)
            (target_entry["checks"] if target_entry else plan["checks"]).append(c.as_dict())
        if pid in selections:
            pe = next(d for d in plan["devices"] if d["id"] == pid)
            for i in snap["order"]:
                f = devs[i]
                if f.get("managed_by") == pid and i not in selections and f.get("sw_version") and selections[pid]:
                    try:
                        if V(f["sw_version"]) > V(selections[pid]):
                            pe["checks"].append(Check("panorama-first", YELLOW, "Panorama target is still below a managed firewall",
                                                      f"{f.get('name')} runs {f['sw_version']}; pick a Panorama target at or above it.").as_dict())
                    except ValueError:
                        pass
    for d in plan["devices"]:
        d["status"] = worst(c["level"] for c in d["checks"])
        f = devs[d["id"]]
        if d["status"] != RED:
            plan["steps"].extend(build_steps(f, d["id"], _path_objs(d["path"]), duplicate_hostnames=dup_hosts))
    plan["status_light"] = worst([d["status"] for d in plan["devices"]] + [c["level"] for c in plan["checks"]])
    plan["blocked"] = plan["status_light"] == RED or not plan["devices"]
    for i, s in enumerate(plan["steps"], 1):
        s["n"] = i
    if save:
        save_plan(profile, plan)
    return plan


class _P:
    def __init__(self, d: dict):
        self.action, self.version, self.why = d["action"], d["version"], d["why"]
        self.downgrade = bool(d.get("downgrade"))


def _path_objs(path: list[dict]) -> list[_P]:
    return [_P(p) for p in path]


def save_plan(profile: Profile, plan: dict) -> None:
    _write(upgrade_dir(profile) / f"{plan['id']}.json", plan)


def load_plan(profile: Profile, pid: str) -> dict:
    if not PLAN_RE.match(pid or ""):
        raise ValueError("bad plan id")
    p = upgrade_dir(profile) / f"{pid}.json"
    if not p.is_file():
        raise FileNotFoundError(pid)
    return json.loads(p.read_text(encoding="utf-8"))


def list_plans(profile: Profile) -> list[str]:
    return sorted((p.stem for p in upgrade_dir(profile).glob("upg-*.json") if PLAN_RE.match(p.stem)), reverse=True)
