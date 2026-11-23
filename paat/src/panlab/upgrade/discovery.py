"""Read-only discovery for OS upgrades.

Every probe is an operational *show/check/request info* command; nothing here
downloads, installs, reboots, or changes config. ``request system software
check`` only refreshes the version list from the update server. A failed
probe is recorded in ``errors`` and never stops the rest of discovery.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Callable
from zoneinfo import ZoneInfo

from panlab.upgrade.device import DeviceError, UpgradeDevice
from panlab.upgrade.messages import friendly
from panlab.upgrade.versions import Available, PanosVersion, parse_versions

TZ = ZoneInfo("America/Chicago")

CMD_SYSINFO = "<show><system><info></info></system></show>"
CMD_SW_CHECK = "<request><system><software><check></check></software></system></request>"
CMD_SW_INFO = "<request><system><software><info></info></software></system></request>"
CMD_HA = "<show><high-availability><state></state></high-availability></show>"
CMD_DISK = "<show><system><disk-space></disk-space></system></show>"
CMD_PANO_STATUS = "<show><panorama-status></panorama-status></show>"
CMD_PENDING = "<check><pending-changes></pending-changes></check>"
CMD_CONNECTED = "<show><devices><connected></connected></devices></show>"
CMD_DEVICES_ALL = "<show><devices><all></all></devices></show>"  # includes firewalls that are not connected now
# Panorama > Device Deployment > Software: the images Panorama can deploy to managed firewalls.
CMD_BATCH_SW_CHECK = "<request><batch><software><check></check></software></batch></request>"
CMD_BATCH_SW_INFO = "<request><batch><software><info></info></software></batch></request>"
CMD_DEVICEGROUPS = "<show><devicegroups></devicegroups></show>"
CMD_INTERFACES = "<show><interface>all</interface></show>"
CMD_SESSIONS = "<show><session><info></info></session></show>"
CMD_JOBS = "<show><jobs><all></all></jobs></show>"


def now_iso() -> str:
    return datetime.now(TZ).isoformat(timespec="seconds")


def _t(el: ET.Element | None, path: str, default: str = "") -> str:
    if el is None:
        return default
    x = el.find(path)
    return (x.text or "").strip() if x is not None and x.text else default


def _yes(s: str) -> bool | None:
    s = (s or "").strip().lower()
    return True if s == "yes" else False if s == "no" else None


def _result(resp: ET.Element) -> ET.Element:
    r = resp.find("result")
    return r if r is not None else resp


def _text(resp: ET.Element) -> str:
    r = _result(resp)
    return "".join(r.itertext())


# ---------------------------------------------------------------- parsers (pure)

def parse_sysinfo(resp: ET.Element) -> dict[str, Any]:
    s = _result(resp).find("system")
    if s is None:
        s = _result(resp)
    return {"hostname": _t(s, "hostname"), "model": _t(s, "model"), "family": _t(s, "family"),
            "serial": _t(s, "serial"), "sw_version": _t(s, "sw-version"), "app_version": _t(s, "app-version"),
            "threat_version": _t(s, "threat-version"), "av_version": _t(s, "av-version"),
            "multi_vsys": _t(s, "multi-vsys"), "uptime": _t(s, "uptime"), "operational_mode": _t(s, "operational-mode"),
            "system_mode": _t(s, "system-mode")}


def parse_software(resp: ET.Element) -> list[Available]:
    out = []
    for e in _result(resp).iter("entry"):
        ver = _t(e, "version")
        if not ver:
            continue
        size = _t(e, "size") or "0"
        try:
            size_mb = float(re.sub(r"[^\d.]", "", size) or 0)
        except ValueError:
            size_mb = 0.0
        if not size_mb and _t(e, "size-kb"):
            try:
                size_mb = float(_t(e, "size-kb")) / 1024
            except ValueError:
                pass
        out.append(Available(version=ver, downloaded=_yes(_t(e, "downloaded")) is True, current=_yes(_t(e, "current")) is True,
                             latest=_yes(_t(e, "latest")) is True, uploaded=_yes(_t(e, "uploaded")) is True, size_mb=size_mb,
                             released_on=_t(e, "released-on"), filename=_t(e, "filename")))
    return parse_versions(out)


def parse_software_meta(resp: ET.Element) -> dict[str, str]:
    sw = _result(resp).find("sw-updates")
    return {"msg": _t(sw, "msg"), "last_updated": sw.get("last-updated-at", "") if sw is not None else ""}


def parse_ha(resp: ET.Element) -> dict[str, Any]:
    r = _result(resp)
    enabled = _yes(_t(r, "enabled"))
    g = r.find("group")
    return {"enabled": bool(enabled), "mode": _t(g, "mode") or _t(g, "local-info/mode"),
            "local_state": _t(g, "local-info/state"), "peer_state": _t(g, "peer-info/state"),
            "peer_conn": _t(g, "peer-info/conn-status"), "peer_mgmt_ip": _t(g, "peer-info/mgmt-ip"),
            "peer_serial": _t(g, "peer-info/serial-num") or _t(g, "peer-info/serial"),
            "running_sync": _t(g, "running-sync"), "running_sync_enabled": _t(g, "running-sync-enabled"),
            "preemptive": _t(g, "local-info/preemptive"), "local_priority": _t(g, "local-info/priority")}


_SIZE = {"K": 1 / 1024, "M": 1, "G": 1024, "T": 1024 * 1024}


def _to_mb(s: str) -> float | None:
    m = re.match(r"^([\d.]+)([KMGT])?i?B?$", s.strip(), re.I)
    if not m:
        return None
    return float(m[1]) * _SIZE.get((m[2] or "M").upper(), 1)


def parse_disk(text: str) -> dict[str, Any]:
    mounts: dict[str, dict] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[-1].startswith("/") and parts[-2].endswith("%"):
            avail = _to_mb(parts[-3])
            mounts[parts[-1]] = {"size": parts[-5], "avail": parts[-3], "avail_mb": avail, "use": parts[-2]}
    repo = mounts.get("/opt/panrepo") or mounts.get("/opt/pancfg") or mounts.get("/")
    return {"mounts": mounts, "repo_mount": next((k for k in ("/opt/panrepo", "/opt/pancfg", "/") if k in mounts), ""),
            "repo_free_mb": repo["avail_mb"] if repo else None}


def parse_panorama_status(text: str) -> dict[str, Any]:
    servers = []
    cur: dict | None = None
    for line in text.splitlines():
        m = re.match(r"\s*Panorama Server (\d+)\s*:\s*(\S*)", line)
        if m:
            cur = {"n": int(m[1]), "address": m[2], "connected": None}
            servers.append(cur)
            continue
        m = re.match(r"\s*Connected\s*:\s*(\w+)", line)
        if m and cur is not None:
            cur["connected"] = m[1].lower() == "yes"
    configured = [s for s in servers if s["address"]]
    return {"servers": configured, "managed": bool(configured),
            "connected": any(s["connected"] for s in configured) if configured else None}


def parse_connected(resp: ET.Element) -> list[dict[str, Any]]:
    out = []
    devs = _result(resp).find("devices")
    for e in (devs.findall("entry") if devs is not None else []):
        serial = _t(e, "serial") or e.get("name", "")
        out.append({"serial": serial, "hostname": _t(e, "hostname"), "model": _t(e, "model"),
                    "sw_version": _t(e, "sw-version"), "app_version": _t(e, "app-version"),
                    "connected": _yes(_t(e, "connected")) is not False,
                    "ha_state": _t(e, "ha/state"), "ha_peer_serial": _t(e, "ha/peer/serial"),
                    "multi_vsys": _t(e, "multi-vsys"), "ip": _t(e, "ip-address"), "family": _t(e, "family"),
                    "threat_version": _t(e, "threat-version"), "av_version": _t(e, "av-version"),
                    # Panorama's view of policy/template sync for this firewall, when it reports it.
                    "sync": {k: _t(e, k) for k in SYNC_FIELDS if _t(e, k)}})
    return out


SYNC_FIELDS = ("shared-policy-status", "template-status", "device-group-sync-status", "template-sync-status")


def sync_for_serial(resp: ET.Element, serial: str) -> list[tuple[str, str, str]]:
    """``show devicegroups`` / ``show templates``: (container, field, status) for this firewall's own entries.

    ``show devices all`` leaves the policy status empty on some Panorama builds; the device group and template
    views carry ``shared-policy-status`` / ``template-status`` ("In Sync", "Out of Sync", "Never pushed" ...).
    """
    out = []
    for cont in _result(resp).iter("entry"):
        devs = cont.find("devices")
        if devs is None:
            continue
        for d in devs.findall("entry"):
            if (d.get("name") or _t(d, "serial")) != serial:
                continue
            for k in SYNC_FIELDS:
                v = _t(d, k)
                if v:
                    out.append((cont.get("name") or "?", k, v))
    return out


def parse_batch_software(resp: ET.Element) -> list[dict[str, Any]]:
    """Panorama ``request batch software info/check``: one row per image (every platform), not de-duplicated."""
    out = []
    for e in _result(resp).iter("entry"):
        ver, fn = _t(e, "version"), _t(e, "filename")
        if not ver:
            continue
        size = _t(e, "size") or "0"
        try:
            size_mb = float(re.sub(r"[^\d.]", "", size) or 0)
        except ValueError:
            size_mb = 0.0
        out.append({"version": ver, "filename": fn, "downloaded": _yes(_t(e, "downloaded")) is True,
                    "size_mb": size_mb, "released_on": _t(e, "released-on"), "platform": _t(e, "platform")})
    return out


def batch_available_for(rows: list[dict[str, Any]], family: str, current: str | None) -> list[Available]:
    """Images Panorama offers for one firewall platform family (``PanOS_<family>-<version>``)."""
    fam = (family or "").strip()
    pref = f"panos_{fam.lower()}-" if fam else ""
    out = []
    for r in rows:
        fn = (r.get("filename") or "").lower()
        plat = (r.get("platform") or "").lower()
        if not fam or not (fn.startswith(pref) or (plat and plat == fam.lower())):
            continue
        out.append(Available(version=r["version"], downloaded=bool(r.get("downloaded")), current=r["version"] == current,
                             size_mb=r.get("size_mb") or 0.0, released_on=r.get("released_on") or "", filename=r.get("filename") or ""))
    return parse_versions(out)


def parse_devicegroups(resp: ET.Element) -> dict[str, list[str]]:
    """serial -> device groups it belongs to (from Panorama ``show devicegroups``)."""
    out: dict[str, list[str]] = {}
    dgs = _result(resp).find("devicegroups")
    for g in (dgs.findall("entry") if dgs is not None else []):
        for d in g.findall("devices/entry"):
            sn = _t(d, "serial") or d.get("name", "")
            if sn:
                out.setdefault(sn, []).append(g.get("name", ""))
    return out


def parse_interfaces(resp: ET.Element) -> dict[str, Any]:
    hw = _result(resp).find("hw")
    ents = hw.findall("entry") if hw is not None else []
    up = sorted(_t(e, "name") for e in ents if _t(e, "state").lower() == "up")
    return {"total": len(ents), "up": len(up), "up_names": up}


def parse_sessions(resp: ET.Element) -> dict[str, Any]:
    r = _result(resp)
    return {"active": _t(r, "num-active"), "max": _t(r, "num-max")}


def parse_last_commit(resp: ET.Element) -> dict[str, Any]:
    best = None
    for j in _result(resp).iter("job"):
        if _t(j, "type").lower() not in ("commit", "commitall", "autocom"):
            continue
        jid = int(_t(j, "id") or 0)
        if best is None or jid > best["id"]:
            best = {"id": jid, "type": _t(j, "type"), "status": _t(j, "status"), "result": _t(j, "result"),
                    "when": _t(j, "tfin") or _t(j, "tenq")}
    return best or {}


def parse_content(resp: ET.Element) -> list[dict[str, Any]]:
    out = []
    for e in _result(resp).iter("entry"):
        if not _t(e, "version"):
            continue
        out.append({"version": _t(e, "version"), "filename": _t(e, "filename"), "downloaded": _yes(_t(e, "downloaded")) is True,
                    "current": _yes(_t(e, "current")) is True, "features": _t(e, "features"), "released_on": _t(e, "released-on")})
    out.sort(key=lambda c: tuple(int(x) for x in re.findall(r"\d+", c["version"])[:2] or [0]), reverse=True)
    return out


def parse_job(resp: ET.Element) -> dict[str, Any]:
    j = _result(resp).find("job")
    if j is None:
        return {"status": "", "result": "", "progress": "", "details": ""}
    details = " ".join(x.strip() for x in (j.find("details").itertext() if j.find("details") is not None else []) if x.strip())
    prog = _t(j, "progress")
    if _t(j, "status").upper() == "FIN" or not prog.isdigit():  # PAN-OS puts the finish time here once done
        prog = "100" if _t(j, "status").upper() == "FIN" else ""
    return {"id": _t(j, "id"), "status": _t(j, "status"), "result": _t(j, "result"), "progress": prog,
            "details": details[:1000]}


def job_id(resp: ET.Element) -> str:
    r = _result(resp)
    j = r.find("job")
    if j is not None and (j.text or "").strip():
        return j.text.strip()
    m = re.search(r"jobid\s+(\d+)", "".join(r.itertext()), re.I)
    return m[1] if m else ""


# ---------------------------------------------------------------- discovery

def _probe(errors: list[str], what: str, fn: Callable[[], Any], default: Any = None) -> Any:
    try:
        return fn()
    except DeviceError as exc:
        errors.append(f"{what}: {exc}")
    except Exception as exc:  # noqa: BLE001 - parser surprises are recorded, not fatal
        errors.append(f"{what}: {type(exc).__name__}: {exc}")
    return default


def discover(dev: UpgradeDevice, *, kind: str, refresh: bool = True, deep: bool = True) -> dict[str, Any]:
    """Facts about one device. ``kind`` is firewall or panorama. Read-only."""
    errors: list[str] = []
    warnings: list[str] = []
    facts: dict[str, Any] = {"label": dev.label, "kind": kind, "discovered_at": now_iso(), "errors": errors, "warnings": warnings}
    info = _probe(errors, "show system info", lambda: parse_sysinfo(dev.op(CMD_SYSINFO)))
    facts["reachable"] = info is not None
    if info is None:
        return facts
    facts.update(info)
    avail = None
    if refresh:
        try:
            resp = dev.op(CMD_SW_CHECK)
            avail = parse_software(resp)
            facts["software_source"] = "check"
            meta = parse_software_meta(resp)
            facts["software_msg"], facts["software_list_updated"] = meta["msg"], meta["last_updated"]
            hint = friendly(meta["msg"])
            if hint:
                facts["can_download"] = False
                warnings.append(f"{hint} (update server said: {meta['msg'].strip()}). Only images already on the device "
                                "can be installed.")
        except DeviceError as exc:
            hint = friendly(str(exc))
            if hint:
                facts["can_download"] = False
            warnings.append((hint + " " if hint else "") + f"Could not refresh the version list from the update server ({exc}); "
                            "showing the list the device already has.")
    if avail is None:
        avail = _probe(errors, "request system software info", lambda: parse_software(dev.op(CMD_SW_INFO)), [])
        facts["software_source"] = "info"
    facts["available"] = [a.__dict__ for a in avail]
    facts["ha"] = _probe(errors, "show high-availability state", lambda: parse_ha(dev.op(CMD_HA)),
                         {"enabled": False, "unknown": True})
    facts["disk"] = _probe(errors, "show system disk-space", lambda: parse_disk(_text(dev.op(CMD_DISK))), {})
    pend = _probe(errors, "check pending-changes", lambda: _text(dev.op(CMD_PENDING)).strip().lower())
    facts["pending_changes"] = None if pend is None else pend == "yes"
    if kind == "firewall":
        facts["panorama_status"] = _probe(errors, "show panorama-status",
                                          lambda: parse_panorama_status(_text(dev.op(CMD_PANO_STATUS))), {})
        if deep:
            facts["interfaces"] = _probe(errors, "show interface all", lambda: parse_interfaces(dev.op(CMD_INTERFACES)), {})
            facts["sessions"] = _probe(errors, "show session info", lambda: parse_sessions(dev.op(CMD_SESSIONS)), {})
    else:
        try:  # 'all' also lists firewalls Panorama manages that are disconnected right now
            facts["managed"] = parse_connected(dev.op(CMD_DEVICES_ALL))
        except DeviceError:
            facts["managed"] = _probe(errors, "show devices connected", lambda: parse_connected(dev.op(CMD_CONNECTED)), [])
        # Images Panorama can deploy to its firewalls (the Panorama-managed upgrade path reads this list).
        facts["device_software"], last = [], None
        for cmd, src in ([(CMD_BATCH_SW_CHECK, "check")] if refresh else []) + [(CMD_BATCH_SW_INFO, "info")]:
            try:
                facts["device_software"] = parse_batch_software(dev.op(cmd))
                facts["device_software_source"] = f"request batch software {src}"
                last = None
                break
            except DeviceError as exc:
                last = exc
        if last is not None:
            warnings.append(f"Panorama did not list device software images (request batch software): {last}")
        try:  # only used to scope users to device groups; never an error if it is not available
            facts["device_groups"] = parse_devicegroups(dev.op(CMD_DEVICEGROUPS))
        except Exception:  # noqa: BLE001
            facts["device_groups"] = {}
    if deep:
        facts["last_commit"] = _probe(errors, "show jobs all", lambda: parse_last_commit(dev.op(CMD_JOBS)), {})
    v = PanosVersion.try_parse(facts.get("sw_version"))
    facts["train"] = v.train if v else ""
    return facts
