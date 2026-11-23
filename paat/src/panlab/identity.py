# SPDX-License-Identifier: Apache-2.0
"""What a device really is: the hostname and serial number it reports.

Profile target names (``pano-1``) are labels someone typed into a customer
profile. Before anyone changes a device, the tool shows what the device says
about itself (``show system info``: hostname and serial, or for a firewall
behind Panorama, Panorama's managed-device list) next to the profile name, so
nobody can say they did not know what they were touching.

Read-only. The last identity read for each device is cached per customer in
``<data>/<customer>/identity/identity.json`` (on the PAAT server, never in git)
so pages that do not talk to the device can still show it, with the time it
was read.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

TZ = ZoneInfo("America/Chicago")
CMD_SYSINFO = "<show><system><info></info></system></show>"
UNKNOWN_HOST = "hostname unknown"
UNKNOWN_SERIAL = "serial unknown"


def _now() -> str:
    return datetime.now(TZ).isoformat(timespec="seconds")


def make(hostname: str | None = None, serial: str | None = None, *, model: str | None = None, source: str = "",
         read_at: str | None = None) -> dict[str, Any]:
    return {"hostname": (hostname or "").strip(), "serial": (serial or "").strip(), "model": (model or "").strip(),
            "source": source, "read_at": read_at or _now()}


def from_facts(f: dict, source: str = "show system info") -> dict[str, Any]:
    return make(f.get("hostname"), f.get("serial"), model=f.get("model"), source=source,
                read_at=f.get("discovered_at"))


def from_sysinfo(resp: ET.Element | None) -> dict[str, Any]:
    """Parse a ``show system info`` response (``<response>`` or its ``<result>``/``<system>``)."""
    if resp is None:
        return make(source="show system info")
    s = resp.find(".//system")
    if s is None:
        s = resp

    def t(tag: str) -> str:
        x = s.find(tag)
        return (x.text or "").strip() if x is not None else ""
    return make(t("hostname"), t("serial"), model=t("model"), source="show system info")


def known(ident: dict | None) -> bool:
    return bool(ident and ident.get("hostname") and ident.get("serial"))


def hs(ident: dict | None) -> str:
    """``HOSTNAME · SN serial`` as the device reports it, with explicit unknowns instead of blanks."""
    ident = ident or {}
    return f"{ident.get('hostname') or UNKNOWN_HOST} · SN {ident.get('serial') or 'unknown'}"


def label(name: str, ident: dict | None) -> str:
    """Plain-text device name: what the device reports first, the profile target name last, in brackets.

    ``PANO-EXAMPLE · SN 0070... [pano-1]``. When the hostname could not be
    read, the profile name leads: ``pano-1 · hostname unknown · SN ...``.
    """
    ident = ident or {}
    if ident.get("hostname"):
        return f"{hs(ident)} [{name}]" if name and name != ident["hostname"] else hs(ident)
    return f"{name} · {hs(ident)}"


def html_label(name: str, ident: dict | None, *, note: bool = True) -> str:
    """HTML headline: **HOSTNAME** · SN serial, profile name in small grey; profile name + yellow box when unknown."""
    from html import escape as e

    ident = ident or {}
    h, sn = ident.get("hostname") or "", ident.get("serial") or ""
    sn_html = f"SN <code>{e(sn)}</code>" if sn else "<span style='color:#9a6700'>SN unknown</span>"
    if h:
        head = (f"<b>{e(h)}</b> · {sn_html}"
                + (f" <span style='color:#777;font-size:12px'>{e(name)}</span>" if name and name != h else ""))
    else:
        head = f"<b>{e(name)}</b> · <span style='color:#9a6700'><b>hostname unknown</b></span> · {sn_html}"
    miss = missing_note(name, ident) if note else ""
    return head + (f"<div style='border-left:4px solid #9a6700;padding:4px 8px;margin:6px 0;background:#fff8e1'>{e(miss)}</div>"
                   if miss else "")


def confirm_word(ident: dict | None, fallback: str, *, duplicate_hostnames: set[str] | frozenset[str] = frozenset()) -> str:
    """What an engineer must type to confirm a change on this device.

    The hostname the device reports. If the hostname is unknown or not unique
    in the plan (two factory-default ``PA-VM``s), the serial number instead. If
    neither is known, the profile name (and the page shows a yellow item).
    """
    ident = ident or {}
    h, s = ident.get("hostname") or "", ident.get("serial") or ""
    if h and h not in duplicate_hostnames:
        return h
    return s or h or fallback


def missing_note(name: str, ident: dict | None) -> str:
    """Plain-English yellow text when the hostname or serial could not be read, else ''."""
    ident = ident or {}
    miss = [w for w, k in (("hostname", "hostname"), ("serial number", "serial")) if not ident.get(k)]
    if not miss:
        return ""
    return (f"Could not read the {' and '.join(miss)} from {name}. Check on the device itself (Dashboard > General "
            "Information, or `show system info`) that it is the one you mean before you change anything.")


# ---------------------------------------------------------------- per-customer cache

def _path(profile) -> Path:
    return profile.data_dir("identity") / "identity.json"


def load(profile) -> dict[str, dict]:
    p = _path(profile)
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def remember(profile, key: str, ident: dict) -> None:
    """Cache what device ``key`` (a profile target name, or ``target/serial``) reported. Unknowns never overwrite a known read."""
    if not ident or not (ident.get("hostname") or ident.get("serial")):
        return
    data = load(profile)
    data[key] = ident
    p = _path(profile)
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    p.chmod(0o600)


def cached(profile, key: str) -> dict | None:
    return load(profile).get(key)


def read_push_device(dev: Any) -> dict[str, Any]:
    """Best-effort ``show system info`` through a panlab.pusher device (read-only). Unknowns on any failure."""
    try:
        op = getattr(dev, "op_xml", None) or getattr(dev, "_op", None)
        if op is None:
            fw = getattr(dev, "fw", None)
            if fw is None:
                return make(source="not readable")
            fw.xapi.op(cmd=CMD_SYSINFO)
            return from_sysinfo(fw.xapi.element_result)
        return from_sysinfo(op(CMD_SYSINFO))
    except Exception:  # noqa: BLE001 - identity is shown as unknown, never fatal for a read
        return make(source="show system info failed")
