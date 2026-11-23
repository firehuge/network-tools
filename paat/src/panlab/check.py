# SPDX-License-Identifier: Apache-2.0
"""Read-only connectivity test against the configured firewall."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from panlab.settings import Settings, connect, load_settings


@dataclass(frozen=True)
class SystemInfo:
    """Fields parsed from the operational `show system info` response."""

    hostname: str | None = None
    model: str | None = None
    version: str | None = None
    serial: str | None = None
    app_version: str | None = None
    threat_version: str | None = None
    multi_vsys: str | None = None
    ip_address: str | None = None


@dataclass(frozen=True)
class CheckResult:
    host: str
    auth: str
    hostname: str | None
    model: str | None
    version: str | None
    serial: str | None = None

    def to_text(self, *, show_serial: bool = False) -> str:
        lines = [
            f"Connected to {self.host} using {self.auth}.",
            f"  device hostname: {self.hostname or '(unknown)'}",
            f"  model:           {self.model or '(unknown)'}",
            f"  sw-version:      {self.version or '(unknown)'}",
        ]
        if show_serial:
            lines.append(f"  serial:          {self.serial or '(unknown)'}")
            lines.append(
                "Do not commit the serial, paste it into this repo, or put it in the setup log."
            )
        else:
            lines.append("  serial:          (omitted; pass --show-serial to print it locally)")
        return "\n".join(lines) + "\n"


def _text(element: ET.Element | None) -> str | None:
    if element is None or element.text is None:
        return None
    value = element.text.strip()
    return value or None


def _from_system_element(system: ET.Element) -> SystemInfo:
    return SystemInfo(
        hostname=_text(system.find("hostname")),
        model=_text(system.find("model")),
        version=_text(system.find("sw-version")),
        serial=_text(system.find("serial")),
        app_version=_text(system.find("app-version")),
        threat_version=_text(system.find("threat-version")),
        multi_vsys=_text(system.find("multi-vsys")),
        ip_address=_text(system.find("ip-address")),
    )


def _from_mapping(data: dict[str, Any]) -> SystemInfo:
    system = data
    if "system" in data and isinstance(data["system"], dict):
        system = data["system"]
    elif "response" in data and isinstance(data["response"], dict):
        result = data["response"].get("result") or {}
        if isinstance(result, dict) and isinstance(result.get("system"), dict):
            system = result["system"]
    return SystemInfo(
        hostname=_optional_str(system.get("hostname")),
        model=_optional_str(system.get("model")),
        version=_optional_str(system.get("sw-version") or system.get("version")),
        serial=_optional_str(system.get("serial")),
        app_version=_optional_str(system.get("app-version")),
        threat_version=_optional_str(system.get("threat-version")),
        multi_vsys=_optional_str(system.get("multi-vsys")),
        ip_address=_optional_str(system.get("ip-address")),
    )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_system_info(source: str | Path | ET.Element | dict[str, Any] | bytes) -> SystemInfo:
    """Parse hostname, model, and version from a `show system info` response.

    Accepts raw XML (string, bytes, path, or Element) or a nested dict such
    as the one returned by pan-os-python's ``show_system_info()``. This does
    not use ``Firewall.hostname`` (that is the API address) or
    ``Firewall.model`` (pan-os-python stores the model on ``platform``).
    """
    if isinstance(source, dict):
        return _from_mapping(source)
    if isinstance(source, Path):
        root = ET.parse(source).getroot()
    elif isinstance(source, bytes):
        root = ET.fromstring(source)
    elif isinstance(source, ET.Element):
        root = source
    elif isinstance(source, str):
        text = source.strip()
        if text.startswith("<"):
            root = ET.fromstring(source)
        else:
            root = ET.parse(text).getroot()
    else:
        raise TypeError(f"unsupported system-info source: {type(source)!r}")

    system = root if root.tag == "system" else root.find(".//system")
    if system is None:
        raise ValueError("no <system> element found in show system info response")
    return _from_system_element(system)


def fetch_system_info_xml(fw) -> str:
    """Return the raw XML from a read-only `show system info` operational command."""
    fw.xapi.op(cmd="show system info", cmd_xml=True)
    xml = fw.xapi.xml_document or fw.xapi.xml_result()
    if not xml:
        raise RuntimeError("device returned an empty show system info response")
    if isinstance(xml, bytes):
        xml = xml.decode("utf-8")
    text = str(xml).strip()
    if not text.startswith("<"):
        raise RuntimeError("show system info response did not look like XML")
    return text


def _auth_label(settings: Settings) -> str:
    if settings.uses_api_key:
        return "API key"
    return f"username {settings.username}"


def check_connection(
    settings: Settings | None = None,
    *,
    show_serial: bool = False,
) -> CheckResult:
    """Fetch system info. This is a read-only operational command; it does not change config."""
    settings = settings or load_settings()
    try:
        fw = connect(settings)
        xml = fetch_system_info_xml(fw)
        info = parse_system_info(xml)
    except Exception as exc:
        raise RuntimeError(settings.redacted(f"connection failed: {exc}")) from exc
    return CheckResult(
        host=settings.host,
        auth=_auth_label(settings),
        hostname=info.hostname,
        model=info.model,
        version=info.version,
        serial=info.serial if show_serial else None,
    )
