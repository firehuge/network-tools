"""Parse an offline PAN-OS config XML for validation and planning."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from panlab.addresses import ParsedAddress, parse_address_value

ZONE_TYPE_TAGS = ("virtual-wire", "layer3", "layer2", "tap", "tunnel", "external")


def zone_type_of(entry: ET.Element) -> str:
    network = entry.find("network")
    if network is None:
        return "unknown"
    for child in list(network):
        tag = child.tag.split("}", 1)[-1]
        if tag in ZONE_TYPE_TAGS:
            return tag
    return "unknown"




@dataclass
class ConfigAddress:
    name: str
    addr_type: str
    value: str
    parsed: ParsedAddress | None = None


@dataclass
class ConfigRule:
    name: str
    from_zones: list[str]
    to_zones: list[str]
    source: list[str]
    destination: list[str]
    applications: list[str]
    services: list[str]
    action: str
    description: str = ""
    disabled: bool = False


@dataclass
class ParsedConfig:
    vsys: str
    zones: list[str] = field(default_factory=list)
    zone_types: dict[str, str] = field(default_factory=dict)
    addresses: dict[str, ConfigAddress] = field(default_factory=dict)
    rules: list[ConfigRule] = field(default_factory=list)
    root: ET.Element | None = None


def load_config_root(source: Path | str | ET.Element) -> ET.Element:
    if isinstance(source, ET.Element):
        root = source
    else:
        tree = ET.parse(source)
        root = tree.getroot()
    if root.tag == "config":
        return root
    found = root.find(".//config")
    if found is not None:
        return found
    raise ValueError("No <config> element found in the XML")


def _text(element: ET.Element | None) -> str:
    if element is None or element.text is None:
        return ""
    return element.text.strip()


def _members(entry: ET.Element, path: str) -> list[str]:
    return [m.text.strip() for m in entry.findall(f"{path}/member") if m.text and m.text.strip()]


def _address_from_entry(entry: ET.Element) -> ConfigAddress:
    name = entry.get("name") or ""
    if (node := entry.find("ip-netmask")) is not None and _text(node):
        addr_type, value = "ip-netmask", _text(node)
    elif (node := entry.find("ip-range")) is not None and _text(node):
        addr_type, value = "ip-range", _text(node)
    elif (node := entry.find("fqdn")) is not None and _text(node):
        addr_type, value = "fqdn", _text(node)
    else:
        addr_type, value = "unknown", ""
    parsed: ParsedAddress | None = None
    if value and addr_type in {"ip-netmask", "ip-range", "fqdn"}:
        try:
            parsed = parse_address_value(value, addr_type)
        except ValueError:
            parsed = None
    return ConfigAddress(name=name, addr_type=addr_type, value=value, parsed=parsed)


def _rule_from_entry(entry: ET.Element) -> ConfigRule:
    disabled = _text(entry.find("disabled")).lower() in {"yes", "true"}
    return ConfigRule(
        name=entry.get("name") or "",
        from_zones=_members(entry, "from"),
        to_zones=_members(entry, "to"),
        source=_members(entry, "source"),
        destination=_members(entry, "destination"),
        applications=_members(entry, "application"),
        services=_members(entry, "service"),
        action=_text(entry.find("action")) or "allow",
        description=_text(entry.find("description")),
        disabled=disabled,
    )


def find_vsys(config: ET.Element, vsys_name: str) -> ET.Element:
    for entry in config.findall(".//vsys/entry"):
        if entry.get("name") == vsys_name:
            return entry
    available = [e.get("name") for e in config.findall(".//vsys/entry") if e.get("name")]
    raise ValueError(
        f"vsys {vsys_name!r} not found in config"
        + (f" (found: {', '.join(available)})" if available else "")
    )


def parse_config(source: Path | str | ET.Element, vsys_name: str = "vsys1") -> ParsedConfig:
    root = load_config_root(source)
    vsys = find_vsys(root, vsys_name)
    zone_entries = [e for e in vsys.findall("./zone/entry") if e.get("name")]
    zones = [e.get("name") or "" for e in zone_entries]
    zone_types = {e.get("name") or "": zone_type_of(e) for e in zone_entries}
    addresses = {}
    for entry in vsys.findall("./address/entry"):
        addr = _address_from_entry(entry)
        if addr.name:
            addresses[addr.name] = addr
    rules = [_rule_from_entry(e) for e in vsys.findall("./rulebase/security/rules/entry")]
    return ParsedConfig(
        vsys=vsys_name,
        zones=zones,
        zone_types=zone_types,
        addresses=addresses,
        rules=rules,
        root=root,
    )


def resolve_member(name: str, config: ParsedConfig | None) -> ParsedAddress | None:
    if name.lower() == "any":
        return parse_address_value("any")
    if config is not None and name in config.addresses:
        return config.addresses[name].parsed
    try:
        return parse_address_value(name, "ip-range" if "-" in name and "/" not in name else "ip-netmask")
    except ValueError:
        return None
