# SPDX-License-Identifier: Apache-2.0
"""Parse and compare address literals used in rule requests."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

FQDN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
# IPv4, IPv6, CIDR, or an IPv4 range. Used to decide "this string is an IP, not an object name".
IPISH_RE = re.compile(r"^[\dA-Fa-f:.]+(?:/\d{1,3})?(?:\s*-\s*[\dA-Fa-f:.]+)?$")
OBJECT_NAME_RE = re.compile(r"^(any|[A-Za-z][A-Za-z0-9._-]{0,62})$")
RULE_NAME_RE = OBJECT_NAME_RE
ZONE_NAME_RE = re.compile(r"^(any|[A-Za-z][A-Za-z0-9._-]*)$")


@dataclass(frozen=True)
class ParsedAddress:
    """A resolved address used for overlap checks."""

    name: str
    kind: str  # ip-netmask, ip-range, fqdn, any, object, unresolved
    raw: str
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()


def looks_like_ip_literal(value: str) -> bool:
    return bool(IPISH_RE.match(value.strip()))


def parse_ip_range(value: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    if "-" not in value:
        raise ValueError(f"not an IP range: {value}")
    start_s, end_s = (part.strip() for part in value.split("-", 1))
    start = ipaddress.ip_address(start_s)
    end = ipaddress.ip_address(end_s)
    if type(start) is not type(end):
        raise ValueError(f"IP range family mismatch: {value}")
    if int(end) < int(start):
        raise ValueError(f"IP range end is before start: {value}")
    # Summarize the inclusive range into covering networks. Overlap checks
    # use these; a single span may become more than one CIDR.
    networks = tuple(ipaddress.summarize_address_range(start, end))
    if not networks:
        raise ValueError(f"empty IP range: {value}")
    return networks


def parse_netmask(value: str, *, strict: bool = False) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(value, strict=strict)


def host_bits_set(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=True)
        return False
    except ValueError:
        try:
            ipaddress.ip_network(value, strict=False)
            return "/" in value
        except ValueError:
            return False


def parse_address_value(value: str, addr_type: str = "ip-netmask") -> ParsedAddress:
    raw = value.strip()
    if raw.lower() == "any":
        return ParsedAddress(name="any", kind="any", raw=raw)
    if addr_type == "fqdn":
        if not FQDN_RE.match(raw) and raw.lower() not in {"localhost"}:
            raise ValueError(f"invalid FQDN: {value}")
        return ParsedAddress(name=raw, kind="fqdn", raw=raw)
    if addr_type == "ip-range":
        networks = parse_ip_range(raw)
        return ParsedAddress(name=raw, kind="ip-range", raw=raw, networks=networks)
    network = parse_netmask(raw, strict=False)
    return ParsedAddress(name=raw, kind="ip-netmask", raw=raw, networks=(network,))


def normalize_spec(spec: str | dict) -> dict:
    """Turn a string or object address spec into a uniform dict."""
    if isinstance(spec, str):
        text = spec.strip()
        if text.lower() == "any":
            return {"name": "any", "value": "any", "type": "any"}
        if looks_like_ip_literal(text):
            addr_type = "ip-range" if "-" in text and "/" not in text else "ip-netmask"
            return {"name": None, "value": text, "type": addr_type, "literal": True}
        return {"name": text, "value": None, "type": "object", "literal": False}
    if not isinstance(spec, dict):
        raise ValueError("address must be a string or object")
    name = spec.get("name")
    value = spec.get("value")
    addr_type = spec.get("type") or "ip-netmask"
    return {
        "name": name,
        "value": value,
        "type": addr_type,
        "description": spec.get("description"),
        "literal": False,
    }


def networks_overlap(left: ParsedAddress, right: ParsedAddress) -> bool | None:
    """Return True/False if comparable, or None if overlap cannot be determined."""
    if left.kind == "any" or right.kind == "any":
        return True
    if not left.networks or not right.networks:
        return None
    return any(a.overlaps(b) for a in left.networks for b in right.networks)
