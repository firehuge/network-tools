# SPDX-License-Identifier: Apache-2.0
"""Port -> App-ID hints and app/port mismatch checks.

PAN-OS predefined App-IDs are not part of a config export, so this uses a
built-in table of common applications and their default ports, plus any
custom applications defined in the config (``custom`` argument: name ->
list of (proto, port)). Output is advisory flags only.
"""

from __future__ import annotations

from panlab.fcr import PortSpec

# app -> default (proto, port) list (PAN-OS application-default ports, common cases)
APP_PORTS: dict[str, list[tuple[str, str]]] = {
    "ssl": [("tcp", "443")], "web-browsing": [("tcp", "80")], "ssh": [("tcp", "22")],
    "ms-rdp": [("tcp", "3389")], "mssql-db": [("tcp", "1433")], "mssql-mon": [("udp", "1434")], "mysql": [("tcp", "3306")],
    "postgres": [("tcp", "5432")], "oracle": [("tcp", "1521")], "ldap": [("tcp", "389"), ("udp", "389")],
    "dns": [("udp", "53"), ("tcp", "53")], "ntp": [("udp", "123")], "snmp": [("udp", "161")], "snmp-trap": [("udp", "162")],
    "syslog": [("udp", "514"), ("tcp", "514")], "smtp": [("tcp", "25")], "ftp": [("tcp", "21")], "kerberos": [("tcp", "88"), ("udp", "88")],
    "ms-ds-smb": [("tcp", "445")], "vnc": [("tcp", "5900")], "radius": [("udp", "1812"), ("udp", "1813")], "telnet": [("tcp", "23")],
    "imap": [("tcp", "143")], "pop3": [("tcp", "110")], "tftp": [("udp", "69")], "http-proxy": [("tcp", "8080"), ("tcp", "3128")],
    "msrpc": [("tcp", "135")], "netbios-ns": [("udp", "137")], "ping": [], "icmp": [],
}
# predefined PAN-OS service objects
PREDEFINED_SERVICE_PORTS = {"service-https": [("tcp", "443")], "service-http": [("tcp", "80"), ("tcp", "8080")]}


def _covers(ps: PortSpec, proto: str, port: str) -> bool:
    return ps.proto in (proto, "any") and ps.port is not None and ps.covers(int(port))


def apps_for_port(ps: PortSpec, table: dict[str, list[tuple[str, str]]]) -> list[str]:
    if not ps.port or "-" in ps.port:
        return []
    return [a for a, ports in table.items() if any(ps.proto == p and ps.port == n for p, n in ports)]


def app_flags(services: list[PortSpec], apps: list[str], custom: dict[str, list[tuple[str, str]]] | None = None) -> list[dict]:
    table = {**APP_PORTS, **(custom or {})}
    out: list[dict] = []
    real = [ps for ps in services if ps.proto in ("tcp", "udp") and ps.port]
    for ps in real:
        for name, ports in PREDEFINED_SERVICE_PORTS.items():
            if any(ps.proto == p and ps.port == n for p, n in ports):
                extra = " (it also allows " + ", ".join(f"{p}/{n}" for p, n in ports if n != ps.port) + ")" if len(ports) > 1 else ""
                out.append({"level": "info", "code": "predefined-service",
                            "message": f"service: predefined service {name} already covers {ps.text}{extra}"
                                       + ("; it is reused, no new service object." if not extra else
                                          "; PAAT keeps an exact port object so nothing extra is opened.")})
    if not apps:
        for ps in real:
            hint = apps_for_port(ps, table)
            if hint:
                out.append({"level": "info", "code": "app-suggest",
                            "message": f"app: {ps.text} is normally App-ID {' or '.join(hint)}. Consider application "
                                       f"{hint[0]} with service application-default instead of a port-only rule "
                                       f"(tighter: only that application, only on its standard ports)."})
        return out
    for a in apps:
        a_l = a.lower()
        if a_l not in table:
            out.append({"level": "info", "code": "app-unknown",
                        "message": f"app: {a} is not in PAAT's built-in App-ID table; check the exact name in Objects > Applications "
                                   f"on the firewall before pushing."})
            continue
        defaults = table[a_l]
        if not defaults:
            continue
        if real and not any(_covers(ps, p, n) for ps in real for p, n in defaults):
            want = ", ".join(f"{p}/{n}" for p, n in defaults)
            got = ", ".join(ps.text for ps in real)
            out.append({"level": "yellow", "code": "app-port-mismatch",
                        "message": f"app: {a} normally uses {want}, but {got} was requested. Either the port is wrong, or the app "
                                   f"runs on a non-standard port (then keep the port service with app {a})."})
        elif real and all(any(_covers(ps, p, n) for p, n in defaults) for ps in real):
            out.append({"level": "info", "code": "app-default",
                        "message": f"app: {a} on its standard port(s); you can use service application-default instead of a port object."})
    return out
