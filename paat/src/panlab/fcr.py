# SPDX-License-Identifier: Apache-2.0
"""Import the customer's Firewall Change Request (FCR) spreadsheet as-is.

Layout (templates/customer-rule-request-form.xlsx): sheet 'Firewall Rules',
a 'Project' cell near the top, header row 3, one rule per row:
Source Address / AD group, Source DNS, Destination address, Destination
DNS, Protocol (blank = TCP), Port(s), Firewall (optional), Notes,
Application. Headers are matched by keyword, so small wording changes do
not break the import. Several files can be imported at once; each file
carries its own ticket numbers (RITM / SCTASK / CR).

If the standard template is not found, every sheet is scanned (first ~30
rows) and columns are matched by synonym (src/dst/service, and so on).
.csv is accepted; Excel 97-2003 .xls is not (save as .xlsx or .csv).
"""

from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any

SHEET = "Firewall Rules"
COLUMNS = {  # key -> header keywords (all must appear, lower-case)
    "source": ("source", "address"),
    "source_dns": ("source", "dns"),
    "destination": ("destination", "address"),
    "destination_dns": ("destination", "dns"),
    "protocol": ("protocol",),
    "ports": ("port",),
    "firewall": ("firewall",),
    "notes": ("notes",),
    "application": ("application",),
}
SPLIT_RE = re.compile(r"[,;\n\r]+|\s{2,}")
FQDN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+\.?$")

# Flexible (non-template) header synonyms, already canonicalized.
SOURCE_SYNS = (
    "source address", "source network", "source host", "source ip",
    "source", "src", "from", "origin",
)
DEST_SYNS = (
    "destination address", "dest address", "destination ip", "dest ip",
    "destination", "dest", "dst", "target", "to",
)
# Rank: lower is preferred when several port-like headers exist.
PORT_SYNS = (
    ("destination port", 0),
    ("dest port", 0),
    ("dst port", 0),
    ("tcp udp ports", 1),
    ("tcp udp port", 1),
    ("ports", 1),
    ("port", 1),
    ("services", 2),
    ("service", 2),
)
PROTO_SYNS = ("protocol", "proto", "transport")
APP_SYNS = ("application", "applications", "app", "apps")
NOTES_SYNS = ("notes", "note")
ADDR_FORBID = frozenset({
    "dns", "port", "ports", "zone", "user", "users", "interface", "nat",
    "proto", "protocol", "service", "services", "app", "application", "apps",
})
FLEX_HEADER_ROWS = 30
_PORT_TOKEN_RE = re.compile(
    r"(?:(?P<p1>tcp|udp)\s*[/:]?\s*)?"
    r"(?P<lo>\d{1,5})(?:\s*[-:]\s*(?P<hi>\d{1,5}))?"
    r"(?:\s*[/:]?\s*(?P<p2>tcp|udp))?",
    re.I,
)
_ANY_TOKEN_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(any|all|\*)(?![A-Za-z0-9])")
_XLS_MSG = "Excel 97-2003 .xls is not supported; save as .xlsx or .csv and upload again"
_LOOKING_FOR = (
    "source (source, src, source ip, source address, source network, source host, from, origin); "
    "destination (destination, dest, dst, destination ip, dest address, target, to); "
    "ports (port, ports, dst port, destination port, service, services, port(s), tcp/udp port)"
)


@dataclass
class Flag:
    level: str  # red | yellow | info
    code: str
    message: str


@dataclass
class Endpoint:
    kind: str  # ip | range | fqdn | user | any
    value: str
    dns: str | None = None

    @property
    def placeable(self) -> bool:
        return self.kind in ("ip", "range")


@dataclass
class PortSpec:
    proto: str  # tcp | udp | icmp | any
    port: str | None  # "443" | "50000-59999" | None

    @property
    def text(self) -> str:
        return f"{self.proto}/{self.port}" if self.port else self.proto

    def covers(self, p: int) -> bool:
        if not self.port:
            return self.proto == "any"
        lo, _, hi = self.port.partition("-")
        return int(lo) <= p <= int(hi or lo)


@dataclass
class Tickets:
    ritm: list[str] = field(default_factory=list)
    sctask: list[str] = field(default_factory=list)
    cr: list[str] = field(default_factory=list)

    def all(self) -> list[str]:
        return self.ritm + self.sctask + self.cr

    def label(self) -> str:
        return " / ".join(self.all())

    def merge(self, other: "Tickets") -> None:
        for k in ("ritm", "sctask", "cr"):
            cur = getattr(self, k)
            for t in getattr(other, k):
                if t not in cur:
                    cur.append(t)


@dataclass
class RuleRequest:
    file: str
    row: int
    project: str
    sources: list[Endpoint]
    destinations: list[Endpoint]
    services: list[PortSpec]
    applications: list[str]
    firewall: str | None
    notes: str
    tickets: Tickets
    requester: str = ""
    flags: list[Flag] = field(default_factory=list)
    origins: list[str] = field(default_factory=list)  # file:row of every merged duplicate

    def key(self) -> tuple:
        return (tuple(sorted((e.kind, e.value) for e in self.sources)),
                tuple(sorted((e.kind, e.value) for e in self.destinations)),
                tuple(sorted(p.text for p in self.services)),
                tuple(sorted(a.lower() for a in self.applications)))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class _Sheet:
    name: str
    rows: list[list[Any]]  # 0-indexed values, as openpyxl would return them

    @property
    def max_row(self) -> int:
        return len(self.rows)

    @property
    def max_column(self) -> int:
        return max((len(r) for r in self.rows), default=0)

    def cell(self, r: int, c: int) -> Any:
        if 1 <= r <= len(self.rows) and 1 <= c <= len(self.rows[r - 1]):
            return self.rows[r - 1][c - 1]
        return None


@dataclass
class _Layout:
    sheet: _Sheet
    header_row: int
    cols: dict[str, int]
    headers: dict[str, str]
    project: str
    standard_template: bool
    mapping_notes: list[str] = field(default_factory=list)
    source_port_col: int | None = None
    source_port_header: str = ""
    # Best incomplete attempt, used only when no layout can be picked.
    score: int = 0
    seen_headers: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ parsing
def split_cell(value: Any) -> list[str]:
    if value is None:
        return []
    return [p.strip() for p in SPLIT_RE.split(str(value)) if p and p.strip()]


def _extract_port_tokens(part: str) -> tuple[list[tuple[str | None, str]], list[str]]:
    """Pull (inline_proto_or_None, port_or_'any') and leftover tokens from one cell part."""
    s = part.strip()
    used = [False] * len(s)

    def _mark(a: int, b: int) -> bool:
        if any(used[i] for i in range(a, b)):
            return False
        for i in range(a, b):
            used[i] = True
        return True

    raw: list[tuple[str | None, str, int, int, str]] = []
    for m in _ANY_TOKEN_RE.finditer(s):
        if _mark(m.start(), m.end()):
            raw.append((None, "any", 0, 0, m.group(0)))
    for m in _PORT_TOKEN_RE.finditer(s):
        if not _mark(m.start(), m.end()):
            continue
        proto = (m.group("p1") or m.group("p2") or "").lower() or None
        lo, hi = int(m.group("lo")), int(m.group("hi") or m.group("lo"))
        raw.append((proto, str(lo) if lo == hi else f"{lo}-{hi}", lo, hi, m.group(0)))
    tokens: list[tuple[str | None, str]] = []
    leftovers: list[str] = []
    for proto, port, lo, hi, orig in raw:
        if port == "any":
            tokens.append((proto, "any"))
            continue
        if not (0 < lo <= 65535 and 0 < hi <= 65535) or hi < lo:
            leftovers.append(f"__range__:{orig.strip()}")
            continue
        tokens.append((proto, port))
    leftover = "".join(ch if not used[i] else " " for i, ch in enumerate(s))
    for tok in leftover.split():
        t = tok.strip().lower().rstrip(".")
        if t in {"and", "or", "of", "&", "+", "/", ":", "-", ","}:
            continue
        if t:
            leftovers.append(t)
    return tokens, leftovers


def parse_ports(value: Any, protocol: Any) -> tuple[list[PortSpec], list[Flag]]:
    """'80,443' / '80;443' / '50000-59999' / '1000:2000' / 'tcp/443' / '443/tcp' / 'TCP 443'.

    Blank protocol column = TCP, unless a protocol is written next to the port.
    """
    flags: list[Flag] = []
    protos_raw = [p.lower() for p in re.split(r"[\s,;/&+]+|\band\b", str(protocol or "")) if p.strip()]
    column_protos: list[str] = []
    for p in protos_raw:
        if p in ("tcp", "udp", "icmp", "any", "ip"):
            column_protos.append("any" if p == "ip" else p)
        elif p in ("both",):
            column_protos += ["tcp", "udp"]
        else:
            flags.append(Flag("yellow", "unknown-protocol", f"protocol '{p}' not understood; treated as TCP"))
    column_was_blank = protocol in (None, "")

    extracted: list[tuple[str | None, str]] = []
    for part in split_cell(value):
        tokens, leftovers = _extract_port_tokens(part)
        extracted.extend(tokens)
        for tok in leftovers:
            if tok.startswith("__range__:"):
                flags.append(Flag("yellow", "bad-port", f"port '{tok.split(':', 1)[1]}' out of range"))
            else:
                flags.append(Flag("yellow", "bad-port", f"port '{tok}' not understood"))

    ports: list[tuple[str | None, str]] = extracted
    if not column_was_blank:
        protos = column_protos or ["tcp"]
        port_values = [p for _, p in ports]
        return _port_specs(protos, port_values, flags)

    # Infer protocol from the port cell when the protocol column is blank.
    if any(inline for inline, _ in ports):
        out: list[PortSpec] = []
        needed_default = False
        for inline, port in ports:
            proto = inline or "tcp"
            if inline is None:
                needed_default = True
            if proto == "icmp":
                if not any(s.proto == "icmp" and s.port is None for s in out):
                    out.append(PortSpec("icmp", None))
                continue
            if proto == "any" or port == "any":
                out.append(PortSpec(proto if proto != "any" else "any", None))
                flags.append(Flag("red", "any-port", f"{proto}: any port requested"))
                continue
            if not any(s.proto == proto and s.port == port for s in out):
                out.append(PortSpec(proto, port))
        if needed_default:
            flags.append(Flag("info", "protocol-default", "protocol blank; treated as TCP (form instructions)"))
        if not ports:
            flags.append(Flag("yellow", "no-port", "tcp: no destination port given"))
        return out, flags

    protos = ["tcp"]
    flags.append(Flag("info", "protocol-default", "protocol blank; treated as TCP (form instructions)"))
    return _port_specs(protos, [p for _, p in ports], flags)


def _port_specs(protos: list[str], ports: list[str], flags: list[Flag]) -> tuple[list[PortSpec], list[Flag]]:
    out: list[PortSpec] = []
    for proto in dict.fromkeys(protos):
        if proto == "icmp":
            out.append(PortSpec("icmp", None))
            continue
        if proto == "any" or "any" in ports:
            out.append(PortSpec(proto if proto != "any" else "any", None))
            flags.append(Flag("red", "any-port", f"{proto}: any port requested"))
            continue
        if not ports:
            flags.append(Flag("yellow", "no-port", f"{proto}: no destination port given"))
        for p in dict.fromkeys(ports):
            out.append(PortSpec(proto, p))
    return out, flags


def parse_endpoints(addr_cell: Any, dns_cell: Any, side: str) -> tuple[list[Endpoint], list[Flag]]:
    flags: list[Flag] = []
    out: list[Endpoint] = []
    addrs, dnss = split_cell(addr_cell), split_cell(dns_cell)
    for i, a in enumerate(addrs):
        dns = dnss[i] if i < len(dnss) and len(dnss) == len(addrs) else None
        a2 = re.sub(r"\s*/\s*", "/", a)
        if a2.lower() in ("any", "all", "0.0.0.0/0", "*"):
            out.append(Endpoint("any", "any"))
            flags.append(Flag("red", "any-address", f"{side} is any"))
            continue
        try:
            net = ipaddress.IPv4Network(a2, strict=False)
            if "/" in a2 and net.network_address != ipaddress.IPv4Address(a2.split("/")[0]):
                flags.append(Flag("yellow", "host-bits", f"{side} {a2} has host bits set; using {net}"))
            out.append(Endpoint("ip", str(net) if net.prefixlen < 32 else str(net.network_address), dns))
            continue
        except ValueError:
            pass
        m = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)", a2)
        if m:
            try:
                ok = ipaddress.IPv4Address(m.group(1)) <= ipaddress.IPv4Address(m.group(2))
            except ValueError:
                ok = False
            if ok:
                out.append(Endpoint("range", f"{m.group(1)}-{m.group(2)}", dns))
            else:
                flags.append(Flag("red", "bad-address", f"{side} range '{a2}' is invalid or reversed"))
            continue
        if FQDN_RE.match(a2) and not re.fullmatch(r"[\d.]+", a2):
            out.append(Endpoint("fqdn", a2.rstrip(".").lower()))
            flags.append(Flag("yellow", "fqdn-no-ip", f"{side} {a2} is a DNS name with no IP: FQDN object, resolve to place"))
            continue
        if side == "source":
            out.append(Endpoint("user", a))
            flags.append(Flag("yellow", "ad-group", f"source '{a}' looks like an AD group: needs User-ID (source-user), not an address object"))
        else:
            flags.append(Flag("red", "bad-address", f"{side} '{a}' is not an IP, CIDR, range, or DNS name"))
    if not addrs:
        for d in dnss:
            out.append(Endpoint("fqdn", d.rstrip(".").lower()))
            flags.append(Flag("yellow", "fqdn-no-ip", f"{side} {d} given only as a DNS name: FQDN object, resolve to place"))
    if not out:
        flags.append(Flag("red", "missing-" + side, f"{side} is empty"))
    return out, flags


def find_tickets(texts: list[str], patterns: dict[str, str]) -> Tickets:
    t = Tickets()
    for k in ("ritm", "sctask", "cr"):
        rx = re.compile(r"(?<![A-Za-z])" + patterns[k] + r"(?!\d)", re.I)
        for s in texts:
            for m in rx.finditer(s or ""):
                v = m.group(0).upper()
                if v not in getattr(t, k):
                    getattr(t, k).append(v)
    return t


def _norm(h: Any) -> str:
    return re.sub(r"\s+", " ", str(h or "")).strip().lower()


def _canon(h: Any) -> str:
    s = str(h or "").strip().lower()
    s = re.sub(r"\(\s*s\s*\)", "s", s)
    s = re.sub(r"[^\w]+", " ", s, flags=re.UNICODE)
    return re.sub(r"\s+", " ", s).strip()


def _header_text(h: Any) -> str:
    return re.sub(r"\s+", " ", str(h or "")).strip()


def _phrase_in(canon: str, phrase: str) -> bool:
    ct, pt = canon.split(), phrase.split()
    if not pt:
        return False
    for i in range(len(ct) - len(pt) + 1):
        if ct[i:i + len(pt)] == pt:
            return True
    return False


def _matches_syn(canon: str, synonyms: tuple[str, ...] | list[str], forbid: frozenset[str] = frozenset()) -> bool:
    if not canon:
        return False
    tokens = set(canon.split())
    if tokens & forbid:
        return False
    for syn in sorted(synonyms, key=lambda s: -len(s.split())):
        if _phrase_in(canon, syn):
            return True
    return False


def _is_source_port_header(canon: str) -> bool:
    tokens = set(canon.split())
    return (("source" in tokens) or ("src" in tokens)) and (("port" in tokens) or ("ports" in tokens))


# ------------------------------------------------------------------ loaders
def _load_xlsx(path: Path) -> list[_Sheet]:
    import openpyxl

    wb = openpyxl.load_workbook(path, data_only=True, read_only=False)
    try:
        sheets: list[_Sheet] = []
        for name in wb.sheetnames:
            ws = wb[name]
            max_r, max_c = ws.max_row or 0, ws.max_column or 0
            rows = [[ws.cell(r, c).value for c in range(1, max_c + 1)] for r in range(1, max_r + 1)]
            sheets.append(_Sheet(name=name, rows=rows))
        return sheets
    finally:
        wb.close()


def _load_csv(path: Path) -> list[_Sheet]:
    raw = path.read_bytes()
    text = None
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        raise ValueError(f"{path.name}: could not decode CSV (try saving as UTF-8)")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",\t;")
    except csv.Error:
        dialect = csv.excel
    rows = [list(r) for r in csv.reader(StringIO(text), dialect)]
    return [_Sheet(name="Sheet1", rows=rows)]


def _find_project(sheet: _Sheet, last_row: int) -> str:
    project = ""
    for r in range(1, min(sheet.max_row, last_row) + 1):
        vals = [sheet.cell(r, c) for c in range(1, min(sheet.max_column, 20) + 1)]
        if vals and _norm(vals[0]).startswith("project"):
            inline = str(vals[0]).split(":", 1)[1].strip() if ":" in str(vals[0]) else ""
            project = inline or next((str(v).strip() for v in vals[1:] if v not in (None, "")), "")
    return project


def _row_headers(sheet: _Sheet, row: int) -> list[str]:
    return [_header_text(sheet.cell(row, c)) for c in range(1, sheet.max_column + 1)
            if sheet.cell(row, c) not in (None, "")]


def _try_standard_layout(sheets: list[_Sheet]) -> _Layout | None:
    """Exact current template path. Returns None if this file is not that layout."""
    ws = next((s for s in sheets if s.name == SHEET), None)
    if ws is None:
        ws = next((s for s in sheets if "firewall" in s.name.lower() and "rule" in s.name.lower()), None)
    if ws is None:
        return None
    project, header_row = "", None
    for r in range(1, min(ws.max_row, 15) + 1):
        vals = [ws.cell(r, c) for c in range(1, min(ws.max_column, 20) + 1)]
        if vals and _norm(vals[0]).startswith("project"):
            inline = str(vals[0]).split(":", 1)[1].strip() if ":" in str(vals[0]) else ""
            project = inline or next((str(v).strip() for v in vals[1:] if v not in (None, "")), "")
        if header_row is None and any("source" in _norm(v) and "address" in _norm(v) for v in vals):
            header_row = r
    if header_row is None:
        return None
    cols: dict[str, int] = {}
    headers: dict[str, str] = {}
    for c in range(1, ws.max_column + 1):
        raw = ws.cell(header_row, c)
        h = _norm(raw)
        for key, words in COLUMNS.items():
            if key in cols or not all(w in h for w in words):
                continue
            if key in ("source", "destination") and "dns" in h:
                continue
            if key == "ports" and "dns" in h:
                continue
            cols[key] = c
            headers[key] = _header_text(raw)
            break
    missing = [k for k in ("source", "destination", "ports") if k not in cols]
    if missing:
        return None
    return _Layout(sheet=ws, header_row=header_row, cols=cols, headers=headers,
                   project=project, standard_template=True, score=30,
                   seen_headers=_row_headers(ws, header_row))


def _map_flexible_row(sheet: _Sheet, row: int) -> tuple[dict[str, int], dict[str, str], int | None, str]:
    cols: dict[str, int] = {}
    headers: dict[str, str] = {}
    port_candidates: list[tuple[int, int, str, int]] = []  # rank, col, text, col
    source_port_col, source_port_header = None, ""
    for c in range(1, sheet.max_column + 1):
        raw = sheet.cell(row, c)
        if raw in (None, ""):
            continue
        text, canon = _header_text(raw), _canon(raw)
        if _is_source_port_header(canon):
            if source_port_col is None:
                source_port_col, source_port_header = c, text
            continue
        if "source" not in cols and _matches_syn(canon, SOURCE_SYNS, ADDR_FORBID):
            cols["source"], headers["source"] = c, text
        elif "destination" not in cols and _matches_syn(canon, DEST_SYNS, ADDR_FORBID):
            cols["destination"], headers["destination"] = c, text
        elif "protocol" not in cols and _matches_syn(canon, PROTO_SYNS):
            cols["protocol"], headers["protocol"] = c, text
        elif "source_dns" not in cols and "source" in canon.split() and "dns" in canon.split():
            cols["source_dns"], headers["source_dns"] = c, text
        elif "destination_dns" not in cols and (
            any(t in canon.split() for t in ("destination", "dest", "dst")) and "dns" in canon.split()
        ):
            cols["destination_dns"], headers["destination_dns"] = c, text
        elif "firewall" not in cols and _phrase_in(canon, "firewall"):
            cols["firewall"], headers["firewall"] = c, text
        elif "notes" not in cols and _matches_syn(canon, NOTES_SYNS):
            cols["notes"], headers["notes"] = c, text
        elif "application" not in cols and _matches_syn(canon, APP_SYNS):
            cols["application"], headers["application"] = c, text
        else:
            for syn, rank in PORT_SYNS:
                if _phrase_in(canon, syn):
                    port_candidates.append((rank, c, text, c))
                    break
    if port_candidates:
        port_candidates.sort()
        _, c, text, _ = port_candidates[0]
        cols["ports"], headers["ports"] = c, text
    return cols, headers, source_port_col, source_port_header


def _score_mapping(cols: dict[str, int], sheet_name: str) -> int:
    score = 0
    for k in ("source", "destination", "ports"):
        if k in cols:
            score += 10
    for k in ("protocol", "source_dns", "destination_dns", "firewall", "notes", "application"):
        if k in cols:
            score += 1
    n = sheet_name.lower()
    if "firewall" in n and "rule" in n:
        score += 2
    elif "rule" in n or "firewall" in n or "acl" in n:
        score += 1
    return score


def _pick_flexible_layout(sheets: list[_Sheet]) -> tuple[_Layout | None, _Layout | None]:
    """Return (best complete layout or None, best attempt for error text)."""
    best: _Layout | None = None
    best_key: tuple | None = None
    best_attempt: _Layout | None = None
    attempt_key: tuple | None = None
    for si, sheet in enumerate(sheets):
        last = min(sheet.max_row, FLEX_HEADER_ROWS)
        for r in range(1, last + 1):
            cols, headers, src_port_c, src_port_h = _map_flexible_row(sheet, r)
            score = _score_mapping(cols, sheet.name)
            seen = _row_headers(sheet, r)
            layout = _Layout(
                sheet=sheet, header_row=r, cols=cols, headers=headers,
                project=_find_project(sheet, max(30, r)), standard_template=False,
                source_port_col=src_port_c, source_port_header=src_port_h,
                score=score, seen_headers=seen,
            )
            key = (score, -r, -si)
            if all(k in cols for k in ("source", "destination", "ports")):
                if best_key is None or key > best_key:
                    best, best_key = layout, key
            # Keep the most useful row for the error text, even when nothing matched.
            if seen and (attempt_key is None or key > attempt_key):
                best_attempt, attempt_key = layout, key
    return best, best_attempt


def _missing_columns_error(path: Path, sheets: list[_Sheet], attempt: _Layout | None) -> str:
    names = ", ".join(s.name for s in sheets) or "(none)"
    if attempt and attempt.seen_headers:
        seen = ", ".join(attempt.seen_headers)
        return (
            f"{path.name}: could not find source, destination, and port columns "
            f"in sheet {attempt.sheet.name!r} (looked at row {attempt.header_row}). "
            f"Headers seen: {seen}. Looking for: {_LOOKING_FOR}."
        )
    return (
        f"{path.name}: could not find source, destination, and port columns "
        f"(looked at every sheet, first {FLEX_HEADER_ROWS} rows: {names}). "
        f"Looking for: {_LOOKING_FOR}."
    )


def _source_port_note(layout: _Layout) -> str | None:
    if not layout.source_port_col:
        return None
    found: list[str] = []
    for r in range(layout.header_row + 1, layout.sheet.max_row + 1):
        val = layout.sheet.cell(r, layout.source_port_col)
        if val in (None, ""):
            continue
        specs, _ = parse_ports(val, "tcp")
        for s in specs:
            if not s.port:
                continue
            lo, _, _ = s.port.partition("-")
            try:
                n = int(lo)
            except ValueError:
                continue
            if n < 1024 and s.port not in found:
                found.append(s.port)
    if not found:
        return None
    shown = ", ".join(found[:8])
    label = layout.source_port_header or "Source Port"
    return (
        f"column {label!r} was ignored (destination ports are used for the rule); "
        f"it contains non-ephemeral values such as {shown}"
    )


def read_fcr(path: str | Path, *, ticket_patterns: dict[str, str], override: Tickets | None = None,
             requester: str = "") -> tuple[list[RuleRequest], dict[str, Any]]:
    """Read one FCR workbook or CSV. Returns (requests, file metadata)."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".xls":
        raise ValueError(f"{path.name}: {_XLS_MSG}")
    if suffix == ".csv":
        sheets = _load_csv(path)
    elif suffix in (".xlsx", ".xlsm"):
        sheets = _load_xlsx(path)
    else:
        raise ValueError(f"{path.name}: use .xlsx or .csv")
    if not sheets:
        raise ValueError(f"{path.name}: workbook has no sheets")

    layout = _try_standard_layout(sheets)
    attempt = None
    if layout is None:
        layout, attempt = _pick_flexible_layout(sheets)
    if layout is None:
        raise ValueError(_missing_columns_error(path, sheets, attempt))

    notes_list: list[str] = list(layout.mapping_notes)
    src_note = _source_port_note(layout)
    if src_note:
        notes_list.append(src_note)
        layout.mapping_notes = notes_list

    ws = layout.sheet
    cols = layout.cols
    header_row = layout.header_row
    project = layout.project
    notes_all = []
    rows = []
    for r in range(header_row + 1, ws.max_row + 1):
        cell = {k: ws.cell(r, c) for k, c in cols.items()}
        if all(v in (None, "") for v in cell.values()):
            continue
        rows.append((r, cell))
        notes_all.append(str(cell.get("notes") or ""))
    file_tickets = find_tickets([path.name, project] + notes_all, ticket_patterns)
    if override:
        for k in ("ritm", "sctask", "cr"):
            if getattr(override, k):
                setattr(file_tickets, k, list(getattr(override, k)))
    out = []
    for r, cell in rows:
        flags: list[Flag] = []
        src, f1 = parse_endpoints(cell.get("source"), cell.get("source_dns"), "source")
        dst, f2 = parse_endpoints(cell.get("destination"), cell.get("destination_dns"), "destination")
        svcs, f3 = parse_ports(cell.get("ports"), cell.get("protocol"))
        flags += f1 + f2 + f3
        apps = [a for a in split_cell(cell.get("application")) if a.lower() not in ("n/a", "na", "none", "unknown")]
        if not file_tickets.all():
            flags.append(Flag("yellow", "no-ticket", "no RITM/SCTASK/CR found; pass --ritm/--sctask/--cr"))
        req = RuleRequest(file=path.name, row=r, project=project, sources=src, destinations=dst, services=svcs,
                          applications=apps, firewall=(str(cell.get("firewall")).strip() or None) if cell.get("firewall") else None,
                          notes=str(cell.get("notes") or "").strip(), tickets=Tickets(**asdict(file_tickets)),
                          requester=requester, flags=flags, origins=[f"{path.name}:{r}"])
        out.append(req)
    mapping = {k: layout.headers[k] for k in
               ("source", "destination", "ports", "protocol",
                "source_dns", "destination_dns", "firewall", "notes", "application")
               if k in layout.headers}
    return out, {
        "file": path.name,
        "project": project,
        "tickets": asdict(file_tickets),
        "rows": len(out),
        "sheet": ws.name,
        "header_row": header_row,
        "mapping": mapping,
        "standard_template": layout.standard_template,
        "mapping_notes": notes_list,
    }
