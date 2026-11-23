"""EDL manager: External Dynamic Lists that security teams edit without touching a firewall.

A list is a plain-text file (one IP, domain or URL per line) that PAN-OS firewalls fetch on a schedule
(an ``external-list`` object). PAAT keeps the list, its history and its audit trail, checks every entry,
and publishes it to one or both of:

* **PAAT-hosted:** ``/edl/<token>.txt`` on this server (optional basic auth and/or source-IP allowlist).
* **S3 / S3-compatible** (AWS S3, MinIO): written atomically (temp key, verify, copy, verify). Credentials
  come from ``/etc/panlab/edl/<customer>.env`` or the server environment, never from the UI.

Everything is per customer (tenant isolation): lists live under the customer's data directory
(``<data>/<customer>/edl/<list-id>/``) and every page checks the customer scope.

Files per list (JSON, mode 600)::

    meta.json            name, type, description, owner, approval, hosted/S3 settings, last publish status
    entries.json         current entries: value, comment, added_by, added_at, expires_at, ticket
    versions/000001.json full snapshot per version: entries, who, when, why, adds/removes
    changes/<id>.json    staged edits waiting for a second person (two-person approval, or risky entries)
    audit.jsonl          one line per action (no secrets)

Per-customer safety settings (``<data>/<customer>/edl/_settings.json``): protected ranges (RFC 1918 and
your own networks: entries inside them need approval), never-block list (DNS servers, management IPs,
your own domains: entries that would block them are refused), how broad a prefix may be, and the firewall
model used for capacity warnings.

Formats follow Palo Alto Networks "Formatting Guidelines for an External Dynamic List" (PAN-OS 11.1) and
limits follow "External Dynamic List" (PAN-OS 11.1 admin guide); see docs/user-manual/edl.md.
"""

from __future__ import annotations

import csv
import fcntl
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo

from panlab.customers import Profile

TZ = ZoneInfo("America/Chicago")
TYPES = {"ip": "IP address", "domain": "Domain (FQDN)", "url": "URL"}
LIST_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
CHANGE_RE = re.compile(r"^chg-\d{8}-\d{6}-[0-9a-f]{6}$")
OBJ_RE = re.compile(r"^obj-\d{8}-\d{6}-[0-9a-f]{6}$")
DRAFT_RE = re.compile(r"^drf-[0-9a-f]{16}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")
PAN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$")
MAX_ENTRY_LEN = 255  # PAN-OS: each domain / URL entry up to 255 characters
MAX_IMPORT_LINES = 200_000
RECURRING = ("five-minute", "hourly", "daily")
RESERVED_IDS = frozenset({"new", "settings", "objects"})
DG_XP = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dg}']"
SHARED_XP = "/config/shared"
VSYS_XP = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']"
# Served when a list has no live entries: PAN-OS expects an EDL to contain entries. These never match real
# traffic: 192.0.2.0/24 is TEST-NET-1 (RFC 5737) and .invalid is reserved (RFC 2606).
PLACEHOLDER = {"ip": "192.0.2.1", "domain": "paat-empty-list.invalid", "url": "paat-empty-list.invalid/"}

# PAN-OS 11.1 per-firewall EDL capacities, from the PAN-OS 11.1 Admin Guide page "External Dynamic List"
# (docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/external-dynamic-list).
# IP: 150,000 on PA-3200, PA-5200 and PA-7000 Series, 50,000 on every other model. URL / domain: the guide's model table.
# Entries only count when the list is referenced in policy. (label, ip, domain, url)
MODEL_LIMITS: dict[str, tuple[str, int, int, int]] = {
    "small": ("PA-220, PA-410, VM-50, VM-100, VM-1000-HV", 50_000, 50_000, 50_000),
    "mid": ("PA-400 Series (not PA-410), PA-820, PA-850, PA-3400 Series", 50_000, 1_000_000, 100_000),
    "pa3200": ("PA-3200 Series", 150_000, 1_000_000, 100_000),
    "vm300": ("VM-300", 50_000, 500_000, 100_000),
    "pa7000": ("PA-7000 Series with 20GQ / 20G NPC (or mixed NPCs)", 150_000, 500_000, 100_000),
    "vm500": ("VM-500, VM-700", 50_000, 2_000_000, 100_000),
    "pa5400": ("PA-5400 Series", 50_000, 4_000_000, 250_000),
    "large": ("PA-5200 Series, PA-7000 Series with 20GXM / 20GQXM / 100G NPC", 150_000, 4_000_000, 250_000),
}
MAX_EDL_OBJECTS = 30  # custom EDLs with unique sources per firewall (PAN-OS 11.1)

RFC1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
SPECIAL_PROTECTED = ["100.64.0.0/10", "fc00::/7"]  # carrier-grade NAT and IPv6 unique-local
# Wildcards over these suffixes match a huge part of the internet: refused outright.
MAJOR_TLDS = frozenset("com net org edu gov mil int info biz io co us uk ca de fr jp cn ru au in br it nl es eu".split())
TWO_LEVEL_SUFFIXES = frozenset("co.uk org.uk ac.uk gov.uk com.au net.au org.au co.jp co.nz com.br com.cn co.in co.za com.mx".split())

DEFAULT_SETTINGS: dict[str, Any] = {
    "protected_rfc1918": True,     # RFC 1918, CGNAT and IPv6 ULA entries need approval
    "protected_ranges": [],         # your own public ranges, one per line, optional "  # label"
    "protected_domains": [],        # your own domains: entries that cover them need approval
    "never_block": [],              # DNS servers, management IPs, critical domains: entries that cover them are refused
    "hard_min_prefix_v4": 8,        # shorter than this is refused (0.0.0.0/0 always is)
    "hard_min_prefix_v6": 16,
    "approval_prefix_v4": 16,       # shorter than this needs approval
    "approval_prefix_v6": 32,
    "model": "small",               # capacity warnings (MODEL_LIMITS)
    "public_base_url": "",          # what firewalls use to reach PAAT, e.g. https://paat.example.net
}


class EdlError(RuntimeError):
    pass


def now() -> datetime:
    return datetime.now(TZ)


def ts() -> str:
    return now().isoformat(timespec="seconds")


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=TZ)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- validation

@dataclass
class Check:
    raw: str
    value: str | None = None       # normalized entry, or None when invalid
    error: str | None = None
    notes: list[str] = field(default_factory=list)
    level: str = "ok"               # ok | approval | blocked (safety)
    why: list[str] = field(default_factory=list)
    comment: str = ""


def split_comment(line: str) -> tuple[str, str]:
    """``value [space] comment`` (PAN-OS IP-list syntax; also accepted for domains and URLs)."""
    s = line.strip()
    if not s:
        return "", ""
    parts = s.split(None, 1)
    com = parts[1].strip().lstrip("#;").strip() if len(parts) > 1 else ""
    return parts[0], com


def _ip_norm(s: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    if "-" in s:
        a, b = (x.strip() for x in s.split("-", 1))
        try:
            ia, ib = ipaddress.ip_address(a), ipaddress.ip_address(b)
        except ValueError:
            raise EdlError("not a valid IP range (use start-end, for example 192.0.2.10-192.0.2.20)") from None
        if ia.version != ib.version:
            raise EdlError("a range must be all IPv4 or all IPv6")
        if int(ia) > int(ib):
            raise EdlError("range start is after the range end")
        if ia == ib:
            return str(ia), ["single-address range written as one address"]
        return f"{ia}-{ib}", notes
    if "/" in s:
        try:
            iface = ipaddress.ip_interface(s)
        except ValueError:
            raise EdlError("not a valid IP subnet (use address/prefix, for example 192.0.2.0/24)") from None
        net = iface.network
        if iface.ip != net.network_address:
            notes.append(f"host bits cleared: {s} is the subnet {net}")
        if net.prefixlen == net.max_prefixlen:
            return str(net.network_address), notes
        return str(net), notes
    try:
        return str(ipaddress.ip_address(s)), notes
    except ValueError:
        raise EdlError("not a valid IPv4 or IPv6 address, subnet or range") from None


def _is_ip(s: str) -> bool:
    try:
        _ip_norm(s)
        return True
    except EdlError:
        return False


def ip_span(value: str) -> tuple[int, int, int]:
    """(version, first, last) as integers for an IP-list value."""
    if "-" in value:
        a, b = value.split("-", 1)
        ia, ib = ipaddress.ip_address(a), ipaddress.ip_address(b)
        return ia.version, int(ia), int(ib)
    net = ipaddress.ip_network(value, strict=False)
    return net.version, int(net.network_address), int(net.broadcast_address)


def _span_prefix(v: int, lo: int, hi: int) -> int:
    bits = 32 if v == 4 else 128
    return bits - ((hi - lo + 1).bit_length() - 1)


_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_URL_TOKEN_SEP = re.compile(r"[./?&=;+]+")


def _strip_scheme(s: str, notes: list[str]) -> str:
    m = re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I)
    if m:
        notes.append(f"removed {m.group(0)} (PAN-OS lists must not include the protocol)")
        s = s[m.end():]
    return s


def _domain_norm(s: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    s = _strip_scheme(s.strip().lower(), notes)
    if s.endswith("/") and "/" not in s[:-1]:
        s = s[:-1]
        notes.append("removed the trailing /")
    if any(c in s for c in "/?&=;+ :"):
        raise EdlError("a domain cannot have a path, port or query; use a URL list for that")
    if s.endswith("."):
        s = s[:-1]
    prefix = ""
    if s.startswith("*."):
        prefix, s = "*.", s[2:]
    elif s.startswith("^"):
        prefix, s = "^", s[1:].lstrip(".")
    if "*" in s or "^" in s:
        raise EdlError("in a domain list a wildcard may only come first (*.example.com), or ^ for an exact match (^example.com)")
    if _is_ip(s):
        raise EdlError("this is an IP address; put it in an IP list")
    labels = s.split(".") if s else []
    if not labels or not all(_LABEL.match(x) for x in labels):
        raise EdlError("not a valid domain name (letters, digits and hyphens between dots)")
    v = prefix + s
    if len(v) > MAX_ENTRY_LEN:
        raise EdlError(f"longer than {MAX_ENTRY_LEN} characters")
    return v, notes


def _url_norm(s: str) -> tuple[str, list[str]]:
    notes: list[str] = []
    s = _strip_scheme(s.strip(), notes)
    if not s:
        raise EdlError("empty URL")
    if any(ch.isspace() for ch in s):
        raise EdlError("URL entries cannot contain spaces")
    host, slash, path = s.partition("/")
    host = host.lower()
    path = path.lower()  # PAN-OS list entries are case-insensitive
    if ":" in host:
        raise EdlError("PAN-OS URL entries cannot include a port")
    toks = host.split(".")
    if not host or any(t == "" for t in toks):
        raise EdlError("not a valid host name")
    for t in toks:
        if t in ("*", "^"):
            continue
        if "*" in t or "^" in t:
            raise EdlError("a wildcard (* or ^) must be a whole token, for example *.example.com, not ex*mple.com")
        if not _LABEL.match(t):
            raise EdlError("not a valid host name (letters, digits and hyphens between dots)")
    if path.startswith("^"):
        raise EdlError("^ cannot follow a slash (example.com/^ is invalid); use *")
    for t in _URL_TOKEN_SEP.split(path):
        if ("*" in t or "^" in t) and t not in ("*", "^"):
            raise EdlError("a wildcard (* or ^) must be a whole token in the path too")
    v = host + slash + path
    if len(v) > MAX_ENTRY_LEN:
        raise EdlError(f"longer than {MAX_ENTRY_LEN} characters")
    return v, notes


def normalize(kind: str, raw: str) -> tuple[str, list[str]]:
    if kind == "ip":
        return _ip_norm(raw.strip())
    if kind == "domain":
        return _domain_norm(raw)
    if kind == "url":
        return _url_norm(raw)
    raise EdlError(f"unknown list type {kind!r}")


# ---------------------------------------------------------------- safety

def _settings_nets(lines: Iterable[str]) -> list[tuple[str, str]]:
    """(value, label) from settings lines like '10.1.1.53  # DNS'."""
    out = []
    for ln in lines or []:
        v, c = split_comment(str(ln))
        if v:
            out.append((v, c))
    return out


def _overlap(a: tuple[int, int, int], b: tuple[int, int, int]) -> bool:
    return a[0] == b[0] and a[1] <= b[2] and b[1] <= a[2]


def _host_part(kind: str, value: str) -> tuple[str, str]:
    """(prefix, host) for domain/url values: prefix is '*.', '^.', '^' or ''."""
    host = value.split("/", 1)[0] if kind == "url" else value
    for p in ("*.", "^."):
        if host.startswith(p):
            return p, host[2:]
    if host.startswith("^"):
        return "^", host[1:]
    return "", host


def _domain_covers(entry_kind: str, entry: str, name: str) -> bool:
    """Would list value ``entry`` match ``name`` (a domain, or *.zone for a whole zone) or part of it?"""
    pre, host = _host_part(entry_kind, entry)
    path = entry.split("/", 1)[1] if entry_kind == "url" and "/" in entry else ""
    npre, nhost = _host_part("domain", name.lower())
    toks = host.split(".")
    if "*" in toks or "^" in toks:  # inner wildcards: compare the fixed suffix after the last wildcard
        last = max(i for i, t in enumerate(toks) if t in ("*", "^"))
        suffix = ".".join(toks[last + 1:])
        return bool(suffix) and (nhost == suffix or nhost.endswith("." + suffix))
    if path not in ("", "*"):
        return False  # a specific page never blocks a whole domain
    if pre == "^":
        return nhost == host
    if nhost == host or nhost.endswith("." + host):
        return True  # the name itself, or a parent zone (wildcard / subdomain expansion)
    return npre == "*." and host.endswith("." + nhost)  # entry inside a protected zone like *.corp.example


def classify(kind: str, value: str, settings: dict) -> tuple[str, list[str]]:
    """Safety level for a normalized value: ('ok' | 'approval' | 'blocked', reasons)."""
    st = {**DEFAULT_SETTINGS, **(settings or {})}
    blocked: list[str] = []
    approval: list[str] = []
    if kind == "ip":
        v, lo, hi = ip_span(value)
        bits = 32 if v == 4 else 128
        pfx = _span_prefix(v, lo, hi)
        if lo == 0 and hi == (1 << bits) - 1:
            blocked.append("matches every address (" + ("0.0.0.0/0" if v == 4 else "::/0") + ")")
        hard = int(st["hard_min_prefix_v4"] if v == 4 else st["hard_min_prefix_v6"])
        soft = int(st["approval_prefix_v4"] if v == 4 else st["approval_prefix_v6"])
        if not blocked and pfx < hard:
            blocked.append(f"far too broad: about /{pfx} (the limit is /{hard})")
        elif not blocked and pfx < soft:
            approval.append(f"very broad: about /{pfx} (wider than /{soft} needs a second person)")
        first = ipaddress.ip_address(lo) if v == 4 else ipaddress.IPv6Address(lo)
        if first.is_loopback or (lo == hi and first.is_unspecified):
            blocked.append("loopback or unspecified address")
        elif first.is_link_local or first.is_multicast:
            approval.append("link-local or multicast address")
        span = (v, lo, hi)
        for nb, label in _settings_nets(st.get("never_block") or []):
            if not _is_ip(nb):
                continue
            nv, _ = _ip_norm(nb)
            if _overlap(span, ip_span(nv)):
                blocked.append(f"would block {nv} on the never-block list" + (f" ({label})" if label else ""))
        prot = list(_settings_nets(st.get("protected_ranges") or []))
        if st.get("protected_rfc1918", True):
            prot += [(n, "RFC 1918 private range") for n in RFC1918] + [(n, "private / shared range") for n in SPECIAL_PROTECTED]
        for pn, label in prot:
            if not _is_ip(pn):
                continue
            pv, _ = _ip_norm(pn)
            if _overlap(span, ip_span(pv)):
                approval.append(f"inside protected range {pv}" + (f" ({label})" if label else ""))
                break
    else:
        pre, host = _host_part(kind, value)
        toks = host.split(".")
        wild = [i for i, t in enumerate(toks) if t in ("*", "^")]
        tail = ".".join(toks[(max(wild) + 1) if wild else 0:])
        if not tail or host in ("*", "^"):
            blocked.append("matches every site")
        elif pre in ("*.", "^.") or wild:
            if "." not in tail:
                (blocked if tail in MAJOR_TLDS else approval).append(f"wildcard over a whole top-level domain (.{tail})")
            elif tail in TWO_LEVEL_SUFFIXES:
                blocked.append(f"wildcard over a public suffix (.{tail})")
        elif len(toks) == 1 and not (kind == "url" and "/" in value.strip("/")):
            blocked.append(f"bare top-level domain ({host}); name the domain, for example example.{host}")
        elif host in TWO_LEVEL_SUFFIXES:
            blocked.append(f"public suffix ({host}), not a domain")
        for nb, label in _settings_nets(st.get("never_block") or []):
            if _is_ip(nb):
                continue  # an IP on the never-block list applies to IP lists
            if _domain_covers(kind, value, nb):
                blocked.append(f"would block {nb} on the never-block list" + (f" ({label})" if label else ""))
        for pd, label in _settings_nets(st.get("protected_domains") or []):
            zone = _host_part("domain", pd.lower())[1]
            if _domain_covers(kind, value, pd) or tail == zone or tail.endswith("." + zone):
                approval.append(f"covers protected domain {pd}" + (f" ({label})" if label else ""))
                break
    if blocked:
        return "blocked", blocked + approval
    if approval:
        return "approval", approval
    return "ok", []


def check(kind: str, line: str, settings: dict | None = None) -> Check:
    val, com = split_comment(line)
    c = Check(raw=line.strip(), comment=com)
    if not val:
        c.error = "empty"
        return c
    try:
        c.value, c.notes = normalize(kind, val)
    except EdlError as exc:
        c.error = str(exc)
        return c
    c.level, c.why = classify(kind, c.value, settings or {})
    return c


def covered_by(kind: str, value: str, others: Iterable[str]) -> str | None:
    """Another entry that already covers ``value`` (informational: both are kept)."""
    if kind != "ip":
        for o in others:
            if o != value and o.startswith("*.") and _domain_covers(kind, o, value.lstrip("^")):
                return o
        return None
    s = ip_span(value)
    for o in others:
        if o == value:
            continue
        try:
            t = ip_span(o)
        except ValueError:
            continue
        if t[0] == s[0] and t[1] <= s[1] and s[2] <= t[2]:
            return o
    return None


def sort_key(kind: str, value: str):
    if kind == "ip":
        try:
            v, lo, hi = ip_span(value)
            return (v, lo, hi, value)
        except ValueError:
            return (9, 0, 0, value)
    return (value.lstrip("*.^"), value)


# ---------------------------------------------------------------- storage

def _root(profile: Profile) -> Path:
    d = profile.data_dir("edl")
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


def list_dir(profile: Profile, lid: str) -> Path:
    if not LIST_ID_RE.match(lid or ""):
        raise EdlError("list ids: lowercase letters, digits and -, up to 40 characters")
    return _root(profile) / lid


def _write_json(p: Path, data: Any) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{secrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.replace(tmp, p)


def _read_json(p: Path, default: Any = None) -> Any:
    if not p.is_file():
        return default
    return json.loads(p.read_text(encoding="utf-8"))


@contextmanager
def _locked(profile: Profile, lid: str):
    d = list_dir(profile, lid)
    d.mkdir(parents=True, exist_ok=True)
    fd = os.open(d / ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield d
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def load_settings(profile: Profile) -> dict:
    return {**DEFAULT_SETTINGS, **(_read_json(_root(profile) / "_settings.json", {}) or {})}


def save_settings(profile: Profile, new: dict, *, actor: str) -> dict:
    cur = load_settings(profile)
    clean = dict(cur)
    for k, dflt in DEFAULT_SETTINGS.items():
        if k not in new:
            continue
        v = new[k]
        if isinstance(dflt, bool):
            clean[k] = bool(v)
        elif isinstance(dflt, int):
            try:
                clean[k] = int(v)
            except (TypeError, ValueError):
                raise EdlError(f"{k} must be a number") from None
        elif isinstance(dflt, list):
            clean[k] = [str(x).strip() for x in (v if isinstance(v, list) else str(v).splitlines()) if str(x).strip()]
        else:
            clean[k] = str(v).strip()
    if clean["model"] not in MODEL_LIMITS:
        raise EdlError("unknown firewall model family")
    for k in ("hard_min_prefix_v4", "approval_prefix_v4"):
        if not 1 <= clean[k] <= 32:
            raise EdlError(f"{k} must be 1-32")
    for k in ("hard_min_prefix_v6", "approval_prefix_v6"):
        if not 1 <= clean[k] <= 128:
            raise EdlError(f"{k} must be 1-128")
    for v, _c in _settings_nets(clean["protected_ranges"]):
        if not _is_ip(v):
            raise EdlError(f"protected range {v!r} is not an IP, subnet or range")
    if clean["public_base_url"] and not re.match(r"^https?://[A-Za-z0-9.\-\[\]:]+(/[A-Za-z0-9._~/-]*)?$", clean["public_base_url"]):
        raise EdlError("public base URL must look like https://paat.example.net")
    clean["public_base_url"] = clean["public_base_url"].rstrip("/")
    _write_json(_root(profile) / "_settings.json", clean)
    audit(profile, "_settings", actor, "settings", "saved", changed=sorted(k for k in clean if clean[k] != cur.get(k)))
    return clean


def _audit_path(profile: Profile, lid: str) -> Path:
    return _root(profile) / ("_audit.jsonl" if lid.startswith("_") else f"{lid}/audit.jsonl")


def audit(profile: Profile, lid: str, actor: str, action: str, result: str, **kw: Any) -> None:
    """One JSON line per action in the list's audit log, and in the customer's main audit log. Never secrets."""
    rec = {"ts": ts(), "customer": profile.name, "list": lid, "actor": actor, "action": action, "result": result}
    rec.update({k: v for k, v in kw.items() if not any(s in k.lower() for s in ("secret", "password", "hash", "access_key"))})
    p = _audit_path(profile, lid)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
    try:
        from panlab.pusher import audit as main_audit

        main_audit(profile, kind="edl", **{k: v for k, v in rec.items() if k not in ("ts", "customer")})
    except Exception:  # noqa: BLE001
        pass


def read_audit(profile: Profile, lid: str, limit: int = 300) -> list[dict]:
    p = _audit_path(profile, lid)
    if not p.is_file():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()][-limit:]


def list_ids(profile: Profile) -> list[str]:
    r = _root(profile)
    return sorted(d.name for d in r.iterdir() if d.is_dir() and LIST_ID_RE.match(d.name) and (d / "meta.json").is_file())


def load_meta(profile: Profile, lid: str) -> dict:
    m = _read_json(list_dir(profile, lid) / "meta.json")
    if not m:
        raise EdlError(f"no list {lid!r} for {profile.name}")
    return m


def load_entries(profile: Profile, lid: str) -> list[dict]:
    return list(_read_json(list_dir(profile, lid) / "entries.json", []) or [])


def all_lists(profile: Profile) -> list[dict]:
    out = []
    for lid in list_ids(profile):
        try:
            m = dict(load_meta(profile, lid))
        except Exception:  # noqa: BLE001
            continue
        ents = load_entries(profile, lid)
        m["count"] = len(live_entries(ents))
        m["expired"] = len(ents) - m["count"]
        m["pending"] = sum(1 for c in list_changes(profile, lid) if c.get("status") == "pending")
        out.append(m)
    return out


def create_list(profile: Profile, *, lid: str, name: str, kind: str, description: str, actor: str,
                require_approval: bool = False, hosted: bool = True, placeholder: bool = True) -> dict:
    if kind not in TYPES:
        raise EdlError("type must be ip, domain or url")
    if lid in RESERVED_IDS:
        raise EdlError(f"{lid!r} is a reserved word; pick another list id")
    d = list_dir(profile, lid)
    if (d / "meta.json").is_file():
        raise EdlError(f"a list {lid!r} already exists")
    if not (name or "").strip():
        raise EdlError("give the list a name")
    meta = {
        "id": lid, "name": name.strip()[:80], "type": kind, "description": (description or "").strip()[:500],
        "owner": profile.name, "created_by": actor, "created_at": ts(), "version": 0,
        "require_approval": bool(require_approval), "placeholder_when_empty": bool(placeholder),
        "hosted": {"enabled": bool(hosted), "token": secrets.token_urlsafe(24), "basic_auth_user": "", "basic_auth_hash": "",
                   "allow_ips": []},
        "s3": {"enabled": False, "endpoint_url": "", "region": "", "bucket": "", "key": "", "path_style": False, "verify": True},
        "firewall": {"object_name": "", "device_group": "", "recurring": "five-minute"},
        "publish": {},
    }
    with _locked(profile, lid):
        _write_json(d / "meta.json", meta)
        _write_json(d / "entries.json", [])
        _version(profile, meta, [], actor=actor, reason="list created", added=[], removed=[], source="create")
    audit(profile, lid, actor, "create", "ok", type=kind, name=meta["name"])
    return meta


def _public(m: dict) -> dict:
    out = json.loads(json.dumps(m))
    if (out.get("hosted") or {}).get("basic_auth_hash"):
        out["hosted"]["basic_auth_hash"] = "set"
    return out


def update_meta(profile: Profile, lid: str, *, actor: str, quiet: bool = False, **changes: Any) -> dict:
    with _locked(profile, lid) as d:
        m = load_meta(profile, lid)
        before = _public(m)
        for k, v in changes.items():
            if k in ("hosted", "s3", "firewall", "publish") and isinstance(v, dict):
                m[k] = {**(m.get(k) or {}), **v}
            elif k in ("name", "description", "require_approval", "placeholder_when_empty"):
                m[k] = v
            else:
                raise EdlError(f"cannot change {k}")
        _write_json(d / "meta.json", m)
    after = _public(m)
    changed = [k for k in after if after.get(k) != before.get(k) and k != "publish"]
    if changed and not quiet:
        audit(profile, lid, actor, "settings", "saved", changed=changed)
    return m


def delete_list(profile: Profile, lid: str, *, actor: str) -> str:
    """Move the list aside (kept for the record, no longer served or published). Returns the archive name."""
    import shutil

    d = list_dir(profile, lid)
    m = load_meta(profile, lid)
    trash = _root(profile) / "_deleted" / f"{lid}-{now():%Y%m%d-%H%M%S}"
    trash.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(d), str(trash))
    audit(profile, "_lists", actor, "delete", "ok", deleted=lid, name=m.get("name"), kept_in=trash.name)
    return trash.name


def live_entries(entries: list[dict], at: datetime | None = None) -> list[dict]:
    t = at or now()
    out = []
    for x in entries:
        exp = _parse_ts(x.get("expires_at"))
        if not (exp and exp <= t):
            out.append(x)
    return out


def render_text(meta: dict, entries: list[dict], at: datetime | None = None) -> str:
    """The list exactly as firewalls get it: one value per line, sorted, expired entries left out."""
    vals = sorted({x["value"] for x in live_entries(entries, at)}, key=lambda v: sort_key(meta["type"], v))
    if not vals and meta.get("placeholder_when_empty", True):
        vals = [PLACEHOLDER[meta["type"]]]
    return "".join(v + "\n" for v in vals)


def _version(profile: Profile, meta: dict, entries: list[dict], *, actor: str, reason: str, added: list[str],
             removed: list[str], approved_by: str = "", ticket: str = "", source: str = "edit") -> int:
    meta["version"] = int(meta.get("version") or 0) + 1
    d = list_dir(profile, meta["id"])
    _write_json(d / "versions" / f"{meta['version']:06d}.json", {
        "version": meta["version"], "ts": ts(), "actor": actor, "approved_by": approved_by, "reason": reason,
        "ticket": ticket, "source": source, "added": added, "removed": removed, "entries": entries})
    _write_json(d / "meta.json", meta)
    return meta["version"]


def versions(profile: Profile, lid: str) -> list[dict]:
    d = list_dir(profile, lid) / "versions"
    out = []
    for p in sorted(d.glob("*.json"), reverse=True) if d.is_dir() else []:
        v = _read_json(p, {})
        v["count"] = len(v.pop("entries", None) or [])
        out.append(v)
    return out


def load_version(profile: Profile, lid: str, n: int) -> dict:
    v = _read_json(list_dir(profile, lid) / "versions" / f"{int(n):06d}.json")
    if not v:
        raise EdlError(f"no version {n}")
    return v


# ---------------------------------------------------------------- edits, approval, revert

def parse_expiry(s: str) -> str:
    """'' | 2026-12-31 | 2026-12-31T08:00 | 12h | 30d -> ISO time (CST) or ''."""
    s = (s or "").strip()
    if not s:
        return ""
    m = re.fullmatch(r"(\d+)\s*([hd])", s.lower())
    if m:
        n = int(m.group(1))
        return (now() + (timedelta(hours=n) if m.group(2) == "h" else timedelta(days=n))).isoformat(timespec="seconds")
    d = _parse_ts(s if "T" in s else s + "T23:59:59")
    if not d:
        raise EdlError("expiry: use a date (2026-12-31), a date and time, or 12h / 30d")
    if d <= now():
        raise EdlError("expiry is in the past")
    return d.isoformat(timespec="seconds")


@dataclass
class Plan:
    adds: list[dict]
    removes: list[str]
    invalid: list[Check]
    blocked: list[Check]
    needs_approval: list[Check]
    unchanged: int
    duplicates: list[str]
    notes: list[str]
    covered: list[tuple[str, str]]

    def summary(self) -> dict:
        return {"adds": len(self.adds), "removes": len(self.removes), "invalid": len(self.invalid), "blocked": len(self.blocked),
                "approval": len(self.needs_approval), "unchanged": self.unchanged, "duplicates": len(self.duplicates)}


def plan_changes(profile: Profile, meta: dict, current: list[dict], *, add_lines: Iterable[str] = (),
                 remove_values: Iterable[str] = (), replace: bool = False, actor: str, expires_at: str = "", ticket: str = "",
                 comment: str = "", rows: Iterable[dict] | None = None) -> Plan:
    """Validate, normalize, dedupe and diff against the current entries. ``rows`` (CSV) carry their own fields."""
    st = load_settings(profile)
    kind = meta["type"]
    cur_vals = {x["value"] for x in current}
    seen: set[str] = set()
    adds, invalid, blocked, appr, dups, notes, covered = [], [], [], [], [], [], []
    unchanged = 0
    items: list[tuple[str, dict]] = [(ln, {}) for ln in add_lines]
    if rows is not None:
        items += [(r.get("value", ""), r) for r in rows]
    if len(items) > MAX_IMPORT_LINES:
        raise EdlError(f"more than {MAX_IMPORT_LINES:,} lines")
    for ln, extra in items:
        s = (ln or "").strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        c = check(kind, s, st)
        if c.error:
            invalid.append(c)
            continue
        if c.value in seen:
            dups.append(c.value)
            continue
        seen.add(c.value)
        notes += [f"{c.raw}: {n}" for n in c.notes]
        if c.value in cur_vals:
            unchanged += 1
            continue
        if c.level == "blocked":
            blocked.append(c)
            continue
        try:
            exp = parse_expiry(str(extra["expires_at"])) if extra.get("expires_at") else expires_at
        except EdlError as exc:
            c.error = str(exc)
            invalid.append(c)
            continue
        if c.level == "approval":
            appr.append(c)
        adds.append({"value": c.value, "comment": (str(extra.get("comment") or "") or comment or c.comment)[:300],
                     "added_by": actor, "added_at": ts(), "expires_at": exp, "ticket": (str(extra.get("ticket") or "") or ticket)[:80]})
    removes = sorted(cur_vals - seen) if replace else sorted(set(remove_values) & cur_vals)
    final = (cur_vals | {a["value"] for a in adds}) - set(removes)
    for a in adds:
        o = covered_by(kind, a["value"], final)
        if o:
            covered.append((a["value"], o))
    return Plan(adds, removes, invalid, blocked, appr, unchanged, dups, notes, covered)


def _change_path(profile: Profile, lid: str, cid: str) -> Path:
    if not CHANGE_RE.match(cid or ""):
        raise EdlError("bad change id")
    return list_dir(profile, lid) / "changes" / f"{cid}.json"


def list_changes(profile: Profile, lid: str) -> list[dict]:
    d = list_dir(profile, lid) / "changes"
    out = [_read_json(p, {}) for p in d.glob("chg-*.json")] if d.is_dir() else []
    return sorted(out, key=lambda c: c.get("id", ""), reverse=True)


def load_change(profile: Profile, lid: str, cid: str) -> dict:
    c = _read_json(_change_path(profile, lid, cid))
    if not c:
        raise EdlError("no such change")
    return c


def pending_count(profile: Profile) -> int:
    return sum(m["pending"] for m in all_lists(profile))


def submit(profile: Profile, lid: str, plan: Plan, *, actor: str, reason: str, ticket: str = "", source: str = "edit",
           publisher=None) -> dict:
    """Apply a planned change now, or stage it for a second person. Returns {'status': 'applied' | 'pending', ...}."""
    if plan.blocked:
        raise EdlError("refused: " + "; ".join(f"{c.value}: {', '.join(c.why)}" for c in plan.blocked[:5]))
    if not plan.adds and not plan.removes:
        raise EdlError("nothing to change")
    if not (reason or "").strip():
        raise EdlError("say why (the reason is kept in the history and the audit log)")
    meta = load_meta(profile, lid)
    why = [f"{c.value}: {', '.join(c.why)}" for c in plan.needs_approval]
    if meta.get("require_approval") or why:
        cid = f"chg-{now():%Y%m%d-%H%M%S}-{secrets.token_hex(3)}"
        ch = {"id": cid, "list": lid, "status": "pending", "requester": actor, "created": ts(), "reason": reason.strip()[:500],
              "ticket": (ticket or "")[:80], "adds": plan.adds, "removes": plan.removes, "source": source,
              "approval_reasons": (["this list needs a second person for every change"] if meta.get("require_approval") else []) + why,
              "base_version": meta["version"]}
        with _locked(profile, lid):
            _write_json(_change_path(profile, lid, cid), ch)
        audit(profile, lid, actor, "stage", "pending", change=cid, adds=[a["value"] for a in plan.adds][:50], removes=plan.removes[:50],
              reason=reason[:300], ticket=ticket, approval_reasons=ch["approval_reasons"][:5])
        return {"status": "pending", "change": ch}
    v = _apply(profile, lid, plan.adds, plan.removes, actor=actor, reason=reason, ticket=ticket, source=source)
    return {"status": "applied", "version": v, "publish": (publisher or publish)(profile, lid, actor=actor)}


def _apply(profile: Profile, lid: str, adds: list[dict], removes: list[str], *, actor: str, reason: str, ticket: str = "",
           approved_by: str = "", source: str = "edit") -> int:
    with _locked(profile, lid) as d:
        meta = load_meta(profile, lid)
        cur = load_entries(profile, lid)
        rm = set(removes)
        have = {x["value"] for x in cur}
        new = [x for x in cur if x["value"] not in rm]
        added = []
        for a in adds:
            if a["value"] in have and a["value"] not in rm:
                continue
            new.append(a)
            added.append(a["value"])
        removed = sorted(have & rm)
        if not added and not removed:
            raise EdlError("nothing to change (the list already has these edits)")
        new.sort(key=lambda x: sort_key(meta["type"], x["value"]))
        _write_json(d / "entries.json", new)
        v = _version(profile, meta, new, actor=actor, reason=reason, added=added, removed=removed, approved_by=approved_by,
                     ticket=ticket, source=source)
    audit(profile, lid, actor, "apply", "ok", version=v, added=added[:50], removed=removed[:50], n_added=len(added),
          n_removed=len(removed), approved_by=approved_by, reason=reason[:300], ticket=ticket, source=source)
    return v


def approve_change(profile: Profile, lid: str, cid: str, *, actor: str, comment: str = "", publisher=None) -> dict:
    ch = load_change(profile, lid, cid)
    if ch["status"] != "pending":
        raise EdlError(f"change is {ch['status']}")
    if actor == ch["requester"]:
        raise EdlError("you cannot approve your own change; a second person must review it")
    st = load_settings(profile)
    meta = load_meta(profile, lid)
    for a in ch["adds"]:  # the safety settings may have changed since the request
        if classify(meta["type"], a["value"], st)[0] == "blocked":
            raise EdlError(f"{a['value']} is now refused by the safety settings; reject this change")
    v = _apply(profile, lid, ch["adds"], ch["removes"], actor=ch["requester"], reason=ch["reason"], ticket=ch.get("ticket", ""),
               approved_by=actor, source=ch.get("source", "edit"))
    ch.update(status="approved", reviewer=actor, reviewed_at=ts(), review_comment=(comment or "")[:500], version=v)
    with _locked(profile, lid):
        _write_json(_change_path(profile, lid, cid), ch)
    audit(profile, lid, actor, "approve", "ok", change=cid, version=v, requester=ch["requester"])
    ch["publish"] = (publisher or publish)(profile, lid, actor=actor)
    return ch


def reject_change(profile: Profile, lid: str, cid: str, *, actor: str, comment: str) -> dict:
    ch = load_change(profile, lid, cid)
    if ch["status"] != "pending":
        raise EdlError(f"change is {ch['status']}")
    if not (comment or "").strip():
        raise EdlError("say why (the requester sees this comment)")
    ch.update(status="withdrawn" if actor == ch["requester"] else "rejected", reviewer=actor, reviewed_at=ts(),
              review_comment=comment.strip()[:500])
    with _locked(profile, lid):
        _write_json(_change_path(profile, lid, cid), ch)
    audit(profile, lid, actor, "reject", ch["status"], change=cid)
    return ch


def revert_plan(profile: Profile, lid: str, n: int, *, actor: str) -> Plan:
    """A plan that makes the list equal to version ``n`` again (re-added entries keep their original details)."""
    meta = load_meta(profile, lid)
    old = load_version(profile, lid, n)["entries"]
    cur_vals = {x["value"] for x in load_entries(profile, lid)}
    old_vals = {x["value"] for x in old}
    st = load_settings(profile)
    adds, blocked, appr = [], [], []
    for x in old:
        if x["value"] in cur_vals:
            continue
        lvl, why = classify(meta["type"], x["value"], st)
        c = Check(raw=x["value"], value=x["value"], level=lvl, why=why)
        if lvl == "blocked":
            blocked.append(c)
            continue
        if lvl == "approval":
            appr.append(c)
        adds.append({**x, "readded_by": actor, "readded_at": ts()})
    return Plan(adds, sorted(cur_vals - old_vals), [], blocked, appr, len(cur_vals & old_vals), [], [], [])


def sweep_expired(profile: Profile, lid: str, *, actor: str = "system") -> int | None:
    """Drop expired entries as a new version (feeds already leave them out). Returns the new version or None."""
    cur = load_entries(profile, lid)
    live = {id(x) for x in live_entries(cur)}
    gone = [x["value"] for x in cur if id(x) not in live]
    if not gone:
        return None
    return _apply(profile, lid, [], gone, actor=actor, reason="expired entries removed", source="expiry")


# ---------------------------------------------------------------- import / export / drafts

def parse_import(text: str, filename: str = "") -> tuple[list[str], list[dict] | None]:
    """Lines for a .txt paste or upload, or rows for a .csv (value, comment, expires_at, ticket; header optional)."""
    head = text.lstrip()[:200].lower()
    if filename.lower().endswith(".csv") or head.startswith(("value,", "entry,", "indicator,")):
        rows, header = [], None
        for r in csv.reader(io.StringIO(text)):
            if not r or not any(x.strip() for x in r):
                continue
            if header is None and r[0].strip().lower() in ("value", "entry", "ip", "domain", "url", "indicator"):
                header = [h.strip().lower() for h in r]
                continue
            cols = header or ["value", "comment", "expires_at", "ticket"]
            d = {(cols[i] if i < len(cols) else f"c{i}"): (r[i] or "").strip() for i in range(len(r))}
            v = next((d[k] for k in ("value", "entry", "ip", "domain", "url", "indicator") if d.get(k)), "")
            rows.append({"value": v, "comment": d.get("comment", ""), "expires_at": d.get("expires_at", "") or d.get("expires", ""),
                         "ticket": d.get("ticket", "")})
        return [], rows
    return text.splitlines(), None


def export_csv(entries: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["value", "comment", "expires_at", "ticket", "added_by", "added_at"])
    for x in entries:
        w.writerow([x.get(k, "") for k in ("value", "comment", "expires_at", "ticket", "added_by", "added_at")])
    return buf.getvalue()


def plan_to_dict(p: Plan) -> dict:
    def ck(c: Check) -> dict:
        return {"raw": c.raw, "value": c.value, "error": c.error, "level": c.level, "why": c.why}
    return {"adds": p.adds, "removes": p.removes, "invalid": [ck(c) for c in p.invalid], "blocked": [ck(c) for c in p.blocked],
            "needs_approval": [ck(c) for c in p.needs_approval], "unchanged": p.unchanged, "duplicates": p.duplicates,
            "notes": p.notes, "covered": [list(x) for x in p.covered]}


def plan_from_dict(d: dict) -> Plan:
    def ck(x: dict) -> Check:
        return Check(raw=x.get("raw", ""), value=x.get("value"), error=x.get("error"), level=x.get("level", "ok"), why=x.get("why", []))
    return Plan(d["adds"], d["removes"], [ck(x) for x in d["invalid"]], [ck(x) for x in d["blocked"]],
                [ck(x) for x in d["needs_approval"]], d["unchanged"], d["duplicates"], d["notes"], [tuple(x) for x in d["covered"]])


def save_draft(profile: Profile, lid: str, plan: Plan, **extra: Any) -> str:
    """Keep an import preview server-side so Confirm applies exactly what was shown."""
    d = list_dir(profile, lid) / "drafts"
    for old in d.glob("drf-*.json") if d.is_dir() else []:  # drafts older than a day are dropped
        if (now().timestamp() - old.stat().st_mtime) > 86400:
            old.unlink(missing_ok=True)
    did = "drf-" + secrets.token_hex(8)
    _write_json(d / f"{did}.json", {"plan": plan_to_dict(plan), "created": ts(), **extra})
    return did


def load_draft(profile: Profile, lid: str, did: str) -> dict:
    if not DRAFT_RE.match(did or ""):
        raise EdlError("bad preview id")
    d = _read_json(list_dir(profile, lid) / "drafts" / f"{did}.json")
    if not d:
        raise EdlError("this preview has expired; paste or upload the list again")
    return d


def drop_draft(profile: Profile, lid: str, did: str) -> None:
    if DRAFT_RE.match(did or ""):
        (list_dir(profile, lid) / "drafts" / f"{did}.json").unlink(missing_ok=True)


# ---------------------------------------------------------------- capacity

def capacity(profile: Profile) -> dict:
    """Entries across this customer's lists vs the PAN-OS limit for the chosen model family."""
    st = load_settings(profile)
    label, lip, ldom, lurl = MODEL_LIMITS.get(st["model"], MODEL_LIMITS["small"])
    totals = {"ip": 0, "domain": 0, "url": 0}
    lists = all_lists(profile)
    for m in lists:
        totals[m["type"]] += m["count"]
    limits = {"ip": lip, "domain": ldom, "url": lurl}
    warn = []
    for k, n in totals.items():
        if n >= limits[k]:
            warn.append(f"{TYPES[k]} entries across this customer's lists ({n:,}) reach the {label} limit of {limits[k]:,}. "
                        "The firewall skips entries over the limit.")
        elif n >= 0.8 * limits[k]:
            warn.append(f"{TYPES[k]} entries ({n:,}) are over 80% of the {label} limit ({limits[k]:,}).")
    if len(lists) > MAX_EDL_OBJECTS:
        warn.append(f"{len(lists)} lists: one firewall can use at most {MAX_EDL_OBJECTS} custom EDLs with unique sources.")
    return {"model": label, "totals": totals, "limits": limits, "warnings": warn, "lists": len(lists)}


# ---------------------------------------------------------------- hosted feed

def find_by_token(token: str) -> tuple[Profile, dict] | None:
    """The (customer profile, list meta) a hosted token belongs to, or None. Tokens are random and unique."""
    from panlab.customers import list_customers, load_profile

    if not TOKEN_RE.match(token or ""):
        return None
    for c in list_customers():
        try:
            prof = load_profile(c)
            ids = list_ids(prof)
        except Exception:  # noqa: BLE001
            continue
        for lid in ids:
            m = _read_json(list_dir(prof, lid) / "meta.json", {}) or {}
            tok = str((m.get("hosted") or {}).get("token") or "")
            if tok and secrets.compare_digest(tok, token):
                return prof, m
    return None


def hosted_url(profile: Profile, meta: dict, base: str = "") -> str:
    b = (load_settings(profile).get("public_base_url") or base or "").rstrip("/")
    return f"{b}/edl/{meta['hosted']['token']}.txt"


def ip_allowed(client_ip: str, allow: list[str]) -> bool:
    if not allow:
        return True
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for a in allow:
        v, _ = split_comment(a)
        try:
            if "-" in v:
                ver, lo, hi = ip_span(v)
                if ip.version == ver and lo <= int(ip) <= hi:
                    return True
            elif ip in ipaddress.ip_network(v, strict=False):
                return True
        except ValueError:
            continue
    return False


def hash_secret(pw: str) -> str:
    from panlab.web.auth import hash_password

    return hash_password(pw, 200_000)


def check_secret(pw: str, stored: str) -> bool:
    from panlab.web.auth import verify_password

    return bool(stored) and verify_password(pw, stored)


def record_fetch(profile: Profile, lid: str, client_ip: str, agent: str, status: int) -> None:
    """Keep the last 20 fetches (which firewall polled the list, when). At most one write a minute per client."""
    p = list_dir(profile, lid) / "fetches.json"
    data = _read_json(p, []) or []
    t = now()
    for row in data:
        if row.get("ip") == client_ip and row.get("status") == status:
            last = _parse_ts(row.get("ts"))
            if last and (t - last).total_seconds() < 60:
                return
            break
    data.insert(0, {"ts": t.isoformat(timespec="seconds"), "ip": client_ip, "agent": (agent or "")[:80], "status": status})
    try:
        _write_json(p, data[:20])
    except OSError:
        pass


def fetches(profile: Profile, lid: str) -> list[dict]:
    return _read_json(list_dir(profile, lid) / "fetches.json", []) or []


# ---------------------------------------------------------------- S3 publishing

def etc_dir() -> Path:
    return Path(os.environ.get("PANLAB_ETC_DIR", "/etc/panlab")) / "edl"


def env_name(lid: str, field_: str) -> str:
    return f"PANLAB_EDL_S3_{re.sub(r'[^A-Z0-9]', '_', lid.upper())}_{field_.upper()}"


def s3_secret(profile: Profile, lid: str, field_: str) -> str:
    """Per-list key, then per-customer key, from /etc/panlab/edl/<customer>.env, then the process environment."""
    vals: dict[str, str] = {}
    p = etc_dir() / f"{profile.name}.env"
    if p.is_file():
        for line in p.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                vals[k.strip()] = v.strip().strip('"').strip("'")
    for k in (env_name(lid, field_), f"PANLAB_EDL_S3_{field_.upper()}"):
        v = vals.get(k) or os.environ.get(k) or ""
        if v:
            return v
    return ""


def s3_creds_status(profile: Profile, lid: str) -> str:
    if s3_secret(profile, lid, "access_key") and s3_secret(profile, lid, "secret_key"):
        return "set on the server"
    return "not set: PAAT uses the server's default AWS credentials (for example an instance role)"


s3_client_factory = None  # tests put a fake S3 client here


def _s3(profile: Profile, meta: dict):
    if s3_client_factory is not None:
        return s3_client_factory(profile, meta)
    from panlab.offsite import s3_client

    s3 = meta["s3"]
    return s3_client(endpoint_url=s3.get("endpoint_url") or "", region=s3.get("region") or "",
                     path_style=bool(s3.get("path_style")), access_key=s3_secret(profile, meta["id"], "access_key"),
                     secret_key=s3_secret(profile, meta["id"], "secret_key"))


def _redact(msg: str, profile: Profile, lid: str) -> str:
    for f in ("access_key", "secret_key"):
        s = s3_secret(profile, lid, f)
        if s:
            msg = msg.replace(s, "***")
    return msg[:400]


def s3_describe(meta: dict) -> str:
    s3 = meta.get("s3") or {}
    return f"s3://{s3.get('bucket')}/{s3.get('key')} ({s3.get('endpoint_url') or 'AWS'})"


def s3_url(meta: dict) -> str:
    """What a firewall fetches for an S3-hosted list (virtual-hosted style on AWS, path style otherwise)."""
    s3 = meta.get("s3") or {}
    ep = (s3.get("endpoint_url") or "").rstrip("/")
    if ep:
        return f"{ep}/{s3.get('bucket')}/{s3.get('key')}"
    return f"https://{s3.get('bucket')}.s3.{s3.get('region') or 'us-east-1'}.amazonaws.com/{s3.get('key')}"


def validate_s3(d: dict) -> dict:
    out = {"enabled": bool(d.get("enabled")), "endpoint_url": str(d.get("endpoint_url") or "").strip().rstrip("/"),
           "region": str(d.get("region") or "").strip(), "bucket": str(d.get("bucket") or "").strip(),
           "key": str(d.get("key") or "").strip().lstrip("/"), "path_style": bool(d.get("path_style")),
           "verify": bool(d.get("verify", True))}
    if out["enabled"]:
        if not re.match(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", out["bucket"]):
            raise EdlError("S3 bucket: 3-63 lowercase letters, digits, dots and hyphens")
        if not out["key"] or not re.match(r"^[A-Za-z0-9!_.*'()/-]{1,512}$", out["key"]):
            raise EdlError("S3 key: the object path, for example edl/blocked-ips.txt")
        if out["endpoint_url"] and not re.match(r"^https?://[A-Za-z0-9.\-:\[\]]+$", out["endpoint_url"]):
            raise EdlError("endpoint URL looks like https://minio.example.net:9000 (leave blank for AWS)")
        if out["region"] and not re.match(r"^[a-z0-9-]{2,30}$", out["region"]):
            raise EdlError("region looks like us-east-1")
    return out


def _get(c, bucket: str, key: str) -> bytes | None:
    try:
        return c.get_object(Bucket=bucket, Key=key)["Body"].read()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None) or {}
        code = str((resp.get("Error") or {}).get("Code", ""))
        if code in ("NoSuchKey", "404", "NotFound") or type(exc).__name__ in ("NoSuchKey", "KeyError"):
            return None
        raise


def s3_status(profile: Profile, lid: str) -> dict:
    """The S3 object vs what PAAT has: in-sync, behind (needs a publish), changed-outside, missing, error or off."""
    meta = load_meta(profile, lid)
    s3 = meta.get("s3") or {}
    if not s3.get("enabled"):
        return {"state": "off"}
    last = (meta.get("publish") or {}).get("s3") or {}
    try:
        body = _get(_s3(profile, meta), s3["bucket"], s3["key"])
    except Exception as exc:  # noqa: BLE001
        return {"state": "error", "detail": _redact(f"{type(exc).__name__}: {exc}", profile, lid)}
    if body is None:
        return {"state": "missing", "detail": f"{s3_describe(meta)} does not exist yet; publish to create it"}
    h = sha256(body)
    if h == sha256(render_text(meta, load_entries(profile, lid)).encode()):
        return {"state": "in-sync", "sha256": h}
    if last.get("sha256") and h == last["sha256"]:
        return {"state": "behind", "sha256": h, "detail": "S3 still has the previous PAAT version; publish to update it"}
    return {"state": "changed-outside", "sha256": h, "body": body.decode("utf-8", "replace"),
            "detail": "the S3 object was changed outside PAAT (or was there before PAAT managed it)"}


def publish_s3(profile: Profile, lid: str, *, actor: str, force: bool = False) -> dict:
    """Atomic write: temp key, GET + SHA-256 check, copy over the real key, GET + SHA-256 again, delete the temp key.

    Refuses (state ``conflict``) when the live object changed outside PAAT since the last publish, unless ``force``:
    nobody's out-of-band edit is overwritten silently.
    """
    meta = load_meta(profile, lid)
    s3 = meta.get("s3") or {}
    text = render_text(meta, load_entries(profile, lid))
    data = text.encode()
    h = sha256(data)
    last = (meta.get("publish") or {}).get("s3") or {}
    res: dict[str, Any] = {"ts": ts(), "actor": actor, "target": s3_describe(meta), "version": meta["version"], "sha256": h,
                           "bytes": len(data), "lines": text.count("\n")}
    try:
        c = _s3(profile, meta)
        cur = _get(c, s3["bucket"], s3["key"])
        if cur is not None and sha256(cur) == h:
            res.update(ok=True, state="published", detail="already up to date (SHA-256 matches)")
        elif cur is not None and not force and sha256(cur) not in (last.get("sha256"), (meta.get("publish") or {}).get("s3_reviewed")):
            res.update(ok=False, state="conflict", detail="the S3 object changed outside PAAT (or existed before PAAT managed it). "
                       "Open the list: import it, or overwrite it on purpose.")
        else:
            meta_tags = {"sha256": h, "paat-version": str(meta["version"]), "paat-list": lid}
            tmp = f"{s3['key']}.paat-tmp-{secrets.token_hex(6)}"
            c.put_object(Bucket=s3["bucket"], Key=tmp, Body=data, ContentType="text/plain; charset=utf-8", Metadata=meta_tags)
            got = _get(c, s3["bucket"], tmp)
            if got is None or sha256(got) != h:
                c.delete_object(Bucket=s3["bucket"], Key=tmp)
                raise EdlError("the temp object did not read back identically; the live object was not touched")
            c.copy_object(Bucket=s3["bucket"], Key=s3["key"], CopySource={"Bucket": s3["bucket"], "Key": tmp},
                          ContentType="text/plain; charset=utf-8", MetadataDirective="REPLACE", Metadata=meta_tags)
            c.delete_object(Bucket=s3["bucket"], Key=tmp)
            ok, detail = True, "written atomically (temp key verified, then copied)"
            if s3.get("verify", True):
                got = _get(c, s3["bucket"], s3["key"])
                ok = got is not None and sha256(got) == h
                detail += "; GET + SHA-256 " + ("matches" if ok else "DIFFERS")
            res.update(ok=ok, state="published" if ok else "verify-failed", detail=detail)
        if res.get("ok"):
            try:
                head = c.head_object(Bucket=s3["bucket"], Key=s3["key"])
                res.update(etag=str(head.get("ETag", "")).strip('"'), version_id=head.get("VersionId") or "",
                           content_type=head.get("ContentType", ""))
            except Exception:  # noqa: BLE001
                pass
    except Exception as exc:  # noqa: BLE001
        res.update(ok=False, state="error", detail=_redact(f"{type(exc).__name__}: {exc}", profile, lid))
    pub = dict(load_meta(profile, lid).get("publish") or {})
    pub["s3"] = res
    update_meta(profile, lid, actor=actor, quiet=True, publish=pub)
    audit(profile, lid, actor, "publish-s3", res["state"], version=meta["version"], sha256=h, detail=str(res.get("detail", ""))[:300])
    return res


def publish(profile: Profile, lid: str, *, actor: str, force: bool = False) -> dict:
    """Publish the current version to every configured target. A PAAT-hosted list is live as soon as it is saved."""
    meta = load_meta(profile, lid)
    out: dict[str, Any] = {}
    if (meta.get("hosted") or {}).get("enabled"):
        text = render_text(meta, load_entries(profile, lid))
        out["hosted"] = {"ok": True, "state": "live", "ts": ts(), "version": meta["version"], "sha256": sha256(text.encode()),
                         "lines": text.count("\n")}
        pub = dict(meta.get("publish") or {})
        pub["hosted"] = out["hosted"]
        update_meta(profile, lid, actor=actor, quiet=True, publish=pub)
    if (meta.get("s3") or {}).get("enabled"):
        out["s3"] = publish_s3(profile, lid, actor=actor, force=force)
    return out


def s3_import_plan(profile: Profile, lid: str, *, actor: str, mode: str = "merge") -> tuple[Plan, int]:
    """Bring the S3 object's content into PAAT: ``merge`` adds what S3 has extra; ``replace`` makes PAAT equal S3."""
    stt = s3_status(profile, lid)
    if stt["state"] != "changed-outside":
        raise EdlError("S3 matches PAAT; nothing to import" if stt["state"] in ("in-sync", "behind") else
                       str(stt.get("detail") or stt["state"]))
    meta = load_meta(profile, lid)
    # Someone looked at this exact S3 content and chose to import it: the next publish may replace it.
    update_meta(profile, lid, actor=actor, quiet=True, publish={**(meta.get("publish") or {}), "s3_reviewed": stt["sha256"]})
    lines = [x for x in stt["body"].splitlines() if x.strip() and split_comment(x)[0] != PLACEHOLDER[meta["type"]]]
    p = plan_changes(profile, meta, load_entries(profile, lid), add_lines=lines, replace=(mode == "replace"), actor=actor,
                     comment="imported from S3")
    return p, len(lines)


# ---------------------------------------------------------------- firewall side (read-only helpers, refresh)

def object_name_ok(name: str) -> str:
    if not PAN_NAME_RE.match(name or "") or "'" in name:
        raise EdlError("object names: up to 63 letters, digits, space, . _ - (start with a letter or digit)")
    return name


def object_element(*, kind: str, name: str, url: str, recurring: str = "five-minute", description: str = "",
                   cert_profile: str = "", username: str = "", expand_domain: bool = False) -> str:
    """The PAN-OS ``external-list`` entry XML. A basic-auth password is never generated: enter it on the device."""
    from xml.sax.saxutils import escape, quoteattr

    object_name_ok(name)
    if kind not in TYPES:
        raise EdlError("unknown list type")
    if recurring not in RECURRING:
        raise EdlError("refresh must be five-minute, hourly or daily")
    if not re.match(r"^https?://[^\s<>\"']+$", url or ""):
        raise EdlError("the source URL must start with http:// or https://")
    if cert_profile and not url.startswith("https://"):
        raise EdlError("a certificate profile only applies to an https:// source")
    if username and not (url.startswith("https://") and cert_profile):
        raise EdlError("client authentication (basic auth) needs an https:// source and a certificate profile (PAN-OS rule)")
    rec = "<daily><at>03</at></daily>" if recurring == "daily" else f"<{recurring}/>"
    inner = f"<recurring>{rec}</recurring><url>{escape(url)}</url>"
    if description:
        inner += f"<description>{escape(description[:255])}</description>"
    if cert_profile:
        inner += f"<certificate-profile>{escape(object_name_ok(cert_profile))}</certificate-profile>"
    if username:
        inner += f"<auth><username>{escape(username[:63])}</username></auth>"
    if kind == "domain":
        inner += f"<expand-domain>{'yes' if expand_domain else 'no'}</expand-domain>"
    return f"<entry name={quoteattr(name)}><type><{kind}>{inner}</{kind}></type></entry>"


def object_set_commands(*, kind: str, name: str, url: str, where: str, recurring: str = "five-minute", description: str = "",
                        cert_profile: str = "", username: str = "", expand_domain: bool = False) -> list[str]:
    """CLI ``set`` commands. ``where``: 'device-group DG', 'shared', 'vsys vsys2', or '' (single-vsys firewall)."""
    object_name_ok(name)
    pre = (f"set {where} " if where else "set ") + f"external-list \"{name}\" type {kind}"
    cmds = [f"{pre} url \"{url}\"", f"{pre} recurring {recurring}" + (" at 03" if recurring == "daily" else "")]
    if description:
        cmds.append(f"{pre} description \"{description[:255]}\"")
    if cert_profile:
        cmds.append(f"{pre} certificate-profile \"{cert_profile}\"")
    if username:
        cmds += [f"{pre} auth username \"{username}\"", f"{pre} auth password   # type the password on the device"]
    if kind == "domain":
        cmds.append(f"{pre} expand-domain {'yes' if expand_domain else 'no'}")
    return cmds


def op_show(kind: str, name: str) -> str:
    from xml.sax.saxutils import escape
    return (f"<request><system><external-list><show><type><{kind}><name>{escape(object_name_ok(name))}</name></{kind}></type>"
            "</show></external-list></system></request>")


def op_refresh(kind: str, name: str) -> str:
    from xml.sax.saxutils import escape
    return (f"<request><system><external-list><refresh><type><{kind}><name>{escape(object_name_ok(name))}</name></{kind}></type>"
            "</refresh></external-list></system></request>")


def _members(el, tag: str) -> list[str]:
    n = el.find(tag) if el is not None else None
    return [(m.text or "").strip() for m in n.findall("member")] if n is not None else []


def find_references(config_root, lists: list[dict]) -> dict[str, list[dict]]:
    """From a Panorama or firewall running config: the EDL objects whose source URL points at each PAAT list
    (by hosted token, or by S3 bucket and key), where they live, which firewalls get them, and what uses them."""
    out: dict[str, list[dict]] = {m["id"]: [] for m in lists}
    scopes = []
    shared = config_root.find("./shared")
    if shared is not None:
        scopes.append(("shared", shared, []))
    for dg in config_root.findall("./devices/entry/device-group/entry"):
        scopes.append((f"device group {dg.get('name')}", dg, [d.get("name") for d in dg.findall("./devices/entry")]))
    for vs in config_root.findall("./devices/entry/vsys/entry"):
        scopes.append((f"vsys {vs.get('name')}", vs, []))

    def which(url: str) -> list[str]:
        hits = []
        for m in lists:
            tok = (m.get("hosted") or {}).get("token")
            s3 = m.get("s3") or {}
            if tok and f"/edl/{tok}.txt" in url:
                hits.append(m["id"])
            elif s3.get("bucket") and s3.get("key") and s3["bucket"] in url and url.split("?")[0].endswith("/" + s3["key"]):
                hits.append(m["id"])
        return hits

    objs = []
    for where, node, devs in scopes:
        for e in node.findall("./external-list/entry"):
            t = e.find("./type")
            kind_el = next(iter(t), None) if t is not None else None
            if kind_el is None:
                continue
            url = (kind_el.findtext("url") or "").strip()
            rec_el = kind_el.find("recurring")
            rec = next(iter(rec_el)).tag if rec_el is not None and len(rec_el) else ""
            for lid in which(url):
                objs.append({"list": lid, "object": e.get("name"), "where": where, "type": kind_el.tag, "url": url, "recurring": rec,
                             "devices": devs, "cert_profile": kind_el.findtext("certificate-profile") or "", "used_by": []})
    for o in objs:
        for where, node, _ in scopes:
            for rb in ("pre-rulebase", "post-rulebase", "rulebase"):
                for r in node.findall(f"./{rb}/security/rules/entry"):
                    fields = [f for f in ("source", "destination", "category") if o["object"] in _members(r, f)]
                    if fields:
                        o["used_by"].append({"kind": "security rule", "name": r.get("name"), "where": f"{where} {rb}",
                                             "field": "/".join(fields), "action": r.findtext("action") or "",
                                             "disabled": (r.findtext("disabled") or "no") == "yes"})
            for p in node.findall("./profiles/url-filtering/entry"):
                acts = [a for a in ("block", "alert", "allow", "continue", "override") if o["object"] in _members(p, a)]
                if acts:
                    o["used_by"].append({"kind": "URL filtering profile", "name": p.get("name"), "where": where, "field": "/".join(acts)})
            for p in node.findall("./profiles/spyware/entry"):
                if any(x.get("name") == o["object"] for x in p.findall("./botnet-domains/lists/entry")):
                    o["used_by"].append({"kind": "anti-spyware DNS policy", "name": p.get("name"), "where": where, "field": "lists"})
        out[o["list"]].append(o)
    return out


def parse_refresh_info(root) -> dict:
    """``request system external-list show`` (PAN-OS 11.1 XML: total-valid, total-ignored, total-invalid and
    valid-members; older text output is matched too). Returns valid, invalid, ignored, members, plus text fields when present."""
    txt = "".join(root.itertext()) if root is not None else ""
    info: dict[str, Any] = {"raw": txt.strip()[:3000]}
    if root is not None:
        for tag, key in (("total-valid", "valid"), ("total-invalid", "invalid"), ("total-ignored", "ignored"),
                         ("valid", "valid"), ("invalid", "invalid"), ("last-update", "last_update"),
                         ("next-update", "next_update"), ("status", "status")):
            v = root.findtext(f".//{tag}")
            if v and v.strip() and key not in info:
                info[key] = v.strip()
        members = [(m.text or "").strip() for m in root.findall(".//valid-members/member") if (m.text or "").strip()]
        if members:
            info["members"] = members[:200]
    pats = {"valid": r"Total valid entries\s*:\s*(\d+)", "invalid": r"Total invalid entries\s*:\s*(\d+)",
            "last_update": r"(?:Last updated|Last successful (?:update|fetch))[^:]*:\s*(.+)", "next_update": r"Next update[^:]*:\s*(.+)",
            "source": r"Source\s*:\s*(\S+)"}
    for k, p in pats.items():
        m = re.search(p, txt, re.I)
        if m and k not in info:
            info[k] = m.group(1).strip()
    return info


op_device_factory = None  # tests: callable(profile, target_name, serial, admin) -> object with .op(cmd) -> Element


def op_device(profile: Profile, target: str, *, serial: str | None = None, admin: bool = False):
    """An op-command device. Read-only key by default; ``admin`` for refresh (a ``request`` command)."""
    if op_device_factory is not None:
        return op_device_factory(profile, target, serial, admin)
    from panlab import liveconfig
    from panlab.sources import settings_for

    t = next((x for x in profile.targets if x.name == target), None)
    if t is None:
        raise EdlError(f"no target {target!r}")
    st = settings_for(profile, t, readonly=not admin)
    if not st.configured:
        raise EdlError(f"credentials for {t.name} are not set on the server")
    return liveconfig.XapiLiveDevice(st.host, st, serial=serial, label=f"{t.name}/{serial}" if serial else t.name)


def firewall_status(profile: Profile, kind: str, object_name: str, *, target: str, serial: str | None = None) -> dict:
    """What the firewall has loaded for an EDL object. Tries the read-only key, then the admin key (still read only)."""
    last = ""
    for admin in (False, True):
        try:
            root = op_device(profile, target, serial=serial, admin=admin).op(op_show(kind, object_name))
            return {"ok": True, **parse_refresh_info(root), "key": "admin" if admin else "read-only"}
        except Exception as exc:  # noqa: BLE001
            last = str(exc)[:300]
            if "not authorized" not in last.lower() and "403" not in last:
                break
    return {"ok": False, "error": last}


def firewall_refresh(profile: Profile, lid: str, kind: str, object_name: str, *, target: str, serial: str | None, actor: str) -> dict:
    try:
        root = op_device(profile, target, serial=serial, admin=True).op(op_refresh(kind, object_name))
        txt = " ".join("".join(root.itertext()).split())[:300]
        res = {"ok": (root.get("status") or "success") == "success", "detail": txt or "refresh requested"}
    except Exception as exc:  # noqa: BLE001
        res = {"ok": False, "detail": str(exc)[:300]}
    audit(profile, lid, actor, "firewall-refresh", "ok" if res["ok"] else "error", object=object_name, target=target,
          serial=serial or "", detail=res["detail"])
    return res


def firewall_limits(profile: Profile, *, target: str, serial: str | None = None) -> dict:
    """``show system state filter cfg.general.max-edl*``: the firewall's own EDL limits (read-only key)."""
    root = op_device(profile, target, serial=serial).op("<show><system><state><filter>cfg.general.max-edl*</filter></state></system></show>")
    txt = "".join(root.itertext())
    return {m.group(1): int(m.group(2)) for m in re.finditer(r"cfg\.general\.(max-edl[\w-]*):\s*(\d+)", txt)}


def references(profile: Profile) -> tuple[dict[str, list[dict]], dict[str, str], str]:
    """(refs per list id, serial -> hostname, error) from the live Panorama (or firewall) running config, read-only."""
    target, backend, _ = obj_target(profile)
    lists = [load_meta(profile, lid) for lid in list_ids(profile)]
    try:
        dev = op_device(profile, target)
        root = dev.op("<show><config><running></running></config></show>")
        cfg = root.find(".//result/config") if root.find(".//result/config") is not None else root.find(".//config")
        if cfg is None:
            return {m["id"]: [] for m in lists}, {}, "no config in the response"
        names: dict[str, str] = {}
        if backend == "panorama":
            try:
                for e in dev.op("<show><devices><all></all></devices></show>").findall(".//devices/entry"):
                    names[e.get("name") or ""] = e.findtext("hostname") or e.get("name") or ""
            except Exception:  # noqa: BLE001
                pass
        return find_references(cfg, lists), names, ""
    except Exception as exc:  # noqa: BLE001
        return {m["id"]: [] for m in lists}, {}, str(exc)[:300]


# ---------------------------------------------------------------- firewall object requests (approve / push)

def obj_target(profile: Profile) -> tuple[str, str, str]:
    """(target name, backend, device group or vsys) from the profile's ``edl:`` block, else its ``url_filter:`` block,
    else the first Panorama (or the only firewall)."""
    raw = dict(getattr(profile, "edl", None) or {})
    src = raw if raw.get("target") else dict(getattr(profile, "url_filter", None) or {})
    tgt = src.get("target") or next((t.name for t in profile.targets if t.type == "panorama"), profile.targets[0].name)
    t = next((x for x in profile.targets if x.name == tgt), None)
    if t is None:
        raise EdlError(f"edl.target {tgt!r} is not a target of {profile.name}")
    where = src.get("device_group") if t.type == "panorama" else (src.get("vsys") or "vsys1")
    return t.name, t.type, str(where or "")


def obj_xpath(backend: str, where: str, name: str) -> str:
    object_name_ok(name)
    if backend == "panorama":
        base = SHARED_XP if where == "shared" else DG_XP.format(dg=object_name_ok(where))
    else:
        base = VSYS_XP.format(vsys=object_name_ok(where or "vsys1"))
    return f"{base}/external-list/entry[@name='{name}']"


def _obj_dir(profile: Profile) -> Path:
    return _root(profile) / "_objects"


def list_object_requests(profile: Profile, lid: str | None = None) -> list[dict]:
    d = _obj_dir(profile)
    out = [_read_json(p, {}) for p in d.glob("obj-*.json")] if d.is_dir() else []
    out = [r for r in out if lid is None or r.get("list") == lid]
    return sorted(out, key=lambda r: r.get("id", ""), reverse=True)


def load_object_request(profile: Profile, rid: str) -> dict:
    if not OBJ_RE.match(rid or ""):
        raise EdlError("bad request id")
    r = _read_json(_obj_dir(profile) / f"{rid}.json")
    if not r:
        raise EdlError("no such request")
    return r


def _save_obj(profile: Profile, r: dict) -> None:
    _write_json(_obj_dir(profile) / f"{r['id']}.json", r)


def _ohist(r: dict, what: str, actor: str, **kw: Any) -> None:
    r.setdefault("history", []).append({"ts": ts(), "actor": actor, "what": what, **kw})


def create_object_request(profile: Profile, lid: str, *, actor: str, name: str, where: str, url: str, recurring: str = "five-minute",
                          description: str = "", cert_profile: str = "", username: str = "", expand_domain: bool = False) -> dict:
    meta = load_meta(profile, lid)
    target, backend, default_where = obj_target(profile)
    where = (where or default_where).strip()
    if backend == "panorama" and not where:
        raise EdlError("pick the device group (or shared) for the object")
    el = object_element(kind=meta["type"], name=name, url=url, recurring=recurring, description=description,
                        cert_profile=cert_profile, username=username, expand_domain=expand_domain)
    where_cli = ("shared" if where == "shared" else f"device-group {where}") if backend == "panorama" else (
        f"vsys {where}" if where and where != "vsys1" else "")
    rid = f"obj-{now():%Y%m%d-%H%M%S}-{secrets.token_hex(3)}"
    r = {"id": rid, "list": lid, "status": "pending", "requester": actor, "created": ts(), "target": target, "backend": backend,
         "where": where, "name": name, "url": url, "type": meta["type"], "recurring": recurring, "element": el,
         "xpath": obj_xpath(backend, where, name),
         "set_commands": object_set_commands(kind=meta["type"], name=name, url=url, where=where_cli, recurring=recurring,
                                             description=description, cert_profile=cert_profile, username=username,
                                             expand_domain=expand_domain)}
    _ohist(r, "requested", actor)
    _save_obj(profile, r)
    audit(profile, lid, actor, "object-request", "pending", request=rid, object=name, where=where, target=target)
    return r


def approve_object(profile: Profile, rid: str, dev, *, actor: str, cr: str, comment: str = "") -> dict:
    """Second person approves with a CR. Records what is there now (for rollback). ``dev``: urlfilter-style device."""
    import xml.etree.ElementTree as ET

    from panlab.pusher import check_cr, live_panorama_push_allowed

    r = load_object_request(profile, rid)
    if r["status"] != "pending":
        raise EdlError(f"request is {r['status']}")
    if actor == r["requester"]:
        raise EdlError("you cannot approve your own request; a second person must review it")
    cr = check_cr(profile, cr)
    before = dev.show(r["xpath"])
    live = r["backend"] == "firewall" or live_panorama_push_allowed(profile)
    r.update(status="approved", reviewer=actor, reviewed_at=ts(), review_comment=(comment or "")[:500], cr=cr,
             before=ET.tostring(before, encoding="unicode") if before is not None else "", mode="live" if live else "dry-run")
    _ohist(r, "approved", actor, cr=cr, mode=r["mode"])
    _save_obj(profile, r)
    audit(profile, r["list"], actor, "object-approve", "approved", request=rid, cr=cr, mode=r["mode"])
    return r


def reject_object(profile: Profile, rid: str, *, actor: str, comment: str) -> dict:
    r = load_object_request(profile, rid)
    if r["status"] not in ("pending", "approved"):
        raise EdlError(f"request is {r['status']}")
    if not (comment or "").strip():
        raise EdlError("say why")
    r.update(status="rejected", reviewer=actor, reviewed_at=ts(), review_comment=comment.strip()[:500])
    _ohist(r, "rejected", actor)
    _save_obj(profile, r)
    audit(profile, r["list"], actor, "object-reject", "rejected", request=rid)
    return r


def _commit_and_push(r: dict, dev, *, actor: str, label: str) -> tuple[bool, str]:
    from xml.sax.saxutils import quoteattr

    job = dev.commit(f"PAAT {r.get('cr', '')} EDL object {r['name']} {label} by {actor}")
    r.setdefault("jobs", []).append({"step": f"{label}-commit", **job})
    if not job.get("success"):
        try:
            dev.revert()
        except Exception:  # noqa: BLE001
            pass
        return False, "commit failed: " + "; ".join(job.get("messages") or ["unknown"]) + "; candidate reverted"
    if r["backend"] != "panorama":
        return True, "committed"
    dgs = [r["where"]] if r["where"] != "shared" else []
    if not dgs:
        return True, "committed on Panorama (shared object: push the device groups that use it)"
    pj = dev.commit_all(f"<commit-all><shared-policy><device-group><entry name={quoteattr(dgs[0])}/></device-group>"
                        "</shared-policy></commit-all>")
    r["jobs"].append({"step": f"{label}-push {dgs[0]}", **pj})
    if not pj.get("success"):
        return False, "committed on Panorama, but the device-group push failed: " + "; ".join(pj.get("messages") or ["unknown"])
    return True, f"committed on Panorama and pushed device group {dgs[0]}"


def _backup_before(profile: Profile, r: dict, dev, label: str) -> str:
    """Full running-config backup of the target before any write (refuses the write if it cannot be taken)."""
    fn = getattr(dev, "export_running", None) or getattr(getattr(dev, "dev", None), "export_running", None)
    if fn is None:
        raise EdlError("this device connection cannot take a backup; nothing was changed")
    try:
        xml = fn()
    except Exception as exc:  # noqa: BLE001
        raise EdlError(f"backup of {r['target']} failed, nothing was changed: {str(exc)[:200]}") from exc
    p = profile.data_dir("backups") / f"{r['target']}-edl-{label}-{now():%Y%m%d-%H%M%S}.xml"
    p.write_text(xml, encoding="utf-8")
    p.chmod(0o600)
    r.setdefault("backups", []).append(p.name)
    return p.name


def push_object(profile: Profile, rid: str, dev, *, actor: str, confirm_target: str) -> dict:
    from panlab.pusher import live_panorama_push_allowed

    r = load_object_request(profile, rid)
    if r["status"] != "approved":
        raise EdlError(f"request is {r['status']}; it must be approved first")
    if r["backend"] == "panorama" and not live_panorama_push_allowed(profile):
        raise EdlError("live Panorama push is off for this customer: add the object by hand with the set commands shown")
    if (confirm_target or "").strip() != r["target"]:
        raise EdlError("typed target does not match; nothing was changed")
    if dev.pending_changes():
        raise EdlError(f"{r['target']} has uncommitted changes from someone else; commit or revert them first")
    bk = _backup_before(profile, r, dev, "pre-push")
    _ohist(r, "backup taken", actor, file=bk)
    r["status"] = "pushing"
    _save_obj(profile, r)
    try:
        dev.edit(r["xpath"], r["element"])
        ok, msg = _commit_and_push(r, dev, actor=actor, label="push")
    except Exception as exc:  # noqa: BLE001
        try:
            dev.revert()
        except Exception:  # noqa: BLE001
            pass
        ok, msg = False, f"write failed: {str(exc)[:300]}; candidate reverted"
    if ok:
        got = dev.show(r["xpath"])
        ok = got is not None and (got.findtext(".//url") or "") == r["url"]
        msg += "; read back " + ("matches" if ok else "DIFFERS")
    r.update(status="pushed" if ok else "failed", pushed_by=actor, pushed_at=ts(), result=msg)
    _ohist(r, f"push finished ({r['status']})", actor, detail=msg)
    _save_obj(profile, r)
    if ok:
        update_meta(profile, r["list"], actor=actor, firewall={"object_name": r["name"], "device_group": r["where"],
                                                              "recurring": r["recurring"], "target": r["target"]})
    audit(profile, r["list"], actor, "object-push", r["status"], request=rid, cr=r.get("cr"), detail=msg[:300],
          job_ids=[j.get("jobid") for j in r.get("jobs", [])])
    return r


def rollback_object(profile: Profile, rid: str, dev, *, actor: str, confirm_target: str) -> dict:
    r = load_object_request(profile, rid)
    if r["status"] not in ("pushed", "failed"):
        raise EdlError(f"request is {r['status']}")
    if (confirm_target or "").strip() != r["target"]:
        raise EdlError("typed target does not match; nothing was changed")
    if dev.pending_changes():
        raise EdlError(f"{r['target']} has uncommitted changes from someone else")
    bk = _backup_before(profile, r, dev, "pre-rollback")
    _ohist(r, "backup taken", actor, file=bk)
    try:
        if r.get("before"):
            dev.edit(r["xpath"], r["before"])
        else:
            dev.delete(r["xpath"])
        ok, msg = _commit_and_push(r, dev, actor=actor, label="rollback")
    except Exception as exc:  # noqa: BLE001
        try:
            dev.revert()
        except Exception:  # noqa: BLE001
            pass
        ok, msg = False, f"rollback failed: {str(exc)[:300]} (if a rule still uses the object, remove it from the rule first)"
    r.update(status="rolled-back" if ok else "failed", rolled_back_by=actor, rollback_result=msg)
    _ohist(r, f"rollback finished ({r['status']})", actor, detail=msg)
    _save_obj(profile, r)
    audit(profile, r["list"], actor, "object-rollback", r["status"], request=rid, detail=msg[:300])
    return r


# ---------------------------------------------------------------- CLI: python -m panlab.edl sweep | status

def main(argv: list[str] | None = None) -> int:
    import argparse

    from panlab.customers import list_customers, load_profile

    ap = argparse.ArgumentParser(prog="python -m panlab.edl", description="PAAT EDL maintenance")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sweep", help="remove expired entries (as a new version) and republish; run from a timer")
    sub.add_parser("status", help="one line per list")
    a = ap.parse_args(argv)
    for c in list_customers():
        prof = load_profile(c)
        for lid in list_ids(prof):
            m = load_meta(prof, lid)
            if a.cmd == "sweep":
                v = sweep_expired(prof, lid)
                if v:
                    res = publish(prof, lid, actor="system")
                    states = ", ".join(f"{k}={x.get('state')}" for k, x in res.items())
                    print(f"{c}/{lid}: expired entries removed, version {v}, publish {states}")
            else:
                s3 = ((m.get("publish") or {}).get("s3") or {}).get("state", "-")
                print(f"{c}/{lid}: {m['type']} v{m['version']} {len(live_entries(load_entries(prof, lid)))} entries, s3 {s3}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
