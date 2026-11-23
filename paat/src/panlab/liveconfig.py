"""Read-only live config snapshot: Panorama running/candidate plus managed firewalls.

Pulls are cached under the customer's data directory with a timestamp. A
refresh is rate-limited. Prefer a dedicated read-only API key when one is
configured; otherwise fall back to the existing admin key and record that
fact (never the secret). Nothing here writes to a device.
"""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Protocol
from zoneinfo import ZoneInfo

from panlab.customers import Profile, Target
from panlab.settings import PLACEHOLDER_KEY, PLACEHOLDER_PASSWORD, Settings

TZ = ZoneInfo("America/Chicago")
META_NAME = "meta.json"
SNAP_DIR = "live-snapshot"
DEFAULT_REFRESH_SECONDS = 60
SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def now() -> datetime:
    return datetime.now(TZ)


def refresh_seconds() -> int:
    raw = os.environ.get("PANLAB_LIVE_REFRESH_SECONDS", str(DEFAULT_REFRESH_SECONDS)).strip()
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_REFRESH_SECONDS


def snapshot_dir(profile: Profile) -> Path:
    d = profile.data_dir("cache") / SNAP_DIR
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


class LiveError(RuntimeError):
    """A live pull or test failed. The message must not contain secrets."""


class LiveDevice(Protocol):
    label: str

    def op(self, cmd: str) -> ET.Element: ...
    def export(self, category: str) -> bytes: ...
    def traffic_logs(self, query: str, nlogs: int) -> list[dict]: ...


DeviceFactory = Callable[..., LiveDevice]
device_factory: DeviceFactory | None = None


def settings_for_read(profile: Profile, target: Target) -> tuple[Settings, str]:
    """Settings for a read-only pull. Prefer the RO key; fall back to the admin key.

    Returns (settings, mode) where mode is ``readonly``, ``admin``, or ``password``.
    """
    profile.load_env()
    c = target.credentials()
    host = c.get("host") or ""
    ro = (c.get("api_key_ro") or "").strip()
    admin = (c.get("api_key") or "").strip()
    user = c.get("username") or ""
    password = c.get("password") or ""
    timeout_raw = os.environ.get("PANOS_TIMEOUT", "180").strip() or "180"
    try:
        timeout = int(timeout_raw)
    except ValueError:
        timeout = 180
    if ro and ro != PLACEHOLDER_KEY:
        return Settings(host=host, api_key=ro, timeout=timeout), "readonly"
    if admin and admin != PLACEHOLDER_KEY:
        return Settings(host=host, api_key=admin, timeout=timeout), "admin"
    return Settings(host=host, username=user, password=password, timeout=timeout), "password"


def can_live_pull(profile: Profile) -> bool:
    try:
        profile.load_env()
    except Exception:
        return False
    for t in profile.targets:
        st, _mode = settings_for_read(profile, t)
        if st.configured:
            return True
    return False


def _safe(name: str) -> str:
    return SAFE.sub("-", name.strip())[:80] or "device"


def _write_secret_file(path: Path, text: str) -> None:
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _config_xml(elem: ET.Element | None, raw: str | bytes | None = None) -> str:
    """Pull a <config> document out of an op/export result."""
    text = ""
    if raw is not None:
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", "replace")
        else:
            text = str(raw)
    if elem is not None and not text:
        text = ET.tostring(elem, encoding="unicode")
    text = (text or "").strip()
    if not text:
        raise LiveError("device returned an empty configuration")
    cfg = None
    try:
        root = ET.fromstring(text)
        cfg = root if root.tag == "config" or root.tag.endswith("}config") else root.find(".//config")
    except ET.ParseError:
        cfg = None
    if cfg is not None:
        text = ET.tostring(cfg, encoding="unicode")
    if "<config" not in text:
        raise LiveError("device export did not look like XML")
    if not text.strip().startswith("<?xml"):
        # Keep just the config element when wrapped.
        start = text.find("<config")
        text = text[start:]
        text = '<?xml version="1.0"?>\n' + text
    return text if text.endswith("\n") else text + "\n"


def _text(elem: ET.Element | None) -> str:
    if elem is None:
        return ""
    return "".join(elem.itertext()).strip()


def _redact(msg: str, secrets: list[str]) -> str:
    out = msg
    for s in secrets:
        if s and s not in {PLACEHOLDER_KEY, PLACEHOLDER_PASSWORD} and s in out:
            out = out.replace(s, "***")
    return out


class XapiLiveDevice:
    """pan-python XML API client. Secrets stay on the object and are never logged."""

    def __init__(self, hostname: str, settings: Settings, *, serial: str | None = None, label: str = "", vsys: str | None = None):
        import ssl

        import pan.xapi

        self._settings = settings
        self._key = settings.api_key or settings.password
        self.label = label or hostname
        self.serial = serial
        kw: dict = {"hostname": hostname, "timeout": max(settings.timeout, 60),
                    "ssl_context": ssl._create_unverified_context()}
        if serial:
            kw["serial"] = serial
        if vsys:
            kw["vsys"] = vsys
        if settings.uses_api_key:
            kw["api_key"] = settings.api_key
        else:
            kw["api_username"] = settings.username
            kw["api_password"] = settings.password
        self._x = pan.xapi.PanXapi(**kw)

    def op(self, cmd: str) -> ET.Element:
        import pan.xapi

        try:
            self._x.op(cmd=cmd)
        except pan.xapi.PanXapiError as exc:
            raise LiveError(_redact(str(exc), [self._key])) from None
        except Exception as exc:
            raise LiveError(_redact(f"{type(exc).__name__}: {exc}", [self._key])) from None
        doc = self._x.xml_document
        if isinstance(doc, bytes):
            doc = doc.decode("utf-8", "replace")
        try:
            return ET.fromstring(doc or "<response/>")
        except ET.ParseError as exc:
            raise LiveError(f"unreadable API response: {exc}") from None

    def export(self, category: str) -> bytes:
        import pan.xapi

        try:
            self._x.export(category=category)
        except pan.xapi.PanXapiError as exc:
            raise LiveError(_redact(str(exc), [self._key])) from None
        except Exception as exc:
            raise LiveError(_redact(f"{type(exc).__name__}: {exc}", [self._key])) from None
        res = getattr(self._x, "export_result", None)
        if isinstance(res, dict) and res.get("content"):
            c = res["content"]
            return c if isinstance(c, bytes) else str(c).encode()
        doc = self._x.xml_document or b""
        return doc if isinstance(doc, bytes) else str(doc).encode()

    def traffic_logs(self, query: str, nlogs: int) -> list[dict]:
        import pan.xapi

        try:
            self._x.log(log_type="traffic", nlogs=nlogs, filter=query, interval=2, timeout=120)
        except pan.xapi.PanXapiError as exc:
            raise LiveError(_redact(f"traffic log query failed: {exc}", [self._key])) from None
        except Exception as exc:
            raise LiveError(_redact(f"traffic log query failed: {type(exc).__name__}: {exc}", [self._key])) from None
        root = getattr(self._x, "element_root", None)
        if root is None:
            doc = self._x.xml_document
            if isinstance(doc, bytes):
                doc = doc.decode("utf-8", "replace")
            try:
                root = ET.fromstring(doc or "<response/>")
            except ET.ParseError:
                return []
        return [{c.tag: (c.text or "") for c in e} for e in root.findall(".//logs/entry")]


def connect(profile: Profile, target: Target | str, *, serial: str | None = None, vsys: str | None = None) -> LiveDevice:
    if isinstance(target, str):
        t = next((x for x in profile.targets if x.name == target), None)
        if t is None:
            raise LiveError(f"no target {target!r} in customer {profile.name}")
    else:
        t = target
    if device_factory is not None:
        return device_factory(profile, t, serial=serial, vsys=vsys)
    st, _mode = settings_for_read(profile, t)
    if not st.configured:
        raise LiveError(f"credentials for {t.name} are not set (env file {profile.env_file or 'not set'}); "
                        f"set {t.api_key_ro_env or t.api_key_env or 'the API key env'} for a read-only pull")
    label = f"{t.name}/{serial}" if serial else t.name
    return XapiLiveDevice(st.host, st, serial=serial, label=label, vsys=vsys)


@dataclass
class LiveSnapshot:
    customer: str
    pulled_at: datetime
    files: list[Path] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    rate_limited: bool = False
    retry_after: int = 0

    def config_files(self, *, use_candidate: bool = True) -> list[Path]:
        """XML configs the tracer should load.

        Policy comes from the Panorama running (and, if requested, differing
        candidate) config. A Panorama-managed firewall's own running config
        does not include pushed policy, so a non-serial export of a managed
        firewall target is skipped when a serial-named pull is present. The
        serial-named file is kept so FlowMapper can merge routes, interfaces
        and zones by filename serial.
        """
        recs = list(self.meta.get("files") or [])
        has_pano_running = any(r.get("role") == "running" and r.get("target_type") == "panorama" for r in recs)
        has_serial_fw = any(r.get("role") == "running" and r.get("serial") for r in recs)
        out: list[Path] = []
        seen: set[str] = set()
        for rec in recs:
            path = Path(rec.get("path") or "")
            role = rec.get("role")
            if role in {"fib", None} and path.suffix.lower() != ".xml":
                continue
            if role == "fib":
                continue
            if role == "candidate" and not (use_candidate and rec.get("differs")):
                continue
            if (has_pano_running and has_serial_fw and role == "running"
                    and rec.get("target_type") == "firewall" and not rec.get("serial")):
                continue
            if path.is_file() and str(path) not in seen:
                seen.add(str(path))
                out.append(path)
        if not out:
            out = [p for p in self.files if p.is_file() and p.suffix == ".xml"]
        return out


def _meta_path(profile: Profile) -> Path:
    return snapshot_dir(profile) / META_NAME


def load_meta(profile: Profile) -> dict | None:
    path = _meta_path(profile)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def cache_status(profile: Profile) -> dict | None:
    """Public status for the UI. No secrets."""
    meta = load_meta(profile)
    if not meta:
        return None
    pulled = _parse_ts(meta.get("pulled_at") or "")
    age = int((now() - pulled).total_seconds()) if pulled else None
    wait = 0
    if pulled:
        left = refresh_seconds() - (age or 0)
        wait = max(0, left)
    return {
        "pulled_at": meta.get("pulled_at"),
        "pulled_at_label": _label(pulled) if pulled else None,
        "age_seconds": age,
        "retry_after": wait,
        "can_refresh": wait == 0,
        "credential_mode": meta.get("credential_mode") or "admin",
        "used_admin_key": bool(meta.get("used_admin_key")),
        "pending_changes": meta.get("pending_changes") or {},
        "devices": meta.get("devices") or [],
        "errors": meta.get("errors") or [],
        "file_count": len(meta.get("files") or []),
        "targets": [t.get("name") for t in (meta.get("targets") or [])],
        "policy_source": meta.get("policy_source") or "",
    }


def _parse_ts(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ)
    return dt.astimezone(TZ)


def _label(dt: datetime) -> str:
    return dt.astimezone(TZ).strftime("%Y-%m-%d %I:%M %p CST")


def rate_limited(profile: Profile) -> tuple[bool, int]:
    meta = load_meta(profile)
    if not meta:
        return False, 0
    pulled = _parse_ts(meta.get("pulled_at") or "")
    if pulled is None:
        return False, 0
    left = refresh_seconds() - int((now() - pulled).total_seconds())
    if left > 0:
        return True, left
    return False, 0


def load_cached_snapshot(profile: Profile) -> LiveSnapshot | None:
    meta = load_meta(profile)
    if not meta:
        return None
    pulled = _parse_ts(meta.get("pulled_at") or "") or now()
    files = [Path(f["path"]) for f in (meta.get("files") or []) if f.get("path")]
    return LiveSnapshot(customer=profile.name, pulled_at=pulled, files=files, meta=meta)


def _pending(dev: LiveDevice) -> bool | None:
    try:
        res = dev.op("<check><pending-changes></pending-changes></check>")
    except LiveError:
        return None
    return _text(res).strip().lower() == "yes"


def _devices_all(pano: LiveDevice) -> list[dict]:
    try:
        res = pano.op("<show><devices><all></all></devices></show>")
    except LiveError:
        return []
    out = []
    for e in res.findall(".//devices/entry"):
        serial = e.get("name") or _text(e.find("serial"))
        out.append({
            "serial": serial,
            "hostname": _text(e.find("hostname")) or serial,
            "connected": _text(e.find("connected")).lower() in {"yes", "connected", "1", "true"},
            "sw_version": _text(e.find("sw-version")),
            "ha": _text(e.find("ha/state")) or _text(e.find("ha-state")),
        })
    return out


def _op_config(dev: LiveDevice, which: str) -> str:
    if which == "candidate":
        cmd = "<show><config><candidate></candidate></config></show>"
    else:
        cmd = "<show><config><running></running></config></show>"
    res = dev.op(cmd)
    return _config_xml(res)


def _export_running(dev: LiveDevice) -> str:
    raw = dev.export("configuration")
    return _config_xml(None, raw)


def _fib_summary(dev: LiveDevice) -> str | None:
    for cmd in (
        "<show><routing><fib></fib></routing></show>",
        "<show><routing><summary></summary></routing></show>",
    ):
        try:
            res = dev.op(cmd)
            text = _text(res)
            if text:
                return text[:100_000]
        except LiveError:
            continue
    return None


def refresh_snapshot(profile: Profile, *, force: bool = False) -> LiveSnapshot:
    """Pull a fresh snapshot, or return the cache if the rate limit still applies."""
    limited, wait = rate_limited(profile)
    if limited and not force:
        snap = load_cached_snapshot(profile)
        if snap is not None:
            snap.rate_limited = True
            snap.retry_after = wait
            return snap
    errors: list[str] = []
    files_meta: list[dict] = []
    devices: list[dict] = []
    pending: dict[str, bool] = {}
    modes: list[str] = []
    dest = snapshot_dir(profile)
    pulled = now()

    def add_file(name: str, xml: str, *, role: str, target: str, serial: str = "",
                 differs: bool | None = None, target_type: str = "") -> Path:
        path = dest / name
        _write_secret_file(path, xml)
        rec = {"name": name, "path": str(path), "role": role, "target": target, "serial": serial,
               "target_type": target_type}
        if differs is not None:
            rec["differs"] = differs
        files_meta.append(rec)
        return path

    for t in profile.targets:
        st, mode = settings_for_read(profile, t)
        if not st.configured:
            errors.append(f"{t.name}: no API credentials configured")
            continue
        modes.append(mode)
        try:
            dev = connect(profile, t)
        except LiveError as exc:
            errors.append(f"{t.name}: {exc}")
            continue
        try:
            running = _export_running(dev)
            add_file(f"{_safe(t.name)}-running.xml", running, role="running", target=t.name, target_type=t.type)
        except LiveError as exc:
            # export can fail on some boxes; fall back to op
            try:
                running = _op_config(dev, "running")
                add_file(f"{_safe(t.name)}-running.xml", running, role="running", target=t.name, target_type=t.type)
            except LiveError as exc2:
                errors.append(f"{t.name} running: {exc}; {exc2}")
                running = ""
        pend = _pending(dev)
        if pend is not None:
            pending[t.name] = pend
        try:
            candidate = _op_config(dev, "candidate")
            differs = bool(running) and candidate != running
            add_file(f"{_safe(t.name)}-candidate.xml", candidate, role="candidate", target=t.name, differs=differs, target_type=t.type)
            if differs:
                pending.setdefault(t.name, True)
        except LiveError as exc:
            errors.append(f"{t.name} candidate: {exc}")
        if t.type == "panorama":
            members = _devices_all(dev)
            devices.extend(members)
            for m in members:
                if not m.get("serial"):
                    continue
                if not m.get("connected"):
                    errors.append(f"{m.get('hostname') or m['serial']}: not connected; skipped running-config pull")
                    continue
                try:
                    fw = connect(profile, t, serial=m["serial"])
                    xml = _op_config(fw, "running")
                    add_file(f"fw-{_safe(m['serial'])}-running.xml", xml, role="running",
                             target=t.name, serial=m["serial"], target_type="firewall")
                    fib = _fib_summary(fw)
                    if fib:
                        fib_path = dest / f"fw-{_safe(m['serial'])}-fib.txt"
                        _write_secret_file(fib_path, fib)
                        files_meta.append({"name": fib_path.name, "path": str(fib_path), "role": "fib",
                                           "target": t.name, "serial": m["serial"]})
                except LiveError as exc:
                    errors.append(f"{m.get('hostname') or m['serial']} running via Panorama: {exc}")

    used_admin = any(m != "readonly" for m in modes) if modes else False
    cred_mode = "readonly" if modes and all(m == "readonly" for m in modes) else (
        "mixed" if "readonly" in modes and used_admin else (modes[0] if modes else "none"))
    policy_source = "panorama" if any(t.type == "panorama" for t in profile.targets) else "firewall"
    meta = {
        "customer": profile.name,
        "pulled_at": pulled.isoformat(timespec="seconds"),
        "policy_source": policy_source,
        "credential_mode": cred_mode,
        "used_admin_key": used_admin,
        "pending_changes": pending,
        "targets": [{"name": t.name, "type": t.type} for t in profile.targets],
        "devices": devices,
        "files": files_meta,
        "errors": errors,
        "rate_limit_seconds": refresh_seconds(),
    }
    _write_secret_file(_meta_path(profile), json.dumps(meta, indent=2))
    return LiveSnapshot(
        customer=profile.name,
        pulled_at=pulled,
        files=[Path(f["path"]) for f in files_meta],
        meta=meta,
    )


def ensure_snapshot(profile: Profile, *, refresh: bool = False) -> LiveSnapshot:
    """Return a usable snapshot, refreshing when asked or when none is cached."""
    if refresh:
        return refresh_snapshot(profile, force=False)
    cached = load_cached_snapshot(profile)
    if cached is not None and cached.config_files():
        return cached
    return refresh_snapshot(profile, force=False)
