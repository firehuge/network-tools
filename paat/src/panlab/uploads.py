# SPDX-License-Identifier: Apache-2.0
"""Uploaded firewall / Panorama backup files used as a plan-only config source.

Files live under ``$PANLAB_DATA_DIR/<customer>/configs/`` (never under the
git repository). The XML itself is never logged; audit records keep only
the file name, sha256, size, kind, and uploader.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import tarfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from panlab.customers import (
    DEFAULT_NAMING,
    DEFAULT_TICKETS,
    NAME_RE,
    Profile,
    Target,
    customers_dir,
    data_root,
    load_profile,
    offline_customers_dir,
)
from panlab.paths import repo_root

TZ = ZoneInfo("America/Chicago")
ID_RE = re.compile(r"^cfg-\d{8}-\d{6}-[a-f0-9]{8}$")
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
MAX_BACKUP_DEFAULT = 200 * 1024 * 1024
EXTRACT_MEMBERS = 500
PLAN_ONLY = "plan only - built from a backup file"


class UploadError(ValueError):
    """User-facing error for a backup upload or lookup. Never includes XML."""


def max_backup_bytes() -> int:
    raw = (os.environ.get("PANLAB_MAX_BACKUP_BYTES") or "").strip()
    if raw.isdigit():
        return int(raw)
    return MAX_BACKUP_DEFAULT


def _now() -> datetime:
    return datetime.now(TZ)


def sanitize_filename(name: str) -> str:
    base = Path(name or "backup.xml").name
    base = SAFE_NAME.sub("_", base).strip("._") or "backup.xml"
    return base[:120]


def assert_outside_repo(path: Path) -> None:
    resolved = path.resolve()
    try:
        resolved.relative_to(repo_root())
    except ValueError:
        return
    raise UploadError("uploaded backups must be stored outside the git repository (set PANLAB_DATA_DIR)")


def _configs_dir(profile: Profile) -> Path:
    from panlab.customers import data_root
    assert_outside_repo(data_root())
    d = profile.data_dir("configs")
    assert_outside_repo(d)
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def _manifest_path(profile: Profile) -> Path:
    return _configs_dir(profile) / "manifest.json"


def _write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    assert_outside_repo(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    tmp.replace(path)
    os.chmod(path, mode)


def _write_text(path: Path, text: str, mode: int = 0o600) -> None:
    _write_bytes(path, text.encode("utf-8"), mode)


def _load_manifest(profile: Profile) -> list[dict]:
    p = _manifest_path(profile)
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    items = data.get("files") if isinstance(data, dict) else data
    return [x for x in (items or []) if isinstance(x, dict) and ID_RE.match(str(x.get("id") or ""))]


def _save_manifest(profile: Profile, items: list[dict]) -> None:
    _write_text(_manifest_path(profile), json.dumps({"files": items}, indent=2, sort_keys=True) + "\n")


def _audit(profile: Profile, **rec: Any) -> None:
    from panlab.pusher import audit

    rec.pop("xml", None)
    rec.pop("content", None)
    rec.pop("config", None)
    audit(profile, **rec)


def _xml_from_tar(data: bytes) -> bytes:
    """Return the PAN-OS XML inside a tarball, refusing traversal and bombs."""
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError as exc:
        raise UploadError(f"could not read archive: {exc.__class__.__name__}") from None
    picked: list[tuple[int, str, bytes]] = []
    total = 0
    with tf:
        members = tf.getmembers()
        if len(members) > EXTRACT_MEMBERS:
            raise UploadError("archive has too many members")
        for m in members:
            if not m.isfile() or m.issym() or m.islnk():
                continue
            name = m.name.replace("\\", "/")
            parts = Path(name).parts
            if m.name.startswith("/") or ".." in parts:
                continue
            if not name.lower().endswith(".xml"):
                continue
            if m.size and m.size > max_backup_bytes():
                raise UploadError("archive member is larger than the size limit")
            f = tf.extractfile(m)
            if f is None:
                continue
            chunk = f.read(max_backup_bytes() + 1)
            total += len(chunk)
            if total > max_backup_bytes() * 2:
                raise UploadError("extracted archive is larger than the size limit")
            if b"<config" not in chunk and b"<config " not in chunk:
                # still might be a namespaced or pretty-printed config; keep if parseable later
                if b"<config" not in chunk.replace(b" ", b""):
                    continue
            score = 0
            lower = Path(name).name.lower()
            if lower in {"running-config.xml", "candidate-config.xml", "panorama.xml"}:
                score = 2
            elif "running-config" in lower or "running_config" in lower:
                score = 1
            picked.append((score, lower, chunk))
    if not picked:
        raise UploadError("archive has no PAN-OS configuration XML")
    picked.sort(key=lambda x: (-x[0], x[1]))
    return picked[0][2]


def extract_xml(data: bytes, filename: str = "") -> bytes:
    """Return usable PAN-OS XML bytes from an .xml upload or a .tgz/.tar.gz bundle."""
    if len(data) > max_backup_bytes():
        raise UploadError(f"file is larger than {max_backup_bytes() // (1024 * 1024)} MB")
    name = (filename or "").lower()
    looks_xml = data.lstrip().startswith(b"<") or data.lstrip().startswith(b"\xef\xbb\xbf<")
    if name.endswith((".tgz", ".tar.gz", ".tar")) or (not looks_xml and not name.endswith(".xml")):
        if looks_xml and name.endswith(".xml"):
            return data
        try:
            return _xml_from_tar(data)
        except UploadError:
            if looks_xml or name.endswith(".xml"):
                return data
            raise
    if not looks_xml and not name.endswith(".xml"):
        raise UploadError("upload a .xml file or a .tgz / .tar.gz Panorama or device-state export")
    return data


def summarize_xml(data: bytes | Path) -> dict[str, Any]:
    """Parse a PAN-OS XML (defusedxml) and return counts. Never logs the XML."""
    from panlab.netmodel import load_environment

    try:
        env = load_environment(data, target="upload", label="upload")
    except ValueError as exc:
        raise UploadError(str(exc) or "could not parse configuration XML") from None
    except Exception:
        raise UploadError("could not parse configuration XML") from None
    vsys = 0
    addresses = len(env.shared.addresses) + len(env.shared.address_groups)
    rules = len(env.shared.security_rules)
    for dg in env.device_groups.values():
        addresses += len(dg.scope.addresses) + len(dg.scope.address_groups)
        rules += len(dg.scope.security_rules)
    for d in env.devices:
        vsys += len(d.vsys)
        for v in d.vsys.values():
            if v.scope:
                addresses += len(v.scope.addresses) + len(v.scope.address_groups)
                rules += len(v.scope.security_rules)
    return {
        "kind": env.kind,
        "hostname": env.hostname or "",
        "version": env.version or "",
        "vsys": vsys,
        "device_groups": len(env.device_groups),
        "template_stacks": len(env.stacks),
        "addresses": addresses,
        "rules": rules,
    }


def stored_path(profile: Profile, rec: dict) -> Path:
    return _configs_dir(profile) / f"{rec['id']}.xml"


def get(profile: Profile, ident: str) -> dict:
    expire(profile)
    for rec in _load_manifest(profile):
        if rec["id"] == ident or rec.get("sha256") == ident or rec.get("sha256", "").startswith(ident):
            p = stored_path(profile, rec)
            if p.is_file():
                rec = dict(rec)
                rec["path"] = str(p)
                return rec
    raise UploadError(f"no uploaded backup {ident!r} for customer {profile.name}")


def list_uploads(profile: Profile) -> list[dict]:
    expire(profile)
    out = []
    for rec in _load_manifest(profile):
        p = stored_path(profile, rec)
        if p.is_file():
            item = dict(rec)
            item["path"] = str(p)
            out.append(item)
    out.sort(key=lambda r: r.get("uploaded") or "", reverse=True)
    return out


def expire(profile: Profile) -> list[str]:
    """Delete uploads older than ``config_retention_days`` when that is set. Default: off."""
    days = int(getattr(profile, "config_retention_days", 0) or 0)
    if days <= 0:
        return []
    cutoff = _now() - timedelta(days=days)
    kept, gone = [], []
    for rec in _load_manifest(profile):
        ts = _parse_ts(rec.get("uploaded") or "")
        if ts is not None and ts < cutoff:
            _unlink(stored_path(profile, rec))
            gone.append(rec["id"])
            _audit(profile, action="config-expire", id=rec["id"], file=rec.get("original_name"),
                   sha256=rec.get("sha256"), uploaded_by=rec.get("uploaded_by"))
        else:
            kept.append(rec)
    if gone:
        _save_manifest(profile, kept)
    return gone


def _parse_ts(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ)
    return dt


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return


def store(profile: Profile, data: bytes, filename: str, *, uploaded_by: str) -> dict:
    """Save an uploaded backup, parse a summary, and append it to the manifest."""
    expire(profile)
    if len(data) > max_backup_bytes():
        raise UploadError(f"file is larger than {max_backup_bytes() // (1024 * 1024)} MB")
    safe = sanitize_filename(filename)
    xml = extract_xml(data, safe)
    if len(xml) > max_backup_bytes():
        raise UploadError(f"extracted configuration is larger than {max_backup_bytes() // (1024 * 1024)} MB")
    summary = summarize_xml(xml)
    sha = hashlib.sha256(xml).hexdigest()
    stamp = _now()
    ident = f"cfg-{stamp.strftime('%Y%m%d-%H%M%S')}-{sha[:8]}"
    rec = {
        "id": ident,
        "original_name": safe,
        "sha256": sha,
        "size": len(xml),
        "kind": summary["kind"],
        "hostname": summary["hostname"],
        "version": summary["version"],
        "vsys": summary["vsys"],
        "device_groups": summary["device_groups"],
        "template_stacks": summary["template_stacks"],
        "addresses": summary["addresses"],
        "rules": summary["rules"],
        "uploaded": stamp.isoformat(timespec="seconds"),
        "uploaded_by": uploaded_by,
    }
    dest = stored_path(profile, rec)
    if dest.exists():
        ident = f"cfg-{stamp.strftime('%Y%m%d-%H%M%S')}-{hashlib.sha256(os.urandom(8)).hexdigest()[:8]}"
        rec["id"] = ident
        dest = stored_path(profile, rec)
    _write_bytes(dest, xml, 0o600)
    items = _load_manifest(profile)
    items.append({k: v for k, v in rec.items() if k != "path"})
    _save_manifest(profile, items)
    _audit(profile, action="config-upload", id=ident, file=safe, sha256=sha, size=len(xml),
           kind=summary["kind"], uploaded_by=uploaded_by)
    rec["path"] = str(dest)
    return rec


def delete(profile: Profile, ident: str, *, actor: str) -> dict:
    rec = get(profile, ident)
    _unlink(stored_path(profile, rec))
    items = [x for x in _load_manifest(profile) if x["id"] != rec["id"]]
    _save_manifest(profile, items)
    _audit(profile, action="config-delete", id=rec["id"], file=rec.get("original_name"),
           sha256=rec.get("sha256"), actor=actor, uploaded_by=rec.get("uploaded_by"))
    return rec


def can_delete(rec: dict, user: str, role: str) -> bool:
    return role == "admin" or rec.get("uploaded_by") == user


def can_live_export(profile: Profile) -> bool:
    from panlab.liveconfig import can_live_pull

    return can_live_pull(profile)


def source_options(profile: Profile) -> list[dict[str, str]]:
    opts = [{"value": "cached", "label": "Cached / profile config"}]
    if can_live_export(profile):
        from panlab.liveconfig import cache_status
        st = cache_status(profile)
        label = "Live snapshot (read-only API pull of running and candidate config)"
        if st and st.get("pulled_at_label"):
            label += f" — cached {st['pulled_at_label']}"
            if st.get("used_admin_key"):
                label += " (used the admin API key; configure a read-only key if you can)"
        else:
            label += " — not cached yet; a pull runs when you use it"
        opts.append({"value": "live", "label": label})
    for rec in list_uploads(profile):
        when = format_uploaded(rec.get("uploaded") or "")
        opts.append({
            "value": f"backup:{rec['id']}",
            "label": f"Uploaded backup {rec['original_name']} ({rec['sha256'][:8]}, {rec['kind']}, {when})",
        })
    return opts


def source_meta(kind: str, rec: dict | None = None) -> dict[str, Any]:
    if kind == "backup" and rec is not None:
        return {
            "kind": "backup",
            "id": rec["id"],
            "file": rec.get("original_name") or rec["id"],
            "sha256": rec.get("sha256") or "",
            "sha8": (rec.get("sha256") or "")[:8],
            "uploaded": rec.get("uploaded") or "",
            "uploaded_by": rec.get("uploaded_by") or "",
            "config_kind": rec.get("kind") or "",
        }
    return {"kind": kind}


def source_label(cs_or_meta: dict) -> str:
    """Human line: 'Offline - from backup FILE (sha8) uploaded TIME'."""
    meta = cs_or_meta.get("config_source") if "config_source" in cs_or_meta else cs_or_meta
    if not meta or meta.get("kind") != "backup":
        return ""
    when = format_uploaded(meta.get("uploaded") or "")
    return f"Offline - from backup {meta.get('file') or meta.get('id')} ({meta.get('sha8') or (meta.get('sha256') or '')[:8]}) uploaded {when}"


def source_note(cs: dict) -> str:
    lab = source_label(cs)
    if not lab:
        return ""
    return f"**Config source:** {lab}\n\nThis plan is for review only ({PLAN_ONLY}). It cannot be pushed to a device."


def format_uploaded(raw: str) -> str:
    dt = _parse_ts(raw)
    if dt is None:
        return raw or "unknown time"
    return dt.astimezone(TZ).strftime("%Y-%m-%d %I:%M %p CST")


def is_plan_only(cs: dict) -> bool:
    if cs.get("plan_only"):
        return True
    src = cs.get("config_source") or {}
    return src.get("kind") == "backup"


def attach_source(cs: dict, meta: dict) -> dict:
    cs["config_source"] = meta
    if meta.get("kind") == "backup":
        cs["plan_only"] = True
    return cs


def refuse_push(cs: dict) -> None:
    if is_plan_only(cs):
        from panlab.pusher import PushError

        raise PushError(PLAN_ONLY)


def resolve_envs(profile: Profile, source: str = "cached", *, configs: list[str] | None = None):
    """Load environments for a GUI/CLI config-source token. Returns (envs, source meta)."""
    from panlab.sources import load_customer_envs

    src = (source or "cached").strip() or "cached"
    if src == "live":
        from panlab.liveconfig import ensure_snapshot, LiveError
        try:
            snap = ensure_snapshot(profile, refresh=False)
        except LiveError as exc:
            raise RuntimeError(str(exc)) from exc
        paths = snap.config_files()
        if paths:
            from panlab.netmodel import load_environment
            envs = []
            for path in paths:
                try:
                    envs.append(load_environment(path, target=profile.targets[0].name if profile.targets else "live", site_codes=profile.site_codes))
                except Exception:
                    continue
            if envs:
                meta = source_meta("live")
                meta["pulled_at"] = snap.meta.get("pulled_at")
                meta["credential_mode"] = snap.meta.get("credential_mode")
                return envs, meta
        return load_customer_envs(profile, configs=configs, live=True), source_meta("live")
    if src.startswith("backup:"):
        rec = get(profile, src.split(":", 1)[1])
        return load_customer_envs(profile, configs=configs, backup_id=rec["id"]), source_meta("backup", rec)
    if src not in ("cached", "cache", ""):
        # bare backup id is also accepted
        if ID_RE.match(src) or src.startswith("cfg-"):
            rec = get(profile, src)
            return load_customer_envs(profile, configs=configs, backup_id=rec["id"]), source_meta("backup", rec)
    return load_customer_envs(profile, configs=configs), source_meta("cached")


def paths_for_changeset(profile: Profile, cs: dict) -> list[Path]:
    from panlab.sources import stored_config_paths

    src = cs.get("config_source") or {}
    if src.get("kind") == "backup" and src.get("id"):
        try:
            rec = get(profile, src["id"])
        except UploadError:
            return stored_config_paths(profile)
        p = stored_path(profile, rec)
        return [p] if p.is_file() else stored_config_paths(profile)
    return stored_config_paths(profile)


def create_offline_customer(name: str, data: bytes, filename: str, *, uploaded_by: str,
                            display_name: str = "") -> tuple[Profile, dict]:
    """Write a generated profile from an upload so a backup can be used without editing YAML."""
    name = (name or "").strip().lower()
    if not NAME_RE.match(name):
        raise UploadError("offline customer name: lowercase letters, digits, hyphen and underscore, starting with a letter or digit")
    if (customers_dir() / name / "profile.yaml").is_file():
        raise UploadError(f"customer {name!r} already exists")
    off = offline_customers_dir() / name
    if (off / "profile.yaml").is_file():
        raise UploadError(f"offline customer {name!r} already exists")
    xml = extract_xml(data, sanitize_filename(filename))
    summary = summarize_xml(xml)
    display = (display_name or "").strip() or f"Offline {name} (from backup)"
    off.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(off, 0o700)
    except OSError:
        pass
    # Temporary profile so store() can write under the data dir.
    stub = Profile(
        name=name, path=off / "profile.yaml",
        targets=[Target(name="backup", type=summary["kind"])],
        display_name=display, origin="backup", naming=dict(DEFAULT_NAMING), tickets=dict(DEFAULT_TICKETS),
    )
    rec = store(stub, data, filename, uploaded_by=uploaded_by)
    yaml_text = _offline_profile_yaml(name, display, summary["kind"], rec["id"])
    _write_text(stub.path, yaml_text, 0o600)
    _audit(stub, action="offline-customer-create", customer=name, id=rec["id"],
           file=rec["original_name"], sha256=rec["sha256"], uploaded_by=uploaded_by)
    return load_profile(name), rec


def _offline_profile_yaml(name: str, display: str, kind: str, ident: str) -> str:
    import yaml

    body = {
        "name": name,
        "display_name": display,
        "origin": "backup",
        "targets": [{"name": "backup", "type": kind, "offline_config": f"data/configs/{ident}.xml"}],
        "naming": dict(DEFAULT_NAMING),
        "tickets": dict(DEFAULT_TICKETS),
        "default_tags": ["panlab"],
        "object_scope": "local",
        "combine_rules": True,
        "combine_across_tickets": True,
        "address_group_threshold": 5,
        "config_retention_days": 0,
    }
    return yaml.safe_dump(body, sort_keys=False)


