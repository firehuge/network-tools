# SPDX-License-Identifier: Apache-2.0
"""Load a customer's configs: --config files, --live (read-only export), profile offline file, or cache.

All caches are under the customer's own data directory; one customer's run
never reads another customer's files.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from panlab.customers import Profile, Target
from panlab.netmodel import Environment, load_environment
from panlab.settings import Settings


def settings_for(profile: Profile, target: Target, *, readonly: bool = False) -> Settings:
    """Load target credentials. When ``readonly`` is true, prefer the RO API key."""
    if readonly:
        from panlab.liveconfig import settings_for_read
        st, _mode = settings_for_read(profile, target)
        return st
    profile.load_env()
    c = target.credentials()
    return Settings(host=c["host"], api_key=c["api_key"], username=c["username"], password=c["password"])


def fetch_live(profile: Profile, target: Target) -> Path:
    """Read-only export of the running config of one target into the customer's cache.

    Prefers a dedicated read-only API key when one is configured. For a full
    Panorama + managed-firewall snapshot (running, candidate, cache, rate
    limit), use ``panlab.liveconfig.refresh_snapshot``.
    """
    from panlab.backup import export_running_config

    s = settings_for(profile, target, readonly=True)
    if not s.configured:
        raise RuntimeError(f"target {target.name}: set {target.host_env} and {target.api_key_env or target.password_env} "
                           f"(customer env file {profile.env_file or 'not set'})")
    if target.type == "panorama":
        from panos.panorama import Panorama as Cls
    else:
        from panos.firewall import Firewall as Cls
    kw = {"hostname": s.host, "timeout": s.timeout}
    if s.uses_api_key:
        kw["api_key"] = s.api_key
    else:
        kw.update(api_username=s.username, api_password=s.password)
    try:
        xml = export_running_config(Cls(**kw))
    except Exception as exc:  # never echo secrets
        raise RuntimeError(s.redacted(f"target {target.name}: export failed: {exc}")) from exc
    cache = profile.data_dir("cache")
    stamp = datetime.now(ZoneInfo("America/Chicago")).strftime("%Y%m%d-%H%M%S")
    path = cache / f"{target.name}-{stamp}.xml"
    path.write_text(xml, encoding="utf-8")
    path.chmod(0o600)
    latest = cache / f"{target.name}-latest.xml"
    latest.write_text(xml, encoding="utf-8")
    latest.chmod(0o600)
    return path


def load_customer_envs(profile: Profile, *, configs: list[str] | None = None, live: bool = False,
                       backup_id: str | None = None) -> list[Environment]:
    """configs: 'target=path' or a bare path (only when the customer has one target).

    ``backup_id`` uses an uploaded backup file as the config for every target whose
    type matches the file (firewall vs Panorama). This is plan-only; the caller
    must refuse a later push.
    """
    by_target: dict[str, Path] = {}
    names = [t.name for t in profile.targets]
    for c in configs or []:
        if "=" in c and c.split("=", 1)[0] in names:
            t, p = c.split("=", 1)
        elif len(names) == 1:
            t, p = names[0], c
        else:
            raise ValueError(f"customer {profile.name} has several targets; use --config <target>=<path> ({', '.join(names)})")
        by_target[t] = Path(p).expanduser()
    backup_path = None
    backup_kind = None
    if backup_id:
        from panlab.uploads import get as get_upload
        rec = get_upload(profile, backup_id)
        backup_path = Path(rec["path"])
        backup_kind = rec.get("kind")
    envs = []
    for t in profile.targets:
        path = by_target.get(t.name)
        if path is None and backup_path is not None and (backup_kind in (None, t.type) or len(profile.targets) == 1):
            path = backup_path
        if path is None and live:
            path = fetch_live(profile, t)
        if path is None and t.offline_config:
            path = profile.resolve_path(t.offline_config)
        if path is None:
            cached = profile.data_dir("cache") / f"{t.name}-latest.xml"
            if cached.is_file():
                path = cached
        if path is None:
            raise FileNotFoundError(f"no config for target {t.name}: pass --config, --live, or set offline_config")
        env = load_environment(path, target=t.name, site_codes=profile.site_codes)
        if env.kind != t.type:
            raise ValueError(f"target {t.name} is type {t.type} but {path.name} is a {env.kind} config")
        envs.append(env)
    return envs


def stored_config_paths(profile: Profile) -> list[Path]:
    """Offline or cached config files for each target (never live)."""
    out = []
    for t in profile.targets:
        path = profile.resolve_path(t.offline_config) if t.offline_config else profile.data_dir("cache") / f"{t.name}-latest.xml"
        if path.is_file():
            out.append(path)
    return out


def list_customer_firewalls(profile: Profile) -> list[str]:
    """Hostnames of primary firewalls in the customer's offline/cached configs."""
    try:
        envs = load_customer_envs(profile)
    except (ValueError, FileNotFoundError):
        return []
    names: list[str] = []
    for env in envs:
        for d in env.devices:
            if d.ha_secondary or d.no_network or d.name in names:
                continue
            names.append(d.name)
    return names

