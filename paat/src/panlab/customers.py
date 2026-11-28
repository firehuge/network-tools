# SPDX-License-Identifier: Apache-2.0
"""Per-customer profiles, data directories, and target credentials.

A customer is one environment: only standalone firewalls, only Panorama,
or a mix. Each lives in ``customers/<name>/profile.yaml`` (no secrets):

    name: example
    targets:
      - name: fw-1
        type: firewall            # firewall | panorama
        host_env: PANOS_HOST      # env var names, never values
        api_key_env: PANOS_API_KEY
        api_key_ro_env: PANOS_API_KEY_RO  # optional read-only key (live pulls)
        offline_config: null      # optional path (profile-relative)
    env_file: ~/panlab/.env       # per-customer secrets, outside the repo
    vpn_landing_zones: [Tunnel]
    naming: {rule: "{project}-{dst}-{port}", ...}
    tickets: {ritm: 'RITM\\d+', sctask: 'SCTASK\\d+', cr: '(?:CHG|CR)\\d+'}
    default_tags: [panlab]

Caches, changesets, and reports go to ``$PANLAB_DATA_DIR/<customer>/``
(default ``~/panlab/data/<customer>/``), never into the repo. Nothing in
one customer's run can read another customer's cache or objects.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from panlab.paths import etc_dir, repo_root

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")

DEFAULT_NAMING = {
    "rule": "{project}-{dst}-{port}",
    "address_host": "H-{ip}",
    "address_net": "N-{ip}_{len}",
    "address_range": "R-{start}-{end}",
    "fqdn": "FQDN-{fqdn}",
    "service": "{proto}-{port}",
    "ticket_tag": "{ticket}",
    "address_group": "{project}-{dst}-SRV-GRP",
    "address_group_source": "{project}-{src}-SRC-GRP",
    "max_rule_len": 63,
}
DEFAULT_TICKETS = {"ritm": r"RITM\d+", "sctask": r"SCTASK\d+", "cr": r"(?:CHG|CR)\d+",
                   "project": r"(?:PRJ|PROJ|PRJT)[-_]?\d{4,}"}
DEFAULT_CHANGE_PLAN = {
    "log_forwarding": "LOG-FWD-DEFAULT",
    "profile_group": "PROFILE-GROUP-DEFAULT",
    # Security profile group applied to every NEW allow rule PAAT generates or pushes. Blank = none. Unlike
    # ``profile_group`` (a label printed in the CR text) this one is written into the rule, so it must already exist
    # on the firewall or Panorama (device group or shared) or the commit fails.
    "rule_profile_group": "",
    "profile_type": "Group",
    "log_at_session_start": "No",
    "log_at_session_end": "Yes",
    "url_category": "any",
    "team_name": "the network team",
    "impact_analysis": (
        "This change adds or updates security policy for the requested traffic only. "
        "Existing production traffic is not intended to be affected. The commit is limited "
        "to the targets listed in this plan."
    ),
    "backout_plan": "",
    "validation_plan": (
        "After commit, confirm each new or edited rule is present, run "
        "`test security-policy-match` for a sample of the traffic, and have the requester "
        "confirm the application works. See the Verification section."
    ),
    "communications_plan": (
        "{team_name} will notify stakeholders before the change window and confirm when "
        "the change is complete."
    ),
    "decom_impact_analysis": (
        "This change removes decommissioned address objects, address groups, and/or security, NAT, or PBF "
        "policies, and removes those objects from remaining policies. Traffic that depended on the removed "
        "rules or objects will no longer match those rules and may be denied (or hit a lower rule). Existing "
        "unrelated policy is not intended to be changed. The commit is limited to the targets listed in this plan."
    ),
    "decom_validation_plan": (
        "After commit, confirm each deleted object and rule is gone, confirm edited rules and groups no longer "
        "list the removed members, and have the requester confirm the decommissioned systems no longer need "
        "the access. See the Verification section."
    ),
    "decom_backout_plan": "",
}


@dataclass
class Target:
    name: str
    type: str  # firewall | panorama
    host_env: str = ""
    api_key_env: str = ""
    api_key_ro_env: str = ""  # optional; preferred for read-only live pulls
    user_env: str = ""
    password_env: str = ""
    offline_config: str | None = None
    vsys: list[str] = field(default_factory=list)
    # How OS upgrades reach a firewall (panlab.upgrade.paths): auto = through its Panorama when a
    # Panorama in this customer manages it, else its own API; panorama = never its own API;
    # direct = its own API (refused for a Panorama-managed firewall unless allow_direct_managed).
    access: str = "auto"

    def credentials(self) -> dict[str, str]:
        """Read credentials from the environment. Values are never logged."""
        get = lambda k: os.environ.get(k, "").strip() if k else ""
        return {"host": get(self.host_env), "api_key": get(self.api_key_env),
                "api_key_ro": get(self.api_key_ro_env),
                "username": get(self.user_env), "password": get(self.password_env)}


@dataclass
class Profile:
    name: str
    path: Path
    targets: list[Target]
    display_name: str = ""
    env_file: str | None = None
    vpn_landing_zones: list[str] = field(default_factory=list)
    naming: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_NAMING))
    tickets: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_TICKETS))
    default_tags: list[str] = field(default_factory=list)
    known_apps: list[str] = field(default_factory=list)  # extra App-ID names the FCR App column may use
    object_scope: str = "local"  # local (device group / vsys) | shared
    broad_prefix_len: int = 8
    mgmt_ports: list[int] = field(default_factory=lambda: [22, 3389, 5900])
    change_plan: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_CHANGE_PLAN))
    combine_rules: bool = True
    combine_across_tickets: bool = True
    address_group_threshold: int = 5
    config_retention_days: int = 0  # 0 = keep uploads until deleted
    origin: str = "profile"  # profile | backup
    # Live Panorama apply is off by default. Only a customer that sets this
    # (committed profile and/or /etc/panlab/customers/<name>.yaml) may use it.
    allow_live_panorama_push: bool = False
    # URL filter self-service (see panlab.urlfilter): off unless the profile has a url_filter block.
    url_filter: dict[str, Any] = field(default_factory=dict)
    # EDL manager (see panlab.edl): where EDL objects go (target, device_group / vsys). Optional.
    edl: dict[str, Any] = field(default_factory=dict)
    # Emergency/test only: allow OS upgrades and config pushes straight to a firewall that a
    # Panorama manages. Off by default; every use is audited. Server override file wins.
    allow_direct_managed: bool = False
    # Optional second-person approval for FCR and push. Off by default. A server override file wins.
    two_person_approval: bool = False
    # Tokens that name a site in vsys / device-group names (for example dc1, dc2).
    # Empty by default: no city or site name is built in. A server override file wins.
    site_codes: list[str] = field(default_factory=list)

    @property
    def kinds(self) -> set[str]:
        return {t.type for t in self.targets}

    def resolve_path(self, p: str) -> Path:
        if str(p).startswith("data/"):
            return (self.data_dir() / str(p)[5:]).resolve()
        q = Path(os.path.expanduser(p))
        return q if q.is_absolute() else (self.path.parent / q).resolve()

    def data_dir(self, sub: str = "") -> Path:
        d = data_root() / self.name / sub if sub else data_root() / self.name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def load_env(self) -> None:
        """Load this customer's secrets file (outside the repo) into the environment."""
        if not self.env_file:
            return
        from dotenv import load_dotenv

        f = Path(os.path.expanduser(self.env_file))
        if f.is_file():
            load_dotenv(f, override=False)


def data_root() -> Path:
    """Customer data (changesets, uploads, cache). Override with PANLAB_DATA_DIR for containers."""
    return Path(os.environ.get("PANLAB_DATA_DIR") or Path.home() / "panlab" / "data")


def customers_dir() -> Path:
    return Path(os.environ.get("PANLAB_CUSTOMERS_DIR") or repo_root() / "customers")


def offline_customers_dir() -> Path:
    """Generated ad-hoc profiles (from an uploaded backup). Never under the repo by default."""
    return Path(os.environ.get("PANLAB_OFFLINE_CUSTOMERS_DIR") or data_root() / "offline-customers")


def profile_yaml(name: str) -> Path | None:
    """Committed profile first, then an ad-hoc offline profile."""
    for d in (customers_dir(), offline_customers_dir()):
        p = d / name / "profile.yaml"
        if p.is_file():
            return p
    return None


def _override_paths(name: str) -> list[Path]:
    """Local files that may overlay ``change_plan`` values. Never committed.

    ``customers/<name>/profile.local.yaml`` (gitignored) and
    ``/etc/panlab/customers/<name>.yaml`` (or ``$PANLAB_CUSTOMER_OVERRIDE_DIR/<name>.yaml``).
    Later files win.
    """
    paths = [customers_dir() / name / "profile.local.yaml"]
    extra = os.environ.get("PANLAB_CUSTOMER_OVERRIDE_DIR")
    paths.append(Path(extra) / f"{name}.yaml" if extra else etc_dir() / "customers" / f"{name}.yaml")
    return paths


def rule_profile_group(profile: "Profile | None") -> str:
    """Profile group for new allow rules from the customer's change_plan (blank = none)."""
    from panlab.flowmapper import clean_profile_group
    cfg = getattr(profile, "change_plan", None) or {}
    return clean_profile_group(cfg.get("rule_profile_group"))


def resolve_change_plan(raw_block: dict[str, Any] | None, name: str) -> dict[str, Any]:
    """Merge generic defaults, committed profile ``change_plan``, then local overrides."""
    out = dict(DEFAULT_CHANGE_PLAN)
    if isinstance(raw_block, dict):
        out.update({k: v for k, v in raw_block.items() if v is not None})
    for p in _override_paths(name):
        if not p.is_file():
            continue
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            continue
        block = data.get("change_plan", data if "log_forwarding" in data or "profile_group" in data else {})
        if isinstance(block, dict):
            out.update({k: v for k, v in block.items() if v is not None})
    team = str(out.get("team_name") or DEFAULT_CHANGE_PLAN["team_name"])
    comms = str(out.get("communications_plan") or "")
    out["communications_plan"] = comms.replace("{team_name}", team)
    return out



def _resolve_flag(raw: dict[str, Any], name: str, as_bool, key: str) -> bool:
    """Default off. Committed profile can opt in; a server override file wins."""
    flag = as_bool(raw.get(key), False)
    for p in _override_paths(name):
        if not p.is_file():
            continue
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if isinstance(data, dict) and key in data:
            flag = as_bool(data.get(key), False)
    return flag


def _resolve_live_pano_flag(raw: dict[str, Any], name: str, as_bool) -> bool:
    return _resolve_flag(raw, name, as_bool, "allow_live_panorama_push")


def _resolve_site_codes(raw: dict[str, Any], name: str) -> list[str]:
    """Committed profile first; a server override or profile.local.yaml replaces the list if it sets site_codes."""
    from panlab.netmodel import normalize_site_codes
    codes = normalize_site_codes(raw.get("site_codes"))
    for p in _override_paths(name):
        if not p.is_file():
            continue
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if isinstance(data, dict) and "site_codes" in data:
            codes = normalize_site_codes(data.get("site_codes"))
    return codes


ACCESS_MODES = ("auto", "panorama", "direct")


def _access(t: dict[str, Any]) -> str:
    a = str(t.get("access") or "auto").strip().lower()
    if a not in ACCESS_MODES:
        raise ValueError(f"target {t.get('name')!r}: access must be one of {', '.join(ACCESS_MODES)}")
    if a == "panorama" and t.get("type") == "panorama":
        raise ValueError(f"target {t.get('name')!r}: a Panorama is always reached on its own API (access: auto or direct)")
    return a


def list_customers() -> list[str]:
    names: set[str] = set()
    for d in (customers_dir(), offline_customers_dir()):
        if d.is_dir():
            names.update(p.parent.name for p in d.glob("*/profile.yaml"))
    return sorted(names)


def load_profile(name: str) -> Profile:
    if not NAME_RE.match(name or ""):
        raise ValueError(f"invalid customer name {name!r} (lowercase letters, digits, - and _)")
    path = profile_yaml(name)
    if path is None:
        raise FileNotFoundError(f"no profile for customer {name!r}; known: {', '.join(list_customers()) or 'none'}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if raw.get("name", name) != name:
        raise ValueError(f"profile {path} says name={raw.get('name')!r}, expected {name!r}")
    targets = []
    for t in raw.get("targets") or []:
        if t.get("type") not in ("firewall", "panorama"):
            raise ValueError(f"target {t.get('name')!r}: type must be firewall or panorama")
        for k in ("host", "api_key", "password"):
            if k in t:
                raise ValueError(f"target {t.get('name')!r}: put secrets in env vars ({k}_env), not in the profile")
        targets.append(Target(name=t["name"], type=t["type"], host_env=t.get("host_env", ""), api_key_env=t.get("api_key_env", ""),
                              api_key_ro_env=t.get("api_key_ro_env", ""),
                              user_env=t.get("user_env", ""), password_env=t.get("password_env", ""),
                              offline_config=t.get("offline_config"), vsys=list(t.get("vsys") or []),
                              access=_access(t)))
    if not targets:
        raise ValueError(f"profile {path} has no targets")
    naming = dict(DEFAULT_NAMING)
    naming.update(raw.get("naming") or {})
    tickets = dict(DEFAULT_TICKETS)
    tickets.update(raw.get("tickets") or {})
    def _bool(val, default=True):
        if val is None:
            return default
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in {"1", "true", "yes", "on"}

    return Profile(name=name, path=path, targets=targets, display_name=raw.get("display_name", name),
                   env_file=raw.get("env_file"), vpn_landing_zones=list(raw.get("vpn_landing_zones") or []),
                   naming=naming, tickets=tickets, default_tags=list(raw.get("default_tags") or []),
                   known_apps=[str(a) for a in (raw.get("known_apps") or [])],
                   object_scope=raw.get("object_scope", "local"), broad_prefix_len=int(raw.get("broad_prefix_len", 8)),
                   mgmt_ports=[int(p) for p in raw.get("mgmt_ports", [22, 3389, 5900])],
                   change_plan=resolve_change_plan(raw.get("change_plan"), name),
                   combine_rules=_bool(raw.get("combine_rules"), True),
                   combine_across_tickets=_bool(raw.get("combine_across_tickets"), True),
                   address_group_threshold=int(raw.get("address_group_threshold", 5) or 5),
                   config_retention_days=int(raw.get("config_retention_days", 0) or 0),
                   origin=str(raw.get("origin") or "profile"),
                   allow_live_panorama_push=_resolve_live_pano_flag(raw, name, _bool),
                   url_filter=dict(raw.get("url_filter") or {}),
                   edl=dict(raw.get("edl") or {}),
                   allow_direct_managed=_resolve_flag(raw, name, _bool, "allow_direct_managed"),
                   two_person_approval=_resolve_flag(raw, name, _bool, "two_person_approval"),
                   site_codes=_resolve_site_codes(raw, name))
