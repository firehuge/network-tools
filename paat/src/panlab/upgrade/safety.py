# SPDX-License-Identifier: Apache-2.0
"""Safety rules for an OS upgrade plan. Red blocks; yellow must be acknowledged.

Rules are enforced in the planner and again by the runner before each step:

* Panorama first: a firewall's target may not be newer than its Panorama's
  current/planned version (PAN: Panorama must run the same or a later PAN-OS
  version than the firewalls it manages; a later feature release on the
  firewall is unmanageable).
* HA: both peers in the plan, config in sync, passive/secondary first.
* Path: downgrades only for a firewall, inside its own train, and only after a yellow
  acknowledgement; target offered by the device; base images available.
* Content: app/threat content installed and (when a PAN-sourced minimum is
  configured) at or above the minimum for the target train.
* Disk: enough free space on the software repository for the images still
  to download.
* No uncommitted changes.
* Device reachable and discovery clean.
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from panlab.upgrade.versions import PanosVersion, V
from panlab.paths import etc_dir

GREEN, YELLOW, RED = "green", "yellow", "red"
DEFAULT_IMAGE_MB = 1200
HEADROOM_MB = 500


@dataclass
class Check:
    id: str
    level: str
    title: str
    detail: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def worst(levels) -> str:
    levels = list(levels)
    return RED if RED in levels else YELLOW if YELLOW in levels else GREEN


# ---------------------------------------------------------------- PAN-sourced reference data

def reference_file() -> Path:
    return Path(os.environ.get("PANLAB_UPGRADE_REFERENCE") or etc_dir() / "upgrade-reference.yaml")


def load_reference(path: Path | None = None) -> dict[str, Any]:
    """Optional operator-maintained data copied from Palo Alto Networks sources.

    ``source`` must be a paloaltonetworks.com URL or the whole file is ignored
    (EoL dates, preferred releases and minimum content are only shown when they
    come from PAN). Keys: ``preferred: {train: [versions]}``,
    ``min_content: {train: "8799-8509"}``, ``eol: {train: "YYYY-MM-DD"}``.
    """
    p = path or reference_file()
    if not p.is_file():
        return {}
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return {}
    host = (urlparse(str(raw.get("source") or "")).hostname or "").lower()
    if not (host == "paloaltonetworks.com" or host.endswith(".paloaltonetworks.com")):
        return {}
    return {"source": raw["source"], "preferred": {str(k): [str(x) for x in v or []] for k, v in (raw.get("preferred") or {}).items()},
            "min_content": {str(k): str(v) for k, v in (raw.get("min_content") or {}).items()},
            "eol": {str(k): str(v) for k, v in (raw.get("eol") or {}).items()}}


def content_key(s: str) -> tuple[int, ...] | None:
    m = re.match(r"^\s*(\d+)-(\d+)", s or "")
    return (int(m[1]), int(m[2])) if m else None


# ---------------------------------------------------------------- per-device checks

def device_checks(facts: dict, target: str | None, path_errors: list[str], download_versions: list[str],
                  ref: dict | None = None, today: date | None = None) -> list[Check]:
    ref = ref or {}
    out: list[Check] = []
    if not facts.get("reachable"):
        out.append(Check("reachable", RED, "Device did not answer the API",
                         "; ".join(facts.get("errors") or []) or "No response. Check the API key and that HTTPS management is on."))
        return out
    out.append(Check("reachable", GREEN, "Device answers the API", f"Running {facts.get('sw_version')}."))
    errs = [x for x in facts.get("errors") or [] if not x.startswith("show jobs")]
    if errs:
        out.append(Check("discovery", YELLOW, "Some read-only checks did not answer", "; ".join(errs)[:600]))
    if not target:
        out.append(Check("target", RED, "No target version picked", "Pick a version to plan this device."))
        return out
    for e in path_errors:
        out.append(Check("path", RED, "Upgrade path is not possible", e))
    if not path_errors:
        cur, tgt = V(facts["sw_version"]), V(target)
        jump = cur.train_key != tgt.train_key
        if tgt < cur:
            out.append(Check("path", YELLOW, "DOWNGRADE to an older version",
                             f"{cur} to {tgt} goes backwards inside the {cur.train} train. Settings that only exist in the newer "
                             f"release may be ignored by {tgt}. Confirm the backup step, the change window and the reason for "
                             "going back before you acknowledge this."))
        elif jump:
            out.append(Check("path", YELLOW, "Feature-release upgrade",
                             f"{cur.train} to {tgt.train} changes features and defaults. Read the PAN-OS {tgt.train} upgrade notes "
                             "and changes to default behavior before the window."))
        else:
            out.append(Check("path", GREEN, "Same-train upgrade",
                             f"{cur} to {tgt} stays in the {cur.train} train (bug and security fixes)."))
    if download_versions and facts.get("can_download") is False:
        out.append(Check("download", RED, "This device cannot download software",
                         "; ".join(w for w in facts.get("warnings") or [] if "update server" in w)[:500] or
                         "The update server refused it. Pick a version that is already downloaded."))
    # Uncommitted changes
    pc = facts.get("pending_changes")
    if pc is True and facts.get("kind") == "panorama":
        out.append(Check("pending", YELLOW, "Uncommitted changes on Panorama",
                         "Someone has candidate changes on Panorama. Download, install and firewall steps can go ahead, but the "
                         "Panorama reboot step waits until there are no uncommitted changes and no running commit or push jobs."))
    elif pc is True:
        out.append(Check("pending", RED, "Uncommitted changes on the device",
                         "Someone has candidate changes that are not committed. Commit or revert them first so the "
                         "upgrade does not carry half-finished work."))
    elif pc is None:
        out.append(Check("pending", YELLOW, "Could not check for uncommitted changes", "Check Commit status in the GUI."))
    else:
        out.append(Check("pending", GREEN, "No uncommitted changes"))
    # Content
    app = facts.get("app_version") or ""
    if not content_key(app):
        out.append(Check("content", RED, "No application/threat content installed",
                         "Install the latest Apps and Threats content first (Device > Dynamic Updates). "
                         "PAN-OS will refuse a software install without it."))
    else:
        need = (ref.get("min_content") or {}).get(V(target).train) if not path_errors else None
        if need and content_key(need) and content_key(app) < content_key(need):
            out.append(Check("content", RED, "Content version too old for the target",
                             f"Installed {app}; PAN-OS {V(target).train} needs {need} or later. Update content first."))
        elif need:
            out.append(Check("content", GREEN, "Content version meets the target minimum", f"Installed {app} >= {need}."))
        else:
            out.append(Check("content", YELLOW, "Minimum content not verified",
                             f"Installed {app}. Confirm the minimum content release in the PAN-OS {V(target).train if not path_errors else ''} "
                             "release notes; if the install job says content is too old, update content and retry."))
    # Disk
    free = (facts.get("disk") or {}).get("repo_free_mb")
    sizes = {a["version"]: a.get("size_mb") or 0 for a in facts.get("available") or []}
    need_mb = sum((sizes.get(v) or DEFAULT_IMAGE_MB) for v in download_versions) + HEADROOM_MB if download_versions else 0
    if free is None:
        out.append(Check("disk", YELLOW, "Could not read free disk space", "Run `show system disk-space` and check /opt/panrepo."))
    elif free < need_mb:
        out.append(Check("disk", RED, "Not enough free disk space",
                         f"{int(free)} MB free on {(facts.get('disk') or {}).get('repo_mount') or 'the repository'}; about "
                         f"{int(need_mb)} MB needed. Delete old images (Device > Software, or `delete software version <old>`)."))
    else:
        out.append(Check("disk", GREEN, "Enough free disk space", f"{int(free)} MB free; about {int(need_mb)} MB needed."))
    # HA
    ha = facts.get("ha") or {}
    if ha.get("enabled"):
        sync = (ha.get("running_sync") or "").lower()
        if sync != "synchronized":
            out.append(Check("ha-sync", RED, "HA configuration is not in sync",
                             f"running-sync is '{ha.get('running_sync') or 'unknown'}'. Sync the peers "
                             "(`request high-availability sync-to-remote running-config`) and re-run discovery."))
        else:
            out.append(Check("ha-sync", GREEN, "HA peers are in sync", f"This unit is {ha.get('local_state') or '?'}."))
    # EoL (PAN-sourced only)
    eol = (ref.get("eol") or {}).get(V(target).train) if not path_errors else None
    if eol:
        try:
            d = date.fromisoformat(eol)
            if d <= (today or date.today()):
                out.append(Check("eol", RED, "Target train is end of life", f"PAN-OS {V(target).train} reached end of life on {eol}."))
            else:
                out.append(Check("eol", GREEN, "Target train is supported", f"End of life {eol} (source: {ref.get('source')})."))
        except ValueError:
            pass
    return out


def panorama_checks(pano_name: str, pano_version: str, planned: bool, firewalls: list[tuple[str, str, bool]]) -> list[Check]:
    """firewalls: (name, version, in_plan) where version is the target if in plan, else current."""
    out = []
    pv = PanosVersion.try_parse(pano_version)
    if pv is None:
        return [Check("panorama-first", RED, "Panorama version unknown", f"Could not read {pano_name}'s version.")]
    when = "after its upgrade" if planned else "as it runs now"
    for name, ver, in_plan in firewalls:
        fv = PanosVersion.try_parse(ver)
        if fv is None:
            continue
        if fv.train_key > pv.train_key:
            out.append(Check("panorama-first", RED if in_plan else YELLOW, f"{name} would be on a newer feature release than Panorama",
                             f"{name} {'target' if in_plan else 'runs'} {fv}; {pano_name} is {pv} {when}. Panorama cannot manage a "
                             "firewall on a later feature release. Upgrade Panorama first, to the same or a newer version."))
        elif fv > pv:
            out.append(Check("panorama-first", RED if in_plan else YELLOW, f"{name} would be newer than Panorama",
                             f"{name} {'target' if in_plan else 'runs'} {fv}; {pano_name} is {pv} {when}. Panorama must be equal to "
                             "or newer than every firewall it manages. Pick a firewall target at or below Panorama's, or "
                             "add Panorama to the plan with a newer target."))
        else:
            out.append(Check("panorama-first", GREEN, f"{name} stays at or below Panorama", f"{name} {fv} <= {pano_name} {pv} {when}."))
    return out
