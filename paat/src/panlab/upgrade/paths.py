"""Which path an OS upgrade takes to a device: through its Panorama, or the device's own API.

Rule: a firewall that a Panorama in the customer manages is
upgraded *only* through that Panorama, so every step shows in Panorama's task
manager and logs and the tool never needs the firewall's own API key or
address. The firewall's own API is for standalone firewalls (and Panoramas).

Per profile target ``access``:

* ``auto`` (default): through Panorama when a Panorama in this customer lists
  the firewall's serial in ``show devices all``; otherwise its own API.
* ``panorama``: never its own API; red if no Panorama in the customer lists it.
* ``direct``: its own API. For a Panorama-managed firewall this is refused
  (red) unless the customer sets ``allow_direct_managed: true`` (test or
  emergency only, off by default); then yellow, and arming and every step are
  audited as a direct override.

Snapshot and plan devices carry ``access_path = {"mode": "panorama"|"direct", "via": <device id>,
"via_label": "hostname · serial", "why": ...}``.
"""

from __future__ import annotations

from typing import Any

from panlab import identity as ident

PANORAMA = "panorama"
DIRECT = "direct"


def via_panorama(pano: dict, *, why: str) -> dict[str, Any]:
    return {"mode": PANORAMA, "via": pano.get("id"), "via_label": ident.label(pano.get("name") or "", pano.get("identity")),
            "why": why}


def direct(*, why: str, managed_override: bool = False) -> dict[str, Any]:
    return {"mode": DIRECT, "via": None, "via_label": "", "why": why, "managed_override": managed_override}


def mode_of(f: dict) -> str:
    """Path for a snapshot or plan device. Older snapshots (no ``path``) count managed firewalls as Panorama."""
    p = f.get("access_path") or {}
    if p.get("mode") in (PANORAMA, DIRECT):
        return p["mode"]
    return PANORAMA if f.get("kind") == "firewall" and f.get("managed_by") else DIRECT


def is_managed_direct(f: dict) -> bool:
    """A firewall a Panorama manages that would be reached on its own API (the override case)."""
    return f.get("kind") == "firewall" and bool(f.get("managed_by") or f.get("external_panorama")) and mode_of(f) == DIRECT


def describe(f: dict) -> str:
    """Plain-English path for pages, step notes and the CR plan."""
    if mode_of(f) == PANORAMA:
        lbl = (f.get("access_path") or {}).get("via_label") or "its Panorama"
        return f"via Panorama {lbl}"
    if f.get("kind") == "panorama":
        return "Panorama's own API"
    if is_managed_direct(f):
        return "DIRECT to the firewall's own API (override: this firewall is managed by Panorama)"
    return "direct to the firewall's own API (standalone firewall)"
