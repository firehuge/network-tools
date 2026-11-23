"""Product name and wording in one place.

The product is PAAT (Policy Automation and Analysis Tool). The Python package,
the ``panlab`` command, the ``PANLAB_*`` settings and the ``/etc/panlab`` paths
keep their original names so existing servers keep working; ``paat`` and
``PAAT_*`` are accepted as aliases (see ``panlab.__init__``).

Keep the trademark rule: "Palo Alto" never appears in the product name. A
description may say what the tool is *for*.
"""

from __future__ import annotations

NAME = "PAAT"
LONG_NAME = "Policy Automation and Analysis Tool"
FULL_NAME = f"{NAME}: {LONG_NAME}"
FOR = "for Palo Alto Networks PAN-OS firewalls and Panorama"
TAGLINE = "Policy Automation & Analysis"
DESCRIPTION = f"{LONG_NAME} {FOR}: plan, check, approve and push firewall rule changes safely."
CLI = "paat"

# Simple mark: a rounded tile with a three-hop flow (source, firewall, destination).
# Colours are the RS-41 brand token (#1f5fd6 light; the page CSS uses var(--brand)).
_MARK_PATHS = ("<path d='M8 22.5c3.5 0 4-13 8-13s4.5 13 8 13' fill='none' stroke='#fff' stroke-width='2.4' "
               "stroke-linecap='round'/><circle cx='8' cy='22.5' r='2.6' fill='#fff'/><circle cx='16' cy='9.5' r='2.9' "
               "fill='#fff'/><circle cx='24' cy='22.5' r='2.6' fill='#fff'/>")


def mark_svg(fill: str = "var(--brand)", cls: str = "mark") -> str:
    """Inline SVG logo mark (no external assets)."""
    return (f"<svg class='{cls}' viewBox='0 0 32 32' aria-hidden='true' focusable='false'>"
            f"<rect x='1' y='1' width='30' height='30' rx='8' fill='{fill}'/>{_MARK_PATHS}</svg>")


def favicon_svg() -> str:
    """Standalone SVG for the browser tab (CSS variables do not apply there)."""
    return ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
            f"<rect x='1' y='1' width='30' height='30' rx='8' fill='#1f5fd6'/>{_MARK_PATHS}</svg>")

