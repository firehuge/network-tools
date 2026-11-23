"""PAAT (Policy Automation and Analysis Tool) for Palo Alto Networks PAN-OS firewalls and Panorama.

The package keeps its original name ``panlab``. Settings may use either prefix:
``PAAT_DATA_DIR`` is read as ``PANLAB_DATA_DIR`` and so on (an explicit
``PANLAB_*`` value wins), so containers and new installs can use PAAT names.
"""

import os as _os

for _k, _v in list(_os.environ.items()):
    if _k.startswith("PAAT_"):
        _os.environ.setdefault("PANLAB_" + _k[5:], _v)

__version__ = "0.3.0"

PANORAMA_NOT_IMPLEMENTED = (
    "Panorama device_group targets in a single request YAML are "
    "not implemented yet. Use 'paat import --customer <name>' to build a placed, "
    "Panorama-aware change set (dry-run) instead."
)
