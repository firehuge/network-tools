"""Export the running configuration to backups/ before a commit."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from panlab.paths import backups_dir
from panlab.settings import Settings, connect, load_settings

_SAFE_HOST = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_host(host: str) -> str:
    cleaned = _SAFE_HOST.sub("-", host.strip()) or "device"
    return cleaned[:63]


def xapi_xml_text(fw) -> str:
    """Return XML from the last xapi call.

    pan-python sometimes leaves ``xml_result()`` empty after
    ``export(category='configuration')`` while ``xml_document`` has the
    ``<config>`` document, or returns an Element. Prefer a real XML
    string and never stringify an Element (that would be
    ``<Element 'config' at 0x...>``).
    """
    xml = fw.xapi.xml_result()
    if not xml:
        xml = getattr(fw.xapi, "xml_document", None)
    if xml is None:
        raise RuntimeError("device returned an empty configuration export")
    if isinstance(xml, bytes):
        xml = xml.decode("utf-8")
    elif isinstance(xml, ET.Element):
        xml = ET.tostring(xml, encoding="unicode")
    text = str(xml).strip()
    if not text.startswith("<") or text.startswith("<Element "):
        raise RuntimeError("device export did not look like XML")
    if not text.startswith("<?xml") and text.startswith("<config"):
        text = '<?xml version="1.0"?>\n' + text
    elif not text.startswith("<?xml") and not text.startswith("<config"):
        # Wrapped response, keep as-is if it already contains XML.
        if "<config" in text or text.startswith("<response"):
            text = '<?xml version="1.0"?>\n' + text
        else:
            raise RuntimeError("device export did not look like XML")
    return text if text.endswith("\n") else text + "\n"


def export_running_config(fw) -> str:
    """Return the running config as an XML string."""
    fw.xapi.export(category="configuration")
    return xapi_xml_text(fw)


def write_backup(xml: str, dest_dir: Path | str | None = None, host: str = "device") -> Path:
    folder = Path(dest_dir) if dest_dir is not None else backups_dir()
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = folder / f"running-{_safe_host(host)}-{stamp}.xml"
    path.write_text(xml, encoding="utf-8")
    return path


def backup_running_config(
    dest_dir: Path | str | None = None,
    settings: Settings | None = None,
) -> Path:
    settings = settings or load_settings()
    fw = connect(settings)
    xml = export_running_config(fw)
    return write_backup(xml, dest_dir=dest_dir, host=settings.host)
