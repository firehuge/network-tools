"""Thin XML-API access for the upgrade wizard.

Everything goes through two calls so a fake device can stand in for tests:

* ``op(cmd)``: an operational command (XML string); returns the ``<response>``
  element, raises :class:`DeviceError` on an API error.
* ``export(category)``: ``configuration`` (XML text) or ``device-state`` (tgz bytes).

A Panorama-managed firewall is reached *through* Panorama with the XML API
``target=<serial>`` parameter, so one Panorama key covers every firewall
behind it. API keys stay inside the client object and are never logged.
"""

from __future__ import annotations

import re
import ssl
import xml.etree.ElementTree as ET
from typing import Protocol

from panlab.customers import Profile, Target


class DeviceError(RuntimeError):
    pass


class UpgradeDevice(Protocol):
    label: str

    def op(self, cmd: str) -> ET.Element: ...
    def export(self, category: str) -> bytes: ...


_KEY_RE = re.compile(r"(key=)[^&\s]+", re.I)


def _redact(msg: str, secret: str = "") -> str:
    msg = _KEY_RE.sub(r"\1***", msg)
    return msg.replace(secret, "***") if secret else msg


class XapiUpgradeDevice:
    def __init__(self, hostname: str, api_key: str, *, serial: str | None = None, label: str = "", timeout: int = 120):
        import pan.xapi

        self._key = api_key
        self.label = label or hostname
        self.serial = serial
        # Devices commonly use self-signed management certificates, same as the rest of PAAT.
        self._x = pan.xapi.PanXapi(hostname=hostname, api_key=api_key, serial=serial, timeout=timeout,
                                   ssl_context=ssl._create_unverified_context())

    def op(self, cmd: str) -> ET.Element:
        import pan.xapi

        try:
            self._x.op(cmd=cmd)
        except pan.xapi.PanXapiError as exc:
            raise DeviceError(_redact(str(exc), self._key)) from None
        except Exception as exc:  # network errors, timeouts
            raise DeviceError(_redact(f"{type(exc).__name__}: {exc}", self._key)) from None
        doc = self._x.xml_document
        if isinstance(doc, bytes):
            doc = doc.decode("utf-8", "replace")
        try:
            return ET.fromstring(doc)
        except ET.ParseError as exc:
            raise DeviceError(f"unreadable API response: {exc}") from None

    def export(self, category: str) -> bytes:
        import pan.xapi

        try:
            self._x.export(category=category)
        except pan.xapi.PanXapiError as exc:
            raise DeviceError(_redact(str(exc), self._key)) from None
        except Exception as exc:
            raise DeviceError(_redact(f"{type(exc).__name__}: {exc}", self._key)) from None
        res = getattr(self._x, "export_result", None)
        if isinstance(res, dict) and res.get("content"):
            c = res["content"]
            return c if isinstance(c, bytes) else str(c).encode()
        doc = self._x.xml_document or ""
        return doc if isinstance(doc, bytes) else str(doc).encode()


def _creds(profile: Profile, t: Target) -> tuple[str, str]:
    from panlab.sources import settings_for

    st = settings_for(profile, t)
    if not st.host or not st.api_key:
        raise DeviceError(f"API host/key for {t.name} are not set (env file {profile.env_file}); "
                          "the upgrade wizard needs an API key, not a username/password.")
    return st.host, st.api_key


def find_target(profile: Profile, name: str) -> Target:
    for t in profile.targets:
        if t.name == name:
            return t
    raise DeviceError(f"no target {name!r} in customer {profile.name}")


def connect(profile: Profile, target_name: str, serial: str | None = None) -> UpgradeDevice:
    """Direct connection to a profile target, or (serial set) to a firewall behind that Panorama target."""
    t = find_target(profile, target_name)
    host, key = _creds(profile, t)
    if serial and t.type != "panorama":
        raise DeviceError(f"{target_name} is not a Panorama; cannot reach serial {serial} through it")
    label = f"{target_name}/{serial}" if serial else target_name
    return XapiUpgradeDevice(host, key, serial=serial, label=label)


# Tests replace this (fake device API); web and CLI call it.
device_factory = connect
