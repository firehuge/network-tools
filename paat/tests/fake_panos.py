# SPDX-License-Identifier: Apache-2.0
"""In-memory fake PAN-OS XML API for upgrade tests. Never touches a real device."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from panlab.upgrade.device import DeviceError


def _resp(inner: str) -> ET.Element:
    return ET.fromstring(f'<response status="success"><result>{inner}</result></response>')


def _resp_config(xml: str) -> ET.Element:
    text = xml.strip()
    if text.startswith("<?xml"):
        text = text.split("?>", 1)[-1].strip()
    return _resp(text)


class FakeBox:
    def __init__(self, name, kind="firewall", version="11.1.6-h7", serial="SN-" + "0" * 4, versions=(), app="8790-8462",
                 ha=None, pending=False, free_gb="3.3G", family="vm", licensed=True):
        self.name, self.kind, self.version, self.serial, self.app, self.family = name, kind, version, serial, app, family
        self.ha = ha or {}
        self.pending = pending
        self.free = free_gb
        self.licensed = licensed
        self.versions = {v: {"downloaded": False} for v in versions}
        self.versions.setdefault(version, {"downloaded": True})
        self.installed = None
        self.jobs: dict[int, dict] = {}
        self.next_job = 100
        self.down_polls = 0
        self.sync_status = "In Sync"  # Panorama: device group / template sync shown for managed firewalls
        self.writes: list[str] = []
        self.managed: list["FakeBox"] = []
        self.busy_jobs: list[str] = []
        self.dgs: dict[str, list[str]] = {}  # Panorama: device group -> member serials
        self.device_versions = list(versions)  # Panorama: PanOS images it can deploy (request batch software info)
        self.repo: set[str] = set()  # Panorama: images downloaded for devices
        self.batch_reads: list[str] = []
        self.calls: list[str] = []  # every op/export that reached this box (directly or through Panorama)
        self.direct_calls: list[str] = []  # only those sent to this box's own API (not through Panorama)
        self.pano_server = "192.0.2.10"  # firewall: Panorama in panorama-status (None = standalone)
        self.running_xml = None  # optional <config>...</config> for live snapshot tests
        self.candidate_xml = None
        self.policy_matches = {}  # (src, dst, port) or 'default' -> {name, action}
        self.fib = {}  # dest ip -> {interface, nexthop, zone}
        self.logs = []  # list of traffic-log dicts

    def _job(self, kind, ok=True, details=""):
        self.next_job += 1
        self.jobs[self.next_job] = {"type": kind, "polls": 0, "ok": ok, "details": details}
        return _resp(f"<job>{self.next_job}</job>")

    def sw_xml(self, platform=None):
        ents = "".join(
            f"<entry><version>{v}</version><filename>{'PanOS_' + self.family if self.kind == 'firewall' else 'Panorama_pc'}-{v}</filename>"
            f"<size>900</size><downloaded>{'yes' if st['downloaded'] else 'no'}</downloaded>"
            f"<current>{'yes' if v == self.version else 'no'}</current><latest>no</latest><uploaded>no</uploaded></entry>"
            for v, st in self.versions.items())
        return f"<sw-updates><versions>{ents}</versions></sw-updates>"

    def op(self, cmd: str, via=None) -> ET.Element:
        if self.down_polls > 0:
            self.down_polls -= 1
            raise DeviceError("URLError: connection refused")
        c = cmd
        self.calls.append(c)
        if "<show><system><info>" in c:
            return _resp(f"<system><hostname>{self.name}</hostname><model>{'Panorama' if self.kind == 'panorama' else 'PA-VM'}</model>"
                         f"<family>{self.family}</family><serial>{self.serial}</serial><sw-version>{self.version}</sw-version>"
                         f"<app-version>{self.app}</app-version><threat-version>0</threat-version></system>")
        if "<request><system><software><check>" in c:
            if not self.licensed:  # what an unregistered PA-440 really returns: success + msg + local images only
                only_local = {v: st for v, st in self.versions.items() if st["downloaded"]}
                ents = "".join(f"<entry><version>{v}</version><downloaded>yes</downloaded><current>{'yes' if v == self.version else 'no'}</current></entry>"
                               for v in only_local)
                return _resp('<sw-updates last-updated-at="2026/11/03 20:39:10"><msg>The device is not found or not registered, '
                             f'please try after some time </msg><versions>{ents}</versions></sw-updates>')
            return _resp(self.sw_xml())
        if "<request><system><software><info>" in c:
            return _resp(self.sw_xml())
        if "<show><high-availability>" in c:
            if not self.ha:
                return _resp("<enabled>no</enabled>")
            h = self.ha
            return _resp(f"<enabled>yes</enabled><group><mode>Active-Passive</mode><local-info><state>{h['state']}</state></local-info>"
                         f"<peer-info><state>{h['peer_state']}</state><serial-num>{h['peer']}</serial-num></peer-info>"
                         f"<running-sync>{h.get('sync', 'synchronized')}</running-sync></group>")
        if "disk-space" in c:
            return _resp(f"<![CDATA[Filesystem Size Used Avail Use% Mounted on\n/dev/sda6 5.9G 2.4G {self.free} 42% /opt/panrepo\n]]>")
        if "<check><pending-changes>" in c:
            return _resp("yes" if self.pending else "no")
        if "<show><panorama-status>" in c:
            return _resp(f"<![CDATA[Panorama Server 1 : {self.pano_server}\n    Connected     : yes\n]]>"
                         if self.kind == "firewall" and self.pano_server else "")
        if "<show><config><running>" in c:
            if self.running_xml:
                return _resp_config(self.running_xml)
            if self.kind == "panorama":
                return _resp("<config version='11.1.0'><devices><entry name='localhost.localdomain'><device-group/></entry></devices></config>")
            return _resp("<config version='11.1.0' src='via op'><devices/></config>")
        if "<show><config><candidate>" in c:
            xml = self.candidate_xml or self.running_xml
            if xml:
                return _resp_config(xml)
            if self.kind == "panorama":
                return _resp("<config version='11.1.0'><devices><entry name='localhost.localdomain'><device-group/></entry></devices></config>")
            return _resp("<config version='11.1.0' src='candidate'><devices/></config>")
        if "<test><security-policy-match>" in c:
            def _tag(tag):
                m = re.search(rf"<{tag}>([^<]*)</{tag}>", c)
                return m.group(1) if m else ""
            src, dst, port = _tag("source"), _tag("destination"), _tag("destination-port")
            hit = self.policy_matches.get((src, dst, port)) or self.policy_matches.get("default")
            if not hit:
                return _resp("")  # no explicit rule
            action = hit.get("action") or "allow"
            name = hit.get("name") or "fake-rule"
            return _resp(f'<rules><entry name="{name}"><action>{action}</action></entry></rules>')
        if "<test><routing><fib-lookup>" in c:
            m = re.search(r"<ip>([^<]*)</ip>", c)
            ip = m.group(1) if m else ""
            fib = self.fib.get(ip) or self.fib.get("default") or {"interface": "ethernet1/1", "nexthop": "192.0.2.1", "zone": "trust"}
            inner = "".join(f"<{k}>{v}</{k}>" for k, v in fib.items())
            return _resp(inner)
        if "<show><routing>" in c:
            return _resp("fib 0.0.0.0/0 via 192.0.2.1 ethernet1/1")
        if "<request><batch><software><check>" in c or "<request><batch><software><info>" in c:
            if self.kind != "panorama":
                raise DeviceError("fake: batch commands are Panorama-only")
            self.batch_reads.append(c)
            ents = "".join(f"<entry><version>{v}</version><filename>PanOS_{fam}-{v}</filename><size>900</size>"
                           f"<downloaded>{'yes' if v in self.repo else 'no'}</downloaded></entry>"
                           for fam in sorted({m.family for m in self.managed} | {"vm"}) for v in self.device_versions)
            return _resp(f"<sw-updates><versions>{ents}</versions></sw-updates>")
        if "<show><devices><connected>" in c or "<show><devices><all>" in c:
            for m in self.managed:
                if m.down_polls:
                    m.down_polls -= 1
            ents = "".join(f"<entry name='{m.serial}'><serial>{m.serial}</serial><hostname>{m.name}</hostname><family>{m.family}</family>"
                           f"<sw-version>{m.version}</sw-version><connected>{'no' if m.down_polls else 'yes'}</connected>"
                           + (f"<ha><state>{m.ha['state']}</state><peer><serial>{m.ha['peer']}</serial></peer></ha>" if m.ha else "")
                           + "</entry>" for m in self.managed)
            return _resp(f"<devices>{ents}</devices>")
        if "<show><devicegroups>" in c:
            ents = "".join(f"<entry name='{g}'><devices>" + "".join(f"<entry name='{sn}'><serial>{sn}</serial>"
                                                                     f"<shared-policy-status>{self.sync_status}</shared-policy-status></entry>" for sn in sns)
                           + "</devices></entry>" for g, sns in self.dgs.items())
            return _resp(f"<devicegroups>{ents}</devicegroups>")
        if "<show><templates>" in c:
            ents = "".join(f"<entry name='TPL'><devices><entry name='{m.serial}'><serial>{m.serial}</serial>"
                           f"<template-status>{self.sync_status}</template-status></entry></devices></entry>" for m in self.managed)
            return _resp(f"<templates>{ents}</templates>")
        if "<show><interface>all" in c:
            return _resp("<hw><entry><name>ethernet1/1</name><state>up</state></entry><entry><name>ethernet1/2</name><state>down</state></entry></hw>")
        if "<show><session><info>" in c:
            return _resp("<num-active>12</num-active><num-max>100000</num-max>")
        if "<show><jobs><all>" in c:
            busy = "".join(f"<job><id>9{i}</id><type>{t}</type><status>ACT</status><result>PEND</result></job>" for i, t in enumerate(self.busy_jobs))
            return _resp(f"<job><id>5</id><type>Commit</type><status>FIN</status><result>OK</result></job>{busy}")
        m = re.search(r"<show><jobs><id>(\d+)</id>", c)
        if m:
            j = self.jobs[int(m[1])]
            j["polls"] += 1
            done = j["polls"] >= 2
            return _resp(f"<job><id>{m[1]}</id><type>{j['type']}</type><status>{'FIN' if done else 'ACT'}</status>"
                         f"<result>{('OK' if j['ok'] else 'FAIL') if done else 'PEND'}</result><progress>{100 if done else 40}</progress>"
                         f"<details><line>{j['details']}</line></details></job>")
        self.writes.append(c)
        if "<request><content><upgrade><check>" in c:
            return _resp("<content-updates><entry><version>9173-10354</version><filename>panupv2-all-contents-9173-10354</filename></entry></content-updates>")
        if "<request><content><upgrade><download>" in c:
            return self._job("Downld")
        if "<request><content><upgrade><install>" in c:
            self.app = "9173-10354"
            return self._job("ContentInstall")
        m = re.search(r"<software><download><version>([^<]+)</version>", c)
        if m:
            self.versions[m[1]]["downloaded"] = True
            return self._job("Downld")
        m = re.search(r"<software><install><version>([^<]+)</version>", c)
        if m:
            self.installed = m[1]
            return self._job("SWInstall")
        if "<request><restart><system>" in c:
            self.version = self.installed or self.version
            self.down_polls = 2
            return _resp("rebooting")
        if "<request><batch><content><check>" in c:
            return _resp("<content-updates><entry><version>9173-10354</version><filename>panupv2-all-contents-9173-10354</filename></entry></content-updates>")
        if "<request><batch><content><download>" in c:
            return self._job("Downld")
        m = re.search(r"<request><batch><content><upload-install><file>[^<]+</file><devices>([^<]+)</devices>", c)
        if m:
            self._fw(m[1]).app = "9173-10354"
            return self._job("DeployInstall")
        m = re.search(r"<request><batch><software><download><file>PanOS_\w+-([^<]+)</file>", c)
        if m:
            self.repo.add(m[1])
            return self._job("Downld")
        m = re.search(r"<request><batch><software><upload-install><file>PanOS_\w+-([^<]+)</file><devices>([^<]+)</devices>", c)
        if m:
            self._fw(m[2]).installed = m[1]
            return self._job("DeployInstall")
        m = re.search(r"<request><batch><reboot><devices>([^<]+)</devices>", c)
        if m:
            fw = self._fw(m[1])
            fw.version = fw.installed or fw.version
            fw.down_polls = 1
            return _resp("rebooted")
        if "<high-availability><state>" in c:
            return _resp("ok")
        raise DeviceError(f"fake: unsupported command {c[:80]}")

    def _fw(self, serial):
        return next(m for m in self.managed if m.serial == serial)

    def export(self, category):
        self.calls.append(f"export {category}")
        if category == "configuration":
            if self.running_xml:
                return self.running_xml.encode() if isinstance(self.running_xml, str) else self.running_xml
            if self.kind == "panorama":
                return b"<config version='11.1.0'><devices><entry name='localhost.localdomain'><device-group/></entry></devices></config>"
            return b"<config version='11.1.0'><devices/></config>"
        return b"\x1f\x8bfake-tgz"


class FakeHandle:
    def __init__(self, box: FakeBox, proxy: FakeBox | None = None):
        self.box, self.proxy = box, proxy
        self.label = box.name

    def op(self, cmd):
        if self.proxy is None:
            self.box.direct_calls.append(cmd)
        return (self.proxy or self.box).op(cmd)

    def export(self, category):
        if self.proxy is None:
            self.box.direct_calls.append(f"export {category}")
        else:  # what real Panorama does: export with target=<serial> ignores the target and returns Panorama's config
            return self.box.export(category)
        return self.box.export(category)

    def traffic_logs(self, query: str, nlogs: int) -> list[dict]:
        box = self.proxy or self.box
        return list(box.logs or [])[:nlogs]


def live_factory_for(boxes: dict[str, FakeBox]):
    """liveconfig.device_factory stand-in. boxes: profile target name -> FakeBox."""
    def f(profile, target, serial=None, vsys=None):
        name = target.name if hasattr(target, "name") else target
        b = boxes[name]
        if serial:
            handle = FakeHandle(next(m for m in b.managed if m.serial == serial))
        else:
            handle = FakeHandle(b)
        handle.vsys = vsys
        return handle
    return f


def factory_for(boxes: dict[str, FakeBox], no_direct: set[str] | frozenset[str] = frozenset()):
    """boxes: profile target name -> FakeBox. Managed firewalls are found by serial.

    ``no_direct``: target names whose own API key is not configured (connect fails like a missing key).
    """
    def f(profile, target, serial=None):
        if target in no_direct and not serial:
            raise DeviceError(f"API host/key for {target} are not set")
        b = boxes[target]
        if serial:
            return FakeHandle(b, next(m for m in b.managed if m.serial == serial))
        return FakeHandle(b)
    return f
