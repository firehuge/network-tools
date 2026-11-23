"""Execute an upgrade plan one confirmed step at a time.

* A plan starts in **dry-run**. ``arm`` switches it to live and needs: an
  approved CR number in the customer's format, the "approved and in window"
  confirmation, acknowledgement of every yellow check, no red check, and the
  server switch ``PANLAB_UPGRADE_EXECUTE=1`` (off by default).
* ``start_step`` runs only the *next* pending step, only after the engineer
  types that device's name, and only if no earlier step failed. Long steps
  (content, download, install, reboot/wait) start a device job and return; the
  page (or CLI) calls ``poll`` until the step is ok or failed.
* Any failure stops the plan (status ``stopped``); nothing after it can run.
* Before rebooting a Panorama the runner refuses while Panorama has running
  or queued jobs or uncommitted changes (someone else may be committing).

Firewalls that a Panorama in the plan manages are upgraded *through* that
Panorama (Panorama > Device Deployment equivalents: ``request batch content``,
``request batch software``, ``request batch reboot``); standalone devices and
Panoramas use their own ``request system software`` / ``request content
upgrade`` / ``request restart system``.
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from panlab import identity as ident
from panlab import offsite
from panlab.customers import Profile
from panlab.upgrade import device as devmod
from panlab.upgrade import discovery as D
from panlab.upgrade import paths
from panlab.upgrade.device import DeviceError
from panlab.upgrade.planner import TZ, load_plan, load_snapshot, save_plan, upgrade_dir
from panlab.upgrade.safety import RED, YELLOW, device_checks, load_reference, worst
from panlab.upgrade.versions import Available, V, upgrade_path

WAIT_LIMIT = timedelta(minutes=50)
JOB_LIMIT = timedelta(minutes=90)


class UpgradeRefused(RuntimeError):
    pass


def now() -> datetime:
    return datetime.now(TZ)


def _ts() -> str:
    return now().isoformat(timespec="seconds")


def execute_enabled() -> bool:
    return os.environ.get("PANLAB_UPGRADE_EXECUTE", "").strip().lower() in ("1", "yes", "true", "on")


def audit(profile: Profile, **rec: Any) -> None:
    from panlab.pusher import audit as push_audit

    push_audit(profile, area="os-upgrade", **rec)


def _log(plan: dict, what: str, **kw: Any) -> None:
    plan.setdefault("log", []).append({"ts": _ts(), "step": what, **kw})


# ---------------------------------------------------------------- friendly errors

from panlab.upgrade.messages import FRIENDLY, friendly  # noqa: E402,F401


# ---------------------------------------------------------------- drivers

def _r(resp) -> str:
    return "".join(D._result(resp).itertext())


class DirectDriver:
    """A standalone firewall or a Panorama, talking to its own API."""

    def __init__(self, dev, kind: str):
        self.dev, self.kind = dev, kind

    def job(self, jid: str) -> dict:
        return D.parse_job(self.dev.op(f"<show><jobs><id>{int(jid)}</id></jobs></show>"))

    def content_phases(self) -> list[tuple[str, Callable[[], str]]]:
        def check():
            self.dev.op("<request><content><upgrade><check></check></upgrade></content></request>")
            return ""
        return [("check content", check),
                ("download latest content", lambda: D.job_id(self.dev.op(
                    "<request><content><upgrade><download><latest></latest></download></upgrade></content></request>"))),
                ("install latest content", lambda: D.job_id(self.dev.op(
                    "<request><content><upgrade><install><version>latest</version></install></upgrade></content></request>")))]

    def download(self, version: str) -> str:
        return D.job_id(self.dev.op(f"<request><system><software><download><version>{version}</version></download></software></system></request>"))

    def install(self, version: str) -> str:
        return D.job_id(self.dev.op(f"<request><system><software><install><version>{version}</version></install></software></system></request>"))

    def reboot(self) -> None:
        try:
            self.dev.op("<request><restart><system></system></restart></request>")
        except DeviceError as exc:  # the box often drops the connection as it goes down
            if not re.search(r"(timed? ?out|reset|closed|refused|unreachable|EOF|URLError|RemoteDisconnected)", str(exc), re.I):
                raise

    def running_version(self) -> str | None:
        try:
            return D.parse_sysinfo(self.dev.op(D.CMD_SYSINFO)).get("sw_version")
        except DeviceError:
            return None

    def ha(self, what: str) -> None:
        self.dev.op(f"<request><high-availability><state><{what}></{what}></state></high-availability></request>")


class ManagedDriver:
    """A firewall upgraded through its Panorama (Device Deployment)."""

    def __init__(self, pano_dev, proxy_dev, serial: str, family: str):
        self.pano, self.proxy, self.serial, self.family = pano_dev, proxy_dev, serial, family or "vm"

    def job(self, jid: str) -> dict:
        return D.parse_job(self.pano.op(f"<show><jobs><id>{int(jid)}</id></jobs></show>"))

    def _try(self, variants: list[str]) -> str:
        last = None
        for cmd in variants:
            try:
                return D.job_id(self.pano.op(cmd))
            except DeviceError as exc:
                last = exc
                if not re.search(r"(syntax|unexpected|not a valid|invalid|missing)", str(exc), re.I):
                    raise
        raise last  # type: ignore[misc]

    def _devices(self, verb: str, area: str, fname: str) -> list[str]:
        s = self.serial
        return [f"<request><batch><{area}><{verb}><file>{fname}</file><devices>{s}</devices></{verb}></{area}></batch></request>",
                f"<request><batch><{area}><{verb}><devices>{s}</devices><file>{fname}</file></{verb}></{area}></batch></request>",
                f"<request><batch><{area}><{verb}><file>{fname}</file><devices><member>{s}</member></devices></{verb}></{area}></batch></request>"]

    def _content_file(self) -> str:
        items = D.parse_content(self.pano.op("<request><batch><content><check></check></content></batch></request>"))
        files = [c for c in items if (c["filename"] or "").startswith("panupv2-all-contents")]
        if not files:
            raise DeviceError("Panorama lists no Apps+Threats content packages for managed devices")
        return files[0]["filename"]

    def content_phases(self) -> list[tuple[str, Callable[[], str]]]:
        state: dict[str, str] = {}

        def dl():
            state["file"] = self._content_file()
            return self._try([f"<request><batch><content><download><file>{state['file']}</file></download></content></batch></request>"])

        def inst():
            f = state.get("file") or self._content_file()
            return self._try(self._devices("upload-install", "content", f))
        return [("Panorama downloads the latest Apps+Threats content for devices", dl),
                ("Panorama uploads and installs the content on the firewall", inst)]

    def _sw_file(self, version: str) -> str:
        return f"PanOS_{self.family}-{version}"

    def download(self, version: str) -> str:
        return self._try([f"<request><batch><software><download><file>{self._sw_file(version)}</file></download></software></batch></request>",
                          f"<request><batch><software><download><version>{version}</version></download></software></batch></request>"])

    def install(self, version: str) -> str:
        return self._try(self._devices("upload-install", "software", self._sw_file(version)))

    def reboot(self) -> None:
        last = None
        for cmd in (f"<request><batch><reboot><devices>{self.serial}</devices></reboot></batch></request>",
                    f"<request><batch><reboot><devices><member>{self.serial}</member></devices></reboot></batch></request>"):
            try:
                self.pano.op(cmd)
                return
            except DeviceError as exc:
                last = exc
                if not re.search(r"(syntax|unexpected|not a valid|invalid)", str(exc), re.I):
                    raise
        raise last  # type: ignore[misc]

    def running_version(self) -> str | None:
        try:
            for m in D.parse_connected(self.pano.op(D.CMD_CONNECTED)):
                if m["serial"] == self.serial:
                    return m["sw_version"] if m["connected"] else None
        except DeviceError:
            return None
        return None

    def ha(self, what: str) -> None:
        self.proxy.op(f"<request><high-availability><state><{what}></{what}></state></high-availability></request>")


def _via_target(snap: dict, f: dict) -> tuple[str, str]:
    """(Panorama profile target, firewall serial) for a firewall on the Panorama path."""
    c = f.get("connect") or {}
    if c.get("serial"):
        return c["target"], c["serial"]
    pid = (f.get("access_path") or {}).get("via") or f.get("managed_by")
    pf = snap["devices"].get(pid or "", {})
    if not pf or not f.get("serial"):
        raise DeviceError(f"{f.get('name')}: Panorama path, but its Panorama or serial is unknown; run discovery again")
    return pf["connect"]["target"], f["serial"]


def driver_for(profile: Profile, snap: dict, dev_entry: dict, factory=None):
    """Panorama path (Device Deployment commands on Panorama) or the device's own API. See panlab.upgrade.paths."""
    factory = factory or devmod.device_factory
    f = snap["devices"][dev_entry["id"]]
    if f.get("kind") == "firewall" and paths.mode_of(f) == paths.PANORAMA:
        pano_t, sn = _via_target(snap, f)
        pf = snap["devices"].get(f"t:{pano_t}", {})
        fam = next((m.get("family") for m in pf.get("managed") or [] if m.get("serial") == sn), "") or f.get("family") or "vm"
        return ManagedDriver(factory(profile, pano_t), factory(profile, pano_t, sn), sn, fam)
    _refuse_direct(profile, f)
    c = f.get("connect") or {}
    return DirectDriver(factory(profile, c["target"], c.get("serial")), f.get("kind"))


def _refuse_direct(profile: Profile, f: dict) -> None:
    if paths.is_managed_direct(f) and not getattr(profile, "allow_direct_managed", False):
        raise UpgradeRefused(f"{f.get('name')} is managed by Panorama; the tool will not use its own API. "
                             "Upgrade it through Panorama (remove 'access: direct').")


def reader_for(profile: Profile, snap: dict, did: str, factory=None):
    """Read-only handle for checks and backup: through Panorama (target=<serial>) on the Panorama path."""
    factory = factory or devmod.device_factory
    f = snap["devices"][did]
    if f.get("kind") == "firewall" and paths.mode_of(f) == paths.PANORAMA:
        pano_t, sn = _via_target(snap, f)
        return factory(profile, pano_t, sn)
    _refuse_direct(profile, f)
    c = f["connect"]
    return factory(profile, c["target"], c.get("serial"))


def _pano_reader(profile: Profile, snap: dict, f: dict, factory=None):
    """Panorama's own API, for a firewall on the Panorama path."""
    factory = factory or devmod.device_factory
    pano_t, _ = _via_target(snap, f)
    return factory(profile, pano_t)


# ---------------------------------------------------------------- arming

def arm(profile: Profile, plan: dict, *, actor: str, cr: str, approved: bool, ack_yellow: bool) -> dict:
    from panlab.pusher import PushError, check_cr

    if plan.get("blocked"):
        raise UpgradeRefused("This plan has red checks. Fix them, run discovery again and build a new plan.")
    if not execute_enabled():
        raise UpgradeRefused("Live upgrades are switched off on this server (PANLAB_UPGRADE_EXECUTE is not set). "
                             "Use the change plan to do it by hand, or ask an admin to enable it.")
    try:
        cr = check_cr(profile, cr)
    except PushError as exc:
        raise UpgradeRefused(str(exc))
    if not approved:
        raise UpgradeRefused("Confirm that the CR is approved and you are inside its change window.")
    yellows = [c for d in plan["devices"] for c in d["checks"] if c["level"] == YELLOW] + \
              [c for c in plan["checks"] if c["level"] == YELLOW]
    if yellows and not ack_yellow:
        raise UpgradeRefused(f"Acknowledge the {len(yellows)} yellow item(s) first.")
    overrides = [d for d in plan["devices"] if d.get("kind") == "firewall" and (d.get("access_path") or {}).get("mode") == paths.DIRECT
                 and (d.get("managed_by") or (d.get("access_path") or {}).get("managed_override"))]
    if overrides and not getattr(profile, "allow_direct_managed", False):
        raise UpgradeRefused("This plan reaches a Panorama-managed firewall on its own API; that is refused. "
                             "Upgrade it through Panorama.")
    for d in overrides:
        audit(profile, actor=actor, action="upgrade-direct-override", cr=cr, plan=plan["id"], target=_dlabel(d),
              detail="Panorama-managed firewall upgraded on its own API (allow_direct_managed)")
    plan.update({"mode": "live", "status": "armed", "cr": cr, "armed_by": actor, "armed_at": _ts(), "ack_yellow": bool(yellows)})
    _log(plan, "armed for live execution", by=actor, cr=cr)
    save_plan(profile, plan)
    audit(profile, actor=actor, action="upgrade-arm", cr=cr, plan=plan["id"], devices=[_dlabel(d) for d in plan["devices"]],
          target=", ".join(_dlabel(d) for d in plan["devices"]))
    return plan


def next_step(plan: dict) -> dict | None:
    for s in plan["steps"]:
        if s["status"] != "ok" and s["status"] != "skipped":
            return s
    return None


# ---------------------------------------------------------------- steps

def _dev(plan: dict, did: str) -> dict:
    return next(d for d in plan["devices"] if d["id"] == did)


def _dlabel(d: dict) -> str:
    """Plan device as 'profile name · hostname (serial)' (older plans: identity fields may be missing)."""
    return ident.label(d.get("name") or d.get("id", ""), d.get("identity") or
                       {"hostname": d.get("hostname"), "serial": d.get("serial")})


def _who(s: dict) -> dict:
    """Audit fields that say exactly which device a step touched."""
    return {"device": s["device_name"], "hostname": s.get("hostname") or ident.UNKNOWN_HOST,
            "serial": s.get("serial") or ident.UNKNOWN_SERIAL,
            "target": ident.label(s["device_name"], s), "via": s.get("path_text", "")}


def confirm_word(s: dict) -> str:
    """What the engineer types to run step ``s``: the device's real hostname (or serial; see panlab.identity)."""
    return s.get("confirm_with") or s["device_name"]


def _start_job(s: dict, label: str, jid: str) -> None:
    s.setdefault("jobs", []).append({"label": label, "jobid": jid, "started": _ts()})


def _fail(profile: Profile, plan: dict, s: dict, msg: str, actor: str = "") -> dict:
    s["status"] = "failed"
    s["error"] = msg
    hint = friendly(msg)
    if hint:
        s["hint"] = hint
    s["finished"] = _ts()
    plan["status"] = "stopped"
    _log(plan, f"FAILED: {s['title']}", error=msg[:500], hint=hint)
    save_plan(profile, plan)
    audit(profile, actor=actor or plan.get("armed_by", ""), action="upgrade-step", cr=plan.get("cr"), plan=plan["id"],
          step=s["n"], what=s["action"], **_who(s), result="failed", error=msg[:300])
    write_report(profile, plan)
    return plan


def _ok(profile: Profile, plan: dict, s: dict, **kw: Any) -> dict:
    s["status"] = "ok"
    s["finished"] = _ts()
    s.update(kw)
    _log(plan, f"ok: {s['title']}")
    if next_step(plan) is None:
        plan["status"] = "complete"
        _log(plan, "plan complete")
    save_plan(profile, plan)
    audit(profile, actor=plan.get("armed_by", ""), action="upgrade-step", cr=plan.get("cr"), plan=plan["id"], step=s["n"],
          what=s["action"], **_who(s), result="ok")
    write_report(profile, plan)
    return plan


def _panorama_busy(dev, pushes_only: bool = False) -> str:
    """Why a Panorama (or, pushes_only, a firewall it pushes to) should not reboot now, or ''."""
    jobs = dev.op(D.CMD_JOBS)
    busy = [f"{D._t(j, 'type')} job {D._t(j, 'id')} ({D._t(j, 'status')})" for j in D._result(jobs).iter("job")
            if D._t(j, "status").upper() in ("ACT", "PEND", "QUEUED")
            and (not pushes_only or D._t(j, "type").lower() in ("commitall", "commit-all", "pushall"))]
    pend = False if pushes_only else D._text(dev.op(D.CMD_PENDING)).strip().lower() == "yes"
    why = []
    if busy:
        why.append("running/queued jobs: " + ", ".join(busy[:5]))
    if pend:
        why.append("uncommitted changes (someone may be mid-change)")
    return "; ".join(why)


def precheck(profile: Profile, plan: dict, snap: dict, s: dict, factory=None) -> list[dict]:
    d = _dev(plan, s["device"])
    f = snap["devices"][s["device"]]
    live = D.discover(reader_for(profile, snap, s["device"], factory), kind=f["kind"], refresh=False)
    via_pano = f["kind"] == "firewall" and paths.mode_of(f) == paths.PANORAMA
    if via_pano and live.get("reachable"):
        _use_panorama_images(profile, snap, f, live, factory)
    target = d["target"]
    path, perr = (upgrade_path(live["sw_version"], target, [Available(**a) for a in live.get("available") or []],
                               allow_downgrade=f["kind"] == "firewall")
                  if live.get("reachable") and V(live["sw_version"]) != V(target) else ([], []))
    have = {a["version"] for a in live.get("available") or [] if a.get("downloaded")}
    dl = [p.version for p in path if p.action == "download" and p.version not in have]
    managed_fw = f["kind"] == "firewall" and f.get("managed_by")
    checks = [c.as_dict() for c in device_checks(live, target, perr, [] if via_pano else dl, load_reference())]
    from panlab.upgrade.planner import path_checks
    checks.extend(c.as_dict() for c in path_checks(profile, snap, f))
    if f["kind"] == "panorama":  # another worker's uncommitted changes are not ours to block on until reboot
        checks = [c for c in checks if c["id"] != "pending"]
    if managed_fw:
        pano = snap["devices"][f["managed_by"]]
        pv = DirectDriver(reader_for(profile, snap, f["managed_by"], factory), "panorama").running_version()
        ok = pv is not None and V(target) <= V(pv)
        checks.append({"id": "panorama-first", "level": "green" if ok else RED,
                       "title": "Panorama already at or above the firewall target" if ok else "Panorama is below the firewall target",
                       "detail": f"{pano.get('name')} runs {pv}; firewall target {target}."})
        if via_pano:  # Panorama stages the image; the firewall check stays in postcheck
            checks = [c for c in checks if c["id"] != "disk"]
    checks.extend(_identity_checks(d, live))
    s["identity_live"] = {"hostname": live.get("hostname") or "", "serial": live.get("serial") or ""}
    s["checks"] = checks
    s["snapshot"] = {k: live.get(k) for k in ("sw_version", "app_version", "threat_version", "ha", "panorama_status",
                                               "interfaces", "sessions", "last_commit", "pending_changes")}
    return checks


def _use_panorama_images(profile: Profile, snap: dict, f: dict, live: dict, factory=None) -> None:
    """Panorama path: the versions on offer are the PanOS_<family> images Panorama can deploy (request batch software info)."""
    try:
        rows = D.parse_batch_software(_pano_reader(profile, snap, f, factory).op(D.CMD_BATCH_SW_INFO))
    except DeviceError:
        return
    pano_t, sn = _via_target(snap, f)
    pf = snap["devices"].get(f"t:{pano_t}", {})
    fam = next((m.get("family") for m in pf.get("managed") or [] if m.get("serial") == sn), "") or live.get("family") or ""
    av = D.batch_available_for(rows, fam, live.get("sw_version"))
    if av:
        live["available"] = [a.__dict__ for a in av]
        live["software_source"] = "panorama"


def _identity_checks(d: dict, live: dict) -> list[dict]:
    """The device answering now must be the one the plan was built for."""
    if not live.get("reachable"):
        return []
    want_s, want_h = d.get("serial") or "", d.get("hostname") or ""
    got_s, got_h = live.get("serial") or "", live.get("hostname") or ""
    out = []
    if want_s and got_s and want_s != got_s:
        out.append({"id": "identity", "level": RED, "title": "A different device answered",
                    "detail": f"Plan is for serial {want_s} ({want_h}); the device now reports serial {got_s} ({got_h}). "
                              "Stop and check the address in the customer profile."})
    elif not got_h or not got_s:
        out.append({"id": "identity", "level": YELLOW, "title": "Hostname unknown" if not got_h else "Serial number unknown",
                    "detail": ident.missing_note(d.get("name") or "", {"hostname": got_h, "serial": got_s})})
    elif want_h and got_h != want_h:
        out.append({"id": "identity", "level": YELLOW, "title": "Hostname changed since the plan",
                    "detail": f"Plan says {want_h}; the device now reports {got_h} (same serial {got_s})."})
    else:
        out.append({"id": "identity", "level": "green", "title": f"Same device: {got_h} ({got_s})",
                    "detail": "Hostname and serial match the plan."})
    return out


def start_step(profile: Profile, plan: dict, *, actor: str, confirm: str, factory=None) -> dict:
    if plan.get("mode") != "live":
        raise UpgradeRefused("This plan is a dry run. Arm it (CR + approval) before running steps.")
    if plan.get("status") in ("stopped", "complete"):
        raise UpgradeRefused(f"This plan is {plan['status']}; nothing more can run. Build a new plan.")
    if not execute_enabled():
        raise UpgradeRefused("Live upgrades are switched off on this server (PANLAB_UPGRADE_EXECUTE).")
    s = next_step(plan)
    if s is None:
        raise UpgradeRefused("All steps are done.")
    if s["status"] == "running":
        raise UpgradeRefused(f"Step {s['n']} is still running; wait for it.")
    word = confirm_word(s)
    if (confirm or "").strip() != word:
        what = ("hostname the device reports" if word == s.get("hostname") else
                "serial number" if word == s.get("serial") else "device name")
        raise UpgradeRefused(f"Type the {what} exactly ({word}) to confirm step {s['n']} on "
                             f"{s.get('device_label') or s['device_name']}.")
    snap = load_snapshot(profile, plan["snapshot"])
    d = _dev(plan, s["device"])
    _refuse_direct(profile, snap["devices"][s["device"]])
    s.update({"status": "running", "started": _ts(), "by": actor})
    plan["status"] = "running"
    _log(plan, f"start: {s['title']}", by=actor)
    save_plan(profile, plan)
    try:
        if s["action"] == "precheck":
            checks = precheck(profile, plan, snap, s, factory)
            reds = [c for c in checks if c["level"] == RED]
            if reds:
                return _fail(profile, plan, s, "; ".join(f"{c['title']}: {c['detail']}" for c in reds), actor)
            return _ok(profile, plan, s, light=worst(c["level"] for c in checks))
        if s["action"] == "backup":
            return _ok(profile, plan, s, files=backup(profile, plan, snap, s, factory))
        drv = driver_for(profile, snap, d, factory)
        if s["action"] == "content":
            s["phases"] = [p[0] for p in drv.content_phases()]
            s["phase"] = 0
            return _advance_phase(profile, plan, s, drv)
        if s["action"] == "download":
            if _already_downloaded(profile, snap, s, factory):
                return _ok(profile, plan, s, note="already downloaded")
            _start_job(s, "download", drv.download(s["version"]))
        elif s["action"] == "install":
            _start_job(s, "install", drv.install(s["version"]))
        elif s["action"] == "reboot":
            f = snap["devices"][s["device"]]
            if f["kind"] == "panorama" or f.get("managed_by"):
                pano_id = s["device"] if f["kind"] == "panorama" else f["managed_by"]
                why = _panorama_busy(reader_for(profile, snap, pano_id, factory), pushes_only=f["kind"] != "panorama")
                if why:
                    s["status"] = "pending"
                    s["waiting"] = f"Panorama is busy ({why}). Wait and try the reboot again."  # noqa: E501
                    _log(plan, "reboot deferred: Panorama busy", detail=why)
                    plan["status"] = "armed"
                    save_plan(profile, plan)
                    raise UpgradeRefused(s["waiting"])
            drv.reboot()
            s["reboot_at"] = _ts()
            return _ok(profile, plan, s)
        elif s["action"] == "wait":
            s["wait_since"] = _ts()
        elif s["action"] in ("ha-suspend", "ha-functional"):
            drv.ha("suspend" if s["action"] == "ha-suspend" else "functional")
            return _ok(profile, plan, s)
        elif s["action"] == "postcheck":
            return postcheck(profile, plan, snap, s, factory)
        save_plan(profile, plan)
        return plan
    except UpgradeRefused:
        raise
    except DeviceError as exc:
        return _fail(profile, plan, s, str(exc), actor)


def _already_downloaded(profile, snap, s, factory) -> bool:
    f = snap["devices"][s["device"]]
    if f["kind"] == "firewall" and paths.mode_of(f) == paths.PANORAMA:
        return False  # Panorama decides; batch download is idempotent
    try:
        items = D.parse_software(reader_for(profile, snap, s["device"], factory).op(D.CMD_SW_INFO))
    except DeviceError:
        return False
    return any(a.version == s["version"] and a.downloaded for a in items)


def _advance_phase(profile: Profile, plan: dict, s: dict, drv) -> dict:
    phases = drv.content_phases()
    while s["phase"] < len(phases):
        label, fn = phases[s["phase"]]
        jid = fn()
        if jid:
            _start_job(s, label, jid)
            save_plan(profile, plan)
            return plan
        s["phase"] += 1
    return _ok(profile, plan, s)


def poll(profile: Profile, plan: dict, factory=None) -> dict:
    """Advance a running step by one look at the device. Safe to call repeatedly."""
    s = next((x for x in plan["steps"] if x["status"] == "running"), None)
    if s is None:
        return plan
    snap = load_snapshot(profile, plan["snapshot"])
    d = _dev(plan, s["device"])
    try:
        drv = driver_for(profile, snap, d, factory)
        if s["action"] == "wait":
            v = drv.running_version()
            s["last_seen"] = v
            if v and V(v) == V(s["version"]):
                return _ok(profile, plan, s, back_at=_ts())
            if now() - datetime.fromisoformat(s["wait_since"]) > WAIT_LIMIT:
                return _fail(profile, plan, s, f"device not back on {s['version']} after {WAIT_LIMIT} (last saw {v})")
            save_plan(profile, plan)
            return plan
        jobs = s.get("jobs") or []
        if not jobs:
            return plan
        j = jobs[-1]
        st = drv.job(j["jobid"])
        j.update({"status": st["status"], "result": st["result"], "progress": st["progress"], "details": st["details"]})
        if st["status"].upper() != "FIN":
            if now() - datetime.fromisoformat(j["started"]) > JOB_LIMIT:
                return _fail(profile, plan, s, f"job {j['jobid']} still {st['status']} after {JOB_LIMIT}")
            save_plan(profile, plan)
            return plan
        if st["result"].upper() != "OK":
            return _fail(profile, plan, s, f"job {j['jobid']} ({j['label']}) failed: {st['details'] or st['result']}")
        j["finished"] = _ts()
        if s["action"] == "content":
            s["phase"] += 1
            return _advance_phase(profile, plan, s, drv)
        return _ok(profile, plan, s)
    except UpgradeRefused as exc:
        return _fail(profile, plan, s, str(exc))
    except DeviceError as exc:
        if s["action"] == "wait":  # still rebooting
            save_plan(profile, plan)
            return plan
        return _fail(profile, plan, s, str(exc))


def backup(profile: Profile, plan: dict, snap: dict, s: dict, factory=None) -> list[str]:
    dev = reader_for(profile, snap, s["device"], factory)
    # Same layout as the off-box copies: <data>/<customer>/upgrade-backups/<hostname>_<serial>/<YYYY>/<MM>/<DD>/<HHMMSS>_<run-id>_<type>
    d = _dev(plan, s["device"])
    idn = {"hostname": s.get("hostname") or d.get("hostname") or "", "serial": s.get("serial") or d.get("serial") or ""}
    when = now()
    folder = profile.data_dir("upgrade-backups") / offsite.device_dir(idn) / offsite.date_dirs(when)
    folder.mkdir(parents=True, exist_ok=True)
    out = []
    f = snap["devices"][s["device"]]
    via_pano = f.get("kind") == "firewall" and paths.mode_of(f) == paths.PANORAMA
    cfg = _export_config(dev, via_pano)
    p = folder / offsite.file_name(when, plan["id"], "running-config", ".xml")
    p.write_bytes(cfg)
    p.chmod(0o600)
    out.append(str(p))
    if via_pano:  # Panorama's own config too: it holds this firewall's device-group and template settings
        pc = _export_config(_pano_reader(profile, snap, f, factory), False)
        q = folder / offsite.file_name(when, plan["id"], "panorama-running-config", ".xml")
        q.write_bytes(pc)
        q.chmod(0o600)
        out.append(str(q))
        s["note"] = ("Exported through Panorama (target=" + (s.get("serial") or "?") + "): firewall running config"
                     " and Panorama's running config")
    if snap["devices"][s["device"]].get("kind") == "panorama":
        s["note"] = "Panorama: running config exported (device-state export applies to firewalls only)"
        _offsite(profile, plan, s, out, when)
        return out
    if via_pano:  # PAN-OS refuses a device-state export through Panorama ("Device parameter needed"), so do not ask
        s["note"] += (". Device state is not exportable through Panorama; Panorama keeps this firewall's config versions "
                      "(Panorama > Managed Devices > Summary > Device Config Backups)")
        _offsite(profile, plan, s, out, when)
        return out
    try:
        ds = dev.export("device-state")
        if ds:
            q = folder / offsite.file_name(when, plan["id"], "device-state", ".tgz")
            q.write_bytes(ds)
            q.chmod(0o600)
            out.append(str(q))
    except DeviceError as exc:
        s["warning"] = f"device-state export failed ({exc}); the running config was saved"
    _offsite(profile, plan, s, out, when)
    return out


def backup_destinations(profile: Profile) -> tuple[list[str], bool]:
    """Where an upgrade backup goes: the local server copy, then each enabled off-box destination. (labels, any off-box)."""
    try:
        dests = [d for d in offsite.load_config(profile.name) if d.get("enabled")]
    except Exception:  # noqa: BLE001 - unreadable config: say local only; the step itself reports the error
        dests = []
    kinds = {"s3": "S3", "sftp": "SFTP", "ftps": "FTPS", "git": "Git repository"}
    labels = ["this server (customer backup folder)"] + [f"{d.get('name') or d['id']} ({kinds.get(d['type'], d['type'])})"
                                                          for d in dests]
    return labels, bool(dests)


def backup_files(profile: Profile, plan: dict, n: int | None = None) -> list[Path]:
    """Backup files a plan's backup step(s) wrote; only paths inside this customer's upgrade-backups folder."""
    root = profile.data_dir("upgrade-backups").resolve()
    out = []
    for s in plan.get("steps") or []:
        if s.get("action") != "backup" or (n is not None and s.get("n") != n):
            continue
        for f in s.get("files") or []:
            p = Path(f).resolve()
            if p.is_file() and root in p.parents:
                out.append(p)
    return out


def _is_panorama_config(cfg: bytes) -> bool:
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(cfg)
    except ET.ParseError:
        return False
    return root.find("./devices/entry/device-group") is not None


def _export_config(dev, via_pano: bool) -> bytes:
    """Running config as XML.

    Through Panorama, ``type=export&category=configuration&target=<serial>`` returns *Panorama's* config (for example
    PAN-OS 11.1.13-h17), so the firewall's config is read with the proxied op ``show config running`` and checked
    to be a firewall config (no device groups).
    """
    import xml.etree.ElementTree as ET

    if via_pano:
        el = D._result(dev.op("<show><config><running></running></config></show>")).find("config")
        cfg = ET.tostring(el) if el is not None else b""
        if not cfg or _is_panorama_config(cfg):
            raise DeviceError("Panorama did not return the firewall's running config (show config running, target=serial)")
        return cfg
    cfg = dev.export("configuration")
    if b"<config" not in cfg[:5000]:
        raise DeviceError("running-config export did not return a <config> document")
    return cfg


def _offsite(profile: Profile, plan: dict, s: dict, files: list[str], when: datetime | None = None) -> None:
    """Copy the local backup to the customer's configured destinations. Never fails the step (yellow only)."""
    d = _dev(plan, s["device"])
    pre = next((x.get("snapshot") for x in plan["steps"] if x["device"] == s["device"] and x["action"] == "precheck"
                and x.get("snapshot")), {}) or {}
    items = [offsite.Item(Path(f), "device-state" if f.endswith(".tgz") else
                          "panorama-running-config" if "panorama-running-config" in Path(f).name else "running-config") for f in files]
    idn = {"hostname": s.get("hostname") or d.get("hostname") or "", "serial": s.get("serial") or d.get("serial") or "",
           "model": d.get("model") or ""}
    try:
        res = offsite.ship(profile, items, run_id=plan["id"], kind="os-upgrade", ident=idn, actor=s.get("by", ""), when=when,
                           cr=plan.get("cr", ""), audit=audit,
                           extra={"profile_name": d.get("name"), "device_kind": d.get("kind"),
                                  "versions": {"running": pre.get("sw_version") or d.get("current"), "target": d.get("target"),
                                               "app": pre.get("app_version") or "", "threat": pre.get("threat_version") or ""},
                                  "plan_step": s["n"]})
    except Exception as exc:  # noqa: BLE001 - belt and braces: ship() itself never raises
        res = [{"dest": "?", "name": "off-box copy", "type": "?", "ok": False, "files": [], "error": str(exc)[:300]}]
    if res:
        s["offsite"] = res
        bad = [r for r in res if not r["ok"]]
        if bad:
            s["offsite_warning"] = "; ".join(offsite.summary_lines(bad))
            _log(plan, "off-box backup copy failed (local backup kept; the upgrade continues)",
                 destinations=[r["name"] for r in bad])


def postcheck(profile: Profile, plan: dict, snap: dict, s: dict, factory=None) -> dict:
    d = _dev(plan, s["device"])
    f = snap["devices"][s["device"]]
    live = D.discover(reader_for(profile, snap, s["device"], factory), kind=f["kind"], refresh=False)
    pre = next((x.get("snapshot") for x in plan["steps"] if x["device"] == s["device"] and x["action"] == "precheck"
                and x.get("snapshot")), {}) or {}
    res = []

    def chk(name, ok, detail=""):
        res.append({"check": name, "ok": bool(ok), "detail": detail})
    chk("version", live.get("sw_version") and V(live["sw_version"]) == V(d["target"]),
        f"running {live.get('sw_version')}, expected {d['target']}")
    ha = live.get("ha") or {}
    if ha.get("enabled"):
        chk("ha state", (ha.get("local_state") or "").lower() in ("active", "passive", "active-primary", "active-secondary"),
            ha.get("local_state", ""))
        chk("ha sync", (ha.get("running_sync") or "").lower() == "synchronized", ha.get("running_sync", ""))
    if f["kind"] == "firewall":
        if f.get("managed_by"):
            m = next((x for x in D.parse_connected(reader_for(profile, snap, f["managed_by"], factory).op(D.CMD_CONNECTED))
                      if x["serial"] == f.get("serial")), None)
            chk("connected to Panorama", m is not None and m["connected"], "show devices connected on Panorama")
            if m is not None and paths.mode_of(f) == paths.PANORAMA:
                chk("Panorama sees the new version", m.get("sw_version") and V(m["sw_version"]) == V(d["target"]),
                    f"Panorama lists {m.get('sw_version')}, expected {d['target']}")
                for k, v in (m.get("sync") or {}).items():  # Panorama's policy/template sync view, when it reports one
                    chk(f"Panorama {k}", "out of sync" not in v.lower() and "fail" not in v.lower(), v)
        if f.get("managed_by") and paths.mode_of(f) == paths.PANORAMA:
            # Panorama's own device group and template views say whether the firewall is in sync after the reboot.
            pano_rd = reader_for(profile, snap, f["managed_by"], factory)
            for cmd, what in (("<show><devicegroups></devicegroups></show>", "device group"),
                              ("<show><templates></templates></show>", "template")):
                try:
                    rows = D.sync_for_serial(pano_rd.op(cmd), d.get("serial") or f.get("serial") or "")
                except DeviceError:
                    continue
                for cont, field, val in rows:
                    ok = val.strip().lower() == "in sync"
                    res.append({"check": f"{what} {cont} sync", "ok": True, "level": "ok" if ok else "warn",
                                "detail": val + ("" if ok else " (not a failure: push from Panorama or wait a minute, then check Panorama > Managed Devices)")})
        ps = live.get("panorama_status") or {}
        if ps.get("managed"):
            chk("panorama-status", ps.get("connected") is True, ", ".join(str(x) for x in ps.get("servers") or []))
        before = (pre.get("interfaces") or {}).get("up")
        after = (live.get("interfaces") or {}).get("up")
        if before is not None and after is not None:
            chk("interfaces up", after >= before, f"{after} up after vs {before} before")
        chk("sessions", True, f"active sessions {(live.get('sessions') or {}).get('active')}")
    lc = live.get("last_commit") or {}
    if lc:
        res_ = (lc.get("result") or "").upper()
        running = res_ in ("PEND", "ACT", "")  # a commit or Panorama push in progress (often someone else's) is not a failure
        chk("last commit", res_ != "FAIL" and (res_ == "OK" or running),
            f"job {lc.get('id')} {lc.get('type')} {lc.get('result')}" + (" (still running; check it finishes)" if running and res_ else ""))
    s["results"] = res
    s["snapshot_after"] = {k: live.get(k) for k in ("sw_version", "app_version", "threat_version", "ha", "panorama_status",
                                                     "interfaces", "sessions", "last_commit")}
    bad = [r for r in res if not r["ok"]]
    if bad:
        return _fail(profile, plan, s, "post-check failed: " + "; ".join(f"{r['check']} ({r['detail']})" for r in bad))
    return _ok(profile, plan, s)


# ---------------------------------------------------------------- report

def write_report(profile: Profile, plan: dict) -> tuple[Path, Path]:
    folder = upgrade_dir(profile)
    jp = folder / f"{plan['id']}-report.json"
    jp.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    jp.chmod(0o600)
    L = [f"# OS upgrade report {plan['id']}", "",
         f"- Customer: {plan['customer']}", f"- Mode: {plan['mode']}  Status: **{plan['status']}**",
         f"- CR: {plan.get('cr') or '(dry run)'}  Armed by: {plan.get('armed_by', '')} at {plan.get('armed_at', '')}",
         f"- Report written: {_ts()} (America/Chicago)", "", "## Devices", "",
         "| Hostname | Serial | Profile name | Kind | Before | Target | Plan check |", "|---|---|---|---|---|---|---|"]
    for d in plan["devices"]:
        L.append(f"| {d.get('hostname') or ident.UNKNOWN_HOST} | {d.get('serial') or ident.UNKNOWN_SERIAL} | {d['name']} "
                 f"| {d['kind']} | {d['current']} | {d['target']} | {d['status']} |")
    L += ["", "## Steps", "", "| # | Step | Status | Started | Finished | Jobs / notes |", "|---|---|---|---|---|---|"]
    for s in plan["steps"]:
        jobs = "; ".join(f"{j['label']} job {j['jobid']} {j.get('result', '')}" for j in s.get("jobs") or [])
        off = "; ".join(offsite.summary_lines(s.get("offsite") or []))
        note = " ".join(x for x in (jobs, s.get("note", ""), off, s.get("error", ""), s.get("hint", ""), s.get("waiting", "")) if x)
        L.append(f"| {s['n']} | {s['title']} | {s['status']} | {s.get('started', '')} | {s.get('finished', '')} | {note[:300]} |")
    posts = [s for s in plan["steps"] if s["action"] == "postcheck" and s.get("results")]
    if posts:
        L += ["", "## Post-checks", ""]
        for s in posts:
            L.append(f"### {ident.label(s['device_name'], s)}")
            L += [f"- {'OK' if r['ok'] else 'FAIL'}: {r['check']} {r['detail']}" for r in s["results"]]
    L += ["", "## Log", ""] + [f"- {x['ts']} {x['step']}" for x in plan.get("log", [])]
    mp = folder / f"{plan['id']}-report.md"
    mp.write_text("\n".join(L) + "\n", encoding="utf-8")
    mp.chmod(0o600)
    return mp, jp


def run_until_idle(profile: Profile, plan_id: str, *, interval: int = 15, factory=None, echo=print) -> dict:
    """CLI helper: poll the running step until it finishes (ok/failed)."""
    while True:
        plan = load_plan(profile, plan_id)
        s = next((x for x in plan["steps"] if x["status"] == "running"), None)
        if s is None:
            return plan
        plan = poll(profile, plan, factory)
        s2 = next((x for x in plan["steps"] if x["n"] == s["n"]), s)
        j = (s2.get("jobs") or [{}])[-1]
        echo(f"{_ts()} step {s2['n']} {s2['action']} {s2['status']} {j.get('label', '')} {j.get('status', '')} "
             f"{j.get('progress', '')} {s2.get('last_seen', '') or ''}")
        if s2["status"] != "running":
            return plan
        time.sleep(interval)
