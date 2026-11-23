"""CR-template change plan for an OS upgrade plan (same section headings as the rule change plans)."""

from __future__ import annotations

from panlab import identity as ident
from panlab.upgrade import paths


def _hs(d: dict) -> str:
    """hostname (serial) as the device reports it; explicit 'unknown' rather than a blank."""
    return ident.hs(d.get("identity") or {"hostname": d.get("hostname"), "serial": d.get("serial")})


def _lbl(d: dict) -> str:
    return ident.label(d["name"], d.get("identity") or {"hostname": d.get("hostname"), "serial": d.get("serial")})


def _gui(s: dict, d: dict) -> list[str]:
    managed = d["kind"] == "firewall" and paths.mode_of(d) == paths.PANORAMA
    a, v = s["action"], s.get("version", "")
    if a == "precheck":
        return ["Dashboard: note the software version, HA state and uptime. Commit status shows no pending changes."]
    if a == "backup":
        nav = "Panorama > Setup > Operations" if d["kind"] == "panorama" else "Device > Setup > Operations"
        return [f"{nav} > Export named configuration snapshot (running-config.xml) and Export device state. Save both to the CR."]
    if a == "content":
        if managed:
            return ["Panorama > Device Deployment > Dynamic Updates > Check Now; Download the newest Apps and Threats package; "
                    f"Install > select {_hs(d)} > OK. Wait for the job to finish (Tasks)."]
        nav = "Panorama > Dynamic Updates" if d["kind"] == "panorama" else "Device > Dynamic Updates"
        return [f"{nav} > Check Now; Download and Install the newest Applications (and Threats) package."]
    if a == "download":
        nav = "Panorama > Device Deployment > Software" if managed else ("Panorama > Software" if d["kind"] == "panorama" else "Device > Software")
        return [f"{nav} > Check Now; find {v}; Download. Wait for the job to finish."]
    if a == "install":
        if managed:
            return [f"Panorama > Device Deployment > Software > {v} > Install > select {_hs(d)} only; leave Reboot unchecked > OK."]
        return [f"{'Panorama' if d['kind'] == 'panorama' else 'Device'} > Software > {v} > Install. Do not reboot yet."]
    if a == "reboot":
        if managed:
            return [f"Panorama > Managed Devices > Summary: confirm {_hs(d)} shows the new version pending; reboot it from its own "
                    "GUI (Device > Setup > Operations > Reboot Device)."]
        return [f"{'Panorama' if d['kind'] == 'panorama' else 'Device'} > Setup > Operations > Reboot. On Panorama, first check "
                "Tasks for running commits/pushes and that nobody has uncommitted changes."]
    if a == "wait":
        return [f"Wait 10-25 minutes; log in again and confirm the Dashboard shows {v}."]
    if a == "ha-suspend":
        return ["Device > High Availability > Operational Commands > Suspend local device."]
    if a == "ha-functional":
        return ["Device > High Availability > Operational Commands > Make local device functional; confirm the peers sync."]
    if a == "postcheck":
        return ["Dashboard: version, HA state; Panorama > Managed Devices > Summary shows Connected and in sync; "
                "Network > Interfaces are up as before; Monitor > Traffic shows sessions."]
    return []


def _cli(s: dict, d: dict) -> list[str]:
    managed = d["kind"] == "firewall" and paths.mode_of(d) == paths.PANORAMA
    a, v = s["action"], s.get("version", "")
    sn = d.get("serial") or "<FW-SERIAL>"
    if a == "precheck":
        return ["show system info | match sw-version", "show high-availability state", "check pending-changes",
                "show system disk-space", "show jobs all"] + (["show panorama-status"] if d["kind"] == "firewall" else [])
    if a == "backup":
        return ["save config to pre-upgrade-<date>.xml",
                "scp export configuration from running-config.xml to <user>@<host>:<path>",
                "scp export device-state to <user>@<host>:<path>"]
    if a == "content":
        if managed:
            return ["# on Panorama", "request batch content check", "request batch content download file <panupv2-all-contents-...>",
                    f"request batch content upload-install file <panupv2-all-contents-...> devices {sn}", "show jobs id <job>"]
        return ["request content upgrade check", "request content upgrade download latest", "show jobs id <job>",
                "request content upgrade install version latest", "show jobs id <job>"]
    if a == "download":
        if managed:
            return ["# on Panorama", "request batch software check", f"request batch software download file PanOS_<platform>-{v}",
                    "show jobs id <job>"]
        return ["request system software check", f"request system software download version {v}", "show jobs id <job>"]
    if a == "install":
        if managed:
            return ["# on Panorama", f"request batch software upload-install file PanOS_<platform>-{v} devices {sn}", "show jobs id <job>"]
        return [f"request system software install version {v}", "show jobs id <job>"]
    if a == "reboot":
        if managed:
            return ["# on Panorama", f"request batch reboot devices {sn}"]
        return (["show jobs all   # nothing ACT/PEND", "check pending-changes   # no"] if d["kind"] == "panorama" else []) + ["request restart system"]
    if a == "wait":
        return ["show system info | match sw-version"] + (["# on Panorama", "show devices connected"] if managed else [])
    if a == "ha-suspend":
        return ["request high-availability state suspend"]
    if a == "ha-functional":
        return ["request high-availability state functional", "show high-availability state"]
    if a == "postcheck":
        return ["show system info | match sw-version", "show high-availability state", "show interface all", "show session info",
                "show jobs all"] + (["show panorama-status"] if d["kind"] == "firewall" else ["show devices connected"])
    return []


def _is_down(d: dict) -> bool:
    from panlab.upgrade.versions import is_downgrade
    return is_downgrade(d.get("current") or "", d.get("target") or "")


def render_cr(plan: dict) -> str:
    devs = {d["id"]: d for d in plan["devices"]}
    order = [d for d in plan["devices"]]
    down = [d for d in order if _is_down(d)]
    word = "downgrade" if down and len(down) == len(order) else "upgrade"
    moves = ", ".join(f"{_lbl(d)} {d['current']} -> {d['target']}" for d in order)
    L = [f"# PAN-OS {word}: {moves}", "",
         f"- Customer: {plan['customer']}", f"- Plan: {plan['id']} (created {plan['created']} America/Chicago)",
         f"- Overall check: **{plan.get('status_light', '').upper()}**", "",
         "## Devices in scope", "",
         "Hostname and serial are what each device reported over the API when the plan was built. Check them on the "
         "device (Dashboard > General Information) before you start.", "",
         "| Hostname | Serial | Profile name | Model | Kind | Current | Target |", "|---|---|---|---|---|---|---|",
         *[f"| {d.get('hostname') or ident.UNKNOWN_HOST} | {d.get('serial') or ident.UNKNOWN_SERIAL} | {d['name']} | "
           f"{d.get('model') or ''} | {d['kind']} | {d['current']} | {d['target']} |" for d in order], "",
         *[f"- Upgrade path for {_lbl(d)}: **{d.get('path_text') or paths.describe(d)}**" for d in order if d["kind"] == "firewall"],
         "",
         "## How to use this plan", "",
         "Do the steps in order, one device at a time. Panorama is always upgraded before the firewalls it manages, and a "
         "firewall is never taken above its Panorama. For an HA pair the passive unit goes first. If any check is red or a job "
         "fails, stop and ask; do not improvise.", "", "## Pre-checks", ""]
    for d in order:
        L.append(f"### {_lbl(d)} ({d['kind']}, {d.get('model') or ''})")
        L += [f"- [{c['level'].upper()}] {c['title']}. {c['detail']}" for c in d["checks"]]
        L.append("")
    L += ["## Implementation Plan", ""]
    for s in plan["steps"]:
        L.append(f"{s['n']}. **{s['title']}**. {s['explain']}")
        L += [f"   - {g}" for g in _gui(s, devs[s['device']])]
    L += ["", "## Implementation (CLI)", ""]
    for s in plan["steps"]:
        cli = _cli(s, devs[s["device"]])
        if cli:
            L += [f"# {s['n']}. {s['title']}", "```", *cli, "```", ""]
    L += ["## Impact Analysis Statement", "",
          "Each device reboots once per install (10-25 minutes). A standalone firewall passes no traffic while it reboots; an HA "
          "pair keeps passing traffic on the peer. While Panorama reboots, managed firewalls keep running their last pushed "
          "config but cannot be changed from Panorama.", "",
          "## Backout Plan", "",
          *([f"This plan **downgrades** {', '.join(_lbl(d) for d in down)}. To go forward again, build a new plan from the OS upgrade "
             "page with the original version as the target (the image stays on Panorama and the firewall). The tool does the same "
             "steps: download, install, reboot, wait, post-check.", ""] if down else []),
          "If a device misbehaves after the change, boot the previous partition (the version it ran before):", "",
          "```", "debug swm revert", "request restart system", "```", "",
          "GUI: Device (or Panorama) > Software > the previously installed version > Revert. If config is damaged, load the "
          "pre-upgrade backup: `load config from pre-upgrade-<date>.xml` then commit. Revert a firewall before its Panorama, "
          "never Panorama below its firewalls.", "",
          "## Validation Plan", "",
          "After each device: version is the target, HA state and sync are normal, the firewall shows Connected in Panorama "
          "(`show panorama-status`), interfaces that were up are up, sessions are flowing, and the last commit job is OK. "
          "The tool's post-check does all of these and writes a timestamped report.", "",
          "## Communications Plan", "",
          "Notify stakeholders before the window, at each device reboot, and when complete with the report attached.", ""]
    return "\n".join(L)
