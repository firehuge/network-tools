# SPDX-License-Identifier: Apache-2.0
"""Push a saved change set to a standalone firewall: backup, re-validate, diff, apply, commit, verify, rollback.

Flow (GUI and CLI share it):

1. ``prepare``: export the running config to the customer's backups folder,
   re-validate the change set against it (vsys/zones/reused objects still
   exist, no rule or object name conflicts), build the exact API operations
   and a dry-run diff, and save a push session file. Nothing is written yet.
2. ``apply``: requires the engineer to type the target name. Refuses if the
   session is stale, someone has uncommitted changes, or a fresh export no
   longer validates. Writes the candidate, commits with the CR in the commit
   description, then verifies the running config (objects and rules exist,
   ``test security-policy-match`` hits the new rule). Any failure before the
   commit reverts the candidate.
3. ``rollback``: deletes the session's rules, then only the objects this push
   created that nothing else references; commits and verifies they are gone.

Every step appends one JSON line to the customer's audit log
(``<data>/<customer>/audit/audit.jsonl``): who, when, CR, target, change
set, session, job ids, result.

Panorama targets are **dry-run only**: ``prepare`` reads the Panorama config
(live read-only export, or the profile's offline file), re-validates against
the device-group hierarchy (DG exists, target firewalls are members, zones
exist on them, reused objects visible in the DG chain or shared, rule names
unique across every device group), builds the device-group XPath operations,
the diff and the commit-and-push plan, and stops with status ``dry-run``.
``apply`` and ``rollback`` refuse for Panorama and write nothing, unless the
customer profile (or a server override) sets ``allow_live_panorama_push: true``.
That opt-in is for a controlled test environment only; dry-run stays the default.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from zoneinfo import ZoneInfo

from panlab.changeplan import PROTO_NUM, _first_ip, _values, referenced_elsewhere
from panlab.customers import Profile, Target
from panlab.netmodel import load_environment

TZ = ZoneInfo("America/Chicago")
STALE_AFTER = timedelta(minutes=30)
SESSION_RE = re.compile(r"^push-\d{8}-\d{6}-[0-9a-f]{6}$")
PREDEFINED = {"any", "application-default", "service-http", "service-https"}
VSYS_XP = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']"
DG_XP = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{dg}']"
PANORAMA_DRY_RUN = ("Panorama push is dry-run only in this version: nothing is written to Panorama. "
                    "Use the change plan (set CLI / GUI steps / commit-and-push plan) to implement it by hand.")


class PushError(RuntimeError):
    pass


def live_panorama_push_allowed(profile: Profile) -> bool:
    """True only when this customer has explicitly opted in to live Panorama apply."""
    return bool(getattr(profile, "allow_live_panorama_push", False))


class DeviceAPI(Protocol):
    def export_running(self) -> str: ...
    def set(self, xpath: str, element: str) -> None: ...
    def delete(self, xpath: str) -> None: ...
    def exists_running(self, xpath: str) -> bool: ...
    def pending_changes(self) -> bool: ...
    def revert(self) -> None: ...
    def commit(self, description: str) -> dict: ...
    def policy_match(self, query: dict) -> str | None: ...
    def commit_all(self, cmd: str) -> dict: ...
    def move(self, xpath: str, where: str, dst: str | None = None) -> None: ...


class XapiDevice:
    """pan-os-python / pan-python XML API. Secrets stay inside the Firewall object."""

    def __init__(self, fw):
        self.fw = fw

    def export_running(self) -> str:
        from panlab.backup import export_running_config

        return export_running_config(self.fw)

    def set(self, xpath: str, element: str) -> None:
        self.fw.xapi.set(xpath=xpath, element=element)

    def delete(self, xpath: str) -> None:
        self.fw.xapi.delete(xpath=xpath)

    def exists_running(self, xpath: str) -> bool:
        try:
            self.fw.xapi.show(xpath=xpath)
        except Exception as exc:  # "No such node" etc.
            if "no such node" in str(exc).lower() or "doesn't exist" in str(exc).lower():
                return False
            raise
        res = self.fw.xapi.element_result
        return res is not None and len(list(res)) > 0

    def _op(self, cmd: str) -> ET.Element | None:
        self.fw.xapi.op(cmd=cmd)
        return self.fw.xapi.element_result

    def pending_changes(self) -> bool:
        res = self._op("<check><pending-changes></pending-changes></check>")
        return (("".join(res.itertext()) if res is not None else "").strip().lower() == "yes")

    def revert(self) -> None:
        self._op("<revert><config></config></revert>")

    def commit(self, description: str) -> dict:
        cmd = f"<commit><description>{_x(description)}</description></commit>"
        r = self.fw.commit(sync=True, cmd=cmd) or {}
        return {"jobid": r.get("jobid"), "success": bool(r.get("success")), "result": r.get("result"),
                "messages": [str(m) for m in (r.get("messages") or [])][:20]}

    def commit_all(self, cmd: str) -> dict:
        """Panorama commit-all (push to devices). ``cmd`` is a <commit-all>... element."""
        if hasattr(self.fw, "commit_all"):
            r = self.fw.commit_all(sync=True, sync_all=True, cmd=cmd) or {}
        else:
            r = self.fw.commit(sync=True, cmd=cmd) or {}
        return {"jobid": r.get("jobid"), "success": bool(r.get("success")), "result": r.get("result"),
                "messages": [str(m) for m in (r.get("messages") or [])][:20]}

    def move(self, xpath: str, where: str, dst: str | None = None) -> None:
        kw = {"xpath": xpath, "where": where}
        if dst:
            kw["dst"] = dst
        self.fw.xapi.move(**kw)

    def policy_match(self, q: dict) -> str | None:
        cmd = ("<test><security-policy-match>" + "".join(f"<{k}>{_x(str(v))}</{k}>" for k, v in q.items())
               + "</security-policy-match></test>")
        res = self._op(cmd)
        if res is None:
            return None
        e = res.find(".//entry")
        return e.get("name") if e is not None else None

    def policy_match_on(self, serial: str, q: dict) -> str | None:
        """Panorama only: run ``test security-policy-match`` on a managed firewall (target=serial)."""
        cmd = ("<test><security-policy-match>" + "".join(f"<{k}>{_x(str(v))}</{k}>" for k, v in q.items())
               + "</security-policy-match></test>")
        self.fw.xapi.op(cmd=cmd, extra_qs={"target": serial})
        res = self.fw.xapi.element_result
        if res is None:
            return None
        e = res.find(".//entry")
        return e.get("name") if e is not None else None


def _x(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _members(tag: str, vals: list[str]) -> str:
    return f"<{tag}>" + "".join(f"<member>{_x(v)}</member>" for v in vals) + f"</{tag}>"


def _q(name: str) -> str:
    if "'" in name:
        raise PushError(f"name {name!r} contains a quote; refusing")
    return name


def _obj_element(o: dict) -> str:
    n = _x(o["name"])
    if o["kind"] == "address":
        d = f"<description>{_x(o['description'])}</description>" if o.get("description") else ""
        return f'<entry name="{n}"><{o["type"]}>{_x(o["value"])}</{o["type"]}>{d}</entry>'
    if o["kind"] == "address-group":
        mem = "".join(f"<member>{_x(m)}</member>" for m in o.get("members") or [])
        d = f"<description>{_x(o['description'])}</description>" if o.get("description") else ""
        return f'<entry name="{n}"><static>{mem}</static>{d}</entry>'
    if o["kind"] == "service":
        return f'<entry name="{n}"><protocol><{o["protocol"]}><port>{_x(str(o["port"]))}</port></{o["protocol"]}></protocol></entry>'
    return f'<entry name="{n}"/>'


def _rule_element(r: dict, targets: list[dict] | None = None) -> str:
    parts = [_members("from", r["from"]), _members("to", r["to"]), _members("source", r["source"] or ["any"]),
             _members("destination", r["destination"] or ["any"]), _members("source-user", r["source_user"] or ["any"]),
             _members("application", r["application"] or ["any"]), _members("service", r["service"] or ["any"]),
             f"<action>{r['action']}</action>", "<log-end>yes</log-end>"]
    if r["tags"]:
        parts.append(_members("tag", r["tags"]))
    if r.get("description"):
        parts.append(f"<description>{_x(r['description'][:1023])}</description>")
    if targets:
        devs = {}
        for t in targets:
            devs.setdefault(t.get("serial") or t["device"], []).append(t["vsys"])
        parts.append("<target><devices>" + "".join(
            f'<entry name="{_x(sn)}"><vsys>' + "".join(f'<entry name="{_x(v)}"/>' for v in vs) + "</vsys></entry>"
            for sn, vs in devs.items()) + "</devices><negate>no</negate></target>")
    return f'<entry name="{_x(r["name"])}">' + "".join(parts) + "</entry>"


def _base(g: dict, o: dict | None = None) -> str:
    if o is not None and o.get("location") == "shared":
        return "/config/shared"
    if g.get("backend") == "panorama":
        return DG_XP.format(dg=_q(g["device_group"]))
    return VSYS_XP.format(vsys=_q(g.get("vsys") or "vsys1"))


def now() -> datetime:
    return datetime.now(TZ)


def cs_hash(cs: dict) -> str:
    return hashlib.sha256(json.dumps(cs, sort_keys=True).encode()).hexdigest()[:16]


def check_cr(profile: Profile, cr: str) -> str:
    cr = (cr or "").strip()
    if not cr or not re.fullmatch(profile.tickets["cr"], cr):
        raise PushError(f"CR number {cr!r} does not match this customer's CR format ({profile.tickets['cr']})")
    return cr


# ---------------------------------------------------------------- audit + sessions

def audit(profile: Profile, **rec: Any) -> None:
    p = profile.data_dir("audit") / "audit.jsonl"
    rec = {"ts": now().isoformat(timespec="seconds"), "customer": profile.name, **rec}
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def read_audit(profile: Profile, limit: int = 200) -> list[dict]:
    p = profile.data_dir("audit") / "audit.jsonl"
    if not p.is_file():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()][-limit:]


def _session_path(profile: Profile, sid: str) -> Path:
    if not SESSION_RE.match(sid or ""):
        raise PushError("bad push session id")
    return profile.data_dir("push") / f"{sid}.json"


def load_session(profile: Profile, sid: str) -> dict:
    p = _session_path(profile, sid)
    if not p.is_file():
        raise PushError(f"no push session {sid}")
    return json.loads(p.read_text(encoding="utf-8"))


def _save(profile: Profile, s: dict) -> None:
    p = _session_path(profile, s["id"])
    p.write_text(json.dumps(s, indent=2), encoding="utf-8")
    p.chmod(0o600)


def _step(s: dict, what: str, **kw: Any) -> None:
    s.setdefault("log", []).append({"ts": now().isoformat(timespec="seconds"), "step": what, **kw})


def _tickets(cs: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"ritm": [], "sctask": [], "cr": []}
    for f in cs.get("files", []):
        for k in out:
            out[k] += [t for t in f.get("tickets", {}).get(k, []) if t not in out[k]]
    return out


def _device_hs(s: dict) -> str:
    from panlab import identity

    return identity.label(s["target"], s.get("identity"))


def write_report(profile: Profile, s: dict, cs: dict) -> tuple[Path, Path]:
    """Change-audit report for one push session (md + json), attachable to the CR."""
    t = _tickets(cs)
    rep = {"schema": "panlab.push-report/v1", "generated": now().isoformat(timespec="seconds"), "timezone": "America/Chicago",
           "customer": profile.name, "session": s["id"], "status": s["status"], "result": s.get("result", ""),
           "cr": s["cr"], "ritm": t["ritm"], "sctask": t["sctask"], "change_set_cr": t["cr"], "target": s["target"],
           "change_set": s["changeset"], "change_set_hash": s["changeset_hash"],
           "prepared_by": s["prepared_by"], "prepared_at": s["prepared_at"], "applied_by": s.get("applied_by"),
           "applied_at": s.get("applied_at"), "backup_file": Path(s["backup"]).name,
           "validation_errors": s["errors"], "warnings": s["warnings"], "skipped_existing": s["skip"], "diff": s["diff"],
           "commit_jobs": s["jobs"], "verification": s.get("verify", []),
           "policy_match": [v for v in s.get("verify", []) if "policy-match" in v["check"]],
           "rollback": s.get("rollback_result"), "rollback_verification": s.get("rollback_verify", []), "steps": s.get("log", []),
           "device_identity": s.get("identity"),
           "target_type": s.get("target_type", "firewall"), "push_plan": s.get("push_plan", []),
           "rollback_ops": [{"kind": o["kind"], "name": o["name"], "xpath": o["xpath"]} for o in s.get("rollback_ops", [])]}
    d = profile.data_dir("push")
    jp, mp = d / f"{s['id']}-report.json", d / f"{s['id']}-report.md"
    jp.write_text(json.dumps(rep, indent=2), encoding="utf-8")
    ok = lambda v: "OK" if v["ok"] else "FAIL"  # noqa: E731
    md = [f"# Firewall change audit report: {s['id']}", "",
          f"- Generated: {rep['generated']} (America/Chicago)", f"- Customer: {profile.name}", f"- Target: {s['target']}",
          f"- Device (as it reported itself): {_device_hs(s)}",
          f"- CR: {s['cr']}", f"- RITM: {', '.join(t['ritm']) or 'none'}", f"- SCTASK: {', '.join(t['sctask']) or 'none'}",
          f"- Change set: {s['changeset']} (sha256 {s['changeset_hash']})",
          f"- Prepared by {s['prepared_by']} at {s['prepared_at']}; applied by {s.get('applied_by') or '-'} at {s.get('applied_at') or '-'}",
          f"- Backup of running config before the change: `{rep['backup_file']}`",
          *[f"- Off-box copy {'OK' if r['ok'] else 'FAILED (local kept)'}: {r['name']} ({r['type']}) {r.get('error') or ''}".rstrip()
            for r in s.get("offsite") or []],
          f"- Final status: **{s['status']}** {s.get('result', '')}", "", "## Steps (America/Chicago)", "",
          "| Time | Step | Detail |", "|---|---|---|"]
    for st in s.get("log", []):
        det = "; ".join(f"{k}={v}" for k, v in st.items() if k not in ("ts", "step"))
        md.append(f"| {st['ts']} | {st['step']} | {det.replace('|', '/')[:300]} |")
    md += ["", "## Change (dry-run diff that was applied)", "", "```", *s["diff"], "```", "", "## Commit jobs", ""]
    md += [f"- {j['step']}: job {j.get('jobid')} success={j.get('success')} ({'; '.join(j.get('messages') or [])[:300]})" for j in s["jobs"]] or ["- none"]
    md += ["", "## Verification", ""] + ([f"- {ok(v)}: {v['check']} {v.get('detail', '')}" for v in s.get("verify", [])] or ["- not run"])
    if s.get("rollback_result"):
        rr = s["rollback_result"]
        md += ["", "## Rollback", "", f"- By {rr['by']} at {rr['at']}; backup before rollback `{Path(rr['backup']).name}`",
               *[f"- kept: {k}" for k in rr["kept"]], *[f"- {ok(v)}: {v['check']}" for v in s.get("rollback_verify", [])]]
    if s.get("push_plan"):
        executed = s.get("live_panorama") and s.get("status") not in ("dry-run", "blocked")
        plan_title = ("## Panorama commit-and-push plan (executed)" if executed
                      else "## Panorama commit-and-push plan (dry run: NOT executed)")
        md += ["", plan_title, "",
               *[f"- {p['step']}: `{p['api']}` `{p['cmd']}`" for p in s["push_plan"]]]
    if s["errors"] or s["warnings"]:
        md += ["", "## Validation", "", *[f"- error: {x}" for x in s["errors"]], *[f"- warning: {x}" for x in s["warnings"]]]
    mp.write_text("\n".join(md) + "\n", encoding="utf-8")
    for x in (jp, mp):
        x.chmod(0o600)
    s["report"] = {"md": mp.name, "json": jp.name}
    return mp, jp


# ---------------------------------------------------------------- validation

def revalidate(cs: dict, config_path: Path, target: Target, site_codes: list[str] | None = None) -> tuple[list[str], list[str], dict[str, str]]:
    """(errors, warnings, skip) against a live export. skip: object name -> why it is not created."""
    if cs.get("kind") == "decommission":
        return _revalidate_decom(cs, config_path, target)
    env = load_environment(config_path, target=target.name, site_codes=site_codes)
    errors, warnings, skip = [], [], {}
    if target.type == "panorama" or env.kind == "panorama":
        if env.kind != "panorama" or target.type != "panorama":
            return [f"target {target.name} is a {target.type} but the config is a {env.kind} config"], warnings, skip
        return _revalidate_panorama(cs, env, target)
    dev = env.devices[0]
    for g in cs["groups"]:
        if g["target"] != target.name:
            continue
        if g["backend"] != "firewall":
            errors.append(f"{g.get('device_group')}: device-group change on a firewall target")
            continue
        v = dev.vsys.get(g["vsys"])
        if v is None:
            errors.append(f"vsys {g['vsys']} no longer exists on {target.name}")
            continue
        scopes = env.scopes_for(dev, g["vsys"])
        addrs = {n: a for s in scopes for n, a in s.addresses.items()}
        groups = {n for s in scopes for n in s.address_groups}
        svcs = {n: o for s in scopes for n, o in s.services.items()}
        tags = {t for s in scopes for t in s.tags}
        rules = {n for s in scopes for n in s.rule_names}
        for o in g["objects"]["new"]:
            n = o["name"]
            if o["kind"] == "tag":
                if n in tags:
                    skip[n] = "tag already exists (left in place, not deleted on rollback)"
                continue
            if o["kind"] == "address" and n in addrs:
                a = addrs[n]
                if (a.type, (a.value or "").lower()) == (o["type"], o["value"].lower()):
                    skip[n] = "address already exists with the same value (reused, not deleted on rollback)"
                else:
                    errors.append(f"name conflict: address {n} now exists with value {a.value}")
            elif o["kind"] == "address" and n in groups:
                errors.append(f"name conflict: {n} is now an address group")
            elif o["kind"] == "address-group" and n in groups:
                existing = next((mems for s in scopes for gn, mems in s.address_groups.items() if gn == n), [])
                dynamic = any(n in s.dynamic_address_groups for s in scopes)
                if not dynamic and set(existing) == set(o.get("members") or []):
                    skip[n] = "address group already exists with the same members (reused, not deleted on rollback)"
                else:
                    errors.append(f"name conflict: address-group {n} already exists"
                                  + (" (dynamic)" if dynamic else " with different members"))
            elif o["kind"] == "address-group" and n in addrs:
                errors.append(f"name conflict: {n} is now an address object")
            elif o["kind"] == "service" and n in svcs:
                s = svcs[n]
                if (s.proto, str(s.port)) == (o["protocol"], str(o["port"])):
                    skip[n] = "service already exists with the same port (reused, not deleted on rollback)"
                else:
                    errors.append(f"name conflict: service {n} now exists as {s.proto}/{s.port}")
        for o in g["objects"]["reused"]:
            n, k = o["name"], o["kind"]
            ok = (n in PREDEFINED or (k == "address" and (n in addrs or n in groups)) or (k == "address-group" and n in groups) or (k == "service" and n in svcs)
                  or (k == "tag" and n in tags))
            if not ok:
                errors.append(f"reused {k} {n} no longer exists on {target.name}")
        for r in g["rules"]:
            op = r.get("operation") or "add"
            if op == "already-allowed":
                if r["name"] not in rules:
                    errors.append(f"existing rule {r['name']} that already allows this traffic is gone")
                continue
            if r["needs_human"]:
                errors.append(f"rule {r['name']} still needs a human (zones or flags); fix the change set first")
            if op == "edit":
                if r["name"] not in rules:
                    errors.append(f"existing rule {r['name']} to edit no longer exists")
            elif r["name"] in rules:
                errors.append(f"name conflict: security rule {r['name']} already exists")
            for z in r["from"] + r["to"]:
                if z not in v.zones:
                    errors.append(f"rule {r['name']}: zone {z} does not exist in {g['vsys']}")
            if any(f["level"] == "red" for f in r["flags"]):
                warnings.append(f"rule {r['name']} has red flags: " + "; ".join(f["message"] for f in r["flags"] if f["level"] == "red"))
    if not any(g["target"] == target.name for g in cs["groups"]):
        errors.append(f"change set has nothing for target {target.name}")
    return errors, warnings, skip


def _check_objects(g: dict, scopes, errors: list, skip: dict, below=()) -> None:
    addrs = {n: a for s in scopes for n, a in s.addresses.items()}
    groups = {n for s in scopes for n in s.address_groups}
    svcs = {n: o for s in scopes for n, o in s.services.items()}
    tags = {t for s in scopes for t in s.tags}
    for o in g["objects"]["new"]:
        n = o["name"]
        if o["kind"] == "tag":
            if n in tags:
                skip[n] = "tag already exists (left in place, not deleted on rollback)"
            continue
        if o["kind"] == "address" and n in addrs:
            a = addrs[n]
            if (a.type, (a.value or "").lower()) == (o["type"], o["value"].lower()):
                skip[n] = "address already exists with the same value (reused, not deleted on rollback)"
            else:
                errors.append(f"name conflict: address {n} now exists with value {a.value}")
        elif o["kind"] == "address" and n in groups:
            errors.append(f"name conflict: {n} is now an address group")
        elif o["kind"] == "address-group" and n in groups:
            existing = next((mems for s in scopes for gn, mems in s.address_groups.items() if gn == n), [])
            dynamic = any(n in s.dynamic_address_groups for s in scopes)
            if not dynamic and set(existing) == set(o.get("members") or []):
                skip[n] = "address group already exists with the same members (reused, not deleted on rollback)"
            else:
                errors.append(f"name conflict: address-group {n} already exists"
                              + (" (dynamic)" if dynamic else " with different members"))
        elif o["kind"] == "address-group" and n in addrs:
            errors.append(f"name conflict: {n} is now an address object")
        elif o["kind"] == "service" and n in svcs:
            sv = svcs[n]
            if (sv.proto, str(sv.port)) == (o["protocol"], str(o["port"])):
                skip[n] = "service already exists with the same port (reused, not deleted on rollback)"
            else:
                errors.append(f"name conflict: service {n} now exists as {sv.proto}/{sv.port}")
        for dg in below:
            if o["kind"] != "tag" and (n in dg.scope.addresses or n in dg.scope.address_groups or n in dg.scope.services):
                errors.append(f"name conflict: {o['kind']} {n} already exists in child device group {dg.name}; firewalls "
                              f"there would use that object instead (rename it in the change set)")
    for o in g["objects"]["reused"]:
        n, k = o["name"], o["kind"]
        ok = (n in PREDEFINED or (k == "address" and (n in addrs or n in groups)) or (k == "address-group" and n in groups) or (k == "service" and n in svcs)
              or (k == "tag" and n in tags))
        if not ok:
            errors.append(f"reused {k} {n} is not visible from {g.get('device_group') or g.get('vsys')} (not in it, its parents, or shared)")


def _revalidate_panorama(cs: dict, env, target: Target) -> tuple[list[str], list[str], dict[str, str]]:
    """Device-group aware re-validation for the Panorama dry run."""
    errors: list[str] = []
    warnings: list[str] = []
    skip: dict[str, str] = {}
    all_rules = set(env.shared.rule_names) | {n for dg in env.device_groups.values() for n in dg.scope.rule_names}
    by_serial = {d.serial: d for d in env.devices if d.serial}
    by_name = {d.name: d for d in env.devices}
    seen_rules: set[str] = set()
    for g in cs["groups"]:
        if g["target"] != target.name:
            continue
        if g["backend"] != "panorama":
            errors.append(f"{g.get('device')}/{g.get('vsys')}: standalone-firewall change on a Panorama target")
            continue
        dgn = g["device_group"]
        if not dgn:
            errors.append("rules placed on a Panorama-managed firewall/vsys that is in no device group; Panorama cannot push "
                          "them (add it to a device group or configure it locally)")
            continue
        if dgn not in env.device_groups:
            errors.append(f"device group {dgn} does not exist on {target.name}")
            continue
        chain = env.dg_chain(dgn)
        below = env.dg_descendants(dgn)
        members: dict[str, set[str] | None] = {}
        for dg in [chain[0], *below]:
            for sn, vs in dg.members:
                if not vs:
                    members[sn] = None  # whole firewall
                elif members.get(sn, set()) is not None:
                    members.setdefault(sn, set()).update(vs)
        _check_objects(g, [dg.scope for dg in chain] + [env.shared], errors, skip, below)
        for r in g["rules"]:
            op = r.get("operation") or "add"
            if op == "already-allowed":
                if r["name"] not in all_rules:
                    errors.append(f"existing rule {r['name']} that already allows this traffic is gone")
                continue
            if r["needs_human"]:
                errors.append(f"rule {r['name']} still needs a human (zones or flags); fix the change set first")
            if op == "edit":
                if r["name"] not in all_rules:
                    errors.append(f"existing rule {r['name']} to edit no longer exists")
            elif r["name"] in all_rules:
                errors.append(f"name conflict: security rule {r['name']} already exists in the device-group hierarchy or shared")
            if r["name"] in seen_rules and op != "edit":
                errors.append(f"name conflict: security rule {r['name']} appears twice in this change set")
            seen_rules.add(r["name"])
            if not r["target_devices"]:
                warnings.append(f"rule {r['name']} has no target firewalls: it would apply to every firewall in {dgn}")
            for t in r["target_devices"]:
                d = by_serial.get(t.get("serial")) or by_name.get(t["device"])
                if d is None:
                    errors.append(f"rule {r['name']}: target firewall {t['device']} is not managed by {target.name}")
                    continue
                if d.serial not in members or (members[d.serial] is not None and t["vsys"] not in members[d.serial]):
                    errors.append(f"rule {r['name']}: target firewall {d.name}/{t['vsys']} is not in device group {dgn} or its children")
                if d.no_network:
                    warnings.append(f"rule {r['name']}: no template for {d.name}; zones not checked")
                    continue
                v = d.vsys.get(t["vsys"])
                if v is None:
                    errors.append(f"rule {r['name']}: {d.name} has no {t['vsys']}")
                    continue
                for z in r["from"] + r["to"]:
                    if z not in v.zones:
                        errors.append(f"rule {r['name']}: zone {z} does not exist on {d.name}/{t['vsys']} (template stack {d.stack})")
            if any(f["level"] == "red" for f in r["flags"]):
                warnings.append(f"rule {r['name']} has red flags: " + "; ".join(f["message"] for f in r["flags"] if f["level"] == "red"))
    if not any(g["target"] == target.name for g in cs["groups"]):
        errors.append(f"change set has nothing for target {target.name}")
    return errors, warnings, skip


def push_plan(cs: dict, target: Target) -> list[dict]:
    """Panorama commit-and-push plan: commit to Panorama, then one commit-all per device group limited to the targets."""
    if cs.get("kind") == "decommission":
        return _decom_push_plan(cs, target)
    out = [{"step": "commit to Panorama", "api": "type=commit", "cmd": "<commit><description>panlab CR</description></commit>"}]
    for g in cs["groups"]:
        if g["target"] != target.name or g["backend"] != "panorama" or not (g.get("rules") or g.get("actions")):
            continue
        serials = []
        for r in g["rules"]:
            serials += [t["serial"] for t in r["target_devices"] if t.get("serial") and t["serial"] not in serials]
        devs = "<devices>" + "".join(f'<entry name="{_x(sn)}"/>' for sn in serials) + "</devices>" if serials else ""
        out.append({"step": f"push device group {g['device_group']} to {', '.join(serials) or 'all members'}",
                    "api": "type=commit&action=all",
                    "cmd": f'<commit-all><shared-policy><device-group><entry name="{_x(g["device_group"])}">{devs}</entry>'
                           "</device-group><include-template>no</include-template></shared-policy></commit-all>"})
    return out


def build_ops(cs: dict, target: Target, skip: dict[str, str]) -> tuple[list[dict], list[dict], list[str]]:
    """(apply ops, rollback ops, diff lines). Rollback = rules, then created objects (default tags kept)."""
    if cs.get("kind") == "decommission":
        return _build_decom_ops(cs, target, skip)
    ops, rb, diff = [], [], []
    default_tags = set(cs.get("default_tags") or [])
    for g in cs["groups"]:
        if g["target"] != target.name or g["backend"] != target.type:
            continue
        pano = g["backend"] == "panorama"
        diff.append(f"# {target.name} / device group {g['device_group']} / pre-rulebase" if pano else f"# {target.name} / {g['vsys']}")
        for kind in ("tag", "address", "address-group", "service"):
            for o in g["objects"]["new"]:
                if o["kind"] != kind:
                    continue
                if o["name"] in skip:
                    diff.append(f"= {kind} {o['name']}  ({skip[o['name']]})")
                    continue
                base = _base(g, o)
                ops.append({"op": "set", "xpath": f"{base}/{kind}", "element": _obj_element(o), "kind": kind, "name": o["name"]})
                diff.append(f"+ {kind} {o['name']}" + (f" {o.get('type')} {o.get('value')}" if kind == "address" else
                                                       f" {', '.join(o.get('members') or [])}" if kind == "address-group" else
                                                       f" {o.get('protocol')}/{o.get('port')}" if kind == "service" else ""))
                if not (kind == "tag" and (o["name"] in default_tags or o.get("rollback") == "keep")):
                    rb.append({"xpath": f"{base}/{kind}/entry[@name='{_q(o['name'])}']", "kind": kind, "name": o["name"]})
        base = _base(g)
        rbase = f"{base}/pre-rulebase/security/rules" if pano else f"{base}/rulebase/security/rules"
        rules_rb = []
        for r in g["rules"]:
            op = r.get("operation") or "add"
            if op == "already-allowed":
                diff.append(f"= rule {r['name']} already allows this traffic (no change)")
                continue
            if op == "edit":
                for ed in r.get("edits") or []:
                    field = ed.get("field")
                    if field in ("source", "destination", "tag") and ed.get("values"):
                        for v in ed["values"]:
                            ops.append({"op": "set", "xpath": f"{rbase}/entry[@name='{_q(r['name'])}']/{field}",
                                        "element": f"<member>{_x(v)}</member>",
                                        "kind": "rule-member", "name": f"{r['name']}:{field}:{v}",
                                        "field": field, "member": v, "rule": r["name"]})
                            diff.append(f"+ rule {r['name']} {field} {v}")
                            rules_rb.append({"op": "delete",
                                            "xpath": f"{rbase}/entry[@name='{_q(r['name'])}']/{field}/member[text()='{_q(v)}']",
                                            "kind": "rule-member", "name": f"{r['name']}:{field}:{v}",
                                            "field": field, "member": v, "rule": r["name"]})
                    elif field == "description":
                        ops.append({"op": "set", "xpath": f"{rbase}/entry[@name='{_q(r['name'])}']",
                                    "element": f"<description>{_x(ed.get('value') or '')}</description>",
                                    "kind": "rule-desc", "name": f"{r['name']}:description", "rule": r["name"]})
                        diff.append(f"+ rule {r['name']} description (append tickets)")
                        prev = ed.get("previous") or ""
                        if prev:
                            rules_rb.append({"op": "set", "xpath": f"{rbase}/entry[@name='{_q(r['name'])}']",
                                            "element": f"<description>{_x(prev)}</description>",
                                            "kind": "rule-desc", "name": f"{r['name']}:description", "rule": r["name"]})
                        else:
                            rules_rb.append({"op": "delete", "xpath": f"{rbase}/entry[@name='{_q(r['name'])}']/description",
                                            "kind": "rule-desc", "name": f"{r['name']}:description", "rule": r["name"]})
                tgt = f" target {','.join(t['device'] + '/' + t['vsys'] for t in r['target_devices'])}" if pano else ""
                diff.append(f"~ edit rule {r['name']}{tgt}: only added members are rolled back")
                continue
            ops.append({"op": "set", "xpath": rbase, "element": _rule_element(r, r["target_devices"] if pano else None),
                        "kind": "rule", "name": r["name"]})
            pos = "appended at the bottom"
            if r.get("place_before"):
                ops.append({"op": "move", "xpath": f"{rbase}/entry[@name='{_q(r['name'])}']", "where": "before",
                            "dst": r["place_before"], "kind": "rule-move", "name": f"{r['name']}:move"})
                pos = f"moved directly above {r['place_before']}, which would otherwise deny this traffic"
            tgt = f" target {','.join(t['device'] + '/' + t['vsys'] for t in r['target_devices'])}" if pano else ""
            diff.append(f"+ rule {r['name']}: {','.join(r['from'])} -> {','.join(r['to'])} src {','.join(r['source'] or ['any'])} "
                        f"dst {','.join(r['destination'])} svc {','.join(r['service'])} tag {','.join(r['tags'])}{tgt} ({pos})")
            rules_rb.append({"xpath": f"{rbase}/entry[@name='{_q(r['name'])}']", "kind": "rule", "name": r["name"]})
        rb = rules_rb + rb
    order = {"rule": 0, "rule-member": 0, "rule-desc": 0, "address-group": 1, "address": 2, "service": 3, "tag": 4}
    rb.sort(key=lambda x: order.get(x["kind"], 9))
    return ops, rb, diff


def _match_queries(cs: dict, target: Target, backend: str = "firewall") -> list[tuple[str, dict]]:
    out = []
    for name, q, _serials in _match_queries_with_targets(cs, target, backend):
        out.append((name, q))
    return out


def _match_queries_with_targets(cs: dict, target: Target, backend: str = "firewall") -> list[tuple[str, dict, list[str]]]:
    """(rule name, policy-match query, target serials) for every new rule in this target's groups."""
    out = []
    for g in cs["groups"]:
        if g["target"] != target.name or g["backend"] != backend:
            continue
        vals = _values(g)
        for r in g["rules"]:
            if (r.get("operation") or "add") != "add":
                continue
            src = _first_ip(vals.get(r["source"][0])) if r["source"] else None
            dst = _first_ip(vals.get(r["destination"][0])) if r["destination"] else None
            svc = vals.get(r["service"][0], "") if r["service"] else ""
            proto, _, port = svc.partition("/")
            if src and dst and proto in PROTO_NUM and port:
                serials = [t["serial"] for t in r.get("target_devices") or [] if t.get("serial")]
                out.append((r["name"], {"from": r["from"][0], "to": r["to"][0], "source": src, "destination": dst,
                                        "protocol": PROTO_NUM[proto], "destination-port": port.split("-")[0].split(",")[0]},
                            serials))
    return out


def firewall_checks(dev: DeviceAPI, cs: dict, target: Target) -> list[dict]:
    """After a Panorama push: does each target firewall now pick the new rule for its own flow?

    Catches a rule that landed below a deny (shadowed) or a hop that was not
    pushed. Skipped when the device handle cannot reach managed firewalls.
    """
    if cs.get("kind") == "decommission":
        return _decom_firewall_checks(dev, cs, target)
    if not hasattr(dev, "policy_match_on"):
        return []
    out = []
    for name, q, serials in _match_queries_with_targets(cs, target, "panorama"):
        for sn in serials:
            try:
                hit = dev.policy_match_on(sn, q)
            except Exception as exc:  # noqa: BLE001
                hit = f"error: {exc}"
            out.append({"check": f"firewall {sn}: test security-policy-match {q['from']}->{q['to']} {q['source']}->"
                                 f"{q['destination']} {q['protocol']}/{q['destination-port']} returns {name}",
                        "ok": hit == name, "detail": f"matched {hit}"})
    return out


# ---------------------------------------------------------------- flow

def _target(profile: Profile, name: str | None, allow_panorama: bool = False) -> Target:
    ts = [t for t in profile.targets if name in (None, t.name)]
    if len(ts) != 1:
        raise PushError(f"pick one target: {', '.join(t.name for t in profile.targets)}")
    if ts[0].type != "firewall" and not allow_panorama:
        raise PushError(PANORAMA_DRY_RUN)
    return ts[0]


def panorama_servers(config_path: Path) -> list[str]:
    """Panorama servers a firewall's running config points at (empty = standalone). Read from the pre-push backup."""
    from defusedxml.ElementTree import parse

    try:
        root = parse(str(config_path)).getroot()
    except Exception:  # noqa: BLE001 - an unreadable backup is caught by revalidate
        return []
    out = []
    for sysel in root.iterfind(".//deviceconfig/system"):
        for el in list(sysel.iterfind("panorama//panorama-server")) + list(sysel.iterfind("panorama-server")) + \
                list(sysel.iterfind("panorama//panorama-server-2")) + list(sysel.iterfind("panorama-server-2")):
            if (el.text or "").strip():
                out.append(el.text.strip())
    return sorted(set(out))


def live_direct_managed_allowed(profile: Profile) -> bool:
    """Test/emergency override (off by default): allow a direct push to a Panorama-managed firewall."""
    return bool(getattr(profile, "allow_direct_managed", False))


def _backup(profile: Profile, dev: DeviceAPI, target: Target, label: str) -> Path:
    xml = dev.export_running()
    p = profile.data_dir("backups") / f"{target.name}-{label}-{now().strftime('%Y%m%d-%H%M%S')}.xml"
    p.write_text(xml, encoding="utf-8")
    p.chmod(0o600)
    return p


def session_changeset(profile: Profile, s: dict) -> dict:
    p = Path(s.get("changeset_path") or profile.data_dir("changesets") / f"{s['changeset']}.json")
    if not p.is_file():
        raise PushError(f"change set file {p} is gone")
    return json.loads(p.read_text(encoding="utf-8"))


def unconfirmed_route_warning(cs: dict) -> str | None:
    """Suggested VR routes are never pushed; say so when a next hop is still unconfirmed."""
    pending = [sr for g in cs.get("groups") or [] for sr in g.get("suggested_routes") or []
               if not sr.get("nexthop_confirmed") and not sr.get("overlap_192")]
    if not pending:
        return None
    dests = ", ".join(sr.get("destination") or sr.get("name") or "?" for sr in pending)
    return (f"{len(pending)} suggested route(s) were not included in this push (next hop REQUIRED-CONFIRM): {dests}. "
            "Add them from the change plan only after the next hop is confirmed.")



def rule_token(group_index: int, rule: dict) -> str:
    return f"rule:{group_index}:{(rule or {}).get('name') or ''}"


def group_token(group_index: int) -> str:
    return f"group:{group_index}"


def selectable_items(cs: dict) -> list[dict]:
    """One entry per planned rule (and per group) the engineer can tick on the Push page."""
    items = []
    for i, g in enumerate(cs.get("groups") or []):
        title = f"{g.get('device_group') or g.get('vsys') or g.get('device') or 'group'} / {g.get('rulebase') or g.get('vsys') or ''}".strip(" /")
        items.append({"token": group_token(i), "kind": "group", "label": title, "index": i})
        for r in g.get("rules") or []:
            if r.get("operation") == "already-allowed":
                continue
            zones = " -> ".join([", ".join(r.get("from") or ["?"]), ", ".join(r.get("to") or ["?"])])
            items.append({"token": rule_token(i, r), "kind": "rule", "label": f"{r.get('name') or '?'} ({zones})",
                          "name": r.get("name"), "index": i, "vsys": g.get("vsys"), "device_group": g.get("device_group")})
    return items


def filter_changeset(cs: dict, selected: list[str] | None) -> dict:
    """Copy of the change set containing only the ticked groups or rules. None means the full plan."""
    if selected is None:
        return cs
    wanted = {str(x) for x in selected if str(x).strip()}
    if not wanted:
        raise PushError("Tick at least one planned rule or group to prepare.")
    import copy
    out = copy.deepcopy(cs)
    kept = []
    for i, g in enumerate(out.get("groups") or []):
        if group_token(i) in wanted:
            kept.append(g)
            continue
        rules = [r for r in g.get("rules") or [] if rule_token(i, r) in wanted]
        if not rules:
            continue
        used: set[str] = set()
        for r in rules:
            for k in ("source", "destination", "service", "application", "tags", "from", "to"):
                v = r.get(k)
                if isinstance(v, list):
                    used.update(str(x) for x in v)
                elif v:
                    used.add(str(v))
        g = dict(g)
        g["rules"] = rules
        objs = dict(g.get("objects") or {})
        if "new" in objs:
            objs["new"] = [o for o in objs["new"] if (o.get("name") or "") in used]
        g["objects"] = objs
        if g.get("suggested_routes"):
            g["suggested_routes"] = [sr for sr in g["suggested_routes"] if any(sr in (r.get("suggested_routes") or []) for r in rules)]
        kept.append(g)
    if not kept:
        raise PushError("None of the ticked items matched this change set.")
    out["groups"] = kept
    out["summary"] = dict(out.get("summary") or {})
    out["summary"]["rules"] = sum(len(g.get("rules") or []) for g in kept)
    out["push_selection"] = sorted(wanted)
    return out


def session_cs(cs: dict, s: dict) -> dict:
    """Change set as prepared: full plan, or the subset stored on the session."""
    sel = s.get("selected")
    return filter_changeset(cs, sel) if sel is not None else cs


def prepare(profile: Profile, cs: dict, stem: str, *, actor: str, cr: str, dev: DeviceAPI,
            target_name: str | None = None, changeset_path: str | None = None,
            selected: list[str] | None = None) -> dict:

    from panlab.uploads import refuse_push
    refuse_push(cs)  # no device contact for a plan built from a backup file
    cr = check_cr(profile, cr)
    if cs.get("customer") != profile.name:
        raise PushError(f"change set belongs to {cs.get('customer')!r}, not {profile.name!r}")
    full_cs = cs
    cs = filter_changeset(cs, selected)
    target = _target(profile, target_name, allow_panorama=True)
    pano = target.type == "panorama"
    t0 = now().isoformat(timespec="seconds")
    backup = _backup(profile, dev, target, "pre-push")
    errors, warnings, skip = revalidate(cs, backup, target, site_codes=profile.site_codes)
    if not pano:
        managers = panorama_servers(backup)
        if managers and live_direct_managed_allowed(profile):
            warnings.append(f"{target.name} is managed by Panorama ({', '.join(managers)}); this customer allows a direct "
                            "push (allow_direct_managed, test or emergency only). Panorama will not see this change.")
            audit(profile, actor=actor, action="push-direct-override", cr=cr, target=target.name, changeset=stem,
                  detail="local commit on a Panorama-managed firewall (allow_direct_managed)")
        elif managers:
            errors.append(f"{target.name} is managed by Panorama ({', '.join(managers)}). Changes to a Panorama-managed "
                          "firewall go through Panorama so they are audited and controlled: build the change set for the "
                          "Panorama target (device group) instead.")
    route_msg = unconfirmed_route_warning(cs)
    if route_msg:
        warnings.append(route_msg)
    ops, rb, diff = build_ops(cs, target, skip) if not errors else ([], [], [])
    # Suggested VR routes are never applied here, even if a next hop were later confirmed in the plan.
    ops = [op for op in ops if "virtual-router" not in (op.get("xpath") or "") and "static-route" not in (op.get("element") or "")]
    sid = f"push-{now().strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"
    s = {"id": sid, "customer": profile.name, "target": target.name, "changeset": stem, "changeset_hash": cs_hash(full_cs), "selected": selected,
         "changeset_path": changeset_path,
         "cr": cr, "prepared_by": actor, "prepared_at": now().isoformat(timespec="seconds"), "backup": str(backup),
         "errors": errors, "warnings": warnings, "skip": skip, "ops": ops, "rollback_ops": rb, "diff": diff,
         "status": "blocked" if errors else ("dry-run" if pano and not live_panorama_push_allowed(profile) else "prepared"),
         "jobs": [], "verify": [], "log": [],
         "target_type": target.type, "push_plan": push_plan(cs, target) if pano and not errors else [],
         "live_panorama": bool(pano and live_panorama_push_allowed(profile))}
    s["log"] = [{"ts": t0, "step": "prepare: backup running config", "by": actor, "file": backup.name},
                {"ts": now().isoformat(timespec="seconds"), "step": "prepare: re-validate against live config",
                 "errors": len(errors), "warnings": len(warnings), "reused_existing": len(skip)},
                {"ts": now().isoformat(timespec="seconds"), "step": "prepare: dry-run diff built", "lines": len(diff)}]
    if pano and not s["live_panorama"]:
        s["result"] = PANORAMA_DRY_RUN
        s["log"].append({"ts": now().isoformat(timespec="seconds"), "step": "prepare: Panorama dry-run only, stopping here",
                         "push_plan_steps": len(s["push_plan"])})
        write_report(profile, s, cs)
    elif pano and s["live_panorama"]:
        s["log"].append({"ts": now().isoformat(timespec="seconds"),
                         "step": "prepare: Panorama live apply enabled for this customer",
                         "push_plan_steps": len(s["push_plan"])})
    _save(profile, s)
    audit(profile, actor=actor, action="prepare", cr=cr, target=target.name, changeset=stem, session=sid,
          result=s["status"], backup=str(backup), errors=errors[:20])
    return s


def _member_in_running(dev: DeviceAPI, list_xpath: str, member: str) -> bool:
    """Whether a <member>text</member> is present under list_xpath in the running config."""
    if hasattr(dev, "member_exists"):
        return bool(dev.member_exists(list_xpath, member))
    try:
        return dev.exists_running(f"{list_xpath}/member[text()='{_q(member)}']")
    except Exception:  # noqa: BLE001
        return False


def _verify(dev: DeviceAPI, s: dict, cs: dict, target: Target, present: bool) -> list[dict]:
    if cs.get("kind") == "decommission":
        out = _verify_decom(dev, s, present)
        if present and target.type != "panorama":
            out += _decom_firewall_checks(dev, cs, target)
        return out
    out = []
    for op in (s["ops"] if present else s["rollback_ops"]):  # noqa: B007
        if op.get("kind") == "rule-member":
            if present:
                ok = _member_in_running(dev, op["xpath"], op["member"])
            else:
                parent = op["xpath"].rsplit("/member[", 1)[0] if "/member[" in op["xpath"] else op["xpath"]
                ok = not _member_in_running(dev, parent, op.get("member") or "")
            out.append({"check": f"{op['kind']} {op['name']} {'present' if present else 'removed'} in running config", "ok": ok})
            continue
        if op.get("kind") == "rule-move":
            if present:
                ok = dev.exists_running(op["xpath"])
                out.append({"check": f"rule {op['name'].rsplit(':', 1)[0]} placed above {op.get('dst')}", "ok": ok})
            continue
        if op.get("kind") == "rule-desc":
            rule_xp = op["xpath"].rsplit("/description", 1)[0]
            ok = dev.exists_running(rule_xp)
            out.append({"check": f"{op['kind']} {op['name']} updated in running config", "ok": ok})
            continue
        xp = op["xpath"] if not present else f"{op['xpath']}/entry[@name='{_q(op['name'])}']"
        ok = dev.exists_running(xp) == present
        out.append({"check": f"{op['kind']} {op['name']} {'present' if present else 'removed'} in running config", "ok": ok})
    if present and target.type != "panorama":
        for name, q in _match_queries(cs, target):
            try:
                hit = dev.policy_match(q)
            except Exception as exc:  # noqa: BLE001
                hit = f"error: {exc}"
            out.append({"check": f"test security-policy-match {q['from']}->{q['to']} {q['source']}->{q['destination']} "
                                 f"{q['protocol']}/{q['destination-port']} returns {name}", "ok": hit == name,
                        "detail": f"matched {hit}"})
    return out


def _refuse_panorama(profile: Profile, s: dict, action: str, actor: str) -> None:
    pano = s.get("target_type") == "panorama" or s["status"] == "dry-run"
    if not pano:
        return
    # A session prepared while the flag was off stays dry-run and cannot be applied.
    if s["status"] != "dry-run" and live_panorama_push_allowed(profile) and s.get("target_type") == "panorama":
        return
    audit(profile, actor=actor, action=action, cr=s["cr"], target=s["target"], changeset=s["changeset"], session=s["id"],
          result="refused", detail="Panorama dry-run only")
    raise PushError(PANORAMA_DRY_RUN)


def _run_commit_all(dev: DeviceAPI, s: dict, label: str) -> tuple[bool, str]:
    """Execute Panorama push_plan commit-all steps. The Panorama commit itself is already done."""
    steps = [p for p in (s.get("push_plan") or []) if p.get("api") == "type=commit&action=all"]
    if not steps:
        return True, ""
    if not hasattr(dev, "commit_all"):
        return False, "device handle cannot commit-all"
    for p in steps:
        try:
            job = dev.commit_all(p["cmd"])
        except Exception as exc:  # noqa: BLE001
            job = {"jobid": None, "success": False, "messages": [str(exc)]}
        s["jobs"].append({"step": f"{label}:{p['step']}", **job})
        _step(s, f"{label}: {p['step']}", job=job.get("jobid"), success=job.get("success"))
        if not job.get("success"):
            return False, f"{p['step']} failed: " + "; ".join(job.get("messages") or ["unknown"])
    return True, ""


def apply(profile: Profile, cs: dict, sid: str, *, actor: str, confirm_target: str, dev: DeviceAPI) -> dict:
    from panlab.uploads import refuse_push
    refuse_push(cs)
    s = load_session(profile, sid)
    _refuse_panorama(profile, s, "apply", actor)
    if s["status"] != "prepared":
        raise PushError(f"session {sid} is {s['status']}; prepare again")
    if confirm_target.strip() != s["target"]:
        raise PushError("typed target does not match; nothing was changed")
    if now() - datetime.fromisoformat(s["prepared_at"]) > STALE_AFTER:
        raise PushError("prepared more than 30 minutes ago; prepare again")
    if cs_hash(cs) != s["changeset_hash"]:
        raise PushError("change set file changed since prepare; prepare again")
    cs = session_cs(cs, s)
    target = _target(profile, s["target"], allow_panorama=True)
    rec = dict(actor=actor, cr=s["cr"], target=s["target"], changeset=s["changeset"], session=sid)

    def finish(status: str, msg: str) -> dict:
        s["status"], s["result"] = status, msg
        s["applied_by"], s["applied_at"] = actor, now().isoformat(timespec="seconds")
        _step(s, f"apply: finished ({status})", detail=msg[:300])
        write_report(profile, s, cs)
        _save(profile, s)
        audit(profile, action="apply", result=status, detail=msg[:500], job_ids=[j.get("jobid") for j in s["jobs"]],
              report=s["report"]["md"], **rec)
        return s

    _step(s, "apply: target confirmed", by=actor, target=s["target"])
    if dev.pending_changes():
        return finish("refused", "the firewall has uncommitted changes from someone else; commit or revert them first")
    fresh = _backup(profile, dev, target, "pre-apply")
    errors, _, skip = revalidate(cs, fresh, target, site_codes=profile.site_codes)
    _step(s, "apply: fresh backup and re-validation", file=fresh.name, errors=len(errors))
    if errors or skip != s["skip"]:
        s["errors"] = errors or ["live config changed since prepare (objects appeared or disappeared)"]
        return finish("refused", "live config no longer matches the prepared plan: " + "; ".join(s["errors"]))
    done = []
    try:
        for op in s["ops"]:
            _exec_op(dev, op)
            done.append(op.get("name") or op.get("xpath"))
    except Exception as exc:  # noqa: BLE001
        dev.revert()
        return finish("failed", f"write failed after {len(done)} item(s): {exc}; candidate reverted, nothing committed")
    _step(s, "apply: candidate written", items=len(done))
    try:
        job = dev.commit(f"panlab {s['cr']} {s['changeset']} by {actor}")
    except Exception as exc:  # noqa: BLE001
        job = {"jobid": None, "success": False, "messages": [str(exc)]}
    s["jobs"].append({"step": "apply-commit", **job})
    _step(s, "apply: commit", job=job.get("jobid"), success=job.get("success"))
    if not job.get("success"):
        try:
            dev.revert()
        except Exception:  # noqa: BLE001
            pass
        return finish("failed", "commit failed: " + "; ".join(job.get("messages") or ["unknown"]) + "; candidate reverted")
    s["verify"] = _verify(dev, s, cs, target, present=True)
    _step(s, "apply: verify", passed=sum(v["ok"] for v in s["verify"]), total=len(s["verify"]))
    bad = [v["check"] for v in s["verify"] if not v["ok"]]
    if bad:
        return finish("committed-verify-failed", "committed, but verification failed: " + "; ".join(bad) + ". Roll back below.")
    if target.type == "panorama":
        ok_push, push_msg = _run_commit_all(dev, s, "apply-push")
        if not ok_push:
            return finish("committed-push-failed", "committed to Panorama, but push to devices failed: " + push_msg)
        s["firewall_checks"] = firewall_checks(dev, cs, target)
        s["verify"] = list(s["verify"]) + s["firewall_checks"]
        _step(s, "apply: firewall policy-match", passed=sum(v["ok"] for v in s["firewall_checks"]),
              total=len(s["firewall_checks"]))
        bad = [v["check"] + f" ({v.get('detail')})" for v in s["firewall_checks"] if not v["ok"]]
        if bad:
            return finish("committed-verify-failed", "pushed, but a firewall does not pick the new rule: " + "; ".join(bad)
                          + ". The rule may be shadowed or another place still blocks it. Roll back below or fix by hand.")
    return finish("committed", f"committed (job {job.get('jobid')}) and verified")


def rollback(profile: Profile, cs: dict, sid: str, *, actor: str, confirm_target: str, dev: DeviceAPI) -> dict:
    s = load_session(profile, sid)
    _refuse_panorama(profile, s, "rollback", actor)
    if s["status"] not in ("committed", "committed-verify-failed", "committed-push-failed"):
        raise PushError(f"session {sid} is {s['status']}; only a committed push can be rolled back")
    if confirm_target.strip() != s["target"]:
        raise PushError("typed target does not match; nothing was changed")
    cs = session_cs(cs, s)
    target = _target(profile, s["target"], allow_panorama=True)
    rec = dict(actor=actor, cr=s["cr"], target=s["target"], changeset=s["changeset"], session=sid)
    if dev.pending_changes():
        audit(profile, action="rollback", result="refused", detail="uncommitted changes on the firewall", **rec)
        raise PushError("the firewall has uncommitted changes; commit or revert them first")
    fresh = _backup(profile, dev, target, "pre-rollback")
    _step(s, "rollback: backup running config", by=actor, file=fresh.name)
    root = ET.parse(str(fresh)).getroot()
    # A decommission rollback re-creates what it removed (and drops only its own deny rules), so nothing is "kept".
    refs = {} if cs.get("kind") == "decommission" else \
        referenced_elsewhere(root, cs, {o["name"] for o in s["rollback_ops"] if o["kind"] != "rule"})
    deleted, kept = [], []
    try:
        for op in s["rollback_ops"]:
            if op["kind"] != "rule" and op["name"] in refs:
                kept.append(f"{op['kind']} {op['name']} (still referenced by {refs[op['name']]})")
                continue
            _exec_op(dev, op)
            deleted.append(op)
        job = dev.commit(f"panlab ROLLBACK {s['cr']} {s['changeset']} by {actor}")
    except Exception as exc:  # noqa: BLE001
        dev.revert()
        job = {"jobid": None, "success": False, "messages": [str(exc)]}
    s["jobs"].append({"step": "rollback-commit", **job})
    _step(s, "rollback: deletes written and committed", deleted=len(deleted), kept=len(kept), job=job.get("jobid"),
          success=job.get("success"))
    ok = bool(job.get("success"))
    if ok and target.type == "panorama":
        ok_push, push_msg = _run_commit_all(dev, s, "rollback-push")
        if not ok_push:
            ok = False
            job = {**job, "messages": list(job.get("messages") or []) + [push_msg]}
    if cs.get("kind") == "decommission":
        s["rollback_verify"] = _verify_decom(dev, s, present=False) if ok else []
    else:
        s["rollback_verify"] = [{"check": f"{op['kind']} {op['name']} removed in running config",
                                 "ok": not dev.exists_running(op["xpath"])} for op in deleted] if ok else []
    ok = ok and all(v["ok"] for v in s["rollback_verify"])
    s["status"] = "rolled-back" if ok else "rollback-failed"
    s["result"] = (f"rolled back (job {job.get('jobid')}) and verified" if ok else
                   "rollback did not complete: " + "; ".join(job.get("messages") or ["verification failed"]))
    s["rollback_result"] = {"by": actor, "at": now().isoformat(timespec="seconds"), "kept": kept,
                            "messages": job.get("messages") or [], "backup": str(fresh)}
    _step(s, f"rollback: finished ({s['status']})")
    write_report(profile, s, cs)
    _save(profile, s)
    audit(profile, action="rollback", result=s["status"], job_ids=[job.get("jobid")], kept=kept, report=s["report"]["md"], **rec)
    return s


class OfflineConfig:
    """Read-only stand-in for a Panorama dry run when no credentials are set: serves the profile's offline export."""

    def __init__(self, path: Path):
        self.path = path

    def export_running(self) -> str:
        return self.path.read_text(encoding="utf-8")

    def _no(self, *a, **k):
        raise PushError("offline config: read-only")

    set = delete = revert = commit = commit_all = _no

    def exists_running(self, xpath: str) -> bool:
        return False

    def pending_changes(self) -> bool:
        return False

    def policy_match(self, query: dict) -> str | None:
        return None


def connect_target(profile: Profile, target_name: str | None = None):
    from panlab.sources import settings_for

    t = _target(profile, target_name, allow_panorama=True)
    st = settings_for(profile, t)
    if t.type == "panorama" and not st.configured and t.offline_config:
        return OfflineConfig(profile.resolve_path(t.offline_config))
    if not st.configured:
        raise PushError(f"credentials for {t.name} are not set (env file {profile.env_file})")
    if t.type == "panorama":
        from panos.panorama import Panorama as Firewall
    else:
        from panos.firewall import Firewall
    kw = {"hostname": st.host, "timeout": max(st.timeout, 60)}
    if st.uses_api_key:
        kw["api_key"] = st.api_key
    else:
        kw.update(api_username=st.username, api_password=st.password)
    return XapiDevice(Firewall(**kw))

# ---------------------------------------------------------------- decommission push

def _decom_refuse_codes() -> frozenset:
    from panlab.decom import BLOCKING_CODES
    return BLOCKING_CODES


def _exec_op(dev: DeviceAPI, op: dict) -> None:
    action = op.get("op") or ("delete" if not op.get("element") else "set")
    if action == "move":
        if not hasattr(dev, "move"):
            raise PushError("this device handle cannot move rules; place the rule by hand above " + str(op.get("dst")))
        dev.move(op["xpath"], op.get("where") or "before", op.get("dst"))
    elif action == "delete":
        dev.delete(op["xpath"])
    else:
        dev.set(op["xpath"], op["element"])


def _members_el(tag: str, vals: list[str]) -> str:
    return f"<{tag}>" + "".join(f"<member>{_x(v)}</member>" for v in vals) + f"</{tag}>"


def _loc_xpath(loc: dict) -> str:
    if loc.get("kind") == "shared" or loc.get("location") == "shared":
        return "/config/shared"
    if loc.get("device_group"):
        return DG_XP.format(dg=_q(loc["device_group"]))
    return VSYS_XP.format(vsys=_q(loc.get("vsys") or "vsys1"))


def _rule_entry_xpath(act: dict) -> str:
    loc = act["location"]
    base = _loc_xpath(loc)
    rb = act.get("rulebase") or ("pre-rulebase" if loc.get("device_group") else "rulebase")
    kind = act.get("rule_kind") or "security"
    return f"{base}/{rb}/{kind}/rules/entry[@name='{_q(act['name'])}']"


def _member_xpath(list_xpath: str, member: str) -> str:
    if "'" in member:
        raise PushError(f"member {member!r} contains a quote; refusing")
    return f"{list_xpath}/member[text()='{member}']"


def _decom_scope_key(loc: dict) -> str:
    if loc.get("kind") == "shared" or loc.get("location") == "shared":
        return "shared"
    return loc.get("device_group") or loc.get("vsys") or loc.get("kind") or ""


def _deny_rule_element(rule: dict) -> str:
    """The narrow deny rule for stop-traffic: exact source, destination and service, logged, targeted to one firewall."""
    targets = ""
    if rule.get("targets"):
        ents = ""
        for t in rule["targets"]:
            vs = f"<vsys><entry name=\"{_x(t['vsys'])}\"/></vsys>" if t.get("vsys") else ""
            ents += f'<entry name="{_x(t["serial"])}">{vs}</entry>'
        targets = f"<target><devices>{ents}</devices></target>"
    desc = f"<description>{_x(rule['description'])}</description>" if rule.get("description") else ""
    return (f'<entry name="{_x(rule["name"])}">' + _members("from", rule.get("from") or ["any"]) + _members("to", rule.get("to") or ["any"])
            + _members("source", rule["source"]) + _members("destination", rule["destination"])
            + _members("source-user", ["any"]) + _members("category", ["any"])
            + _members("application", rule.get("application") or ["any"]) + _members("service", rule.get("service") or ["any"])
            + "<action>deny</action><log-end>yes</log-end>" + desc + targets + "</entry>")


def _service_element(act: dict) -> str:
    proto = act.get("protocol") or "tcp"
    return f'<entry name="{_x(act["name"])}"><protocol><{proto}><port>{_x(str(act["port"]))}</port></{proto}></protocol></entry>'


def _revalidate_decom(cs: dict, config_path: Path, target: Target) -> tuple[list[str], list[str], dict[str, str]]:
    """Every action must still apply to the fresh export, scope by scope. skip: services that already exist (reused)."""
    from panlab.decom import inventory_from_xml

    errors, warnings, skip = [], [], {}
    inv = inventory_from_xml(config_path, target=target.name, kind=target.type)
    sk = _decom_scope_key
    addrs = {(a.name, sk(a.location)) for a in inv.addresses}
    groups = {(g.name, sk(g.location)): g for g in inv.groups}
    rules = {(r.kind, r.name, sk(r.location)): r for r in inv.rules}
    rule_names = {(r.kind, r.name) for r in inv.rules}
    root = ET.parse(str(config_path)).getroot()

    for f in cs.get("flags") or []:
        if f.get("level") == "red" and f.get("code") in _decom_refuse_codes():
            errors.append(f["message"])
        elif f.get("level") in ("red", "yellow"):
            warnings.append(f["message"])
    for u in cs.get("unresolved") or []:
        item = u.get("item") if isinstance(u, dict) else u
        errors.append(f"unresolved item {item}")

    mine = [(g, a) for g in cs.get("groups") or [] if not g.get("target") or g["target"] == target.name for a in g.get("actions") or []]
    if cs.get("groups") and not mine:
        errors.append(f"change set has nothing for target {target.name}")
    for g, act in mine:
        if g.get("backend") and g["backend"] != target.type:
            errors.append(f"group backend {g.get('backend')} does not match target {target.type}")
            continue
        name, loc, op = act.get("name"), act["location"], act["op"]
        where = _decom_scope_key(loc)
        if op in {"edit-rule", "delete-rule", "disable-rule"}:
            r = rules.get((act.get("rule_kind") or "security", name, where))
            if r is None:
                errors.append(f"rule {name} ({act.get('rule_kind')}, {where}) is not in the current config")
                continue
            if op == "edit-rule":
                for fld, vals in (act.get("remove") or {}).items():
                    have = set(getattr(r, fld, []) or [])
                    missing = [v for v in vals if v not in have]
                    if missing:
                        errors.append(f"rule {name}: {fld} no longer contains {', '.join(missing)}")
                    left = [m for m in have if m not in vals]
                    if not left:
                        errors.append(f"rule {name}: removing {', '.join(vals)} would now leave {fld} empty (any); rebuild the plan")
        elif op in {"edit-group", "delete-group"}:
            gobj = groups.get((name, where))
            if gobj is None:
                errors.append(f"address group {name} ({where}) is not in the current config")
            elif op == "edit-group":
                missing = [v for v in (act.get("remove") or []) if v not in gobj.members]
                if missing:
                    errors.append(f"address group {name} no longer contains {', '.join(missing)}")
                if not [m for m in gobj.members if m not in (act.get("remove") or [])]:
                    errors.append(f"address group {name}: removing {', '.join(act.get('remove') or [])} would now empty it; rebuild the plan")
        elif op == "delete-address":
            if (name, where) not in addrs:
                errors.append(f"address {name} ({where}) is not in the current config")
        elif op == "add-service":
            ent = root.find(_et_path(loc) + f"/service/entry[@name='{name}']")
            if ent is not None:
                proto = act.get("protocol") or "tcp"
                port = (ent.findtext(f"protocol/{proto}/port") or "").strip()
                if port == str(act.get("port")):
                    skip[name] = "already exists with the same port"
                else:
                    errors.append(f"service {name} ({where}) already exists with a different definition")
        elif op == "add-deny-rule":
            if ("security", name) in rule_names:
                errors.append(f"deny rule {name} already exists; pick another name or delete it first")
            ref = (act.get("place") or {}).get("ref")
            if ref and (act.get("place") or {}).get("where") == "before" and ("security", ref, where) not in rules:
                errors.append(f"deny rule {name}: the rule it goes above ({ref}) is not in {where} any more; rebuild the plan")
    return errors, warnings, skip


def _et_path(loc: dict) -> str:
    """ElementTree path (relative to <config>) for a location, used to read the fresh export."""
    if loc.get("kind") == "shared" or loc.get("location") == "shared":
        return "./shared"
    if loc.get("device_group"):
        return f"./devices/entry/device-group/entry[@name='{loc['device_group']}']"
    return f"./devices/entry/vsys/entry[@name='{loc.get('vsys') or 'vsys1'}']"


def _build_decom_ops(cs: dict, target: Target, skip: dict[str, str] | None = None) -> tuple[list[dict], list[dict], list[str]]:
    """Ops in the engine's push order across every scope (deny rules first; child device groups before parents;
    shared last). Rollback is the exact reverse, one unit per action, so objects come back before the rules
    that use them and a re-created rule is moved back to where it was."""
    from panlab.decom import iter_actions

    skip = skip or {}
    ops: list[dict] = []
    units: list[list[dict]] = []
    diff: list[str] = []
    last = None
    for g, act in iter_actions(cs):
        if g.get("target") and g["target"] != target.name:
            continue
        if g.get("backend") and g["backend"] != target.type:
            continue
        loc = act["location"]
        scope = "shared" if loc.get("kind") == "shared" else (f"device group {loc['device_group']}" if loc.get("device_group") else loc.get("vsys") or "vsys1")
        if scope != last:
            diff.append(f"# {target.name} / {scope}")
            last = scope
        base = _loc_xpath(loc)
        name, op = act["name"], act["op"]
        rb: list[dict] = []
        if op == "add-service":
            if name in skip:
                diff.append(f"= service {name} (reused: {skip[name]})")
                continue
            ops.append({"op": "set", "xpath": f"{base}/service", "element": _service_element(act), "kind": "service",
                        "name": name, "verify": "present"})
            rb.append({"op": "delete", "xpath": f"{base}/service/entry[@name='{_q(name)}']", "kind": "service", "name": name, "verify": "absent"})
            diff.append(f"+ service {name} {act.get('protocol')}/{act.get('port')}")
        elif op == "add-deny-rule":
            xp = _rule_entry_xpath(act)
            parent = xp.rpartition("/")[0]
            ops.append({"op": "set", "xpath": parent, "element": _deny_rule_element(act["rule"]), "kind": "deny-rule",
                        "name": name, "verify": "present"})
            place = act.get("place") or {}
            if place.get("where") == "before" and place.get("ref"):
                ops.append({"op": "move", "xpath": xp, "where": "before", "dst": place["ref"], "kind": "rule-move",
                            "name": name, "verify": "exists"})
            elif place.get("where") in ("top", "bottom"):
                ops.append({"op": "move", "xpath": xp, "where": place["where"], "kind": "rule-move", "name": name, "verify": "exists"})
            rb.append({"op": "delete", "xpath": xp, "kind": "deny-rule", "name": name, "verify": "absent"})
            r = act["rule"]
            diff.append(f"+ deny rule {name}: {', '.join(r['source'])} -> {', '.join(r['destination'])} {', '.join(r.get('service') or [])}"
                        + (f" above {place['ref']}" if place.get("ref") else ""))
        elif op == "edit-rule":
            xp = _rule_entry_xpath(act)
            for fld, vals in (act.get("remove") or {}).items():
                for v in vals:
                    # PAN-OS 'set' merges list members; removing one means deleting its member node
                    ops.append({"op": "delete", "xpath": _member_xpath(f"{xp}/{fld}", v), "kind": "rule-member",
                                "name": name, "member": v, "verify": "absent"})
                    rb.append({"op": "set", "xpath": f"{xp}/{fld}", "element": f"<member>{_x(v)}</member>", "kind": "rule-member",
                               "name": name, "member": v, "verify": "present-member"})
                diff.append(f"- rule {name} {fld}: {', '.join(vals)} (keeps {', '.join((act.get('remaining') or {}).get(fld) or [])})")
        elif op == "disable-rule":
            xp = _rule_entry_xpath(act)
            ops.append({"op": "set", "xpath": xp, "element": "<disabled>yes</disabled>", "kind": "disable-rule", "name": name, "verify": "exists"})
            rb.append({"op": "set", "xpath": xp, "element": "<disabled>no</disabled>", "kind": "disable-rule", "name": name, "verify": "exists"})
            diff.append(f"~ disable rule {name}")
        elif op == "delete-rule":
            xp = _rule_entry_xpath(act)
            parent = xp.rpartition("/")[0]
            snap = act.get("snapshot") or {}
            element = snap.get("xml") or _rule_element({
                "name": name, "from": snap.get("from") or ["any"], "to": snap.get("to") or ["any"],
                "source": snap.get("source") or ["any"], "destination": snap.get("destination") or ["any"],
                "source_user": snap.get("source_user") or [], "application": snap.get("application") or ["any"],
                "service": snap.get("service") or ["any"], "action": snap.get("action") or "allow",
                "tags": snap.get("tags") or [], "description": snap.get("description") or "",
            })
            ops.append({"op": "delete", "xpath": xp, "kind": "rule", "name": name, "verify": "absent"})
            rb.append({"op": "set", "xpath": parent, "element": element, "kind": "rule", "name": name, "verify": "present"})
            if snap.get("before"):
                rb.append({"op": "move", "xpath": xp, "where": "before", "dst": snap["before"], "kind": "rule-move", "name": name, "verify": "exists"})
            diff.append(f"- rule {name} ({act.get('rule_kind')})")
        elif op == "edit-group":
            xp = f"{base}/address-group/entry[@name='{_q(name)}']"
            for v in act.get("remove") or []:
                ops.append({"op": "delete", "xpath": _member_xpath(f"{xp}/static", v), "kind": "group-member",
                            "name": name, "member": v, "verify": "absent"})
                rb.append({"op": "set", "xpath": f"{xp}/static", "element": f"<member>{_x(v)}</member>", "kind": "group-member",
                           "name": name, "member": v, "verify": "present-member"})
            diff.append(f"- address-group {name} members {', '.join(act.get('remove') or [])} (keeps {', '.join(act.get('remaining') or [])})")
        elif op == "delete-group":
            xp = f"{base}/address-group/entry[@name='{_q(name)}']"
            snap = act.get("snapshot") or {}
            members = "".join(f"<member>{_x(m)}</member>" for m in snap.get("members") or [])
            desc = f"<description>{_x(snap['description'])}</description>" if snap.get("description") else ""
            element = f'<entry name="{_x(name)}"><static>{members}</static>{desc}</entry>'
            ops.append({"op": "delete", "xpath": xp, "kind": "address-group", "name": name, "verify": "absent"})
            rb.append({"op": "set", "xpath": f"{base}/address-group", "element": element, "kind": "address-group", "name": name, "verify": "present"})
            diff.append(f"- address-group {name}")
        elif op == "delete-address":
            xp = f"{base}/address/entry[@name='{_q(name)}']"
            snap = act.get("snapshot") or act
            obj = {"kind": "address", "name": name, "type": snap.get("type") or act.get("type") or "ip-netmask",
                   "value": snap.get("value") or act.get("value") or "", "description": snap.get("description") or ""}
            ops.append({"op": "delete", "xpath": xp, "kind": "address", "name": name, "verify": "absent"})
            rb.append({"op": "set", "xpath": f"{base}/address", "element": _obj_element(obj), "kind": "address", "name": name, "verify": "present"})
            diff.append(f"- address {name} {obj['type']} {obj['value']}")
        units.append(rb)
    rollback = [op for unit in reversed(units) for op in unit]
    return ops, rollback, diff


def _verify_decom(dev: DeviceAPI, s: dict, present: bool) -> list[dict]:
    """present=True after apply: removed things are gone, added things are there. present=False after rollback."""
    out = []
    if present:
        for op in s.get("ops") or []:
            if op.get("op") == "move":
                ok = dev.exists_running(op["xpath"])
                out.append({"check": f"rule {op.get('name')} placed {op.get('where')} {op.get('dst') or ''}".strip(), "ok": ok})
            elif op.get("verify") == "absent":
                ok = not dev.exists_running(op["xpath"])
                what = f"{op.get('kind')} {op.get('name')}" + (f" no longer lists {op['member']}" if op.get("member") else " removed")
                out.append({"check": f"{what} in running config", "ok": ok})
            elif op.get("verify") == "present":
                ok = dev.exists_running(f"{op['xpath']}/entry[@name='{_q(op['name'])}']")
                out.append({"check": f"{op.get('kind')} {op.get('name')} present in running config", "ok": ok})
            else:
                ok = dev.exists_running(op["xpath"])
                out.append({"check": f"{op.get('kind')} {op.get('name')} still present in running config", "ok": ok})
        return out
    for op in s.get("rollback_ops") or []:
        if op.get("op") == "move":
            continue
        if op.get("verify") == "present-member":
            ok = dev.exists_running(_member_xpath(op["xpath"], op["member"]))
            out.append({"check": f"{op.get('kind')} {op.get('name')} lists {op['member']} again", "ok": ok})
        elif op.get("verify") == "present":
            xp = op["xpath"]
            if op.get("name") and not xp.endswith(f"[@name='{op['name']}']"):
                xp = f"{xp}/entry[@name='{_q(op['name'])}']"
            ok = dev.exists_running(xp)
            out.append({"check": f"{op.get('kind')} {op.get('name')} restored in running config", "ok": ok})
        elif op.get("verify") == "absent":
            ok = not dev.exists_running(op["xpath"])
            out.append({"check": f"{op.get('kind')} {op.get('name')} removed again in running config", "ok": ok})
        elif op.get("op") == "set":
            ok = dev.exists_running(op["xpath"])
            out.append({"check": f"{op.get('kind')} {op.get('name')} still present after rollback", "ok": ok})
    return out


_PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}


def _decom_policy_queries(cs: dict, target: Target) -> list[tuple[str, dict, list[str]]]:
    """(deny rule, policy-match query, firewall serials) for each stop-traffic deny in this change set."""
    from panlab.decom import iter_actions

    out = []
    for g, act in iter_actions(cs):
        if act.get("op") != "add-deny-rule" or (g.get("target") and g["target"] != target.name):
            continue
        r = act["rule"]
        flow = next((f for f in ((cs.get("decom") or {}).get("block") or {}).get("flows") or []
                     if f["flow"].get("dst") in r["destination"] and f["flow"].get("src") in r["source"]), None)
        if not flow:
            continue
        fl = flow["flow"]
        q = {"from": r["from"][0], "to": r["to"][0], "source": fl["src"], "destination": fl["dst"],
             "protocol": _PROTO_NUM.get((fl.get("proto") or "tcp").lower(), 6)}
        if fl.get("port") not in (None, ""):
            q["destination-port"] = str(fl["port"]).split("-")[0].split(",")[0]
        serials = [t["serial"] for t in r.get("targets") or [] if t.get("serial")]
        out.append((act["name"], q, serials))
    return out


def _decom_firewall_checks(dev: DeviceAPI, cs: dict, target: Target) -> list[dict]:
    """After the push: each firewall on the path must now pick the deny rule for its flow."""
    out = []
    for name, q, serials in _decom_policy_queries(cs, target):
        runs = [(sn, (lambda sn=sn: dev.policy_match_on(sn, q))) for sn in serials] if target.type == "panorama" and hasattr(dev, "policy_match_on") \
            else ([("", lambda: dev.policy_match(q))] if target.type != "panorama" else [])
        for sn, call in runs:
            try:
                hit = call()
            except Exception as exc:  # noqa: BLE001
                hit = f"error: {exc}"
            out.append({"check": (f"firewall {sn}: " if sn else "") + f"test security-policy-match {q['from']}->{q['to']} "
                                 f"{q['source']}->{q['destination']} {q['protocol']}/{q.get('destination-port', 'any')} returns {name}",
                        "ok": hit == name, "detail": f"matched {hit}"})
    return out


def _decom_push_plan(cs: dict, target: Target) -> list[dict]:
    """Commit to Panorama, then push each device group the plan touched (and the groups below it, which inherit
    from it). Shared changes push every device group that has firewalls."""
    out = [{"step": "commit to Panorama", "api": "type=commit", "cmd": "<commit><description>panlab CR</description></commit>"}]
    info = ((cs.get("decom") or {}).get("panorama") or {}).get(target.name) or {}
    with_devs = set(info.get("with_devices") or [])
    desc = info.get("descendants") or {}
    dgs: list[str] = []
    for g in cs.get("groups") or []:
        if g.get("target") != target.name or g.get("backend") != "panorama" or not g.get("actions"):
            continue
        if g.get("shared") or not g.get("device_group"):
            cands = sorted(with_devs)
        else:
            cands = [g["device_group"]] + list(desc.get(g["device_group"]) or [])
        for d in cands:
            if d not in dgs and (not with_devs or d in with_devs):
                dgs.append(d)
    for dg in dgs:
        out.append({"step": f"push device group {dg} to all members", "api": "type=commit&action=all",
                    "cmd": f'<commit-all><shared-policy><device-group><entry name="{_x(dg)}"/></device-group>'
                           "<include-template>no</include-template></shared-policy></commit-all>"})
    return out

