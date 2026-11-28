# SPDX-License-Identifier: Apache-2.0
"""Run the vendored FlowMapper engine (core.js) with Node.

The JavaScript in vendor/flowmapper/core.js is the single source for path
tracing, FCR annotation, local-backup merge and the vsys map. This module
only shells out to Node, checks the vendored hash, and converts results into
change sets. Do not reimplement the tracer here.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from panlab.fcr import Endpoint, PortSpec, RuleRequest, Tickets, read_fcr
from panlab.placement import Placement

REPO_ROOT = Path(__file__).resolve().parents[2]
VENDOR = REPO_ROOT / "vendor" / "flowmapper"
CORE = VENDOR / "core.js"
RENDER = VENDOR / "render.js"
DECOM = VENDOR / "decom.js"
CLI = VENDOR / "cli.js"
MANIFEST = VENDOR / "manifest.json"

# Large Panorama exports (tens of MB, plus local backups) can take a while.
DEFAULT_TIMEOUT = int(os.environ.get("PANLAB_FLOWMAPPER_TIMEOUT", "180"))


class FlowMapperError(RuntimeError):
    """The engine could not start, failed the hash check, or rejected the job."""


@dataclass
class ConfigFile:
    path: Path
    name: str


def node_bin() -> str:
    exe = os.environ.get("PANLAB_NODE") or shutil.which("node")
    if not exe:
        raise FlowMapperError(
            "Node.js is required to run FlowMapper path tracing. "
            "Install Node.js 18+ on the PAAT server (install.sh does this).")
    return exe


def verify_engine() -> dict[str, Any]:
    if not CORE.is_file() or not MANIFEST.is_file() or not CLI.is_file():
        raise FlowMapperError(f"vendored FlowMapper engine is missing under {VENDOR}")
    man = json.loads(MANIFEST.read_text())
    sha = hashlib.sha256(CORE.read_bytes()).hexdigest()
    if sha != man.get("sha256"):
        raise FlowMapperError(
            "vendored core.js does not match vendor/flowmapper/manifest.json. "
            "Re-run python3 tools/sync-flowmapper.py.")
    rend = man.get("render") or {}
    if rend:
        if not RENDER.is_file() or hashlib.sha256(RENDER.read_bytes()).hexdigest() != rend.get("sha256"):
            raise FlowMapperError(
                "vendored render.js is missing or does not match vendor/flowmapper/manifest.json. "
                "Re-run python3 tools/sync-flowmapper.py.")
    dec = man.get("decom") or {}
    if dec:
        if not DECOM.is_file() or hashlib.sha256(DECOM.read_bytes()).hexdigest() != dec.get("sha256"):
            raise FlowMapperError(
                "vendored decom.js is missing or does not match vendor/flowmapper/manifest.json. "
                "Re-run python3 tools/sync-flowmapper.py.")
    return {"version": man.get("engine_version"), "sha256": sha, "source_commit": man.get("source_commit"),
            "has_render": bool(rend), "has_decom": bool(dec), "decom_version": dec.get("version")}


def fcr_text_from_requests(requests: Iterable[RuleRequest]) -> str:
    """Turn imported FCR rows into the paste/CSV text the engine parses."""
    lines = ["source,destination,protocol,port,application,ticket"]
    for r in requests:
        srcs = [e.value for e in r.sources if e.kind in ("ip", "range")] or [e.value for e in r.sources]
        dsts = [e.value for e in r.destinations if e.kind in ("ip", "range")] or [e.value for e in r.destinations]
        svcs = r.services or [PortSpec("tcp", None)]
        ticket = r.tickets.label() or ""
        app = ",".join(a for a in r.applications if a and a != "any")
        for src in srcs or [""]:
            for dst in dsts or [""]:
                for svc in svcs:
                    lines.append(",".join([
                        src, dst, svc.proto, svc.port or "", app, ticket
                    ]))
    return "\n".join(lines) + "\n"


def fcr_from_upload(path: Path, *, ticket_patterns=None, override=None, requester: str = "") -> tuple[str, list[RuleRequest], Any]:
    """Use the FCR importer for .xlsx/.csv, otherwise treat the file as paste/CSV text."""
    suffix = path.suffix.lower()
    if suffix in {".xlsx", ".xlsm", ".csv", ".xls"}:
        reqs, meta = read_fcr(path, ticket_patterns=ticket_patterns, override=override, requester=requester)
        return fcr_text_from_requests(reqs), reqs, meta
    text = path.read_text(encoding="utf-8", errors="replace")
    return text, [], {"file": path.name, "format": "paste"}


@dataclass
class RouteTable:
    """Output of show routing route / show advanced-routing route (or a CSV) for one firewall.

    Actual learned routes win over BGP/OSPF inference for that firewall's routers."""
    device: str
    text: str
    label: str = "pasted route table"


def parse_route_spec(spec: str) -> RouteTable:
    """FILE@DEVICE (CLI form). DEVICE is the firewall name, hostname or serial."""
    if "@" not in spec:
        raise FlowMapperError(f"--routes needs FILE@DEVICE, got {spec!r}")
    path_s, device = spec.rsplit("@", 1)
    p = Path(path_s).expanduser()
    if not p.is_file():
        raise FlowMapperError(f"route table not found: {p}")
    return RouteTable(device=device.strip(), text=p.read_text(encoding="utf-8", errors="replace"), label=p.name)


def split_route_paste(text: str, default_device: str = "") -> list[RouteTable]:
    """One paste box can hold tables for several firewalls: a line '# device: NAME' starts each one."""
    out: list[RouteTable] = []
    dev, buf = (default_device or "").strip(), []

    def flush() -> None:
        body = "\n".join(buf).strip()
        if body:
            out.append(RouteTable(device=dev, text=body + "\n", label=f"pasted for {dev or '?'}"))

    for line in (text or "").splitlines():
        low = line.strip().lower()
        if low.startswith("# device:") or low.startswith("#device:"):
            flush()
            buf = []
            dev = line.split(":", 1)[1].strip()
            continue
        buf.append(line)
    flush()
    missing = [t for t in out if not t.device]
    if missing:
        raise FlowMapperError("Name the firewall for each pasted route table (the Firewall box, or a '# device: NAME' line).")
    return out


def parse_link_spec(spec: str) -> dict[str, Any]:
    """FROMDEV:IFACE[:NEXTHOP]=TODEV[:IFACE] -> engine link (a custom next hop)."""
    if "=" not in spec:
        raise FlowMapperError(f"--link needs FROMDEV:IFACE[:NEXTHOP]=TODEV[:IFACE], got {spec!r}")
    left, right = spec.split("=", 1)
    lp, rp = left.split(":"), right.split(":")
    if len(lp) < 2 or not lp[0] or not lp[1] or not rp[0]:
        raise FlowMapperError(f"--link needs FROMDEV:IFACE[:NEXTHOP]=TODEV[:IFACE], got {spec!r}")
    frm: dict[str, Any] = {"device": lp[0], "iface": lp[1]}
    if len(lp) > 2 and lp[2]:
        frm["nexthop"] = lp[2]
    return {"from": frm, "to": {"device": rp[0], "iface": rp[1] if len(rp) > 1 and rp[1] else None}, "label": "panlab link"}


def clean_profile_group(name: str | None) -> str:
    """Same cleaning as the engine: no quotes or angle brackets, trimmed, at most 63 characters."""
    import re as _re
    return _re.sub(r"[\x00-\x1f\"<>&']", "", str(name or "")).strip()[:63]


def run_trace(files: list[ConfigFile], fcr_text: str, *,
              ignore_intrazone: bool = False, timeout: int | None = None,
              route_tables: list[RouteTable] | None = None,
              links: list[dict[str, Any]] | None = None,
              pins: dict[str, dict[str, Any]] | None = None,
              roles: dict[str, Any] | None = None, scope: str | dict[str, Any] | None = None,
              profile_group: str | None = None) -> dict[str, Any]:
    """Load the given XML files in the engine, merge local backups, and annotate each FCR row.

    route_tables: actual learned routes per firewall (they win over inference).
    links: custom next-hop links, applied to every row.
    pins: per row ("1", "2", ... or "*" for all): {"choices": {key: devId}, "dstDevice": devId, "srcDevice": devId}.
    roles: the site-role profile (panlab.siteroles); scope: "production" | "all" | "sites=a,b" (or the parsed dict) overrides its scope.
    With neither, the engine default applies: Production only (firewalls with no role words are kept).
    profile_group: optional security profile group added to every generated allow rule (blank or None = none).
    Generated allow rules always log at session end.
    """
    info = verify_engine()
    if not files:
        raise FlowMapperError("no configuration files were given")
    job = {
        "files": [{"path": str(f.path), "name": f.name} for f in files],
        "fcr": fcr_text or "",
        "options": {"ignoreIntrazoneDefault": bool(ignore_intrazone), "profileGroup": clean_profile_group(profile_group)},
        "routeTables": [{"device": t.device, "text": t.text, "label": t.label} for t in (route_tables or [])],
        "links": list(links or []),
        "pins": dict(pins or {}),
    }
    if roles is not None:
        job["roles"] = roles
    if scope is not None:
        from panlab.siteroles import parse_scope
        job["scope"] = parse_scope(scope) if isinstance(scope, str) else dict(scope)
    result = _run_node(job, timeout)
    result.setdefault("engine", {})
    result["engine"]["sha256"] = info["sha256"]
    result["engine"]["source_commit"] = info.get("source_commit")
    result["engine"]["version"] = result["engine"].get("version") or info.get("version")
    return result


def run_diagram(files: list[ConfigFile], kind: str = "site", *, timeout: int | None = None,
                roles: dict[str, Any] | None = None) -> dict[str, Any]:
    """Environment ("site") or Panorama ("pano") diagram for the given config files: {svg, drawio, summary}."""
    verify_engine()
    if kind not in ("site", "pano"):
        raise FlowMapperError(f"unknown diagram kind {kind!r}")
    if not files:
        raise FlowMapperError("no configuration files were given")
    if not RENDER.is_file():
        raise FlowMapperError("the vendored engine has no diagram renderer; re-run tools/sync-flowmapper.py")
    job = {"mode": "diagram", "diagram": {"kind": kind}, "files": [{"path": str(f.path), "name": f.name} for f in files]}
    if roles is not None:
        job["roles"] = roles
    return _run_node(job, timeout)


def run_decom(files: list[ConfigFile], targets: list[str] | str, *, mode: str = "remove",
              flows: list[dict[str, Any]] | None = None, flows_text: str = "",
              select: list[str] | None = None, timeout: int | None = None) -> dict[str, Any]:
    """Decommission analysis in the shared engine (FlowMapper decom.js).

    targets: IPs, subnets, ranges, FQDNs, object, group or rule names.
    mode: "remove" (clean out references) or "block" (stop traffic: also flows / flows_text).
    select: candidate and deny-fix ids to include; None means the default (Exact items and every deny fix).
    Returns the engine result: candidates (tier exact / likely / possible), plan {actions, dangers, kept},
    notes, block (in block mode), counts and exports {csv, markdown, cli, rollback}.
    """
    info = verify_engine()
    if not info.get("has_decom"):
        raise FlowMapperError("the vendored engine has no decommission module; re-run tools/sync-flowmapper.py")
    if not files:
        raise FlowMapperError("no configuration files were given")
    if isinstance(targets, str):
        targets = [t for t in re.split(r"[\n,;]+", targets) if t.strip()]
    job: dict[str, Any] = {
        "mode": "decom",
        "files": [{"path": str(f.path), "name": f.name} for f in files],
        "decom": {"targets": [str(t).strip() for t in targets if str(t).strip()],
                  "mode": "block" if mode in ("block", "stop") else "remove",
                  "flows": list(flows or []), "flowsText": flows_text or ""},
    }
    if select is not None:
        job["decom"]["select"] = list(select)
    result = _run_node(job, timeout)
    result.setdefault("engine", {})
    result["engine"]["sha256"] = info["sha256"]
    result["engine"]["source_commit"] = info.get("source_commit")
    return result


def _run_node(job: dict[str, Any], timeout: int | None) -> dict[str, Any]:
    timeout = DEFAULT_TIMEOUT if timeout is None else timeout
    with tempfile.TemporaryDirectory(prefix="panlab-fm-") as td:
        job_path = Path(td) / "job.json"
        out_path = Path(td) / "out.json"
        job_path.write_text(json.dumps(job))
        proc = subprocess.run(
            [node_bin(), str(CLI), "--core", str(CORE), "--job", str(job_path), "--out", str(out_path)],
            capture_output=True, text=True, timeout=timeout, check=False)
        if not out_path.is_file():
            err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
            raise FlowMapperError(f"FlowMapper engine failed to start: {err}")
        try:
            result = json.loads(out_path.read_text())
        except json.JSONDecodeError as exc:
            raise FlowMapperError(f"FlowMapper engine wrote invalid JSON: {exc}") from exc
        if proc.returncode != 0 or not result.get("ok"):
            raise FlowMapperError(result.get("error") or (proc.stderr or "FlowMapper engine failed").strip())
        return result


def _match_candidate(cands: list[dict[str, Any]], who: str) -> dict[str, Any] | None:
    k = who.strip().lower()
    for x in cands:
        if k in {str(v).lower() for v in (x.get("devId"), x.get("device"), x.get("hostname"), x.get("serial")) if v}:
            return x
    return None


def pins_from_picks(result: dict[str, Any], picks: list[str]) -> dict[str, dict[str, Any]]:
    """--pick ROW.N=DEVICE answers decision N of row ROW (numbers as printed by panlab flowtrace)."""
    pins: dict[str, dict[str, Any]] = {}
    rows = result.get("rows") or []
    for spec in picks:
        try:
            ref, who = spec.split("=", 1)
            r_s, n_s = ref.split(".", 1)
            r, n = int(r_s), int(n_s)
        except ValueError:
            raise FlowMapperError(f"--pick needs ROW.N=DEVICE, got {spec!r}") from None
        if not 1 <= r <= len(rows):
            raise FlowMapperError(f"--pick {spec}: there is no flow {r}")
        choices = (rows[r - 1].get("pathStatus") or {}).get("choices") or []
        if not 1 <= n <= len(choices):
            raise FlowMapperError(f"--pick {spec}: flow {r} has {len(choices)} decision(s)")
        c = choices[n - 1]
        x = _match_candidate(c.get("candidates") or [], who)
        if not x:
            names = ", ".join(str(y.get("hostname") or y.get("device")) for y in c.get("candidates") or [])
            raise FlowMapperError(f"--pick {spec}: {who} is not a candidate ({names})")
        pin = pins.setdefault(str(r), {})
        if c.get("kind") == "next-hop":
            pin.setdefault("choices", {})[c.get("key")] = x["devId"]
        elif c.get("kind") == "destination":
            pin["dstDevice"] = x["devId"]
        else:
            pin["srcDevice"] = x["devId"]
    return pins


def request_from_query(q: dict[str, Any], *, file: str = "fcr", row: int = 1, project: str = "flowtrace") -> RuleRequest:
    proto = (q.get("proto") or "tcp").lower()
    port = q.get("port")
    port_s = None if port is None or port == "" else str(port)
    apps = [q["app"]] if q.get("app") else []
    ticket = (q.get("ticket") or "").strip()
    tickets = Tickets()
    if ticket:
        up = ticket.upper()
        if up.startswith("RITM"):
            tickets.ritm.append(ticket)
        elif up.startswith("SCTASK"):
            tickets.sctask.append(ticket)
        else:
            tickets.cr.append(ticket)
    return RuleRequest(
        file=file, row=row, project=project,
        sources=[Endpoint("ip", q["src"])],
        destinations=[Endpoint("ip", q["dst"])],
        services=[PortSpec(proto, port_s)],
        applications=apps,
        firewall=None, notes="path-trace",
        tickets=tickets, origins=[f"{file}:{row}"],
    )


def placements_from_row(row: dict[str, Any], *, target: str) -> list[Placement]:
    """One placement per hop. Already-allowed hops keep rule_needed=False and the matching rule name."""
    out: list[Placement] = []
    why = ((row.get("why") or {}).get("text") or "")
    uncertain = "uncertain" in why.lower() or (row.get("plan") or {}).get("uncertain", 0) > 0
    hops = row.get("hops") or []
    for h in hops:
        allow = h.get("verdict") == "allow"
        dg = h.get("dg")
        notes = ["path-trace hop %s" % h.get("n")]
        if h.get("hairpin"):
            notes.append("re-enters through an unknown network (hairpin)")
        if h.get("transit"):
            notes.append("crosses a router or WAN not in the config")
        out.append(Placement(
            target=target,
            backend="panorama" if dg else "firewall",
            device=h.get("device") or "unknown",
            serial=None,
            vsys=h.get("vsys") or "vsys1",
            device_group=dg,
            stack=None,
            from_zone=h.get("fromZone"),
            to_zone=h.get("toZone"),
            reason="FlowMapper path hop %s on %s %s" % (h.get("n"), h.get("device"), h.get("vsys") or ""),
            confidence="low" if uncertain else "high",
            needs_human=bool(uncertain or not h.get("fromZone") or not h.get("toZone")),
            rule_needed=not allow,
            already_permitted_by=(h.get("rule") if allow else None),
            role="path-hop",
            notes=notes,
            hop=h.get("n") if len(hops) > 1 else None,
            hops_total=len(hops) if len(hops) > 1 else None,
        ))
    return out




def _engine_hops_are_authoritative(row: dict[str, Any], hops: list[Placement]) -> bool:
    """When to prefer the engine path over the older zone picker.

    Always use a multi-hop path, or a hop that still needs a rule. A single hop
    that the engine already-allows is trusted only when the path is Complete
    (specific routing). A Suggested or Incomplete default-route hop is left to
    the fallback placer, which can propose routes and an untrust/untrust rule
    for networks that are not on the firewall yet.
    """
    if not hops:
        return False
    if len(hops) >= 2 or any(h.rule_needed for h in hops):
        return True
    status = str((row.get("pathStatus") or {}).get("status") or "").lower()
    return status == "complete"


def placements_for_requests(envs, requests: list[RuleRequest], *, target: str,
                            links: list[dict[str, Any]] | None = None,
                            scope: str = "all",
                            timeout: int | None = None) -> dict[tuple, list[Placement]]:
    """Trace the requests through the engine and return path placements keyed by RuleRequest.key().

    Used by FCR import so the change plan follows the same hops as Trace a flow
    (including an off-box hairpin between vsys). Falls back to an empty dict when
    the configs were not loaded from files or the engine cannot run. Matching is
    by source, destination, protocol and port (not application), so an FCR that
    names ssl still attaches to the trace of that flow.
    """
    files: list[ConfigFile] = []
    seen: set[str] = set()
    for env in envs or []:
        raw = getattr(env, "source_path", "") or ""
        path = Path(raw)
        if not path.is_file():
            continue
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        files.append(ConfigFile(path=path, name=path.name))
    if not files or not requests:
        return {}
    try:
        result = run_trace(files, fcr_text_from_requests(requests), links=links, scope=scope, timeout=timeout)
    except FlowMapperError:
        return {}
    rows = list(result.get("rows") or [])
    used: set[int] = set()
    placed: dict[tuple, list[Placement]] = {}
    for r in requests:
        srcs = {e.value for e in r.sources}
        dsts = {e.value for e in r.destinations}
        ports = {str(p.port) for p in r.services if p.port}
        protos = {(p.proto or "").lower() for p in r.services if p.proto}
        match = None
        for i, row in enumerate(rows):
            if i in used:
                continue
            q = row.get("query") or {}
            if q.get("src") not in srcs or q.get("dst") not in dsts:
                continue
            if protos and (q.get("proto") or "").lower() not in protos:
                continue
            if ports and str(q.get("port") or "") not in ports:
                continue
            match = row
            used.add(i)
            break
        if match:
            hops = placements_from_row(match, target=target)
            if _engine_hops_are_authoritative(match, hops):
                placed[r.key()] = hops
    return placed


def requests_and_placements(result: dict[str, Any], *, target: str, project: str = "flowtrace") -> tuple[list[RuleRequest], dict[tuple, list[Placement]]]:
    reqs: list[RuleRequest] = []
    placed: dict[tuple, list[Placement]] = {}
    for i, row in enumerate(result.get("rows") or [], 1):
        q = row.get("query") or {}
        if not q.get("src") or not q.get("dst"):
            continue
        req = request_from_query(q, file="fcr", row=i, project=project)
        reqs.append(req)
        hops = placements_from_row(row, target=target)
        if hops:
            placed[req.key()] = hops
    return reqs, placed
