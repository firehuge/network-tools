"""Optional live confirmation of a FlowMapper trace against the running device.

For each traced hop this asks the firewall (or the firewall through Panorama)
for a ``test security-policy-match``, a ``test routing fib-lookup``, and a
short traffic-log sample. Results are compared with the config-trace verdict.
Disagreements are highlighted; API failures are reported as errors, not as
disagreements. Read-only: nothing is written to a device.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import timedelta
from typing import Any

from panlab.customers import Profile
from panlab.denylog import build_query, summarize
from panlab.liveconfig import LiveDevice, LiveError, LiveSnapshot, connect, now

PROTO_NUM = {"tcp": "6", "udp": "17", "icmp": "1"}
DENY_VERDICTS = {"deny", "drop", "reset", "reset-client", "reset-server", "reset-both"}
DEFAULT_RULES = {"interzone-default", "intrazone-default"}


def _x(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _text(elem: ET.Element | None) -> str:
    if elem is None:
        return ""
    return "".join(elem.itertext()).strip()


def _proto_num(proto: str | None) -> str:
    p = (proto or "tcp").strip().lower()
    return PROTO_NUM.get(p, p if p.isdigit() else "6")


def _verdict_kind(v: str) -> str:
    v = (v or "").strip().lower()
    if v == "allow":
        return "allow"
    if v in DENY_VERDICTS:
        return "deny"
    return "other"


def _match_kind(name: str | None, action: str | None = None) -> str:
    if action:
        a = action.lower()
        if a == "allow":
            return "allow"
        if a in DENY_VERDICTS:
            return "deny"
    if not name:
        return "deny"  # implicit interzone deny
    if name in DEFAULT_RULES:
        return "deny"
    return "allow"


def policy_match(dev: LiveDevice, hop: dict, query: dict) -> dict:
    """Run test security-policy-match. Returns name/action/error."""
    q: dict[str, str] = {}
    if hop.get("fromZone"):
        q["from"] = hop["fromZone"]
    if hop.get("toZone"):
        q["to"] = hop["toZone"]
    src = (query.get("src") or "").split("/")[0]
    dst = (query.get("dst") or "").split("/")[0]
    if src:
        q["source"] = src
    if dst:
        q["destination"] = dst
    q["protocol"] = _proto_num(query.get("proto"))
    if query.get("port") is not None and str(query.get("port")) not in {"", "None"}:
        q["destination-port"] = str(query["port"])
    if not q.get("from") or not q.get("to") or not q.get("source") or not q.get("destination"):
        return {"ok": False, "error": "missing from/to/source/destination for a policy test"}
    cmd = ("<test><security-policy-match>"
           + "".join(f"<{k}>{_x(v)}</{k}>" for k, v in q.items())
           + "</security-policy-match></test>")
    try:
        res = dev.op(cmd)
    except LiveError as exc:
        return {"ok": False, "error": str(exc), "query": q}
    entry = res.find(".//entry")
    name = entry.get("name") if entry is not None else None
    action = None
    if entry is not None:
        action = (entry.findtext("action") or entry.get("action") or "").strip() or None
    return {"ok": True, "rule": name, "action": action, "query": q, "kind": _match_kind(name, action)}


def fib_lookup(dev: LiveDevice, dest: str, virtual_router: str | None) -> dict:
    if not dest:
        return {"ok": False, "error": "no destination for a FIB lookup"}
    vr = virtual_router or "default"
    cmd = (f"<test><routing><fib-lookup><ip>{_x(dest)}</ip>"
           f"<virtual-router>{_x(vr)}</virtual-router></fib-lookup></routing></test>")
    try:
        res = dev.op(cmd)
    except LiveError as exc:
        return {"ok": False, "error": str(exc), "virtual_router": vr}
    # Typical result: interface, nexthop, zone, vr, metric, flags.
    fields = {}
    for tag in ("interface", "nexthop", "nh", "ip", "zone", "virtual-router", "vr", "metric", "flags"):
        el = res.find(f".//{tag}")
        if el is not None and (_text(el) or el.get("name")):
            fields[tag] = _text(el) or el.get("name")
    # Some PAN-OS versions dump a CDATA blob.
    blob = _text(res)
    return {"ok": True, "virtual_router": vr, "fields": fields, "text": blob[:2000] if blob else ""}


def hop_logs(dev: LiveDevice, query: dict, *, days: int = 7, nlogs: int = 20, hop: dict | None = None) -> dict:
    src = (query.get("src") or "").split("/")[0] or None
    dst = (query.get("dst") or "").split("/")[0] or None
    port = query.get("port")
    port_s = str(port) if port is not None and str(port) not in {"", "None"} else None
    since = now() - timedelta(days=days)
    # Any action, so we can confirm allow as well as deny.
    parts = []
    if src:
        parts.append(f"(addr.src in {src})")
    if dst:
        parts.append(f"(addr.dst in {dst})")
    if port_s:
        parts.append(f"(port.dst eq {port_s})")
    # Zone-scope the hop: a flow that leaves one virtual router and comes back in on another is logged twice in
    # the same vsys, once per pass. Without zones, the allow of pass 1 hides the deny of pass 2.
    if hop:
        if hop.get("fromZone"):
            parts.append(f"(zone.src eq {hop['fromZone']})")
        if hop.get("toZone"):
            parts.append(f"(zone.dst eq {hop['toZone']})")
    parts.append(f"(receive_time geq '{since.strftime('%Y/%m/%d %H:%M:%S')}')")
    filt = " and ".join(parts)
    try:
        entries = dev.traffic_logs(filt, nlogs)
    except LiveError as exc:
        return {"ok": False, "error": str(exc), "filter": filt}
    summ = summarize(entries)
    # The newest log decides: after a change, a week of old denies must not outvote the first allow.
    latest = max(entries, key=lambda x: x.get("receive_time") or x.get("time_generated") or "", default=None)
    top_action = (latest.get("action") or None) if latest else None
    top_rule = (latest.get("rule") or None) if latest else None
    return {
        "ok": True, "filter": filt, "summary": summ,
        "top_action": top_action, "top_rule": top_rule,
        "last_time": (latest.get("receive_time") or latest.get("time_generated")) if latest else None,
        "kind": _verdict_kind(top_action or ""),
    }


def _device_for_hop(profile: Profile, hop: dict, snap: LiveSnapshot | None) -> LiveDevice:
    """Reach the firewall that owns this hop: direct target, or via Panorama serial."""
    name = (hop.get("device") or hop.get("hostname") or "").strip()
    serial = (hop.get("serial") or "").strip()
    vsys = (hop.get("vsys") or "").strip() or None
    if snap:
        for d in snap.meta.get("devices") or []:
            if serial and d.get("serial") == serial:
                break
            if name and d.get("hostname") == name:
                serial = d.get("serial") or serial
                break
    # Prefer a matching firewall target, else the first Panorama (proxied).
    fw_tgt = next((t for t in profile.targets if t.type == "firewall" and t.name == name), None)
    if fw_tgt is None:
        fw_tgt = next((t for t in profile.targets if t.type == "firewall"), None)
    pano = next((t for t in profile.targets if t.type == "panorama"), None)
    if pano is not None and serial:
        return connect(profile, pano, serial=serial, vsys=vsys)
    if fw_tgt is not None:
        return connect(profile, fw_tgt, vsys=vsys)
    if pano is not None:
        return connect(profile, pano, vsys=vsys)
    raise LiveError("no Panorama or firewall target is configured for a live check")


def _log_device(profile: Profile, hop: dict, snap: LiveSnapshot | None) -> LiveDevice:
    """Query traffic logs on the firewall itself.

    Panorama log jobs can come back empty on some setups, so prefer a direct
    firewall target over a Panorama-proxied log query.
    """
    vsys = (hop.get("vsys") or "").strip() or None
    fw_tgt = next((t for t in profile.targets if t.type == "firewall"), None)
    if fw_tgt is not None:
        return connect(profile, fw_tgt, vsys=vsys)
    return _device_for_hop(profile, hop, snap)


def check_hop(profile: Profile, hop: dict, query: dict, snap: LiveSnapshot | None = None) -> dict:
    out: dict[str, Any] = {
        "n": hop.get("n"),
        "device": hop.get("device"),
        "vsys": hop.get("vsys"),
        "vr": hop.get("vr"),
        "from": hop.get("fromZone"),
        "to": hop.get("toZone"),
        "trace_verdict": hop.get("verdict"),
        "trace_rule": hop.get("rule"),
        "trace_kind": _verdict_kind(hop.get("verdict") or ""),
        "ok": True,
        "agree": True,
        "disagreements": [],
        "errors": [],
    }
    try:
        dev = _device_for_hop(profile, hop, snap)
    except LiveError as exc:
        out["ok"] = False
        out["agree"] = None
        out["errors"].append(str(exc))
        return out

    pm = policy_match(dev, hop, query)
    out["policy_match"] = pm
    if not pm.get("ok"):
        out["errors"].append(f"policy-match: {pm.get('error')}")
    else:
        live_kind = pm.get("kind")
        if out["trace_kind"] in {"allow", "deny"} and live_kind in {"allow", "deny"} and live_kind != out["trace_kind"]:
            out["disagreements"].append(
                f"Config trace says {out['trace_verdict']}"
                + (f" by {out['trace_rule']}" if out.get("trace_rule") else "")
                + f", but live policy-match returned {live_kind}"
                + (f" rule '{pm.get('rule')}'" if pm.get("rule") else " (no explicit rule / default deny)")
                + "."
            )

    dest = (query.get("dst") or "").split("/")[0]
    vr = hop.get("vr") or hop.get("virtualRouter") or hop.get("virtual_router")
    fib = fib_lookup(dev, dest, vr)
    out["fib"] = fib
    if not fib.get("ok"):
        out["errors"].append(f"fib-lookup: {fib.get('error')}")
    else:
        live_if = (fib.get("fields") or {}).get("interface")
        want_if = hop.get("egressIf")
        if live_if and want_if and live_if != want_if:
            out["disagreements"].append(
                f"Config trace leaves {hop.get('vr') or 'the router'} on {want_if}, but the live FIB in "
                f"{fib.get('virtual_router')} uses {live_if}.")

    try:
        logs = hop_logs(_log_device(profile, hop, snap), query, hop=hop)
    except LiveError as exc:
        logs = {"ok": False, "error": str(exc)}
    out["logs"] = logs
    if not logs.get("ok"):
        out["errors"].append(f"traffic logs: {logs.get('error')}")
    elif logs.get("summary", {}).get("hits") and logs.get("kind") in {"allow", "deny"}:
        if out["trace_kind"] in {"allow", "deny"} and logs["kind"] != out["trace_kind"]:
            out["disagreements"].append(
                f"Config trace says {out['trace_verdict']}, but the newest of the traffic logs"
                + (f" ({logs['last_time']}, firewall clock)" if logs.get("last_time") else "")
                + f" shows {logs.get('top_action') or 'unknown'}"
                + (f" by rule '{logs.get('top_rule')}'" if logs.get("top_rule") else "")
                + f" ({logs['summary']['hits']} hit(s) in the window). If the rule was pushed after that time,"
                " send fresh traffic and check again."
            )

    if out["errors"] and not (pm.get("ok") or logs.get("ok") or fib.get("ok")):
        out["ok"] = False
        out["agree"] = None
    else:
        out["agree"] = not out["disagreements"]
        out["ok"] = True
    return out


def check_trace(profile: Profile, result: dict, snap: LiveSnapshot | None = None) -> dict:
    """Run a live check for every hop in a FlowMapper trace result."""
    rows_out = []
    disagreements = 0
    errors = 0
    hops_n = 0
    for i, row in enumerate(result.get("rows") or [], 1):
        q = row.get("query") or {}
        hop_results = []
        for hop in row.get("hops") or []:
            hops_n += 1
            hr = check_hop(profile, hop, q, snap)
            hop_results.append(hr)
            disagreements += len(hr.get("disagreements") or [])
            errors += len(hr.get("errors") or [])
        rows_out.append({"flow": i, "query": q, "hops": hop_results})
    return {
        "ok": errors == 0,
        "hops": hops_n,
        "disagreements": disagreements,
        "errors": errors,
        "rows": rows_out,
        "checked_at": now().isoformat(timespec="seconds"),
    }
