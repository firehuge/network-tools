# SPDX-License-Identifier: Apache-2.0
"""Traffic-log deny lookup (read-only): find the block, name the rule, and say whether the new rule fixes it.

For each rule in a change set (or an ad-hoc src/dst/port), on a standalone firewall:

1. Query traffic logs with an XML API log job (``type=log&log-type=traffic``)
   filtered on ``addr.src``/``addr.dst``/``port.dst`` and deny/drop/reset
   actions over a time window (default 7 days, capped result count). The
   pan-python client polls the job.
2. Summarize: hits (repeat counts included), first/last seen, blocking
   rule(s) incl. interzone-default / intrazone-default, zones, apps.
3. Run ``test security-policy-match`` for the request as it stands today.
4. Explain in plain English whether the proposed rule (appended at the
   bottom of the rulebase) would allow it, or would be shadowed by an
   explicit rule above it.

Never writes to the firewall. Panorama: TODO (query the managed firewalls'
forwarded logs on Panorama with the same filter, then run the policy match
on the firewall that logged the deny); refused for now.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from panlab.customers import Profile
from panlab.pusher import TZ, PushError, _match_queries, _target, now

DENY_ACTIONS = ("deny", "drop", "drop-icmp", "reset-client", "reset-server", "reset-both", "drop-all-packets")
DEFAULT_RULES = ("interzone-default", "intrazone-default")
PROTO_NAME = {6: "tcp", 17: "udp", 1: "icmp"}


class LogAPI(Protocol):
    def traffic_logs(self, query: str, nlogs: int) -> list[dict]: ...
    def policy_match(self, q: dict) -> str | None: ...
    def running_rule_names(self) -> list[str] | dict[str, str]: ...  # ordered; dict maps name -> action


class XapiLogs:
    def __init__(self, fw):
        self.fw = fw

    def traffic_logs(self, query: str, nlogs: int) -> list[dict]:
        try:
            self.fw.xapi.log(log_type="traffic", nlogs=nlogs, filter=query, interval=2, timeout=120)
        except Exception as exc:  # noqa: BLE001 - surface the API message, never credentials
            raise PushError(f"traffic log query failed: {exc}") from exc
        root = self.fw.xapi.element_root
        out = []
        for e in (root.findall(".//logs/entry") if root is not None else []):
            out.append({c.tag: (c.text or "") for c in e})
        return out

    def policy_match(self, q: dict) -> str | None:
        from panlab.pusher import XapiDevice

        return XapiDevice(self.fw).policy_match(q)

    def running_rule_names(self) -> list[str]:
        """Security rule names in order, from a read-only running-config read."""
        import xml.etree.ElementTree as ET

        from panlab.backup import export_running_config

        return _rule_names(ET.fromstring(export_running_config(self.fw).split("?>", 1)[-1]))


def build_query(src: str | None, dst: str | None, port: str | None, since: datetime) -> str:
    parts = []
    if src:
        parts.append(f"(addr.src in {src})")
    if dst:
        parts.append(f"(addr.dst in {dst})")
    if port:
        parts.append(f"(port.dst eq {port})")
    parts.append("(action neq allow)")  # deny, drop, drop-icmp, reset-* (portable across PAN-OS versions)
    parts.append(f"(receive_time geq '{since.strftime('%Y/%m/%d %H:%M:%S')}')")
    return " and ".join(parts)


def summarize(entries: list[dict]) -> dict[str, Any]:
    hits, rules, zones, apps, actions, times = 0, Counter(), Counter(), Counter(), Counter(), []
    for e in entries:
        n = int(e.get("repeatcnt") or 1)
        hits += n
        rules[e.get("rule") or "?"] += n
        zones[f"{e.get('from') or '?'} -> {e.get('to') or '?'}"] += n
        apps[e.get("app") or "?"] += n
        actions[e.get("action") or "?"] += n
        t = e.get("receive_time") or e.get("time_generated")
        if t:
            times.append(t)
    times.sort()
    return {"entries": len(entries), "hits": hits, "first_seen": times[0] if times else None,
            "last_seen": times[-1] if times else None, "rules": rules.most_common(5), "zones": zones.most_common(5),
            "apps": apps.most_common(5), "actions": actions.most_common(5)}


def explain(new_rule: str, summ: dict, match_now: str | None, requested_apps: list[str], rulebase: list[str] | None) -> str:
    lines = []
    actions = rulebase if isinstance(rulebase, dict) else {}
    if summ["hits"]:
        top = summ["rules"][0][0]
        lines.append(f"Traffic was blocked {summ['hits']} time(s) between {summ['first_seen']} and {summ['last_seen']} "
                     f"(firewall clock), mostly by rule '{top}' ({', '.join(z for z, _ in summ['zones'][:2])}).")
    else:
        lines.append("No denied traffic for this source/destination/port was found in the time window. Either it has not been "
                     "tried yet, or the blocking rule does not log: interzone-default does NOT log by default (override it in "
                     "Policies > Security > interzone-default > Actions > Log at Session End to see these blocks).")
    blocker = match_now
    if blocker in (None, "", *DEFAULT_RULES):
        what = f"the default rule '{blocker}'" if blocker else "no explicit rule (the default interzone deny applies)"
        lines.append(f"Today the firewall's policy test matches {what}. Your new rule '{new_rule}' is added at the bottom of the "
                     f"rulebase, which is still above the default rules, so it WOULD allow this traffic.")
    elif actions.get(blocker) == "allow":
        lines.append(f"Today the policy test already matches ALLOW rule '{blocker}'. The traffic may already be permitted, so a new "
                     f"rule may not be needed. If no zones were given, the test can match broadly; re-check with the source and "
                     f"destination zones.")
    elif rulebase is not None and blocker in rulebase:
        lines.append(f"Today the policy test matches rule '{blocker}', which is above where '{new_rule}' will be added (bottom). "
                     f"The new rule would be SHADOWED: move '{new_rule}' above '{blocker}' "
                     f"(Policies > Security > select the rule > Move > Move Up / Move Before '{blocker}').")
    else:
        lines.append(f"Today the policy test matches rule '{blocker}'. If that rule allows the traffic, the request may already be "
                     f"covered; if it denies it, place '{new_rule}' above '{blocker}'.")
    logged = {a for a, _ in summ["apps"] if a not in ("?", "", "incomplete", "not-applicable", "insufficient-data")}
    req = {a.lower() for a in requested_apps if a.lower() not in ("any", "")}
    if logged and req and not (logged & req):
        lines.append(f"Note: the logs show app(s) {', '.join(sorted(logged))}, but the request asks for {', '.join(sorted(req))}.")
    elif logged and not req:
        lines.append(f"Logged app(s): {', '.join(sorted(logged))} (the rule uses application any).")
    return " ".join(lines)


def _rule_names(root) -> dict[str, str]:
    out: dict[str, str] = {}
    for rules in root.iter("rules"):
        for e in rules.findall("entry"):
            if e.get("name"):
                out[e.get("name")] = (e.findtext("action") or "").strip()
    return out


def lookup(api: LogAPI, *, name: str, q: dict, apps: list[str], days: int, max_logs: int,
           rulebase: list[str] | None) -> dict[str, Any]:
    since = now() - timedelta(days=days)
    port = str(q.get("destination-port") or "") or None
    query = build_query(q.get("source"), q.get("destination"), port, since)
    entries = api.traffic_logs(query, max_logs)
    summ = summarize(entries)
    try:
        match_now = api.policy_match(q)
        perr = None
    except Exception as exc:  # noqa: BLE001
        match_now, perr = None, str(exc)[:200]
    return {"rule": name, "query": query, "window_days": days, "max_logs": max_logs, "capped": len(entries) >= max_logs,
            "summary": summ, "policy_match_now": match_now, "policy_match_error": perr,
            "explanation": explain(name, summ, match_now, apps, rulebase)}


def changeset_evidence(profile: Profile, cs: dict, api: LogAPI, *, target_name: str | None = None, days: int = 7,
                       max_logs: int = 200) -> dict[str, Any]:
    try:
        target = _target(profile, target_name)
    except PushError as exc:
        raise PushError(f"{exc} (Panorama deny lookup is a TODO)") from exc
    rb = api.running_rule_names()
    apps = {r["name"]: r["application"] for g in cs["groups"] for r in g["rules"]}
    results = [lookup(api, name=n, q=q, apps=apps.get(n, []), days=days, max_logs=max_logs, rulebase=rb)
               for n, q in _match_queries(cs, target)]
    return {"schema": "panlab.denylog/v1", "generated": now().isoformat(timespec="seconds"), "timezone": "America/Chicago",
            "customer": profile.name, "target": target.name, "window_days": days, "results": results,
            "skipped": "rules without a single IP source, IP destination and tcp/udp port are not looked up"}


def save_evidence(profile: Profile, stem: str, ev: dict) -> Path:
    p = profile.data_dir("evidence") / f"{stem}-denylog.json"
    p.write_text(json.dumps(ev, indent=2), encoding="utf-8")
    p.chmod(0o600)
    return p


def load_evidence(profile: Profile, stem: str) -> dict | None:
    p = profile.data_dir("evidence") / f"{stem}-denylog.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None


def evidence_lines(ev: dict | None) -> list[str]:
    if not ev:
        return ["- Not checked. Run the traffic-log deny lookup (GUI: change set page > Check traffic logs; CLI: `paat denylog`)."]
    out = [f"- Checked {ev['generated']} on {ev['target']}, last {ev['window_days']} day(s) of traffic logs (read-only)."]
    for r in ev["results"]:
        s = r["summary"]
        out.append(f"- `{r['rule']}`: {s['hits']} denied hit(s)"
                   + (f", first {s['first_seen']}, last {s['last_seen']}, rule(s) {', '.join(f'{k} ({v})' for k, v in s['rules'])}, "
                      f"zones {', '.join(k for k, _ in s['zones'])}, app(s) {', '.join(k for k, _ in s['apps'])}" if s["hits"] else "")
                   + (" (result capped)" if r["capped"] else "") + f". Policy test today: {r['policy_match_now'] or 'no explicit rule'}.")
        out.append(f"  - {r['explanation']}")
    return out


def connect_logs(profile: Profile, target_name: str | None = None) -> XapiLogs:
    from panlab.pusher import connect_target

    return XapiLogs(connect_target(profile, target_name).fw)


def adhoc_query(src: str, dst: str, proto: str, port: str, from_zone: str = "", to_zone: str = "") -> dict:
    """Validated query for the ad-hoc form (values go into a log filter and an op command)."""
    import ipaddress
    import re

    q: dict[str, Any] = {}
    for k, v in (("from", from_zone), ("to", to_zone)):
        v = v.strip()
        if v:
            if not re.fullmatch(r"[A-Za-z0-9_.\- ]{1,63}", v):
                raise PushError(f"bad zone name {v!r}")
            q[k] = v
    for k, v in (("source", src), ("destination", dst)):
        try:
            ipaddress.IPv4Address(v.strip())
        except ValueError:
            raise PushError(f"{k} must be a single IPv4 address, got {v!r}") from None
        q[k] = v.strip()
    if proto.lower() not in ("tcp", "udp"):
        raise PushError("protocol must be tcp or udp")
    if not re.fullmatch(r"\d{1,5}", port.strip()) or not 0 < int(port) < 65536:
        raise PushError("port must be 1-65535")
    q["protocol"] = 6 if proto.lower() == "tcp" else 17
    q["destination-port"] = port.strip()
    return q


__all__ = ["TZ"]
