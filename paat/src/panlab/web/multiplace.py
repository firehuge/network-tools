"""The 'rule needed in more than one place' warning shown on plan, change-plan and push pages.

A flow that crosses two firewalls, two vsys, or the same firewall twice
(out of one virtual router and back in on another) is checked by security
policy at every one of those points. Missing one leaves the traffic blocked
even though "the rule was pushed". The change set lists every point in
``requests[].enforcement_points`` (see ``changeset.annotate_enforcement_points``).
"""

from __future__ import annotations

from panlab.changeplan import assumes_outside_hop

import html

e = html.escape

_STATUS = {
    "new-rule": ("new rule", "#b00020"),
    "already-allowed": ("already allowed", "#1b7f3b"),
    "no-rule-needed": ("no rule needed", "#1b7f3b"),
    "needs-human": ("needs a human", "#8a6d00"),
}


def multi_requests(cs: dict) -> list[dict]:
    return [rq for rq in cs.get("requests") or [] if len(rq.get("enforcement_points") or []) > 1]



def banner_html(cs: dict) -> str:
    rqs = multi_requests(cs)
    if not rqs:
        return ""
    rows = []
    for rq in rqs:
        pts = rq["enforcement_points"]
        items = []
        for i, p in enumerate(pts, 1):
            label, color = _STATUS.get(p.get("status") or "", (p.get("status") or "?", "#333"))
            rule = f" <code>{e(p['rule'])}</code>" if p.get("rule") else ""
            pos = f" <small>(placed above <code>{e(p['place_before'])}</code>)</small>" if p.get("place_before") else ""
            where = e(p.get("device_group") or p.get("vsys") or "")
            items.append(f"<li><b>Place {i}:</b> {e(str(p.get('device') or '?'))} <small>{where}</small> "
                         f"<code>{e(str(p.get('from') or '?'))}</code> &rarr; <code>{e(str(p.get('to') or '?'))}</code>: "
                         f"<span style='color:{color};font-weight:700'>{e(label)}</span>{rule}{pos}</li>")
        todo = sum(1 for p in pts if p.get("status") in ("new-rule", "needs-human"))
        what = (f"{todo} of {len(pts)} places need a new rule" if todo else f"all {len(pts)} places are already allowed")
        rows.append(f"<div class='mp-req'><b>{e(str(rq.get('id')))}</b> "
                    f"<small>{e(', '.join(rq.get('origins') or []))}</small>: {e(what)}<ol>{''.join(items)}</ol></div>")
    need = sum(1 for rq in rqs for p in rq["enforcement_points"] if p.get("status") in ("new-rule", "needs-human"))
    places = sum(len(rq["enforcement_points"]) for rq in rqs)
    assumes = assumes_outside_hop(cs)
    lead = f"This flow needs {need} rule{'s' if need != 1 else ''} across {places} vsys/firewalls."
    if assumes:
        lead += " The count assumes the suggested outside hop."
    lead += " These flows are checked by security policy more than once on their path (two firewalls, two vsys, or the same firewall twice through two virtual routers). Each place below needs an allow. The push writes every new rule listed here, and the post-push check tests each one on the firewall."
    return ("<div class='multiplace' role='alert'>"
            "<h3 style='margin:0 0 6px'>Rule needed in more than one place</h3>"
            f"<p style='margin:0 0 6px'>{e(lead)}</p>"
            + "".join(rows) + "</div>")
