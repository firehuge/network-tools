"""Port-to-App-ID advisor pages (read-only; nothing is pushed).

Running an analysis needs the ``fcr`` permission; reading saved results needs ``view`` or ``fcr``. The customer must be in
the user's scope, and only firewalls in the user's device scope are queried for logs.
"""

from __future__ import annotations

import html
from urllib.parse import quote

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from panlab import appadvisor, identity
from panlab.customers import load_profile
from panlab.pusher import PushError, audit

router = APIRouter()
e = html.escape
VIEW = ("view", "fcr")
STATUS_COLOR = {"migrate": "#1b7f3b", "mixed": "#b26a00", "review": "#b26a00", "unused": "#666"}


def _web():
    from panlab.web import app as webapp
    return webapp


def _prof(customer: str):
    try:
        return load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")


def _dev(prof, name: str) -> str:
    return identity.label(name, identity.cached(prof, name))


def _ident_line(prof, adv: dict) -> str:
    seen = "; ".join(f"{d.get('hostname') or identity.UNKNOWN_HOST} · SN {d.get('serial') or 'unknown'}" for d in adv.get("log_devices") or [])
    return seen or ", ".join(_dev(prof, t) for t in adv.get("log_targets") or [])


@router.get("/advisor", response_class=HTMLResponse)
def advisor_page(request: Request, customer: str = "", msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, VIEW)
    names = w.list_customers()
    customer = customer if customer in names else (names[0] if names else "")
    opts = "".join(f"<option {'selected' if c == customer else ''}>{e(c)}</option>" for c in names)
    body = ("<h2>Port to App-ID advisor</h2>"
            "<div class='note'>Finds allow rules that match on <b>ports only</b> (application <i>any</i> + service ports), reads "
            "their traffic logs from the firewall and suggests App-ID rules instead: the app with <i>application-default</i> "
            "where it runs on its normal port, the app plus the explicit port where it does not (ssh on 2222), "
            "<b>needs review</b> where the firewall could not identify the traffic, and removal for ports nobody used. "
            "The result is a CR change plan. <b>Read-only: nothing is changed on any device.</b></div>"
            + (f"<p class='note'>{e(msg)}</p>" if msg else "")
            + f"<form method='get' action='/advisor'><label>Customer</label><select name='customer' onchange='this.form.submit()'>{opts}</select></form>")
    if customer:
        prof = _prof(customer)
        if user.can("fcr"):
            targets = appadvisor.log_targets_for(prof, user)
            topts = "<option value=''>all in my scope</option>" + "".join(
                f"<option value='{e(t)}'>{e(_dev(prof, t))}</option>" for t in targets)
            body += (f"<form method='post' action='/advisor/run' class='card'><h3>New analysis</h3>"
                     f"<input type='hidden' name='customer' value='{e(customer)}'>"
                     "<label>Rule name(s), comma separated (blank = every port-based allow rule)</label>"
                     "<input name='rules' size='70' placeholder='e.g. RULE-ONE, RULE-TWO'>"
                     f"<label>Read logs from</label><select name='target'>{topts}</select>"
                     "<label>Log window (days, 1-90; 30+ gives better confidence)</label><input name='days' value='7' size='4'>"
                     "<label>Max log entries per rule (100-5000)</label><input name='max_logs' value='5000' size='6'><br>"
                     "<button>Analyze (read-only)</button></form>")
            if not targets:
                body += "<p class='note'>No firewall of this customer is in your device scope.</p>"
        runs = appadvisor.list_runs(prof)[:50]
        rows = []
        for rid in runs:
            try:
                a = appadvisor.load(prof, rid)
            except (OSError, ValueError):
                continue
            rows.append(f"<tr><td><a href='/advisor/{e(customer)}/{e(rid)}'>{e(rid)}</a></td><td>{e(a.get('created', ''))}</td>"
                        f"<td>{e(a.get('by', ''))}</td><td>{e(', '.join(r['rule']['name'] for r in a.get('results', [])))}</td>"
                        f"<td>{a.get('window_days')} d</td></tr>")
        body += ("<h3>Saved analyses</h3><table><tr><th>Id</th><th>Created (CST)</th><th>By</th><th>Rules</th><th>Window</th></tr>"
                 + "".join(rows) + "</table>") if rows else "<p class='muted'>No analyses yet.</p>"
    return w.page("App-ID advisor", body, user)


def _bounded(v: str, lo: int, hi: int, default: int) -> int:
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


@router.post("/advisor/run")
def advisor_run(request: Request, customer: str = Form(...), rules: str = Form(""), target: str = Form(""),
                days: str = Form("7"), max_logs: str = Form("5000")):
    w = _web()
    user = w.need(request, "fcr", customer=customer)
    prof = _prof(customer)
    allowed = appadvisor.log_targets_for(prof, user)
    if target and target not in allowed:
        raise HTTPException(403, "that device is not in your scope")
    targets = [target] if target else allowed
    names = [r.strip() for r in rules.split(",") if r.strip()]
    d, n = _bounded(days, 1, 90, 7), _bounded(max_logs, 100, 5000, 5000)
    try:
        adv = appadvisor.run(prof, rules=names or None, days=d, max_logs=n, actor=user[0], log_targets=targets)
    except PushError as exc:
        audit(prof, actor=user[0], action="app_advisor", result="error", reason=str(exc)[:200], rules=names)
        return RedirectResponse(f"/advisor?customer={quote(customer)}&msg={quote(str(exc)[:200])}", 303)
    audit(prof, actor=user[0], action="app_advisor", result="ok", advisor=adv["id"], rules=[r["rule"]["name"] for r in adv["results"]],
          days=d, targets=targets)
    if not adv["results"]:
        return RedirectResponse(f"/advisor?customer={quote(customer)}&msg=No+port-based+allow+rules+found.", 303)
    return RedirectResponse(f"/advisor/{customer}/{adv['id']}", 303)


def _load(prof, aid: str) -> dict:
    try:
        return appadvisor.load(prof, aid)
    except (ValueError, OSError):
        raise HTTPException(404, "unknown analysis")


@router.get("/advisor/{customer}/{aid}", response_class=HTMLResponse)
def advisor_view(request: Request, customer: str, aid: str) -> HTMLResponse:
    w = _web()
    user = w.need(request, VIEW)
    prof = _prof(customer)
    adv = _load(prof, aid)
    body = (f"<h2>App-ID advisor: {e(customer)}</h2><p class='muted'>{e(adv['id'])} · created {e(adv['created'])} (CST) by "
            f"{e(adv.get('by', ''))} · log window: last {adv['window_days']} day(s), since {e(adv['since'])} (firewall clock), "
            f"max {adv['max_logs']} entries/rule</p>"
            f"<p>Logs from: <b>{e(_ident_line(prof, adv))}</b> · policy owner: {e(_dev(prof, adv['policy_owner']))}</p>"
            f"<p><a href='/advisor/{e(customer)}/{e(aid)}/changeplan.md'>Download CR change plan (markdown)</a> · "
            "advisory only, never pushed automatically</p>")
    for r in adv["results"]:
        rule = r["rule"]
        rows = "".join(
            f"<tr><td>{e(p['proto'])}/{p['port']}</td><td style='color:{STATUS_COLOR.get(p['status'], '#000')}'><b>{e(p['status'])}</b></td><td>"
            + ("<br>".join(f"{e(a['app'])}: {a['sessions']} sess, {a['bytes']} B, {e(a['first'])} → {e(a['last'])} · "
                           f"<b>{e(a['verdict'])}</b> ({e(a['confidence'])}) <span class='muted'>{e(a['why'])}</span>" for a in p["apps"])
               or f"no traffic: remove ({e(p['unused_confidence'] or '')} confidence)") + "</td></tr>" for p in r["ports"])
        props = "".join(f"<li>New rule <b>{e(n['name'])}</b>: {e(', '.join(n['application']))} · service {e(', '.join(n['service']))} "
                        f"<span class='muted'>({e(n['why'])}; {e(n['confidence'])})</span></li>" for n in r["new_rules"])
        o = r["original"]
        props += (f"<li>Narrow <b>{e(rule['name'])}</b> to {e(', '.join(o['service']))}: {e(o['why'])}</li>" if o["action"] == "narrow"
                  else f"<li>Disable <b>{e(rule['name'])}</b>: {e(o['why'])}</li>")
        if r["new_services"]:
            props += "<li>New service objects: " + e(", ".join(f"{s['name']} ({s['proto']}/{s['port']})" for s in r["new_services"])) + "</li>"
        if r["remove_ports"]:
            props += f"<li>Unused, remove: {e(', '.join(r['remove_ports']))}</li>"
        if r["review_ports"]:
            props += f"<li><b>Needs review / more data:</b> {e(', '.join(r['review_ports']))}</li>"
        body += (f"<div class='card'><h3>{e(rule['name'])} <span class='muted'>({e(rule['scope'])} {e(rule['rulebase'])})</span></h3>"
                 f"<p>Today: application any · {e(', '.join(rule['service']))} = {e(', '.join(r['configured_ports']))} · "
                 f"{r['sessions']} session(s) from {r['log_entries']} log entr(ies)"
                 + (" · <b>capped</b>: shorten the window" if r["capped"] else "")
                 + f" · overall confidence <b>{e(r['overall_confidence'])}</b></p>"
                 f"<table><tr><th>Port</th><th>Status</th><th>Apps seen</th></tr>{rows}</table><h4>Suggested</h4><ul>{props}</ul></div>")
    md = appadvisor.render_cr(adv, _ident_line(prof, adv))
    body += f"<h3>CR change plan</h3><pre style='white-space:pre-wrap;background:#f6f6f6;padding:12px'>{e(md)}</pre>"
    return w.page(f"App-ID advisor {aid}", body, user)


@router.get("/advisor/{customer}/{aid}/changeplan.md")
def advisor_md(request: Request, customer: str, aid: str):
    _web().need(request, VIEW)
    prof = _prof(customer)
    adv = _load(prof, aid)
    return PlainTextResponse(appadvisor.render_cr(adv, _ident_line(prof, adv)), media_type="text/markdown",
                             headers={"Content-Disposition": f"attachment; filename={aid}-changeplan.md"})
