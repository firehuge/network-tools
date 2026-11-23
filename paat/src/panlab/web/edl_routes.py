# SPDX-License-Identifier: Apache-2.0
"""EDL manager pages (``/edls``) and the hosted feed (``/edl/<token>.txt``).

Permissions: ``edl_view`` read lists; ``edl_edit`` add / remove / import / revert (staged for a second person when the
list requires approval or an entry is risky); ``edl_approve`` approve or reject staged changes and EDL firewall-object
requests (never your own); ``edl_admin`` create and delete lists, publishing targets, safety settings, firewall objects
and "refresh now". Pushing an approved firewall object also needs ``push`` (the normal red push area rule). Every page
checks the customer scope, so one customer never sees another's lists. The hosted feed has no session: it is
reached by an unguessable token, optionally with basic auth and a source-IP allowlist.
"""

from __future__ import annotations

import html
import re
from urllib.parse import quote

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

from panlab import edl
from panlab.customers import load_profile
from panlab.web import theme
from panlab.web.auth import device_in_scope

router = APIRouter()
e = html.escape
ANY = ("edl_view", "edl_edit", "edl_approve", "edl_admin")
device_factory = None  # tests: callable(profile, target) -> urlfilter-style device (show/edit/delete/commit/commit_all)
STATUS_TONE = {"pending": "warning", "approved": "success", "rejected": "danger", "withdrawn": "neutral", "pushed": "success",
               "failed": "danger", "pushing": "push", "rolled-back": "neutral", "dry-run": "info"}
PUB_TONE = {"published": "success", "live": "success", "in-sync": "success", "behind": "warning", "conflict": "danger",
            "changed-outside": "danger", "error": "danger", "verify-failed": "danger", "missing": "warning", "off": "neutral"}


def _web():
    from panlab.web import app as webapp
    return webapp


def _prof(customer: str):
    try:
        return load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")


def _meta(prof, lid: str) -> dict:
    try:
        return edl.load_meta(prof, lid)
    except edl.EdlError:
        raise HTTPException(404, "no such list")


def _back(customer: str, lid: str = "", sub: str = "", msg: str = "") -> RedirectResponse:
    url = f"/edls/{quote(customer)}" + (f"/{quote(lid)}" if lid else "") + (f"/{sub}" if sub else "")
    if not lid and not sub:
        url = f"/edls?customer={quote(customer)}"
    return RedirectResponse(url + (f"{'&' if '?' in url else '?'}msg={quote(msg)}" if msg else ""), status_code=303)


def _ts(s: str) -> str:
    return e((s or "")[:16].replace("T", " "))


def _kind(meta: dict) -> str:
    return theme.badge({"ip": "IP", "domain": "FQDN", "url": "URL"}[meta["type"]], "info")


def _pub_summary(meta: dict) -> str:
    out = []
    h = meta.get("hosted") or {}
    if h.get("enabled"):
        out.append(theme.badge("PAAT-hosted", "success"))
    s3 = meta.get("s3") or {}
    if s3.get("enabled"):
        st = ((meta.get("publish") or {}).get("s3") or {}).get("state", "not published")
        out.append(theme.badge(f"S3: {st}", PUB_TONE.get(st, "warning")))
    return " ".join(out) or theme.badge("not published", "warning")


def _base(request: Request) -> str:
    return f"{request.url.scheme}://{request.headers.get('host') or request.url.netloc}"


def _textarea_lines(s: str) -> list[str]:
    return [x for x in (s or "").splitlines() if x.strip()]


def _help() -> str:
    return theme.help_note("edl.md", "An external dynamic list (EDL) is a text file of IPs, domains or URLs that firewalls fetch on "
                           "a schedule. Edit the list here and every firewall that points at it picks the change up on its next "
                           "refresh (5 minutes by default). Nobody has to log in to a firewall.")


# ---------------------------------------------------------------- index

@router.get("/edls", response_class=HTMLResponse)
def index(request: Request, customer: str = "", msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, ANY)
    custs = w.list_customers()
    if customer and customer not in custs:
        raise HTTPException(403, f"customer {customer} is not in your scope")
    shown = [customer] if customer else custs
    chips = ""
    if len(custs) > 1:
        chips = ("<div class='chips'>" + f"<a class='chip{'' if customer else ' on'}' href='/edls'>All customers</a>" +
                 "".join(f"<a class='chip{' on' if c == customer else ''}' href='/edls?customer={quote(c)}'>{e(c)}</a>" for c in custs)
                 + "</div>")
    head = ("<div class='pagehead'><div><h2>External dynamic lists</h2><p>Block lists of IPs, domains (FQDN) and URLs that "
            "firewalls fetch by themselves. Change the list here; no firewall login, no commit.</p></div></div>")
    body = head + (f"<div class='note'>{e(msg)}</div>" if msg else "") + _help() + chips
    any_list = False
    for c in shown:
        prof = _prof(c)
        lists = edl.all_lists(prof)
        objs = [r for r in edl.list_object_requests(prof) if r.get("status") in ("pending", "approved")]
        acts = []
        if user.can("edl_admin"):
            acts.append(f"<a class='btn' href='/edls/{e(c)}/new'>{theme.icon('list')}New list</a>")
        acts.append(f"<a class='btn secondary' href='/edls/{e(c)}/settings'>Safety settings</a>")
        acts.append(f"<a class='btn secondary' href='/edls/{e(c)}/objects'>Firewall objects"
                    + (f" <b>{len(objs)}</b>" if objs else "") + "</a>")
        body += (f"<div class='card'><div class='pagehead' style='margin-bottom:8px'><div><h3 style='margin:0'>{e(prof.display_name or c)}</h3>"
                 f"<p>Customer <code>{e(c)}</code></p></div><div class='actions'>{''.join(acts)}</div></div>")
        if not lists:
            body += theme.empty_state("No lists yet", "An EDL admin creates a list (IP, FQDN or URL), then editors add entries.",
                                      "", "list") + "</div>"
            continue
        any_list = True
        rows = "".join(
            f"<tr><td><a href='/edls/{e(c)}/{e(m['id'])}'><b>{e(m['name'])}</b></a><br><span class='muted'>{e(m['id'])}</span></td>"
            f"<td>{_kind(m)}</td><td>{m['count']:,}" + (f" <span class='muted'>(+{m['expired']} expired)</span>" if m['expired'] else "") +
            f"</td><td>v{m['version']}</td><td>{theme.badge('two-person', 'warning') if m.get('require_approval') else theme.badge('direct', 'neutral')}</td>"
            f"<td>{theme.badge(str(m['pending']) + ' waiting', 'warning') if m['pending'] else '-'}</td><td>{_pub_summary(m)}</td></tr>"
            for m in lists)
        body += ("<div class='tablewrap'><table><tr><th>List</th><th>Type</th><th>Entries</th><th>Version</th><th>Approval</th>"
                 f"<th>Waiting</th><th>Publishing</th></tr>{rows}</table></div>")
        cap = edl.capacity(prof)
        for wmsg in cap["warnings"]:
            body += f"<div class='note' style='border-left-color:#b00020'>{e(wmsg)}</div>"
        body += "</div>"
    if not shown:
        body += theme.empty_state("No customers in your scope", "Ask a user admin to add your customer to your account.", "", "lock")
    del any_list
    return w.page("External dynamic lists", body, user)


# ---------------------------------------------------------------- new list

@router.get("/edls/{customer}/new", response_class=HTMLResponse)
def new_form(request: Request, customer: str, msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, "edl_admin", customer)
    _prof(customer)
    body = ("<div class='pagehead'><div><h2>New external dynamic list</h2><p>One list holds one type of entry. Most teams "
            "keep one IP list and one FQDN list per purpose (for example \"SOC block IPs\").</p></div></div>"
            + (f"<div class='note'>{e(msg)}</div>" if msg else "") + _help() +
            f"<form method='post' action='/edls/{e(customer)}/new' class='card'>"
            "<label>Name (what people see)</label><input name='name' required maxlength='80' size='40' placeholder='SOC block IPs'>"
            "<label>List id (in URLs and file names: lowercase letters, digits, -)</label>"
            "<input name='lid' required pattern='[a-z0-9][a-z0-9-]{0,39}' size='30' placeholder='soc-block-ips'>"
            "<label>Type</label><select name='kind'><option value='ip'>IP addresses, subnets and ranges</option>"
            "<option value='domain'>Domains (FQDN), for DNS Security / anti-spyware</option><option value='url'>URLs, for URL filtering</option></select>"
            "<label>Description (purpose, who owns it)</label><textarea name='description' rows='2' cols='60' maxlength='500'></textarea>"
            "<label style='font-weight:400'><input type='checkbox' name='require_approval' value='yes'> "
            "<b>Two-person approval</b>: every change waits until someone with EDL approve (for example an ISSO) approves it</label>"
            "<label style='font-weight:400'><input type='checkbox' name='hosted' value='yes' checked> "
            "<b>Host it on PAAT</b>: firewalls fetch it from this server (you can add S3 afterwards)</label>"
            "<br><button>Create list</button></form>")
    return w.page("New list", body, user)


@router.post("/edls/{customer}/new")
def new_post(request: Request, customer: str, name: str = Form(...), lid: str = Form(...), kind: str = Form(...),
             description: str = Form(""), require_approval: str = Form(""), hosted: str = Form("")):
    w = _web()
    user = w.need(request, "edl_admin", customer)
    prof = _prof(customer)
    try:
        edl.create_list(prof, lid=lid.strip(), name=name, kind=kind, description=description, actor=user.name,
                        require_approval=require_approval == "yes", hosted=hosted == "yes")
    except edl.EdlError as exc:
        return RedirectResponse(f"/edls/{quote(customer)}/new?msg={quote(str(exc))}", status_code=303)
    return _back(customer, lid.strip(), msg="List created. Add entries, then point a firewall object at it.")


# ---------------------------------------------------------------- one list

def _entry_rows(meta: dict, ents: list[dict], can_edit: bool) -> str:
    live = {id(x) for x in edl.live_entries(ents)}
    rows = []
    for x in ents:
        exp = x.get("expires_at") or ""
        state = theme.badge("expired", "neutral") if id(x) not in live else (theme.badge("expires " + _ts(exp)[:10], "info") if exp else "")
        box = (f"<td><input type='checkbox' name='value' value='{e(x['value'])}' form='rmform' aria-label='select {e(x['value'])}'></td>"
               if can_edit else "")
        rows.append(f"<tr>{box}<td><code>{e(x['value'])}</code> {state}</td><td>{e(x.get('comment', ''))}</td><td>{e(x.get('ticket', ''))}</td>"
                    f"<td>{e(x.get('added_by', ''))}</td><td>{_ts(x.get('added_at', ''))}</td></tr>")
    return "".join(rows)


def _publish_card(request: Request, prof, meta: dict, user) -> str:
    c, lid = prof.name, meta["id"]
    pub = meta.get("publish") or {}
    out = ["<div class='card'><h3>Where firewalls get this list</h3>"]
    h = meta.get("hosted") or {}
    if h.get("enabled"):
        url = edl.hosted_url(prof, meta, _base(request))
        prot = []
        if h.get("basic_auth_user"):
            prot.append("basic auth")
        if h.get("allow_ips"):
            prot.append(f"{len(h['allow_ips'])} allowed source range(s)")
        out.append(f"<p><b>PAAT-hosted</b> {theme.badge('live', 'success')} · protection: {e(', '.join(prot) or 'unguessable URL only')}</p>"
                   f"<p><code id='edl-url'>{e(url)}</code> {_web()._copy_btn('edl-url')}</p>")
        f = edl.fetches(prof, lid)
        if f:
            out.append("<p class='muted'>Last fetches: " + "; ".join(
                f"{_ts(x['ts'])} from {e(x['ip'])} ({x['status']})" for x in f[:5]) + "</p>")
        else:
            out.append("<p class='muted'>No firewall has fetched it yet.</p>")
    s3 = meta.get("s3") or {}
    if s3.get("enabled"):
        last = pub.get("s3") or {}
        st = last.get("state", "not published")
        out.append(f"<p><b>S3</b> <code>{e(edl.s3_describe(meta))}</code> {theme.badge(st, PUB_TONE.get(st, 'warning'))}</p>")
        if last:
            out.append(f"<p class='muted'>Last publish {_ts(last.get('ts', ''))} by {e(last.get('actor', ''))}: version "
                       f"{last.get('version')}, {last.get('lines')} lines, SHA-256 <code>{e(str(last.get('sha256', ''))[:16])}</code>. "
                       f"{e(str(last.get('detail', '')))}</p>")
        out.append(f"<p class='muted'>Firewall URL: <code>{e(edl.s3_url(meta))}</code></p>")
        btns = f"<form method='post' action='/edls/{e(c)}/{e(lid)}/s3/check' class='inline'><button class='secondary'>Check S3 now</button></form>"
        if user.can("edl_edit") or user.can("edl_admin"):
            btns += f" <form method='post' action='/edls/{e(c)}/{e(lid)}/publish' class='inline'><button class='secondary'>Publish again</button></form>"
        out.append(f"<p>{btns}</p>")
    if not h.get("enabled") and not s3.get("enabled"):
        out.append("<p>Not published anywhere yet." + (f" <a href='/edls/{e(c)}/{e(lid)}/settings'>Set up publishing</a>." if user.can("edl_admin") else "") + "</p>")
    fw = meta.get("firewall") or {}
    if fw.get("object_name"):
        out.append(f"<p>Firewall object <code>{e(fw['object_name'])}</code> in {e(fw.get('device_group', ''))}, refresh {e(fw.get('recurring', ''))}.</p>")
    out.append(f"<p><a class='btn secondary' href='/edls/{e(c)}/{e(lid)}/firewall'>Which firewalls use it (live)</a>"
               + (f" <a class='btn secondary' href='/edls/{e(c)}/{e(lid)}/object'>Make the firewall object</a>" if user.can("edl_admin") else "")
               + "</p></div>")
    return "".join(out)


@router.get("/edls/{customer}/{lid}", response_class=HTMLResponse)
def detail(request: Request, customer: str, lid: str, msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, ANY, customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    ents = edl.load_entries(prof, lid)
    live = edl.live_entries(ents)
    changes = edl.list_changes(prof, lid)
    pend = [x for x in changes if x["status"] == "pending"]
    can_edit = user.can("edl_edit")
    acts = [f"<a class='btn secondary' href='/edls/{e(customer)}/{e(lid)}/history'>History</a>",
            f"<a class='btn secondary' href='/edls/{e(customer)}/{e(lid)}/export.txt'>Download .txt</a>",
            f"<a class='btn secondary' href='/edls/{e(customer)}/{e(lid)}/export.csv'>Download .csv</a>",
            f"<a class='btn secondary' href='/edls/{e(customer)}/{e(lid)}/audit'>Audit log</a>"]
    if can_edit:
        acts.insert(0, f"<a class='btn' href='/edls/{e(customer)}/{e(lid)}/import'>Bulk import</a>")
    if user.can("edl_admin"):
        acts.append(f"<a class='btn secondary' href='/edls/{e(customer)}/{e(lid)}/settings'>List settings</a>")
    body = (f"<div class='pagehead'><div><h2>{e(meta['name'])} {_kind(meta)}</h2><p>{e(meta.get('description') or 'No description.')}</p></div>"
            f"<div class='actions'>{''.join(acts)}</div></div>" + (f"<div class='note'>{e(msg)}</div>" if msg else "") + _help())
    body += ("<div class='stats'>" + theme.kpi("Live entries", f"{len(live):,}", ic="list")
             + theme.kpi("Version", meta["version"], f"/edls/{customer}/{lid}/history", ic="clock")
             + theme.kpi("Waiting for approval", len(pend), "", "warning" if pend else "neutral", ic="check")
             + theme.kpi("Expired (left out)", len(ents) - len(live), "", "neutral", ic="alert") + "</div>")
    if meta.get("require_approval"):
        body += ("<div class='note'><b>Two-person approval is on.</b> Every change waits until someone with EDL approve "
                 "(for example an ISSO) approves it. Risky entries always wait, on every list.</div>")
    if pend:
        rows = "".join(f"<tr><td><a href='/edls/{e(customer)}/{e(lid)}/changes/{e(x['id'])}'>{e(x['id'])}</a></td><td>{e(x['requester'])}</td>"
                       f"<td>{_ts(x['created'])}</td><td>+{len(x['adds'])} / -{len(x['removes'])}</td><td>{e(x['reason'])}</td>"
                       f"<td>{e('; '.join(x.get('approval_reasons', []))[:200])}</td></tr>" for x in pend)
        body += ("<div class='card'><h3>Waiting for a second person</h3><table><tr><th>Change</th><th>Requested by</th><th>When (CST)</th>"
                 f"<th>Adds / removes</th><th>Reason</th><th>Why it waits</th></tr>{rows}</table></div>")
    if can_edit:
        body += (f"<form method='post' action='/edls/{e(customer)}/{e(lid)}/add' class='card'><h3>Add entries</h3>"
                 f"<p class='muted'>{e(_example(meta['type']))} One per line; text after a space is kept as a comment.</p>"
                 "<label>Entries</label><textarea name='entries' rows='3' cols='70' required></textarea>"
                 "<div class='grow' style='display:flex;gap:12px;flex-wrap:wrap'>"
                 "<span><label>Reason (required, kept in history)</label><input name='reason' required size='40' placeholder='SOC case: phishing campaign'></span>"
                 "<span><label>Ticket (optional)</label><input name='ticket' size='18' placeholder='INC0012345'></span>"
                 "<span><label>Expires (optional: 2026-12-31, 12h, 30d)</label><input name='expires' size='18'></span></div>"
                 "<button>Add</button></form>")
    cap = edl.capacity(prof)
    for wmsg in cap["warnings"]:
        body += f"<div class='note' style='border-left-color:#b00020'>{e(wmsg)}</div>"
    head_box = "<th><span class='visually-hidden'>Select</span></th>" if can_edit else ""
    if ents:
        body += ("<div class='card'><h3>Entries</h3><div class='tablewrap'><table><tr>" + head_box +
                 "<th>Entry</th><th>Comment</th><th>Ticket</th><th>Added by</th><th>Added (CST)</th></tr>"
                 + _entry_rows(meta, ents, can_edit) + "</table></div>")
        if can_edit:
            body += (f"<form method='post' action='/edls/{e(customer)}/{e(lid)}/remove' id='rmform' class='inline'>"
                     "<label>Reason for removing the selected entries</label><input name='reason' required size='40'> "
                     "<button class='danger'>Remove selected</button></form>")
        body += "</div>"
    else:
        body += theme.empty_state("This list is empty", "Firewalls get one harmless placeholder line (" + edl.PLACEHOLDER[meta["type"]]
                                  + ") so the object stays valid.", "", "list")
    body += _publish_card(request, prof, meta, user)
    return w.page(meta["name"], body, user)


def _example(kind: str) -> str:
    return {"ip": "Examples: 203.0.113.7, 198.51.100.0/24, 192.0.2.10-192.0.2.20, 2001:db8::/48.",
            "domain": "Examples: bad.example.net, *.bad.example.net (every subdomain), ^exact.example.net (exactly that name).",
            "url": "Examples: bad.example.net/login, *.bad.example.net/, bad.example.net/path/* (no http://)."}[kind]


def _plan_html(meta: dict, p: edl.Plan) -> str:
    s = p.summary()
    out = ["<div class='stats'>", theme.kpi("Adds", s["adds"], tone="success", ic="check"), theme.kpi("Removes", s["removes"], tone="danger", ic="trash"),
           theme.kpi("Already in the list", s["unchanged"], ic="list"), theme.kpi("Invalid lines", s["invalid"], tone="warning" if s["invalid"] else "neutral", ic="alert"),
           theme.kpi("Refused (unsafe)", s["blocked"], tone="danger" if s["blocked"] else "neutral", ic="lock"),
           theme.kpi("Needs a second person", s["approval"], tone="warning" if s["approval"] else "neutral", ic="users"), "</div>"]
    if p.blocked:
        out.append("<div class='card' style='border-left:4px solid #b00020'><h3>Refused: these will not be added</h3><ul>" + "".join(
            f"<li><code>{e(c.value or c.raw)}</code>: {e('; '.join(c.why))}</li>" for c in p.blocked[:200]) + "</ul></div>")
    if p.needs_approval:
        out.append("<div class='card' style='border-left:4px solid #9a6700'><h3>Needs a second person (EDL approve)</h3><ul>" + "".join(
            f"<li><code>{e(c.value or '')}</code>: {e('; '.join(c.why))}</li>" for c in p.needs_approval[:200]) + "</ul></div>")
    if p.invalid:
        out.append("<div class='card'><h3>Invalid lines (skipped)</h3><table><tr><th>Line</th><th>Problem</th></tr>" + "".join(
            f"<tr><td><code>{e(c.raw)}</code></td><td>{e(c.error or '')}</td></tr>" for c in p.invalid[:500]) + "</table></div>")
    if p.adds:
        out.append("<div class='card'><h3>Will be added</h3><table><tr><th>Entry</th><th>Comment</th><th>Expires</th></tr>" + "".join(
            f"<tr><td><code>{e(a['value'])}</code></td><td>{e(a.get('comment', ''))}</td><td>{_ts(a.get('expires_at', ''))}</td></tr>"
            for a in p.adds[:1000]) + "</table>" + (f"<p class='muted'>and {len(p.adds) - 1000:,} more</p>" if len(p.adds) > 1000 else "") + "</div>")
    if p.removes:
        out.append("<div class='card'><h3>Will be removed</h3><p>" + ", ".join(f"<code>{e(v)}</code>" for v in p.removes[:1000]) + "</p></div>")
    if p.notes:
        out.append("<div class='card'><h3>Cleaned up for you</h3><ul>" + "".join(f"<li>{e(n)}</li>" for n in p.notes[:200]) + "</ul></div>")
    if p.covered:
        out.append("<div class='card'><h3>Already covered by a broader entry (kept anyway)</h3><ul>" + "".join(
            f"<li><code>{e(a)}</code> is inside <code>{e(b)}</code></li>" for a, b in p.covered[:200]) + "</ul></div>")
    if p.duplicates:
        out.append(f"<p class='muted'>{len(p.duplicates)} duplicate line(s) were counted once.</p>")
    return "".join(out)


def _preview_page(w, user, prof, meta: dict, p: edl.Plan, *, reason: str, ticket: str, source: str, title: str) -> HTMLResponse:
    did = edl.save_draft(prof, meta["id"], p, reason=reason, ticket=ticket, source=source)
    c, lid = prof.name, meta["id"]
    waits = bool(meta.get("require_approval") or p.needs_approval)
    can_go = bool(p.adds or p.removes)
    btn = ("Stage for approval" if waits else "Apply now") if can_go else ""
    body = (f"<div class='pagehead'><div><h2>{e(title)}: {e(meta['name'])}</h2><p>Check the preview. Nothing changes until you confirm.</p></div></div>"
            + _plan_html(meta, p))
    if can_go:
        body += (f"<form method='post' action='/edls/{e(c)}/{e(lid)}/confirm' class='card'><input type='hidden' name='draft' value='{e(did)}'>"
                 f"<label>Reason (kept in history)</label><input name='reason' required size='50' value='{e(reason)}'>"
                 f"<label>Ticket (optional)</label><input name='ticket' size='20' value='{e(ticket)}'><br>"
                 + ("<p class='muted'>This will wait for someone with EDL approve before firewalls see it.</p>" if waits else
                    "<p class='muted'>Firewalls see it on their next refresh.</p>") +
                 f"<button>{btn}</button> <a class='btn secondary' href='/edls/{e(c)}/{e(lid)}'>Cancel</a></form>")
    else:
        body += f"<p>Nothing to change. <a class='btn secondary' href='/edls/{e(c)}/{e(lid)}'>Back to the list</a></p>"
    return w.page(title, body, user)


def _done_msg(res: dict) -> str:
    if res["status"] == "pending":
        return "Staged for approval: a second person with EDL approve must approve it before firewalls see it."
    pub = res.get("publish") or {}
    bits = [f"version {res['version']} saved"]
    if "hosted" in pub:
        bits.append("PAAT-hosted list is live")
    if "s3" in pub:
        bits.append("S3: " + pub["s3"].get("state", "") + ("" if pub["s3"].get("ok") else " (" + str(pub["s3"].get("detail", ""))[:120] + ")"))
    return "Done: " + ", ".join(bits) + ". Firewalls pick it up on their next refresh."


@router.post("/edls/{customer}/{lid}/add")
def add(request: Request, customer: str, lid: str, entries: str = Form(...), reason: str = Form(...), ticket: str = Form(""),
        expires: str = Form("")):
    w = _web()
    user = w.need(request, "edl_edit", customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    try:
        exp = edl.parse_expiry(expires)
        p = edl.plan_changes(prof, meta, edl.load_entries(prof, lid), add_lines=_textarea_lines(entries), actor=user.name,
                             expires_at=exp, ticket=ticket.strip())
        if p.invalid or p.blocked or p.covered or not p.adds:
            return _preview_page(w, user, prof, meta, p, reason=reason, ticket=ticket, source="edit", title="Check these entries")
        res = edl.submit(prof, lid, p, actor=user.name, reason=reason, ticket=ticket.strip())
    except edl.EdlError as exc:
        return _back(customer, lid, msg=f"Could not add: {exc}")
    return _back(customer, lid, msg=_done_msg(res))


@router.post("/edls/{customer}/{lid}/remove")
async def remove(request: Request, customer: str, lid: str):
    w = _web()
    user = w.need(request, "edl_edit", customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    form = await request.form()
    vals = [str(v) for v in form.getlist("value")]
    reason = str(form.get("reason") or "")
    try:
        p = edl.plan_changes(prof, meta, edl.load_entries(prof, lid), remove_values=vals, actor=user.name)
        res = edl.submit(prof, lid, p, actor=user.name, reason=reason)
    except edl.EdlError as exc:
        return _back(customer, lid, msg=f"Could not remove: {exc}")
    return _back(customer, lid, msg=_done_msg(res))


@router.get("/edls/{customer}/{lid}/import", response_class=HTMLResponse)
def import_form(request: Request, customer: str, lid: str) -> HTMLResponse:
    w = _web()
    user = w.need(request, "edl_edit", customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    body = (f"<div class='pagehead'><div><h2>Bulk import: {e(meta['name'])}</h2><p>Paste a list or upload a .txt or .csv file. "
            "You get a preview of every add, remove and invalid line before anything changes.</p></div></div>" + _help() +
            f"<form method='post' action='/edls/{e(customer)}/{e(lid)}/import' enctype='multipart/form-data' class='card'>"
            f"<label>Paste entries (one per line)</label><textarea name='text' rows='10' cols='80'></textarea>"
            "<label>or upload a file (.txt one per line, or .csv with columns value, comment, expires_at, ticket)</label>"
            "<input type='file' name='file' accept='.txt,.csv,text/plain,text/csv'>"
            "<label>Mode</label><select name='mode'><option value='merge'>Add these to the list (keep everything already there)</option>"
            "<option value='replace'>Replace the list with exactly this (entries not in the file are removed)</option></select>"
            "<label>Reason (kept in history)</label><input name='reason' size='50' required>"
            "<label>Ticket (optional)</label><input name='ticket' size='20'>"
            "<label>Expires (optional, applies to rows without their own)</label><input name='expires' size='18'>"
            "<br><button>Preview</button></form>")
    return w.page("Bulk import", body, user)


@router.post("/edls/{customer}/{lid}/import", response_class=HTMLResponse)
async def import_post(request: Request, customer: str, lid: str, text: str = Form(""), mode: str = Form("merge"),
                      reason: str = Form(...), ticket: str = Form(""), expires: str = Form(""), file: UploadFile | None = File(None)):
    w = _web()
    user = w.need(request, "edl_edit", customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    raw, fname = text or "", ""
    if file is not None and file.filename:
        data = await file.read(25 * 1024 * 1024 + 1)
        if len(data) > 25 * 1024 * 1024:
            return _back(customer, lid, "import", msg="File is larger than 25 MB")
        raw, fname = data.decode("utf-8-sig", "replace"), file.filename
    try:
        lines, rows = edl.parse_import(raw, fname)
        p = edl.plan_changes(prof, meta, edl.load_entries(prof, lid), add_lines=lines, rows=rows, replace=(mode == "replace"),
                             actor=user.name, expires_at=edl.parse_expiry(expires), ticket=ticket.strip())
    except edl.EdlError as exc:
        return _back(customer, lid, "import", msg=f"Could not read the import: {exc}")
    return _preview_page(w, user, prof, meta, p, reason=reason, ticket=ticket, source=f"import ({mode})", title="Import preview")


@router.post("/edls/{customer}/{lid}/confirm")
def confirm(request: Request, customer: str, lid: str, draft: str = Form(...), reason: str = Form(...), ticket: str = Form("")):
    w = _web()
    user = w.need(request, "edl_edit", customer)
    prof = _prof(customer)
    _meta(prof, lid)
    try:
        d = edl.load_draft(prof, lid, draft)
        res = edl.submit(prof, lid, edl.plan_from_dict(d["plan"]), actor=user.name, reason=reason, ticket=ticket.strip(),
                         source=d.get("source", "edit"))
        edl.drop_draft(prof, lid, draft)
    except edl.EdlError as exc:
        return _back(customer, lid, msg=f"Not applied: {exc}")
    return _back(customer, lid, msg=_done_msg(res))


@router.get("/edls/{customer}/{lid}/export.txt")
def export_txt(request: Request, customer: str, lid: str) -> PlainTextResponse:
    w = _web()
    w.need(request, ANY, customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    return PlainTextResponse(edl.render_text(meta, edl.load_entries(prof, lid)),
                             headers={"Content-Disposition": f"attachment; filename={lid}.txt"})


@router.get("/edls/{customer}/{lid}/export.csv")
def export_csv(request: Request, customer: str, lid: str) -> Response:
    w = _web()
    w.need(request, ANY, customer)
    prof = _prof(customer)
    _meta(prof, lid)
    return Response(edl.export_csv(edl.load_entries(prof, lid)), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={lid}.csv"})


# ---------------------------------------------------------------- the hosted feed (no session)

@router.get("/edl/{token}.txt")
def feed(request: Request, token: str):
    import base64

    hit = edl.find_by_token(token)
    if hit is None:
        return PlainTextResponse("not found\n", status_code=404)
    prof, meta = hit
    h = meta.get("hosted") or {}
    ip = request.client.host if request.client else ""
    agent = request.headers.get("user-agent", "")
    if not h.get("enabled"):
        return PlainTextResponse("not found\n", status_code=404)
    if not edl.ip_allowed(ip, h.get("allow_ips") or []):
        edl.record_fetch(prof, meta["id"], ip, agent, 403)
        return PlainTextResponse("forbidden\n", status_code=403)
    if h.get("basic_auth_user"):
        ok = False
        hdr = request.headers.get("authorization", "")
        if hdr.lower().startswith("basic "):
            try:
                u, _, pw = base64.b64decode(hdr[6:]).decode("utf-8", "replace").partition(":")
                ok = u == h["basic_auth_user"] and edl.check_secret(pw, h.get("basic_auth_hash", ""))
            except Exception:  # noqa: BLE001
                ok = False
        if not ok:
            edl.record_fetch(prof, meta["id"], ip, agent, 401)
            return PlainTextResponse("authentication required\n", status_code=401, headers={"WWW-Authenticate": 'Basic realm="PAAT EDL"'})
    text = edl.render_text(meta, edl.load_entries(prof, meta["id"]))
    etag = '"' + edl.sha256(text.encode())[:32] + '"'
    edl.record_fetch(prof, meta["id"], ip, agent, 200)
    headers = {"ETag": etag, "Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff", "X-PAAT-List-Version": str(meta["version"])}
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    return Response(text, media_type="text/plain; charset=utf-8", headers=headers)


# ---------------------------------------------------------------- history, revert, audit

@router.get("/edls/{customer}/{lid}/history", response_class=HTMLResponse)
def history(request: Request, customer: str, lid: str) -> HTMLResponse:
    w = _web()
    user = w.need(request, ANY, customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    rows = []
    for v in edl.versions(prof, lid):
        diff = (" ".join(f"<code style='color:#1a7f37'>+{e(x)}</code>" for x in v.get("added", [])[:20])
                + " " + " ".join(f"<code style='color:#b00020'>-{e(x)}</code>" for x in v.get("removed", [])[:20]))
        more = len(v.get("added", [])) + len(v.get("removed", [])) - 40
        rev = ""
        if user.can("edl_edit") and v["version"] != meta["version"]:
            rev = (f"<form method='post' action='/edls/{e(customer)}/{e(lid)}/revert/{v['version']}' class='inline'>"
                   f"<button class='secondary sm'>Revert to v{v['version']}</button></form>")
        rows.append(f"<tr><td><b>v{v['version']}</b></td><td>{_ts(v['ts'])}</td><td>{e(v['actor'])}</td><td>{e(v.get('approved_by') or '-')}</td>"
                    f"<td>{e(v.get('reason', ''))}{(' · ' + e(v['ticket'])) if v.get('ticket') else ''}</td><td>{diff}"
                    f"{f' <span class=muted>+{more} more</span>' if more > 0 else ''}</td><td>{v['count']}</td><td>{rev}</td></tr>")
    body = (f"<div class='pagehead'><div><h2>History: {e(meta['name'])}</h2><p>Every version is kept. Revert makes a new version "
            "equal to an old one (it goes through approval like any other change).</p></div>"
            f"<div class='actions'><a class='btn secondary' href='/edls/{e(customer)}/{e(lid)}'>Back to the list</a></div></div>"
            "<div class='tablewrap'><table><tr><th>Version</th><th>When (CST)</th><th>By</th><th>Approved by</th><th>Why</th>"
            f"<th>Changes</th><th>Entries</th><th></th></tr>{''.join(rows)}</table></div>")
    return w.page("History", body, user)


@router.post("/edls/{customer}/{lid}/revert/{n}", response_class=HTMLResponse)
def revert(request: Request, customer: str, lid: str, n: int):
    w = _web()
    user = w.need(request, "edl_edit", customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    try:
        p = edl.revert_plan(prof, lid, n, actor=user.name)
    except edl.EdlError as exc:
        return _back(customer, lid, "history", msg=str(exc))
    return _preview_page(w, user, prof, meta, p, reason=f"revert to version {n}", ticket="", source=f"revert to v{n}",
                         title=f"Revert to version {n}")


@router.get("/edls/{customer}/{lid}/audit", response_class=HTMLResponse)
def audit_page(request: Request, customer: str, lid: str) -> HTMLResponse:
    w = _web()
    user = w.need(request, ANY, customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    skip = {"ts", "customer", "list", "actor", "action", "result"}
    rows = "".join(f"<tr><td>{_ts(r['ts'])}</td><td>{e(r['actor'])}</td><td>{e(r['action'])}</td><td>{e(str(r['result']))}</td>"
                   f"<td>{e('; '.join(f'{k}={v}' for k, v in r.items() if k not in skip))[:400]}</td></tr>"
                   for r in reversed(edl.read_audit(prof, lid)))
    body = (f"<div class='pagehead'><div><h2>Audit log: {e(meta['name'])}</h2><p>Every action on this list, newest first. "
            "Also written to the customer's main audit log.</p></div></div>"
            f"<table><tr><th>When (CST)</th><th>Who</th><th>Action</th><th>Result</th><th>Detail</th></tr>{rows}</table>")
    return w.page("Audit log", body, user)


# ---------------------------------------------------------------- staged changes

@router.get("/edls/{customer}/{lid}/changes/{cid}", response_class=HTMLResponse)
def change_page(request: Request, customer: str, lid: str, cid: str, msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, ANY, customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    try:
        ch = edl.load_change(prof, lid, cid)
    except edl.EdlError:
        raise HTTPException(404, "no such change")
    st = edl.load_settings(prof)
    adds = "".join(f"<tr><td><code>{e(a['value'])}</code></td><td>{e(a.get('comment', ''))}</td><td>{_ts(a.get('expires_at', ''))}</td>"
                   f"<td>{e('; '.join(edl.classify(meta['type'], a['value'], st)[1]) or '-')}</td></tr>" for a in ch["adds"])
    body = (f"<div class='pagehead'><div><h2>Change {e(cid)} {theme.badge(ch['status'], STATUS_TONE.get(ch['status'], 'neutral'))}</h2>"
            f"<p>{e(meta['name'])} · requested by <b>{e(ch['requester'])}</b> at {_ts(ch['created'])} · reason: {e(ch['reason'])}"
            f"{(' · ticket ' + e(ch['ticket'])) if ch.get('ticket') else ''}</p></div></div>" + (f"<div class='note'>{e(msg)}</div>" if msg else ""))
    if ch.get("approval_reasons"):
        body += "<div class='note'><b>Why it needs a second person:</b><ul>" + "".join(f"<li>{e(x)}</li>" for x in ch["approval_reasons"]) + "</ul></div>"
    if adds:
        body += f"<div class='card'><h3>Adds ({len(ch['adds'])})</h3><table><tr><th>Entry</th><th>Comment</th><th>Expires</th><th>Safety notes</th></tr>{adds}</table></div>"
    if ch["removes"]:
        body += "<div class='card'><h3>Removes (" + str(len(ch["removes"])) + ")</h3><p>" + ", ".join(f"<code>{e(v)}</code>" for v in ch["removes"]) + "</p></div>"
    if ch["status"] == "pending":
        if user.can("edl_approve") and user.name != ch["requester"]:
            body += (f"<form method='post' action='/edls/{e(customer)}/{e(lid)}/changes/{e(cid)}/approve' class='card'><h3>Review</h3>"
                     "<label>Comment (optional for approve, required for reject)</label><input name='comment' size='60'><br>"
                     "<button name='action' value='approve'>Approve and publish</button> "
                     "<button name='action' value='reject' class='danger'>Reject</button></form>")
        elif user.name == ch["requester"]:
            body += (f"<form method='post' action='/edls/{e(customer)}/{e(lid)}/changes/{e(cid)}/approve' class='card'>"
                     "<p>You made this change, so someone else must approve it. You can withdraw it.</p>"
                     "<label>Why withdraw</label><input name='comment' size='50' required> <button name='action' value='reject' class='secondary'>Withdraw</button></form>")
        else:
            body += "<p class='muted'>Waiting for someone with EDL approve.</p>"
    else:
        body += (f"<p>Reviewed by <b>{e(ch.get('reviewer', ''))}</b> at {_ts(ch.get('reviewed_at', ''))}: {e(ch.get('review_comment') or 'no comment')}"
                 + (f" · became version {ch['version']}" if ch.get("version") else "") + "</p>")
    body += f"<p><a class='btn secondary' href='/edls/{e(customer)}/{e(lid)}'>Back to the list</a></p>"
    return w.page(f"Change {cid}", body, user)


@router.post("/edls/{customer}/{lid}/changes/{cid}/approve")
def change_review(request: Request, customer: str, lid: str, cid: str, action: str = Form(...), comment: str = Form("")):
    w = _web()
    prof = _prof(customer)
    _meta(prof, lid)
    try:
        ch = edl.load_change(prof, lid, cid)
    except edl.EdlError:
        raise HTTPException(404, "no such change")
    user = w.need(request, ANY, customer)
    try:
        if action == "approve":
            w.need(request, "edl_approve", customer)
            res = edl.approve_change(prof, lid, cid, actor=user.name, comment=comment)
            m = _done_msg({"status": "applied", "version": res["version"], "publish": res.get("publish")})
        else:
            if user.name != ch["requester"]:
                w.need(request, "edl_approve", customer)
            edl.reject_change(prof, lid, cid, actor=user.name, comment=comment)
            m = "Withdrawn." if user.name == ch["requester"] else "Rejected. The requester sees your comment."
    except edl.EdlError as exc:
        m = f"Not done: {exc}"
    return RedirectResponse(f"/edls/{quote(customer)}/{quote(lid)}/changes/{quote(cid)}?msg={quote(m)}", status_code=303)


# ---------------------------------------------------------------- list settings (admin)

def _chk(name: str, on: bool, label: str) -> str:
    return f"<label style='font-weight:400'><input type='checkbox' name='{name}' value='yes' {'checked' if on else ''}> {label}</label>"


@router.get("/edls/{customer}/{lid}/settings", response_class=HTMLResponse)
def list_settings(request: Request, customer: str, lid: str, msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, "edl_admin", customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    h, s3 = meta.get("hosted") or {}, meta.get("s3") or {}
    body = (f"<div class='pagehead'><div><h2>List settings: {e(meta['name'])}</h2><p>Approval, where the list is published, and who may "
            "fetch it.</p></div></div>" + (f"<div class='note'>{e(msg)}</div>" if msg else "") +
            f"<form method='post' action='/edls/{e(customer)}/{e(lid)}/settings' class='card'><h3>General</h3>"
            f"<label>Name</label><input name='name' value='{e(meta['name'])}' size='40' maxlength='80'>"
            f"<label>Description</label><textarea name='description' rows='2' cols='60'>{e(meta.get('description', ''))}</textarea>"
            + _chk("require_approval", meta.get("require_approval", False), "<b>Two-person approval</b> for every change")
            + _chk("placeholder", meta.get("placeholder_when_empty", True), f"When empty, serve the placeholder <code>{e(edl.PLACEHOLDER[meta['type']])}</code> (recommended: PAN-OS expects entries)")
            + "<h3>PAAT-hosted</h3>"
            + _chk("hosted", h.get("enabled", False), "Serve this list from PAAT at its own URL")
            + "<label>Basic auth user (optional; PAN-OS sends it only to an https:// source with a certificate profile)</label>"
            f"<input name='basic_user' value='{e(h.get('basic_auth_user', ''))}' size='24' autocomplete='off'>"
            "<label>Basic auth password (" + ("set; leave blank to keep" if h.get("basic_auth_hash") else "not set") + ")</label>"
            "<input name='basic_password' type='password' size='24' autocomplete='new-password' minlength='12'>"
            "<label>Allowed source IPs (optional; one subnet per line; blank = any)</label>"
            f"<textarea name='allow_ips' rows='3' cols='40'>{e(chr(10).join(h.get('allow_ips') or []))}</textarea>"
            + _chk("new_token", False, "Issue a new URL (the old URL stops working: update every firewall object first)")
            + "<h3>S3 or S3-compatible (MinIO)</h3>"
            + _chk("s3_enabled", s3.get("enabled", False), "Publish to S3 after every change")
            + f"<label>Bucket</label><input name='s3_bucket' value='{e(s3.get('bucket', ''))}' size='30'>"
            f"<label>Object key (path in the bucket)</label><input name='s3_key' value='{e(s3.get('key', ''))}' size='40' placeholder='edl/{e(lid)}.txt'>"
            f"<label>Region (AWS)</label><input name='s3_region' value='{e(s3.get('region', ''))}' size='16' placeholder='us-east-1'>"
            f"<label>Endpoint URL (blank for AWS; for MinIO for example https://minio.example.net:9000)</label>"
            f"<input name='s3_endpoint' value='{e(s3.get('endpoint_url', ''))}' size='40'>"
            + _chk("s3_path_style", s3.get("path_style", False), "Path-style addressing (MinIO)")
            + _chk("s3_verify", s3.get("verify", True), "Verify every publish (GET and SHA-256)")
            + f"<p class='muted'>Credentials: {e(edl.s3_creds_status(prof, lid))}. They never go in this form. On the server, put "
            f"<code>{e(edl.env_name(lid, 'access_key'))}</code> and <code>{e(edl.env_name(lid, 'secret_key'))}</code> (or the customer-wide "
            f"<code>PANLAB_EDL_S3_ACCESS_KEY</code> / <code>PANLAB_EDL_S3_SECRET_KEY</code>) in <code>/etc/panlab/edl/{e(customer)}.env</code>, mode 600.</p>"
            "<br><button>Save settings</button></form>"
            f"<form method='post' action='/edls/{e(customer)}/{e(lid)}/delete' class='card' style='border-left:4px solid #b00020'>"
            "<h3>Delete this list</h3><p>The list stops being served and published. Its files are kept on the server for the record. "
            "Remove it from every firewall rule and object first.</p><label>Type the list id to confirm</label>"
            "<input name='confirm' size='30' required> <button class='danger'>Delete list</button></form>")
    return w.page("List settings", body, user)


@router.post("/edls/{customer}/{lid}/settings")
def list_settings_post(request: Request, customer: str, lid: str, name: str = Form(""), description: str = Form(""),
                       require_approval: str = Form(""), placeholder: str = Form(""), hosted: str = Form(""), basic_user: str = Form(""),
                       basic_password: str = Form(""), allow_ips: str = Form(""), new_token: str = Form(""), s3_enabled: str = Form(""),
                       s3_bucket: str = Form(""), s3_key: str = Form(""), s3_region: str = Form(""), s3_endpoint: str = Form(""),
                       s3_path_style: str = Form(""), s3_verify: str = Form("")):
    import secrets as _s

    w = _web()
    user = w.need(request, "edl_admin", customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    try:
        allow = _textarea_lines(allow_ips)
        for a in allow:
            if not edl._is_ip(edl.split_comment(a)[0]):
                raise edl.EdlError(f"allowed source {a!r} is not an IP, subnet or range")
        bu = basic_user.strip()
        if bu and not re.fullmatch(r"[A-Za-z0-9._@-]{1,63}", bu):
            raise edl.EdlError("basic auth user: letters, digits . _ @ -")
        hosted_new = {"enabled": hosted == "yes", "basic_auth_user": bu, "allow_ips": allow}
        if basic_password:
            if len(basic_password) < 12:
                raise edl.EdlError("basic auth password: at least 12 characters")
            hosted_new["basic_auth_hash"] = edl.hash_secret(basic_password)
        elif bu and not (meta.get("hosted") or {}).get("basic_auth_hash"):
            raise edl.EdlError("set a basic auth password for that user")
        if not bu:
            hosted_new["basic_auth_hash"] = ""
        if new_token == "yes":
            hosted_new["token"] = _s.token_urlsafe(24)
        s3 = edl.validate_s3({"enabled": s3_enabled == "yes", "bucket": s3_bucket, "key": s3_key, "region": s3_region,
                              "endpoint_url": s3_endpoint, "path_style": s3_path_style == "yes", "verify": s3_verify == "yes"})
        edl.update_meta(prof, lid, actor=user.name, name=(name or meta["name"]).strip()[:80], description=description.strip()[:500],
                        require_approval=require_approval == "yes", placeholder_when_empty=placeholder == "yes", hosted=hosted_new, s3=s3)
    except edl.EdlError as exc:
        return _back(customer, lid, "settings", msg=f"Not saved: {exc}")
    return _back(customer, lid, "settings", msg="Settings saved.")


@router.post("/edls/{customer}/{lid}/delete")
def delete_post(request: Request, customer: str, lid: str, confirm: str = Form(...)):
    w = _web()
    user = w.need(request, "edl_admin", customer)
    prof = _prof(customer)
    _meta(prof, lid)
    if confirm.strip() != lid:
        return _back(customer, lid, "settings", msg="The typed id does not match; nothing was deleted.")
    edl.delete_list(prof, lid, actor=user.name)
    return _back(customer, msg=f"List {lid} deleted (kept on the server for the record).")


# ---------------------------------------------------------------- publish, S3 status and import

@router.post("/edls/{customer}/{lid}/publish")
def publish_post(request: Request, customer: str, lid: str, force: str = Form("")):
    w = _web()
    user = w.need(request, ("edl_edit", "edl_admin"), customer)
    prof = _prof(customer)
    _meta(prof, lid)
    if force == "yes":
        w.need(request, "edl_admin", customer)
    res = edl.publish(prof, lid, actor=user.name, force=force == "yes")
    s3 = res.get("s3") or {}
    m = ("S3: " + s3.get("state", "") + ". " + str(s3.get("detail", ""))) if s3 else "Published."
    return _back(customer, lid, msg=m[:300])


@router.post("/edls/{customer}/{lid}/s3/check", response_class=HTMLResponse)
def s3_check(request: Request, customer: str, lid: str):
    w = _web()
    user = w.need(request, ANY, customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    st = edl.s3_status(prof, lid)
    body = (f"<div class='pagehead'><div><h2>S3 check: {e(meta['name'])} {theme.badge(st['state'], PUB_TONE.get(st['state'], 'warning'))}</h2>"
            f"<p><code>{e(edl.s3_describe(meta))}</code></p></div></div><p>{e(str(st.get('detail', '')))}</p>")
    if st["state"] == "changed-outside":
        remote = [x for x in st["body"].splitlines() if x.strip()]
        mine = set(edl.render_text(meta, edl.load_entries(prof, lid)).splitlines())
        theirs = {edl.split_comment(x)[0] for x in remote}
        only_s3, only_paat = sorted(theirs - mine), sorted(mine - theirs)
        body += ("<div class='card'><h3>Differences</h3>"
                 f"<p><b>Only in S3</b> ({len(only_s3)}): " + (", ".join(f"<code>{e(x)}</code>" for x in only_s3[:300]) or "none") + "</p>"
                 f"<p><b>Only in PAAT</b> ({len(only_paat)}): " + (", ".join(f"<code>{e(x)}</code>" for x in only_paat[:300]) or "none") + "</p></div>")
        if user.can("edl_edit"):
            body += (f"<form method='post' action='/edls/{e(customer)}/{e(lid)}/s3/import' class='card'><h3>Bring S3's version into PAAT</h3>"
                     "<label>Mode</label><select name='mode'><option value='merge'>Merge: add what only S3 has (keep PAAT's entries)</option>"
                     "<option value='replace'>Replace: make PAAT equal to S3</option></select><br>"
                     "<button>Preview the import</button></form>")
        if user.can("edl_admin"):
            body += (f"<form method='post' action='/edls/{e(customer)}/{e(lid)}/publish' class='card' style='border-left:4px solid #b00020'>"
                     "<h3>Or overwrite S3 with PAAT's version</h3><p>The out-of-band edit in S3 is lost (unless bucket versioning is on).</p>"
                     "<input type='hidden' name='force' value='yes'><button class='danger'>Overwrite S3</button></form>")
    body += f"<p><a class='btn secondary' href='/edls/{e(customer)}/{e(lid)}'>Back to the list</a></p>"
    return w.page("S3 check", body, user)


@router.post("/edls/{customer}/{lid}/s3/import", response_class=HTMLResponse)
def s3_import(request: Request, customer: str, lid: str, mode: str = Form("merge")):
    w = _web()
    user = w.need(request, "edl_edit", customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    try:
        p, n = edl.s3_import_plan(prof, lid, actor=user.name, mode=mode)
    except edl.EdlError as exc:
        return _back(customer, lid, msg=f"Nothing imported: {exc}")
    return _preview_page(w, user, prof, meta, p, reason=f"import from S3 ({mode}, {n} lines)", ticket="", source=f"s3 import ({mode})",
                         title="Import from S3")


# ---------------------------------------------------------------- firewall side

def _dev(prof, target: str):
    if device_factory is not None:
        return device_factory(prof, target)
    from panlab import urlfilter as uf

    return uf.connect(prof, target)


@router.get("/edls/{customer}/{lid}/firewall", response_class=HTMLResponse)
def firewall_page(request: Request, customer: str, lid: str, msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, ANY, customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    try:
        target, backend, _where = edl.obj_target(prof)
    except edl.EdlError as exc:
        raise HTTPException(409, str(exc))
    refs, names, err = edl.references(prof)
    mine = refs.get(lid, [])
    body = (f"<div class='pagehead'><div><h2>Firewalls using {e(meta['name'])}</h2><p>Read live (read-only key) from "
            f"<b>{e(target)}</b>. An object counts when its source URL is this list's PAAT URL or S3 object.</p></div>"
            f"<div class='actions'><a class='btn secondary' href='/edls/{e(customer)}/{e(lid)}'>Back to the list</a></div></div>"
            + (f"<div class='note'>{e(msg)}</div>" if msg else ""))
    if err:
        body += f"<div class='note' style='border-left-color:#b00020'>Could not read {e(target)}: {e(err)}</div>"
    if not mine and not err:
        body += theme.empty_state("No firewall object points at this list yet",
                                  "An EDL admin can generate the object (set commands, or push it through approval).",
                                  f"<a class='btn' href='/edls/{e(customer)}/{e(lid)}/object'>Make the firewall object</a>" if user.can("edl_admin") else "",
                                  "route")
    for o in mine:
        used = "".join(f"<li>{e(u['kind'])} <b>{e(u['name'])}</b> ({e(u['where'])}, {e(u['field'])}"
                       + (f", {e(u.get('action', ''))}" if u.get("action") else "") + (", disabled" if u.get("disabled") else "") + ")</li>"
                       for u in o["used_by"]) or "<li>Not used by any rule or profile yet: it filters nothing.</li>"
        body += (f"<div class='card'><h3>Object <code>{e(o['object'])}</code> in {e(o['where'])}</h3>"
                 f"<p>Type {e(o['type'])}, refresh {e(o['recurring'] or '?')}, source <code>{e(o['url'])}</code>"
                 + (f", certificate profile {e(o['cert_profile'])}" if o.get("cert_profile") else "") + "</p>"
                 f"<h4>Used by</h4><ul>{used}</ul>")
        devs = o["devices"] if backend == "panorama" else [None]
        if backend == "panorama" and not devs:
            body += "<p class='muted'>No firewall is in this device group.</p>"
        rows = []
        for serial in devs:
            st = edl.firewall_status(prof, meta["type"], o["object"], target=target, serial=serial)
            label = (names.get(serial or "", "") or serial or target)
            if st.get("ok"):
                info = ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in st.items() if k in ("valid", "invalid", "ignored", "last_update", "next_update", "status", "source"))
                if st.get("members"):
                    info += "; loaded: " + ", ".join(st["members"][:20]) + (" ..." if len(st["members"]) > 20 else "")
                detail = e(info or "loaded") + f"<details><summary>Firewall output</summary><pre>{e(st.get('raw', ''))}</pre></details>"
            else:
                detail = "<span class='muted'>could not read: " + e(st.get("error", "")) + "</span>"
            btn = ""
            if user.can("edl_admin"):
                btn = (f"<form method='post' action='/edls/{e(customer)}/{e(lid)}/firewall/refresh' class='inline'>"
                       f"<input type='hidden' name='object' value='{e(o['object'])}'><input type='hidden' name='serial' value='{e(serial or '')}'>"
                       "<button class='secondary sm'>Refresh now</button></form>")
            rows.append(f"<tr><td>{e(label)}<br><span class='muted'>{e(serial or '')}</span></td><td>{detail}</td><td>{btn}</td></tr>")
        if rows:
            body += f"<table><tr><th>Firewall</th><th>What it has loaded</th><th></th></tr>{''.join(rows)}</table>"
        body += "</div>"
    body += ("<p class='muted'>Firewalls refresh on their own schedule (5 minutes at the fastest). <b>Refresh now</b> (EDL admin) runs "
             "<code>request system external-list refresh</code> on that firewall.</p>")
    return w.page("Firewalls using this list", body, user)


@router.post("/edls/{customer}/{lid}/firewall/refresh")
def firewall_refresh(request: Request, customer: str, lid: str, object: str = Form(...), serial: str = Form("")):
    w = _web()
    user = w.need(request, "edl_admin", customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    target, _b, where = edl.obj_target(prof)
    if not device_in_scope(user.device_scope(customer), target=target, serial=serial, device_groups=[where] if where else []):
        raise HTTPException(403, "that firewall is not in your device scope")
    refs, _n, _err = edl.references(prof)
    if object not in {o["object"] for o in refs.get(lid, [])}:
        raise HTTPException(409, "that object does not point at this list")
    res = edl.firewall_refresh(prof, lid, meta["type"], object, target=target, serial=serial or None, actor=user.name)
    return _back(customer, lid, "firewall", msg=("Refresh requested: " if res["ok"] else "Refresh failed: ") + res["detail"][:200])


# ---------------------------------------------------------------- firewall object generator and requests

def _obj_fields(meta: dict, f: dict) -> str:
    rec = "".join(f"<option {'selected' if f.get('recurring') == r else ''}>{r}</option>" for r in edl.RECURRING)
    exp = ("<label style='font-weight:400'><input type='checkbox' name='expand_domain' value='yes' "
           f"{'checked' if f.get('expand_domain') else ''}> Also match subdomains (PAN-OS counts each entry twice)</label>") if meta["type"] == "domain" else ""
    return (f"<label>Object name on the firewall</label><input name='name' value='{e(f.get('name', ''))}' size='40' required>"
            f"<label>Device group (or <code>shared</code>; vsys for a standalone firewall)</label><input name='where' value='{e(f.get('where', ''))}' size='30'>"
            f"<label>Source URL the firewall fetches</label><input name='url' value='{e(f.get('url', ''))}' size='80' required>"
            f"<label>Refresh</label><select name='recurring'>{rec}</select>"
            f"<label>Description</label><input name='description' value='{e(f.get('description', ''))}' size='60'>"
            f"<label>Certificate profile (https:// sources: the profile with the CA that signed the server's certificate)</label>"
            f"<input name='cert_profile' value='{e(f.get('cert_profile', ''))}' size='30'>"
            f"<label>Basic auth user (optional; type the password on the device)</label><input name='username' value='{e(f.get('username', ''))}' size='24'>"
            + exp)


@router.get("/edls/{customer}/{lid}/object", response_class=HTMLResponse)
def object_form(request: Request, customer: str, lid: str) -> HTMLResponse:
    w = _web()
    user = w.need(request, "edl_admin", customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    target, backend, where = edl.obj_target(prof)
    s3 = meta.get("s3") or {}
    url = edl.hosted_url(prof, meta, _base(request)) if (meta.get("hosted") or {}).get("enabled") else (edl.s3_url(meta) if s3.get("enabled") else "")
    f = {"name": "EDL-" + lid.upper(), "where": where, "url": url, "recurring": "five-minute",
         "description": f"PAAT list {meta['name']} (managed in PAAT; do not edit entries on the firewall)"}
    srcs = []
    if (meta.get("hosted") or {}).get("enabled"):
        srcs.append(f"PAAT-hosted: <code>{e(edl.hosted_url(prof, meta, _base(request)))}</code>")
    if s3.get("enabled"):
        srcs.append(f"S3: <code>{e(edl.s3_url(meta))}</code>")
    body = (f"<div class='pagehead'><div><h2>Firewall object for {e(meta['name'])}</h2><p>Generates the PAN-OS <code>external-list</code> "
            f"object for <b>{e(target)}</b> ({e(backend)}). Copy the set commands, or request it: a second person approves with a CR, then "
            "an operator pushes it from the red push area.</p></div></div>"
            + ("<div class='note'>Sources for this list: " + " · ".join(srcs) + "</div>" if srcs else "")
            + "<div class='note'>Firewalls fetch EDLs from their <b>management interface</b> by default (Device &gt; Setup &gt; Services &gt; "
            "Service Route, \"External Dynamic Lists\"). For an https:// source the firewall needs a certificate profile with the CA that "
            "signed the server's certificate, or the fetch fails.</div>"
            f"<form method='post' action='/edls/{e(customer)}/{e(lid)}/object' class='card'>{_obj_fields(meta, f)}<br>"
            "<button name='action' value='preview' class='secondary'>Preview commands</button> <button name='action' value='request'>Request this object</button></form>")
    return w.page("Firewall object", body, user)


@router.post("/edls/{customer}/{lid}/object", response_class=HTMLResponse)
def object_post(request: Request, customer: str, lid: str, action: str = Form("preview"), name: str = Form(...), where: str = Form(""),
                url: str = Form(...), recurring: str = Form("five-minute"), description: str = Form(""), cert_profile: str = Form(""),
                username: str = Form(""), expand_domain: str = Form("")):
    w = _web()
    user = w.need(request, "edl_admin", customer)
    prof = _prof(customer)
    meta = _meta(prof, lid)
    target, backend, dwhere = edl.obj_target(prof)
    where = (where or dwhere).strip()
    if not device_in_scope(user.device_scope(customer), target=target, device_groups=[where] if where else []):
        raise HTTPException(403, f"{target} ({where}) is not in your device scope")
    kw = dict(name=name.strip(), url=url.strip(), recurring=recurring, description=description.strip(), cert_profile=cert_profile.strip(),
              username=username.strip(), expand_domain=expand_domain == "yes")
    try:
        if action == "request":
            r = edl.create_object_request(prof, lid, actor=user.name, where=where, **kw)
            return RedirectResponse(f"/edls/{quote(customer)}/objects/{r['id']}?msg={quote('Requested. A second person must approve it with a CR.')}",
                                    status_code=303)
        xml = edl.object_element(kind=meta["type"], **kw)
        wcli = ("shared" if where == "shared" else f"device-group {where}") if backend == "panorama" else (f"vsys {where}" if where and where != "vsys1" else "")
        cmds = edl.object_set_commands(kind=meta["type"], where=wcli, **kw)
    except edl.EdlError as exc:
        return w.page("Firewall object", f"<div class='note'>{e(str(exc))}</div><p><a class='btn secondary' href='/edls/{e(customer)}/{e(lid)}/object'>Back</a></p>", user)
    f = {**kw, "where": where}
    body = (f"<div class='pagehead'><div><h2>Preview: {e(name)}</h2><p>Target {e(target)}, {e(where)}</p></div></div>"
            "<div class='card'><h3>CLI set commands</h3><pre id='edl-set'>" + e("\n".join(cmds)) + "</pre>" + w._copy_btn("edl-set") + "</div>"
            "<div class='card'><h3>XML API element</h3><p class='muted'>xpath <code>" + e(edl.obj_xpath(backend, where, name.strip())) + "</code></p>"
            f"<pre id='edl-xml'>{e(xml)}</pre>{w._copy_btn('edl-xml')}</div>"
            f"<form method='post' action='/edls/{e(customer)}/{e(lid)}/object' class='card'>{_obj_fields(meta, f)}<br>"
            "<button name='action' value='preview' class='secondary'>Preview again</button> <button name='action' value='request'>Request this object</button></form>")
    return w.page("Firewall object preview", body, user)


@router.get("/edls/{customer}/objects", response_class=HTMLResponse)
def objects_index(request: Request, customer: str) -> HTMLResponse:
    w = _web()
    user = w.need(request, ANY, customer)
    prof = _prof(customer)
    reqs = edl.list_object_requests(prof)
    rows = "".join(f"<tr><td><a href='/edls/{e(customer)}/objects/{e(r['id'])}'>{e(r['id'])}</a></td><td>{theme.badge(r['status'], STATUS_TONE.get(r['status'], 'neutral'))}</td>"
                   f"<td><code>{e(r['name'])}</code></td><td>{e(r['list'])}</td><td>{e(r['target'])} / {e(r['where'])}</td><td>{e(r['requester'])}</td>"
                   f"<td>{_ts(r['created'])}</td></tr>" for r in reqs)
    body = ("<div class='pagehead'><div><h2>EDL firewall objects</h2><p>Requests to create the <code>external-list</code> objects that point "
            "firewalls at PAAT lists. Each needs a second person's approval with a CR before an operator pushes it.</p></div></div>"
            + (f"<table><tr><th>Request</th><th>Status</th><th>Object</th><th>List</th><th>Where</th><th>Requested by</th><th>When (CST)</th></tr>{rows}</table>"
               if rows else theme.empty_state("No requests yet", "Open a list and choose Make the firewall object.", "", "route")))
    return w.page("EDL firewall objects", body, user)


@router.get("/edls/{customer}/objects/{rid}", response_class=HTMLResponse)
def object_detail(request: Request, customer: str, rid: str, msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, ANY, customer)
    prof = _prof(customer)
    try:
        r = edl.load_object_request(prof, rid)
    except edl.EdlError:
        raise HTTPException(404, "no such request")
    push_area = r["status"] in ("approved", "pushed", "failed") and user.can("push")
    body = (f"<div class='pagehead'><div><h2>Object {e(r['name'])} {theme.badge(r['status'], STATUS_TONE.get(r['status'], 'neutral'))}</h2>"
            f"<p>List <a href='/edls/{e(customer)}/{e(r['list'])}'>{e(r['list'])}</a> · {e(r['target'])} ({e(r['backend'])}) {e(r['where'])} · "
            f"requested by {e(r['requester'])} at {_ts(r['created'])}" + (f" · CR {e(r['cr'])}" if r.get("cr") else "") + "</p></div></div>"
            + (f"<div class='note'>{e(msg)}</div>" if msg else "")
            + f"<div class='card'><h3>Set commands</h3><pre id='o-set'>{e(chr(10).join(r['set_commands']))}</pre>{w._copy_btn('o-set')}"
            f"<h3>XML</h3><p class='muted'>xpath <code>{e(r['xpath'])}</code></p><pre>{e(r['element'])}</pre></div>")
    if r["status"] == "pending":
        if (user.can("edl_approve") or user.can("approve")) and user.name != r["requester"]:
            body += (f"<form method='post' action='/edls/{e(customer)}/objects/{e(rid)}/review' class='card'><h3>Review</h3>"
                     f"<label>Approved CR number</label><input name='cr' size='20' placeholder='{e(prof.tickets.get('cr', ''))}'>"
                     "<label>Comment</label><input name='comment' size='60'><br>"
                     "<button name='action' value='approve'>Approve</button> <button name='action' value='reject' class='danger'>Reject</button></form>")
        else:
            body += "<p class='muted'>Waiting for a second person with EDL approve (or approve). The requester cannot approve it.</p>"
    if push_area:
        body += (f"<div class='redbar' role='alert'>{theme.icon('alert')}PUSH AREA: this writes to {e(r['target'])} and commits"
                 + (" and pushes the device group" if r["backend"] == "panorama" else "") + ". Every step is audited.</div>")
        if r["status"] == "approved":
            if r.get("mode") == "dry-run":
                body += "<p>Live push is off for this customer: add the object by hand with the set commands above.</p>"
            else:
                body += (f"<form method='post' action='/edls/{e(customer)}/objects/{e(rid)}/push' class='card'><label>Type the target name "
                         f"(<code>{e(r['target'])}</code>) to push</label><input name='confirm' size='20' required> <button class='danger'>Push</button></form>")
        else:
            body += (f"<form method='post' action='/edls/{e(customer)}/objects/{e(rid)}/rollback' class='card'><h3>Roll back</h3>"
                     "<p>Removes the object again (or restores what was there at approval). Remove it from rules first.</p>"
                     f"<label>Type the target name (<code>{e(r['target'])}</code>)</label><input name='confirm' size='20' required> "
                     "<button class='danger'>Roll back</button></form>")
    if r.get("result"):
        body += f"<p><b>Push result:</b> {e(r['result'])}</p>"
    if r.get("rollback_result"):
        body += f"<p><b>Rollback result:</b> {e(r['rollback_result'])}</p>"
    hist = "".join(f"<tr><td>{_ts(h['ts'])}</td><td>{e(h['actor'])}</td><td>{e(h['what'])}</td><td>{e(str(h.get('detail', h.get('cr', ''))))}</td></tr>"
                   for h in r.get("history", []))
    jobs = "".join(f"<li>{e(j.get('step', ''))}: job {e(str(j.get('jobid')))} {'OK' if j.get('success') else 'FAILED'}</li>" for j in r.get("jobs", []))
    body += f"<div class='card'><h3>History</h3><table><tr><th>When</th><th>Who</th><th>What</th><th>Detail</th></tr>{hist}</table>" + (f"<ul>{jobs}</ul>" if jobs else "") + "</div>"
    return w.page(f"Object {r['name']}", body, user, push=push_area)


def _obj_scope(user, customer: str, r: dict) -> None:
    if not device_in_scope(user.device_scope(customer), target=r["target"], device_groups=[r["where"]] if r.get("where") else []):
        raise HTTPException(403, f"{r['target']} ({r['where']}) is not in your device scope")


@router.post("/edls/{customer}/objects/{rid}/review")
def object_review(request: Request, customer: str, rid: str, action: str = Form(...), cr: str = Form(""), comment: str = Form("")):
    w = _web()
    user = w.need(request, ("edl_approve", "approve"), customer)
    prof = _prof(customer)
    try:
        r = edl.load_object_request(prof, rid)
        _obj_scope(user, customer, r)
        if action == "approve":
            edl.approve_object(prof, rid, _dev(prof, r["target"]), actor=user.name, cr=cr, comment=comment)
            m = "Approved. An operator can push it from the push area."
        else:
            edl.reject_object(prof, rid, actor=user.name, comment=comment)
            m = "Rejected."
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - EdlError, PushError (CR format), device errors
        m = f"Not done: {str(exc)[:200]}"
    return RedirectResponse(f"/edls/{quote(customer)}/objects/{quote(rid)}?msg={quote(m)}", status_code=303)


@router.post("/edls/{customer}/objects/{rid}/push")
def object_push(request: Request, customer: str, rid: str, confirm: str = Form(...)):
    w = _web()
    user = w.need(request, "push", customer)
    prof = _prof(customer)
    try:
        r = edl.load_object_request(prof, rid)
        _obj_scope(user, customer, r)
        r = edl.push_object(prof, rid, _dev(prof, r["target"]), actor=user.name, confirm_target=confirm)
        m = f"Push {r['status']}: {r.get('result', '')}"
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        m = f"Not pushed: {str(exc)[:200]}"
    return RedirectResponse(f"/edls/{quote(customer)}/objects/{quote(rid)}?msg={quote(m[:300])}", status_code=303)


@router.post("/edls/{customer}/objects/{rid}/rollback")
def object_rollback(request: Request, customer: str, rid: str, confirm: str = Form(...)):
    w = _web()
    user = w.need(request, "push", customer)
    prof = _prof(customer)
    try:
        r = edl.load_object_request(prof, rid)
        _obj_scope(user, customer, r)
        r = edl.rollback_object(prof, rid, _dev(prof, r["target"]), actor=user.name, confirm_target=confirm)
        m = f"Rollback {r['status']}: {r.get('rollback_result', '')}"
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        m = f"Not rolled back: {str(exc)[:200]}"
    return RedirectResponse(f"/edls/{quote(customer)}/objects/{quote(rid)}?msg={quote(m[:300])}", status_code=303)


# ---------------------------------------------------------------- per-customer safety settings

@router.get("/edls/{customer}/settings", response_class=HTMLResponse)
def safety(request: Request, customer: str, msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, ANY, customer)
    prof = _prof(customer)
    st = edl.load_settings(prof)
    ro = "" if user.can("edl_admin") else " disabled"
    models = "".join(f"<option value='{k}' {'selected' if st['model'] == k else ''}>{e(v[0])}: IP {v[1]:,}, domains {v[2]:,}, URLs {v[3]:,}</option>"
                     for k, v in edl.MODEL_LIMITS.items())
    cap = edl.capacity(prof)
    body = ("<div class='pagehead'><div><h2>EDL safety settings</h2><p>What PAAT refuses, and what needs a second person, for "
            f"<b>{e(prof.display_name or customer)}</b>. These apply to every list of this customer.</p></div></div>"
            + (f"<div class='note'>{e(msg)}</div>" if msg else "") + _help() +
            "<div class='card'><h3>Always refused</h3><ul><li><code>0.0.0.0/0</code>, <code>::/0</code>, loopback</li>"
            f"<li>IPv4 wider than /{st['hard_min_prefix_v4']}, IPv6 wider than /{st['hard_min_prefix_v6']}</li>"
            "<li>Bare top-level domains (<code>com</code>), wildcards over major ones (<code>*.com</code>, <code>*.co.uk</code>), <code>*</code></li>"
            "<li>Anything that would block an entry on the never-block list below</li></ul>"
            "<h3>Needs a second person (EDL approve)</h3><ul>"
            f"<li>IPv4 wider than /{st['approval_prefix_v4']}, IPv6 wider than /{st['approval_prefix_v6']}</li>"
            + ("<li>Anything inside RFC 1918, 100.64.0.0/10 or fc00::/7</li>" if st["protected_rfc1918"] else "")
            + "<li>Anything inside your protected ranges or protected domains below</li><li>Wildcards over smaller TLDs (<code>*.click</code>)</li></ul></div>"
            f"<form method='post' action='/edls/{e(customer)}/settings' class='card'><h3>Settings</h3>"
            f"<label style='font-weight:400'><input type='checkbox' name='protected_rfc1918' value='yes' {'checked' if st['protected_rfc1918'] else ''}{ro}> "
            "Private ranges (RFC 1918, CGNAT, IPv6 ULA) need a second person</label>"
            f"<label>Protected ranges (your own networks; one per line, optional <code># label</code>)</label>"
            f"<textarea name='protected_ranges' rows='4' cols='50'{ro}>{e(chr(10).join(st['protected_ranges']))}</textarea>"
            f"<label>Protected domains (your own; entries inside or covering them need a second person)</label>"
            f"<textarea name='protected_domains' rows='3' cols='50'{ro}>{e(chr(10).join(st['protected_domains']))}</textarea>"
            f"<label>Never block (DNS servers, management IPs, identity providers; IPs or domains; entries that would block these are refused)</label>"
            f"<textarea name='never_block' rows='4' cols='50'{ro}>{e(chr(10).join(st['never_block']))}</textarea>"
            "<div style='display:flex;gap:12px;flex-wrap:wrap'>"
            f"<span><label>Refuse IPv4 wider than /</label><input name='hard_min_prefix_v4' value='{st['hard_min_prefix_v4']}' size='4'{ro}></span>"
            f"<span><label>Approval for IPv4 wider than /</label><input name='approval_prefix_v4' value='{st['approval_prefix_v4']}' size='4'{ro}></span>"
            f"<span><label>Refuse IPv6 wider than /</label><input name='hard_min_prefix_v6' value='{st['hard_min_prefix_v6']}' size='4'{ro}></span>"
            f"<span><label>Approval for IPv6 wider than /</label><input name='approval_prefix_v6' value='{st['approval_prefix_v6']}' size='4'{ro}></span></div>"
            f"<label>Firewall model (for capacity warnings)</label><select name='model'{ro}>{models}</select>"
            f"<label>Public base URL firewalls use to reach PAAT (blank: the address in your browser)</label>"
            f"<input name='public_base_url' value='{e(st['public_base_url'])}' size='40' placeholder='https://paat.example.net'{ro}>"
            + ("<br><button>Save</button>" if not ro else "<p class='muted'>Only an EDL admin can change these.</p>") + "</form>"
            f"<div class='card'><h3>Capacity</h3><p>{e(cap['model'])}: IP {cap['totals']['ip']:,} of {cap['limits']['ip']:,} · domains "
            f"{cap['totals']['domain']:,} of {cap['limits']['domain']:,} · URLs {cap['totals']['url']:,} of {cap['limits']['url']:,} · "
            f"{cap['lists']} of {edl.MAX_EDL_OBJECTS} lists. Entries count only when the list is used in a rule or profile.</p></div>")
    return w.page("EDL safety settings", body, user)


@router.post("/edls/{customer}/settings")
async def safety_post(request: Request, customer: str):
    w = _web()
    user = w.need(request, "edl_admin", customer)
    prof = _prof(customer)
    f = await request.form()
    new = {k: str(f.get(k) or "") for k in ("protected_ranges", "protected_domains", "never_block", "hard_min_prefix_v4", "approval_prefix_v4",
                                            "hard_min_prefix_v6", "approval_prefix_v6", "model", "public_base_url")}
    new["protected_rfc1918"] = f.get("protected_rfc1918") == "yes"
    try:
        edl.save_settings(prof, new, actor=user.name)
    except edl.EdlError as exc:
        return RedirectResponse(f"/edls/{quote(customer)}/settings?msg={quote('Not saved: ' + str(exc))}", status_code=303)
    return RedirectResponse(f"/edls/{quote(customer)}/settings?msg={quote('Saved.')}", status_code=303)


# Static paths (/new, /settings, /objects) must win over /{lid}.
router.routes.sort(key=lambda r: "{lid}" in getattr(r, "path", ""))
