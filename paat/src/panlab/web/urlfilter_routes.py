"""URL filter self-service pages.

``urlfilter_request``: see the customer's URL Filtering profile (live) and submit change requests.
``urlfilter_approve``: review requests, approve (with an approved CR) or reject, push approved ones where live
push is allowed, roll back. Both honor customer scope, and a device scope must include the URL filter target
(its profile target name or ``dg:<device group>``). A requester cannot approve their own request unless the
customer sets ``url_filter.allow_self_approval``.
"""

from __future__ import annotations

import html
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from panlab import urlfilter as uf
from panlab.customers import load_profile
from panlab.web.auth import device_in_scope

router = APIRouter()
e = html.escape
ANY = ("urlfilter_request", "urlfilter_approve")
device_factory = uf.connect  # tests replace this with a fake device
STATUS_CLS = {"pending": "#9a6700", "stale": "#b00020", "approved": "#2563eb", "rejected": "#64748b", "pushed": "#1a7f37",
              "failed": "#b00020", "rolled-back": "#64748b", "pushing": "#7c3aed", "rolling-back": "#7c3aed"}
ACT_CLS = {"block": "#b00020", "continue": "#9a6700", "override": "#9a6700", "alert": "#2563eb", "allow": "#1a7f37"}


def _web():
    from panlab.web import app as webapp
    return webapp


def _ctx(customer: str, user):
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")
    try:
        cfg = uf.config_for(prof)
    except uf.UrlFilterError as exc:
        raise HTTPException(409, f"URL filter settings for {customer} are invalid: {exc}")
    if cfg is None:
        raise HTTPException(404, f"URL filter self-service is not set up for {customer}")
    if not device_in_scope(user.device_scope(customer), target=cfg.target, device_groups=[cfg.device_group] if cfg.device_group else []):
        raise HTTPException(403, f"{cfg.target} ({cfg.where}) is not in your device scope")
    return prof, cfg


def _badge(status: str) -> str:
    return f"<span style='color:#fff;background:{STATUS_CLS.get(status, '#64748b')};border-radius:10px;padding:1px 9px;font-size:12px'>{e(status)}</span>"


def _act(a: str | None) -> str:
    return f"<b style='color:{ACT_CLS.get(a or '', '#334155')}'>{e(a or '-')}</b>"


def _live(prof, cfg):
    dev = device_factory(prof, cfg.target)
    return dev, uf.read_live(dev, cfg)


def _attach_note(att: dict, cfg) -> str:
    if att["attached"]:
        used = ", ".join(f"{r['rule']} ({r['via']})" for r in att["rules"][:8])
        return f"<p class='muted'>In use by {len(att['rules'])} security rule(s): {e(used)}.</p>"
    grp = (f" It is in profile group(s) {e(', '.join(att['groups']))}, but no enabled security rule uses them." if att["groups"]
           else " It is not in any security profile group.")
    return ("<div class='note' style='border-left-color:#b00020'><b>Not attached:</b> no security rule in "
            f"{e(cfg.where)} uses <b>{e(cfg.profile)}</b> yet, so changes here do not filter any traffic.{grp} "
            "Administrators: add it to the customer's security profile group on their rules (this tool does not attach it).</div>")


@router.get("/urlfilter", response_class=HTMLResponse)
def index(request: Request, customer: str = "", msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, ANY)
    names = []
    for c in w.list_customers():
        try:
            if uf.config_for(load_profile(c)):
                names.append(c)
        except Exception:  # noqa: BLE001
            continue
    customer = customer if customer in names else (names[0] if names else "")
    opts = "".join(f"<option {'selected' if c == customer else ''}>{e(c)}</option>" for c in names)
    body = ("<h2>URL filter self-service</h2>"
            "<div class='note'>Requesters pick the action for each URL category (and optional allow / block lists) for one "
            "customer's URL Filtering profile. An approver reviews the differences against the live profile and the Palo Alto "
            "recommendation, approves with a CR, and pushes it. Attaching the profile to security rules stays with the "
            "administrators.</div>" + (f"<p class='note'>{e(msg)}</p>" if msg else ""))
    if not names:
        return w.page("URL filter self-service", body + "<p class='muted'>No customer in your scope has URL filter self-service set up.</p>", user)
    body += f"<form method='get' action='/urlfilter'><label>Customer</label><select name='customer' onchange='this.form.submit()'>{opts}</select></form>"
    prof, cfg = _ctx(customer, user)
    mode = "live push enabled" if uf.live_allowed(prof, cfg) else "dry-run only (change plan for a manual change)"
    body += (f"<div class='card'><h3>{e(cfg.profile)}</h3><p>Where: <b>{e(cfg.target)}</b>, {e(cfg.where)} · allow list "
             f"<code>{e(cfg.allow_category)}</code> · block list <code>{e(cfg.block_category)}</code> · {e(mode)}</p>")
    try:
        dev, state = _live(prof, cfg)
        body += ("" if state["exists"] else "<p class='muted'>The profile does not exist yet; the first approved request creates it.</p>")
        body += _attach_note(uf.attachment(dev, cfg), cfg)
    except Exception as exc:  # noqa: BLE001
        body += f"<p class='note'>Could not read the live profile: {e(str(exc)[:200])}</p>"
    if user.can("urlfilter_request"):
        body += f"<p><a class='btn' href='/urlfilter/{e(customer)}/new'>Request a change</a></p>"
    body += "</div>"
    reqs = uf.list_requests(prof)[:100]
    rows = "".join(
        f"<tr><td><a href='/urlfilter/{e(customer)}/{e(r['id'])}'>{e(r['id'])}</a></td><td>{_badge(r['status'])}</td>"
        f"<td>{e(r['requester'])}</td><td>{e(r['created'])}</td><td>{len(uf.diff_lines(r))}</td>"
        f"<td>{len(uf.deviations(r))}</td><td>{e(r.get('reviewer', ''))}</td></tr>" for r in reqs)
    body += ("<h3>Requests</h3><table><tr><th>Request</th><th>Status</th><th>Requester</th><th>Created (CST)</th><th>Changes</th>"
             f"<th>Differs from PA</th><th>Reviewer</th></tr>{rows}</table>") if rows else "<p class='muted'>No requests yet.</p>"
    return w.page("URL filter self-service", body, user)


_JS = """<script>
(function(){
 const q=document.getElementById('uf-q'), g=document.getElementById('uf-g'), ch=document.getElementById('uf-ch'), cnt=document.getElementById('uf-count');
 const rows=[...document.querySelectorAll('tr.uf-row')];
 function upd(){let n=0;rows.forEach(r=>{const s=r.querySelector('select');const c=s.value!==r.dataset.cur;r.classList.toggle('uf-changed',c);
   r.querySelector('.uf-dev').textContent=(s.value!==r.dataset.rec)?'differs from PA':'';if(c)n++;
   const t=(r.dataset.id+' '+r.dataset.name+' '+r.dataset.desc).toLowerCase();
   r.style.display=((!q.value||t.includes(q.value.toLowerCase()))&&(!g.value||r.dataset.group===g.value)&&(!ch.checked||c))?'':'none';});
   document.querySelectorAll('tr.uf-grp').forEach(h=>{h.style.display=(!g.value||h.dataset.group===g.value)&&!ch.checked&&!q.value?'':'none';});
   cnt.textContent=n+' categor'+(n===1?'y':'ies')+' changed';}
 rows.forEach(r=>r.querySelector('select').addEventListener('change',upd));[q,g,ch].forEach(x=>x.addEventListener('input',upd));
 document.getElementById('uf-rec').addEventListener('click',ev=>{ev.preventDefault();rows.forEach(r=>{if(r.style.display!=='none')r.querySelector('select').value=r.dataset.rec;});upd();});
 document.getElementById('uf-reset').addEventListener('click',ev=>{ev.preventDefault();rows.forEach(r=>r.querySelector('select').value=r.dataset.cur);upd();});
 upd();})();
</script>
<style>tr.uf-changed td{background:#fff7d6!important}.uf-dev{color:#b00020;font-size:12px}tr.uf-grp td{background:#e8eef6!important;font-weight:600;color:#0f2742}
.uf-tools{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:8px 0}.uf-tools input,.uf-tools select{margin:0}</style>"""


@router.get("/urlfilter/{customer}/new", response_class=HTMLResponse)
def new_form(request: Request, customer: str, msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, "urlfilter_request", customer=customer)
    prof, cfg = _ctx(customer, user)
    try:
        _, state = _live(prof, cfg)
    except Exception as exc:  # noqa: BLE001
        return w.page("New URL filter request", f"<h2>New request: {e(customer)}</h2><p class='note'>Could not read the live profile "
                      f"from {e(cfg.target)}: {e(str(exc)[:200])}. Try again later.</p>", user)
    rws = uf.rows(state)
    groups = list(dict.fromkeys(r["group"] for r in rws))
    trs, last = [], None
    for r in rws:
        if r["group"] != last:
            trs.append(f"<tr class='uf-grp' data-group='{e(r['group'])}'><td colspan='5'>{e(r['group'])}</td></tr>")
            last = r["group"]
        sel = "".join(f"<option {'selected' if a == r['current'] else ''}>{a}</option>" for a in uf.ACTIONS)
        trs.append(f"<tr class='uf-row' data-id='{e(r['id'])}' data-name='{e(r['name'])}' data-desc='{e(r['desc'])}' "
                   f"data-group='{e(r['group'])}' data-cur='{e(r['current'])}' data-rec='{e(r['recommended'])}'>"
                   f"<td><b>{e(r['name'])}</b><br><code class='muted'>{e(r['id'])}</code></td><td class='muted'>{e(r['desc'])}</td>"
                   f"<td>{_act(r['recommended'])}</td><td>{_act(r['current'])}</td>"
                   f"<td><select name='cat__{e(r['id'])}'>{sel}</select><div class='uf-dev'></div></td></tr>")
    def lst(kind):
        urls = state["custom"][kind]["urls"]
        rm = "".join(f"<label style='font-weight:400'><input type='checkbox' name='{kind}_remove' value='{e(u)}'> remove <code>{e(u)}</code></label>"
                     for u in urls) or "<p class='muted'>Empty.</p>"
        return (f"<div class='card' style='flex:1;min-width:300px'><h4>{'Always allow' if kind == 'allow' else 'Always block'} list "
                f"<code>{e(getattr(cfg, kind + '_category'))}</code></h4>{rm}<label>Add sites (one per line: example.com, *.example.com, "
                f"example.com/path)</label><textarea name='{kind}_add' rows='4' style='width:100%'></textarea></div>")
    gopts = "<option value=''>All groups</option>" + "".join(f"<option>{e(g)}</option>" for g in groups)
    body = (f"<h2>New URL filter request: {e(customer)}</h2>"
            f"<p class='muted'>Profile <b>{e(cfg.profile)}</b> on {e(cfg.target)}, {e(cfg.where)} · read live {e(state['read_at'])} (CST)"
            + ("" if state["exists"] else " · <b>the profile does not exist yet</b>: unlisted categories are allow") + "</p>"
            + (f"<p class='note'>{e(msg)}</p>" if msg else "")
            + "<div class='note'><b>How to use:</b> change the <b>Requested</b> column only where you want a different action. "
            "<b>alert</b> = allow and log; <b>continue</b> = warning page, the user may continue; <b>override</b> = needs an admin "
            "override password; <b>block</b> = block page. Rows you change turn yellow; choices that differ from the Palo Alto "
            "recommendation are flagged for the approver. Nothing changes on the firewall until an approver approves and pushes it.</div>"
            f"<form method='post' action='/urlfilter/{e(customer)}/new'>"
            "<div class='uf-tools'><input id='uf-q' placeholder='Search categories' size='28'>"
            f"<select id='uf-g'>{gopts}</select><label style='font-weight:400;margin:0'><input type='checkbox' id='uf-ch'> only changed</label>"
            "<button class='secondary' id='uf-rec'>Set shown rows to PA recommended</button><button class='secondary' id='uf-reset'>Reset to live</button>"
            "<b id='uf-count'></b></div>"
            "<table><tr><th>Category</th><th>What it is</th><th>PA recommended</th><th>Live now</th><th>Requested</th></tr>"
            + "".join(trs) + "</table><h3>Allow and block lists (optional)</h3>"
            "<p class='muted'>Sites on the allow list are allowed whatever their category; sites on the block list are always blocked. "
            "No http://, no ports.</p><div style='display:flex;gap:14px;flex-wrap:wrap'>" + lst("allow") + lst("block") + "</div>"
            "<label>Notes for the approver (why you need this, ticket number)</label><textarea name='notes' rows='3' style='width:100%'></textarea>"
            f"<input type='hidden' name='base' value='{e(uf.state_hash(state))}'><br><button>Submit request</button></form>" + _JS)
    return w.page("New URL filter request", body, user)


@router.post("/urlfilter/{customer}/new")
async def new_submit(request: Request, customer: str):
    w = _web()
    user = w.need(request, "urlfilter_request", customer=customer)
    prof, cfg = _ctx(customer, user)
    form = await request.form()
    desired = {k[5:]: str(v) for k, v in form.items() if k.startswith("cat__")}
    errs, lists = [], {}
    for kind in ("allow", "block"):
        good, bad = uf.parse_urls(str(form.get(f"{kind}_add") or ""))
        lists[kind] = good
        errs += bad
    if errs:
        return RedirectResponse(f"/urlfilter/{quote(customer)}/new?msg=" + quote("Fix the site list: " + "; ".join(errs[:5])), 303)
    try:
        _, state = _live(prof, cfg)
        if str(form.get("base") or "") and form.get("base") != uf.state_hash(state):
            raise uf.UrlFilterError("the live profile changed while you were editing; review the Live now column and submit again")
        req = uf.create_request(prof, cfg, state, actor=user[0], desired=desired, allow_add=lists["allow"], block_add=lists["block"],
                                allow_remove=[str(x) for x in form.getlist("allow_remove")],
                                block_remove=[str(x) for x in form.getlist("block_remove")], notes=str(form.get("notes") or ""))
    except uf.UrlFilterError as exc:
        return RedirectResponse(f"/urlfilter/{quote(customer)}/new?msg={quote(str(exc)[:300])}", 303)
    except Exception as exc:  # noqa: BLE001
        return RedirectResponse(f"/urlfilter/{quote(customer)}/new?msg={quote('Could not read the live profile: ' + str(exc)[:200])}", 303)
    return RedirectResponse(f"/urlfilter/{customer}/{req['id']}", 303)


def _load(prof, rid: str) -> dict:
    try:
        return uf.load(prof, rid)
    except uf.UrlFilterError:
        raise HTTPException(404, "unknown request")


@router.get("/urlfilter/{customer}/{rid}", response_class=HTMLResponse)
def show(request: Request, customer: str, rid: str, msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, ANY, customer=customer)
    prof, cfg = _ctx(customer, user)
    req = _load(prof, rid)
    stale_note, live = "", None
    if req["status"] in ("pending", "stale", "approved"):
        try:
            _, live = _live(prof, cfg)
            base = uf.state_hash(req["approved_state"]) if req["status"] == "approved" else req["base_hash"]
            if uf.state_hash(live) != base:
                stale_note = ("<div class='note' style='border-left-color:#b00020'><b>Stale:</b> the live profile changed since this "
                              "request was " + ("approved" if req["status"] == "approved" else "made") + ". An approver must re-review it "
                              "against the live profile before it can be approved or pushed.</div>")
        except Exception as exc:  # noqa: BLE001
            stale_note = f"<p class='note'>Could not read the live profile: {e(str(exc)[:200])}</p>"
    ch = "".join(f"<tr><td><code>{e(c)}</code></td><td>{_act(x['from'])}</td><td>{_act(x['to'])}</td><td>{_act(uf.recommended(c))}</td>"
                 f"<td>{'<span style=color:#b00020>differs</span>' if x['to'] != uf.recommended(c) else 'matches'}</td></tr>"
                 for c, x in sorted(req["changes"].items()))
    cu = "".join(f"<li>{k} list: {'add' if op == 'add' else 'remove'} <code>{e(u)}</code></li>"
                 for k in ("allow", "block") for op in ("add", "remove") for u in req["custom"][k][op])
    dev = uf.deviations(req)
    body = (f"<h2>URL filter request {e(rid)} {_badge(req['status'])}</h2>"
            f"<p class='muted'>Customer {e(customer)} · profile <b>{e(req['profile'])}</b> on {e(req['target'])}, {e(req['where'])} · "
            f"requested by <b>{e(req['requester'])}</b> {e(req['created'])} (CST)</p>" + (f"<p class='note'>{e(msg)}</p>" if msg else "")
            + stale_note + (f"<p><b>Notes:</b> {e(req['notes'])}</p>" if req["notes"] else "")
            + ("<h3>Category changes</h3><table><tr><th>Category</th><th>Live (at request)</th><th>Requested</th><th>PA recommended</th>"
               f"<th></th></tr>{ch}</table>" if ch else "") + (f"<h3>Allow / block lists</h3><ul>{cu}</ul>" if cu else "")
            + (("<div class='note'><b>Differs from the Palo Alto recommendation:</b><ul>" + "".join(f"<li>{e(d)}</li>" for d in dev)
                + "</ul></div>") if dev else ""))
    if req.get("review_comment") or req.get("reviewer"):
        body += f"<p><b>Reviewer:</b> {e(req.get('reviewer', ''))} {e(req.get('reviewed_at', ''))} — {e(req.get('review_comment', ''))}</p>"
    if req.get("result"):
        body += f"<p><b>Push result:</b> {e(req['result'])}</p>"
    if req.get("verify") or req.get("rollback_verify"):
        body += "<ul>" + "".join(f"<li>{'PASS' if v['ok'] else 'FAIL'} {e(v['check'])} {e(v.get('detail', ''))}</li>"
                                 for v in (req.get("verify") or []) + (req.get("rollback_verify") or [])) + "</ul>"
    a = f"/urlfilter/{e(customer)}/{e(rid)}"
    if user.can("urlfilter_approve"):
        own = req["requester"] == user[0] and not cfg.allow_self_approval
        st = req["status"]
        if st in ("pending", "stale") and stale_note and live is not None or st == "stale":
            body += (f"<form method='post' action='{a}/rebase' class='card'><h3>Re-review against the live profile</h3><p>Recomputes the "
                     "changes against what is live now (drops anything already live). Then review and approve again.</p>"
                     "<button class='secondary'>Re-review</button></form>")
        elif st == "pending" and not own:
            body += (f"<form method='post' action='{a}/approve' class='card'><h3>Approve</h3>"
                     f"<label>Approved CR number (format {e(prof.tickets['cr'])})</label><input name='cr' required size='20'>"
                     "<label>Comment (optional)</label><input name='comment' size='70'><br><button>Approve (re-reads live, builds the change plan)</button></form>")
        elif st == "pending" and own:
            body += "<p class='note'>You made this request, so another approver must approve it.</p>"
        if st in ("pending", "stale", "approved"):
            body += (f"<form method='post' action='{a}/reject' class='card'><h3>Reject</h3><label>Reason (the requester sees it)</label>"
                     "<input name='comment' required size='70'><br><button class='secondary'>Reject</button></form>")
        if st == "approved" and not stale_note:
            if req.get("mode") == "live" and uf.live_allowed(prof, cfg):
                body += (f"<form method='post' action='{a}/push' class='card' style='border:2px solid #b00020'><h3>Push (live)</h3>"
                         f"<p>Writes the change to <b>{e(cfg.target)}</b>, commits"
                         + (f", pushes device group {e(cfg.device_group)}" if cfg.backend == "panorama" else "")
                         + f" and reads it back. CR {e(req.get('cr', ''))}.</p><label>Type the target name <code>{e(cfg.target)}</code> to confirm</label>"
                         "<input name='confirm_target' required><br><button class='danger'>Push</button></form>")
            else:
                body += ("<p class='note'><b>Dry-run only</b> for this customer: implement the change plan below by hand in the CR "
                         "window, then record it in the CR.</p>")
        if st in ("pushed", "failed") and req.get("jobs") and uf.live_allowed(prof, cfg):
            body += (f"<form method='post' action='{a}/rollback' class='card'><h3>Roll back</h3><p>Restores the profile and lists as they "
                     f"were at approval, commits and pushes.</p><label>Type <code>{e(cfg.target)}</code> to confirm</label>"
                     "<input name='confirm_target' required><br><button class='danger'>Roll back</button></form>")
    if req.get("plan_md"):
        body += (f"<h3>CR change plan</h3><p><a href='{a}/changeplan.md'>Download (markdown)</a></p>"
                 f"<pre style='white-space:pre-wrap;background:#f6f6f6;padding:12px'>{e(req['plan_md'])}</pre>")
    hist = "".join(f"<tr><td>{e(h['ts'])}</td><td>{e(h['by'])}</td><td>{e(h['step'])}</td></tr>" for h in req.get("history", []))
    body += f"<h3>History</h3><table><tr><th>When (CST)</th><th>Who</th><th>What</th></tr>{hist}</table>"
    return w.page(f"URL filter {rid}", body, user)


@router.post("/urlfilter/{customer}/{rid}/{action}")
async def act(request: Request, customer: str, rid: str, action: str):
    w = _web()
    if action not in ("approve", "reject", "rebase", "push", "rollback"):
        raise HTTPException(404, "unknown action")
    user = w.need(request, "urlfilter_approve", customer=customer)
    prof, cfg = _ctx(customer, user)
    req = _load(prof, rid)
    form = await request.form()
    back = f"/urlfilter/{quote(customer)}/{quote(rid)}"
    try:
        if action == "reject":
            uf.reject(prof, req, actor=user[0], comment=str(form.get("comment") or ""))
            return RedirectResponse(back + "?msg=Rejected.", 303)
        dev = device_factory(prof, cfg.target)
        if action == "rebase":
            uf.rebase(prof, req, uf.read_live(dev, cfg), actor=user[0])
            msg = "Re-reviewed against the live profile. Check the changes and approve again."
        elif action == "approve":
            uf.approve(prof, cfg, req, dev, actor=user[0], cr=str(form.get("cr") or ""), comment=str(form.get("comment") or ""))
            msg = "Approved. " + ("Push it below." if req["mode"] == "live" else "Dry-run only: use the change plan.")
        else:
            verify = {t: device_factory(prof, t) for t in cfg.verify_targets} if cfg.backend == "panorama" else {}
            fn = uf.push if action == "push" else uf.rollback
            fn(prof, cfg, req, dev, actor=user[0], confirm_target=str(form.get("confirm_target") or ""), verify_devs=verify)
            msg = req.get("result") if action == "push" else req.get("rollback_result")
    except uf.UrlFilterError as exc:
        msg = str(exc)
    except Exception as exc:  # noqa: BLE001  (pusher.PushError from check_cr, device errors)
        msg = str(exc)[:300]
    return RedirectResponse(back + "?msg=" + quote(str(msg or "")[:400]), 303)


@router.get("/urlfilter/{customer}/{rid}/changeplan.md")
def plan_md(request: Request, customer: str, rid: str):
    w = _web()
    user = w.need(request, ANY, customer=customer)
    prof, _ = _ctx(customer, user)
    req = _load(prof, rid)
    if not req.get("plan_md"):
        raise HTTPException(404, "no change plan yet (approve the request first)")
    return PlainTextResponse(req["plan_md"], media_type="text/markdown",
                             headers={"Content-Disposition": f"attachment; filename={rid}-changeplan.md"})
