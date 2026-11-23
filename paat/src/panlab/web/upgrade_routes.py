"""GUI for OS upgrades: /upgrade wizard (discover -> pick -> plan) and the red-bar run page.

Permissions: ``upgrade_plan`` runs read-only discovery and builds dry-run plans;
``upgrade_exec`` arms a plan (approved CR) and runs its steps. Each user only sees
and touches the customers and devices in their scope; Panorama itself needs
``upgrade_panorama``. Every check is made on the server, on every request.
"""

from __future__ import annotations

import html
import json

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

from panlab import identity
from panlab.customers import load_profile
from panlab.upgrade import paths, planner, runner
from panlab.upgrade.crplan import render_cr
from panlab.upgrade.versions import Available, group_by_train
from panlab.web import auth, theme, upgrade_view as uv

router = APIRouter()
e = html.escape
LIGHT = {"green": "#1a7f37", "yellow": "#9a6700", "red": "#b00020"}
WORD = {"green": "GOOD", "yellow": "CHECK", "red": "STOP"}
CSS = "<style>.chk li{margin:3px 0}</style>"


def _web():
    from panlab.web import app as webapp  # late import: app.py includes this router
    return webapp


def _light(level: str) -> str:
    return f"<span class='lt' style='background:{LIGHT.get(level, '#555')}'>{WORD.get(level, level.upper())}</span>"


def _checks(checks: list[dict]) -> str:
    return "<ul class='chk'>" + "".join(f"<li>{_light(c['level'])} <b>{e(c['title'])}</b>. {e(c.get('detail', ''))}</li>"
                                        for c in checks) + "</ul>"


UPG_ANY = ("upgrade_plan", "upgrade_exec")
REPORT_ANY = ("view", "upgrade_plan", "upgrade_exec")


def device_allowed(user, customer: str, f: dict) -> bool:
    """May this user plan/run an upgrade of this discovered device (or plan device entry)?"""
    if f.get("kind") == "panorama" and not user.can("upgrade_panorama"):
        return False
    idn = f.get("identity") or {}
    target = f.get("profile_target") or ((f.get("connect") or {}).get("target") if not (f.get("connect") or {}).get("serial") else "")
    return auth.device_in_scope(user.device_scope(customer), target=target or "", hostname=idn.get("hostname") or f.get("hostname") or "",
                                serial=idn.get("serial") or f.get("serial") or "", device_groups=f.get("device_groups") or ())


def device_visible(user, customer: str, f: dict) -> bool:
    """Shown on the discovery page: in scope, or a Panorama (read-only, so 'Panorama first' is visible)."""
    return device_allowed(user, customer, f) or f.get("kind") == "panorama"


def plan_allowed(user, plan: dict) -> bool:
    return all(device_allowed(user, plan.get("customer", ""), d) for d in plan.get("devices") or [])


def _guard_plan(user, plan: dict) -> None:
    if not plan_allowed(user, plan):
        raise HTTPException(403, "this plan includes a device outside your scope or permissions")


def _prof(customer: str):
    try:
        return load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")


@router.get("/upgrade", response_class=HTMLResponse)
def upgrade_home(request: Request, customer: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, UPG_ANY)
    opts = "".join(f"<option {'selected' if c == customer else ''}>{e(c)}</option>" for c in w.list_customers())
    recent = ""
    if customer:
        prof = _prof(customer)
        plans = []
        for p in planner.list_plans(prof):
            try:
                if plan_allowed(user, planner.load_plan(prof, p)):
                    plans.append(p)
            except (ValueError, FileNotFoundError):
                continue
            if len(plans) >= 10:
                break
        recent = "<h3>Recent plans</h3><ul>" + "".join(
            f"<li><a href='/upgrade/{e(customer)}/plan/{e(p)}'>{e(p)}</a></li>" for p in plans) + "</ul>" if plans else ""
    body = (CSS + (f"<h2>Customer: {e(customer)}</h2><h3>OS upgrades</h3>" if customer else "<h2>OS upgrades</h2>") +
            theme.help_note("os-upgrades.md", "Discover reads each device (read-only). Pick chooses a version; older versions of a firewall's own train are "
                            "offered as a downgrade. Build the plan runs the checks. Nothing changes until a plan is armed and every step is confirmed.") +
            "<div class='note'><b>Step 1 of 3: Discover.</b> The tool asks each device (read-only) what it runs, which versions it "
            "can install, its HA state, disk space, content version and whether anyone has uncommitted changes. For a Panorama it "
            "also finds every firewall connected to it. Nothing is changed on any device in this step.</div>"
            "<form method='post' action='/upgrade/discover'><label>Customer</label>"
            f"<select name='customer'>{opts}</select>"
            "<label><input type='checkbox' name='refresh' value='yes' checked> Ask the update server for the newest list "
            "(<code>request system software check</code>)</label>"
            "<br><button>Discover devices (read-only)</button></form>" + recent)
    return w.page("OS upgrades", body, user)


@router.post("/upgrade/discover")
def upgrade_discover(request: Request, customer: str = Form(...), refresh: str = Form("")):
    w = _web()
    user = w.need(request, "upgrade_plan", customer=customer)
    prof = _prof(customer)
    snap = planner.discover_customer(prof, actor=user[0], refresh=refresh == "yes")
    return RedirectResponse(f"/upgrade/{customer}/disc/{snap['id']}", status_code=303)


def _picker(did: str, f: dict, ceiling: str = "") -> str:
    rec = (f.get("recommended") or {}).get("version")
    cur = f.get("sw_version", "")
    av = [Available(**a) for a in f.get("available") or []]
    groups = []
    from panlab.upgrade.versions import V
    older: list[str] = []
    for tv in group_by_train(av):
        opts = []
        for a in tv.versions:
            if V(a.version) <= V(cur):
                # Downgrade: firewalls only, inside the train they run now (see panlab.upgrade.versions)
                if V(a.version) < V(cur) and f.get("kind") == "firewall" and V(a.version).train_key == V(cur).train_key \
                        and V(a.version).suffix in ("", "h"):
                    older.append(f"<option value='{e(a.version)}'>{e(a.version)}{' (downloaded)' if a.downloaded else ''}</option>")
                continue
            tag = " (recommended)" if a.version == rec else (" (downloaded)" if a.downloaded else "")
            if ceiling and V(a.version) > V(ceiling):
                tag = f" (blocked: newer than Panorama {ceiling})"
            opts.append(f"<option value='{e(a.version)}' {'selected' if a.version == rec else ''}>{e(a.version)}{tag}</option>")
        if opts:
            groups.append(f"<optgroup label='{e(tv.train)}.x'>{''.join(opts)}</optgroup>")
    if older:
        groups.append(f"<optgroup label='Older versions: DOWNGRADE (same {e(V(cur).train)} train only)'>{''.join(older)}</optgroup>")
    return (f"<select name='v::{e(did)}'><option value=''>(leave as is)</option>{''.join(groups)}</select>"
            if groups else "<i>Nothing newer offered</i>")


YBOX = "border-left:4px solid #9a6700;padding:4px 8px;margin:6px 0;background:#fff8e1"


def _ident_html(name: str, idn: dict | None) -> str:
    """Device headline: reported hostname + serial; profile name small and grey (see identity.html_label)."""
    return identity.html_label(name, idn)


def _path_html(d: dict) -> str:
    """'via Panorama <hostname · serial>' (or direct) for a plan device."""
    if d.get("kind") != "firewall":
        return ""
    txt = d.get("path_text") or paths.describe(d)
    style = "color:#b00020" if "DIRECT" in txt else "color:#0b5394"
    return f"<div style='{style};font-size:13px'>Upgrade path: <b>{e(txt)}</b></div>"


def _dest_html(prof) -> str:
    labels, has_off = runner.backup_destinations(prof)
    txt = "Backed up to: " + ", ".join(labels) + "."
    if not has_off:
        txt += " No off-box backup destination is configured for this customer; use Download backup after this step."
    return f"<div class='muted'>{e(txt)}</div>"


def backup_files(prof, plan: dict, n: int | None = None):
    return runner.backup_files(prof, plan, n)


def _zip_response(prof, user, plan: dict, files, name: str, step: int | None) -> Response:
    import io
    import zipfile

    if not files:
        raise HTTPException(404, "no backup files for this run yet")
    buf = io.BytesIO()
    root = prof.data_dir("upgrade-backups").resolve()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            z.write(p, str(p.relative_to(root)))
    runner.audit(prof, actor=user[0], action="upgrade-backup-download", plan=plan["id"], step=step,
                 files=[p.name for p in files], target=", ".join(runner._dlabel(d) for d in plan["devices"]))
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/upgrade/{customer}/run/{pid}/backup/{n}.zip")
def upgrade_backup_zip(request: Request, customer: str, pid: str, n: int) -> Response:
    w = _web()
    user = w.need(request, UPG_ANY)
    prof = _prof(customer)
    plan = _load(prof, pid)
    _guard_plan(user, plan)
    s = next((x for x in plan["steps"] if x["n"] == n and x["action"] == "backup"), None)
    if s is None:
        raise HTTPException(404)
    d = runner._dev(plan, s["device"])
    tag = "_".join(x for x in (d.get("hostname"), d.get("serial")) if x) or d.get("name") or "device"
    return _zip_response(prof, user, plan, backup_files(prof, plan, n), f"{pid}_{tag}_backup.zip", n)


@router.get("/upgrade/{customer}/run/{pid}/backups.zip")
def upgrade_backups_zip(request: Request, customer: str, pid: str) -> Response:
    w = _web()
    user = w.need(request, UPG_ANY)
    prof = _prof(customer)
    plan = _load(prof, pid)
    _guard_plan(user, plan)
    return _zip_response(prof, user, plan, backup_files(prof, plan), f"{pid}_backups.zip", None)


def _plan_ident(d: dict) -> dict:
    return d.get("identity") or {"hostname": d.get("hostname"), "serial": d.get("serial")}


@router.get("/upgrade/{customer}/disc/{sid}", response_class=HTMLResponse)
def upgrade_snapshot(request: Request, customer: str, sid: str) -> HTMLResponse:
    w = _web()
    user = w.need(request, "upgrade_plan")
    prof = _prof(customer)
    try:
        snap = planner.load_snapshot(prof, sid)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404)
    cards = []
    hidden = 0
    for did in snap["order"]:
        f = snap["devices"][did]
        if not device_visible(user, customer, f):
            hidden += 1
            continue
        if f.get("reachable") and not device_allowed(user, customer, f):
            cards.append(f"<div class='card' style='background:#f6f8fa'>{_ident_html(f.get('name') or did, planner.device_identity(f))} "
                         f"<span class='muted'>{e(f.get('kind'))} · running <b>{e(f.get('sw_version'))}</b> · read-only for you "
                         "(upgrading Panorama needs the upgrade_panorama permission, or it is outside your scope). "
                         "Firewalls cannot be planned above this version.</span></div>")
            continue
        if not f.get("reachable"):
            cards.append(f"<div class='card'>{_light('red')} {_ident_html(f.get('name') or did, f.get('identity'))}: did not answer. "
                         f"{e('; '.join(f.get('errors') or []))}</div>")
            continue
        rec = f.get("recommended") or {}
        ha = f.get("ha") or {}
        mp = snap["devices"].get(f.get("managed_by") or "", {})
        mb = f" · managed by {e(identity.label(mp.get('name', ''), planner.device_identity(mp)))}" if mp else ""
        mb += f" · upgrade path: <b>{e(paths.describe(f))}</b>" if f.get("kind") == "firewall" else ""
        warn = "".join(f"<div class='yellow' style='border-left:4px solid #9a6700;padding:4px 8px;margin:6px 0'>{e(x)}</div>"
                       for x in f.get("warnings") or [])
        cards.append(
            f"<div class='card'><label style='margin:0'><input type='checkbox' name='pick' value='{e(did)}' "
            f"{'checked' if rec.get('version') else ''}> {_ident_html(f.get('name') or did, planner.device_identity(f))}</label> "
            f"<span class='muted'>{e(f.get('kind'))} · {e(f.get('model') or '')}{mb}</span>"
            f"<p>Running <b>{e(f.get('sw_version'))}</b> · content {e(f.get('app_version') or '?')} · "
            f"HA {'on, ' + e(ha.get('local_state') or '?') if ha.get('enabled') else 'off'} · "
            f"uncommitted changes: {'YES' if f.get('pending_changes') else 'no'} · "
            f"free disk {int((f.get('disk') or {}).get('repo_free_mb') or 0)} MB</p>"
            f"<p>Newest hotfix of {e(f.get('sw_version', '').split('-')[0])}: <b>{e(rec.get('latest_same_release') or '-')}</b> · "
            f"newest in the {e(f.get('train', ''))} train: <b>{e(rec.get('latest_in_train') or '-')}</b></p>"
            f"<p class='muted'>{e(rec.get('why') or '')}</p>{warn}"
            f"<label>Target version (recommended is preselected)</label>{_picker(did, f, (mp.get('sw_version') or '') if f.get('kind') == 'firewall' else '')}</div>")
    body = (CSS + f"<h2>Customer: {e(customer)}</h2><h3>OS upgrades: discovery</h3><p class='muted'>Discovery {e(sid)} at {e(snap['created'])} by {e(snap['by'])}</p>"
            "<div class='note'><b>Step 2 of 3: Pick.</b> Tick the devices to upgrade and check the target version. The recommended "
            "version is the newest release in the train the device already runs. Panorama is always planned first, and the tool "
            "will refuse any firewall target newer than its Panorama. To go <b>back</b> to an earlier hotfix, pick it from the "
            "<i>Older versions: DOWNGRADE</i> group of a firewall's list; that plan carries a yellow item you must acknowledge. "
            "Panorama itself is never downgraded here.</div>"
            + (f"<p class='muted'>{hidden} device(s) outside your scope are hidden.</p>" if hidden else "")
            + f"<form method='post' action='/upgrade/{e(customer)}/disc/{e(sid)}/plan'>{''.join(cards)}"
            "<button>Build the plan (dry run)</button></form>")
    return w.page("OS upgrades", body, user)


@router.post("/upgrade/{customer}/disc/{sid}/plan")
async def upgrade_build(request: Request, customer: str, sid: str):
    w = _web()
    user = w.need(request, "upgrade_plan")
    prof = _prof(customer)
    form = await request.form()
    picks = form.getlist("pick")
    sel = {p: str(form.get(f"v::{p}") or "") for p in picks}
    sel = {k: v for k, v in sel.items() if v}
    if not sel:
        raise HTTPException(400, "Tick at least one device and pick a target version.")
    try:
        snap = planner.load_snapshot(prof, sid)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404)
    denied = [k for k in sel if k not in snap["devices"] or not device_allowed(user, customer, snap["devices"][k])]
    if denied:
        raise HTTPException(403, "not in your scope or permissions: " + ", ".join(denied))
    try:
        plan = planner.build_plan(prof, snap, sel, actor=user[0])
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(400, str(exc))
    return RedirectResponse(f"/upgrade/{customer}/plan/{plan['id']}", status_code=303)


def _eta(plan: dict) -> str:
    """Rough wall-clock for the plan: ~25 min per reboot (PA-VM 10 to 25), plus a few minutes of other steps."""
    reboots = sum(1 for s in plan["steps"] if s["action"] == "reboot")
    lo, hi = 5 + 12 * reboots, 10 + 28 * reboots
    return f"{lo} to {hi} minutes"


def _load(prof, pid: str) -> dict:
    try:
        return planner.load_plan(prof, pid)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404)


@router.get("/upgrade/{customer}/plan/{pid}", response_class=HTMLResponse)
def upgrade_plan(request: Request, customer: str, pid: str, msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, UPG_ANY)
    prof = _prof(customer)
    plan = _load(prof, pid)
    _guard_plan(user, plan)
    if plan.get("mode") == "live":
        return RedirectResponse(f"/upgrade/{customer}/run/{pid}", status_code=303)
    devs = "".join(f"<div class='card'>{_light(d['status'])} {_ident_html(d['name'], _plan_ident(d))} ({e(d['kind'])}) {uv.change_badge(d)}{e(d['current'])} &rarr; "
                   f"<b>{e(d['target'])}</b>{_path_html(d)}{_checks(d['checks'])}</div>" for d in plan["devices"])
    dest_txt = _dest_html(prof)
    steps = "<ol>" + "".join(f"<li><b>{e(s['title'])}</b>. <span class='muted'>{e(s['explain'])}</span>"
                             + (dest_txt if s["action"] == "backup" else "") + "</li>" for s in plan["steps"]) + "</ol>"
    arm = ""
    if plan["blocked"]:
        arm = "<div class='note' style='border-color:#b00020'><b>This plan is blocked (red).</b> Fix the red items, run discovery again and rebuild.</div>"
    elif user.can("upgrade_exec"):
        arm = (f"<h3>Step 3 of 3: Run it</h3>"
               + ("" if runner.execute_enabled() else "<div class='note'>Live upgrades are switched off on this server. Use the change "
                  "plan to do it by hand.</div>")
               + f"<form method='post' action='/upgrade/{e(customer)}/plan/{e(pid)}/arm'>"
               f"<label>Approved CR number (format {e(prof.tickets['cr'])})</label><input name='cr' required size='20'>"
               "<label><input type='checkbox' name='approved' value='yes' required> This CR is approved and I am inside its change window</label>"
               "<label><input type='checkbox' name='ack' value='yes'> I have read every yellow item above</label>"
               "<br><button class='danger'>Arm for live upgrade</button></form>")
    legend = ("<div class='note'><b>How to read this plan.</b> Each device has <b>pre-checks</b>: "
              f"{_light('green')} fine, {_light('yellow')} read it and acknowledge it when you arm, {_light('red')} blocks the plan "
              "until fixed. Below the checks is the exact list of steps. Each step is run by you, one at a time, and each one "
              "asks you to type the device's name. Nothing runs until the plan is armed in step 3. Allow about "
              f"{_eta(plan)} for a firewall reboot included; a firewall passes no traffic while it reboots (unless an HA peer "
              "carries it).</div>")
    body = (CSS + f"<h2>Customer: {e(customer)}</h2><h3>Upgrade plan {e(pid)}</h3>" + (f"<div class='note'>{e(msg)}</div>" if msg else "")
            + f"<p>Overall: {_light(plan['status_light'])} · mode <b>{e(plan['mode'])}</b> · "
            f"<a href='/upgrade/{e(customer)}/plan/{e(pid)}/changeplan.md'>CR change plan (.md)</a></p>"
            + theme.help_note("os-upgrades.md", "Green is fine, yellow must be read and acknowledged, red blocks the plan. Arming attaches an approved CR; "
                              "nothing runs until then.")
            + legend + devs + "<h3>Steps (in this order, one device at a time)</h3>" + steps + arm)
    return w.page("upgrade plan", body, user)


@router.post("/upgrade/{customer}/plan/{pid}/arm")
def upgrade_arm(request: Request, customer: str, pid: str, cr: str = Form(""), approved: str = Form(""), ack: str = Form("")):
    w = _web()
    user = w.need(request, "upgrade_exec")
    prof = _prof(customer)
    plan = _load(prof, pid)
    _guard_plan(user, plan)
    try:
        runner.arm(prof, plan, actor=user[0], cr=cr, approved=approved == "yes", ack_yellow=ack == "yes")
    except runner.UpgradeRefused as exc:
        return upgrade_plan(request, customer, pid, msg=f"Refused: {exc}")
    return RedirectResponse(f"/upgrade/{customer}/run/{pid}", status_code=303)


@router.get("/upgrade/{customer}/run/{pid}", response_class=HTMLResponse)
def upgrade_run(request: Request, customer: str, pid: str, msg: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, "upgrade_exec")
    prof = _prof(customer)
    plan = _load(prof, pid)
    _guard_plan(user, plan)
    if plan.get("mode") != "live":
        return RedirectResponse(f"/upgrade/{customer}/plan/{pid}", status_code=303)
    plan = runner.poll(prof, plan)
    nxt = runner.next_step(plan)
    rows = []
    icon = {"ok": "&#9989;", "failed": "&#10060;", "running": "&#9203;", "pending": "&#9711;"}
    for s in plan["steps"]:
        j = (s.get("jobs") or [{}])[-1]
        extra = f" job {e(str(j.get('jobid')))} {e(j.get('status', ''))} {e(str(j.get('progress', '')))}%" if j else ""
        err = (f"<div style='color:#b00020'>{e(s.get('error', ''))}</div>" + (f"<div><b>What to do:</b> {e(s['hint'])}</div>" if s.get("hint") else "")) if s.get("error") else ""
        wait = f"<div class='muted'>{e(s['waiting'])}</div>" if s.get("waiting") else ""
        for r in s.get("offsite") or []:
            if r["ok"]:
                wait += f"<div class='muted'>Off-box copy OK: {e(r['name'])} ({e(r['type'])}), {len(r['files'])} file(s) verified</div>"
            else:
                wait += (f"<div style='{YBOX}'><b>CHECK: off-box copy to {e(r['name'])} ({e(r['type'])}) failed.</b> "
                         f"{e(r['error'])} The local backup is kept and the upgrade can continue.</div>")
        if s["action"] == "backup":
            wait += _dest_html(prof)
            if backup_files(prof, plan, s["n"]):
                _, has_off = runner.backup_destinations(prof)
                wait += (f"<div><a class='btn' href='/upgrade/{e(customer)}/run/{e(pid)}/backup/{s['n']}.zip'>Download backup</a>"
                         + ("" if has_off else " <span class='muted'>No off-box destination is configured, so keep this download "
                            "with the CR.</span>") + "</div>")
        wait += (uv.checks_details(s) if s["action"] == "precheck" else "") + (uv.results_table(s) if s["action"] == "postcheck" else "")
        wait += uv.timing(s)
        rows.append(f"<tr><td>{s['n']}</td><td>{icon.get(s['status'], '')} {e(s['status'])}</td><td><b>{e(s['title'])}</b>"
                    + (f"<div class='muted'>{e(s.get('device_label') or '')}</div>" if s.get("device_label") and s.get("device_label") not in s["title"] else "")
                    + f"<div class='muted'>{e(s['explain'])}</div>{err}{wait}</td><td>{extra}</td></tr>")
    action = ""
    refresh = ""
    if plan["status"] == "stopped":
        action = ("<div class='note' style='border-color:#b00020'><b>Stopped.</b> A step failed, so nothing else will run. Read the "
                  "error and 'What to do', fix it, then run discovery again and build a new plan. If a device is unhealthy, use the "
                  "Backout Plan in the change plan.</div>")
    elif plan["status"] == "complete":
        action = ("<div class='note'><b>Done.</b> Every device passed its post-check. Download the report and attach it to the CR."
                  + (f" <a class='btn' href='/upgrade/{e(customer)}/run/{e(pid)}/backups.zip'>Download backups (zip)</a>"
                     if backup_files(prof, plan) else "") + "</div>" + uv.before_after(plan))
    elif nxt and nxt["status"] == "running":
        refresh = "<meta http-equiv='refresh' content='15'>"
        action = f"<div class='note'>Step {nxt['n']} is running on the device. This page refreshes every 15 seconds.</div>"
    elif nxt:
        word = runner.confirm_word(nxt)
        what = ("the hostname the device reports" if word == nxt.get("hostname") else
                "the serial number" if word == nxt.get("serial") else "the device name")
        action = (f"<div class='note'><b>Next: step {nxt['n']}: {e(nxt['title'])}.</b> {e(nxt['explain'])}"
                  f"<p>This step touches {_ident_html(nxt['device_name'], _plan_ident(runner._dev(plan, nxt['device'])))}"
                  f" · <b>{e(nxt.get('path_text') or runner._dev(plan, nxt['device']).get('path_text') or '')}</b></p></div>"
                  f"<form method='post' action='/upgrade/{e(customer)}/run/{e(pid)}/next'>"
                  f"<label>Type {what}, <code>{e(word)}</code>, to confirm</label><input name='confirm' required autocomplete='off'>"
                  f"<br><button class='danger'>Run step {nxt['n']}</button></form>")
    body = (refresh + CSS + f"<h2>Customer: {e(customer)}</h2><h3>Live upgrade {e(pid)}</h3>" + (f"<div class='note'>{e(msg)}</div>" if msg else "")
            + f"<p>CR <b>{e(plan.get('cr', ''))}</b> · armed by {e(plan.get('armed_by', ''))} · status <b>{e(plan['status'])}</b> · "
            f"<a href='/upgrade/{e(customer)}/plan/{e(pid)}/report.md'>report.md</a> · "
            f"<a href='/upgrade/{e(customer)}/plan/{e(pid)}/report.json'>report.json</a> · "
            f"<a href='/upgrade/{e(customer)}/plan/{e(pid)}/changeplan.md'>change plan</a></p>"
            + "<h3>Devices</h3><ul>" + "".join(f"<li>{_ident_html(d['name'], _plan_ident(d))} {uv.change_badge(d)}{e(d['current'])} &rarr; "
                                              f"{e(d['target'])}{_path_html(d)}</li>" for d in plan["devices"]) + "</ul>"
            + theme.help_note("os-upgrades.md", "One step at a time: press Run step and type the device's hostname. The reboot wait is normally 10 to 25 "
                              "minutes; the page reloads every 15 seconds and you can close it and come back.")
            + uv.progress_html(plan) + uv.now_panel(plan, nxt) + action + "<table><tr><th>#</th><th>Status</th><th>Step</th><th>Job</th></tr>" + "".join(rows) + "</table>")
    return w.page("live upgrade", body, user, push=True)


@router.post("/upgrade/{customer}/run/{pid}/next")
def upgrade_next(request: Request, customer: str, pid: str, confirm: str = Form("")):
    w = _web()
    user = w.need(request, "upgrade_exec")
    prof = _prof(customer)
    plan = _load(prof, pid)
    _guard_plan(user, plan)
    try:
        runner.start_step(prof, plan, actor=user[0], confirm=confirm)
    except runner.UpgradeRefused as exc:
        return upgrade_run(request, customer, pid, msg=f"Refused: {exc}")
    return RedirectResponse(f"/upgrade/{customer}/run/{pid}", status_code=303)


@router.get("/upgrade/{customer}/plan/{pid}/changeplan.md")
def upgrade_changeplan(request: Request, customer: str, pid: str) -> PlainTextResponse:
    w = _web()
    user = w.need(request, REPORT_ANY)
    plan = _load(_prof(customer), pid)
    _guard_plan(user, plan)
    return PlainTextResponse(render_cr(plan), media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="{pid}-changeplan.md"'})


@router.get("/upgrade/{customer}/plan/{pid}/report.{fmt}")
def upgrade_report(request: Request, customer: str, pid: str, fmt: str) -> PlainTextResponse:
    w = _web()
    user = w.need(request, REPORT_ANY)
    prof = _prof(customer)
    plan = _load(prof, pid)
    _guard_plan(user, plan)
    if fmt not in ("md", "json"):
        raise HTTPException(404)
    md, js = runner.write_report(prof, plan)
    p = md if fmt == "md" else js
    return PlainTextResponse(p.read_text(encoding="utf-8"), media_type="text/markdown" if fmt == "md" else "application/json",
                             headers={"Content-Disposition": f'attachment; filename="{p.name}"'})
