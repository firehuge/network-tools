# SPDX-License-Identifier: Apache-2.0
"""Users page: per-user permission checkboxes and customer/device scope (MSP/NOC model).

Needs ``user_admin``. Create users (initial password, changed at first login), edit
permission checkboxes and customer/device scope, reset passwords, disable/enable and
delete users. A user admin can only grant permissions and customers they hold
themselves and cannot touch a user who holds more than they do. Nobody can disable,
delete or remove user_admin from themselves, and the last enabled user admin cannot
be disabled, deleted or demoted. Every change is written to the user audit log with
before/after (never a password or hash).
"""

from __future__ import annotations

import html

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from panlab.web import auth, layers

router = APIRouter()
e = html.escape
DIM = " style='color:#888'"


def _web():
    from panlab.web import app as webapp
    return webapp


def _access(rec: dict) -> dict:
    p = auth.Principal("x", rec)
    return {"permissions": sorted(p.perms), "customers": sorted(p.customers), "devices": p.devices}


def _summary(rec: dict) -> str:
    a = _access(rec)
    cust = "all customers" if "*" in a["customers"] else ", ".join(a["customers"]) or "no customers"
    devs = "; ".join(f"{c}: {', '.join(v)}" for c, v in sorted(a["devices"].items()))
    return cust + (f" · devices {devs}" if devs else "")


def _editor(actor, name: str, rec: dict | None, customers: list[str]) -> str:
    a = _access(rec) if rec else {"permissions": ["view"], "customers": [], "devices": {}}
    held = set(a["permissions"])
    perms = "".join(
        f"<label style='font-weight:400'><input type='checkbox' name='perm' value='{p}' {'checked' if p in held else ''}"
        f"{'' if actor.can(p) else ' disabled'}> <b>{p}</b> — {e(d)}</label>" for p, d in auth.PERMS.items())
    allc = "*" in a["customers"]
    custs = (f"<label style='font-weight:400'><input type='checkbox' name='customer' value='*' {'checked' if allc else ''}"
             f"{'' if actor.all_customers() else ' disabled'}> <b>All customers</b> (current and future)</label>")
    for c in customers:
        custs += (f"<label style='font-weight:400'><input type='checkbox' name='customer' value='{e(c)}' "
                  f"{'checked' if c in a['customers'] else ''}> {e(c)}</label>"
                  f"<div style='margin-left:24px'><span class='muted'>Only these devices of {e(c)} (optional; one per line: "
                  "profile target name, hostname, serial, or dg:&lt;device group&gt;; blank = all)</span><br>"
                  f"<textarea name='devices_{e(c)}' rows='2' cols='50'>{e(chr(10).join(a['devices'].get(c, [])))}</textarea></div>")
    head = (f"<input type='hidden' name='username' value='{e(name)}'>" if rec else
            "<label>New user name</label><input name='username' required pattern='[A-Za-z0-9_.-]+' size='24'>"
            "<label>Initial password (at least 12 characters; leave blank to generate one)</label>"
            "<input name='new_password' type='password' minlength='12' autocomplete='new-password'>"
            "<label>Confirm initial password</label><input name='confirm' type='password' minlength='12' autocomplete='new-password'>"
            "<label style='font-weight:400'><input type='checkbox' name='must_change' value='yes' checked> "
            "Must choose a new password at first login</label>")
    action = "/users/access" if rec else "/users/add"
    title = f"Permissions for {e(name)}" if rec else "Add a user"
    note = "" if rec else "<p class='muted'>Tick what the user can do and which customers it applies to. A generated password is shown once.</p>"
    presets = (
        "<h4>Layer preset</h4>"
        "<p class='muted'>Picking a preset ticks the boxes below. It does not save until you click Save. "
        "Existing accounts keep their current boxes until you change them.</p>"
        f"<label>Apply a layer preset</label><select id='layer-preset'>{layers.preset_options_html()}</select>"
        + layers.preset_script()
    )
    return (f"<form method='post' action='{action}' class='card'><h3>{title}</h3>{note}{head}"
            f"{presets}<h4>Can do</h4>{perms}<h4>For</h4>{custs}<br><button>Save</button></form>")


def render(request: Request, msg: str = "", generated: str | None = None, generated_for: str | None = None,
           edit: str = "") -> HTMLResponse:
    w = _web()
    actor = w.need(request, "user_admin")
    users = auth.load_users()
    customers = w.list_customers()
    def _acts(n: str, u: dict) -> str:
        out = f"<a href='/users?edit={e(n)}'>edit</a>"
        if n == actor[0]:
            return out + " <span class='muted'>(you)</span>"
        flip = "enable" if u.get("disabled") else "disable"
        return (out + f" <form method='post' action='/users/{flip}' style='display:inline'>"
                f"<input type='hidden' name='username' value='{e(n)}'><button style='padding:2px 8px'>{flip.title()}</button></form>"
                f" <form method='post' action='/users/delete' style='display:inline' "
                f"onsubmit=\"return confirm('Delete user {e(n)}? This cannot be undone.')\">"
                f"<input type='hidden' name='username' value='{e(n)}'><button class='danger' style='padding:2px 8px'>Delete</button></form>")

    rows = "".join(
        f"<tr{DIM if u.get('disabled') else ''}><td>{e(n)}"
        f"{' <b>(disabled)</b>' if u.get('disabled') else ''}{' <span class=muted>(must change password)</span>' if u.get('must_change_password') else ''}</td>"
        f"<td>{e(layers.layer_label(auth.Principal(n, u)))}</td><td>{e(', '.join(sorted(auth.effective_perms(u))))}</td>"
        f"<td>{e(_summary(u))}</td><td>{_acts(n, u)}</td></tr>"
        for n, u in sorted(users.items()))
    shown = ""
    if generated and generated_for:
        shown = (f"<div class='note'><b>Temporary password for {e(generated_for)}</b> — copy it now; "
                 f"it is not shown again.</div><p><code>{e(generated)}</code></p>")
    note = f"<div class='note'>{e(msg)}</div>" if msg else ""
    editor = _editor(actor, edit, users[edit], customers) if edit in users else _editor(actor, "", None, customers)
    opts = "".join(f"<option value='{e(n)}'>{e(n)}</option>" for n in sorted(users))
    audit_rows = "".join(
        f"<tr><td>{e(str(r.get('ts', '')))}</td><td>{e(str(r.get('actor', '')))}</td>"
        f"<td>{e(str(r.get('action', '')))}</td><td>{e(str(r.get('target', '')))}</td>"
        f"<td>{e(str(r.get('result', '')))}</td><td>{e(str(r.get('reason', '') or _diff(r)))}</td></tr>"
        for r in reversed(auth.read_user_audit()))
    body = (f"<h2>Users</h2>{note}{shown}"
            "<p class='muted'>Each user gets checkboxes for what they can do, and the customers (optionally specific "
            "firewalls or device groups) they can do it for. Out-of-scope customers and devices are hidden and refused "
            "on the server. Upgrading Panorama itself needs <b>upgrade_panorama</b>.</p>"
            "<table><tr><th>User</th><th>Matches layer</th><th>Permissions</th><th>Scope</th><th></th></tr>"
            f"{rows}</table>"
            + ("<p><a href='/users'>+ Add a user</a></p>" if edit in users else "") + editor +
            "<h3>Reset a password</h3><p class='muted'>The user must choose a new password at their next login.</p>"
            "<form method='post' action='/users/reset'>"
            f"<label>User</label><select name='username' required>{opts}</select>"
            "<label>New password (at least 12 characters; leave blank to generate)</label>"
            "<input name='new_password' type='password' minlength='12'>"
            "<label>Confirm new password</label><input name='confirm' type='password' minlength='12'>"
            "<br><button name='action' value='set'>Set password</button> "
            "<button name='action' value='generate'>Generate random password</button></form>"
            "<p class='note'>The new password is stored hashed. Generated passwords are shown once on this page.</p>"
            "<h3>User and permission audit</h3><table><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th>"
            f"<th>Result</th><th>Detail</th></tr>{audit_rows or '<tr><td colspan=6>None yet</td></tr>'}</table>")
    return w.page("users", body, actor)


def _diff(r: dict) -> str:
    b, a = r.get("before") or {}, r.get("after") or {}
    if not isinstance(a, dict) or not a:
        return ""
    out = []
    bp, ap = set(b.get("permissions") or []), set(a.get("permissions") or [])
    if ap - bp:
        out.append("+" + ",".join(sorted(ap - bp)))
    if bp - ap:
        out.append("-" + ",".join(sorted(bp - ap)))
    if b.get("customers") != a.get("customers"):
        out.append("customers=" + ",".join(a.get("customers") or []))
    if (b.get("devices") or {}) != (a.get("devices") or {}):
        out.append("devices=" + "; ".join(f"{k}:{','.join(v)}" for k, v in sorted((a.get("devices") or {}).items())))
    return " ".join(out)


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, edit: str = "", msg: str = "") -> HTMLResponse:
    return render(request, msg=msg, edit=edit)


async def _parse(request: Request, actor) -> tuple[str, list[str], list[str], dict[str, list[str]]]:
    form = await request.form()
    name = str(form.get("username", "")).strip()
    perms = [str(x) for x in form.getlist("perm")]
    custs = [str(x) for x in form.getlist("customer")]
    devices = {}
    for k, v in form.items():
        if k.startswith("devices_"):
            lines = [x.strip() for x in str(v).replace(",", "\n").splitlines() if x.strip()]
            if lines:
                devices[k[len("devices_"):]] = lines
    return name, perms, custs, devices


def _enabled_admins(users: dict) -> list[str]:
    return [n for n, u in users.items() if not u.get("disabled") and "user_admin" in auth.effective_perms(u)]


def last_admin_reason(actor, name: str, users: dict, what: str) -> str | None:
    """Refuse self-lockout and removing the last enabled user admin."""
    if name == actor[0]:
        return f"you cannot {what} yourself; ask another user admin"
    if "user_admin" in auth.effective_perms(users[name]) and not users[name].get("disabled") \
            and _enabled_admins(users) == [name]:
        return f"{name} is the last enabled user admin; give someone else user_admin first"
    return None


def check_grant(actor, target_rec: dict | None, perms: list[str], custs: list[str], devices: dict[str, list[str]]) -> str | None:
    """Anti-escalation rules. Returns a reason string if refused."""
    bad = [p for p in perms if p not in auth.PERMS]
    if bad:
        return f"unknown permission {bad[0]}"
    if not set(perms) <= actor.perms:
        return "you cannot grant permissions you do not have: " + ", ".join(sorted(set(perms) - actor.perms))
    if not actor.all_customers():
        if "*" in custs:
            return "only a user with all customers can grant all customers"
        extra = [c for c in custs if not actor.sees_customer(c)] + [c for c in devices if not actor.sees_customer(c)]
        if extra:
            return f"customer {extra[0]} is not in your scope"
    if target_rec is not None:
        t = auth.Principal("t", target_rec)
        if not t.perms <= actor.perms or (t.all_customers() and not actor.all_customers()) or \
                any(not actor.sees_customer(c) for c in t.customers if c != "*"):
            return "this user has access you do not have; ask someone with at least the same access"
    return None


@router.post("/users/access", response_class=HTMLResponse)
async def users_access(request: Request) -> HTMLResponse:
    w = _web()
    actor = w.need(request, "user_admin")
    name, perms, custs, devices = await _parse(request, actor)
    users = auth.load_users()
    ip = w._client_ip(request)
    if name not in users:
        auth.write_user_audit(actor=actor[0], action="permissions_change", target=name, result="rejected", reason="no_such_user", ip=ip)
        return render(request, msg="No such user.")
    before = _access(users[name])
    devices = {c: v for c, v in devices.items() if c in custs or "*" in custs}
    why = check_grant(actor, users[name], perms, custs, devices)
    if why is None and "user_admin" in before["permissions"] and "user_admin" not in perms:
        why = last_admin_reason(actor, name, users, "remove user_admin from")
    if why:
        auth.write_user_audit(actor=actor[0], action="permissions_change", target=name, result="denied", reason=why, ip=ip)
        raise HTTPException(403, why)
    after = auth.set_access(name, perms, custs, devices)
    after = {k: after[k] for k in ("permissions", "customers", "devices")}
    auth.write_user_audit(actor=actor[0], action="permissions_change", target=name, result="ok",
                          before=before, after=after, ip=ip)
    return render(request, msg=f"Saved permissions for {name}.", edit=name)


@router.post("/users/add", response_class=HTMLResponse)
async def users_add(request: Request) -> HTMLResponse:
    w = _web()
    actor = w.need(request, "user_admin")
    name, perms, custs, devices = await _parse(request, actor)
    ip = w._client_ip(request)
    import re
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name or ""):
        return render(request, msg="User names may use letters, digits, dot, dash and underscore.")
    if name in auth.load_users():
        auth.write_user_audit(actor=actor[0], action="user_add", target=name, result="rejected", reason="exists", ip=ip)
        return render(request, msg="That user already exists; edit it instead.", edit=name)
    devices = {c: v for c, v in devices.items() if c in custs or "*" in custs}
    why = check_grant(actor, None, perms, custs, devices)
    if why:
        auth.write_user_audit(actor=actor[0], action="user_add", target=name, result="denied", reason=why, ip=ip)
        raise HTTPException(403, why)
    form = await request.form()
    pw, confirm = str(form.get("new_password") or ""), str(form.get("confirm") or "")
    must = form.get("must_change") == "yes"
    generated = None
    if pw:
        err = auth.validate_new_password(pw, confirm)
        if err:
            auth.write_user_audit(actor=actor[0], action="user_add", target=name, result="rejected", reason="invalid_password", ip=ip)
            return render(request, msg=err)
    else:
        pw = generated = auth.generate_password()
    auth.add_user(name, "viewer", pw, permissions=perms, customers=custs or [], devices=devices, must_change=must)
    auth.write_user_audit(actor=actor[0], action="user_add", target=name, result="ok", must_change=must,
                          method="generate" if generated else "set",
                          after={"permissions": sorted(perms), "customers": sorted(custs), "devices": devices}, ip=ip)
    return render(request, msg=f"User {name} added." + (" They must choose a new password at first login." if must else ""),
                  generated=generated, generated_for=name if generated else None, edit=name)


async def _target(request: Request, action: str):
    w = _web()
    actor = w.need(request, "user_admin")
    form = await request.form()
    name = str(form.get("username", "")).strip()
    users = auth.load_users()
    ip = w._client_ip(request)
    if name not in users:
        auth.write_user_audit(actor=actor[0], action=action, target=name, result="rejected", reason="no_such_user", ip=ip)
        raise HTTPException(404, "no such user")
    return actor, name, users, ip


def _refuse(actor, name, action, ip, why):
    auth.write_user_audit(actor=actor[0], action=action, target=name, result="denied", reason=why, ip=ip)
    raise HTTPException(403, why)


@router.post("/users/disable", response_class=HTMLResponse)
async def users_disable(request: Request) -> HTMLResponse:
    actor, name, users, ip = await _target(request, "user_disable")
    why = last_admin_reason(actor, name, users, "disable") or check_grant(actor, users[name], [], [], {})
    if why:
        _refuse(actor, name, "user_disable", ip, why)
    auth.set_flag(name, "disabled", True)
    auth.write_user_audit(actor=actor[0], action="user_disable", target=name, result="ok", ip=ip)
    return render(request, msg=f"{name} is disabled and can no longer log in (open sessions end on their next click).")


@router.post("/users/enable", response_class=HTMLResponse)
async def users_enable(request: Request) -> HTMLResponse:
    actor, name, users, ip = await _target(request, "user_enable")
    why = check_grant(actor, users[name], [], [], {})
    if why:
        _refuse(actor, name, "user_enable", ip, why)
    auth.set_flag(name, "disabled", False)
    auth.write_user_audit(actor=actor[0], action="user_enable", target=name, result="ok", ip=ip)
    return render(request, msg=f"{name} is enabled again.")


@router.post("/users/delete", response_class=HTMLResponse)
async def users_delete(request: Request) -> HTMLResponse:
    actor, name, users, ip = await _target(request, "user_delete")
    why = last_admin_reason(actor, name, users, "delete") or check_grant(actor, users[name], [], [], {})
    if why:
        _refuse(actor, name, "user_delete", ip, why)
    before = _access(users[name])
    auth.remove_user(name)
    auth.write_user_audit(actor=actor[0], action="user_delete", target=name, result="ok", before=before, ip=ip)
    return render(request, msg=f"User {name} deleted.")
