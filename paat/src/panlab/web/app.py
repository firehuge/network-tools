# SPDX-License-Identifier: Apache-2.0
"""PAAT web GUI (package panlab): prep area (upload FCRs, preview) and the separate push area.

Login required (local users, see ``auth.py``). viewer: read change sets;
prep: upload FCRs and backup files; engineer/admin: push. The prep area
uses each customer's offline or cached config, an uploaded backup, or
(if chosen) a read-only live export. Change sets built from a backup are
plan-only and cannot be pushed. Change sets are saved under the
customer's data directory (``PANLAB_DATA_DIR``).

The push area (``/push/...``, red bar) is the only part that connects to a
device; see ``panlab.pusher`` for the flow and audit log.

Run: uvicorn panlab.web.app:app --host 127.0.0.1 --port 8080 (nginx on :80 in front)
"""

from __future__ import annotations

import html
import json
import re
import tempfile
import time
from datetime import datetime
from urllib.parse import quote, urlencode
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response

from panlab import __version__, brand
from panlab.changeset import build_changeset, requests_from_changeset
from panlab.combine import apply_reuse_choice
from panlab.decom import build_decom_changeset, is_decom, parse_item_text, parse_item_xlsx
from panlab.web import decom_view
from panlab.changeplan import changeplan_sections, load_configs, render_changeplan
from contextvars import ContextVar

from panlab.customers import list_customers as _all_customers, load_profile
from panlab.fcr import Tickets, read_fcr
from panlab.report import to_html, write_outputs
from panlab.sources import list_customer_firewalls, load_customer_envs, stored_config_paths
from panlab import uploads
from panlab.web import approval, auth, dashboard, layers, multiplace, theme
from panlab.web.blast_radius import html_block as blast_html
from panlab.web.workflow import html_block as stepper_html
from panlab import denylog, identity, pusher

app = FastAPI(title=f"{brand.NAME}: {brand.LONG_NAME}", description=brand.DESCRIPTION, version=__version__,
              docs_url=None, redoc_url=None)
STEM_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
MAX_BYTES = 10 * 1024 * 1024
e = html.escape

CSS = theme.CSS
RED = ("<div class='redbar' role='alert'>" + theme.icon("alert") +
       "PUSH AREA: actions here change a live firewall. Approved CR required. Every step is audited.</div>")
device_factory = pusher.connect_target  # tests replace this with a fake device
log_factory = denylog.connect_logs  # read-only traffic-log access; tests replace it


def page(title: str, body: str, user: tuple[str, str] | None = None, push: bool = False,
         status_code: int = 200, path: str | None = None) -> HTMLResponse:
    """Wrap ``body`` in the shared layout: grouped sidebar (permission-filtered), top bar with breadcrumbs, one stylesheet."""
    path = _CURRENT_PATH.get() if path is None else path
    return HTMLResponse(theme.document(title, body, user, path, push, __version__, RED if push else ""), status_code=status_code)


_CURRENT_USER: ContextVar = ContextVar("panlab_user", default=None)
_CURRENT_PATH: ContextVar = ContextVar("panlab_path", default="")


def list_customers() -> list[str]:
    """Customers the signed-in user may see (all of them outside a request)."""
    u = _CURRENT_USER.get()
    names = _all_customers()
    return names if u is None else [c for c in names if u.sees_customer(c)]


def need(request: Request, role: str | tuple[str, ...], customer: str | None = None) -> "auth.Principal":
    """Signed-in user holding ``role`` (a permission name, or a legacy role name mapped to its permission).

    The customer in the path, query string or ``customer`` argument must be in the user's scope.
    """
    u = auth.read_cookie(request.cookies.get(auth.COOKIE))
    if u is None:
        raise HTTPException(303, headers={"Location": "/login"})
    _CURRENT_USER.set(u)
    _CURRENT_PATH.set(request.url.path)
    if u.must_change and request.url.path not in ("/password", "/logout"):
        raise HTTPException(303, headers={"Location": "/password?msg=Choose+a+new+password+before+you+continue."})
    perms = role if isinstance(role, tuple) else (auth.ROLE_TO_PERM.get(role, role),)
    if "login" not in perms and not any(u.can(p) for p in perms):
        raise HTTPException(403, f"needs the '{' or '.join(perms)}' permission")
    for cust in (customer, request.path_params.get("customer"), request.query_params.get("customer")):
        if cust and not u.sees_customer(cust):
            raise HTTPException(403, f"customer {cust} is not in your scope")
    if request.method == "POST":  # cookie is SameSite=Strict; also reject cross-site form posts
        origin = request.headers.get("origin")
        if origin and origin.split("://", 1)[-1] != request.headers.get("host"):
            raise HTTPException(403, "cross-site request refused")
    return u


def _wants_html(request: Request) -> bool:
    accept = (request.headers.get("accept") or "").lower()
    if "text/html" in accept:
        return True
    if "application/json" in accept.split(",")[0]:
        return False
    # Browser form posts (and TestClient */*) still get a readable HTML page
    # when the path is a GUI form endpoint.
    return request.url.path in {
        "/", "/import", "/decom", "/backups", "/backups/upload", "/backups/new-customer",
        "/login", "/search",
    } or request.url.path.startswith("/changesets") or request.url.path.startswith("/push") \
        or request.url.path.startswith("/upgrade") or request.url.path.startswith("/admin/") \
        or request.url.path.startswith("/edls")


def _form_error_page(request: Request, status: int, title: str, messages: list[str]) -> HTMLResponse:
    user = auth.read_cookie(request.cookies.get(auth.COOKIE))
    items = "".join(f"<li>{e(m)}</li>" for m in messages)
    body = (
        f"<h2>{e(title)}</h2>"
        "<div class='yellow' style='padding:8px 12px;border-left:4px solid #8a6d00;border-radius:4px'>"
        f"<ul style='margin:8px 0'>{items}</ul></div>"
        "<p><a class='btn secondary' href='/home'>Back to Home</a> <a class='btn secondary' href='/'>Back to upload</a></p>"
    )
    return page(title, body, user, status_code=status, path=request.url.path)


@app.exception_handler(HTTPException)
async def _http_error_as_html(request: Request, exc: HTTPException):
    if exc.status_code in (301, 302, 303, 307, 308):
        return HTMLResponse(status_code=exc.status_code, headers=exc.headers)
    if not _wants_html(request):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)
    detail = exc.detail
    messages = detail if isinstance(detail, list) else [str(detail)]
    title = "Could not complete that request"
    if exc.status_code == 403:
        title = "Not allowed"
    elif exc.status_code == 404:
        title = "Not found"
    return _form_error_page(request, exc.status_code, title, [str(m) for m in messages])


@app.exception_handler(RequestValidationError)
async def _validation_error_as_html(request: Request, exc: RequestValidationError):
    if not _wants_html(request):
        return JSONResponse({"detail": exc.errors()}, status_code=422)
    msgs = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err.get("loc") or [] if x != "body")
        if loc in ("files", "file"):
            msgs.append("Choose one or more files and try again.")
        else:
            msgs.append(f"{loc or 'form'}: {err.get('msg') or 'invalid'}")
    return _form_error_page(request, 422, "The form was incomplete", msgs or ["The form was incomplete."])


@app.get("/login", response_class=HTMLResponse)
def login_form(msg: str = "") -> HTMLResponse:
    note = f"<div class='note'>{e(msg)}</div>" if msg else ""
    if not auth.load_users():
        note += "<div class='note'>No users are configured on this server (users file missing).</div>"
    return page("Log in", "<div class='login-wrap'><div class='login-brand'>" + theme.LOGO + f"<b>{brand.NAME}</b>"
                          f"<small>{e(brand.LONG_NAME)}</small></div><div class='login-card'>"
                          f"<h2>Sign in to {brand.NAME}</h2><p class='muted'>Use the account your {brand.NAME} administrator gave you.</p>{note}"
                          "<form method='post' action='/login'><label for='u'>User</label><input id='u' name='username' autocomplete='username' required autofocus>"
                          "<label for='p'>Password</label><input id='p' name='password' type='password' autocomplete='current-password' required>"
                          "<button type='submit'>Log in</button></form></div>"
                          "<p class='muted' style='text-align:center;margin-top:16px'>Changes reach a firewall only from the red Push area, and every push is audited.</p>"
                          f"<p class='muted' style='text-align:center;font-size:12px'>{e(brand.FULL_NAME)}, {e(brand.FOR)}. <a href='/about'>About</a></p></div>",
                path="/login")


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if auth.authenticate(username.strip(), password) is None:
        time.sleep(0.5)
        return RedirectResponse("/login?msg=Wrong+user+or+password", status_code=303)
    r = RedirectResponse("/home", status_code=303)
    r.set_cookie(auth.COOKIE, auth.make_cookie(username.strip()), httponly=True, samesite="strict", max_age=auth.SESSION_SECONDS)
    return r


@app.get("/logout")
def logout():
    r = RedirectResponse("/login", status_code=303)
    r.delete_cookie(auth.COOKIE)
    return r


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


@app.get("/password", response_class=HTMLResponse)
def password_form(request: Request, msg: str = "") -> HTMLResponse:
    user = need(request, "login")
    note = f"<div class='note'>{e(msg)}</div>" if msg else ""
    body = (f"<h2>Change password</h2>{note}"
            "<form method='post' action='/password'>"
            "<label>Current password</label><input name='current' type='password' required autofocus>"
            "<label>New password (at least 12 characters)</label><input name='new_password' type='password' minlength='12' required>"
            "<label>Confirm new password</label><input name='confirm' type='password' minlength='12' required>"
            "<br><button>Change password</button></form>")
    return page("change password", body, user)


@app.post("/password", response_class=HTMLResponse)
def password_change(request: Request, current: str = Form(""), new_password: str = Form(""), confirm: str = Form("")) -> HTMLResponse:
    user = need(request, "login")
    name = user[0]
    err = auth.validate_new_password(new_password, confirm)
    if err:
        auth.write_user_audit(actor=name, action="password_change", target=name, result="rejected", reason="invalid_new", ip=_client_ip(request))
        return password_form(request, msg=err)
    if auth.authenticate(name, current) is None:
        auth.write_user_audit(actor=name, action="password_change", target=name, result="denied", reason="bad_current", ip=_client_ip(request))
        return password_form(request, msg="Current password is incorrect.")
    if not auth.set_password(name, new_password):
        auth.write_user_audit(actor=name, action="password_change", target=name, result="error", reason="missing_user", ip=_client_ip(request))
        return password_form(request, msg="Could not update the password.")
    auth.write_user_audit(actor=name, action="password_change", target=name, result="ok", ip=_client_ip(request))
    return password_form(request, msg="Password changed.")


def _users_page(request: Request, msg: str = "", generated: str | None = None, generated_for: str | None = None) -> HTMLResponse:
    from panlab.web import access_routes
    return access_routes.render(request, msg=msg, generated=generated, generated_for=generated_for)


@app.post("/users/reset", response_class=HTMLResponse)
def users_reset(request: Request, username: str = Form(""), action: str = Form("set"),
                new_password: str = Form(""), confirm: str = Form("")) -> HTMLResponse:
    admin = need(request, "admin")
    target = username.strip()
    users = auth.load_users()
    if target not in users:
        auth.write_user_audit(actor=admin[0], action="password_reset", target=target, result="rejected", reason="no_such_user", ip=_client_ip(request))
        return _users_page(request, msg="No such user.")
    from panlab.web.access_routes import check_grant
    why = check_grant(admin, users[target], [], [], {}) if target != admin[0] else None
    if why:
        auth.write_user_audit(actor=admin[0], action="password_reset", target=target, result="denied", reason=why, ip=_client_ip(request))
        raise HTTPException(403, why)
    generated = None
    if action == "generate":
        new_password = auth.generate_password()
        generated = new_password
    else:
        err = auth.validate_new_password(new_password, confirm)
        if err:
            auth.write_user_audit(actor=admin[0], action="password_reset", target=target, result="rejected", reason="invalid_new", ip=_client_ip(request))
            return _users_page(request, msg=err)
    if not auth.set_password(target, new_password, must_change=target != admin[0]):
        auth.write_user_audit(actor=admin[0], action="password_reset", target=target, result="error", reason="missing_user", ip=_client_ip(request))
        return _users_page(request, msg="Could not update the password.")
    auth.write_user_audit(actor=admin[0], action="password_reset", target=target, result="ok",
                          method="generate" if generated else "set", ip=_client_ip(request))
    msg = f"Password for {target} was reset."
    return _users_page(request, msg=msg, generated=generated, generated_for=target if generated else None)



def _customer_firewall_map() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for c in list_customers():
        try:
            out[c] = list_customer_firewalls(load_profile(c))
        except (ValueError, FileNotFoundError):
            out[c] = []
    return out


def _target_fw_fields(selected: str = "") -> str:
    fwmap = _customer_firewall_map()
    blob = json.dumps(fwmap)
    opts = "<option value=''>(auto — use the only firewall, or pick one if networks aren't on any firewall yet)</option>"
    return f"""<label>Target firewall (if networks aren't on any firewall yet)</label>
<select name="target_firewall" id="target-fw">{opts}</select>
<script>
(function(){{
  const fws = {blob};
  const sel = document.getElementById('target-fw');
  const cust = document.querySelector("select[name='customer']");
  const picked = {json.dumps(selected)};
  function sync(){{
    if (!sel || !cust) return;
    const names = fws[cust.value] || [];
    const cur = sel.value || picked;
    sel.innerHTML = "<option value=''>(auto — use the only firewall, or pick one if networks aren't on any firewall yet)</option>";
    names.forEach(n => {{
      const o = document.createElement('option');
      o.value = n; o.textContent = n;
      if (n === cur) o.selected = true;
      sel.appendChild(o);
    }});
  }}
  if (cust) cust.addEventListener('change', sync);
  sync();
}})();
</script>
"""


def _retarget_form(cs: dict, customer: str, stem: str) -> str:
    if not cs.get("unplaced") and not cs.get("candidate_firewalls"):
        return ""
    names = cs.get("candidate_firewalls") or []
    if not names:
        try:
            names = list_customer_firewalls(load_profile(customer))
        except (ValueError, FileNotFoundError):
            names = []
    if not names:
        return ""
    opts = "".join(f"<option value='{e(n)}'>{e(n)}</option>" for n in names)
    return (
        "<div class='yellow' style='margin:16px 24px;padding:8px 12px;border-left:4px solid #8a6d00;background:#fffbea'>"
        "<form method='post' action='/changesets/" + e(customer) + "/" + e(stem) + "/retarget'>"
        "<label>Target firewall (if networks aren't on any firewall yet)</label>"
        f"<select name='target_firewall'>{opts}</select> "
        "<button type='submit'>Rebuild the plan for this firewall</button>"
        "<div class='note'>The networks in this request are not on a connected subnet or specific route. "
        "Picking a firewall builds the proposed objects, rule, and route suggestions. Nothing is pushed.</div>"
        "</form></div>"
    )


def _source_map() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for c in list_customers():
        try:
            out[c] = uploads.source_options(load_profile(c))
        except (ValueError, FileNotFoundError, uploads.UploadError):
            out[c] = [{"value": "cached", "label": "Cached / profile config"}]
    return out


def _config_source_fields() -> str:
    blob = json.dumps(_source_map())
    return f"""<label>Config source</label>
<select name='config_source' id='config-source'></select>
<span class='note' style='display:block;font-weight:400'>Cached uses the last exported or profile config. Live uses the cached read-only snapshot (Panorama running and candidate, plus managed firewall running configs; refresh it on Trace a flow). An uploaded backup is plan-only and cannot be pushed. Hop-level live policy/FIB/log checks are on Trace a flow.</span>
<script>
(function(){{
  const smap = {blob};
  const sel = document.getElementById('config-source');
  const cust = document.querySelector("select[name='customer']");
  function sync(){{
    if (!sel || !cust) return;
    const opts = smap[cust.value] || [{{value:'cached', label:'Cached / profile config'}}];
    const cur = sel.value;
    sel.innerHTML = "";
    opts.forEach(o => {{
      const el = document.createElement('option');
      el.value = o.value; el.textContent = o.label;
      if (o.value === cur) el.selected = true;
      sel.appendChild(el);
    }});
  }}
  if (cust) cust.addEventListener('change', sync);
  sync();
}})();
</script>"""


async def _read_upload(f: UploadFile, limit: int) -> bytes:
    buf = bytearray()
    while True:
        chunk = await f.read(1024 * 1024)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > limit:
            raise HTTPException(400, f"file is larger than {limit // (1024 * 1024)} MB")
    return bytes(buf)


@app.get("/home", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    """Role-aware dashboard: real counts for the user's scope, the work for their layer, quick actions, recent change sets."""
    user = need(request, "login")
    custs = list_customers()
    lid = layers.layer_id(user)
    ov = dashboard.overview(custs) if user.can("view") else dashboard.Overview(customers=len(custs))
    cards = [theme.kpi("Customers in your scope", len(custs), ic="building")]
    if user.can("view"):
        waiting = ov.count("Awaiting approval")
        ready = ov.count("Approved")
        attn = ov.count("Verify failed", "Push failed", "Rollback failed")
        cards.append(theme.kpi("Saved change sets", len(ov.rows), "/changesets", "info", ic="layers"))
        cards.append(theme.kpi("Awaiting approval", waiting, "/changesets?status=Awaiting+approval", "warning" if waiting else "neutral",
                               "Two-person rule" if waiting else "", ic="clock"))
        cards.append(theme.kpi("Approved, not pushed", ready, "/changesets?status=Approved", "info" if ready else "neutral", ic="check"))
        cards.append(theme.kpi("Pushed", ov.count("Pushed"), "/changesets?status=Pushed", "success", ic="send"))
        if attn:
            cards.append(theme.kpi("Needs attention", attn, "/changesets?status=attention", "danger", "Verify or push failed", ic="alert"))
        if lid == "approver":
            cards.insert(1, cards.pop(2))  # the approver's queue leads
        elif lid == "operator":
            cards.insert(1, cards.pop(3))  # ready to push leads
    if user.can("upgrade_plan") or user.can("upgrade_exec"):
        cards.append(theme.kpi("Upgrade plans", dashboard.upgrade_plan_count(custs), "/upgrade", ic="upgrade"))
    if user.can("edl_approve"):
        cards.append(theme.kpi("EDL changes waiting", dashboard.edl_pending(custs), "/edls", ic="list"))
    if user.can("urlfilter_request") or user.can("urlfilter_approve"):
        cards.append(theme.kpi("URL filter requests open", dashboard.urlfilter_pending(custs), "/urlfilter", ic="shield"))
    stats = "<div class='stats'>" + "".join(cards) + "</div>"
    activity = ""
    if user.can("view"):
        rows = "".join(
            f"<tr><td><a href='/changesets/{e(r.customer)}/{e(r.stem)}'>{e(r.stem)}</a></td><td>{e(r.customer)}</td>"
            f"<td>{theme.badge(r.status, r.tone)}</td><td>{e(str(r.summary.get('requests_unique', '')))}</td>"
            f"<td>{e(str(r.summary.get('rules', '')))}</td><td>{e(str(r.summary.get('red_flags', '')))}</td></tr>"
            for r in ov.rows[:8])
        new_btn = "<a class='btn' href='/'>" + theme.icon("upload") + "Upload an FCR</a>" if user.can("fcr") or user.can("request") else ""
        activity = ("<div class='sectitle'>Recent change sets</div>" + (
            "<table><tr><th>Change set</th><th>Customer</th><th>Status</th><th>Requests</th><th>Rules</th><th>Red flags</th></tr>"
            f"{rows}</table><p><a href='/changesets'>All saved change sets &rarr;</a></p>" if rows else
            theme.empty_state("No change sets yet", "Upload a firewall change request (FCR) to build the first plan.", new_btn, "layers")))
    intro = layers.home_intro(user)
    helpb = theme.help_note("navigation.md", "Home leads with the work for your layer. The counts, tiles and sidebar only show what your permissions allow.")
    head = (f"<div class='pagehead'><div><h2>Home</h2><p>Signed in as <b>{e(user[0])}</b> · {e(layers.layer_label(user))}"
            + (f" · {e(theme.scope_text(user))}" if theme.scope_text(user) else "") + "</p></div></div>")
    body = f"{head}{intro}{stats}{helpb}<div class='sectitle'>Quick actions</div>{theme.home_tiles(user)}{activity}"
    return page("Home", body, user)


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    u = auth.read_cookie(request.cookies.get(auth.COOKIE))
    if u is not None and not (u.can("fcr") or u.can("request")):  # land on the first area this user may use
        for perm, url in (("upgrade_plan", "/upgrade"), ("upgrade_exec", "/upgrade"), ("view", "/changesets"),
                          ("user_admin", "/users"), ("backup_admin", "/admin/backup-destinations")):
            if u.can(perm):
                return RedirectResponse(url, status_code=303)
        return RedirectResponse("/password", status_code=303)
    user = need(request, ("fcr", "request"))
    opts = "".join(f"<option value='{e(c)}'>{e(load_profile(c).display_name)} ({e(c)})</option>" for c in list_customers())
    body = f"""<h2>Preview firewall change requests</h2>
<div class='note'>Upload one or more filled-in FCR spreadsheets (the customer's ServiceNow form). The tool works out which firewall,
vsys or Panorama device group each rule belongs on, which zones, which objects exist already, and flags anything risky.
Nothing is sent to any firewall from this page.</div>
<div class='note'>Need the blank request form to send to a requester? <a href='/fcr-template.xlsx'>Download the FCR request form (.xlsx)</a>.
It checks the format as people type, has an Instructions tab, and a Row check column.</div>
<form method='post' action='/import' enctype='multipart/form-data'>
<label>Customer</label><select name='customer'>{opts}</select>
<label>FCR files (.xlsx or .csv, several allowed)</label><input type='file' name='files' accept='.xlsx,.xlsm,.csv,.xls' multiple required>
<span class='note' style='display:block;font-weight:400'>You can select several spreadsheets at once (.xlsx or .csv; if you still have an Excel 97-2003 .xls, save it as .xlsx or .csv first). Each file is listed in the change set, including which columns were used. If one file has a problem, the others are still processed and the errors are shown on the result page.</span>
<label>Ticket numbers (optional; otherwise read from file name, Project, or Notes)</label>
RITM <input name='ritm' size='14'> SCTASK <input name='sctask' size='14'> CR/CHG <input name='cr' size='14'>
<label>Requester (optional)</label><input name='requester' size='30'>
{_target_fw_fields()}
{_config_source_fields()}
<label><input type='checkbox' name='combine_on' value='yes' checked> Combine rules where possible</label>
<span class='note' style='display:block;font-weight:400'>When checked, similar requests (same zones, action, and port or the same addresses) become one rule, and hosts can be placed in an address group. If an existing rule already covers the traffic, the plan will suggest adding the object there instead of making a new rule.</span>
<br><button type='submit'>Preview</button></form>"""
    return page("Upload FCRs", body, user)


FCR_TEMPLATE = Path(__file__).resolve().parents[3] / "templates" / "customer-rule-request-form.xlsx"


@app.get("/fcr-template.xlsx")
def fcr_template(request: Request) -> FileResponse:
    """The blank FCR request form (Instructions tab, validation, Row check) to hand to requesters."""
    need(request, ("fcr", "view"))
    if not FCR_TEMPLATE.is_file():
        raise HTTPException(404, "the FCR request form is not installed on this server")
    return FileResponse(
        FCR_TEMPLATE, filename="FCR-request-form.xlsx",
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.post("/import", response_class=HTMLResponse)
async def do_import(request: Request, customer: str = Form(...), files: list[UploadFile] = File(...), ritm: str = Form(""),
                    sctask: str = Form(""), cr: str = Form(""), requester: str = Form(""),
                    target_firewall: str = Form(""), combine_on: str = Form(""),
                    config_source: str = Form("cached")) -> HTMLResponse:
    user = need(request, ("fcr", "request"), customer=customer)
    try:
        prof = load_profile(customer)
        envs, src_meta = uploads.resolve_envs(prof, config_source)
    except (ValueError, FileNotFoundError, RuntimeError, uploads.UploadError) as exc:
        raise HTTPException(400, str(exc))
    override = Tickets(ritm=[ritm.strip()] if ritm.strip() else [], sctask=[sctask.strip()] if sctask.strip() else [],
                       cr=[cr.strip()] if cr.strip() else [])
    requests, metas, file_errors = [], [], []
    with tempfile.TemporaryDirectory() as td:
        used_names: set[str] = set()
        for f in files:
            raw = (f.filename or "").strip()
            name = Path(raw).name if raw else ""
            data = await f.read()
            if not name and not data:
                continue  # empty leftover slot some browsers attach
            if not name:
                name = "upload.xlsx"
            if not name.lower().endswith((".xlsx", ".xlsm", ".csv", ".xls")):
                file_errors.append(f"{name}: use .xlsx or .csv")
                continue
            if len(data) > MAX_BYTES:
                file_errors.append(f"{name}: larger than 10 MB")
                continue
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "upload.xlsx"
            dest = Path(td) / safe
            if dest.name in used_names or dest.exists():
                stem, suf = dest.stem, dest.suffix
                i = 2
                while True:
                    cand = Path(td) / f"{stem}-{i}{suf}"
                    if cand.name not in used_names and not cand.exists():
                        dest = cand
                        break
                    i += 1
            used_names.add(dest.name)
            dest.write_bytes(data)
            try:
                reqs, meta = read_fcr(dest, ticket_patterns=prof.tickets, override=override, requester=requester.strip())
            except Exception as exc:  # show the person what is wrong with their file
                file_errors.append(f"{name}: {exc}")
                continue
            if isinstance(meta, dict):
                meta["file"] = name
            requests += reqs
            metas.append(meta)
    if not metas:
        msgs = file_errors or ["No FCR files were received. Select one or more .xlsx or .csv spreadsheets and try again."]
        raise HTTPException(400, msgs if len(msgs) > 1 else msgs[0])
    cs = build_changeset(prof, envs, requests, files=metas,
                         fallback_firewall=target_firewall.strip() or None,
                         combine=(combine_on == "yes"),
                         use_engine_path=True)
    if file_errors:
        cs["file_errors"] = file_errors
    uploads.attach_source(cs, src_meta)
    cs["created_by"] = user[0]
    stem = "cs-" + datetime.now(ZoneInfo("America/Chicago")).strftime("%Y%m%d-%H%M%S")
    write_outputs(cs, prof.data_dir("changesets"), stem)
    return HTMLResponse(_wrap_report(cs, customer, stem, user))



@app.get("/decom", response_class=HTMLResponse)
def decom_form(request: Request) -> HTMLResponse:
    user = need(request, "prep")
    opts = "".join(f"<option value='{e(c)}'>{e(load_profile(c).display_name)} ({e(c)})</option>" for c in list_customers())
    # targets per customer
    tmap = {}
    for c in list_customers():
        try:
            tmap[c] = [t.name + (" (Panorama)" if t.type == "panorama" else "") for t in load_profile(c).targets]
        except (ValueError, FileNotFoundError):
            tmap[c] = []
    blob = json.dumps({k: v for k, v in tmap.items()})
    body = f"""<h2>Decommission objects and rules</h2>
{theme.help_note("decommission.md", "How the tiers work, what the plan will never do, and how to stop traffic.")}
<div class='note'>Paste IPs, CIDRs, ranges, hostnames (FQDNs), address object or group names, or rule names (one per line, or
comma-separated), and/or upload a spreadsheet with one item per row. The tool looks them up in the <b>cached</b> config and grades
every reference: <b>Exact</b> (pre-selected), <b>Highly likely</b> (one click) and <b>Possible</b> (advice only: a /16 that merely
contains a retired /32 is never changed). Nothing is sent to any firewall from this page.</div>
<form method='post' action='/decom' enctype='multipart/form-data'>
<label>Customer</label><select name='customer'>{opts}</select>
<label>Target (optional; default is every target in the customer profile)</label>
<select name='target' id='decom-target'><option value=''>(all targets)</option></select>
{_config_source_fields()}
<label>Items to decommission</label>
<textarea name='items' rows='10' style='width:100%;font-family:monospace' placeholder='10.1.2.3&#10;HOST-EXAMPLE&#10;old-app.example.test&#10;OLD-RULE-NAME'></textarea>
<fieldset class='card'><legend><b>Intent</b></legend>
<label><input type='radio' name='mode' value='remove' checked> <b>Remove references</b>: the server is retired; clean it out of rules, groups and objects.</label><br>
<label><input type='radio' name='mode' value='block'> <b>Stop traffic</b>: make sure nothing still allows it. Every rule on the path that would
still let the flow through is found, and a narrow deny is added above the first one in each place.</label>
<label>Flows to stop (Stop traffic only; one per line: <code>source destination tcp/443</code>)</label>
<textarea name='flows' rows='3' style='width:100%;font-family:monospace' placeholder='10.1.1.10 10.50.1.25 tcp/443'></textarea>
</fieldset>
<label>Or upload a list (.xlsx, first column, one item per row; .txt also accepted)</label>
<input type='file' name='file' accept='.xlsx,.txt,.csv'>
<label>Ticket numbers (optional)</label>
RITM <input name='ritm' size='14'> SCTASK <input name='sctask' size='14'> CR/CHG <input name='cr' size='14'>
<br><button type='submit'>Build decommission plan</button></form>
<script>
(function(){{
  const tmap = {blob};
  const sel = document.getElementById('decom-target');
  const cust = document.querySelector("select[name='customer']");
  function sync(){{
    if (!sel || !cust) return;
    const names = tmap[cust.value] || [];
    const cur = sel.value;
    sel.innerHTML = "<option value=''>(all targets)</option>";
    names.forEach(n => {{
      const val = n.split(' ')[0];
      const o = document.createElement('option');
      o.value = val; o.textContent = n;
      if (val === cur) o.selected = true;
      sel.appendChild(o);
    }});
  }}
  if (cust) cust.addEventListener('change', sync);
  sync();
}})();
</script>
"""
    return page("decommission", body, user)


@app.post("/decom", response_class=HTMLResponse)
async def do_decom(request: Request, customer: str = Form(...), items: str = Form(""),
                   ritm: str = Form(""), sctask: str = Form(""), cr: str = Form(""),
                   target: str = Form(""), file: UploadFile | None = File(None),
                   config_source: str = Form("cached"), mode: str = Form("remove"),
                   flows: str = Form("")) -> HTMLResponse:
    user = need(request, "prep", customer=customer)
    mode = "block" if mode in ("block", "stop") else "remove"
    if mode == "block" and not flows.strip():
        raise HTTPException(400, "Stop traffic needs at least one flow (source destination tcp/443).")
    try:
        prof = load_profile(customer)
        envs, src_meta = uploads.resolve_envs(prof, config_source)
    except (ValueError, FileNotFoundError, RuntimeError, uploads.UploadError) as exc:
        raise HTTPException(400, str(exc))
    if target.strip():
        envs = [e for e in envs if e.target == target.strip()]
        if not envs:
            raise HTTPException(400, f"no cached config for target {target.strip()}")
    found = parse_item_text(items)
    metas = []
    if file is not None and (file.filename or "").strip():
        name = Path(file.filename or "upload.xlsx").name
        data = await file.read()
        if len(data) > MAX_BYTES:
            raise HTTPException(400, f"{name}: larger than 10 MB")
        with tempfile.TemporaryDirectory() as td:
            safe = Path(td) / re.sub(r"[^A-Za-z0-9_.-]", "_", name)
            safe.write_bytes(data)
            try:
                if name.lower().endswith(".xlsx"):
                    found += parse_item_xlsx(safe)
                elif name.lower().endswith((".txt", ".csv")):
                    found += parse_item_text(safe.read_text(encoding="utf-8", errors="replace"))
                else:
                    raise HTTPException(400, f"{name}: use .xlsx, .txt, or .csv")
            except HTTPException:
                raise
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(400, f"{name}: {exc}")
        metas.append({"file": name, "project": "decommission",
                      "tickets": {"ritm": [ritm.strip()] if ritm.strip() else [],
                                  "sctask": [sctask.strip()] if sctask.strip() else [],
                                  "cr": [cr.strip()] if cr.strip() else []},
                      "rows": 0})
    # unique, keep order
    seen: set[str] = set()
    uniq = []
    for i in found:
        if i not in seen:
            seen.add(i)
            uniq.append(i)
    if not uniq:
        raise HTTPException(400, "Give at least one item to decommission (paste a list or upload a file).")
    tickets = {"ritm": [ritm.strip()] if ritm.strip() else [],
               "sctask": [sctask.strip()] if sctask.strip() else [],
               "cr": [cr.strip()] if cr.strip() else []}
    if not metas:
        metas = [{"file": "pasted-items", "project": "decommission", "tickets": tickets, "rows": len(uniq)}]
    else:
        for m in metas:
            m["rows"] = len(uniq)
            if tickets["ritm"] or tickets["sctask"] or tickets["cr"]:
                m["tickets"] = tickets
    try:
        cs = build_decom_changeset(prof, envs, uniq, tickets=tickets, files=metas, created_by=user[0],
                                   mode=mode, flows_text=flows)
    except Exception as exc:  # noqa: BLE001 - engine missing or rejected the job
        raise HTTPException(400, f"decommission analysis failed: {exc}")
    if target.strip():
        cs["decom"]["targets"] = [target.strip()]
    uploads.attach_source(cs, src_meta)
    stem = "decom-" + datetime.now(ZoneInfo("America/Chicago")).strftime("%Y%m%d-%H%M%S")
    write_outputs(cs, prof.data_dir("changesets"), stem)
    return HTMLResponse(_wrap_report(cs, customer, stem, user))


@app.post("/decom/{customer}/{stem}/select")
async def decom_select(request: Request, customer: str, stem: str):
    """Rebuild a decommission plan with a new selection (Exact / Highly likely ticks, deny rules). Resets approval."""
    user = need(request, "prep", customer=customer)
    if not STEM_RE.match(stem):
        raise HTTPException(404)
    form = await request.form()
    picks = [str(v) for v in form.getlist("pick")]
    try:
        prof = load_profile(customer)
        cs = json.loads(_cs_path(customer, stem, "json").read_text())
        if not is_decom(cs) or not cs.get("decom"):
            raise HTTPException(400, "not a decommission change set")
        src = cs.get("config_source") or {}
        token = f"backup:{src['id']}" if src.get("kind") == "backup" and src.get("id") else "cached"
        envs, _ = uploads.resolve_envs(prof, token)
        wanted = (cs.get("decom") or {}).get("targets")
        if wanted:
            envs = [x for x in envs if x.target in wanted]
        from panlab.decom import rebuild_with_selection
        new_cs = rebuild_with_selection(prof, envs, cs, picks)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"could not rebuild the plan: {exc}")
    if wanted:
        new_cs["decom"]["targets"] = wanted
    new_cs["decom"]["selected_by"] = user[0]
    write_outputs(new_cs, prof.data_dir("changesets"), stem)
    approval.reset(prof, stem)
    pusher.audit(prof, actor=user[0], action="decom-select", changeset=stem, result="rebuilt",
                 detail=f"{len(picks)} item(s) selected; approval reset")
    return RedirectResponse(f"/changesets/{customer}/{stem}", status_code=303)


@app.get("/changesets/{customer}/{stem}/decom.csv")
def decom_csv(request: Request, customer: str, stem: str):
    need(request, "viewer")
    cs = json.loads(_cs_path(customer, stem, "json").read_text())
    text = ((cs.get("decom") or {}).get("exports") or {}).get("csv") or ""
    return PlainTextResponse(text, media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename={stem}-decommission.csv"})


@app.get("/changesets/{customer}/{stem}/decom.cli")
def decom_cli(request: Request, customer: str, stem: str):
    from panlab.decom import delete_commands
    need(request, "viewer")
    cs = json.loads(_cs_path(customer, stem, "json").read_text())
    return PlainTextResponse("\n".join(delete_commands(cs)))


@app.get("/changesets/{customer}/{stem}/decom-rollback.cli")
def decom_rollback_cli(request: Request, customer: str, stem: str):
    from panlab.decom import rollback_commands
    need(request, "viewer")
    cs = json.loads(_cs_path(customer, stem, "json").read_text())
    return PlainTextResponse("\n".join(rollback_commands(cs)))


def _wrap_report(cs: dict, customer: str, stem: str, user: tuple[str, str] | None = None) -> str:
    rep = to_html(cs)
    plan_only = uploads.is_plan_only(cs)
    push_bit = (theme.badge("Push not available (built from a backup file)", "warning")
                if plan_only else
                (f"<a class='btn danger sm' href='/push/{e(customer)}/{e(stem)}'>{theme.icon('send')}Push area &rarr;</a>"
                 if user and auth.has_role(user, "engineer") else ""))
    links = (f"<div class='subbar toolbar'><a href='/home'>&larr; Home</a><span class='tsep'></span>"
             f"<span class='muted'>Saved as</span> <b>{e(stem)}</b><span class='tsep'></span>"
             f"<a href='/'>New upload</a> · <a href='/changesets/{e(customer)}/{e(stem)}.md'>Markdown</a> · "
             f"<a href='/changesets/{e(customer)}/{e(stem)}.json'>JSON</a>"
             f"<span class='grow'></span><a class='btn secondary sm' href='/changesets/{e(customer)}/{e(stem)}/changeplan'>"
             f"{theme.icon('file')}Change plan (GUI steps, CLI, rollback, checks)</a>"
             + push_bit + "</div>")
    if cs.get("file_errors"):
        items = "".join(f"<li>{e(m)}</li>" for m in cs["file_errors"])
        links += (
            "<div class='yellow' style='margin:0 0 0;padding:8px 24px;border-left:4px solid #8a6d00;background:#fff6d6;"
            "font-family:system-ui'>"
            "<b>Some files could not be imported</b> and were skipped. The change set includes the files that parsed."
            f"<ul style='margin:8px 0 0'>{items}</ul></div>"
        )
    try:
        prof = load_profile(customer)
        links += stepper_html(cs, customer, stem, current="request", prof=prof, user=user) + multiplace.banner_html(cs) + blast_html(cs)
    except Exception:
        prof = None
    ev = denylog.load_evidence(load_profile(customer), stem)
    log_form = ""
    if plan_only:
        log_form = "<p>Traffic-log lookup is not available for change sets built from a backup file.</p>"
    elif user and auth.has_role(user, "prep"):
        log_form = (f"<form method='post' action='/denylog/{e(customer)}/{e(stem)}'>Window <input name='days' value='7' size='3'> days, "
                    f"max <input name='max_logs' value='200' size='4'> logs <button>Check traffic logs for denies</button> "
                    "<span style='opacity:.7'>(reads logs and runs a policy test; never changes the firewall)</span></form>")
    evid = _retarget_form(cs, customer, stem) + (
            "<div class='card' style='border-left:4px solid var(--warning)'>"
            "<h3>Evidence from traffic logs (read-only)</h3><ul>"
            + "".join(f"<li>{e(x.lstrip('- ').strip())}</li>" for x in denylog.evidence_lines(ev)) + "</ul>"
            + log_form
            + (f" <a href='/denylog/{e(customer)}'>ad-hoc lookup</a>" if user and auth.has_role(user, "prep") else "") + "</div>")
    inner = rep.split("<body>", 1)[-1].rsplit("</body>", 1)[0]  # the report's own <head>/<style> is dropped: one stylesheet
    if is_decom(cs) and cs.get("decom"):
        inner = decom_view.plan_html(cs, customer, stem, bool(user and auth.has_role(user, "prep")) and not plan_only)
    title = f"Change set {stem}"
    return theme.document(title, links + "<div class='report'>" + inner + evid + "</div>", user,
                          f"/changesets/{customer}/{stem}", False, __version__)


@app.get("/changesets", response_class=HTMLResponse)
def changesets(request: Request, status: str = "") -> HTMLResponse:
    user = need(request, "viewer")
    ov = dashboard.overview(list_customers(), per_customer=50)
    want = {"attention": ("Verify failed", "Push failed", "Rollback failed")}.get(status, (status,) if status else ())
    shown = [r for r in ov.rows if not want or r.status in want]
    rows = [f"<tr><td><a href='/changesets/{e(r.customer)}/{e(r.stem)}'>{e(r.stem)}</a></td><td>{e(r.customer)}</td>"
            f"<td>{theme.badge(r.status, r.tone)}</td><td>{r.summary.get('requests_unique', '')}</td>"
            f"<td>{r.summary.get('rules', '')}</td><td>{r.summary.get('red_flags', '')}</td><td>{r.summary.get('needs_human', '')}</td></tr>"
            for r in shown]
    labels = ("Awaiting approval", "Approved", "Pushed", "Planned", "Plan only", "Rejected")
    chips = "".join(f"<a class='chip{' on' if status == lab else ''}' href='/changesets?status={quote(lab)}'>{e(lab)} "
                    f"<b>{ov.count(lab)}</b></a>" for lab in labels if ov.count(lab))
    chips = (f"<div class='chips'><a class='chip{'' if status else ' on'}' href='/changesets'>All <b>{len(ov.rows)}</b></a>{chips}</div>"
             if ov.rows else "")
    new_btn = ("<a class='btn' href='/'>" + theme.icon("upload") + "Upload an FCR</a>") if (user.can("fcr") or user.can("request")) else ""
    head = ("<div class='pagehead'><div><h2>Saved change sets</h2><p>Plans built from FCRs, newest first. "
            "Open one to review it, follow the Request &rarr; Plan &rarr; Approval &rarr; Push steps, or download it.</p></div>"
            f"<div class='actions'>{new_btn}</div></div>")
    if not ov.rows:
        table = theme.empty_state("No change sets yet", "Upload a firewall change request (FCR) and the plan is saved here.", new_btn, "layers")
    else:
        table = ("<table><tr><th>Change set</th><th>Customer</th><th>Status</th><th>Requests</th><th>Rules</th><th>Red flags</th><th>Needs a human</th></tr>"
                 + "".join(rows) + "</table>")
    return page("change sets", head + chips + table, user)


def _cs_path(customer: str, stem: str, ext: str) -> Path:
    if not STEM_RE.match(stem):
        raise HTTPException(404)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404)
    p = prof.data_dir("changesets") / f"{stem}.{ext}"
    if not p.is_file():
        raise HTTPException(404)
    return p


@app.get("/changesets/{customer}/{stem}", response_class=HTMLResponse)
def show(request: Request, customer: str, stem: str) -> HTMLResponse:
    user = need(request, "viewer")
    if stem.endswith(".md"):
        return PlainTextResponse(_cs_path(customer, stem[:-3], "md").read_text())
    if stem.endswith(".json"):
        return PlainTextResponse(_cs_path(customer, stem[:-5], "json").read_text(), media_type="application/json")
    cs = json.loads(_cs_path(customer, stem, "json").read_text())
    return HTMLResponse(_wrap_report(cs, customer, stem, user))


@app.post("/changesets/{customer}/{stem}/retarget", response_class=HTMLResponse)
def retarget(request: Request, customer: str, stem: str, target_firewall: str = Form("")) -> HTMLResponse:
    user = need(request, "prep")
    if not STEM_RE.match(stem):
        raise HTTPException(404)
    try:
        prof = load_profile(customer)
        # load original later so we can reuse its config source
        cs = json.loads(_cs_path(customer, stem, "json").read_text())
        src = cs.get("config_source") or {}
        token = f"backup:{src['id']}" if src.get("kind") == "backup" and src.get("id") else "cached"
        envs, src_meta = uploads.resolve_envs(prof, token)
    except (ValueError, FileNotFoundError, RuntimeError, uploads.UploadError) as exc:
        raise HTTPException(400, str(exc))
    fw = target_firewall.strip()
    if not fw:
        raise HTTPException(400, "Pick a target firewall.")
    reqs = requests_from_changeset(cs)
    new_cs = build_changeset(prof, envs, reqs, files=cs.get("files") or [], fallback_firewall=fw,
                            combine=cs.get("combine", True), use_engine_path=True)
    uploads.attach_source(new_cs, src_meta)
    new_cs["created_by"] = user[0]
    new_cs["retarget_of"] = stem
    new_stem = "cs-" + datetime.now(ZoneInfo("America/Chicago")).strftime("%Y%m%d-%H%M%S")
    write_outputs(new_cs, prof.data_dir("changesets"), new_stem)
    return HTMLResponse(_wrap_report(new_cs, customer, new_stem, user))


def _plan_parts(customer: str, stem: str) -> dict[str, str]:
    cs = json.loads(_cs_path(customer, stem, "json").read_text())
    try:  # reference check against the stored (offline/cached) config; never live from the GUI
        root = load_configs(uploads.paths_for_changeset(load_profile(customer), cs))
    except Exception:  # noqa: BLE001 - plan still renders, with the "not checked" note
        root = None
    parts = changeplan_sections(cs, root, denylog.load_evidence(load_profile(customer), stem))
    block = _identity_block(load_profile(customer))
    for k in ("full", "cr"):  # right under the title, so the CR names the real devices
        head, sep, rest = parts[k].partition("\n")
        parts[k] = head + sep + block + rest
    return parts


def _identity_block(prof) -> str:
    """CR text: each profile target with the hostname and serial it last reported over the API."""
    rows = []
    for t in prof.targets:
        idn = identity.cached(prof, t.name)
        when = f", read {idn.get('read_at')}" if idn and idn.get("read_at") else ""
        miss = "" if identity.known(idn) else " (could not be read yet; push Prepare reads it, or run OS upgrade discovery)"
        rows.append(f"- {identity.label(t.name, idn)} ({t.type}){when}{miss}")
    return "\nDevices in this customer profile, as they last reported themselves (hostname, serial):\n\n" + "\n".join(rows) + "\n\n"


def _plan_text(customer: str, stem: str) -> str:
    return _plan_parts(customer, stem)["full"]


def _copy_btn(eid: str) -> str:
    return (f"<button type='button' onclick=\"navigator.clipboard.writeText(document.getElementById('{eid}').innerText)"
            f".then(()=>{{this.innerText='Copied'}}).catch(()=>{{}} )\">Copy</button>")


def _plan_downloads(customer: str, stem: str, part: str) -> str:
    base = f"/changesets/{e(customer)}/{e(stem)}/changeplan"
    if part == "full":
        return f"<a href='{base}.md'>Download .md</a> <a href='{base}.txt'>Download .txt</a>"
    return f"<a href='{base}/{e(part)}.md'>Download .md</a> <a href='{base}/{e(part)}.txt'>Download .txt</a>"


_PLAN_SECTIONS = (
    ("cr", "Change request (GUI steps)"),
    ("cli", "Implementation (CLI)"),
    ("rollback", "Rollback"),
    ("verify", "Verification"),
)


def _reuse_form(cs: dict, customer: str, stem: str, user: tuple[str, str] | None) -> str:
    rows = []
    for g in cs.get("groups") or []:
        for r in g.get("rules") or []:
            cands = (r.get("reuse") or {}).get("candidates") or []
            if not cands:
                continue
            selected = (r.get("reuse") or {}).get("selected") or "new"
            uid = r.get("uid") or r["name"]
            radios = []
            for c in cands:
                if c.get("already_allowed"):
                    label = f"Already allowed by `{c['name']}` (no change)"
                else:
                    reasons = "; ".join(c.get("reasons") or [])
                    label = f"Add to existing `{c['name']}`" + (f" — {reasons}" if reasons else "")
                checked = "checked" if selected == c["name"] else ""
                radios.append(f"<label style='display:block;font-weight:400;margin:4px 0'>"
                              f"<input type='radio' name='choice-{e(uid)}' value='{e(c['name'])}' {checked}> {e(label)}</label>")
            checked_new = "checked" if selected in ("new", "add") else ""
            proposed = r.get("proposed_name") or r["name"]
            radios.append(f"<label style='display:block;font-weight:400;margin:4px 0'>"
                          f"<input type='radio' name='choice-{e(uid)}' value='new' {checked_new}> "
                          f"Create new rule `{e(proposed)}`</label>")
            rows.append(f"<fieldset style='margin:10px 0;padding:8px 12px;border:1px solid #d0d5dd'>"
                        f"<legend><b>{e(proposed)}</b></legend>" + "".join(radios) + "</fieldset>")
    if not rows:
        return ""
    can_edit = user and auth.has_role(user, "prep")
    inner = "".join(rows)
    if not can_edit:
        return ("<div class='note'><h3>Existing rule or new rule</h3>"
                "<p>An existing allow rule can cover some of these requests. A prep user can switch "
                "each one between editing that rule and creating a new rule.</p>" + inner + "</div>")
    return ("<div class='note'><h3>Existing rule or new rule</h3>"
            "<p>When an existing allow rule can cover a request, the plan defaults to editing that rule. "
            "Pick <b>create new rule</b> if you'd rather add a separate rule. Updating the plan only changes "
            "the text; nothing is pushed.</p>"
            f"<form method='post' action='/changesets/{e(customer)}/{e(stem)}/reuse'>"
            + inner + "<button type='submit'>Update plan</button></form></div>")


@app.get("/changesets/{customer}/{stem}/changeplan", response_class=HTMLResponse)
def changeplan(request: Request, customer: str, stem: str) -> HTMLResponse:
    user = need(request, "viewer")
    parts = _plan_parts(customer, stem)
    cs = json.loads(_cs_path(customer, stem, "json").read_text())
    c, st = e(customer), e(stem)
    sections = []
    for key, title in _PLAN_SECTIONS:
        text = parts.get(key) or ""
        sections.append(
            f"<div class='plan-sec'><h3>{title} <span class='acts'>{_copy_btn('plan-'+key)} "
            f"{_plan_downloads(customer, stem, key)}</span></h3>"
            f"<pre id='plan-{key}'>{e(text)}</pre></div>"
        )
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        prof = None
    lead = ""
    if prof is not None:
        lead = (stepper_html(cs, customer, stem, current="plan", prof=prof, user=user)
                + multiplace.banner_html(cs) + blast_html(cs) + approval.form_html(cs, customer, stem, prof, user))
    body = (
        f"<h2>Change plan: {st}</h2>"
        + lead
        + theme.help_note("fcr-upload-and-change-plans.md", "This is the plan to paste into a CR. Nothing is pushed from this page.")
        + "<div class='note'>The change-request section is the field-by-field GUI plan "
        "to paste into the CR (or download and attach). CLI, rollback, and verification are also shown in full below, "
        "each with its own Copy and Download buttons. A full-plan download is at the top.</div>"
        f"<p>{_copy_btn('plan-full')} {_plan_downloads(customer, stem, 'full')} · "
        f"<a href='/changesets/{c}/{st}'>back to the change set</a></p>"
        + _reuse_form(cs, customer, stem, user)
        + f"<pre id='plan-full' hidden>{e(parts['full'])}</pre>"
        + "".join(sections)
    )
    return page("change plan", body, user)


@app.post("/changesets/{customer}/{stem}/reuse", response_class=HTMLResponse)
async def reuse_choice(request: Request, customer: str, stem: str) -> HTMLResponse:
    user = need(request, "prep")
    cs = json.loads(_cs_path(customer, stem, "json").read_text())
    form = await request.form()
    selections = {}
    for key, val in form.items():
        if str(key).startswith("choice-") and val:
            selections[str(key)[len("choice-"):]] = str(val)
    apply_reuse_choice(cs, selections)
    write_outputs(cs, load_profile(customer).data_dir("changesets"), stem)
    return RedirectResponse(f"/changesets/{customer}/{stem}/changeplan", status_code=303)


@app.get("/changesets/{customer}/{stem}/changeplan.{fmt}")
def changeplan_file(request: Request, customer: str, stem: str, fmt: str) -> PlainTextResponse:
    need(request, "viewer")
    if fmt not in ("txt", "md"):
        raise HTTPException(404)
    return PlainTextResponse(_plan_text(customer, stem), media_type="text/markdown" if fmt == "md" else "text/plain",
                             headers={"Content-Disposition": f'attachment; filename="changeplan-{customer}-{stem}.{fmt}"'})


@app.get("/changesets/{customer}/{stem}/changeplan/{part}.{fmt}")
def changeplan_part_file(request: Request, customer: str, stem: str, part: str, fmt: str) -> PlainTextResponse:
    need(request, "viewer")
    if fmt not in ("txt", "md") or part not in ("cr", "cli", "rollback", "verify"):
        raise HTTPException(404)
    text = _plan_parts(customer, stem).get(part) or ""
    return PlainTextResponse(text, media_type="text/markdown" if fmt == "md" else "text/plain",
                             headers={"Content-Disposition": f'attachment; filename="changeplan-{customer}-{stem}-{part}.{fmt}"'})


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get("/favicon.svg")
@app.get("/favicon.ico")
def favicon() -> Response:
    """Browser tab icon (inline SVG; same mark as the sidebar). Public, like /healthz."""
    return Response(brand.favicon_svg(), media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=86400"})



# ------------------------------------------------------------------ backup files (prep+)

def _backup_rows(prof, user: tuple[str, str]) -> str:
    rows = []
    for rec in uploads.list_uploads(prof):
        when = uploads.format_uploaded(rec.get("uploaded") or "")
        host = rec.get("hostname") or "—"
        ver = rec.get("version") or "—"
        counts = (f"vsys {rec.get('vsys', 0)}, device groups {rec.get('device_groups', 0)}, "
                  f"template stacks {rec.get('template_stacks', 0)}, addresses {rec.get('addresses', 0)}, "
                  f"rules {rec.get('rules', 0)}")
        can = uploads.can_delete(rec, user[0], "admin" if user.can("user_admin") else user[1])
        delete = (f"<form method='post' action='/backups/{e(prof.name)}/{e(rec['id'])}/delete' style='display:inline'>"
                  "<button class='danger' style='margin:0;padding:4px 10px'>Delete</button></form>"
                  if can else "")
        rows.append(
            f"<tr><td><code>{e(rec['id'])}</code></td><td>{e(rec.get('original_name') or '')}</td>"
            f"<td>{e(rec.get('kind') or '')}</td><td>{e(host)}</td><td>{e(ver)}</td>"
            f"<td>{e(counts)}</td><td>{e(when)}</td><td>{e(rec.get('uploaded_by') or '')}</td>"
            f"<td><code>{e(rec.get('sha256') or '')}</code></td><td>{delete}</td></tr>"
        )
    if not rows:
        return "<p>No backup files uploaded for this customer yet.</p>"
    return ("<table><tr><th>Id</th><th>File</th><th>Type</th><th>Hostname</th><th>PAN-OS</th>"
            "<th>Summary</th><th>Uploaded</th><th>By</th><th>SHA-256</th><th></th></tr>"
            + "".join(rows) + "</table>")


@app.get("/backups", response_class=HTMLResponse)
def backups_page(request: Request, customer: str = "", msg: str = "") -> HTMLResponse:
    user = need(request, "prep")
    names = list_customers()
    chosen = customer if customer in names else (names[0] if names else "")
    opts = "".join(
        f"<option value='{e(c)}'{' selected' if c == chosen else ''}>{e(load_profile(c).display_name)} ({e(c)})</option>"
        for c in names
    )
    listing = ""
    retention = ""
    if chosen:
        prof = load_profile(chosen)
        days = int(getattr(prof, "config_retention_days", 0) or 0)
        retention = (f"<p>Auto-expiry: {days} day(s) (profile <code>config_retention_days</code>).</p>"
                     if days > 0 else "<p>Auto-expiry is off for this customer (<code>config_retention_days</code> unset).</p>")
        listing = _backup_rows(prof, user)
    note = f"<div class='note'>{e(msg)}</div>" if msg else ""
    body = f"""<h2>Backup files</h2>
{note}
<div class='note'>Upload a Palo Alto firewall or Panorama configuration snapshot (.xml; .tgz / .tar.gz device-state or
Panorama bundles are accepted). The file is stored under this customer's data directory (mode 600), never in git.
You can build a change plan from it; those change sets are <b>plan only</b> and cannot be pushed. Maximum size is
{uploads.max_backup_bytes() // (1024 * 1024)} MB. The configuration XML itself is never written to the audit log.</div>
<form method='get' action='/backups'><label>Customer</label><select name='customer' onchange='this.form.submit()'>{opts}</select></form>
{retention}
{listing}
<h3>Upload to {e(chosen) or 'a customer'}</h3>
<form method='post' action='/backups/upload' enctype='multipart/form-data'>
<input type='hidden' name='customer' value='{e(chosen)}'>
<label>Backup file (.xml, .tgz, .tar.gz)</label>
<input type='file' name='file' accept='.xml,.tgz,.tar.gz,.tar' required>
<br><button>Upload backup</button>
</form>
<h3>Create an offline customer from a backup</h3>
<p>Use this when you just have a file and no existing customer profile. A placeholder profile is generated
(no device credentials). Naming uses the built-in templates; edit the generated YAML later if you need to.</p>
<form method='post' action='/backups/offline' enctype='multipart/form-data'>
<label>New customer name (lowercase letters, digits, hyphen, underscore)</label>
<input name='name' required pattern='[a-z0-9][a-z0-9_-]{{0,62}}' size='30'>
<label>Display name (optional)</label>
<input name='display_name' size='40'>
<label>Backup file</label>
<input type='file' name='file' accept='.xml,.tgz,.tar.gz,.tar' required>
<br><button>Create offline customer</button>
</form>
"""
    return page("backup files", body, user)


@app.post("/backups/upload", response_class=HTMLResponse)
async def backups_upload(request: Request, customer: str = Form(...), file: UploadFile = File(...)) -> HTMLResponse:
    user = need(request, "prep", customer=customer)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(400, str(exc))
    name = Path(file.filename or "backup.xml").name
    data = await _read_upload(file, uploads.max_backup_bytes())
    try:
        rec = uploads.store(prof, data, name, uploaded_by=user[0])
    except uploads.UploadError as exc:
        raise HTTPException(400, str(exc))
    msg = (f"Stored {rec['original_name']} as {rec['id']} ({rec['kind']}, sha256 {rec['sha256'][:8]}). "
           "Use it as the config source on the Upload FCRs or Decommission page.")
    return RedirectResponse("/backups?" + urlencode({"customer": customer, "msg": msg}), status_code=303)


@app.post("/backups/offline", response_class=HTMLResponse)
async def backups_offline(request: Request, name: str = Form(...), display_name: str = Form(""),
                          file: UploadFile = File(...)) -> HTMLResponse:
    user = need(request, "prep")
    if not user.all_customers():
        raise HTTPException(403, "adding a new customer needs access to all customers")
    fname = Path(file.filename or "backup.xml").name
    data = await _read_upload(file, uploads.max_backup_bytes())
    try:
        prof, rec = uploads.create_offline_customer(name, data, fname, uploaded_by=user[0], display_name=display_name)
    except uploads.UploadError as exc:
        raise HTTPException(400, str(exc))
    msg = (f"Created offline customer {prof.name} from {rec['original_name']} ({rec['id']}, {rec['kind']}). "
           "It appears in the customer list; change sets from this backup cannot be pushed.")
    return RedirectResponse("/backups?" + urlencode({"customer": prof.name, "msg": msg}), status_code=303)


@app.post("/backups/{customer}/{ident}/delete", response_class=HTMLResponse)
def backups_delete(request: Request, customer: str, ident: str) -> HTMLResponse:
    user = need(request, "prep")
    try:
        prof = load_profile(customer)
        rec = uploads.get(prof, ident)
    except (ValueError, FileNotFoundError, uploads.UploadError) as exc:
        raise HTTPException(404, str(exc))
    if not uploads.can_delete(rec, user[0], "admin" if user.can("user_admin") else user[1]):
        raise HTTPException(403, "only the uploader or an admin can delete this file")
    uploads.delete(prof, ident, actor=user[0])
    return RedirectResponse("/backups?" + urlencode({"customer": customer, "msg": f"Deleted {rec['original_name']} ({rec['id']})."}), status_code=303)


# ------------------------------------------------------------------ push area (engineer only, red bar)

def _list(items: list[str], cls: str = "") -> str:
    return "<ul>" + "".join(f"<li class='{cls}'>{e(i)}</li>" for i in items) + "</ul>" if items else "<p>None.</p>"



def _push_item_picker(cs: dict) -> str:
    """Tick boxes for each planned rule (and each group). All are on by default. Gates stay on the same form."""
    items = pusher.selectable_items(cs)
    rules = [it for it in items if it["kind"] == "rule"]
    if not rules:
        return ""
    rows: list[str] = []
    for it in items:
        tok = e(it["token"])
        if it["kind"] == "group":
            rows.append(
                f"<li class='push-group'><label><input type='checkbox' name='item' value='{tok}' "
                f"checked class='push-group-all'> <b>Whole group:</b> {e(it['label'])}</label></li>"
            )
            continue
        extra = e(it.get("device_group") or it.get("vsys") or "")
        small = f" <small>{extra}</small>" if extra else ""
        rows.append(
            f"<li><label><input type='checkbox' name='item' value='{tok}' checked> {e(it['label'])}{small}</label></li>"
        )
    js_all = "document.querySelectorAll('.push-pick input[name=item]').forEach(function(x){x.checked=true})"
    js_none = "document.querySelectorAll('.push-pick input[name=item]').forEach(function(x){x.checked=false})"
    return (
        "<div class='push-pick'><p><b>Rules to include in this prepare</b></p>"
        "<p class='muted'>Tick a subset to push only those rules (for example the first vsys, then the second). "
        "An approved CR, confirmation, and backup are still required. Leaving every box ticked prepares the full plan.</p>"
        '<p><button type="button" class="sm" onclick="' + js_all + '">Select all</button> '
        '<button type="button" class="sm" onclick="' + js_none + '">Select none</button></p>'
        "<input type='hidden' name='have_selection' value='yes'>"
        f"<ul>{''.join(rows)}</ul></div>"
    )


@app.get("/push/{customer}/{stem}", response_class=HTMLResponse)
def push_form(request: Request, customer: str, stem: str) -> HTMLResponse:
    user = need(request, "engineer")
    cs = json.loads(_cs_path(customer, stem, "json").read_text())
    prof = load_profile(customer)
    if uploads.is_plan_only(cs):
        lab = uploads.source_label(cs) or "uploaded backup"
        body = (f"<h2>Customer: {e(customer)}</h2><h3>Push change set {e(stem)}</h3>"
                f"<div class='note'><b>{e(uploads.PLAN_ONLY)}</b>. {e(lab)}. "
                "This change set was built from an uploaded backup and cannot be prepared or applied on a device. "
                "Copy the change plan into the CR instead.</div>"
                f"<p><a href='/changesets/{e(customer)}/{e(stem)}'>review</a> · "
                f"<a href='/changesets/{e(customer)}/{e(stem)}/changeplan'>change plan</a></p>")
        return page("push", body, user, push=True)
    live_pano = pusher.live_panorama_push_allowed(prof)
    targets = [(t.name, identity.label(t.name, identity.cached(prof, t.name)) + (
        " (Panorama: live apply opted in)" if t.type == "panorama" and live_pano
        else " (Panorama: dry run only)" if t.type == "panorama" else "")) for t in prof.targets
        if _target_ok(user, prof, t.name)]
    if any(t.type == "panorama" for t in prof.targets) and live_pano:
        pano_note = ("<div class='note'><b>Panorama (explicit opt-in):</b> this customer has "
                     "<code>allow_live_panorama_push</code> enabled. Prepare still writes nothing. "
                     "Apply commits to Panorama, then pushes each device group with commit-all limited "
                     "to the target serials. A CR, confirmation, and the engineer role are required, "
                     "same as a firewall push.</div>")
    elif any(t.type == "panorama" for t in prof.targets):
        pano_note = ("<div class='note'><b>Panorama:</b> the push is a <b>dry run only</b>. Prepare reads the Panorama config, re-checks "
                     "device groups, target firewalls, zones, objects and rule names, and shows the exact changes and the commit-and-push "
                     "plan. Nothing is written to Panorama; implement it by hand from the change plan.</div>")
    else:
        pano_note = ""
    sm = cs["summary"]
    kind = cs.get("kind") or "add"
    counts = (f"{sm.get('edited_rules', 0)} rules edited, {sm.get('deleted_rules', 0)} deleted, "
              f"{sm.get('deleted_objects', 0)} objects deleted, {sm['needs_human']} need a human, {sm['red_flags']} red flags"
              if kind == "decommission" else
              f"{sm['rules']} rules, {sm['new_objects']} new objects, {sm['needs_human']} need a human, {sm['red_flags']} red flags")
    lead = stepper_html(cs, customer, stem, current="push", prof=prof, user=user) + multiplace.banner_html(cs) + blast_html(cs)
    gate = approval.check_push_allowed(prof, cs, stem, user[0])
    gate_note = f"<div class='blast red'><p class='verdict'>{e(gate)}</p></div>" if gate else ""
    form = ""
    if not gate:
        form = (
            f"<form method='post' action='/push/{e(customer)}/{e(stem)}/prepare'>"
            f"<label>Approved CR number (format {e(prof.tickets['cr'])})</label><input name='cr' required size='20'>"
            "<label><input type='checkbox' name='approved' value='yes' required> This CR is approved and I am inside its change window</label>"
            "<label>Target (profile name · hostname (serial) the device last reported; Prepare reads it again)</label>"
            "<select name='target'>" + "".join(f"<option value='{e(v)}'>{e(t)}</option>" for v, t in targets) + "</select>"
            + _push_item_picker(cs)
            + "<br><button class='danger'>Prepare (backup + re-validate + dry-run diff)</button></form>"
        )
    body = (f"<h2>Customer: {e(customer)}</h2><h3>Push change set {e(stem)}</h3>" + lead + gate_note
            + theme.help_note("plan-only-and-live-push.md", "Prepare is a dry-run. Apply is the write. An approved CR and, when the customer requires it, a second-person approval are required.")
            + f"<p>{counts}. "
            f"<a href='/changesets/{e(customer)}/{e(stem)}'>review</a> · <a href='/changesets/{e(customer)}/{e(stem)}/changeplan'>change plan</a></p>"
            "<div class='note'>Step 1 of 3: <b>Prepare</b> backs up the running config, re-validates this change set against the live "
            "config, and shows exactly what would change. Nothing is written in this step.</div>" + pano_note + form
            + f"<p><a href='/audit/{e(customer)}'>Audit log for {e(customer)}</a></p>")
    return page("push", body, user, push=True)


def _target_ok(user, prof, target: str) -> bool:
    """Is this profile target inside the user's device scope for the customer (by name, hostname or serial)?"""
    pats = user.device_scope(prof.name)
    if pats is None:
        return True
    idn = identity.cached(prof, target) or {}
    return auth.device_in_scope(pats, target=target, hostname=idn.get("hostname") or "", serial=idn.get("serial") or "")


def _session_page(prof, s: dict, user, msg: str = "") -> HTMLResponse:
    c = e(prof.name)
    sid = e(s["id"])
    idn = s.get("identity")
    word = identity.confirm_word(idn, s["target"])
    what = "the hostname the device reports" if idn and word == idn.get("hostname") else (
        "the serial number" if idn and word == idn.get("serial") else "the target name")
    tgt_input = (f"<label>Type {what}, <code>{e(word)}</code>, to confirm</label>"
                 "<input name='confirm_target' required autocomplete='off'>")
    actions = ""
    if s["status"] == "prepared":
        pano_live = s.get("target_type") == "panorama"
        apply_blurb = ("writes the candidate, commits to Panorama with CR {cr} in the description, "
                       "pushes each device group with commit-all limited to the target serials, then verifies."
                       if pano_live else
                       "writes the candidate, commits with CR {cr} in the description, then verifies.")
        apply_btn = "Apply + commit to Panorama, then push to firewalls" if pano_live else "Apply + commit to the firewall"
        actions = (f"<div class='note'>Step 2 of 3: <b>Apply + commit</b> re-checks the live config, "
                   + apply_blurb.format(cr=e(s['cr'])) + "</div>"
                   f"<form method='post' action='/push/{c}/session/{sid}/apply'>{tgt_input}"
                   f"<br><button class='danger'>{apply_btn}</button></form>")
    elif s["status"] == "dry-run":
        plan = "".join(f"<li>{e(p['step'])}: <code>{e(p['api'])}</code> <code>{e(p['cmd'])}</code></li>" for p in s.get("push_plan", []))
        actions = ("<div class='note'><b>Dry run only (Panorama).</b> Nothing was written to Panorama and there is no Apply button. "
                   "Implement it by hand from the change plan: Commit to Panorama, then Push to Devices for each device group, "
                   "only the target firewalls.</div>"
                   f"<h3>Commit-and-push plan (not executed)</h3><ul>{plan}</ul>"
                   f"<p><a href='/changesets/{c}/{e(s['changeset'])}/changeplan'>Open the change plan</a></p>")
    elif s["status"] in ("committed", "committed-verify-failed", "committed-push-failed"):
        actions = (f"<div class='note'>Step 3: if anything is wrong, run the generated rollback (deletes this push's rules, then only "
                   f"objects it created that nothing else references; the shared tag is kept).</div>"
                   f"<form method='post' action='/push/{c}/session/{sid}/rollback'>{tgt_input}"
                   "<br><button class='secondary'>Run rollback</button></form>")
    ver = "".join(f"<li>{'OK' if v['ok'] else 'FAIL'}: {e(v['check'])} {e(v.get('detail', ''))}</li>"
                  for v in s.get("verify", []) + s.get("rollback_verify", []))
    jobs = "".join(f"<li>{e(j['step'])}: job {e(str(j.get('jobid')))} success={j.get('success')} "
                   f"{e('; '.join(j.get('messages') or [])[:600])}</li>" for j in s["jobs"])
    body = (f"<h2>Customer: {c}</h2><h3>Push session {sid}</h3>" + (f"<div class='note'>{e(msg)}</div>" if msg else "")
            + f"<p>Status <b>{e(s['status'])}</b>{(' · ' + e(s.get('result', ''))) if s.get('result') else ''}</p>"
            f"<p>Target {_ident_html(s['target'], s.get('identity'))}</p><p>CR <b>{e(s['cr'])}</b> · change set {e(s['changeset'])} · prepared by {e(s['prepared_by'])} "
            f"at {e(s['prepared_at'])} · backup {e(Path(s['backup']).name)}</p>" + (f"<p>This prepare includes a subset of the plan: <code>{e(', '.join(s['selected']))}</code></p>" if s.get('selected') is not None else "")
            + "".join(f"<p class='muted'>Off-box copy OK: {e(r['name'])} ({e(r['type'])}), {len(r['files'])} file(s) verified</p>"
                      if r["ok"] else
                      f"<div style='border-left:4px solid #9a6700;padding:4px 8px;margin:6px 0;background:#fff8e1'><b>CHECK: off-box "
                      f"copy to {e(r['name'])} ({e(r['type'])}) failed.</b> {e(r['error'])} The local backup is kept.</div>"
                      for r in s.get("offsite") or [])
            + f"<h3>Re-validation errors</h3>{_list(s['errors'])}<h3>Warnings</h3>{_list(s['warnings'])}"
            "<h3>Dry-run diff</h3><pre style='background:#f6f6f6;padding:8px'>" + e("\n".join(s["diff"]) or "(nothing)") + "</pre>"
            + (f"<h3>Commit jobs</h3><ul>{jobs}</ul>" if jobs else "") + (f"<h3>Verification</h3><ul>{ver}</ul>" if ver else "")
            + (f"<h3>Rollback</h3><pre>{e(json.dumps(s['rollback_result'], indent=1))}</pre>" if s.get("rollback_result") else "")
            + (f"<h3>Change audit report</h3><p>Download and attach to the CR: <a href='/push/{c}/session/{sid}/report.md'>report.md</a> · "
               f"<a href='/push/{c}/session/{sid}/report.json'>report.json</a></p>" if s.get("report") else "")
            + actions + f"<p><a href='/audit/{c}'>Audit log</a></p>")
    return page("push session", body, user, push=True)


def _ident_html(name: str, idn: dict | None) -> str:
    """Device headline: reported hostname + serial; profile name small and grey (see identity.html_label)."""
    return identity.html_label(name, idn)


def _read_identity(prof, s: dict, dev, actor: str, when: str) -> dict:
    """Read hostname + serial from the push target (read-only), cache it, and write an audit line."""
    idn = identity.read_push_device(dev)
    identity.remember(prof, s["target"], idn)
    pusher.audit(prof, actor=actor, action=f"device-identity ({when})", session=s["id"], cr=s.get("cr"),
                 target=identity.label(s["target"], idn), hostname=idn["hostname"] or identity.UNKNOWN_HOST,
                 serial=idn["serial"] or identity.UNKNOWN_SERIAL, changeset=s.get("changeset"))
    return idn


def _load_cs(prof, stem: str) -> dict:
    return json.loads(_cs_path(prof.name, stem, "json").read_text())


@app.post("/push/{customer}/{stem}/prepare", response_class=HTMLResponse)
def push_prepare(request: Request, customer: str, stem: str, cr: str = Form(...), approved: str = Form(""),
                 target: str = Form(...), have_selection: str = Form(""), item: list[str] = Form(default=[])) -> HTMLResponse:
    user = need(request, "engineer")
    prof = load_profile(customer)
    cs = _load_cs(prof, stem)
    if uploads.is_plan_only(cs):
        raise HTTPException(400, uploads.PLAN_ONLY)
    if approved != "yes":
        raise HTTPException(400, "confirm that the CR is approved")
    blocked = approval.check_push_allowed(prof, cs, stem, user[0])
    if blocked:
        raise HTTPException(400, blocked)
    if not _target_ok(user, prof, target):
        raise HTTPException(403, f"{target} is not in your device scope")
    try:
        pusher.check_cr(prof, cr)
        dev = device_factory(prof, target)
        selected = list(item) if have_selection == "yes" else None
        if have_selection == "yes" and not selected:
            raise pusher.PushError("Tick at least one planned rule or group to prepare.")
        s = pusher.prepare(prof, cs, stem, actor=user[0], cr=cr, dev=dev, target_name=target, selected=selected)
    except pusher.PushError as exc:
        raise HTTPException(400, str(exc))
    s["identity"] = _read_identity(prof, s, dev, user[0], "prepare")
    if s.get("backup") and Path(s["backup"]).is_file():  # admin-configured off-box copies; never blocks the push
        from panlab import offsite
        s["offsite"] = offsite.ship(prof, [offsite.Item(Path(s["backup"]), "pre-change-running-config")], run_id=s["id"],
                                    kind="push", ident=s["identity"], actor=user[0], cr=s.get("cr", ""),
                                    extra={"profile_name": s["target"], "changeset": s.get("changeset")})
    pusher._save(prof, s)
    if s.get("report"):
        pusher.write_report(prof, s, cs)
    return _session_page(prof, s, user)


@app.get("/push/{customer}/session/{sid}", response_class=HTMLResponse)
def push_session(request: Request, customer: str, sid: str) -> HTMLResponse:
    user = need(request, "engineer")
    prof = load_profile(customer)
    try:
        return _session_page(prof, pusher.load_session(prof, sid), user)
    except pusher.PushError:
        raise HTTPException(404)


@app.post("/push/{customer}/session/{sid}/{action}", response_class=HTMLResponse)
def push_action(request: Request, customer: str, sid: str, action: str, confirm_target: str = Form(...)) -> HTMLResponse:
    user = need(request, "engineer")
    prof = load_profile(customer)
    if action not in ("apply", "rollback"):
        raise HTTPException(404)
    try:
        s = pusher.load_session(prof, sid)
        if not _target_ok(user, prof, s["target"]):
            raise HTTPException(403, f"{s['target']} is not in your device scope")
        cs = _load_cs(prof, s["changeset"])
        if action == "apply":
            blocked = approval.check_push_allowed(prof, cs, s["changeset"], user[0])
            if blocked:
                raise HTTPException(400, blocked)
        fn = pusher.apply if action == "apply" else pusher.rollback
        word = identity.confirm_word(s.get("identity"), s["target"])
        if confirm_target.strip() != word:
            raise pusher.PushError(f"type {word} exactly to confirm (what {s['target']} reported when it was prepared)")
        dev = device_factory(prof, s["target"])
        was, now_id = s.get("identity") or {}, identity.read_push_device(dev)
        if was.get("serial") and now_id.get("serial") and was["serial"] != now_id["serial"]:
            raise pusher.PushError(f"a different device answered: prepared on serial {was['serial']} ({was.get('hostname')}), "
                                   f"now serial {now_id['serial']} ({now_id.get('hostname')}). Nothing was written.")
        s = fn(prof, cs, sid, actor=user[0], confirm_target=s["target"], dev=dev)
    except pusher.PushError as exc:
        s = pusher.load_session(prof, sid) if pusher.SESSION_RE.match(sid) else None
        if s is None:
            raise HTTPException(400, str(exc))
        return _session_page(prof, s, user, msg=f"Refused: {exc}")
    return _session_page(prof, s, user)


@app.get("/push/{customer}/session/{sid}/report.{fmt}")
def push_report(request: Request, customer: str, sid: str, fmt: str) -> PlainTextResponse:
    need(request, "engineer")
    prof = load_profile(customer)
    if fmt not in ("md", "json") or not pusher.SESSION_RE.match(sid):
        raise HTTPException(404)
    p = prof.data_dir("push") / f"{sid}-report.{fmt}"
    if not p.is_file():
        raise HTTPException(404)
    return PlainTextResponse(p.read_text(encoding="utf-8"), media_type="application/json" if fmt == "json" else "text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="{sid}-report.{fmt}"'})


def _audit_device(prof, r: dict) -> str:
    """hostname (serial) for an audit line: from the line itself, else from its push session."""
    if r.get("hostname") or r.get("serial"):
        return f"{r.get('hostname') or identity.UNKNOWN_HOST} ({r.get('serial') or identity.UNKNOWN_SERIAL})"
    if r.get("session"):
        try:
            idn = pusher.load_session(prof, r["session"]).get("identity")
        except (pusher.PushError, OSError, ValueError):
            idn = None
        if idn:
            return identity.label("", idn)
    return ""


@app.get("/audit/{customer}", response_class=HTMLResponse)
def audit_page(request: Request, customer: str) -> HTMLResponse:
    user = need(request, "engineer")
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404)
    rows = "".join(
        f"<tr><td>{e(r.get('ts', ''))}</td><td>{e(r.get('actor', ''))}</td><td>{e(r.get('action', ''))}</td><td>{e(r.get('cr', ''))}</td>"
        f"<td>{e(r.get('target', ''))}</td><td>{e(_audit_device(prof, r))}</td><td>{e(r.get('changeset', ''))}</td>"
        f"<td><a href='/push/{e(customer)}/session/{e(r.get('session', ''))}'>{e(r.get('session', ''))}</a></td>"
        f"<td>{e(', '.join(str(j) for j in r.get('job_ids') or []))}</td><td>{e(r.get('result', ''))}</td>"
        + (f"<td><a href='/push/{e(customer)}/session/{e(r['session'])}/report.md'>md</a> · "
           f"<a href='/push/{e(customer)}/session/{e(r['session'])}/report.json'>json</a></td>" if r.get("report") else "<td></td>")
        + "</tr>"
        for r in reversed(pusher.read_audit(prof)))
    body = ("<h2>Customer: " + e(customer) + "</h2><h3>Audit log</h3><table><tr><th>When (America/Chicago)</th><th>Who</th><th>Action</th><th>CR</th>"
            "<th>Target</th><th>Device (hostname, serial)</th><th>Change set</th><th>Session</th><th>Job ids</th><th>Result</th><th>Audit report</th></tr>" + rows + "</table>")
    return page("audit", body, user, push=True)


# ------------------------------------------------------------------ traffic-log deny lookup (read-only)

def _bounded(v: str, lo: int, hi: int, default: int) -> int:
    try:
        return max(lo, min(hi, int(v)))
    except ValueError:
        return default


@app.post("/denylog/{customer}/{stem}")
def denylog_changeset(request: Request, customer: str, stem: str, days: str = Form("7"), max_logs: str = Form("200")):
    user = need(request, "prep")
    prof = load_profile(customer)
    cs = json.loads(_cs_path(customer, stem, "json").read_text())
    if uploads.is_plan_only(cs):
        raise HTTPException(400, "Traffic-log lookup is not available for change sets built from a backup file.")
    try:
        ev = denylog.changeset_evidence(prof, cs, log_factory(prof, None), days=_bounded(days, 1, 30, 7),
                                        max_logs=_bounded(max_logs, 10, 1000, 200))
    except pusher.PushError as exc:
        raise HTTPException(400, str(exc))
    ev["by"] = user[0]
    denylog.save_evidence(prof, stem, ev)
    return RedirectResponse(f"/changesets/{customer}/{stem}", status_code=303)


@app.get("/denylog/{customer}", response_class=HTMLResponse)
def denylog_form(request: Request, customer: str) -> HTMLResponse:
    user = need(request, "prep")
    load_profile(customer)
    body = (f"<h2>Why is my traffic blocked? ({e(customer)})</h2><div class='note'>Looks up denied traffic in the firewall's "
            "traffic logs and tests today's policy. Read-only: nothing on the firewall is changed.</div>"
            f"<form method='post' action='/denylog/{e(customer)}'><label>Source IP</label><input name='src' required>"
            "<label>Destination IP</label><input name='dst' required><label>Protocol</label><select name='proto'><option>tcp</option>"
            "<option>udp</option></select><label>Destination port</label><input name='port' required size='6'>"
            "<label>Source zone / destination zone (optional, improves the policy test)</label><input name='from_zone'> "
            "<input name='to_zone'><label>Days to search</label><input name='days' value='7' size='3'>"
            "<br><button>Look up denies</button></form>")
    return page("deny lookup", body, user)


@app.post("/denylog/{customer}", response_class=HTMLResponse)
def denylog_adhoc(request: Request, customer: str, src: str = Form(...), dst: str = Form(...), proto: str = Form("tcp"),
                  port: str = Form(...), from_zone: str = Form(""), to_zone: str = Form(""), days: str = Form("7")) -> HTMLResponse:
    user = need(request, "prep")
    prof = load_profile(customer)
    try:
        q = denylog.adhoc_query(src, dst, proto, port, from_zone, to_zone)
        api = log_factory(prof, None)
        r = denylog.lookup(api, name="(proposed rule)", q=q, apps=[], days=_bounded(days, 1, 30, 7), max_logs=200,
                           rulebase=api.running_rule_names())
    except pusher.PushError as exc:
        raise HTTPException(400, str(exc))
    lines = denylog.evidence_lines({"generated": pusher.now().isoformat(timespec="seconds"), "target": prof.targets[0].name,
                                    "window_days": r["window_days"], "results": [r]})
    body = (f"<h2>Deny lookup: {e(src)} &rarr; {e(dst)} {e(proto)}/{e(port)}</h2><ul>"
            + "".join(f"<li>{e(x.lstrip('- ').strip())}</li>" for x in lines) + "</ul>"
            f"<p><a href='/denylog/{e(customer)}'>new lookup</a></p>")
    return page("deny lookup", body, user)


# OS upgrade wizard (separate module; see panlab.web.upgrade_routes).
from panlab.web.upgrade_routes import router as _upgrade_router  # noqa: E402
from panlab.web.offsite_routes import router as _offsite_router  # noqa: E402
from panlab.web.access_routes import router as _access_router  # noqa: E402
from panlab.web.advisor_routes import router as _advisor_router  # noqa: E402
from panlab.web.urlfilter_routes import router as _urlfilter_router  # noqa: E402
from panlab.web.edl_routes import router as _edl_router  # noqa: E402
from panlab.web.flowmapper_routes import router as _flow_router  # noqa: E402
from panlab.web.search_routes import router as _search_router  # noqa: E402
from panlab.web.approval_routes import router as _approval_router  # noqa: E402
from panlab.web.api_v1 import router as _api_v1_router  # noqa: E402
from panlab.web.help_routes import router as _help_router  # noqa: E402

app.include_router(_help_router)
app.include_router(_upgrade_router)
app.include_router(_offsite_router)
app.include_router(_access_router)
app.include_router(_advisor_router)
app.include_router(_urlfilter_router)
app.include_router(_edl_router)
app.include_router(_flow_router)
app.include_router(_search_router)
app.include_router(_approval_router)
app.include_router(_api_v1_router)
