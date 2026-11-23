# SPDX-License-Identifier: Apache-2.0
"""Admin page: per-customer off-box backup destinations (git, SFTP, FTPS, S3).

Needs the backup_admin permission (and the customer in scope). Secrets are written to /etc/panlab/backup-destinations/<customer>.env
(mode 600) and are never shown again: the page only says whether each one is set.
"""

from __future__ import annotations

import html

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from panlab import offsite
from panlab.customers import load_profile

router = APIRouter()
e = html.escape
BASE = "/admin/backup-destinations"
HELP = {
    "git": "A separate <b>private</b> repo for this customer (never the tool's own repo; it is refused). "
           "https:// URL + token with write access, or git@host:owner/repo.git + a deploy key with write access.",
    "sftp": "SSH file transfer. Password or private key. The server's host key must be pinned (Test shows it).",
    "ftps": "FTP over TLS (explicit). Plain FTP is not offered: it sends the password and configs in clear text.",
    "s3": "AWS S3 or S3-compatible (MinIO, Wasabi...). Leave endpoint blank for AWS. Path-style is usually needed for MinIO.",
}
LABEL = {"url": "Repository URL", "branch": "Branch (default main)", "base_dir": "Folder inside the destination (optional)",
         "host_key": "Pinned SSH host key (type + base64; Test shows it)", "host": "Host", "port": "Port",
         "username": "Username", "verify_tls": "Verify the TLS certificate (yes/no)", "endpoint_url": "Endpoint URL (blank = AWS)",
         "region": "Region", "bucket": "Bucket", "prefix": "Key prefix (optional)", "path_style": "Path-style addressing (yes/no)",
         "token": "Access token", "ssh_key": "Private key (OpenSSH format)", "password": "Password",
         "access_key": "Access key id", "secret_key": "Secret access key"}


def _web():
    from panlab.web import app as webapp
    return webapp


def _prof(customer: str):
    try:
        return load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")


def _form(customer: str, typ: str, d: dict | None, setmap: dict[str, bool]) -> str:
    d = d or {}
    fields = "".join(
        f"<label>{e(LABEL[f])}</label><input name='{f}' value='{e(str(d.get(f, '')))}' size='60'"
        f"{' readonly' if f == 'host_key' and False else ''}>" for f in offsite.FIELDS[typ])
    secs = "".join(
        (f"<label>{e(LABEL[f])} <span class='muted'>({'set; leave blank to keep' if setmap.get(f) else 'not set'})</span></label>"
         + (f"<textarea name='sec_{f}' rows='3' cols='60' autocomplete='off'></textarea>" if f == "ssh_key"
            else f"<input type='password' name='sec_{f}' size='60' autocomplete='new-password'>"))
        for f in offsite.SECRETS[typ])
    return (f"<form method='post' action='{BASE}/{e(customer)}/save' class='card'>"
            f"<h3>{'Edit' if d.get('id') else 'Add'} {e(typ.upper())} destination</h3><p class='muted'>{HELP[typ]}</p>"
            f"<input type='hidden' name='type' value='{e(typ)}'>"
            f"<label>Id (lowercase, e.g. {e(typ)}1)</label><input name='id' value='{e(d.get('id', typ + '1'))}' "
            f"{'readonly' if d.get('id') else ''} size='20'>"
            f"<label>Name</label><input name='name' value='{e(d.get('name', ''))}' size='40'>"
            f"{fields}{secs}"
            f"<label><input type='checkbox' name='enabled' value='yes' {'checked' if d.get('enabled', True) else ''}> Enabled "
            "(every backup for this customer is also copied here)</label><br><button>Save</button></form>")


@router.get(BASE, response_class=HTMLResponse)
def dest_page(request: Request, customer: str = "", edit: str = "", add: str = "", msg: str = "", ok: str = "",
              hostkey: str = "", hk_for: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, "backup_admin")
    names = w.list_customers()
    customer = customer if customer in names else (names[0] if names else "")
    opts = "".join(f"<option {'selected' if c == customer else ''}>{e(c)}</option>" for c in names)
    body = ((f"<h2>Customer: {e(customer)}</h2>" if customer else "")
            + "<h3>Backup destinations (admin)</h3>"
            "<div class='note'>Every backup the tool takes (OS upgrade backups, the running config saved before a push) is "
            "always kept on this server. Here an admin can add <b>extra</b> off-box copies for a customer. They apply to every "
            "run for that customer, whoever runs it. Each file is verified after upload and audited. If a copy fails, the run "
            "shows a yellow CHECK and carries on; it never blocks an upgrade or push. Passwords, tokens and keys are stored in "
            "<code>/etc/panlab/backup-destinations/&lt;customer&gt;.env</code> (mode 600) and never shown again.</div>"
            f"<form method='get' action='{BASE}'><label>Customer</label><select name='customer' onchange='this.form.submit()'>{opts}"
            "</select> <button>Open</button></form>")
    if msg:
        color = "#1a7f37" if ok == "1" else "#9a6700"
        body += f"<div class='note' style='border-color:{color}'>{e(msg)}</div>"
    if not customer:
        return w.page("backup destinations", body, user)
    dests = offsite.load_config(customer)
    rows = []
    for d in dests:
        try:
            where = offsite.backend(customer, d).describe()
        except Exception as exc:  # noqa: BLE001
            where = f"(invalid: {exc})"
        sm = offsite.secrets_set(customer, d)
        sec = ", ".join(f"{k} {'set' if v else 'not set'}" for k, v in sm.items())
        c, i = e(customer), e(d["id"])
        hk = ""
        if hostkey and hk_for == d["id"]:
            hk = (f"<div class='note'>The server presented <code>{e(hostkey)}</code>. Compare it with the server's real key "
                  "(e.g. <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code> on the server, or the provider's published "
                  "fingerprints) before pinning."
                  f"<form method='post' action='{BASE}/{c}/{i}/pin'><input type='hidden' name='host_key' value='{e(hostkey)}'>"
                  "<button>Pin this host key</button></form></div>")
        btn = lambda a, label, col="#1f3b57": (f"<form method='post' action='{BASE}/{c}/{i}/{a}' style='display:inline'>"  # noqa: E731
                                              f"<button style='background:{col};margin:2px;padding:4px 10px'>{label}</button></form>")
        rows.append(f"<tr><td><b>{e(d.get('name', ''))}</b><br><code>{i}</code></td><td>{e(d['type'])}</td><td>{e(where)}</td>"
                    f"<td>{'yes' if d.get('enabled') else 'no'}</td><td>{e(sec)}</td><td>"
                    + btn("test", "Test connection")
                    + (btn("scan", "Fetch host key") if d["type"] in ("sftp", "git") else "")
                    + f"<a href='{BASE}?customer={c}&edit={i}'>Edit</a> "
                    + btn("delete", "Delete", "#b00020") + f"{hk}</td></tr>")
    from panlab import identity
    devs = "".join(f"<li>{identity.html_label(t.name, identity.cached(_prof(customer), t.name), note=False)} "
                   f"<span class='muted'>folder <code>{e(offsite.device_path(customer, identity.cached(_prof(customer), t.name)))}/</code></span></li>"
                   for t in _prof(customer).targets)
    body += ("<h3>Devices (as they last reported themselves) and their backup folders</h3><ul>" + devs + "</ul>"
             "<p class='muted'>Inside each device folder, backups are filed by year, month and day: <code>YYYY/MM/DD/</code>.</p>"
             "<p class='muted'>A device shown as hostname unknown has not been read yet; run OS upgrade discovery or a push "
             "Prepare for it.</p>")
    body += ("<h3>Destinations</h3>" + ("<table><tr><th>Destination</th><th>Type</th><th>Where</th><th>Enabled</th>"
                                         "<th>Secrets</th><th></th></tr>" + "".join(rows) + "</table>" if rows else
                                         "<p>None. Backups for this customer stay on this server only (the default).</p>"))
    cur = next((d for d in dests if d["id"] == edit), None)
    if cur:
        body += _form(customer, cur["type"], cur, offsite.secrets_set(customer, cur))
    elif add in offsite.TYPES:
        body += _form(customer, add, None, {})
    else:
        body += ("<p>Add a destination: " + " · ".join(
            f"<a href='{BASE}?customer={e(customer)}&add={t}'>{t.upper()}</a>" for t in offsite.TYPES) + "</p>")
    return w.page("backup destinations", body, user)


def _back(customer: str, msg: str, ok: bool, **kw: str) -> RedirectResponse:
    from urllib.parse import urlencode

    return RedirectResponse(f"{BASE}?" + urlencode({"customer": customer, "msg": msg, "ok": "1" if ok else "0", **kw}),
                            status_code=303)


@router.post(f"{BASE}/{{customer}}/save")
async def dest_save(request: Request, customer: str):
    w = _web()
    user = w.need(request, "backup_admin")
    prof = _prof(customer)
    form = await request.form()
    typ = str(form.get("type") or "")
    d = {k: str(form.get(k) or "") for k in ("id", "type", "name", *offsite.FIELDS.get(typ, ()))}
    d["enabled"] = form.get("enabled") == "yes"
    secs = {f: str(form.get(f"sec_{f}") or "") for f in offsite.SECRETS.get(typ, ())}
    try:
        d = offsite.save_destination(customer, d, secs)
    except offsite.OffsiteError as exc:
        return _back(customer, f"Not saved: {exc}", False, **({"add": typ} if typ in offsite.TYPES else {}))
    from panlab.pusher import audit
    audit(prof, actor=user[0], action="backup-destination-save", destination=f"{d['name']} ({d['type']})", dest_id=d["id"],
          enabled=d["enabled"], secrets_changed=sorted(k for k, v in secs.items() if v.strip()), result="ok")
    return _back(customer, f"Saved {d['name']}. Use Test connection before relying on it.", True)


@router.post(f"{BASE}/{{customer}}/{{did}}/{{action}}")
def dest_action(request: Request, customer: str, did: str, action: str, host_key: str = Form("")):
    w = _web()
    user = w.need(request, "backup_admin")
    prof = _prof(customer)
    from panlab.pusher import audit
    if not any(d["id"] == did for d in offsite.load_config(customer)):
        raise HTTPException(404)
    if action == "delete":
        offsite.delete_destination(customer, did)
        audit(prof, actor=user[0], action="backup-destination-delete", dest_id=did, result="ok")
        return _back(customer, f"Deleted {did} and its stored secrets.", True)
    if action == "test":
        ok, msg = offsite.test_destination(customer, did, prof.data_dir())
        audit(prof, actor=user[0], action="backup-destination-test", dest_id=did, result="ok" if ok else "failed",
              error="" if ok else msg[:300])
        return _back(customer, ("Test passed: " if ok else "Test FAILED: ") + msg, ok)
    if action == "scan":
        try:
            key = offsite.scan_host_key(customer, did)
        except Exception as exc:  # noqa: BLE001
            return _back(customer, f"Could not fetch the host key: {type(exc).__name__}: {exc}", False)
        return _back(customer, "Host key fetched; check it before pinning.", True, hostkey=key, hk_for=did)
    if action == "pin":
        parts = host_key.split()
        if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-")):
            return _back(customer, "That does not look like an SSH host key.", False)
        offsite.set_field(customer, did, "host_key", " ".join(parts[:2]))
        audit(prof, actor=user[0], action="backup-destination-pin-hostkey", dest_id=did, host_key=" ".join(parts[:2]), result="ok")
        return _back(customer, "Host key pinned. Run Test connection.", True)
    raise HTTPException(404)
