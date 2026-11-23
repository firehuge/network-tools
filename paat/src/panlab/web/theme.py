"""Shared look and navigation for every PAAT GUI page: design tokens, one stylesheet,
a grouped left sidebar, a top bar with breadcrumbs, the user/role chip and Help.

Pure presentation: it only builds strings from the signed-in user's permissions and
the current path. No page logic lives here. Element ids, form field names and routes
used by the pages are untouched. No external assets: icons are inline SVG and the
small script is inline, so the GUI works on an offline server.
"""

from __future__ import annotations

import html

from panlab import brand
from panlab.web import layers

e = html.escape

# (label, href, permissions that show it (any of), path prefixes that mark it current, icon, sidebar group)
NAV: list[tuple[str, str, tuple[str, ...], tuple[str, ...], str, str]] = [
    ("Upload FCRs", "/", ("fcr", "request"), ("/import",), "upload", "Change requests"),
    ("Trace a flow", "/flow", ("flow", "fcr", "view"), ("/flow",), "route", "Change requests"),
    ("Change sets", "/changesets", ("view",), ("/changesets", "/denylog", "/audit", "/push"), "layers", "Change requests"),
    ("Decommission", "/decom", ("fcr",), ("/decom",), "trash", "Change requests"),
    ("OS upgrades", "/upgrade", ("upgrade_plan", "upgrade_exec"), ("/upgrade",), "upgrade", "Operations"),
    ("URL filter", "/urlfilter", ("urlfilter_request", "urlfilter_approve"), ("/urlfilter",), "shield", "Operations"),
    ("External dynamic lists", "/edls", ("edl_view", "edl_edit", "edl_approve", "edl_admin"), ("/edls",), "list", "Operations"),
    ("App-ID advisor", "/advisor", ("view", "fcr"), ("/advisor",), "bulb", "Operations"),
    ("Backup files", "/backups", ("fcr",), ("/backups",), "database", "Operations"),
]
ADMIN: list[tuple[str, str, str, tuple[str, ...], str]] = [
    ("Users", "/users", "user_admin", ("/users",), "users"),
    ("Backup destinations", "/admin/backup-destinations", "backup_admin", ("/admin/backup-destinations",), "cloud"),
]
GROUPS = ("Change requests", "Operations")

# Home quick actions: (title, href, any-of permissions, description, icon)
TILES: list[tuple[str, str, tuple[str, ...], str, str]] = [
    ("Upload FCRs", "/", ("fcr", "request"), "Upload firewall change request spreadsheets and preview the plan: placement, objects, risks, and rules already permitted.", "upload"),
    ("Trace a flow", "/flow", ("flow", "fcr", "view"), "Trace an FCR against a live read-only pull of Panorama and the firewalls (or backups): every hop, verdict, and the full change plan.", "route"),
    ("Saved change sets", "/changesets", ("view",), "Open earlier plans, change plans, reports, traffic-log evidence and audits.", "layers"),
    ("Push changes", "/changesets", ("push",), "Open a saved change set and use its Push area (approved CR required, every step audited).", "send"),
    ("Decommission", "/decom", ("fcr",), "Find the rules and objects that reference old hosts or names and plan their removal.", "trash"),
    ("OS upgrades", "/upgrade", ("upgrade_plan", "upgrade_exec"), "Discover devices, build a safe upgrade plan, and run it step by step.", "upgrade"),
    ("URL filter self-service", "/urlfilter", ("urlfilter_request", "urlfilter_approve"), "Request URL Filtering category and allow/block list changes, or review, approve and push them.", "shield"),
    ("External dynamic lists", "/edls", ("edl_view", "edl_edit", "edl_approve", "edl_admin"), "Add or remove blocked IPs, domains and URLs. Firewalls fetch the list themselves: nobody touches a firewall.", "list"),
    ("App-ID advisor", "/advisor", ("view", "fcr"), "Turn a port-based rule into an App-ID rule from what the traffic logs show.", "bulb"),
    ("Backup files", "/backups", ("fcr",), "Upload device backups to plan against, or record an offline device.", "database"),
    ("Users", "/users", ("user_admin",), "Add people, set permissions, customer and device scope, and reset passwords.", "users"),
    ("Backup destinations", "/admin/backup-destinations", ("backup_admin",), "Per-customer git, SFTP or S3 destinations for device backups.", "cloud"),
]

# First path segment -> section label (breadcrumbs)
SECTIONS = {
    "": "Upload FCRs", "import": "Upload FCRs", "decom": "Decommission", "changesets": "Saved change sets",
    "backups": "Backup files", "advisor": "App-ID advisor", "upgrade": "OS upgrades", "push": "Saved change sets",
    "audit": "Saved change sets", "denylog": "Saved change sets", "users": "Users", "password": "Change password",
    "admin": "Backup destinations", "home": "", "urlfilter": "URL filter self-service", "flow": "Trace a flow", "search": "Search",
    "help": "Help", "about": "About", "edls": "External dynamic lists",
}
SECTION_HREF = {"Upload FCRs": "/", "Decommission": "/decom", "Saved change sets": "/changesets", "Backup files": "/backups",
                "App-ID advisor": "/advisor", "OS upgrades": "/upgrade", "Users": "/users",
                "Backup destinations": "/admin/backup-destinations", "Change password": "/password",
                "URL filter self-service": "/urlfilter", "Trace a flow": "/flow", "Search": "/search",
                "Help": "/help", "About": "/help/about", "External dynamic lists": "/edls"}

# 24x24 stroke icons (drawn for PAAT; no icon font, no CDN)
_ICON_PATHS = {
    "home": "<path d='M3 11l9-8 9 8'/><path d='M5 10v10h5v-6h4v6h5V10'/>",
    "upload": "<path d='M12 15V4'/><path d='M7 9l5-5 5 5'/><path d='M4 15v5h16v-5'/>",
    "route": "<circle cx='5' cy='6' r='2'/><path d='M7 6h7a3 3 0 0 1 0 6h-4a3 3 0 0 0 0 6h7'/><path d='M16 15l3 3-3 3'/>",
    "layers": "<path d='M12 3l9 5-9 5-9-5 9-5z'/><path d='M3 13l9 5 9-5'/>",
    "trash": "<path d='M4 7h16'/><path d='M9 7V4h6v3'/><path d='M6 7l1 13h10l1-13'/><path d='M10 11v6M14 11v6'/>",
    "upgrade": "<circle cx='12' cy='12' r='9'/><path d='M12 16V8M8 12l4-4 4 4'/>",
    "shield": "<path d='M12 3l8 3v6c0 5-3.4 8-8 9-4.6-1-8-4-8-9V6l8-3z'/><path d='M9 12l2 2 4-4'/>",
    "bulb": "<path d='M9 18h6M10 21h4'/><path d='M12 3a6 6 0 0 0-4 10.5c.7.7 1 1.5 1 2.5h6c0-1 .3-1.8 1-2.5A6 6 0 0 0 12 3z'/>",
    "database": "<ellipse cx='12' cy='6' rx='8' ry='3'/><path d='M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6'/><path d='M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3'/>",
    "users": "<circle cx='9' cy='8' r='4'/><path d='M2 20v-1a5 5 0 0 1 5-5h4a5 5 0 0 1 5 5v1'/><path d='M16 4a4 4 0 0 1 0 8M22 20v-1a5 5 0 0 0-3-4.6'/>",
    "cloud": "<path d='M7 18h10a4 4 0 0 0 .6-8A6 6 0 0 0 6.2 9.6 4.2 4.2 0 0 0 7 18z'/>",
    "help": "<circle cx='12' cy='12' r='9'/><path d='M9.5 9.5a2.5 2.5 0 0 1 5 .2c0 1.6-2.5 2-2.5 3.6'/><path d='M12 17h.01'/>",
    "info": "<circle cx='12' cy='12' r='9'/><path d='M12 11v6'/><path d='M12 7.5h.01'/>",
    "search": "<circle cx='11' cy='11' r='7'/><path d='M20 20l-4-4'/>",
    "send": "<path d='M21 3L10 14'/><path d='M21 3l-7 18-4-7-7-4 18-7z'/>",
    "moon": "<path d='M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z'/>",
    "menu": "<path d='M4 6h16M4 12h16M4 18h16'/>",
    "chevron": "<path d='M6 9l6 6 6-6'/>",
    "logout": "<path d='M15 4h4v16h-4'/><path d='M10 8l-4 4 4 4M6 12h10'/>",
    "key": "<circle cx='8' cy='15' r='4'/><path d='M11 12l9-9M17 6l3 3'/>",
    "check": "<path d='M5 12l5 5 9-10'/>",
    "alert": "<path d='M12 3l10 18H2L12 3z'/><path d='M12 10v5M12 18h.01'/>",
    "clock": "<circle cx='12' cy='12' r='9'/><path d='M12 7v5l3 2'/>",
    "file": "<path d='M14 3H6v18h12V7l-4-4z'/><path d='M14 3v4h4'/>",
    "lock": "<rect x='5' y='11' width='14' height='10' rx='2'/><path d='M8 11V7a4 4 0 0 1 8 0v4'/>",
    "list": "<path d='M9 6h11M9 12h11M9 18h11'/><path d='M4 6h.01M4 12h.01M4 18h.01'/>",
    "building": "<path d='M4 21V5l8-2v18M12 8h8v13M8 8h.01M8 12h.01M8 16h.01M16 12h.01M16 16h.01'/>",
}


def icon(name: str, cls: str = "ic") -> str:
    inner = _ICON_PATHS.get(name, _ICON_PATHS["file"])
    return (f"<svg class='{cls}' viewBox='0 0 24 24' aria-hidden='true' focusable='false' fill='none' stroke='currentColor' "
            f"stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'>{inner}</svg>")


LOGO = brand.mark_svg()
FAVICON = "/favicon.svg"  # served by the app (same origin; no external asset)


def badge(text: str, tone: str = "neutral") -> str:
    """Status pill. tone: success, warning, danger, info, neutral, push."""
    return f"<span class='badge b-{e(tone)}'>{e(text)}</span>"


def empty_state(title: str, text: str = "", action: str = "", icon_name: str = "file") -> str:
    return (f"<div class='empty'>{icon(icon_name, 'ic empty-ic')}<h3>{e(title)}</h3>"
            + (f"<p>{e(text)}</p>" if text else "") + action + "</div>")


def _can(user, *perms: str) -> bool:
    c = getattr(user, "can", None)
    return bool(user) and c is not None and any(c(p) for p in perms)


def _current(path: str, prefixes: tuple[str, ...], href: str) -> bool:
    if href == "/":
        return path in ("/", "/import") or path.startswith("/import")
    return any(path == p or path.startswith(p + "/") for p in prefixes)


def scope_text(user) -> str:
    cs = getattr(user, "customers", None)
    if cs is None:
        return ""
    if not cs:
        return "No customers"
    if "*" in cs:
        return "All customers"
    return cs[0] if len(cs) == 1 else f"{len(cs)} customers"


def crumbs(path: str, title: str) -> str:
    parts = [p for p in path.strip("/").split("/") if p]
    if path == "/":
        return ("<nav class='crumbs' aria-label='Breadcrumb'><a href='/home'>Home</a> <span class='sep'>/</span> "
                "<span aria-current='page'>Upload FCRs</span></nav>")
    if not parts or parts[0] == "home":
        return ""
    sec = SECTIONS.get(parts[0], "")
    items = [("Home", "/home")]
    if parts[0] == "admin" and len(parts) > 1 and parts[1] != "backup-destinations":
        sec = ""
    if sec:
        items.append((sec, SECTION_HREF.get(sec, "")))
    if parts[0] in ("changesets", "push") and len(parts) >= 3 and parts[1] != "session":
        stem = parts[2]
        items.append((stem, f"/changesets/{parts[1]}/{stem}"))
        if parts[0] == "push" and len(parts) == 3:
            items.append(("Push area", ""))
        elif parts[0] == "changesets" and len(parts) > 3:
            items.append((parts[3].split(".")[0].replace("changeplan", "change plan"), ""))
    elif parts[0] in ("push", "upgrade", "advisor", "audit", "denylog", "urlfilter") and len(parts) >= 2:
        up = {"disc": "Step 2: pick devices", "plan": "Upgrade plan", "run": "Live upgrade"}
        label = {"push": "Push session", "upgrade": up.get(parts[2], title) if len(parts) > 2 else title,
                 "advisor": "Result " + parts[2] if len(parts) > 2 else title,
                 "audit": "Audit", "denylog": "Traffic-log lookup",
                 "urlfilter": ("New request" if parts[2] == "new" else "Request " + parts[2]) if len(parts) > 2 else parts[1]}[parts[0]]
        if label and label != items[-1][0]:
            items.append((label, ""))

    elif parts[0] == "edls" and len(parts) >= 3:
        items.append((parts[2] if parts[2] not in ("new", "settings", "objects") else
                      {"new": "New list", "settings": "Safety settings", "objects": "Firewall objects"}[parts[2]],
                      f"/edls/{parts[1]}/{parts[2]}" if len(parts) > 3 else ""))
        if len(parts) > 3:
            items.append((title, ""))
    elif parts[0] not in SECTIONS and title:
        items.append((title, ""))
    out = []
    for i, (label, href) in enumerate(items):
        last = i == len(items) - 1
        out.append(f"<span aria-current='page'>{e(label)}</span>" if last or not href else f"<a href='{e(href)}'>{e(label)}</a>")
    return "<nav class='crumbs' aria-label='Breadcrumb'>" + " <span class='sep'>/</span> ".join(out) + "</nav>"


def _navlink(label: str, href: str, cur: bool, icon_name: str) -> str:
    # Keep "href='…' class='cur'" adjacent: tests and the crawler key on it.
    aria = " aria-current='page'" if cur else ""
    return f"<a href='{href}' class='{'cur' if cur else ''}'{aria}>{icon(icon_name)}<span>{e(label)}</span></a>"


def sidebar(user, path: str, push: bool, version: str) -> str:
    """Left navigation grouped by function. Only links the user's permissions allow."""
    links = [_navlink("Home", "/home", path == "/home", "home")]
    groups: dict[str, list[str]] = {g: [] for g in GROUPS}
    if user:
        for label, href, perms, prefixes, ic, grp in NAV:
            if _can(user, *perms):
                groups[grp].append(_navlink(label, href, _current(path, prefixes, href), ic))
    sec = ["<div class='navsec'>" + "".join(links) + "</div>"]
    for g in GROUPS:
        if groups[g]:
            sec.append(f"<div class='navsec'><div class='navhead'>{e(g)}</div>{''.join(groups[g])}</div>")
    adm = [(l, h, p, ic) for l, h, perm, p, ic in ADMIN if user and _can(user, perm)]
    if adm:
        items = "".join(_navlink(l, h, _current(path, p, h), ic) for l, h, p, ic in adm)
        sec.append(f"<div class='navsec admin'><div class='navhead'>Administration</div>{items}</div>")
    help_cur = path == "/help" or path.startswith("/help/")
    foot = (f"<div class='sidefoot'>{_navlink('Help & SOP', '/help', help_cur, 'help')}"
            f"<div class='ver'>{brand.NAME} v{e(version)}</div></div>")
    return ("<aside class='sidebar' id='pl-sidebar' aria-label='Main navigation'>"
            "<a class='brand' href='/home' title='Home'>" + LOGO +
            f"<span><b>{brand.NAME}</b><small>{e(brand.TAGLINE)}</small></span></a>"
            "<nav class='sidenav mainnav'>" + "".join(sec) + "</nav>" + foot + "</aside>")


def topbar(user, path: str, push: bool, version: str, crumb: str = "") -> str:
    """Top bar: menu button (narrow screens), breadcrumbs, search, Help, theme toggle, user/role chip."""
    right = []
    if user and _can(user, "view"):
        right.append("<form class='search' method='get' action='/search' role='search'>" + icon("search") +
                     "<input type='search' name='q' placeholder='Search change sets, RITM, CR' aria-label='Search change sets'>"
                     "<button type='submit' class='visually-hidden'>Search</button></form>")
    if push:
        right.append("<span class='area push'>" + icon("alert") + "PUSH AREA</span>")
    right.append(f"<a href='/help' class='iconbtn' title='Help and step-by-step guide'>{icon('help')}<span class='lbl'>Help</span></a>")
    right.append(f"<button type='button' class='iconbtn' id='pl-theme' title='Switch light / dark' aria-label='Switch light or dark theme'>{icon('moon')}</button>")
    if user:
        scope = scope_text(user)
        initials = e((user[0] or "?")[:2].upper())
        right.append(
            "<details class='usermenu'><summary class='who' aria-label='Account menu'>"
            f"<span class='avatar'>{initials}</span><span class='whotext'><b>{e(user[0])}</b>"
            f"<span class='role'>{e(layers.layer_label(user))}</span></span>{icon('chevron', 'ic chev')}</summary>"
            "<div class='drop'>"
            f"<div class='drophead'><b>{e(user[0])}</b><span>{e(layers.layer_label(user))}</span>"
            + (f"<span class='scope'>{icon('building')}{e(scope)}</span>" if scope else "") + "</div>"
            f"<a href='/password'>{icon('key')}Change password</a>"
            f"<a href='/help'>{icon('help')}Help</a>"
            f"<a href='/help/about'>{icon('info')}About {brand.NAME}</a>"
            f"<a href='/logout'>{icon('logout')}Log out</a></div></details>")
    burger = ("<label for='pl-navtoggle' class='burger' aria-label='Menu' title='Menu'>" + icon("menu") + "</label>") if user else ""
    return (f"<header class='top{' pushbar' if push else ''}'>{burger}<div class='crumbwrap'>{crumb}</div>"
            f"<div class='right'>{''.join(right)}</div></header>")


def document(title: str, body: str, user, path: str, push: bool, version: str, redbar: str = "") -> str:
    """Whole HTML page: sidebar + top bar for signed-in users, a centred card layout otherwise."""
    head = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<meta name='color-scheme' content='light dark'><title>{e(title)} · {brand.NAME}</title>"
            f"<meta name='description' content='{e(brand.DESCRIPTION)}'><meta name='application-name' content='{brand.NAME}'>"
            f"<link rel='icon' type='image/svg+xml' href='{FAVICON}'>"
            f"<script>{HEAD_JS}</script><style>{CSS}</style></head>")
    if not user:
        return (head + "<body class='bare'><main class='baremain'>" + body + "</main>"
                f"<div class='foot'>{brand.FULL_NAME} · v{e(version)}</div><div id='pl-toasts' aria-live='polite'></div>"
                f"<script>{JS}</script></body></html>")
    crumb = crumbs(path, title)
    return (head + f"<body class='app{' push' if push else ''}'>"
            "<input type='checkbox' id='pl-navtoggle' class='navtoggle' aria-hidden='true'>"
            + sidebar(user, path, push, version) +
            "<label for='pl-navtoggle' class='scrim' aria-hidden='true'></label>"
            "<div class='shell'>" + topbar(user, path, push, version, crumb) + redbar +
            f"<main id='main'>{body}</main><div class='foot'>{brand.FULL_NAME} · v{e(version)} · {e(brand.FOR)}</div></div>"
            "<div id='pl-toasts' aria-live='polite'></div>"
            f"<script>{JS}</script></body></html>")


def help_note(manual_page: str, sentence: str) -> str:
    """Short in-page help that names the matching user-manual page."""
    return (
        f"<details class='help'><summary>{icon('help')}How this page works</summary>"
        f"<p>{e(sentence)}</p>"
        f"<p class='muted'>User manual: <a href='/help/{e(manual_page.removesuffix('.md'))}'>{e(manual_page)}</a>"
        " &middot; <a href='/help/index'>Manual index</a></p></details>"
    )


def home_tiles(user) -> str:
    tiles = []
    for title, href, perms, desc, ic in TILES:
        if _can(user, *perms):
            tiles.append(f"<a class='tile' href='{href}'><span class='tile-ic'>{icon(ic)}</span>"
                         f"<span class='tile-body'><h3>{e(title)}</h3><p>{e(desc)}</p></span></a>")
    if not tiles:
        return empty_state("No tools yet", "Your account has no tool permissions yet. Ask an administrator.", icon_name="lock")
    return "<div class='tiles'>" + "".join(tiles) + "</div>"


def kpi(label: str, value, href: str = "", tone: str = "neutral", hint: str = "", ic: str = "file") -> str:
    inner = (f"<span class='kpi-ic t-{e(tone)}'>{icon(ic)}</span><span class='kpi-body'><b>{e(str(value))}</b>"
             f"<span class='kpi-label'>{e(label)}</span>" + (f"<span class='kpi-hint'>{e(hint)}</span>" if hint else "") + "</span>")
    return (f"<a class='stat kpi' href='{e(href)}'>{inner}</a>" if href else f"<div class='stat kpi'>{inner}</div>")


# Runs before first paint: apply the saved theme so there is no flash.
HEAD_JS = ("(function(){try{var t=localStorage.getItem('pl-theme');if(t)document.documentElement.setAttribute('data-theme',t);}"
           "catch(e){}})();")

JS = r"""
(function(){
var d=document;
// theme toggle
var tb=d.getElementById('pl-theme');
if(tb)tb.addEventListener('click',function(){var r=d.documentElement,n=r.getAttribute('data-theme')==='dark'?'light':'dark';
 r.setAttribute('data-theme',n);try{localStorage.setItem('pl-theme',n);}catch(e){}});
// toasts: ?msg= and ?ok= flash messages (text only)
function toast(text,tone){var box=d.getElementById('pl-toasts');if(!box||!text)return;var t=d.createElement('div');
 t.className='toast t-'+tone;t.setAttribute('role',tone==='danger'?'alert':'status');var s=d.createElement('span');s.textContent=text;
 var x=d.createElement('button');x.type='button';x.className='toastx';x.setAttribute('aria-label','Dismiss');x.textContent='\u00d7';
 x.onclick=function(){t.remove();};t.appendChild(s);t.appendChild(x);box.appendChild(t);setTimeout(function(){t.classList.add('out');
 setTimeout(function(){t.remove();},400);},7000);}
window.plToast=toast;
try{var q=new URLSearchParams(location.search);var m=q.get('msg')||q.get('ok');
 var shown=Array.prototype.some.call(d.querySelectorAll('main .note'),function(n){return n.textContent.indexOf(m)>=0;});
 if(m&&!shown){toast(m,/wrong|fail|error|could not|refus|not allowed|denied|fix |invalid|reject/i.test(m)?'danger':'success');}}catch(e){}
// loading state on submit (disable after the browser has read the form, so button values still post)
d.addEventListener('submit',function(ev){var f=ev.target;if(ev.defaultPrevented||f.method.toLowerCase()==='get'&&f.classList.contains('search'))return;
 if(f.target==='_blank'||f.hasAttribute('data-noload'))return;var b=ev.submitter||f.querySelector('button[type=submit],button:not([type])');
 d.body.classList.add('loading');if(b){setTimeout(function(){b.classList.add('busy');b.setAttribute('aria-busy','true');b.disabled=true;},0);
 setTimeout(function(){b.disabled=false;b.classList.remove('busy');d.body.classList.remove('loading');},20000);}},false);
window.addEventListener('pageshow',function(){d.body.classList.remove('loading');d.querySelectorAll('button.busy').forEach(function(b){b.disabled=false;b.classList.remove('busy');});});
// tables: sortable headers, filter box for long tables, empty state for empty tables
function txt(c){return (c&&c.textContent||'').trim();}
function num(s){var m=s.replace(/,/g,'').match(/^-?\d+(\.\d+)?$/);return m?parseFloat(s.replace(/,/g,'')):null;}
d.querySelectorAll('main table').forEach(function(tbl){
 if(tbl.classList.contains('nosort')||tbl.closest('.helpdoc'))return;
 var rows=Array.prototype.slice.call(tbl.rows);if(!rows.length)return;var head=rows[0];
 var isHead=head.cells.length&&Array.prototype.every.call(head.cells,function(c){return c.tagName==='TH';});
 if(!isHead)return;var data=rows.slice(1);
 if(!data.length){var r=tbl.insertRow();var c=r.insertCell();c.colSpan=head.cells.length;c.className='emptyrow';c.textContent='Nothing here yet.';return;}
 if(tbl.querySelector('[rowspan],[colspan]'))return;
 var body=data[0].parentNode;tbl.classList.add('sortable');
 Array.prototype.forEach.call(head.cells,function(th,i){if(!txt(th))return;th.tabIndex=0;th.setAttribute('aria-sort','none');th.title='Sort';
  function go(){var asc=th.getAttribute('aria-sort')!=='ascending';Array.prototype.forEach.call(head.cells,function(h){h.setAttribute('aria-sort','none');});
   th.setAttribute('aria-sort',asc?'ascending':'descending');var cur=Array.prototype.slice.call(tbl.rows,1);
   cur.sort(function(a,b){var x=txt(a.cells[i]),y=txt(b.cells[i]),nx=num(x),ny=num(y);var r=(nx!==null&&ny!==null)?nx-ny:x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'});return asc?r:-r;});
   cur.forEach(function(r){body.appendChild(r);});}
  th.addEventListener('click',go);th.addEventListener('keydown',function(k){if(k.key==='Enter'||k.key===' '){k.preventDefault();go();}});});
 if(data.length>=8){var w=d.createElement('div');w.className='tablefilter';var inp=d.createElement('input');inp.type='search';
  inp.placeholder='Filter '+data.length+' rows';inp.setAttribute('aria-label','Filter table rows');var cnt=d.createElement('span');cnt.className='muted';
  w.appendChild(inp);w.appendChild(cnt);tbl.parentNode.insertBefore(w,tbl);
  inp.addEventListener('input',function(){var v=inp.value.toLowerCase(),n=0;Array.prototype.slice.call(tbl.rows,1).forEach(function(r){
   var ok=!v||r.textContent.toLowerCase().indexOf(v)>=0;r.style.display=ok?'':'none';if(ok)n++;});cnt.textContent=v?(n+' shown'):'';});}
});
// close the account menu on outside click / Escape
d.addEventListener('click',function(ev){d.querySelectorAll('details.usermenu[open]').forEach(function(m){if(!m.contains(ev.target))m.removeAttribute('open');});});
d.addEventListener('keydown',function(ev){if(ev.key==='Escape'){d.querySelectorAll('details.usermenu[open]').forEach(function(m){m.removeAttribute('open');});
 var t=d.getElementById('pl-navtoggle');if(t)t.checked=false;}});
})();
"""

CSS = """
:root{
--brand:#1f5fd6;--brand-hover:#184cad;--brand-soft:#eaf1fe;--brand-ring:rgba(31,95,214,.28);
--bg:#f3f5f8;--surface:#fff;--surface-2:#f8fafc;--surface-3:#eef2f6;--border:#e1e6ed;--border-strong:#c9d2dd;
--text:#101828;--text-2:#344054;--muted:#667085;--faint:#98a2b3;
--side-bg:#0d1726;--side-bg2:#121f33;--side-text:#aeb9ca;--side-head:#6c7a90;--side-active:#fff;
--success:#157f3c;--success-soft:#e6f4ea;--warning:#a15c07;--warning-soft:#fef4e2;--danger:#c4271f;--danger-soft:#fdecea;
--info:#1f5fd6;--info-soft:#eaf1fe;--neutral:#475467;--neutral-soft:#eef1f5;--push:#9b1c1c;
--fs-xs:12px;--fs-sm:13px;--fs-md:14px;--fs-lg:16px;--fs-xl:20px;--fs-2xl:24px;
--sp-1:4px;--sp-2:8px;--sp-3:12px;--sp-4:16px;--sp-5:24px;--sp-6:32px;
--r-sm:6px;--r-md:8px;--r-lg:12px;--shadow-1:0 1px 2px rgba(16,24,40,.06);--shadow-2:0 4px 14px rgba(16,24,40,.08);--shadow-3:0 12px 32px rgba(16,24,40,.16);
--side-w:248px;--top-h:56px;
/* legacy names used by page fragments */
--navy:var(--text);--navy2:var(--text-2);--ink:var(--text);--line:var(--border);--card:var(--surface);--accent:var(--brand);--accent-d:var(--brand-hover);
--green:var(--success);--amber:var(--warning);--red:var(--danger)}
[data-theme=dark]{
--brand:#5b8dff;--brand-hover:#7aa2ff;--brand-soft:#16233d;--brand-ring:rgba(91,141,255,.35);
--bg:#0b1220;--surface:#111a2b;--surface-2:#152036;--surface-3:#1b2840;--border:#24324a;--border-strong:#33445f;
--text:#e6ebf3;--text-2:#c4cddb;--muted:#93a0b5;--faint:#6b7890;
--side-bg:#070d18;--side-bg2:#0c1424;
--success:#4ac26b;--success-soft:#11291b;--warning:#e3a23b;--warning-soft:#2e2310;--danger:#f2645c;--danger-soft:#33161a;
--info:#6f9bff;--info-soft:#16233d;--neutral:#a6b1c2;--neutral-soft:#1b2537;--push:#f2645c;
--shadow-1:0 1px 2px rgba(0,0,0,.4);--shadow-2:0 4px 14px rgba(0,0,0,.4);--shadow-3:0 12px 32px rgba(0,0,0,.55)}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;margin:0;color:var(--text);
 background:var(--bg);font-size:var(--fs-md);line-height:1.5;-webkit-font-smoothing:antialiased}
a{color:var(--brand);text-decoration:none}a:hover{text-decoration:underline}
h1,h2,h3,h4{color:var(--text);line-height:1.25;letter-spacing:-.01em}
h1{font-size:var(--fs-2xl);margin:4px 0 16px}h2{font-size:var(--fs-2xl);font-weight:650;margin:4px 0 16px}
h3{font-size:var(--fs-lg);font-weight:600}h4{font-size:var(--fs-md)}
.ic{width:18px;height:18px;flex:none;vertical-align:-4px}
.visually-hidden{position:absolute!important;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0;padding:0;margin:0}
:focus-visible{outline:2px solid var(--brand);outline-offset:2px}
/* app shell */
body.app{display:flex;align-items:flex-start;background:linear-gradient(to right,var(--side-bg) var(--side-w),var(--bg) var(--side-w))}
.sidebar{position:sticky;top:0;height:100vh;width:var(--side-w);flex:none;background:linear-gradient(180deg,var(--side-bg),var(--side-bg2));color:var(--side-text);
 display:flex;flex-direction:column;z-index:40;border-right:1px solid rgba(255,255,255,.04)}
.brand{display:flex;align-items:center;gap:10px;padding:16px 18px 14px;color:#fff!important;text-decoration:none!important}
.brand .mark{width:30px;height:30px;flex:none}
.brand b{font-size:17px;letter-spacing:.2px;display:block;line-height:1.1;color:#fff}.brand small{display:block;font-size:11px;color:#8494ab;font-weight:400}
.sidenav{flex:1;overflow-y:auto;padding:4px 10px 10px}
.navsec{margin:0 0 14px}.navhead{font-size:10.5px;text-transform:uppercase;letter-spacing:.09em;color:var(--side-head);font-weight:700;padding:8px 10px 6px}
.sidebar a{display:flex;align-items:center;gap:11px;padding:8px 10px;margin:1px 0;border-radius:var(--r-sm);color:var(--side-text);font-size:13.5px;font-weight:500;position:relative}
.sidebar a:hover{background:rgba(255,255,255,.06);color:#fff;text-decoration:none}
.sidebar a.cur{background:rgba(91,141,255,.16);color:var(--side-active)}
.sidebar a.cur::before{content:"";position:absolute;left:-10px;top:7px;bottom:7px;width:3px;border-radius:0 3px 3px 0;background:#5b8dff}
.sidebar a .ic{opacity:.9}
.sidefoot{border-top:1px solid rgba(255,255,255,.06);padding:8px 10px 12px}.sidefoot .ver{font-size:11px;color:var(--side-head);padding:6px 10px 0}
body.push .sidebar a.cur{background:rgba(242,100,92,.18)}body.push .sidebar a.cur::before{background:#f2645c}
.shell{flex:1;min-width:0;min-height:100vh;display:flex;flex-direction:column;background:var(--bg)}
header.top{position:sticky;top:0;z-index:30;height:var(--top-h);display:flex;align-items:center;gap:var(--sp-3);padding:0 var(--sp-5);
 background:color-mix(in srgb,var(--surface) 92%,transparent);backdrop-filter:saturate(1.4) blur(8px);border-bottom:1px solid var(--border)}
header.top.pushbar{border-bottom:2px solid var(--danger)}
.crumbwrap{flex:1;min-width:0;overflow:hidden}
.crumbs{font-size:var(--fs-sm);color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin:0}
.crumbs a{color:var(--muted)}.crumbs a:hover{color:var(--brand)}.crumbs .sep{margin:0 6px;color:var(--faint)}.crumbs [aria-current]{color:var(--text);font-weight:600}
.right{display:flex;align-items:center;gap:var(--sp-2);flex:none}
form.search{display:flex;align-items:center;gap:6px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r-md);padding:0 10px;height:36px;color:var(--muted)}
form.search:focus-within{border-color:var(--brand);box-shadow:0 0 0 3px var(--brand-ring)}
form.search input{border:0;background:transparent;outline:0;padding:0;height:34px;width:230px;font-size:var(--fs-sm);color:var(--text);box-shadow:none}
form.search input:focus{outline:0;box-shadow:none}
.iconbtn{display:inline-flex;align-items:center;gap:6px;height:36px;padding:0 10px;margin:0;border-radius:var(--r-md);border:1px solid transparent;background:transparent;
 color:var(--text-2)!important;font-size:var(--fs-sm);font-weight:500;cursor:pointer}
.iconbtn:hover{background:var(--surface-3);text-decoration:none;color:var(--text)!important}
.area.push{display:inline-flex;align-items:center;gap:6px;background:var(--danger);color:#fff;border-radius:999px;padding:4px 11px;font-size:11px;font-weight:700;letter-spacing:.06em}
.area.push .ic{width:14px;height:14px}
details.usermenu{position:relative}
details.usermenu summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:9px;padding:4px 8px 4px 4px;border-radius:999px;border:1px solid var(--border);background:var(--surface)}
details.usermenu summary::-webkit-details-marker{display:none}
details.usermenu summary:hover{background:var(--surface-2)}
.avatar{width:28px;height:28px;border-radius:50%;background:var(--brand);color:#fff;display:inline-flex;align-items:center;justify-content:center;font-size:11.5px;font-weight:700}
.whotext{display:flex;flex-direction:column;line-height:1.15}.whotext b{font-size:12.5px;color:var(--text)}
.role{font-size:11px;color:var(--muted)}
.chev{width:14px;height:14px;color:var(--muted)}
details.usermenu .drop{position:absolute;right:0;top:calc(100% + 6px);min-width:230px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);box-shadow:var(--shadow-3);padding:6px;z-index:50}
.drophead{padding:8px 10px 10px;border-bottom:1px solid var(--border);margin-bottom:4px;display:flex;flex-direction:column;gap:2px}
.drophead span{font-size:var(--fs-xs);color:var(--muted)}.drophead .scope{display:flex;align-items:center;gap:5px}.drophead .scope .ic{width:13px;height:13px}
details.usermenu .drop a{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:var(--r-sm);color:var(--text-2);font-size:var(--fs-sm)}
details.usermenu .drop a:hover{background:var(--surface-3);text-decoration:none}
main{padding:var(--sp-5) var(--sp-6) 40px;width:100%;max-width:1400px;margin:0 auto;flex:1}
.foot{max-width:1400px;width:100%;margin:0 auto;padding:0 var(--sp-6) 20px;color:var(--faint);font-size:11.5px}
.navtoggle,.burger,.scrim{display:none}
.burger{color:var(--text-2);cursor:pointer;padding:6px;border-radius:var(--r-sm);margin-left:-6px}.burger:hover{background:var(--surface-3)}.burger .ic{width:22px;height:22px}
.redbar{display:flex;align-items:center;gap:8px;background:var(--danger);color:#fff;padding:10px var(--sp-6);font-weight:600;font-size:13.5px;position:sticky;top:var(--top-h);z-index:20}
.subbar{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-md);padding:10px 14px;margin:0 0 16px;font-size:var(--fs-sm);box-shadow:var(--shadow-1)}
/* bare layout (login, signed-out errors) */
body.bare{min-height:100vh;background:radial-gradient(1200px 600px at 10% -10%,rgba(31,95,214,.16),transparent 60%),radial-gradient(900px 500px at 110% 110%,rgba(31,95,214,.10),transparent 60%),var(--bg)}
.baremain{max-width:980px;margin:0 auto;padding:48px 24px}
.login-wrap{max-width:400px;margin:40px auto}
.login-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:28px 30px 30px;box-shadow:var(--shadow-3)}
.login-card h2{margin:0 0 4px;font-size:var(--fs-xl)}.login-card input{width:100%}.login-card button{width:100%;margin-top:22px;padding:10px;justify-content:center}
.login-brand{text-align:center;margin-bottom:18px;color:var(--text)}
.login-brand .mark{width:56px;height:56px;display:inline-block;filter:drop-shadow(0 6px 14px rgba(31,95,214,.35))}
body.bare .foot{text-align:center}
.login-brand b{display:block;font-size:22px;margin-top:10px}.login-brand small{color:var(--muted)}
/* forms */
label{display:block;margin:14px 0 6px;font-weight:600;font-size:var(--fs-sm);color:var(--text-2)}
label:has(input[type=checkbox]),label:has(input[type=radio]){font-weight:500;display:flex;align-items:center;gap:2px}
input,select,textarea{padding:8px 11px;font-size:var(--fs-md);border:1px solid var(--border-strong);border-radius:var(--r-sm);background:var(--surface);color:var(--text);font-family:inherit;
 transition:border-color .12s,box-shadow .12s;max-width:100%}
input:hover,select:hover,textarea:hover{border-color:var(--faint)}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--brand);box-shadow:0 0 0 3px var(--brand-ring)}
input:user-invalid,select:user-invalid,textarea:user-invalid{border-color:var(--danger);box-shadow:0 0 0 3px rgba(196,39,31,.15)}
input[type=checkbox],input[type=radio]{padding:0;margin-right:6px;width:16px;height:16px;accent-color:var(--brand);vertical-align:-3px}
input[type=file]{padding:6px;background:var(--surface-2);border-style:dashed}
input[type=file]::file-selector-button{border:1px solid var(--border-strong);background:var(--surface);color:var(--text);border-radius:var(--r-sm);padding:5px 12px;margin-right:10px;font:inherit;cursor:pointer}
label:has(+input[required])::after,label:has(+select[required])::after,label:has(+textarea[required])::after{content:" *";color:var(--danger)}
button,.btn{display:inline-flex;align-items:center;gap:7px;background:var(--brand);color:#fff;border:1px solid var(--brand);padding:8px 16px;font-size:var(--fs-md);font-weight:600;
 border-radius:var(--r-sm);margin-top:14px;cursor:pointer;font-family:inherit;line-height:1.35;box-shadow:var(--shadow-1);transition:background .12s,box-shadow .12s}
button:hover,.btn:hover{background:var(--brand-hover);border-color:var(--brand-hover);text-decoration:none;color:#fff}
button.secondary,.btn.secondary{background:var(--surface);color:var(--text-2);border-color:var(--border-strong)}
button.secondary:hover,.btn.secondary:hover{background:var(--surface-3);color:var(--text)}
button.danger,.btn.danger{background:var(--danger);border-color:var(--danger)}button.danger:hover{filter:brightness(.92)}
button:disabled{opacity:.55;cursor:not-allowed}
button.busy::after{content:"";width:13px;height:13px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:plspin .7s linear infinite;margin-left:4px}
.iconbtn,header.top button{box-shadow:none}
@keyframes plspin{to{transform:rotate(360deg)}}
body.loading::before{content:"";position:fixed;top:0;left:0;height:3px;width:100%;z-index:100;background:linear-gradient(90deg,transparent,var(--brand),transparent);
 background-size:50% 100%;background-repeat:no-repeat;animation:plbar 1.1s ease-in-out infinite}
@keyframes plbar{from{background-position:-50% 0}to{background-position:150% 0}}
fieldset{border:1px solid var(--border);border-radius:var(--r-md);padding:10px 16px 16px;margin:14px 0;background:var(--surface)}
legend{font-weight:600;padding:0 6px;color:var(--text-2)}
/* notes, cards, sections */
.note{background:var(--info-soft);border:1px solid color-mix(in srgb,var(--info) 25%,transparent);border-left:4px solid var(--info);border-radius:var(--r-md);padding:10px 14px;margin:12px 0;color:var(--text)}
.muted{color:var(--muted);font-size:var(--fs-sm)}
.card,.plan-sec{border:1px solid var(--border);border-radius:var(--r-lg);background:var(--surface);padding:16px 20px;margin:16px 0;box-shadow:var(--shadow-1)}
.card>h3:first-child,.card>h2:first-child{margin-top:0}
.plan-sec{padding:0;margin:20px 0 28px;overflow:hidden}
.plan-sec h3{margin:0;padding:12px 18px;background:var(--surface-2);border-bottom:1px solid var(--border)}
.plan-sec .acts{float:right;font-weight:400;font-size:var(--fs-sm)}
.plan-sec .acts a,.plan-sec .acts button{margin:0 0 0 8px;padding:4px 10px;font-size:var(--fs-sm);border-radius:var(--r-sm)}
.plan-sec pre{white-space:pre-wrap;background:var(--surface-2);padding:14px 18px;margin:0;border:0;border-radius:0}
pre{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r-md);padding:12px 14px;overflow:auto;font-size:12.5px;line-height:1.5}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
code{background:var(--surface-3);border-radius:4px;padding:1px 5px;font-size:.92em}pre code{background:none;padding:0}
/* tables */
table{border-collapse:separate;border-spacing:0;background:var(--surface);border:1px solid var(--border);border-radius:var(--r-md);margin:8px 0 20px;box-shadow:var(--shadow-1);max-width:100%}
td,th{border-bottom:1px solid var(--border);padding:9px 12px;font-size:var(--fs-sm);vertical-align:top;text-align:left}
td+td,th+th{border-left:1px solid color-mix(in srgb,var(--border) 55%,transparent)}
tr:last-child>td{border-bottom:0}
th{background:var(--surface-2);color:var(--muted);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;position:sticky;top:var(--top-h);z-index:2}
tr:first-child>th:first-child{border-top-left-radius:var(--r-md)}tr:first-child>th:last-child{border-top-right-radius:var(--r-md)}
table.sortable th{cursor:pointer;user-select:none}table.sortable th:hover{color:var(--text)}
table.sortable th::after{content:"\\2195";opacity:.3;margin-left:5px;font-size:10px}
table.sortable th[aria-sort=ascending]::after{content:"\\25B2";opacity:.8}table.sortable th[aria-sort=descending]::after{content:"\\25BC";opacity:.8}
tr:not(.red):not(.yellow):not(.green):hover>td{background:color-mix(in srgb,var(--brand-soft) 60%,var(--surface))}
td.emptyrow{text-align:center;color:var(--muted);padding:22px;font-style:italic}
.tablefilter{display:flex;align-items:center;gap:10px;margin:10px 0 4px}.tablefilter input{width:280px;padding:6px 10px;font-size:var(--fs-sm)}
.red,tr.red>td{background:var(--danger-soft)}.yellow,tr.yellow>td{background:var(--warning-soft)}.green,tr.green>td{background:var(--success-soft)}
.new{color:var(--brand);font-weight:600}
.hop-allow td{background:var(--success-soft)}.hop-deny td{background:var(--danger-soft)}.hop-conditional td{background:var(--warning-soft)}
.lt{display:inline-block;color:#fff;border-radius:999px;padding:1px 9px;font-size:11.5px;font-weight:700;letter-spacing:.3px}
.tablewrap{overflow-x:auto}.tablewrap th{top:0}  /* inside a scroll box a sticky header must not be pushed down by the top bar height */
/* badges */
.badge{display:inline-flex;align-items:center;gap:5px;border-radius:999px;padding:2px 9px;font-size:11.5px;font-weight:600;white-space:nowrap;border:1px solid transparent}
.badge::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.b-success{background:var(--success-soft);color:var(--success)}.b-warning{background:var(--warning-soft);color:var(--warning)}
.b-danger{background:var(--danger-soft);color:var(--danger)}.b-info{background:var(--info-soft);color:var(--info)}
.b-neutral{background:var(--neutral-soft);color:var(--neutral)}.b-push{background:var(--danger);color:#fff}
/* report toolbar */
.toolbar{display:flex;align-items:center;flex-wrap:wrap;gap:8px}.toolbar .tsep{width:1px;height:18px;background:var(--border)}.toolbar .grow{flex:1}
.btn.sm,button.sm{padding:5px 11px;font-size:var(--fs-sm);margin:0}.btn.sm .ic{width:15px;height:15px}
.report>h1:first-child,.report h1{font-size:var(--fs-2xl);font-weight:650;margin:8px 0 6px}
/* filter chips */
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 12px}
.chip{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:999px;border:1px solid var(--border);background:var(--surface);color:var(--text-2);font-size:var(--fs-sm);font-weight:500}
.chip b{font-size:11.5px;background:var(--surface-3);border-radius:999px;padding:0 7px;color:var(--text-2)}
.chip:hover{text-decoration:none;border-color:var(--border-strong)}.chip.on{background:var(--brand);border-color:var(--brand);color:#fff}.chip.on b{background:rgba(255,255,255,.22);color:#fff}
/* change-set report */
.report th{text-transform:none;letter-spacing:0;font-size:12.5px}
.report table td:last-child{min-width:320px}
/* forms on the page surface read as cards; buttons inside tables stay compact */
main>form{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:6px 22px 20px;margin:14px 0 18px;box-shadow:var(--shadow-1)}
main>form.search,main>form.inline{background:none;border:0;box-shadow:none;padding:0}
td button,td .btn,td form button{margin:2px 4px 2px 0;padding:4px 10px;font-size:12.5px}
td form{display:inline}td:has(>form){white-space:nowrap}
td button:not(.danger){background:var(--surface);color:var(--text-2);border-color:var(--border-strong);box-shadow:none}td button:not(.danger):hover{background:var(--surface-3);color:var(--text)}
/* page header */
.pagehead{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;margin:0 0 18px}
.pagehead h2{margin:0}.pagehead p{margin:4px 0 0;color:var(--muted)}
.pagehead .actions{display:flex;gap:8px;flex-wrap:wrap}.pagehead .actions .btn{margin:0}
/* home dashboard */
.stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:14px;margin:6px 0 22px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:14px 16px;box-shadow:var(--shadow-1);display:flex;gap:12px;align-items:flex-start;color:var(--text)}
a.stat:hover{text-decoration:none;border-color:var(--border-strong);box-shadow:var(--shadow-2)}
.stat b{display:block;font-size:26px;line-height:1.1;font-weight:700;color:var(--text);letter-spacing:-.02em}
.stat span{color:var(--muted);font-size:var(--fs-xs)}.kpi-body{display:flex;flex-direction:column;gap:2px}
.kpi-label{font-weight:600;color:var(--text-2)!important;font-size:12.5px!important}
.kpi-ic{width:38px;height:38px;border-radius:10px;display:inline-flex;align-items:center;justify-content:center;flex:none}
.kpi-ic .ic{width:20px;height:20px}
.t-neutral{background:var(--neutral-soft);color:var(--neutral)}.t-info{background:var(--info-soft);color:var(--info)}.t-success{background:var(--success-soft);color:var(--success)}
.t-warning{background:var(--warning-soft);color:var(--warning)}.t-danger{background:var(--danger-soft);color:var(--danger)}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin:12px 0 26px}
a.tile{display:flex;gap:14px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:16px 18px;color:var(--text);box-shadow:var(--shadow-1);transition:box-shadow .15s,border-color .15s,transform .15s}
a.tile:hover{text-decoration:none;box-shadow:var(--shadow-2);border-color:color-mix(in srgb,var(--brand) 40%,var(--border));transform:translateY(-1px)}
.tile-ic{width:40px;height:40px;border-radius:10px;background:var(--brand-soft);color:var(--brand);display:inline-flex;align-items:center;justify-content:center;flex:none}
.tile-ic .ic{width:20px;height:20px}
a.tile h3{margin:2px 0 4px;font-size:15px}a.tile p{margin:0;color:var(--muted);font-size:var(--fs-sm);line-height:1.45}
.sectitle{font-size:var(--fs-sm);text-transform:uppercase;letter-spacing:.07em;color:var(--muted);font-weight:700;margin:26px 0 10px}
.job{background:linear-gradient(135deg,var(--brand-soft),var(--surface) 70%);border:1px solid var(--border);border-radius:var(--r-lg);padding:16px 20px;margin:8px 0 20px;box-shadow:var(--shadow-1)}
.job h3{margin:0 0 4px;font-size:var(--fs-lg)}.job p{margin:0;color:var(--text-2)}
.empty{text-align:center;padding:36px 20px;border:1px dashed var(--border-strong);border-radius:var(--r-lg);background:var(--surface);color:var(--muted);margin:12px 0 20px}
.empty h3{margin:8px 0 4px;color:var(--text)}.empty p{margin:0 auto;max-width:480px}.empty-ic{width:34px;height:34px;color:var(--faint)}
.empty .btn{margin-top:14px}
/* in-page help */
details.help{margin:4px 0 16px;font-size:var(--fs-sm);color:var(--muted);background:var(--surface);border:1px solid var(--border);border-radius:var(--r-md);padding:8px 14px}
details.help summary{cursor:pointer;color:var(--text-2);font-weight:600;display:flex;align-items:center;gap:7px;list-style:none}
details.help summary::-webkit-details-marker{display:none}details.help summary .ic{width:16px;height:16px;color:var(--brand)}
details.help[open] summary{margin-bottom:4px}
/* stepper: request -> plan -> approve -> push */
ol.stepper{list-style:none;display:flex;gap:0;padding:6px;margin:4px 0 18px;border:1px solid var(--border);border-radius:var(--r-lg);background:var(--surface);box-shadow:var(--shadow-1);counter-reset:none}
ol.stepper li{flex:1;display:flex;align-items:center;justify-content:center;gap:8px;padding:9px 8px;font-size:var(--fs-sm);color:var(--muted);position:relative;border-radius:var(--r-md)}
ol.stepper li+li::before{content:"";position:absolute;left:-14px;top:50%;width:28px;height:2px;background:var(--border-strong);transform:translateY(-50%)}
ol.stepper li.done+li::before{background:var(--success)}
ol.stepper li a{color:inherit;display:inline-flex;align-items:center;gap:8px}ol.stepper li a:hover{text-decoration:none;color:var(--text)}
ol.stepper li .n{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:50%;background:var(--surface-3);color:var(--text-2);font-weight:700;font-size:12px;border:2px solid var(--border-strong);position:relative;z-index:1}
ol.stepper li.done .n{background:var(--success);border-color:var(--success);color:#fff}
ol.stepper li.cur{font-weight:700;color:var(--text);background:var(--brand-soft)}
ol.stepper li.cur .n{background:var(--brand);border-color:var(--brand);color:#fff;box-shadow:0 0 0 4px var(--brand-ring)}
ol.stepper li.blocked{color:var(--danger)}ol.stepper li.blocked .n{background:var(--danger-soft);border-color:var(--danger);color:var(--danger)}
ol.stepper li.locked{color:var(--faint)}ol.stepper li small{font-size:11px;font-weight:500;background:var(--surface-3);border-radius:999px;padding:1px 7px}
ol.stepper li .st{font-size:11px;font-weight:500;color:var(--muted)}
/* blast radius, approvals, multi-place */
.blast{border:1px solid var(--border);border-radius:var(--r-lg);padding:14px 18px;margin:12px 0 16px;background:var(--surface);box-shadow:var(--shadow-1)}
.blast.green{border-left:4px solid var(--success)}.blast.yellow{border-left:4px solid var(--warning);background:var(--warning-soft)}.blast.red{border-left:4px solid var(--danger);background:var(--danger-soft)}
.blast h3{margin:0 0 6px}.blast .verdict{font-weight:600;margin:0 0 8px}.blast ul{margin:0;padding-left:18px}
.approval form button{margin-right:8px}
main .multiplace{margin:12px 0 16px;padding:14px 18px;border:1px solid color-mix(in srgb,var(--danger) 28%,transparent);border-left:5px solid var(--danger);
 background:var(--danger-soft);border-radius:var(--r-lg);box-shadow:var(--shadow-1)}
/* toasts */
#pl-toasts{position:fixed;right:20px;bottom:20px;z-index:90;display:flex;flex-direction:column;gap:8px;max-width:420px}
.toast{display:flex;align-items:flex-start;gap:10px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-left:4px solid var(--info);border-radius:var(--r-md);
 padding:11px 12px 11px 14px;box-shadow:var(--shadow-3);font-size:var(--fs-sm);animation:plin .2s ease-out;transition:opacity .35s,transform .35s}
.toast.t-success{border-left-color:var(--success)}.toast.t-danger{border-left-color:var(--danger)}.toast.out{opacity:0;transform:translateY(6px)}
.toast span{flex:1}.toastx{background:none;border:0;color:var(--muted);font-size:18px;line-height:1;padding:0 2px;margin:0;box-shadow:none;cursor:pointer}.toastx:hover{background:none;color:var(--text)}
@keyframes plin{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
""" + r"""
/* in-app user manual */
.helpwrap{display:grid;grid-template-columns:250px 1fr;gap:24px;align-items:start}
.helpnav{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:14px 16px;position:sticky;top:calc(var(--top-h) + 12px);font-size:var(--fs-sm);box-shadow:var(--shadow-1);max-height:calc(100vh - 90px);overflow:auto}
.helpnav ul{list-style:none;padding:0;margin:8px 0 0}.helpnav li{margin:0 0 2px}.helpnav li a{display:block;padding:4px 8px;border-radius:var(--r-sm);color:var(--text-2)}
.helpnav li a:hover{background:var(--surface-3);text-decoration:none}.helpnav a.cur{font-weight:700;color:var(--brand);background:var(--brand-soft)}
.helpdoc{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);padding:10px 36px 30px;max-width:980px;font-size:15px;line-height:1.65;box-shadow:var(--shadow-1)}
.helpdoc h2{font-size:26px;margin-top:18px}.helpdoc h3{font-size:20px;margin-top:30px;padding-top:12px;border-top:1px solid var(--border)}
.helpdoc h4{font-size:16.5px;margin-top:22px}.helpdoc h5{font-size:15px}
.helpdoc .anchor{visibility:hidden;font-size:.8em;margin-left:4px;color:var(--faint)}.helpdoc h3:hover .anchor,.helpdoc h4:hover .anchor{visibility:visible}
.helpdoc pre{background:#0f172a;color:#e2e8f0;padding:12px 14px;border-radius:var(--r-md);overflow:auto;font-size:13px;border:0}
.helpdoc code{background:var(--surface-3);padding:1px 5px;border-radius:4px;font-size:.92em}.helpdoc pre code{background:none;color:inherit}
.helpdoc img.shot{max-width:100%;border:1px solid var(--border);border-radius:var(--r-md);margin:8px 0;box-shadow:var(--shadow-2)}
.helpdoc blockquote{margin:12px 0;padding:10px 14px;border-left:4px solid var(--info);background:var(--info-soft);border-radius:var(--r-sm)}
.helpdoc blockquote.warn{border-left-color:var(--danger);background:var(--danger-soft)}
.helpdoc .tablewrap{overflow:auto}.helpdoc table.doc{border-collapse:collapse;margin:10px 0;font-size:14px;box-shadow:none}
.helpdoc table.doc th,.helpdoc table.doc td{border:1px solid var(--border);padding:7px 11px;text-align:left;vertical-align:top;position:static}
.helpdoc table.doc th{background:var(--surface-2);text-transform:none;letter-spacing:0;font-size:13.5px;color:var(--text)}
.helpdoc details.toc{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--r-md);padding:8px 14px;margin:10px 0 16px}
.helpdoc details.toc ul{margin:6px 0 0;padding-left:18px}.helpdoc details.toc li.l3{margin-left:16px;font-size:13.5px}
/* dark mode: soften light inline backgrounds that page fragments set */
[data-theme=dark] [style*="background:#f"],[data-theme=dark] [style*="background:#e"],[data-theme=dark] [style*="background: #f"]{background:var(--surface-2)!important;color:var(--text)!important}
[data-theme=dark] [style*="color:#0f2742"],[data-theme=dark] [style*="color:#334155"]{color:var(--text)!important}
[data-theme=dark] .helpdoc pre{background:#060b16}
[data-theme=dark] img.shot{filter:brightness(.9)}
/* responsive */
@media (max-width:1100px){form.search input{width:160px}.whotext{display:none}}
@media (max-width:900px){
 body.app{display:block;background:var(--bg)}
 .sidebar{position:fixed;inset:0 auto 0 0;transform:translateX(-100%);transition:transform .2s ease;box-shadow:var(--shadow-3)}
 .navtoggle:checked~.sidebar{transform:none}
 .navtoggle:checked~.scrim{display:block;position:fixed;inset:0;background:rgba(9,15,28,.45);z-index:35}
 .shell{margin-left:0}.burger{display:inline-flex}
 header.top{padding:0 14px;gap:8px}main{padding:16px 14px 30px}.foot{padding:0 14px 18px}
 form.search{display:none}.iconbtn .lbl{display:none}.redbar{padding:10px 14px}
 table{display:block;overflow-x:auto}th{position:static}
 ol.stepper{flex-wrap:wrap}ol.stepper li{flex:1 1 45%}ol.stepper li+li::before{display:none}
 .helpwrap{grid-template-columns:1fr}.helpnav{position:static;max-height:none}.helpdoc{padding:6px 16px 20px}
 .pagehead{align-items:flex-start}
}
@media (max-width:520px){.crumbs .sep,.crumbs a{display:none}.area.push{padding:3px 7px;font-size:10px}.tiles{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}}
@media print{.sidebar,header.top,.redbar,#pl-toasts,.scrim{display:none!important}.shell{margin:0}body{background:#fff}main{padding:0}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""
