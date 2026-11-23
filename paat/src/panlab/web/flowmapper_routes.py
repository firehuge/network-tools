"""FlowMapper path-tracing pages in the PAAT web GUI.

The engine is the vendored FlowMapper core.js (run with Node). This module
only collects backups, shows results, and feeds required hops into the
existing change-set / change-plan flow. Traces are plan-only: nothing is
pushed from this page.
"""
from __future__ import annotations

import html
import json
import re
import tempfile
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from panlab import flowmapper as fm
from panlab import uploads
from panlab.changeset import build_changeset
from panlab.customers import load_profile
from panlab.report import write_outputs
from panlab.sources import fetch_live, stored_config_paths
from panlab import liveconfig, livecheck
from panlab import siteroles
from panlab.web import flow_scope

router = APIRouter()
e = html.escape
TZ = ZoneInfo("America/Chicago")
SAFE = re.compile(r"^ft-[0-9]{8}-[0-9]{6}$")
# Existing viewer and FCR accounts can use this page; push is never granted here.
FLOW_PERMS = ("flow", "fcr", "view")


def _web():
    from panlab.web import app as webapp
    return webapp


def _stem() -> str:
    return "ft-" + datetime.now(TZ).strftime("%Y%m%d-%H%M%S")


def _trace_dir(profile) -> Path:
    d = profile.data_dir("flowtraces")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_trace(profile, payload: dict) -> str:
    stem = _stem()
    path = _trace_dir(profile) / f"{stem}.json"
    while path.exists():  # a re-trace in the same second (pin a choice) gets the next free stem
        import time
        time.sleep(1)
        stem = _stem()
        path = _trace_dir(profile) / f"{stem}.json"
    path.write_text(json.dumps(payload, indent=2))
    path.chmod(0o600)
    return stem


def _load_trace(profile, stem: str) -> dict:
    if not SAFE.match(stem or ""):
        raise HTTPException(404, "unknown trace")
    path = _trace_dir(profile) / f"{stem}.json"
    if not path.is_file():
        raise HTTPException(404, "trace not found")
    return json.loads(path.read_text())


def _need_flow(w, request, customer: str = ""):
    return w.need(request, FLOW_PERMS, customer=customer or None)


# ---- custom next-hop links ("Save as link") and pasted route tables ----
def _links_path(profile) -> Path:
    return _trace_dir(profile) / "links.json"


def _load_links(profile) -> list[dict]:
    p = _links_path(profile)
    try:
        data = json.loads(p.read_text()) if p.is_file() else []
    except (OSError, json.JSONDecodeError):
        return []
    return [x for x in data if isinstance(x, dict) and x.get("from") and x.get("to")]


def _save_links(profile, links: list[dict]) -> None:
    p = _links_path(profile)
    p.write_text(json.dumps(links, indent=2))
    p.chmod(0o600)


def _links_card(customer: str, links: list[dict]) -> str:
    if not links:
        return ""
    rows = "".join(
        f"<tr><td>{e(str((l.get('from') or {}).get('device') or ''))} {e(str((l.get('from') or {}).get('iface') or ''))}</td>"
        f"<td>{e(str((l.get('from') or {}).get('nexthop') or 'any'))}</td>"
        f"<td>{e(str((l.get('to') or {}).get('device') or ''))}</td><td>{e(l.get('label') or '')}</td>"
        f"<td><form method='post' action='/flow/{e(customer)}/links/delete' style='margin:0'>"
        f"<input type='hidden' name='index' value='{i}'><button type='submit' class='secondary'>Remove</button></form></td></tr>"
        for i, l in enumerate(links))
    return ("<section class='card' id='flow-links'><h3>Saved next-hop links</h3>"
            "<p class='muted'>Every trace for this customer uses these. They answer 'Needs your choice' for a next hop "
            "that several firewalls share.</p><table><tr><th>From</th><th>Next hop</th><th>Goes to</th><th>Label</th><th></th></tr>"
            f"{rows}</table></section>")


def _route_tables_from_form(rt_device: str, rt_text: str, files: list[tuple[str, str]]) -> list[dict]:
    """Paste box (with optional '# device: NAME' lines) plus uploaded files for the firewall in rt_device."""
    out = [vars(t) for t in fm.split_route_paste(rt_text, rt_device)] if (rt_text or "").strip() else []
    for name, text in files:
        if not text.strip():
            continue
        tabs = fm.split_route_paste(text, rt_device)
        for t in tabs:
            t.label = name if len(tabs) == 1 else f"{name} ({t.device})"
            out.append(vars(t))
    return out


def _tables(payload: dict) -> list:
    return [fm.RouteTable(**t) for t in payload.get("route_tables") or []]


# design-system tones (theme.py): success / warning / danger
LABEL_TONE = {"complete": "success", "suggested": "warning", "incomplete": "danger"}


def _status_html(i: int, row: dict, customer: str, stem: str) -> str:
    ps = row.get("pathStatus") or {}
    label = ps.get("label") or ps.get("status") or row.get("status") or ""
    tone = LABEL_TONE.get(ps.get("status") or "", "info")
    out = [f"<div class='note path-status' data-label='{e(label)}' role='status' "
           f"style='border-left-color:var(--{tone});background:var(--{tone}-soft)'>"
           f"<span class='badge b-{tone}'>{e(label)}</span>"
           f"{(' <span class=muted>' + e(ps['confidence']) + ' confidence</span>') if ps.get('confidence') else ''}"
           f"<div>{e(ps.get('text') or '')}</div>"]
    asm = [a for a in ps.get("assumptions") or []]
    if asm:
        out.append("<ul class='assumptions'>" + "".join(
            f"<li><b>{e(a.get('hop') or '')}</b>: {e(a.get('what') or '')}"
            + (f" <span class='muted'>Confirm: {e(a['confirm'])}</span>" if a.get("confirm") and a.get("kind") != "pinned" else "")
            + "</li>" for a in asm) + "</ul>")
    stop = ps.get("stop") or {}
    if stop and not stop.get("choice") and stop.get("fix"):
        out.append(f"<div><b>To finish it:</b> {e(stop['fix'])}</div>")
    for j, c in enumerate(ps.get("choices") or [], 1):
        head = (f"Pinned: {e(c.get('what') or '')}" if c.get("pinned") else f"Pick one: {e(c.get('what') or '')}")
        rows = []
        for x in c.get("candidates") or []:
            btns = (f"<form method='post' action='/flow/{e(customer)}/{e(stem)}/pin' style='display:inline;margin:0'>"
                    f"<input type='hidden' name='row' value='{i}'><input type='hidden' name='choice' value='{j}'>"
                    f"<input type='hidden' name='device' value='{e(x.get('devId') or '')}'>"
                    "<button type='submit' name='action' value='pin' class='sm'>Use for this trace</button>")
            if c.get("kind") == "next-hop" and c.get("link"):
                btns += " <button type='submit' name='action' value='link' class='sm secondary'>Save as link</button>"
            btns += "</form>"
            cur = " class='green'" if c.get("pinned") and x.get("device") == c.get("chosen") else ""
            rows.append(f"<tr{cur}><td>{e(x.get('hostname') or x.get('device') or '')}</td><td>{e(x.get('serial') or '')}</td>"
                        f"<td>{e(x.get('stack') or '')}</td><td>{e(x.get('site') or '')}</td><td>{e(x.get('reason') or '')}</td><td>{btns}</td></tr>")
        pinned_by = f" Using the highlighted firewall ({e(c.get('pinBy') or '')})." if c.get("pinned") else " The path below is only a placeholder until you pick."
        out.append(f"<div class='choice' data-kind='{e(c.get('kind') or '')}' style='margin-top:8px'><b>{head}</b> at {e(c.get('at') or '')}"
                   f"<div class='muted'>{e(c.get('reason') or '')}{pinned_by}</div>"
                   "<div class='tablewrap'><table><tr><th>Firewall</th><th>Serial</th><th>Template stack</th><th>Site</th><th>Why it fits</th><th></th></tr>"
                   + "".join(rows) + "</table></div></div>")
    out.append("</div>")
    return "".join(out)


def _no_network_html(nn: list) -> str:
    """Firewalls the Panorama export knows but has no interfaces or routes for: a trace that reaches one stops there."""
    if not nn:
        return ""
    names = "".join(f"<li>{e(x.get('hostname') or x.get('device') or '')}"
                    f"{(' <span class=muted>' + e(x['serial']) + '</span>') if x.get('serial') and x.get('hostname') else ''}</li>"
                    for x in nn[:200])
    more = f" (first 200 of {len(nn)} shown)" if len(nn) > 200 else ""
    return (f"<div class='note warn' id='nonet-callout' style='border-left-color:var(--warn)'>"
            f"<b>{len(nn)} firewall{' has' if len(nn) == 1 else 's have'} no network config in this export.</b> "
            f"Traces that reach {'it' if len(nn) == 1 else 'them'} stop there (Incomplete path). Use the live snapshot, or load each "
            f"firewall's own local backup alongside the Panorama export, to trace through {'it' if len(nn) == 1 else 'them'}."
            f"<details{' open' if len(nn) <= 6 else ''}><summary>{'Firewalls' if len(nn) <= 6 else 'Show the ' + str(len(nn)) + ' firewalls'}{e(more)}</summary>"
            f"<ul>{names}</ul></details></div>")


def _overlap_html(ov: dict | None) -> str:
    if not ov or not ov.get("total"):
        return ""
    items = []
    for x in (ov.get("sharedIps") or [])[:20]:
        items.append(f"<li><b>{e(x.get('ip') or '')}</b> on " + ", ".join(
            f"{e(o.get('hostname') or o.get('device') or '')} {e(o.get('iface') or '')}" for o in x.get("owners") or []) + "</li>")
    for x in (ov.get("overlaps") or [])[:20]:
        items.append(f"<li>subnet <b>{e(x.get('prefix') or '')}</b> on " + ", ".join(
            f"{e(o.get('hostname') or o.get('device') or '')}" for o in x.get("owners") or []) + "</li>")
    for c in ov.get("cloned") or []:
        items.append(f"<li>look-alike firewalls {e((c.get('a') or {}).get('label') or '')} and {e((c.get('b') or {}).get('label') or '')}: "
                     f"not treated as HA ({e(c.get('notHa') or '')})</li>")
    return ("<div class='note' id='overlap-callout' style='border-left-color:var(--warning);background:var(--warning-soft)'>"
            "<span class='badge b-warning'>Overlapping address space</span> "
            f"{e(ov.get('text') or '')}<ul>{''.join(items)}</ul></div>")


def _bgp_html(bgp: list, tables: list) -> str:
    out = ""
    if tables:
        out += ("<h3>Route tables used</h3><table><tr><th>Firewall</th><th>Source</th><th>Format</th><th>Routes used</th><th>Notes</th></tr>"
                + "".join(f"<tr><td>{e(str(t.get('device') or ''))}</td><td>{e(str(t.get('label') or ''))}</td><td>{e(str(t.get('format') or ''))}</td>"
                          f"<td>{e(str(t.get('routes') or 0))}</td><td>{e('; '.join((t.get('warnings') or []) + (['no router named ' + ', '.join(t['unmatchedRouters'])] if t.get('unmatchedRouters') else [])))}</td></tr>"
                          for t in tables) + "</table>")
    if bgp:
        out += ("<details id='bgp-summary'><summary>BGP in the loaded configs (" + str(len(bgp)) + " router(s))</summary>"
                "<table><tr><th>Firewall</th><th>Router</th><th>Engine</th><th>Local AS</th><th>Peers</th><th>Advertises</th></tr>"
                + "".join(
                    f"<tr><td>{e(str(b.get('hostname') or b.get('device') or ''))}</td><td>{e(str(b.get('vr') or ''))}</td>"
                    f"<td>{'advanced routing' if b.get('engine') == 'advanced' else 'legacy'}</td><td>{e(str(b.get('localAs') or ''))}</td>"
                    f"<td>{e(', '.join(str(p.get('peerIp') or '?') + ' AS ' + str(p.get('peerAs') or '?') for p in b.get('peers') or []))}</td>"
                    f"<td>{e('; '.join(x for x in [('redistributes ' + ', '.join(r.get('name') or '' for r in b.get('redistribution') or [])) if b.get('redistribution') else '', ('networks ' + ', '.join(b.get('networks') or [])) if b.get('networks') else '', ('aggregates ' + ', '.join(str(a.get('prefix')) + (' summary-only' if a.get('summaryOnly') else '') for a in b.get('aggregates') or [])) if b.get('aggregates') else '', ('observed (pasted table)' if b.get('observed') else '')] if x))}</td></tr>"
                    for b in bgp) + "</table></details>")
    return out


def _live_card(profile, customer: str) -> str:
    """Status of the cached live snapshot, plus a rate-limited refresh button."""
    if not liveconfig.can_live_pull(profile):
        return (
            "<div class='card'><h3>Live config</h3>"
            "<p class='muted'>No API credentials are configured for this customer, so a live pull is "
            "not available. Upload a Panorama export and local backups instead. To enable a live "
            "pull, set a read-only API key (preferred) or the existing admin key in the customer's "
            "env file — never in the repo. See the user manual.</p></div>"
        )
    st = liveconfig.cache_status(profile)
    if not st:
        body = ("<p>No live snapshot is cached yet. Refresh pulls the Panorama running and candidate "
                "config and each managed firewall's running config (read-only). The result is cached "
                "and rate-limited.</p>")
        disabled = ""
        btn = "Pull live config"
    else:
        mode = st.get("credential_mode") or "admin"
        warn = ""
        if st.get("used_admin_key"):
            warn = ("<div class='note'>This pull used the admin API key because no read-only key "
                    "is configured. Add <code>api_key_ro_env</code> and the matching env var "
                    "when you can. The key itself is never stored here.</div>")
        errs = "".join(f"<li>{e(x)}</li>" for x in (st.get("errors") or []))
        pending = st.get("pending_changes") or {}
        pend = ", ".join(k for k, v in pending.items() if v)
        pend_html = (f"<p>Uncommitted candidate changes on: {e(pend)}.</p>" if pend else "")
        devs = st.get("devices") or []
        dev_html = ""
        if devs:
            bits = ", ".join(f"{d.get('hostname') or d.get('serial')} ({'up' if d.get('connected') else 'down'})"
                             for d in devs[:12])
            dev_html = f"<p class='muted'>Managed firewalls: {e(bits)}.</p>"
        src_note = ""
        if st.get("policy_source") == "panorama":
            src_note = ("<p class='muted'>Traces use the Panorama running config for policy. "
                        "A managed firewall's own running config does not include pushed policy; "
                        "it is kept only to merge routes, interfaces and zones. Traffic-log "
                        "checks query the firewall directly (Panorama log jobs come back empty).</p>")
        body = (
            f"<p>Last pulled <b>{e(st.get('pulled_at_label') or st.get('pulled_at') or '')}</b> "
            f"({st.get('file_count') or 0} file(s), credential mode: {e(mode)}).</p>"
            f"{src_note}"
            f"{warn}{pend_html}{dev_html}"
            + (f"<div class='note'><b>Pull notes</b><ul>{errs}</ul></div>" if errs else "")
        )
        if st.get("can_refresh"):
            disabled, btn = "", "Refresh live config"
        else:
            disabled = " disabled"
            btn = f"Refresh available in {int(st.get('retry_after') or 0)}s"
    return (
        "<div class='card'><h3>Live config</h3>"
        f"{body}"
        f"<form method='post' action='/flow/live/refresh'>"
        f"<input type='hidden' name='customer' value='{e(customer)}'>"
        f"<button type='submit'{disabled}>{e(btn)}</button>"
        "<p class='muted'>Read-only. Rate-limited to one pull a minute. Does not change Panorama or "
        "the firewall. This pull only reads.</p>"
        "</form></div>"
    )


def _backup_boxes(profile, selected: set[str]) -> str:
    rows = []
    for rec in uploads.list_uploads(profile):
        ident = rec["id"]
        checked = " checked" if ident in selected or (not selected and rec.get("kind") in ("panorama", "firewall")) else ""
        when = uploads.format_uploaded(rec.get("uploaded") or "")
        label = f"{rec.get('original_name') or ident} ({rec.get('kind')}, {when})"
        rows.append(
            f"<label style='font-weight:400'><input type='checkbox' name='backups' value='{e(ident)}'{checked}> "
            f"{e(label)}</label>")
    cached = stored_config_paths(profile)
    if cached:
        rows.append(
            "<label style='font-weight:400'><input type='checkbox' name='include_cached' value='yes'> "
            "Also include the customer's cached / profile config</label>")
    if uploads.can_live_export(profile):
        rows.append(
            "<label style='font-weight:400'><input type='checkbox' name='include_live' value='yes'> "
            "Also merge a fresh one-target export (legacy; prefer the live snapshot above)</label>")
    if not rows:
        return ("<p class='muted'>No uploaded backups yet. Upload a Panorama export and any local firewall "
                "backups below (or on the Backup files page). Several files are merged the same way "
                "the offline FlowMapper page does.</p>")
    return "<div class='card'>" + "<br>".join(rows) + "</div>"


def _collect_files(profile, backup_ids: list[str], include_cached: bool, include_live: bool) -> list[fm.ConfigFile]:
    files: list[fm.ConfigFile] = []
    seen: set[str] = set()

    def add(path: Path, name: str) -> None:
        key = str(path.resolve()) if path.exists() else ""
        if not path.is_file() or key in seen:
            return
        seen.add(key)
        files.append(fm.ConfigFile(path=path, name=name))

    for ident in backup_ids:
        rec = uploads.get(profile, ident)
        add(uploads.stored_path(profile, rec), rec.get("original_name") or ident)
    if include_cached:
        for p in stored_config_paths(profile):
            add(p, p.name)
    if include_live:
        for t in profile.targets:
            try:
                p = fetch_live(profile, t)
            except Exception as exc:
                raise fm.FlowMapperError(f"live export of {t.name} failed: {exc}") from exc
            add(p, p.name)
    return files


def _verdict_cls(v: str) -> str:
    if v == "allow":
        return "hop-allow"
    if v in {"deny", "drop", "reset"}:
        return "hop-deny"
    return "hop-conditional"


def _svg(layout: dict | None) -> str:
    if not layout:
        return ""
    shapes = {s["id"]: s for s in (layout.get("shapes") or []) if s.get("id")}
    w = int(layout.get("width") or 800)
    h = int(layout.get("height") or 400)
    parts = [
        f"<svg viewBox='0 0 {w} {h}' width='100%' role='img' aria-label='Vsys map' "
        f"style='max-width:{w}px;background:#fff;border:1px solid var(--line);border-radius:8px'>"
    ]
    for edge in layout.get("edges") or []:
        a, b = shapes.get(edge.get("s") or ""), shapes.get(edge.get("t") or "")
        if not a or not b:
            continue
        x1, y1 = a["x"] + a["w"] / 2, a["y"] + a["h"] / 2
        x2, y2 = b["x"] + b["w"] / 2, b["y"] + b["h"] / 2
        parts.append(f"<line x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' stroke='#94a3b8' stroke-width='1.5'/>")
    for s in layout.get("shapes") or []:
        x, y, sw, sh = s.get("x", 0), s.get("y", 0), s.get("w", 80), s.get("h", 40)
        kind = s.get("kind") or "box"
        fill = "#eef4ff" if kind != "cloud" else "#f8fafc"
        stroke = "#2563eb" if kind != "cloud" else "#64748b"
        rx = 18 if kind == "cloud" else 6
        parts.append(f"<rect x='{x}' y='{y}' width='{sw}' height='{sh}' rx='{rx}' fill='{fill}' stroke='{stroke}'/>")
        label = (s.get("label") or "").replace("\n", " · ")
        sub = s.get("sub") or ""
        parts.append(
            f"<text x='{x + 8}' y='{y + 18}' font-size='11' font-family='sans-serif' fill='#0f2742'>"
            f"{e(label[:80])}</text>")
        if sub:
            parts.append(
                f"<text x='{x + 8}' y='{y + 32}' font-size='10' font-family='sans-serif' fill='#64748b'>"
                f"{e(str(sub)[:80])}</text>")
    parts.append("</svg>")
    return "".join(parts)



_DIAGRAM_JS = """<script>
(function () {
  function svgOf(id) { var el = document.getElementById(id); return el ? el.querySelector('svg') : null; }
  function dl(name, blob) { var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500); }
  function png(svg, name) {
    var xml = new XMLSerializer().serializeToString(svg), url = URL.createObjectURL(new Blob([xml], { type: 'image/svg+xml' })), img = new Image();
    img.onload = function () {
      var sc = 2, w = svg.width.baseVal.value, h = svg.height.baseVal.value, c = document.createElement('canvas');
      c.width = w * sc; c.height = h * sc; var g = c.getContext('2d'); g.fillStyle = '#fff'; g.fillRect(0, 0, c.width, c.height); g.scale(sc, sc); g.drawImage(img, 0, 0);
      URL.revokeObjectURL(url); c.toBlob(function (b) { dl(name + '.png', b); }, 'image/png');
    };
    img.src = url;
  }
  document.addEventListener('click', function (ev) {
    var b = ev.target.closest('[data-svg-export]'); if (!b) return;
    var svg = svgOf(b.getAttribute('data-target')); if (!svg) return;
    var name = b.getAttribute('data-name') || 'diagram';
    if (b.getAttribute('data-svg-export') === 'png') png(svg, name);
    else dl(name + '.svg', new Blob([new XMLSerializer().serializeToString(svg)], { type: 'image/svg+xml' }));
  });
})();
</script>"""


def _diagram_card(dom_id: str, title: str, svg: str, name: str, *, drawio_href: str = "", svg_href: str = "",
                  note: str = "") -> str:
    """An inline SVG diagram with Export SVG / PNG (and draw.io) buttons. `svg` is engine output (it escapes its text)."""
    buttons = (f"<button type='button' class='btn secondary' data-svg-export='svg' data-target='{e(dom_id)}' data-name='{e(name)}'>Export SVG</button> "
               f"<button type='button' class='btn secondary' data-svg-export='png' data-target='{e(dom_id)}' data-name='{e(name)}'>Export PNG</button>")
    if drawio_href:
        buttons += f" <a class='btn secondary' href='{e(drawio_href)}'>Export draw.io</a>"
    if svg_href:
        buttons += f" <a class='btn secondary' href='{e(svg_href)}'>Download SVG file</a>"
    return (f"<div class='diagram-card' style='margin:10px 0'><div style='display:flex;gap:8px;align-items:center;flex-wrap:wrap'>"
            f"<h3 style='margin:0;flex:1'>{e(title)}</h3>{buttons}</div>"
            f"{('<p class=muted>' + e(note) + '</p>') if note else ''}"
            f"<div id='{e(dom_id)}' style='overflow:auto;max-width:100%;border:1px solid var(--line);border-radius:8px;background:#fff;margin-top:6px'>{svg}</div></div>")


def _order_html(it: dict) -> str:
    o = it.get("order") or {}
    if not o.get("text"):
        return ""
    return f"<div class='muted order-advice' data-order='{e(o.get('mode') or '')}'><b>Rule order:</b> {e(o['text'])}</div>"


def _multiplace_html(row: dict) -> str:
    """The red box. The text and the place list come from the engine (`enforcement`), the same as the offline page."""
    en = row.get("enforcement") or {}
    if not en.get("multi"):
        return ""
    need = en.get("level") == "need" or (en.get("level") is None and en.get("needRule"))
    items = ""
    for pl in en.get("places") or []:
        label = pl.get("hostname") or pl.get("device") or ""
        where = (pl.get("display") if pl.get("display") and pl.get("display") != pl.get("vsys") else pl.get("vsys")) or ""
        zones = f" ({pl.get('fromZone')} → {pl.get('toZone') or '?'})" if pl.get("fromZone") else ""
        state = (f"<b>needs an allow</b>{(' (new rule ' + e(pl['newRule']) + ')') if pl.get('newRule') else ''}"
                 if pl.get("needs") else f"already allowed{(' by ' + e(pl['rule'])) if pl.get('rule') else ''}")
        items += (f"<li{' class=bad' if pl.get('needs') else ''}><b>Place {e(str(pl.get('n')))}:</b> {e(label)} {e(where)}{e(zones)}"
                  f"{' [hairpin]' if pl.get('hairpin') else ''} &mdash; {state}</li>")
    text = en.get("text") or (f"Checked by security policy in {en.get('points')} places.")
    olist = ("<ol style=\"margin:6px 0 0 18px\">" + items + "</ol>") if items else ""  # no backslash inside f-strings (Python 3.10)
    return (f"<div class='multiplace' role='alert' style='margin:6px 0;padding:6px 10px;border-left:6px solid "
            f"{'#b00020' if need else '#1b7f3b'};background:{'#fff1f1' if need else '#eefaf1'}'>"
            f"<b>Rule needed in more than one place{'!' if need else '?'}</b> {e(text)}"
            f"{olist}</div>")


def _row_html(i: int, row: dict, customer: str = "", stem: str = "") -> str:
    q = row.get("query") or {}
    title = f"{q.get('src') or '?'} → {q.get('dst') or '?'} {(q.get('proto') or 'tcp')}"
    if q.get("port") is not None:
        title += f"/{q['port']}"
    hops = row.get("hops") or []
    hop_rows = "".join(
        f"<tr class='{_verdict_cls(h.get('verdict') or '')}'>"
        f"<td>{e(str(h.get('n')))}</td><td>{e(h.get('hostname') or h.get('device') or '')}"
        f"{(' <span class=muted>' + e(h['device']) + '</span>') if h.get('hostname') else ''}</td>"
        f"<td>{e((h.get('display') or h.get('vsys') or '') + ('' if not h.get('vsys') or h.get('display') == h.get('vsys') else ' (' + h['vsys'] + ')'))}</td>"
        f"<td>{e(h.get('dg') or '—')}</td><td>{e(h.get('fromZone') or '—')}</td><td>{e(h.get('toZone') or '—')}</td>"
        f"<td><b>{e(h.get('verdict') or '?')}</b>"
        f"{' by ' + e(h['rule']) if h.get('rule') else ''}"
        f"{' · hairpin' if h.get('hairpin') else ''}"
        f"{' · transit' if h.get('transit') else ''}</td></tr>"
        for h in hops)
    hop_table = (
        "<table><tr><th>#</th><th>Firewall</th><th>Vsys</th><th>Device group</th><th>From</th><th>To</th><th>Verdict</th></tr>"
        f"{hop_rows or '<tr><td colspan=7 class=muted>No hops — no path was found in the loaded configuration.</td></tr>'}"
        "</table>")
    if len(hops) > 1:
        hop_table = _multiplace_html(row) + hop_table
    why = (row.get("why") or {}).get("text") or ""
    plan = row.get("plan") or {}
    item_bits = []
    for it in plan.get("items") or []:
        extra = ""
        if it.get("dg") or it.get("uncertain"):
            tag = e(it.get("dg") or "")
            if it.get("uncertain"):
                tag = (tag + " " if tag else "") + "placement uncertain"
            extra += f' <span class="muted">[DG {tag}]</span>'
        if it.get("optional"):
            extra += ' <span class="muted">(optional)</span>'
        item_bits.append(f"<li>{e(it.get('summary') or '')}{extra}{_order_html(it)}</li>")
    items = "".join(item_bits)
    plan_html = (f"<h3>Combined change plan ({plan.get('required') or 0} required, "
                 f"{plan.get('uncertain') or 0} with uncertain device-group placement)</h3>"
                 f"<ul>{items or '<li class=muted>No changes proposed.</li>'}</ul>")
    if plan.get("cli"):
        plan_html += f"<pre>{e(plan['cli'])}</pre>"
    status = f"<p><b>Trace result:</b> {e(row.get('status') or '')}</p>" + _status_html(i, row, customer, stem)
    notes = "".join(f"<div class='note'>{e(n.get('text') or '')}</div>" for n in (row.get("notes") or []) if n.get("level") in ("warn", "error") and not n.get("choice"))
    checklist = "".join(f"<li>{e(x)}</li>" for x in (row.get("checklist") or []))
    filters = "".join(
        f"<li>Hop {e(str(h.get('hop')))} {e(h.get('device') or '')} {e(h.get('vsys') or '')}: <code>{e(h.get('filter') or '')}</code>"
        + (("<div class='muted'>Or on the firewall itself"
            + (f" (first <code>set system setting target-vsys {e(h['testVsys'])}</code>)" if h.get("testVsys") else "")
            + ":</div><pre>" + e("\n".join(h["testCli"])) + "</pre>") if h.get("testCli") else "")
        + "</li>"
        for h in ((row.get("filters") or {}).get("hops") or []))
    diagram = ""
    if row.get("diagram"):
        diagram = _diagram_card(f"flow-diagram-{i}", "Flow diagram", row["diagram"], f"flow-{i}",
                                svg_href=(f"/flow/{customer}/{stem}/flow-{i}.svg" if customer and stem else ""))
    return (
        f"<section class='card' id='flow-row-{i}'><h3>Flow {i}: {e(title)}</h3>{status}"
        f"{('<p>' + e(why) + '</p>') if why else ''}"
        f"{flow_scope.via_hidden_html(row, customer, stem)}{flow_scope.conflict_html(row, customer, stem)}{notes}{diagram}{hop_table}{plan_html}{flow_scope.mirror_html(row)}"
        f"{('<h3>Before you push</h3><ol>' + checklist + '</ol>') if checklist else ''}"
        f"{('<h3>Check it after the push</h3><ul>' + filters + '</ul>') if filters else ''}"
        "</section>")


@router.get("/flow", response_class=HTMLResponse)
def flow_form(request: Request, customer: str = "") -> HTMLResponse:
    w = _web()
    user = _need_flow(w, request, customer)
    names = w.list_customers()
    if not names:
        return w.page("Trace a flow", "<h2>Trace a flow</h2><div class='note'>No customers are in your scope.</div>", user)
    if customer and customer not in names:
        raise HTTPException(403, f"customer {customer} is not in your scope")
    chosen = customer if customer in names else names[0]
    opts = "".join(
        f"<option value='{e(c)}'{' selected' if c == chosen else ''}>{e(load_profile(c).display_name)} ({e(c)})</option>"
        for c in names)
    links_card = ""
    scope_html = flow_scope.scope_select(siteroles.default())
    try:
        prof = load_profile(chosen)
        scope_html = flow_scope.scope_select(siteroles.load(prof))
        links_card = _links_card(chosen, _load_links(prof))
        boxes = _backup_boxes(prof, set())
        live_card = _live_card(prof, chosen)
        live_ok = liveconfig.can_live_pull(prof)
    except (ValueError, FileNotFoundError) as exc:
        boxes = f"<div class='note'>{e(str(exc))}</div>"
        live_card = ""
        live_ok = False
    live_opts = ""
    if live_ok:
        live_opts = """<label style='font-weight:400'><input type='checkbox' name='use_live' value='yes' checked>
Use the live snapshot as the config (Panorama running and candidate, plus managed firewall running configs)</label>
<label style='font-weight:400'><input type='checkbox' name='use_candidate' value='yes'>
Prefer the candidate config when it differs from running</label>
<label style='font-weight:400'><input type='checkbox' name='live_check' value='yes'>
Confirm each hop against live policy-match, FIB lookup, and traffic logs, and show disagreements</label>"""
    # When the customer dropdown changes, reload the form so backup lists match.
    body = f"""<h2>Trace a flow</h2>
<div class='note'>Paste a firewall change request (or upload the usual FCR spreadsheet) and check it
against a live, read-only API pull of your Panorama and firewalls, or against uploaded backups.
You will see every vsys hop, the verdicts, the full change plan (CLI and GUI steps), the pre-push
checklist, and log filters. Nothing is written to a firewall or to Panorama from this page, and
creating a change set is plan-only — the push area stays behind the push permission.</div>
<form method='get' action='/flow'><label>Customer</label>
<select name='customer' onchange='this.form.submit()'>{opts}</select></form>
{live_card}
<form method='post' action='/flow' enctype='multipart/form-data'>
<input type='hidden' name='customer' value='{e(chosen)}'>
<label>Configurations to load</label>
<p class='muted'>Use the live snapshot, or pick a Panorama export plus any local firewall backups
(the engine unions their routes, interfaces and zones). You can also upload more files with this
form; they are stored as plan-only backups for this customer.</p>
{live_opts}
{boxes}
<label>Upload additional backups (optional, .xml or .tgz)</label>
<input type='file' name='configs' accept='.xml,.tgz,.tar,.gz,.zip' multiple>
<label>FCR (paste one flow per line, or CSV with source and destination columns)</label>
<textarea name='fcr' rows='6' style='width:100%;max-width:720px' placeholder='10.10.1.50 -&gt; 10.20.1.50 tcp/443'></textarea>
<label>Or upload an FCR file (.xlsx, .csv, or a text/CSV paste)</label>
<input type='file' name='fcr_file' accept='.xlsx,.xlsm,.csv,.xls,.txt'>
<details id='rt-box'><summary><b>Route tables (optional): what the firewalls actually learned</b></summary>
<p class='muted'>BGP routes are not in a config file, so the trace infers them from the peers' BGP settings and marks those
hops <i>Suggested (BGP-inferred)</i>. Paste the output of <code>show routing route</code> (legacy) or
<code>show advanced-routing route</code> (advanced routing), the XML API answer, or a CSV
(destination,nexthop,interface,protocol[,virtual-router]) and the real routes win for that firewall.
For several firewalls in one box, start each table with a line <code># device: NAME</code>.</p>
<label>Firewall (name, hostname or serial)</label>
<input type='text' name='rt_device' placeholder='dc2-core-fw'>
<label>Paste the route table</label>
<textarea name='route_tables' rows='5' style='width:100%;max-width:720px' placeholder='# device: dc2-core-fw&#10;VIRTUAL ROUTER: LR-CORE ...'></textarea>
<label>Or upload route table files (for the firewall above)</label>
<input type='file' name='rt_files' accept='.txt,.xml,.csv,.log' multiple>
</details>
<label><input type='checkbox' name='ignore_intrazone' value='yes'> Ignore the implicit intrazone-default allow
(treat those hops as needing an explicit rule)</label>
{scope_html}
<br><button type='submit'>Trace</button>
</form>
{links_card}
<p class='muted'>The offline FlowMapper page is unchanged: it is still a single HTML file you can
open with no server. Wins in the shared engine go to both tools.</p>"""
    return w.page("Trace a flow", body, user)


@router.post("/flow", response_class=HTMLResponse)
async def do_trace(request: Request, customer: str = Form(...), fcr: str = Form(""),
                   ignore_intrazone: str = Form(""), include_cached: str = Form(""),
                   include_live: str = Form(""),
                   backups: list[str] | None = Form(None),
                   configs: list[UploadFile] | None = File(None),
                   fcr_file: UploadFile | None = File(None)) -> HTMLResponse:
    w = _web()
    user = w.need(request, FLOW_PERMS, customer=customer)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(400, str(exc))
    if isinstance(backups, str):
        backup_ids = [backups] if backups else []
    else:
        backup_ids = list(backups or [])
    # Store any newly uploaded configs as backups (plan only; XML stays out of the repo).
    form = await request.form()
    uploaded = form.getlist("configs") if hasattr(form, "getlist") else (configs or [])
    for f in uploaded:
        if not getattr(f, "filename", None):
            continue
        data = await f.read()
        if not data:
            continue
        try:
            rec = uploads.store(prof, data, f.filename or "backup.xml", uploaded_by=user[0])
        except uploads.UploadError as exc:
            raise HTTPException(400, str(exc))
        backup_ids.append(rec["id"])
    use_live = (str(form.get("use_live") or "") == "yes")
    use_candidate = (str(form.get("use_candidate") or "") == "yes")
    do_live_check = (str(form.get("live_check") or "") == "yes")
    snap_meta = None
    try:
        files = _collect_files(prof, backup_ids, include_cached == "yes", include_live == "yes")
        if use_live:
            files = _merge_live_files(prof, files, use_candidate=use_candidate)
            snap_meta = liveconfig.cache_status(prof)
    except (uploads.UploadError, fm.FlowMapperError, FileNotFoundError, ValueError, liveconfig.LiveError, RuntimeError) as exc:
        raise HTTPException(400, str(exc))
    if not files:
        raise HTTPException(400, "Select the live snapshot, or upload at least one Panorama or firewall backup.")
    fcr_text = (fcr or "").strip()
    fcr_meta: list = []
    if fcr_file is not None and fcr_file.filename:
        raw = await fcr_file.read()
        if raw:
            suffix = Path(fcr_file.filename).suffix.lower() or ".txt"
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                tmp.write(raw)
                tmp_path = Path(tmp.name)
            try:
                text, reqs, meta = fm.fcr_from_upload(
                    tmp_path, ticket_patterns=prof.tickets, requester=user[0])
            except Exception as exc:
                tmp_path.unlink(missing_ok=True)
                raise HTTPException(400, f"{fcr_file.filename}: {exc}") from exc
            tmp_path.unlink(missing_ok=True)
            fcr_text = (text + "\n" + fcr_text).strip() if fcr_text else text
            fcr_meta.append(meta if isinstance(meta, dict) else {"file": fcr_file.filename, "requests": len(reqs)})
    if not fcr_text:
        raise HTTPException(400, "Paste a flow (for example 10.10.1.50 -> 10.20.1.50 tcp/443) or upload an FCR file.")
    rt_uploads = []
    for f in (form.getlist("rt_files") if hasattr(form, "getlist") else []):
        if getattr(f, "filename", None):
            rt_uploads.append((f.filename, (await f.read()).decode("utf-8", errors="replace")))
    try:
        route_tables = _route_tables_from_form(str(form.get("rt_device") or ""), str(form.get("route_tables") or ""), rt_uploads)
    except fm.FlowMapperError as exc:
        raise HTTPException(400, str(exc)) from exc
    links = _load_links(prof)
    # scope: the form choice is remembered for this customer (roles themselves are edited on the result page)
    saved_roles = siteroles.load(prof)
    pick = str(form.get("scope_mode") or "")
    if pick in ("production", "all", "custom") and pick != saved_roles["scope"]["mode"]:
        saved_roles = siteroles.save(prof, siteroles.apply_form(saved_roles, {"scope_mode": pick}))
    try:
        result = fm.run_trace(files, fcr_text, ignore_intrazone=(ignore_intrazone == "yes"),
                              route_tables=[fm.RouteTable(**t) for t in route_tables], links=links, roles=saved_roles)
    except fm.FlowMapperError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:  # engine or node failure; no config content in the message we show
        raise HTTPException(500, f"Path tracing failed: {exc}") from exc
    payload = {
        "customer": customer,
        "created_by": user[0],
        "created": datetime.now(TZ).isoformat(timespec="seconds"),
        "files": [{"name": f.name, "path": str(f.path)} for f in files],
        "backup_ids": backup_ids,
        "include_cached": include_cached == "yes",
        "use_live": use_live,
        "use_candidate": use_candidate,
        "ignore_intrazone": ignore_intrazone == "yes",
        "fcr_files": fcr_meta,
        "fcr_text": fcr_text,
        "route_tables": route_tables,
        "pins": {},
        "roles": saved_roles,
        "result": result,
        "live_snapshot": snap_meta,
    }
    if do_live_check:
        try:
            snap = liveconfig.load_cached_snapshot(prof)
            payload["live_check"] = livecheck.check_trace(prof, result, snap)
        except liveconfig.LiveError as exc:
            payload["live_check"] = {"ok": False, "error": str(exc), "hops": 0, "disagreements": 0, "rows": []}
    stem = _save_trace(prof, payload)
    return _result_page(w, user, customer, stem, payload)


def _result_page(w, user, customer: str, stem: str, payload: dict) -> HTMLResponse:
    result = payload.get("result") or {}
    summary = result.get("summary") or {}
    rows = result.get("rows") or []
    required = sum((r.get("plan") or {}).get("required") or 0 for r in rows)
    engine = result.get("engine") or {}
    parse_errs = "".join(f"<li>{e(err.get('error') or str(err))}</li>" for err in (result.get("parseErrors") or []))
    body = [
        f"<h2>Flow trace {e(stem)}</h2>",
        "<div class='note'>Plan only. Nothing was written to a firewall or to Panorama. "
        "Required hops can be turned into a change set and opened in the usual change-plan view. "
        "The push area will refuse that change set. Export the trace or the plan below.</div>",
        f"<p>Loaded <b>{summary.get('files') or 0}</b> file(s), <b>{summary.get('devices') or 0}</b> firewall(s), "
        f"<b>{summary.get('staticRoutes') or 0}</b> routes"
        f"{' (including ' + str(summary.get('mergedLocal')) + ' merged with a local backup)' if summary.get('mergedLocal') else ''}. "
        f"Engine FlowMapper {e(str(engine.get('version') or ''))}.</p>",
    ]
    body.append(flow_scope.scope_card(customer, stem, result, payload.get("roles") or siteroles.default()))
    live_src = payload.get("live_snapshot") or {}
    if live_src.get("pulled_at_label") or live_src.get("pulled_at"):
        body.append(
            f"<p>Live snapshot from <b>{e(live_src.get('pulled_at_label') or live_src.get('pulled_at'))}</b>"
            f"{' (used the admin API key)' if live_src.get('used_admin_key') else ''}.</p>")
    lc = payload.get("live_check")
    if lc:
        body.append(_live_check_html(lc))
    if parse_errs:
        body.append(f"<div class='note' style='border-left-color:#b00020'><b>FCR parse notes</b><ul>{parse_errs}</ul></div>")
    body.append(_no_network_html(result.get("noNetwork") or []))
    body.append(_overlap_html(result.get("overlap")))
    body.append(_bgp_html(result.get("bgp") or [], result.get("routeTables") or []))
    if result.get("links"):
        body.append(f"<p class='muted'>{result['links']} saved next-hop link(s) were used.</p>")
    vm = result.get("vsysMap") or {}
    if vm.get("svg"):
        body.append(_diagram_card("vsys-map", "Vsys map", vm["svg"], "vsys-map",
                                  drawio_href=f"/flow/{customer}/{stem}/vsys-map.drawio",
                                  svg_href=f"/flow/{customer}/{stem}/vsys-map.svg",
                                  note="Firewalls and their vsys, with the vsys on this trace pulled out. "
                                       "Next hops no loaded firewall owns go to the unknown-network cloud."))
    elif vm.get("layout"):
        body.append("<h3>Vsys map</h3>")
        body.append(_svg(vm["layout"]))
    if payload.get("files"):
        body.append(
            f"<p class='muted'>More diagrams for the loaded configuration: "
            f"<a href='/flow/{e(customer)}/{e(stem)}/diagram/site'>Environment by site</a> &middot; "
            f"<a href='/flow/{e(customer)}/{e(stem)}/diagram/pano'>Panorama device groups and template stacks</a> "
            f"(each can be exported as SVG, PNG or draw.io).</p>")
    if not rows:
        body.append("<div class='note'>No flows were parsed.</div>")
    for i, row in enumerate(rows, 1):
        body.append(_row_html(i, row, customer, stem))
    body.append(
        f"<form method='post' action='/flow/{e(customer)}/{e(stem)}/changeset'>"
        f"<p>Turn the required changes into a saved change set "
        f"({required} required item(s) across {len(rows)} flow(s)). "
        "The change set is always plan-only from this page; the push area will refuse it.</p>"
        f"<button type='submit'>Create change set</button> "
        f"<a class='btn secondary' href='/flow/{e(customer)}/{e(stem)}/export.json'>Export JSON</a> "
        f"<a class='btn secondary' href='/flow/{e(customer)}/{e(stem)}/export.md'>Export plan</a> "
        f"<a class='btn secondary' href='/flow/{e(customer)}/{e(stem)}/export.csv'>Export CSV</a> "
        f"<a class='btn secondary' href='/flow?customer={e(customer)}'>Trace another</a></form>")
    body.append(_DIAGRAM_JS)
    return w.page("Flow trace", "".join(body), user)


@router.get("/flow/{customer}/roles.json")
def roles_json(request: Request, customer: str) -> Response:
    """The saved site roles for this customer, in the JSON FlowMapper exports and imports."""
    w = _web()
    w.need(request, FLOW_PERMS, customer=customer)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")
    return Response(json.dumps(siteroles.load(prof), indent=2), media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename=site-roles-{customer}.json"})


@router.post("/flow/{customer}/{stem}/scope", response_class=HTMLResponse)
async def set_scope(request: Request, customer: str, stem: str) -> HTMLResponse:
    """Change the scope and/or the site roles for this customer, then trace the same flows again (new trace saved)."""
    w = _web()
    user = w.need(request, FLOW_PERMS, customer=customer)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")
    payload = _load_trace(prof, stem)
    if "fcr_text" not in payload:
        raise HTTPException(400, "This trace was made before scope existed; trace it again.")
    form = await request.form()
    flat = {k: (v if isinstance(v, str) else "") for k, v in form.items()}
    current = siteroles.load(prof)
    up = form.get("roles_file")
    try:
        if up is not None and getattr(up, "filename", None):
            raw = await up.read()
            if len(raw) > 2_000_000:
                raise siteroles.RolesError("the roles file is too large")
            try:
                current = siteroles.normalize(json.loads(raw.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise siteroles.RolesError(f"that is not a roles JSON file: {exc}") from exc
        roles = siteroles.save(prof, siteroles.apply_form(current, flat))
    except siteroles.RolesError as exc:
        raise HTTPException(400, str(exc)) from exc
    files = [fm.ConfigFile(path=Path(f["path"]), name=f.get("name") or Path(f["path"]).name)
             for f in payload.get("files") or [] if Path(f.get("path") or "").is_file()]
    if not files:
        raise HTTPException(400, "The configuration files of this trace are gone; trace it again.")
    try:
        result = fm.run_trace(files, payload["fcr_text"], ignore_intrazone=bool(payload.get("ignore_intrazone")),
                              route_tables=_tables(payload), links=_load_links(prof), pins=payload.get("pins") or {}, roles=roles)
    except fm.FlowMapperError as exc:
        raise HTTPException(400, str(exc)) from exc
    new = dict(payload, result=result, roles=roles, created=datetime.now(TZ).isoformat(timespec="seconds"),
               created_by=user[0], scoped_from=stem)
    new.pop("live_check", None)
    new_stem = _save_trace(prof, new)
    return RedirectResponse(f"/flow/{customer}/{new_stem}", status_code=303)


@router.get("/flow/{customer}/{stem}", response_class=HTMLResponse)
def show_trace(request: Request, customer: str, stem: str) -> HTMLResponse:
    w = _web()
    user = w.need(request, FLOW_PERMS, customer=customer)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")
    payload = _load_trace(prof, stem)
    return _result_page(w, user, customer, stem, payload)


@router.post("/flow/{customer}/{stem}/pin", response_class=HTMLResponse)
def pin_choice(request: Request, customer: str, stem: str, row: int = Form(...), choice: int = Form(...),
               device: str = Form(...), action: str = Form("pin")) -> HTMLResponse:
    """Answer a 'Needs your choice' decision: pin it for this trace (new trace saved) or save a next-hop link."""
    w = _web()
    user = w.need(request, FLOW_PERMS, customer=customer)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")
    payload = _load_trace(prof, stem)
    if "fcr_text" not in payload:
        raise HTTPException(400, "This trace was made before pins existed; trace it again.")
    rows = (payload.get("result") or {}).get("rows") or []
    if not 1 <= row <= len(rows):
        raise HTTPException(400, "no such flow")
    choices = (rows[row - 1].get("pathStatus") or {}).get("choices") or []
    if not 1 <= choice <= len(choices):
        raise HTTPException(400, "no such decision")
    c = choices[choice - 1]
    cand = next((x for x in c.get("candidates") or [] if x.get("devId") == device), None)
    if not cand:
        raise HTTPException(400, "that firewall is not a candidate")
    pins = dict(payload.get("pins") or {})
    if action == "link":
        if c.get("kind") != "next-hop" or not c.get("link"):
            raise HTTPException(400, "only a shared next hop can be saved as a link")
        links = [l for l in _load_links(prof) if not ((l.get("from") or {}).get("device") == c["link"]["device"]
                                                       and (l.get("from") or {}).get("iface") == c["link"]["iface"]
                                                       and (l.get("from") or {}).get("nexthop") == c["link"].get("nexthop"))]
        links.append({"from": dict(c["link"]), "to": {"device": cand.get("device"), "iface": cand.get("iface")},
                      "label": f"saved from {stem} by {user[0]}"})
        _save_links(prof, links)
    else:
        pin = dict(pins.get(str(row)) or {})
        if c.get("kind") == "next-hop":
            pin["choices"] = dict(pin.get("choices") or {}, **{c.get("key"): device})
        elif c.get("kind") == "destination":
            pin["dstDevice"] = device
        else:
            pin["srcDevice"] = device
        pins[str(row)] = pin
    files = [fm.ConfigFile(path=Path(f["path"]), name=f.get("name") or Path(f["path"]).name)
             for f in payload.get("files") or [] if Path(f.get("path") or "").is_file()]
    if not files:
        raise HTTPException(400, "The configuration files of this trace are gone; trace it again.")
    try:
        result = fm.run_trace(files, payload["fcr_text"], ignore_intrazone=bool(payload.get("ignore_intrazone")),
                              route_tables=_tables(payload), links=_load_links(prof), pins=pins,
                              roles=payload.get("roles"))
    except fm.FlowMapperError as exc:
        raise HTTPException(400, str(exc)) from exc
    new = dict(payload, result=result, pins=pins, created=datetime.now(TZ).isoformat(timespec="seconds"),
               created_by=user[0], pinned_from=stem)
    new.pop("live_check", None)
    new_stem = _save_trace(prof, new)
    return RedirectResponse(f"/flow/{customer}/{new_stem}", status_code=303)


@router.post("/flow/{customer}/links/delete", response_class=HTMLResponse)
def delete_link(request: Request, customer: str, index: int = Form(...)) -> HTMLResponse:
    w = _web()
    w.need(request, FLOW_PERMS, customer=customer)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")
    links = _load_links(prof)
    if 0 <= index < len(links):
        links.pop(index)
        _save_links(prof, links)
    return RedirectResponse(f"/flow?customer={customer}", status_code=303)


@router.post("/flow/{customer}/{stem}/changeset", response_class=HTMLResponse)
def make_changeset(request: Request, customer: str, stem: str) -> HTMLResponse:
    w = _web()
    user = w.need(request, FLOW_PERMS, customer=customer)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")
    payload = _load_trace(prof, stem)
    result = payload.get("result") or {}
    files = [fm.ConfigFile(path=Path(f["path"]), name=f.get("name") or Path(f["path"]).name)
             for f in payload.get("files") or [] if Path(f.get("path") or "").is_file()]
    target = prof.targets[0].name if prof.targets else "offline"
    reqs, placed = fm.requests_and_placements(result, target=target, project="flowtrace")
    if not reqs:
        raise HTTPException(400, "This trace has no parsed flows to turn into a change set.")
    envs = _envs(prof, files, target)
    if not envs:
        raise HTTPException(400, "Could not load a configuration model from the files used in this trace.")
    cs = build_changeset(
        prof, envs, reqs, files=payload.get("fcr_files") or [{"file": "flow-trace", "format": "paste"}],
        path_placements=placed, require_profile_targets=False, combine=False)
    cs["created_by"] = user[0]
    cs["flow_trace"] = stem
    # Always plan-only from the trace page, including live-snapshot traces.
    cs["plan_only"] = True
    if payload.get("use_live"):
        src = {"kind": "live", "pulled_at": (payload.get("live_snapshot") or {}).get("pulled_at")}
        cs["config_source"] = src
    elif payload.get("backup_ids") or files:
        first = None
        if payload.get("backup_ids"):
            try:
                first = uploads.get(prof, payload["backup_ids"][0])
            except uploads.UploadError:
                first = None
        if first:
            uploads.attach_source(cs, uploads.source_meta("backup", first))
        else:
            cs["config_source"] = {"kind": "backup", "file": files[0].name if files else "trace"}
    else:
        cs["config_source"] = {"kind": "trace"}
    cs_stem = "cs-" + datetime.now(TZ).strftime("%Y%m%d-%H%M%S")
    write_outputs(cs, prof.data_dir("changesets"), cs_stem)
    return RedirectResponse(f"/changesets/{customer}/{cs_stem}", status_code=303)


def _envs(profile, files: list[fm.ConfigFile], target: str):
    from panlab.netmodel import load_environment
    envs = []
    for f in files:
        try:
            envs.append(load_environment(f.path, target=target, site_codes=getattr(profile, 'site_codes', None)))
        except Exception:
            continue
    return envs



def _merge_live_files(profile, files: list[fm.ConfigFile], *, use_candidate: bool) -> list[fm.ConfigFile]:
    snap = liveconfig.ensure_snapshot(profile, refresh=False)
    extra: list[fm.ConfigFile] = []
    seen = {str(f.path.resolve()) for f in files if f.path.exists()}
    for path in snap.config_files(use_candidate=use_candidate):
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        extra.append(fm.ConfigFile(path=path, name=path.name))
    if not extra and not files:
        raise liveconfig.LiveError("The live snapshot has no configuration files yet. Refresh it first.")
    return extra + files


def _live_check_html(lc: dict) -> str:
    if lc.get("error") and not lc.get("rows"):
        return f"<div class='note' style='border-left-color:#b00020'><b>Live check failed:</b> {e(lc['error'])}</div>"
    n_dis = lc.get("disagreements") or 0
    n_err = lc.get("errors") or 0
    color = "#b00020" if n_dis else ("#8a6d00" if n_err else "#0a7a3e")
    head = (f"<div class='note' style='border-left-color:{color}'><h3>Live check</h3>"
            f"<p>Checked {lc.get('hops') or 0} hop(s) against the running device at "
            f"{e(lc.get('checked_at') or '')}. "
            f"<b>{n_dis}</b> disagreement(s), {n_err} live-test error(s).</p>")
    bits = [head]
    for row in lc.get("rows") or []:
        q = row.get("query") or {}
        title = f"{q.get('src') or '?'} → {q.get('dst') or '?'} {q.get('proto') or 'tcp'}"
        if q.get("port") is not None:
            title += f"/{q['port']}"
        bits.append(f"<p><b>Flow:</b> {e(title)}</p>")
        rows = []
        for h in row.get("hops") or []:
            agree = h.get("agree")
            mark = "agree" if agree else ("disagrees" if agree is False else "n/a")
            pm = h.get("policy_match") or {}
            logs = h.get("logs") or {}
            fib = h.get("fib") or {}
            fib_s = (fib.get("fields") or {}).get("interface") or (fib.get("error") or "—")
            detail = (
                f"policy-match: {e(str(pm.get('rule') or 'no explicit rule'))} "
                f"({e(str(pm.get('kind') or pm.get('error') or '?'))}); "
                f"FIB: {e(str(fib_s))}; "
                f"logs: {e(str(logs.get('top_action') or 'none'))}"
                + (f" by {e(str(logs.get('top_rule')))}" if logs.get("top_rule") else "")
            )
            dis = "".join(f"<div class='note' style='border-left-color:#b00020'>{e(d)}</div>" for d in (h.get("disagreements") or []))
            errs = "".join(f"<div class='muted'>{e(x)}</div>" for x in (h.get("errors") or []))
            rows.append(
                f"<tr class='{_verdict_cls('deny' if agree is False else ('allow' if agree else ''))}'>"
                f"<td>{e(str(h.get('n')))}</td><td>{e(h.get('hostname') or h.get('device') or '')}"
        f"{(' <span class=muted>' + e(h['device']) + '</span>') if h.get('hostname') else ''}</td>"
                f"<td>{e(h.get('vsys') or '')}</td><td><b>{e(mark)}</b></td>"
                f"<td>{e(h.get('trace_verdict') or '')}"
                f"{' by ' + e(h['trace_rule']) if h.get('trace_rule') else ''}</td>"
                f"<td>{detail}{dis}{errs}</td></tr>"
            )
        bits.append("<table><tr><th>#</th><th>Firewall</th><th>Vsys</th><th>Live vs trace</th>"
                    "<th>Trace verdict</th><th>Live tests</th></tr>"
                    + "".join(rows) + "</table>")
    bits.append("</div>")
    return "".join(bits)


@router.post("/flow/live/refresh", response_class=HTMLResponse)
def refresh_live(request: Request, customer: str = Form(...)) -> HTMLResponse:
    w = _web()
    _need_flow(w, request, customer)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(400, str(exc))
    if not liveconfig.can_live_pull(prof):
        raise HTTPException(400, "No API credentials are configured for a live pull.")
    try:
        snap = liveconfig.refresh_snapshot(prof, force=False)
    except liveconfig.LiveError as exc:
        raise HTTPException(400, str(exc))
    # Re-show the form; the card will include the new timestamp (or the rate-limit wait).
    return RedirectResponse(f"/flow?customer={customer}" + ("&rate_limited=1" if snap.rate_limited else ""), status_code=303)


@router.get("/flow/{customer}/{stem}/export.json")
def export_trace_json(request: Request, customer: str, stem: str):
    from fastapi.responses import Response

    w = _web()
    _need_flow(w, request, customer)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")
    payload = _load_trace(prof, stem)
    # Drop absolute server paths from the export.
    safe = dict(payload)
    safe["files"] = [{"name": f.get("name")} for f in (payload.get("files") or [])]
    safe["result"] = _without_diagrams(payload.get("result") or {})
    body = json.dumps(safe, indent=2)
    return Response(content=body, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{stem}.json"'})



def _without_diagrams(result: dict) -> dict:
    """The JSON export is for data, not pictures: drop the inline SVG / draw.io strings."""
    out = dict(result)
    out["rows"] = [{k: v for k, v in r.items() if k != "diagram"} for r in (result.get("rows") or [])]
    if result.get("vsysMap"):
        out["vsysMap"] = {k: v for k, v in result["vsysMap"].items() if k not in ("svg", "drawio")}
    return out


def _trace_for_export(request: Request, customer: str, stem: str):
    w = _web()
    _need_flow(w, request, customer)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")
    return w, prof, _load_trace(prof, stem)


def _attachment(body: str, media: str, filename: str):
    from fastapi.responses import Response
    return Response(content=body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _svg_doc(svg: str) -> str:
    return svg if svg.lstrip().startswith("<?xml") else '<?xml version="1.0" encoding="UTF-8"?>\n' + svg


@router.get("/flow/{customer}/{stem}/flow-{n}.svg")
def export_flow_svg(request: Request, customer: str, stem: str, n: int):
    _, _, payload = _trace_for_export(request, customer, stem)
    rows = (payload.get("result") or {}).get("rows") or []
    if not 1 <= n <= len(rows) or not rows[n - 1].get("diagram"):
        raise HTTPException(404, "no diagram for that flow (trace it again to draw it)")
    return _attachment(_svg_doc(rows[n - 1]["diagram"]), "image/svg+xml", f"{stem}-flow-{n}.svg")


@router.get("/flow/{customer}/{stem}/vsys-map.svg")
def export_vsys_svg(request: Request, customer: str, stem: str):
    _, _, payload = _trace_for_export(request, customer, stem)
    vm = (payload.get("result") or {}).get("vsysMap") or {}
    if not vm.get("svg"):
        raise HTTPException(404, "no vsys map for this trace (trace it again to draw it)")
    return _attachment(_svg_doc(vm["svg"]), "image/svg+xml", f"{stem}-vsys-map.svg")


@router.get("/flow/{customer}/{stem}/vsys-map.drawio")
def export_vsys_drawio(request: Request, customer: str, stem: str):
    _, _, payload = _trace_for_export(request, customer, stem)
    vm = (payload.get("result") or {}).get("vsysMap") or {}
    if not vm.get("drawio"):
        raise HTTPException(404, "no vsys map for this trace (trace it again to draw it)")
    return _attachment(vm["drawio"], "application/xml", f"{stem}-vsys-map.drawio")


def _diagram_files(payload: dict) -> list:
    files = [fm.ConfigFile(path=Path(f["path"]), name=f.get("name") or Path(f["path"]).name)
             for f in payload.get("files") or [] if Path(f.get("path") or "").is_file()]
    if not files:
        raise HTTPException(400, "The configuration files of this trace are gone; trace it again.")
    return files


def _environment_diagram(payload: dict, kind: str) -> dict:
    if kind not in ("site", "pano"):
        raise HTTPException(404, "unknown diagram")
    try:
        return fm.run_diagram(_diagram_files(payload), kind, roles=payload.get("roles"))
    except fm.FlowMapperError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/flow/{customer}/{stem}/diagram/{kind}.svg")
def export_environment_svg(request: Request, customer: str, stem: str, kind: str):
    _, _, payload = _trace_for_export(request, customer, stem)
    d = _environment_diagram(payload, kind)
    return _attachment(_svg_doc(d["svg"]), "image/svg+xml", f"{stem}-{kind}.svg")


@router.get("/flow/{customer}/{stem}/diagram/{kind}.drawio")
def export_environment_drawio(request: Request, customer: str, stem: str, kind: str):
    _, _, payload = _trace_for_export(request, customer, stem)
    d = _environment_diagram(payload, kind)
    return _attachment(d["drawio"], "application/xml", f"{stem}-{kind}.drawio")


@router.get("/flow/{customer}/{stem}/diagram/{kind}", response_class=HTMLResponse)
def show_environment_diagram(request: Request, customer: str, stem: str, kind: str) -> HTMLResponse:
    w = _web()
    user = w.need(request, FLOW_PERMS, customer=customer)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")
    payload = _load_trace(prof, stem)
    d = _environment_diagram(payload, kind)
    title = "Panorama: device groups, template stacks and firewalls" if kind == "pano" else "Environment by site"
    other = "site" if kind == "pano" else "pano"
    body = (f"<h2>{e(title)}</h2><p>{e(d.get('summary') or '')}</p>"
            + _diagram_card("env-diagram", title, d.get("svg") or "<p class='muted'>Nothing to draw.</p>", f"{stem}-{kind}",
                            drawio_href=f"/flow/{customer}/{stem}/diagram/{kind}.drawio",
                            svg_href=f"/flow/{customer}/{stem}/diagram/{kind}.svg",
                            note="Plan-only picture of the loaded configuration. Nothing here touches a firewall.")
            + f"<p><a class='btn secondary' href='/flow/{e(customer)}/{e(stem)}'>Back to the trace</a> "
              f"<a class='btn secondary' href='/flow/{e(customer)}/{e(stem)}/diagram/{other}'>"
              f"{'Environment by site' if other == 'site' else 'Panorama view'}</a></p>" + _DIAGRAM_JS)
    return w.page(title, body, user)


CSV_HEAD = ["Flow", "#", "Firewall", "vsys", "Where", "Type", "Required", "Change", "Rule name", "From zone", "To zone",
            "Source", "Destination", "Application", "Service", "Place before", "Rule order", "Device group", "CLI"]


def _plan_csv(payload: dict) -> str:
    """One line per planned change, in the offline page's ticket-CSV column order (plus the device group)."""
    import csv
    import io

    buf = io.StringIO()
    _w = csv.writer(buf)

    class _Guard:
        """Cells that start with = + - @ would run as formulas in a spreadsheet; mark them as text."""
        @staticmethod
        def writerow(cells):
            _w.writerow([("'" + c) if isinstance(c, str) and c[:1] in ("=", "+", "-", "@") else c for c in cells])

    w = _Guard()
    result = payload.get("result") or {}
    w.writerow(["Trace", payload.get("created") or "", "Plan only; cannot be used to push"])
    for i, row in enumerate(result.get("rows") or [], 1):
        en = row.get("enforcement") or {}
        if en.get("multi"):
            w.writerow([f"Flow {i}", "Places checked by security policy", en.get("text") or ""])
    w.writerow([])
    w.writerow(CSV_HEAD)
    for i, row in enumerate(result.get("rows") or [], 1):
        q = row.get("query") or {}
        title = f"{q.get('src')} -> {q.get('dst')} {q.get('proto') or 'tcp'}" + (f"/{q['port']}" if q.get("port") is not None else "")
        for n, it in enumerate((row.get("plan") or {}).get("items") or [], 1):
            rule = it.get("rule") if isinstance(it.get("rule"), dict) else {}
            w.writerow([title, n, it.get("device") or "", it.get("vsys") or "", it.get("where") or "", it.get("kind") or "",
                        "verify" if it.get("optional") else "yes", it.get("summary") or "", rule.get("name") or "",
                        rule.get("from") or "", rule.get("to") or "", rule.get("source") or "", rule.get("destination") or "",
                        rule.get("application") or "", rule.get("service") or "", rule.get("placeBefore") or "",
                        (it.get("order") or {}).get("text") or "", it.get("dg") or "", "\n".join(it.get("cli") or [])])
    return buf.getvalue()


@router.get("/flow/{customer}/{stem}/export.csv")
def export_trace_csv(request: Request, customer: str, stem: str):
    _, _, payload = _trace_for_export(request, customer, stem)
    return _attachment(_plan_csv(payload), "text/csv", f"{stem}-plan.csv")


@router.get("/flow/{customer}/{stem}/export.md")
def export_trace_plan(request: Request, customer: str, stem: str):
    from fastapi.responses import Response

    w = _web()
    _need_flow(w, request, customer)
    try:
        prof = load_profile(customer)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "unknown customer")
    payload = _load_trace(prof, stem)
    return Response(content=_plan_markdown(customer, stem, payload), media_type="text/markdown",
                    headers={"Content-Disposition": f'attachment; filename="{stem}-plan.md"'})


def _plan_markdown(customer: str, stem: str, payload: dict) -> str:
    result = payload.get("result") or {}
    lines = [f"# Flow trace {stem}", "", f"Customer: {customer}", "Plan only. This export cannot be used to push.", ""]
    if payload.get("live_snapshot"):
        st = payload["live_snapshot"]
        lines.append(f"Live snapshot: {st.get('pulled_at_label') or st.get('pulled_at')}")
        lines.append("")
    lc = payload.get("live_check")
    if lc:
        lines.append(f"Live check: {lc.get('hops') or 0} hop(s), {lc.get('disagreements') or 0} disagreement(s), "
                     f"{lc.get('errors') or 0} error(s).")
        lines.append("")
    for i, row in enumerate(result.get("rows") or [], 1):
        q = row.get("query") or {}
        title = f"{q.get('src')} -> {q.get('dst')} {q.get('proto') or 'tcp'}"
        if q.get("port") is not None:
            title += f"/{q['port']}"
        lines += [f"## Flow {i}: {title}", "", (row.get("why") or {}).get("text") or "", ""]
        lines.append("| # | Firewall | Vsys | From | To | Verdict |")
        lines.append("|---|---|---|---|---|---|")
        for h in row.get("hops") or []:
            lines.append(
                f"| {h.get('n')} | {h.get('device') or ''} | {h.get('display') or h.get('vsys') or ''} | "
                f"{h.get('fromZone') or ''} | {h.get('toZone') or ''} | "
                f"{h.get('verdict') or ''}{' by ' + h['rule'] if h.get('rule') else ''} |"
            )
        lines.append("")
        en = row.get("enforcement") or {}
        if en.get("multi"):
            lines += [f"**Rule needed in more than one place.** {en.get('text') or ''}", ""]
            for pl in en.get("places") or []:
                lines.append(f"- Place {pl.get('n')}: {pl.get('hostname') or pl.get('device') or ''} {pl.get('vsys') or ''} "
                             f"({pl.get('fromZone') or '?'} -> {pl.get('toZone') or '?'}): "
                             + ("needs an allow" + (f" (new rule {pl['newRule']})" if pl.get("newRule") else "")
                                if pl.get("needs") else "already allowed"))
            lines.append("")
        plan = row.get("plan") or {}
        lines.append(f"### Change plan ({plan.get('required') or 0} required)")
        for it in plan.get("items") or []:
            extra = ""
            if it.get("dg"):
                extra += f" [DG {it['dg']}]"
            if it.get("uncertain"):
                extra += " (placement uncertain)"
            if it.get("optional"):
                extra += " (optional)"
            lines.append(f"- {it.get('summary') or ''}{extra}")
            if (it.get("order") or {}).get("text"):
                lines.append(f"  - Rule order: {it['order']['text']}")
        if plan.get("cli"):
            lines += ["", "CLI steps:", "", "```", plan["cli"].rstrip(), "```"]
        if plan.get("gui"):
            lines += ["", "GUI steps:", ""]
            gui = plan["gui"]
            if isinstance(gui, list):
                lines.extend(f"- {g}" for g in gui)
            else:
                lines.append(str(gui))
        checklist = row.get("checklist") or []
        if checklist:
            lines += ["", "### Before you push"]
            lines.extend(f"{n}. {x}" for n, x in enumerate(checklist, 1))
        filters = ((row.get("filters") or {}).get("hops") or [])
        if filters:
            lines += ["", "### Traffic-log filters"]
            for h in filters:
                lines.append(f"- Hop {h.get('hop')} {h.get('device') or ''} {h.get('vsys') or ''}: `{h.get('filter') or ''}`")
                for c in h.get("testCli") or []:
                    lines.append(f"  - on the firewall: `{c}`")
        if lc:
            for lr in lc.get("rows") or []:
                if (lr.get("query") or {}) == q or lr.get("flow") == i:
                    for h in lr.get("hops") or []:
                        for d in h.get("disagreements") or []:
                            lines += ["", f"**Live disagreement (hop {h.get('n')}):** {d}"]
        lines.append("")
    return "\n".join(lines) + "\n"
