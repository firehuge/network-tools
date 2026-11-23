"""Scope chip, site-role editor, DR-copy advice and Panorama HA card for the flow trace page.

Pure HTML builders: the routes that use them live in flowmapper_routes.py. Roles belong to firewalls
(and sites), never to Panorama; the Panorama HA card is shown for information only.
"""
from __future__ import annotations

import html

e = html.escape
MODES = (("production", "Production only"), ("all", "All sites"), ("custom", "My custom set"))


def _role_options(defs: list[dict], selected: str | None, guess_label: str = "Use the guess") -> str:
    out = [f"<option value=''{' selected' if not selected else ''}>{e(guess_label)}</option>"]
    for d in defs:
        out.append(f"<option value='{e(d['id'])}'{' selected' if d['id'] == selected else ''}>{e(d['label'])}</option>")
    return "".join(out)


def scope_select(saved: dict) -> str:
    """The scope choice on the trace form (remembered for this customer)."""
    cur = (saved.get("scope") or {}).get("mode") or "production"
    n = len((saved.get("scope") or {}).get("sites") or [])
    opts = [("production", "Production only (leaves DR, Lab and Test firewalls out)"), ("all", "All sites")]
    if n:
        opts.append(("custom", f"My custom set ({n} site{'s' if n != 1 else ''})"))
    if cur == "custom" and not n:
        cur = "production"
    return ("<label>Scope: which firewalls take part</label><select name='scope_mode' id='scope-mode'>"
            + "".join(f"<option value='{k}'{' selected' if k == cur else ''}>{e(v)}</option>" for k, v in opts)
            + "</select><p class='muted'>Roles are guessed from words in firewall names (prod, dr, lab, test and similar) and you can change "
              "any of them on the result page. The choice is remembered for this customer.</p>")


def panorama_card(p: dict | None, defs: list[dict]) -> str:
    if not p or not p.get("haEnabled"):
        return ""
    rows = []
    for side in (p.get("this"), p.get("peer")):
        if not side:
            continue
        key = side["key"]
        state = side.get("state") or ""
        rows.append(
            f"<tr><td>{e(side['name'])}{' <span class=muted>(this export)</span>' if side.get('isThisExport') else ''}</td>"
            f"<td><select name='pano_role__{e(key)}'>{_role_options(defs, side.get('role'), 'Not set')}</select>"
            f"<div class='muted'>{e(side.get('roleWhy') or '')}</div></td>"
            f"<td><select name='pano_state__{e(key)}'><option value=''{' selected' if not state else ''}>Not set</option>"
            f"<option value='active'{' selected' if state == 'active' else ''}>Active</option>"
            f"<option value='passive'{' selected' if state == 'passive' else ''}>Passive</option></select></td></tr>")
    return ("<div class='note'><b>Panorama high availability.</b> This Panorama is one of an HA pair. "
            f"{e(p.get('note') or '')}"
            "<div class='tablewrap'><table><tr><th>Panorama</th><th>Site role</th><th>Active or passive</th></tr>"
            + "".join(rows) + "</table></div></div>")


def scope_card(customer: str, stem: str, result: dict, saved: dict) -> str:
    """Chip with one-click scope change, plus the editable roles (sites, firewalls, new role, Panorama pair)."""
    sc = result.get("scope")
    roles = result.get("roles")
    if not sc or not roles:
        return ""
    mode = sc.get("mode") or "production"
    action = f"/flow/{e(customer)}/{e(stem)}/scope"
    hidden = sc.get("hidden") or 0
    tone = "warning" if hidden else "success"
    chip = e(sc.get("chip") or "")
    quick = []
    for k, label in MODES:
        if k == "custom" and not (saved.get("scope") or {}).get("sites"):
            continue
        if k == mode:
            continue
        quick.append(f"<button type='submit' name='scope_mode' value='{k}' class='btn secondary'>Show: {e(label)}</button>")
    hid_list = ""
    if hidden:
        names = ", ".join(e(x) for x in (sc.get("hiddenDevices") or [])[:40])
        more = f" and {hidden - 40} more" if hidden > 40 else ""
        hid_list = f"<details><summary>Which firewalls are left out</summary><p>{names}{more}</p><p class='muted'>{e(sc.get('text') or '')}</p></details>"
    defs = roles.get("defs") or []
    saved_rules = list((roles.get("profile") or saved or {}).get("rules") or saved.get("rules") or [])
    site_rows = []
    for s in roles.get("sites") or []:
        incl = ""
        if mode == "custom":
            incl = f"<td><input type='checkbox' name='incl__{e(s['id'])}' value='1'{' checked' if s.get('included') else ''}></td>"
        site_rows.append(
            f"<tr><td>{e(s['id'])}</td><td>{s.get('count')}</td>"
            f"<td><select name='site_role__{e(s['id'])}'>{_role_options(defs, s.get('setBy'))}</select></td>"
            f"<td>{e(s.get('why') or '')}</td>{incl}</tr>")
    fw_all = list(roles.get("firewalls") or [])
    fw_rows = []
    for f in fw_all[:300]:
        src = f.get("why") or f.get("source") or ""
        fw_rows.append(
            f"<tr data-fwrow='1' data-name='{e(f.get('name') or '')}' data-site='{e(f.get('site') or '')}' data-stack='{e(f.get('stack') or '')}' data-role='{e(f.get('role') or '')}' data-why='{e(f.get('why') or '')}'>"
            f"<td>{e(f.get('name') or '')}{' <span class=muted>(left out)</span>' if f.get('hidden') else ''}</td>"
            f"<td>{e(f.get('site') or '')}</td>"
            f"<td class='muted'>{e(f.get('stack') or '')}</td>"
            f"<td><select name='fw_role__{e(f['key'])}'>{_role_options(defs, f.get('setBy'))}</select></td>"
            f"<td class='muted'>{e(src)}</td></tr>")
    fw_more = f"<p class='muted'>Showing the first 300 of {roles.get('firewallCount')} firewalls. Set the rest by a matching rule or by site, or import a roles file.</p>" if (roles.get("firewallCount") or 0) > 300 else ""
    mirror_on = (roles.get("profile") or {}).get("mirror", {}).get("enabled") is not False
    custom_head = "<th>Include</th>" if mode == "custom" else ""
    field_opts = (("hostname", "Hostname"), ("stack", "Template stack"), ("dg", "Device group"),
                  ("serial", "Serial"), ("site", "Site id"), ("name", "Any name field"))
    match_opts = (("contains", "contains"), ("word", "whole word"), ("regex", "regex"))

    def _opts(pairs, selected):
        return "".join(f"<option value='{e(k)}'{' selected' if k == selected else ''}>{e(lab)}</option>" for k, lab in pairs)

    def _role_req(selected):
        v = selected or "production"
        return "".join(f"<option value='{e(d['id'])}'{' selected' if d['id'] == v else ''}>{e(d['label'])}</option>" for d in defs)

    rule_rows = []
    if not saved_rules:
        # one blank row so a first rule can be typed without clicking Add first
        saved_rules = [{"field": "stack", "match": "contains", "value": "", "role": "dr"}]
    for i, rule in enumerate(saved_rules):
        rule_rows.append(
            f"<tr class='rule-row' data-ridx='{i}'><td class='rnum'>{i+1}</td>"
            f"<td><select name='rule_field__{i}' class='rule-field'>{_opts(field_opts, rule.get('field') or 'stack')}</select></td>"
            f"<td><select name='rule_match__{i}' class='rule-match'>{_opts(match_opts, rule.get('match') or 'contains')}</select></td>"
            f"<td><input type='text' name='rule_value__{i}' class='rule-value' value='{e(rule.get('value') or '')}' placeholder='e.g. backup' style='min-width:8em'></td>"
            f"<td><select name='rule_role__{i}' class='rule-role'>{_role_req(rule.get('role'))}</select></td>"
            f"<td><button type='button' class='btn secondary rule-up'>Up</button> "
            f"<button type='button' class='btn secondary rule-down'>Down</button> "
            f"<button type='button' class='btn secondary rule-del'>Remove</button></td></tr>"
            f"<tr class='rule-preview'><td></td><td colspan='5'><div class='muted rule-note'></div></td></tr>"
        )
    fw_payload = [{
        "key": f.get("key"), "name": f.get("name"), "hostname": f.get("hostname") or f.get("name"),
        "serial": f.get("serial"), "stack": f.get("stack"), "dg": f.get("dg"), "site": f.get("site"),
    } for f in fw_all]
    import json as _json
    counts = {}
    for f in fw_all:
        counts[f.get("role") or "other"] = counts.get(f.get("role") or "other", 0) + 1
    count_line = " · ".join(f"{e(d['label'])} {counts[d['id']]}" for d in defs if counts.get(d["id"]))
    return (
        f"<div class='note' id='scope-card' style='border-left-color:var(--{tone});background:var(--{tone}-soft)'>"
        f"<form method='post' action='{action}'><p><span class='chip on' id='scope-chip'>{chip}</span> "
        f"{' '.join(quick)}</p>{hid_list}</form>"
        "<details id='roles-box' open><summary><b>Site roles</b> — matching rules, and which firewalls are Production, DR, Lab or Test</summary>"
        "<p class='muted'>Add a matching rule at the top (for example: template stack <i>contains</i> a word you type, set to DR). "
        "First match wins. A setting on one firewall or one site still beats a rule. The preview updates as you type. "
        "Save to keep the rules for this customer and trace again.</p>"
        f"<form method='post' action='{action}' enctype='multipart/form-data' id='roles-form'>"
        "<input type='hidden' name='incl_present' value='1'><input type='hidden' name='mirror_present' value='1'>"
        "<input type='hidden' name='rules_present' value='1'>"
        f"<input type='hidden' name='scope_mode' value='{e(mode)}'>"
        "<script type='application/json' id='roles-fw-data'>" + _json.dumps(fw_payload).replace("<", "\\u003c") + "</script>"
        "<h4>Matching rules</h4>"
        "<div class='tablewrap'><table id='roles-rules'><tr><th>#</th><th>Look in</th><th>Match</th><th>Text</th><th>Role</th><th></th></tr>"
        + "".join(rule_rows) + "</table></div>"
        "<p><button type='button' class='btn secondary' id='rule-add'>Add rule</button> "
        "<span class='muted'>Leave the text empty while you think — the preview still updates.</span></p>"
        f"<h4>Firewalls ({len(fw_all)}" + (f" — {count_line}" if count_line else "") + ")</h4>"
        "<p><input type='search' id='roles-q' placeholder='Filter by hostname, stack, site, role or reason' style='max-width:28em'> "
        "<button type='button' class='btn secondary' id='roles-bulk-set'>Set role on shown</button> "
        f"<select id='roles-bulk-role'>{_role_options(defs, None, 'Choose a role')}</select></p>"
        "<div class='tablewrap'><table id='roles-fws'><tr><th>Firewall</th><th>Site</th><th>Stack</th><th>Role</th><th>Source</th></tr>"
        + "".join(fw_rows) + "</table></div>" + fw_more
        + "<details id='roles-sites-wrap'><summary><b>Sites</b> — set every firewall at a site, or pick a custom set</summary>"
        "<div class='tablewrap'><table id='roles-sites'><tr><th>Site</th><th>Firewalls</th><th>Role</th><th>Why</th>" + custom_head + "</tr>"
        + "".join(site_rows) + "</table></div></details>"
        f"{panorama_card(roles.get('panorama'), defs)}"
        "<h4>Your own role</h4><p class='muted'>Add a role such as Staging. Tick &quot;Keep in Production only&quot; if Production only should still include it; "
        "tick &quot;DR copy target&quot; if it is a place rules should be copied to.</p>"
        "<input type='text' name='new_role' placeholder='Role name' style='max-width:220px'> "
        "<label style='display:inline;font-weight:400'><input type='checkbox' name='new_focus' value='1'> Keep in Production only</label> "
        "<label style='display:inline;font-weight:400'><input type='checkbox' name='new_mirror' value='1'> DR copy target</label>"
        f"<p><label style='font-weight:400'><input type='checkbox' name='mirror' value='yes'{' checked' if mirror_on else ''}> "
        "Tell me when a change probably needs a copy on a DR firewall (DR is never traced)</label></p>"
        "<p><label>Or load a roles file (the JSON FlowMapper exports); it replaces the saved roles</label>"
        "<input type='file' name='roles_file' accept='.json'></p>"
        f"<button type='submit'>Save roles and trace again</button> "
        f"<a class='btn secondary' href='/flow/{e(customer)}/roles.json'>Export roles JSON</a></form>"
        "<script>(function(){"
        "function words(s){return String(s||'').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);}"
        "function fieldText(d,field){"
        "  var hn=d.hostname||'', name=d.name||'', stack=d.stack||'', serial=d.serial||'', site=d.site||'', dg=d.dg||'';"
        "  if(field==='hostname') return hn || (/^\\d{9,}$/.test(name)?'':name);"
        "  if(field==='stack') return stack; if(field==='dg') return dg; if(field==='serial') return String(serial);"
        "  if(field==='site') return site;"
        "  return [hn,name,stack,dg,site].filter(Boolean).join(' ');"
        "}"
        "function applies(d,field,match,value){"
        "  value=String(value||''); if(!value) return false;"
        "  var text=fieldText(d,field);"
        "  if(match==='regex'){ try{ return new RegExp(value,'i').test(text);}catch(e){return false;} }"
        "  var t=String(text).toLowerCase(), v=value.toLowerCase();"
        "  if(match==='word'){ var tw=words(t), vw=words(v); if(!vw.length) return false; if(t===v) return true;"
        "    for(var i=0;i+vw.length<=tw.length;i++){ var ok=true; for(var j=0;j<vw.length;j++) if(tw[i+j]!==vw[j]){ok=false;break;} if(ok) return true; } return false; }"
        "  return t.indexOf(v)>=0;"
        "}"
        "function devices(){ try{return JSON.parse(document.getElementById('roles-fw-data').textContent)||[];}catch(e){return [];} }"
        "function rows(){ return Array.prototype.slice.call(document.querySelectorAll('#roles-rules tr.rule-row')); }"
        "function renumber(){ rows().forEach(function(tr,i){ tr.dataset.ridx=i; tr.querySelector('.rnum').textContent=i+1;"
        "  tr.querySelector('.rule-field').name='rule_field__'+i; tr.querySelector('.rule-match').name='rule_match__'+i;"
        "  tr.querySelector('.rule-value').name='rule_value__'+i; tr.querySelector('.rule-role').name='rule_role__'+i; }); }"
        "function preview(){ var list=devices(), claimed={};"
        "  rows().forEach(function(tr,i){"
        "    var field=tr.querySelector('.rule-field').value, match=tr.querySelector('.rule-match').value;"
        "    var value=tr.querySelector('.rule-value').value, note=tr.nextElementSibling && tr.nextElementSibling.querySelector('.rule-note');"
        "    var hits=[], overlap=0, err=null;"
        "    if(!String(value).trim()) err='This rule matches nothing (no text to look for).';"
        "    else if(match==='regex'){ try{ new RegExp(value,'i'); }catch(ex){ err='This rule has an invalid regular expression.'; } }"
        "    if(!err){ list.forEach(function(d){ if(!applies(d,field,match,value)) return; hits.push(d); if(claimed[d.key||d.name]) overlap++; else claimed[d.key||d.name]=i+1; }); }"
        "    var msg=err||(!hits.length?'This rule matches nothing.':(hits.length+' firewall'+(hits.length===1?'':'s')+': '+hits.slice(0,8).map(function(d){return d.name;}).join(', ')+(hits.length>8?' +'+(hits.length-8)+' more':'')));"
        "    if(overlap) msg+=' — '+overlap+' already match an earlier rule, so this rule will not apply to them.';"
        "    if(note){ note.textContent=msg; note.className='rule-note '+(err||!hits.length||overlap?'':'muted'); if(err||!hits.length||overlap) note.style.color='var(--warning)'; else note.style.color=''; }"
        "  }); }"
        "function bind(){ var tbl=document.getElementById('roles-rules'); if(!tbl) return;"
        "  tbl.addEventListener('input', preview); tbl.addEventListener('change', preview);"
        "  tbl.addEventListener('click', function(ev){"
        "    var b=ev.target; if(!b.classList) return; var tr=b.closest('tr.rule-row'); if(!tr) return;"
        "    var prv=tr.nextElementSibling;"
        "    if(b.classList.contains('rule-del')){ if(prv) prv.remove(); tr.remove(); renumber(); preview(); }"
        "    if(b.classList.contains('rule-up') && tr.previousElementSibling){ var prevRow=tr.previousElementSibling.previousElementSibling; if(prevRow&&prevRow.classList.contains('rule-row')){ tr.parentNode.insertBefore(tr, prevRow); if(prv) tr.parentNode.insertBefore(prv, tr.nextElementSibling); renumber(); preview(); } }"
        "    if(b.classList.contains('rule-down') && prv && prv.nextElementSibling){ var next=prv.nextElementSibling, nextPr=next.nextElementSibling; tr.parentNode.insertBefore(next, tr); if(nextPr) tr.parentNode.insertBefore(nextPr, next.nextElementSibling); renumber(); preview(); }"
        "  });"
        "  var add=document.getElementById('rule-add');"
        "  if(add) add.addEventListener('click', function(){ var proto=document.querySelector('#roles-rules tr.rule-row'); if(!proto) return;"
        "    var tr=proto.cloneNode(true), pr=proto.nextElementSibling.cloneNode(true);"
        "    tr.querySelector('.rule-value').value=''; var last=document.querySelector('#roles-rules tr.rule-preview:last-of-type')||proto;"
        "    last.parentNode.appendChild(tr); last.parentNode.appendChild(pr); renumber(); preview(); tr.querySelector('.rule-value').focus(); });"
        "  var q=document.getElementById('roles-q');"
        "  if(q) q.addEventListener('input', function(){ var s=q.value.toLowerCase(); document.querySelectorAll('#roles-fws tr[data-fwrow]').forEach(function(tr){ var hay=((tr.dataset.name||'')+' '+(tr.dataset.site||'')+' '+(tr.dataset.stack||'')+' '+(tr.dataset.role||'')+' '+(tr.dataset.why||'')).toLowerCase(); tr.style.display=!s||hay.indexOf(s)>=0?'':'none'; }); });"
        "  var bulk=document.getElementById('roles-bulk-set'), br=document.getElementById('roles-bulk-role');"
        "  if(bulk) bulk.addEventListener('click', function(){ var role=br&&br.value; if(!role) return;"
        "    document.querySelectorAll('#roles-fws tr[data-fwrow]').forEach(function(tr){ if(tr.style.display==='none') return; var sel=tr.querySelector('select'); if(sel) sel.value=role; }); });"
        "  preview(); }"
        "if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', bind); else bind();"
        "})();</script>"
        "</details></div>")




def via_hidden_html(row: dict, customer: str, stem: str) -> str:
    v = (row.get("scope") or {}).get("viaHidden")
    if not v:
        return ""
    return (f"<div class='note warn' style='border-left-color:var(--warning);background:var(--warning-soft)'><b>This flow needs a firewall the scope hides.</b> "
            f"{e(v.get('text') or '')} "
            f"<form method='post' action='/flow/{e(customer)}/{e(stem)}/scope' style='display:inline'>"
            "<button type='submit' name='scope_mode' value='all' class='btn secondary'>Show all sites</button></form></div>")


def mirror_html(row: dict) -> str:
    m = row.get("drMirror")
    if not m:
        return ""
    items = []
    for it in m.get("items") or []:
        cands = "".join(
            f"<li>{e(c.get('device') or '')}: <b>{e(c.get('level') or '')}</b> ({e('; '.join(c.get('reasons') or []))})"
            f"{(' ' + e(c['addrNote'])) if c.get('addrNote') else ''}</li>" for c in it.get("candidates") or [])
        items.append(f"<li>{e(it.get('device') or '')}{(': ' + e(it['note'])) if it.get('note') else ''}<ul>{cands}</ul></li>")
    return ("<div class='note'><b>DR copy likely needed.</b> " + e(m.get("text") or "") +
            " <span class='muted'>This is advice only: DR firewalls were not traced.</span>"
            f"<ul>{''.join(items)}</ul></div>")


def conflict_html(row: dict, customer: str, stem: str) -> str:
    """Routing vs rules, with a distinct notice when the disagreement only appears because the scope hid a firewall."""
    k = row.get("conflict")
    if not k:
        return ""
    cause = k.get("scopeCause") or ""
    text = k.get("scopeText") or ""
    if cause in ("hidden-routed-hop", "hidden-owner"):
        return (f"<div class='note warn' id='scope-conflict' style='border-left-color:var(--warning);background:var(--warning-soft)'>"
                f"<b>Routing and rules disagree only because of the scope.</b> {e(text)} "
                f"<form method='post' action='/flow/{e(customer)}/{e(stem)}/scope' style='display:inline'>"
                "<button type='submit' name='scope_mode' value='all' class='btn secondary'>Show all sites</button></form></div>")
    return (f"<div class='note warn' id='scope-conflict' style='border-left-color:var(--warning);background:var(--warning-soft)'>"
            f"<b>Routing and rules disagree.</b> Routing says {e(k.get('routing') or '')}; rules suggest {e(k.get('rules') or '')}. "
            f"{e(text or 'This is worth reviewing (a stale rule or a routing problem). The trace follows routing.')}</div>")
