# SPDX-License-Identifier: Apache-2.0
"""Search saved change sets and ticket numbers, limited to the user's scope."""

from __future__ import annotations

import html
import json
import re

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from panlab.web import theme

router = APIRouter()
e = html.escape
TOKEN = re.compile(r"[A-Za-z0-9_.:/-]+")


def _web():
    from panlab.web import app as webapp
    return webapp


def _tickets(cs: dict) -> list[str]:
    out: list[str] = []
    def add(val):
        if not val:
            return
        if isinstance(val, list):
            for x in val:
                add(x)
            return
        s = str(val).strip()
        if s and s not in out:
            out.append(s)
    for f in cs.get("files") or []:
        add((f.get("tickets") or {}))
        if isinstance(f.get("tickets"), dict):
            for v in f["tickets"].values():
                add(v)
        add(f.get("ritm"))
        add(f.get("sctask"))
        add(f.get("cr"))
    for rq in cs.get("requests") or []:
        tix = rq.get("tickets") or {}
        if isinstance(tix, dict):
            for v in tix.values():
                add(v)
        add(tix)
    add(cs.get("tickets"))
    if isinstance(cs.get("tickets"), dict):
        for v in cs["tickets"].values():
            add(v)
    return out


def _rule_names(cs: dict) -> list[str]:
    names = []
    for g in cs.get("groups") or []:
        for r in g.get("rules") or []:
            n = str(r.get("name") or "").strip()
            if n:
                names.append(n)
    return names


def _haystack(customer: str, stem: str, cs: dict) -> str:
    parts = [customer, stem]
    parts.extend(_tickets(cs))
    parts.extend(_rule_names(cs))
    created = cs.get("created_by") or ""
    if created:
        parts.append(str(created))
    return " ".join(parts).lower()


def search_changesets(customers: list[str], query: str, limit: int = 50) -> list[dict]:
    from panlab.customers import load_profile

    terms = [t.lower() for t in TOKEN.findall(query) if t.strip()]
    if not terms:
        return []
    hits = []
    for c in customers:
        try:
            prof = load_profile(c)
            files = list(prof.data_dir("changesets").glob("*.json"))
        except Exception:
            continue
        for path in files:
            if path.name.endswith(".approval.json"):
                continue
            # sidecar is stem.approval.json, glob of *.json includes it; skip those
            if path.name.endswith("approval.json"):
                continue
            try:
                cs = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(cs, dict) or "summary" not in cs:
                continue
            hay = _haystack(c, path.stem, cs)
            if all(t in hay for t in terms):
                sm = cs.get("summary") or {}
                hits.append({
                    "customer": c,
                    "stem": path.stem,
                    "tickets": _tickets(cs),
                    "rules": sm.get("rules"),
                    "red_flags": sm.get("red_flags"),
                    "mtime": path.stat().st_mtime,
                })
    hits.sort(key=lambda r: r["mtime"], reverse=True)
    return hits[:limit]


@router.get("/search", response_class=HTMLResponse)
def search_page(request: Request, q: str = "") -> HTMLResponse:
    w = _web()
    user = w.need(request, "view")
    q = (q or "").strip()
    rows = ""
    note = ""
    if q:
        hits = search_changesets(w.list_customers(), q)
        if hits:
            rows = "".join(
                f"<tr><td>{e(h['customer'])}</td>"
                f"<td><a href='/changesets/{e(h['customer'])}/{e(h['stem'])}'>{e(h['stem'])}</a></td>"
                f"<td>{e(', '.join(h['tickets']))}</td>"
                f"<td>{e(str(h['rules'] or ''))}</td>"
                f"<td>{e(str(h['red_flags'] or ''))}</td></tr>"
                for h in hits
            )
            note = f"<p class='muted'>{len(hits)} in your scope.</p>"
        else:
            note = "<p class='muted'>No change sets in your scope matched that search.</p>"
    else:
        note = "<p class='muted'>Search change-set ids, RITM, SCTASK, CR, or rule names. Results stay inside your customer scope.</p>"
    body = (
        f"<h2>Search</h2>"
        f"{theme.help_note('navigation.md', 'Search looks at saved change sets and ticket numbers in your scope only.')}"
        f"<form method='get' action='/search' class='card'><label>Query</label>"
        f"<input type='search' name='q' value='{e(q)}' size='40' autofocus>"
        f"<br><button>Search</button></form>{note}"
        + (f"<table><tr><th>Customer</th><th>Change set</th><th>Tickets</th><th>Rules</th><th>Red flags</th></tr>{rows}</table>" if rows else "")
    )
    return w.page("Search", body, user)
