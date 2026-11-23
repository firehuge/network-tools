"""In-app help: the user manual (docs/user-manual/*.md) rendered as GUI pages at /help.

Every signed-in user can read it. The renderer covers the Markdown the manual uses (headings,
paragraphs, lists, tables, code, quotes, links, images) and escapes everything else, so a page
can never inject HTML. Links between manual pages stay inside /help.
"""

from __future__ import annotations

import html
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

router = APIRouter()
e = html.escape
MANUAL = Path(__file__).resolve().parents[3] / "docs" / "user-manual"
PAGE_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
IMG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.(png|svg|jpg|jpeg|gif)$")
REPO = ""  # TBD: set to the public documentation URL after the repository is published


def _web():
    from panlab.web import app as webapp
    return webapp


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9 -]", "", text.lower()).strip()
    return re.sub(r"[ ]+", "-", s)


def _href(url: str) -> str:
    """Map a manual link to a GUI link (manual pages and images) or leave it as is."""
    if re.match(r"^(https?:|mailto:|#|/)", url):
        return url
    path, _, frag = url.partition("#")
    frag = f"#{frag}" if frag else ""
    if path.startswith("img/"):
        return f"/help/{path}"
    if path.endswith(".md") and "/" not in path:
        return f"/help/{path[:-3]}{frag}"
    if path.startswith("../"):
        return REPO + path[3:] + frag  # repo docs outside the manual open on GitHub
    return url


def _inline(text: str) -> str:
    out, pos = [], 0
    for m in re.finditer(r"`([^`]+)`", text):
        out.append(_inline_plain(text[pos:m.start()]))
        out.append(f"<code>{e(m.group(1))}</code>")
        pos = m.end()
    out.append(_inline_plain(text[pos:]))
    return "".join(out)


def _inline_plain(text: str) -> str:
    t = e(text, quote=False)
    t = re.sub(r"!\[([^\]]*)\]\(([^)\s]+)\)",
               lambda m: f"<img src='{e(_href(html.unescape(m.group(2))))}' alt='{m.group(1)}' class='shot'>", t)
    t = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", lambda m: f"<a href='{e(_href(html.unescape(m.group(2))))}'>{m.group(1)}</a>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"(?<![\w*])\*([^*\s][^*]*)\*(?![\w*])", r"<i>\1</i>", t)
    return t


def render(md: str) -> tuple[str, str, list[tuple[int, str, str]]]:
    """Markdown to HTML. Returns (title, body, headings)."""
    lines = md.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    heads: list[tuple[int, str, str]] = []
    title = ""
    i = 0
    para: list[str] = []
    seen: dict[str, int] = {}

    def flush():
        if para:
            out.append("<p>" + _inline(" ".join(x.strip() for x in para)) + "</p>")
            para.clear()

    while i < len(lines):
        ln = lines[i]
        if ln.startswith("```"):
            flush()
            j = i + 1
            buf = []
            while j < len(lines) and not lines[j].startswith("```"):
                buf.append(lines[j])
                j += 1
            out.append("<pre>" + e("\n".join(buf)) + "</pre>")
            i = j + 1
            continue
        m = re.match(r"^(#{1,4})\s+(.*)$", ln)
        if m:
            flush()
            lvl, txt = len(m.group(1)), m.group(2).strip()
            sid = slug(txt)
            if sid in seen:
                seen[sid] += 1
                sid = f"{sid}-{seen[sid]}"
            else:
                seen[sid] = 0
            if lvl == 1 and not title:
                title = re.sub(r"[`*]", "", txt)
            heads.append((lvl, re.sub(r"[`*]", "", txt), sid))
            out.append(f"<h{lvl + 1} id='{sid}'>{_inline(txt)} <a class='anchor' href='#{sid}' aria-label='Link to this section'>#</a></h{lvl + 1}>")
            i += 1
            continue
        if re.match(r"^\s*(-{3,}|\*{3,})\s*$", ln):
            flush()
            out.append("<hr>")
            i += 1
            continue
        if ln.startswith("|") and i + 1 < len(lines) and re.match(r"^\|?\s*:?-{2,}", lines[i + 1]):
            flush()
            cells = lambda r: [c.strip() for c in r.strip().strip("|").split("|")]  # noqa: E731
            hdr = cells(ln)
            rows = []
            j = i + 2
            while j < len(lines) and lines[j].startswith("|"):
                rows.append(cells(lines[j]))
                j += 1
            out.append("<div class='tablewrap'><table class='doc'><thead><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in hdr)
                       + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>" for r in rows)
                       + "</tbody></table></div>")
            i = j
            continue
        if ln.startswith(">"):
            flush()
            buf = []
            while i < len(lines) and lines[i].startswith(">"):
                buf.append(lines[i][1:].strip())
                i += 1
            kind = "tip"
            if buf and re.match(r"^\*\*(Warning|Important|Danger)", buf[0], re.I):
                kind = "warn"
            out.append(f"<blockquote class='{kind}'>" + _inline(" ".join(buf)) + "</blockquote>")
            continue
        lm = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", ln)
        if lm:
            flush()
            out.append(_list(lines, i))
            i = _list_end(lines, i)
            continue
        if not ln.strip():
            flush()
            i += 1
            continue
        para.append(ln)
        i += 1
    flush()
    return title, "\n".join(out), heads


def _list_end(lines: list[str], i: int) -> int:
    while i < len(lines) and (re.match(r"^\s*([-*]|\d+\.)\s+", lines[i]) or (lines[i].startswith("  ") and lines[i].strip())):
        i += 1
    return i


def _list(lines: list[str], i: int) -> str:
    """One list, with nested lists by indentation and continuation lines."""
    end = _list_end(lines, i)
    items: list[tuple[int, bool, str]] = []
    for ln in lines[i:end]:
        m = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", ln)
        if m:
            items.append((len(m.group(1)), m.group(2)[0].isdigit(), m.group(3)))
        elif items:
            ind, num, txt = items[-1]
            items[-1] = (ind, num, txt + " " + ln.strip())
    out: list[str] = []
    stack: list[tuple[int, str]] = []
    for ind, num, txt in items:
        tag = "ol" if num else "ul"
        while stack and ind < stack[-1][0]:
            out.append(f"</li></{stack.pop()[1]}>")
        if not stack or ind > stack[-1][0]:
            out.append(f"<{tag}>")
            stack.append((ind, tag))
        else:
            out.append("</li>")
        out.append("<li>" + _inline(txt))
    while stack:
        out.append(f"</li></{stack.pop()[1]}>")
    return "".join(out)


def pages() -> list[tuple[str, str]]:
    out = []
    for p in sorted(MANUAL.glob("*.md")):
        first = next((ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.startswith("# ")), "# " + p.stem)
        out.append((p.stem, first[2:].strip().replace("`", "")))
    return out


@router.get("/help", response_class=HTMLResponse)
def help_index(request: Request) -> HTMLResponse:
    return help_page(request, "index")


@router.get("/about", response_class=HTMLResponse)
def about(request: Request) -> HTMLResponse:
    """About PAAT. Public (linked from the login page); signed-in users get the normal layout."""
    w = _web()
    try:
        user = w.need(request, "login")
    except Exception:  # not signed in: show it on the bare layout
        user = None
    if user is not None:
        return help_page(request, "about")
    _title, body, _heads = render((MANUAL / "about.md").read_text(encoding="utf-8"))
    return w.page("About", f"<article class='helpdoc' style='max-width:780px;margin:0 auto'>{body}"
                           "<p><a href='/login'>Sign in</a></p></article>", None, path="/about")


@router.get("/help/img/{name}")
def help_img(request: Request, name: str):
    _web().need(request, "login")
    if not IMG_RE.match(name) or not (MANUAL / "img" / name).is_file():
        raise HTTPException(404)
    return FileResponse(MANUAL / "img" / name)


@router.get("/help/{page}", response_class=HTMLResponse)
def help_page(request: Request, page: str) -> HTMLResponse:
    w = _web()
    user = w.need(request, "login")
    if not PAGE_RE.match(page) or not (MANUAL / f"{page}.md").is_file():
        raise HTTPException(404, "no such help page")
    title, body, heads = render((MANUAL / f"{page}.md").read_text(encoding="utf-8"))
    toc = "".join(f"<li class='l{lvl}'><a href='#{sid}'>{e(t)}</a></li>" for lvl, t, sid in heads if 2 <= lvl <= 3)
    side = "".join(f"<li><a href='/help/{s}' class='{'cur' if s == page else ''}'>{e(t)}</a></li>"
                   for s, t in sorted(pages(), key=lambda x: (x[0] not in ("index", "about"), x[0] != "index", x[1].lower())))
    tocb = f"<details class='toc' open><summary>On this page</summary><ul>{toc}</ul></details>" if len(heads) > 3 else ""
    if tocb and body.startswith("<h2") and "</h2>" in body:
        cut = body.index("</h2>") + 5
        body = body[:cut] + tocb + body[cut:]
    elif tocb:
        body = tocb + body
    html_ = (f"<div class='helpwrap'><aside class='helpnav'><b>User manual</b><ul>{side}</ul></aside>"
             f"<article class='helpdoc'>{body}</article></div>")
    return w.page(f"Help: {title or page}", html_, user)
