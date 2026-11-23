# SPDX-License-Identifier: Apache-2.0
"""Progress, phase and result panels for the OS upgrade pages (pure HTML helpers, no I/O).

Kept apart from ``upgrade_routes`` so the run page can show, in plain words: how far along the plan is, which
phase it is in, what the current step is waiting for (including the long reboot wait), and what the pre- and
post-checks found.
"""

from __future__ import annotations

import html
from datetime import datetime, timedelta

from panlab.upgrade import runner
from panlab.upgrade.versions import is_downgrade

e = html.escape

PHASES = [
    ("precheck", "Pre-checks"),
    ("backup", "Backup"),
    ("content", "Content"),
    ("software", "Download and install"),
    ("reboot", "Reboot and reconnect"),
    ("postcheck", "Post-checks"),
]
PHASE_OF = {"precheck": "precheck", "backup": "backup", "content": "content", "download": "software", "install": "software",
            "ha-suspend": "software", "reboot": "reboot", "wait": "reboot", "ha-functional": "reboot", "postcheck": "postcheck"}
ICON = {"ok": "&#9989;", "skipped": "&#9989;", "failed": "&#10060;", "running": "&#9203;", "pending": "&#9711;"}
GOOD, WARN, BAD = "#1a7f37", "#9a6700", "#b00020"


def _dt(x: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(x) if x else None
    except ValueError:
        return None


def fmt_dur(td: timedelta) -> str:
    sec = max(int(td.total_seconds()), 0)
    m, s = divmod(sec, 60)
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m" if h else f"{m}m {s:02d}s"


def change_word(d: dict) -> str:
    return "DOWNGRADE" if is_downgrade(d.get("current") or "", d.get("target") or "") else "upgrade"


def change_badge(d: dict) -> str:
    if change_word(d) == "DOWNGRADE":
        return "<span class='lt' style='background:#9a6700'>DOWNGRADE</span> "
    return ""


def phase_states(plan: dict) -> list[tuple[str, str, str]]:
    """(key, label, state) per phase that this plan has; state is done|current|failed|pending."""
    nxt = runner.next_step(plan)
    out = []
    for key, label in PHASES:
        steps = [s for s in plan["steps"] if PHASE_OF.get(s["action"]) == key]
        if not steps:
            continue
        if any(s["status"] == "failed" for s in steps):
            st = "failed"
        elif all(s["status"] in ("ok", "skipped") for s in steps):
            st = "done"
        elif nxt is not None and PHASE_OF.get(nxt["action"]) == key:
            st = "current"
        elif any(s["status"] in ("ok", "skipped", "running") for s in steps):
            st = "current"
        else:
            st = "pending"
        out.append((key, label, st))
    return out


def progress_html(plan: dict) -> str:
    steps = plan["steps"]
    total = len(steps) or 1
    done = sum(1 for s in steps if s["status"] in ("ok", "skipped"))
    pct = int(done * 100 / total)
    colour = BAD if plan.get("status") == "stopped" else GOOD
    pills = []
    for _, label, st in phase_states(plan):
        bg, fg, bd = {"done": ("#e6f4ea", GOOD, GOOD), "current": ("#fff8e1", WARN, WARN), "failed": ("#fde7e9", BAD, BAD),
                      "pending": ("#f6f8fa", "#555", "#d0d7de")}[st]
        mark = {"done": "&#10003; ", "current": "&#9654; ", "failed": "&#10007; ", "pending": ""}[st]
        pills.append(f"<span style='display:inline-block;margin:2px 6px 2px 0;padding:3px 10px;border-radius:12px;"
                     f"border:1px solid {bd};background:{bg};color:{fg};font-size:13px'>{mark}{e(label)}</span>")
    started = _dt(plan.get("armed_at"))
    el = f" · running for {fmt_dur(runner.now() - started)}" if started and plan.get("status") not in ("complete",) else ""
    return ("<div class='card'><b>Progress: step {done} of {total} done ({pct}%)</b>{el}"
            "<div style='background:#e1e4e8;border-radius:6px;height:14px;margin:6px 0'>"
            "<div style='width:{pct}%;background:{colour};height:14px;border-radius:6px'></div></div>{pills}</div>"
            ).format(done=done, total=len(steps), pct=pct, el=el, colour=colour, pills="".join(pills))


def now_panel(plan: dict, nxt: dict | None) -> str:
    """Plain-words panel for the step that is running right now (jobs, the reboot wait)."""
    run = next((s for s in plan["steps"] if s["status"] == "running"), None)
    if run is None:
        return ""
    act = run["action"]
    t0 = _dt(run.get("started"))
    el = fmt_dur(runner.now() - t0) if t0 else "?"
    if act == "wait":
        since = _dt(run.get("wait_since")) or t0
        waited = runner.now() - since if since else timedelta(0)
        seen = run.get("last_seen")
        lim = int(runner.WAIT_LIMIT.total_seconds() // 60)
        state = (f"Panorama lists the device as connected on <b>{e(str(seen))}</b>, waiting for <b>{e(run['version'])}</b>."
                 if seen else "The device is not answering yet. That is normal while it reboots.")
        late = ("<p style='color:#b00020'><b>This is taking longer than usual.</b> A PA-VM normally returns in 10 to 25 minutes. "
                f"The tool stops waiting at {lim} minutes and marks the step failed. Check the VM console in vCenter and "
                "Panorama's Managed Devices list; do not start another step.</p>" if waited > timedelta(minutes=30) else "")
        return ("<div class='note'><b>Rebooting: waiting for the device to come back.</b><p>"
                f"Waiting for {e(run.get('hostname') or run['device_name'])} for <b>{fmt_dur(waited)}</b> "
                f"(usual: 10 to 25 minutes; the tool gives up after {lim}). {state}</p>{late}"
                "<p class='muted'>The tool only checks on the device while this page is open (it reloads every 15 seconds). If you "
                "close it, reopen this page later and it carries on from where it was.</p></div>")
    j = (run.get("jobs") or [{}])[-1]
    jtxt = ""
    if j.get("jobid"):
        pr = str(j.get("progress") or "").strip()
        jtxt = (f" Job <b>{e(str(j['jobid']))}</b> ({e(j.get('label', ''))}): {e(j.get('status', '') or 'queued')}"
                + (f" {e(pr)}%." if pr else "."))
    return (f"<div class='note'><b>Running: {e(run['title'])}</b> for {el}.{jtxt} "
            "<span class='muted'>Panorama's Task Manager shows the same job.</span></div>")


def checks_details(s: dict) -> str:
    """Pre-check result list under the step row."""
    cs = s.get("checks") or []
    if not cs:
        return ""
    colour = {"green": GOOD, "yellow": WARN, "red": BAD}
    word = {"green": "GOOD", "yellow": "CHECK", "red": "STOP"}
    lis = "".join(f"<li><b style='color:{colour.get(c['level'], '#555')}'>{word.get(c['level'], c['level'])}</b> "
                  f"<b>{e(c['title'])}</b>. {e(c.get('detail', ''))}</li>" for c in cs)
    return f"<details><summary>Pre-check results ({len(cs)} checks)</summary><ul class='chk'>{lis}</ul></details>"


def results_table(s: dict) -> str:
    """Post-check result table under the step row."""
    rs = s.get("results") or []
    if not rs:
        return ""
    def word(r):
        return ("CHECK", WARN) if r.get("level") == "warn" else ("OK", GOOD) if r["ok"] else ("FAIL", BAD)
    rows = "".join(f"<tr><td style='color:{word(r)[1]}'><b>{word(r)[0]}</b></td>"
                   f"<td>{e(r['check'])}</td><td>{e(str(r.get('detail', '')))}</td></tr>" for r in rs)
    return f"<table class='mini'><tr><th>Result</th><th>Check</th><th>Detail</th></tr>{rows}</table>"


def before_after(plan: dict) -> str:
    """Summary of what changed, built from the pre-check and post-check snapshots."""
    rows = []
    for d in plan["devices"]:
        pre = next((x.get("snapshot") for x in plan["steps"] if x["device"] == d["id"] and x["action"] == "precheck"
                    and x.get("snapshot")), None) or {}
        post = next((x.get("snapshot_after") for x in plan["steps"] if x["device"] == d["id"] and x["action"] == "postcheck"
                     and x.get("snapshot_after")), None) or {}
        if not post:
            continue
        rows.append(f"<tr><td>{e(d.get('hostname') or d['name'])}</td><td>{e(str(pre.get('sw_version') or d['current']))}</td>"
                    f"<td><b>{e(str(post.get('sw_version')))}</b></td><td>{e(str(pre.get('app_version') or '?'))}</td>"
                    f"<td>{e(str(post.get('app_version') or '?'))}</td></tr>")
    if not rows:
        return ""
    return ("<h3>Before and after</h3><table><tr><th>Device</th><th>Version before</th><th>Version after</th>"
            "<th>Content before</th><th>Content after</th></tr>" + "".join(rows) + "</table>")


def timing(s: dict) -> str:
    a, b = _dt(s.get("started")), _dt(s.get("finished"))
    if a and b:
        return f"<div class='muted'>took {fmt_dur(b - a)}</div>"
    return ""
