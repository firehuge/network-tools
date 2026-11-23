"""FCR-to-plan-to-approval-to-push stepper shown on change-set pages."""

from __future__ import annotations

import html

from panlab import uploads
from panlab.web import approval

e = html.escape

_CHECK = ("<svg viewBox='0 0 24 24' width='13' height='13' aria-label='done' fill='none' stroke='currentColor' "
          "stroke-width='3' stroke-linecap='round' stroke-linejoin='round'><path d='M5 12l5 5 9-10'/></svg>")

STEPS = (
    ("request", "Request"),
    ("plan", "Plan"),
    ("approval", "Approval"),
    ("push", "Push"),
)


def states(cs: dict, customer: str, stem: str, prof=None) -> dict[str, str]:
    """Map step id to done, current, blocked, or waiting."""
    plan_only = uploads.is_plan_only(cs)
    rec = approval.load(prof, stem) if prof is not None else approval.load_for(customer, stem)
    two = bool(getattr(prof, "two_person_approval", False)) if prof is not None else False
    request = "done" if (cs.get("files") or cs.get("requests") or cs.get("kind") == "decommission") else "waiting"
    plan = "done"
    if rec and rec.get("approved"):
        appro = "done"
    elif rec and rec.get("rejected"):
        appro = "blocked"
    elif two:
        appro = "waiting"
    else:
        appro = "waiting"  # optional; still shown
    if plan_only:
        push = "blocked"
    elif rec and rec.get("approved") and not rec.get("rejected"):
        push = "waiting"
    elif two:
        push = "blocked"
    else:
        push = "waiting"
    return {"request": request, "plan": plan, "approval": appro, "push": push}


def html_block(cs: dict, customer: str, stem: str, current: str, prof=None, user=None) -> str:
    st = states(cs, customer, stem, prof)
    items = []
    hrefs = {
        "request": f"/changesets/{customer}/{stem}",
        "plan": f"/changesets/{customer}/{stem}/changeplan",
        "approval": f"/changesets/{customer}/{stem}/changeplan",
        "push": f"/push/{customer}/{stem}",
    }
    can_push = bool(user and getattr(user, "can", lambda _p: False)("push"))
    for i, (sid, label) in enumerate(STEPS, 1):
        state = st[sid]
        cls = "cur" if sid == current else state
        num = _CHECK if state == "done" and sid != current else str(i)
        hint = {"done": "done", "blocked": "blocked"}.get(state, "")
        hint_html = f" <span class='st'>{e(hint)}</span>" if hint and sid != current else ""
        if sid == "push" and not can_push:
            items.append(f"<li class='{e(cls)} locked'><span class='n'>{i}</span> {e(label)} <small>locked</small></li>")
            continue
        items.append(
            f"<li class='{e(cls)}'><a href='{e(hrefs[sid])}'><span class='n'>{num}</span> {e(label)}{hint_html}</a></li>"
        )
    return "<ol class='stepper' aria-label='Change workflow'>" + "".join(items) + "</ol>"
