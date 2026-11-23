"""Optional two-person approval for FCR and push, stored next to the change set.

Default off per customer (``two_person_approval``). The sidecar is
``<stem>.approval.json`` in the customer's changesets directory. It never
holds secrets or config XML.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from panlab.customers import load_profile

CHICAGO = ZoneInfo("America/Chicago")


class ApprovalError(ValueError):
    pass


def _path(prof, stem: str) -> Path:
    return prof.data_dir("changesets") / f"{stem}.approval.json"


def load(prof, stem: str) -> dict | None:
    p = _path(prof, stem)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def load_for(customer: str, stem: str) -> dict | None:
    try:
        return load(load_profile(customer), stem)
    except (ValueError, FileNotFoundError):
        return None


def save(prof, stem: str, rec: dict) -> dict:
    p = _path(prof, stem)
    p.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    p.chmod(0o600)
    return rec


def reset(prof, stem: str) -> bool:
    """Drop any approval or rejection: the change set it was given for has changed. True if one was removed."""
    p = _path(prof, stem)
    if p.is_file():
        p.unlink()
        return True
    return False


def approve(prof, stem: str, *, actor: str, cr: str, created_by: str = "", note: str = "") -> dict:
    cr = (cr or "").strip()
    if not cr:
        raise ApprovalError("An approved CR number is required.")
    if created_by and actor == created_by and getattr(prof, "two_person_approval", False):
        raise ApprovalError("The two-person rule does not let the person who built this change approve it.")
    rec = {
        "approved": True,
        "rejected": False,
        "approver": actor,
        "cr": cr,
        "note": (note or "").strip(),
        "created_by": created_by or "",
        "at": datetime.now(CHICAGO).isoformat(timespec="seconds"),
    }
    return save(prof, stem, rec)


def reject(prof, stem: str, *, actor: str, reason: str, created_by: str = "") -> dict:
    rec = {
        "approved": False,
        "rejected": True,
        "approver": actor,
        "cr": "",
        "note": (reason or "").strip() or "Rejected",
        "created_by": created_by or "",
        "at": datetime.now(CHICAGO).isoformat(timespec="seconds"),
    }
    return save(prof, stem, rec)


def check_push_allowed(prof, cs: dict, stem: str, actor: str) -> str | None:
    """Error message if prepare/apply must stop, otherwise None.

    When the two-person rule is off, the existing CR checkbox is enough.
    """
    if not getattr(prof, "two_person_approval", False):
        return None
    rec = load(prof, stem)
    if rec is None or rec.get("rejected") or not rec.get("approved"):
        return "This customer requires a second-person approval before prepare or apply."
    builder = rec.get("created_by") or cs.get("created_by") or ""
    if builder and rec.get("approver") == builder:
        return "The approver is the same person who built this change. Another person must approve it."
    return None


def form_html(cs: dict, customer: str, stem: str, prof, user) -> str:
    import html
    e = html.escape
    rec = load(prof, stem)
    two = bool(getattr(prof, "two_person_approval", False))
    bits = []
    if two:
        bits.append("<p>This customer requires a second person to approve before anyone can prepare a push.</p>")
    else:
        bits.append("<p>Second-person approval is optional for this customer. Recording an approval still helps the next person.</p>")
    if rec and rec.get("approved"):
        bits.append(
            f"<p class='verdict'>Approved by <b>{e(str(rec.get('approver') or ''))}</b> "
            f"at {e(str(rec.get('at') or ''))} with CR <b>{e(str(rec.get('cr') or ''))}</b>.</p>"
        )
    elif rec and rec.get("rejected"):
        bits.append(
            f"<p class='verdict'>Rejected by <b>{e(str(rec.get('approver') or ''))}</b>: "
            f"{e(str(rec.get('note') or ''))}.</p>"
        )
    can = bool(user and getattr(user, "can", lambda _p: False)("approve"))
    builder = cs.get("created_by") or ""
    is_builder = bool(user and builder and user[0] == builder)
    if is_builder and two and (not rec or rec.get("rejected") or not rec.get("approved")):
        bits.append("<p class='muted'>You built this change, so you cannot approve it while the two-person rule is on.</p>")
    elif can and (not rec or rec.get("rejected") or not rec.get("approved")):
        bits.append(
            f"<form method='post' action='/changesets/{e(customer)}/{e(stem)}/approve'>"
            "<label>CR number</label><input name='cr' required size='20'>"
            "<label>Note (optional)</label><input name='note' size='40'>"
            "<br><button>Approve</button> "
            "<button class='secondary' name='decision' value='reject'>Reject</button></form>"
        )
    elif not can:
        bits.append("<p class='muted'>You can see the approval status. Approving needs the approve permission.</p>")
    return "<div class='card approval'><h3>Approval</h3>" + "".join(bits) + "</div>"
