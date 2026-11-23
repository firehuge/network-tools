"""Change-set status and Home dashboard counts (read-only; reads the files the other pages already write).

Status of a change set, newest evidence first:
pushed / verify failed / rolled back (a push session) > plan only (built from a backup) >
rejected / approved (the approval sidecar) > awaiting approval (two-person rule on) > planned.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from panlab import uploads
from panlab.customers import load_profile
from panlab.web import approval

# session status -> (label, badge tone)
_PUSH = {
    "committed": ("Pushed", "success"),
    "committed-verify-failed": ("Verify failed", "danger"),
    "committed-push-failed": ("Push failed", "danger"),
    "rolled-back": ("Rolled back", "neutral"),
    "rollback-failed": ("Rollback failed", "danger"),
}


@dataclass
class CsRow:
    customer: str
    stem: str
    mtime: float
    summary: dict
    status: str
    tone: str


@dataclass
class Overview:
    customers: int = 0
    rows: list[CsRow] = field(default_factory=list)

    def count(self, *labels: str) -> int:
        return sum(1 for r in self.rows if r.status in labels)


def _push_status(prof) -> dict[str, tuple[str, str]]:
    """Latest finished push outcome per change set stem."""
    d = Path(prof.data_dir("push"))
    latest: dict[str, tuple[str, str, str]] = {}
    for p in d.glob("push-*.json"):
        try:
            s = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        st = s.get("status") or ""
        if st not in _PUSH or not s.get("changeset"):
            continue
        when = s.get("applied_at") or s.get("prepared_at") or ""
        if s["changeset"] not in latest or when > latest[s["changeset"]][0]:
            latest[s["changeset"]] = (when, *_PUSH[st])
    return {k: (v[1], v[2]) for k, v in latest.items()}


def status_of(prof, stem: str, cs: dict, pushed: dict[str, tuple[str, str]] | None = None) -> tuple[str, str]:
    pushed = _push_status(prof) if pushed is None else pushed
    if stem in pushed:
        return pushed[stem]
    if uploads.is_plan_only(cs):
        return ("Plan only", "neutral")
    rec = approval.load(prof, stem)
    if rec and rec.get("rejected"):
        return ("Rejected", "danger")
    if rec and rec.get("approved"):
        return ("Approved", "info")
    if getattr(prof, "two_person_approval", False):
        return ("Awaiting approval", "warning")
    return ("Planned", "neutral")


def overview(customers: list[str], per_customer: int = 200) -> Overview:
    ov = Overview(customers=len(customers))
    for c in customers:
        try:
            prof = load_profile(c)
            files = sorted((p for p in prof.data_dir("changesets").glob("*.json") if ".approval" not in p.name),
                           key=lambda p: p.stat().st_mtime, reverse=True)[:per_customer]
            pushed = _push_status(prof)
        except Exception:  # noqa: BLE001 - a broken profile must not take Home down
            continue
        for j in files:
            try:
                cs = json.loads(j.read_text(encoding="utf-8"))
                summary = cs["summary"]
            except Exception:  # noqa: BLE001
                continue
            label, tone = status_of(prof, j.stem, cs, pushed)
            ov.rows.append(CsRow(c, j.stem, j.stat().st_mtime, summary, label, tone))
    ov.rows.sort(key=lambda r: r.mtime, reverse=True)
    return ov


def upgrade_plan_count(customers: list[str]) -> int:
    from panlab.upgrade import planner
    n = 0
    for c in customers:
        try:
            n += len(planner.list_plans(load_profile(c)))
        except Exception:  # noqa: BLE001
            continue
    return n


def urlfilter_pending(customers: list[str]) -> int:
    from panlab import urlfilter
    n = 0
    for c in customers:
        try:
            n += sum(1 for r in urlfilter.list_requests(load_profile(c)) if r.get("status") in ("pending", "stale"))
        except Exception:  # noqa: BLE001
            continue
    return n


def edl_pending(customers: list[str]) -> int:
    """Staged EDL changes and EDL firewall-object requests waiting for a second person."""
    from panlab import edl
    n = 0
    for c in customers:
        try:
            prof = load_profile(c)
            n += edl.pending_count(prof) + sum(1 for r in edl.list_object_requests(prof) if r.get("status") == "pending")
        except Exception:  # noqa: BLE001
            continue
    return n
