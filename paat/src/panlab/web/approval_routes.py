# SPDX-License-Identifier: Apache-2.0
"""POST endpoints for optional FCR and push approval."""

from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from panlab.customers import load_profile
from panlab.web import approval, auth

router = APIRouter()


def _web():
    from panlab.web import app as webapp
    return webapp


@router.post("/changesets/{customer}/{stem}/approve")
def approve_changeset(request: Request, customer: str, stem: str, cr: str = Form(""),
                      note: str = Form(""), decision: str = Form("")):
    w = _web()
    user = w.need(request, "approve", customer=customer)
    try:
        prof = load_profile(customer)
        cs = w._load_cs(prof, stem)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(404, str(exc))
    try:
        if decision == "reject":
            approval.reject(prof, stem, actor=user[0], reason=note or cr, created_by=cs.get("created_by") or "")
        else:
            if getattr(prof, "two_person_approval", False) and cs.get("created_by") == user[0]:
                raise approval.ApprovalError(
                    "The two-person rule does not let the person who built this change approve it."
                )
            approval.approve(prof, stem, actor=user[0], cr=cr, created_by=cs.get("created_by") or "", note=note)
    except approval.ApprovalError as exc:
        raise HTTPException(400, str(exc))
    action = "changeset_rejected" if decision == "reject" else "changeset_approved"
    auth.write_user_audit(actor=user[0], action=action, target=f"{customer}/{stem}", result="ok",
                          customer=customer, stem=stem)
    return RedirectResponse(f"/changesets/{customer}/{stem}/changeplan", status_code=303)
