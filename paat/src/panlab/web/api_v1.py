"""Read-only /api/v1 for change sets and the signed-in user.

Write actions stay on the existing HTML form routes until a later phase.
Auth is the session cookie or a Bearer API token with the same scope.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from panlab import __version__
from panlab.customers import load_profile
from panlab.web import auth, tokens
from panlab.web.blast_radius import summarize

router = APIRouter(prefix="/api/v1")

OPENAPI = {
    "openapi": "3.0.3",
    "info": {
        "title": "PAAT API (Policy Automation and Analysis Tool)",
        "version": "1.0.0",
        "description": "Read-only change-set API. Session cookie or Bearer token. Scope and view permission are enforced.",
    },
    "servers": [{"url": "/", "description": "This PAAT server"}],
    "paths": {
        "/api/v1/health": {"get": {"summary": "Liveness", "security": [], "responses": {"200": {"description": "ok"}}}},
        "/api/v1/me": {"get": {"summary": "Signed-in user and permissions", "responses": {"200": {"description": "principal"}}}},
        "/api/v1/customers": {"get": {"summary": "Customers in scope", "responses": {"200": {"description": "list"}}}},
        "/api/v1/customers/{name}/changesets": {"get": {"summary": "Saved change sets", "responses": {"200": {"description": "list"}}}},
        "/api/v1/customers/{name}/changesets/{stem}": {"get": {"summary": "One change set", "responses": {"200": {"description": "change set"}}}},
        "/api/v1/customers/{name}/changesets/{stem}/plan": {"get": {"summary": "Change plan Markdown plus blast-radius", "responses": {"200": {"description": "plan"}}}},
    },
    "components": {
        "securitySchemes": {
            "cookie": {"type": "apiKey", "in": "cookie", "name": "panlab_session"},
            "bearer": {"type": "http", "scheme": "bearer"},
        }
    },
    "security": [{"cookie": []}, {"bearer": []}],
}


def _web():
    from panlab.web import app as webapp
    return webapp


def _principal(request: Request, perm: str = "login"):
    """Session cookie first, then Bearer token. Same permission checks as the GUI."""
    u = auth.read_cookie(request.cookies.get(auth.COOKIE))
    if u is None:
        header = request.headers.get("authorization") or ""
        if header.lower().startswith("bearer "):
            u = tokens.read_token(header.split(" ", 1)[1].strip())
    if u is None:
        raise HTTPException(401, "sign in or pass a Bearer token")
    if u.must_change and request.url.path not in ("/api/v1/me", "/api/v1/health"):
        raise HTTPException(403, "change your password before using the API")
    if perm != "login" and not u.can(perm):
        raise HTTPException(403, f"needs the '{perm}' permission")
    w = _web()
    w._CURRENT_USER.set(u)
    w._CURRENT_PATH.set(request.url.path)
    return u


def _customer(user, name: str):
    if not user.sees_customer(name):
        raise HTTPException(403, f"customer {name} is not in your scope")
    try:
        return load_profile(name)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, f"no such customer {name}")


@router.get("/health")
def health():
    return {"status": "ok", "version": __version__}


@router.get("/openapi.json")
def openapi():
    return JSONResponse(OPENAPI)


@router.get("/me")
def me(request: Request):
    from panlab.web import layers
    u = _principal(request, "login")
    return {
        "name": u[0],
        "layer": layers.layer_label(u),
        "permissions": sorted(u.perms),
        "customers": list(u.customers),
    }


@router.get("/customers")
def customers(request: Request):
    u = _principal(request, "view")
    w = _web()
    w._CURRENT_USER.set(u)
    return {"customers": w.list_customers()}


@router.get("/customers/{name}/changesets")
def list_changesets(request: Request, name: str):
    u = _principal(request, "view")
    prof = _customer(u, name)
    out = []
    for path in sorted(prof.data_dir("changesets").glob("*.json")):
        if path.name.endswith("approval.json"):
            continue
        try:
            cs = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(cs, dict) or "summary" not in cs:
            continue
        out.append({"stem": path.stem, "summary": cs.get("summary") or {}, "created_by": cs.get("created_by") or ""})
    return {"customer": name, "changesets": out}


@router.get("/customers/{name}/changesets/{stem}")
def get_changeset(request: Request, name: str, stem: str):
    u = _principal(request, "view")
    prof = _customer(u, name)
    w = _web()
    path = w._cs_path(name, stem, "json")
    cs = json.loads(path.read_text(encoding="utf-8"))
    return {"customer": name, "stem": stem, "changeset": cs, "blast_radius": summarize(cs)}


@router.get("/customers/{name}/changesets/{stem}/plan")
def get_plan(request: Request, name: str, stem: str):
    u = _principal(request, "view")
    _customer(u, name)
    w = _web()
    cs = json.loads(w._cs_path(name, stem, "json").read_text(encoding="utf-8"))
    parts = w._plan_parts(name, stem)
    return {
        "customer": name,
        "stem": stem,
        "plan": parts.get("full") or "",
        "sections": {k: parts.get(k) or "" for k, _t in w._PLAN_SECTIONS},
        "blast_radius": summarize(cs),
    }


@router.get("/docs", response_class=JSONResponse)
def docs_hint(request: Request):
    """Machine-readable pointer. The OpenAPI document is /api/v1/openapi.json."""
    _principal(request, "login")
    return {"openapi": "/api/v1/openapi.json", "note": "This phase ships the OpenAPI document, not a Swagger UI."}
