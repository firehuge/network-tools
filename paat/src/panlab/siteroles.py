# SPDX-License-Identifier: Apache-2.0
"""Site roles and the trace scope (Production only) for the flow tracer.

A role (Production, DR, Lab, Test, Other, or one you add) belongs to a FIREWALL or a site,
never to Panorama. The FlowMapper engine guesses roles from generic words in names
(prod, dr, backup, lab, test ...) and explains each guess; this module only stores what
the user decided, per customer, and turns the CLI/web scope choice into the job the engine runs.

The saved file is the same JSON FlowMapper exports ("Export roles JSON"), so a profile built in
the offline page works here and the other way round:

    {"kind": "flowmapper-site-roles", "version": 1,
     "roles": [{"id": "staging", "label": "Staging", "focus": false, "mirror": false}],
     "tokens": {"staging": ["stg"]},
     "sites": {"<site id>": "dr"}, "devices": {"<serial or hostname>": "lab"},
     "rules": [{"field": "stack", "match": "contains", "value": "backup", "role": "dr"}],
     "scope": {"mode": "production" | "all" | "custom", "sites": []},
     "mirror": {"enabled": true}, "panoramas": {}}
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

BUILTIN = ("production", "dr", "lab", "test", "other")
FILE_NAME = "site-roles.json"
_ID = re.compile(r"[^a-z0-9_-]+")


class RolesError(ValueError):
    """The scope or the roles file is not something we can use."""


def default() -> dict[str, Any]:
    return {"kind": "flowmapper-site-roles", "version": 1, "roles": [], "tokens": {}, "sites": {}, "devices": {},
            "rules": [], "scope": {"mode": "production", "sites": []}, "mirror": {"enabled": True}, "panoramas": {}}


def parse_scope(text: str | None) -> dict[str, Any]:
    """--scope production | all | sites=a,b  ->  {"mode", "sites"}. Anything else is an error, never a silent default."""
    t = (text or "").strip()
    if not t or re.fullmatch(r"production(-only)?", t, re.I):
        return {"mode": "production", "sites": []}
    if re.fullmatch(r"all(-sites)?", t, re.I):
        return {"mode": "all", "sites": []}
    m = re.fullmatch(r"sites?\s*=\s*(.+)", t, re.I)
    if m:
        sites = [x.strip() for x in m.group(1).split(",") if x.strip()]
        if sites:
            return {"mode": "custom", "sites": sites}
    raise RolesError(f"unknown scope {t!r}: use production, all, or sites=name1,name2")



_RULE_FIELDS = {"hostname", "stack", "dg", "serial", "site", "name"}
_RULE_FIELD_ALIAS = {
    "template-stack": "stack", "template_stack": "stack", "templatestack": "stack",
    "device-group": "dg", "device_group": "dg", "devicegroup": "dg",
    "site-id": "site", "site_id": "site",
    "any": "name", "any-name": "name", "any_name": "name", "anyname": "name",
}
_RULE_MATCH = {"contains": "contains", "word": "word", "whole-word": "word", "whole_word": "word",
               "regex": "regex", "regexp": "regex"}


def _rule_field(raw: Any) -> str | None:
    rid = _ID.sub("-", str(raw or "").strip().lower()).strip("-")
    if rid in _RULE_FIELDS:
        return rid
    return _RULE_FIELD_ALIAS.get(rid)


def _rule_match(raw: Any) -> str:
    return _RULE_MATCH.get(str(raw or "contains").strip().lower(), "contains")


def normalize_rules(raw: Any, valid: set[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if not isinstance(raw, list):
        return out
    for r in raw:
        if not isinstance(r, dict):
            continue
        field = _rule_field(r.get("field"))
        if not field:
            continue
        role = _ID.sub("-", str(r.get("role") or "").strip().lower()).strip("-")
        if role not in valid:
            continue
        value = str(r.get("value") if r.get("value") is not None else "")[:120]
        out.append({"field": field, "match": _rule_match(r.get("match", r.get("op"))), "value": value, "role": role})
    return out


def normalize(data: Any) -> dict[str, Any]:
    """Keep only well-formed parts (the engine normalises again; this keeps junk out of the saved file)."""
    out = default()
    if not isinstance(data, dict):
        return out
    roles = []
    for r in data.get("roles") or []:
        if not isinstance(r, dict):
            continue
        rid = _ID.sub("-", str(r.get("id") or r.get("label") or "").strip().lower()).strip("-")
        if rid and rid not in BUILTIN and all(x["id"] != rid for x in roles):
            roles.append({"id": rid, "label": str(r.get("label") or rid)[:40], "focus": bool(r.get("focus")), "mirror": bool(r.get("mirror"))})
    out["roles"] = roles
    valid = set(BUILTIN) | {r["id"] for r in roles}
    for key in ("sites", "devices"):
        src = data.get(key)
        if isinstance(src, dict):
            out[key] = {str(k): str(v) for k, v in src.items() if str(v) in valid}
    out["rules"] = normalize_rules(data.get("rules"), valid)
    toks = data.get("tokens")
    if isinstance(toks, dict):
        for k, v in toks.items():
            if str(k) in valid and isinstance(v, list):
                words = [str(w).lower().strip() for w in v if re.fullmatch(r"[a-zA-Z0-9]{1,24}", str(w).strip())]
                if words:
                    out["tokens"][str(k)] = words
    sc = data.get("scope")
    if isinstance(sc, dict):
        mode = str(sc.get("mode") or "").lower()
        out["scope"]["mode"] = mode if mode in ("all", "custom") else "production"
        out["scope"]["sites"] = [str(s) for s in (sc.get("sites") or []) if str(s)]
    mir = data.get("mirror")
    if isinstance(mir, dict):
        out["mirror"]["enabled"] = mir.get("enabled") is not False
    pan = data.get("panoramas")
    if isinstance(pan, dict):
        for k, v in pan.items():
            if isinstance(v, dict):
                e: dict[str, str] = {}
                if str(v.get("role") or "") in valid:
                    e["role"] = str(v["role"])
                if str(v.get("state") or "").lower() in ("active", "passive"):
                    e["state"] = str(v["state"]).lower()
                out["panoramas"][str(k)] = e
    return out


def load_file(path: str | Path) -> dict[str, Any]:
    try:
        return normalize(json.loads(Path(path).read_text()))
    except (OSError, json.JSONDecodeError) as exc:
        raise RolesError(f"cannot read roles file {path}: {exc}") from exc


def _path(profile) -> Path:
    d = profile.data_dir("flowtraces")
    d.mkdir(parents=True, exist_ok=True)
    return d / FILE_NAME


def load(profile) -> dict[str, Any]:
    """The saved roles, or the defaults. Reading never creates folders (the CLI may run where the data folder is not writable)."""
    from panlab.customers import data_root
    try:
        p = data_root() / profile.name / "flowtraces" / FILE_NAME
        return normalize(json.loads(p.read_text())) if p.is_file() else default()
    except (OSError, json.JSONDecodeError):
        return default()


def save(profile, data: dict[str, Any]) -> dict[str, Any]:
    clean = normalize(data)
    p = _path(profile)
    p.write_text(json.dumps(clean, indent=2))
    p.chmod(0o600)
    return clean


def with_scope(data: dict[str, Any], scope: str | None) -> dict[str, Any]:
    """The saved roles with the scope replaced by an explicit --scope value (None keeps the saved scope)."""
    out = normalize(data)
    if scope is not None:
        out["scope"] = parse_scope(scope)
    return out


def apply_form(current: dict[str, Any], form: dict[str, Any]) -> dict[str, Any]:
    """Update a saved profile from the web form: scope, site roles, firewall roles, new role, mirror on/off.

    Fields: scope_mode; site_role__<site id> and fw_role__<key> (empty = back to the guess);
    incl__<site id> for the custom set; new_role / new_focus / new_mirror; mirror ("yes" when on);
    rules_present plus rule_field__N / rule_match__N / rule_value__N / rule_role__N (ordered)."""
    d = normalize(current)
    mode = str(form.get("scope_mode") or "")
    if mode in ("all", "production", "custom"):
        d["scope"]["mode"] = mode
    custom = [k[len("incl__"):] for k, v in form.items() if k.startswith("incl__") and v]
    if form.get("incl_present") or custom:
        d["scope"]["sites"] = custom
    for k, v in form.items():
        if k.startswith("site_role__"):
            if v:
                d["sites"][k[len("site_role__"):]] = str(v)
            else:
                d["sites"].pop(k[len("site_role__"):], None)
        elif k.startswith("fw_role__"):
            if v:
                d["devices"][k[len("fw_role__"):]] = str(v)
            else:
                d["devices"].pop(k[len("fw_role__"):], None)
        elif k.startswith("pano_role__") or k.startswith("pano_state__"):
            kind, key = ("role", k[len("pano_role__"):]) if k.startswith("pano_role__") else ("state", k[len("pano_state__"):])
            ent = d["panoramas"].setdefault(key, {})
            if v:
                ent[kind] = str(v)
            else:
                ent.pop(kind, None)
    name = str(form.get("new_role") or "").strip()
    if name:
        rid = _ID.sub("-", name.lower()).strip("-")
        if not rid or rid in BUILTIN or any(r["id"] == rid for r in d["roles"]):
            raise RolesError(f"role name {name!r} is taken or empty")
        d["roles"].append({"id": rid, "label": name[:40], "focus": bool(form.get("new_focus")), "mirror": bool(form.get("new_mirror"))})
    if "mirror_present" in form:
        d["mirror"]["enabled"] = str(form.get("mirror") or "") == "yes"
    if "rules_present" in form:
        idxs = []
        for k in form:
            if k.startswith("rule_field__"):
                try:
                    idxs.append(int(k[len("rule_field__"):]))
                except ValueError:
                    continue
        d["rules"] = [{
            "field": form.get(f"rule_field__{i}"),
            "match": form.get(f"rule_match__{i}"),
            "value": form.get(f"rule_value__{i}"),
            "role": form.get(f"rule_role__{i}"),
        } for i in sorted(set(idxs))]
    return normalize(d)
