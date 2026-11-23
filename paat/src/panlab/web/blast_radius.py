# SPDX-License-Identifier: Apache-2.0
"""Short blast-radius summary for a saved change set.

Computed only from the change set JSON. It does not talk to a device and
does not rerun placement.
"""

from __future__ import annotations

import html

e = html.escape


def summarize(cs: dict) -> dict:
    """Facts a reviewer should see before approve or push."""
    sm = cs.get("summary") or {}
    groups = cs.get("groups") or []
    targets: list[str] = []
    dgs: list[str] = []
    flags_red = []
    flags_yellow = []
    broad = []
    serial_limited = False
    panorama = False
    rule_names = []
    for g in groups:
        backend = g.get("backend") or ""
        if backend == "panorama":
            panorama = True
        tgt = g.get("target") or g.get("device") or ""
        if tgt and tgt not in targets:
            targets.append(str(tgt))
        dg = g.get("device_group") or ""
        if dg and dg not in dgs:
            dgs.append(str(dg))
        also = g.get("also_targets") or g.get("target_devices") or []
        if also:
            serial_limited = True
            for name in also:
                n = str(name)
                if n not in targets:
                    targets.append(n)
        for r in g.get("rules") or []:
            if r.get("name"):
                rule_names.append(str(r["name"]))
            for side in ("source", "destination", "from_zone", "to_zone", "application", "service"):
                vals = r.get(side) or r.get(side.replace("_", "-")) or []
                if isinstance(vals, str):
                    vals = [vals]
                if any(str(v).lower() == "any" for v in vals):
                    broad.append(f"rule {r.get('name') or '?'} uses any on {side}")
            for f in r.get("flags") or []:
                line = f.get("message") or f.get("text") or f.get("code") or ""
                level = f.get("level") or ""
                if level == "red":
                    flags_red.append(str(line))
                elif level == "yellow":
                    flags_yellow.append(str(line))
    unplaced = cs.get("unplaced") or []
    kind = cs.get("kind") or "add"
    if kind == "decommission":
        return _summarize_decom(cs, sm, targets, dgs, panorama, unplaced)
    red_count = int(sm.get("red_flags") or 0)
    needs_human = int(sm.get("needs_human") or 0)
    if red_count or needs_human or unplaced:
        verdict = "Do not push until a person clears the red flags or unplaced requests."
        level = "red" if red_count or unplaced else "yellow"
    elif broad:
        verdict = "Review the broad matches (any or a wide prefix) before you approve."
        level = "yellow"
    elif kind == "decommission":
        verdict = "This plan removes or edits existing policy. Confirm the backout before you approve."
        level = "yellow"
    elif int(sm.get("rules") or 0) == 0 and int(sm.get("edited_rules") or 0) == 0:
        verdict = "No new or edited rules. The traffic may already be allowed, or the plan only adds objects."
        level = "green"
    else:
        verdict = "This plan is ready for review. Approve it only after you have read the steps and the diff."
        level = "green"
    return {
        "verdict": verdict,
        "level": level,
        "kind": kind,
        "targets": targets,
        "device_groups": dgs,
        "panorama": panorama,
        "serial_limited": serial_limited,
        "rules": int(sm.get("rules") or 0),
        "edited_rules": int(sm.get("edited_rules") or 0),
        "deleted_rules": int(sm.get("deleted_rules") or 0),
        "new_objects": int(sm.get("new_objects") or 0),
        "red_flags": red_count,
        "needs_human": needs_human,
        "unplaced": len(unplaced),
        "broad": broad[:12],
        "flags_red": flags_red[:12],
        "flags_yellow": flags_yellow[:8],
        "rule_names": rule_names,
    }


def _summarize_decom(cs: dict, sm: dict, targets: list, dgs: list, panorama: bool, unplaced: list) -> dict:
    """Decommission: what the plan removes, how sure each finding is, and the red callouts to read."""
    flags = cs.get("flags") or []
    blocking = [f["message"] for f in flags if f.get("level") == "red" and f.get("code") in ("unresolved", "invalid-item", "deny-manual")]
    dangers = [f["message"] for f in flags if f.get("level") == "red" and f.get("code") not in ("unresolved", "invalid-item", "deny-manual")]
    tiers = sm.get("tiers") or {}
    if blocking or unplaced:
        verdict, level = "Do not push until a person clears the red flags or unresolved items.", "red"
    elif dangers:
        verdict, level = (f"{len(dangers)} red callout(s): a rule is deleted or disabled because removing the target would "
                          "leave a field empty (any), or a negated field changes. Read them before you approve."), "yellow"
    else:
        verdict, level = "This plan removes or edits existing policy. Confirm the backout before you approve.", "yellow"
    return {
        "verdict": verdict, "level": level, "kind": "decommission", "targets": targets, "device_groups": dgs,
        "panorama": panorama, "serial_limited": False, "rules": int(sm.get("rules") or 0),
        "edited_rules": int(sm.get("edited_rules") or 0), "deleted_rules": int(sm.get("deleted_rules") or 0),
        "disabled_rules": int(sm.get("disabled_rules") or 0), "deny_rules": int(sm.get("deny_rules") or 0),
        "new_objects": int(sm.get("new_objects") or 0), "deleted_objects": int(sm.get("deleted_objects") or 0),
        "red_flags": len(blocking), "dangers": len(dangers), "needs_human": int(sm.get("needs_human") or 0),
        "unplaced": len(unplaced), "broad": [], "flags_red": (blocking + dangers)[:12], "flags_yellow": [],
        "rule_names": [], "tiers": {"exact": int(tiers.get("exact") or 0), "likely": int(tiers.get("likely") or 0),
                                    "possible": int(tiers.get("possible") or 0)},
        "selected": int(sm.get("selected") or 0),
    }


def html_block(cs: dict) -> str:
    s = summarize(cs)
    items = []
    if s["targets"]:
        items.append("<li><b>Targets:</b> " + e(", ".join(s["targets"])) + "</li>")
    if s["device_groups"]:
        items.append("<li><b>Device groups:</b> " + e(", ".join(s["device_groups"])) + "</li>")
    if s["panorama"]:
        scope = "commit-all is limited to named serials" if s["serial_limited"] else "Panorama-managed (check that commit-all stays serial-limited)"
        items.append("<li><b>Path:</b> " + e(scope) + "</li>")
    counts = []
    if s["kind"] == "decommission":
        t = s.get("tiers") or {}
        items.append("<li><b>Findings:</b> " + e(f"{t.get('exact', 0)} exact, {t.get('likely', 0)} highly likely, "
                                                   f"{t.get('possible', 0)} possible (advice only); {s.get('selected', 0)} selected") + "</li>")
        counts.append(f"{s['edited_rules']} rules edited")
        counts.append(f"{s['deleted_rules']} rules deleted")
        if s.get("disabled_rules"):
            counts.append(f"{s['disabled_rules']} rules disabled")
        counts.append(f"{s.get('deleted_objects', 0)} objects deleted")
        if s.get("deny_rules"):
            counts.append(f"{s['deny_rules']} deny rules added")
        counts.append(f"{s.get('dangers', 0)} red callouts")
    else:
        counts.append(f"{s['rules']} rules in the plan")
        counts.append(f"{s['new_objects']} new objects")
    counts.append(f"{s['red_flags']} red flags")
    counts.append(f"{s['needs_human']} need a human")
    if s["unplaced"]:
        counts.append(f"{s['unplaced']} unplaced")
    items.append("<li><b>Size:</b> " + e(", ".join(counts)) + "</li>")
    if s["broad"]:
        items.append("<li><b>Broad matches:</b> " + e("; ".join(s["broad"])) + "</li>")
    if s["flags_red"]:
        items.append(("<li><b>Red flags and callouts:</b> " if s["kind"] == "decommission" else "<li><b>Red flags:</b> ")
                     + e("; ".join(s["flags_red"])) + "</li>")
    return (
        f"<div class='blast {e(s['level'])}'><h3>Blast radius</h3>"
        f"<p class='verdict'>{e(s['verdict'])}</p><ul>{''.join(items)}</ul></div>"
    )
