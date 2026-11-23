"""Named job layers (presets) on top of permission checkboxes.

Checkboxes stay the source of truth. A layer is an exact match to a known
set, used in the header, Home, and the Users page. Existing viewer / prep /
engineer / admin accounts keep their current access.
"""

from __future__ import annotations

from panlab.web import auth

# Display name, job sentence, and exact permission set for "Apply preset".
LAYERS: list[dict] = [
    {
        "id": "viewer",
        "name": "Viewer",
        "job": "Review plans and reports in your scope. You can copy and download them. You cannot submit, approve, or push.",
        "perms": frozenset({"view"}),
    },
    {
        "id": "requester",
        "name": "Requester",
        "job": "Start a request and follow the plan it produces. You cannot approve or push.",
        "perms": frozenset({"view", "request", "urlfilter_request"}),
    },
    {
        "id": "engineer",
        "name": "Engineer",
        "job": "Build and validate change sets, traces, and upgrade plans. You do not push, and you do not approve your own change when the two-person rule is on.",
        "perms": frozenset({"view", "fcr", "upgrade_plan"}),
    },
    {
        "id": "approver",
        "name": "Approver",
        "job": "Review the plan, the blast-radius, and the diff. Approve or reject with a CR. You do not have to be the person who pushes.",
        "perms": frozenset({"view", "urlfilter_approve", "approve"}),
    },
    {
        "id": "operator",
        "name": "Admin / operator",
        "job": "Push approved changes and run armed upgrade steps in a change window. The push bar is red for a reason.",
        "perms": frozenset({"view", "fcr", "upgrade_plan", "push", "upgrade_exec"}),
    },
    {
        "id": "edl_customer",
        "name": "EDL editor (customer)",
        "job": "Add and remove entries in your own organization's external dynamic lists. Firewalls pick the list up on their own; you never touch a firewall.",
        "perms": frozenset({"edl_view", "edl_edit"}),
    },
    {
        "id": "soc",
        "name": "SOC analyst",
        "job": "Block and unblock IPs, domains and URLs in the EDLs for the customers you cover, and read plans and reports. Risky entries wait for an ISSO.",
        "perms": frozenset({"view", "edl_view", "edl_edit"}),
    },
    {
        "id": "isso",
        "name": "ISSO (security approver)",
        "job": "Review and approve or reject EDL changes and EDL firewall objects that need a second person. You cannot approve your own.",
        "perms": frozenset({"view", "edl_view", "edl_approve"}),
    },
    {
        "id": "edl_admin",
        "name": "EDL admin",
        "job": "Create lists, choose where they publish (PAAT-hosted or S3), set the safety rules, and request the firewall objects that point at them.",
        "perms": frozenset({"view", "edl_view", "edl_edit", "edl_approve", "edl_admin"}),
    },
    {
        "id": "platform_admin",
        "name": "Platform admin",
        "job": "Manage users, scope, and backup destinations, and use every tool you are allowed to grant.",
        "perms": frozenset(auth.PERMS),
    },
]

# Home leads with these tasks; tiles still follow checkboxes.
HOME_LEAD: dict[str, tuple[str, str]] = {
    "viewer": ("Plans and reports in your scope", "Open a recent change set, read the plan, and note red flags. Nothing you do here changes a device."),
    "requester": ("Start a request", "Download the FCR form, upload a filled spreadsheet, or open URL filter self-service. Then watch the plan."),
    "engineer": ("Build or review a plan", "Upload an FCR, trace a flow, or open a draft that still needs a human. Push stays in the red area after approval."),
    "approver": ("Waiting for you", "Open a plan, read the blast-radius and the verdict, then approve or send it back. Approval is not a push."),
    "operator": ("Approved, ready to push", "Open an approved change set or an armed upgrade. Prepare still does a dry-run before anything is written."),
    "edl_customer": ("Your block lists", "Open External dynamic lists, pick your list, and add or remove an entry with a reason. Firewalls fetch the new list within minutes."),
    "soc": ("Block or unblock fast", "Open External dynamic lists to add an indicator (with a ticket and an optional expiry) or remove one. Risky entries wait for an ISSO."),
    "isso": ("Waiting for your review", "Open External dynamic lists and review the staged changes. Approve or reject with a comment; you cannot approve your own."),
    "edl_admin": ("Lists and where they publish", "Create lists, set PAAT-hosted or S3 publishing, safety rules, and request the firewall objects that point at the lists."),
    "platform_admin": ("The tool itself", "Add users, set layer presets and scope, and check backup destinations. The quick actions below are the same tools as the sidebar."),
    "prep": ("Build or review a plan", "This account still matches the older prep role. Use the quick actions below. A user admin can apply a named layer preset without changing your access until they save."),
    "engineer-legacy": ("Build, and push when a CR is approved", "This account still matches the older engineer role, including Panorama upgrades. A user admin can apply a named layer preset if you want a tighter set."),
    "admin": ("The tool itself", "This account still matches the older admin role. The quick actions below cover every area you can use."),
    "custom": ("Your tools", "This account uses a custom permission set. The quick actions below are what you can do."),
}


def perms_of(user) -> frozenset[str]:
    p = getattr(user, "perms", None)
    if p is not None:
        return frozenset(p)
    rec = user if isinstance(user, dict) else {}
    return auth.effective_perms(rec) if rec else frozenset()


def match_layer(perms: frozenset[str]) -> dict | None:
    """Exact match to a named layer, or None."""
    for layer in LAYERS:
        if perms == layer["perms"]:
            return layer
    # Accounts saved before later permissions (request, approve, EDL) existed still read as Platform admin.
    if auth.is_legacy_platform_admin(perms):
        return LAYERS[-1]
    if perms == frozenset({"view", "urlfilter_request"}):  # requester saved before "request" existed
        return next(layer for layer in LAYERS if layer["id"] == "requester")
    return None


def match_legacy(perms: frozenset[str]) -> str | None:
    for role in reversed(auth.ROLES):
        if auth.ROLE_PERMS[role] == perms:
            return role
    return None


def layer_id(user) -> str:
    perms = perms_of(user)
    layer = match_layer(perms)
    if layer:
        return layer["id"]
    legacy = match_legacy(perms)
    if legacy == "engineer":
        return "engineer-legacy"
    return legacy or "custom"


def layer_label(user) -> str:
    """Badge text for the header and the Users page."""
    perms = perms_of(user)
    layer = match_layer(perms)
    if layer:
        return layer["name"]
    legacy = match_legacy(perms)
    return legacy or "custom"


def home_intro(user) -> str:
    lid = layer_id(user)
    title, body = HOME_LEAD.get(lid, HOME_LEAD["custom"])
    return (f"<div class='job'><h3>{_e(title)}</h3><p>{_e(body)}</p></div>")


def _e(text: str) -> str:
    import html
    return html.escape(text)


def preset_options_html(selected: str = "") -> str:
    import html
    e = html.escape
    opts = ["<option value=''>Choose a preset (does not save until you click Save)</option>"]
    for layer in LAYERS:
        sel = " selected" if layer["id"] == selected else ""
        opts.append(f"<option value='{e(layer['id'])}'{sel}>{e(layer['name'])}</option>")
    return "".join(opts)


def preset_script() -> str:
    """Tick permission checkboxes from a layer id. Save still posts the boxes."""
    mapping = {layer["id"]: sorted(layer["perms"]) for layer in LAYERS}
    import json
    js = (
        "(function(){var m=" + json.dumps(mapping) + ";"
        "var s=document.getElementById('layer-preset');if(!s)return;"
        "s.addEventListener('change',function(){var p=m[s.value];if(!p)return;"
        "document.querySelectorAll('input[name=perm]').forEach(function(c){"
        "if(!c.disabled)c.checked=p.indexOf(c.value)>=0;});});})();"
    )
    return "<script>" + js + "</script>"
