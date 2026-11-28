# Change plans

Each change set can be turned into a Markdown change plan (`PAAT
changeplan`, or the **Change plan** link in the GUI) to paste into a
change request or attach as a file.

The plan uses a fixed structure:

1. A **Panorama Change Request** or **Firewall Change Request** heading,
   with RITM and SCTask.
2. An **Implementation Plan** with one **Add Address Object**, **Add
   Address Group**, or Add Service / Add Tag block per new object, then one **Add Static Route**
   block per suggested VR route (Network > Virtual Routers > &lt;VR&gt; >
   Static Routes, with next hop `REQUIRED-CONFIRM`), then one **Add
   Policy**, **Edit Policy**, or **Already allowed** block per rule, then **Add NAT Policy**.
   Address objects are listed first because they must exist before the
   policy. Suggested routes are for the engineer to confirm and add;
   they are never pushed automatically.
   Each Add Policy block has the General / Source / Destination /
   Application / Service-URL Category / Actions / Target fields,
   including Log at Session Start/End, Log Forwarding, Profile Type
   Group, and Group Profile.
3. A **Commit** section (description is the CHG number, then Commit
   Summary / Validate / Commit). Panorama also gets the commit-and-push
   plan. Standalone firewalls use **Policies > Security** and, for
   backout, **Device > Setup > Operations > Load configuration version**.
4. **Impact Analysis Statement**, **Backout Plan**, **Validation Plan**,
   and **Communications Plan**.
5. After that, the PAN-OS **CLI** (`set` commands), **Verification**,
   and **Rollback** sections, so nothing from the earlier plan is lost.

The GUI change-plan page shows those last four areas as separate
sections. Each section (and the full plan) has a Copy button and
Download (.md / .txt) buttons.

## Customer profile settings

Customer-specific names (log forwarding profile, security profile group,
the team named in the communications plan, and the four statement
boilerplates) come from a `change_plan:` block in
`customers/<name>/profile.yaml`. Committed profiles use only generic
placeholders:

```yaml
change_plan:
  log_forwarding: LOG-FWD-DEFAULT
  profile_group: PROFILE-GROUP-DEFAULT   # label printed in the CR text only
  rule_profile_group: ""                 # optional: a profile group that already exists; written into every NEW allow rule
  profile_type: Group
  log_at_session_start: "No"
  log_at_session_end: "Yes"
  url_category: any
  team_name: the network team
  # optional overrides; omit to keep the built-in wording
  # impact_analysis: ...
  # backout_plan: ...
  # validation_plan: ...
  # communications_plan: "{team_name} will notify stakeholders..."
```

**Safe defaults on new rules.** Every allow rule PAAT generates (change plan, push, flow trace) is written with
`log-end yes`. If `rule_profile_group` is set, the same rule also gets `profile-setting group <name>`; blank (the default)
adds nothing. The group must already exist on the firewall or in the Panorama device group (or shared), otherwise the
commit fails. The CR text then shows that group under *Group Profile*.

To use real values on the PAAT server, do **not** edit the committed
profile. Put them in a gitignored local file, either:

- `customers/<name>/profile.local.yaml` in the checkout, or
- `/etc/paat/customers/<name>.yaml`

Both use the same `change_plan:` shape. `/etc/paat/customers/<name>.yaml`
wins if both set the same key. Restart `paat` after changing them
so the GUI picks up the new text.

`communications_plan` may include `{team_name}`; it is replaced with the
resolved team name.

## Suggested routes

When a requested RFC1918 network is not on a connected subnet or a
specific route, the plan still proposes the address objects and the
security rule, and adds an **Add Static Route** block plus CLI:

```
set network virtual-router <VR> routing-table ip static-route <name> destination <prefix> interface <egress-interface> nexthop ip-address REQUIRED-CONFIRM
```

Rollback is the matching `delete`. The next hop and interface are
placeholders the engineer must confirm. Open items lists each
unconfirmed route. A request that overlaps an existing 192.x route is
called out and no overlapping route is suggested.

If the customer has more than one firewall and none of them already
owns the networks, pick a target on the upload form or on the change
set page ("Target firewall (if networks aren't on any firewall yet)")
so the plan can be built.

## Combining rules and reusing existing ones

By default, after placement, similar requests are merged into one rule
when they land on the same target (firewall + vsys, or the same Panorama
device group and the same target devices), have the same source and
destination zones, the same action, and the same service/application
set. Requests that already share the same addresses but use different
ports are also merged (the rule gets the union of services). The merged
rule description lists every RITM and row, and the rule keeps a tag for
each ticket.

When five or more hosts share one side of a rule (configurable as
`address_group_threshold` in the profile, default 5), they are placed in
a new static address group named from the customer's template
(`{project}-{dst}-SRV-GRP`, or a prefix of your choice). If a static group
with exactly that membership already exists, it is reused. The plan may
note `N of M hosts in 10.x.x.0/24; consider using the subnet object` as
info only — it never auto-summarizes to a subnet.

If an existing enabled allow rule already has the same zones and the
same or a broader service/app, and adding the new address(es) would
cover the request, the plan proposes **Edit Policy** (add source or
destination address) instead of a new rule, with an alternative to
create a new rule. On the Change plan page you can pick per rule with a
radio. The plan will not suggest adding to a deny rule, or to a rule
whose `any` is on the side being extended. A yellow flag is raised if
the existing rule is broad, may be shadowed, or uses a different
security profile. When the traffic is already fully allowed, the plan
says so and does not add or edit a rule.

The CLI uses one `set rulebase security rules <existing> source OBJ`
(and the matching `delete` on rollback) per added member, so rollback of
an edit only removes what this change added. Address-group `set` /
`delete` commands are included when a group is created. These shapes are
also used by the standalone push path (Panorama stays a dry run).

Turn combining off with `--no-combine` or by unchecking **Combine rules
where possible** on the upload form. To keep separate rules for
separate tickets, set `combine_across_tickets: false` in the customer
profile (default is true). Combining itself defaults to on
(`combine_rules: true`).

## Backup files (plan only)

An uploaded firewall or Panorama snapshot can be the config source for
an add or a decommission plan. The change plan still uses this CR
template. Those change sets cannot be pushed. See
[backup-files.md](backup-files.md).

## Decommission

A decommission change set (`paat decom`, or the **Decommission** page)
uses the same CR template, with a "(Decommission)" heading.

The implementation plan is in this order:

1. **Edit Policy** — "Remove source address" / "Remove destination address" as a bulleted list (same style as Add).
2. **Delete Policy** (or Disable) — used when removing the last address would leave a field empty. PAN-OS treats an empty field as 'any', which would broaden the rule; the plan never leaves a rule with an empty address field. These steps are flagged red. The engineer can disable the rule instead of deleting it.
3. **Edit Address Group** / **Delete Address Group** — same empty-member rule.
4. **Delete Address Object** — only after references are removed, and only if nothing else still uses the object.
5. **Commit**, then the four statements, CLI (`delete` in the same order), rollback (`set` that re-creates exactly what was removed, from the cached config, objects first), and verification.

Shared or parent device-group objects used by other device groups, dynamic (tag-based) groups, other unclassified references, and anything ambiguous are flagged red and are not pushed until those flags are cleared (you can still copy the plan into ServiceNow). Containing and contained address objects (for example a /24 that contains a host you named) are called out and are not selected for removal unless you name them.

Profile overrides may include `decom_impact_analysis`, `decom_validation_plan`, and `decom_backout_plan`. If they are omitted, the plan uses a decommission-specific impact sentence (traffic that depended on the removed rules may be denied) and keeps the add-path communications plan.
