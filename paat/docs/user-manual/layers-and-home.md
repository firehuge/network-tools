# Layers, Home, and the change workflow

The GUI still enforces access with permission checkboxes and customer
scope. A **layer** is a named preset of those checkboxes, and the words
the account menu (top right) and Home use for your job.

See the product plan for the full direction.

## The layers

| Layer | Default checkboxes | Your job |
|---|---|---|
| Viewer | `view` | Read plans and reports in your scope |
| Requester | `view`, `request`, `urlfilter_request` | Submit FCRs (upload builds a change set) and URL filter requests, then follow the plan |
| Engineer | `view`, `fcr`, `upgrade_plan` | Build and validate change sets |
| Approver | `view`, `urlfilter_approve`, `approve` | Approve or reject with a CR |
| Admin / operator | Engineer plus `push`, `upgrade_exec` | Push approved changes and run upgrades |
| Platform admin | Every checkbox, including `user_admin`, `backup_admin`, and `approve` | Run the tool itself |

Older accounts that still match viewer, prep, engineer, or admin keep
that access. The header shows the older name until a user admin applies
a preset and saves. Nobody gains `push` or `upgrade_panorama` from a
rename. The new `approve` checkbox is on Platform admin (and any admin
role-only account, because that role includes every checkbox). It is
not added to engineer or prep.

## Home

After you log in you land on Home. The first block is the work for your
layer. Under it are live counts for your scope (saved change sets,
awaiting approval, approved but not pushed, pushed; plus upgrade plans
and open URL filter requests when you have those tools). An Approver's
dashboard leads with *Awaiting approval*, an Operator's with *Approved,
not pushed*. The **Quick actions** cards are the same permission-filtered
list as the sidebar. Open **How this page works** for a short reminder
and the name of the user-manual page. See
[Finding your way around](navigation.md) for the status colours.

## Search

If you have `view`, a search box is in the top bar (right side). It looks at saved
change-set ids, RITM, SCTASK, CR, and rule names, only for customers in
your scope. It does not search inside a live device config.

## The stepper, blast radius, and approval

On a change set, the change plan, and the push page you will see a
four-step trail: Request, Plan, Approval, Push. Push stays locked if
you do not have the `push` permission.

**Blast radius** is a short block computed from the saved change set:
targets, device groups, size, red flags, and a one-line verdict. It
does not talk to a device.

**Approval** is recorded on the change plan page by someone with
`approve`. For most customers this is optional. If the customer profile
sets `two_person_approval: true` (or a server override file does),
prepare and apply refuse until a second person has approved. The person
who built the change cannot be that approver.

Live Panorama push, dry-run by default, and "backup-file plans cannot
be pushed" are unchanged. See [Plan-only vs live push](plan-only-and-live-push.md).

## API

A read-only API lives at `/api/v1`. Sign in with your GUI session
cookie, or pass a Bearer token. The document is `/api/v1/openapi.json`.
See [The PAAT API](api.md).
