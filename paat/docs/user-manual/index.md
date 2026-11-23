# PAAT user manual

This manual is for engineers and prep staff who use **PAAT** (Policy Automation and Analysis Tool): the web GUI
and the `paat` command line. It is a running document: add a page when a feature is tested and
ready to use. 
How to install PAAT is in INSTALL.md at the top of the PAAT folder.

## How to use this manual

Each page is a junior-friendly walkthrough: what to click, what you should
see, the safety checks the tool already enforces, and what to do when
something looks wrong. Prefer the GUI unless you already use the CLI.

The GUI listens on the PAAT server (see INSTALL.md). Put HTTPS in front of it for anything beyond a test. Log in with your own GUI account. What you can
do, and for which customers and devices, is set per user with checkboxes;
see [Users and permissions](users-and-permissions.md).

## Start here

- **[About PAAT](about.md)**: what it is, who it is for, and how it relates to FlowMapper (the offline companion that shares its engine).


## Install and run

- See `INSTALL.md` in the PAAT folder for server and container installs.

## Features

- [Layers, Home, and the change workflow](layers-and-home.md) — named job layers, task-based Home, search, blast radius, and optional two-person approval.
- [The PAAT API](api.md) — read-only `/api/v1`, session or Bearer token, OpenAPI.
- [Finding your way around](navigation.md) — the sidebar, the top bar, the Home dashboard, change-set status colours and breadcrumbs.
- [FCR upload and change plans](fcr-upload-and-change-plans.md) — turn a firewall change request spreadsheet into a CR-ready plan.
- [Trace a flow](trace-a-flow.md) — path-trace an FCR against a live read-only pull of Panorama and the firewalls (or against backups), see every vsys hop and the full change plan, flow and environment diagrams (SVG, PNG, draw.io), the *rule needed in more than one place* box and rule-order advice; viewers can review and export, only push-permission users can execute.
- [The FCR request form](fcr-request-form.md) — the Excel template requesters fill in: format checks on every column, an Instructions tab, a Row check column, and where to download it.
- [Backup-file plans](backup-file-plans.md) — plan against an uploaded XML snapshot, without talking to a live device.
- [Combine rules](combine-rules.md) — how similar requests are merged, when to turn that off, and how existing-rule reuse works.
- [Decommission](decommission.md) — exact, graded removals of addresses, groups and rules, and stop-traffic denies.
- [Plan-only vs live push](plan-only-and-live-push.md) — dry-run, applying a plan by hand, and the opt-in tool path from PAAT to Panorama to the firewall.
- [OS upgrades](os-upgrades.md) — upgrade PAN-OS on standalone firewalls, or on a Panorama and the firewalls behind it, one checked step at a time.
- [Backup destinations](backup-destinations.md) — admin-configured off-box copies of upgrade and pre-push backups (git, SFTP, FTPS, S3), verified and audited; the local copy is always kept.
- [Users and permissions](users-and-permissions.md): per-user checkboxes (FCRs, push, OS upgrade plan/run, Panorama, backup destinations, user admin) and customer/device scope for an MSP/NOC model, with the admin Users page.
- [Port to App-ID advisor](app-id-advisor.md): read a port-based rule's traffic logs and get a CR plan that moves it to App-ID rules (read-only).
- [External dynamic lists (EDLs)](edl.md): customers, SOC and ISSOs add or remove IPs, domains and URLs on block lists that firewalls fetch every few minutes, with safety checks, two-person approval, history and revert; published by PAAT and/or to S3, with the Panorama EDL object generated and pushed through approval.
- [URL filter self-service](url-filtering.md): requesters pick URL category actions and allow/block sites for one customer's URL Filtering profile; approvers review the diff against live and the Palo Alto recommendation, approve with a CR and push.

## If you are lost

1. Ask a PAAT admin for an account if you cannot log in.
2. Use **Upload FCRs** or **Decommission** first; do not start in the push area.
3. If a page talks about a live device and you only have a file, use a [backup-file plan](backup-file-plans.md).
4. On any customer except one explicitly opted-in customer, a Panorama push stays dry-run only.
