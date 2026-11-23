# About PAAT

**PAAT** stands for **Policy Automation and Analysis Tool**. It is a web
application (with a matching command line) for **Palo Alto Networks PAN-OS
firewalls and Panorama**. It helps a team turn firewall change requests into
safe, reviewed, audited rule changes.

> PAAT is an independent tool. It is not made, endorsed or supported by Palo
> Alto Networks. "Palo Alto Networks", "PAN-OS" and "Panorama" are trademarks
> of Palo Alto Networks, Inc., used here only to say what PAAT works with.

## What it does, in one minute

| You want to… | PAAT does this for you |
|---|---|
| Ask for a firewall rule | Takes the filled-in request form (FCR spreadsheet) and checks every row. |
| Know where the rule must go | Traces the flow hop by hop through every firewall and virtual system on the path, and tells you each place a rule is needed, including when the same flow passes the same firewall twice. |
| Get a change plan for the CR | Writes the plan: objects, rules, rule position, CLI, rollback steps and how to verify. |
| Get it approved | Records the approval and the CR number. The person who approves cannot be the person who pushes (when two-person approval is on). |
| Make the change | Pushes through Panorama (or straight to a firewall) from a separate, red Push area, then asks the firewall which rule it now picks in every place. |
| Undo it | One-click rollback from the snapshot PAAT took before the push. |
| Keep firewalls current | Plans and runs PAN-OS upgrades step by step, never past the managing Panorama's version. |

Everything else (URL filtering requests, App-ID advice, decommissioning old
hosts, backup copies) follows the same pattern: **plan first, approve, then
push, with an audit record at every step.**

## Who it is for

- **Requesters and service-desk staff**: upload a request and see, in plain
  words, whether it is already allowed or what will change.
- **Network and security engineers**: review the trace, the plan and the
  risks before anything touches a firewall.
- **Approvers and change managers**: see exactly what will change and approve
  it against a CR.
- **Operators**: run approved pushes and upgrades with checks built in.
- **Platform admins**: manage users, permissions, customers and backup
  destinations.

Each person sees only the pages and customers their role allows. See
[Users and permissions](users-and-permissions.md).

## Safe by design

- **Read-only until you say otherwise.** Tracing, planning and previews never
  change a device. Live reads use a read-only API account.
- **Push is separate and audited.** Changes reach a device only from the red
  Push area, only after approval, and every step is logged.
- **Checks after every push.** PAAT asks the firewall which rule it now uses
  for the flow in every place, and shows **verify failed** if any place misses.
- **Rollback is always ready.** A snapshot is taken before each push.
- **Your data stays on your server.** Configs, backups and users live on the
  PAAT server only; nothing is sent to a cloud service.

## PAAT and FlowMapper

**FlowMapper** is PAAT's offline companion: a single web page you open on your
own computer to trace flows through firewall backups, with no server and no
network access. **PAAT and FlowMapper share the same path-tracing engine**
(PAAT keeps a hash-checked copy of FlowMapper's engine), so a trace gives the
same answer in both.

| | FlowMapper | PAAT |
|---|---|---|
| Runs | In your browser, offline | On a Linux server (or container) for the team |
| Data | Backups you load on your own PC | Backups **or** a live read-only pull of Panorama and firewalls |
| Trace a flow, diagrams, "rule needed in more than one place" | Yes | Yes (same engine) |
| Users, roles, approvals, audit | No | Yes |
| Push, verify, rollback, OS upgrades | No | Yes |

Use FlowMapper when you need a quick answer from backups on your own machine.
Use PAAT when the change has to be planned, approved and made. The FlowMapper folder in this repository documents its features.

## Names you may still see

PAAT used to be called **panlab**. The old name is kept where changing it
could break a running server or an existing script:

- the `panlab` command still works (`paat` is the same command);
- settings may start with `PAAT_` or `PANLAB_` (for example `PAAT_DATA_DIR`); the `PAAT_` form is preferred;
- rule tags and commit comments written to firewalls still say `panlab`, so
  older changes stay easy to find.

## Get help

- In the app: **Help** in the top bar (this manual), and the
  **How this page works** box on every page.
- Install: see `INSTALL.md` in the PAAT folder.
