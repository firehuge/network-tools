# Port to App-ID advisor

Many rulebases still have rules like "allow **any application** on tcp/8080,
8443" or "allow any on 2222, 2525, 3389, 23, 3306". Any program can use those
ports. The advisor reads what the firewall actually saw on those rules, then
suggests App-ID rules that allow only those applications. It writes a
CR-ready change plan. **It is read-only: it never changes or pushes anything.**

## Who can use it

- **Run** an analysis: the *FCRs* permission (`fcr`).
- **Read** saved analyses and download the plan: *View* or *FCRs*.
- Only customers in your scope. Logs are read only from firewalls in your
  device scope. If none is in scope, the run is refused.
- Every run is written to the customer's audit log (`app_advisor`).

## Run it (GUI)

1. Click **App-ID advisor** in the left sidebar (Operations) and pick the customer.
2. **Rule name(s)**: one or more rules, comma separated, e.g.
   `RULE-ONE, RULE-TWO`. Leave it blank to check every
   *port-based* rule: allow, enabled, application `any`, and explicit service
   ports (not `any`, not `application-default`).
3. **Read logs from**: one firewall, or all firewalls in your scope.
4. **Log window**: 1 to 90 days. Use 30 days or more before you remove a port:
   a monthly job will not show up in a 7-day window.
5. **Max log entries per rule** (100 to 5000). If a rule hits the cap, the
   page says **capped**. Shorten the window or run it again later.
6. Click **Analyze (read-only)**. The result page opens.

CLI equivalent (on the server, as the service user):

```
paat appadvisor --customer example --rule RULE-TWO --days 30
```

## What it does

1. Reads the rule and its service objects and groups from the policy owner's
   running config. That is the Panorama device group, including its parent
   groups and shared, or the firewall's vsys for a standalone firewall.
2. Pulls the rule's traffic logs over the XML API, using the filter
   `(rule eq '<name>') and (receive_time geq '<window start>')`.
3. For each port, counts each application's sessions and bytes, and records
   when it was first and last seen.
4. Asks the firewall for each app's default ports (`show predefined`). If the
   firewall cannot answer (for example a custom app), it falls back to a
   built-in table.

## How to read the result

The result page header shows the log window, the firewall the logs came from
(hostname · serial), and the policy owner.

Each port gets one status:

| Status | Meaning | Suggestion |
|---|---|---|
| **migrate** | Every session was a known application. | One rule with those apps and `application-default` if the port is the app's default port. If not (ssh on 2222), a rule for that app plus that explicit port. Existing service objects are reused; a new one follows the customer's naming pattern. |
| **mixed** | Known apps plus unidentified traffic. | New App-ID rule for the known apps. The port stays on the original rule until someone reviews it. |
| **review** | Only `insufficient-data`, `incomplete`, `unknown-*`, or a building-block app such as `cotp` (RDP's transport). | **Needs review / more data.** The port stays on the original rule. For a building-block app, the note names the real app to allow (`ms-rdp`), never the building block on its own. |
| **unused** | No sessions in the window. | Remove the port. Confidence is low under 30 days and medium at 30 days or more. |

What happens to the original rule:

- If some ports still need review, it is **narrowed** to only those ports.
  The plan sets the rule's service to individual objects; it never edits a
  shared service group that other rules may use.
- If nothing is left on it, it is **disabled**. Delete it after a quiet
  period.

Each suggestion has a confidence:

- **high**: at least 20 sessions and a window of at least 7 days.
- **medium**: at least 3 sessions.
- **low**: fewer.

A rule's overall confidence is the lowest of its suggestions.

## The change plan

**Download CR change plan** gives markdown in the usual CR template:

- summary per rule, with a port table;
- Implementation Plan (GUI steps);
- Implementation (CLI): `set ... security rules`, `move ... before <old rule>`,
  narrowing or disabling the old rule, then `commit` and `commit-all
  shared-policy device-group ...`;
- Impact Analysis;
- Backout Plan: restore the old service or re-enable the rule, delete the new
  rules and objects;
- Validation Plan;
- Communications Plan.

The new rules copy the old rule's zones, addresses, log forwarding, profile
group, and tags. They go directly above the old rule.

Nothing is pushed. Treat the plan like any CR: review it, get it approved,
apply it in a window, then watch the deny log. Run the advisor again a few
days later.

