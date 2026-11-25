# FCR upload and change plans

Use this to turn one or more firewall change request (FCR) files into a
change set and a CR-ready change plan. Nothing is written to a firewall
or to Panorama until someone uses the push area (or applies the plan's
CLI by hand). This page is plan generation only.

What the finished change set looks like: the stepper (Request, Plan, Approval, Push), the blast-radius box and the files that were read.


## What you need

- A GUI account with the **fcr** permission (see [Users and permissions](users-and-permissions.md)).
- The FCR file (`.xlsx` or `.xlsm` in the standard template, or a
  `.csv` / close-equivalent spreadsheet). The standard template is
  `templates/customer-rule-request-form.xlsx`. You can download the blank form from
  the **Upload FCRs** page; see [The FCR request form](fcr-request-form.md).
- Ticket numbers if you have them (RITM, SCTask, CR/CHG).
- A customer to plan against (for example `example`).

## Step by step (GUI)

1. Open the GUI and go to **Upload FCRs**.
2. Choose the **Customer**.
3. Choose the **Config source**:
   - A cached or live export of the running config (live is a
     *read-only* export).
   - An uploaded [backup file](backup-file-plans.md) if you must not
     talk to the device.
4. Leave **Combine rules where possible** checked unless you have a
   reason to keep one rule per request (see [Combine rules](combine-rules.md)).
5. Attach one or more FCR files. Optional: RITM, SCTask, CR, requester.
6. If the source and destination networks are not on any firewall yet,
   you can pick a **Target firewall** so the tool still builds a
   fallback plan instead of leaving the rows unplaced.
7. Submit. You land on the change-set page.

## What you should see

- A **Files** table: sheet name, header row, and which file headers
  mapped to source, destination, ports, and protocol.
- A yellow **non-standard format, check the mapping** note if the file
  was not the standard template. Read that mapping before you trust the
  plan.
- New address objects, address groups, services, and tags when the
  values are not already in the config.
- Proposed security rules, or an **Already allowed** / **Edit Policy**
  note when an existing allow rule already covers the request (or can
  with a small edit).
- The device group or firewall/vsys and the **from** / **to** zones the
  tool chose.
- Red flags and "needs a human" counts, if any.
- A **Change plan** link. That page is a Panorama or Firewall Change
  Request with implementation, commit, impact, backout, validation,
  communications, then **CLI**, **Verification**, and **Rollback**.
  Each section has Copy and Download buttons.

## Already permitted (green) and partly permitted (yellow)

Before proposing a rule, the planner checks each FCR row against the policy
that is already on the device. It walks the rules in the order the firewall
uses them:

- **Panorama:** shared pre-rules, then each device group's pre-rules from the
  top parent down to the device's group, then post-rules from the device's
  group back up, then shared post-rules.
- **Standalone firewall:** the vsys rulebase.

The first rule that decides the traffic counts. A rule decides it when it
matches all of the following:

- **Zones:** the row's from and to zones, or `any`.
- **Source and destination:** objects, nested address groups, ranges,
  subnets, `any`, and *negate*.
- **Application:** the app, an application group, or `any`.
- **Service:** `application-default` (the app's normal ports), service objects
  and groups, port ranges, or `any`.

Rules the check skips or treats as blocking:

- Disabled rules are skipped.
- Rules whose Target leaves out this firewall or vsys are skipped.
- A deny, drop or reset rule **above** the allow rule that matches any of the
  traffic means *not permitted*.

| Result | What you see | What the plan does |
|---|---|---|
| **Already permitted** | Green row: "Already permitted by `<rule>` (`<device group>`)" | No new rule, no new objects. The plan lists it under *Already allowed*, with the flow and the rule. |
| **Partly permitted** | Yellow flag: "partly permitted already: tcp/443 by `<rule>` …; this rule only adds tcp/8443" | Only the missing ports go into the new rule. |
| **Allowed for other apps only** | Info note on the new rule | Example: the row has no application but the existing rule allows only `ssl` with application-default. The tool cannot prove the row is covered, so it proposes a rule. If the traffic really is that app, you can drop the rule. |
| **Denied above** | Yellow flag "… denies part of this traffic above where this rule goes" | The new rule is still proposed. Place it above the deny, or confirm the deny is intended. A deny in the post-rules (such as a catch-all deny-log rule) is expected and is not flagged. |

The check is conservative. The tool will **not** call a row permitted when it
depends on something it cannot prove:

- FQDN objects matched against IPs;
- dynamic address groups;
- application filters;
- source users;
- `application-default` for an app whose ports it does not know.

In those cases you get a normal (or yellow) rule plus a note. The check runs
the same way on a live config read and on an uploaded backup file
([backup-file plans](backup-file-plans.md)).

## Safety checks already in the tool

- Import is read-only against the device. `--live` only exports
  running config.
- Existing objects are reused by value; the plan does not create a
  second object for the same IP.
- Suggested static routes are for the engineer to confirm. They are
  never pushed automatically, and the next hop is `REQUIRED-CONFIRM`.
- A backup-file change set cannot be pushed (the push area refuses it).

## CLI equivalent

```text
paat import --customer example FCR.xlsx --live \
    --ritm RITM... --sctask SCTASK... --cr CHG... --requester NAME
paat plan --customer example --changeset <file.json>
paat changeplan --customer example --changeset <file.json>
```

`paat import` also accepts `.csv`. Use `--no-combine` to disable rule
combining. Use `--backup cfg-...` instead of `--live` to plan against a
stored snapshot.

## Troubleshooting

| What you see | What to try |
| --- | --- |
| Per-file error listing **Headers seen** and **Looking for** | The file has no source / destination / port columns the importer recognizes. Rename headers, or save the standard template as `.xlsx`. |
| Rows look empty or the mapped columns are on the wrong sheet | Workbooks that carry an **Instructions** sheet repeating the form headers are fine: a sheet named like the rule list (for example `Firewall Rules`) is read first and instruction-style sheets are skipped. Headers written with underscores (`Destination_IP`) work like spaced ones. A column that only names a VLAN or network (`Source_VLAN_VNET_Name`) is used as an address column only when no IP/address column exists. |
| Source or ports blank on the second and later destination rows | Cells merged down over several rows (source, ports, and so on) are repeated on every row they span, so each destination row is a full request. |
| Yellow flag **app-not-appid** | The App column held a name that is not a PAN-OS App-ID (a system, project or team name). The rule uses application `any` on the listed ports and the name is kept in the rule description as `FCR app: ...`. Tighten it with the App-ID advisor. If it is a real App-ID PAAT does not know, add it to `known_apps:` in the customer profile. |
| Rows say **no-ticket** | PRJ-style numbers (`PRJ0012345`, `PROJ-123456`) in the file name, the Project cell or the notes count as the ticket. Change the pattern with `tickets: {project: '...'}` in the customer profile. They are labels only: a push still needs a real `--cr`. |
| Rule names are not what you asked for | A `Rule Name` (or `Policy Name`) column is used as the proposed rule name after cleanup to PAN-OS limits (letters, digits, space, `-`, `_`, `.`; 63 characters). Two rows with the same name and the same source/ports combine into one rule; rows with different names are never combined. Usage and VLAN/network-name columns go into the rule description. |
| `.xls` rejected | Save as `.xlsx` or `.csv`. Old `.xls` is not supported. |
| Yellow mapping note | Confirm the mapped columns. "Source port" is not treated as a source address. If only a source port column exists, you may see a yellow note about non-ephemeral values. |
| Requests **unplaced** | Networks are not in the routing table. Pick a target firewall for a fallback plan, or add the missing routes (by hand, not from a push). |
| Zones say `NEEDS-HUMAN` | The tool could not pick a from/to zone (for example an FQDN with no IP, or an interface with no zone). Fill the zone in before anyone applies the plan. |
| "Already allowed" but you expected a new rule | Check the existing rule and the combine / reuse decision. Use `--no-combine` only if you truly need a separate rule. |

When the plan looks right, see [Plan-only vs live push](plan-only-and-live-push.md).
