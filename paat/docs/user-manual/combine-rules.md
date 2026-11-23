# Combine rules

By default, PAAT **combines** similar FCR rows into fewer proposed
security rules, and it will **reuse** an existing allow rule when
adding an object is enough. This page explains what that looks like and
when to turn it off.

## What "combine" does

When **Combine rules where possible** is checked (the default):

- Rows that share the same placement (same device group or vsys, same
  zones, same action) and that can honestly share a service or
  application are merged into one proposed rule instead of one rule
  per row.
- Several hosts in the same role are placed in a new address group
  rather than a long list of objects in the rule.
- If an existing allow rule already matches the flow, the plan says
  **Already allowed** and proposes no change.
- If adding a source, destination, or service to an existing allow
  rule is enough, the plan proposes an **Edit Policy** instead of a
  new rule.

Ticket tags (RITM / CR) still go on the new or edited rule name and
tags so the change can be traced.

## When to turn it off

Uncheck the box (or pass `--no-combine` on the CLI) when:

- The change request must have **one rule per application or per row**,
  as written in the FCR.
- You are troubleshooting a bad merge and want to see the uncombined
  plan.
- An auditor or the CR language forbids combining.

Turning combine off does not disable object reuse (the same IP still
reuses the existing address object).

## What you should see

- Fewer proposed rules than FCR rows, with a source or destination
  group when many hosts were requested together.
- An **Already allowed by `RULENAME` (no change)** line when a current
  rule already covers the request.
- An edit of an existing rule, with the added object listed, when reuse
  is enough.
- The change plan CLI has one `set` block per new object, then one
  **Add Policy** or **Edit Policy** block per resulting rule.

## Safety checks already in the tool

- Combine will not invent a path the rows did not ask for (different
  zones or a deny mixed with an allow stay separate).
- Broad or dangerous reuse (for example tightening a rule the wrong
  way) is called out; anything ambiguous is marked **needs a human**.
- You can still discard the change set and re-import with combine off.
  Nothing has been pushed yet.

## CLI equivalent

```text
paat import --customer example FCR.xlsx --live
paat import --customer example FCR.xlsx --live --no-combine
```

## Troubleshooting

| What you see | What to try |
| --- | --- |
| Two rows you wanted separate became one rule | Re-import with combine off, or split the FCR. |
| A row you expected to combine stayed separate | Zones, applications, or services did not match. Check the change-set placement and the original columns. |
| "Already allowed" but traffic is denied in production | The plan is based on the config it loaded, not on live traffic. Confirm the config source is current, and use the deny-log tools if you have a standalone firewall. |
| Edit Policy would add 'any' or empty a field | That should be flagged. Do not apply; fix the request or the existing rule by hand. |
