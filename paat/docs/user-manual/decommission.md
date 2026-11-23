# Decommission

Decommission finds every place a retired host, subnet, FQDN, object or rule
is used and builds a **precise** removal plan. It never removes a broader
object because your address is inside it: a `/16` that happens to contain your
`/32` is reported as **Possible** and left alone. Real configs are messy, so
the page grades each finding and shows the reason and the evidence.

There are two intents:

- **Remove references** (the default): take the item out of rules and groups,
  then delete objects that nothing uses any more.
- **Stop traffic**: do the same clean-up, then trace each flow you give and find
  every rule that *still* lets it through (a broad subnet, an `any`, a parent
  group), and propose a narrow deny above the first permit in each place.

Nothing is changed until an Operator pushes the approved plan from the Push
area, the same as an FCR change set.

## What you need

- The **Engineer** role (or higher) for the **Decommission** page.
- Targets: IPs, subnets (`10.1.30.0/24`), ranges, FQDNs, object or group
  names, rule names. Paste them, or upload a small spreadsheet.
- For **Stop traffic**: one or more flows, one per line
  (`source destination tcp/443`), or the FCR CSV format.
- Ticket numbers if you have them, and the right **Config source** (live
  snapshot, cached export, or a backup file for a plan-only decommission).

## The three tiers

| Tier | What it means | In the plan |
| --- | --- | --- |
| **Exact (100%)** | The object, group member, literal or rule *is* your target: same value, same name. | Ticked for you. |
| **Highly likely** | Strong evidence but not proof: a rule you named that leaves an object used by nothing else, a host object that sits inside the subnet you are retiring, an object whose name matches the target, a negated field that would change meaning. | One click: tick it and press **Rebuild plan with this selection**. |
| **Possible** | Overlap only: a subnet, range or group that *contains* your target but also covers other addresses. The card shows how many other addresses it covers. | Advice only. It can never be ticked or pushed. |

Each finding shows the evidence: where it is (vsys or device group, shared or
local), what references it, how many other addresses it covers, and why it
got its tier.

## What the plan will and will not do

- **Remove a member** from a rule field or a group only when other members
  remain.
- **Delete an object or group** only when nothing else references it after the
  plan (rules of every type, other groups, NAT, PBF, decryption, other device
  groups that inherit it).
- **Delete a rule** only when one of its address fields would be left empty
  *and* every member that is being removed is Exact (or ticked by you).
- **Never** leave an empty address field. PAN-OS treats an empty field as
  `any`, so that would open the rule up. If the only way to remove your item
  would do that, the plan keeps it and shows a red **Dangerous: would become
  any** card instead.
- Dynamic address groups, EDLs and security profiles are listed as notes;
  they are not edited automatically.
- Order: deny rules first (stop-traffic only), then rule and group edits, then
  rule deletes, then object deletes. Child device groups go before their parent,
  `shared` goes last.

## Stop traffic

1. Choose **Stop traffic** and paste the flows.
2. PAAT traces each flow through every firewall and vsys on the path. For each
   place it lists every rule that permits the flow, graded the same way
   (a rule that permits it through a `/16` is *Possible*, not Exact), and says
   whether the flow is **still allowed after the clean-up**.
3. Where it is, the plan proposes a **minimal deny**: the flow's own source,
   destination and port (a new service object is created only when no service
   with that port exists), placed directly above the first remaining permit in
   that place. Each deny comes with the `test security-policy-match` command
   for that place.
4. Untick a deny if you would rather change the broad rule by hand; the plan is
   rebuilt without it.

## Step by step (GUI)

1. Open **Decommission**.
2. Choose the customer, config source and intent.
3. Paste the targets (and flows for Stop traffic) or upload the file.
4. Add RITM / SCTask / CR if you have them, then **Build decommission plan**.
5. Read the tier cards. Tick any Highly likely rows you agree with and press
   **Rebuild plan with this selection**. Rebuilding resets any approval, because
   the plan changed.
6. Check the red cards (would become `any`, unresolved items) and the notes.
7. Download the plan as **CSV**, **Markdown** (Change plan) or **CLI**
   (`set` / `delete` lines, plus the rollback CLI).
8. Approve and push as for any change set. See [Plan-only vs live push](plan-only-and-live-push.md).

## Push, verify and rollback

- **Prepare** re-reads the running config and refuses if anything moved since
  the plan: a group or field that would now be emptied, a deny name already in
  use, or the rule the deny must sit above has gone.
- Members are removed one by one, so other members of the group or rule are
  never touched.
- After the commit PAAT checks that every removed member and object is gone,
  every deny is in place above its permit, and (on a firewall) that
  `test security-policy-match` for each flow now returns the new deny.
- **Rollback** puts back exactly what was removed, in reverse order, including
  rule positions, and removes the added denies and service objects.

## CLI equivalent

```text
paat decom --customer example --items '10.10.20.1,OLD-HOST,OLD-RULE' \
    --ritm RITM... --cr CHG...
paat decom --customer example --items OLD-RULE --likely          # also tick every Highly likely
paat decom --customer example --items 10.1.30.25 --mode stop \
    --flow '10.1.20.5 10.1.30.25 tcp/443'
paat decom --customer example --file items.xlsx --live
paat changeplan --customer example --changeset <file.json>
```

`--select` takes candidate ids from a previous run if you want to choose them
one by one.

## Troubleshooting

| What you see | What to try |
| --- | --- |
| Item not found (red, push refused) | The name or IP is not in the config you loaded. Check spelling, vsys / device group, and the config source. In Stop traffic mode a literal IP that no object uses is a yellow note: the flow trace still runs. |
| Only **Possible** findings | Nothing references your exact value; only broader subnets or groups contain it. That is usually correct: leave them, or use Stop traffic if the goal is to block. |
| **Dangerous: would become any** | Removing the item would empty a field. The plan keeps it. Delete the whole rule (tick it if offered) or change the rule by hand. |
| Shared object | The delete goes last and needs a push to every device group with firewalls. Rules local to a firewall are not in a Panorama export; check them first. |
| Dynamic group named | Dynamic groups match by tag, not membership. Remove the tag from the object instead. |
| Flow has no path | The flow does not reach a firewall in this config. Check the addresses and the config source. |
| Push refused: config changed | Rebuild the plan from a fresh snapshot. |
