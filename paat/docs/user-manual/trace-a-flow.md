# Trace a flow

Use this to see every vsys hop an FCR would take, why the path crosses
more than one vsys, and which rules (if any) already allow it. You can
trace against a **live, read-only API pull** of your Panorama and
firewalls, or against uploaded backups. Required changes can be turned
into a change set and opened as a change plan. Nothing is written to a
firewall or to Panorama from this page.

This is the same tracer as the offline FlowMapper HTML page, run on the
PAAT server so it can reuse saved backups, pull live config, and feed the
existing change-plan flow. Live API features are optional; they are not
part of the offline page.

## What you need

- A GUI account with the **view** or **fcr** permission (see [Users and permissions](users-and-permissions.md)).
  Viewers can upload or paste an FCR, see the full trace and change plan,
  and export them. They cannot use the red push area.
- Either:
  - API credentials for the customer (a dedicated **read-only** API key is
    preferred; see below), or
  - a Panorama export and, when the device-group policy is not enough on
    its own, the local running-config backups of the firewalls on the path.
    Upload them under [Backup files](backup-file-plans.md), or on this page.
- The flow: paste it, or upload the usual FCR spreadsheet (the same
  importer as [FCR upload](fcr-upload-and-change-plans.md)).

## Live snapshot

The live source is a cached, timestamped, rate-limited (one pull a minute)
read-only pull of:

- Panorama **running** and **candidate** config
- each **managed firewall's running** config, via `show config running`
  through Panorama (`target=<serial>`). `export` with a target is not used;
  on Panorama that returns Panorama's own config.
- routing/FIB summaries when the device answers those op commands

A **Refresh live config** button is on the page. If only an admin API key
is configured, the pull still works and the page says so. To use a
read-only key instead:

1. On Panorama (and on a standalone firewall, if you talk to it directly),
   create an admin role that can use the XML API for operational / show /
   log / test commands, with no commit or configure rights.
2. Create a user in that role, generate an API key, and put it in the
   customer's env file on the PAAT server (for `example`,
   `VM_LAB_PANO_API_KEY_RO` and `VM_LAB_PALO_API_KEY_RO` in
   `/etc/paat/customers/example.env`, mode 600). The profile lists only
   the env var **names**. Never put a key in git or in chat.
3. Refresh the snapshot. The page should show credential mode `readonly`.

Secrets are never written to the snapshot metadata or to this repo.

## Step by step (GUI)

1. Open **Trace a flow**.
2. Choose the **Customer**.
3. If credentials are configured, refresh or use the **live snapshot**.
   Tick **Confirm each hop against live policy-match, FIB lookup, and
   traffic logs** if you want the live check. You can also tick uploaded
   backups (Panorama plus local files). The engine unions routes,
   interfaces and zones when a local backup matches a managed firewall by
   filename serial.
4. Paste a flow (`10.10.1.50 -> 10.20.1.50 tcp/443`), a small CSV, or
   upload an FCR `.xlsx` / `.csv`.
5. Optional: open **Route tables** and paste what a firewall actually
   learned (see *Route tables* below).
6. Optionally ignore the implicit intrazone-default allow.
7. Click **Trace**. On the result, export JSON or the markdown plan, or
   **Create change set** to open the usual change-plan view. That change
   set is always plan-only; the push area refuses it.

## What you should see

- How many files, firewalls and routes were loaded, including how many
  devices merged a local backup, and the live snapshot timestamp when one
  was used.
- A vsys map of the path, including the unknown network / WAN when a
  hop leaves the box toward a next hop that is not on any loaded
  firewall.
- For each flow: the path status, a short "why these vsys" explanation,
  a hop table (device, vsys, device group, from/to zones, allow or deny
  and the matching rule), a combined change plan with CLI and GUI steps,
  a pre-push checklist, and per-hop traffic-log filters.
- When a live check was requested: per-hop policy-match, FIB lookup, and
  recent traffic-log action, with any **disagreement** between the config
  trace and the live test called out.
- A note when device-group vsys joins were inferred by order rather than
  an exact name match. Confirm those before anyone pushes.
- A **flow diagram** for every flow, the **red or green "Rule needed in more
  than one place" box**, and a **Rule order** line under every new rule
  (see the next section).
- A yellow **"no network config in this export"** box when Panorama knows a
  firewall but has no interfaces or routes for it (a trace that reaches it
  stops there). Use the live snapshot or load that firewall's local backup.

## Diagrams, rule order and exports


**Flow diagram.** Each flow draws the hop-by-hop path: source, every
firewall and vsys with its route, NAT/PBF, security policy verdict and
zones, the unknown network between firewalls, and the destination. Buttons
above it: **Export SVG**, **Export PNG** and **Download SVG file**.

**Vsys map.** The same map the offline page draws, with **Export SVG**,
**Export PNG** and **Export draw.io** (open it in diagrams.net to edit).

**Environment and Panorama views.** Under the vsys map, *Environment by
site* and *Panorama device groups and template stacks* draw the whole loaded
configuration (sites, WAN, device groups, template stacks, firewalls). Each
exports as SVG, PNG or draw.io. They are drawn on demand from the files of
that trace, so they cost nothing until you open them.


**Rule needed in more than one place.** When the flow is checked by
security policy at more than one place (two vsys, two firewalls, or one
firewall twice because it hairpins out and back in), a box lists every
place and says which still need an allow. Red means at least one place
needs a rule; green means every place already allows it. One allow is not
enough: the traffic stays blocked at the place you missed.

**Rule order.** Under each new rule the page says where it must sit: *above
the deny that blocks it today* (the plan also contains the `move ... before`
command), or *position does not matter* when only the default rule blocks it
or the blocker is in the post-rulebase.

**Check it after the push.** For every place, a traffic-log filter and the
two commands you can paste on the firewall itself: `test routing fib-lookup`
and `test security-policy-match` (for a multi-vsys firewall, first
`set system setting target-vsys vsysN`). The live check automates the same
two tests.

**Exports.** *Export JSON* (data only, no pictures), *Export plan* (markdown
with the places, rule order and test commands) and *Export CSV* (one line
per planned change, with the rule name, zones, objects, *Place before* and
*Rule order* columns, for pasting into a ticket). All of them are plan-only.

The offline page does the same with the same code. See
FlowMapper and PAAT parity.

## Path labels (read this first)

Every flow opens with a coloured label. In plain words:

| Label | What it means | What to do |
| --- | --- | --- |
| **Complete** | Every step comes from the config: connected or static routes, links, firewall-owned next hops. | Nothing. Still confirm on the box before a push. |
| **Complete (pasted route table)** | As above, and at least one step comes from a route table you pasted. | Nothing. |
| **Suggested** | At least one step is a guess about routers or the WAN outside the configs. | Read the "assumed" lines; each says how to confirm it. |
| **Suggested (BGP-inferred)** | A step uses a BGP route the tool worked out from the peers' BGP settings. The line starts "BGP-inferred" and has a "Why:" part. | Run the command it names (`show routing route` or `show advanced-routing route`) and paste the result under **Route tables**. |
| **Needs your choice** | The next hop, the source or the destination is an address that two or more firewalls have (cloned builds, overlapping space). The tool will not pick one for you. | Pick the right firewall in the table (see below). |
| **Incomplete** | The trace stopped. | The banner says where, why, and what would finish it. |

## BGP (what the tool knows without a live box)

**Plain words.** Routes that firewalls learn from each other over BGP are
not in a config file. The tool reads every firewall's BGP settings in
the loaded files and works out which routes each one should have learned.

**Technical.** Read from local backups and Panorama templates/stacks
(variables resolved), for legacy virtual routers and PAN-OS 10.2/11
advanced-routing logical routers. Covered: peers and peer groups, AS
numbers, redistribution profiles (and their route maps), network
statements, aggregates (summary-only suppresses the more-specific
routes), legacy import/export rules, advanced filtering profiles (prefix
lists, access lists, route maps), and conditional advertisement
(evaluated against the config, so marked low confidence). Not modelled:
AS-path/community matches, MED/local-preference tie-breaks, route
reflectors, BFD/timers, IPv6, OSPF on advanced routing. The result page
lists every BGP router found under **BGP in the loaded configs**.

**Import and export rules (legacy).** Rules are read top to bottom for the
peer groups in their *used-by* list, first match wins. Once any rule applies
to a peer group, a route that matches none of them is **not** exchanged
(implicit deny). A list that only denies one prefix therefore blocks
everything unless it ends with an allow-everything rule. A peer group with no
rules passes everything. This was checked live (BGP test, PAN-OS 11.1) and the tool matches it.

## Route tables (actual learned routes)

Paste or upload, per firewall:

- `show routing route` (legacy engine) or `show advanced-routing route`
  (advanced routing);
- the XML API answer to `<show><routing><route/></routing></show>`;
- a CSV: `destination,nexthop,interface,protocol[,virtual-router]`.

Flags that print run together (`A?B`, `A Oi`) are read correctly, and a BGP
route that lost to a better static route (` ?B`, no `A`) is ignored.

Type the firewall's name, hostname or serial in **Firewall**. To paste
tables for several firewalls in one box, start each with a line
`# device: NAME`. An uploaded file without a firewall name is refused
rather than guessed. Only active IPv4 routes are used. A router with a
pasted table gets no inferred routes: the real table wins. The result
page shows **Route tables used** with the format and how many routes were
used. Tables are kept with the saved trace on the PAAT server only.

## Same IP on several firewalls

**Plain words.** If two firewalls have the same address (for example two
data centers built from one template), the tool cannot know which one
the traffic reaches, so it asks.

- A yellow **Overlapping address space** box on the result lists the
  shared addresses, overlapping subnets, and look-alike firewalls with the
  reason they were *not* treated as an HA pair.
- Under **Needs your choice**, each decision has one row per candidate:
  firewall (hostname), serial, template stack, site, and why it fits.
  - **Use for this trace** re-runs the trace with that firewall pinned and
    saves it as a new trace (the old one stays). Nothing else changes.
  - **Save as link** (shared next hops only) saves a custom next-hop link
    for the customer. Every later trace from that interface goes to that
    firewall. Saved links are listed on the **Trace a flow** form, where
    you can remove them.
- HA: HA settings in the config win. Without them, firewalls with the same
  addresses are only treated as one HA pair when they are on the same
  template stack and their hostnames name the same site. Different stacks
  never pair, and firewalls whose names point to different sites never pair.

## Look at production only (site roles and scope)

Many environments have a disaster-recovery (DR) copy of production, and a Panorama that manages both. The trace page can leave the DR, Lab and Test firewalls out so that the picture, the next-hop questions and the plan only talk about production.

**How to use it**

1. On **Trace a flow**, the **Scope** box says *Production only* (the default) or *All sites*. Pick one and trace.
2. The result page shows a chip such as **Scope: Production only, 12 firewalls hidden (9 DR, 3 Lab)**. Click **Show: All sites** to change it. Nothing needs to be uploaded again.
3. Open **Site roles**. Add matching rules at the top (for example: template stack *contains* a word you type, set to DR). The preview lists how many firewalls match as you type, and warns if a rule matches nothing or overlaps an earlier one. First match wins. You can still set one site or one firewall by hand, filter the table, or bulk-set the rows you see. Then **Save roles and trace again**.

**How the roles are guessed.** Only generic words in names count: *prod, prd, production* mean Production; *dr, cob, bcp, backup, failover, recovery, disaster* mean DR; *lab, sandbox, poc* mean Lab; *test, qa, uat, dev, staging* mean Test. Weaker words (*primary*, *secondary*, *standby*) count only in a template stack or device group name. The firewall's hostname, template stack and device group are all looked at, and the reason is written next to each role (for example "2 of 2 firewalls at this site point to DR by name"). If there is no clue at all the firewall is **Other**, and Other is never hidden by a guess. No site or customer name is built in: a site name like "dc1" means nothing until you say so.

**Your decisions win.** The order is: a setting on one firewall, then a setting on its site, then the guess. You can also add your own roles (for example *Staging*, and say whether Production only keeps it). Saved roles belong to the customer and are used by the CLI too. **Export roles JSON** gives you a file you can load into the offline FlowMapper page, and the other way round.

**What leaving a firewall out means.** Hidden firewalls are left out of the trace, next-hop and shared-address questions, alternate paths, HA pairing, the site diagram, and the plan. If a flow can only finish through a hidden firewall, the flow says so in a yellow box ("This flow needs a firewall the scope hides") instead of quietly stopping. If Production only would hide every loaded firewall (for example a lab with only lab firewalls) the page shows them all and says so in the chip.


**Why the conflict count can jump under Production only.** Hiding DR can remove the firewall that routing would use. A rule-allowed path on the remaining firewalls is then flagged as a disagreement that is not present with All sites. The result says so, with a button to show all sites. That is not, by itself, a stale rule. Conflicts that also exist with All sites are the ones to review.

**DR copy advice.** When a plan changes a production firewall and a likely DR counterpart exists, a box says **DR copy likely needed** and names it, with the reasons (same template stack or device group, matching hostname once the site and role words are removed, same zones). It is advice only. DR firewalls are never traced. Untick the box under **Site roles** to turn it off.

**Panorama in an HA pair.** A role belongs to firewalls, never to Panorama. Panorama's own HA pair is shown under **Site roles** with its own role (for example Production or DR) and Active or Passive, which you set because an export cannot say which peer is active right now. An export taken from either Panorama of the pair gives the same result, because the pair is keyed by the HA address. Panorama's peer is never used to place or pair firewalls.

## Safety checks already in the tool

- This page never pushes. A change set built from it is marked plan-only
  and the push area refuses it, including for admins. Pushing stays in
  the gated push area and still needs the **push** permission, an approved
  CR, and the usual confirmations.
- Non-admin users (`view` or `fcr` without `push`) can use every part of
  this page and can export the plan. They receive HTTP 403 on every
  `/push/...` endpoint.
- Device-group placement that was guessed is flagged uncertain.
- Live pulls and live checks are read-only and rate-limited.
- The offline FlowMapper page is unchanged and still needs no server.
  Engine-level fixes still go into FlowMapper `core.js` first, then get
  vendored. Live API features stay in PAAT.

## CLI equivalent

```text
paat flowtrace --customer example --live --live-check \
    --fcr flows.csv --changeset /tmp/cs-flow
```

Route tables, choices and links:

```text
paat flowtrace --customer example --config pano.xml --fcr flows.csv \
    --routes dc2-routes.txt@dc2-core-fw          # actual learned routes (repeat per firewall)
# output shows "path=Needs your choice" and numbered decisions, for example:
#   choice 1.1 next-hop: next hop 10.99.0.2 at edge-dal-fw ethernet1/1  [NEEDS YOUR CHOICE]
#       - core-dc1-fw · serial 009940000002 · stack ST-DC1 · site core-dc1: has 10.99.0.2 on ethernet1/1
paat flowtrace ... --pick 1.1=core-dc2-fw       # pin for this run (hostname, serial or device id)
paat flowtrace ... --link edge-dal-fw:ethernet1/1:10.99.0.2=core-dc2-fw   # custom next-hop link
```

Production only and site roles:

```text
paat flowtrace --customer example --config pano.xml --fcr flows.csv                  # Production only (default)
paat flowtrace ... --scope all                                                    # every firewall
paat flowtrace ... --scope sites=site-a,site-b                                    # exactly these sites
paat flowtrace ... --roles my-roles.json                                          # roles file (what Export roles JSON gives you)
# the first lines say what was left out:
#   Scope: Production only, 3 firewalls hidden (2 DR, 1 Lab)
#   SCOPE: This path only completes through <firewall> (DR), a firewall hidden by the scope ...
```

Without `--roles`, the customer's saved roles (from the page) are used. `--scope` always wins over the scope in the file. An unknown `--scope` value stops with an error.

Each flow prints its label (`path=Suggested (BGP-inferred)` and so on),
every assumption with how to confirm it, and the overlap summary.

`--refresh-live` forces a new pull (still rate-limited). `--backup cfg-...`
and `--config path` still work. Omit `--fcr` to read paste/CSV from stdin.
`--json` prints the machine-readable trace, including a `live_check`
block when one was requested (keep that off shared logs if it has real
addresses).

## Troubleshooting

| What you see | What to try |
| --- | --- |
| No live snapshot / no API credentials | Set the customer's env file (read-only key preferred). Until then, upload backups. |
| Refresh button disabled for N seconds | The pull is rate-limited (default 60 seconds, `PAAT_LIVE_REFRESH_SECONDS`). Use the cached snapshot. |
| Used the admin API key | A read-only key is not configured. The pull still only *reads*, but add a RO role/key when you can. |
| No path / no hops | The source or destination is not in any loaded routing table. Refresh the live snapshot, add the local backup for that firewall, or confirm the addresses. |
| Live check disagreements | The running device does not match the config the tracer just loaded (pending candidate, different vsys, or a log of earlier traffic). Read the per-hop detail before anyone pushes. |
| Live check errors, no disagreements | The test command or log query failed (permissions, vsys, timeout). The config trace is still valid. A read-only role must be allowed to run `test` and query logs. |
| Live check disagrees on an earlier hop of a hairpin, but policy-match agrees | The traffic-log sample is keyed by address, protocol and vsys, not by from/to zone, so a later hop's allow or deny can show up on the first hop of the same 5-tuple. Trust policy-match for the per-hop verdict; use the hop's from/to zones when you read the logs. |
| Live check logs are empty, but the firewall has sessions | Some Panorama setups return empty log jobs. The tool queries the firewall's local traffic logs directly. The log API is asynchronous (job enqueue, then poll). Generate traffic (`sudo lab-hairpin-traffic` on the test-traffic VM) and retry. |
| Trace misses pushed policy on the PA-VM | A managed firewall's own `show config running` does not include policy pushed from Panorama. Traces use the Panorama running config for policy and keep the firewall file only to merge routes, interfaces and zones. |
| Routes look too thin after a local merge | The engine unions Panorama template routes with the local file; a local exact-match route still wins. Load both files. |
| Device-group placement uncertain | Vsys names in the template do not match the vsys names in the device group. Confirm the vsys on the target before you commit. |
| Suggested (BGP-inferred) | Paste the firewall's `show routing route` / `show advanced-routing route` under **Route tables**. |
| Needs your choice | Pick the firewall (**Use for this trace**) or **Save as link** if it is always the same one. |
| Route table: "no router named X" | The table's virtual/logical router name does not match the config. Check the `VIRTUAL ROUTER:` / `logical-router` line. |
| Node.js is required | The PAAT server needs the `nodejs` package. `deploy/install-web.sh` installs it. |
