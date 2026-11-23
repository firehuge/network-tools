# PAN-OS FlowMapper

A single offline HTML page that reads a Palo Alto Networks **firewall config XML** or a **Panorama export** and answers: *"If 10.1.1.10 talks to 10.2.2.20 on tcp/1433, which firewalls, vsys, zones and routers does it cross, what allows or blocks it, and what do I have to change?"*

It is built for messy multi-vsys environments where nobody knows the flows. It follows the routing and tells you **every place a rule (or route, or zone) is needed**, so you stop adding one rule at a time and waiting to see where the traffic dies next.
## Quick start (no networking background needed)

1. Open `pan-flowmapper.html` in Chrome, Edge or Firefox. It works offline; nothing is uploaded.
2. Drop in the config file(s): a firewall backup or a Panorama export (see *How to get the config file*).
3. Type the source address, destination address, protocol and port, then press **Trace**.
4. Read the coloured banner at the top of the result:
   - **Complete**: every step is known from the config (or from a route table you pasted).
   - **Suggested** / **Suggested (BGP-inferred)**: the path is a best guess. The banner lists each guess and how to check it.
   - **Needs your choice**: the same address exists on more than one firewall. Pick the right one in the table.
   - **Incomplete**: the trace stopped. The banner says where, why, and what would finish it.
5. Look at **Changes needed**: every rule, route or NAT change the flow needs, on every firewall, with CLI.

Press **Help** in the page header for the same guide, with a plain-language and a technical part per topic.

## What it does

1. **Load** one or more config XML files: firewall running-config or saved snapshot, or a Panorama export (any number of managed firewalls). Load several firewall files together to trace *across* firewalls.
2. **Enter a source, destination, protocol and port.** You can use an IP, a subnet, a range, or an address object name.
3. **Trace the path** hop by hop:
   - Finds the ingress interface, zone, vsys and router. It uses the connected subnet first, then a reverse route lookup. You can pick the ingress interface yourself.
   - Looks up routes per virtual router or logical router (advanced routing): connected, static, `next-vr` and discard routes, with longest match and then metric.
   - Follows inter-vsys hops through **external zones** and `next-vr`. Policy is checked in **each** vsys the packet crosses.
   - Handles **shared gateways**: no security policy is evaluated there, but NAT and PBF are.
   - Applies **NAT** the way PAN-OS does. The destination zone comes from the route lookup on the *pre-NAT* destination. Destination NAT then changes the egress zone, so the security rule must use the **pre-NAT IP with the post-NAT zone**. Source NAT, port translation and bi-directional static NAT are supported.
   - **Inbound NAT, either address.** You can trace an internet flow by the public address *or* by the server's private address. When you enter the private (translated) address, the tool finds the NAT rule that translates to it (from the zone the traffic enters, matching its source, translated port and to-zone). It then checks the security rule the way PAN-OS does, on the public address and pre-NAT port with the post-NAT zone. So a working inbound rule is no longer reported as missing. Also covered: NAT rules from Panorama device groups (pre, post and parent groups) merged with local rules, NAT to an address object or a 1:1 subnet, dynamic destination translation to an address object, NAT on the firewall's own interface address, proxy-ARP public blocks that no interface owns, `to-interface`, bi-directional static NAT in reverse, U-turn NAT, and an internet firewall that NATs and forwards to a DMZ firewall that only sees the private address and translated port. If the internet interface uses DHCP (its subnet is not in the config) and the firewall owns another address in the same /24 as the VIP in the NAT's to-zone, a VIP that the config would only route inside through a broad route counts as on that runtime subnet, and the trace notes the assumption. If the routed entry is blocked and another firewall's destination NAT owns the address, the trace enters there when that path does better (no deny), and says so. A NAT to an FQDN object stops with a note, because it cannot be resolved offline.
   - Applies **PBF** (forward to interface or next hop, forward to vsys, discard).
   - Finds the **source firewall and destination firewall** first, searches the **inferred network graph** for the chain of firewalls between them, then checks each firewall in that chain. This works across routers and MPLS that are not in any config. See [Multi-firewall paths](#multi-firewall-paths).
   - Checks the **return path** in every hop and flags missing or asymmetric return routes.
4. **Policy checks.** For each vsys crossed you get the device, vsys, device group, from and to zone, the first matching rule (allow or deny), and earlier rules that *might* match. Those are rules that depend on App-ID, User-ID, HIP, URL category, FQDN, dynamic groups or partial address overlap. If no rule matches, it shows `intrazone-default` or `interzone-default`.
5. **Changes needed.** One entry per vsys or device that needs something, in path order:
   - **Security rules** with the from/to zone, source, destination (pre-NAT), service and placement ("place above deny-x"). For Panorama it picks the scope that is evaluated first: the device group, a parent DG, or the shared pre-rulebase.
   - **Routes**: missing forward routes, missing `next-vr` routes between vsys, missing or asymmetric return routes.
   - **Zones**: missing external zones and `visible-vsys`.
   - Each entry comes with a **`set` CLI snippet**, plus a **Copy all CLI** button.
6. **Firewall change request (FCR).** Paste a single flow (`10.1.1.10 -> 10.2.2.20 tcp/443`), several lines, or a CSV. The tool traces every vsys on the path, explains why those vsys are involved, and builds **one combined change plan** (object reuse and `set` CLI, with device-group placement) plus a pre-push checklist and per-hop traffic-log filters to use after the push. See [Firewall change requests](#firewall-change-requests-fcr).
7. **Flow diagram (SVG).** Shows source → firewall → vsys (ingress, VR, NAT, policy, egress) → destination. Policy checks are green, red or amber. A hop that leaves one vsys and re-enters another vsys of the same firewall through a router that is not in the config is drawn as a hairpin through an unknown network. Export as SVG or PNG.
8. **Config browser.** Lists vsys, shared gateways, zones, interfaces (with IPs, zone, vsys and VR), route tables, and security and NAT rules. A filter box searches all tables.
9. **Network map**: the inferred topology across all loaded firewalls (firewalls, subnets, inferred routers, inferred WAN/MPLS core), with a filter and the last trace highlighted. Use it to check what the tool assumed. *Inference details* lists every inferred router (which routes use it, and why it joined the core) and every shared subnet.
10. **Device topology** per device: vsys and shared gateways with their zones and interfaces, external zone links, virtual routers, and `next-vr` links. Export as SVG or PNG.
11. **Raw XML view** with search. **Hide secrets** is on by default and masks password hashes, keys, PSKs, secrets and API keys.

Nothing is uploaded. The page makes no network requests. A Content-Security-Policy blocks them, and the tests check for zero requests. Copy `pan-flowmapper.html` anywhere and double-click it.

## Environment view

The **Environment** tab draws every mapped firewall at once. Use **By site** to group them by inferred site, **By vsys** for a vsys-level map, or **Panorama** to see device groups and template stacks. HA pairs are merged into one box that lists both members. In the site view, lines connect each firewall to the inferred WAN/MPLS core, the internet (a default route to a public next hop) and external BGP fabrics. Badges show HA, multi-vsys, BGP/OSPF and *no network config*. **By vsys** lists every vsys on a firewall, pulls the vsys of the last trace out, collapses the rest into an “other vsys” pool, and draws an *unknown network* cloud for next hops no loaded firewall owns. Expand all lists every vsys. Export SVG, PNG or draw.io from any mode.

- **Sites** are inferred by documented rules only:
  - firewalls in one HA group;
  - firewalls sharing a LAN subnet (not point-to-point /30–/31, link-local, tunnel or WAN-core subnets);
  - firewalls with the same hostname site token, once firewall words and unit numbers are removed (`nyc-fw1`/`nyc-fw2` → `nyc`, while `br-east-01` stays a site of its own);
  - a device group used by exactly two firewalls.

  Hover a site box to see why it was grouped.
- **Filter** by firewall, site, zone, subnet or IP. Firewalls that match on a zone or subnet open automatically.
- **Expand and collapse**: click a firewall to show its vsys, zones and interfaces with their subnets and virtual routers. *Expand all* and *Collapse all* do the same for every firewall. Double-click a firewall to open its detail diagram in *Device topology*.
- **Export** as SVG, PNG or **draw.io** (`.drawio`). The draw.io file opens in diagrams.net for editing and can be imported into Visio through draw.io. The exports use the same layout as the screen.
- With 67 firewalls, the view renders in about 0.15 s.

### Panorama view

Switch the Environment tab from **By site** to **Panorama** (when a Panorama export is loaded) to see how Panorama manages the estate. Panorama sits in the middle. The device-group tree (parent to child) grows to the right and ends in the managed firewalls, with HA pairs merged and the vsys count shown. Template stacks and their templates are on the left.

- Every firewall card names its template stack. A multi-vsys firewall whose vsys sit in different device groups hangs under the first one, with dashed links from the others.
- Flagged in amber: firewalls with **no template stack** (mapped only; Panorama has their rules but not their interfaces, zones or routes), firewalls with **no network config**, and firewalls in **no device group**. Dashed grey cards are device-group members that are **not loaded** (no stack and no local backup). Empty device groups, stacks with no loaded firewall and templates in no stack are hidden (counted in the summary). Tick **Empty groups, unused stacks/templates** to draw them dimmed; large legacy Panoramas often have hundreds.
- **Network (WAN, internet, BGP)** overlays the inferred network: links from each firewall to the WAN/MPLS core, the internet and the BGP fabrics. **Template-stack links** draws a line from each stack to its firewalls.
- The same filter (it also matches device-group and stack names), click-to-expand, and SVG / PNG / draw.io export work here. With 67 firewalls the view renders in about 30 ms.
## Multi-firewall paths

Real paths often go firewall → WAN/MPLS routers → firewall → another vsys → another firewall. The routers and switches are not in any config, so the tool builds an **inferred network graph** from all loaded firewalls:

- **Firewalls**: one node per loaded firewall. The vsys, virtual routers and shared gateways inside it are handled by the per-firewall engine.
- **Subnets**: every interface subnet. Firewalls with interfaces in the same subnet are on the same segment, so they are layer 3 neighbours.
- **Routers**: every static-route next hop that is not a firewall interface becomes a router on the subnet that contains it. The same next hop seen from several firewalls is one router. The far end of a /30 or /31 with no known router is assumed to be a router (marked *inferred*).
- **WAN/MPLS core**: a router joins the inferred core if a firewall routes another firewall's networks through it (strong evidence), or if it has a private address, or if its subnet is named like `mpls`, `wan`, `transit`, `core` or `uplink`. A WAN-named interface with no known router attaches to the core as a weak hint.

**Ownership.** The source and destination are placed first. The *owner* is the firewall with the prefix on a connected interface (most specific wins). If no firewall has it connected, the owner is the closest gateway: the firewall with the most specific non-default route that points inward. You can pin the **Source firewall** and **Destination firewall** in the form, and list firewalls the path **must pass through**.

**Path search.** A shortest-path search (Dijkstra, top 3 alternatives) runs from the source owner to the destination owner. Each edge costs more when its evidence is weaker. From strongest to weakest:

1. User-defined link
2. Next hop is another firewall's interface
3. Shared subnet
4. Specific route plus a reverse route on the far firewall
5. Specific route only
6. Default route only
7. Zone or interface naming hint

Default-route-only edges are allowed when the destination is internal: it is owned by a loaded firewall, or it is a private address with a gateway. Typical MPLS branches only have a default route to the PE router. Public or unknown destinations are not chained into internal firewalls; the trace ends where traffic leaves toward the internet.

**Validation.** The chosen chain is then checked firewall by firewall with the normal engine: ingress and egress zones, vsys crossings, NAT, PBF, policy and routes. If a firewall's own routing would not send the traffic toward the next firewall in the chain, the trace **does not stop**. It lists the route needed (VR, prefix, next hop, interface; the next hop is the inferred router or the far end of the /30) and continues. Destination NAT re-plans the chain from that firewall to the translated address. The result always shows the whole chain from source owner to destination owner when any path exists in the graph.

**What you see:**

- **Firewall chain** with a confidence level per hop (high, medium or low). Medium and low hops are drawn with **dashed amber lines** in the diagram.
- **Alternative paths**: the top 3, selectable. There is also a per-hop branch picker when two firewalls tie.
- **Why this path / why it stopped**: the owners found, the evidence for each hop, other firewalls that were considered and why they were not used, and buttons to pin a firewall.
- **Changes needed**: covers every firewall, vsys and device group in the chain, plus return-path checks on each one. For example, an asymmetric reply that leaves the vendor firewall via its internet default route gets a return-route fix toward the B2B firewall.

**Links** (under the trace form, *Links between firewalls*) are stored in this browser (`localStorage`) by firewall name. You can export and import them as JSON, so a team can share one file:

```json
{ "type": "pan-flowmapper-links", "version": 1, "links": [
  { "from": { "device": "fw-dmz", "iface": "ethernet1/3", "nexthop": null }, "to": { "device": "fw-core", "iface": "ethernet1/5" }, "label": "MPLS" },
  { "from": { "device": null, "nexthop": "10.250.9.2" }, "to": { "device": "fw-core", "iface": null }, "label": "WAN" } ] }
```

Links are the strongest edges in the graph, so they override anything inferred.

### Device names: hostname, serial, template stack

Wherever a firewall is identified, it is shown as **hostname · serial · template stack**, with each part shown once and missing parts left out (no blanks). This applies to Environment cards (By site and Panorama), HA pair labels (both hostnames), trace hops, the chain and path, the firewall pickers, the links and public-space map lists, the change list and ticket export (HTML and CSV), and the zone-findings CSV. It also applies to free text: guess notes, "Confirm: add a link from … to …" lines, path-status assumptions, alternate-path reasons and stop reasons. A serial that appears alone in that text is shown with its hostname and stack. Network-map and Environment drawings keep their own short labels.

The hostname comes from the config, in this order:
1. a local firewall backup's `deviceconfig/system/hostname`;
2. Panorama's managed-device list (`mgt-config/devices/entry/hostname`);
3. a `hostname` under a device group's or template stack's `devices/entry` (the entry named by the serial);
4. a per-device `$hostname` template-stack variable.

5. a template's (or template stack's) `deviceconfig/system/hostname`, but only when the stack serves exactly one firewall. Panorama pushes that value, so on a one-firewall stack it names that firewall. On a stack with two or more firewalls it would name all of them, so it is ignored;
6. the `deviceconfig/setting/management/initcfg/hostname` an imported device config leaves in a template. It is used only for a one-firewall stack, when no other firewall's template carries the same name. It can be stale, so a hostname you paste wins over it.

Many Panorama exports carry no managed-device hostnames at all. For those, paste `serial,hostname` lines or a Panorama *Managed Devices* CSV export (with columns named like *Device Name* and *Serial Number*) into **Device hostnames** under the trace form. Hostnames from the config (items 1-5) always win; a pasted hostname wins over an init-cfg one. The pasted list is saved in this browser. Hostnames only change the label: a firewall is still matched by its serial, so saved links and map entries keep working.

### Firewalls without network config

Some managed firewalls have rules in the Panorama export but no network config (no template stack, or an empty one). When any firewall in the trace set is like that, Loaded configs shows an amber callout. It names them (hostname · serial · stack), collapsed when there are many, and explains the fix. Load each firewall's own local backup alongside the Panorama export, and the two merge into one device. Traces can then continue through it. The backup also carries the firewall's HA settings (peer-ip, HA1), which are often set locally, so HA pairs can be confirmed. An Incomplete path that stops because traffic leaves toward one of these firewalls says the same, with a button that jumps to the list.

### Public-space / circuit map

Public IP space is often routed in by provider or upstream routers and several internet circuits, and that routing is not in the firewall configs. The **Public-space map** (under the trace form) records, for each public prefix, which circuit it arrives on and which firewall (and interface or zone) it lands on.

- **Using it in a trace.** For an inbound flow (public source), the source's mapped prefix decides the entry firewall and interface. If the source isn't mapped, the destination's mapped prefix decides. The longest prefix wins, and an entry on an HA peer counts as the pair. The result shows a *Public-space map* line: it is green when routing agrees, and it shows a red *disagrees with routing* pill when the map and the firewall routing (or a provider static route) point to different places. The trace then follows the map.
- **Provider static routes.** A virtual router can have only one default route, so provider-assigned public space is often steered back to its provider with a more-specific static route (for example, 0.0.0.0/0 to ISP-A plus 198.51.100.0/27 to ISP-B's next hop). FlowMapper treats this as a valid ingress and return pattern. Inbound traffic for that prefix enters on the provider interface the static points to, not the default-route interface. The reply that follows the default route out another provider interface is reported as information, not as a required change. An explicit map entry always wins; if it disagrees with the static, that is flagged.
- **Suggestions.** After a load, *Not in the map yet* lists the public prefixes the config routes or owns that the map does not cover:
  - provider statics (non-default static routes for public prefixes toward an untrust, WAN, ISP or default-route interface), with the circuit named after the zone and next hop;
  - public NAT original addresses and bi-directional static NAT public addresses, landing on the NAT's from-zone interface;
  - public interface subnets.

  For each one you can choose **Add**, **Edit** (prefills the form) or **Ignore**, and the filter box narrows a long list. A suggestion never replaces an entry you made.
- **Bulk accept.** The kind menu (*Provider statics*, *NAT addresses*, *Interface subnets*) and the filter box narrow the list. **Accept N shown suggestions** adds every suggestion the list shows (including ones past the first 60 rows), after a confirm.
  - A prefix already in the map, or inside an entry you made, is skipped. Your entry wins.
  - The same prefix found on both members of an HA pair becomes one entry for the pair.
  - The same prefix found on two unrelated firewalls is skipped, for you to decide (see the next item).
  - A note gives the counts accepted and skipped, with the reasons. Accepted entries become ordinary map entries. They leave the suggestion list, are saved in the browser, and are included in the export.
- **Same prefix on several firewalls.** A box above the suggestions lists each prefix that more than one unrelated firewall claims. For each candidate it shows the firewall (hostname · serial · stack), the source kind (provider static, NAT address, interface) and the interface or zone. The map holds one landing per prefix, so you pick one candidate and click **Use this landing**. Nothing is preselected. The pick becomes an ordinary map entry (saved, exported), and the other candidates leave the list. **Ignore this prefix** hides all of them and adds nothing. HA peers count as one candidate, and a prefix that an entry of yours already covers never shows up here.
- **Environment view.** Each circuit (map entries grouped by circuit name) is drawn as a cloud linked to the firewalls its prefixes land on. An entry on an HA peer links to the pair.
  - In the *By site* view, a circuit whose firewalls are all in one site sits inside that site's box. A circuit that lands in several sites goes in a band at the top.
  - In the *Panorama* view, circuits appear with *Network* on.
  - SVG, PNG and draw.io exports include the clouds.
- **Saving and sharing.** The map is saved in this browser (`localStorage`), and you can export or import it as `{ "type": "pan-flowmapper-public-space", "version": 1, "circuits": [ { "prefix": "198.51.100.0/27", "circuit": "ISP-B", "device": "fw-edge", "iface": "ethernet1/2", "zone": null } ] }`.
**No rule in this export.** When the trace needs a security rule and no allow rule anywhere in the loaded export names the source and destination (any/any rules excluded), the result says so. It explains that the flow is denied on the path found, and that the allow is likely in rules local to a firewall (load that firewall's own backup alongside the Panorama export) or behind a different ingress circuit (use the public-space map).

### Path status: complete, suggested or incomplete

FlowMapper only sees the firewalls. The routers, switches and WAN between them are not in the export, so some hops are guesses. Every trace now opens with a banner that says how much of the path is known:

- **Complete path** (high confidence): every hop comes from a connected, local or static route, PBF, a link you added, a next hop that is a firewall interface, a shared subnet, or a public-space map entry.
- **Suggested path** (medium or low): at least one hop is assumed. That covers a next firewall reached through routers or the WAN/MPLS core, a BGP or OSPF route inferred from peer configs, a suggested (missing) route, a hairpin over an outside router, a default route to a next hop that no loaded firewall owns (when the destination is private), a firewall picked by destination NAT or by rules, or a source placed only by a default route. The banner lists each assumption in plain words with how to confirm it, for example "add a link" or "run `show routing route`". The same note also appears on that hop in the hop table.
- **Suggested (BGP-inferred)**: the same as Suggested, but at least one hop rests on a BGP route FlowMapper worked out from the peers' configs. The banner says why it thinks the route exists ("Why: dc1-core-fw aggregates 3 route(s) into 10.10.0.0/22 (summary only)") and tells you to run `show routing route` (legacy) or `show advanced-routing route` (advanced routing) on that firewall, or paste that output under **Route tables**.
- **Complete (pasted route table)**: every hop is explicit, and at least one comes from a route table you pasted. Pasted routes are what the firewall actually learned, so they count as explicit.
- **Needs your choice**: the next hop, the source or the destination is an address configured on two or more firewalls (cloned builds, overlapping address space). The trace never picks one silently. It shows a placeholder path, marks it incomplete and lists the candidates for you to pick (see *Same IP on several firewalls* below).
- **Incomplete path**: the trace stopped. The banner names the firewall, vsys, virtual router and interface where it stopped, why it stopped (no route, FQDN NAT target, loop, no next firewall, firewalls without network config) and what would finish it.

When other reasonable paths exist, up to five are listed under **Other possible paths**. Each one says in plain words:

- **Why offered**: an equal-cost option that routing fits as well as the path shown, a costlier one that routing also fits, a path the security rules point to when routing does not, another firewall that fits the next hop, and the evidence behind it (a link you added, a next hop that is a firewall interface, a shared next-hop subnet, routers outside the export, or a hairpin).
- **Differs**: where it leaves the path shown, for example "after fw-dmz it goes to fw-site2 instead of fw-site1", or the different exit interface or next hop when the firewalls are the same.
- **To make it complete**: add a link, add a missing route, confirm a dynamic route, or load the local backup of a firewall without network config. If every hop is already explicit, it says so.

The routing choice stays on top. Nothing is scored for show. Click an alternate to trace it. If the current path is low confidence or contradicts routing and a stronger option exists, the banner says so. A link you add turns that guess into an explicit hop, so the path can become complete.
### Ignore the intrazone-default allow (optional)

PAN-OS allows same-zone traffic through the predefined `intrazone-default` rule when no explicit rule matches. FlowMapper follows that by default. Tick **Ignore intrazone-default allow** on the trace form when you want every hop to have an explicit rule. A same-zone hop that only `intrazone-default` allows then shows **NEEDS RULE** in Policy checks, with "ignored: would allow". It also goes into Changes needed and the ticket export, like any other missing rule.

- Routing still picks the path. The path status (complete, suggested, incomplete) and the path options do not change, and an ignored default never counts as a rules-versus-routing conflict.
- Explicit rules are never ignored, including rules with rule type `intrazone`. `interzone-default` is unchanged.
- If a config already sets intrazone-default to deny, the toggle does nothing there.
- The setting is saved in your browser and is off until you turn it on. Ticking or clearing it retraces the current flow. Rule validation (replay) does not use it.
### Picking the devices to trace (Panorama)

The Loaded configs table lists the managed firewalls. The filter matches hostname (including hostnames you pasted), serial, template stack and device group, and the filter text stays put while you work.

- **All** with a filter makes the trace set exactly the devices the filter shows. For example, type `dc1` and click All to trace only that data center. With no filter, All selects every listed device. It skips unmapped stacks unless "show unmapped" is on.
- **None** with a filter removes only the devices the filter shows, so you can take one site out of a larger set. With no filter, it clears the set.
- **HA pairs** that the engine detects get one row with an "HA pair" badge, listing both members. One checkbox selects or clears both, and a filter that matches either member shows the pair. Each member keeps its own Override DG control. Pairing is strict (see HA pairs below). HA peers named in the HA settings show "from HA config". Without HA settings, firewalls on different template stacks are never paired. Devices without network config in the export (no interface addresses) can't be paired, so they stay as separate rows. Pairs are never guessed from similar names.
### Production only: leave DR out (site roles and scope)

Many networks have a production site and a disaster-recovery (DR) site built almost alike, so a Panorama export or a folder of backups holds both. **Scope** (the bar above the tabs) decides which firewalls take part. **Production only** leaves DR, Lab and Test firewalls out of traces, next-hop candidates, shared-address pickers, alternate paths, HA inference, diagrams, batch FCR runs and plans. **All sites** brings everything back, and **Custom sites** lets you tick exactly the sites you want. A chip always says what is hidden, for example `Scope: Production only, 12 DR firewalls hidden (12 DR)`, and one click changes it.
**Roles.** Every firewall has a role: Production, DR, Lab, Test or Other, plus any roles you add. Open **Site roles** and add matching rules at the top (for example: template stack *contains* a word you type → DR). The preview lists how many firewalls match as you type, and warns if a rule matches nothing or overlaps an earlier rule. First match wins. A setting on one firewall or one site still beats a rule; a rule beats the built-in guess from words such as prod, dr, backup, lab or test. The compact table below the rules shows every firewall with a filter and a bulk set. You can still add a role (say, Staging) and export or import the same JSON file the lab tool uses (`--roles`). Settings are also saved in this browser.
**How the guess works.** It uses only generic words found in the firewall's hostname (weight 3), template stack (2) and device group (2): `prod`, `prd`, `production`; `dr`, `drc`, `cob`, `bcp`, `backup`, `bkp`, `failover`, `recovery`, `disaster`; `lab`, `labs`, `sandbox`, `poc`; `test`, `tst`, `qa`, `uat`, `dev`, `stage`, `staging`, `stg`, `preprod`. `primary` and `secondary` / `standby` count only in stack and device-group names (in a hostname they usually label an HA unit). A site takes the majority role of its firewalls; an HA secondary follows its primary. Firewalls with no clue stay **Other**, and Production only keeps Other, so nothing is hidden by silence. No site or customer name is built in, and a test checks that. Authority order: your firewall setting, your site setting, the firewall's own clue, the site's clue, Other.

**When DR is needed to finish a path.** The trace says so ("This path only completes through ..., a firewall hidden by the scope") with a *Show all sites* button, instead of stopping quietly.

**DR copy advice (optional).** When a plan adds rules or objects on production firewalls, FlowMapper lists the DR firewalls that probably need the same change: same template-stack pattern, same device-group pattern, matching hostname once site and role words are removed, and the same zones (with a note when the DR subnets differ). A DR firewall in the **same device group** is marked *reached automatically*: a rule pushed to that group already applies. This is advice only; DR firewalls are never traced. Turn it off in Site roles.

**Panorama itself.** A Panorama can be an HA pair with one peer at each site. Roles belong to firewalls only: Panorama's HA settings (`peer-ip`, HA1 address, priority) are never used to place or pair a firewall, and an export from either peer gives the same firewalls, roles and scope. On the Environment tab, in Panorama view, a **Panorama HA pair** card shows both Panoramas with their own Role and Active/Passive (the active unit is runtime state and is not in the export, so you set it). They are stored by HA address, so what you set on one export shows on the other.
### FAQ

**How do I look at production only?** Click **Production only** in the Scope bar. If the chip says nothing is hidden, the tool found no DR words in your names: open **Site roles** and add a rule (template stack or hostname contains the word that marks your backup site) set to DR, or mark the site by hand. To trace from a script, use `--scope production` and `--roles` in the lab tool (see the PAAT guide).

**My Panorama is HA across production and DR, so why do I see both sites and how does Production only work?** A Panorama export lists every firewall that Panorama manages, production and DR alike, and both Panorama peers hold the same list, so you see both sites whichever peer you exported from. Production only does not look at Panorama at all: it hides the firewalls whose *site* is marked DR (or Lab or Test). The two Panoramas are not firewalls, so they are never hidden and never change the scope. They have their own Role and Active/Passive on the Environment tab.

**Why is a firewall hidden?** Open **Site roles**, find it in the firewall table, and read the *Source* column (for example `Rule 1: template stack contains "backup"`). Change the rule or the role, or switch the scope to All sites.

**Why did the routing/rules conflict count jump when I chose Production only?** Usually because the routed path went through a DR firewall that is now hidden. The tool still finds a rule-allowed path on the remaining firewalls, so it flags a disagreement that is not there when every site is included. The Validate summary splits that count: conflicts that only appear because the scope hid the routed next hop (or the address's owner), versus conflicts that also exist with All sites (worth reviewing as a stale rule or a routing problem). On a single trace the yellow box says which kind it is, with a button to show all sites.


**Will DR be left out of a change plan?** The plan only covers the firewalls in scope. The *DR copy likely needed?* box lists DR firewalls to check by hand.

### BGP and OSPF route inference

**In plain words.** Firewalls that run BGP learn routes from each other while they run. Those routes are not in the config file, so FlowMapper works out which routes each firewall *should* have learned by reading every firewall's BGP settings in the same export or backup set. A hop that depends on such a guess is labelled **Suggested (BGP-inferred)** and says why. If you have the real route table, paste it (next section) and FlowMapper uses that instead of guessing.

**Technical detail.**

- **Where it reads BGP from.** Local firewall backups and Panorama templates and template stacks (with template variables resolved per device), for both routing engines:
  - *legacy* virtual routers: `network/virtual-router/<vr>/protocol/bgp`;
  - *advanced routing* (PAN-OS 10.2/11.x) logical routers: `network/logical-router/<lr>/vrf/<vrf>/bgp`, with profiles and filters from `network/routing-profile`.
- **Import and export rules (legacy VRs).** Rules apply top to bottom to the peer groups in their *used-by* list, and the first match wins. Once any rule applies to a peer group, a route that matches none of them is **not** exchanged (implicit deny), exactly as on a real PA-VM (PAN-OS 11.1, checked live). So a rule list that only denies one prefix blocks everything: add a final allow-everything rule (empty match, action allow). A peer group with no rules passes everything.
- **What it reads.**

  | | Legacy VR | Advanced routing LR |
  |---|---|---|
  | Local AS, router-id, enable | yes | yes |
  | Peer groups (type, peers, peer AS, local interface/address, peer address) | yes | yes (incl. per-peer `inherit no`) |
  | Redistribution | redist-rules + redistribution profile (connected/static/OSPF, interface and destination filters) | `redistribution-profile` (connected/static/OSPF/RIP) and its route map (prefix-list matches) |
  | Network statements | n/a | `advertise-network` (advertised when the prefix is in the router's config RIB, or always with *always advertise network route*) |
  | Export/import filters | `policy/export` and `policy/import` rules (prefix match, exact or longer) | filtering profiles: inbound/outbound prefix lists, distribute lists (access lists) and route maps that match prefix lists; implicit deny at the end of a list |
  | Aggregates | `policy/aggregation` (summary or not) | `aggregate-routes` (summary-only) |
  | Conditional advertisement | `policy/conditional-advertisement` (non-exist filters + advertise filters) | filtering profile `conditional-advertisement` exist / non-exist (advertise map + exist/non-exist map) |
- **How routes spread.** Firewalls whose peer addresses are each other's interface addresses exchange routes directly. Firewalls whose eBGP peers share a provider AS (or whose iBGP peers share a local AS) join one provider fabric (MPLS): a prefix one member advertises is learned by every other member with **its own** PE as next hop. Re-advertisement follows the BGP rules (eBGP-learned routes go to all peers, iBGP-learned routes are not re-sent to iBGP peers), and a router never learns its own prefixes back.
- **Aggregates** are advertised when at least one more-specific route exists in the router's table. With *summary only*, the more-specifics are held back.
- **Conditional advertisement** is evaluated against the advertising router's config routes plus what FlowMapper inferred. The result is marked **low confidence**, because the condition depends on the live table (a primary link can go down).
- **Withheld routes are explained.** When a filter, summary-only aggregate or condition stops a prefix, the router remembers why. A change card that adds a route there says, for example, "BGP: dc1-core-fw does not advertise 10.10.9.0/24 to 10.200.0.2: prefix list PL-NO-MGMT denies it".
- **Two firewalls with the same peer address.** When a BGP peer address is configured on several firewalls, the same-site one is used; otherwise the peer is counted as ambiguous (`inference.ambiguousPeers`) and not used.
- **Result.** Routes typed `inferred-bgp` / `inferred-ospf` with the matching admin distance (eBGP 20, iBGP 200, OSPF 30/150). Static and connected routes still win on equal prefix. They are marked medium confidence (low for conditional ones), labelled "BGP"/"OSPF" in the flow diagram and the Config browser, and each carries its reason. A checkbox hides them. The **Route tables** panel lists every BGP router found (engine, AS, peers, redistribution, networks, aggregates, filters, conditions).
- **OSPF** (legacy VRs): non-passive OSPF interfaces on a shared subnet form an adjacency. Networks on OSPF interfaces are advertised and can be redistributed into BGP and back.
- **Not modelled.** AS-path and community matching, MED / local-preference / weight tie-breaks (best path is admin distance then prefix length), route-reflector clusters and confederations, BFD and timers, IPv6 address families, OSPF/OSPFv3 on advanced routing, provider VRFs and route targets (peers with the same provider AS are assumed to be one domain).
### Route tables: paste what the firewall actually learned

**In plain words.** If a guess is wrong, or you just want certainty, run one command on the firewall and paste the output. FlowMapper then uses the real routes for that firewall. Nothing leaves your browser, and nothing is saved when you close the page.

**How.** Open **Route tables (actual learned routes)** under the file list, pick the firewall, then paste or upload one of:

- `show routing route` (legacy engine),
- `show advanced-routing route` (advanced routing engine),
- the XML API answer to `<show><routing><route/></routing></show>`,
- a TSF-derived table or any CSV with columns `destination,nexthop,interface,protocol[,virtual-router]`.

**Technical detail.** Only active IPv4 routes are used (flag `A` / `*`). PAN-OS prints flags run together (`A?B` = active, loose, BGP; `A Oi` = active, OSPF intra-area); both forms are read, and a BGP route that lost to a better static route (` ?B`, no `A`) is ignored. Connected and local routes are skipped (the config already has them). Static routes already in the config are not duplicated. Every other route is added as `learned-<protocol>` (for example `learned-bgp`) with the proper admin distance and the pasted label as its source. A router that has a pasted table **stops receiving inferred routes**: actual learned routes always win over inference. Routers are matched by name (`virtual-router`/`logical-router` column); a firewall with one router takes the whole table. Unmatched router names are listed as notes. Hops that use pasted routes are high confidence, and a path made only of explicit and pasted hops is **Complete (pasted route table)**. Remove a table to go back to inference.
### Same IP on several firewalls (cloned builds, overlapping space)

**In plain words.** Some networks reuse addresses: two data centers built from one template, or two sites with the same internal ranges. When the path reaches an address that more than one firewall owns, FlowMapper cannot know which firewall the traffic really reaches, so it **asks you**. It never picks one silently.

- **Overlapping address space callout.** Right under the file list, a yellow box lists every interface address configured on two or more firewalls and every subnet that overlaps across firewalls, plus look-alike firewalls (same addressing) with the reason they were *not* treated as an HA pair.
- **Picker.** The trace banner says **Needs your choice** and shows a table per decision (next hop, source or destination): one row per candidate firewall with hostname, serial, template stack, site and why it fits (for example "has 10.99.0.2 on ethernet1/1 (zone core)").
  - **Use for this trace** pins that firewall for this trace only.
  - **Save as link** (next hops) saves a custom next-hop link, so every later trace from that interface goes to that firewall. Links are saved in the browser and can be exported.
  - Pinned decisions stay listed as "Pinned: ..." with the source of the pin (your choice, a saved link, or your destination choice). The trace is then Complete or Suggested as usual.

**Technical detail.** The graph keeps one next-hop edge per owning firewall (no last-wins), and `FM.sharedIpChoices` reports every stitch whose next hop has two or more owners, and every source/destination that sits in subnets connected on several firewalls with the **same** gateway address. Two firewalls on the same subnet with different addresses are a shared segment, not an overlap. Pins: `opts.choices[key]`, `opts.dstDevice`, `opts.srcDevice` or a link (`{from:{device,iface,nexthop},to:{device,iface}}`).

**HA is not inferred across sites or stacks.** HA settings in the config win. Without them, two firewalls with identical addresses pair only when they are on the same template stack, match only each other, *and* their hostnames name the same site (`core-dc1-fw` and `core-dc2-fw` never pair; `fw01` and `fw02` at one site can). Look-alike firewalls at different sites never pair.
### Changes needed at a glance, and ticket export

Every trace starts with a summary: one line per firewall and vsys on the path. It shows the zones, whether an existing rule already allows the flow (and which one), and what has to change there: a rule to add, a route to add, or a zone. When an existing allow rule in the same zones misses the flow on exactly one field (source, destination or service), the change also offers adding that one member to the existing rule, with CLI. This is often the smaller change.

**Export for ticket (HTML)** downloads a printable page with the summary, the path (interfaces, zones and the basis of each hop), every change with its CLI, and the warnings. **Export CSV** gives one row per change (firewall, vsys, device group, rule fields, CLI) for a change-management system. Both are built in the browser from the loaded config; nothing is sent anywhere.

### Routing decides, rules break ties

Each hop is decided in this order:

1. **Explicit config routing:** connected subnets, static routes, `next-vr`, PBF, your links and pins, and HA pairs. When these give a unique next hop, that hop is final.
2. **Inferred BGP/OSPF routes** (see below).
3. **Rule and NAT evidence**, only to break ties between equally valid routing options, to place an address that no specific route covers, and to pick an internet edge. Evidence never overrides a more specific explicit route.

A rule path is still accepted when it passes through the firewall that routing names and obeys routing on every hop. A specific route only says an address is *behind* that firewall, so the rules can show where it actually enters. Such paths are marked *extends routing via rules*.

- **Routing says X, rules suggest Y:** sometimes the allow rules point at a path that routing would not take. For example, a narrow rule on a firewall that would have to send the traffic back out the interface it arrived on, toward a firewall on the same subnet. The trace still follows routing. A notice (in the trace and the *Why this path* panel) shows both paths, the rules involved (firewall, vsys, zones) and the route entries that contradict them. **Trace alternative** shows the rules' path, and **Back to the routing path** returns. These are usually stale rules, or routing that is not what the rulebase expects, so they are worth reviewing.
- **Ambiguous: fw-A or fw-B:** when the best paths differ only by which of two parallel firewalls (not an HA pair) carries the flow, and routing and rule evidence fit both about equally, the trace does not pick silently. A banner at the top names both, with *Trace via* buttons for each. Changes needed and the ticket exports note that rules are needed on whichever of them carries the flow (or both for redundancy). A matching rule on one of them settles it.
- **Why each hop:** every firewall in the chain and diagram states its basis with a confidence: *static route 10.0.0.0/8 via 10.1.1.1 out ae1.10 (vr-core)*, *connected*, *default route*, *BGP inferred*, *PBF*, *rule evidence*, or *no route, suggested route*. Each link between firewalls says how the next firewall was chosen: *routing*, *routing, then rule evidence between equally valid options*, *user link*, or *your choice*.
- **Validate with existing rules** counts flows where routing and rules disagree and lists them (*Show them*). A rule whose flow only passes along the rules' path is filed as *routing disagrees with rule*.

### Rules as path evidence, internet edges and HA pairs

Routing alone often cannot tell which of several firewalls a flow crosses, because the routers and switches between them are not in the config. The rulebase is the other half of the picture: if a firewall has a specific allow rule for this source and destination, the traffic very likely passes through it.

- **Rule evidence:** every enabled allow rule that matches the flow (source, destination, service) with a specific address on at least one side counts as evidence for its firewall. Narrow rules on few firewalls weigh more than broad rules pushed to many. The weight only counts in full where the path enters and leaves that firewall through the rule's own zones. Paths through the evidence firewalls are always tried, and evidence outweighs a few extra hops of path cost. The *Why this path* panel lists the rules that were used.
- **Placing addresses:** a source or destination that no firewall has connected (behind routers) is placed on the firewall whose allow rule names it, provided the rule's zone interface really routes it (connected, or a route more specific than the default for a destination).
- **Internet edges:** public addresses enter and leave at internet edges. A firewall is an edge on the interface that carries its default route when that route goes to a public next hop, the interface has a public address, or the zone is named like the internet (untrust, outside, internet, isp...). A firewall is also an edge when one of its rules allows the public address through the zone that carries its default route. A default route toward another firewall or into the WAN/MPLS core does not make an edge. Edges with a matching rule or a destination NAT rule for the address are preferred, so *internet → edge (DNAT) → DMZ* comes out by itself.
- **HA pairs:** a missed pair only shows as two firewalls, but a false pair hides one, so pairing is strict.
  - **HA settings first.** FlowMapper reads `deviceconfig/high-availability` after the template and stack merge, with per-device `$variables` resolved: enabled, `peer-ip` and `peer-ip-backup`, and the HA1 and HA1-backup addresses.
    - Two firewalls whose peer-ip settings point at each other's HA1 or interface address are a pair. That holds even across template stacks, because the config says so.
    - A one-way peer-ip is enough only when it names exactly one other firewall's own HA1 address.
    - A firewall with HA disabled, or whose peer-ip names a different firewall, is never paired by inference. Neither are two firewalls whose HA addresses contradict each other.
    - A peer-ip that three or more firewalls share (a template literal with no per-device variables) is ignored. So is a variable that does not resolve.
  - **Otherwise, inference.** When there is no usable HA setting, two firewalls are one hop only when all of these hold:
  - they are on the same template stack. Different stacks mean different sites and never pair. If only one has a stack, the stack is not used either way;
  - **active/passive:** their interface addresses are nearly the same on both sides (at least 2 shared and at least 80% of the larger set), or, **active/active or cluster:** same stack, same device groups, and the same subnets on the same interfaces (at least 3 and 80% of the larger set, or identical sets);
  - each matches only the other. When three or more firewalls share the same addresses or subnets (a repeated design, such as branches built from one template or data centers with copied addressing), none of them are paired;
  - a group is never more than two firewalls, and names are never used.

  The trace uses the first one and shows the peer as *(HA: name)* in the chain and diagram.

### Validate with existing rules

The rulebase is also a test set. **Validate with existing rules** (Trace tab) turns each enabled allow rule with concrete addresses into one flow. It uses the first host of the rule's source and destination and the first port of its service. A rule with source *any* from an internet-facing zone gets a public probe address. The tool traces each flow and checks that the path crosses one of the rule's firewalls through the rule's zones. You get a pass rate, failure categories and a list of failures. Click **Trace** on a failure to see the path the tool picked and why it misses the rule.

- **Leave the replayed rule out:** a stricter mode. The rule being replayed is not used as evidence, so the result shows what routing and the other rules predict on their own.
- **Failure categories:**
  - *routing bypasses the rule's firewalls:* routing keeps the replayed flow on firewalls that do not carry the rule. This is common for broad rules pushed to many firewalls.
  - *destination owned by another firewall:* routing or another rule puts the destination behind a different firewall.
  - *source is the firewall's own address:* the rule's source is an interface address of its own firewall. Traffic the firewall originates is not matched by security rules, so the rule is probably meant for something else, or is stale.
  - Harness `--dnat` adds an **inbound-DNAT** check. It takes allow rules whose destination overlaps a destination NAT rule's original address on the same firewall (same from-zone, overlapping source). It replays each one twice, once by the public address and once by the translated private address, and prints both pass rates with failure categories.
  - *rule uses pre-NAT zone (DNAT):* the rule's to-zone is the zone of the original destination, but with destination NAT PAN-OS matches the post-NAT zone. The trace says so too.
  - *routing disagrees with rule:* the flow only crosses the rule's firewall along a path that routing would not take (see *Routing says X, rules suggest Y*).
  - *chain does not reach rule's firewall*
  - *wrong from-zone / wrong to-zone:* the right firewall, but through other zones.
  - *routing gap*
  - *rule's firewall has no network config:* the device group has a device with no template stack. Load that firewall's local backup alongside the Panorama export to trace through it.
  - *pass (ambiguous parallel firewalls):* the trace flagged two parallel firewalls, and the rule sits on the alternative one.
- **Zone findings (cleanup list):** the button next to *Run validation* lists allow rules whose source or destination object never routes to the rule's from/to-zone on any firewall that carries the rule. PAN-OS takes the from-zone from the interface the source routes to, and the to-zone from the egress interface toward the destination. So that object never matches that rule there: a stale object, a wrong zone or a missing route. An object routed into another vsys counts as the external zone that lists that vsys. Destinations behind destination NAT are skipped, because the post-NAT zone decides. Rules pushed to many sites are only flagged when the object fits the rule's zones on none of them. Export as CSV or HTML. Harness: `--findings`, plus `--zonediag` for a per-case zone breakdown (template parts, interface subnets, rule targets).
- **Trace this rule:** in the Config browser, the button next to each security rule traces that rule's representative flow. It also says whether the path goes through the rule.

The same replay runs from the command line, which is useful on a large export or a machine without a browser:

```
```

The harness prints counts, pass rates (with evidence, leave-one-out, routing only) and failure examples. Firewall serials in the examples are replaced by fw-01, fw-02... Rule, zone and address values are printed as they are in the file, so use it on a pseudonymized copy if the output leaves the machine. Its output can contain rule names and addresses, so treat it like the config. `ROUTING-STATS` counts how often routing overrode the inferred plan, how often a route had to be suggested, and how many traces reported a routing/rules conflict. `--conflicts N` prints N such conflicts. `--percase` writes one line per replayed rule (for diffing two runs), and `--core` runs another engine build. `--diag` re-traces each failure pinned through the rule's firewall to show whether the miss is a ranking problem (it passes when pinned) or a connectivity gap.

The validation summary also counts the path status of the replayed traces: how many are complete, suggested (some hop assumed) or incomplete. Adding links and public-space map entries should move suggested traces to complete.

### Inter-vsys without external zones

`next-vr` to a VR that belongs to another vsys counts as an inter-vsys hop (rules in both vsys) only when PAN-OS would allow it: the vsys lists the other one in `visible-vsys`, an external zone exists, or a shared gateway is used. Otherwise traffic is assumed to **hairpin**: it leaves one vsys through an interface, an outside router or switch sends it back, and it enters the other vsys. This is detected when:

- the next hop is an interface of the same firewall in another vsys (high confidence),
- or the two VRs have interfaces in a shared transit subnet (medium),
- or the destination is connected (or has a more-specific route than a default) on another vsys of the same firewall, and traffic leaves toward an outside next hop that no loaded firewall owns (medium). The packet is assumed to re-enter that vsys through its WAN-side interface. This covers environments with no external zones and no shared subnet, where each vsys only has a point-to-point link toward an unseen router.

The diagram draws a "HAIRPIN (outside)" or "HAIRPIN via unknown network" box and lists rules in both vsys. With neither a permitted on-box hand-off nor one of the hairpin conditions, an error explains that the next-vr cannot be used.

## Decommission: retire a server or stop its traffic

Open the **Decommission** tab, type what is being retired (IPs, subnets,
ranges, FQDNs, object, group or rule names; one per line) and pick an intent:

- **Remove references**: the server is gone. Clean it out of rules, groups and objects.
- **Stop traffic**: make sure nothing still lets a flow through. Type the
  flows (`source destination tcp/443`, or paste an FCR CSV).

Real configs are messy, so every finding gets a grade, with the reason, the
evidence and the blast radius (other addresses, rules and groups it touches):

| Grade | What it means | Examples | In the plan? |
|---|---|---|---|
| **Exact (100%)** | It IS the target | same host, prefix, range or FQDN; the object, group or rule with that name; the value typed in a rule; a group left empty when its exact members go | Pre-ticked |
| **Highly likely** | Built for the target, not identical | a /30, /31 or range of up to 4 addresses holding it; a /28 or smaller whose name or description names it (or names its object, say `app01`); a group named for it whose members all point at it; a NAT rule translating to it; an object used only by a rule you are deleting; a negated field that lists it | One click |
| **Possible** | It only falls inside something broader, or overlaps it | the /24, /16 or /8 the host sits in; `any`; an FQDN object whose name mentions it | Never: advice only |

What the plan will and will not do:

- It never deletes or edits a broader object (a /16) because a /32 inside it is retired. Possible items show what to do instead: leave it, carve the host out as a separate change, or use **Stop traffic**.
- It removes the target from a rule or group only if other members remain.
- If a rule's source or destination would end up empty, PAN-OS would read it as **any**. The plan never does that. It deletes the rule if every member was an exact match. Otherwise it disables the rule. Either way the change is shown in red.
- A negated field ("everything except X") is left alone unless you tick it. Removing X would make the rule start matching X.
- An object is deleted only when nothing in the loaded configs still uses it. Anything kept is listed with the reason, for example "still used by NAT rule ...".
- The order is rule edits, rule deletes, group edits, group deletes (outer first), then objects. Child device groups come before parents, and shared objects come last.
- **Stop traffic** traces each flow and checks every place on the path with the plan applied. It grades each rule that would still allow the flow (definite, likely or possible), including redundant broad permits elsewhere in the config. In each place it adds a narrow deny (exact source, destination and port, targeted to that firewall) directly above the first permit. Each deny comes with a `test security-policy-match` command.

Exports: CSV, Markdown, `set` commands and rollback commands. PAAT runs the same engine (`build/decom.js`) and can push the plan through
its approval flow.
## Firewall change requests (FCR)

Use this when you have a requested flow (source, destination, port/application) and you need to change policy once, correctly, instead of pushing a rule, discovering another vsys still denies, and pushing again.

1. **Load the configs.** Drop a Panorama export and, for any firewall whose network is missing from that export, that firewall's own backup XML. Local backups are matched by serial (including a single 12–16 digit serial in the filename) or hostname. Nothing is uploaded; the page stays in the browser.
2. **Paste the FCR.** On **Trace a flow**, open *Firewall change request (FCR)*. Paste one line (`10.1.1.10 -> 10.2.2.20 tcp/443`), `src:` / `dst:` / `port:` fields, or a CSV with a header such as `source,destination,protocol,port,application,ticket`. You can also load a `.csv` file. *Parse and trace* fills the trace form and runs it. A CSV with several rows traces up to 50 flows and lists hop counts and denies; click **Show** for one of them.
3. **Read the path.** The result names every firewall and vsys on the path, with a per-hop verdict (allow, deny, or conditional). **Why these vsys** explains how many vsys are crossed, and when traffic hairpins through an outside router or an unknown WAN/MPLS core (there is no on-box hand-off with an external zone, `visible-vsys` or shared gateway). A later vsys can still deny after the first rule is added — that is the point of doing them together. The same applies to **one firewall checked twice**: one vsys with two virtual routers and no `next-vr` between them, where the flow leaves one router toward an outside router and comes back in on the other. A red *Rule needed in more than one place* box (on screen, in the batch table, in the ticket HTML and in the CSV) says how many places check the flow, lists each place, and says which still need an allow. Each hop also carries its virtual router (`vr`) and ingress/egress interfaces for FIB lookups.
4. **Use the combined change plan.** *Changes needed* lists every hop in path order, with object reuse and `set` CLI. For Panorama, placement uses the device group of that vsys. If the device group lists `vsys1`…`vsysN` and the template uses different vsys names, the tool joins them by an exact name or display-name match when it can, otherwise by order and count, and **flags the placement as uncertain**. Confirm those joins before you commit. Under each new rule, **Rule order** says where it must sit: above the deny that blocks it today (the CLI includes the `move ... before` line), or "position does not matter" when only the default rule blocks it. Export the ticket (HTML or CSV) for the change request; the HTML includes the explanation, verdicts, checklist and log filters.
5. **Pre-push checklist.** Save a named snapshot, commit to Panorama first, push only the device groups in the plan (do not Push All), check shadowing, NAT, PBF and the return path, and confirm any inferred vsys join.
6. **After the push.** Each hop has a traffic-log filter (`addr.src`, `addr.dst`, `proto`, `port.dst`, `vsys.name`, `zone.src`, `zone.dst`, and the new rule name when one was suggested; the zones tell apart two passes through the same vsys). Use it on that vsys (or in the Panorama traffic log) to confirm the new allow or to see a later deny. Under each filter are the two commands to paste on the firewall itself, `test routing fib-lookup` and `test security-policy-match` (the lab GUI's live check runs the same two tests for you).

## Redacted diagnostics (optional)

**Export redacted diagnostics** (top right) downloads a JSON file with the structure only. It contains device, vsys, zone and interface counts, interface types, routes and subnets, the links you added, and graph statistics. Firewall, vsys, zone and router names are replaced (`fw-1`, `zone-7`). IP addresses are pseudonymized with a prefix-preserving keyed mapping, so shared subnets and route coverage are kept. The key is random for each export and is never stored. The file has no rules, objects, comments or secrets. Zone names keep only generic hints such as `mpls` or `wan`. Nothing is sent anywhere. Share the file only if your policy allows it. The tool never requires it.

## Panorama

- **Device groups**: the full hierarchy, read from `readonly` `parent-dg`. Policy order is shared pre → parent DG pre → child DG pre → child DG post → parent DG post → shared post → default rules. Objects resolve DG → parent DG → shared. Rule `target` (devices, vsys, negate) is honored.
- **Templates and template stacks**: templates are merged in stack priority order, with the stack's own config on top. **Template variables** (`$wan-ip`) resolve per device, then stack, then template.
- **Mapped devices only**: a firewall is in the trace set only if a template stack or device group lists its serial. Stacks without devices and templates outside any stack are hidden by default (*show unmapped* lists them). A firewall in a device group but no stack is kept for policy, without network config. The device table, any trace whose flow its rules cover, and Validate say so: *"No network config in this Panorama export for <fw>. Load this firewall's local backup alongside the Panorama export to trace through it."*
- **Panorama plus local backups**: load a firewall's own backup together with the Panorama export and the two become one device, matched by serial or hostname. If the local XML has no serial of its own, a single 12–16 digit token in the filename is used (for example `running-config_010000000042.xml`). Two such tokens in the same name are not guessed. When both have a network, interfaces, zones and static routes are unioned: template-only routes are kept, and a local value wins on an exact conflict (same interface name, or the same virtual router, destination, next hop and metric). The config browser shows whether each static route came from the Panorama template or the local backup. If the Panorama export has no network for that firewall, the local file supplies it in full. Policy runs in PAN-OS order: Panorama pre-rules, then the local rules, then Panorama post-rules. Objects resolve local first, then DG and shared. The device-group override list is filled when opened, with the groups used by managed firewalls first.
- **Device-group vsys names**: a device group often lists `vsys1`…`vsysN` while the template uses descriptive vsys names. The tool joins them by an exact vsys name or display-name match when it can. If the unmatched counts are equal, it joins by order (vsys number to template order) and flags the result as inferred. If the counts disagree, it does not guess, and the change plan marks placement as uncertain. Confirm those joins before you push.
- **Static routes**: routes are read from `routing-table/ip/static-route` (current PAN-OS) and from the older `vr/ip/static-route` and `vr/static-route` layouts.
- **Per-device and per-vsys mapping**: each serial in a template stack becomes a device. It is paired with its device group by serial, and **per vsys** where the DG `devices` entry lists vsys. Hostnames come from `mgt-config/devices`. You can override the DG of a device.
- **Many devices**: all managed firewalls are in the trace set by default, so a search finds which firewall and vsys the source and destination sit behind, then finds the chain between them. The device table has a filter and All/None buttons, so you can narrow the set or pick one start device.
- **Scale**: the XML is parsed in time slices with a progress display, so the page never freezes while a large export loads. A synthetic export shaped like a large real one (11 MB, 589 device groups, 344 templates, 322 stacks with most unmapped, 67 managed firewalls, 55 BGP-only branches on MPLS) loads, models and infers routes in about 0.6 s in Chrome. The longest main-thread block is about 0.3 s (route inference), so no Web Worker is needed. Inflated to 31 MB with 250k shared objects, it takes about 1 s.

## How to get the config file

- **Firewall (GUI):** Device → Setup → Operations → *Export named configuration snapshot* → `running-config.xml`.
- **Firewall (CLI/API):** `scp export configuration from running-config.xml to user@host:/path` or the XML API `type=export&category=configuration`.
- **Panorama:** Panorama → Setup → Operations → *Export named Panorama configuration snapshot* → `running-config.xml`. This contains device groups, templates and stacks.
- A Panorama-managed firewall's own `running-config.xml` does **not** contain pushed policy. Load the Panorama export instead, or export the merged config (`show config merged`) from the firewall.

## Limitations (read before trusting a result)

- **Dynamic routing** is inferred from config, not simulated (paste a route table for the real thing). BGP is read on legacy virtual routers and advanced routing logical routers; prefix lists, access lists, route maps that match prefix lists, aggregates and conditional advertisement are applied, but AS-path and community matches are ignored, and BGP best-path selection is just admin distance plus prefix length. OSPF on advanced routing is not inferred. Provider PE VRFs and route targets are not visible, so all peers with the same provider AS are assumed to share one routing domain. OSPF areas are merged, and RIP is not inferred. DHCP-learned addresses and default routes are not in the config. A missing return route on a router running a dynamic protocol is marked as *verify*.
- **Hairpins** assume the outside router forwards the traffic back. Rules or ACLs on that router are not visible.
- **App-ID, User-ID, HIP, URL categories, FQDN objects, EDLs, regions and dynamic group members** are runtime data. Rules that depend on them are shown as *conditional*. `application-default` is matched against a built-in table of common app ports plus any custom apps in the config.
- **IPv4 only.** IPv6 objects and routes are ignored.
- **Layer 3 only.** Virtual wire, layer 2 and tap zones are listed but not traced.
- **The firewall chain is inferred** from interface subnets, static routes and naming, because routers, switches and MPLS are not in the config. Check the confidence per hop, the *Why this path* panel and the Network map. Use links or pins when the guess is wrong. Firewalls without BGP/OSPF config or static routes link up only through private next hops or naming hints, at lower confidence. A firewall in the chain that the inferred router would not actually forward to (for example a VRF or route policy in the WAN) cannot be detected. Asymmetry is checked per firewall: does its own reply route leave the way the traffic came in? The return path through the WAN is not simulated.
- **ECMP:** the first equal-cost route is shown and a warning is added. Path monitoring, route redistribution and PBF symmetric return are not simulated.
- **NAT pools:** for a pool, the first address is shown. Wildcard address objects are not evaluated.
- **Panorama:** the CLI snippet names a template placeholder for template changes (it can't know which template in the stack you prefer). It assumes the device group shown is the one to edit. When that group was joined from a `vsysN` list to a differently named template vsys by order and count, the placement is flagged uncertain and must be confirmed.
- **Same-box re-entry through an unknown router** assumes that router forwards the packet back into the destination vsys. Filters, VRFs or policy on that router are not visible. BGP and OSPF routes learned at runtime are still not in the config (only inferred from peer configuration where supported).
- **Rule evidence assumes the rulebase reflects real traffic.** Routing comes first, but where routing is ambiguous (several firewalls behind the same inferred WAN core), stale or overly broad rules can still pick the wrong one. Conflicts are only detected where some route contradicts the rules' path. Inside the inferred core, *would send it back out the interface it arrived on* is a heuristic. Rules on many firewalls (pushed from a parent device group) weigh little, and rules with *any* on both sides are ignored. Pin a firewall or add a link when you know better.
- **HA detection** uses the HA settings when they name a loaded firewall uniquely. Otherwise it falls back to matching interface addresses (or, for active/active, the same stack, device groups and subnets), and only between exactly two firewalls on the same template stack. Panorama exports often leave out the peer's HA1 address, or set it only in the device's local config. In that case the HA settings can't confirm a pair, and inference decides. Real pairs are missed (shown as two firewalls) when the export has no network config for them, when they sit on different stacks, or when a third firewall reuses the same addressing. Two distinct firewalls on the same stack and at the same site (by hostname) with nearly identical addresses, and no third look-alike, would still be paired. Firewalls whose hostnames name different sites are never paired by inference.
- **Ingress VR:** where the arriving interface is unknown, a hop is checked against the firewall's best route across all its VRs, which can miss a VR-specific route.
- **Discard routes** (for example a blackhole default in a DMZ vsys) are treated as real drops, so flows the rulebase allows can show as *routing gap*.
- **Validation replays one flow per rule** (first host, first port; a different pair is picked when source and destination would be the same host). A rule that covers many networks passes or fails on its first one. Rules with FQDN/EDL destinations, destination *any*, or source *any* from inside zones are skipped and counted.
- **Generated CLI is a starting point.** Review object names, rule placement, security profiles and logging before you commit.
- Always confirm on the box with `test security-policy-match`, `test nat-policy-match` and `test routing fib-lookup`.
