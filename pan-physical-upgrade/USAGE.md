# Usage: PAN Physical Upgrade Planner

The planner reads a Palo Alto Networks tech-support file (TSF) from the old firewall, sizes a replacement, lists the
hardware and licenses to quote, converts the config to the new model, and writes a report and a cutover runbook. It runs
only in your browser. Nothing is uploaded.

## Before you start: what to collect

You need two things from the old firewall. Only the first is required for sizing; the second is needed for a conversion
you can actually load.

### 1. A tech-support file (required)

- **GUI:** Device > Support > **Generate Tech Support File**, wait a few minutes, then **Download Tech Support File**.
- **CLI:** `scp export tech-support to user@host.example.com:/tmp/` (or `tftp export tech-support to <host>`).
- **HA pair:** take it from the **active** unit. It has the live session and throughput data.
- **Panorama-managed firewall:** generate it on the firewall (its own web UI, or Panorama's Context switch). A Panorama
  tech-support file is a different thing.
- Treat the file as sensitive. It contains hostnames, serial numbers, IP addresses, usernames and the running config.
  Do not post it, e-mail it or commit it. More detail in [docs/COLLECT_TSF.md](docs/COLLECT_TSF.md).

### 2. A real configuration export (for a config you will load)

A tech-support file holds the running config with every secret replaced by `********` (admin password hashes, private
keys, pre-shared keys, RADIUS/TACACS+/LDAP secrets). **PAN-OS refuses to load a config in that state.** `validate full`
answers *"This config has been sanitized of password data because it was exported by a non-superuser or was part of a
tech support export. Please use a non-sanitized config."*

So, for a conversion you will actually load:

1. Sign in to the old firewall as a **superuser** (a limited role exports masked values too).
2. Device > Setup > Operations > **Export named configuration snapshot** (choose `running-config.xml`), or use
   `scp export configuration from running-config.xml to user@host.example.com:/tmp/`.
3. Keep that file for step 5 below ("Real exported config" on the Convert tab).

Without it the tool still sizes, lists hardware and licenses, and converts. The converted file is then good for checking
references and structure, but encrypted values stay as placeholders and the new firewall will not accept the file.

## Quick tour

1. Open `pan-physical-upgrade.html`, drop the TSF on the page.
2. Walk the seven tabs from left to right. Every tab shows its sources and says **not in file** instead of guessing.
3. On Convert, load the real export, convert, download the XML and the change log.
4. Export the report (finance/sales) and the cutover runbook.

## Load the file

Open `pan-physical-upgrade.html` and drop the old firewall's tech-support file on the page
(`.tgz`, `.tar.gz` or `.zip`). For an HA pair, use the TSF from the **active** unit.
A `running-config.xml` also works, but then there is no usage data for sizing.

The page is **offline by default** and never contacts the network on its own. The badge in the header shows which model
catalog is in use: **bundled** (inside the page), **online** (a newer copy, only after you click **Check for newer
catalog**; this reloads the page in online mode), or a file you loaded with **Catalog file**. The **Help** button
(next to **Dark**) opens a built-in guide.

## Tab 1: Current device

- Status line: model, PAN-OS, sale/support status, HA, Panorama and vsys.
- **Usage vs. this model's capacity**: now (one snapshot from `show session info`), peak
  (from the `dp-monitor` logs in the TSF, about every 10 minutes for the last few days), the
  datasheet figure, and how full the box is. "Not in file" means the TSF did not include it.
- **Interfaces**: mode, zones, subinterfaces, media (from `show interface ethernetX`), link speed,
  and average in/out. Average use = byte counters ÷ uptime, so it shows how busy a port is on
  average, not its peak.
- Tick **Hide serial numbers** before you share screens or the report.

## Tab 2: Pick the new firewall

- **What the new firewall must handle**: measured peak + headroom. Type a number in any box to
  override it. Sizing uses Threat Prevention throughput when threat services are licensed
  (untick to size on firewall throughput).
- **Suggested**: the smallest currently sold model that fits everything, a next step in a
  different series, and a VM-Series size. **Why not smaller?** lists what each smaller model is missing.
- **Pick any model** to compare your own choice. The matrix shows needed vs. today vs. proposed,
  plus the minimum PAN-OS version for the target.
- **Panorama rule**: Panorama must run the same or a newer PAN-OS than the firewalls it manages.
  Upgrade Panorama first if the new model needs a newer release.
- **HA pair on the new firewall** defaults to on when the old firewall is in HA.

## Tab 3: Hardware & cabling

Everything finance needs so power cords, optics and HA cables are not missed. No prices.

- **Power.** How many power supplies the old firewall had (read from the tech-support file when it lists them,
  otherwise from the catalog and marked so), what the new model ships with, and how many it can take. If the old
  firewall was redundant and the new one ships with one supply, an optional second supply and its cord are added
  and called out. Cords are counted per supply, ×2 for an HA pair. You can change the number.
- **Interface changes.** Each mapped port is compared with its new port: speed down/up, copper ↔ fiber, and cage
  changes (SFP → SFP+, QSFP+ → QSFP28 and so on). Optics seen in the old firewall are listed when the file has
  them. Existing optics are reused only when the cage fits and the speed does not change.
- **Optics and cables to quote.** Grouped by form factor (SFP, SFP+, SFP28, QSFP+, QSFP28, QSFP-DD) and copper
  patch cables, for data ports and for HA links. Choose the type (SR, LR, DAC, copper SFP) and edit quantities.
  Fiber type and the far-end device are not in a tech-support file, so the type starts as "to be chosen".
- **HA cabling.** For each HA link: the old and new port, and what to connect. A dedicated RJ45 HA port takes a
  plain Ethernet cable; SFP+/QSFP HA ports need optics (2 per link) or a DAC. Models without dedicated HA ports use
  data ports.

## Tab 4: Licenses

1. **Review.** Every license in the file with expiry and status, a Keep/Drop choice, and a hint from the config
   (for example GlobalProtect with no portal, or a URL filtering profile no rule uses). The hint is only a hint.
   Active licenses default to Keep and expired ones to Drop.
2. **Add or change.** Subscriptions currently sold for the target, none ticked by default, plus support tier and
   extra virtual systems. Wording is neutral; where an Advanced subscription overlaps one you hold, it says to check
   with the account team.
3. **List for the quote.** Kept + added items ×2 for HA, and what was dropped. The report uses this list.
   Auth codes and license serials are never shown.

## Tab 5: Convert config

1. Check the port map. Each old interface gets a port on the new model; the check column warns
   about speed or media changes (for example a 10G link on a 1G port). Pick **don't migrate** to leave
   an interface out. References to it are removed (list members) or flagged (single values).
2. For HA, pick ports for HA1/HA2 links if the new model has no dedicated HA ports. The tool suggests
   free copper ports and sets them to type HA.
3. Choose the mode. **100% conversion** changes only the interface map (and what the new hardware requires).
   **Customized** adds: hostname, management IP/netmask/gateway (and IPv6 if the config has it), DNS servers,
   standalone (remove Panorama), and an optional **break-glass local admin**. Customized mode warns when the old
   management IP is still referenced (permitted IPs, service routes, objects), when a Panorama server is set, and
   when the hostname is unchanged.
4. Break-glass admin: a local account whose password is stored on the firewall and that uses no authentication
   profile, so it still works if TACACS+/LDAP/RADIUS fails after the commit. The password is typed in the page and
   hashed in the browser as SHA-256 crypt (`$5$`, the format current PAN-OS exports use). Only the hash goes into
   the XML. Neither the password nor the hash is stored, logged, or shown in the change log; the field is cleared
   after you convert. Roles offered: superuser, superuser (read only).
5. Click **Convert config**, then download the XML and the change log CSV.

**Fix before you commit** lists anything the tool could not place. **Encrypted values to check**
lists certificate private keys, pre-shared keys and server secrets: they only work if the new
firewall uses the same master key (set it first, or re-enter them).

Port numbering for models other than the PA-440 is assumed from the datasheet order. If your hardware
differs, open **Edit the target port list**. For VM-Series, set the number of data vNICs.

### Load it on the new firewall

1. Install the target PAN-OS version (same as or newer than the old firewall).
2. Device > Setup > Operations > **Import named configuration snapshot**.
3. **Load named configuration snapshot** (changes only the candidate config).
4. **Validate commit** (CLI: `validate full`). Fix what it reports.
5. Check licenses, certificates and HA, then commit.
   Panorama-managed: add the new serial in Panorama and push the template stack and device group.

**Real exported config.** If the tech-support file has masked secrets (`********`) the tool says so. Export the
config from the firewall (Device > Setup > Operations > Export named configuration snapshot, as a superuser) and pick it
under "Real exported config" on this tab. The file stays in the page, is not saved in a plan, and replaces the tech-support
copy for the conversion. A file that still has masked values is refused.

## Tab 6: Readiness checks

Everything to check before you commit to the plan, for the model you picked on step 2:

- **PAN-OS version and upgrade path.** Which release to install on the new firewall before the import (same feature release as the old firewall or newer, and at least the model's minimum), a blocker if the old config is newer than the last release the model supports, HA peers within one feature release, Panorama same or later, and the Skip Software Version Upgrade notes. Legacy IKE/IPsec algorithms found in the config are listed.
- **What will not move with the config.** Built from the config in your file: certificates and private keys, encrypted secrets (counted, never shown), authentication servers, VPN pre-shared keys, User-ID agents. Always listed: master key, licenses, content versions, sessions/ARP, logs, API keys.
- **Panorama-managed firewalls.** Move the serial, device group and template stack, push order, and local versus pushed config. Only shown when the config points at Panorama.
- **Features and platform differences.** Config features the target may not support, from the Palo Alto docs the catalog cites: LACP and jumbo frames on VM-Series, Decrypt Mirror, the Log Card interface, PoE, Advanced Routing Engine. The list is partial; the tool says so.
- **Capacity.** Rule, NAT, decryption, zone, address, service, tunnel and route counts from your config against the model's published limits, with sources. A limit the sources do not give is shown as **unknown**, never guessed. GlobalProtect users are not in a config, so compare that limit with the old firewall's peak user count.
- **Rack and power.** Rack units, depth, weight, airflow, maximum watts, power inlet type (C13/C14, C19/C20) and PSU wattage, old versus new. Rail kits are not in the datasheets; confirm them on the quote.

## Tab 7: Report for finance / sales

A summary: current device and status, peak load, the proposed model and why, quantity,
the hardware, power and cabling list, the license list and a short readiness section. It always prints in light mode and never includes prices.
**Export report (HTML)** saves a standalone file; **Print / save as PDF** prints it.
**Export cutover runbook (Markdown)** writes the change checklist: pre-checks, import and validate, cutover (HA failover order, ARP/MAC clear on neighbors), post-checks with CLI commands, and rollback.
**Save plan (JSON)** keeps your choices (target, port map, hardware, licenses, convert options) so you can reload them with **Load plan** after loading the same tech-support file again. The plan file never contains the admin password or its hash. It does hold the hostname and IP addresses you typed, so keep it with the project files.


## High availability (HA)

- The TSF from the **active** unit is the input. The Current tab shows the HA mode and the peer.
- On **Pick the new firewall**, "HA pair on the new firewall" defaults to on when the old firewall is in HA. Quantities
  for the hardware, cords, optics and the quote list are doubled; turn it off for a single replacement.
- On **Hardware & cabling**, each HA link (HA1, HA2, backup links) gets its old port, its new port and what to connect:
  a dedicated RJ45 HA port takes a plain Ethernet cable; SFP+/QSFP HA ports need optics (two per link) or a DAC.
  Models without dedicated HA ports use data ports.
- On **Convert config**, pick the data ports for HA1/HA2 when the target has no dedicated HA ports. The tool suggests
  free copper ports and sets them to type HA. If you turn HA off on the Pick tab, the HA section is removed from the
  converted config (logged in the change log) and the dropped HA ports are not reported as unresolved.
- The cutover runbook has the HA order: suspend the passive unit, cable one side at a time, clear ARP/MAC upstream, keep the old firewall for rollback.
- The config of the pair is shared, but each unit has its own serial, management IP and HA addresses. Check the peer
  addresses in the converted config.

## Convert options at a glance

| Option | What it does |
|---|---|
| Port map | Old interface to new port. **Don't migrate** leaves an interface out; references to it are removed (list members) or flagged (single values). |
| 100% conversion | Only the interface map, plus what the new hardware requires. |
| Customized | Hostname, management IP/netmask/gateway (and IPv6), DNS servers, standalone (remove Panorama). Warns when the old management IP is still referenced. |
| Break-glass admin | Local superuser (or read-only superuser) with no authentication profile, password hashed in the browser as `$5$` SHA-256 crypt. The password and hash are never stored, logged or shown in the change log. |
| Real exported config | A superuser export from the old firewall. Replaces the TSF copy for the conversion; kept only in the page; never saved in a plan. A file that still has `********` values is refused. |
| Output | Converted XML and a change-log CSV. **Fix before you commit** and **Encrypted values to check** list what needs a human. |

## Troubleshooting and caveats

- **"Sanitized" or "bad encryption" on `validate full`.** The input was the masked config. Re-run the conversion from a
  superuser export (see above). Encrypted values (`-AQ==`) still need the same master key on the new firewall.
- **Masked values are counted, not shown.** The Current, Convert and Readiness tabs say how many there are, by field.
- **Panorama-managed firewall.** Interfaces and inventory come from the merged config in the TSF. Only the local config
  is converted. Update the interface names in the template (stack) in Panorama by hand and add the new serial there.
- **Break-glass login.** The `$5$` hash format was tested on a PAN-OS 11.1 firewall (API login and SSH). Test the login
  on your own new firewall before cutover. Older releases that expect `$1$` were not tested.
- **Very small samples.** A device with only a few days of uptime and little load gets a "very low measured load" note
  on the Target tab. Add headroom or type your own numbers.
- **Not a substitute for review.** Check every output against the Palo Alto documentation and your change process.

## Privacy

The page makes one optional network request, to look for a newer model catalog (see
[docs/DATA_SOURCES.md](docs/DATA_SOURCES.md)). It sends no data from your file. Tick **Hide serial numbers** before you
share a screen or a report. Plan files hold the hostname and IP addresses you typed, so keep them with the project
files. Never commit a real TSF or config; the repository `.gitignore` blocks `*.tgz` and `*.xml` except for the
synthetic samples.

Known gaps are listed in [docs/KNOWN_GAPS.md](docs/KNOWN_GAPS.md); how the converter was checked is in
[docs/VALIDATION.md](docs/VALIDATION.md).
